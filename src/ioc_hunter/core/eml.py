"""Parse .eml messages into IOCs.

Phishing triage is a daily task — analysts get an .eml, need to know:

- who claims to be sending it (From, Reply-To, Return-Path)
- the real chain of MTAs (Received hops, X-Originating-IP)
- every URL in the body (both text/plain and rendered text/html)
- every attachment's filename + hash
- bare IOCs (IPs, domains, emails) anywhere in the message

Built on stdlib `email` only — no extra deps. The HTML side is decoded
with a tiny stdlib HTML stripper rather than BeautifulSoup; we only need
text and `href=` attributes.
"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path

from ioc_hunter.core.parser import extract_iocs
from ioc_hunter.core.types import IOC, IOCType

# A Received hop with `from <name> (<host> [<ip>])` style; we pull the IP.
_RECEIVED_IP = re.compile(r"\[((?:\d{1,3}\.){3}\d{1,3})\]")
# Cap on attachment size we hash. Stops a malicious .eml claiming a 4GB
# attachment from blowing up memory.
_MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024
# Cap on total decoded body text. Same defense.
_MAX_BODY_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class EmailAttachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str


@dataclass(frozen=True, slots=True)
class EmailReport:
    """Structured view of one parsed .eml."""

    subject: str | None
    from_addr: str | None
    reply_to: str | None
    return_path: str | None
    to_addrs: tuple[str, ...]
    message_id: str | None
    date: str | None
    received_chain: tuple[str, ...]
    x_originating_ip: str | None
    body_text: str
    body_html: str
    attachments: tuple[EmailAttachment, ...] = ()
    iocs: tuple[IOC, ...] = field(default=())


class _HTMLToText(HTMLParser):
    """Tiny stdlib HTML stripper. Keeps href values so URLs survive."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self._chunks.append(f" {v} ")

    def get_text(self) -> str:
        return "".join(self._chunks)


def _decode_payload(part: Message) -> bytes:
    """Return the raw bytes of a leaf MIME part, decoded from any CTE."""
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload
    return b""


def _decode_text_part(part: Message) -> str:
    raw = _decode_payload(part)
    if not raw:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _is_attachment(part: Message) -> bool:
    """A leaf part is an attachment if Content-Disposition says so OR it has
    a filename. Inline images with a filename also count — they're a common
    phishing artifact."""
    if part.is_multipart():
        return False
    if part.get_filename():
        return True
    disp = (part.get("Content-Disposition") or "").lower()
    return disp.startswith("attachment")


def _hash_attachment(data: bytes) -> tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


def parse_eml(source: str | bytes | Path) -> EmailReport:
    """Parse an .eml from a path, bytes, or string into an EmailReport."""
    if isinstance(source, Path):
        raw = source.read_bytes()
    elif isinstance(source, str):
        raw = source.encode("utf-8", errors="replace")
    else:
        raw = source

    msg: Message = email.message_from_bytes(raw)

    text_chunks: list[str] = []
    html_chunks: list[str] = []
    attachments: list[EmailAttachment] = []

    total_body_bytes = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        if _is_attachment(part):
            data = _decode_payload(part)[:_MAX_ATTACHMENT_BYTES]
            if not data:
                continue
            sha256, md5 = _hash_attachment(data)
            # Use only the basename — defends against path-traversal filenames
            # like ../../etc/passwd.
            raw_name = part.get_filename() or "(unnamed)"
            safe_name = Path(raw_name).name or "(unnamed)"
            attachments.append(
                EmailAttachment(
                    filename=safe_name,
                    content_type=ctype,
                    size=len(data),
                    sha256=sha256,
                    md5=md5,
                )
            )
            continue
        if ctype == "text/plain":
            chunk = _decode_text_part(part)
            if total_body_bytes + len(chunk) > _MAX_BODY_BYTES:
                chunk = chunk[: _MAX_BODY_BYTES - total_body_bytes]
            total_body_bytes += len(chunk)
            text_chunks.append(chunk)
        elif ctype == "text/html":
            chunk = _decode_text_part(part)
            if total_body_bytes + len(chunk) > _MAX_BODY_BYTES:
                chunk = chunk[: _MAX_BODY_BYTES - total_body_bytes]
            total_body_bytes += len(chunk)
            html_chunks.append(chunk)

    body_text = "".join(text_chunks)
    body_html = "".join(html_chunks)

    html_as_text = ""
    if body_html:
        stripper = _HTMLToText()
        try:
            stripper.feed(body_html)
            html_as_text = stripper.get_text()
        except Exception:
            # Malformed HTML shouldn't kill the whole parse.
            html_as_text = body_html

    received_chain: list[str] = []
    for hdr in msg.get_all("Received") or []:
        flat = " ".join(hdr.split())
        received_chain.append(flat)

    x_originating = None
    raw_xoi = msg.get("X-Originating-IP")
    if raw_xoi:
        m = re.search(r"((?:\d{1,3}\.){3}\d{1,3})", raw_xoi)
        if m:
            x_originating = m.group(1)

    to_addrs: list[str] = []
    for hdr_name in ("To", "Cc"):
        raw_val = msg.get(hdr_name)
        if raw_val:
            for addr in raw_val.split(","):
                addr = addr.strip()
                if addr:
                    to_addrs.append(addr)

    combined_for_iocs = "\n".join(
        [
            msg.get("Subject") or "",
            msg.get("From") or "",
            msg.get("Reply-To") or "",
            msg.get("Return-Path") or "",
            msg.get("To") or "",
            msg.get("Cc") or "",
            "\n".join(received_chain),
            raw_xoi or "",
            body_text,
            html_as_text,
            "\n".join(a.filename for a in attachments),
        ]
    )

    iocs = list(extract_iocs(combined_for_iocs))

    # Surface Received-hop IPs explicitly — extract_iocs would catch them
    # in the joined text too, but we want them in the IOC list even when
    # the regex above failed (e.g. IPv6 hops).
    seen = {(i.type, i.value) for i in iocs}
    for hop in received_chain:
        for m in _RECEIVED_IP.finditer(hop):
            ip = m.group(1)
            key = (IOCType.IPV4, ip)
            if key not in seen:
                seen.add(key)
                iocs.append(IOC(value=ip, type=IOCType.IPV4))

    if x_originating:
        key = (IOCType.IPV4, x_originating)
        if key not in seen:
            iocs.append(IOC(value=x_originating, type=IOCType.IPV4))

    # Attachment hashes as IOCs.
    for att in attachments:
        for h_value, h_type in ((att.sha256, IOCType.SHA256), (att.md5, IOCType.MD5)):
            key = (h_type, h_value)
            if key not in seen:
                seen.add(key)
                iocs.append(IOC(value=h_value, type=h_type))

    return EmailReport(
        subject=msg.get("Subject"),
        from_addr=msg.get("From"),
        reply_to=msg.get("Reply-To"),
        return_path=msg.get("Return-Path"),
        to_addrs=tuple(to_addrs),
        message_id=msg.get("Message-ID"),
        date=msg.get("Date"),
        received_chain=tuple(received_chain),
        x_originating_ip=x_originating,
        body_text=body_text,
        body_html=body_html,
        attachments=tuple(attachments),
        iocs=tuple(iocs),
    )
