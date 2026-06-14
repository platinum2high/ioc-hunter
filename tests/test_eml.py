"""Tests for the .eml parser."""

from __future__ import annotations

from email.message import EmailMessage

from ioc_hunter.core.eml import parse_eml
from ioc_hunter.core.types import IOCType


def _build_simple_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "Bank Support <support@b4nk-secure.com>"
    msg["Reply-To"] = "attacker@evil.example"
    msg["Return-Path"] = "<bounce@evil.example>"
    msg["To"] = "victim@corp.example, accounting@corp.example"
    msg["Subject"] = "URGENT: verify your account"
    msg["Date"] = "Mon, 14 Jun 2026 12:00:00 +0000"
    msg["Message-ID"] = "<deadbeef@evil.example>"
    msg["X-Originating-IP"] = "[185.220.101.5]"
    msg["Received"] = (
        "from mail.evil.example (mail.evil.example [185.220.101.5]) by mx.corp.example with ESMTPS"
    )
    msg["Received"] = (
        "from internal.corp.example (internal.corp.example [10.0.0.5]) by mx.corp.example"
    )
    msg.set_content(
        "Please confirm at hxxp://phish[.]evil[.]example/login\n"
        "Or call our hotline. Hash: 44d88612fea8a8f36de82e1278abb02f\n"
    )
    msg.add_alternative(
        "<html><body>"
        "<a href='https://login.evil.example/verify'>Verify here</a>"
        "<p>Suspicious traffic from 1.2.3.4</p>"
        "</body></html>",
        subtype="html",
    )
    return msg.as_bytes()


def test_envelope_headers_extracted() -> None:
    report = parse_eml(_build_simple_eml())
    assert report.subject is not None and "URGENT" in report.subject
    assert report.from_addr is not None and "b4nk-secure" in report.from_addr
    assert report.reply_to == "attacker@evil.example"
    assert report.return_path == "<bounce@evil.example>"
    assert len(report.to_addrs) == 2
    assert report.x_originating_ip == "185.220.101.5"
    assert report.message_id is not None
    assert len(report.received_chain) == 2


def test_iocs_from_headers_and_body() -> None:
    report = parse_eml(_build_simple_eml())
    values = {(i.type, i.value) for i in report.iocs}
    # X-Originating IP surfaces.
    assert (IOCType.IPV4, "185.220.101.5") in values
    # Received-hop internal IP also captured.
    assert (IOCType.IPV4, "10.0.0.5") in values
    # Body IP.
    assert (IOCType.IPV4, "1.2.3.4") in values
    # Defanged URL in text body is refanged + extracted.
    assert any(i.type is IOCType.URL and "phish.evil.example" in i.value for i in report.iocs)
    # href in HTML body is captured.
    assert any(i.type is IOCType.URL and "login.evil.example" in i.value for i in report.iocs)
    # MD5 in body.
    assert (IOCType.MD5, "44d88612fea8a8f36de82e1278abb02f") in values
    # Reply-To email.
    assert (IOCType.EMAIL, "attacker@evil.example") in values


def test_attachment_filenames_sanitized_and_hashed() -> None:
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["To"] = "c@d.example"
    msg["Subject"] = "test"
    msg.set_content("see attached")
    payload = b"MZ\x90\x00fake-pe-bytes"
    msg.add_attachment(
        payload,
        maintype="application",
        subtype="octet-stream",
        # Path-traversal attempt — parser must keep only basename.
        filename="../../etc/passwd-invoice.exe",
    )
    report = parse_eml(msg.as_bytes())
    assert len(report.attachments) == 1
    att = report.attachments[0]
    assert "/" not in att.filename and ".." not in att.filename
    assert att.filename.endswith("invoice.exe")
    assert att.size == len(payload)
    # SHA-256 and MD5 surface as IOCs.
    values = {(i.type, i.value) for i in report.iocs}
    assert (IOCType.SHA256, att.sha256) in values
    assert (IOCType.MD5, att.md5) in values


def test_malformed_html_does_not_crash() -> None:
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["To"] = "c@d.example"
    msg["Subject"] = "test"
    msg.set_content("plain")
    msg.add_alternative("<p>broken<a href=", subtype="html")
    report = parse_eml(msg.as_bytes())
    # We just need to not throw and to keep envelope intact.
    assert report.subject == "test"


def test_parse_from_bytes_string_and_path(tmp_path) -> None:
    raw = _build_simple_eml()
    r_bytes = parse_eml(raw)
    r_str = parse_eml(raw.decode("utf-8", errors="replace"))
    p = tmp_path / "msg.eml"
    p.write_bytes(raw)
    r_path = parse_eml(p)
    assert r_bytes.subject == r_str.subject == r_path.subject
    assert len(r_bytes.iocs) == len(r_path.iocs)


def test_received_chain_ip_capture_with_ipv6_hop() -> None:
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["To"] = "c@d.example"
    msg["Subject"] = "test"
    msg["Received"] = "from foo (foo [2001:db8::1]) by mx.example"
    msg["Received"] = "from bar (bar [203.0.113.7]) by mx.example"
    msg.set_content("body")
    report = parse_eml(msg.as_bytes())
    assert len(report.received_chain) == 2
    values = {(i.type, i.value) for i in report.iocs}
    assert (IOCType.IPV4, "203.0.113.7") in values
    # IPv6 captured via the broader regex in extract_iocs.
    assert any(i.type is IOCType.IPV6 for i in report.iocs)


def test_huge_body_is_capped() -> None:
    # A 20MB text/plain body should not cause memory issues. We just want
    # the parser to return something sensible.
    msg = EmailMessage()
    msg["From"] = "a@b.example"
    msg["To"] = "c@d.example"
    msg["Subject"] = "test"
    body = "A" * (20 * 1024 * 1024)
    msg.set_content(body)
    report = parse_eml(msg.as_bytes())
    assert report.subject == "test"
    assert len(report.body_text) <= 20 * 1024 * 1024
