"""Recursive archive analyzer.

Malware almost never arrives as a bare executable — it arrives zipped,
often nested (``invoice.zip`` → ``invoice.iso``-alike → ``invoice.exe``),
and frequently password-protected to slip past gateway AV. This module
unpacks the common container families with **stdlib only** (``zipfile``,
``tarfile``, ``gzip``/``zlib``, ``bz2``, ``lzma``) and re-dispatches every
member back through the analyzer, so a PE buried three layers down still
gets its imports walked and its IOCs swept.

Three things make this safe to point at hostile input:

- **Depth cap** — recursion stops at ``MAX_ARCHIVE_DEPTH`` so an archive
  that contains itself can't loop.
- **Budget cap** — a shared uncompressed-bytes budget across the whole
  recursion bounds total work regardless of how the bomb is shaped.
- **Ratio check** — a member whose compression ratio is wildly high (the
  classic zip-bomb signature) is reported and skipped, not expanded.

Everything is total: a corrupt central directory, a truncated gzip
stream, or a member that lies about its size degrades the report, it
never raises.
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    Finding,
    Severity,
)

# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

#: How deep we recurse into nested archives (zip-in-zip-in-...).
MAX_ARCHIVE_DEPTH = 4

#: Members we extract per archive. Past this we stop and note truncation.
MAX_ARCHIVE_MEMBERS = 1000

#: Largest single member we will decompress, in bytes.
MAX_MEMBER_BYTES = 64 * 1024 * 1024  # 64 MiB

#: Total uncompressed bytes we will produce across the *whole* recursion.
MAX_TOTAL_BYTES = 512 * 1024 * 1024  # 512 MiB

#: Compression ratio (uncompressed / compressed) above which, combined with
#: a large absolute size, we treat a member as a zip bomb and skip it.
ZIP_BOMB_RATIO = 200
ZIP_BOMB_MIN_BYTES = 8 * 1024 * 1024  # only ratio-flag members over 8 MiB

#: File extensions that are executable / script payloads — a strong phishing
#: tell when they're the cargo of a mailed archive.
_EXECUTABLE_EXTS = frozenset(
    {
        ".exe",
        ".scr",
        ".com",
        ".pif",
        ".bat",
        ".cmd",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".wsf",
        ".wsh",
        ".hta",
        ".ps1",
        ".jar",
        ".lnk",
        ".msi",
        ".dll",
        ".cpl",
        ".reg",
        ".iso",
        ".img",
        ".vhd",
    }
)

#: Recursion callback type: ``(member_bytes, label) -> AnalyzerReport``.
RecurseFn = Callable[[bytes, str], AnalyzerReport]


@dataclass(slots=True)
class _Member:
    name: str
    data: bytes
    encrypted: bool
    declared_size: int
    compressed_size: int


# ---------------------------------------------------------------------------
# Subtype detection
# ---------------------------------------------------------------------------


def is_tar(raw: bytes) -> bool:
    """The tar ``ustar`` magic lives at offset 257, so it can't be a head
    check — the dispatcher calls this on the full buffer."""
    return len(raw) > 263 and raw[257:262] == b"ustar"


def detect_archive_kind(raw: bytes) -> str:
    """Return ``'zip' | 'gzip' | 'bzip2' | 'xz' | 'tar' | ''``."""
    if raw[:2] == b"PK" and raw[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08"):
        return "zip"
    if raw[:2] == b"\x1f\x8b":
        return "gzip"
    if raw[:3] == b"BZh":
        return "bzip2"
    if raw[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if is_tar(raw):
        return "tar"
    return ""


# ---------------------------------------------------------------------------
# Bounded decompression helpers
# ---------------------------------------------------------------------------


def _inflate_bounded(decompressor, raw: bytes, cap: int) -> tuple[bytes, bool]:
    """Drive a zlib/bz2/lzma decompressor object with an output cap.

    Returns (data, truncated). The decompressor's ``decompress(data, max)``
    contract lets us stop the moment we hit ``cap`` even if the stream
    claims to expand to gigabytes — the zip-bomb defence for single-stream
    formats.
    """
    try:
        out = decompressor.decompress(raw, cap + 1)
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return (b"", False)
    if len(out) > cap:
        return (bytes(out[:cap]), True)
    return (bytes(out), False)


def _gunzip(raw: bytes, cap: int) -> tuple[bytes, bool]:
    return _inflate_bounded(zlib.decompressobj(zlib.MAX_WBITS | 16), raw, cap)


def _bunzip2(raw: bytes, cap: int) -> tuple[bytes, bool]:
    return _inflate_bounded(bz2.BZ2Decompressor(), raw, cap)


def _unxz(raw: bytes, cap: int) -> tuple[bytes, bool]:
    return _inflate_bounded(lzma.LZMADecompressor(), raw, cap)


# ---------------------------------------------------------------------------
# Per-format member iteration
# ---------------------------------------------------------------------------


def _iter_zip_members(raw: bytes, budget: list[int]) -> Iterator[_Member]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile, OSError, EOFError):
        return
    with zf:
        for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
            if info.is_dir():
                continue
            if budget[0] <= 0:
                return
            encrypted = bool(info.flag_bits & 0x1)
            declared = info.file_size
            compressed = info.compress_size or 1
            # Ratio bomb: never even attempt to read a wildly-expanding entry.
            if declared >= ZIP_BOMB_MIN_BYTES and declared / compressed >= ZIP_BOMB_RATIO:
                yield _Member(info.filename, b"", encrypted, declared, info.compress_size)
                continue
            data = b""
            if not encrypted:
                cap = min(MAX_MEMBER_BYTES, budget[0])
                try:
                    with zf.open(info) as fh:
                        data = fh.read(cap)
                except (RuntimeError, zipfile.BadZipFile, OSError, EOFError, NotImplementedError):
                    data = b""
                budget[0] -= len(data)
            yield _Member(info.filename, data, encrypted, declared, info.compress_size)


def _iter_tar_members(raw: bytes, budget: list[int]) -> Iterator[_Member]:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            count = 0
            for member in tf:
                if count >= MAX_ARCHIVE_MEMBERS or budget[0] <= 0:
                    return
                if not member.isfile():
                    continue
                count += 1
                cap = min(MAX_MEMBER_BYTES, budget[0])
                data = b""
                try:
                    fh = tf.extractfile(member)
                    if fh is not None:
                        data = fh.read(cap)
                except (tarfile.TarError, OSError, EOFError):
                    data = b""
                budget[0] -= len(data)
                yield _Member(member.name, data, False, member.size, member.size)
    except (tarfile.TarError, OSError, EOFError):
        return


def _single_stream_member(raw: bytes, kind: str, budget: list[int]) -> _Member | None:
    cap = min(MAX_MEMBER_BYTES, budget[0])
    if kind == "gzip":
        data, _ = _gunzip(raw, cap)
        name = "gzip-stream"
    elif kind == "bzip2":
        data, _ = _bunzip2(raw, cap)
        name = "bzip2-stream"
    elif kind == "xz":
        data, _ = _unxz(raw, cap)
        name = "xz-stream"
    else:
        return None
    if not data:
        return None
    budget[0] -= len(data)
    return _Member(name, data, False, len(data), len(raw))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyze_archive(
    raw: bytes,
    *,
    report: AnalyzerReport,
    recurse: RecurseFn,
    depth: int,
    budget: list[int] | None = None,
) -> None:
    """Unpack ``raw`` and re-dispatch each member through ``recurse``.

    ``budget`` is a one-element mutable list carrying the shared
    uncompressed-byte allowance down the recursion; the top-level caller
    leaves it ``None`` and we seed it.
    """
    if budget is None:
        budget = [MAX_TOTAL_BYTES]
    kind = detect_archive_kind(raw)
    report.metadata["archive_kind"] = kind

    if depth >= MAX_ARCHIVE_DEPTH:
        report.add(
            Finding(
                rule="archive.depth_limit",
                severity=Severity.INFO,
                category="anomaly",
                message=f"Nested-archive depth limit ({MAX_ARCHIVE_DEPTH}) reached — "
                "deeper members not expanded.",
            )
        )
        return

    if kind == "zip":
        members = list(_iter_zip_members(raw, budget))
    elif kind == "tar":
        members = list(_iter_tar_members(raw, budget))
    elif kind in ("gzip", "bzip2", "xz"):
        single = _single_stream_member(raw, kind, budget)
        members = [single] if single is not None else []
    else:
        report.add(
            Finding(
                rule="archive.unsupported",
                severity=Severity.INFO,
                category="anomaly",
                message="Archive container recognised but no stdlib extractor applies.",
            )
        )
        members = []

    summaries: list[dict] = []
    seen_iocs = {(i.type, i.value) for i in report.iocs}
    encrypted_count = 0
    executable_members: list[str] = []
    worst_member: tuple[str, str] | None = None  # (name, verdict)

    for m in members:
        ext = _ext(m.name)
        if ext in _EXECUTABLE_EXTS:
            executable_members.append(m.name)
        if m.encrypted:
            encrypted_count += 1
            summaries.append({"name": m.name, "format": "?", "verdict": "encrypted", "findings": 0})
            continue
        if not m.data:
            # Ratio-bombed or unreadable entry.
            if m.declared_size >= ZIP_BOMB_MIN_BYTES and m.compressed_size:
                report.add(
                    Finding(
                        rule="archive.zip_bomb",
                        severity=Severity.HIGH,
                        category="anomaly",
                        message=(
                            f"Member {m.name!r} expands {m.declared_size:,} B from "
                            f"{m.compressed_size:,} B "
                            f"(ratio {m.declared_size // max(1, m.compressed_size)}:1) — "
                            "decompression-bomb shape; skipped."
                        ),
                        evidence=(m.name,),
                    )
                )
            continue

        child = recurse(m.data, m.name)
        # Merge child IOCs into the parent (dedup on (type, value)).
        for ioc in child.iocs:
            key = (ioc.type, ioc.value)
            if key not in seen_iocs:
                seen_iocs.add(key)
                report.iocs.append(ioc)

        verdict = child.verdict.value
        summaries.append(
            {
                "name": m.name,
                "format": child.format.value,
                "verdict": verdict,
                "findings": len(child.findings),
            }
        )
        if verdict in ("malicious", "suspicious"):
            if worst_member is None or verdict == "malicious":
                worst_member = (m.name, verdict)
            top = sorted(child.findings, key=lambda f: f.severity, reverse=True)[:3]
            report.add(
                Finding(
                    rule="archive.member_malicious"
                    if verdict == "malicious"
                    else "archive.member_suspicious",
                    severity=Severity.HIGH if verdict == "malicious" else Severity.MEDIUM,
                    category="embedded",
                    message=(
                        f"Archive member {m.name!r} ({child.format.value}) graded "
                        f"{verdict}: {', '.join(f.rule for f in top)}"
                    ),
                    evidence=(m.name, *[f.rule for f in top]),
                )
            )

    if encrypted_count:
        report.add(
            Finding(
                rule="archive.encrypted_member",
                severity=Severity.MEDIUM,
                category="evasion",
                message=(
                    f"{encrypted_count} password-protected member(s) — a common way "
                    "malware-laden archives defeat gateway AV scanning."
                ),
            )
        )
    if executable_members:
        report.add(
            Finding(
                rule="archive.executable_payload",
                severity=Severity.MEDIUM,
                category="delivery",
                message=(
                    f"{len(executable_members)} executable/script member(s) "
                    f"(e.g. {', '.join(executable_members[:3])}) — phishing-delivery shape."
                ),
                evidence=tuple(executable_members[:8]),
            )
        )
    if budget[0] <= 0:
        report.add(
            Finding(
                rule="archive.budget_exhausted",
                severity=Severity.INFO,
                category="anomaly",
                message="Uncompressed-size budget exhausted — some members were not expanded.",
            )
        )

    report.metadata["archive_members"] = summaries
    report.metadata["archive_member_count"] = len(members)


def _ext(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    dot = base.rfind(".")
    return base[dot:].lower() if dot >= 0 else ""
