"""Tests for the recursive archive analyzer (phase 14.3b).

We build real zip / gzip / tar containers in-memory, drop known-bad
payloads inside (a PCAP whose SMB stream screams lateral movement), and
assert the analyzer unpacks, recurses, merges child IOCs, and holds its
zip-bomb / depth / encryption defences.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import tempfile
import zipfile
from pathlib import Path

from ioc_hunter.analyze import FileFormat, analyze
from ioc_hunter.analyze.dispatcher import analyze_bytes
from tests._pcap_fixtures import build_pcap, eth_ipv4_tcp, smb2_tree_connect


def _malicious_pcap() -> bytes:
    """A capture that grades malicious: SMB TREE_CONNECT to an admin share."""
    return build_pcap(
        [
            (
                1.0,
                eth_ipv4_tcp(
                    "10.0.0.5", "10.0.0.9", 50000, 445, payload=smb2_tree_connect(r"\\DC01\ADMIN$")
                ),
            )
        ]
    )


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _set_encrypted_bit(zip_bytes: bytes) -> bytes:
    """Flip the general-purpose 'encrypted' flag in a stdlib-written zip.

    ``zipfile`` can't *write* encrypted archives, but the analyzer only
    reads the flag (it never tries to decrypt), so toggling bit 0 of the
    GP-flags field in the local + central headers is enough to exercise
    the detection path.
    """
    data = bytearray(zip_bytes)
    # Local file header: PK\x03\x04, GP flags at offset +6.
    i = data.find(b"PK\x03\x04")
    if i >= 0:
        data[i + 6] |= 0x01
    # Central directory header: PK\x01\x02, GP flags at offset +8.
    j = data.find(b"PK\x01\x02")
    if j >= 0:
        data[j + 8] |= 0x01
    return bytes(data)


def _write(raw: bytes, suffix: str = ".zip") -> Path:
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(raw)
        return Path(f.name)


def _rules(report) -> set[str]:
    return {f.rule for f in report.findings}


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def test_plain_zip_routes_to_archive_not_ooxml():
    report = analyze(_write(_zip({"a.txt": b"hello"})))
    assert report.format == FileFormat.ARCHIVE


def test_real_docx_still_routes_to_ooxml():
    docx = _zip({"[Content_Types].xml": b"<x/>", "word/document.xml": b"<w/>"})
    report = analyze(_write(docx, ".docx"))
    assert report.format == FileFormat.OOXML


# ---------------------------------------------------------------------------
# Recursion + IOC merge
# ---------------------------------------------------------------------------


def test_zip_member_malicious_escalates_parent_verdict():
    report = analyze(_write(_zip({"capture.pcap": _malicious_pcap()})))
    assert report.verdict.value == "malicious"
    assert "archive.member_malicious" in _rules(report)
    members = report.metadata["archive_members"]
    assert any(m["name"] == "capture.pcap" and m["verdict"] == "malicious" for m in members)


def test_zip_merges_member_iocs():
    report = analyze(_write(_zip({"note.txt": b"reach http://evil.example/payload now"})))
    values = {i.value for i in report.iocs}
    assert any("evil.example" in v for v in values)


def test_nested_zip_is_unpacked():
    inner = _zip({"capture.pcap": _malicious_pcap()})
    outer = _zip({"stage1.zip": inner})
    report = analyze(_write(outer))
    assert report.verdict.value == "malicious"
    assert "archive.member_malicious" in _rules(report)


# ---------------------------------------------------------------------------
# Delivery / evasion tells
# ---------------------------------------------------------------------------


def test_executable_member_flagged():
    report = analyze(_write(_zip({"invoice.pdf.js": b"var x = 1;", "readme.txt": b"hi"})))
    assert "archive.executable_payload" in _rules(report)
    finding = next(f for f in report.findings if f.rule == "archive.executable_payload")
    assert "T1204.002" in finding.mitre


def test_encrypted_member_flagged():
    enc = _set_encrypted_bit(_zip({"secret.exe": b"payload-bytes"}))
    report = analyze(_write(enc))
    assert "archive.encrypted_member" in _rules(report)


# ---------------------------------------------------------------------------
# Zip-bomb + safety
# ---------------------------------------------------------------------------


def test_zip_bomb_is_detected_and_skipped():
    bomb = _zip({"big.bin": b"\x00" * (9 * 1024 * 1024)})
    report = analyze(_write(bomb))
    assert "archive.zip_bomb" in _rules(report)
    # The bomb member must NOT have been expanded into a child report.
    members = report.metadata["archive_members"]
    assert all(m["verdict"] != "malicious" for m in members)


def test_corrupt_zip_is_total():
    # PK magic but a shredded central directory — must not raise.
    report = analyze(_write(b"PK\x03\x04" + b"\xff" * 200))
    assert report.format in (FileFormat.ARCHIVE, FileFormat.UNKNOWN)


def test_deeply_nested_zip_is_bounded():
    # Nest well past MAX_ARCHIVE_DEPTH; must terminate without error.
    payload = _zip({"capture.pcap": _malicious_pcap()})
    for i in range(8):
        payload = _zip({f"layer{i}.zip": payload})
    report = analyze(_write(payload))
    assert report.format == FileFormat.ARCHIVE  # completed, no infinite recursion


# ---------------------------------------------------------------------------
# Other containers
# ---------------------------------------------------------------------------


def test_gzip_stream_is_recursed():
    raw = gzip.compress(_malicious_pcap())
    report = analyze(_write(raw, ".gz"))
    assert report.format == FileFormat.ARCHIVE
    assert "archive.member_malicious" in _rules(report)


def test_tar_is_recursed():
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w") as t:
        data = _malicious_pcap()
        info = tarfile.TarInfo("capture.pcap")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    report = analyze(_write(tb.getvalue(), ".tar"))
    assert report.format == FileFormat.ARCHIVE
    assert "archive.member_malicious" in _rules(report)


def test_tar_gz_double_wrap():
    inner_tar = io.BytesIO()
    with tarfile.open(fileobj=inner_tar, mode="w") as t:
        data = _malicious_pcap()
        info = tarfile.TarInfo("capture.pcap")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    raw = gzip.compress(inner_tar.getvalue())
    report = analyze(_write(raw, ".tar.gz"))
    assert "archive.member_malicious" in _rules(report)


# ---------------------------------------------------------------------------
# analyze_bytes direct
# ---------------------------------------------------------------------------


def test_analyze_bytes_hashes_full_member():
    data = b"some content"
    report = analyze_bytes(data, label="x")
    import hashlib

    assert report.sha256 == hashlib.sha256(data).hexdigest()
