"""Compound File Binary (CFB) container parser.

CFB is the OLE2 storage layer underneath legacy Office (.doc, .xls,
.ppt), .msi installers, and the ``vbaProject.bin`` blob inside every
macro-enabled OOXML document. Parsing it ourselves keeps the analyzer
dep-free and means OOXML / OLE / VBA all share a single defensive
reader.

The format in 90 seconds:

- A 512-byte header at offset 0 (signature ``D0 CF 11 E0 A1 B1 1A E1``)
  carries layout metadata: sector size, # FAT sectors, first directory
  sector, first MiniFAT sector, the first 109 DiFAT entries.
- Sectors after the header are sector_size bytes each; file offset of
  sector ``N`` is ``(N+1) * sector_size``.
- The **FAT** is a flat array of next-sector pointers. To read a stream
  with starting sector ``S``, walk the chain ``FAT[S], FAT[FAT[S]], ...``
  until ``ENDOFCHAIN`` (0xFFFFFFFE).
- The **directory** is itself a stream (chain starting from
  ``first_directory_sector``). Each entry is 128 bytes — name (UTF-16LE),
  object type (storage / stream / root), starting sector, size, plus a
  red-black tree of left/right/child IDs that describes the storage
  hierarchy.
- Streams smaller than 4 KiB live in the **mini stream**, indexed by a
  separate MiniFAT with 64-byte sectors. The mini stream itself is a
  regular stream whose starting sector is in the root directory entry.

References:
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from ioc_hunter.analyze.common import (
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Special FAT entries.
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
MAXREGSECT = 0xFFFFFFFA

# Caps. Pathological CFBs that point at themselves can loop forever —
# bound every traversal.
MAX_SECTORS = 1 << 20  # 1 M sectors ⇒ 4 GiB at 4 KiB sectors
MAX_DIR_ENTRIES = 50_000
MAX_STREAM_BYTES = 256 * 1024 * 1024  # 256 MiB — same cap as analyze pipeline

# Directory entry object types.
OBJ_EMPTY = 0
OBJ_STORAGE = 1
OBJ_STREAM = 2
OBJ_ROOT = 5

NOSTREAM = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OleDirEntry:
    """One entry from the CFB directory table."""

    index: int
    name: str
    obj_type: int
    starting_sector: int
    size: int
    left: int
    right: int
    child: int
    clsid: str  # hex string, "" if all-zero


@dataclass(slots=True)
class OleContainer:
    """Parsed CFB. ``streams`` maps storage-path → bytes for every
    stream we successfully extracted. ``directory`` is the flat
    directory dump for tools that want to inspect storage hierarchy.
    """

    raw: bytes
    sector_size: int = 0
    mini_sector_size: int = 0
    mini_cutoff: int = 0
    first_dir_sector: int = ENDOFCHAIN
    num_fat_sectors: int = 0
    first_minifat_sector: int = ENDOFCHAIN
    num_minifat_sectors: int = 0
    first_difat_sector: int = ENDOFCHAIN
    num_difat_sectors: int = 0
    major_version: int = 0
    minor_version: int = 0
    fat: list[int] = field(default_factory=list)
    minifat: list[int] = field(default_factory=list)
    mini_stream: bytes = b""
    directory: list[OleDirEntry] = field(default_factory=list)
    streams: dict[str, bytes] = field(default_factory=dict)
    parse_error: str = ""

    def has_stream(self, path: str) -> bool:
        return path in self.streams

    def read_stream(self, path: str) -> bytes | None:
        return self.streams.get(path)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def is_cfb(head: bytes) -> bool:
    return head[:8] == CFB_SIGNATURE


def parse_cfb(raw: bytes) -> OleContainer:
    """Parse a CFB blob into an ``OleContainer``. Never raises.

    On malformed input returns a container with ``parse_error`` set
    and as much partial state as we managed to extract.
    """
    container = OleContainer(raw=raw)

    if len(raw) < 512 or not is_cfb(raw):
        container.parse_error = "not a CFB file"
        return container

    try:
        _parse_header(raw, container)
    except struct.error as e:
        container.parse_error = f"header: {e}"
        return container

    if container.sector_size <= 0:
        return container

    # FAT comes next — needed to walk every other chain.
    try:
        _build_fat(raw, container)
    except (struct.error, IndexError) as e:
        container.parse_error = f"fat: {e}"
        return container

    # Directory chain → entries.
    try:
        _build_directory(raw, container)
    except (struct.error, IndexError) as e:
        container.parse_error = f"directory: {e}"
        return container

    # Root entry's starting sector / size define the mini stream + cutoff.
    try:
        _build_mini_stream(raw, container)
    except (struct.error, IndexError) as e:
        container.parse_error = f"mini_stream: {e}"
        # Non-fatal — regular streams still parse.

    # MiniFAT — used to walk mini-stream chains.
    try:
        _build_minifat(raw, container)
    except (struct.error, IndexError) as e:
        container.parse_error = f"minifat: {e}"

    # Resolve every stream into raw bytes via DFS over the directory tree.
    _resolve_streams(container)

    return container


def analyze_ole(raw: bytes, *, report: AnalyzerReport) -> AnalyzerReport:
    """Top-level analyzer entry for a CFB blob (legacy .doc/.xls/.ppt,
    .msi, or a bare ``vbaProject.bin``)."""
    report.format = FileFormat.OLE

    container = parse_cfb(raw)
    if container.parse_error:
        report.add(
            Finding(
                rule="ole.parse_error",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=f"CFB parse failure: {container.parse_error}",
            )
        )
        return report

    report.metadata["ole_sector_size"] = container.sector_size
    report.metadata["ole_streams"] = sorted(container.streams.keys())
    report.metadata["ole_stream_count"] = len(container.streams)
    report.metadata["ole_directory"] = [
        {
            "name": e.name,
            "type": e.obj_type,
            "size": e.size,
            "clsid": e.clsid,
        }
        for e in container.directory
        if e.obj_type != OBJ_EMPTY
    ]

    _emit_ole_findings(container, report)

    # If the CFB carries VBA, hand off to the VBA module (imported lazily
    # to avoid a circular module dep).
    if _looks_like_vba_project(container):
        from ioc_hunter.analyze.vba import analyze_vba_project

        analyze_vba_project(container, report=report)

    # Equation Native: the CVE-2017-11882 marker. Just spotting the
    # stream is enough — analysts pivot on filename alone.
    if any(name.endswith("Equation Native") for name in container.streams):
        report.add(
            Finding(
                rule="ole.equation_editor",
                severity=Severity.HIGH,
                category="exploit",
                message="Document contains an 'Equation Native' stream — classic "
                "CVE-2017-11882 / CVE-2018-0802 exploit primitive.",
                evidence=("Equation Native",),
            )
        )

    return report


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def _parse_header(raw: bytes, c: OleContainer) -> None:
    # struct layout for header fields starting at offset 0x18.
    minor_ver = struct.unpack_from("<H", raw, 0x18)[0]
    major_ver = struct.unpack_from("<H", raw, 0x1A)[0]
    byte_order = struct.unpack_from("<H", raw, 0x1C)[0]
    sector_shift = struct.unpack_from("<H", raw, 0x1E)[0]
    mini_sector_shift = struct.unpack_from("<H", raw, 0x20)[0]
    # offset 0x22..0x28: reserved (6 bytes)
    num_dir_sectors = struct.unpack_from("<I", raw, 0x28)[0]
    num_fat_sectors = struct.unpack_from("<I", raw, 0x2C)[0]
    first_dir_sector = struct.unpack_from("<I", raw, 0x30)[0]
    # 0x34 transaction signature
    mini_cutoff = struct.unpack_from("<I", raw, 0x38)[0]
    first_minifat_sector = struct.unpack_from("<I", raw, 0x3C)[0]
    num_minifat_sectors = struct.unpack_from("<I", raw, 0x40)[0]
    first_difat_sector = struct.unpack_from("<I", raw, 0x44)[0]
    num_difat_sectors = struct.unpack_from("<I", raw, 0x48)[0]

    if byte_order != 0xFFFE:
        c.parse_error = f"unexpected byte order 0x{byte_order:04x}"
        return
    # Real-world sector shift is 9 (512) for v3 and 12 (4096) for v4.
    if sector_shift not in (9, 12):
        c.parse_error = f"unsupported sector shift {sector_shift}"
        return
    if mini_sector_shift != 6:
        c.parse_error = f"unsupported mini sector shift {mini_sector_shift}"
        return

    c.sector_size = 1 << sector_shift
    c.mini_sector_size = 1 << mini_sector_shift
    c.mini_cutoff = mini_cutoff
    c.first_dir_sector = first_dir_sector
    c.num_fat_sectors = num_fat_sectors
    c.first_minifat_sector = first_minifat_sector
    c.num_minifat_sectors = num_minifat_sectors
    c.first_difat_sector = first_difat_sector
    c.num_difat_sectors = num_difat_sectors
    c.major_version = major_ver
    c.minor_version = minor_ver
    _ = num_dir_sectors  # v3 ignores this; v4 uses it via the chain anyway


# ---------------------------------------------------------------------------
# Sector I/O
# ---------------------------------------------------------------------------


def _sector_offset(c: OleContainer, sector_id: int) -> int:
    return (sector_id + 1) * c.sector_size


def _read_sector(c: OleContainer, sector_id: int) -> bytes:
    off = _sector_offset(c, sector_id)
    return c.raw[off : off + c.sector_size]


def _walk_chain(
    c: OleContainer, start: int, fat: list[int], cap_sectors: int = MAX_SECTORS
) -> list[int]:
    """Walk a FAT/MiniFAT chain. Detects cycles and bounds-checks."""
    if start > MAXREGSECT:
        return []
    seen: set[int] = set()
    chain: list[int] = []
    cur = start
    while cur <= MAXREGSECT and len(chain) < cap_sectors:
        if cur in seen:  # cycle defence
            break
        if cur >= len(fat):
            break
        seen.add(cur)
        chain.append(cur)
        cur = fat[cur]
    return chain


# ---------------------------------------------------------------------------
# FAT
# ---------------------------------------------------------------------------


def _build_fat(raw: bytes, c: OleContainer) -> None:
    """Materialise the FAT as a flat ``list[int]`` of next-sector ids."""
    sector_size = c.sector_size
    entries_per_sector = sector_size // 4

    # Up to 109 FAT sector IDs live inline in the header (the DiFAT).
    difat: list[int] = []
    inline = struct.unpack_from(f"<{109}I", raw, 0x4C)
    difat.extend(s for s in inline if s != FREESECT)

    # If more FAT sectors exist, the additional DiFAT chain extends them.
    next_difat = c.first_difat_sector
    safety = 0
    while next_difat <= MAXREGSECT and safety < MAX_SECTORS:
        block = _read_sector(c, next_difat)
        if len(block) < sector_size:
            break
        # Last 4 bytes point to the next DiFAT sector.
        difat.extend(
            s for s in struct.unpack_from(f"<{entries_per_sector - 1}I", block, 0) if s != FREESECT
        )
        next_difat = struct.unpack_from("<I", block, sector_size - 4)[0]
        safety += 1

    fat: list[int] = []
    for fat_sect in difat[: c.num_fat_sectors]:
        block = _read_sector(c, fat_sect)
        if len(block) < sector_size:
            break
        fat.extend(struct.unpack_from(f"<{entries_per_sector}I", block, 0))
        if len(fat) >= MAX_SECTORS:
            break
    c.fat = fat


# ---------------------------------------------------------------------------
# Directory
# ---------------------------------------------------------------------------


def _build_directory(raw: bytes, c: OleContainer) -> None:
    first_dir = c.first_dir_sector
    chain = _walk_chain(c, first_dir, c.fat)
    dir_data = b"".join(_read_sector(c, s) for s in chain)

    entries_per_sector = c.sector_size // 128
    total_entries = min(len(chain) * entries_per_sector, MAX_DIR_ENTRIES)

    directory: list[OleDirEntry] = []
    for i in range(total_entries):
        off = i * 128
        if off + 128 > len(dir_data):
            break
        e = _parse_dir_entry(dir_data, off, i)
        directory.append(e)
    c.directory = directory


def _parse_dir_entry(buf: bytes, off: int, index: int) -> OleDirEntry:
    name_bytes = buf[off : off + 64]
    name_len = struct.unpack_from("<H", buf, off + 0x40)[0]
    if name_len < 2 or name_len > 64:
        name = ""
    else:
        # name_len includes the trailing NUL.
        name_chunk = name_bytes[: name_len - 2]
        try:
            name = name_chunk.decode("utf-16-le")
        except UnicodeDecodeError:
            name = name_chunk.decode("utf-16-le", "replace")

    obj_type = buf[off + 0x42]
    left, right, child = struct.unpack_from("<III", buf, off + 0x44)
    clsid_bytes = buf[off + 0x50 : off + 0x60]
    clsid = "" if clsid_bytes == b"\x00" * 16 else clsid_bytes.hex()
    starting_sector = struct.unpack_from("<I", buf, off + 0x74)[0]
    size_lo = struct.unpack_from("<I", buf, off + 0x78)[0]
    size_hi = struct.unpack_from("<I", buf, off + 0x7C)[0]
    # Spec: high 32 bits are 0 for v3 (512 sector); we honour them on v4.
    size = size_lo | (size_hi << 32)

    return OleDirEntry(
        index=index,
        name=name,
        obj_type=obj_type,
        starting_sector=starting_sector,
        size=size,
        left=left,
        right=right,
        child=child,
        clsid=clsid,
    )


# ---------------------------------------------------------------------------
# Mini stream + MiniFAT
# ---------------------------------------------------------------------------


def _build_mini_stream(raw: bytes, c: OleContainer) -> None:
    if not c.directory:
        return
    root = c.directory[0]
    if root.obj_type != OBJ_ROOT or root.starting_sector > MAXREGSECT:
        return
    chain = _walk_chain(c, root.starting_sector, c.fat)
    data = b"".join(_read_sector(c, s) for s in chain)
    c.mini_stream = data[: root.size]


def _build_minifat(raw: bytes, c: OleContainer) -> None:
    first = c.first_minifat_sector
    if first > MAXREGSECT:
        return
    chain = _walk_chain(c, first, c.fat)
    data = b"".join(_read_sector(c, s) for s in chain)
    entries = len(data) // 4
    c.minifat = list(struct.unpack_from(f"<{entries}I", data, 0))


def _read_mini_chain(c: OleContainer, start: int, size: int) -> bytes:
    chain = _walk_chain(c, start, c.minifat, cap_sectors=MAX_SECTORS)
    msz = c.mini_sector_size
    out = bytearray()
    for mid in chain:
        off = mid * msz
        out.extend(c.mini_stream[off : off + msz])
        if len(out) >= size:
            break
    return bytes(out[:size])


# ---------------------------------------------------------------------------
# Stream resolution — DFS across the storage tree
# ---------------------------------------------------------------------------


def _resolve_streams(c: OleContainer) -> None:
    if not c.directory:
        return

    streams: dict[str, bytes] = {}

    def _walk(idx: int, prefix: str, depth: int) -> None:
        if idx == NOSTREAM or idx >= len(c.directory) or depth > 32:
            return
        e = c.directory[idx]
        path = f"{prefix}/{e.name}" if prefix else e.name

        if e.obj_type == OBJ_STREAM and e.starting_sector <= MAXREGSECT:
            data = _read_stream_data(c, e)
            if data:
                streams[path] = data
        elif e.obj_type in (OBJ_STORAGE, OBJ_ROOT):
            _walk(e.child, path, depth + 1)

        # Red-black tree siblings live at the same logical level.
        _walk(e.left, prefix, depth + 1)
        _walk(e.right, prefix, depth + 1)

    # Root entry is index 0; its children form the top-level storages/streams.
    root = c.directory[0]
    _walk(root.child, "", 0)
    c.streams = streams


def _read_stream_data(c: OleContainer, e: OleDirEntry) -> bytes:
    if e.size == 0:
        return b""
    capped_size = min(e.size, MAX_STREAM_BYTES)
    if capped_size < c.mini_cutoff and c.mini_stream:
        return _read_mini_chain(c, e.starting_sector, capped_size)
    chain = _walk_chain(c, e.starting_sector, c.fat)
    out = bytearray()
    for s in chain:
        out.extend(_read_sector(c, s))
        if len(out) >= capped_size:
            break
    return bytes(out[:capped_size])


# ---------------------------------------------------------------------------
# Heuristics + VBA-presence detection
# ---------------------------------------------------------------------------


def _looks_like_vba_project(c: OleContainer) -> bool:
    """A CFB carries a VBA project if it has a ``VBA`` storage with a
    ``dir`` stream inside. Both .doc/.xls/.ppt and bare vbaProject.bin
    follow this convention."""
    streams = c.streams.keys()
    return any("VBA/dir" in p or p.endswith("/VBA/dir") or p == "VBA/dir" for p in streams)


def _emit_ole_findings(c: OleContainer, report: AnalyzerReport) -> None:
    # Carrying a VBA project at all is a finding for legacy Office.
    if _looks_like_vba_project(c):
        report.add(
            Finding(
                rule="ole.vba_project",
                severity=Severity.MEDIUM,
                category="document",
                message="Compound file carries a VBA macro project.",
                evidence=("VBA/dir",),
            )
        )

    # Embedded OLE objects = nested document trickery. CLSID is the tell.
    suspicious_clsids = {
        "0002ce020000000000000000000000c0": "Equation Editor 3.0",
        "0002ce030000000000000000000000c0": "Equation Editor 3.0",
        "00021290000000000000000000000046": "Package (legacy file launcher)",
    }
    for e in c.directory:
        if e.clsid in suspicious_clsids:
            report.add(
                Finding(
                    rule="ole.suspicious_clsid",
                    severity=Severity.HIGH,
                    category="exploit",
                    message=f"Embedded OLE object with risky CLSID: "
                    f"{suspicious_clsids[e.clsid]} ({e.clsid}).",
                    evidence=(e.name, e.clsid),
                )
            )

    # Streams with a /Package or /Ole10Native marker — classic dropped-file
    # vector going back to ~2014 Hancitor campaigns.
    for path in c.streams:
        if path.endswith("/\x01Ole10Native") or path.endswith("Ole10Native"):
            report.add(
                Finding(
                    rule="ole.ole10native",
                    severity=Severity.HIGH,
                    category="document",
                    message="\\x01Ole10Native stream — Packager-based file drop.",
                    evidence=(path,),
                )
            )
