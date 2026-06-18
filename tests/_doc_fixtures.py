"""Synthetic fixtures for OOXML / OLE / VBA tests.

We construct CFBs and OOXMLs byte-by-byte so the tests don't depend on
``python-docx`` / ``olefile`` / any other deps the analyzer refuses to
take. The builders are deliberately small and dumb — enough surface
area for parser coverage, no general-purpose authoring API.
"""

from __future__ import annotations

import struct
import zipfile
from io import BytesIO

from ioc_hunter.analyze.ole import (
    CFB_SIGNATURE,
    ENDOFCHAIN,
    FATSECT,
    FREESECT,
    NOSTREAM,
    OBJ_ROOT,
    OBJ_STORAGE,
    OBJ_STREAM,
)

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096


# ---------------------------------------------------------------------------
# MS-OVBA CompressedAtom encoder (just enough to build test inputs).
#
# We always emit literal-only chunks. That makes the encoder trivially
# correct (no copy-token math) while still producing a stream the
# decoder must walk byte-for-byte through the full chunk-header /
# flag-byte / literal machinery.
# ---------------------------------------------------------------------------


def build_compressed_atom(payload: bytes) -> bytes:
    """Encode ``payload`` as a CompressedAtom (literal-only chunks).

    Literal-only compressed chunks expand the body by 12.5 % (one flag
    byte per 8 literals), so we cap each chunk's plaintext at 3640
    bytes — keeps the encoded chunk under the 4098-byte ceiling.
    """
    out = bytearray([0x01])  # signature byte
    pos = 0
    # 3640 plaintext → 3640 + 3640/8 = 4095 body bytes → 4097 total chunk.
    plain_per_chunk = 3640
    while pos < len(payload):
        chunk_plain = payload[pos : pos + plain_per_chunk]
        pos += len(chunk_plain)
        body = bytearray()
        for i in range(0, len(chunk_plain), 8):
            group = chunk_plain[i : i + 8]
            body.append(0x00)  # flag byte: all 8 bits = literal
            body.extend(group)
        chunk_total = 2 + len(body)
        size_field = chunk_total - 3
        header = (1 << 15) | (0b011 << 12) | (size_field & 0x0FFF)
        out.extend(struct.pack("<H", header))
        out.extend(body)
    return bytes(out)


# ---------------------------------------------------------------------------
# CFB builder.
#
# Layout we produce (always v3, 512-byte sectors, no mini stream):
#
#   offset 0          : 512-byte header
#   sector 0          : FAT
#   sector 1          : directory chain (one sector ⇒ 4 entries)
#   sector 2..N       : stream data, packed in order
#
# Streams smaller than the mini cutoff are NOT pushed into a mini stream
# — instead we mark them as "size >= mini cutoff" by padding them. This
# keeps the FAT walk straightforward for the parser and avoids us having
# to also build a MiniFAT.
# ---------------------------------------------------------------------------


def build_minimal_cfb(streams: dict[str, bytes]) -> bytes:
    """Build a CFB blob containing the given storage-path → bytes streams.

    Storage hierarchy is encoded with each storage's ``child`` pointing
    at its first child and each child chaining siblings via ``right``.
    ``left`` is always NOSTREAM — the directory red-black tree is
    allowed to be degenerate per the spec, and our reader DFS walks it
    fine that way.
    """
    nodes = _build_tree(streams)

    # ---- Allocate sectors for stream data --------------------------------
    sector_data: list[bytes] = []  # one entry per stream-data sector
    stream_sector_starts: dict[str, int] = {}
    for path, body in streams.items():
        # Pad up to a multiple of MINI_CUTOFF so we always go through the
        # regular FAT instead of the mini stream.
        padded = body.ljust(max(len(body), MINI_CUTOFF), b"\x00")
        n_sectors = (len(padded) + SECTOR_SIZE - 1) // SECTOR_SIZE
        sector_data_start = len(sector_data)
        # 2 = header sector skip, FAT sector, dir sector
        stream_sector_starts[path] = 2 + sector_data_start
        for i in range(n_sectors):
            chunk = padded[i * SECTOR_SIZE : (i + 1) * SECTOR_SIZE]
            if len(chunk) < SECTOR_SIZE:
                chunk = chunk.ljust(SECTOR_SIZE, b"\x00")
            sector_data.append(chunk)

    total_sectors = 2 + len(sector_data)  # FAT, dir, plus stream data
    # Build FAT.
    fat: list[int] = [FREESECT] * max(total_sectors, SECTOR_SIZE // 4)
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN  # directory chain ends after one sector

    cursor = 2
    for _path, body in streams.items():
        padded = body.ljust(max(len(body), MINI_CUTOFF), b"\x00")
        n = (len(padded) + SECTOR_SIZE - 1) // SECTOR_SIZE
        for i in range(n):
            sect = cursor + i
            fat[sect] = (cursor + i + 1) if i + 1 < n else ENDOFCHAIN
        cursor += n

    # ---- Build directory sector (128 bytes per entry, 4 per sector) ------
    dir_entries: list[bytes] = []
    for node in nodes:
        # Each non-empty stream has a starting sector + size; storages get
        # sentinel values per spec.
        starting_sector = (
            stream_sector_starts.get(node.path, ENDOFCHAIN) if node.obj_type == OBJ_STREAM else 0
        )
        size = len(node.body) if node.obj_type == OBJ_STREAM else 0
        dir_entries.append(
            _encode_dir_entry(
                name=node.name,
                obj_type=node.obj_type,
                left=node.left,
                right=node.right,
                child=node.child,
                starting_sector=starting_sector,
                size=size,
            )
        )
    # Pad to a multiple of 4 entries (one sector).
    while len(dir_entries) % 4 != 0:
        dir_entries.append(_encode_dir_entry("", 0, NOSTREAM, NOSTREAM, NOSTREAM, 0, 0))
    dir_sector = b"".join(dir_entries)
    assert len(dir_sector) == SECTOR_SIZE, "dir sector must fit in one sector"

    # ---- Build FAT sector ------------------------------------------------
    # Pad to a full sector.
    fat_entries = max(SECTOR_SIZE // 4, len(fat))
    fat_padded = (fat + [FREESECT] * fat_entries)[:fat_entries]
    fat_sector = struct.pack(f"<{fat_entries}I", *fat_padded)
    # Truncate to exactly one sector.
    fat_sector = fat_sector[:SECTOR_SIZE].ljust(SECTOR_SIZE, b"\xff")

    # ---- Header ----------------------------------------------------------
    header = bytearray(b"\x00" * 512)
    header[0:8] = CFB_SIGNATURE
    header[0x08:0x18] = b"\x00" * 16  # CLSID
    struct.pack_into("<H", header, 0x18, 0x003E)  # minor version
    struct.pack_into("<H", header, 0x1A, 3)  # major version (v3)
    struct.pack_into("<H", header, 0x1C, 0xFFFE)  # byte order
    struct.pack_into("<H", header, 0x1E, 9)  # sector shift → 512
    struct.pack_into("<H", header, 0x20, 6)  # mini sector shift → 64
    struct.pack_into("<I", header, 0x28, 0)  # # dir sectors (v3 = 0)
    struct.pack_into("<I", header, 0x2C, 1)  # # FAT sectors
    struct.pack_into("<I", header, 0x30, 1)  # first directory sector
    struct.pack_into("<I", header, 0x38, MINI_CUTOFF)  # mini cutoff
    struct.pack_into("<I", header, 0x3C, ENDOFCHAIN)  # first MiniFAT sector
    struct.pack_into("<I", header, 0x40, 0)  # # MiniFAT sectors
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)  # first DiFAT sector
    struct.pack_into("<I", header, 0x48, 0)  # # DiFAT sectors
    # Inline DiFAT: just the one FAT sector at index 0.
    struct.pack_into("<I", header, 0x4C, 0)
    for i in range(1, 109):
        struct.pack_into("<I", header, 0x4C + i * 4, FREESECT)

    # ---- Assemble --------------------------------------------------------
    blob = bytearray()
    blob.extend(header)
    blob.extend(fat_sector)
    blob.extend(dir_sector)
    for s in sector_data:
        blob.extend(s)
    return bytes(blob)


class _DirNode:
    __slots__ = ("body", "child", "left", "name", "obj_type", "path", "right")

    def __init__(self, name: str, obj_type: int):
        self.name = name
        self.obj_type = obj_type
        self.path = ""  # full storage path; "" for root
        self.body = b""  # raw bytes for streams
        self.child = NOSTREAM
        self.left = NOSTREAM
        self.right = NOSTREAM


def _build_tree(streams: dict[str, bytes]) -> list[_DirNode]:
    """Build the directory node list for the given streams.

    Layout: index 0 = Root Entry. Children link via a right-only sibling
    chain.
    """
    root = _DirNode("Root Entry", OBJ_ROOT)
    nodes: list[_DirNode] = [root]
    # path → node index, for storages we've already created.
    storage_idx: dict[str, int] = {"": 0}

    for path, body in streams.items():
        parts = path.split("/")
        # Ensure all parent storages exist.
        for depth in range(1, len(parts)):
            sub = "/".join(parts[:depth])
            if sub in storage_idx:
                continue
            node = _DirNode(parts[depth - 1], OBJ_STORAGE)
            node.path = sub
            nodes.append(node)
            new_idx = len(nodes) - 1
            storage_idx[sub] = new_idx
            _attach_child("/".join(parts[: depth - 1]), new_idx, nodes, storage_idx)

        # Append the stream node itself.
        sn = _DirNode(parts[-1], OBJ_STREAM)
        sn.path = path
        sn.body = body
        nodes.append(sn)
        leaf_idx = len(nodes) - 1
        _attach_child("/".join(parts[:-1]), leaf_idx, nodes, storage_idx)

    return nodes


def _attach_child(
    parent_path: str,
    child_idx: int,
    nodes: list[_DirNode],
    storage_idx: dict[str, int],
) -> None:
    parent_idx = storage_idx[parent_path]
    parent = nodes[parent_idx]
    if parent.child == NOSTREAM:
        parent.child = child_idx
        return
    # Append to the rightmost descendant of the existing child chain.
    cur = parent.child
    while nodes[cur].right != NOSTREAM:
        cur = nodes[cur].right
    nodes[cur].right = child_idx


def _encode_dir_entry(
    name: str,
    obj_type: int,
    left: int,
    right: int,
    child: int,
    starting_sector: int,
    size: int,
) -> bytes:
    name_utf16 = (name + "\x00").encode("utf-16-le")
    if len(name_utf16) > 64:
        name_utf16 = name_utf16[:62] + b"\x00\x00"
    name_padded = name_utf16.ljust(64, b"\x00")
    out = bytearray()
    out += name_padded  # 0x00..0x40
    out += struct.pack("<H", len(name_utf16))  # 0x40 name length
    out += bytes([obj_type, 1])  # 0x42 type, 0x43 color (black)
    out += struct.pack("<III", left, right, child)  # 0x44..0x50
    out += b"\x00" * 16  # CLSID
    out += struct.pack("<I", 0)  # state bits
    out += b"\x00" * 16  # creation + modified time
    out += struct.pack("<I", starting_sector)  # 0x74
    out += struct.pack("<Q", size)  # 0x78 size (8 bytes)
    assert len(out) == 128
    return bytes(out)


# ---------------------------------------------------------------------------
# OOXML builder.
#
# Real OOXMLs are a ZIP containing [Content_Types].xml + per-part XMLs.
# Our minimum is enough to satisfy our walker:
#   - [Content_Types].xml declaring the subtype (and macroEnabled when asked)
#   - word/_rels/document.xml.rels (optional, for external-relationship tests)
#   - xl/sharedStrings.xml (optional, for DDE tests)
#   - word/vbaProject.bin (optional, for VBA tests)
# ---------------------------------------------------------------------------


def build_minimal_docm(
    *,
    with_vba: bytes | None = None,
    external_rel_urls: list[str] | None = None,
    msdt_uri: bool = False,
    macro_enabled: bool = True,
) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _make_content_types(macro_enabled))
        zf.writestr(
            "word/document.xml",
            b'<?xml version="1.0"?><doc>'
            + (b"<msdt>ms-msdt:id /id PCWDiagnostic /skip force</msdt>" if msdt_uri else b"")
            + b"</doc>",
        )
        if external_rel_urls:
            zf.writestr(
                "word/_rels/document.xml.rels",
                _make_external_rels(external_rel_urls),
            )
        if with_vba is not None:
            zf.writestr("word/vbaProject.bin", with_vba)
    return buf.getvalue()


def build_minimal_xlsm_with_dde() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _make_content_types(macro_enabled=True))
        zf.writestr(
            "xl/sharedStrings.xml",
            b'<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            b"<si><t>=cmd|'/c calc.exe'!A1</t></si>"
            b"</sst>",
        )
    return buf.getvalue()


def _make_content_types(macro_enabled: bool) -> bytes:
    base = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        b'<Default Extension="xml" ContentType="application/xml"/>'
    )
    if macro_enabled:
        base += (
            b'<Override PartName="/word/document.xml" '
            b'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
            b'<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        )
    else:
        base += (
            b'<Override PartName="/word/document.xml" '
            b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        )
    base += b"</Types>"
    return base


def _make_external_rels(urls: list[str]) -> bytes:
    parts = [
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    ]
    for i, url in enumerate(urls, start=1):
        parts.append(
            f'<Relationship Id="rId{i}" '
            f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            f'Target="{url}" TargetMode="External"/>'.encode()
        )
    parts.append(b"</Relationships>")
    return b"".join(parts)
