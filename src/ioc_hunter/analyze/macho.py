"""Mach-O (macOS / iOS / watchOS) analyzer.

Covers single-arch ``MH_MAGIC{,_64}`` and universal/fat
``FAT_MAGIC{,_64}`` containers. For a fat binary we analyse the first
slice fully and record every additional slice as metadata — that's the
right call for triage: most threats only weaponise one arch per slice
and the analyst rarely needs to see both walked twice in the terminal.

What we surface:

- header summary: arch, bitness, file type, MH_* flags decoded
  (notably ``MH_PIE``, ``MH_NO_HEAP_EXECUTION``, ``MH_ALLOW_STACK_EXECUTION``);
- LOAD commands walked: every ``LC_SEGMENT_64`` becomes a Section row
  with per-section entropy; every ``LC_LOAD_DYLIB`` / ``LC_LOAD_WEAK_DYLIB``
  becomes a linked-library entry;
- ``LC_RPATH`` entries — loader-hijack hint;
- ``LC_CODE_SIGNATURE`` presence → ``is_signed``;
- ``LC_ENCRYPTION_INFO{_64}`` with ``cryptid != 0`` → encrypted region
  finding (App Store FairPlay is the common benign case; on a sample
  from a phishing site it's a strong tell);
- ``LC_UUID`` — useful pivot back into VirusTotal / Apple notarisation;
- entry point from ``LC_MAIN`` or ``LC_UNIXTHREAD``;
- packer signatures (UPX exists for Mach-O too) + suspicious symbol
  matches on the dynamic symbol table.

Defensive: every offset goes through ``Reader``, command iteration is
bounded by ``ncmds`` ∧ ``MAX_SECTIONS``, and each LC's ``cmdsize`` is
required to be > 0 to avoid an infinite advance loop.
"""

from __future__ import annotations

import struct

from ioc_hunter.analyze.common import (
    MAX_IMPORT_LIBS,
    MAX_SECTIONS,
    POSIX_SUSPICIOUS_SYMBOLS,
    AnalyzerReport,
    FileFormat,
    Finding,
    Import,
    Reader,
    Section,
    Severity,
    packer_match,
    shannon_entropy,
)

# Magic numbers
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

# CPU types (subset; full list in <mach/machine.h>)
_CPU_NAMES = {
    7: "x86",
    7 | 0x01000000: "x86_64",
    12: "ARM",
    12 | 0x01000000: "ARM64",
    18: "PowerPC",
    18 | 0x01000000: "PowerPC64",
}

# File types
_FILETYPE_NAMES = {
    1: "OBJECT",
    2: "EXECUTE",
    3: "FVMLIB",
    4: "CORE",
    5: "PRELOAD",
    6: "DYLIB",
    7: "DYLINKER",
    8: "BUNDLE",
    9: "DYLIB_STUB",
    10: "DSYM",
    11: "KEXT_BUNDLE",
}

# MH_* flags
_MH_PIE = 0x200000
_MH_ALLOW_STACK_EXECUTION = 0x20000
_MH_NO_HEAP_EXECUTION = 0x1000000

_FLAG_NAMES = {
    0x1: "NOUNDEFS",
    0x4: "DYLDLINK",
    0x80: "TWOLEVEL",
    0x10000: "BINDS_TO_WEAK",
    _MH_ALLOW_STACK_EXECUTION: "ALLOW_STACK_EXECUTION",
    0x40000: "ROOT_SAFE",
    0x80000: "SETUID_SAFE",
    _MH_PIE: "PIE",
    0x800000: "HAS_TLV_DESCRIPTORS",
    _MH_NO_HEAP_EXECUTION: "NO_HEAP_EXECUTION",
}

# LC_REQ_DYLD bit
_LC_REQ_DYLD = 0x80000000

# Load commands
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_UNIXTHREAD = 0x5
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_LOAD_WEAK_DYLIB = 0x18 | _LC_REQ_DYLD
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_RPATH = 0x1C | _LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO_ONLY = 0x22 | _LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x24
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x28 | _LC_REQ_DYLD
LC_DATA_IN_CODE = 0x29
LC_SOURCE_VERSION = 0x2A
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTION = 0x2D
LC_BUILD_VERSION = 0x32


def _section_flags_text(prot: int) -> str:
    out = []
    if prot & 0x1:
        out.append("R")
    if prot & 0x2:
        out.append("W")
    if prot & 0x4:
        out.append("X")
    return "".join(out) or "-"


def _decode_flags(flags: int) -> list[str]:
    return [name for bit, name in _FLAG_NAMES.items() if flags & bit]


def analyze_macho(
    raw: bytes,
    *,
    report: AnalyzerReport,
    slice_offset: int = 0,
) -> AnalyzerReport:
    """Analyse a single Mach-O slice starting at ``slice_offset``.

    The dispatcher handles fat-binary detection upstream and calls us
    once per slice; we therefore see one ``MH_MAGIC{,_64}`` header at
    ``slice_offset``.
    """
    r = Reader(raw)
    base = slice_offset

    magic = r.u32(base, little=True)
    # Magic also identifies endianness.
    if magic in (MH_MAGIC, MH_MAGIC_64):
        little = True
        is_64 = magic == MH_MAGIC_64
    elif magic in (MH_CIGAM, MH_CIGAM_64):
        little = False
        is_64 = magic == MH_CIGAM_64
    else:
        report.add(
            Finding(
                rule="macho.bad_magic",
                severity=Severity.HIGH,
                category="anomaly",
                message=f"Not a Mach-O slice at offset {base} (magic=0x{magic:x}).",
            )
        )
        return report

    report.bitness = 64 if is_64 else 32
    report.format = FileFormat.MACHO

    hdr_size = 32 if is_64 else 28
    hdr = r.slice(base, hdr_size)
    if hdr is None:
        report.add(
            Finding(
                rule="macho.truncated_header",
                severity=Severity.HIGH,
                category="anomaly",
                message="Mach-O header truncated.",
            )
        )
        return report

    endian = "<" if little else ">"
    if is_64:
        _, cputype, _cpusubtype, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack(
            endian + "IIIIIIII", hdr
        )
    else:
        _, cputype, _cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            endian + "IIIIIII", hdr
        )

    report.architecture = _CPU_NAMES.get(cputype, f"cpu=0x{cputype:x}")
    report.metadata["filetype"] = _FILETYPE_NAMES.get(filetype, str(filetype))
    report.metadata["mh_flags"] = _decode_flags(flags)
    report.metadata["pie"] = bool(flags & _MH_PIE)
    report.metadata["allow_stack_execution"] = bool(flags & _MH_ALLOW_STACK_EXECUTION)
    report.metadata["no_heap_execution"] = bool(flags & _MH_NO_HEAP_EXECUTION)

    if flags & _MH_ALLOW_STACK_EXECUTION:
        report.add(
            Finding(
                rule="macho.allow_stack_execution",
                severity=Severity.MEDIUM,
                category="anomaly",
                message="MH_ALLOW_STACK_EXECUTION flag set — executable stack permitted.",
            )
        )
    if not (flags & _MH_PIE) and filetype == 2:
        report.add(
            Finding(
                rule="macho.no_pie",
                severity=Severity.LOW,
                category="anomaly",
                message="Executable without MH_PIE — ASLR coverage reduced.",
            )
        )

    # ---- Walk load commands -----------------------------------------------
    libs: list[str] = []
    rpaths: list[str] = []
    code_signature_present = False
    encryption_present = False
    uuid_str: str | None = None
    entry_point = 0
    symtab: tuple[int, int, int, int] | None = None  # (symoff, nsyms, stroff, strsize)

    cmd_off = base + hdr_size
    end = cmd_off + sizeofcmds
    walked = 0
    cs_offset_size: tuple[int, int] | None = None

    while walked < ncmds and cmd_off + 8 <= min(end, r.size):
        cmd_hdr = r.slice(cmd_off, 8)
        if cmd_hdr is None:
            break
        cmd, cmdsize = struct.unpack(endian + "II", cmd_hdr)
        if cmdsize == 0 or cmd_off + cmdsize > r.size:
            report.add(
                Finding(
                    rule="macho.bad_lc_size",
                    severity=Severity.MEDIUM,
                    category="anomaly",
                    message=f"Load command at {cmd_off} has cmdsize={cmdsize} (bad).",
                )
            )
            break

        if cmd == LC_SEGMENT_64:
            _parse_segment(r, cmd_off, endian, is_64=True, report=report, slice_off=base)
        elif cmd == LC_SEGMENT:
            _parse_segment(r, cmd_off, endian, is_64=False, report=report, slice_off=base)
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB):
            name = _read_lc_str(r, cmd_off, cmdsize, endian, str_field_off=8)
            if name and len(libs) < MAX_IMPORT_LIBS:
                libs.append(name)
        elif cmd == LC_RPATH:
            name = _read_lc_str(r, cmd_off, cmdsize, endian, str_field_off=8)
            if name:
                rpaths.append(name)
        elif cmd == LC_CODE_SIGNATURE:
            code_signature_present = True
            # cmd, cmdsize, dataoff, datasize. dataoff is relative to the
            # slice start in a fat container — add ``base`` to get the
            # absolute file offset our Reader works in.
            data_hdr = r.slice(cmd_off + 8, 8)
            if data_hdr is not None:
                d_off, d_sz = struct.unpack(endian + "II", data_hdr)
                report.metadata["code_signature_offset"] = base + d_off
                report.metadata["code_signature_size"] = d_sz
                cs_offset_size = (base + d_off, d_sz)
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # cryptoff(4), cryptsize(4), cryptid(4), [pad(4)]
            info = r.slice(cmd_off + 8, 12)
            if info is not None:
                c_off, c_sz, c_id = struct.unpack(endian + "III", info)
                if c_id != 0:
                    encryption_present = True
                    report.metadata["encryption_offset"] = c_off
                    report.metadata["encryption_size"] = c_sz
                    report.metadata["encryption_id"] = c_id
        elif cmd == LC_UUID:
            uuid_bytes = r.slice(cmd_off + 8, 16)
            if uuid_bytes is not None and len(uuid_bytes) == 16:
                uuid_str = (
                    f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-"
                    f"{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-"
                    f"{uuid_bytes[10:16].hex()}"
                ).upper()
        elif cmd == LC_MAIN:
            main = r.slice(cmd_off + 8, 16)
            if main is not None:
                entryoff, _stack = struct.unpack(endian + "QQ", main)
                entry_point = entryoff
        elif cmd == LC_SYMTAB:
            sym = r.slice(cmd_off + 8, 16)
            if sym is not None:
                symoff, nsyms, stroff, strsize = struct.unpack(endian + "IIII", sym)
                # Same rebasing concern as LC_CODE_SIGNATURE.
                symtab = (base + symoff, nsyms, base + stroff, strsize)
        elif cmd == LC_LOAD_DYLINKER:
            name = _read_lc_str(r, cmd_off, cmdsize, endian, str_field_off=8)
            if name:
                report.metadata["dylinker"] = name

        cmd_off += cmdsize
        walked += 1
        if walked > MAX_SECTIONS * 4:  # belt and suspenders
            break

    report.linked_libraries = libs
    report.imports = [Import(library=lib, symbols=()) for lib in libs]
    report.entry_point = entry_point
    report.is_signed = code_signature_present
    report.metadata["rpaths"] = rpaths
    if uuid_str:
        report.metadata["uuid"] = uuid_str

    # ---- Code signature: identifier, teamID, entitlements -----------------
    if cs_offset_size is not None:
        cs_info = _parse_code_signature(r, cs_offset_size[0], cs_offset_size[1])
        if cs_info.identifier:
            report.signer_cn = cs_info.identifier  # bundle id is the SOC-meaningful name
            report.metadata["cs_identifier"] = cs_info.identifier
        if cs_info.team_id:
            report.metadata["cs_team_id"] = cs_info.team_id
        if cs_info.flags:
            report.metadata["cs_flags"] = cs_info.flags
        if cs_info.entitlements:
            report.entitlements = cs_info.entitlements
            risky = _classify_entitlements(cs_info.entitlements)
            for rule, label, sev in risky:
                report.add(
                    Finding(
                        rule=rule,
                        severity=sev,
                        category="anomaly",
                        message=f"Risky entitlement: {label}",
                        evidence=(label,),
                    )
                )

    if rpaths:
        report.add(
            Finding(
                rule="macho.rpath",
                severity=Severity.LOW,
                category="anomaly",
                message=f"LC_RPATH set: {rpaths!r} — dylib-loader path override (hijack hint).",
                evidence=tuple(rpaths),
            )
        )

    if encryption_present:
        report.add(
            Finding(
                rule="macho.encrypted",
                severity=Severity.MEDIUM,
                category="packer",
                message="Encrypted Mach-O region (LC_ENCRYPTION_INFO.cryptid != 0). "
                "FairPlay for App Store binaries — outside that context, a strong tell.",
            )
        )

    # ---- Dynamic symbols (best-effort via LC_SYMTAB) ----------------------
    dyn_symbols: list[str] = []
    if symtab is not None:
        symoff, nsyms, stroff, strsize = symtab
        # nlist64 is 16 bytes, nlist is 12. We only need n_strx (first 4 bytes).
        ent_size = 16 if is_64 else 12
        n = min(nsyms, 65536)
        strblob = r.slice(stroff, min(strsize, 8 * 1024 * 1024)) or b""
        for i in range(n):
            sx = r.u32(symoff + i * ent_size, little)
            if sx is None:
                break
            if sx == 0 or sx >= len(strblob):
                continue
            nul = strblob.find(b"\x00", sx)
            if nul == -1:
                continue
            nm = strblob[sx:nul].decode("ascii", errors="replace")
            if nm:
                # Strip leading underscore that Mach-O symbols carry.
                if nm.startswith("_"):
                    nm = nm[1:]
                if nm and nm not in dyn_symbols:
                    dyn_symbols.append(nm)
        report.metadata["dyn_symbols"] = dyn_symbols

        matched = sorted(set(dyn_symbols) & POSIX_SUSPICIOUS_SYMBOLS)
        report.metadata["suspicious_posix_symbols"] = matched
        if "task_for_pid" in matched or "mach_vm_write" in matched:
            report.add(
                Finding(
                    rule="macho.mach_injection",
                    severity=Severity.HIGH,
                    category="injection",
                    message="Mach-VM injection primitives present (task_for_pid / mach_vm_write).",
                    evidence=tuple(s for s in matched if s in {"task_for_pid", "mach_vm_write"}),
                )
            )
        if "ptrace" in matched:
            report.add(
                Finding(
                    rule="macho.ptrace",
                    severity=Severity.MEDIUM,
                    category="anti_debug",
                    message="Imports ptrace() — anti-debug pattern (PT_DENY_ATTACH).",
                    evidence=("ptrace",),
                )
            )

    # ---- Overall entropy + packer -----------------------------------------
    sample = r.data[: 1024 * 1024]
    report.overall_entropy = shannon_entropy(sample)
    label = packer_match((s.name for s in report.sections), r.data)
    if label:
        report.is_packed = True
        report.detected_packer = label
        report.add(
            Finding(
                rule="macho.packer_signature",
                severity=Severity.MEDIUM,
                category="packer",
                message=f"Packer signature matched: {label}.",
                evidence=(label,),
            )
        )

    return report


def _parse_segment(
    r: Reader,
    cmd_off: int,
    endian: str,
    *,
    is_64: bool,
    report: AnalyzerReport,
    slice_off: int = 0,
) -> None:
    """Parse an ``LC_SEGMENT_64`` / ``LC_SEGMENT`` and append its sections.

    Layout (LC_SEGMENT_64, 72 bytes header + 80 bytes/section):
        cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8)
        fileoff(8) filesize(8) maxprot(4) initprot(4)
        nsects(4) flags(4)
    Then nsects of:
        sectname(16) segname(16) addr(8) size(8)
        offset(4) align(4) reloff(4) nreloc(4)
        flags(4) reserved1(4) reserved2(4) reserved3(4)

    File offsets inside a load command (``fileoff`` for the segment,
    ``offset`` for each section) are relative to the **slice** start in
    a fat container — the universal-binary loader maps each slice as
    its own address space. We accept the slice's universal-file offset
    via ``slice_off`` and rebase before reading bytes.
    """
    if is_64:
        seg_hdr = r.slice(cmd_off, 72)
        if seg_hdr is None:
            return
        segname = seg_hdr[8:24].rstrip(b"\x00").decode("ascii", errors="replace")
        _vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _flags = struct.unpack(
            endian + "QQQQIIII", seg_hdr[24:]
        )
        sect_off = cmd_off + 72
        sect_size = 80
    else:
        seg_hdr = r.slice(cmd_off, 56)
        if seg_hdr is None:
            return
        segname = seg_hdr[8:24].rstrip(b"\x00").decode("ascii", errors="replace")
        _vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _flags = struct.unpack(
            endian + "IIIIIIII", seg_hdr[24:]
        )
        sect_off = cmd_off + 56
        sect_size = 68

    # Add the segment itself as one Section row.
    abs_fileoff = slice_off + fileoff
    seg_blob = r.slice(abs_fileoff, min(filesize, 8 * 1024 * 1024)) if filesize else None
    seg_entropy = shannon_entropy(seg_blob) if seg_blob else 0.0
    report.sections.append(
        Section(
            name=segname,
            virtual_size=vmsize,
            raw_size=filesize,
            file_offset=abs_fileoff,
            entropy=seg_entropy,
            flags=_section_flags_text(initprot),
        )
    )
    if (initprot & 0x2) and (initprot & 0x4):
        report.add(
            Finding(
                rule="macho.wx_segment",
                severity=Severity.HIGH,
                category="anomaly",
                message=f"Segment {segname!r} mapped writable + executable.",
                evidence=(segname,),
            )
        )

    # Walk individual sections too — separated for cleaner Section table.
    nsects = min(nsects, MAX_SECTIONS)
    for i in range(nsects):
        s_hdr = r.slice(sect_off + i * sect_size, sect_size)
        if s_hdr is None:
            break
        sectname = s_hdr[:16].rstrip(b"\x00").decode("ascii", errors="replace")
        if is_64:
            _addr, size, offset = struct.unpack(endian + "QQI", s_hdr[32:52])
        else:
            _addr, size, offset = struct.unpack(endian + "III", s_hdr[32:44])

        abs_offset = slice_off + offset
        blob = r.slice(abs_offset, min(size, 4 * 1024 * 1024)) if size else None
        ent = shannon_entropy(blob) if blob else 0.0
        report.sections.append(
            Section(
                name=f"{segname}/{sectname}",
                virtual_size=size,
                raw_size=size,
                file_offset=abs_offset,
                entropy=ent,
                flags=_section_flags_text(initprot),
            )
        )


def _read_lc_str(
    r: Reader,
    cmd_off: int,
    cmdsize: int,
    endian: str,
    *,
    str_field_off: int,
) -> str | None:
    """Read an ``lc_str`` value from a load command.

    ``lc_str`` is a 4-byte offset relative to the load command start;
    the string lives later within the same command and is NUL-padded.
    """
    str_off = r.u32(cmd_off + str_field_off, little=endian == "<")
    if str_off is None or str_off >= cmdsize:
        return None
    blob = r.slice(cmd_off + str_off, cmdsize - str_off)
    if blob is None:
        return None
    nul = blob.find(b"\x00")
    if nul == -1:
        nul = len(blob)
    try:
        return blob[:nul].decode("utf-8", errors="replace")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Fat / universal binary helper used by dispatcher.
# ---------------------------------------------------------------------------


def parse_fat_header(raw: bytes) -> list[tuple[int, int, int, int]] | None:
    """If ``raw`` starts with a FAT magic, return a list of slices.

    Each tuple is ``(cputype, cpusubtype, file_offset, slice_size)``.
    ``None`` means the file is not a fat container.

    Fat headers are always big-endian on disk (the architecture name is
    "universal", not "fat"); a tool calling us with the bytes already
    correctly oriented does not need to care.
    """
    r = Reader(raw)
    magic = r.u32(0, little=True)
    if magic in (FAT_MAGIC, FAT_CIGAM):
        is_64 = False
    elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
        is_64 = True
    else:
        return None

    # nfat_arch is at offset 4 in big-endian for both.
    nfat = r.u32(4, little=False)
    if nfat is None or nfat == 0 or nfat > 32:
        return None

    out: list[tuple[int, int, int, int]] = []
    if is_64:
        ent_size = 32
        offset_in_struct = 16
        size_in_struct = 24
    else:
        ent_size = 20
        offset_in_struct = 8
        size_in_struct = 12

    base = 8
    for i in range(nfat):
        ent = r.slice(base + i * ent_size, ent_size)
        if ent is None:
            break
        cputype = struct.unpack(">I", ent[0:4])[0]
        cpusub = struct.unpack(">I", ent[4:8])[0]
        if is_64:
            offset = struct.unpack(">Q", ent[offset_in_struct : offset_in_struct + 8])[0]
            size = struct.unpack(">Q", ent[size_in_struct : size_in_struct + 8])[0]
        else:
            offset = struct.unpack(">I", ent[offset_in_struct : offset_in_struct + 4])[0]
            size = struct.unpack(">I", ent[size_in_struct : size_in_struct + 4])[0]
        if offset + size > len(raw):
            continue
        out.append((cputype, cpusub, offset, size))
    return out


# ---------------------------------------------------------------------------
# Code signature: SuperBlob → CodeDirectory + Entitlements
#
# The data referenced by LC_CODE_SIGNATURE is itself a SuperBlob; every
# integer in this region is **big-endian** on disk, regardless of the host
# Mach-O's endianness.
#
#   SuperBlob: u32 magic (0xfade0cc0) | u32 length | u32 count
#              count * { u32 type | u32 offset }   <- BlobIndex
#
# We follow the offsets to find:
#   - type 0  → CodeDirectory (magic 0xfade0c02): identifier, teamID, flags
#   - type 5  → Embedded entitlements (magic 0xfade7171): XML plist payload
# ---------------------------------------------------------------------------


_CS_MAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CS_MAGIC_CODEDIRECTORY = 0xFADE0C02
_CS_MAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
_CS_MAGIC_ENTITLEMENTS_DER = 0xFADE7172
_CS_SLOT_CODEDIRECTORY = 0
_CS_SLOT_ENTITLEMENTS = 5

_CS_FLAG_NAMES = {
    0x1: "VALID",
    0x2: "ADHOC",
    0x4: "GET_TASK_ALLOW",
    0x10: "INSTALLER",
    0x40: "HARD",
    0x100: "KILL",
    0x800: "RESTRICT",
    0x1000: "ENFORCEMENT",
    0x2000: "LIBRARY_VALIDATION",
    0x10000: "RUNTIME",
    0x20000: "LINKER_SIGNED",
}


class _CSInfo:
    """Plain holder for the bits of a code signature we care about."""

    __slots__ = ("entitlements", "flags", "identifier", "team_id")

    def __init__(self) -> None:
        self.identifier = ""
        self.team_id = ""
        self.flags: list[str] = []
        self.entitlements: list[str] = []


def _parse_code_signature(r: Reader, cs_off: int, cs_size: int) -> _CSInfo:
    info = _CSInfo()
    if cs_size < 12:
        return info

    # SuperBlob header is big-endian.
    sb = r.slice(cs_off, 12)
    if sb is None:
        return info
    magic, total_len, count = struct.unpack(">III", sb)
    if magic != _CS_MAGIC_EMBEDDED_SIGNATURE:
        return info
    if count == 0 or count > 64:
        return info

    for i in range(count):
        ent = r.slice(cs_off + 12 + i * 8, 8)
        if ent is None:
            break
        slot_type, slot_off = struct.unpack(">II", ent)
        blob_abs = cs_off + slot_off
        head = r.slice(blob_abs, 8)
        if head is None:
            continue
        blob_magic, blob_len = struct.unpack(">II", head)
        # Sanity: the blob must fit inside the SuperBlob.
        if blob_len < 8 or slot_off + blob_len > total_len:
            continue

        if slot_type == _CS_SLOT_CODEDIRECTORY and blob_magic == _CS_MAGIC_CODEDIRECTORY:
            _parse_codedirectory(r, blob_abs, blob_len, info)
        elif slot_type == _CS_SLOT_ENTITLEMENTS and blob_magic == _CS_MAGIC_EMBEDDED_ENTITLEMENTS:
            payload = r.slice(blob_abs + 8, blob_len - 8)
            if payload:
                info.entitlements = _parse_entitlements_plist(payload)

    return info


def _parse_codedirectory(r: Reader, abs_off: int, blob_len: int, info: _CSInfo) -> None:
    """Pull identifier / teamID / flags from a CodeDirectory blob.

    Field layout (offsets from the magic byte, big-endian):

        +0x00  u32 magic
        +0x04  u32 length
        +0x08  u32 version
        +0x0C  u32 flags
        +0x10  u32 hashOffset
        +0x14  u32 identOffset
        ...
        +0x30  u32 teamOffset      (only when version >= 0x20200)

    ``ident_off`` / ``team_off`` are relative to the blob magic (``abs_off``).
    """
    # Read the whole header in one go from the blob start (relative to magic).
    body = r.slice(abs_off, min(blob_len, 60))
    if body is None or len(body) < 0x18:
        return
    version = struct.unpack(">I", body[0x08:0x0C])[0]
    flags = struct.unpack(">I", body[0x0C:0x10])[0]
    ident_off = struct.unpack(">I", body[0x14:0x18])[0]
    ident_abs = abs_off + ident_off
    ident_str = r.cstr(ident_abs, max_len=256)
    if ident_str:
        info.identifier = ident_str
    if version >= 0x20200 and len(body) >= 0x34:
        team_off = struct.unpack(">I", body[0x30:0x34])[0]
        if team_off:
            team_str = r.cstr(abs_off + team_off, max_len=64)
            if team_str:
                info.team_id = team_str
    info.flags = [name for bit, name in _CS_FLAG_NAMES.items() if flags & bit]


def _parse_entitlements_plist(payload: bytes) -> list[str]:
    """Pull entitlement keys out of an XML plist with regex.

    Apple's plist DTD is tiny and our needs are tiny — we want the list
    of ``<key>...</key>`` entries whose value is ``<true/>``. That tells
    us which capabilities the binary has been granted by the developer.
    """
    out: list[str] = []
    text = payload.decode("utf-8", errors="replace")
    # Match <key>NAME</key> followed by an optional whitespace and <true/>.
    # We intentionally skip <false/>-keyed entries — they're explicit
    # denials and aren't a tell.
    import re as _re

    pattern = _re.compile(
        r"<key>\s*([^<]+?)\s*</key>\s*<true\s*/>",
        _re.IGNORECASE | _re.DOTALL,
    )
    for m in pattern.finditer(text):
        key = m.group(1).strip()
        if key and key not in out and len(key) < 200:
            out.append(key)
        if len(out) >= 128:
            break
    return out


_RISKY_ENTITLEMENTS: tuple[tuple[str, str, Severity], ...] = (
    (
        "macho.ent_disable_library_validation",
        "com.apple.security.cs.disable-library-validation",
        Severity.HIGH,
    ),
    (
        "macho.ent_allow_unsigned_exec",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        Severity.HIGH,
    ),
    (
        "macho.ent_dyld_env",
        "com.apple.security.cs.allow-dyld-environment-variables",
        Severity.HIGH,
    ),
    (
        "macho.ent_disable_page_protection",
        "com.apple.security.cs.disable-executable-page-protection",
        Severity.HIGH,
    ),
    (
        "macho.ent_get_task_allow",
        "com.apple.security.get-task-allow",
        Severity.MEDIUM,
    ),
    ("macho.ent_allow_jit", "com.apple.security.cs.allow-jit", Severity.LOW),
)


def _classify_entitlements(entries: list[str]) -> list[tuple[str, str, Severity]]:
    out: list[tuple[str, str, Severity]] = []
    have = set(entries)
    for rule, key, sev in _RISKY_ENTITLEMENTS:
        if key in have:
            out.append((rule, key, sev))
    return out
