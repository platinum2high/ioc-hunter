"""Windows PE / PE32+ analyzer.

We walk the file the same way the loader does:

    DOS header → PE signature → COFF header → Optional header
        → Section table → Data directories (imports, exports,
          resources, TLS, security/Authenticode)

…then we apply project-wide concerns: per-section Shannon entropy,
overlay detection (data after the last section's raw range), Rich
header parsing (Microsoft compiler fingerprint), packer signature
match, suspicious-import combo heuristics.

No third-party deps. Everything is ``struct``-based bounded reads.
A malformed file degrades gracefully — the report carries whatever we
managed to parse plus an ``error`` finding.

References worth knowing while reading this file:

- Microsoft PE/COFF spec
  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- ``IMAGE_OPTIONAL_HEADER`` layout differs between PE32 and PE32+ in
  three places: ``BaseOfData`` only exists in PE32, ``ImageBase``
  widens to 8 bytes in PE32+, the four ``SizeOfStack*/SizeOfHeap*``
  fields widen to 8 bytes. We branch on the ``Magic`` field.
"""

from __future__ import annotations

import struct

from ioc_hunter.analyze.authenticode import extract_signer_names
from ioc_hunter.analyze.common import (
    MAX_IMPORT_LIBS,
    MAX_IMPORT_SYMBOLS_PER_LIB,
    MAX_SECTIONS,
    AnalyzerReport,
    Export,
    Finding,
    Import,
    Reader,
    Section,
    Severity,
    packer_match,
    shannon_entropy,
)
from ioc_hunter.analyze.imphash import compute_imphash
from ioc_hunter.analyze.resources import parse_resource_tree

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DOS_SIG = 0x5A4D  # 'MZ'
_PE_SIG = 0x00004550  # 'PE\0\0'

_OPT_MAGIC_PE32 = 0x10B
_OPT_MAGIC_PE32_PLUS = 0x20B

_MACHINE_NAMES: dict[int, str] = {
    0x014C: "i386",
    0x0162: "MIPS R3000",
    0x0166: "MIPS R4000",
    0x0184: "Alpha",
    0x01A2: "SH3",
    0x01A6: "SH4",
    0x01C0: "ARM",
    0x01C2: "ARM Thumb",
    0x01C4: "ARMv7 Thumb-2",
    0x01F0: "PowerPC",
    0x0200: "Intel Itanium",
    0x0EBC: "EFI byte code",
    0x8664: "x86_64",
    0xAA64: "ARM64",
}


_SUBSYSTEM_NAMES: dict[int, str] = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2",
    7: "POSIX",
    9: "Windows CE GUI",
    10: "EFI App",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot App",
}


# IMAGE_FILE_* characteristics flags.
_CHAR_EXECUTABLE_IMAGE = 0x0002
_CHAR_DLL = 0x2000


# IMAGE_DLLCHARACTERISTICS_*.
_DLL_HIGH_ENTROPY_VA = 0x0020
_DLL_DYNAMIC_BASE = 0x0040  # ASLR
_DLL_FORCE_INTEGRITY = 0x0080
_DLL_NX_COMPAT = 0x0100  # DEP
_DLL_NO_ISOLATION = 0x0200
_DLL_NO_SEH = 0x0400
_DLL_NO_BIND = 0x0800
_DLL_APPCONTAINER = 0x1000
_DLL_WDM_DRIVER = 0x2000
_DLL_GUARD_CF = 0x4000  # CFG
_DLL_TERMINAL_SERVER_AWARE = 0x8000


# Data-directory indices we actually inspect.
_DD_EXPORT = 0
_DD_IMPORT = 1
_DD_RESOURCE = 2
_DD_EXCEPTION = 3
_DD_SECURITY = 4  # Authenticode
_DD_BASERELOC = 5
_DD_DEBUG = 6
_DD_TLS = 9
_DD_LOAD_CONFIG = 10
_DD_DELAY_IMPORT = 13
_DD_COM_DESCRIPTOR = 14  # CLR / .NET


# IMAGE_SECTION_HEADER characteristics.
_SCN_CNT_CODE = 0x00000020
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000


def _section_flags_text(chars: int) -> str:
    out = []
    if chars & _SCN_MEM_READ:
        out.append("R")
    if chars & _SCN_MEM_WRITE:
        out.append("W")
    if chars & _SCN_MEM_EXECUTE:
        out.append("X")
    return "".join(out) or "-"


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def analyze_pe(
    raw: bytes,
    *,
    report: AnalyzerReport,
) -> AnalyzerReport:
    """Walk a PE/PE32+ image and fill ``report`` in-place.

    The report is returned for fluent use. We mutate it rather than
    replace it because the dispatcher pre-populates path/format/hashes
    before calling us.
    """
    r = Reader(raw)

    # ---- DOS header --------------------------------------------------------
    if r.u16(0) != _DOS_SIG:
        report.add(
            Finding(
                rule="pe.bad_dos",
                severity=Severity.HIGH,
                category="anomaly",
                message="Missing MZ DOS signature — not a valid PE.",
            )
        )
        return report

    e_lfanew = r.u32(0x3C)
    if e_lfanew is None or e_lfanew >= r.size - 4:
        report.add(
            Finding(
                rule="pe.bad_e_lfanew",
                severity=Severity.HIGH,
                category="anomaly",
                message="e_lfanew points outside the file.",
            )
        )
        return report

    pe_sig = r.u32(e_lfanew)
    if pe_sig != _PE_SIG:
        report.add(
            Finding(
                rule="pe.bad_pe_sig",
                severity=Severity.HIGH,
                category="anomaly",
                message="Missing PE signature at e_lfanew.",
            )
        )
        return report

    # ---- COFF (file) header — 20 bytes immediately after PE\0\0 ------------
    coff_off = e_lfanew + 4
    coff = r.slice(coff_off, 20)
    if coff is None:
        report.add(
            Finding(
                rule="pe.truncated_coff",
                severity=Severity.HIGH,
                category="anomaly",
                message="File truncated inside COFF header.",
            )
        )
        return report

    (
        machine,
        num_sections,
        timestamp,
        _ptr_sym_table,
        _num_sym,
        size_opt_hdr,
        characteristics,
    ) = struct.unpack("<HHIIIHH", coff)

    report.architecture = _MACHINE_NAMES.get(machine, f"0x{machine:04x}")
    report.timestamp = timestamp
    report.metadata["characteristics"] = characteristics
    report.metadata["is_dll"] = bool(characteristics & _CHAR_DLL)
    report.metadata["num_sections_claimed"] = num_sections

    if num_sections == 0:
        report.add(
            Finding(
                rule="pe.zero_sections",
                severity=Severity.HIGH,
                category="anomaly",
                message="Zero sections in PE — unusual; common in droppers that fix up at runtime.",
            )
        )

    if num_sections > MAX_SECTIONS:
        report.add(
            Finding(
                rule="pe.too_many_sections",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=f"Suspicious section count: {num_sections} (capped at {MAX_SECTIONS}).",
            )
        )
        num_sections = MAX_SECTIONS

    # ---- Optional header ---------------------------------------------------
    opt_off = coff_off + 20
    opt = r.slice(opt_off, size_opt_hdr)
    if opt is None or size_opt_hdr < 2:
        report.add(
            Finding(
                rule="pe.truncated_opt",
                severity=Severity.HIGH,
                category="anomaly",
                message="Optional header truncated.",
            )
        )
        return report

    opt_magic = struct.unpack("<H", opt[:2])[0]
    pe32_plus = opt_magic == _OPT_MAGIC_PE32_PLUS
    report.bitness = 64 if pe32_plus else 32

    if opt_magic not in (_OPT_MAGIC_PE32, _OPT_MAGIC_PE32_PLUS):
        report.add(
            Finding(
                rule="pe.bad_opt_magic",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=f"Unknown optional-header magic 0x{opt_magic:04x}.",
            )
        )

    # Fields we need regardless of bitness.
    entry_rva = r.u32(opt_off + 16) or 0
    report.entry_point = entry_rva

    if pe32_plus:
        image_base = r.u64(opt_off + 24) or 0
        size_image = r.u32(opt_off + 56) or 0
        size_headers = r.u32(opt_off + 60) or 0
        checksum = r.u32(opt_off + 64) or 0
        subsystem = r.u16(opt_off + 68) or 0
        dll_chars = r.u16(opt_off + 70) or 0
        num_rva = r.u32(opt_off + 108) or 0
        dd_off = opt_off + 112
    else:
        image_base = r.u32(opt_off + 28) or 0
        size_image = r.u32(opt_off + 56) or 0
        size_headers = r.u32(opt_off + 60) or 0
        checksum = r.u32(opt_off + 64) or 0
        subsystem = r.u16(opt_off + 68) or 0
        dll_chars = r.u16(opt_off + 70) or 0
        num_rva = r.u32(opt_off + 92) or 0
        dd_off = opt_off + 96

    report.metadata["image_base"] = image_base
    report.metadata["size_image"] = size_image
    report.metadata["size_headers"] = size_headers
    report.metadata["checksum"] = checksum
    report.metadata["subsystem"] = _SUBSYSTEM_NAMES.get(subsystem, str(subsystem))
    report.metadata["dll_characteristics"] = dll_chars

    # Mitigation flags
    mitigations: dict[str, bool] = {
        "ASLR": bool(dll_chars & _DLL_DYNAMIC_BASE),
        "HIGH_ENTROPY_VA": bool(dll_chars & _DLL_HIGH_ENTROPY_VA),
        "DEP/NX": bool(dll_chars & _DLL_NX_COMPAT),
        "CFG": bool(dll_chars & _DLL_GUARD_CF),
        "SAFE_SEH": not (dll_chars & _DLL_NO_SEH),
        "FORCE_INTEGRITY": bool(dll_chars & _DLL_FORCE_INTEGRITY),
    }
    report.metadata["mitigations"] = mitigations

    if not mitigations["ASLR"]:
        report.add(
            Finding(
                rule="pe.no_aslr",
                severity=Severity.LOW,
                category="anomaly",
                message="ASLR disabled (DYNAMIC_BASE flag missing).",
            )
        )
    if not mitigations["DEP/NX"]:
        report.add(
            Finding(
                rule="pe.no_dep",
                severity=Severity.LOW,
                category="anomaly",
                message="DEP/NX disabled (NX_COMPAT flag missing).",
            )
        )

    if checksum == 0 and characteristics & _CHAR_DLL:
        # Microsoft-signed DLLs always have a non-zero checksum. A DLL
        # with checksum==0 is either non-Microsoft or a strip artefact.
        report.add(
            Finding(
                rule="pe.zero_checksum_dll",
                severity=Severity.INFO,
                category="anomaly",
                message="PE checksum is zero for a DLL.",
            )
        )

    # ---- Data directories --------------------------------------------------
    data_dirs: list[tuple[int, int]] = []
    num_rva = min(num_rva, 16)  # max defined
    for i in range(num_rva):
        rva = r.u32(dd_off + i * 8)
        sz = r.u32(dd_off + i * 8 + 4)
        if rva is None or sz is None:
            break
        data_dirs.append((rva, sz))

    # ---- Section table -----------------------------------------------------
    sec_off = opt_off + size_opt_hdr
    sections: list[Section] = []
    section_raw_ranges: list[tuple[int, int, int]] = []  # (va, raw_off, raw_size)
    for i in range(num_sections):
        s_off = sec_off + i * 40
        s_hdr = r.slice(s_off, 40)
        if s_hdr is None:
            break
        name_b = s_hdr[:8].rstrip(b"\x00")
        try:
            name = name_b.decode("ascii", errors="replace")
        except Exception:
            name = ""
        # IMAGE_SECTION_HEADER: 8s Name | 4 VSize | 4 VAddr | 4 RawSize |
        #                       4 RawPtr | 4 RelocPtr | 4 LinePtr |
        #                       2 NumReloc | 2 NumLine | 4 Characteristics
        (_, vsize, vaddr, rsize, raddr, _rp, _lp, _nr, _nl, scn_chars) = struct.unpack(
            "<8sIIIIIIHHI", s_hdr
        )

        # Section raw bytes — clamp on the file.
        if raddr and rsize:
            blob = r.slice(raddr, rsize)
            ent = shannon_entropy(blob) if blob else 0.0
            section_raw_ranges.append((vaddr, raddr, rsize))
        else:
            ent = 0.0
        sections.append(
            Section(
                name=name,
                virtual_size=vsize,
                raw_size=rsize,
                file_offset=raddr,
                entropy=ent,
                flags=_section_flags_text(scn_chars),
            )
        )

    report.sections = sections

    # Per-section anomalies.
    for s in sections:
        if s.entropy >= 7.5 and s.raw_size > 0:
            report.add(
                Finding(
                    rule="pe.high_entropy_section",
                    severity=Severity.MEDIUM,
                    category="packer",
                    message=f"Section {s.name!r} has entropy {s.entropy:.2f} — packed/encrypted payload likely.",
                    evidence=(s.name,),
                )
            )
        if "W" in s.flags and "X" in s.flags:
            report.add(
                Finding(
                    rule="pe.wx_section",
                    severity=Severity.HIGH,
                    category="anomaly",
                    message=f"Section {s.name!r} is both writable and executable — unpacker stub or shellcode loader.",
                    evidence=(s.name,),
                )
            )
        if s.virtual_size > 10 * s.raw_size and s.raw_size > 0:
            report.add(
                Finding(
                    rule="pe.virt_much_larger",
                    severity=Severity.LOW,
                    category="packer",
                    message=f"Section {s.name!r} VirtualSize {s.virtual_size} ≫ RawSize {s.raw_size} — runtime-unpack hint.",
                    evidence=(s.name,),
                )
            )

    # ---- RVA → file offset translator (closure over sections) -------------
    def rva_to_offset(rva: int) -> int | None:
        if rva == 0:
            return None
        for va, raw_off, raw_size in section_raw_ranges:
            if va <= rva < va + max(raw_size, 1):
                delta = rva - va
                if delta < raw_size:
                    return raw_off + delta
        return None

    # ---- Imports -----------------------------------------------------------
    if len(data_dirs) > _DD_IMPORT:
        imp_rva, _imp_sz = data_dirs[_DD_IMPORT]
        report.imports = _parse_imports(r, rva_to_offset, imp_rva, pe32_plus)
        # CLR / .NET binary?
        if (
            len(data_dirs) > _DD_COM_DESCRIPTOR
            and data_dirs[_DD_COM_DESCRIPTOR][0]
            and data_dirs[_DD_COM_DESCRIPTOR][1]
        ):
            report.metadata["dotnet"] = True

    # ---- Delayed imports (often where injection APIs hide) ----------------
    if len(data_dirs) > _DD_DELAY_IMPORT:
        d_rva, _d_sz = data_dirs[_DD_DELAY_IMPORT]
        delayed = _parse_delay_imports(r, rva_to_offset, d_rva, pe32_plus)
        if delayed:
            # Merge into imports list with a "(delayed)" suffix so the user sees them.
            for imp in delayed:
                report.imports.append(
                    Import(library=f"{imp.library} (delayed)", symbols=imp.symbols)
                )

    # ---- Imphash (Mandiant pivot) -----------------------------------------
    report.imphash = compute_imphash(report.imports)

    # ---- Exports -----------------------------------------------------------
    if len(data_dirs) > _DD_EXPORT:
        exp_rva, exp_sz = data_dirs[_DD_EXPORT]
        if exp_rva and exp_sz:
            report.exports = _parse_exports(r, rva_to_offset, exp_rva)

    # ---- TLS callbacks (a classic anti-debug entry point) -----------------
    if len(data_dirs) > _DD_TLS:
        tls_rva, tls_sz = data_dirs[_DD_TLS]
        if tls_rva and tls_sz:
            report.metadata["tls_directory"] = True
            report.add(
                Finding(
                    rule="pe.tls_callbacks",
                    severity=Severity.MEDIUM,
                    category="anti_debug",
                    message="TLS directory present — code may run *before* the entry point (anti-debug).",
                )
            )

    # ---- Authenticode signature -------------------------------------------
    if len(data_dirs) > _DD_SECURITY:
        sec_rva, sec_sz = data_dirs[_DD_SECURITY]
        if sec_rva and sec_sz:
            # NB: for SECURITY only, "rva" is actually a file offset.
            report.is_signed = True
            report.metadata["signature_offset"] = sec_rva
            report.metadata["signature_size"] = sec_sz
            # The WIN_CERTIFICATE wrapper is 8 bytes (dwLength, wRevision,
            # wCertificateType); the PKCS#7 SignedData starts after that.
            blob = r.slice(sec_rva + 8, max(sec_sz - 8, 0))
            if blob:
                signer, issuer = extract_signer_names(blob)
                report.signer_cn = signer
                report.issuer_cn = issuer

    # ---- Resource directory: VERSIONINFO, Manifest, embedded MZ -----------
    if len(data_dirs) > _DD_RESOURCE:
        rsrc_rva, rsrc_sz = data_dirs[_DD_RESOURCE]
        if rsrc_rva and rsrc_sz:
            res = parse_resource_tree(r, rva_to_offset, rsrc_rva, rsrc_sz)
            if res.version_info:
                report.version_info = res.version_info
            if res.manifest:
                report.manifest = res.manifest
                level = res.manifest.get("requestedExecutionLevel", "")
                if level in {"requireAdministrator", "highestAvailable"}:
                    report.add(
                        Finding(
                            rule="pe.manifest_admin",
                            severity=Severity.LOW,
                            category="anomaly",
                            message=f"Manifest requests admin elevation ({level}).",
                            evidence=(level,),
                        )
                    )
                if res.manifest.get("autoElevate") == "true":
                    report.add(
                        Finding(
                            rule="pe.manifest_autoelevate",
                            severity=Severity.MEDIUM,
                            category="anomaly",
                            message="Manifest sets autoElevate=true — silent UAC bypass primitive.",
                        )
                    )
                if res.manifest.get("uiAccess") == "true":
                    report.add(
                        Finding(
                            rule="pe.manifest_uiaccess",
                            severity=Severity.MEDIUM,
                            category="anomaly",
                            message="Manifest sets uiAccess=true — UI access privilege.",
                        )
                    )
            if res.embedded_pe_count:
                report.add(
                    Finding(
                        rule="pe.embedded_pe_in_resources",
                        severity=Severity.HIGH,
                        category="dropper",
                        message=f"{res.embedded_pe_count} embedded PE(s) in resource directory — classic dropper.",
                    )
                )
            report.metadata["resource_types"] = res.type_counts

    # ---- Debug directory: extract PDB path -------------------------------
    if len(data_dirs) > _DD_DEBUG:
        dbg_rva, dbg_sz = data_dirs[_DD_DEBUG]
        pdb = _extract_pdb_path(r, rva_to_offset, dbg_rva, dbg_sz)
        if pdb:
            report.metadata["pdb_path"] = pdb

    # ---- Overlay (data past the last section's raw range) -----------------
    if section_raw_ranges:
        end_of_image = max(raw_off + raw_size for _, raw_off, raw_size in section_raw_ranges)
        if r.size > end_of_image + 8:
            overlay_size = r.size - end_of_image
            overlay = r.data[end_of_image:]
            report.has_overlay = True
            report.overlay_size = overlay_size
            report.overlay_entropy = shannon_entropy(overlay[: 1024 * 1024])
            if overlay_size > 1024:
                report.add(
                    Finding(
                        rule="pe.overlay",
                        severity=Severity.LOW,
                        category="dropper",
                        message=f"Overlay present: {overlay_size:,} bytes (entropy {report.overlay_entropy:.2f}). "
                        "Common in droppers and self-extracting installers.",
                    )
                )
                if report.overlay_entropy >= 7.5:
                    report.add(
                        Finding(
                            rule="pe.overlay_high_entropy",
                            severity=Severity.MEDIUM,
                            category="packer",
                            message=f"Overlay entropy {report.overlay_entropy:.2f} — encrypted/packed payload appended.",
                        )
                    )

    # ---- Rich header -------------------------------------------------------
    rich = _parse_rich_header(r, e_lfanew)
    if rich is not None:
        report.compiler = rich["summary"]
        report.metadata["rich_header"] = rich

    # ---- Overall entropy ---------------------------------------------------
    # Use a 1 MiB sample to keep this cheap for huge files.
    sample = r.data[: 1024 * 1024]
    report.overall_entropy = shannon_entropy(sample)

    # ---- Packer signature --------------------------------------------------
    label = packer_match((s.name for s in sections), r.data)
    if label:
        report.is_packed = True
        report.detected_packer = label
        report.add(
            Finding(
                rule="pe.packer_signature",
                severity=Severity.MEDIUM,
                category="packer",
                message=f"Packer signature matched: {label}.",
                evidence=(label,),
            )
        )

    # ---- Anomaly: entry point not inside any executable section -----------
    # Classic patch-and-jump: malware overwrites a non-executable section's
    # raw bytes and points AddressOfEntryPoint at it. A clean compiler always
    # emits ``.text`` (or equivalent) with MEM_EXECUTE set and entry there.
    if entry_rva:
        ep_section = None
        for s, (va, _ro, rs_) in zip(sections, section_raw_ranges, strict=False):
            if va <= entry_rva < va + max(rs_, 1):
                ep_section = s
                break
        if ep_section is None:
            report.add(
                Finding(
                    rule="pe.entry_outside_sections",
                    severity=Severity.HIGH,
                    category="anomaly",
                    message=f"Entry point 0x{entry_rva:x} lies outside every section's raw range.",
                )
            )
        elif "X" not in ep_section.flags:
            report.add(
                Finding(
                    rule="pe.entry_in_nonexec_section",
                    severity=Severity.HIGH,
                    category="anomaly",
                    message=f"Entry point lives in non-executable section {ep_section.name!r} ({ep_section.flags}).",
                    evidence=(ep_section.name,),
                )
            )

    # ---- Anomaly: timestamp ------------------------------------------------
    # Linkers between 2005 and now-ish. Either side ⇒ stamped / cleared.
    # The 1995 lower bound is the MSDN-published "earliest plausibly real
    # timestamp"; the upper bound allows for clock skew.
    import datetime as _dt

    now_unix = int(_dt.datetime.now(tz=_dt.UTC).timestamp())
    if timestamp != 0 and timestamp < 0x30000000:  # 1995-07-12
        report.add(
            Finding(
                rule="pe.timestamp_ancient",
                severity=Severity.INFO,
                category="anomaly",
                message=f"COFF timestamp pre-1995 (0x{timestamp:08x}) — likely zeroed or fake.",
            )
        )
    elif timestamp > now_unix + 86400 * 365:
        report.add(
            Finding(
                rule="pe.timestamp_future",
                severity=Severity.INFO,
                category="anomaly",
                message=f"COFF timestamp in the future (0x{timestamp:08x}).",
            )
        )

    # ---- Anomaly: PE checksum mismatch ------------------------------------
    # Algorithm: 16-bit one's-complement sum of all words in the file, with
    # the 4 bytes of OptionalHeader.CheckSum itself treated as zero, then
    # adding the file size at the end. Cheap to compute (single pass).
    if checksum:  # only worth checking if the binary even sets one
        checksum_field_off = opt_off + 64  # CheckSum lives at opt+64 in both PE32/PE32+
        computed = _compute_pe_checksum(r.data, checksum_field_off)
        if computed and computed != checksum:
            report.add(
                Finding(
                    rule="pe.checksum_mismatch",
                    severity=Severity.INFO,
                    category="anomaly",
                    message=f"PE checksum mismatch: header=0x{checksum:08x}, computed=0x{computed:08x}.",
                )
            )

    return report


def _compute_pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Re-implement the PE checksum algorithm (CheckSumMappedFile).

    Sums 16-bit little-endian words, treats the four CheckSum bytes as
    zero, folds the upper-half carries back, then adds the file size.
    Returns 0 on an oddly-sized truncated buffer (we don't want a noisy
    finding when the input is just clipped).
    """
    n = len(data)
    if n < checksum_offset + 4:
        return 0
    total = 0
    i = 0
    # Pad to even length so the loop is symmetric.
    end = n & ~1
    while i < end:
        if i == checksum_offset:
            # Skip the 4-byte CheckSum field (two words).
            i += 4
            continue
        total += data[i] | (data[i + 1] << 8)
        # Fold carries periodically to keep the int small.
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if n & 1:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + n) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


def _parse_imports(
    r: Reader,
    rva_to_offset,
    imp_rva: int,
    pe32_plus: bool,
) -> list[Import]:
    """Walk the IMPORT_DIRECTORY_TABLE.

    Each descriptor is 20 bytes; iteration ends at an all-zero descriptor.
    For each library we walk the ILT (Import Lookup Table) and resolve
    the IMAGE_IMPORT_BY_NAME entries.
    """
    out: list[Import] = []
    base = rva_to_offset(imp_rva)
    if base is None:
        return out

    thunk_size = 8 if pe32_plus else 4
    ordinal_flag = 1 << 63 if pe32_plus else 1 << 31

    for i in range(MAX_IMPORT_LIBS):
        desc_off = base + i * 20
        desc = r.slice(desc_off, 20)
        if desc is None:
            break
        ilt_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack("<IIIII", desc)
        if not any((ilt_rva, name_rva, iat_rva)):
            break  # all-zero terminator

        name_off = rva_to_offset(name_rva)
        lib_name = r.cstr(name_off, 256) if name_off is not None else None
        if not lib_name:
            lib_name = "<unnamed>"

        # Prefer ILT (original, never patched); fall back to IAT.
        thunk_rva = ilt_rva or iat_rva
        thunk_off = rva_to_offset(thunk_rva) if thunk_rva else None
        symbols: list[str] = []
        if thunk_off is not None:
            for j in range(MAX_IMPORT_SYMBOLS_PER_LIB):
                ent = (
                    r.u64(thunk_off + j * thunk_size)
                    if pe32_plus
                    else r.u32(thunk_off + j * thunk_size)
                )
                if ent is None or ent == 0:
                    break
                if ent & ordinal_flag:
                    ord_num = ent & 0xFFFF
                    symbols.append(f"#{ord_num}")
                    continue
                # RVA lives in the low 31 bits on both PE32 and PE32+; bit
                # 31 (PE32) / bit 63 (PE32+) is the ordinal flag, handled above.
                sym_off = rva_to_offset(ent & 0x7FFFFFFF)
                if sym_off is None:
                    continue
                # IMAGE_IMPORT_BY_NAME: 2-byte Hint, NUL-terminated Name.
                sym_name = r.cstr(sym_off + 2, 256)
                if sym_name:
                    symbols.append(sym_name)
        out.append(Import(library=lib_name, symbols=tuple(symbols)))
    return out


def _parse_delay_imports(
    r: Reader,
    rva_to_offset,
    rva: int,
    pe32_plus: bool,
) -> list[Import]:
    """Walk the delay-load import directory.

    Each ``ImgDelayDescr`` is 32 bytes; iteration ends at an all-zero
    descriptor. Layout follows MS:

        DWORD grAttrs;
        DWORD szName;          // RVA to DLL name
        DWORD phmod;           // RVA to HMODULE slot
        DWORD pIAT;            // RVA to IAT
        DWORD pINT;            // RVA to INT (we use this)
        DWORD pBoundIAT;
        DWORD pUnloadIAT;
        DWORD dwTimeStamp;
    """
    out: list[Import] = []
    base = rva_to_offset(rva)
    if base is None:
        return out

    thunk_size = 8 if pe32_plus else 4
    ordinal_flag = 1 << 63 if pe32_plus else 1 << 31

    for i in range(MAX_IMPORT_LIBS):
        desc_off = base + i * 32
        desc = r.slice(desc_off, 32)
        if desc is None:
            break
        _attrs, name_rva, _phmod, _piat, pint_rva = struct.unpack("<IIIII", desc[:20])
        if not any((name_rva, pint_rva)):
            break

        name_off = rva_to_offset(name_rva)
        lib_name = r.cstr(name_off, 256) if name_off is not None else None
        if not lib_name:
            continue

        thunk_off = rva_to_offset(pint_rva) if pint_rva else None
        symbols: list[str] = []
        if thunk_off is not None:
            for j in range(MAX_IMPORT_SYMBOLS_PER_LIB):
                ent = (
                    r.u64(thunk_off + j * thunk_size)
                    if pe32_plus
                    else r.u32(thunk_off + j * thunk_size)
                )
                if ent is None or ent == 0:
                    break
                if ent & ordinal_flag:
                    symbols.append(f"#{ent & 0xFFFF}")
                    continue
                # RVA lives in the low 31 bits on both PE32 and PE32+; bit
                # 31 (PE32) / bit 63 (PE32+) is the ordinal flag, handled above.
                sym_off = rva_to_offset(ent & 0x7FFFFFFF)
                if sym_off is None:
                    continue
                sym_name = r.cstr(sym_off + 2, 256)
                if sym_name:
                    symbols.append(sym_name)
        out.append(Import(library=lib_name, symbols=tuple(symbols)))
    return out


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


def _parse_exports(r: Reader, rva_to_offset, exp_rva: int) -> list[Export]:
    base = rva_to_offset(exp_rva)
    if base is None:
        return []
    hdr = r.slice(base, 40)
    if hdr is None:
        return []
    (
        _chars,
        _ts,
        _maj,
        _min,
        _name_rva,
        ordinal_base,
        _num_funcs,
        num_names,
        _addr_funcs_rva,
        addr_names_rva,
        addr_name_ords_rva,
    ) = struct.unpack("<IIHHIIIIII", hdr)

    out: list[Export] = []
    names_table_off = rva_to_offset(addr_names_rva)
    ords_table_off = rva_to_offset(addr_name_ords_rva)
    if names_table_off is None or ords_table_off is None:
        return out

    # Limit to a sane number.
    num_names = min(num_names, 65536)
    for i in range(num_names):
        name_rva = r.u32(names_table_off + i * 4)
        ord_val = r.u16(ords_table_off + i * 2)
        if name_rva is None or ord_val is None:
            break
        n_off = rva_to_offset(name_rva)
        if n_off is None:
            continue
        n = r.cstr(n_off, 256)
        if n:
            out.append(Export(name=n, ordinal=ordinal_base + ord_val))
    return out


# ---------------------------------------------------------------------------
# Debug directory → PDB path
# ---------------------------------------------------------------------------


def _extract_pdb_path(
    r: Reader,
    rva_to_offset,
    dbg_rva: int,
    dbg_size: int,
) -> str | None:
    """Find the PDB path from a CODEVIEW (RSDS) debug entry, if present.

    Each IMAGE_DEBUG_DIRECTORY is 28 bytes; we look for type==2 (CODEVIEW),
    then read the CV record which for modern PDBs starts with 'RSDS'
    (RSDS + 16-byte GUID + 4-byte age + NUL-terminated UTF-8 path).
    """
    base = rva_to_offset(dbg_rva)
    if base is None or dbg_size == 0:
        return None
    n_entries = dbg_size // 28
    for i in range(min(n_entries, 32)):
        entry = r.slice(base + i * 28, 28)
        if entry is None:
            break
        # offset 12: Type, 16: SizeOfData, 24: PointerToRawData
        cv_type = struct.unpack("<I", entry[12:16])[0]
        cv_size = struct.unpack("<I", entry[16:20])[0]
        cv_off = struct.unpack("<I", entry[24:28])[0]
        if cv_type != 2 or cv_size < 24 or cv_off == 0:
            continue
        magic = r.slice(cv_off, 4)
        if magic != b"RSDS":
            continue
        # GUID(16) + Age(4) → name starts at cv_off + 24
        pdb_bytes = r.slice(cv_off + 24, cv_size - 24)
        if pdb_bytes is None:
            continue
        nul = pdb_bytes.find(b"\x00")
        if nul == -1:
            nul = min(len(pdb_bytes), 260)
        try:
            return pdb_bytes[:nul].decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Rich header
# ---------------------------------------------------------------------------


def _parse_rich_header(r: Reader, e_lfanew: int) -> dict | None:
    """Extract the Microsoft Rich header (compiler/linker fingerprint).

    The header lives between the DOS stub and the PE header. It ends with
    a ``Rich`` marker followed by a 4-byte XOR key. Decoding XORs the
    preceding DWORDs with the key until we hit ``DanS`` — the header
    start. Each post-DanS DWORD pair is (compid, count): the high 16
    bits identify the tool (linker, C/C++ compiler), the low 16 bits
    the build number.
    """
    head = r.slice(0, e_lfanew)
    if head is None or len(head) < 16:
        return None
    rich_pos = head.rfind(b"Rich")
    if rich_pos == -1 or rich_pos + 8 > len(head):
        return None
    xor_key = head[rich_pos + 4 : rich_pos + 8]
    if len(xor_key) != 4:
        return None

    # Walk backwards in 4-byte words; XOR with key; stop at 'DanS'.
    out_words: list[int] = []
    pos = rich_pos - 4
    dans_found = False
    while pos >= 0:
        word = head[pos : pos + 4]
        if len(word) != 4:
            break
        decoded = bytes(a ^ b for a, b in zip(word, xor_key, strict=False))
        if decoded == b"DanS":
            dans_found = True
            break
        out_words.append(struct.unpack("<I", decoded)[0])
        pos -= 4

    if not dans_found:
        return None

    # Words are in reverse (we walked backwards), and the structure is
    # 3 padding zeros then pairs of (compid, count). Reverse and parse.
    out_words.reverse()
    # Skip leading zero padding.
    while out_words and out_words[0] == 0:
        out_words.pop(0)

    entries: list[dict[str, int]] = []
    summary_parts: list[str] = []
    for i in range(0, len(out_words) - 1, 2):
        compid = out_words[i]
        count = out_words[i + 1]
        tool_id = (compid >> 16) & 0xFFFF
        build = compid & 0xFFFF
        entries.append({"tool_id": tool_id, "build": build, "count": count})
        summary_parts.append(f"tool=0x{tool_id:04x} build={build} count={count}")
    summary = "; ".join(summary_parts[:4])
    if len(summary_parts) > 4:
        summary += f"; +{len(summary_parts) - 4} more"
    return {"summary": summary or "Rich header present", "entries": entries}
