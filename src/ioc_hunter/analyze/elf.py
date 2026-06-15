"""ELF (Linux/BSD/Android) analyzer.

Parses the ELF header, walks program headers and section headers,
follows the dynamic section to enumerate ``DT_NEEDED`` libraries and
``DT_RUNPATH`` / ``DT_RPATH`` (loader hijack hint), pulls dynamic
symbols out of ``.dynsym``, and applies the same per-section entropy
+ packer signature pass we use for PE.

Hardening summary (the things the loader checks for, that defensive
analysts should highlight):

- NX bit on the stack — derived from ``PT_GNU_STACK`` flags.
- PIE — ``e_type == ET_DYN`` and at least one ``DT_DEBUG`` plate is
  the canonical detection.
- RELRO — full RELRO needs both a ``PT_GNU_RELRO`` segment AND
  ``DT_FLAGS`` carrying ``DF_BIND_NOW``.
- Stack canary — ``__stack_chk_fail`` symbol referenced.
- Stripped — no ``.symtab`` section is the reliable signal (the
  ``.strtab`` table is also absent or shorter than expected).

Everything goes through the same defensive ``Reader`` as the PE
module: malformed input yields a degraded report, not an exception.
"""

from __future__ import annotations

import struct

from ioc_hunter.analyze.common import (
    MAX_SECTIONS,
    POSIX_SUSPICIOUS_SYMBOLS,
    AnalyzerReport,
    Finding,
    Import,
    Reader,
    Section,
    Severity,
    packer_match,
    shannon_entropy,
)

_MAG = b"\x7fELF"

_ELFCLASS32 = 1
_ELFCLASS64 = 2

_ELFDATA2LSB = 1
_ELFDATA2MSB = 2

_ET_NONE = 0
_ET_REL = 1
_ET_EXEC = 2
_ET_DYN = 3
_ET_CORE = 4

_E_TYPE_NAMES = {
    _ET_NONE: "NONE",
    _ET_REL: "REL",
    _ET_EXEC: "EXEC",
    _ET_DYN: "DYN/PIE",
    _ET_CORE: "CORE",
}

_E_MACHINE_NAMES = {
    0x02: "SPARC",
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0x16: "S390",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86_64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}

_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_INTERP = 3
_PT_NOTE = 4
_PT_PHDR = 6
_PT_TLS = 7
_PT_GNU_EH_FRAME = 0x6474E550
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552

_PF_X = 1
_PF_W = 2
_PF_R = 4

_SHT_NULL = 0
_SHT_PROGBITS = 1
_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_RELA = 4
_SHT_HASH = 5
_SHT_DYNAMIC = 6
_SHT_NOTE = 7
_SHT_NOBITS = 8
_SHT_REL = 9
_SHT_DYNSYM = 11

_NT_GNU_BUILD_ID = 3
_NT_GNU_GOLD_VERSION = 4

_SHF_W = 1
_SHF_A = 2
_SHF_X = 4

_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_STRSZ = 10
_DT_SONAME = 14
_DT_RPATH = 15
_DT_RUNPATH = 29
_DT_FLAGS = 30
_DT_DEBUG = 0x15

_DF_BIND_NOW = 0x8


def _section_flags_text(flags: int) -> str:
    out = []
    if flags & _SHF_A:
        out.append("R")
    if flags & _SHF_W:
        out.append("W")
    if flags & _SHF_X:
        out.append("X")
    return "".join(out) or "-"


def _p_flags_text(p_flags: int) -> str:
    out = []
    if p_flags & _PF_R:
        out.append("R")
    if p_flags & _PF_W:
        out.append("W")
    if p_flags & _PF_X:
        out.append("X")
    return "".join(out) or "-"


def analyze_elf(raw: bytes, *, report: AnalyzerReport) -> AnalyzerReport:
    r = Reader(raw)

    head = r.slice(0, 16)
    if head is None or head[:4] != _MAG:
        report.add(
            Finding(
                rule="elf.bad_magic",
                severity=Severity.HIGH,
                category="anomaly",
                message="Missing ELF magic.",
            )
        )
        return report

    ei_class = head[4]
    ei_data = head[5]
    ei_osabi = head[7]
    little = ei_data == _ELFDATA2LSB
    is_64 = ei_class == _ELFCLASS64
    report.bitness = 64 if is_64 else 32

    if ei_class not in (_ELFCLASS32, _ELFCLASS64):
        report.add(
            Finding(
                rule="elf.bad_class",
                severity=Severity.HIGH,
                category="anomaly",
                message=f"Unknown EI_CLASS {ei_class}.",
            )
        )
        return report

    e_type = r.u16(16, little) or 0
    e_machine = r.u16(18, little) or 0
    _e_version = r.u32(20, little) or 0

    if is_64:
        e_entry = r.u64(24, little) or 0
        e_phoff = r.u64(32, little) or 0
        e_shoff = r.u64(40, little) or 0
        _e_flags = r.u32(48, little) or 0
        _e_ehsize = r.u16(52, little) or 0
        e_phentsize = r.u16(54, little) or 0
        e_phnum = r.u16(56, little) or 0
        e_shentsize = r.u16(58, little) or 0
        e_shnum = r.u16(60, little) or 0
        e_shstrndx = r.u16(62, little) or 0
    else:
        e_entry = r.u32(24, little) or 0
        e_phoff = r.u32(28, little) or 0
        e_shoff = r.u32(32, little) or 0
        _e_flags = r.u32(36, little) or 0
        _e_ehsize = r.u16(40, little) or 0
        e_phentsize = r.u16(42, little) or 0
        e_phnum = r.u16(44, little) or 0
        e_shentsize = r.u16(46, little) or 0
        e_shnum = r.u16(48, little) or 0
        e_shstrndx = r.u16(50, little) or 0

    report.architecture = _E_MACHINE_NAMES.get(e_machine, f"e_machine=0x{e_machine:x}")
    report.entry_point = e_entry
    report.metadata["e_type"] = _E_TYPE_NAMES.get(e_type, str(e_type))
    report.metadata["endian"] = "little" if little else "big"
    report.metadata["osabi"] = ei_osabi

    if e_phnum > MAX_SECTIONS:
        report.add(
            Finding(
                rule="elf.too_many_phdr",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=f"Suspicious program header count: {e_phnum}.",
            )
        )
        e_phnum = MAX_SECTIONS
    if e_shnum > MAX_SECTIONS:
        report.add(
            Finding(
                rule="elf.too_many_shdr",
                severity=Severity.MEDIUM,
                category="anomaly",
                message=f"Suspicious section header count: {e_shnum}.",
            )
        )
        e_shnum = MAX_SECTIONS

    # ---- Program headers ---------------------------------------------------
    nx_stack = True  # absence of PT_GNU_STACK ⇒ kernel may use default executable
    has_relro = False
    has_load_wx = False
    interp = ""

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is_64:
            ph = r.slice(off, 56)
            if ph is None:
                break
            p_type, p_flags = struct.unpack(("<" if little else ">") + "II", ph[:8])
            p_offset, _p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack(
                ("<" if little else ">") + "QQQQQQ", ph[8:]
            )
        else:
            ph = r.slice(off, 32)
            if ph is None:
                break
            (
                p_type,
                p_offset,
                _p_vaddr,
                _p_paddr,
                p_filesz,
                p_memsz,
                p_flags,
                _p_align,
            ) = struct.unpack(("<" if little else ">") + "IIIIIIII", ph)

        if p_type == _PT_LOAD:
            blob = r.slice(p_offset, min(p_filesz, 8 * 1024 * 1024))
            ent = shannon_entropy(blob) if blob else 0.0
            report.sections.append(
                Section(
                    name=f"LOAD#{i}",
                    virtual_size=p_memsz,
                    raw_size=p_filesz,
                    file_offset=p_offset,
                    entropy=ent,
                    flags=_p_flags_text(p_flags),
                )
            )
            if (p_flags & _PF_W) and (p_flags & _PF_X):
                has_load_wx = True
        elif p_type == _PT_INTERP:
            buf = r.slice(p_offset, min(p_filesz, 256))
            if buf:
                interp = buf.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        elif p_type == _PT_GNU_STACK:
            nx_stack = not (p_flags & _PF_X)
        elif p_type == _PT_GNU_RELRO:
            has_relro = True

    if interp:
        report.metadata["interpreter"] = interp
    report.metadata["nx_stack"] = nx_stack
    report.metadata["relro"] = has_relro

    if has_load_wx:
        report.add(
            Finding(
                rule="elf.wx_segment",
                severity=Severity.HIGH,
                category="anomaly",
                message="A LOAD segment is mapped writable + executable — packer stub or shellcode loader.",
            )
        )
    if not nx_stack:
        report.add(
            Finding(
                rule="elf.exec_stack",
                severity=Severity.MEDIUM,
                category="anomaly",
                message="Executable stack — PT_GNU_STACK has X flag.",
            )
        )

    # ---- Section headers + .shstrtab --------------------------------------
    sections_meta: list[tuple[str, int, int, int, int, int]] = []
    #   ^ (name, type, flags, offset, size, addr)

    shstrtab_blob = b""
    if 0 < e_shstrndx < e_shnum and e_shoff:
        sh_off = e_shoff + e_shstrndx * e_shentsize
        if is_64:
            hdr = r.slice(sh_off, 64)
            if hdr is not None:
                _name, _typ, _flags, _addr, off, size = struct.unpack(
                    ("<" if little else ">") + "IIQQQQ", hdr[:40]
                )
                shstrtab_blob = r.slice(off, min(size, 256 * 1024)) or b""
        else:
            hdr = r.slice(sh_off, 40)
            if hdr is not None:
                _name, _typ, _flags, _addr, off, size, *_ = struct.unpack(
                    ("<" if little else ">") + "IIIIIIIIII", hdr
                )
                shstrtab_blob = r.slice(off, min(size, 256 * 1024)) or b""

    def _name_at(o: int) -> str:
        if o < 0 or o >= len(shstrtab_blob):
            return ""
        nul = shstrtab_blob.find(b"\x00", o)
        if nul == -1:
            nul = len(shstrtab_blob)
        return shstrtab_blob[o:nul].decode("ascii", errors="replace")

    dynamic_sh: tuple[int, int] | None = None
    dynsym_sh: tuple[int, int, int] | None = None  # (offset, size, link-to-strtab)
    symtab_sh: tuple[int, int, int] | None = None
    strtab_blob = b""

    for i in range(e_shnum):
        sh_off = e_shoff + i * e_shentsize
        if is_64:
            hdr = r.slice(sh_off, 64)
            if hdr is None:
                break
            name_off, sh_type, sh_flags, sh_addr, off, size, link, _info, _aa, _es = struct.unpack(
                ("<" if little else ">") + "IIQQQQIIQQ", hdr
            )
        else:
            hdr = r.slice(sh_off, 40)
            if hdr is None:
                break
            (
                name_off,
                sh_type,
                sh_flags,
                sh_addr,
                off,
                size,
                link,
                _info,
                _aa,
                _es,
            ) = struct.unpack(("<" if little else ">") + "IIIIIIIIII", hdr)

        name = _name_at(name_off)
        sections_meta.append((name, sh_type, sh_flags, off, size, sh_addr))

        # Track key sections we need to follow.
        if sh_type == _SHT_DYNAMIC:
            dynamic_sh = (off, size)
        elif sh_type == _SHT_DYNSYM:
            dynsym_sh = (off, size, link)
        elif sh_type == _SHT_SYMTAB:
            symtab_sh = (off, size, link)
        elif sh_type == _SHT_STRTAB and name == ".dynstr":
            blob = r.slice(off, min(size, 1024 * 1024))
            if blob is not None:
                strtab_blob = blob

        # Build sections list — only PROGBITS / NOBITS show in the section view.
        if sh_type in (_SHT_PROGBITS, _SHT_NOBITS):
            if sh_type == _SHT_PROGBITS and size:
                blob = r.slice(off, min(size, 8 * 1024 * 1024))
                ent = shannon_entropy(blob) if blob else 0.0
            else:
                ent = 0.0
            report.sections.append(
                Section(
                    name=name or f"<sh#{i}>",
                    virtual_size=size,
                    raw_size=0 if sh_type == _SHT_NOBITS else size,
                    file_offset=off,
                    entropy=ent,
                    flags=_section_flags_text(sh_flags),
                )
            )

    # ---- Dynamic section ---------------------------------------------------
    needed: list[str] = []
    rpath = ""
    runpath = ""
    soname = ""
    df_flags = 0
    entries: list[tuple[int, int]] = []

    if dynamic_sh is not None:
        d_off, d_size = dynamic_sh
        ent_size = 16 if is_64 else 8
        # First pass: capture DT_STRTAB / DT_STRSZ if we don't have .dynstr yet.
        dt_strtab_addr = 0
        dt_strsz = 0
        n = min(d_size // ent_size, 4096)
        for i in range(n):
            entry_off = d_off + i * ent_size
            if is_64:
                tag = r.u64(entry_off, little) or 0
                val = r.u64(entry_off + 8, little) or 0
            else:
                tag = r.u32(entry_off, little) or 0
                val = r.u32(entry_off + 4, little) or 0
            if tag == _DT_NULL:
                break
            entries.append((tag, val))
            if tag == _DT_STRTAB:
                dt_strtab_addr = val
            elif tag == _DT_STRSZ:
                dt_strsz = val
            elif tag == _DT_FLAGS:
                df_flags = val

        # If we didn't find .dynstr by section name, resolve via the address.
        if not strtab_blob and dt_strtab_addr and dt_strsz:
            # Find the section containing this virtual address.
            for _name, _typ, _flags, off, size, addr in sections_meta:
                if addr and addr <= dt_strtab_addr < addr + size:
                    delta = dt_strtab_addr - addr
                    blob = r.slice(off + delta, min(dt_strsz, 1024 * 1024))
                    if blob is not None:
                        strtab_blob = blob
                        break

        def _dyn_str(o: int) -> str:
            if not strtab_blob or o < 0 or o >= len(strtab_blob):
                return ""
            nul = strtab_blob.find(b"\x00", o)
            if nul == -1:
                nul = len(strtab_blob)
            return strtab_blob[o:nul].decode("ascii", errors="replace")

        for tag, val in entries:
            if tag == _DT_NEEDED:
                lib = _dyn_str(val)
                if lib:
                    needed.append(lib)
            elif tag == _DT_RPATH:
                rpath = _dyn_str(val)
            elif tag == _DT_RUNPATH:
                runpath = _dyn_str(val)
            elif tag == _DT_SONAME:
                soname = _dyn_str(val)

    report.linked_libraries = needed
    report.metadata["soname"] = soname
    report.metadata["rpath"] = rpath
    report.metadata["runpath"] = runpath
    report.metadata["df_flags"] = df_flags

    full_relro = has_relro and bool(df_flags & _DF_BIND_NOW)
    report.metadata["full_relro"] = full_relro

    if rpath:
        report.add(
            Finding(
                rule="elf.rpath",
                severity=Severity.LOW,
                category="anomaly",
                message=f"DT_RPATH set: {rpath!r} — loader path override (potential hijack vector).",
                evidence=(rpath,),
            )
        )
    if runpath:
        report.add(
            Finding(
                rule="elf.runpath",
                severity=Severity.LOW,
                category="anomaly",
                message=f"DT_RUNPATH set: {runpath!r} — loader path override.",
                evidence=(runpath,),
            )
        )

    # ---- Dynamic symbol table ---------------------------------------------
    dyn_symbols: list[str] = []
    if dynsym_sh is not None and strtab_blob:
        d_off, d_size, _link = dynsym_sh
        ent_size = 24 if is_64 else 16
        n = min(d_size // ent_size, 65536)
        for i in range(n):
            so = d_off + i * ent_size
            if is_64:
                # st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
                name_off = r.u32(so, little) or 0
                _info = r.u8(so + 4) or 0
            else:
                # st_name(4), st_value(4), st_size(4), st_info(1), st_other(1), st_shndx(2)
                name_off = r.u32(so, little) or 0
                _info = r.u8(so + 12) or 0
            if name_off == 0:
                continue
            n_str = strtab_blob.find(b"\x00", name_off)
            if n_str == -1:
                continue
            nm = strtab_blob[name_off:n_str].decode("ascii", errors="replace")
            if nm and nm not in dyn_symbols:
                dyn_symbols.append(nm)

    if dyn_symbols:
        report.imports = [Import(library=lib, symbols=()) for lib in needed]
        # Also surface the dynsym names — heuristics consumes them.
        report.metadata["dyn_symbols"] = dyn_symbols
    else:
        report.imports = [Import(library=lib, symbols=()) for lib in needed]

    # Stripped: no .symtab.
    if symtab_sh is None:
        report.is_stripped = True

    # Stack canary detection.
    if "__stack_chk_fail" in dyn_symbols:
        report.metadata["stack_canary"] = True
    else:
        report.metadata["stack_canary"] = False

    # PIE detection: ET_DYN with a DT_DEBUG dynamic entry is the canonical
    # tell for a PIE executable (vs a plain shared library, which has no
    # DT_DEBUG). Pure shared libraries also report ET_DYN but lack DT_DEBUG.
    pie = (e_type == _ET_DYN) and any(t == _DT_DEBUG for t, _ in entries)
    report.metadata["pie"] = pie

    # Surface a single hardening summary finding for SOC viewers.
    hardening_missing = []
    if not pie and e_type == _ET_EXEC:
        hardening_missing.append("PIE")
    if not nx_stack:
        hardening_missing.append("NX")
    if not full_relro:
        hardening_missing.append("FULL_RELRO")
    if not report.metadata.get("stack_canary"):
        hardening_missing.append("CANARY")
    if hardening_missing:
        report.add(
            Finding(
                rule="elf.weak_hardening",
                severity=Severity.LOW,
                category="anomaly",
                message="Missing hardening: " + ", ".join(hardening_missing) + ".",
                evidence=tuple(hardening_missing),
            )
        )

    # ---- Suspicious POSIX symbols ----------------------------------------
    # Surface the set as metadata so heuristics.py can combo across
    # categories; ptrace gets a standalone finding because it is, on its
    # own, a strong tell on a Linux user-space binary.
    matched = sorted(set(dyn_symbols) & POSIX_SUSPICIOUS_SYMBOLS)
    report.metadata["suspicious_posix_symbols"] = matched
    if "ptrace" in matched:
        report.add(
            Finding(
                rule="elf.ptrace",
                severity=Severity.MEDIUM,
                category="anti_debug",
                message="Imports ptrace() — classic ptrace-self anti-debug or process injection on Linux.",
                evidence=("ptrace",),
            )
        )

    # ---- Notes: GNU build-id, Go build-id, ABI tag -----------------------
    # SHT_NOTE sections carry typed records; we mostly want NT_GNU_BUILD_ID
    # (a SHA-1 of the binary contents, the canonical pivot for stripped
    # ELFs) and the Go runtime build-id (.note.go.buildid).
    for sname, stype, _sflags, soff, ssize, _saddr in sections_meta:
        if stype != _SHT_NOTE:
            continue
        notes_blob = r.slice(soff, min(ssize, 64 * 1024))
        if not notes_blob:
            continue
        _walk_notes(notes_blob, sname, little, report)

    # ---- Overall entropy + packer match ----------------------------------
    sample = r.data[: 1024 * 1024]
    report.overall_entropy = shannon_entropy(sample)

    label = packer_match((s.name for s in report.sections), r.data)
    if label:
        report.is_packed = True
        report.detected_packer = label
        report.add(
            Finding(
                rule="elf.packer_signature",
                severity=Severity.MEDIUM,
                category="packer",
                message=f"Packer signature matched: {label}.",
                evidence=(label,),
            )
        )

    return report


def _walk_notes(blob: bytes, section_name: str, little: bool, report: AnalyzerReport) -> None:
    """Parse the typed records inside a SHT_NOTE section.

    Each record is:
        u32 namesz | u32 descsz | u32 type | name (padded to 4)
                                          | desc (padded to 4)

    We bail out at the first malformed record rather than try to recover —
    these sections are tiny and a broken header is itself signal.
    """
    fmt = ("<" if little else ">") + "III"
    pos = 0
    end = len(blob)
    safety = 0
    while pos + 12 <= end and safety < 64:
        safety += 1
        namesz, descsz, ntype = struct.unpack(fmt, blob[pos : pos + 12])
        if namesz > 64 or descsz > 4096:
            return
        name_off = pos + 12
        name_end = name_off + namesz
        if name_end > end:
            return
        name = blob[name_off : name_end - 1].decode("ascii", errors="replace") if namesz else ""
        desc_off = (name_end + 3) & ~3
        desc_end = desc_off + descsz
        if desc_end > end:
            return
        desc = blob[desc_off:desc_end]

        if name == "GNU" and ntype == _NT_GNU_BUILD_ID and desc:
            # SHA-1 (20 bytes) is the GNU convention; can be MD5 (16) or
            # SHA-256 (32) on alternate toolchains. Hex either way.
            if not report.build_id:
                report.build_id = desc.hex()
        elif name == "Go" and ntype == 4 and desc:
            # Go binaries embed their build-id as ASCII.
            txt = desc.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
            if txt and "go_build_id" not in report.metadata:
                report.metadata["go_build_id"] = txt
                report.metadata["is_go_binary"] = True
        elif section_name == ".note.ABI-tag" and name == "GNU" and len(desc) >= 16:
            # NT_GNU_ABI_TAG: os(4) + major(4) + minor(4) + revision(4)
            try:
                osv, maj, mnr, rev = struct.unpack(("<" if little else ">") + "IIII", desc[:16])
                report.metadata["abi_tag"] = f"os={osv} kernel {maj}.{mnr}.{rev}"
            except struct.error:
                pass

        pos = desc_end
        # Records are 4-byte aligned overall.
        pos = (pos + 3) & ~3
