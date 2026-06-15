"""Hand-rolled, minimal-but-valid binaries for analyser tests.

We intentionally do *not* ship real malware samples — the analyser is
exercised end-to-end against synthetic binaries built at runtime. Each
builder returns ``bytes`` and is structured so the test can flip one
field (e.g. add an import) without rewriting the whole layout.

Layouts are minimal but obey enough of each format that the analyser's
defensive ``Reader`` walks them happily.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# PE32+ minimal executable, optionally with an import table.
# ---------------------------------------------------------------------------


_DOS_STUB = (
    b"MZ"
    + b"\x90" * 58  # padding
    + struct.pack("<I", 0x40)  # e_lfanew at offset 0x3C
)


def build_minimal_pe(
    *,
    imports: list[tuple[str, list[str]]] | None = None,
    extra_section_name: bytes | None = None,
    extra_section_data: bytes | None = None,
    extra_section_chars: int = 0xE0000020,
) -> bytes:
    """Build a tiny PE32+ x86_64 executable.

    ``imports`` is a list of ``(dll_name, [symbol, ...])`` that gets
    placed in an ``.idata`` section with a proper Import Directory.

    ``extra_section_*`` lets a test add a third section that triggers
    specific findings — for example a packed section with
    high-entropy payload, or a writable+executable section.
    """
    imports = imports or []

    machine = 0x8664  # AMD64
    section_align = 0x1000
    file_align = 0x200

    # ---- Lay out section contents in memory first; we need RVAs to
    #      stitch them into headers.
    text_rva = 0x1000
    text_size = 0x10  # tiny stub
    text_raw = b"\x90" * text_size  # NOPs

    idata_rva = 0x2000
    idata_blob, _idata_size = (
        _build_import_directory(imports, idata_rva)
        if imports
        else (
            b"",
            0,
        )
    )
    idata_size = len(idata_blob)

    # Extra section (e.g., a high-entropy ".upx0" packed payload).
    extra_rva = 0x3000 if extra_section_data else 0
    extra_data = extra_section_data or b""
    extra_size = len(extra_data)

    sections: list[tuple[bytes, int, int, int, int]] = []
    # name, vsize, vrva, raw_size, raw_off
    sections.append((b".text\x00\x00\x00", text_size, text_rva, text_size, 0))  # raw_off TBD
    if imports:
        sections.append((b".idata\x00\x00", idata_size, idata_rva, idata_size, 0))
    if extra_section_data:
        name = (extra_section_name or b".rdata\x00\x00")[:8].ljust(8, b"\x00")
        sections.append((name, extra_size, extra_rva, extra_size, 0))

    num_sections = len(sections)

    # ---- Header sizes -----------------------------------------------------
    dos_size = len(_DOS_STUB)  # 64
    coff_size = 24  # 4 ('PE\0\0') + 20 (COFF)
    size_opt_hdr = 240  # PE32+
    sec_table_size = num_sections * 40
    headers_end = dos_size + coff_size + size_opt_hdr + sec_table_size
    size_of_headers = _round_up(headers_end, file_align)

    # ---- Assign raw offsets for each section -----------------------------
    raw_cursor = size_of_headers
    for i, (name, vsize, vrva, rsize, _) in enumerate(sections):
        sections[i] = (name, vsize, vrva, rsize, raw_cursor)
        raw_cursor = _round_up(raw_cursor + rsize, file_align)
    image_end = raw_cursor

    # ---- Build optional header ------------------------------------------
    opt = bytearray()
    opt += struct.pack("<H", 0x20B)  # Magic PE32+
    opt += struct.pack("<BB", 14, 0)  # MajorLinkerVersion / Minor
    opt += struct.pack("<I", text_size)  # SizeOfCode
    opt += struct.pack("<I", 0)  # SizeOfInitializedData
    opt += struct.pack("<I", 0)  # SizeOfUninitializedData
    opt += struct.pack("<I", text_rva)  # AddressOfEntryPoint
    opt += struct.pack("<I", text_rva)  # BaseOfCode
    opt += struct.pack("<Q", 0x140000000)  # ImageBase (PE32+ uses 8 bytes here)
    opt += struct.pack("<I", section_align)
    opt += struct.pack("<I", file_align)
    opt += struct.pack("<HH", 6, 0)  # OS version
    opt += struct.pack("<HH", 0, 0)  # Image version
    opt += struct.pack("<HH", 6, 0)  # Subsystem version
    opt += struct.pack("<I", 0)  # Win32VersionValue
    opt += struct.pack("<I", _round_up(image_end, section_align))  # SizeOfImage
    opt += struct.pack("<I", size_of_headers)
    opt += struct.pack("<I", 0)  # CheckSum
    opt += struct.pack("<H", 3)  # Subsystem (CUI)
    opt += struct.pack("<H", 0x8160)  # DllCharacteristics
    opt += struct.pack("<Q", 0x100000)  # SizeOfStackReserve
    opt += struct.pack("<Q", 0x1000)  # SizeOfStackCommit
    opt += struct.pack("<Q", 0x100000)  # SizeOfHeapReserve
    opt += struct.pack("<Q", 0x1000)  # SizeOfHeapCommit
    opt += struct.pack("<I", 0)  # LoaderFlags
    opt += struct.pack("<I", 16)  # NumberOfRvaAndSizes

    # Data directories
    dd = [(0, 0)] * 16
    if imports:
        dd[1] = (idata_rva, idata_size)
    for rva, sz in dd:
        opt += struct.pack("<II", rva, sz)

    assert len(opt) == size_opt_hdr, f"opt header size {len(opt)} != {size_opt_hdr}"

    # ---- Build COFF header ----------------------------------------------
    coff_signature = b"PE\x00\x00"
    coff = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_opt_hdr,
        0x0022,  # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    # ---- Section table --------------------------------------------------
    sec_table = bytearray()
    for i, (name, vsize, vrva, rsize, roff) in enumerate(sections):
        if i == 0:
            chars = 0x60000020  # CNT_CODE | MEM_EXECUTE | MEM_READ
        elif imports and i == 1:
            chars = 0xC0000040  # CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
        else:
            chars = extra_section_chars
        sec_table += name
        sec_table += struct.pack(
            "<IIII",
            vsize,
            vrva,
            rsize,
            roff,
        )
        sec_table += struct.pack("<IIHHI", 0, 0, 0, 0, chars)

    assert len(sec_table) == sec_table_size

    # ---- Stitch everything together ------------------------------------
    out = bytearray()
    out += _DOS_STUB
    out += coff_signature
    out += coff
    out += opt
    out += sec_table
    # Pad to size_of_headers
    if len(out) < size_of_headers:
        out += b"\x00" * (size_of_headers - len(out))

    # Append each section's raw data at its assigned offset.
    section_raw_map = {
        0: text_raw,
        **({1: idata_blob} if imports else {}),
        **({2 if imports else 1: extra_data} if extra_section_data else {}),
    }
    for i, (_, _, _, rsize, roff) in enumerate(sections):
        if len(out) < roff:
            out += b"\x00" * (roff - len(out))
        blob = section_raw_map.get(i, b"\x00" * rsize)
        # Truncate/pad to declared rsize.
        out += blob[:rsize]
        if len(blob) < rsize:
            out += b"\x00" * (rsize - len(blob))

    # Pad to file alignment for the last section.
    if len(out) < image_end:
        out += b"\x00" * (image_end - len(out))

    return bytes(out)


def _round_up(n: int, align: int) -> int:
    return (n + align - 1) & ~(align - 1)


def _build_import_directory(
    imports: list[tuple[str, list[str]]],
    base_rva: int,
) -> tuple[bytes, int]:
    """Lay out an Import Directory + ILT + name strings.

    Layout produced (in this exact order, inside one section):

        [ import descriptor table         ]  20 * (N+1) bytes
        [ ILT entries per DLL              ]  variable
        [ IMAGE_IMPORT_BY_NAME blocks      ]  variable
        [ DLL name strings                 ]  variable
    """
    n = len(imports)
    desc_table_size = 20 * (n + 1)  # +1 for terminator

    # First pass: figure out ILT/string offsets.
    ilt_offsets: list[int] = []
    cursor = desc_table_size

    for _, syms in imports:
        ilt_offsets.append(cursor)
        cursor += 8 * (len(syms) + 1)  # PE32+ thunks, NULL-terminated

    by_name_offsets: list[list[int]] = []
    for _, syms in imports:
        offsets_for_dll: list[int] = []
        for sym in syms:
            offsets_for_dll.append(cursor)
            # 2-byte Hint + NUL-terminated name; align to even.
            block = b"\x00\x00" + sym.encode("ascii") + b"\x00"
            if len(block) % 2:
                block += b"\x00"
            cursor += len(block)
        by_name_offsets.append(offsets_for_dll)

    dll_name_offsets: list[int] = []
    for dll, _ in imports:
        dll_name_offsets.append(cursor)
        cursor += len(dll.encode("ascii")) + 1
        if cursor % 2:
            cursor += 1  # pad

    total_size = cursor
    blob = bytearray(total_size)

    # Descriptor table
    for i in range(len(imports)):
        desc_off = i * 20
        ilt_rva = base_rva + ilt_offsets[i]
        name_rva = base_rva + dll_name_offsets[i]
        iat_rva = ilt_rva  # share with ILT for simplicity (loader fixes up)
        struct.pack_into("<IIIII", blob, desc_off, ilt_rva, 0, 0, name_rva, iat_rva)
    # Terminator descriptor is already zero.

    # ILT entries
    for i, (_, syms) in enumerate(imports):
        ilt = ilt_offsets[i]
        for j, _sym in enumerate(syms):
            rva_to_byname = base_rva + by_name_offsets[i][j]
            struct.pack_into("<Q", blob, ilt + j * 8, rva_to_byname)
        # NULL terminator already zeroed.

    # IMAGE_IMPORT_BY_NAME blocks
    for i, (_, syms) in enumerate(imports):
        for j, sym in enumerate(syms):
            off = by_name_offsets[i][j]
            blob[off] = 0
            blob[off + 1] = 0  # Hint
            name_b = sym.encode("ascii") + b"\x00"
            blob[off + 2 : off + 2 + len(name_b)] = name_b

    # DLL name strings
    for i, (dll, _) in enumerate(imports):
        off = dll_name_offsets[i]
        nb = dll.encode("ascii") + b"\x00"
        blob[off : off + len(nb)] = nb

    return bytes(blob), total_size


# ---------------------------------------------------------------------------
# ELF64 minimal executable
# ---------------------------------------------------------------------------


def build_minimal_elf64(
    *,
    nx_stack: bool = True,
    e_type: int = 2,  # ET_EXEC
    high_entropy_payload: bytes | None = None,
) -> bytes:
    """Build a tiny ELF64 LE executable.

    ``nx_stack`` controls the PT_GNU_STACK p_flags. When False the
    analyser should emit an ``elf.exec_stack`` finding.
    """
    EI_MAG = b"\x7fELF"
    EI_CLASS_64 = 2
    EI_DATA_LSB = 1
    EI_VERSION = 1
    EI_OSABI_SYSV = 0
    e_machine = 0x3E  # x86_64
    e_version = 1

    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 2
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    # Compute layout.
    e_phoff = e_ehsize
    payload = high_entropy_payload or b"\x90" * 64
    payload_off = e_phoff + e_phnum * e_phentsize

    e_ident = EI_MAG + bytes([EI_CLASS_64, EI_DATA_LSB, EI_VERSION, EI_OSABI_SYSV]) + b"\x00" * 8

    # ELF64 header
    ehdr = bytearray(e_ident)
    ehdr += struct.pack("<HHI", e_type, e_machine, e_version)
    ehdr += struct.pack("<QQQ", 0x400000 + payload_off, e_phoff, 0)  # entry, phoff, shoff
    ehdr += struct.pack("<I", 0)  # flags
    ehdr += struct.pack(
        "<HHHHHH",
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )
    assert len(ehdr) == 64

    # PT_LOAD (type=1) p_flags=RX (5), spans the payload.
    phdr_load = struct.pack(
        "<II",
        1,  # p_type LOAD
        5,  # p_flags RX
    ) + struct.pack(
        "<QQQQQQ",
        payload_off,  # p_offset
        0x400000 + payload_off,  # p_vaddr
        0x400000 + payload_off,  # p_paddr
        len(payload),  # p_filesz
        len(payload),  # p_memsz
        0x1000,  # p_align
    )
    assert len(phdr_load) == 56

    # PT_GNU_STACK (type=0x6474e551). p_flags: R + W (no X) if nx_stack.
    stack_flags = 6 if nx_stack else 7
    phdr_stack = struct.pack(
        "<II",
        0x6474E551,
        stack_flags,
    ) + struct.pack(
        "<QQQQQQ",
        0,
        0,
        0,
        0,
        0,
        0,
    )
    assert len(phdr_stack) == 56

    out = bytearray(ehdr)
    out += phdr_load
    out += phdr_stack
    if len(out) < payload_off:
        out += b"\x00" * (payload_off - len(out))
    out += payload
    return bytes(out)


# ---------------------------------------------------------------------------
# Mach-O 64-bit minimal binary
# ---------------------------------------------------------------------------


def build_minimal_macho64(
    *,
    dylibs: list[str] | None = None,
    code_signature: bool = True,
    encrypted: bool = False,
    rpaths: list[str] | None = None,
) -> bytes:
    """Build a tiny Mach-O 64-bit executable with one TEXT segment.

    The dylibs list becomes ``LC_LOAD_DYLIB`` commands; the analyser
    should surface them in ``linked_libraries``.
    """
    dylibs = dylibs or ["/usr/lib/libSystem.B.dylib"]
    rpaths = rpaths or []

    MH_MAGIC_64 = 0xFEEDFACF
    CPU_TYPE_X86_64 = 7 | 0x01000000
    CPU_SUBTYPE_X86_64_ALL = 3
    MH_EXECUTE = 2
    MH_FLAGS = 0x200000 | 0x4  # MH_PIE | MH_DYLDLINK

    LC_SEGMENT_64 = 0x19
    LC_LOAD_DYLIB = 0xC
    LC_CODE_SIGNATURE = 0x1D
    LC_ENCRYPTION_INFO_64 = 0x2C
    LC_RPATH = 0x1C | 0x80000000
    LC_MAIN = 0x28 | 0x80000000

    # Build load commands.
    commands: list[bytes] = []

    # LC_SEGMENT_64 for __TEXT
    seg_cmd_size = 72  # no sections
    seg_cmd = struct.pack("<II", LC_SEGMENT_64, seg_cmd_size)
    seg_cmd += b"__TEXT".ljust(16, b"\x00")
    seg_cmd += struct.pack("<QQQQ", 0x100000000, 0x1000, 0, 0x1000)
    seg_cmd += struct.pack("<II", 5, 5)  # maxprot RX, initprot RX
    seg_cmd += struct.pack("<II", 0, 0)  # nsects, flags
    assert len(seg_cmd) == seg_cmd_size
    commands.append(seg_cmd)

    # LC_LOAD_DYLIB for each.
    for d in dylibs:
        name_b = d.encode("utf-8") + b"\x00"
        cmd_size = (24 + len(name_b) + 7) & ~7  # 8-byte align
        body = (
            struct.pack("<II", LC_LOAD_DYLIB, cmd_size)
            + struct.pack("<I", 24)  # str offset
            + struct.pack("<III", 0, 0, 0)  # ts, cur, compat
            + name_b
        )
        body += b"\x00" * (cmd_size - len(body))
        commands.append(body)

    # LC_RPATH for each rpath
    for rp in rpaths:
        name_b = rp.encode("utf-8") + b"\x00"
        cmd_size = (12 + len(name_b) + 7) & ~7
        body = struct.pack("<II", LC_RPATH, cmd_size) + struct.pack("<I", 12) + name_b
        body += b"\x00" * (cmd_size - len(body))
        commands.append(body)

    # LC_MAIN
    main_cmd = struct.pack("<II", LC_MAIN, 24) + struct.pack("<QQ", 0x1000, 0)
    commands.append(main_cmd)

    if code_signature:
        # cmd, cmdsize, dataoff, datasize
        commands.append(
            struct.pack("<II", LC_CODE_SIGNATURE, 16) + struct.pack("<II", 0x2000, 0x100)
        )

    if encrypted:
        commands.append(
            struct.pack("<II", LC_ENCRYPTION_INFO_64, 24)
            + struct.pack("<III", 0x1000, 0x1000, 1)
            + struct.pack("<I", 0)
        )

    sizeofcmds = sum(len(c) for c in commands)
    ncmds = len(commands)

    # Mach-O header (32 bytes, 64-bit)
    hdr = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        MH_EXECUTE,
        ncmds,
        sizeofcmds,
        MH_FLAGS,
        0,  # reserved
    )

    out = bytearray(hdr)
    for c in commands:
        out += c
    # Pad to 0x2000 so the (fake) code signature offset lands inside the file.
    if len(out) < 0x2100:
        out += b"\x00" * (0x2100 - len(out))
    return bytes(out)


def build_fat_macho(slices: list[bytes]) -> bytes:
    """Wrap multiple Mach-O slices in a FAT/universal header."""
    FAT_MAGIC = 0xCAFEBABE
    header = struct.pack(">II", FAT_MAGIC, len(slices))
    cursor = 8 + 20 * len(slices)
    # Round to 0x1000.
    cursor = (cursor + 0xFFF) & ~0xFFF
    arch_table = bytearray()
    blob = bytearray()
    for i, sl in enumerate(slices):
        cputype = 7 | 0x01000000 if i == 0 else 12 | 0x01000000
        arch_table += struct.pack(">IIIII", cputype, 3, cursor, len(sl), 12)
        # Pad blob so this slice lands at `cursor`.
        if 8 + 20 * len(slices) + len(blob) < cursor:
            blob += b"\x00" * (cursor - (8 + 20 * len(slices) + len(blob)))
        blob += sl
        cursor = (cursor + len(sl) + 0xFFF) & ~0xFFF
    return bytes(header + bytes(arch_table) + bytes(blob))
