"""Mandiant-style PE import hash (``imphash``).

The de-facto industry pivot for PE binaries: every PE security
platform — VirusTotal, MalwareBazaar, ANY.RUN, Hybrid Analysis,
Joe Sandbox — surfaces it. Samples from the same compiled source
import the same DLLs in the same order with the same symbol names,
so the MD5 of that flattened list groups variants beautifully.

Algorithm (per Mandiant's original FLOSS / Stuxnet write-up):

1. For each ``(dll, function)`` pair, in IAT order:
   - Lowercase the DLL name.
   - If the DLL ends in ``.dll``, ``.ocx`` or ``.sys`` strip that suffix.
   - For ordinal-only imports, render as ``ord<N>``.
   - Lowercase the function name.
2. Join all pairs with ``,`` as ``"<dll>.<func>,<dll>.<func>,..."``.
3. MD5-hexdigest the joined string.

The result is the canonical 32-char lowercase hex.
"""

from __future__ import annotations

import hashlib

from ioc_hunter.analyze.common import Import

_STRIP_SUFFIXES = (".dll", ".ocx", ".sys")


def _normalize_dll(name: str) -> str:
    n = name.lower()
    for suf in _STRIP_SUFFIXES:
        if n.endswith(suf):
            return n[: -len(suf)]
    return n


def compute_imphash(imports: list[Import]) -> str:
    """Return the 32-char hex ``imphash`` over an import list.

    Empty input returns ``""`` rather than the MD5 of an empty string —
    callers use the falsy value to decide whether to surface the field.
    """
    if not imports:
        return ""
    pairs: list[str] = []
    for imp in imports:
        # Skip the "(delayed)" markers we add to the library name when
        # walking the delay-import directory — they would corrupt the
        # pivot. The real DLL name is the part before " (delayed)".
        lib_raw = imp.library
        if " (delayed)" in lib_raw:
            lib_raw = lib_raw.split(" (delayed)", 1)[0]
        dll = _normalize_dll(lib_raw)
        for sym in imp.symbols:
            s = sym.lower()
            # Ordinal-only symbols are emitted as ``#NNN`` by our parser;
            # the canonical imphash uses ``ord<N>`` instead.
            if s.startswith("#") and s[1:].isdigit():
                s = "ord" + s[1:]
            pairs.append(f"{dll}.{s}")
    if not pairs:
        return ""
    joined = ",".join(pairs)
    return hashlib.md5(joined.encode("utf-8")).hexdigest()
