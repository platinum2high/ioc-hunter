"""Cross-cutting behavioural rules.

The format-specific analyzers (``pe.py`` / ``elf.py`` / ``macho.py``)
emit *atomic* findings — "TLS directory present", "high-entropy section",
"W+X segment". This module is where atomic facts get combined into
*behaviour* — "process-injection toolkit", "keylogger present",
"credential stealer".

The rules are deliberately narrow. A high-precision rule is far more
useful on a SOC desk than a noisy one: if ``rules.dpapi_credential_theft``
fires you know to spend the next hour on the sample. We trade recall
for that signal-to-noise.

Each rule is a free function so it's trivially testable in isolation;
``apply_heuristics`` walks them and appends to ``report.findings``.

Severity ladder used here:
- LOW: combinations that are slightly unusual on their own.
- MEDIUM: behaviour we'd flag in a code review of an unknown binary.
- HIGH: behaviour with low benign baseline (kernel32+ntdll+inject combo,
  service install, DPAPI dump).
- CRITICAL: a textbook combo with essentially no benign use case.
"""

from __future__ import annotations

from collections.abc import Iterable

from ioc_hunter.analyze.common import (
    WIN_ANTI_DEBUG_APIS,
    WIN_ANTI_VM_APIS,
    WIN_CRYPTO_APIS,
    WIN_INFOSTEALER_APIS,
    WIN_INJECTION_APIS,
    WIN_NETWORK_APIS,
    WIN_PERSISTENCE_APIS,
    AnalyzerReport,
    FileFormat,
    Finding,
    Severity,
)


def _all_symbols(report: AnalyzerReport) -> set[str]:
    """All importable symbol names referenced by the binary."""
    syms: set[str] = set()
    for imp in report.imports:
        syms.update(imp.symbols)
    extra = report.metadata.get("dyn_symbols")
    if isinstance(extra, Iterable):
        syms.update(s for s in extra if isinstance(s, str))
    return syms


# ---------------------------------------------------------------------------
# Per-rule helpers
# ---------------------------------------------------------------------------


def _rule_injection(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    hits = syms & WIN_INJECTION_APIS
    if len(hits) >= 3:
        return Finding(
            rule="combo.process_injection",
            severity=Severity.CRITICAL,
            category="injection",
            message=f"Process-injection toolkit: {len(hits)} matching APIs.",
            evidence=tuple(sorted(hits)),
        )
    if len(hits) == 2:
        return Finding(
            rule="combo.process_injection_partial",
            severity=Severity.MEDIUM,
            category="injection",
            message="Partial process-injection signature (2 APIs).",
            evidence=tuple(sorted(hits)),
        )
    return None


def _rule_anti_debug(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    hits = syms & WIN_ANTI_DEBUG_APIS
    if len(hits) >= 3:
        return Finding(
            rule="combo.anti_debug",
            severity=Severity.MEDIUM,
            category="anti_debug",
            message=f"Anti-debug battery: {len(hits)} APIs.",
            evidence=tuple(sorted(hits)),
        )
    return None


def _rule_anti_vm(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    hits = syms & WIN_ANTI_VM_APIS
    if len(hits) >= 2:
        return Finding(
            rule="combo.anti_vm",
            severity=Severity.MEDIUM,
            category="anti_vm",
            message=f"Sandbox/VM enumeration: {len(hits)} APIs.",
            evidence=tuple(sorted(hits)),
        )
    return None


def _rule_persistence(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    hits = syms & WIN_PERSISTENCE_APIS

    service_install = bool(
        {"CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"} & syms
        and {"OpenSCManagerA", "OpenSCManagerW"} & syms
    )
    if service_install:
        return Finding(
            rule="combo.service_install",
            severity=Severity.HIGH,
            category="persistence",
            message="Service-install persistence (OpenSCManager + CreateService).",
            evidence=tuple(
                sorted(
                    hits
                    & ({"CreateServiceA", "CreateServiceW"} | {"OpenSCManagerA", "OpenSCManagerW"})
                )
            ),
        )

    reg_run = bool(
        {"RegCreateKeyExA", "RegCreateKeyExW", "RegOpenKeyExA", "RegOpenKeyExW"} & syms
        and {"RegSetValueExA", "RegSetValueExW"} & syms
    )
    if reg_run:
        return Finding(
            rule="combo.registry_persistence",
            severity=Severity.MEDIUM,
            category="persistence",
            message="Registry write toolkit (RegOpen/Create + RegSetValue).",
            evidence=tuple(sorted(hits & WIN_PERSISTENCE_APIS)),
        )
    return None


def _rule_keylogger(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    if ("GetAsyncKeyState" in syms and "GetForegroundWindow" in syms) or (
        "SetWindowsHookExA" in syms or "SetWindowsHookExW" in syms
    ):
        evidence = tuple(
            s
            for s in (
                "GetAsyncKeyState",
                "GetForegroundWindow",
                "SetWindowsHookExA",
                "SetWindowsHookExW",
                "GetWindowTextA",
                "GetWindowTextW",
            )
            if s in syms
        )
        if evidence:
            return Finding(
                rule="combo.keylogger",
                severity=Severity.HIGH,
                category="infostealer",
                message="Keylogger pattern: keystate polling and/or low-level keyboard hook.",
                evidence=evidence,
            )
    return None


def _rule_screenshot(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    needed = {"BitBlt", "CreateCompatibleBitmap", "GetDC"}
    if len(syms & needed) >= 2:
        return Finding(
            rule="combo.screenshot_capture",
            severity=Severity.HIGH,
            category="infostealer",
            message="Screenshot-capture pipeline (GDI BitBlt path).",
            evidence=tuple(sorted(syms & needed)),
        )
    return None


def _rule_clipboard(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    needed = {"GetClipboardData", "OpenClipboard"}
    if needed.issubset(syms):
        return Finding(
            rule="combo.clipboard_stealer",
            severity=Severity.MEDIUM,
            category="infostealer",
            message="Clipboard-read pattern (OpenClipboard + GetClipboardData).",
            evidence=tuple(sorted(needed)),
        )
    return None


def _rule_dpapi(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    if "CryptUnprotectData" in syms:
        return Finding(
            rule="combo.dpapi_dump",
            severity=Severity.HIGH,
            category="infostealer",
            message="CryptUnprotectData — DPAPI secret unwrap (browser credential theft).",
            evidence=("CryptUnprotectData",),
        )
    return None


def _rule_dynamic_resolution(report: AnalyzerReport) -> Finding | None:
    """GetProcAddress + LoadLibrary{A,W} is the classic API hashing /
    runtime resolution pattern. Benign apps use it too (plugin loaders),
    so on its own it's LOW; we bump it to MEDIUM when paired with
    high-entropy code or with packer findings."""
    syms = _all_symbols(report)
    has_resolve = "GetProcAddress" in syms and (
        "LoadLibraryA" in syms or "LoadLibraryW" in syms or "LoadLibraryExA" in syms
    )
    if not has_resolve:
        return None
    aggravator = report.is_packed or any(
        s.entropy >= 7.0 and s.raw_size > 1024 for s in report.sections
    )
    sev = Severity.MEDIUM if aggravator else Severity.LOW
    return Finding(
        rule="combo.dynamic_resolution",
        severity=sev,
        category="injection",
        message="Runtime API resolution (LoadLibrary + GetProcAddress)"
        + (" combined with high-entropy code." if aggravator else "."),
        evidence=("GetProcAddress", "LoadLibrary*"),
    )


def _rule_network_combo(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    hits = syms & WIN_NETWORK_APIS
    if not hits:
        return None
    has_http = bool(
        {"InternetOpenA", "InternetOpenW", "WinHttpOpen", "HttpOpenRequestA", "HttpOpenRequestW"}
        & syms
    )
    has_sockets = bool({"socket", "WSASocketA", "WSASocketW", "WSAStartup", "connect"} & syms)
    has_dns = bool({"DnsQuery_A", "DnsQuery_W", "gethostbyname", "getaddrinfo"} & syms)
    crypto_hits = syms & WIN_CRYPTO_APIS
    if has_http and crypto_hits:
        return Finding(
            rule="combo.crypto_c2",
            severity=Severity.MEDIUM,
            category="c2",
            message="HTTP + crypto APIs — likely encrypted C2 traffic.",
            evidence=tuple(sorted(hits | crypto_hits)),
        )
    if has_sockets and has_dns:
        return Finding(
            rule="combo.raw_socket_c2",
            severity=Severity.LOW,
            category="c2",
            message="Raw socket + DNS resolution — bespoke network channel.",
            evidence=tuple(sorted(hits)),
        )
    return None


def _rule_infostealer_combo(report: AnalyzerReport) -> Finding | None:
    syms = _all_symbols(report)
    hits = syms & WIN_INFOSTEALER_APIS
    if len(hits) >= 4:
        return Finding(
            rule="combo.infostealer_battery",
            severity=Severity.HIGH,
            category="infostealer",
            message=f"Multi-vector infostealer: {len(hits)} clipboard/keylog/screen APIs.",
            evidence=tuple(sorted(hits)),
        )
    return None


def _rule_no_imports(report: AnalyzerReport) -> Finding | None:
    """A non-driver PE with zero imports is wildly suspicious — it means
    code is resolving APIs at runtime through hashing or syscalls."""
    if report.format != FileFormat.PE:
        return None
    if report.metadata.get("dotnet"):
        return None
    if report.imports:
        return None
    return Finding(
        rule="pe.no_imports",
        severity=Severity.HIGH,
        category="injection",
        message="PE has zero imports — APIs are resolved at runtime (hashing, syscall, manual mapping).",
    )


def _rule_packed_with_few_imports(report: AnalyzerReport) -> Finding | None:
    """Packer signature + tiny import table is the canonical 'unpack stub'
    look. We don't double-fire if no_imports already fired."""
    if not report.is_packed:
        return None
    import_count = sum(len(i.symbols) for i in report.imports)
    # 3 is a reasonable cutoff: a UPX-packed binary typically imports
    # LoadLibraryA, GetProcAddress, ExitProcess and that's it.
    if 0 < import_count <= 6:
        return Finding(
            rule="combo.packed_thin_imports",
            severity=Severity.MEDIUM,
            category="packer",
            message=f"Packer + minimal import table ({import_count}) — runtime unpacker stub.",
        )
    return None


# ---- POSIX-side combos -----------------------------------------------------


def _rule_posix_reverse_shell(report: AnalyzerReport) -> Finding | None:
    if report.format not in (FileFormat.ELF, FileFormat.MACHO):
        return None
    syms = _all_symbols(report)
    if {"socket", "connect"} <= syms and {"execve", "execvp", "execv"} & syms and "dup2" in syms:
        return Finding(
            rule="combo.posix_reverse_shell",
            severity=Severity.HIGH,
            category="c2",
            message="Reverse-shell pattern: socket + connect + dup2 + execve.",
            evidence=("socket", "connect", "dup2", "execve"),
        )
    return None


def _rule_posix_loader(report: AnalyzerReport) -> Finding | None:
    if report.format not in (FileFormat.ELF, FileFormat.MACHO):
        return None
    syms = _all_symbols(report)
    if {"dlopen", "dlsym", "mprotect"} <= syms:
        return Finding(
            rule="combo.posix_in_memory_loader",
            severity=Severity.MEDIUM,
            category="injection",
            message="In-memory loader pattern (dlopen + dlsym + mprotect).",
            evidence=("dlopen", "dlsym", "mprotect"),
        )
    return None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


_RULES = (
    _rule_injection,
    _rule_anti_debug,
    _rule_anti_vm,
    _rule_persistence,
    _rule_keylogger,
    _rule_screenshot,
    _rule_clipboard,
    _rule_dpapi,
    _rule_dynamic_resolution,
    _rule_network_combo,
    _rule_infostealer_combo,
    _rule_no_imports,
    _rule_packed_with_few_imports,
    _rule_posix_reverse_shell,
    _rule_posix_loader,
)


def apply_heuristics(report: AnalyzerReport) -> None:
    """Run every behavioural rule and append findings to the report."""
    for rule in _RULES:
        try:
            f = rule(report)
        except Exception:
            # A buggy rule should not break the whole analyser.
            continue
        if f is not None:
            report.add(f)
