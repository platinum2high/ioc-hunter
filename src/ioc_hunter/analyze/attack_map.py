"""Tag findings with MITRE ATT&CK technique IDs.

Static-analysis findings are *behaviours*; SOC analysts pivot via
ATT&CK technique IDs. We keep a small, opinionated table mapping each
of our rules to one or more ATT&CK techniques (and sub-techniques
where applicable). The mapping is conservative — we only tag rules
where the implied behaviour is unambiguous.

After ``apply_heuristics`` runs we walk every finding and rewrite its
``mitre`` tuple. Rewriting (not in-place mutation) preserves the
frozen-dataclass invariant.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations

from ioc_hunter.analyze.common import AnalyzerReport, Finding

# Rule → ATT&CK technique IDs.
_MAP: dict[str, tuple[str, ...]] = {
    # ---- Injection ---------------------------------------------------------
    "combo.process_injection": ("T1055",),
    "combo.process_injection_partial": ("T1055",),
    "combo.dynamic_resolution": ("T1620", "T1027"),  # Reflective Code Loading, Obfuscation
    "combo.posix_in_memory_loader": ("T1620",),
    "macho.mach_injection": ("T1055.009",),  # Proc Memory (mach_vm_*)
    "pe.no_imports": ("T1027", "T1027.007"),  # Dynamic API Resolution
    # ---- Persistence -------------------------------------------------------
    "combo.service_install": ("T1543.003",),  # New Service (Windows)
    "combo.registry_persistence": ("T1547.001",),  # Registry Run Keys
    "pe.manifest_autoelevate": ("T1548.002",),  # UAC Bypass
    "pe.manifest_admin": ("T1548.002",),
    "pe.manifest_uiaccess": ("T1548",),
    # ---- Defence evasion ---------------------------------------------------
    "pe.tls_callbacks": ("T1497",),  # Sandbox / VM evasion via TLS
    "combo.anti_debug": ("T1622",),  # Debugger Evasion
    "elf.ptrace": ("T1622",),
    "macho.ptrace": ("T1622",),
    "combo.anti_vm": ("T1497",),
    "pe.packer_signature": ("T1027.002",),  # Software Packing
    "elf.packer_signature": ("T1027.002",),
    "macho.packer_signature": ("T1027.002",),
    "pe.high_entropy_section": ("T1027.002",),
    "pe.overlay_high_entropy": ("T1027.002",),
    "combo.packed_thin_imports": ("T1027.002",),
    "pe.wx_section": ("T1055",),
    "elf.wx_segment": ("T1055",),
    "macho.wx_segment": ("T1055",),
    "macho.encrypted": ("T1027",),
    # ---- Credentials -------------------------------------------------------
    "combo.dpapi_dump": ("T1555.003",),  # Credentials from Web Browsers
    # ---- Collection --------------------------------------------------------
    "combo.keylogger": ("T1056.001",),  # Keylogging
    "combo.screenshot_capture": ("T1113",),  # Screen Capture
    "combo.clipboard_stealer": ("T1115",),
    "combo.infostealer_battery": ("T1056.001", "T1113", "T1115"),
    # ---- Command & control -------------------------------------------------
    "combo.crypto_c2": ("T1573.001", "T1071.001"),  # Encrypted C2 over HTTP
    "combo.raw_socket_c2": ("T1095",),  # Non-Application Layer C2
    "combo.posix_reverse_shell": ("T1059.004", "T1071"),  # Unix Shell + App Layer C2
    "c2.cobalt_strike_beacon_marker": ("T1071.001", "T1573.001"),
    "c2.cobalt_strike_xor_marker": ("T1071.001", "T1573.001"),
    # ---- Discovery / staging -----------------------------------------------
    "embedded.pe": ("T1027.009",),  # Embedded Payloads
    "embedded.elf": ("T1027.009",),
    "embedded.macho": ("T1027.009",),
    "embedded.archive": ("T1027.009",),
    "pe.embedded_pe_in_resources": ("T1027.009",),
    # ---- Shellcode ---------------------------------------------------------
    "shellcode.msfvenom_x64": ("T1059.001", "T1027"),
    "shellcode.msfvenom_x86_hash": ("T1059.001", "T1027"),
    "shellcode.metasploit_egghunter": ("T1059.001",),
    "shellcode.donut_loader": ("T1620",),
    # ---- macOS entitlements ------------------------------------------------
    "macho.ent_disable_library_validation": ("T1055.001", "T1574"),
    "macho.ent_allow_unsigned_exec": ("T1620",),
    "macho.ent_dyld_env": ("T1574.006",),  # Dynamic Linker Hijacking
    "macho.ent_disable_page_protection": ("T1055",),
    "macho.ent_get_task_allow": ("T1622",),
    # ---- Entry / timestamp -------------------------------------------------
    "pe.entry_outside_sections": ("T1027",),
    "pe.entry_in_nonexec_section": ("T1027",),
    "pe.timestamp_ancient": ("T1070.006",),  # Timestomp
    "pe.timestamp_future": ("T1070.006",),
    # ---- PDF document analyzer (phase 14.2a) -------------------------------
    "pdf.javascript": ("T1059.005", "T1204.002"),  # VB scripting / User Execution
    "pdf.js_shortform": ("T1059.005", "T1204.002"),
    "pdf.auto_javascript": ("T1059.005", "T1204.002"),
    "pdf.launch_action": ("T1204.002", "T1218"),  # User Execution / System Binary Proxy
    "pdf.gotor_remote": ("T1187",),  # Forced Authentication (UNC → SMB NTLM leak)
    "pdf.submit_form": ("T1567",),  # Exfiltration Over Web Service
    "pdf.rich_media": ("T1203",),  # Exploitation for Client Execution
    "pdf.jbig2_filter": ("T1203",),
    "pdf.embedded_file": ("T1027.009", "T1204.002"),  # Embedded Payloads
    "pdf.open_action": ("T1204.002",),
    "pdf.additional_actions": ("T1204.002",),
    "pdf.js_obfuscation": ("T1027", "T1059.005"),
    "pdf.filter_chain": ("T1027",),
    "pdf.uri": ("T1204.001",),  # Malicious Link
    "pdf.movie": ("T1203",),
    # ---- OOXML / OLE / VBA (phase 14.2a) -----------------------------------
    "ooxml.macro_enabled": ("T1204.002", "T1566.001"),
    "ooxml.external_relationship": ("T1221", "T1566.001"),  # Template Injection
    "ooxml.msdt_scheme": ("T1218", "T1566.001"),  # Follina (CVE-2022-30190)
    "ooxml.dde_field": ("T1559.002", "T1204.002"),  # Dynamic Data Exchange
    "ole.vba_project": ("T1204.002", "T1566.001"),
    "ole.equation_editor": ("T1203",),  # CVE-2017-11882
    "ole.suspicious_clsid": ("T1218",),
    "ole.ole10native": ("T1027.009", "T1204.002"),
    "vba.auto_exec": ("T1204.002", "T1137.001"),  # Office Application Startup
    "vba.suspicious_api": ("T1059.005",),
    "vba.lolbin_spawn": ("T1218", "T1059"),
    "vba.encoded_powershell": ("T1027", "T1059.001", "T1059.005"),
    "vba.obfuscation_density": ("T1027",),
    "vba.obfuscation_present": ("T1027",),
    # ---- RTF analyzer (phase 14.2b) ----------------------------------------
    "rtf.equation_editor_3": ("T1203", "T1566.001"),  # CVE-2017-11882
    "rtf.equation_editor_2": ("T1203", "T1566.001"),  # CVE-2018-0802
    "rtf.ole2link": ("T1203", "T1566.001"),  # CVE-2017-0199
    "rtf.package_dropper": ("T1027.009", "T1204.002"),
    "rtf.embedded_word": ("T1566.001",),
    "rtf.auto_object_fire": ("T1204.002", "T1203"),
    "rtf.objocx": ("T1559.001", "T1204.002"),  # Component Object Model
    "rtf.raw_binary_blob": ("T1027",),
    "rtf.embedded_cfb": ("T1027.009", "T1203"),
    "rtf.equation_native_payload": ("T1203", "T1566.001"),
    # ---- PCAP analyzer (phase 14.3a) ---------------------------------------
    "pcap.beaconing": ("T1071.001", "T1573", "T1029"),  # App-layer C2 + scheduled
    "pcap.port_scan": ("T1046",),  # Network Service Scanning
    "pcap.host_sweep": ("T1018",),  # Remote System Discovery
    "pcap.unidirectional_exfil": ("T1041", "T1567"),  # Exfil over C2 / Web Service
    "pcap.dga_dns": ("T1568.002",),  # Domain Generation Algorithms
    "pcap.dga_dns_outlier": ("T1568.002",),
    "pcap.dns_tunneling_txt_volume": ("T1071.004", "T1572"),  # DNS / Protocol Tunnel
    "pcap.dns_tunneling_query_rate": ("T1071.004", "T1572"),
    "pcap.high_nxdomain_ratio": ("T1568.002",),
    "pcap.plaintext_ftp_creds": ("T1040",),  # Network Sniffing (exposed creds)
    "pcap.plaintext_http_basic": ("T1040",),
    "pcap.icmp_tunnel": ("T1095", "T1572"),  # Non-App-Layer C2
    "pcap.suspicious_user_agent": ("T1071.001",),
    # ---- TLS fingerprint / SMB / NTLM / Kerberos (phase 14.3b) -------------
    "pcap.ja3_known_bad": ("T1071.001", "T1573.001"),  # App-layer + encrypted C2
    "pcap.ja3s_known_bad": ("T1071.001", "T1573.001"),
    "pcap.tls_non_standard_port": ("T1571", "T1573.001"),  # Non-Standard Port
    "pcap.tls_no_sni": ("T1071.001",),
    "pcap.smb_admin_share": ("T1021.002", "T1570"),  # SMB Admin Shares / Lateral Tool Transfer
    "pcap.smb1_in_use": ("T1210",),  # Exploitation of Remote Services (MS17-010 transport)
    "pcap.netntlmv2_capture": ("T1040", "T1557.001"),  # Sniffing / LLMNR-NBT-NS + SMB relay
    "pcap.kerberoasting": ("T1558.003",),  # Kerberoasting
    "pcap.asrep_roasting": ("T1558.004",),  # AS-REP Roasting
    "pcap.kerberos_rc4_downgrade": ("T1558.003", "T1550"),
    # ---- Recursive archive analyzer (phase 14.3b) -------------------------
    "archive.executable_payload": ("T1204.002", "T1566.001"),  # User Execution / attachment
    "archive.encrypted_member": ("T1027", "T1027.002"),  # Obfuscation to evade AV
    "archive.member_malicious": ("T1027.009",),  # Embedded Payloads
    "archive.member_suspicious": ("T1027.009",),
}


def tag_findings(report: AnalyzerReport) -> None:
    """Rewrite every finding to carry its ATT&CK technique IDs."""
    new: list[Finding] = []
    for f in report.findings:
        techniques = _MAP.get(f.rule, ())
        if not techniques:
            new.append(f)
            continue
        # Findings are frozen dataclasses — recreate with the new tuple.
        new.append(
            Finding(
                rule=f.rule,
                severity=f.severity,
                category=f.category,
                message=f.message,
                evidence=f.evidence,
                mitre=techniques,
            )
        )
    report.findings = new


def all_techniques(report: AnalyzerReport) -> list[str]:
    """Unique, sorted technique IDs covered by the report's findings."""
    seen: set[str] = set()
    for f in report.findings:
        seen.update(f.mitre)
    return sorted(seen)
