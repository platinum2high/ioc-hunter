# IOC Hunter Report

_Generated:_ `2026-06-13T11:31:31+00:00`  |  _Indicators:_ **10**

## Summary

| Verdict | Count |
| ------- | ----- |
| MALICIOUS | 5 |
| SUSPICIOUS | 1 |
| BENIGN | 1 |
| UNKNOWN | 3 |

## Indicators

### 1. `CVE-2024-21762` — cve — **MALICIOUS** (100%)

**Tags:** actively_exploited_kev, fortigate, CVE-2022-40684, CVE-2024-21762, z0r0, edge-device, access-broker, auth-bypass

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| otx | malicious | 1.00 | actively_exploited_kev, fortigate, CVE-2022-40684, CVE-2024-21762, z0r0 |

**References:**

- https://otx.alienvault.com/indicator/cve/CVE-2024-21762

---

### 2. `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` — sha256 — **MALICIOUS** (48%)

**Tags:** windows, malware, ioc, threat-hunting, malware, ransomware, windows, phishing, auditoria, academico, cobalt-strike, cryptomining, lab, Windows, training, via-tor, detect-debug-environment, powershell, long-sleeps, known-distributor, idle, attachment, direct-cpu-clock-access

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| otx | malicious | 1.00 | windows, malware, ioc, threat-hunting, malware, ransomware, windows, phishing |
| virustotal | malicious | 0.97 | via-tor, detect-debug-environment, powershell, long-sleeps, known-distributor |

**References:**

- https://otx.alienvault.com/indicator/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
- https://www.virustotal.com/gui/search/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

---

### 3. `185[.]220[.]101[.]42` — ipv4 — **MALICIOUS** (46%)

**Tags:** tor, anonymizer, country:DE, usage:Commercial, isp:Network for Tor-Exit traffic., Bruteforce, Brute-Force, SSH, Honeypot, webscanner, bruteforce, web app attack, probing, webscan, scanning, suspicious-udp

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| tor_exit | suspicious | 0.50 | tor, anonymizer |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| abuseipdb | malicious | 1.00 | country:DE, usage:Commercial, isp:Network for Tor-Exit traffic. |
| otx | malicious | 1.00 | Bruteforce, Brute-Force, SSH, Honeypot, webscanner, bruteforce, web app attack |
| virustotal | malicious | 0.15 | suspicious-udp, tor |

**References:**

- https://check.torproject.org/torbulkexitlist
- https://www.abuseipdb.com/check/185.220.101.42
- https://otx.alienvault.com/indicator/IPv4/185.220.101.42
- https://www.virustotal.com/gui/search/185.220.101.42

---

### 4. `185[.]220[.]101[.]99` — ipv4 — **MALICIOUS** (46%)

**Tags:** tor, anonymizer, country:DE, usage:Commercial, isp:Digitalcourage e.V., Bruteforce, Brute-Force, SSH, Honeypot, suspicious-udp

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| tor_exit | suspicious | 0.50 | tor, anonymizer |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| abuseipdb | malicious | 1.00 | country:DE, usage:Commercial, isp:Digitalcourage e.V. |
| otx | malicious | 1.00 | Bruteforce, Brute-Force, SSH, Honeypot |
| virustotal | malicious | 0.13 | tor, suspicious-udp |

**References:**

- https://check.torproject.org/torbulkexitlist
- https://www.abuseipdb.com/check/185.220.101.99
- https://otx.alienvault.com/indicator/IPv4/185.220.101.99
- https://www.virustotal.com/gui/search/185.220.101.99

---

### 5. `8[.]8[.]8[.]8` — ipv4 — **BENIGN** (37%)

**Tags:** country:US, usage:Content Delivery Network, isp:Google LLC

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| tor_exit | unknown | 0.00 |  |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| abuseipdb | benign | 0.00 | country:US, usage:Content Delivery Network, isp:Google LLC |
| otx | unknown | 0.00 |  |
| virustotal | benign | 0.00 |  |

**References:**

- https://www.abuseipdb.com/check/8.8.8.8
- https://otx.alienvault.com/indicator/IPv4/8.8.8.8
- https://www.virustotal.com/gui/search/8.8.8.8

---

### 6. `evil[.]com` — domain — **MALICIOUS** (36%)

**Tags:** ssl certificate, network, malware, whois record, contacted, pegasus, resolutions, communicating, sa victim, assaulter, quasar, brian sabey, go.sabey, ioc search, new ioc, teams api, contact, threat analyzer, threat, paste, iocs, urls https, samples, united, aaaa

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| otx | malicious | 1.00 | ssl certificate, network, malware, whois record, contacted |
| virustotal | malicious | 0.05 |  |

**References:**

- https://otx.alienvault.com/indicator/domain/evil.com
- https://www.virustotal.com/gui/search/evil.com

---

### 7. `hxxps://evil[.]com/login[.]php` — url — **SUSPICIOUS** (13%)

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| otx | unknown | 0.00 |  |
| virustotal | malicious | 0.07 |  |

**References:**

- https://otx.alienvault.com/indicator/url/https://evil.com/login.php
- https://www.virustotal.com/gui/search/https://evil.com/login.php

---

### 8. `1BoatSLRHtKNngkdXEeobR76b53LETtpyT` — btc_address — **UNKNOWN** (0%)

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |

---

### 9. `bad[@]evil[.]com` — email — **UNKNOWN** (0%)

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| threatfox | unknown | 0.00 |  |

---

### 10. `hxxps://evil[.]com/install[.]exe` — url — **UNKNOWN** (0%)

**Per-source results:**

| Source | Verdict | Score | Notes |
| ------ | ------- | ----- | ----- |
| urlhaus | unknown | 0.00 |  |
| threatfox | unknown | 0.00 |  |
| otx | unknown | 0.00 |  |
| virustotal | unknown | 0.00 |  |

**References:**

- https://otx.alienvault.com/indicator/url/https://evil.com/install.exe

---
