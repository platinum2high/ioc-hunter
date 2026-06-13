# IOC Hunter

> Async threat intelligence correlation engine for SOC analysts.
> Paste in a phishing report, get back verdicts from six TI feeds,
> a correlation graph, and ready-to-deploy Sigma / Suricata / STIX / MISP.

[![CI](https://github.com/platinum2high/ioc-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/platinum2high/ioc-hunter/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-217%20passing-brightgreen)

---

## ⚡ Works keyless out of the box

You don't need any API keys to try it. Clone, install, run — the
**Tor exit** source works immediately with no signup, so you can demo
the whole pipeline (parsing, defang, scoring, output, correlation,
exporters, decoder) without registering for anything.

```bash
git clone https://github.com/platinum2high/ioc-hunter
cd ioc-hunter
python -m venv .venv && source .venv/bin/activate
pip install -e .
ioc-hunter check "185[.]220[.]101[.]42"   # ← works right now, no key needed
```

For **the other five sources** (URLhaus, ThreatFox, AbuseIPDB, OTX,
VirusTotal) you need free API keys — they all register in under a minute
and the tool walks you through it with `ioc-hunter configure`. Without
them, those sources return `UNKNOWN` with a clear "missing API key"
message — they don't crash, just gracefully skip.

---

## What it does that other IOC tools don't

| Capability | Most IOC checkers | IOC Hunter |
| --- | --- | --- |
| Input | one IOC at a time | drag in a whole report |
| Defang-aware | usually no | `evil[.]com`, `hxxp://`, `[at]` all understood |
| Sources | 1 (usually VT) | 6 in parallel: VT, AbuseIPDB, OTX, URLhaus, ThreatFox, Tor exit |
| Scoring | bad/good | transparent weighted model with per-source contribution |
| Output | terminal text | JSON, Markdown, **STIX 2.1**, **MISP**, **Sigma**, **Suricata** |
| Correlation | none | shared-subnet + shared-tag pivots across the batch |
| Decoding | none | base64 / hex / URL / JWT / gzip / zlib + magic auto-detect |
| Cache | none | SQLite with TTL — survives across runs, doesn't burn API quota |

---

## Install

### 1. Clone and create a virtualenv

```bash
git clone https://github.com/platinum2high/ioc-hunter
cd ioc-hunter
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
```

### 2. Install the package

```bash
pip install -e .
```

This pulls in 4 runtime dependencies (`httpx`, `typer`, `rich`,
`python-dotenv`) and gives you the `ioc-hunter` command in your shell.

### 3. (Optional) Add API keys

You can skip this and the tool still works — only the Tor-exit feed
will run. To unlock the other 5 feeds, all free:

| Source | Register | Adds support for |
| --- | --- | --- |
| **abuse.ch Auth-Key** (URLhaus + ThreatFox) | <https://auth.abuse.ch/> | URLs, domains, IPs, hashes, emails |
| **AbuseIPDB** | <https://www.abuseipdb.com/register> | IPv4/IPv6 reputation |
| **AlienVault OTX** | <https://otx.alienvault.com/> | IPs, domains, URLs, hashes, CVEs |
| **VirusTotal** | <https://www.virustotal.com/> | IPs, domains, URLs, hashes |

Registration on each is ~30 seconds. Then run the interactive setup:

```bash
ioc-hunter configure
```

It walks through each key with the registration URL, writes a local
`.env` (gitignored), leaves untouched keys alone.

### 4. Verify the install

```bash
ioc-hunter sources
```

```
                                   TI sources
  Source       Status   Weight   Supports                         Key required
 ──────────────────────────────────────────────────────────────────────────────
  tor_exit     active     0.40   ipv4, ipv6                       no
  urlhaus      active     0.85   domain, ipv4, md5, sha256, url   yes
  threatfox    active     0.85   domain, email, ipv4, ipv6,       yes
                                 md5, sha1, sha256, url
  abuseipdb    active     0.80   ipv4, ipv6                       yes
  otx          active     0.75   cve, domain, ipv4, ipv6, md5,    yes
                                 sha1, sha256, url
  virustotal   active     0.90   domain, ipv4, ipv6, md5, sha1,   yes
                                 sha256, url
```

Sources marked `missing key` will skip with a clear message at runtime —
not crash. You can run with as few as one (the keyless Tor feed).

---

## Run it with Docker

```bash
cp .env.example .env             # fill in any keys you have
docker compose run --rm ioc-hunter check evil[.]com
```

The image is multi-stage (non-root runtime, ~120 MB), the SQLite cache is
mounted as a volume so it survives across containers.

---

## Commands

```
ioc-hunter check <ioc>                       single IOC verdict
ioc-hunter scan-file <path>                  extract + enrich every IOC in a file
ioc-hunter correlate <path>                  shared-infra and shared-tag pivots
ioc-hunter report <path> --format <fmt>      json | md | stix | misp | sigma | suricata
ioc-hunter decode <text> [--op <name>]       base64 / hex / URL / JWT / gzip / ... (magic by default)
ioc-hunter sources                           list configured sources
ioc-hunter configure                         interactive .env wizard
```

Global flags: `--version`, `--help`. Per-command: `--no-cache` for fresh
lookups.

---

## Demo with real output

### Single IOC — defanged in, defanged out

```console
$ ioc-hunter check "185[.]220[.]101[.]42" --no-cache

╭─────── IOC Hunter ────────╮
│ 185[.]220[.]101[.]42      │
│ type: ipv4                │
│                           │
│ MALICIOUS  confidence 46% │
╰───────────────────────────╯
                               Per-source results
  Source       Verdict      Score   Notes
 ──────────────────────────────────────────────────────────────────────────────
  tor_exit     SUSPICIOUS    0.50   tor, anonymizer
  urlhaus      UNKNOWN       0.00
  threatfox    UNKNOWN       0.00
  abuseipdb    MALICIOUS     1.00   country:DE, usage:Commercial,
                                    isp:Network for Tor-Exit traffic.
  otx          MALICIOUS     1.00   Bruteforce, Brute-Force, SSH
  virustotal   MALICIOUS     0.15   suspicious-udp, tor
Tags: tor, anonymizer, country:DE, Bruteforce, SSH, Honeypot, webscanner, ...
References:
  • https://check.torproject.org/torbulkexitlist
  • https://www.abuseipdb.com/check/185.220.101.42
  • https://otx.alienvault.com/indicator/IPv4/185.220.101.42
  • https://www.virustotal.com/gui/search/185.220.101.42
```

That's a real Tor exit relay — flagged by 4 of 6 sources, with country,
ISP, and attack-pattern tags. Confidence is shown explicitly so you can
defend the verdict in a ticket.

### Scan a whole report

`examples/sample-incident.txt` is included in the repo:

```console
$ ioc-hunter scan-file examples/sample-incident.txt --no-cache

Extracted 10 IOC(s) from examples/sample-incident.txt
                                   10 IOC(s)
  IOC                Type          Verdict      Conf   Hits   Tags
 ──────────────────────────────────────────────────────────────────────────────
  CVE-2024-21762     cve           MALICIOUS    100%    1/1   actively_exploited_kev,
                                                              fortigate
  275a021bbfb...     sha256        MALICIOUS     48%    4/4   windows, malware, ioc
  185[.]220[.]101[.]42  ipv4       MALICIOUS     46%    6/6   tor, anonymizer
  185[.]220[.]101[.]99  ipv4       MALICIOUS     46%    6/6   tor, anonymizer
  8[.]8[.]8[.]8      ipv4          BENIGN        37%    6/6   country:US,
                                                              isp:Google LLC
  evil[.]com         domain        MALICIOUS     36%    4/4   ssl certificate, malware
  hxxps://evil[.]com/login.php  url SUSPICIOUS   13%    4/4
  hxxps://evil[.]com/install.exe url UNKNOWN     0%    4/4
  bad[@]evil[.]com   email         UNKNOWN        0%    1/1
  1BoatSLRHtKNngkdX... btc_address UNKNOWN        0%    0/0
```

Note: every IOC is **defanged on output** so you can't accidentally
click `evil.com` from your terminal. They were also defanged on input
(`185[.]220[.]101[.]42`, `hxxps://`, `bad[at]evil[.]com`) — refanging
is automatic.

### Find cross-IOC pivots

```console
$ ioc-hunter correlate examples/sample-incident.txt --no-cache

Extracted 10 IOC(s)
                               Correlations (12)
  Kind              Source                    →   Target              Evidence
 ──────────────────────────────────────────────────────────────────────────────
  url_to_host       hxxps://evil[.]com/login.php → evil[.]com         URL hosted on evil.com
  url_to_host       hxxps://evil[.]com/install.exe → evil[.]com       URL hosted on evil.com
  email_to_domain   bad[@]evil[.]com          →   evil[.]com          Email at evil.com
  shared_subnet     185[.]220[.]101[.]42      →   185[.]220[.]101[.]99 both in 185.220.101.0/24
  shared_tag        185[.]220[.]101[.]42      →   185[.]220[.]101[.]99 both tagged 'tor'
  shared_tag        185[.]220[.]101[.]42      →   185[.]220[.]101[.]99 both tagged 'Bruteforce'
  shared_tag        evil[.]com                →   275a021bbfb...      both tagged 'malware'
  ...
```

### Generate detection rules

```console
$ ioc-hunter report examples/sample-incident.txt --format sigma --no-cache

title: IOC Hunter - 1 malicious domain indicator(s)
id: 14ffc8c8-355c-402e-9920-69bab9d13546
status: experimental
description: Auto-generated from threat-intel verdicts on 2026/06/13.
date: 2026/06/13
references:
  - https://otx.alienvault.com/indicator/domain/evil.com
  - https://www.virustotal.com/gui/search/evil.com
author: ioc-hunter
logsource:
  category: dns
detection:
  selection:
    QueryName:
      - 'evil.com'
  condition: selection
level: high
tags:
  - malware
  - phishing
---
title: IOC Hunter - 2 malicious ipv4 indicator(s)
...
```

Same input also exports as `--format suricata`, `--format stix`,
`--format misp`, `--format json`, `--format markdown`.

### Magic decode

```console
$ ioc-hunter decode "aHR0cHM6Ly9ldmlsLmNvbS9sb2dpbi5waHA="

                 Magic decode — 2 candidate(s)
  Op       Score   IOCs   Decoded
 ──────────────────────────────────────────────────────────────
  base64    0.95      2   https://evil.com/login.php
  rot13     0.85      0   nUE0pUZ6Yl9yqzyfYzAioF9fo2qcov5jnUN=
```

The base64 candidate ranks first because the decoded text contains
extractable IOCs — IOC presence is a tiebreaker in the scoring.

Force a specific op: `--op base64`, `--op hex`, `--op url`, `--op jwt`,
`--op gzip`, `--op zlib`, `--op rot13`, `--op html`, `--op base32`.

---

## Architecture

```
                   ┌───────────────┐
   raw text ─────▶│  parser/defang │
                   └──────┬────────┘
                          ▼
                   ┌───────────────┐    cache hit ──▶ result
                   │  SQLite cache │───┐
                   └──────┬────────┘   │ miss
                          ▼            ▼
            ┌──────────────────────────────────────┐
            │   async orchestrator (httpx)         │
            │   ┌────────┬────────┬────────┐       │
            │   │URLhaus │ OTX    │ VT     │  ...  │
            │   └────────┴────────┴────────┘       │
            └──────────────────┬───────────────────┘
                               ▼
                       ┌────────────────┐
                       │ weighted scorer│
                       └──────┬─────────┘
                              ▼
                       ┌────────────────┐
                       │  correlator    │
                       └──────┬─────────┘
                              ▼
              ┌────────────────────────────────┐
              │ exporters: JSON / MD /         │
              │           STIX / MISP          │
              │ rule gen:  Sigma / Suricata    │
              │ TUI dashboard                  │
              └────────────────────────────────┘
```

| Module | Role |
| --- | --- |
| `core/` | IOC extraction, defang/refang, type detection |
| `cache/` | TTL SQLite cache, gracefully shared across runs |
| `sources/` | Plugin per TI feed (one file each — add yours in 50 lines) |
| `engine.py` | Async orchestrator + semaphore-limited concurrency |
| `scorer.py` | Weighted confidence aggregation across sources |
| `correlator.py` | Shared-subnet / shared-tag / URL→host pivots |
| `exporters/` | JSON, Markdown, STIX 2.1, MISP Event |
| `rules/` | Sigma + Suricata generators with severity floor |
| `decoder/` | CyberChef-style operations + magic auto-detect |
| `cli.py` | Rich-powered terminal UI |

---

## TI Sources

| Source | Auth | Supports | Weight |
| --- | --- | --- | --- |
| URLhaus (abuse.ch) | Auth-Key (free) | URL, domain, IPv4, MD5, SHA256 | 0.85 |
| ThreatFox (abuse.ch) | Auth-Key (free) | URL, domain, IP, hashes, email | 0.85 |
| AbuseIPDB | API key (free 1k/day) | IPv4, IPv6 | 0.80 |
| AlienVault OTX | API key (free) | IPv4, IPv6, domain, URL, file, CVE | 0.75 |
| VirusTotal | API key (free 4/min) | IPv4, IPv6, domain, URL, file | 0.90 |
| Tor exit list | **none** | IPv4, IPv6 | 0.40 |

Adding a source is one file: subclass `Source`, implement `async lookup()`,
import in `sources/__init__.py`. See `sources/tor_exit.py` for the
shortest possible example (40 lines).

---

## Status

All planned phases done.

| Phase | Status |
| --- | --- |
| 0 — project skeleton | ✅ |
| 1 — IOC parsing core | ✅ |
| 2 — TTL SQLite cache | ✅ |
| 3 — keyless TI sources | ✅ |
| 4 — keyed TI sources | ✅ |
| 5 — async engine + scorer | ✅ |
| 6 — CLI + Rich TUI | ✅ |
| 7 — JSON / Markdown / STIX / MISP exporters | ✅ |
| 8 — correlation graph | ✅ |
| 9 — Sigma / Suricata rule generation | ✅ |
| 10 — CyberChef-style decoder | ✅ |
| 11 — Docker, CI, README | ✅ |

**217 tests, all green.** CI runs the full matrix (Python 3.11 + 3.12),
Docker build, `ruff` lint + format check, and `gitleaks` secret scan on
every push.

---

## Security

API keys live in `.env`, which is gitignored. `gitleaks` runs on every
push to catch accidents. The Dockerfile builds a non-root runtime image.

If you find a vulnerability, please open a private security advisory
rather than a public issue.

---

## License

MIT — see [LICENSE](LICENSE).
