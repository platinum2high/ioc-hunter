# IOC Hunter

> Async threat intelligence correlation engine for SOC analysts.

[![CI](https://github.com/platinum2high/ioc-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/platinum2high/ioc-hunter/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-216%20passing-brightgreen)

IOC Hunter takes raw text — a phishing report, a Slack export, a memory
dump — extracts every indicator inside it, enriches each one across six
threat-intel sources in parallel, and produces verdicts you can drop
straight into a ticket or a SIEM.

## What it does that other IOC tools don't

| Capability | Most IOC checkers | IOC Hunter |
| --- | --- | --- |
| Input | one IOC at a time | drag in a whole report |
| Defang-aware | usually no | `evil[.]com`, `hxxp://`, `[at]` all understood |
| Sources | 1 (usually VT) | 6 in parallel: VT, AbuseIPDB, OTX, URLhaus, ThreatFox, Tor exit |
| Scoring | bad/good | transparent weighted model with per-source contribution |
| Output | terminal text | JSON, Markdown, **STIX 2.1**, **MISP**, **Sigma**, **Suricata** |
| Correlation | none | shared-subnet + shared-tag pivots across the batch |
| Decoding | none | base64/hex/URL/JWT/gzip/zlib + magic auto-detect |
| Cache | none | SQLite with TTL — survives across runs, doesn't burn API quota |

## Demo

```console
$ ioc-hunter check 1.1.1.1 --no-cache
╭────── IOC Hunter ──────╮
│ 1[.]1[.]1[.]1          │
│ type: ipv4             │
│                        │
│ BENIGN  confidence 37% │
╰────────────────────────╯
                               Per-source results
  Source       Verdict   Score   Notes
 ──────────────────────────────────────────────────────────────────────────────
  tor_exit     UNKNOWN    0.00
  urlhaus      UNKNOWN    0.00
  threatfox    UNKNOWN    0.00
  abuseipdb    BENIGN     0.00   country:AU, usage:Content Delivery Network
  otx          UNKNOWN    0.00
  virustotal   BENIGN     0.00
References:
  • https://www.abuseipdb.com/check/1.1.1.1
  • https://otx.alienvault.com/indicator/IPv4/1.1.1.1
  • https://www.virustotal.com/gui/search/1.1.1.1
```

```console
$ ioc-hunter scan-file incident-report.eml
Extracted 14 IOC(s) from incident-report.eml
                                    14 IOC(s)
  IOC                              Type     Verdict      Conf   Hits  Tags
 ─────────────────────────────────────────────────────────────────────────────
  hxxps://evil[.]com/login.php     url      MALICIOUS    91%    6/6   phishing, redline
  185[.]220[.]101[.]42             ipv4    MALICIOUS    87%    5/6   tor, c2
  evil[.]com                       domain   MALICIOUS    85%    5/6   phishing
  e3b0c44298fc1c149afbf4c8996...   sha256   SUSPICIOUS   54%    3/6   dropper
  ...
```

## Commands

```bash
ioc-hunter check <ioc>                       # single IOC verdict
ioc-hunter scan-file <path>                  # extract + enrich every IOC in a file
ioc-hunter correlate <path>                  # find shared-infra and shared-tag pivots
ioc-hunter report <path> --format <fmt>      # json | md | stix | misp | sigma | suricata
ioc-hunter decode <text> [--op <name>]       # base64/hex/URL/JWT/gzip/zlib (auto-magic by default)
ioc-hunter sources                           # which TI sources are active right now
ioc-hunter configure                         # interactive .env wizard
```

## Quickstart

### Install from source

```bash
git clone https://github.com/platinum2high/ioc-hunter
cd ioc-hunter
python -m venv .venv && source .venv/bin/activate
pip install -e .
ioc-hunter configure        # prompts for API keys, writes .env
ioc-hunter sources          # confirm everything is active
```

### Run with Docker

```bash
cp .env.example .env        # fill in your keys
docker compose run --rm ioc-hunter check evil[.]com
```

### API keys

All keys are **optional** — sources without a key short-circuit to UNKNOWN
with a hint, the others still run. Free signup links:

- abuse.ch Auth-Key (URLhaus + ThreatFox + MalwareBazaar) — <https://auth.abuse.ch/>
- AbuseIPDB — <https://www.abuseipdb.com/register>
- AlienVault OTX — <https://otx.alienvault.com/>
- VirusTotal — <https://www.virustotal.com/>

`ioc-hunter configure` walks through them interactively.

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

- **`core/`** — IOC extraction, defang/refang, type detection
- **`cache/`** — TTL SQLite cache, gracefully shared across runs
- **`sources/`** — plugin per TI feed: URLhaus, ThreatFox, AbuseIPDB, OTX, VirusTotal, Tor exit list
- **`engine.py`** — async orchestrator + semaphore-limited concurrency
- **`scorer.py`** — weighted confidence aggregation across sources
- **`correlator.py`** — shared-subnet / shared-tag pivots
- **`exporters/`** — JSON, Markdown, STIX 2.1, MISP Event
- **`rules/`** — Sigma + Suricata generators with severity floor
- **`decoder/`** — CyberChef-style operations + magic auto-detect
- **`cli.py`** — Rich-powered terminal UI

## Threat Intel Sources

| Source | Auth | Supports | Reliability weight |
| --- | --- | --- | --- |
| URLhaus (abuse.ch) | Auth-Key (free) | URL, domain, IPv4, MD5, SHA256 | 0.85 |
| ThreatFox (abuse.ch) | Auth-Key (free) | URL, domain, IP, hashes, email | 0.85 |
| AbuseIPDB | API key (free 1k/day) | IPv4, IPv6 | 0.80 |
| AlienVault OTX | API key (free) | IPv4, IPv6, domain, URL, file, CVE | 0.75 |
| VirusTotal | API key (free 4/min) | IPv4, IPv6, domain, URL, file | 0.90 |
| Tor exit list | none | IPv4, IPv6 | 0.40 |

Adding a source is one file: subclass `Source`, implement `async lookup()`.

## Status

| Phase | Status |
| --- | --- |
| 0 — project skeleton | done |
| 1 — IOC parsing core | done |
| 2 — TTL SQLite cache | done |
| 3 — keyless TI sources | done |
| 4 — keyed TI sources | done |
| 5 — async engine + scorer | done |
| 6 — CLI + Rich TUI | done |
| 7 — JSON / Markdown / STIX / MISP exporters | done |
| 8 — correlation graph | done |
| 9 — Sigma / Suricata rule generation | done |
| 10 — CyberChef-style decoder | done |
| 11 — Docker, CI, README polish | done |

216 tests, all green. CI runs the full matrix (Python 3.11 + 3.12),
Docker build, ruff lint + format check, and `gitleaks` secret scan
on every push.

## Security

API keys live in `.env`, which is gitignored. `gitleaks` runs on every
push to catch accidents. If you find a vulnerability, open a private
security advisory rather than a public issue.

## License

MIT — see [LICENSE](LICENSE).
