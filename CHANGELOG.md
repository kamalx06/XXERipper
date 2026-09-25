# Changelog

All notable changes to **XXERipper** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-09-25

Initial public release. XXERipper is a standalone, black-box XXE scanner with
statistical baselining, differential parser fingerprinting, out-of-band
confirmation via `interactsh-client` (manual or automatic), a browser-based
console, end-to-end exploit-chain detection, credential extraction with
paste-ready shell snippets, CWE-mapped findings, and JSON / SARIF / HTML
output for CI/CD integration.

### Added

#### Attack techniques

- **30+ technique families across ten classes.** In-band file read, PHP
  filter chains, PHP `expect://` RCE, error-based (local DTD reuse and
  malformed entity), blind OOB (DNS, external DTD, parameter entity,
  CDATA), encoding bypass (UTF-16, UTF-7, UCS-4, alternate DOCTYPE),
  XInclude (`parse='text'` and `parse='xml'`), SVG upload, SAML and SOAP
  envelopes, timing-based blind detection, XSLT `document()` and
  `xsl:include`, XSD `schemaLocation` and `xsd:import`,
  `xml-stylesheet` PI, multipart XML, DOCX upload, Office-document XSLT
  invocation, and YAML deserialization.
- **RCE-via-protocol-wrapper detection.** Java `jar:`, PHP `data://`,
  `phar://`, `glob://`, and `compress.zlib://`. Each wrapper is
  matched against its characteristic success signal — jar manifest
  entries, inline PHP, unserialize traces, directory listings, file
  content.
- **SAML pre-signature detection.** Sends a well-formed assertion
  carrying an invalid signature, interprets the response to determine
  whether the endpoint reached XML parsing, and only then sends the
  XXE payload. Runs on SAML-shaped URLs by default; forced with
  `--saml`.
- **Office-document XSLT invocation.** DOCX and XLSX payloads whose
  `word/document.xml` or `xl/workbook.xml` part carries an
  `xml-stylesheet` PI pointing at an attacker-controlled XSLT. Fires
  when a server-side document processor applies the transform.
- **Unsafe YAML deserialization** (CWE-502). PyYAML
  `!!python/object/apply:os.system` and SnakeYAML
  `!!javax.script.ScriptEngineManager`, delivered both as a raw
  `application/x-yaml` body and wrapped in an XML envelope.

#### Delivery vectors

- **Content-Type matrix.** The classic file-read payload is retried
  under nine XML-adjacent content types (`application/xhtml+xml`,
  `application/atom+xml`, `application/rss+xml`, `application/rdf+xml`,
  `application/mathml+xml`, `application/xslt+xml`, and others).
- **HTTP method variation.** Payloads retried with `PUT` and `PATCH`.
- **Query-parameter injection.** Payload delivered as `?xml=`,
  `?data=`, `?payload=`, or `?input=`.
- **JSON-to-XML content-type switching.** A benign XML probe tests
  whether a JSON endpoint silently accepts `application/xml`; if the
  endpoint does not reject with `415`, the classic file-read payload
  follows. Finding ID `XXE-JSON-TO-XML`.

#### Cloud metadata

- **Dedicated cloud-metadata phase.** Eleven endpoints across six
  providers are probed and fingerprinted against provider-specific
  keys: AWS IMDS (instance metadata, IAM credentials, user-data), GCP
  (service-account token, project-id), Azure (instance,
  managed-identity OAuth token), Alibaba Cloud, Oracle Cloud, and the
  Kubernetes service-account API.
- **IMDSv2 detection.** An AWS response with status `401` and `token`
  in the body is reported as `XXE-CLOUD-METADATA-IMDSV2` (HIGH),
  distinct from full credential exposure.
- **Per-provider finding IDs.**
  `XXE-CLOUD-METADATA-{AWS,GCP,AZURE,ALIBABA,OCI,K8S,IMDSV2}` produce
  individually-actionable entries on a multi-cloud target.
- **Credential extraction from metadata responses.** Extracted
  credentials are routed into the loot store and their IDs attached
  to the finding's evidence.
- **Fingerprint coverage extended to all six providers.**
  `CLOUD_METADATA_FINGERPRINTS` previously covered only AWS, GCP, and
  Azure while the probe list covered all six.

#### Credential extraction

- **Seven credential kinds.** AWS IAM (JSON and INI), Alibaba RAM, SSH
  private keys (RSA, OpenSSH, DSA, EC, PKCS#8), GCP service accounts,
  OAuth access tokens (GCP metadata and Azure managed identity), and
  Kubernetes service-account tokens (from a `SecretList` response or a
  bare token file). Each kind produces its own `kind` string, its own
  field set, and its own paste-ready shell snippets.
- **Paste-ready snippets per kind.**
  - AWS IAM — `aws sts get-caller-identity`, `aws s3 ls`, IAM policy
    enumeration, environment export block.
  - Alibaba RAM — `aliyun sts GetCallerIdentity`, `aliyun oss ls`,
    environment export block.
  - SSH private key — install, fingerprint, try against
    `github.com` / `gitlab.com` / `bitbucket.org`.
  - GCP service account — `gcloud auth activate-service-account`.
  - OAuth access token — Google userinfo endpoint (GCP), Azure
    subscriptions endpoint (Azure).
  - Kubernetes service-account token — `kubectl --token=…` built from
    the JWT's decoded namespace and service-account claims, plus a
    `jq` command to inspect the claims without verifying.
  - Generic bearer — `httpbin.org/bearer` liveness check.
- **Full credential value in loot previews.** The masked summary
  format (`SecretAccessKey=***`, `SessionToken(len=N)`) was removed
  since the full value is already unmasked in the Inspector, the JSON
  output, the SARIF output, and the HTML report.
- **Generic bearer-token fallback** with a low confidence weight,
  guarded against prefix collisions with higher-confidence extractors.

#### Loot and chain tracking

- **Loot store.** Every file-read finding routes through a universal
  extractor that pulls raw file content from the response,
  deduplicates by SHA-256, and stores it in a central repository.
  `FileContentExtractor` dispatches by `(file_path, fingerprint_type)`
  with per-file matchers for `/etc/passwd`, `/etc/shadow`, SSH keys,
  `.env`, `win.ini` / `system.ini` / `boot.ini`, `web.config`, and
  `/proc/*`, plus a generic structural fallback.
- **Content truncation with credential preservation.** Stored content
  is capped at 256 KB; credentials are extracted from the full text
  before truncation.
- **Exploit-chain detection.** A chain tracker derives stages from
  each finding's ID and evidence and fires a rollup finding when a
  template completes. Thirteen templates ship, including
  `xxe_imds_iam_aws_takeover`, `xxe_k8s_serviceaccount_token`,
  `xxe_ssh_key_lateral_movement`, and `xxe_gcp_oauth_token_extraction`.
  Rollups appear in JSON, SARIF, and HTML output like any other
  finding. Firing is guarded against concurrency races.

#### Blind exfiltration

- **Three DTD-hosting modes.** `--oob-listen HOST:PORT
  --oob-public-url URL` binds a built-in HTTP server;
  `--oob-dtd-dir PATH --oob-dtd-url-prefix URL` writes DTD files into
  a directory served by the operator; the WebUI-hosted mode serves
  DTDs at `/dtd/<token>.dtd` from the same Flask process as the
  console.
- **End-to-end extraction.** When exfiltration is active,
  `XXE-BLIND-OOB-EXTERNAL-DTD-CORRELATED` and `XXE-CDATA-BYPASS-OOB`
  findings carry extracted content and credentials in their evidence.
  The same extraction pipeline that runs on in-band reads runs on the
  exfiltrated bytes.
- **OOB callback extraction.** Interactsh callback objects are parsed
  for exfiltrated data in HTTP request paths/queries and DNS subdomain
  labels. URL-encoding, CDATA framing, and base64 are handled
  transparently.
- **Manual-mode warning.** Both the CLI banner and the WebUI job
  runner warn when exfiltration is configured but auto mode is off,
  so the operator knows to read content from the interactsh terminal.

#### Accuracy engine

- **Weighted scoring model with mandatory signal gates.** Weights:
  correlated OOB callback (+50), file content fingerprint (+40 plus
  +5 per additional indicator), chain integrity (+25), parser error
  delta (+20 high / +15 medium / +5 low), timing anomaly (+20),
  windowed entropy anomaly (+5 to +20), uncorrelated OOB callback
  (+15), length delta (+10), status-code shift (+5).
- **Windowed entropy anomaly.** Byte-level sliding-window Shannon
  entropy (256-byte windows, 128-byte step, first 16 KiB scanned).
  Fires only when `median_length >= 256`, only on upward shifts, and
  only when the delta exceeds 0.5 bits/byte. Scales from +5 at the
  threshold to +20 at 4.0 bits/byte.
- **Graded reflection penalty.** A hard −100 veto when no strong
  signal is present, downgraded to a −30 penalty when a file
  fingerprint, correlated OOB callback, chain integrity, or
  high-confidence parser error is present.
- **No-change veto (−50)** and **normalized baseline match veto
  (−75)**, both gated on the absence of a strong signal.
- **Mandatory signal gates.** Promotion to `CONFIRMED` or `POTENTIAL`
  requires at least one of `file_type`, `oob_correlated`, or
  `chain_integrity`. Parser errors and timing anomalies contribute to
  score but cannot confirm alone.
- **Two-family requirement for `CONFIRMED`.** A finding at score ≥70
  is only promoted to CRITICAL when at least two independent signal
  families are present.
- **INFO suppression.** Findings below `MEDIUM` are computed for score
  shaping but never surfaced. The informational
  `XXE-PARSER-FINGERPRINT` finding is emitted directly.
- **CWE mapping.** Longest-prefix-first lookup. XXE findings carry
  CWE-611; information disclosure adds CWE-200; SSRF-via-entity, the
  XSLT/XSD fetchers, Office XSLT, and every `XXE-CLOUD-METADATA-*`
  finding add CWE-918; PHP `expect://` and the `XXE-RCE-*` wrappers
  add CWE-78; error-based local-DTD reuse adds CWE-829;
  `XXE-SAML-PRESIG` adds CWE-347; `XXE-WAF-BYPASS-*` adds CWE-693;
  `XXE-YAML-DESER-*` adds CWE-502; Billion Laughs is CWE-776.

#### Parser fingerprinting

- **Differential capability probes.** Nine test/control pairs; a
  capability is recorded as present only when the test's success
  predicate passes and the control's does not, eliminating the
  "status 200 means vulnerable" false-positive class.
- **Eleven XML-stack signature families.** libxml2, Xerces, .NET
  `System.Xml`, Java SAX/JAXP, Java StAX, Python stdlib (`etree`,
  `minidom`, `sax`, `parsers.expat`), PHP `DOMDocument` /
  `SimpleXMLElement`, Ruby (REXML, Nokogiri), Node.js (`xml2js`,
  `libxmljs`, `node-expat`, `sax.js`, `fast-xml-parser`), Perl
  (`XML::LibXML`, `XML::Parser`, `XML::SAX`, `XML::Simple`,
  `XML::Twig`), and Go `encoding/xml`. Best-match scoring across
  families: the family with the most distinct signature hits wins.
- **Tail-based parser-error capture.** Reads the last 2 kB of each
  probe response, since Python tracebacks place the exception name at
  the tail.
- **On-disk cache** at `~/.cache/xxeripper/fingerprints.json`, keyed
  by URL. Repeat scans skip the nine-probe sequence. Only parser
  identity and boolean capability flags are stored.
- **Capability gating.** In-band file read and error-based local-DTD
  sweep are skipped when the fingerprint succeeded and reported no
  entity-resolution capability. The gate is lenient: a fingerprint
  that measured every capability as `False` runs phases
  unconditionally rather than silently suppressing them.

#### Statistical baseline

- Seven-sample benign baseline computing median length, median
  elapsed time, IQR, p95, mode status code, most-common body hash,
  whole-body Shannon entropy, and windowed entropy.
- **Status mode** rather than first-sample status.
- **Timing-anomaly fallback when IQR is zero.** On uniform baselines,
  the anomaly test requires the delta to exceed twice the observed
  jitter range.
- **Union-of-samples body membership** for baseline-anchored parser
  error matching.
- Timing anomaly requires delta ≥1.5s **and** ratio ≥2.5× median
  **and** either delta ≥4× IQR or delta ≥2× observed jitter range.

#### Web console

- **Browser-based console** (`--serve`), bound to `127.0.0.1` by
  default. `--host` and `--port` allow rebinding; the startup banner
  warns against non-loopback binds.
- **Zero-dependency frontend.** One self-contained HTML document with
  embedded CSS and JavaScript. No CDN, no build step, no framework.
- **Live event stream.** Backend scan jobs accumulate events; the
  frontend polls `/api/jobs/<id>?since=<cursor>` and appends new
  events. A visibility-change listener forces an immediate re-poll
  when the tab regains focus.
- **Three-pane workbench.** Target list (left), tabbed center pane,
  inspector (right).
- **Five center tabs.** Findings (filterable, searchable, sortable),
  Events, OOB (with per-payload correlation status and an
  exfiltrated block for callbacks that carried data), Loot
  (files-first, with copy buttons for content and per-command copy
  buttons for shell snippets), and Log.
- **Inspector with four sub-tabs.** Overview (with inline credentials
  and per-snippet copy buttons), Evidence, Reasons, Raw.
- **Command palette** (`⌘K` / `Ctrl+K`): fuzzy search across
  commands, targets, and findings.
- **Keyboard shortcuts.** `j` / `k` navigate targets; `n` / `p`
  navigate findings; `/` focuses the filter; `c` opens the new-scan
  drawer; `r` re-runs the selected scan; `?` opens the shortcuts
  dialog; `Esc` dismisses progressively.
- **New-scan drawer** exposes every CLI flag, including the blind
  exfiltration section (WebUI-hosted DTD server or DTD directory) and
  the full WAF-bypass encoder grid. Encoder selections and the
  include-custom checkbox reset to off when the drawer closes.
- **Per-job artifacts.** JSON, SARIF, and self-contained HTML reports
  for any completed job. Two HTML buttons: **HTML** downloads via
  `Content-Disposition: attachment`; **View HTML** opens the same
  report inline.
- **Cooperative cancellation** via `/api/jobs/<id>/cancel`, checked
  by every phase before each payload send.
- **Shared interactsh subprocess** for the process lifetime, spawned
  lazily on the first auto-OOB job, with per-target token sets.

#### CLI

- Positional URL, `-u/--urls FILE`, or `-r/--request FILE` (Burp
  format). `-o/--output FILE`, `--format {json,sarif,both}`,
  `--report-html PATH`, `--fail-on {critical,high,medium,low,never}`,
  `--debug`.
- **Out-of-band.** `--oob-domain`, `--oob-auto`, `--oob-timeout`.
- **Blind exfiltration.** `--oob-listen HOST:PORT`,
  `--oob-public-url URL`, `--oob-dtd-dir PATH`,
  `--oob-dtd-url-prefix URL`.
- **Web console.** `--serve`, `--host ADDRESS`, `--port PORT`.
- **Fingerprint and file targeting.** `--no-fingerprint`,
  `--no-fingerprint-cache`, `--full-file-scan`.
- **Sessions.** `--cookie`, `--cookie-file`, `--no-cookie-merge`,
  `--pre-auth-request FILE` (repeatable for multi-step auth).
- **Payloads.** `--payload`, `--payload-file`, `--payload-dir` with
  `{FILE}`, `{CALLBACK}`, `{DOMAIN}`, `{URL}`, `{HOST}` placeholders.
- **Attack modes.** `--timing`, `--unsafe`, `--svg`, `--saml`.
- **WAF bypass.** `--bypass-waf [ENCODERS]` with fifteen encoders;
  `--bypass-waf-include-custom`.
- **Network.** `--proxy`, `--threads`, `--rate`, `--timeout-connect`,
  `--timeout-read`, `--budget`, `--verify-tls`.

#### Reliability

- **Per-phase exception isolation.** Every phase catches any
  exception, logs the traceback under `--debug`, and continues to the
  next phase.
- **Per-target rate limiting** independent of `--threads`. Both the
  standard send path and the query-parameter send path consult the
  limiter.
- **Retry with exponential backoff** on transient network errors
  (`httpx.ConnectError`, `RemoteProtocolError`, `ReadError`,
  `WriteError`, `TimeoutException`), three attempts at 0.5 / 0.75 /
  1.125 second delays.
- **`Retry-After` honored** on 429 and 503, capped at 10 seconds.
- **HTTP 500 never retried.** Error-based XXE targets return 500 on
  purpose; retrying hides the signal.
- **Null-response guard on OOB sends.** A failed send skips the poll
  wait rather than stalling.
- **Wall-clock scan budget** via `--budget SECONDS`, checked before
  every payload send.
- **Configurable timeouts** via `--timeout-connect` and
  `--timeout-read`.
- **TLS verification toggle.** Disabled by default for pentest use;
  `--verify-tls` re-enables.
- **CI exit codes.** `0` clean, `1` configuration error, `2` finding
  at or above `--fail-on`, `130` on Ctrl-C.
- **Thread-safe finding accumulation.** Duplicate finding IDs are
  merged in place — severity bumped, `confirmed` ORed,
  `max(confidence)` taken, reasons and evidence unioned. Every merge
  and new finding emits an event so the console updates live.
- **Thread-safe OOB statistics.** Locked snapshot returned by the
  stats accessor.
- **Deduplicated loot.** Loot entries key on SHA-256 of stored
  content.

#### Output formats

- **JSON schema `1.1`** with `cwe`, `loot`, and `loot_counts`. The
  internal `skipped_phases` bookkeeping field is stripped from
  serialized JSON.
- **SARIF v2.1.0** with per-rule `helpUri` pointing at the primary
  CWE definition. Severity maps to SARIF levels: CRITICAL/HIGH →
  `error`, MEDIUM → `warning`, LOW/INFO → `note`.
- **Self-contained HTML report** with executive summary, exploit
  chains, extracted loot with paste-ready snippets, findings by
  target, and print-friendly CSS.
- **Four console verdicts.** `[VULNERABLE]` (findings present),
  `[MANUAL-OOB]` (OOB payloads sent, awaiting operator confirmation),
  `[INFO-ONLY]` (nothing surfaced, at least one phase skipped), and
  `[OK]` (nothing to report, no skips).

#### CI/CD integration

- **SARIF v2.1.0** for GitHub code scanning, GitLab SAST, Azure
  DevOps, and any SARIF consumer.
- **Exit-code gate** via `--fail-on`.
- **HTML report** for human review, attachable to CI artifacts.
- **Documented GitHub Actions and GitLab CI integrations.**
- **CWE references in SARIF rules.**
- **Persistent fingerprint cache in CI.** Point `HOME` at a persisted
  cache directory so repeat scans skip the fingerprint phase.

#### Packaging

- **PyPI**: `pip install xxeripper`.
- **Debian** (`.deb`), **RPM** (`.rpm`), **Arch AUR**
  (`xxeripper` and `xxeripper-git`).
- **GitHub Actions** workflow for release builds.
- **Optional extras**: `xxeripper[socks]` for SOCKS proxy support;
  `xxeripper[http2]` as an alias for the base install.

#### Test labs

- **Python lab v7** (`xxe_lab.py`): 54 endpoints across three verdict
  classes (`vuln` = 36, `safe` = 17, `fn` bait = 1) and two response
  modes:
  - **`realistic`** (default): wrong Content-Type returns `415`;
    wrong shape either falls through to the parser (soft gate) or
    returns a generic `400` (hard gate). No reason leak.
  - **`scoped`**: every out-of-scope request returns a stable
    `200 out of scope: <reason>` body that parses nothing.
  Per-request override via `X-Lab-Mode` header or `?lab_mode=` query
  parameter; precedence is header > query > env default.
- **Safe counterparts for every scoped vuln endpoint.** Thirteen
  endpoints run the same scope check but parse with entities disabled
  and network blocked, closing a false-positive class where a
  form-encoded payload sent to a "safe" endpoint with no scope check
  would be accepted and parsed.
- **Machine-readable verdicts API.** `GET /api/verdicts` returns
  `{"<method> <path>": "vuln"|"safe"|"fn"}` for every endpoint.
- **Deterministic noise mode** via `XXE_LAB_NOISE_SEED`.
- **Provider-dispatched synthetic metadata.** `/xml/meta` returns
  provider-appropriate JSON based on the URL in the payload — AWS
  IAM credentials, GCP service-account OAuth tokens, Azure
  managed-identity tokens, Alibaba RAM credentials, OCI instance
  metadata, Kubernetes `SecretList` responses.
- **Coverage of newer phases.** `/xml/timing`, `/xml/saml-presig`,
  `/xml/json-to-xml`, `/xml/yaml`, `/xml/rce-jar`,
  `/xml/office-xslt-docx`, `/xml/office-xslt-xlsx`,
  `/xml/encoding-ucs4`, `/xml/encoding-altdoctype`,
  `/xml/xinclude-ssrf`.
- **Startup sanity check.** Verifies `ENDPOINT_META` has no duplicate
  paths and every entry has required keys.
- **Java lab** (`xxe_lab.java`): single endpoint `/xml/error` on
  `com.sun.net.httpserver` + Xerces. Required for error-based XXE
  testing, since libxml2 rejects internal-subset parameter entities
  at the C level.

### Changed

- **HTTP client migrated from `requests` + `urllib3` to `httpx`.**
  HTTP/2 negotiation is enabled by default via ALPN, with silent
  fallback to HTTP/1.1. Retry logic uses httpx's exception hierarchy.
  The retry-on-429/502/503/504 behavior and the deliberate
  non-retry-on-500 behavior are preserved.
- **WAF bypass phase reordered.** The phase now runs *after* the
  core phases. Previously the encoded catalogue (up to ~1,500
  requests per target with `--bypass-waf all`) ran before the ~20
  direct requests that would have found the same bug in the vast
  majority of cases. Direct findings now surface immediately; the
  encoded sweep is the fallback for targets where the direct probes
  were filtered.
- **JSON schema bumped from `1.0` to `1.1`.** Adds `cwe` on findings
  and `loot` / `loot_counts` on results. Consumers reading by key are
  unaffected.
- **Web console inspector restructured** from three tabs to four
  (Overview, Evidence, Reasons, Raw), with credentials rendered
  inline in Overview.
- **Web console center pane expanded** from four tabs to five, adding
  a Loot tab.
- **Blind-exfiltration gap closed.** Previously the scanner could
  confirm a target fetched an attacker-controlled DTD but not recover
  the exfiltrated content. This release ships DTD hosting on both the
  CLI and the Web console, an OOB-callback extractor, and routing of
  the recovered content into the same loot store that in-band reads
  use.

### Security

- All findings include evidence dictionaries and reason chains for
  auditability and reproducible reporting.
- Every finding carries one or more CWE identifiers.
- DoS payloads (Billion Laughs) require explicit `--unsafe` opt-in.
- Rate limiting, retry caps, and a wall-clock budget prevent
  accidental denial of service on fragile targets.
- OOB subdomains embed a unique 16-hex token per payload so callbacks
  cannot be misattributed. Auto mode gates callback correlation on
  the same token.
- OOB observations record technique labels alongside each subdomain,
  so manual confirmation cannot be attributed to the wrong phase.
- The on-disk fingerprint cache stores only parser identity and
  boolean capability flags. No credentials, session data, response
  bodies, or control-probe results are persisted.
- Extracted credentials are held in memory only and are serialized
  into the JSON, SARIF, and HTML reports as evidence. Reports
  containing credentials should be treated as secrets.
- The web console binds to `127.0.0.1` by default and has no
  authentication. Re-binding via `--host` prints an explicit warning.
  Front the console with an authenticated reverse proxy for remote
  access.
- GPL-3.0-or-later licensing ensures downstream modifications remain
  open source and auditable.

### Known limitations

- **Fingerprint cache has no TTL.** Invalidate by deleting
  `~/.cache/xxeripper/fingerprints.json` or passing
  `--no-fingerprint-cache`. Stale entries after a target upgrade will
  produce stale capability gating.
- **Manual OOB mode does not extract exfiltration.** Exfiltration
  requires `--oob-auto`. In manual mode the DTDs are served and the
  callbacks arrive, but the operator reads the file content from the
  interactsh terminal rather than seeing it in the Loot tab. Both the
  CLI banner and the WebUI job runner print a warning when this
  configuration is detected.
- **Error-based XXE is parser-dependent.** `error_based_malformed`
  requires Xerces or .NET; `error_based_local_dtd` requires a
  hijackable DTD on the target's filesystem. The fingerprint phase
  reports the target's parser, so this is visible in the scan output.
- **Custom-payload phase is serial.** Each payload is tested against
  every file target sequentially.
- **No persistent scan state.** A killed process loses its findings;
  the console's in-memory job store is cleared on exit.
- **No configuration file.** Every setting is a CLI flag.
- **No SBOM or signed releases.**

---

## [Unreleased]

### Planned

- Browser-based confirmation via Playwright for DOM-rendered XXE
  sinks.
- SAML-specific payload refinements (signature wrapping, assertion ID
  injection, namespace confusion).
- Configuration file (`.xxeripper.toml`) with CLI-flag overrides.
- Fingerprint cache TTL (`--fingerprint-cache-ttl 7d`).
- Resumable scans via on-disk state.
- Docker image publication to GitHub Container Registry.
- Response diff visualization in console output for confirmed
  findings.
- SBOM emission and signed release artifacts.
- Web console authentication for non-loopback binds.
- Persistent loot store for multi-session engagements.

### Under consideration

- Phase-level parallelization.
- Plugin architecture for community payload families.
- Library-mode import for embedding the detector in other pipelines.
- Additional OOB backends (BOAST, self-hosted interactsh, custom DNS
  capture).
- Interactive request iteration mode for manual confirmation.

---

## Version history

| Version | Date | Summary |
|---|---|---|
| 1.0.0 | 2026-09-25 | Initial public release. |

---

[1.0.0]: https://github.com/kamalx06/XXERipper/releases/tag/v1.0.0
[Unreleased]: https://github.com/kamalx06/XXERipper/compare/v1.0.0...HEAD