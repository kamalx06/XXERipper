# Security Policy

## Reporting a vulnerability

If you discover a security issue in **XXERipper** itself, please report
it privately to **kamalx06github@gmail.com**. Do not open a public
GitHub issue.

You can expect:

- **Acknowledgement** within 72 hours.
- A **fix or mitigation plan** within 14 days.
- **Credit** in the release notes unless you prefer anonymity.

When reporting, please include:

- A clear description of the issue.
- Steps to reproduce (command line, input file, environment).
- The impact you believe it has.
- Any suggested fix or mitigation, if you have one.

Please do not include exploit code in the initial report; we will
request it privately if needed.

---

## Scope

XXERipper is an offensive security tool intended for **authorized
testing only**. Vulnerabilities in the following areas are in scope:

| Category | Examples |
|---|---|
| **Code execution** | A crafted payload, Burp request file, or uploaded document causes arbitrary code execution on the machine running XXERipper. |
| **SSRF / outbound requests from the scanner host** | Parsing an untrusted payload file, custom payload template, or Burp request causes XXERipper itself to make outbound requests the user did not intend. |
| **Subprocess hijack** | `--oob-auto` executes `interactsh-client` by name. A sanitization gap between user inputs and the subprocess invocation is in scope. |
| **Web console bypass** | The `--serve` console has no authentication. Any authentication bypass, CSRF, or route reachable through the console that is not documented as such is in scope. |
| **DTD server exposure** | The blind-exfiltration DTD server serves attacker-controlled content. Path traversal, token collision, or content leakage beyond the specific token requested is in scope. |
| **Crash / DoS of the scanner host** | A crafted input crashes XXERipper, causes unbounded memory growth, or triggers a denial of service against the scanner host. |
| **Path traversal** | A payload file path, DTD output directory, or custom payload name escapes the intended directory. |
| **Dependency confusion** | A malicious package is resolved during installation. |
| **Leaked secrets** | A real credential is found embedded in any committed file. |

---

## Out of scope

- The scanner reporting false positives or false negatives on a live
  target.
- Issues that require the user to run XXERipper with elevated
  privileges.
- Findings in third-party dependencies (`httpx`, `h2`, `Flask`,
  `PySocks`, `interactsh`). Report those upstream.
- The target application being vulnerable to XXE. That is the intended
  use case.
- Denial of service caused by `--unsafe`. Billion Laughs is explicitly
  opt-in and documented as dangerous.
- The web console being reachable, or having no authentication, when
  the user bound it to a non-loopback address. Both are documented
  behavior; the startup banner warns about the first.
- The DTD server being reachable by the target. It is designed to be.

---

## Responsible use

XXERipper is intended for **authorized security testing only**. Do not
use it against systems you do not own or have explicit written
permission to test. Unauthorized scanning may violate the CFAA, the
Computer Misuse Act, similar laws in your jurisdiction, and cloud
provider terms of service.

See the README's *Disclaimer* section for the full text.

---

## Disclosure policy

We follow **coordinated disclosure**:

1. You report the issue privately.
2. We acknowledge and investigate.
3. We develop and test a fix.
4. We release a patched version.
5. We publish a security advisory with credit (unless you prefer
   anonymity).

We ask that you do not publicly disclose the issue until a fix has been
released, or until 90 days have passed since your report, whichever
comes first.

---

## Build and release verification

Build scripts and release targets are public and auditable. They contain
no credentials — every secret is read at runtime from `.env` (which is
`.gitignore`d) or from the local user's keyring (`~/.gnupg/`,
`~/.ssh/`, `~/.pypirc`).

Any published artifact can be reproduced from a public git clone:

- `make build` — Python wheel and sdist
- `make deb` — Debian package
- `make rpm` — RPM package
- `make arch` — Arch package
- `make all` — all of the above

If a published artifact cannot be reproduced from a public clone using
these commands, or if a secret is found embedded in any committed file,
please report it privately. We will rotate the credential immediately
and rewrite history.

---

## Contact

- **Security reports:** kamalx06github@gmail.com
- **GitHub Issues (non-security):** https://github.com/kamalx06/XXERipper/issues