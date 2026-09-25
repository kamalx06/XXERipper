Name:           xxeripper
Version:        1.0.0
Release:        1%{?dist}
Summary:        Advanced XXE scanner with manual OOB confirmation

License:        GPL-3.0-or-later
URL:            https://github.com/kamalx06/XXERipper
Source0:        %{url}/archive/refs/tags/v%{version}/%{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires: python3-devel
BuildRequires: python3-pip
BuildRequires: python3-hatchling
BuildRequires: pyproject-rpm-macros

Requires: python3-httpx
Requires: python3-h2
Requires: python3-flask

%description
XXERipper is a standalone black-box XXE scanner that combines in-band,
error-based, and blind out-of-band detection techniques.

Features:
  - 30+ attack technique families across six classes
  - Manual and Automatic OOB confirmation via interactsh-client with per-technique
    callback labels
  - Statistical baseline with IQR + entropy analysis
  - Differential parser fingerprinting across 11 XML stacks
  - Multi-indicator file and cloud metadata fingerprinting
  - Universal extraction: file content, credentials, and ready-to-use
    exploit snippets
  - Multi-stage exploit chain detection (XXE -> SSRF -> cloud
    metadata -> IAM credentials, XXE -> K8s secrets, and more)
  - HTTP/2 negotiation with HTTP/1.1 fallback
  - Content-Type matrix, HTTP method variation, and query-parameter
    injection
  - XSLT-in-Office detection (DOCX/XLSX xml-stylesheet PI)
  - YAML deserialization detection (CWE-502)
  - Per-phase exception isolation for stability on flaky targets
  - CWE-mapped findings (CWE-611, CWE-200, CWE-918, CWE-78, CWE-776,
    CWE-502)
  - SARIF v2.1.0 output for CI/CD integration
  - Exit-code gating via --fail-on for pipeline use
  - Custom payload injection with placeholder substitution
  - Burp request ingestion with automatic cookie extraction

%prep
%autosetup -n %{name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files xxeripper

# Desktop integration files
install -d %{buildroot}%{_datadir}/applications
install -d %{buildroot}%{_datadir}/icons/hicolor/256x256/apps
install -d %{buildroot}%{_datadir}/metainfo

install -m 0644 packaging/xxeripper.desktop \
    %{buildroot}%{_datadir}/applications/
install -m 0644 packaging/xxeripper.png \
    %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/
install -m 0644 packaging/xxeripper.appdata.xml \
    %{buildroot}%{_datadir}/metainfo/

%check
%pyproject_check_import

%files -f %{pyproject_files}
%license LICENSE
%doc README.md CHANGELOG.md SECURITY.md
%{_bindir}/xxeripper
%{_datadir}/applications/xxeripper.desktop
%{_datadir}/icons/hicolor/256x256/apps/xxeripper.png
%{_datadir}/metainfo/xxeripper.appdata.xml

%changelog
* Fri Sep 25 2026 Kamal Khalilov <kamalx06github@gmail.com> - 1.0.0-1
- Initial RPM release
- Standalone black-box XXE scanner covering 20+ attack technique
  families across six classes: in-band, error-based, blind OOB,
  encoding-bypass, alternative-sink, and extended-fetcher
- HTTP/2 transport via httpx[http2] with ALPN negotiation and HTTP/1.1
  fallback; optional SOCKS proxy support via PySocks
- Differential parser fingerprinting across 11 XML stacks
- Statistical baseline with IQR + entropy analysis and zero-IQR
  timing fallback
- Multi-indicator file and cloud-metadata fingerprinting
- Manual OOB confirmation against a user-supplied interactsh session
  domain; --oob-auto spawns interactsh-client when present in PATH.
  interactsh-client is optional but required for OOB phases; install
  from https://github.com/projectdiscovery/interactsh
- Universal extraction: file content, AWS IAM credentials, SSH private
  keys, and GCP service-account JSON with paste-ready shell snippets
- Multi-stage exploit chain detection with rollup findings
  (XXE -> SSRF -> cloud metadata -> IAM credentials; XXE -> K8s
  secrets; XXE -> SSH key -> lateral movement)
- Delivery vectors: Content-Type matrix, HTTP methods, query params,
  15 WAF-bypass encoders, XSLT-in-Office (DOCX/XLSX xml-stylesheet PI),
  and YAML deserialization (CWE-502)
- CWE-mapped findings: CWE-611, CWE-200, CWE-918, CWE-78, CWE-776,
  CWE-502
- Output: JSON, SARIF v2.1.0, and self-contained HTML report
- Exit-code gating via --fail-on for CI/CD integration
- Rate limiting, exponential retry/backoff, and wall-clock budget to
  avoid accidental DoS on fragile targets