#!/usr/bin/env python3
"""
XXE Test Lab v1 — advanced playground for XXE scanner testing.

!! LOCAL TESTING ONLY. Binds to 127.0.0.1. Several endpoints read arbitrary
   local files by design. Never expose this to a public or untrusted network.

Two modes
---------
  realistic (default) — mimics a real application. Wrong Content-Type -> 415,
    wrong shape -> parse anyway (soft gate) or generic 400 (hard gate). No
    reason leak. The scanner must distinguish "target rejected my payload"
    from "target accepted but didn't resolve" using response shape alone.

  scoped — deterministic legacy behavior. Every out-of-scope body gets a
    stable `200 out of scope: <reason>` that parses nothing. Opt-in for
    regression suites where you want cross-technique FP vetoes to be exact.

Per-request override:
  Header:      X-Lab-Mode: scoped  |  X-Lab-Mode: realistic
  Query param: ?lab_mode=scoped    |  ?lab_mode=realistic

Precedence: header > query param > env var XXE_LAB_MODE > default.

Install:  pip install 'flask>=3.0,<4.0' 'lxml>=5.0' \
                      'httpx[http2]>=0.27,<0.29' 'PyYAML>=6.0'
          (or: pip install -r requirements.txt)

Run:      python3 xxe_lab.py                     # http://127.0.0.1:5000
          python3 xxe_lab.py --https             # reuse/generate cert
          python3 xxe_lab.py --autocert          # force fresh cert
          python3 xxe_lab.py --cert c.pem --key k.pem
          python3 xxe_lab.py --host 0.0.0.0 --port 8443   # don't do this

Env:      XXE_LAB_MODE=realistic|scoped (default: realistic)
          FLASK_HOST, FLASK_PORT (overridden by --host / --port)
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import time
import random
import string
import threading
import traceback
import urllib.request
import zipfile
from collections import deque
from datetime import datetime, timezone

from flask import Flask, request, Response, jsonify, g
from lxml import etree
import httpx

try:
    import yaml as _yaml
    _HAVE_YAML = True
except ImportError:
    _HAVE_YAML = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_RESP_BYTES = 4 * 1024 * 1024
MAX_TRACE_BYTES = 8 * 1024
LOG_SIZE = 500
PREVIEW_CHARS = 2048
RESP_PREVIEW_CHARS = 2048
FETCH_TIMEOUT = 4.0
TIMING_SLEEP_SECONDS = 4.0

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

# ---------------------------------------------------------------------------
# Lab mode — realistic (default) vs scoped (deterministic legacy)
# ---------------------------------------------------------------------------

LAB_MODE = os.environ.get("XXE_LAB_MODE", "realistic").lower()
if LAB_MODE not in ("scoped", "realistic"):
    LAB_MODE = "realistic"

_VALID_MODES = ("scoped", "realistic")


def _mode() -> str:
    hdr = (request.headers.get("X-Lab-Mode") or "").lower()
    if hdr in _VALID_MODES:
        return hdr
    qs = (request.args.get("lab_mode") or "").lower()
    if qs in _VALID_MODES:
        return qs
    return LAB_MODE


# ---------------------------------------------------------------------------
# Request log (thread-safe ring buffer) + counters
# ---------------------------------------------------------------------------

_LOG: deque = deque(maxlen=LOG_SIZE)
_LOG_LOCK = threading.Lock()
_STATS = {"total": 0, "by_path": {}, "by_mode": {},
          "started": time.time(), "errors": 0}
_STATS_LOCK = threading.Lock()


def _preview(body: bytes, limit: int = PREVIEW_CHARS) -> str:
    if not body:
        return ""
    try:
        text = body[:limit].decode("utf-8", "replace")
    except Exception:
        text = repr(body[:limit])
    return text.replace("\x00", "·")


def _mk_entry(path: str, **kw) -> dict:
    try:
        method = request.method
        ct = request.content_type or ""
        ua = (request.headers.get("User-Agent") or "")[:200]
        remote = request.remote_addr or ""
        mode = _mode()
        lab_override = "header" if (
            (request.headers.get("X-Lab-Mode") or "").lower() in _VALID_MODES
        ) else ("query" if (
            (request.args.get("lab_mode") or "").lower() in _VALID_MODES
        ) else "default")
    except Exception:
        method = ct = ua = remote = ""
        mode = LAB_MODE
        lab_override = "default"

    entry = {
        "id": getattr(g, "req_id", ""),
        "path": path,
        "endpoint": path,
        "method": method,
        "ct": ct,
        "ua": ua,
        "remote": remote,
        "mode": mode,
        "mode_source": lab_override,
    }
    entry.update(kw)
    return entry


def _log(entry: dict):
    entry.setdefault("ts", time.time())
    entry.setdefault(
        "iso",
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    )
    with _LOG_LOCK:
        _LOG.appendleft(entry)
    with _STATS_LOCK:
        _STATS["total"] += 1
        p = entry.get("path", "?")
        _STATS["by_path"][p] = _STATS["by_path"].get(p, 0) + 1
        m = entry.get("mode", "?")
        _STATS["by_mode"][m] = _STATS["by_mode"].get(m, 0) + 1
        if entry.get("error") or entry.get("status", 200) >= 500:
            _STATS["errors"] += 1


def _log_req(entry: dict):
    entry.setdefault("endpoint", getattr(request, "path", "?"))
    entry.setdefault("method", getattr(request, "method", "?"))
    _log(entry)


@app.before_request
def _stamp_request():
    g.req_id = f"{int(time.time() * 1000):x}-{os.urandom(4).hex()}"


@app.after_request
def _enrich_log(response: Response) -> Response:
    rid = getattr(g, "req_id", None)
    if not rid:
        return response
    try:
        data = response.get_data()
        resp_len = len(data)
        resp_prev = _preview(data[:RESP_PREVIEW_CHARS], RESP_PREVIEW_CHARS)
    except Exception:
        resp_len = 0
        resp_prev = ""
    with _LOG_LOCK:
        for entry in _LOG:
            if entry.get("id") == rid:
                entry["resp_len"] = resp_len
                entry["resp_preview"] = resp_prev
                break
    return response


def _libxml_version_string() -> str:
    try:
        return ".".join(str(p) for p in etree.LIBXML_VERSION[:3])
    except Exception:
        return "unknown"

_LIBXML_VER = _libxml_version_string()

# ---------------------------------------------------------------------------
# Parser configuration matrix
# ---------------------------------------------------------------------------

PARSER_CONFIGS = {
    "vuln_full": dict(
        resolve_entities=True, load_dtd=True, no_network=False,
        dtd_validation=False, huge_tree=False,
    ),
    "safe": dict(
        resolve_entities=False, load_dtd=False, no_network=True,
        dtd_validation=False, huge_tree=False,
    ),
    "xinclude_only": dict(
        resolve_entities=False, load_dtd=False, no_network=False,
        dtd_validation=False, huge_tree=False,
    ),
}


# ---------------------------------------------------------------------------
# URL fetching helper
# ---------------------------------------------------------------------------

_HTTPX_CLIENT: httpx.Client | None = None
_HTTPX_CLIENT_LOCK = threading.Lock()


def _httpx_client() -> httpx.Client:
    global _HTTPX_CLIENT
    with _HTTPX_CLIENT_LOCK:
        if _HTTPX_CLIENT is None:
            try:
                _HTTPX_CLIENT = httpx.Client(
                    timeout=FETCH_TIMEOUT,
                    verify=False,
                    follow_redirects=True,
                    http2=True,
                    headers={"User-Agent": "xxe-lab/7"},
                )
            except ImportError:
                print("  [_httpx_client] h2 not installed; falling back "
                      "to HTTP/1.1. Install with: "
                      "pip install 'httpx[http2]'", flush=True)
                _HTTPX_CLIENT = httpx.Client(
                    timeout=FETCH_TIMEOUT,
                    verify=False,
                    follow_redirects=True,
                    http2=False,
                    headers={"User-Agent": "xxe-lab/7"},
                )
        return _HTTPX_CLIENT


def _fetch_url(url: str) -> bytes | None:
    if url.startswith(("http://", "https://")):
        try:
            r = _httpx_client().get(url)
            return r.content[:MAX_RESP_BYTES]
        except Exception as e:
            print(f"  [_fetch_url] http failed: {url} — {e!r}", flush=True)
            return None
    if url.startswith("ftp://"):
        try:
            with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT) as r:
                return r.read(MAX_RESP_BYTES)
        except Exception as e:
            print(f"  [_fetch_url] ftp failed: {url} — {e!r}", flush=True)
            return None
    if url.startswith("file://"):
        path = url[len("file://"):]
        if path.startswith("localhost/"):
            path = path[len("localhost"):]
        if os.name == "nt" and len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        try:
            with open(path, "rb") as f:
                return f.read(MAX_RESP_BYTES)
        except Exception as e:
            print(f"  [_fetch_url] file failed: {path} — {e!r}", flush=True)
            return None
    if url.startswith("jar:file://"):
        rest = url[len("jar:"):]
        if "!/" in rest:
            jar_url, inner = rest.split("!/", 1)
        else:
            return None
        jar_path = jar_url[len("file://"):]
        try:
            with zipfile.ZipFile(jar_path) as z:
                return z.read(inner)[:MAX_RESP_BYTES]
        except Exception as e:
            print(f"  [_fetch_url] jar failed: {jar_path}!/{inner} — "
                  f"{e!r}", flush=True)
            return None
    return None


class _HTTPResolver(etree.Resolver):
    def resolve(self, url, pubid, context):
        if not url.startswith(("http://", "https://")):
            return None
        data = _fetch_url(url)
        if data is None:
            return None
        return self.resolve_string(data, context)


_HTTP_RESOLVER = _HTTPResolver()
_PARSER_CACHE: dict[str, etree.XMLParser] = {}
_PARSER_CACHE_LOCK = threading.Lock()


def _make_parser(cfg_name: str) -> etree.XMLParser:
    with _PARSER_CACHE_LOCK:
        cached = _PARSER_CACHE.get(cfg_name)
        if cached is not None:
            return cached
        parser = etree.XMLParser(**PARSER_CONFIGS[cfg_name])
        if cfg_name == "vuln_full":
            parser.resolvers.add(_HTTP_RESOLVER)
        _PARSER_CACHE[cfg_name] = parser
        return parser


def _parse_and_text(body: bytes, cfg_name: str) -> str:
    parser = _make_parser(cfg_name)
    root = etree.fromstring(body, parser)
    text = "".join(root.itertext())
    return _truncate(text)


def _truncate(text: str) -> str:
    if text is None:
        return ""
    b = text.encode("utf-8", errors="replace")
    if len(b) > MAX_RESP_BYTES:
        return b[:MAX_RESP_BYTES].decode("utf-8", errors="replace") + \
               "\n\n…[truncated]"
    return text


def _traceback_text() -> str:
    tb = traceback.format_exc()
    if len(tb) > MAX_TRACE_BYTES:
        tb = tb[:MAX_TRACE_BYTES] + "\n…[truncated]"
    return tb


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

_CT_ALIASES = {
    "application/soap+xml": ("text/xml", "application/xml"),
    "image/svg+xml": ("text/xml", "application/xml", "application/octet-stream"),
    "multipart/form-data": ("multipart/mixed", "multipart/related"),
    "application/x-www-form-urlencoded": ("application/xml", "text/xml"),
    "application/json": ("application/xml", "text/xml"),
    "application/x-yaml": ("text/yaml", "text/x-yaml", "application/yaml"),
}

_REJECT_BODIES = {
    400: ("Bad Request",
          "The request could not be understood by the server due to "
          "malformed syntax."),
    405: ("Method Not Allowed",
          "The method is not allowed for the requested URL."),
    413: ("Payload Too Large",
          "The request entity is larger than the server is willing or "
          "able to process."),
    415: ("Unsupported Media Type",
          "The server does not support the media type transmitted in "
          "the request."),
    422: ("Unprocessable Entity",
          "The request was well-formed but contained semantic errors."),
}
_REJECT_MIME = {
    400: "text/plain",
    405: "text/plain",
    413: "text/plain",
    415: "text/plain",
    422: "application/json",
}


def _ct_in(*expected: str) -> bool:
    ct = (request.content_type or "").lower()
    if any(e.lower() in ct for e in expected):
        return True
    if _mode() == "realistic":
        for e in expected:
            for alias in _CT_ALIASES.get(e.lower(), ()):
                if alias in ct:
                    return True
    return False


def _root_element_name(body: bytes) -> str:
    cleaned = body
    if cleaned[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            cleaned = cleaned.decode("utf-16").encode("utf-8")
        except Exception:
            return ""
    if cleaned[:4] in (b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00"):
        try:
            cleaned = cleaned.decode("utf-32").encode("utf-8")
        except Exception:
            return ""
    cleaned = re.sub(rb"<\?[^?]*\?>", b"", cleaned)
    cleaned = re.sub(rb"<!--.*?-->", b"", cleaned, flags=re.DOTALL)
    cleaned = re.sub(
        rb"<!DOCTYPE\s+[^\[>]*(\[[^\]]*\])?\s*>",
        b"", cleaned, count=1, flags=re.DOTALL,
    )
    m = re.search(rb"<([A-Za-z_][\w:.\-]*)[\s/>]", cleaned)
    return m.group(1).decode("ascii", "replace").lower() if m else ""


def _has_doctype(body: bytes) -> bool:
    return re.search(rb"<!DOCTYPE", body, flags=re.IGNORECASE) is not None


def _has_parameter_entity(body: bytes) -> bool:
    return re.search(rb"<!ENTITY\s+%", body) is not None


def _has_external_http_entity(body: bytes) -> bool:
    return re.search(
        rb"""SYSTEM\s+['"]https?://""", body, flags=re.IGNORECASE
    ) is not None


def _has_xinclude(body: bytes) -> bool:
    return (b"<xi:include" in body
            or b"<xinclude" in body
            or b"http://www.w3.org/2001/XInclude" in body)


def _has_xinclude_parse_xml(body: bytes) -> bool:
    if not _has_xinclude(body):
        return False
    return bool(re.search(rb"""parse\s*=\s*['"]xml['"]""", body))


def _has_xinclude_http(body: bytes) -> bool:
    if not _has_xinclude(body):
        return False
    return bool(re.search(
        rb"""href\s*=\s*['"]https?://""", body, flags=re.IGNORECASE
    ))


def _has_xml_stylesheet_pi(body: bytes) -> bool:
    return re.search(rb"<\?xml-stylesheet", body,
                     flags=re.IGNORECASE) is not None


def _has_utf16_bom(body: bytes) -> bool:
    return body[:2] in (b"\xff\xfe", b"\xfe\xff")


def _declares_utf7(body: bytes) -> bool:
    return re.search(
        rb"""encoding\s*=\s*['"]UTF-7['"]""", body, flags=re.IGNORECASE
    ) is not None


def _has_ucs4_bom(body: bytes) -> bool:
    return body[:4] in (b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")


def _has_altdoctype(body: bytes) -> bool:
    if re.search(rb"<!doctype", body):
        return True
    if re.search(rb"<!DOC<!--\s*-->\s*TYPE", body):
        return True
    if re.search(rb"<!DOC\s+TYPE", body):
        return True
    return False


def _has_metadata_url(body: bytes) -> bool:
    b = body.lower()
    return (b"169.254.169.254" in b
            or b"metadata.google.internal" in b
            or b"100.100.100.200" in b
            or b"/opc/" in b                   
            or b"kubernetes.default.svc" in b   
            or b"/metadata/identity/" in b      
            or b"/metadata/instance" in b)      


def _has_external_system_uri(body: bytes) -> bool:
    return _has_external_http_entity(body)


def _has_jar_uri(body: bytes) -> bool:
    return b"jar:file://" in body or b"jar:http://" in body


def _is_saml_shaped(body: bytes) -> bool:
    root = _root_element_name(body)
    if not root:
        return False
    return (root.startswith("saml:")
            or root.startswith("saml2:")
            or root.startswith("assertion")
            or root.endswith(":assertion")
            or root == "response"
            or root.endswith(":response"))


def _is_soap_shaped(body: bytes) -> bool:
    root = _root_element_name(body)
    if not root:
        return False
    return (root == "envelope"
            or root.endswith(":envelope")
            or root == "body"
            or root.endswith(":body"))


def _is_xslt_shaped(body: bytes) -> bool:
    root = _root_element_name(body)
    return root in ("xsl:stylesheet", "xsl:transform")


def _is_xsd_shaped(body: bytes) -> bool:
    if _root_element_name(body) in ("xs:schema", "xsd:schema", "schema"):
        return True
    return re.search(rb"\bxsi:[A-Za-z]", body) is not None


def _is_xsd_import_shaped(body: bytes) -> bool:
    if not _is_xsd_shaped(body):
        return False
    return (re.search(rb"<xsd?:import", body) is not None
            or re.search(rb"<xsd?:include", body) is not None)


def _is_yaml_shaped(body: bytes) -> bool:
    lower = body.lower()
    if b"!!python/object" in lower:
        return True
    if b"!!javax.script" in lower:
        return True
    if b"!!java." in lower:
        return True
    return False

# ---------------------------------------------------------------------------
# Rejection helper (deterministic)
# ---------------------------------------------------------------------------

def _reject(endpoint: str, reason: str, status: int = 400,
            gate: str = "hard") -> Response:
    body = request.get_data() or b""

    if _mode() == "scoped":
        _log_req(_mk_entry(endpoint, status=200, gate="rejected",
                           gate_kind=gate,
                           gate_reason=reason,
                           len=len(body), req_len=len(body),
                           note=f"out-of-scope: {reason}",
                           preview=_preview(body[:400])))
        return _ok(f"out of scope: {reason}", endpoint=endpoint)

    short, long = _REJECT_BODIES.get(status, _REJECT_BODIES[400])
    seed_material = f"{endpoint}|{gate}|{status}".encode("utf-8")
    seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:4], "big")
    text = short if (seed & 1) == 0 else long

    _log_req(_mk_entry(endpoint, status=status, gate="rejected",
                       gate_kind=gate, gate_reason=reason,
                       len=len(body), req_len=len(body),
                       note="rejected (realistic)",
                       preview=_preview(body[:400])))

    r = Response(text, status=status,
                 mimetype=_REJECT_MIME.get(status, "text/plain"))
    r.headers["X-Lab-Endpoint"] = endpoint
    r.headers["X-Request-Id"] = g.get("req_id", "")
    return r


def _hard_gate(endpoint: str, reason: str, in_scope: bool,
               status: int = 400) -> Response | None:
    if in_scope:
        return None
    return _reject(endpoint, reason, status=status, gate="hard")


def _soft_gate(endpoint: str, reason: str, in_scope: bool) -> Response | None:
    if in_scope:
        return None
    if _mode() == "scoped":
        return _reject(endpoint, reason, gate="soft")
    return None


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _ok(text: str, endpoint: str = "") -> Response:
    r = Response(text or "OK", mimetype="text/plain")
    if endpoint:
        r.headers["X-Lab-Endpoint"] = endpoint
    return r


def _bad(msg: str, status: int = 400, endpoint: str = "") -> Response:
    r = Response(msg, status=status, mimetype="text/plain")
    if endpoint:
        r.headers["X-Lab-Endpoint"] = endpoint
    return r


def _err(endpoint: str = "") -> Response:
    r = Response(_traceback_text(), status=500, mimetype="text/plain")
    if endpoint:
        r.headers["X-Lab-Endpoint"] = endpoint
    return r


def _require_body() -> bytes | None:
    body = request.get_data()
    return body if body else None


def _accept(endpoint: str, **kw) -> dict:
    kw.setdefault("gate", "accepted")
    kw.setdefault("status", 200)
    return _mk_entry(endpoint, **kw)


@app.errorhandler(413)
def _too_large(_e):
    _log_req(_mk_entry(request.path, status=413, gate="rejected",
                       gate_kind="hard", gate_reason="body too large",
                       note="payload too large", preview=""))
    return _bad("payload too large", 413)


# ---------------------------------------------------------------------------
# Unscoped vulnerable endpoints
# ---------------------------------------------------------------------------

@app.route("/xml/vulnerable", methods=["POST"])
def xml_vulnerable():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/vulnerable")
    t0 = time.time()
    try:
        text = _parse_and_text(body, "vuln_full")
        dt = round((time.time() - t0) * 1000, 1)
        _log_req(_accept("/xml/vulnerable", ms=dt, len=len(body),
                         req_len=len(body), preview=_preview(body)))
        return _ok(text, endpoint="/xml/vulnerable")
    except etree.XMLSyntaxError:
        dt = round((time.time() - t0) * 1000, 1)
        _log_req(_mk_entry("/xml/vulnerable", status=500, ms=dt,
                           len=len(body), req_len=len(body),
                           error=True, gate="error",
                           preview=_preview(body)))
        return _err(endpoint="/xml/vulnerable")
    except Exception:
        return _err(endpoint="/xml/vulnerable")


@app.route("/xml/blind", methods=["POST"])
def xml_blind():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/blind")
    t0 = time.time()
    try:
        _ = _parse_and_text(body, "vuln_full")
    except Exception:
        pass
    dt = round((time.time() - t0) * 1000, 1)
    _log_req(_accept("/xml/blind", ms=dt, len=len(body),
                     req_len=len(body),
                     note="blind — no reflection",
                     preview=_preview(body)))
    return _ok("processed", endpoint="/xml/blind")


@app.route("/xml/error", methods=["POST"])
def xml_error():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/error")
    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/error", note="parsed ok",
                         preview=_preview(body),
                         req_len=len(body)))
        return _ok(text or "parsed ok", endpoint="/xml/error")
    except etree.XMLSyntaxError as e:
        _log_req(_mk_entry("/xml/error", status=500, error=True,
                           gate="error", note="XMLSyntaxError",
                           preview=_preview(body), req_len=len(body)))
        return Response(f"XML parse error: {e}",
                        status=500, mimetype="text/plain",
                        headers={"X-Lab-Endpoint": "/xml/error"})
    except Exception as e:
        _log_req(_mk_entry("/xml/error", status=500, error=True,
                           gate="error", note=type(e).__name__,
                           preview=_preview(body), req_len=len(body)))
        return Response(f"Internal error: {type(e).__name__}",
                        status=500, mimetype="text/plain",
                        headers={"X-Lab-Endpoint": "/xml/error"})


@app.route("/xml/reflect", methods=["POST"])
def xml_reflect():
    body = _require_body() or b""
    try:
        reflected = body.decode("utf-8", errors="replace")
    except Exception:
        reflected = repr(body)

    parsed = ""
    try:
        parsed = _parse_and_text(body, "vuln_full")
    except Exception:
        pass

    out = "--- reflected ---\n" + reflected + "\n--- parsed ---\n" + parsed
    _log_req(_accept("/xml/reflect", note="reflected + parsed",
                     preview=_preview(body), req_len=len(body)))
    return _ok(_truncate(out), endpoint="/xml/reflect")


@app.route("/xml/timing", methods=["POST"])
def xml_timing():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/timing")
    t0 = time.time()
    if _has_external_system_uri(body):
        time.sleep(TIMING_SLEEP_SECONDS)
    try:
        text = _parse_and_text(body, "vuln_full")
    except Exception:
        text = "processed"
    dt = round((time.time() - t0) * 1000, 1)
    _log_req(_accept("/xml/timing", ms=dt,
                     note="sleep on external entity",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "processed", endpoint="/xml/timing")


# ---------------------------------------------------------------------------
# Scoped vulnerable endpoints
# ---------------------------------------------------------------------------

@app.route("/xml/ssrf", methods=["POST"])
def xml_ssrf():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/ssrf")

    gate = _soft_gate("/xml/ssrf",
                      "requires <!ENTITY ... SYSTEM \"http(s)://...\">",
                      _has_external_http_entity(body))
    if gate:
        return gate

    t0 = time.time()
    try:
        text = _parse_and_text(body, "vuln_full")
        dt = round((time.time() - t0) * 1000, 1)
        _log_req(_accept("/xml/ssrf", ms=dt, len=len(body),
                         req_len=len(body), preview=_preview(body)))
        return _ok(text, endpoint="/xml/ssrf")
    except Exception:
        dt = round((time.time() - t0) * 1000, 1)
        _log_req(_mk_entry("/xml/ssrf", status=500, ms=dt,
                           len=len(body), req_len=len(body),
                           error=True, gate="error",
                           preview=_preview(body)))
        return _err(endpoint="/xml/ssrf")


@app.route("/xml/svg", methods=["POST"])
def xml_svg():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/svg")

    gate = _hard_gate("/xml/svg",
                      "Content-Type must be image/svg+xml",
                      _ct_in("image/svg+xml", "svg"),
                      status=415)
    if gate:
        return gate

    gate = _soft_gate("/xml/svg",
                      "root element must be <svg>",
                      _root_element_name(body) == "svg")
    if gate:
        return gate

    try:
        root = etree.fromstring(body, _make_parser("vuln_full"))
        text = _truncate("".join(root.itertext())) or "svg ok"
        _log_req(_accept("/xml/svg", ct=request.content_type,
                         preview=_preview(body), req_len=len(body)))
        return _ok(text, endpoint="/xml/svg")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/svg", status=500, error=True,
                           gate="error", ct=request.content_type,
                           preview=_preview(body), req_len=len(body)))
        return _err(endpoint="/xml/svg")
    except Exception:
        return _err(endpoint="/xml/svg")


@app.route("/xml/saml", methods=["POST"])
def xml_saml():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/saml")

    gate = _soft_gate("/xml/saml",
                      "root element must be <saml:...>, <Response>, or "
                      "<Assertion>",
                      _is_saml_shaped(body))
    if gate:
        return gate

    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/saml", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/saml")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/saml", status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/saml")
    except Exception:
        return _err(endpoint="/xml/saml")


@app.route("/xml/saml-presig", methods=["POST"])
def xml_saml_presig():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/saml-presig")

    gate = _soft_gate("/xml/saml-presig",
                      "root element must be SAML-shaped",
                      _is_saml_shaped(body))
    if gate:
        return gate

    try:
        text = _parse_and_text(body, "vuln_full")
        out = ("assertion parsed\n"
               "signature verification failed: invalid signature\n"
               + (text or ""))
        _log_req(_accept("/xml/saml-presig",
                         note="parsed before signature verify",
                         preview=_preview(body), req_len=len(body)))
        return _ok(_truncate(out), endpoint="/xml/saml-presig")
    except etree.XMLSyntaxError as e:
        _log_req(_mk_entry("/xml/saml-presig", status=500, error=True,
                           gate="error", note=str(e)[:120],
                           preview=_preview(body), req_len=len(body)))
        return Response(f"XML parse error: {e}",
                        status=500, mimetype="text/plain",
                        headers={"X-Lab-Endpoint": "/xml/saml-presig"})
    except Exception:
        return _err(endpoint="/xml/saml-presig")


@app.route("/xml/soap", methods=["POST"])
def xml_soap():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/soap")

    gate = _hard_gate("/xml/soap",
                      "Content-Type must be application/soap+xml",
                      _ct_in("application/soap+xml"),
                      status=415)
    if gate:
        return gate

    gate = _soft_gate("/xml/soap",
                      "root element must be <soap:Envelope> or <Envelope>",
                      _is_soap_shaped(body))
    if gate:
        return gate

    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/soap", ct=request.content_type,
                         preview=_preview(body), req_len=len(body)))
        return _ok(text, endpoint="/xml/soap")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/soap", status=500, error=True,
                           gate="error", ct=request.content_type,
                           preview=_preview(body), req_len=len(body)))
        return _err(endpoint="/xml/soap")
    except Exception:
        return _err(endpoint="/xml/soap")


class _XIncludeResolver(etree.Resolver):
    def resolve(self, url, pubid, context):
        if url.startswith("file://"):
            path = url[len("file://"):]
            if path.startswith("localhost/"):
                path = path[len("localhost"):]
            if os.name == "nt" and len(path) > 2 and path[0] == "/" and path[2] == ":":
                path = path[1:]
            try:
                return self.resolve_filename(path, context)
            except Exception:
                return None
        if url.startswith(("http://", "https://", "ftp://")):
            data = _fetch_url(url)
            if data is None:
                return None
            return self.resolve_string(data, context)
        return None

_XINCLUDE_RESOLVER = _XIncludeResolver()


def _xinclude_parse(body: bytes) -> str:
    parser = etree.XMLParser(**PARSER_CONFIGS["xinclude_only"])
    parser.resolvers.add(_XINCLUDE_RESOLVER)
    root = etree.fromstring(body, parser)
    root.getroottree().xinclude()
    return _truncate("".join(root.itertext()) or "xinclude ok")


def _xinclude_common(endpoint: str, extra_gate: callable = None):
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint=endpoint)

    gate = _hard_gate(endpoint, "DOCTYPE is not accepted here",
                      not _has_doctype(body))
    if gate:
        return gate

    if extra_gate is not None:
        g2 = _soft_gate(endpoint, extra_gate[0], extra_gate[1](body))
        if g2:
            return g2
    else:
        g2 = _soft_gate(endpoint, "requires <xi:include>",
                        _has_xinclude(body))
        if g2:
            return g2

    try:
        text = _xinclude_parse(body)
        _log_req(_accept(endpoint, preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint=endpoint)
    except Exception:
        _log_req(_mk_entry(endpoint, status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint=endpoint)


@app.route("/xml/xinclude", methods=["POST"])
def xml_xinclude():
    return _xinclude_common("/xml/xinclude")


@app.route("/xml/xinclude-xml", methods=["POST"])
def xml_xinclude_xml():
    return _xinclude_common(
        "/xml/xinclude-xml",
        extra_gate=("requires <xi:include ... parse=\"xml\">",
                    _has_xinclude_parse_xml),
    )


@app.route("/xml/xinclude-ssrf", methods=["POST"])
def xml_xinclude_ssrf():
    return _xinclude_common(
        "/xml/xinclude-ssrf",
        extra_gate=("requires <xi:include href=\"http(s)://...\">",
                    _has_xinclude_http),
    )


def _maybe_decode_utf16(raw: bytes) -> bytes:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            decoded = raw.decode("utf-16")
        except UnicodeDecodeError as e:
            raise ValueError(f"utf-16 decode failed: {e}") from e
        decoded = re.sub(
            r'(<\?xml[^?]*?)\s+encoding\s*=\s*["\']UTF-16["\']',
            r"\1", decoded, count=1, flags=re.IGNORECASE,
        )
        return decoded.encode("utf-8")
    return raw


def _maybe_decode_utf7(raw: bytes) -> bytes:
    lowered = raw.lower()
    if b'encoding="utf-7"' in lowered or b"encoding='utf-7'" in lowered:
        try:
            return raw.decode("utf-7").encode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"utf-7 decode failed: {e}") from e
    return raw


def _maybe_decode_ucs4(raw: bytes) -> bytes:
    if raw[:4] == b"\x00\x00\xfe\xff":
        try:
            decoded = raw.decode("utf-32-be")
        except UnicodeDecodeError as e:
            raise ValueError(f"ucs-4 be decode failed: {e}") from e
        decoded = re.sub(
            r'(<\?xml[^?]*?)\s+encoding\s*=\s*["\']UCS-4["\']',
            r"\1", decoded, count=1, flags=re.IGNORECASE,
        )
        return decoded.encode("utf-8")
    if raw[:4] == b"\xff\xfe\x00\x00":
        try:
            decoded = raw.decode("utf-32-le")
        except UnicodeDecodeError as e:
            raise ValueError(f"ucs-4 le decode failed: {e}") from e
        return decoded.encode("utf-8")
    return raw


@app.route("/xml/utf16", methods=["POST"])
def xml_utf16():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/utf16")

    gate = _hard_gate("/xml/utf16", "requires a UTF-16 BOM",
                      _has_utf16_bom(raw))
    if gate:
        return gate

    try:
        body = _maybe_decode_utf16(raw)
    except ValueError as e:
        _log_req(_mk_entry("/xml/utf16", status=400, error=True,
                           gate="error", note=str(e),
                           preview=_preview(raw), req_len=len(raw)))
        return _bad(str(e), 400, endpoint="/xml/utf16")
    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/utf16", preview=_preview(raw),
                         req_len=len(raw)))
        return _ok(text, endpoint="/xml/utf16")
    except Exception:
        _log_req(_mk_entry("/xml/utf16", status=500, error=True,
                           gate="error", preview=_preview(raw),
                           req_len=len(raw)))
        return _err(endpoint="/xml/utf16")


@app.route("/xml/utf7", methods=["POST"])
def xml_utf7():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/utf7")

    gate = _hard_gate("/xml/utf7",
                      "XML declaration must claim encoding=\"UTF-7\"",
                      _declares_utf7(raw))
    if gate:
        return gate

    try:
        body = _maybe_decode_utf7(raw)
    except ValueError as e:
        _log_req(_mk_entry("/xml/utf7", status=400, error=True,
                           gate="error", note=str(e),
                           preview=_preview(raw), req_len=len(raw)))
        return _bad(str(e), 400, endpoint="/xml/utf7")
    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/utf7", preview=_preview(raw),
                         req_len=len(raw)))
        return _ok(text, endpoint="/xml/utf7")
    except Exception:
        _log_req(_mk_entry("/xml/utf7", status=500, error=True,
                           gate="error", preview=_preview(raw),
                           req_len=len(raw)))
        return _err(endpoint="/xml/utf7")


@app.route("/xml/encoding-ucs4", methods=["POST"])
def xml_encoding_ucs4():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/encoding-ucs4")

    gate = _hard_gate("/xml/encoding-ucs4", "requires a UCS-4 BOM",
                      _has_ucs4_bom(raw))
    if gate:
        return gate

    try:
        body = _maybe_decode_ucs4(raw)
    except ValueError as e:
        _log_req(_mk_entry("/xml/encoding-ucs4", status=400, error=True,
                           gate="error", note=str(e),
                           preview=_preview(raw), req_len=len(raw)))
        return _bad(str(e), 400, endpoint="/xml/encoding-ucs4")
    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/encoding-ucs4", preview=_preview(raw),
                         req_len=len(raw)))
        return _ok(text, endpoint="/xml/encoding-ucs4")
    except Exception:
        _log_req(_mk_entry("/xml/encoding-ucs4", status=500, error=True,
                           gate="error", preview=_preview(raw),
                           req_len=len(raw)))
        return _err(endpoint="/xml/encoding-ucs4")


@app.route("/xml/encoding-altdoctype", methods=["POST"])
def xml_encoding_altdoctype():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/encoding-altdoctype")

    gate = _hard_gate("/xml/encoding-altdoctype",
                      "requires an alternate DOCTYPE form "
                      "(lowercase, comment-split, or space-injected)",
                      _has_altdoctype(raw))
    if gate:
        return gate

    try:
        text = _parse_and_text(raw, "vuln_full")
        _log_req(_accept("/xml/encoding-altdoctype",
                         preview=_preview(raw), req_len=len(raw)))
        return _ok(text, endpoint="/xml/encoding-altdoctype")
    except Exception:
        _log_req(_mk_entry("/xml/encoding-altdoctype", status=500,
                           error=True, gate="error",
                           preview=_preview(raw), req_len=len(raw)))
        return _err(endpoint="/xml/encoding-altdoctype")


@app.route("/xml/parameter", methods=["POST"])
def xml_parameter():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/parameter")

    gate = _soft_gate("/xml/parameter",
                      "requires a parameter entity (<!ENTITY % ...>)",
                      _has_parameter_entity(body))
    if gate:
        return gate

    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/parameter", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/parameter")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/parameter", status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/parameter")
    except Exception:
        return _err(endpoint="/xml/parameter")


_DOC_CALL_RE = re.compile(rb"""document\(\s*['"]([^'"]+)['"]\s*\)""")


@app.route("/xml/xslt", methods=["POST"])
def xml_xslt():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/xslt")

    gate = _soft_gate("/xml/xslt",
                      "root element must be <xsl:stylesheet> or "
                      "<xsl:transform>",
                      _is_xslt_shaped(body))
    if gate:
        return gate

    try:
        sty = etree.fromstring(body, _make_parser("vuln_full"))
        src = etree.fromstring(
            b'<?xml version="1.0"?><root><data>x</data></root>',
            _make_parser("safe"),
        )
        transform = etree.XSLT(sty)
        result = transform(src)
        text = _truncate(str(result)) or "xslt ok"

        chunks: list[str] = []
        for m in _DOC_CALL_RE.findall(body):
            url = m.decode("utf-8", "replace")
            data = _fetch_url(url)
            if data:
                chunks.append(data.decode("utf-8", "replace"))
        if chunks:
            text += "\n" + "\n".join(chunks)

        _log_req(_accept("/xml/xslt", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/xslt")
    except Exception:
        _log_req(_mk_entry("/xml/xslt", status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/xslt")


_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
_XSI_NONS = f"{{{_XSI_NS}}}noNamespaceSchemaLocation"
_XSI_LOC = f"{{{_XSI_NS}}}schemaLocation"
_XSD_NS = "http://www.w3.org/2001/XMLSchema"
_XSD_IMPORT = f"{{{_XSD_NS}}}import"
_XSD_INCLUDE = f"{{{_XSD_NS}}}include"


@app.route("/xml/xsd", methods=["POST"])
def xml_xsd():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/xsd")

    gate = _soft_gate("/xml/xsd",
                      "requires an xsi:... attribute or <xs:schema> root",
                      _is_xsd_shaped(body))
    if gate:
        return gate

    try:
        parser = _make_parser("vuln_full")
        root = etree.fromstring(body, parser)
        text = _truncate("".join(root.itertext())) or "xsd ok"

        loc = root.get(_XSI_NONS) or root.get(_XSI_LOC)
        if loc:
            url = loc.split()[-1]
            data = _fetch_url(url)
            if data:
                text += "\n" + data.decode("utf-8", "replace")

        _log_req(_accept("/xml/xsd", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/xsd")
    except Exception:
        _log_req(_mk_entry("/xml/xsd", status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/xsd")


@app.route("/xml/xsd-import", methods=["POST"])
def xml_xsd_import():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/xsd-import")

    gate = _soft_gate("/xml/xsd-import",
                      "requires <xs:import> or <xs:include> inside "
                      "<xs:schema>",
                      _is_xsd_import_shaped(body))
    if gate:
        return gate

    try:
        parser = _make_parser("vuln_full")
        root = etree.fromstring(body, parser)
        text = _truncate("".join(root.itertext())) or "xsd-import ok"

        url = None
        for child in root.iter():
            if child.tag in (_XSD_IMPORT, _XSD_INCLUDE):
                url = child.get("schemaLocation")
                if url:
                    break
        if url:
            data = _fetch_url(url)
            if data:
                text += "\n" + data.decode("utf-8", "replace")

        _log_req(_accept("/xml/xsd-import", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/xsd-import")
    except Exception:
        _log_req(_mk_entry("/xml/xsd-import", status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/xsd-import")


_XML_STYLESHEET_RE = re.compile(
    rb"""<\?xml-stylesheet[^>]*?href\s*=\s*['"]([^'"]+)['"][^>]*?\?>""",
    re.IGNORECASE,
)


@app.route("/xml/pi", methods=["POST"])
def xml_pi():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/pi")

    gate = _soft_gate("/xml/pi",
                      "requires an <?xml-stylesheet ...?> PI",
                      _has_xml_stylesheet_pi(body))
    if gate:
        return gate

    try:
        parser = _make_parser("vuln_full")
        root = etree.fromstring(body, parser)
        text = _truncate("".join(root.itertext())) or "pi ok"

        for m in _XML_STYLESHEET_RE.findall(body):
            url = m.decode("utf-8", "replace")
            data = _fetch_url(url)
            if data:
                text += "\n" + data.decode("utf-8", "replace")

        _log_req(_accept("/xml/pi", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/pi")
    except Exception:
        _log_req(_mk_entry("/xml/pi", status=500, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/pi")


@app.route("/xml/upload", methods=["POST"])
def xml_upload():
    gate = _hard_gate("/xml/upload",
                      "Content-Type must be multipart/form-data",
                      _ct_in("multipart/form-data"),
                      status=415)
    if gate:
        return gate

    xml_body = None
    for field_name in ("xml", "data", "file", "document", "upload"):
        f = request.files.get(field_name)
        if f is not None:
            data = f.read()
            if data:
                xml_body = data
                break
        val = request.form.get(field_name)
        if val:
            xml_body = val.encode("utf-8", errors="ignore")
            break
    if not xml_body:
        gate = _hard_gate(
            "/xml/upload",
            "no XML-bearing field found in the multipart body",
            False, status=400,
        )
        return gate

    try:
        text = _parse_and_text(xml_body, "vuln_full")
        _log_req(_accept("/xml/upload", ct=request.content_type,
                         preview=_preview(xml_body),
                         req_len=len(xml_body)))
        return _ok(text, endpoint="/xml/upload")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/upload", status=500, error=True,
                           gate="error", ct=request.content_type,
                           preview=_preview(xml_body),
                           req_len=len(xml_body)))
        return _err(endpoint="/xml/upload")
    except Exception:
        return _err(endpoint="/xml/upload")


def _read_docx_part(raw: bytes, part: str) -> bytes | None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            return z.read(part)
    except (zipfile.BadZipFile, KeyError):
        return None
    except Exception:
        return None


@app.route("/xml/docx", methods=["POST"])
def xml_docx():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/docx")
    doc_xml = _read_docx_part(raw, "word/document.xml")
    if doc_xml is None:
        gate = _hard_gate("/xml/docx", "no word/document.xml in docx",
                          False, status=400)
        return gate
    try:
        text = _parse_and_text(doc_xml, "vuln_full")
        _log_req(_accept("/xml/docx",
                         note="parsed word/document.xml",
                         len=len(doc_xml), req_len=len(raw),
                         preview=_preview(doc_xml)))
        return _ok(text, endpoint="/xml/docx")
    except Exception:
        _log_req(_mk_entry("/xml/docx", status=500, error=True,
                           gate="error", note="docx parse failure",
                           preview=_preview(doc_xml),
                           req_len=len(raw)))
        return _err(endpoint="/xml/docx")


@app.route("/xml/office-xslt-docx", methods=["POST"])
def xml_office_xslt_docx():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/office-xslt-docx")
    doc_xml = _read_docx_part(raw, "word/document.xml")
    if doc_xml is None:
        return _hard_gate("/xml/office-xslt-docx",
                          "no word/document.xml in docx", False, status=400)
    if not _has_xml_stylesheet_pi(doc_xml):
        return _soft_gate("/xml/office-xslt-docx",
                          "requires <?xml-stylesheet ...?> PI in "
                          "word/document.xml", False)
    text = "docx accepted\n"
    for m in _XML_STYLESHEET_RE.findall(doc_xml):
        url = m.decode("utf-8", "replace")
        data = _fetch_url(url)
        if data:
            text += data.decode("utf-8", "replace")
    _log_req(_accept("/xml/office-xslt-docx",
                     note="docx PI XSLT fetch",
                     preview=_preview(doc_xml), req_len=len(raw)))
    return _ok(_truncate(text), endpoint="/xml/office-xslt-docx")


@app.route("/xml/office-xslt-xlsx", methods=["POST"])
def xml_office_xslt_xlsx():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/office-xslt-xlsx")
    wk_xml = _read_docx_part(raw, "xl/workbook.xml")
    if wk_xml is None:
        return _hard_gate("/xml/office-xslt-xlsx",
                          "no xl/workbook.xml in xlsx", False, status=400)
    if not _has_xml_stylesheet_pi(wk_xml):
        return _soft_gate("/xml/office-xslt-xlsx",
                          "requires <?xml-stylesheet ...?> PI in "
                          "xl/workbook.xml", False)
    text = "xlsx accepted\n"
    for m in _XML_STYLESHEET_RE.findall(wk_xml):
        url = m.decode("utf-8", "replace")
        data = _fetch_url(url)
        if data:
            text += data.decode("utf-8", "replace")
    _log_req(_accept("/xml/office-xslt-xlsx",
                     note="xlsx PI XSLT fetch",
                     preview=_preview(wk_xml), req_len=len(raw)))
    return _ok(_truncate(text), endpoint="/xml/office-xslt-xlsx")


@app.route("/xml/method-restricted", methods=["PUT", "PATCH"])
def xml_method_restricted():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/method-restricted")
    try:
        text = _parse_and_text(body, "vuln_full")
        _log_req(_accept("/xml/method-restricted", method=request.method,
                         preview=_preview(body), req_len=len(body)))
        return _ok(text, endpoint="/xml/method-restricted")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/method-restricted", status=500,
                           method=request.method, error=True,
                           gate="error", preview=_preview(body),
                           req_len=len(body)))
        return _err(endpoint="/xml/method-restricted")
    except Exception:
        return _err(endpoint="/xml/method-restricted")


@app.route("/xml/query", methods=["GET", "POST"])
def xml_query():
    xml_body = None
    matched_param = None
    for param in ("xml", "data", "payload", "input"):
        val = request.args.get(param)
        if val:
            xml_body = val.encode("utf-8", errors="ignore")
            matched_param = param
            break
    if xml_body is None and request.method == "POST":
        xml_body = _require_body()
        if xml_body is not None:
            matched_param = "body"
    if xml_body is None:
        gate = _hard_gate("/xml/query", "no xml parameter", False,
                          status=400)
        return gate
    try:
        text = _parse_and_text(xml_body, "vuln_full")
        _log_req(_accept("/xml/query", method=request.method,
                         note=f"param={matched_param}",
                         preview=_preview(xml_body),
                         req_len=len(xml_body)))
        return _ok(text, endpoint="/xml/query")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/query", status=500, error=True,
                           gate="error", method=request.method,
                           preview=_preview(xml_body),
                           req_len=len(xml_body)))
        return _err(endpoint="/xml/query")
    except Exception:
        return _err(endpoint="/xml/query")


@app.route("/xml/form", methods=["POST"])
def xml_form():
    ct = request.content_type or ""
    gate = _hard_gate(
        "/xml/form",
        "Content-Type must be application/x-www-form-urlencoded",
        "x-www-form-urlencoded" in ct.lower(),
        status=415,
    )
    if gate:
        return gate

    xml_body = None
    matched_field = None
    for field in ("xml", "data", "payload", "input"):
        val = request.form.get(field)
        if val:
            xml_body = val.encode("utf-8", errors="ignore")
            matched_field = field
            break
    if xml_body is None:
        gate = _hard_gate("/xml/form",
                          "no 'xml' (or data/payload/input) form field",
                          False, status=400)
        return gate

    try:
        text = _parse_and_text(xml_body, "vuln_full")
        _log_req(_accept("/xml/form", ct=ct,
                         note=f"field={matched_field}",
                         preview=_preview(xml_body),
                         req_len=len(xml_body)))
        return _ok(text, endpoint="/xml/form")
    except etree.XMLSyntaxError:
        _log_req(_mk_entry("/xml/form", status=500, error=True,
                           gate="error", ct=ct,
                           preview=_preview(xml_body),
                           req_len=len(xml_body)))
        return _err(endpoint="/xml/form")
    except Exception:
        return _err(endpoint="/xml/form")


def _fake_cloud_response(body_lower: bytes) -> str:
    if b"metadata.google.internal" in body_lower:
        if b"service-accounts/default/token" in body_lower:
            return (
                '{\n'
                '  "access_token": "ya29.c.El9SAXl2S-9vXQ9lXqBcXhXx",\n'
                '  "expires_in": 3599,\n'
                '  "token_type": "Bearer"\n'
                '}\n'
            )
        if b"project-id" in body_lower:
            return "my-gcp-project-12345\n"
        return "computeMetadata/v1/\n"

    if b"100.100.100.200" in body_lower:
        if b"ram/security-credentials" in body_lower:
            return (
                '{\n'
                '  "AccessKeyId": "STS.L4aBSCSJVMuKg5U1vFDw",\n'
                '  "AccessKeySecret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
                '  "SecurityToken": "CAISgAJ1q6Ft5B2yf' + ("A" * 100) + '"\n'
                '}\n'
            )
        return "instance-id\nregion-id\nzone-id\n"

    if b"/opc/" in body_lower:
        return (
            '{\n'
            '  "id": "ocid1.instance.oc1.iad.anuwcljr1234567890",\n'
            '  "displayName": "prod-vm-01",\n'
            '  "compartmentId": "ocid1.compartment.oc1..aaaaaaa",\n'
            '  "region": "us-ashburn-1"\n'
            '}\n'
        )

    if b"kubernetes.default.svc" in body_lower:
        import base64 as _b64
        import json as _json

        sa_jwt_claims = {
            "iss": "kubernetes/serviceaccount",
            "kubernetes.io/serviceaccount/namespace": "kube-system",
            "kubernetes.io/serviceaccount/service-account.name":
                "default",
            "kubernetes.io/serviceaccount/service-account.uid":
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "sub": "system:serviceaccount:kube-system:default",
        }
        header = _b64.urlsafe_b64encode(
            _json.dumps({"alg": "RS256", "typ": "JWT"},
                        separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        payload = _b64.urlsafe_b64encode(
            _json.dumps(sa_jwt_claims, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        signature = "A" * 342
        jwt = f"{header}.{payload}.{signature}"
        token_b64 = _b64.b64encode(jwt.encode()).decode()

        return _json.dumps({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": {"resourceVersion": "12345"},
            "items": [{
                "metadata": {
                    "name": "default-token-abc12",
                    "namespace": "kube-system",
                },
                "type": "kubernetes.io/service-account-token",
                "data": {
                    "token": token_b64,
                    "namespace": _b64.b64encode(b"kube-system").decode(),
                    "ca.crt": _b64.b64encode(b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n").decode(),
                },
            }],
        }, indent=2)

    if b"/metadata/identity/" in body_lower:
        return (
            '{\n'
            '  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ",\n'
            '  "expires_on": "1735660800",\n'
            '  "token_type": "Bearer"\n'
            '}\n'
        )
    if b"/metadata/instance" in body_lower:
        return (
            '{\n'
            '  "vmId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",\n'
            '  "subscriptionId": "00000000-0000-0000-0000-000000000001",\n'
            '  "resourceGroupName": "prod-rg",\n'
            '  "azEnvironment": "AzurePublicCloud"\n'
            '}\n'
        )

    if b"169.254.169.254" in body_lower:
        if b"/iam/security-credentials" in body_lower:
            return (
                '{\n'
                '  "Code": "Success",\n'
                '  "LastUpdated": "2026-01-01T00:00:00Z",\n'
                '  "Type": "AWS-HMAC",\n'
                '  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",\n'
                '  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
                '  "Token": "' + ("IQoJb3JpZ2luX2VjEB4aCXVzLWVhc3QtMSJGMEQCIH" + "A" * 120) + '",\n'
                '  "Expiration": "2026-01-01T06:00:00Z"\n'
                '}\n'
            )
        if b"/user-data" in body_lower:
            return (
                "#cloud-config\n"
                "runcmd:\n"
                "  - echo hello\n"
                "  - systemctl restart app\n"
            )
        return (
            "ami-id\ninstance-id\ninstance-type\nplacement\n"
            "placement/availability-zone\niam\n"
            "iam/security-credentials\n"
        )

    return ""

@app.route("/xml/meta", methods=["POST"])
def xml_meta():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/meta")

    gate = _soft_gate(
        "/xml/meta",
        "requires a metadata URL (169.254.169.254 / "
        "metadata.google.internal / 100.100.100.200)",
        _has_metadata_url(body),
    )
    if gate:
        return gate

    fake = _fake_cloud_response(body.lower()) or "no metadata available\n"
    _log_req(_accept("/xml/meta",
                     note="synthetic metadata dispatched on URL",
                     preview=_preview(body), req_len=len(body)))
    return _ok(fake, endpoint="/xml/meta")


@app.route("/xml/json-to-xml", methods=["POST"])
def xml_json_to_xml():
    ct = (request.content_type or "").lower()

    if "json" in ct:
        body = _require_body()
        if body is None:
            return _bad("no body", endpoint="/xml/json-to-xml")
        text = body.decode("utf-8", "replace")
        if not text.strip().startswith("{"):
            return _bad("invalid json", 400, endpoint="/xml/json-to-xml")
        _log_req(_accept("/xml/json-to-xml", ct=ct, note="json accepted",
                         preview=_preview(body), req_len=len(body)))
        return Response('{"ok":true}',
                        mimetype="application/json",
                        headers={"X-Lab-Endpoint": "/xml/json-to-xml"})

    if "xml" in ct:
        body = _require_body()
        if body is None:
            return _bad("no body", endpoint="/xml/json-to-xml")
        try:
            text = _parse_and_text(body, "vuln_full")
            _log_req(_accept("/xml/json-to-xml", ct=ct,
                             note="xml accepted on json endpoint",
                             preview=_preview(body),
                             req_len=len(body)))
            return _ok(text, endpoint="/xml/json-to-xml")
        except etree.XMLSyntaxError:
            _log_req(_mk_entry("/xml/json-to-xml", status=500,
                               error=True, gate="error", ct=ct,
                               preview=_preview(body),
                               req_len=len(body)))
            return _err(endpoint="/xml/json-to-xml")

    return _hard_gate("/xml/json-to-xml",
                      "Content-Type must be json or xml",
                      False, status=415)


@app.route("/xml/yaml", methods=["POST"])
def xml_yaml():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/yaml")

    if not _is_yaml_shaped(body) and b"!!" not in body:
        gate = _soft_gate("/xml/yaml",
                          "requires a YAML type tag (!!python/... or "
                          "!!java...)",
                          False)
        return gate

    chunks: list[str] = []
    for m in re.finditer(rb"https?://[^\s\"'<>]+", body):
        url = m.group(0).decode("utf-8", "replace").rstrip(".,);")
        data = _fetch_url(url)
        if data:
            chunks.append(data.decode("utf-8", "replace"))

    note = "yaml type tag detected"
    if _HAVE_YAML:
        try:
            parsed = _yaml.safe_load(body.decode("utf-8", "replace"))
            if parsed is not None:
                note += f" (safe-loaded {type(parsed).__name__})"
        except Exception:
            pass

    text = "yaml processed\n" + "\n".join(chunks)
    _log_req(_accept("/xml/yaml", note=note,
                     preview=_preview(body), req_len=len(body)))
    return _ok(_truncate(text), endpoint="/xml/yaml")


@app.route("/xml/rce-jar", methods=["POST"])
def xml_rce_jar():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/rce-jar")

    gate = _soft_gate("/xml/rce-jar",
                      "requires a jar:file:// SYSTEM entity",
                      _has_jar_uri(body))
    if gate:
        return gate

    m = re.search(rb"""['"](jar:file://[^'"]+)['"]""", body)
    if not m:
        return _soft_gate("/xml/rce-jar",
                          "requires a jar:file:// URI", False)

    url = m.group(1).decode("utf-8", "replace")
    data = _fetch_url(url)
    if data is None:
        text = "jar fetch failed"
    else:
        text = data.decode("utf-8", "replace")
    _log_req(_accept("/xml/rce-jar", note="jar resolved",
                     preview=_preview(body), req_len=len(body)))
    return _ok(_truncate(text) or "processed", endpoint="/xml/rce-jar")


# ---------------------------------------------------------------------------
# Blind OOB-only endpoints (no reflection)
# ---------------------------------------------------------------------------

@app.route("/xml/oob-external-dtd", methods=["POST"])
def xml_oob_external_dtd():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/oob-external-dtd")

    ok = (_has_doctype(body)
          and _has_parameter_entity(body)
          and _has_external_http_entity(body))
    gate = _soft_gate("/xml/oob-external-dtd",
                      "requires DOCTYPE + parameter entity + "
                      "SYSTEM \"http(s)://...\"",
                      ok)
    if gate:
        return gate

    t0 = time.time()
    try:
        _ = _parse_and_text(body, "vuln_full")
    except Exception:
        pass
    dt = round((time.time() - t0) * 1000, 1)
    _log_req(_accept("/xml/oob-external-dtd", ms=dt,
                     note="blind — external DTD",
                     preview=_preview(body), req_len=len(body)))
    return _ok("processed", endpoint="/xml/oob-external-dtd")


@app.route("/xml/oob-cdata", methods=["POST"])
def xml_oob_cdata():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/oob-cdata")

    ok = (_has_doctype(body)
          and _has_parameter_entity(body)
          and _has_external_http_entity(body))
    gate = _soft_gate("/xml/oob-cdata",
                      "requires DOCTYPE + parameter entity + "
                      "SYSTEM \"http(s)://...\"",
                      ok)
    if gate:
        return gate

    t0 = time.time()
    try:
        _ = _parse_and_text(body, "vuln_full")
    except Exception:
        pass
    dt = round((time.time() - t0) * 1000, 1)
    _log_req(_accept("/xml/oob-cdata", ms=dt, note="blind — CDATA",
                     preview=_preview(body), req_len=len(body)))
    return _ok("processed", endpoint="/xml/oob-cdata")


@app.route("/xml/oob-pe", methods=["POST"])
def xml_oob_pe():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/oob-pe")

    ok = _has_parameter_entity(body) and _has_external_http_entity(body)
    gate = _soft_gate("/xml/oob-pe",
                      "requires a parameter entity with an http(s) SYSTEM "
                      "URL", ok)
    if gate:
        return gate

    t0 = time.time()
    try:
        _ = _parse_and_text(body, "vuln_full")
    except Exception:
        pass
    dt = round((time.time() - t0) * 1000, 1)
    _log_req(_accept("/xml/oob-pe", ms=dt,
                     note="blind — parameter entity",
                     preview=_preview(body), req_len=len(body)))
    return _ok("processed", endpoint="/xml/oob-pe")


# ---------------------------------------------------------------------------
# Safe counterparts of the scoped vuln endpoints
# ---------------------------------------------------------------------------

@app.route("/xml/safe-form", methods=["POST"])
def xml_safe_form():
    ct = request.content_type or ""
    if "x-www-form-urlencoded" not in ct.lower():
        return _bad("unsupported media type", 415,
                    endpoint="/xml/safe-form")
    xml_body = None
    for field in ("xml", "data", "payload", "input"):
        val = request.form.get(field)
        if val:
            xml_body = val.encode("utf-8", errors="ignore")
            break
    if xml_body is None:
        return _bad("no xml field", 400, endpoint="/xml/safe-form")
    try:
        text = _parse_and_text(xml_body, "safe")
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-form", note="safe form parser",
                     preview=_preview(xml_body),
                     req_len=len(xml_body)))
    return _ok(text or "OK", endpoint="/xml/safe-form")


@app.route("/xml/safe-query", methods=["GET", "POST"])
def xml_safe_query():
    xml_body = None
    for param in ("xml", "data", "payload", "input"):
        val = request.args.get(param)
        if val:
            xml_body = val.encode("utf-8", errors="ignore")
            break
    if xml_body is None:
        return _bad("no xml parameter", 400, endpoint="/xml/safe-query")
    try:
        text = _parse_and_text(xml_body, "safe")
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-query", note="safe query parser",
                     preview=_preview(xml_body),
                     req_len=len(xml_body)))
    return _ok(text or "OK", endpoint="/xml/safe-query")


@app.route("/xml/safe-svg", methods=["POST"])
def xml_safe_svg():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-svg")
    if not _ct_in("image/svg+xml", "svg"):
        return _bad("unsupported media type", 415, endpoint="/xml/safe-svg")
    if _root_element_name(body) != "svg":
        return _bad("not svg", 400, endpoint="/xml/safe-svg")
    try:
        root = etree.fromstring(body, _make_parser("safe"))
        text = _truncate("".join(root.itertext())) or "svg ok"
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-svg", note="safe svg parser",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-svg")


@app.route("/xml/safe-saml", methods=["POST"])
def xml_safe_saml():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-saml")
    if not _is_saml_shaped(body):
        return _bad("not saml", 400, endpoint="/xml/safe-saml")
    try:
        text = _parse_and_text(body, "safe")
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-saml", note="safe saml parser",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-saml")


@app.route("/xml/safe-soap", methods=["POST"])
def xml_safe_soap():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-soap")
    if not _ct_in("application/soap+xml"):
        return _bad("unsupported media type", 415, endpoint="/xml/safe-soap")
    if not _is_soap_shaped(body):
        return _bad("not soap", 400, endpoint="/xml/safe-soap")
    try:
        text = _parse_and_text(body, "safe")
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-soap", note="safe soap parser",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-soap")


@app.route("/xml/safe-multipart", methods=["POST"])
def xml_safe_multipart():
    if not _ct_in("multipart/form-data"):
        return _bad("unsupported media type", 415,
                    endpoint="/xml/safe-multipart")
    xml_body = None
    for field_name in ("xml", "data", "file", "document", "upload"):
        f = request.files.get(field_name)
        if f is not None:
            data = f.read()
            if data:
                xml_body = data
                break
        val = request.form.get(field_name)
        if val:
            xml_body = val.encode("utf-8", errors="ignore")
            break
    if xml_body is None:
        return _bad("no xml field", 400, endpoint="/xml/safe-multipart")
    try:
        text = _parse_and_text(xml_body, "safe")
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-multipart", note="safe multipart parser",
                     preview=_preview(xml_body),
                     req_len=len(xml_body)))
    return _ok(text or "OK", endpoint="/xml/safe-multipart")


@app.route("/xml/safe-docx", methods=["POST"])
def xml_safe_docx():
    raw = _require_body()
    if raw is None:
        return _bad("no body", endpoint="/xml/safe-docx")
    doc_xml = _read_docx_part(raw, "word/document.xml")
    if doc_xml is None:
        return _bad("no word/document.xml", 400, endpoint="/xml/safe-docx")
    try:
        text = _parse_and_text(doc_xml, "safe")
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-docx", note="safe docx parser",
                     preview=_preview(doc_xml), req_len=len(raw)))
    return _ok(text or "OK", endpoint="/xml/safe-docx")


def _safe_xinclude_common(endpoint: str, extra_gate=None):
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint=endpoint)
    if _has_doctype(body):
        return _bad("doctype not accepted", 400, endpoint=endpoint)
    if extra_gate is not None:
        if not extra_gate(body):
            return _bad("scope mismatch", 400, endpoint=endpoint)
    elif not _has_xinclude(body):
        return _bad("no xinclude", 400, endpoint=endpoint)

    try:
        parser = etree.XMLParser(**PARSER_CONFIGS["safe"])
        root = etree.fromstring(body, parser)
        text = _truncate("".join(root.itertext())) or "OK"
    except Exception:
        text = "parse error"
    _log_req(_accept(endpoint, note="safe xinclude parser",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint=endpoint)


@app.route("/xml/safe-xinclude", methods=["POST"])
def xml_safe_xinclude():
    return _safe_xinclude_common("/xml/safe-xinclude")


@app.route("/xml/safe-xinclude-xml", methods=["POST"])
def xml_safe_xinclude_xml():
    return _safe_xinclude_common(
        "/xml/safe-xinclude-xml",
        extra_gate=_has_xinclude_parse_xml,
    )


@app.route("/xml/safe-xslt", methods=["POST"])
def xml_safe_xslt():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-xslt")
    if not _is_xslt_shaped(body):
        return _bad("not xslt", 400, endpoint="/xml/safe-xslt")
    try:
        sty = etree.fromstring(body, _make_parser("safe"))
        src = etree.fromstring(
            b'<?xml version="1.0"?><root/>', _make_parser("safe"))
        transform = etree.XSLT(sty)
        text = _truncate(str(transform(src))) or "xslt ok"
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-xslt", note="safe xslt",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-xslt")


@app.route("/xml/safe-xsd", methods=["POST"])
def xml_safe_xsd():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-xsd")
    if not _is_xsd_shaped(body):
        return _bad("not xsd", 400, endpoint="/xml/safe-xsd")
    try:
        root = etree.fromstring(body, _make_parser("safe"))
        text = _truncate("".join(root.itertext())) or "OK"
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-xsd", note="safe xsd",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-xsd")


@app.route("/xml/safe-xsd-import", methods=["POST"])
def xml_safe_xsd_import():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-xsd-import")
    if not _is_xsd_import_shaped(body):
        return _bad("not xsd-import", 400, endpoint="/xml/safe-xsd-import")
    try:
        root = etree.fromstring(body, _make_parser("safe"))
        text = _truncate("".join(root.itertext())) or "OK"
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-xsd-import", note="safe xsd-import",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-xsd-import")


@app.route("/xml/safe-pi", methods=["POST"])
def xml_safe_pi():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-pi")
    if not _has_xml_stylesheet_pi(body):
        return _bad("no xml-stylesheet PI", 400, endpoint="/xml/safe-pi")
    try:
        root = etree.fromstring(body, _make_parser("safe"))
        text = _truncate("".join(root.itertext())) or "OK"
    except Exception:
        text = "parse error"
    _log_req(_accept("/xml/safe-pi", note="safe pi (no fetch)",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text or "OK", endpoint="/xml/safe-pi")


# ---------------------------------------------------------------------------
# Safe endpoints (baseline FP bait)
# ---------------------------------------------------------------------------

@app.route("/xml/safe", methods=["POST"])
def xml_safe():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe")
    try:
        text = _parse_and_text(body, "safe")
        _log_req(_accept("/xml/safe", preview=_preview(body),
                         req_len=len(body)))
        return _ok(text, endpoint="/xml/safe")
    except etree.XMLSyntaxError as e:
        _log_req(_mk_entry("/xml/safe", status=400, error=True,
                           gate="error", note=str(e)[:120],
                           preview=_preview(body), req_len=len(body)))
        return _bad("parse error", 400, endpoint="/xml/safe")
    except Exception:
        return _bad("parse error", 400, endpoint="/xml/safe")


_NOISE_SEED_ENV = os.environ.get("XXE_LAB_NOISE_SEED")


@app.route("/xml/noise", methods=["POST"])
def xml_noise():
    if _NOISE_SEED_ENV:
        rng = random.Random(int(_NOISE_SEED_ENV))
    else:
        rng = random.Random()
    pad = "".join(rng.choice(string.ascii_letters)
                  for _ in range(rng.randint(800, 3000)))
    decoys = [
        "function foo(){ return 1; }",
        "class Widget {}",
        "<?php echo 'hi'; ?>",
        "DB_HOST=localhost",
        "SECRET_KEY=random",
        "compute network vmId resourceGroupName",
        "root:x:0:0:decoy",
        "daemon:x:decoy",
        "[extensions]decoy",
        "[fonts]decoy",
    ]
    rng.shuffle(decoys)
    html = (
        "<!doctype html><html><head><title>noise</title></head>"
        f"<body><p>{pad}</p>"
        + "".join(f"<!-- {d} -->" for d in decoys)
        + "</body></html>"
    )
    _log_req(_accept("/xml/noise", note="FP bait", preview="",
                     req_len=len(request.get_data() or b"")))
    return Response(html, mimetype="text/html",
                    headers={"X-Lab-Endpoint": "/xml/noise"})


_DOCTYPE_RE = re.compile(
    rb"<!DOCTYPE\s+[^\[>]*(\[[^\]]*\])?\s*>",
    re.DOTALL,
)


@app.route("/xml/stripped", methods=["POST"])
def xml_stripped():
    body = _require_body() or b""
    cleaned = re.sub(rb"<!ENTITY[^>]*>", b"", body)
    cleaned = _DOCTYPE_RE.sub(b"", cleaned)
    try:
        root = etree.fromstring(cleaned, _make_parser("safe"))
        text = _truncate("".join(root.itertext())) or "OK"
    except Exception:
        text = "OK"
    _log_req(_accept("/xml/stripped", note="ENTITY decls stripped",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text, endpoint="/xml/stripped")


@app.route("/xml/silent", methods=["POST"])
def xml_silent():
    body = _require_body() or b""
    cleaned = re.sub(rb"<\?xml[^>]*\?>", b"", body)
    cleaned = _DOCTYPE_RE.sub(b"", cleaned)
    try:
        root = etree.fromstring(cleaned, _make_parser("safe"))
        text = _truncate("".join(root.itertext())) or "OK"
    except Exception:
        text = "OK"
    _log_req(_accept("/xml/silent", note="DOCTYPE stripped",
                     preview=_preview(body), req_len=len(body)))
    return _ok(text, endpoint="/xml/silent")


@app.route("/xml/safe-metadata", methods=["POST"])
def xml_safe_metadata():
    body = _require_body()
    if body is None:
        return _bad("no body", endpoint="/xml/safe-metadata")
    html = (
        "<!doctype html><html><head><title>safe</title></head><body>"
        "<p>ok</p>"
        "<!-- decoys: ami-id instance-id iam/security-credentials "
        "computeMetadata project/project-id vmId subscriptionId -->"
        "</body></html>"
    )
    _log_req(_accept("/xml/safe-metadata", note="metadata decoys in HTML",
                     preview=_preview(body), req_len=len(body)))
    return Response(html, mimetype="text/html",
                    headers={"X-Lab-Endpoint": "/xml/safe-metadata"})


# ---------------------------------------------------------------------------
# Meta API
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return _ok("ok", endpoint="/health")


@app.route("/api/mode")
def api_mode():
    return jsonify({
        "mode": _mode(),
        "default": LAB_MODE,
        "override_header": "X-Lab-Mode",
        "override_query": "lab_mode",
        "valid": list(_VALID_MODES),
        "note": (
            "realistic: generic 4xx rejections, no reason leak, soft gates "
            "fall through to parser. scoped: stable 200 out-of-scope for "
            "out-of-scope bodies, deterministic for regression suites."
        ),
    })


@app.route("/api/log")
def api_log():
    with _LOG_LOCK:
        rows = list(_LOG)
    return jsonify(rows)


@app.route("/api/log/clear", methods=["POST"])
def api_log_clear():
    with _LOG_LOCK:
        _LOG.clear()
    with _STATS_LOCK:
        _STATS["total"] = 0
        _STATS["by_path"] = {}
        _STATS["by_mode"] = {}
        _STATS["errors"] = 0
    return _ok("cleared")


@app.route("/api/stats")
def api_stats():
    with _STATS_LOCK:
        stats = {
            "total": _STATS["total"],
            "errors": _STATS["errors"],
            "by_path": dict(_STATS["by_path"]),
            "by_mode": dict(_STATS["by_mode"]),
            "uptime": round(time.time() - _STATS["started"], 1),
            "current_mode": LAB_MODE,
            "fingerprint_cache_hint":
                "if you edit endpoints, pass --no-fingerprint-cache "
                "to the scanner or rm ~/.cache/xxeripper/fingerprints.json",
        }
    return jsonify(stats)


@app.route("/api/endpoints")
def api_endpoints():
    return jsonify(ENDPOINT_META)


@app.route("/api/verdicts")
def api_verdicts():
    out = {}
    for ep in ENDPOINT_META:
        method = ep.get("method", "POST")
        primary = method.split("|")[0].strip()
        key = f"{primary} {ep['path']}"
        out[key] = ep["verdict"]
    return jsonify(out)


# ---------------------------------------------------------------------------
# Endpoint metadata (single source of truth for the UI)
# ---------------------------------------------------------------------------

ENDPOINT_META = [
    # ------------------------- VULN (unscoped) --------------------------
    {"path": "/xml/vulnerable", "method": "POST", "verdict": "vuln",
     "title": "Full vulnerable parser (unscoped)",
     "desc": "External entities, DTD loading, network fetches all "
             "enabled. Any XML accepted. Text is reflected.",
     "config": "resolve_entities=true, load_dtd=true, no_network=false",
     "phase": "in-band, error-based, fingerprint", "scope": "any XML"},

    {"path": "/xml/blind", "method": "POST", "verdict": "vuln",
     "title": "Blind silent parser (unscoped)",
     "desc": "Same parser as /xml/vulnerable but never reflects input "
             "or errors. Only OOB callbacks can confirm.",
     "config": "resolve_entities=true, load_dtd=true, no reflection",
     "phase": "OOB", "scope": "any XML"},

    {"path": "/xml/error", "method": "POST", "verdict": "vuln",
     "title": "Error-leaking parser (unscoped)",
     "desc": "Returns parser error messages to the client, matching "
             "what a vulnerable app that logs `str(e)` looks like.",
     "config": "resolve_entities=true, verbose errors",
     "phase": "error-based", "scope": "any XML",
     "note": (f"libxml2 {_LIBXML_VER} blocks external-DTD access by "
              f"default (since 2.13.0). Error-based XXE payloads that "
              f"depend on an external subset or a URI-fetching parameter "
              f"entity cannot succeed against this endpoint. Use the "
              f"Java lab at http://127.0.0.1:5001/xml/error for those.")},

    {"path": "/xml/reflect", "method": "POST", "verdict": "vuln",
     "title": "Reflect + parse (unscoped)",
     "desc": "Reflects the raw body AND parses it with the vulnerable "
             "parser. Exercises reflection-veto logic.",
     "config": "resolve_entities=true, body echoed",
     "phase": "reflection veto", "scope": "any XML"},

    {"path": "/xml/timing", "method": "POST", "verdict": "vuln",
     "title": "Slow-resolver timing probe",
     "desc": "Sleeps for several seconds when the payload contains an "
             "external SYSTEM entity. Tests timing-based blind "
             "detection.",
     "config": "resolve_entities=true, forced delay on external entity",
     "phase": "timing",
     "scope": "any XML (sleeps on external entity)"},

    # ------------------------- VULN (scoped) ----------------------------
    {"path": "/xml/ssrf", "method": "POST", "verdict": "vuln",
     "title": "SSRF via entity fetch",
     "desc": "Entity URLs are fetched and the response is returned. "
             "Only accepts bodies with an http(s) SYSTEM entity.",
     "config": "resolve_entities=true, no_network=false",
     "phase": "SSRF",
     "scope": "requires <!ENTITY ... SYSTEM \"http(s)://...\">"},

    {"path": "/xml/svg", "method": "POST", "verdict": "vuln",
     "title": "SVG upload",
     "desc": "Parses uploaded SVG with the vulnerable parser.",
     "config": "resolve_entities=true (SVG context)",
     "phase": "alternative sink",
     "scope": "Content-Type image/svg+xml + <svg> root"},

    {"path": "/xml/saml", "method": "POST", "verdict": "vuln",
     "title": "SAML envelope",
     "desc": "SAML assertion parsing with the vulnerable parser.",
     "config": "resolve_entities=true (SAML context)",
     "phase": "alternative sink",
     "scope": "root must be <saml:*>, <Response>, or <Assertion>"},

    {"path": "/xml/saml-presig", "method": "POST", "verdict": "vuln",
     "title": "SAML pre-signature parse",
     "desc": "Parses the assertion body before checking the signature. "
             "Matches a spec-compliant SP, and the sequence that "
             "CVE-2026-28809 exposed.",
     "config": "resolve_entities=true, parse before sig verify",
     "phase": "SAML presig",
     "scope": "root must be SAML-shaped"},

    {"path": "/xml/soap", "method": "POST", "verdict": "vuln",
     "title": "SOAP envelope",
     "desc": "SOAP envelope parsing.",
     "config": "resolve_entities=true (SOAP context)",
     "phase": "alternative sink",
     "scope": "Content-Type application/soap+xml + <soap:Envelope>"},

    {"path": "/xml/xinclude", "method": "POST", "verdict": "vuln",
     "title": "XInclude (parse=text)",
     "desc": "Entities and DTDs disabled but XInclude is honored.",
     "config": "resolve_entities=false, XInclude=true",
     "phase": "XInclude",
     "scope": "<xi:include> present, no DOCTYPE"},

    {"path": "/xml/xinclude-xml", "method": "POST", "verdict": "vuln",
     "title": "XInclude (parse=xml)",
     "desc": "XInclude with parse='xml' inlines the target as an XML "
             "node (not escaped text).",
     "config": "resolve_entities=false, XInclude=true, parse=xml",
     "phase": "XInclude",
     "scope": "<xi:include parse=\"xml\">, no DOCTYPE"},

    {"path": "/xml/xinclude-ssrf", "method": "POST", "verdict": "vuln",
     "title": "XInclude SSRF",
     "desc": "XInclude that fetches an http(s) URL.",
     "config": "resolve_entities=false, XInclude=true, http href",
     "phase": "XInclude SSRF",
     "scope": "<xi:include href=\"http(s)://...\">"},

    {"path": "/xml/utf16", "method": "POST", "verdict": "vuln",
     "title": "UTF-16 parser path",
     "desc": "UTF-16 BOM triggers a UTF-16 decode path.",
     "config": "resolve_entities=true, UTF-16 enabled",
     "phase": "encoding bypass",
     "scope": "requires a UTF-16 BOM"},

    {"path": "/xml/utf7", "method": "POST", "verdict": "vuln",
     "title": "UTF-7 parser path",
     "desc": "Decodes UTF-7 when the XML declaration claims UTF-7.",
     "config": "resolve_entities=true, UTF-7 enabled",
     "phase": "encoding bypass",
     "scope": "requires encoding=\"UTF-7\" in declaration"},

    {"path": "/xml/encoding-ucs4", "method": "POST", "verdict": "vuln",
     "title": "UCS-4 (UTF-32) parser path",
     "desc": "UCS-4 BOM triggers a UTF-32 decode path.",
     "config": "resolve_entities=true, UCS-4 enabled",
     "phase": "encoding bypass",
     "scope": "requires a UCS-4 BOM"},

    {"path": "/xml/encoding-altdoctype", "method": "POST", "verdict": "vuln",
     "title": "Alternate DOCTYPE syntax",
     "desc": "Accepts lowercase DOCTYPE, comment-split DOCTYPE, or "
             "space-injected DOCTYPE.",
     "config": "resolve_entities=true, filter bypass",
     "phase": "encoding bypass",
     "scope": "requires lowercase/comment-split DOCTYPE"},

    {"path": "/xml/parameter", "method": "POST", "verdict": "vuln",
     "title": "Parameter entity required",
     "desc": "Only parameter-entity payloads resolve.",
     "config": "resolve_entities=true, PEs required",
     "phase": "parameter entity",
     "scope": "requires <!ENTITY % ...>"},

    {"path": "/xml/xslt", "method": "POST", "verdict": "vuln",
     "title": "XSLT processor",
     "desc": "Applies the submitted XSLT stylesheet.",
     "config": "resolve_entities=true (XSLT context)",
     "phase": "extended fetchers",
     "scope": "root must be <xsl:stylesheet> or <xsl:transform>"},

    {"path": "/xml/xsd", "method": "POST", "verdict": "vuln",
     "title": "XSD schemaLocation fetch",
     "desc": "Fetches the URL referenced by xsi:schemaLocation or "
             "xsi:noNamespaceSchemaLocation.",
     "config": "resolve_entities=true, explicit schema fetch",
     "phase": "extended fetchers",
     "scope": "xsi:... attribute or <xs:schema> root"},

    {"path": "/xml/xsd-import", "method": "POST", "verdict": "vuln",
     "title": "XSD import fetch",
     "desc": "Fetches the schemaLocation on any xsd:import or "
             "xsd:include.",
     "config": "resolve_entities=true, explicit import fetch",
     "phase": "extended fetchers",
     "scope": "<xs:schema> root with <xs:import> or <xs:include>"},

    {"path": "/xml/pi", "method": "POST", "verdict": "vuln",
     "title": "xml-stylesheet PI",
     "desc": "Extracts the href from any xml-stylesheet PI and fetches "
             "it explicitly.",
     "config": "resolve_entities=true, explicit PI fetch",
     "phase": "extended fetchers",
     "scope": "requires <?xml-stylesheet ...?> PI"},

    {"path": "/xml/upload", "method": "POST", "verdict": "vuln",
     "title": "Multipart upload",
     "desc": "Accepts a multipart form and parses the 'xml' field.",
     "config": "resolve_entities=true (multipart context)",
     "phase": "multipart",
     "scope": "Content-Type multipart/form-data with an XML field"},

    {"path": "/xml/docx", "method": "POST", "verdict": "vuln",
     "title": "DOCX upload",
     "desc": "Extracts word/document.xml from the uploaded zip and "
             "parses it with the vulnerable parser.",
     "config": "resolve_entities=true (docx context)",
     "phase": "multipart / DOCX",
     "scope": "requires a valid zip with word/document.xml"},

    {"path": "/xml/office-xslt-docx", "method": "POST", "verdict": "vuln",
     "title": "DOCX with XSLT PI",
     "desc": "DOCX whose word/document.xml carries an xml-stylesheet PI. "
             "The lab simulates the XSLT processor by fetching the "
             "stylesheet URL.",
     "config": "resolve_entities=true, PI XSLT fetch",
     "phase": "Office XSLT",
     "scope": "docx with xml-stylesheet PI in word/document.xml"},

    {"path": "/xml/office-xslt-xlsx", "method": "POST", "verdict": "vuln",
     "title": "XLSX with XSLT PI",
     "desc": "XLSX whose xl/workbook.xml carries an xml-stylesheet PI.",
     "config": "resolve_entities=true, PI XSLT fetch",
     "phase": "Office XSLT",
     "scope": "xlsx with xml-stylesheet PI in xl/workbook.xml"},

    {"path": "/xml/method-restricted", "method": "PUT|PATCH",
     "verdict": "vuln",
     "title": "Method-restricted parser",
     "desc": "Accepts XML only on PUT and PATCH.",
     "config": "resolve_entities=true, PUT/PATCH only",
     "phase": "method variation", "scope": "PUT or PATCH only"},

    {"path": "/xml/query", "method": "GET|POST", "verdict": "vuln",
     "title": "Query parameter parser",
     "desc": "Accepts XML via ?xml=, ?data=, ?payload=, or ?input=.",
     "config": "resolve_entities=true (query param context)",
     "phase": "query param",
     "scope": "requires ?xml= (or data/payload/input)"},

    {"path": "/xml/form", "method": "POST", "verdict": "vuln",
     "title": "Form-encoded XML",
     "desc": "Reads XML from the 'xml' form field. Matches the "
             "scanner's form-encoded OOB phase.",
     "config": "resolve_entities=true (form context)",
     "phase": "form-encoded / OOB",
     "scope": "urlencoded CT + xml= field"},

    {"path": "/xml/json-to-xml", "method": "POST", "verdict": "vuln",
     "title": "JSON endpoint also accepts XML",
     "desc": "Advertises JSON but silently parses XML on the same "
             "path. Matches Spring MVC with jackson-dataformat-xml "
             "auto-registered.",
     "config": "resolve_entities=true, dual content-type",
     "phase": "json-to-xml",
     "scope": "Content-Type application/json OR xml"},

    {"path": "/xml/yaml", "method": "POST", "verdict": "vuln",
     "title": "YAML deserialization probe",
     "desc": "Detects YAML type tags and fetches any URL in the "
             "payload. Simulates the outbound side effect without "
             "running the deserializer.",
     "config": "yaml tag detection, URL fetch",
     "phase": "yaml deser",
     "scope": "requires a YAML type tag (!!...)"},

    {"path": "/xml/rce-jar", "method": "POST", "verdict": "vuln",
     "title": "jar: protocol resolver",
     "desc": "Opens the referenced jar and returns the requested entry. "
             "Point the payload at any jar on the system.",
     "config": "jar: URI resolver",
     "phase": "RCE wrappers",
     "scope": "requires a jar:file:// SYSTEM entity"},

    {"path": "/xml/meta", "method": "POST", "verdict": "vuln",
    "title": "Synthetic cloud metadata",
    "desc": "Returns provider-shaped metadata based on the URL "
            "referenced in the payload. AWS IAM, GCP service-account, "
            "Azure managed-identity, Alibaba RAM, Oracle, and "
            "Kubernetes responses are all simulated.",
    "config": "URL-dispatched synthetic response",
    "phase": "SSRF / cloud metadata",
    "scope": "requires a known metadata URL in the body "
             "(AWS/GCP/Alibaba/Oracle/Azure/K8s)",
    "note": "The response is generated by the lab, not fetched from a "
            "real IMDS. Tests detection and extraction, not reachability."},

    {"path": "/xml/oob-external-dtd", "method": "POST", "verdict": "vuln",
     "title": "Blind external DTD",
     "desc": "Blind external-DTD exfil. Never reflects. OOB-only.",
     "config": "resolve_entities=true, no reflection",
     "phase": "OOB",
     "scope": "DOCTYPE + PE + http(s) SYSTEM entity"},

    {"path": "/xml/oob-cdata", "method": "POST", "verdict": "vuln",
     "title": "Blind CDATA exfil",
     "desc": "Blind CDATA-wrapped exfil. Never reflects. OOB-only.",
     "config": "resolve_entities=true, no reflection",
     "phase": "OOB",
     "scope": "DOCTYPE + PE + http(s) SYSTEM entity"},

    {"path": "/xml/oob-pe", "method": "POST", "verdict": "vuln",
     "title": "Blind parameter entity",
     "desc": "Blind parameter-entity-only OOB. Never reflects.",
     "config": "resolve_entities=true, PEs required, no reflection",
     "phase": "OOB",
     "scope": "PE with http(s) SYSTEM URL"},

    # ------------------------- SAFE (scoped counterparts) ---------------
    {"path": "/xml/safe-form", "method": "POST", "verdict": "safe",
     "title": "Safe form-encoded",
     "desc": "Safe parser; only accepts form-encoded XML field.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "urlencoded CT + xml= field"},

    {"path": "/xml/safe-query", "method": "GET|POST", "verdict": "safe",
     "title": "Safe query param",
     "desc": "Safe parser; only accepts XML via query parameter.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "requires ?xml= (or data/payload/input)"},

    {"path": "/xml/safe-svg", "method": "POST", "verdict": "safe",
     "title": "Safe SVG parser",
     "desc": "Safe parser on SVG-shaped input.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "Content-Type image/svg+xml + <svg> root"},

    {"path": "/xml/safe-saml", "method": "POST", "verdict": "safe",
     "title": "Safe SAML parser",
     "desc": "Safe parser on SAML-shaped input.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "SAML-shaped root"},

    {"path": "/xml/safe-soap", "method": "POST", "verdict": "safe",
     "title": "Safe SOAP parser",
     "desc": "Safe parser on SOAP-shaped input.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "Content-Type application/soap+xml + <soap:Envelope>"},

    {"path": "/xml/safe-multipart", "method": "POST", "verdict": "safe",
     "title": "Safe multipart parser",
     "desc": "Safe parser on multipart form data.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "Content-Type multipart/form-data with XML field"},

    {"path": "/xml/safe-docx", "method": "POST", "verdict": "safe",
     "title": "Safe DOCX parser",
     "desc": "Safe parser on word/document.xml.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "valid zip with word/document.xml"},

    {"path": "/xml/safe-xinclude", "method": "POST", "verdict": "safe",
     "title": "Safe XInclude (not expanded)",
     "desc": "XInclude present but XInclude processing disabled.",
     "config": "resolve_entities=false, XInclude=false",
     "phase": "baseline",
     "scope": "<xi:include> present, no DOCTYPE"},

    {"path": "/xml/safe-xinclude-xml", "method": "POST", "verdict": "safe",
     "title": "Safe XInclude parse=xml (not expanded)",
     "desc": "Same as safe-xinclude but requires parse='xml'.",
     "config": "resolve_entities=false, XInclude=false",
     "phase": "baseline",
     "scope": "<xi:include parse=\"xml\">"},

    {"path": "/xml/safe-xslt", "method": "POST", "verdict": "safe",
     "title": "Safe XSLT",
     "desc": "XSLT transform with entities disabled and no network.",
     "config": "resolve_entities=false, no_network=true",
     "phase": "baseline",
     "scope": "<xsl:stylesheet> or <xsl:transform>"},

    {"path": "/xml/safe-xsd", "method": "POST", "verdict": "safe",
     "title": "Safe XSD",
     "desc": "XSD-shaped input, safe parser, no external fetch.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "xsi:... attribute or <xs:schema> root"},

    {"path": "/xml/safe-xsd-import", "method": "POST", "verdict": "safe",
     "title": "Safe XSD import",
     "desc": "XSD import-shaped input, safe parser, no fetch.",
     "config": "resolve_entities=false",
     "phase": "baseline",
     "scope": "<xs:schema> with <xs:import> or <xs:include>"},

    {"path": "/xml/safe-pi", "method": "POST", "verdict": "safe",
     "title": "Safe xml-stylesheet PI",
     "desc": "PI present but href is not fetched.",
     "config": "resolve_entities=false, no PI fetch",
     "phase": "baseline",
     "scope": "requires <?xml-stylesheet ...?> PI"},

    # ------------------------- SAFE (baseline) --------------------------
    {"path": "/xml/safe", "method": "POST", "verdict": "safe",
     "title": "Correctly configured",
     "desc": "Entities, DTD loading, and network fetches all disabled.",
     "config": "resolve_entities=false, load_dtd=false, no_network=true",
     "phase": "baseline", "scope": "any XML (must NOT resolve)"},

    {"path": "/xml/noise", "method": "POST", "verdict": "safe",
     "title": "FP bait",
     "desc": "Random HTML with decoy tokens on every request.",
     "config": "n/a (does not parse XML)",
     "phase": "baseline", "scope": "n/a"},

    {"path": "/xml/stripped", "method": "POST", "verdict": "safe",
     "title": "WAF simulation",
     "desc": "ENTITY declarations stripped before parsing.",
     "config": "safe + input sanitization",
     "phase": "baseline", "scope": "any (stripped before parse)"},

    {"path": "/xml/safe-metadata", "method": "POST", "verdict": "safe",
     "title": "Metadata decoy (safe)",
     "desc": "Safe parser returns HTML containing metadata-like strings.",
     "config": "safe + metadata decoys in HTML",
     "phase": "baseline", "scope": "any XML"},

    # ------------------------- FN BAIT ----------------------------------
    {"path": "/xml/silent", "method": "POST", "verdict": "fn",
     "title": "DOCTYPE stripped (FN bait)",
     "desc": "DOCTYPE removed before parsing. No entity remains.",
     "config": "safe + DOCTYPE removal",
     "phase": "baseline", "scope": "any (DOCTYPE stripped)"},
]

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XXE Test Lab</title>
<style>
  :root{
    --bg:#0a0e14; --bg-2:#0e131c; --panel:#131a26; --panel-2:#182130;
    --line:#243044; --line-2:#2d3b52;
    --fg:#dbe4f0; --fg-2:#8896ab; --muted:#5d6b82;
    --accent:#4db8ff; --accent-2:#1f6feb; --accent-3:#7c5cff;
    --red:#ff6b6b; --orange:#f5a623; --green:#4ade80; --cyan:#22d3ee;
    --mono:"JetBrains Mono","SF Mono","Fira Code",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0;height:100%;background:var(--bg);
    color:var(--fg);font-family:var(--sans);font-size:14px;line-height:1.5;
    -webkit-font-smoothing:antialiased}
  body{display:grid;grid-template-columns:230px 1fr;grid-template-rows:56px 1fr;
    height:100vh;overflow:hidden}
  header{grid-column:1/-1;display:flex;align-items:center;gap:14px;
    padding:0 20px;background:var(--bg-2);border-bottom:1px solid var(--line);
    z-index:5}
  header .brand{display:flex;align-items:center;gap:10px;font-weight:600;
    font-size:15px;letter-spacing:.2px}
  header .brand .dot{width:8px;height:8px;border-radius:2px;
    background:linear-gradient(135deg,var(--cyan),var(--accent-2));
    box-shadow:0 0 10px rgba(77,184,255,.5)}
  header .tag{font-size:11px;color:var(--muted);border:1px solid var(--line);
    padding:2px 8px;border-radius:20px;font-family:var(--mono)}
  header .mode{font-size:11px;font-family:var(--mono);
    padding:2px 8px;border-radius:20px;cursor:pointer;
    border:1px solid var(--line-2);transition:all .12s;user-select:none}
  header .mode.realistic{color:var(--accent);border-color:rgba(77,184,255,.4);
    background:rgba(77,184,255,.08)}
  header .mode.scoped{color:var(--accent-3);border-color:rgba(124,92,255,.4);
    background:rgba(124,92,255,.08)}
  header .mode:hover{filter:brightness(1.2)}
  header .spacer{flex:1}
  header .stat{font-family:var(--mono);font-size:11.5px;color:var(--fg-2)}
  header .warn{font-size:11.5px;color:var(--orange);padding:4px 10px;
    border-radius:6px;background:rgba(245,166,35,.08);
    border:1px solid rgba(245,166,35,.25)}

  nav{background:var(--bg-2);border-right:1px solid var(--line);
    padding:16px 10px;overflow-y:auto}
  nav .group{font-size:10.5px;color:var(--muted);text-transform:uppercase;
    letter-spacing:.8px;padding:12px 10px 6px}
  nav a{display:flex;align-items:center;gap:10px;padding:8px 10px;
    color:var(--fg-2);text-decoration:none;border-radius:6px;font-size:13px;
    cursor:pointer;margin-bottom:1px;transition:background .1s}
  nav a:hover{background:var(--panel);color:var(--fg)}
  nav a.active{background:var(--panel-2);color:var(--fg);
    box-shadow:inset 2px 0 0 var(--accent)}
  nav a .ico{width:14px;text-align:center;opacity:.7;font-size:13px}

  main{overflow-y:auto;padding:24px 28px}
  .view{display:none;animation:fade .15s ease}
  .view.active{display:block}
  @keyframes fade{from{opacity:0}to{opacity:1}}
  h1{margin:0 0 4px;font-size:20px;font-weight:600;letter-spacing:.2px}
  .sub{color:var(--fg-2);font-size:13px;margin-bottom:22px}
  h2{font-size:12px;font-weight:600;color:var(--fg-2);
    text-transform:uppercase;letter-spacing:.7px;margin:0 0 14px}

  .endpoints{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
    gap:12px;margin-bottom:28px}
  .ep{background:var(--panel);border:1px solid var(--line);border-radius:10px;
    padding:14px 16px;position:relative;overflow:hidden}
  .ep .top{display:flex;align-items:center;gap:8px;margin-bottom:8px}
  .ep .path{font-family:var(--mono);font-size:12px;color:var(--accent);
    font-weight:500}
  .ep .verdict{margin-left:auto;font-size:10px;padding:2px 7px;
    border-radius:10px;font-weight:600;letter-spacing:.4px}
  .v-vuln{color:var(--red);background:rgba(255,107,107,.1);
    border:1px solid rgba(255,107,107,.3)}
  .v-safe{color:var(--green);background:rgba(74,222,128,.1);
    border:1px solid rgba(74,222,128,.3)}
  .v-fn{color:var(--orange);background:rgba(245,166,35,.1);
    border:1px solid rgba(245,166,35,.3)}
  .ep .title{font-weight:500;margin-bottom:5px}
  .ep .desc{font-size:12.5px;color:var(--fg-2);margin-bottom:8px;
    line-height:1.55}
  .ep .cfg{font-family:var(--mono);font-size:11px;color:var(--muted);
    padding:6px 8px;background:var(--bg-2);border-radius:5px;
    border:1px solid var(--line);word-break:break-all}
  .ep .scope{font-family:var(--mono);font-size:11px;color:var(--orange);
    padding:5px 8px;background:rgba(245,166,35,.06);border-radius:5px;
    border:1px solid rgba(245,166,35,.2);margin-top:6px;word-break:break-all}
  .ep .phase{font-family:var(--mono);font-size:10.5px;color:var(--accent-3);
    margin-top:6px;letter-spacing:.3px}
  .ep .note{font-family:var(--sans);font-size:12px;color:var(--orange);
    padding:8px 10px;background:rgba(245,166,35,.07);border-radius:5px;
    border:1px solid rgba(245,166,35,.25);margin-top:8px;line-height:1.55}
  .ep .note::before{content:"⚠ ";font-weight:600}

  button{background:var(--accent-2);color:white;border:0;border-radius:7px;
    padding:9px 16px;font-size:13px;font-weight:500;cursor:pointer;
    transition:background .12s;font-family:var(--sans)}
  button:hover{background:#388bfd}
  button.ghost{background:transparent;color:var(--fg-2);
    border:1px solid var(--line)}
  button.ghost:hover{background:var(--panel);color:var(--fg)}

  input,select{background:var(--bg-2);color:var(--fg);
    border:1px solid var(--line);border-radius:7px;padding:9px 12px;
    font-family:var(--mono);font-size:12.5px;outline:none;transition:all .12s}
  input:focus,select:focus{border-color:var(--accent-2);
    box-shadow:0 0 0 3px rgba(31,111,235,.15)}

  .hint{font-size:11.5px;color:var(--muted);margin-left:auto}

  .log-tools{display:flex;gap:10px;align-items:center;margin-bottom:14px;
    flex-wrap:wrap}
  .log{background:var(--bg-2);border:1px solid var(--line);
    border-radius:10px;overflow:hidden;max-height:calc(100vh - 260px);
    overflow-y:auto}
  .log .lhead,.log .row{
    display:grid;
    grid-template-columns:96px 56px 1fr 54px 60px 60px 60px 70px 80px;
    gap:10px;padding:8px 14px;font-family:var(--mono);font-size:11.5px;
    align-items:center;
  }
  .log .lhead{font-size:10.5px;color:var(--muted);text-transform:uppercase;
    letter-spacing:.6px;background:var(--panel);border-bottom:1px solid var(--line);
    position:sticky;top:0;z-index:2}
  .log .row{border-bottom:1px solid var(--line);cursor:pointer;
    transition:background .1s}
  .log .row:hover{background:var(--panel)}
  .log .row.open{background:var(--panel-2)}
  .log .t{color:var(--muted)}
  .log .m{color:var(--accent-3);font-weight:500}
  .log .p{color:var(--accent);overflow:hidden;text-overflow:ellipsis;
    white-space:nowrap}
  .log .s{text-align:right;font-weight:500}
  .log .n{color:var(--fg-2);text-align:right}
  .log .mode-cell{font-size:10.5px}
  .log .gate{font-size:10.5px;font-weight:500}
  .log .empty{padding:40px;text-align:center;color:var(--muted);
    font-size:13px}
  .status-2xx{color:var(--green)} .status-4xx{color:var(--orange)}
  .status-5xx{color:var(--red)}
  .mode-realistic{color:var(--accent)} .mode-scoped{color:var(--accent-3)}
  .gate-accepted{color:var(--green)} .gate-rejected{color:var(--orange)}
  .gate-error{color:var(--red)}

  .log .detail{grid-column:1/-1;padding:0;background:var(--bg);
    border-bottom:1px solid var(--line);display:none}
  .log .row.open + .detail{display:block}
  .log .detail-inner{padding:14px 20px;font-family:var(--mono);
    font-size:11.5px;line-height:1.7}
  .log .detail-inner .kv{display:grid;
    grid-template-columns:140px 1fr;gap:6px 14px;margin-bottom:10px}
  .log .detail-inner .kv .k{color:var(--muted)}
  .log .detail-inner .kv .v{color:var(--fg);word-break:break-all}
  .log .detail-inner h4{margin:12px 0 6px;font-size:10.5px;
    color:var(--muted);text-transform:uppercase;letter-spacing:.6px;
    font-weight:600}
  .log .detail-inner pre{margin:0;padding:10px 12px;background:var(--bg-2);
    border:1px solid var(--line);border-radius:6px;white-space:pre-wrap;
    word-break:break-all;max-height:320px;overflow:auto;
    font-family:var(--mono);font-size:11px;color:var(--fg-2)}

  .about p{color:var(--fg-2);line-height:1.7;margin:0 0 14px}
  .about code{font-family:var(--mono);font-size:12px;
    background:var(--bg-2);padding:1px 6px;border-radius:4px;
    border:1px solid var(--line);color:var(--accent)}
  .about ul{color:var(--fg-2);line-height:1.8;padding-left:20px;margin:0 0 14px}
  .about .modeblock{background:var(--panel);border:1px solid var(--line);
    border-radius:10px;padding:16px 18px;margin:14px 0}

  ::-webkit-scrollbar{width:10px;height:10px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:5px}
  ::-webkit-scrollbar-thumb:hover{background:#3a4a68}
</style>
</head>
<body>

<header>
  <div class="brand"><span class="dot"></span>XXE Test Lab</div>
  <span class="tag">v1 · 127.0.0.1</span>
  <span class="mode realistic" id="modeTag" title="Click for override instructions">mode: realistic</span>
  <div class="spacer"></div>
  <span class="stat" id="hStat">0 requests</span>
  <span class="warn">⚠ Intentional vulnerability lab</span>
</header>

<nav>
  <div class="group">Explore</div>
  <a data-view="endpoints" class="active"><span class="ico">◆</span>Endpoints</a>
  <a data-view="log"><span class="ico">≡</span>Request Log</a>
  <div class="group">Info</div>
  <a data-view="about"><span class="ico">?</span>About</a>
</nav>

<main>

<div class="view active" id="view-endpoints">
  <h1>Endpoints</h1>
  <div class="sub">Every endpoint, its scope, and the scanner phase it
    exercises. Orange "scope" lines show what each endpoint accepts.</div>

  <h2>Vulnerable — scanner should flag</h2>
  <div class="endpoints" id="eps-vuln"></div>

  <h2>Safe — scanner must NOT flag</h2>
  <div class="endpoints" id="eps-safe"></div>

  <h2>False-negative bait — scanner may miss</h2>
  <div class="endpoints" id="eps-fn"></div>
</div>

<div class="view" id="view-log">
  <h1>Request Log</h1>
  <div class="sub">In-memory ring buffer, most recent 500 requests.
    Click any row to expand full request/response detail.</div>
  <div class="log-tools">
    <input id="logFilter" placeholder="filter by path…" style="max-width:240px">
    <select id="modeFilter">
      <option value="">all modes</option>
      <option value="realistic">realistic</option>
      <option value="scoped">scoped</option>
    </select>
    <select id="gateFilter">
      <option value="">all gates</option>
      <option value="accepted">accepted</option>
      <option value="rejected">rejected</option>
      <option value="error">error</option>
    </select>
    <select id="statusFilter">
      <option value="">all statuses</option>
      <option value="2xx">2xx</option>
      <option value="4xx">4xx</option>
      <option value="5xx">5xx</option>
    </select>
    <button class="ghost" onclick="refreshLog()">Refresh</button>
    <button class="ghost" onclick="clearLog()">Clear</button>
    <span class="hint" id="logMeta"></span>
  </div>
  <div class="log">
    <div class="lhead">
      <span>time</span>
      <span>method</span>
      <span>path</span>
      <span>status</span>
      <span>ms</span>
      <span>req B</span>
      <span>resp B</span>
      <span>mode</span>
      <span>gate</span>
    </div>
    <div id="logBody"></div>
  </div>
</div>

<div class="view" id="view-about">
  <h1>About</h1>
  <div class="sub">What this lab is and how to use it.</div>
  <div class="about">

    <div class="modeblock">
      <h2 style="margin-top:0">Two modes</h2>
      <p><b style="color:var(--accent)">realistic</b> (default) — mimics a
        real application. Wrong Content-Type → 415, wrong shape → parse
        anyway (soft gate) or generic 400 (hard gate). No reason leak.
        The scanner must distinguish "target rejected my payload" from
        "target accepted but didn't resolve" using response shape alone.</p>
      <p><b style="color:var(--accent-3)">scoped</b> — deterministic legacy
        behavior. Every out-of-scope body gets a stable
        <code>200 out of scope: &lt;reason&gt;</code> that parses nothing.
        Opt-in for regression suites where cross-technique FP vetoes must
        be exact.</p>
      <p style="margin-bottom:0">Override per request with header
        <code>X-Lab-Mode: scoped|realistic</code> or query param
        <code>?lab_mode=scoped</code>. Precedence: header &gt; query &gt;
        env default (<code>XXE_LAB_MODE</code>).</p>
    </div>

    <h2 style="margin-top:20px">Endpoint verdicts</h2>
    <ul>
      <li><b style="color:var(--red)">VULN</b> — a correct scanner should
        report a finding.</li>
      <li><b style="color:var(--green)">SAFE</b> — a correct scanner must
        report nothing.</li>
      <li><b style="color:var(--orange)">FN bait</b> — designed to test a
        known limitation.</li>
    </ul>

    <h2 style="margin-top:20px">Machine-readable verdicts</h2>
    <p>Fetch <code>GET /api/verdicts</code> for a JSON map from
      <code>"&lt;method&gt; &lt;path&gt;"</code> to
      <code>"vuln" | "safe" | "fn"</code>. A scoring harness can diff
      that against the scanner's findings to compute precision and
      recall automatically.</p>

    <h2 style="margin-top:20px">Gate types</h2>
    <ul>
      <li><b>Hard gate</b> — Content-Type, required query param, required
        form field, method. Rejected in both modes with a realistic status
        (415/400/405) and a generic body. Real apps enforce these.</li>
      <li><b>Soft gate</b> — root element name, payload keyword presence,
        DOCTYPE absence. In scoped mode, rejected with a stable 200
        out-of-scope. In realistic mode, falls through to the parser
        anyway (real apps frequently skip shape validation).</li>
    </ul>

    <h2 style="margin-top:20px">Parser limitations</h2>
    <p>This lab runs on Python + lxml, which uses <b>libxml2</b>. Since
      libxml2 2.13.0, external DTD access is disabled by default. Error-based
      XXE techniques that depend on loading an external subset or a
      URI-fetching parameter entity cannot succeed against the Python
      endpoints.</p>
    <p>The Java lab at <code>http://127.0.0.1:5001/xml/error</code> runs on
      Xerces, which permits those constructs.</p>

    <h2 style="margin-top:20px">Running the scanner</h2>
    <ul>
      <li>After editing this lab, clear the scanner's fingerprint cache
        (<code>~/.cache/xxeripper/fingerprints.json</code>) or pass
        <code>--no-fingerprint-cache</code>.</li>
      <li>For OOB phases, run
        <code>interactsh-client -json -v &gt; /tmp/interactsh.jsonl</code>
        and point the scanner's <code>--oob-domain</code> at the
        session domain.</li>
      <li>Set <code>XXE_LAB_NOISE_SEED=1</code> before starting the lab
        to make <code>/xml/noise</code> deterministic across runs.</li>
      <li>For deterministic regression runs, send
        <code>X-Lab-Mode: scoped</code> on every request.</li>
    </ul>

    <h2 style="margin-top:20px">Safety</h2>
    <p>Reads arbitrary local files on request. Bound to
      <code>127.0.0.1</code>. Do not expose it.</p>
  </div>
</div>

</main>

<script>
"use strict";

let ENDPOINTS = [];
let OPEN_ROWS = new Set();

const $ = id => document.getElementById(id);

function esc(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[c]);
}

function showView(name){
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelectorAll("nav a").forEach(a => a.classList.remove("active"));
  const v = $("view-" + name);
  if(v) v.classList.add("active");
  const link = document.querySelector(`nav a[data-view="${name}"]`);
  if(link) link.classList.add("active");
  if(name === "log") refreshLog();
}

document.querySelectorAll("nav a").forEach(a => {
  a.addEventListener("click", () => showView(a.dataset.view));
});

async function refreshMode(){
  try{
    const r = await fetch("/api/mode");
    const m = await r.json();
    const tag = $("modeTag");
    tag.textContent = "mode: " + m.mode;
    tag.className = "mode " + m.mode;
    tag.title = "Default: " + m.default +
      " · override with X-Lab-Mode header or ?lab_mode=";
  }catch(e){}
}

$("modeTag").addEventListener("click", () => {
  alert("Per-request override:\n\n" +
        "  Header:  X-Lab-Mode: scoped|realistic\n" +
        "  Query:   ?lab_mode=scoped|realistic\n\n" +
        "Server default is set by env XXE_LAB_MODE.");
});

async function loadEndpoints(){
  try{
    const r = await fetch("/api/endpoints");
    ENDPOINTS = await r.json();
  }catch(e){ ENDPOINTS = []; }
  renderEndpoints();
}

function renderEndpoints(){
  const groups = { vuln: [], safe: [], fn: [] };
  ENDPOINTS.forEach(e => groups[e.verdict]?.push(e));

  const card = e => `
    <div class="ep">
      <div class="top">
        <span class="path">${esc(e.method)} ${esc(e.path)}</span>
        <span class="verdict v-${e.verdict}">${
          e.verdict === "vuln" ? "VULN" :
          e.verdict === "safe" ? "SAFE" : "FN BAIT"}</span>
      </div>
      <div class="title">${esc(e.title)}</div>
      <div class="desc">${esc(e.desc)}</div>
      <div class="cfg">${esc(e.config)}</div>
      ${e.scope ? `<div class="scope">scope: ${esc(e.scope)}</div>` : ""}
      ${e.phase ? `<div class="phase">scanner phase: ${esc(e.phase)}</div>` : ""}
      ${e.note  ? `<div class="note">${esc(e.note)}</div>`  : ""}
    </div>`;

  $("eps-vuln").innerHTML = groups.vuln.map(card).join("");
  $("eps-safe").innerHTML = groups.safe.map(card).join("");
  $("eps-fn").innerHTML   = groups.fn.map(card).join("");
}

async function refreshLog(){
  try{
    const r = await fetch("/api/log");
    const rows = await r.json();

    const pathF = ($("logFilter").value || "").toLowerCase();
    const modeF = $("modeFilter").value;
    const gateF = $("gateFilter").value;
    const statF = $("statusFilter").value;

    const filtered = rows.filter(x => {
      if(pathF && !((x.path || "").toLowerCase().includes(pathF))) return false;
      if(modeF && x.mode !== modeF) return false;
      if(gateF && x.gate !== gateF) return false;
      if(statF){
        const s = x.status || 0;
        if(statF === "2xx" && !(s >= 200 && s < 300)) return false;
        if(statF === "4xx" && !(s >= 400 && s < 500)) return false;
        if(statF === "5xx" && !(s >= 500 && s < 600)) return false;
      }
      return true;
    });

    const body = $("logBody");
    if(!filtered.length){
      body.innerHTML = `<div class="empty">${
        (pathF || modeF || gateF || statF)
          ? "no rows match filter"
          : "no requests yet"}</div>`;
    }else{
      body.innerHTML = filtered.map(row => {
        const id = row.id || (row.ts + "|" + row.path);
        const open = OPEN_ROWS.has(id);
        const t = new Date(row.ts * 1000).toLocaleTimeString();
        const s = row.status || 0;
        const sCls = s >= 500 ? "status-5xx"
                   : s >= 400 ? "status-4xx" : "status-2xx";
        const modeCls = "mode-" + (row.mode || "realistic");
        const gateCls = "gate-" + (row.gate || "accepted");

        return `
          <div class="row ${open ? "open" : ""}" data-id="${esc(id)}">
            <span class="t">${esc(t)}</span>
            <span class="m">${esc(row.method || "")}</span>
            <span class="p" title="${esc(row.path || "")}">${esc(row.path || "")}</span>
            <span class="s ${sCls}">${esc(s || "")}</span>
            <span class="n">${esc(row.ms ?? "")}</span>
            <span class="n">${esc(row.req_len ?? row.len ?? "")}</span>
            <span class="n">${esc(row.resp_len ?? "")}</span>
            <span class="mode-cell ${modeCls}">${esc(row.mode || "")}</span>
            <span class="gate ${gateCls}">${esc(row.gate || "—")}</span>
          </div>
          <div class="detail">${renderDetail(row)}</div>`;
      }).join("");
    }
    $("logMeta").textContent = `${filtered.length} of ${rows.length} entries`;

    document.querySelectorAll(".log .row").forEach(row => {
      row.addEventListener("click", () => {
        const id = row.dataset.id;
        if(OPEN_ROWS.has(id)) OPEN_ROWS.delete(id);
        else OPEN_ROWS.add(id);
        row.classList.toggle("open");
      });
    });
  }catch(e){ /* ignore */ }
}

function renderDetail(r){
  const kv = (k, v) => v === undefined || v === null || v === ""
    ? "" : `<div class="k">${esc(k)}</div><div class="v">${esc(String(v))}</div>`;

  return `
    <div class="detail-inner">
      <div class="kv">
        ${kv("request id", r.id)}
        ${kv("iso time", r.iso)}
        ${kv("endpoint", r.endpoint || r.path)}
        ${kv("method", r.method)}
        ${kv("status", r.status)}
        ${kv("duration ms", r.ms)}
        ${kv("content-type", r.ct)}
        ${kv("user-agent", r.ua)}
        ${kv("remote addr", r.remote)}
        ${kv("mode", r.mode + (r.mode_source ? " (" + r.mode_source + ")" : ""))}
        ${kv("gate", r.gate)}
        ${kv("gate kind", r.gate_kind)}
        ${kv("gate reason", r.gate_reason)}
        ${kv("note", r.note)}
        ${kv("request bytes", r.req_len ?? r.len)}
        ${kv("response bytes", r.resp_len)}
        ${kv("error", r.error ? "true" : "")}
      </div>
      ${r.preview ? `<h4>request preview</h4><pre>${esc(r.preview)}</pre>` : ""}
      ${r.resp_preview ? `<h4>response preview</h4><pre>${esc(r.resp_preview)}</pre>` : ""}
    </div>`;
}

async function clearLog(){
  try{
    await fetch("/api/log/clear", {method: "POST"});
    OPEN_ROWS.clear();
    refreshLog();
  }catch(e){}
}

async function refreshStats(){
  try{
    const r = await fetch("/api/stats");
    const s = await r.json();
    $("hStat").textContent = `${s.total} request${s.total === 1 ? "" : "s"}`;
  }catch(e){}
}

$("logFilter").addEventListener("input", refreshLog);
$("modeFilter").addEventListener("change", refreshLog);
$("gateFilter").addEventListener("change", refreshLog);
$("statusFilter").addEventListener("change", refreshLog);

(async function boot(){
  await loadEndpoints();
  await refreshMode();
  refreshLog();
  refreshStats();
  setInterval(refreshLog, 2500);
  setInterval(refreshStats, 3000);
})();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


# ---------------------------------------------------------------------------
# Startup sanity check
# ---------------------------------------------------------------------------

def _sanity_check() -> list[str]:
    warnings: list[str] = []
    seen: set[str] = set()
    for ep in ENDPOINT_META:
        path = ep["path"]
        if path in seen:
            warnings.append(f"duplicate path in ENDPOINT_META: {path}")
        seen.add(path)
        for key in ("path", "method", "verdict", "title", "desc",
                    "config", "phase", "scope"):
            if key not in ep:
                warnings.append(f"{path}: missing key {key!r}")
        if ep.get("verdict") not in ("vuln", "safe", "fn"):
            warnings.append(f"{path}: unknown verdict {ep.get('verdict')!r}")
    return warnings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _generate_dev_cert(force: bool = False,
                       cert_dir: str | None = None,
                       reason: str = "TLS requested") -> tuple[str, str]:
    import shutil
    import subprocess
    import tempfile

    if shutil.which("openssl") is None:
        raise SystemExit(
            f"[!] {reason} but openssl is not on PATH.\n"
            f"    Install openssl, or pass --cert / --key explicitly."
        )

    cert_dir = cert_dir or os.path.join(tempfile.gettempdir(),
                                        "xxe-lab-certs")
    os.makedirs(cert_dir, exist_ok=True)
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")

    if not force and os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "365", "-nodes",
        "-subj", "/CN=127.0.0.1",
        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
    ]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode("utf-8", "replace").strip()
        raise SystemExit(
            f"[!] {reason} but openssl failed to generate a cert "
            f"(exit {e.returncode}).\n"
            f"    openssl stderr:\n    {err or '(empty)'}\n"
            f"    -addext requires OpenSSL 1.1.1 or newer. If your "
            f"openssl is older, generate a cert yourself and pass "
            f"--cert / --key."
        )
    return cert_file, key_file


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="xxe_lab",
        description="XXE Test Lab v1 — local-only XXE scanner playground.",
    )
    p.add_argument("--https", action="store_true",
                   help="serve over TLS. Reuses the cached self-signed "
                        "cert if one exists, otherwise generates one.")

    cert_group = p.add_mutually_exclusive_group()
    cert_group.add_argument("--autocert", action="store_true",
                            help="serve over TLS with a freshly generated "
                                 "self-signed cert. Always runs openssl "
                                 "and overwrites the cached cert. "
                                 "Implies --https. Mutually exclusive "
                                 "with --cert/--key.")
    cert_group.add_argument("--cert", default=None,
                            help="path to a PEM certificate (implies "
                                 "--https)")
    cert_group.add_argument("--key", default=None,
                            help="path to a PEM private key (implies "
                                 "--https)")
    p.add_argument("--host", default=os.environ.get("FLASK_HOST",
                                                    "127.0.0.1"),
                   help="bind address (default: %(default)s)")
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("FLASK_PORT", "5000")),
                   help="bind port (default: %(default)s)")
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()

    use_tls = (args.https or args.autocert
               or bool(args.cert) or bool(args.key))
    ssl_context = None
    cert_origin = ""

    if use_tls:
        if args.cert or args.key:
            if bool(args.cert) != bool(args.key):
                raise SystemExit(
                    "[!] --cert and --key must be supplied together")
            cert_file, key_file = args.cert, args.key
            cert_origin = "supplied"
        else:
            reason = ("--autocert requested" if args.autocert
                      else "--https requested")
            cert_file, key_file = _generate_dev_cert(
                force=args.autocert, reason=reason)
            cert_origin = ("generated (fresh)" if args.autocert
                           else "generated (cached)")
        ssl_context = (cert_file, key_file)

    scheme = "https" if use_tls else "http"

    for w in _sanity_check():
        print(f"[!] {w}")

    print(f"[*] XXE Test Lab v1 on {scheme}://{args.host}:{args.port}")
    if use_tls:
        print(f"[*] TLS cert: {ssl_context[0]}  [{cert_origin}]")
        print(f"[*] TLS key:  {ssl_context[1]}")
        print(f"[*] Self-signed — scanners must skip cert verification.")
    print(f"[*] Default mode: {LAB_MODE} (override: X-Lab-Mode header "
          f"or ?lab_mode=)")
    print(f"[*] {len(ENDPOINT_META)} endpoints registered")
    print(f"[*] Verdicts API: GET /api/verdicts")
    print(f"[*] Do NOT expose this to untrusted networks.")
    print(f"[*] After editing endpoints, clear the scanner cache:")
    print(f"[*]   rm ~/.cache/xxeripper/fingerprints.json")
    print(f"[*]   or pass --no-fingerprint-cache to the scanner.")

    app.run(
        host=args.host, port=args.port,
        debug=False, threaded=True,
        ssl_context=ssl_context,
    )