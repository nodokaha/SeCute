#!/usr/bin/env python3
"""SeCute traffic audit: an original, dependency-free egress proxy that
checks what a target application actually sends over the network.

This is NOT a wrapper around an existing proxy package. The proxy, the
detector and the source mapper are implemented here on top of the
Python standard library; the only external tool used is the `openssl`
command line, to mint a throwaway local CA for HTTPS inspection.

How it works:
  1. A run generates synthetic "canary" values (a fake email address,
     device id, chat message, access token, ...). They are exported to
     the target through the environment (SECUTE_CANARY_*), so a test
     harness / fixture can plant them in the app under audit. They are
     unique per run and are not real data.
  2. The target command is started with http_proxy / https_proxy
     pointing at this proxy, so its HTTP(S) traffic is recorded.
     HTTPS is decrypted locally with the throwaway CA (the target is
     pointed at the CA through the usual *_CA_BUNDLE / SSL_CERT_FILE
     variables). CONNECT tunnels that cannot be inspected are relayed
     blind and recorded as uninspected, never as clean.
  3. A deterministic detector (no AI, no guessing) looks for:
       - canary values leaving for a destination that is not on the
         allowlist                          -> canary_egress (high)
       - sensitive field names (email, token, password, ...) or an
         Authorization / Cookie header sent to a non-allowlisted
         destination                        -> sensitive_egress
       - any request to a non-allowlisted destination
                                              -> unknown_destination
       - sensitive data over plain HTTP     -> plaintext_egress
  4. When a source tree is given, findings are mapped back to the
     code that plausibly sent them by searching the source for the
     destination host, the request path and the field names.

Safety properties (same rules as the rest of SeCute):
  - Canary values, header secrets and request bodies are NEVER copied
    into report.json or capture.json. Reports carry canary ids and
    SHA256 hashes only; capture entries carry field *names*, header
    values with secrets replaced, and a body hash.
  - The canary values themselves live only in canaries.json (mode
    0600) inside the results directory, because the operator needs
    them to plant the canaries. Treat that file as a secret and
    delete it with the results.
  - The audit CA private key never leaves the results directory and
    is only trusted, through environment variables, by the audited
    process for the duration of the run. Do not install it system-wide.
  - The proxy binds to 127.0.0.1 only.

Coverage honesty: certificate pinning, QUIC, DNS-over-HTTPS and code
that ignores proxy environment variables can bypass this proxy. Any
blind tunnel or bypass shows up as partial coverage in the report
status instead of being silently treated as a pass.

Report shape mirrors seccheck.py: schema_version 2, a per-tool entry
with its own status and findings, an overall status, a summary, and a
provenance section with hashes of the raw outputs.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import ssl
import subprocess
import sys
import threading
from datetime import datetime
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, urlsplit

TOOL_NAME = "egress-proxy"
TRAFFIC_VERSION = "0.1.0"
REPORT_SCHEMA_VERSION = 2

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-connection", "proxy-authorization",
    "proxy-authenticate", "te", "trailer", "trailers", "transfer-encoding",
    "upgrade",
}

SENSITIVE_FIELD_PATTERNS = [
    re.compile(p) for p in (
        r"pass(word|wd)?", r"secret", r"token", r"api[_-]?key",
        r"authorization", r"cookie", r"e[_-]?mail", r"phone",
        r"address", r"contact", r"location", r"latitude|longitude",
        r"device[_-]?id", r"imei|idfa|advertising[_-]?id",
        r"credit[_-]?card|card[_-]?number", r"ssn|social[_-]?security",
        r"chat|message[_-]?body|full[_-]?name|birth",
    )
]

TEXT_FILE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".cs", ".go", ".rb", ".java",
    ".kt", ".rs", ".php", ".json", ".yml", ".yaml", ".toml", ".ini",
    ".cfg", ".env", ".txt", ".md", ".html", ".xml", ".sh",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --- canaries ---------------------------------------------------------

CANARY_ENV = {
    "email": "SECUTE_CANARY_EMAIL",
    "phone": "SECUTE_CANARY_PHONE",
    "device_id": "SECUTE_CANARY_DEVICE_ID",
    "display_name": "SECUTE_CANARY_DISPLAY_NAME",
    "chat_message": "SECUTE_CANARY_CHAT_MESSAGE",
    "access_token": "SECUTE_CANARY_ACCESS_TOKEN",
}


def generate_canaries():
    """Synthetic per-run values. Never real data, always recognisable."""
    token = secrets.token_hex(4)
    values = {
        "email": f"canary-{token}@example.invalid",
        "phone": f"+81-90-0000-{int(token[:4], 16) % 10000:04d}",
        "device_id": f"canary-device-{token}",
        "display_name": f"Canary User {token}",
        "chat_message": f"CANARY-CHAT-{token.upper()}",
        "access_token": f"canary-access-{token}-{secrets.token_hex(4)}",
    }
    return [
        {"id": cid, "value": value, "sha256": sha256_hex(value),
         "env": CANARY_ENV[cid]}
        for cid, value in values.items()
    ]


def redact_text(text, canaries):
    """Replace canary values (raw and URL-encoded) with <canary:id>."""
    if not text:
        return text
    for c in canaries:
        text = text.replace(c["value"], f"<canary:{c['id']}>")
        text = text.replace(quote(c["value"], safe=""),
                            f"<canary:{c['id']}>")
    return text


# --- request records and detection ------------------------------------

def extract_field_names(body, content_type):
    """Field *names* only, from a JSON or form-encoded body."""
    names = []
    if not body:
        return names
    ctype = (content_type or "").lower()
    text = body.decode("utf-8", errors="replace")
    if "json" in ctype or text.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if parsed is not None:
            def walk(node):
                if isinstance(node, dict):
                    for k, v in node.items():
                        names.append(str(k))
                        walk(v)
                elif isinstance(node, list):
                    for item in node:
                        walk(item)
            walk(parsed)
            return names
    if "form" in ctype or "=" in text:
        for key, _ in parse_qsl(text, keep_blank_values=True):
            names.append(key)
    return names


def make_record(method, scheme, host, port, path, query, headers,
                body=b""):
    """One recorded request. `body` stays in memory only; the writers
    below hash and redact it before anything reaches disk."""
    hdrs = {}
    for k, v in headers:
        hdrs[k.lower()] = v
    return {
        "time": datetime.now().isoformat(timespec="seconds"),
        "method": method,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path or "/",
        "query": query or "",
        "headers": hdrs,
        "field_names": extract_field_names(
            body, hdrs.get("content-type", "")),
        "body": body,
        "status": None,
        "response_size": 0,
        "tunnel": False,
        "uninspected": False,
        "error": None,
    }


def is_sensitive_field(name):
    low = name.lower()
    return any(p.search(low) for p in SENSITIVE_FIELD_PATTERNS)


def host_allowed(host, allowlist):
    """True/False when an allowlist is given, None when there is none."""
    if allowlist is None:
        return None
    host = (host or "").lower()
    for entry in allowlist:
        entry = entry.lower()
        if entry.startswith("*."):
            if host == entry[2:] or host.endswith(entry[1:]):
                return True
        elif host == entry:
            return True
    return False


def inspect_record(record, canaries, allowlist):
    """Deterministic detection. Returns (findings, observations).

    Findings never contain canary values or field values: ids, names,
    hashes and destinations only.
    """
    findings, observations = [], []
    if record.get("tunnel"):
        return findings, observations
    host = record["host"]
    allowed = host_allowed(host, allowlist)
    base = {"host": host, "port": record["port"],
            "method": record["method"], "path": record["path"],
            "scheme": record["scheme"]}
    haystacks = {
        "url": record["path"] + "?" + record["query"],
        "headers": "\n".join(f"{k}: {v}" for k, v in
                             record["headers"].items()),
        "body": record["body"].decode("utf-8", errors="replace"),
    }
    # Canary egress.
    for c in canaries:
        encoded = quote(c["value"], safe="")
        where = [name for name, text in haystacks.items()
                 if c["value"] in text or encoded in text]
        if not where:
            continue
        entry = dict(base, canary_id=c["id"],
                     canary_sha256=c["sha256"][:16], where=where)
        if allowed:
            observations.append(dict(entry, type="canary_to_allowed"))
        else:
            findings.append(dict(
                entry, type="canary_egress",
                severity="high" if allowed is False else "medium",
                destination_allowed=allowed))
    # Sensitive fields / credential headers to third parties.
    sensitive = sorted({n for n in record["field_names"]
                        if is_sensitive_field(n)})
    cred_headers = [h for h in ("authorization", "cookie")
                    if h in record["headers"]]
    if allowed is False:
        if sensitive:
            findings.append(dict(
                base, type="sensitive_field_egress", severity="medium",
                fields=sensitive, destination_allowed=False))
        if cred_headers:
            findings.append(dict(
                base, type="credential_header_egress", severity="high",
                headers=cred_headers, destination_allowed=False))
        findings.append(dict(
            base, type="unknown_destination", severity="low",
            destination_allowed=False))
    elif allowed:
        if sensitive or cred_headers:
            observations.append(dict(
                base, type="sensitive_to_allowed", fields=sensitive,
                headers=cred_headers))
    # Plaintext transport of anything sensitive.
    if record["scheme"] == "http" and (sensitive or cred_headers or
                                       any(f.get("type") == "canary_egress"
                                           for f in findings)):
        findings.append(dict(base, type="plaintext_egress",
                             severity="medium"))
    return findings, observations


def analyze_records(records, canaries, allowlist, source_dir=None):
    findings, observations = [], []
    seen = set()
    for record in records:
        f, o = inspect_record(record, canaries, allowlist)
        for item in f:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                findings.append(item)
        observations.extend(o)
    if source_dir:
        for item in findings:
            terms = [item["host"], item["path"]]
            terms += item.get("fields", [])
            if item.get("canary_id"):
                terms.append(item["canary_id"].split("_")[0])
            item["source_locations"] = map_to_source(source_dir, terms)
    return findings, observations


# --- source mapping ----------------------------------------------------

def map_to_source(source_dir, terms, limit=5):
    """Find host / path / field-name mentions in a source tree.

    This is the deterministic stand-in for "which code sent it": for
    one's own codebase, the endpoint string and the field names are
    almost always written literally where the request is built.
    """
    terms = [t for t in dict.fromkeys(terms) if t and len(t) >= 3]
    matches = []
    if not terms or not source_dir or not os.path.isdir(source_dir):
        return matches
    lowered = [(t, t.lower()) for t in terms]
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if os.path.splitext(name)[1].lower() not in TEXT_FILE_EXTS:
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) > 512 * 1024:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                low = line.lower()
                for term, term_low in lowered:
                    if term_low in low:
                        matches.append({
                            "file": os.path.relpath(path, source_dir),
                            "line": lineno, "matched": term})
                        break
                if len(matches) >= limit:
                    return matches
    return matches


# --- throwaway CA (via the openssl CLI) --------------------------------

def _run_openssl(args):
    proc = subprocess.run(["openssl", *args], capture_output=True,
                          text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl failed: {proc.stderr.strip()[:200]}")
    return proc


class CAManager:
    def __init__(self, directory):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)
        self.ca_crt = os.path.join(self.dir, "ca.crt")
        self.ca_key = os.path.join(self.dir, "ca.key")
        self._leaf_cache = {}
        self._lock = threading.Lock()

    def ensure(self):
        if os.path.exists(self.ca_crt) and os.path.exists(self.ca_key):
            return
        _run_openssl([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", self.ca_key, "-out", self.ca_crt, "-days", "2",
            "-subj", "/CN=SeCute Traffic Audit CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ])
        os.chmod(self.ca_key, 0o600)

    def leaf_for(self, host):
        """Per-host (crt, key) signed by the audit CA, cached."""
        with self._lock:
            if host in self._leaf_cache:
                return self._leaf_cache[host]
            self.ensure()
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
            crt = os.path.join(self.dir, f"leaf-{safe}.crt")
            key = os.path.join(self.dir, f"leaf-{safe}.key")
            csr = os.path.join(self.dir, f"leaf-{safe}.csr")
            ext = os.path.join(self.dir, f"leaf-{safe}.ext")
            try:
                ip = ipaddress.ip_address(host)
                san = f"IP:{ip}"
            except ValueError:
                san = f"DNS:{host}"
            with open(ext, "w", encoding="utf-8") as fh:
                fh.write(f"subjectAltName={san}\n")
            _run_openssl([
                "req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", csr, "-subj", f"/CN={host}"])
            _run_openssl([
                "x509", "-req", "-in", csr, "-CA", self.ca_crt,
                "-CAkey", self.ca_key, "-CAcreateserial",
                "-out", crt, "-days", "2", "-extfile", ext])
            os.chmod(key, 0o600)
            self._leaf_cache[host] = (crt, key)
            return crt, key

    def server_context(self, host):
        crt, key = self.leaf_for(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        return ctx


def openssl_version():
    try:
        proc = subprocess.run(["openssl", "version"], capture_output=True,
                              text=True, timeout=10)
        return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


# --- the proxy itself ---------------------------------------------------

class Recorder:
    def __init__(self):
        self.records = []
        self._lock = threading.Lock()

    def add(self, record):
        with self._lock:
            self.records.append(record)
        return record


def _filter_headers(items, extra_drop=()):
    out = {}
    for k, v in items:
        low = k.lower()
        if low in HOP_BY_HOP or low in extra_drop or \
                low.startswith("proxy-") or low == "host" or \
                low == "content-length":
            continue
        out[k] = v
    return out


class ProxyHandler(BaseHTTPRequestHandler):
    # One request per connection keeps the relay logic simple and
    # predictable; audited clients reconnect as needed.
    protocol_version = "HTTP/1.1"
    server_version = "SeCuteTrafficAudit/" + TRAFFIC_VERSION

    def log_message(self, *args):  # silence
        pass

    # -- plumbing helpers
    @property
    def cfg(self):
        return self.server

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        try:
            return self.rfile.read(int(length))
        except (ValueError, OSError):
            return b""

    def _relay_response(self, status, reason, headers, body):
        self.send_response_only(status, reason)
        sent = _filter_headers(headers.items() if hasattr(headers, "items")
                               else headers)
        for k, v in sent.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)
        self.close_connection = True

    def _upstream(self, scheme, host, port, method, path_q, headers, body):
        """Perform the real request. Returns (status, reason,
        header_pairs, body). Host mappings redirect the TCP target
        while keeping the original host for Host / SNI / verification."""
        mapped = self.cfg.host_map.get(host.lower())
        fwd = _filter_headers(headers.items())
        if scheme == "https":
            if mapped:
                raw = socket.create_connection(
                    (mapped[0], mapped[1]), timeout=15)
                ctx = ssl.create_default_context(
                    cafile=self.cfg.ca.ca_crt if self.cfg.ca else None)
                tls = ctx.wrap_socket(raw, server_hostname=host)
                conn = HTTPConnection(host, port, timeout=15)
                conn.sock = tls
            else:
                conn = HTTPSConnection(host, port, timeout=15)
            conn.request(method, path_q, body=body, headers=fwd)
            resp = conn.getresponse()
            data = resp.read()
            pairs = resp.getheaders()
            status, reason = resp.status, resp.reason
            conn.close()
            return status, reason, pairs, data
        if mapped:
            conn = HTTPConnection(mapped[0], mapped[1], timeout=15)
            fwd["Host"] = host if port in (80, 443) else f"{host}:{port}"
        else:
            conn = HTTPConnection(host, port, timeout=15)
        conn.request(method, path_q, body=body, headers=fwd)
        resp = conn.getresponse()
        data = resp.read()
        pairs = resp.getheaders()
        status, reason = resp.status, resp.reason
        conn.close()
        return status, reason, pairs, data

    # -- plain HTTP and decrypted HTTPS
    def _handle_http(self):
        body = self._read_body()
        mitm = getattr(self, "_mitm_target", None)
        parsed = urlsplit(self.path)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == "https" else 80)
            path_q = parsed.path or "/"
            if parsed.query:
                path_q += "?" + parsed.query
            query = parsed.query
            path = parsed.path or "/"
        elif mitm:
            scheme, host, port = mitm
            path_q = self.path
            path = parsed.path or "/"
            query = parsed.query
        else:
            host_header = self.headers.get("Host", "127.0.0.1")
            host = host_header.split(":")[0]
            port = int(host_header.split(":")[1]) if ":" in host_header \
                else 80
            scheme, path_q = "http", self.path
            path, query = parsed.path or "/", parsed.query
        record = self.cfg.recorder.add(make_record(
            self.command, scheme, host, port, path, query,
            list(self.headers.items()), body))
        try:
            status, reason, pairs, data = self._upstream(
                scheme, host, port, self.command, path_q,
                self.headers, body)
            record["status"] = status
            record["response_size"] = len(data)
            self._relay_response(status, reason, pairs, data)
        except Exception as exc:  # upstream unreachable etc.
            record["error"] = f"{type(exc).__name__}: {exc}"[:200]
            payload = b"traffic audit proxy: upstream error\n"
            self._relay_response(502, "Bad Gateway",
                                 [("Content-Type", "text/plain")], payload)

    do_GET = _handle_http
    do_POST = _handle_http
    do_PUT = _handle_http
    do_PATCH = _handle_http
    do_DELETE = _handle_http
    do_HEAD = _handle_http
    do_OPTIONS = _handle_http

    # -- CONNECT: MITM when possible, blind tunnel otherwise
    def do_CONNECT(self):
        hostport = self.path
        host, _, port_s = hostport.rpartition(":")
        host = host or hostport
        port = int(port_s) if port_s.isdigit() else 443
        if self.cfg.mitm and self.cfg.ca is not None:
            try:
                self._mitm_connect(host, port)
                return
            except Exception:
                pass  # fall through to a blind tunnel
        self._blind_tunnel(host, port)

    def _connect_upstream(self, host, port):
        mapped = self.cfg.host_map.get(host.lower())
        target = mapped if mapped else (host, port)
        return socket.create_connection(target, timeout=15)

    def _mitm_connect(self, host, port):
        ctx = self.cfg.ca.server_context(host)
        self.send_response_only(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        tls_conn = ctx.wrap_socket(self.connection, server_side=True)
        tls_conn.settimeout(30)
        self.connection = tls_conn
        self.rfile = tls_conn.makefile("rb")
        self.wfile = tls_conn.makefile("wb")
        self._mitm_target = ("https", host, port)
        self.close_connection = False
        while not self.close_connection:
            self.handle_one_request()
        try:
            tls_conn.close()
        except OSError:
            pass

    def _blind_tunnel(self, host, port):
        record = self.cfg.recorder.add({
            "time": datetime.now().isoformat(timespec="seconds"),
            "method": "CONNECT", "scheme": "https", "host": host,
            "port": port, "path": "", "query": "", "headers": {},
            "field_names": [], "body": b"", "status": None,
            "response_size": 0, "tunnel": True, "uninspected": True,
            "error": None, "bytes_in": 0, "bytes_out": 0,
        })
        try:
            upstream = self._connect_upstream(host, port)
        except OSError as exc:
            record["error"] = f"connect failed: {exc}"[:200]
            self.send_response_only(502, "Bad Gateway")
            self.end_headers()
            self.close_connection = True
            return
        self.send_response_only(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    break
                for src in readable:
                    data = src.recv(65536)
                    if not data:
                        return
                    dst = upstream if src is self.connection \
                        else self.connection
                    dst.sendall(data)
                    if src is self.connection:
                        record["bytes_in"] += len(data)
                    else:
                        record["bytes_out"] += len(data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass
            self.close_connection = True


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, recorder, ca=None, mitm=True,
                 host_map=None):
        super().__init__(address, ProxyHandler)
        self.recorder = recorder
        self.ca = ca
        self.mitm = mitm
        self.host_map = {k.lower(): v for k, v in (host_map or {}).items()}


# --- redacted writers ---------------------------------------------------

def capture_entry(record, canaries):
    headers = {}
    for k, v in record["headers"].items():
        if k in ("authorization", "cookie", "set-cookie"):
            headers[k] = "<redacted>"
        else:
            headers[k] = redact_text(v, canaries)
    return {
        "time": record["time"],
        "method": record["method"],
        "scheme": record["scheme"],
        "host": record["host"],
        "port": record["port"],
        "path": redact_text(record["path"], canaries),
        "query": redact_text(record["query"], canaries),
        "status": record["status"],
        "request_size": len(record["body"]),
        "response_size": record["response_size"],
        "body_sha256": sha256_hex(record["body"]),
        "field_names": record["field_names"],
        "headers": headers,
        "tunnel": record["tunnel"],
        "uninspected": record["uninspected"],
        "error": record["error"],
    }


def write_outputs(out_dir, records, canaries, findings, observations,
                  report_meta):
    os.makedirs(out_dir, exist_ok=True)
    capture = [capture_entry(r, canaries) for r in records]
    capture_path = os.path.join(out_dir, "capture.json")
    with open(capture_path, "w", encoding="utf-8") as fh:
        json.dump(capture, fh, ensure_ascii=False, indent=2)
    uninspected = sum(1 for r in records if r.get("uninspected"))
    errors = sum(1 for r in records if r.get("error"))
    if report_meta.get("timed_out"):
        tool_status = "timeout"
        overall = "partial"
    elif not records and report_meta.get("child_exit") not in (0, None):
        tool_status = "error"
        overall = "failed"
    else:
        tool_status = "findings" if findings else "passed"
        overall = "partial" if (uninspected or errors) else "complete"
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target": report_meta.get("target", ""),
        "profile": "traffic",
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "container_exit_code": report_meta.get("child_exit"),
        "timed_out": bool(report_meta.get("timed_out")),
        "status": overall,
        "tools": {
            TOOL_NAME: {
                "status": tool_status,
                "exit_code": report_meta.get("child_exit"),
                "findings": findings,
            }
        },
        "observations": observations,
        "coverage": {
            "requests": sum(1 for r in records if not r.get("tunnel")),
            "tunnels_total": sum(1 for r in records if r.get("tunnel")),
            "tunnels_uninspected": uninspected,
            "upstream_errors": errors,
        },
        "summary": {
            "total_findings": len(findings),
            "tools_ok": 1 if tool_status in ("passed", "findings") else 0,
            "tools_failed": 0 if tool_status in ("passed", "findings")
                            else 1,
        },
        "provenance": {
            "tool": TOOL_NAME,
            "tool_version": TRAFFIC_VERSION,
            "openssl": openssl_version(),
            "started_at": report_meta.get("started_at"),
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "settings": report_meta.get("settings", {}),
            "raw_outputs": {
                "capture.json": {
                    "sha256": sha256_hex(open(capture_path, "rb").read()),
                    "size": os.path.getsize(capture_path),
                }
            },
        },
    }
    with open(os.path.join(out_dir, "report.json"), "w",
              encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


# --- runner ---------------------------------------------------------------

def parse_host_map(items):
    host_map = {}
    for item in items or []:
        name, _, target = item.partition("=")
        ip, _, port_s = target.rpartition(":")
        host_map[name.strip().lower()] = (ip.strip(), int(port_s))
    return host_map


def run_target(command, out_dir, allowlist=None, source_dir=None,
               mitm=True, host_map=None, timeout=300, port=0):
    """Run `command` with its traffic routed through the audit proxy."""
    os.makedirs(out_dir, exist_ok=True)
    started_at = datetime.now().isoformat(timespec="seconds")
    canaries = generate_canaries()
    canary_path = os.path.join(out_dir, "canaries.json")
    with open(canary_path, "w", encoding="utf-8") as fh:
        json.dump(canaries, fh, ensure_ascii=False, indent=2)
    os.chmod(canary_path, 0o600)

    ca = CAManager(os.path.join(out_dir, "ca")) if mitm else None
    if ca is not None:
        ca.ensure()
    recorder = Recorder()
    server = ProxyServer(("127.0.0.1", port), recorder, ca=ca, mitm=mitm,
                         host_map=host_map)
    proxy_url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    env = dict(os.environ)
    env.update({
        "http_proxy": proxy_url, "https_proxy": proxy_url,
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url,
        "no_proxy": "", "NO_PROXY": "",
        "SECUTE_AUDIT": "traffic",
    })
    if ca is not None:
        for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                    "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"):
            env[var] = ca.ca_crt
    for c in canaries:
        env[c["env"]] = c["value"]

    timed_out = False
    child_exit = None
    try:
        proc = subprocess.run(command, env=env, timeout=timeout,
                              capture_output=True, text=True)
        child_exit = proc.returncode
        with open(os.path.join(out_dir, "target.log"), "w",
                  encoding="utf-8") as fh:
            fh.write(proc.stdout or "")
            fh.write(proc.stderr or "")
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        server.shutdown()
        server.server_close()

    findings, observations = analyze_records(
        recorder.records, canaries, allowlist, source_dir=source_dir)
    report = write_outputs(
        out_dir, recorder.records, canaries, findings, observations, {
            "target": " ".join(command),
            "child_exit": child_exit,
            "timed_out": timed_out,
            "started_at": started_at,
            "settings": {
                "allowlist": allowlist, "mitm": mitm,
                "host_map": sorted((host_map or {}).keys()),
                "timeout": timeout, "source_dir": source_dir,
            },
        })
    return report


# --- built-in demo ---------------------------------------------------------

_DEMO_CLIENT = r"""
import json, os, urllib.request

def post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except Exception as exc:
        print("client:", url, exc)

def get(url):
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            resp.read()
    except Exception as exc:
        print("client:", url, exc)

email = os.environ["SECUTE_CANARY_EMAIL"]
device = os.environ["SECUTE_CANARY_DEVICE_ID"]
chat = os.environ["SECUTE_CANARY_CHAT_MESSAGE"]
name = os.environ["SECUTE_CANARY_DISPLAY_NAME"]

post("http://api.example/v1/profile", {"email": email, "name": name})
get("http://api.example/config")
post("http://tracker.example/collect",
     {"email": email, "device_id": device, "chat_message": chat,
      "event": "app_start"})
print("demo client done")
"""


def _demo_upstream():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            received.append((self.command, self.path, body))
            payload = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _reply
        do_POST = _reply

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received


def run_demo(out_dir):
    """Self-contained check: a fake app talks to an allowed API and to
    an unlisted tracker; only the tracker traffic may be flagged."""
    api, _ = _demo_upstream()
    tracker, _ = _demo_upstream()
    host_map = {
        "api.example": ("127.0.0.1", api.server_address[1]),
        "tracker.example": ("127.0.0.1", tracker.server_address[1]),
    }
    try:
        return run_target(
            [sys.executable, "-c", _DEMO_CLIENT], out_dir,
            allowlist=["api.example"], mitm=True, host_map=host_map,
            timeout=120)
    finally:
        api.shutdown()
        tracker.shutdown()


# --- CLI ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SeCute traffic audit (original egress proxy)")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="audit a target command")
    run_p.add_argument("--out", default="results")
    run_p.add_argument("--allow", action="append", default=None,
                       help="allowed destination host (repeatable); "
                            "*.example.com also matches subdomains")
    run_p.add_argument("--source", default=None,
                       help="source tree used to map findings to code")
    run_p.add_argument("--no-mitm", action="store_true",
                       help="relay HTTPS as blind tunnels (recorded "
                            "as uninspected, never as clean)")
    run_p.add_argument("--map-host", action="append", default=None,
                       help="host=ip:port redirect for the TCP target "
                            "(local stand-ins for external services)")
    run_p.add_argument("--timeout", type=int, default=300)
    run_p.add_argument("target_cmd", nargs=argparse.REMAINDER,
                       help="target command, after --")

    demo_p = sub.add_parser("demo", help="run the built-in demo")
    demo_p.add_argument("--out", default="results")

    args = parser.parse_args()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if args.command == "demo":
        out_dir = os.path.abspath(os.path.join(args.out, stamp))
        report = run_demo(out_dir)
    else:
        command = list(args.target_cmd)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            raise SystemExit("no target command given (use -- <cmd>)")
        out_dir = os.path.abspath(os.path.join(args.out, stamp))
        report = run_target(
            command, out_dir, allowlist=args.allow,
            source_dir=args.source, mitm=not args.no_mitm,
            host_map=parse_host_map(args.map_host), timeout=args.timeout)

    print(f"report: {os.path.join(out_dir, 'report.json')}")
    print(f"status: {report['status']}")
    print(f"findings: {report['summary']['total_findings']}")
    for finding in report["tools"][TOOL_NAME]["findings"]:
        print(f"  {finding['type']}: {finding['method']} "
              f"{finding['scheme']}://{finding['host']}{finding['path']}"
              + (f" canary={finding['canary_id']}"
                 if "canary_id" in finding else ""))
    cov = report["coverage"]
    print(f"coverage: {cov['requests']} requests, "
          f"{cov['tunnels_uninspected']} uninspected tunnels")


if __name__ == "__main__":
    main()
