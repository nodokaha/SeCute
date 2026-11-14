"""Tests for the traffic audit tool (harness/traffic_audit.py).

Covers the detector, the source mapper, the redaction invariant
(canary values must never reach report.json / capture.json), a blind
CONNECT tunnel, HTTPS MITM end to end, and the built-in demo.
"""
import http.client
import json
import os
import socket
import ssl
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import pytest

import traffic_audit as ta


# --- canaries and detector ---------------------------------------------

def test_canaries_are_unique_and_recognisable():
    canaries = ta.generate_canaries()
    values = [c["value"] for c in canaries]
    assert len(values) == len(set(values))
    # Every value carries the canary marker except the phone number,
    # which stays numeric so format-validating apps accept it; it is
    # still tracked by its exact value and hash.
    marked = [v for v in values if "canary" in v.lower()]
    assert len(marked) == len(values) - 1
    assert all(c["sha256"] != c["value"] for c in canaries)


def _record(url, body=b"", headers=()):
    from urllib.parse import urlsplit
    p = urlsplit(url)
    return ta.make_record(
        "POST", p.scheme, p.hostname, p.port or 80, p.path, p.query,
        list(headers) + [("Content-Type", "application/json")], body)


def test_canary_to_unlisted_destination_is_a_redacted_finding():
    canaries = ta.generate_canaries()
    email = next(c["value"] for c in canaries if c["id"] == "email")
    rec = _record("http://tracker.example/collect",
                  json.dumps({"email": email}).encode())
    findings, _ = ta.inspect_record(rec, canaries, ["api.example"])
    types = {f["type"] for f in findings}
    assert "canary_egress" in types
    assert "unknown_destination" in types
    assert "plaintext_egress" in types
    # The report material must never carry the canary value itself.
    assert email not in json.dumps(findings)


def test_canary_to_allowed_destination_is_not_a_finding():
    canaries = ta.generate_canaries()
    email = next(c["value"] for c in canaries if c["id"] == "email")
    rec = _record("https://api.example/v1/profile",
                  json.dumps({"email": email}).encode())
    findings, observations = ta.inspect_record(rec, canaries,
                                               ["api.example"])
    assert findings == []
    assert any(o["type"] == "canary_to_allowed"
               for o in observations)


def test_sensitive_fields_and_credential_headers():
    rec = _record(
        "https://analytics.example/events",
        json.dumps({"user_id": 1, "password": "x",
                    "event": "start"}).encode(),
        headers=[("Authorization", "Bearer abc")])
    findings, _ = ta.inspect_record(rec, ta.generate_canaries(),
                                    ["api.example"])
    types = {f["type"] for f in findings}
    assert "sensitive_field_egress" in types
    assert "credential_header_egress" in types
    blob = json.dumps(findings)
    assert "Bearer abc" not in blob and '"x"' not in blob


def test_source_mapping(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "import requests\n"
        "requests.post('https://tracker.example/collect',\n"
        "              json={'device_id': device})\n",
        encoding="utf-8")
    matches = ta.map_to_source(str(tmp_path),
                               ["tracker.example", "/collect",
                                "device_id"])
    assert matches and matches[0]["file"] == "app.py"
    assert all("line" in m for m in matches)


# --- proxy behaviour ------------------------------------------------------

def test_blind_connect_tunnel_is_recorded_as_uninspected():
    # A trivial TCP echo server as the tunnel target.
    echo = socket.socket()
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    echo_port = echo.getsockname()[1]

    def serve_echo():
        conn, _ = echo.accept()
        data = conn.recv(4096)
        conn.sendall(data)
        conn.close()
        echo.close()

    threading.Thread(target=serve_echo, daemon=True).start()

    recorder = ta.Recorder()
    proxy = ta.ProxyServer(("127.0.0.1", 0), recorder, ca=None,
                           mitm=False)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        sock = socket.create_connection(proxy.server_address, timeout=10)
        sock.sendall(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                     f"Host: 127.0.0.1:{echo_port}\r\n\r\n".encode())
        response = sock.recv(4096)
        assert b"200" in response
        sock.sendall(b"ping-through-tunnel")
        assert sock.recv(4096) == b"ping-through-tunnel"
        sock.close()
    finally:
        proxy.shutdown()
    tunnels = [r for r in recorder.records if r.get("tunnel")]
    assert tunnels and tunnels[0]["uninspected"] is True


def _recording_https_upstream(ca, host):
    crt, key = ca.leaf_for(host)
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            received.append(self.rfile.read(length))
            payload = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, received


@pytest.mark.skipif(ta.openssl_version() is None,
                    reason="openssl CLI not available")
def test_mitm_https_is_decrypted_and_detected(tmp_path):
    ca = ta.CAManager(str(tmp_path / "ca"))
    ca.ensure()
    upstream, received = _recording_https_upstream(ca, "api.example")
    recorder = ta.Recorder()
    proxy = ta.ProxyServer(
        ("127.0.0.1", 0), recorder, ca=ca, mitm=True,
        host_map={"api.example": ("127.0.0.1", upstream.server_address[1])})
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    canaries = ta.generate_canaries()
    device = next(c["value"] for c in canaries if c["id"] == "device_id")
    body = json.dumps({"device_id": device}).encode()
    try:
        ctx = ssl.create_default_context(cafile=ca.ca_crt)
        conn = http.client.HTTPSConnection(
            "127.0.0.1", proxy.server_address[1], context=ctx, timeout=15)
        conn.set_tunnel("api.example", upstream.server_address[1])
        conn.request("POST", "/v1/sync", body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()
    finally:
        proxy.shutdown()
        upstream.shutdown()

    assert received and device.encode() in received[0]
    https_records = [r for r in recorder.records if r["scheme"] == "https"]
    assert https_records and https_records[0]["path"] == "/v1/sync"
    findings, _ = ta.inspect_record(https_records[0], canaries,
                                    ["other.example"])
    assert any(f["type"] == "canary_egress" for f in findings)


# --- full demo --------------------------------------------------------------

def test_demo_flags_only_the_tracker(tmp_path):
    out_dir = str(tmp_path / "out")
    report = ta.run_demo(out_dir)
    findings = report["tools"][ta.TOOL_NAME]["findings"]
    leak_hosts = {f["host"] for f in findings
                  if f["type"] == "canary_egress"}
    assert leak_hosts == {"tracker.example"}
    assert report["coverage"]["requests"] == 3

    # Redaction invariant across everything the run writes to disk
    # (except canaries.json, which is the operator's planting sheet).
    with open(os.path.join(out_dir, "canaries.json"),
              encoding="utf-8") as fh:
        canaries = json.load(fh)
    for name in ("report.json", "capture.json"):
        with open(os.path.join(out_dir, name), encoding="utf-8") as fh:
            text = fh.read()
        for c in canaries:
            assert c["value"] not in text, f"{c['id']} leaked into {name}"
