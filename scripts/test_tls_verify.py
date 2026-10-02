"""Prove the Dreame HTTPS client verifies server certificates (fails on upstream v2.0.x's DreameTLSSocket).

Run inside the HA container, where the integration's dependencies live:

    python3 test_tls_verify.py <dir containing custom_components/dreame_vacuum>

Exit 0 only if:
  1. the real API host answers through the real DreameVacuumDreameHomeCloudProtocol._http()
  2. the same host under a wrong server name is rejected
  3. a local HTTPS server with a self-signed certificate is rejected by _http()

Demonstrated against pre-fix code: pointing the directory at upstream v2.0.1 makes
check 3 fail ("self-signed server was accepted"), because its hand-rolled TLS client
never verifies the certificate.
"""

import base64
import datetime
import json
import ssl
import sys
import threading
import types
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

root = Path(sys.argv[1]) / "custom_components" / "dreame_vacuum"
for name, path in (("dvx", root), ("dvx.dreame", root / "dreame")):
    mod = types.ModuleType(name)
    mod.__path__ = [str(path)]
    sys.modules[name] = mod

from dvx.dreame import protocol as P  # noqa: E402

proto = P.DreameVacuumDreameHomeCloudProtocol("u", "p")
proto._strings = json.loads(zlib.decompress(base64.b64decode(P.DREAME_STRINGS), zlib.MAX_WBITS | 32))
HEADERS = {"user-agent": "tls-check"}
failures = []


def check(label, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + label + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(label)


# 1. real host through the real _http()
try:
    status, _ = proto._http("GET", "https://eu.iot.dreame.tech:13267/", HEADERS, None, 10)
    check("real API host answers via _http()", isinstance(status, int), f"HTTP {status}")
except Exception as ex:
    check("real API host answers via _http()", False, repr(ex))
proto._conns.clear()

# 2. real host, wrong server name
try:
    P.DreameVacuumDreameHomeCloudProtocol.DreameTLSSocket(
        "eu.iot.dreame.tech", 13267, "wrong.example.com", 10, proto._strings
    ).connect()
    check("wrong server name rejected", False, "connected")
except ssl.SSLError as ex:
    check("wrong server name rejected", True, type(ex).__name__)
except Exception as ex:
    check("wrong server name rejected", False, repr(ex))

# 3. self-signed local server
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=1))
    .not_valid_after(now + datetime.timedelta(hours=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    .sign(key, hashes.SHA256())
)
tmp = Path("/tmp/dv-selfsigned")
tmp.mkdir(exist_ok=True)
(tmp / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
(tmp / "k.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
)


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
try:
    status, _ = proto._http("GET", f"https://localhost:{port}/", HEADERS, None, 5)
    check("self-signed server rejected", False, f"self-signed server was accepted (HTTP {status})")
except (ssl.SSLError, ConnectionError, OSError) as ex:
    check("self-signed server rejected", True, type(ex).__name__)
srv.shutdown()

print("RESULT:", "FAIL" if failures else "PASS")
sys.exit(1 if failures else 0)
