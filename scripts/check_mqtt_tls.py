"""Check that the pinned Dreame MQTT CA verifies the live broker - and that verification is real.

Run with the same paho-mqtt that Home Assistant uses, e.g. inside the HA container:

    python3 check_mqtt_tls.py dreame_iot_mqtt_ca.pem [host] [port]

Only a TLS handshake is made (no MQTT CONNECT, no credentials). Exit 0 only if:
  1. pinned CA + real hostname     -> handshake succeeds
  2. system CA store + real host   -> rejected (the broker's CA is private)
  3. pinned CA + wrong hostname    -> rejected (hostname checking is on)
"""

import socket
import ssl
import sys

import paho.mqtt.client as mqtt


def handshake(host: str, port: int, server_hostname: str, ca_file: str | None) -> str:
    # Build the context exactly the way paho's tls_set() does for the integration.
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    client.tls_set(ca_certs=ca_file, cert_reqs=ssl.CERT_REQUIRED)
    client.tls_insecure_set(False)
    ctx = client._ssl_context
    with socket.create_connection((host, port), timeout=10) as raw:
        try:
            with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
                return "ok " + tls.version()
        except ssl.SSLError as ex:
            return f"rejected {ex.reason or ex}"


def main() -> int:
    ca = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "10000.mt.eu.iot.dreame.tech"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 19973
    cases = [
        ("pinned CA, real hostname", host, ca, True),
        ("system CA store, real hostname", host, None, False),
        ("pinned CA, wrong hostname", "evil.example.com", ca, False),
    ]
    failed = 0
    for name, sni, ca_file, expect_ok in cases:
        result = handshake(host, port, sni, ca_file)
        good = result.startswith("ok") == expect_ok
        failed += not good
        print(f"{'PASS' if good else 'FAIL'}  {name}: {result}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
