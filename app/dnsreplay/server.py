"""HTTP API for the IXFR replay engine (standard library only).

Endpoints:
  GET  /healthz               liveness/readiness probe
  POST /api/dns/ixfr/replay   replay an IXFR log, return final zone image
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnsreplay import __version__
from dnsreplay.engine import ReplayError, replay

REPLAY_PATH = "/api/dns/ixfr/replay"
HEALTH_PATH = "/healthz"
MAX_BODY_BYTES = 16 * 1024 * 1024

DEFAULT_PORT = 8080


class ReplayHandler(BaseHTTPRequestHandler):
    server_version = f"dns-ixfr-replay/{__version__}"
    protocol_version = "HTTP/1.1"

    # -- helpers -----------------------------------------------------------

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code, rule, message):
        self._send_json(status, {
            "ok": False,
            "error": {"code": code, "rule": rule, "message": message,
                      "transaction": None, "detail": {}},
        })

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == HEALTH_PATH:
            self._send_json(200, {"status": "ok", "version": __version__})
        elif path == REPLAY_PATH:
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._error(404, "E_NOT_FOUND", "ROUTE", "unknown path")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != REPLAY_PATH:
            self._error(404, "E_NOT_FOUND", "ROUTE", "unknown path")
            return

        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header else 0
        except ValueError:
            self._error(400, "E_SCHEMA", "SCHEMA",
                        "invalid Content-Length header")
            return
        if length <= 0:
            self._error(400, "E_SCHEMA", "SCHEMA", "request body is empty")
            return
        if length > MAX_BODY_BYTES:
            self._error(413, "E_SCHEMA", "SCHEMA",
                        f"request body exceeds {MAX_BODY_BYTES} bytes")
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._error(400, "E_SCHEMA", "SCHEMA",
                        f"request body is not valid JSON: {exc}")
            return

        try:
            result = replay(payload)
        except ReplayError as err:
            self._send_json(400, {"ok": False, "error": err.to_dict()})
            return
        except Exception:  # pragma: no cover - defensive
            self.log_exception("unhandled error during replay")
            self._error(500, "E_INTERNAL", "INTERNAL",
                        "unexpected internal error")
            return

        response = {"ok": True}
        response.update(result)
        self._send_json(200, response)

    # -- logging -----------------------------------------------------------

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def log_exception(self, message):
        sys.stderr.write("ERROR: %s\n" % message)


def main():
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    server = ThreadingHTTPServer(("0.0.0.0", port), ReplayHandler)
    sys.stderr.write(
        f"dns-ixfr-replay {__version__} listening on 0.0.0.0:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
