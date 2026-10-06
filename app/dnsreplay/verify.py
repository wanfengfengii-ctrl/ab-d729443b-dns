"""One-shot verification: code tests, build checks and an API smoke test.

Run as ``python -m dnsreplay.verify``. Exits 0 when every stage passes,
1 otherwise. The smoke stage talks to the API at ``API_URL`` (default
http://127.0.0.1:8080) and includes an RFC 1982 serial-wraparound replay.
"""

from __future__ import annotations

import compileall
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from dnsreplay import engine

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent.parent
TESTS_DIR = Path(os.environ.get("TESTS_DIR", REPO_DIR / "tests"))
API_URL = os.environ.get("API_URL", "http://127.0.0.1:8080").rstrip("/")
HEALTH_TIMEOUT = 60.0

_failures = []


def _stage(name):
    print(f"\n=== {name} ===", flush=True)


def _passed(msg):
    print(f"[PASS] {msg}", flush=True)


def _failed(msg):
    print(f"[FAIL] {msg}", flush=True)
    _failures.append(msg)


# ---------------------------------------------------------------------------
# Stage 1: build check
# ---------------------------------------------------------------------------

def build_check():
    _stage("build check: byte-compile all sources and import modules")
    ok = True
    for target in (PACKAGE_DIR, TESTS_DIR):
        if target.is_dir() and not compileall.compile_dir(
                str(target), quiet=1, force=True):
            _failed(f"byte-compilation failed under {target}")
            ok = False
    try:
        from dnsreplay import server  # noqa: F401
        from dnsreplay import engine as eng  # noqa: F401
    except Exception as exc:  # pragma: no cover - defensive
        _failed(f"module import failed: {exc}")
        ok = False
    if ok:
        _passed("all sources compile and import cleanly")
    return ok


# ---------------------------------------------------------------------------
# Stage 2: unit tests
# ---------------------------------------------------------------------------

def unit_tests():
    _stage("code tests: unittest suite")
    suite = unittest.TestLoader().discover(str(TESTS_DIR))
    result = unittest.TextTestRunner(verbosity=1, stream=sys.stdout).run(suite)
    if result.wasSuccessful():
        _passed(f"unit tests passed ({result.testsRun} tests)")
        return True
    _failed(f"unit tests failed ({len(result.failures)} failures, "
            f"{len(result.errors)} errors)")
    return False


# ---------------------------------------------------------------------------
# Stage 3: API smoke test
# ---------------------------------------------------------------------------

def _http(method, url, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _soa(serial, ttl=3600):
    return {
        "name": "Example.COM.", "type": "SOA", "ttl": ttl,
        "rdata": {"mname": "NS1.Example.com", "rname": "Hostmaster.Example.com",
                  "serial": serial, "refresh": 7200, "retry": 3600,
                  "expire": 1209600, "minimum": 300},
    }


def _wraparound_payload():
    """Serial path 4294967290 -> 4294967295 -> 4 -> 9 (wraps past 2**32)."""
    return {
        "zone": "Example.COM.",
        "initial": {
            "soa": _soa(4294967290),
            "records": [
                {"name": "WWW.Example.COM", "type": "A", "ttl": 300,
                 "rdata": "192.0.2.1"},
                {"name": "www.example.com", "type": "AAAA", "ttl": 300,
                 "rdata": "2001:DB8::1"},
                {"name": "mail.example.com", "type": "CNAME", "ttl": 600,
                 "rdata": "WWW.Example.COM."},
            ],
        },
        "transactions": [
            {"begin_soa": _soa(4294967290),
             "deletes": [],
             "adds": [{"name": "example.com", "type": "TXT", "ttl": 300,
                       "rdata": "v=spf1 -all"}],
             "end_soa": _soa(4294967295)},
            {"begin_soa": _soa(4294967295),
             "deletes": [{"name": "www.example.com", "type": "AAAA",
                          "ttl": 300, "rdata": "2001:db8::1"}],
             "adds": [{"name": "www.example.com", "type": "A", "ttl": 300,
                       "rdata": "192.0.2.2"},
                      {"name": "alias.example.com", "type": "CNAME",
                       "ttl": 600, "rdata": "www.example.com"}],
             "end_soa": _soa(4)},
            {"begin_soa": _soa(4), "deletes": [], "adds": [],
             "end_soa": _soa(9)},
        ],
    }


def _check(cond, msg):
    if cond:
        _passed(msg)
    else:
        _failed(msg)
    return cond


def smoke():
    _stage(f"API smoke test against {API_URL}")

    deadline = time.monotonic() + HEALTH_TIMEOUT
    healthy = False
    while time.monotonic() < deadline:
        try:
            status, body = _http("GET", API_URL + "/healthz")
            if status == 200 and body.get("status") == "ok":
                healthy = True
                break
        except Exception:
            pass
        time.sleep(1.0)
    if not _check(healthy, "GET /healthz reports ok"):
        return False

    ok = True

    # 1. Valid replay with serial wraparound; cross-check against the engine.
    payload = _wraparound_payload()
    status, body = _http("POST", API_URL + "/api/dns/ixfr/replay", payload)
    ok &= _check(status == 200 and body.get("ok") is True,
                 "wraparound replay accepted (HTTP 200)")
    if status == 200 and body.get("ok"):
        expected = engine.replay(payload)
        ok &= _check(body.get("final_serial") == 9,
                     f"final serial is 9 after wraparound "
                     f"(got {body.get('final_serial')})")
        ok &= _check(body.get("records") == expected["records"],
                     "API records match engine canonical ordering")
        ok &= _check(body.get("sha256") == expected["sha256"],
                     f"API sha256 matches engine ({body.get('sha256')})")
        names = [r["name"] for r in body.get("records", [])]
        ok &= _check(all(n == n.lower() and not n.endswith(".")
                         for n in names),
                     "record names are canonical (lowercase, no trailing dot)")

    # 2. Determinism: identical replay -> identical digest.
    status2, body2 = _http("POST", API_URL + "/api/dns/ixfr/replay", payload)
    ok &= _check(status2 == 200 and body2.get("sha256") == body.get("sha256"),
                 "replayed digest is stable across calls")

    # 3. Serial not advancing -> stable error code, no partial snapshot.
    bad_serial = {
        "zone": "example.com",
        "initial": {"soa": _soa(10), "records": []},
        "transactions": [{"begin_soa": _soa(10), "deletes": [], "adds": [],
                          "end_soa": _soa(5)}],
    }
    status, body = _http("POST", API_URL + "/api/dns/ixfr/replay", bad_serial)
    err = body.get("error", {})
    ok &= _check(status == 400 and body.get("ok") is False
                 and err.get("code") == "E_SERIAL_NOT_ADVANCING"
                 and err.get("transaction") == 0,
                 f"non-advancing serial rejected with E_SERIAL_NOT_ADVANCING "
                 f"at transaction 0 (got {err.get('code')})")
    ok &= _check("records" not in body and "sha256" not in body,
                 "error response exposes no partial snapshot")

    # 4. Delete of a missing record -> E_DELETE_NOT_FOUND at transaction 1.
    bad_delete = {
        "zone": "example.com",
        "initial": {"soa": _soa(1), "records": []},
        "transactions": [
            {"begin_soa": _soa(1), "deletes": [], "adds": [],
             "end_soa": _soa(2)},
            {"begin_soa": _soa(2),
             "deletes": [{"name": "ghost.example.com", "type": "A",
                          "ttl": 300, "rdata": "192.0.2.99"}],
             "adds": [], "end_soa": _soa(3)},
        ],
    }
    status, body = _http("POST", API_URL + "/api/dns/ixfr/replay", bad_delete)
    err = body.get("error", {})
    ok &= _check(status == 400
                 and err.get("code") == "E_DELETE_NOT_FOUND"
                 and err.get("transaction") == 1,
                 f"missing delete rejected with E_DELETE_NOT_FOUND at "
                 f"transaction 1 (got {err.get('code')})")

    # 5. CNAME conflict -> E_CNAME_CONFLICT.
    bad_cname = {
        "zone": "example.com",
        "initial": {"soa": _soa(1), "records": [
            {"name": "www.example.com", "type": "CNAME", "ttl": 300,
             "rdata": "target.example.com"}]},
        "transactions": [
            {"begin_soa": _soa(1), "deletes": [],
             "adds": [{"name": "www.example.com", "type": "A", "ttl": 300,
                       "rdata": "192.0.2.1"}],
             "end_soa": _soa(2)},
        ],
    }
    status, body = _http("POST", API_URL + "/api/dns/ixfr/replay", bad_cname)
    err = body.get("error", {})
    ok &= _check(status == 400 and err.get("code") == "E_CNAME_CONFLICT",
                 f"CNAME conflict rejected with E_CNAME_CONFLICT "
                 f"(got {err.get('code')})")

    # 6. Malformed JSON -> E_SCHEMA.
    req = urllib.request.Request(API_URL + "/api/dns/ixfr/replay",
                                 data=b"{not json", method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        status = 200
        body = {}
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = json.loads(exc.read().decode("utf-8"))
    ok &= _check(status == 400
                 and body.get("error", {}).get("code") == "E_SCHEMA",
                 "malformed JSON rejected with E_SCHEMA")

    return ok


# ---------------------------------------------------------------------------

def main():
    print(f"dnsreplay verify: API_URL={API_URL} TESTS_DIR={TESTS_DIR}",
          flush=True)
    results = [
        ("build check", build_check()),
        ("unit tests", unit_tests()),
        ("API smoke", smoke()),
    ]
    print("\n=== summary ===", flush=True)
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}", flush=True)
    if _failures:
        print(f"\n{len(_failures)} check(s) failed:", flush=True)
        for msg in _failures:
            print(f"  - {msg}", flush=True)
        return 1
    print("\nall verification stages passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
