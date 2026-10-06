"""IXFR replay engine.

Validates an ordered list of IXFR-style transactions against an initial zone
snapshot and produces the final canonical zone image plus a SHA-256 digest.

Guarantees:
  * RFC 1982 32-bit serial arithmetic: every transaction's new SOA serial must
    be strictly ahead of the current serial and unique across the replay.
  * Every transaction begins with the exact current SOA and ends with a unique
    new SOA; the zone apex always holds exactly one SOA.
  * Deletes must hit existing records; adds must not duplicate existing ones.
  * Names are canonicalized per DNS case-insensitive rules (lowercase, no
    trailing dot); every RRset shares one TTL; CNAME never coexists with other
    data at the same owner name.
  * Any error aborts the whole replay: the failing transaction and everything
    after it produce no result, and no partial snapshot is ever exposed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

SERIAL_MOD = 1 << 32
SERIAL_HALF = 1 << 31
MAX_UINT32 = SERIAL_MOD - 1
MAX_TTL = (1 << 31) - 1  # RFC 2181: TTL is a 31-bit unsigned value

MIN_TRANSACTIONS = 1
MAX_TRANSACTIONS = 64
MAX_RECORDS = 5000
MAX_TXT_LEN = 65535
MAX_NAME_LEN = 253

SUPPORTED_TYPES = ("A", "AAAA", "CNAME", "TXT", "SOA")
# Numeric type codes, used for the canonical (RFC 4034 style) record ordering.
TYPE_CODES = {"A": 1, "CNAME": 5, "SOA": 6, "TXT": 16, "AAAA": 28}

_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")


class ReplayError(Exception):
    """A stable, machine-readable replay failure.

    ``code`` and ``rule`` are stable identifiers safe for clients to match on.
    ``transaction`` is the 0-based transaction index that failed, or None for
    envelope/initial-state failures.
    """

    def __init__(self, code, rule, message, transaction=None, detail=None):
        super().__init__(message)
        self.code = code
        self.rule = rule
        self.message = message
        self.transaction = transaction
        self.detail = detail or {}

    def to_dict(self):
        return {
            "code": self.code,
            "rule": self.rule,
            "message": self.message,
            "transaction": self.transaction,
            "detail": self.detail,
        }


def _fail(code, rule, message, transaction=None, detail=None):
    raise ReplayError(code, rule, message, transaction, detail)


# ---------------------------------------------------------------------------
# Canonicalization helpers
# ---------------------------------------------------------------------------

def canonical_name(value, field="name", transaction=None):
    """Normalize a DNS name: strip one trailing dot, lowercase every label."""
    if not isinstance(value, str):
        _fail("E_NAME_INVALID", "NAME_CANONICAL",
              f"{field} must be a string", transaction, {"value": value})
    name = value.strip()
    if name.endswith("."):
        name = name[:-1]
    if not name:
        _fail("E_NAME_INVALID", "NAME_CANONICAL",
              f"{field} must not be empty", transaction, {"value": value})
    if len(name) > MAX_NAME_LEN:
        _fail("E_NAME_INVALID", "NAME_CANONICAL",
              f"{field} exceeds {MAX_NAME_LEN} octets", transaction,
              {"value": value})
    labels = name.split(".")
    for label in labels:
        if not _LABEL_RE.match(label):
            _fail("E_NAME_INVALID", "NAME_CANONICAL",
                  f"{field} contains invalid label {label!r}", transaction,
                  {"value": value})
    return ".".join(label.lower() for label in labels)


def name_sort_key(name):
    """RFC 4034 canonical DNS name order: compare labels right to left."""
    labels = name.split(".")
    labels.reverse()
    return tuple(labels)


def serial_strictly_ahead(new, old):
    """RFC 1982: ``new`` is strictly greater than ``old`` in serial arithmetic."""
    return new != old and ((new - old) % SERIAL_MOD) < SERIAL_HALF


def _uint(value, field, maximum, code, rule, transaction=None):
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(code, rule, f"{field} must be an integer", transaction,
              {"value": value})
    if value < 0 or value > maximum:
        _fail(code, rule, f"{field} must be in [0, {maximum}]", transaction,
              {"value": value})
    return value


# ---------------------------------------------------------------------------
# Record parsing / canonicalization
# ---------------------------------------------------------------------------

def _canonical_soa_rdata(rdata, field, transaction):
    if not isinstance(rdata, dict):
        _fail("E_RDATA_INVALID", "RDATA_SYNTAX",
              f"{field}.rdata must be an object", transaction)
    missing = [k for k in ("mname", "rname", "serial", "refresh", "retry",
                           "expire", "minimum") if k not in rdata]
    if missing:
        _fail("E_SCHEMA", "SCHEMA",
              f"{field}.rdata missing keys: {', '.join(missing)}", transaction)
    canon = {
        "mname": canonical_name(rdata["mname"], f"{field}.rdata.mname",
                                transaction),
        "rname": canonical_name(rdata["rname"], f"{field}.rdata.rname",
                                transaction),
    }
    for key in ("serial", "refresh", "retry", "expire", "minimum"):
        canon[key] = _uint(rdata[key], f"{field}.rdata.{key}", MAX_UINT32,
                           "E_RDATA_INVALID", "RDATA_SYNTAX", transaction)
    return canon


def _canonical_rdata(rtype, rdata, field, transaction):
    if rtype == "SOA":
        return _canonical_soa_rdata(rdata, field, transaction)
    if not isinstance(rdata, str):
        _fail("E_RDATA_INVALID", "RDATA_SYNTAX",
              f"{field}.rdata must be a string", transaction,
              {"value": rdata})
    if rtype == "A":
        try:
            return str(ipaddress.IPv4Address(rdata))
        except ipaddress.AddressValueError:
            _fail("E_RDATA_INVALID", "RDATA_SYNTAX",
                  f"{field}.rdata is not a valid IPv4 address", transaction,
                  {"value": rdata})
    if rtype == "AAAA":
        try:
            return ipaddress.IPv6Address(rdata).compressed
        except ipaddress.AddressValueError:
            _fail("E_RDATA_INVALID", "RDATA_SYNTAX",
                  f"{field}.rdata is not a valid IPv6 address", transaction,
                  {"value": rdata})
    if rtype == "CNAME":
        return canonical_name(rdata, f"{field}.rdata", transaction)
    # TXT: opaque character-string, case preserved.
    if len(rdata) > MAX_TXT_LEN:
        _fail("E_RDATA_INVALID", "RDATA_SYNTAX",
              f"{field}.rdata exceeds {MAX_TXT_LEN} characters", transaction)
    return rdata


def parse_record(obj, field, transaction=None):
    """Validate and canonicalize one record object.

    Returns ``(name, rtype, ttl, rdata)`` with the name lowercased, the type
    uppercased and the rdata in canonical form (a dict for SOA, a string
    otherwise).
    """
    if not isinstance(obj, dict):
        _fail("E_SCHEMA", "SCHEMA", f"{field} must be an object", transaction)
    for key in ("name", "type", "ttl", "rdata"):
        if key not in obj:
            _fail("E_SCHEMA", "SCHEMA", f"{field} missing key {key!r}",
                  transaction)
    rtype = obj["type"]
    if not isinstance(rtype, str):
        _fail("E_TYPE_UNSUPPORTED", "TYPE_SUPPORT",
              f"{field}.type must be a string", transaction,
              {"value": rtype})
    rtype = rtype.upper()
    if rtype not in TYPE_CODES:
        _fail("E_TYPE_UNSUPPORTED", "TYPE_SUPPORT",
              f"{field}.type {rtype!r} is not supported", transaction,
              {"value": obj["type"], "supported": list(SUPPORTED_TYPES)})
    name = canonical_name(obj["name"], f"{field}.name", transaction)
    ttl = _uint(obj["ttl"], f"{field}.ttl", MAX_TTL,
                "E_TTL_INVALID", "TTL_RANGE", transaction)
    rdata = _canonical_rdata(rtype, obj["rdata"], field, transaction)
    return name, rtype, ttl, rdata


def parse_soa(obj, field, transaction=None):
    """Parse a record that must be an SOA; returns ``(name, ttl, rdata)``."""
    name, rtype, ttl, rdata = parse_record(obj, field, transaction)
    if rtype != "SOA":
        _fail("E_SOA_CARDINALITY", "SOA_CARDINALITY",
              f"{field} must be an SOA record, got {rtype}", transaction)
    return name, ttl, rdata


def soa_text(rdata):
    return "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}".format(
        **rdata)


def rdata_text(rtype, rdata):
    """Canonical text form of rdata used for sorting and the digest."""
    if rtype == "SOA":
        return soa_text(rdata)
    if rtype == "TXT":
        # JSON quoting keeps embedded whitespace/quotes unambiguous.
        return json.dumps(rdata, ensure_ascii=False)
    return rdata


# ---------------------------------------------------------------------------
# Zone state
# ---------------------------------------------------------------------------

class _Zone:
    """Mutable zone image. SOA is kept separately (apex singleton)."""

    def __init__(self, apex):
        self.apex = apex
        self.rrsets = {}  # (name, rtype) -> {"ttl": int, "rdatas": set[str]}
        self.soa = None   # (ttl, rdata_dict)

    def types_at(self, name):
        types = {t for (n, t) in self.rrsets if n == name}
        if self.soa is not None and name == self.apex:
            types.add("SOA")
        return types

    def require_in_zone(self, name, transaction):
        if name != self.apex and not name.endswith("." + self.apex):
            _fail("E_NAME_OUT_OF_ZONE", "ZONE_ALIGNMENT",
                  f"record name {name!r} is outside zone {self.apex!r}",
                  transaction, {"name": name, "zone": self.apex})

    def add(self, name, rtype, ttl, rdata, transaction):
        if rtype == "SOA":
            _fail("E_SOA_CARDINALITY", "SOA_CARDINALITY",
                  "SOA records may not appear in add sets; the apex SOA is "
                  "carried by the transaction framing", transaction,
                  {"name": name})
        self.require_in_zone(name, transaction)
        key = (name, rtype)
        rrset = self.rrsets.get(key)
        if rrset is None:
            present = self.types_at(name)
            if rtype == "CNAME":
                if present:
                    _fail("E_CNAME_CONFLICT", "CNAME_EXCLUSIVE",
                          f"CNAME at {name!r} would coexist with "
                          f"{sorted(present)}", transaction,
                          {"name": name, "coexisting": sorted(present)})
            elif "CNAME" in present:
                _fail("E_CNAME_CONFLICT", "CNAME_EXCLUSIVE",
                      f"{rtype} at {name!r} would coexist with a CNAME",
                      transaction, {"name": name, "type": rtype})
            self.rrsets[key] = {"ttl": ttl, "rdatas": {rdata}}
            return
        if rrset["ttl"] != ttl:
            _fail("E_RRSET_TTL_MISMATCH", "RRSET_TTL",
                  f"RRset {name!r}/{rtype} has TTL {rrset['ttl']}, cannot add "
                  f"rdata with TTL {ttl}", transaction,
                  {"name": name, "type": rtype,
                   "existing_ttl": rrset["ttl"], "new_ttl": ttl})
        if rdata in rrset["rdatas"]:
            _fail("E_ADD_DUPLICATE", "ADD_UNIQUE",
                  f"record {name!r} {rtype} {rdata_text(rtype, rdata)} "
                  f"already exists", transaction,
                  {"name": name, "type": rtype, "rdata": rdata})
        if rtype == "CNAME":
            _fail("E_CNAME_CONFLICT", "CNAME_EXCLUSIVE",
                  f"CNAME RRset at {name!r} is a singleton", transaction,
                  {"name": name})
        rrset["rdatas"].add(rdata)

    def delete(self, name, rtype, ttl, rdata, transaction):
        if rtype == "SOA":
            _fail("E_SOA_CARDINALITY", "SOA_CARDINALITY",
                  "SOA records may not appear in delete sets; the apex SOA is "
                  "carried by the transaction framing", transaction,
                  {"name": name})
        self.require_in_zone(name, transaction)
        key = (name, rtype)
        rrset = self.rrsets.get(key)
        if rrset is None or rdata not in rrset["rdatas"]:
            _fail("E_DELETE_NOT_FOUND", "DELETE_EXISTING",
                  f"no such record: {name!r} {rtype} "
                  f"{rdata_text(rtype, rdata)}", transaction,
                  {"name": name, "type": rtype, "rdata": rdata})
        if rrset["ttl"] != ttl:
            _fail("E_RRSET_TTL_MISMATCH", "RRSET_TTL",
                  f"RRset {name!r}/{rtype} has TTL {rrset['ttl']}, delete "
                  f"names TTL {ttl}", transaction,
                  {"name": name, "type": rtype,
                   "existing_ttl": rrset["ttl"], "delete_ttl": ttl})
        rrset["rdatas"].discard(rdata)
        if not rrset["rdatas"]:
            del self.rrsets[key]


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------

def _require_dict(value, field, transaction=None):
    if not isinstance(value, dict):
        _fail("E_SCHEMA", "SCHEMA", f"{field} must be an object", transaction)
    return value


def _require_list(value, field, transaction=None):
    if not isinstance(value, list):
        _fail("E_SCHEMA", "SCHEMA", f"{field} must be an array", transaction)
    return value


def _require_key(obj, key, field, transaction=None):
    if key not in obj:
        _fail("E_SCHEMA", "SCHEMA", f"{field} missing key {key!r}",
              transaction)
    return obj[key]


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def replay(request):
    """Replay an IXFR log. Returns the final canonical zone image.

    Raises ReplayError on the first violated rule; nothing partial is
    returned in that case.
    """
    _require_dict(request, "request")
    zone_name = canonical_name(_require_key(request, "zone", "request"),
                               "zone")
    initial = _require_dict(_require_key(request, "initial", "request"),
                            "initial")
    transactions = _require_list(
        _require_key(request, "transactions", "request"), "transactions")

    if not (MIN_TRANSACTIONS <= len(transactions) <= MAX_TRANSACTIONS):
        _fail("E_TXN_COUNT", "TXN_COUNT",
              f"transactions must contain {MIN_TRANSACTIONS}.."
              f"{MAX_TRANSACTIONS} entries, got {len(transactions)}",
              detail={"count": len(transactions)})

    # Record budget: initial records plus every delete/add entry.
    init_records = _require_list(_require_key(initial, "records", "initial"),
                                 "initial.records")
    total = len(init_records)
    if total > MAX_RECORDS:
        _fail("E_RECORD_LIMIT", "RECORD_LIMIT",
              f"initial state carries {total} records, limit is {MAX_RECORDS}",
              detail={"count": total, "limit": MAX_RECORDS})
    for index, txn in enumerate(transactions):
        _require_dict(txn, f"transactions[{index}]", index)
        deletes = _require_list(
            _require_key(txn, "deletes", f"transactions[{index}]", index),
            f"transactions[{index}].deletes", index)
        adds = _require_list(
            _require_key(txn, "adds", f"transactions[{index}]", index),
            f"transactions[{index}].adds", index)
        total += len(deletes) + len(adds)
        if total > MAX_RECORDS:
            _fail("E_RECORD_LIMIT", "RECORD_LIMIT",
                  f"record budget {MAX_RECORDS} exceeded ({total} entries)",
                  index, {"count": total, "limit": MAX_RECORDS})

    zone = _Zone(zone_name)

    # Initial SOA: exactly one, at the apex.
    soa_name, soa_ttl, soa_rdata = parse_soa(
        _require_key(initial, "soa", "initial"), "initial.soa")
    if soa_name != zone_name:
        _fail("E_SOA_CARDINALITY", "SOA_CARDINALITY",
              f"SOA must sit at the zone apex {zone_name!r}, got "
              f"{soa_name!r}", detail={"name": soa_name, "zone": zone_name})
    zone.soa = (soa_ttl, soa_rdata)

    for pos, raw in enumerate(init_records):
        name, rtype, ttl, rdata = parse_record(raw, f"initial.records[{pos}]")
        zone.add(name, rtype, ttl, rdata, None)

    serials_seen = {soa_rdata["serial"]}
    current_serial = soa_rdata["serial"]

    for index, txn in enumerate(transactions):
        field = f"transactions[{index}]"
        # 1. The transaction must open with the exact current SOA.
        begin_name, begin_ttl, begin_rdata = parse_soa(
            _require_key(txn, "begin_soa", field, index),
            f"{field}.begin_soa", index)
        if begin_name != zone_name:
            _fail("E_SOA_CARDINALITY", "SOA_CARDINALITY",
                  f"begin_soa must sit at the zone apex {zone_name!r}",
                  index, {"name": begin_name})
        if (begin_ttl, begin_rdata) != zone.soa:
            _fail("E_SOA_BEGIN_MISMATCH", "SOA_BEGIN",
                  f"transaction {index} does not begin with the current SOA "
                  f"(current serial {zone.soa[1]['serial']})", index,
                  {"expected_serial": zone.soa[1]["serial"],
                   "got_serial": begin_rdata["serial"]})

        # 2. It must close with a unique, strictly advancing new SOA.
        end_name, end_ttl, end_rdata = parse_soa(
            _require_key(txn, "end_soa", field, index),
            f"{field}.end_soa", index)
        if end_name != zone_name:
            _fail("E_SOA_CARDINALITY", "SOA_CARDINALITY",
                  f"end_soa must sit at the zone apex {zone_name!r}",
                  index, {"name": end_name})
        new_serial = end_rdata["serial"]
        if new_serial in serials_seen:
            _fail("E_SOA_END_UNIQUE", "SOA_END_UNIQUE",
                  f"transaction {index} ends with serial {new_serial} which "
                  f"was already used in this replay", index,
                  {"serial": new_serial})
        if not serial_strictly_ahead(new_serial, current_serial):
            _fail("E_SERIAL_NOT_ADVANCING", "SERIAL_ADVANCE",
                  f"transaction {index} serial {new_serial} does not "
                  f"strictly advance past {current_serial} (RFC 1982)",
                  index, {"current_serial": current_serial,
                          "new_serial": new_serial})

        # 3. Apply deletes, then adds (classic IXFR ordering).
        for pos, raw in enumerate(txn["deletes"]):
            name, rtype, ttl, rdata = parse_record(
                raw, f"{field}.deletes[{pos}]", index)
            zone.delete(name, rtype, ttl, rdata, index)
        for pos, raw in enumerate(txn["adds"]):
            name, rtype, ttl, rdata = parse_record(
                raw, f"{field}.adds[{pos}]", index)
            zone.add(name, rtype, ttl, rdata, index)

        # 4. Commit: the new SOA becomes current.
        serials_seen.add(new_serial)
        current_serial = new_serial
        zone.soa = (end_ttl, end_rdata)

    return _render(zone, current_serial)


def _render(zone, final_serial):
    """Flatten the zone into a canonically sorted record list + digest."""
    records = []
    soa_ttl, soa_rdata = zone.soa
    records.append({"name": zone.apex, "type": "SOA", "ttl": soa_ttl,
                    "rdata": dict(soa_rdata)})
    for (name, rtype), rrset in zone.rrsets.items():
        for rdata in rrset["rdatas"]:
            records.append({"name": name, "type": rtype,
                            "ttl": rrset["ttl"], "rdata": rdata})

    def sort_key(rec):
        return (name_sort_key(rec["name"]), TYPE_CODES[rec["type"]],
                rdata_text(rec["type"], rec["rdata"]))

    records.sort(key=sort_key)

    lines = []
    for rec in records:
        lines.append("{name} {ttl} {type} {rdata}\n".format(
            name=rec["name"], ttl=rec["ttl"], type=rec["type"],
            rdata=rdata_text(rec["type"], rec["rdata"])))
    digest = hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()

    return {
        "zone": zone.apex,
        "final_serial": final_serial,
        "record_count": len(records),
        "records": records,
        "sha256": digest,
    }
