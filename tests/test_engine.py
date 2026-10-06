"""Unit tests for the IXFR replay engine."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from dnsreplay.engine import (  # noqa: E402
    MAX_RECORDS,
    ReplayError,
    canonical_name,
    name_sort_key,
    replay,
    serial_strictly_ahead,
)


def soa(serial, ttl=3600, name="example.com"):
    return {
        "name": name, "type": "SOA", "ttl": ttl,
        "rdata": {"mname": "ns1.example.com", "rname": "hostmaster.example.com",
                  "serial": serial, "refresh": 7200, "retry": 3600,
                  "expire": 1209600, "minimum": 300},
    }


def rec(name, rtype, rdata, ttl=300):
    return {"name": name, "type": rtype, "ttl": ttl, "rdata": rdata}


def txn(serial_from, serial_to, deletes=None, adds=None):
    return {"begin_soa": soa(serial_from), "deletes": deletes or [],
            "adds": adds or [], "end_soa": soa(serial_to)}


def base_request(serial=100, records=None, transactions=None):
    return {
        "zone": "example.com",
        "initial": {"soa": soa(serial), "records": records or []},
        "transactions": transactions if transactions is not None
        else [txn(serial, serial + 1)],
    }


class TestHelpers(unittest.TestCase):
    def test_canonical_name_lowercases_and_strips_dot(self):
        self.assertEqual(canonical_name("WWW.Example.COM."), "www.example.com")
        self.assertEqual(canonical_name("example.com"), "example.com")

    def test_canonical_name_rejects_bad_labels(self):
        for bad in ("", ".", "bad..name", "exa mple.com", "a" * 64 + ".com",
                    "bad!.com", "na me.example.com", 42):
            with self.assertRaises(ReplayError) as ctx:
                canonical_name(bad)
            self.assertEqual(ctx.exception.code, "E_NAME_INVALID")

    def test_serial_arithmetic_rfc1982(self):
        self.assertTrue(serial_strictly_ahead(1, 0))
        self.assertTrue(serial_strictly_ahead(0, 2 ** 32 - 1))  # wrap
        self.assertTrue(serial_strictly_ahead(2 ** 31 - 1, 0))
        self.assertFalse(serial_strictly_ahead(2 ** 31, 0))  # ambiguous half
        self.assertFalse(serial_strictly_ahead(5, 5))
        self.assertFalse(serial_strictly_ahead(4, 5))
        self.assertFalse(serial_strictly_ahead(2 ** 32 - 1, 0))

    def test_name_sort_key_canonical_order(self):
        names = ["www.example.com", "example.com", "a.example.com",
                 "example.org", "mail.example.com"]
        ordered = sorted(names, key=name_sort_key)
        self.assertEqual(ordered, ["example.com", "a.example.com",
                                   "mail.example.com", "www.example.com",
                                   "example.org"])


class EngineTestCase(unittest.TestCase):
    def assertFails(self, request, code, transaction="keep"):
        with self.assertRaises(ReplayError) as ctx:
            replay(request)
        err = ctx.exception
        self.assertEqual(err.code, code,
                         f"expected {code}, got {err.code}: {err.message}")
        if transaction != "keep":
            self.assertEqual(err.transaction, transaction)
        return err


class TestEnvelope(EngineTestCase):
    def test_schema_errors(self):
        self.assertFails(["not", "a", "dict"], "E_SCHEMA", None)
        self.assertFails({"initial": {}, "transactions": []}, "E_SCHEMA", None)
        req = base_request()
        del req["initial"]["soa"]
        self.assertFails(req, "E_SCHEMA", None)
        req = base_request()
        req["transactions"][0] = "oops"
        self.assertFails(req, "E_SCHEMA", 0)
        req = base_request()
        del req["transactions"][0]["adds"]
        self.assertFails(req, "E_SCHEMA", 0)

    def test_transaction_count_bounds(self):
        req = base_request(transactions=[])
        self.assertFails(req, "E_TXN_COUNT", None)
        req = base_request()
        req["transactions"] = []
        serial = 100
        for _ in range(65):
            req["transactions"].append(txn(serial, serial + 1))
            serial += 1
        self.assertFails(req, "E_TXN_COUNT", None)

    def test_record_limit(self):
        records = [rec(f"h{i}.example.com", "A", "192.0.2.1")
                   for i in range(MAX_RECORDS + 1)]
        req = base_request(records=records)
        self.assertFails(req, "E_RECORD_LIMIT", None)

    def test_record_limit_inside_transaction(self):
        adds = [rec(f"h{i}.example.com", "A", "192.0.2.1")
                for i in range(MAX_RECORDS)]
        req = base_request(records=[rec("a.example.com", "A", "192.0.2.1")],
                           transactions=[txn(100, 101),
                                         txn(101, 102, adds=adds)])
        err = self.assertFails(req, "E_RECORD_LIMIT", 1)
        self.assertEqual(err.detail["limit"], MAX_RECORDS)

    def test_unknown_type(self):
        req = base_request(records=[rec("x.example.com", "MX", "10 mail")])
        self.assertFails(req, "E_TYPE_UNSUPPORTED", None)

    def test_type_is_case_insensitive(self):
        req = base_request(records=[rec("x.example.com", "a", "192.0.2.1")])
        result = replay(req)
        self.assertEqual(result["records"][1]["type"], "A")

    def test_ttl_bounds(self):
        req = base_request(records=[rec("x.example.com", "A", "192.0.2.1",
                                        ttl=2 ** 31)])
        self.assertFails(req, "E_TTL_INVALID", None)
        req = base_request(records=[rec("x.example.com", "A", "192.0.2.1",
                                        ttl=True)])
        self.assertFails(req, "E_TTL_INVALID", None)

    def test_bad_rdata(self):
        req = base_request(records=[rec("x.example.com", "A", "999.0.2.1")])
        self.assertFails(req, "E_RDATA_INVALID", None)
        req = base_request(records=[rec("x.example.com", "AAAA", ":::")])
        self.assertFails(req, "E_RDATA_INVALID", None)
        req = base_request(records=[rec("x.example.com", "TXT", 5)])
        self.assertFails(req, "E_RDATA_INVALID", None)

    def test_name_out_of_zone(self):
        req = base_request(records=[rec("other.org", "A", "192.0.2.1")])
        self.assertFails(req, "E_NAME_OUT_OF_ZONE", None)
        req = base_request(records=[rec("notexample.com", "A", "192.0.2.1")])
        self.assertFails(req, "E_NAME_OUT_OF_ZONE", None)


class TestInitialState(EngineTestCase):
    def test_initial_rrset_ttl_must_match(self):
        req = base_request(records=[
            rec("x.example.com", "A", "192.0.2.1", ttl=300),
            rec("x.example.com", "A", "192.0.2.2", ttl=600)])
        self.assertFails(req, "E_RRSET_TTL_MISMATCH", None)

    def test_initial_duplicate_record(self):
        req = base_request(records=[
            rec("x.example.com", "A", "192.0.2.1"),
            rec("X.Example.COM.", "a", "192.0.2.1")])
        self.assertFails(req, "E_ADD_DUPLICATE", None)

    def test_initial_cname_conflict(self):
        req = base_request(records=[
            rec("x.example.com", "CNAME", "y.example.com"),
            rec("x.example.com", "TXT", "hello")])
        self.assertFails(req, "E_CNAME_CONFLICT", None)

    def test_initial_soa_record_forbidden(self):
        req = base_request(records=[soa(100)])
        self.assertFails(req, "E_SOA_CARDINALITY", None)

    def test_initial_soa_must_be_at_apex(self):
        req = base_request()
        req["initial"]["soa"] = soa(100, name="sub.example.com")
        self.assertFails(req, "E_SOA_CARDINALITY", None)


class TestTransactions(EngineTestCase):
    def test_begin_soa_must_match_current(self):
        req = base_request(transactions=[txn(100, 101), txn(100, 102)])
        self.assertFails(req, "E_SOA_BEGIN_MISMATCH", 1)

    def test_begin_soa_wrong_serial(self):
        bad = txn(999, 101)
        req = base_request(transactions=[bad])
        err = self.assertFails(req, "E_SOA_BEGIN_MISMATCH", 0)
        self.assertEqual(err.detail["expected_serial"], 100)

    def test_end_serial_must_advance(self):
        req = base_request(transactions=[txn(100, 99)])
        self.assertFails(req, "E_SERIAL_NOT_ADVANCING", 0)

    def test_end_serial_equal_is_not_unique(self):
        req = base_request(transactions=[txn(100, 100)])
        self.assertFails(req, "E_SOA_END_UNIQUE", 0)

    def test_end_serial_reuse_across_transactions(self):
        req = base_request(transactions=[txn(100, 200), txn(200, 100)])
        # 100 is ahead of 200 in RFC 1982 arithmetic but already used.
        self.assertFails(req, "E_SOA_END_UNIQUE", 1)

    def test_ambiguous_half_range_serial_rejected(self):
        req = base_request(serial=0, transactions=[txn(0, 2 ** 31)])
        self.assertFails(req, "E_SERIAL_NOT_ADVANCING", 0)

    def test_serial_wraparound_success(self):
        req = base_request(serial=2 ** 32 - 2, transactions=[
            txn(2 ** 32 - 2, 2 ** 32 - 1),
            txn(2 ** 32 - 1, 0),
            txn(0, 7),
        ])
        result = replay(req)
        self.assertEqual(result["final_serial"], 7)

    def test_delete_must_hit_existing(self):
        req = base_request(transactions=[
            txn(100, 101, deletes=[rec("ghost.example.com", "A",
                                       "192.0.2.1")])])
        self.assertFails(req, "E_DELETE_NOT_FOUND", 0)

    def test_delete_ttl_mismatch(self):
        req = base_request(
            records=[rec("x.example.com", "A", "192.0.2.1", ttl=300)],
            transactions=[txn(100, 101, deletes=[
                rec("x.example.com", "A", "192.0.2.1", ttl=600)])])
        self.assertFails(req, "E_RRSET_TTL_MISMATCH", 0)

    def test_double_delete_in_one_transaction(self):
        req = base_request(
            records=[rec("x.example.com", "A", "192.0.2.1")],
            transactions=[txn(100, 101, deletes=[
                rec("x.example.com", "A", "192.0.2.1"),
                rec("x.example.com", "A", "192.0.2.1")])])
        self.assertFails(req, "E_DELETE_NOT_FOUND", 0)

    def test_add_duplicate_existing(self):
        req = base_request(
            records=[rec("x.example.com", "A", "192.0.2.1")],
            transactions=[txn(100, 101, adds=[
                rec("X.example.com.", "A", "192.0.2.1")])])
        self.assertFails(req, "E_ADD_DUPLICATE", 0)

    def test_add_duplicate_within_transaction(self):
        req = base_request(transactions=[txn(100, 101, adds=[
            rec("x.example.com", "A", "192.0.2.1"),
            rec("x.example.com", "A", "192.0.2.1")])])
        self.assertFails(req, "E_ADD_DUPLICATE", 0)

    def test_add_ttl_mismatch(self):
        req = base_request(
            records=[rec("x.example.com", "A", "192.0.2.1", ttl=300)],
            transactions=[txn(100, 101, adds=[
                rec("x.example.com", "A", "192.0.2.2", ttl=600)])])
        self.assertFails(req, "E_RRSET_TTL_MISMATCH", 0)

    def test_cname_conflict_add_data_over_cname(self):
        req = base_request(
            records=[rec("x.example.com", "CNAME", "y.example.com")],
            transactions=[txn(100, 101, adds=[
                rec("x.example.com", "A", "192.0.2.1")])])
        self.assertFails(req, "E_CNAME_CONFLICT", 0)

    def test_cname_conflict_add_cname_over_data(self):
        req = base_request(
            records=[rec("x.example.com", "A", "192.0.2.1")],
            transactions=[txn(100, 101, adds=[
                rec("x.example.com", "CNAME", "y.example.com")])])
        self.assertFails(req, "E_CNAME_CONFLICT", 0)

    def test_cname_singleton(self):
        req = base_request(
            records=[rec("x.example.com", "CNAME", "y.example.com")],
            transactions=[txn(100, 101, adds=[
                rec("x.example.com", "CNAME", "z.example.com")])])
        self.assertFails(req, "E_CNAME_CONFLICT", 0)

    def test_cname_at_apex_conflicts_with_soa(self):
        req = base_request(transactions=[txn(100, 101, adds=[
            rec("example.com", "CNAME", "y.example.com")])])
        self.assertFails(req, "E_CNAME_CONFLICT", 0)

    def test_soa_in_add_set_forbidden(self):
        req = base_request(transactions=[txn(100, 101, adds=[soa(101)])])
        self.assertFails(req, "E_SOA_CARDINALITY", 0)

    def test_soa_in_delete_set_forbidden(self):
        req = base_request(transactions=[txn(100, 101, deletes=[soa(100)])])
        self.assertFails(req, "E_SOA_CARDINALITY", 0)

    def test_error_in_later_transaction_reports_index(self):
        req = base_request(transactions=[
            txn(100, 101),
            txn(101, 102),
            txn(102, 103, deletes=[rec("ghost.example.com", "A",
                                       "192.0.2.1")]),
        ])
        self.assertFails(req, "E_DELETE_NOT_FOUND", 2)


class TestReplaySuccess(EngineTestCase):
    def test_full_replay_canonical_output(self):
        req = {
            "zone": "Example.COM.",
            "initial": {
                "soa": soa(1),
                "records": [
                    rec("WWW.Example.COM", "A", "192.0.2.1", ttl=300),
                    rec("www.example.com", "AAAA", "2001:DB8::1", ttl=300),
                    rec("mail.example.com", "CNAME", "WWW.Example.COM.",
                        ttl=600),
                ],
            },
            "transactions": [
                {"begin_soa": soa(1), "deletes": [],
                 "adds": [rec("example.com", "TXT", "v=spf1 -all")],
                 "end_soa": soa(2)},
                {"begin_soa": soa(2),
                 "deletes": [rec("www.example.com", "AAAA", "2001:db8::1")],
                 "adds": [rec("www.example.com", "A", "192.0.2.2"),
                          rec("alias.example.com", "CNAME",
                              "www.example.com", ttl=600)],
                 "end_soa": soa(3)},
            ],
        }
        result = replay(req)
        self.assertEqual(result["zone"], "example.com")
        self.assertEqual(result["final_serial"], 3)

        names = [r["name"] for r in result["records"]]
        self.assertEqual(names, sorted(names, key=lambda n: tuple(
            reversed(n.split(".")))))
        for r in result["records"]:
            self.assertEqual(r["name"], r["name"].lower())
            self.assertNotIn("..", r["name"])

        by_type = {}
        for r in result["records"]:
            by_type.setdefault(r["type"], 0)
            by_type[r["type"]] += 1
        self.assertEqual(by_type["SOA"], 1)
        self.assertEqual(by_type["A"], 2)
        self.assertEqual(by_type["CNAME"], 2)
        self.assertEqual(by_type["TXT"], 1)
        self.assertNotIn("AAAA", by_type)

        # Digest is deterministic and changes with content.
        again = replay(req)
        self.assertEqual(result["sha256"], again["sha256"])
        self.assertEqual(len(result["sha256"]), 64)
        req2 = base_request(serial=1)
        self.assertNotEqual(result["sha256"], replay(req2)["sha256"])

    def test_apex_soa_singleton_after_replay(self):
        req = base_request(serial=1, transactions=[
            txn(1, 2), txn(2, 3), txn(3, 4)])
        result = replay(req)
        soas = [r for r in result["records"] if r["type"] == "SOA"]
        self.assertEqual(len(soas), 1)
        self.assertEqual(soas[0]["name"], "example.com")
        self.assertEqual(soas[0]["rdata"]["serial"], 4)

    def test_delete_then_readd_same_record(self):
        req = base_request(
            records=[rec("x.example.com", "A", "192.0.2.1")],
            transactions=[txn(100, 101,
                              deletes=[rec("x.example.com", "A",
                                           "192.0.2.1")],
                              adds=[rec("x.example.com", "A",
                                        "192.0.2.9")])])
        result = replay(req)
        rdatas = [r["rdata"] for r in result["records"] if r["type"] == "A"]
        self.assertEqual(rdatas, ["192.0.2.9"])

    def test_empty_transaction_is_serial_bump_only(self):
        req = base_request(serial=1, records=[
            rec("x.example.com", "TXT", "keep me")])
        result = replay(req)
        self.assertEqual(result["final_serial"], 2)
        self.assertEqual(result["record_count"], 2)

    def test_canonical_ipv6_in_output(self):
        req = base_request(records=[
            rec("x.example.com", "AAAA", "2001:0DB8:0000:0000:0000:0000:0000:0001")])
        result = replay(req)
        aaaa = [r for r in result["records"] if r["type"] == "AAAA"]
        self.assertEqual(aaaa[0]["rdata"], "2001:db8::1")


if __name__ == "__main__":
    unittest.main()
