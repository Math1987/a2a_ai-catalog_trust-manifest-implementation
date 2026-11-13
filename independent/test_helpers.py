"""Pure parsing and policy checks; no network and no signing keys."""
from decimal import Decimal
import unittest

from verify_catalog import VerificationError, catalog_shape, decode64, parse_json, root_did, timestamp


class HelperTests(unittest.TestCase):
    def test_duplicate_json_rejected_at_any_depth(self):
        for raw in (b'{"a":1,"a":2}', b'{"x":{"kid":"a","kid":"b"}}'):
            with self.assertRaises(VerificationError):
                parse_json(raw)

    def test_invalid_json_numbers_and_utf8_rejected(self):
        for raw in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":"\xff"}'):
            with self.assertRaises(VerificationError):
                parse_json(raw)

    def test_timestamps_compare_instants_and_preserve_precision(self):
        self.assertEqual(timestamp("2026-11-12T12:00:00Z"), timestamp("2026-11-12T13:00:00+01:00"))
        self.assertGreater(timestamp("2026-11-12T12:00:00.000000000000000000000001Z"),
                           timestamp("2026-11-12T12:00:00Z"))
        self.assertEqual(timestamp("1970-01-01T00:00:00.1Z"), Decimal("0.1"))

    def test_invalid_calendar_date_and_leap_policy(self):
        for value in ("2026-02-30T00:00:00Z", "2026-11-12T25:00:00Z", "2026-11-12T12:00:00+24:00",
                      "2026-11-12T12:00:00", "2016-12-31T23:59:60Z"):
            with self.assertRaises(VerificationError):
                timestamp(value)

    def test_root_did_rejects_normalization_and_network_address_forms(self):
        for value in ("did:web:EXAMPLE.com", "did:web:example.com.", "did:web:example.com:service",
                      "did:web:127.0.0.1", "did:web:127.1", "did:web:example.com%3A443", "did:web:éxample.com"):
            with self.assertRaises(VerificationError):
                root_did(value)

    def test_idna2008_alabel_supported(self):
        self.assertEqual(root_did("did:web:xn--fa-hia.de"), "https://xn--fa-hia.de/.well-known/did.json")

    def test_strict_base64url(self):
        self.assertEqual(decode64("_w"), b"\xff")
        for value in ("/w", "_w==", "_x", ""):
            with self.assertRaises(VerificationError):
                decode64(value)


if __name__ == "__main__":
    unittest.main()
