"""Mail-key DNS specimens have valid public data, without claiming identity trust."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.zone

from fresh_fixtures import answer_fresh
import test_additional_records as wire_helpers

ZONE = wire_helpers.ZONE


ROOT = Path(__file__).resolve().parent.parent


def pgp_tags(data):
    """Read bounded packet headers so accidental secret-key packets fail tests."""
    offset, tags = 0, []
    while offset < len(data):
        header = data[offset]
        offset += 1
        if not header & 0x80:
            raise ValueError("Invalid OpenPGP packet header")
        if header & 0x40:
            tag = header & 0x3f
            first = data[offset]
            offset += 1
            if first < 192:
                length = first
            elif first < 224:
                length = ((first - 192) << 8) + data[offset] + 192
                offset += 1
            elif first == 255:
                length = int.from_bytes(data[offset:offset + 4], "big")
                offset += 4
            else:
                raise ValueError("Unexpected partial length in static public specimen")
        else:
            tag, length_type = (header >> 2) & 0xf, header & 3
            if length_type == 3:
                raise ValueError("Unexpected indeterminate static packet length")
            count = (1, 2, 4)[length_type]
            length = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        offset += length
        if offset > len(data):
            raise ValueError("Truncated OpenPGP packet")
        tags.append(tag)
    return tags


class SecurityRecordTests(unittest.TestCase):
    def ask(self, key, kind, tcp=False):
        query = dns.message.make_query(f"{key}.{ZONE}", kind, use_edns=True, payload=1232)
        return dns.message.from_wire(answer_fresh(query.to_wire(), tcp=tcp))

    def test_public_key_and_smimea_are_consistent_udp_tcp_rdata(self):
        for key, kind in (("openpgpkey", "OPENPGPKEY"), ("smimea", "SMIMEA")):
            for tcp in (False, True):
                with self.subTest(key=key, tcp=tcp):
                    response = self.ask(key, kind, tcp)
                    self.assertEqual(response.rcode(), dns.rcode.NOERROR)
                    self.assertTrue(response.flags & dns.flags.AA)
                    self.assertFalse(response.flags & (dns.flags.TC | dns.flags.AD | dns.flags.RA))
                    self.assertEqual(len(response.answer), 1)
                    self.assertEqual(response.answer[0].rdtype, dns.rdatatype.from_text(kind))
                    self.assertEqual(response.answer[0].ttl, 0)
                    self.assertEqual(response.additional, [])
                    wrong_type = self.ask(key, "A", tcp)
                    self.assertEqual(wrong_type.rcode(), dns.rcode.NOERROR)
                    self.assertEqual(wrong_type.answer, [])
                    self.assertEqual(wrong_type.authority[0].rdtype, dns.rdatatype.SOA)
            self.assertEqual(self.ask(key, kind).answer, self.ask(key, kind, True).answer)

    def test_openpgpkey_contains_public_key_uid_and_certification_only(self):
        data = self.ask("openpgpkey", "OPENPGPKEY").answer[0][0].key
        self.assertEqual(pgp_tags(data), [6, 13, 2])
        self.assertNotIn(b"PRIVATE KEY", data)
        self.assertIn(b"DNS QA Synthetic <dns-qa@example.invalid>", data)

    def test_public_key_uses_tc_when_legacy_udp_payload_is_too_small(self):
        query = dns.message.make_query(f"openpgpkey.{ZONE}", "OPENPGPKEY")
        wire = answer_fresh(query.to_wire(), tcp=False)
        self.assertLessEqual(len(wire), 512)
        self.assertTrue(dns.message.from_wire(wire).flags & dns.flags.TC)
        tcp = dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))
        self.assertFalse(tcp.flags & dns.flags.TC)
        self.assertEqual(pgp_tags(tcp.answer[0][0].key), [6, 13, 2])

    @unittest.skipUnless(shutil.which("gpg"), "gpg required for independent OpenPGP self-signature verification")
    def test_openpgpkey_has_a_valid_self_signature(self):
        data = self.ask("openpgpkey", "OPENPGPKEY").answer[0][0].key
        with tempfile.TemporaryDirectory(prefix="dns-qa-public-check-") as directory:
            args = ["gpg", "--homedir", directory, "--batch", "--no-auto-key-retrieve"]
            subprocess.run([*args, "--import"], input=data, capture_output=True, check=True)
            checked = subprocess.run([*args, "--with-colons", "--check-sigs"], capture_output=True, check=True).stdout.decode()
            self.assertIn("sig:!:", checked)
            self.assertNotIn("sig:-:", checked)
            self.assertNotIn("sec:", checked)

    @unittest.skipUnless(shutil.which("openssl"), "openssl required for independent certificate/SPKI verification")
    def test_smimea_digest_is_sha256_of_published_synthetic_certificate_spki(self):
        rr = self.ask("smimea", "SMIMEA").answer[0][0]
        self.assertEqual((rr.usage, rr.selector, rr.mtype), (3, 1, 1))
        self.assertEqual(len(rr.cert), 32)
        cert = ROOT / "docs/test-records/smimea-public-cert.pem"
        self.assertNotIn("PRIVATE KEY", cert.read_text())
        public_pem = subprocess.run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"], capture_output=True, check=True).stdout
        spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public_pem, capture_output=True, check=True).stdout
        self.assertEqual(rr.cert, hashlib.sha256(spki).digest())

    def test_cloudflare_records_match_lan_payloads_without_changing_delegation(self):
        zone = dns.zone.from_file(str(ROOT / "external/cloudflare-security-records.zone"), origin="quality-assurance.fyi.", check_origin=False)
        self.assertEqual(sum(len(node.rdatasets) for node in zone.nodes.values()), 4)
        for key, kind in (("openpgpkey", "OPENPGPKEY"), ("smimea", "SMIMEA")):
            expected = self.ask(key, kind).answer[0][0]
            for owner in (f"{key}.dns", f"*.{key}.dns"):
                records = zone.get_rdataset(owner, kind)
                self.assertIsNotNone(records)
                self.assertEqual(records.ttl, 300)
                self.assertEqual(records[0].to_wire(), expected.to_wire())


class SecurityWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wire_helpers.AdditionalWireTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        wire_helpers.AdditionalWireTests.tearDownClass.__func__(cls)

    def test_security_records_over_real_udp_and_tcp_sockets(self):
        for key, kind in (("openpgpkey", "OPENPGPKEY"), ("smimea", "SMIMEA")):
            with self.subTest(key=key):
                query = dns.message.make_query(f"{key}.{ZONE}", kind, use_edns=True, payload=1232)
                udp = dns.query.udp(query, "127.0.0.1", port=self.servers[0].server_address[1], timeout=1)
                tcp = dns.query.tcp(query, "127.0.0.1", port=self.servers[1].server_address[1], timeout=1)
                self.assertEqual(udp.rcode(), dns.rcode.NOERROR)
                self.assertEqual(len(udp.answer), 1)
                self.assertEqual(udp.answer, tcp.answer)
                self.assertEqual(udp.answer[0].rdtype, dns.rdatatype.from_text(kind))


if __name__ == "__main__":
    unittest.main()
