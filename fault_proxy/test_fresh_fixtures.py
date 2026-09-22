import unittest
import struct
from pathlib import Path
import dns.edns
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.zone
import dns.rdatatype
import dns.dnssec
import dns.flags
from fresh_fixtures import answer_fresh

NONCE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

class FreshTests(unittest.TestCase):
    def ask(self, key, kind="A", do=False, payload=1232):
        query = dns.message.make_query(f"{key}.{NONCE}.fresh.example.test", kind, use_edns=True, payload=payload, want_dnssec=do)
        return dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))

    def test_alias_chain_has_no_shared_cached_targets(self):
        response = self.ask("cname-chain")
        self.assertEqual(len(response.answer), 3)
        for rrset in response.answer:
            self.assertIn(NONCE, str(rrset.name))
            self.assertEqual(rrset.ttl, 0)
            if rrset.rdtype == dns.rdatatype.CNAME:
                self.assertIn(NONCE, str(rrset[0].target))

    def test_internal_zone_is_unsigned_even_when_do_requested(self):
        response = self.ask("signed", do=True)
        self.assertFalse(any(rr.rdtype in (46,48,47,50) for rr in response.answer + response.authority))

    def test_udp_size_and_edns_truncation(self):
        q = dns.message.make_query(f"large-1232.{NONCE}.fresh.example.test", "TXT", use_edns=True, payload=1232)
        raw = answer_fresh(q.to_wire(), tcp=False)
        self.assertLessEqual(len(raw), 1232)
        r = dns.message.from_wire(raw)
        self.assertTrue(r.flags & dns.flags.TC)
        self.assertEqual(r.edns, 0)

    def test_negative_answer_has_zero_negative_ttl(self):
        r = self.ask("negative")
        self.assertEqual(r.rcode(), 3)
        self.assertEqual(r.authority[0].ttl, 0)
        self.assertEqual(r.authority[0][0].minimum, 0)


class OrdinaryConformanceTests(unittest.TestCase):
    """Assertions from DNS semantics, independent of response-building helpers."""

    zone = f"{NONCE}.fresh.example.test."

    def ask(self, key, kind="A", **options):
        name = self.zone if key == "@" else f"{key}.{self.zone}"
        query = dns.message.make_query(name, kind, **options)
        return dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))

    def test_nonce_and_suffix_are_case_insensitive(self):
        name = f"A.{self.zone.upper()}"
        query = dns.message.make_query(name, "A")
        response = dns.message.from_wire(answer_fresh(query.to_wire()))
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)
        self.assertEqual(response.question, query.question)
        self.assertEqual(response.answer[0][0].address, "192.0.2.10")

    def test_non_in_class_never_receives_in_answers(self):
        for rdclass in (dns.rdataclass.CH, dns.rdataclass.HS):
            with self.subTest(rdclass=rdclass):
                response = self.ask("a", rdclass=rdclass)
                self.assertEqual(response.rcode(), dns.rcode.REFUSED)
                self.assertEqual(response.answer, [])
                self.assertFalse(response.flags & dns.flags.AA)

    def test_unsupported_opcodes_return_notimp(self):
        for opcode in (1, 2, 4, 5, 15):
            with self.subTest(opcode=opcode):
                query = dns.message.make_query(f"a.{self.zone}", "A")
                query.set_opcode(opcode)
                response = dns.message.from_wire(answer_fresh(query.to_wire()))
                self.assertEqual(response.rcode(), dns.rcode.NOTIMP)
                self.assertEqual(response.opcode(), opcode)
                self.assertEqual(response.answer, [])

    def test_nxdomain_is_independent_of_qtype(self):
        for key in ("negative", "dnssec-negative", "child.negative"):
            for kind in ("A", "AAAA", "DNSKEY", "DS", "NSEC", "RRSIG", "NSEC3"):
                with self.subTest(key=key, kind=kind):
                    response = self.ask(key, kind)
                    self.assertEqual(response.rcode(), dns.rcode.NXDOMAIN)
                    self.assertTrue(response.flags & dns.flags.AA)
                    self.assertEqual(response.authority[0].rdtype, dns.rdatatype.SOA)
                    self.assertEqual(response.authority[0].ttl, 0)
                    self.assertEqual(response.authority[0][0].minimum, 0)

    def test_large_fixtures_only_return_the_requested_type(self):
        for key, kind in (("large-512", "A"), ("large-1232", "MX"),
                          ("near-max", "AAAA"), ("large-multi-a", "TXT"),
                          ("large-multi-aaaa", "A"), ("large-srv", "A")):
            with self.subTest(key=key):
                response = self.ask(key, kind)
                self.assertEqual(response.rcode(), dns.rcode.NOERROR)
                self.assertEqual(response.answer, [])
                self.assertEqual(response.authority[0].rdtype, dns.rdatatype.SOA)

    def test_additional_addresses_match_direct_lookups(self):
        for key, kind in (("mx", "MX"), ("ns", "NS"), ("srv", "SRV")):
            response = self.ask(key, kind)
            for additional in response.additional:
                query = dns.message.make_query(additional.name, additional.rdtype)
                direct = dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))
                self.assertIn(additional, direct.answer)

    def test_cname_chain_followups_and_qtype_are_consistent(self):
        chain = self.ask("cname-chain")
        for rrset in chain.answer:
            query = dns.message.make_query(rrset.name, rrset.rdtype)
            direct = dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))
            self.assertIn(rrset, direct.answer)
        cname = self.ask("cname-chain", "CNAME")
        self.assertEqual(len(cname.answer), 1)
        aaaa = self.ask("cname-chain", "AAAA")
        self.assertEqual([r.rdtype for r in aaaa.answer], [5, 5, 28])
        missing = self.ask("cname-chain", "DNSKEY")
        self.assertEqual([r.rdtype for r in missing.answer], [5, 5])
        self.assertEqual(missing.authority[0].rdtype, dns.rdatatype.SOA)

    def test_dname_owner_does_not_redirect_itself(self):
        response = self.ask("dname-child", "DNAME")
        self.assertEqual(response.answer[0].name.to_text(), f"dname-child.{self.zone}")
        response = self.ask("dname-child", "A")
        self.assertEqual(response.answer, [])
        self.assertEqual(response.authority[0].rdtype, dns.rdatatype.SOA)

    def test_dname_substitution_preserves_all_prefix_labels(self):
        response = self.ask("x.child.dname-child", "A")
        self.assertEqual([r.rdtype for r in response.answer], [39, 5, 1])
        dname, cname, address = response.answer
        self.assertEqual(dname.name.to_text(), f"dname-child.{self.zone}")
        self.assertEqual(cname[0].target.to_text(), f"x.child.target-tree.{self.zone}")
        self.assertEqual(address.name, cname[0].target)
        query = dns.message.make_query(cname[0].target, "A")
        direct = dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))
        self.assertIn(address, direct.answer)
        aaaa = self.ask("child.dname-child", "AAAA")
        self.assertNotIn(dns.rdatatype.A, [r.rdtype for r in aaaa.answer])
        self.assertEqual([r.rdtype for r in self.ask("child.dname-child", "CNAME").answer], [39, 5])
        self.assertEqual(self.ask("@", "DNAME").answer, [])

    def test_referral_descendants_keep_the_same_zone_cut(self):
        first = self.ask("referral")
        for key in ("child.referral", "ns.referral"):
            response = self.ask(key)
            self.assertEqual(response.authority, first.authority)
            self.assertEqual(response.additional, first.additional)
            self.assertFalse(response.flags & dns.flags.AA)
        ds = self.ask("referral", "DS")
        self.assertTrue(ds.flags & dns.flags.AA)
        self.assertEqual(ds.authority[0].rdtype, dns.rdatatype.SOA)
        below = self.ask("child.referral", "DS")
        self.assertEqual(below.authority, first.authority)

    def test_any_returns_an_existing_rrset(self):
        response = self.ask("any", "ANY")
        self.assertTrue(response.answer)
        for rrset in response.answer:
            direct = self.ask("any", rrset.rdtype)
            self.assertIn(rrset, direct.answer)

    def test_two_question_formerr_does_not_echo_multiple_questions(self):
        query = dns.message.make_query(f"a.{self.zone}", "A", use_edns=True)
        query.question.append(dns.message.make_query(f"aaaa.{self.zone}", "AAAA").question[0])
        response = dns.message.from_wire(answer_fresh(query.to_wire()))
        self.assertEqual(response.rcode(), dns.rcode.FORMERR)
        self.assertLessEqual(len(response.question), 1)
        self.assertEqual(response.edns, 0)

    def test_malformed_edns_formerr_keeps_question_and_one_opt(self):
        good = dns.message.make_query(f"a.{self.zone}", "A", use_edns=True)
        duplicate = bytearray(good.to_wire())
        duplicate[10:12] = struct.pack("!H", 2)
        duplicate.extend(good.to_wire()[-11:])
        bad_option = dns.message.make_query(
            f"a.{self.zone}", "A", use_edns=True,
            options=[dns.edns.GenericOption(8, b"\x00\x01")],
        ).to_wire()
        for wire in (bytes(duplicate), bad_option):
            with self.subTest(wire=wire.hex()):
                response = dns.message.from_wire(answer_fresh(wire))
                self.assertEqual(response.rcode(), dns.rcode.FORMERR)
                self.assertEqual(response.question, good.question)
                self.assertEqual(response.edns, 0)
                self.assertEqual(struct.unpack("!H", response.to_wire()[10:12])[0], 1)

    def test_edns_limits_unknown_options_and_badvers(self):
        for payload in (128, 512, 1232, 4096):
            query = dns.message.make_query(f"large-1232.{self.zone}", "TXT", use_edns=True, payload=payload,
                                           options=[dns.edns.GenericOption(65001, b"test")])
            query.ednsflags |= dns.flags.DO | 0x4000
            wire = answer_fresh(query.to_wire())
            response = dns.message.from_wire(wire)
            self.assertLessEqual(len(wire), max(512, payload))
            self.assertEqual(response.ednsflags, dns.flags.DO)
            self.assertEqual(response.options, ())
        response = self.ask("a", use_edns=1, want_dnssec=True)
        self.assertEqual(response.rcode(), dns.rcode.BADVERS)
        self.assertEqual(response.edns, 0)
        self.assertTrue(response.ednsflags & dns.flags.DO)

    def test_literal_apex_label_is_not_confused_with_the_zone_apex(self):
        response = self.ask("apex", "SOA")
        self.assertEqual(response.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(response.answer, [])

    def test_authoritative_negative_soa_uses_the_nearest_served_zone(self):
        for key in ("ns", "soa"):
            response = self.ask(f"missing.{key}", "A")
            self.assertEqual(response.rcode(), dns.rcode.NXDOMAIN)
            self.assertEqual(response.authority[0].name.to_text(), f"{key}.{self.zone}")
            ds = self.ask(key, "DS")
            self.assertEqual(ds.authority[0].name.to_text(), self.zone)

    def test_dname_overlong_substitution_returns_yxdomain(self):
        suffix = f"dname.{self.zone}"
        # Construct a valid 255-octet question; target-tree adds five octets.
        remaining = 255 - len(dns.name.from_text(suffix).to_wire())
        labels = []
        while remaining:
            length = min(63, remaining - 1)
            labels.append("x" * length)
            remaining -= length + 1
        query = dns.message.make_query(".".join(labels) + "." + suffix, "A")
        response = dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))
        self.assertEqual(response.rcode(), dns.rcode.YXDOMAIN)
        self.assertEqual([r.rdtype for r in response.answer], [dns.rdatatype.DNAME])

    def test_shipped_record_families_return_their_declared_types(self):
        fixtures = {
            "a": "A", "aaaa": "AAAA", "ns": "NS", "soa": "SOA", "mx": "MX",
            "txt": "TXT", "ptr": "PTR", "srv": "SRV", "https": "HTTPS", "svcb": "SVCB",
            "cert": "CERT", "caa": "CAA", "naptr": "NAPTR", "tlsa": "TLSA", "sshfp": "SSHFP",
            "uri": "URI", "loc": "LOC", "hinfo": "HINFO", "rp": "RP", "afsdb": "AFSDB",
            "unknown": "TYPE65280", "multi-a": "A", "multi-aaaa": "AAAA", "cname": "CNAME",
            "cname-a": "A", "cname-chain": "A", "dname": "DNAME", "child.dname-child": "A",
            "svcb-alias": "SVCB", "https-alias": "HTTPS", "ad-guid": "CNAME", "ad-ptr": "PTR",
            "ad-ldap": "SRV", "ad-kerberos": "SRV", "ad-kpasswd": "SRV", "ad-site": "SRV",
            "ad-gc": "SRV", "ad-pdc": "SRV", "exact": "A", "wildcard": "A", "mixed-case": "A",
            "child.long-label": "A", "child.long-name": "A", "ttl-zero": "A", "ttl-normal": "A",
            "ttl-high": "A", "large-512": "TXT", "large-1232": "TXT", "near-max": "TXT",
            "large-multi-a": "A", "large-multi-aaaa": "AAAA", "large-srv": "SRV",
        }
        for key, kind in fixtures.items():
            with self.subTest(key=key, kind=kind):
                response = self.ask(key, kind)
                self.assertEqual(response.rcode(), dns.rcode.NOERROR)
                self.assertIn(dns.rdatatype.from_text(kind), [rr.rdtype for rr in response.answer])
        for key, ttl in (("ttl-zero", 0), ("ttl-normal", 60), ("ttl-high", 86400)):
            self.assertEqual(self.ask(key).answer[0].ttl, ttl)

    def test_service_alias_targets_and_address_hints_are_resolvable(self):
        for key, kind in (("https-alias", "HTTPS"), ("svcb-alias", "SVCB")):
            alias = self.ask(key, kind).answer[0][0]
            query = dns.message.make_query(alias.target, kind)
            service = dns.message.from_wire(answer_fresh(query.to_wire(), tcp=True))
            self.assertEqual(service.answer[0][0].priority, 1)
            for kind, address in (("A", "192.0.2.40"), ("AAAA", "2001:db8::40")):
                query = dns.message.make_query(alias.target, kind)
                response = dns.message.from_wire(answer_fresh(query.to_wire()))
                self.assertEqual(response.answer[0][0].address, address)

    def test_cert_specimens_use_experimental_type_without_claiming_pkix(self):
        fresh = self.ask("cert", "CERT").answer[0][0]
        zone_path = Path(__file__).resolve().parent.parent / "bind/zones/db.example.test"
        # Generated large-answer includes are unrelated to the static CERT RR.
        zone_text = "\n".join(line for line in zone_path.read_text().splitlines()
                              if not line.lstrip().startswith("$INCLUDE"))
        zone = dns.zone.from_text(zone_text, origin="example.test.")
        static = zone.get_rdataset("cert", "CERT")[0]
        for record in (fresh, static):
            with self.subTest(record=record):
                self.assertEqual(record.certificate_type, 65280)
                self.assertEqual(record.key_tag, 0)
                self.assertEqual(record.algorithm, 0)
                self.assertEqual(record.certificate, b"\x01\x02\x03\x04")

if __name__ == "__main__":
    unittest.main()
