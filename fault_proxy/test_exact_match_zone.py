"""Contract checks for fixed exact-match and PTR test data."""
from pathlib import Path
import unittest
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone

ROOT = Path(__file__).resolve().parents[1]


class ExactMatchZoneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT / "bind/zones/db.exact-match.test").open() as source:
            cls.zone = dns.zone.from_file(
                source,
                origin=dns.name.from_text("exact-match.test."),
                relativize=False,
            )

    def rrset(self, owner, rdtype):
        node = self.zone.get_node(dns.name.from_text(owner))
        self.assertIsNotNone(node, owner)
        rrset = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype))
        self.assertIsNotNone(rrset, f"{owner} {rdtype}")
        self.assertEqual(rrset.ttl, 60)
        return rrset

    def test_exact_name_pool_has_direct_a_and_aaaa_records(self):
        for suffix, last in (("01", 101), ("02", 102)):
            owner = f"allapp-a-{suffix}.exact-match.test."
            self.assertEqual(str(self.rrset(owner, "A")[0]), f"192.0.2.{last}")
            self.assertEqual(str(self.rrset(owner, "AAAA")[0]), f"2001:db8::{last}")

    def test_cname_mx_srv_ns_and_https_targets_are_in_zone(self):
        for suffix in ("01", "02"):
            self.rrset(f"allapp-cname-a-{suffix}.exact-match.test.", "CNAME")
            self.rrset(f"allapp-canonical-{suffix}.exact-match.test.", "A")
            for rrtype, owner, target in (
                ("MX", f"allapp-mx-{suffix}", f"allapp-mail-{suffix}"),
                ("SRV", f"allapp-srv-{suffix}", f"allapp-service-{suffix}"),
                ("NS", f"allapp-child-{suffix}", f"allapp-ns-{suffix}"),
            ):
                rrset = self.rrset(f"{owner}.exact-match.test.", rrtype)
                self.assertTrue(any(
                    str(getattr(rr, "target", getattr(rr, "exchange", ""))).lower() == f"{target}.exact-match.test."
                    for rr in rrset
                ))
                self.rrset(f"{target}.exact-match.test.", "A")
                self.rrset(f"{target}.exact-match.test.", "AAAA")
            https = self.rrset(f"allapp-https-{suffix}.exact-match.test.", "HTTPS")
            self.assertIn("ipv4hint", https.to_text().lower())
            self.assertIn("ipv6hint", https.to_text().lower())

    def test_large_a_and_exact_apex_are_present(self):
        self.assertEqual(self.rrset("exact-match.test.", "SOA").ttl, 60)
        example_text = (ROOT / "bind/zones/db.example.test").read_text()
        example_text = "\n".join(line for line in example_text.splitlines() if not line.startswith("$INCLUDE"))
        example = dns.zone.from_text(example_text, origin=dns.name.from_text("example.test."), relativize=False)
        apex = example.get_node(dns.name.from_text("example.test.")).find_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
        self.assertEqual(apex.ttl, 60)
        self.assertEqual(apex[0].address, "192.0.2.9")
        zone_text = (ROOT / "bind/zones/db.exact-match.test").read_text()
        self.assertIn("$GENERATE 1-240 allapp-large-a-01 IN A 192.0.2.$", zone_text)
        self.assertIn("$GENERATE 1-240 allapp-large-a-02 IN A 198.51.100.$", zone_text)

    def test_reverse_zone_ptr_owners_map_to_exact_test_targets(self):
        with (ROOT / "bind/zones/db.192.0.2").open() as source:
            reverse = dns.zone.from_file(
                source,
                origin=dns.name.from_text("2.0.192.in-addr.arpa."),
                relativize=False,
            )
        for octet, target in ((101, "allapp-a-01"), (102, "allapp-a-02"), (111, "allapp-mail-01"), (121, "allapp-service-01")):
            owner = dns.name.from_text(f"{octet}.2.0.192.in-addr.arpa.")
            rrset = reverse.get_node(owner).find_rdataset(dns.rdataclass.IN, dns.rdatatype.PTR)
            self.assertEqual(rrset.ttl, 60)
            self.assertEqual(str(rrset[0].target).lower(), f"{target}.exact-match.test.")


if __name__ == "__main__":
    unittest.main()
