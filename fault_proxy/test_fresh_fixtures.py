import unittest
import dns.message
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

if __name__ == "__main__":
    unittest.main()
