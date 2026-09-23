"""Independent contracts for controlled additional records and DNS glue."""
import threading
import unittest

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset

from dns_fault_proxy import Config, _make_server, _TCPHandler, _TCPServer, _UDPHandler, _UDPServer
from fresh_fixtures import answer_fresh, _encode_response


ZONE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fresh.example.test."
CASES = (
    ("additional-mx", "MX", "additional-mail", "25"),
    ("additional-srv", "SRV", "additional-service", "40"),
    ("additional-ad", "SRV", "additional-dc", "60"),
    ("additional-ns", "NS", "additional-ns-host", "53"),
)


class AdditionalRecordTests(unittest.TestCase):
    def ask(self, key, kind, tcp=False):
        query = dns.message.make_query(f"{key}.{ZONE}", kind, use_edns=True, payload=1232)
        return dns.message.from_wire(answer_fresh(query.to_wire(), tcp=tcp))

    def test_all_dedicated_answers_supply_exact_dual_stack_additional_sets(self):
        for key, kind, target, suffix in CASES:
            for tcp in (False, True):
                with self.subTest(key=key, tcp=tcp):
                    response = self.ask(key, kind, tcp)
                    self.assertEqual(response.rcode(), dns.rcode.NOERROR)
                    self.assertTrue(response.flags & dns.flags.AA)
                    self.assertFalse(response.flags & (dns.flags.TC | dns.flags.AD | dns.flags.RA))
                    self.assertEqual(len(response.answer), 1)
                    self.assertEqual(response.answer[0].rdtype, dns.rdatatype.from_text(kind))
                    rr = response.answer[0][0]
                    actual_target = rr.exchange if kind == "MX" else rr.target
                    self.assertEqual(actual_target.to_text(), f"{target}.{ZONE}")
                    self.assertEqual({(rrset.name.to_text(), rrset.rdtype, rr.address)
                                      for rrset in response.additional for rr in rrset}, {
                        (f"{target}.{ZONE}", dns.rdatatype.A, f"192.0.2.{suffix}"),
                        (f"{target}.{ZONE}", dns.rdatatype.AAAA, f"2001:db8::{suffix}"),
                    })
                    self.assertTrue(all(rrset.ttl == 0 for rrset in response.additional))
                    for rrset in response.additional:
                        direct = self.ask(target, rrset.rdtype, tcp)
                        self.assertEqual(direct.answer, [rrset])

    def test_ldap_discovery_is_dns_data_not_a_deployed_directory(self):
        srv = self.ask("additional-ad", "SRV").answer[0][0]
        self.assertEqual((srv.priority, srv.weight, srv.port), (10, 60, 389))

    def test_authoritative_ns_zone_has_consistent_soa_and_negative_owner(self):
        ns_owner = f"additional-ns.{ZONE}"
        soa = self.ask("additional-ns", "SOA")
        self.assertEqual(soa.answer[0].name.to_text(), ns_owner)
        self.assertEqual(soa.answer[0][0].mname.to_text(), f"additional-ns-host.{ZONE}")
        self.assertEqual(soa.answer[0][0].rname.to_text(), f"hostmaster.{ns_owner}")
        for key, kind, rcode in (("additional-ns", "TXT", dns.rcode.NOERROR),
                                 ("missing.additional-ns", "A", dns.rcode.NXDOMAIN)):
            response = self.ask(key, kind)
            self.assertEqual(response.rcode(), rcode)
            self.assertEqual(response.answer, [])
            self.assertEqual(response.authority, soa.answer)
        ds = self.ask("additional-ns", "DS")
        self.assertEqual(ds.authority[0].name.to_text(), ZONE)

    def test_referral_retains_available_in_domain_glue_for_descendants(self):
        cut = f"additional-referral.{ZONE}"
        for key, kind in (("additional-referral", "NS"), ("www.additional-referral", "A"),
                          ("ns.additional-referral", "A"), ("ns.additional-referral", "AAAA")):
            for tcp in (False, True):
                with self.subTest(key=key, kind=kind, tcp=tcp):
                    response = self.ask(key, kind, tcp)
                    self.assertEqual(response.rcode(), dns.rcode.NOERROR)
                    self.assertFalse(response.flags & dns.flags.AA)
                    self.assertEqual(response.answer, [])
                    self.assertEqual(response.authority[0].name.to_text(), cut)
                    self.assertEqual(response.authority[0][0].target.to_text(), f"ns.{cut}")
                    self.assertEqual({(rrset.name.to_text(), rrset.rdtype, rr.address)
                                      for rrset in response.additional for rr in rrset}, {
                        (f"ns.{cut}", dns.rdatatype.A, "192.0.2.53"),
                        (f"ns.{cut}", dns.rdatatype.AAAA, "2001:db8::53"),
                    })
        ds = self.ask("additional-referral", "DS")
        self.assertEqual(ds.rcode(), dns.rcode.NOERROR)
        self.assertTrue(ds.flags & dns.flags.AA)
        self.assertEqual(ds.authority[0].name.to_text(), ZONE)
        self.assertEqual(ds.additional, [])


class AdditionalWireTests(unittest.TestCase):
    """Real loopback UDP/TCP through the public service dispatch path."""

    @classmethod
    def setUpClass(cls):
        config = Config(listen_host="127.0.0.1", listen_port=0, io_timeout_seconds=0.3)
        cls.servers = [_make_server(server, handler, config, threading.BoundedSemaphore(4))
                       for server, handler in ((_UDPServer, _UDPHandler), (_TCPServer, _TCPHandler))]
        cls.threads = []
        for server in cls.servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=1)

    def test_udp_and_tcp_retain_identical_additional_records(self):
        for key, kind, _, _ in (*CASES, ("additional-referral", "NS", "", "")):
            with self.subTest(key=key):
                query = dns.message.make_query(f"{key}.{ZONE}", kind, use_edns=True, payload=1232)
                udp = dns.query.udp(query, "127.0.0.1", port=self.servers[0].server_address[1], timeout=1)
                tcp = dns.query.tcp(query, "127.0.0.1", port=self.servers[1].server_address[1], timeout=1)
                self.assertEqual(udp.rcode(), dns.rcode.NOERROR)
                self.assertEqual(len(udp.additional), 2)
                self.assertEqual(udp.answer, tcp.answer)
                self.assertEqual(udp.authority, tcp.authority)
                self.assertEqual(udp.additional, tcp.additional)
                self.assertEqual(udp.flags, tcp.flags)


class GlueTruncationTests(unittest.TestCase):
    def response(self, cut="child.example.test.", target_zone="child.example.test."):
        query = dns.message.make_query(f"www.{cut}", "A", use_edns=True, payload=512)
        response = dns.message.make_response(query)
        response.authority.append(dns.rrset.from_text(cut, 0, "IN", "NS",
                                  *(f"ns{i}.{target_zone}" for i in range(12))))
        for i in range(12):
            response.additional.append(dns.rrset.from_text(f"ns{i}.{target_zone}", 0, "IN", "A", f"192.0.2.{i + 1}"))
            response.additional.append(dns.rrset.from_text(f"ns{i}.{target_zone}", 0, "IN", "AAAA", f"2001:db8::{i + 1:x}"))
        return response

    def test_missing_available_in_domain_glue_sets_tc_within_size_limit(self):
        full = self.response()
        # Authority fits; truncation happens specifically in additional data.
        generic = dns.message.from_wire(full.to_wire(max_size=512, prefer_truncation=True))
        self.assertEqual(generic.authority, full.authority)
        self.assertLess(len(generic.additional), len(full.additional))
        wire = _encode_response(full, 512)
        self.assertLessEqual(len(wire), 512)
        truncated = dns.message.from_wire(wire)
        self.assertTrue(truncated.flags & dns.flags.TC)
        self.assertEqual(truncated.authority, full.authority)
        self.assertEqual(truncated.question, full.question)
        tcp = dns.message.from_wire(_encode_response(full, 65535))
        self.assertFalse(tcp.flags & dns.flags.TC)
        self.assertEqual(tcp.additional, full.additional)

    def test_omitting_optional_out_of_domain_addresses_does_not_force_tc(self):
        full = self.response(target_zone="sibling.example.test.")
        truncated = dns.message.from_wire(_encode_response(full, 512))
        self.assertEqual(truncated.authority, full.authority)
        self.assertLess(len(truncated.additional), len(full.additional))
        self.assertFalse(truncated.flags & dns.flags.TC)


if __name__ == "__main__":
    unittest.main()
