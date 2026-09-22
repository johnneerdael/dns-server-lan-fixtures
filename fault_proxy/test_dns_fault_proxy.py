import socket
import socketserver
import struct
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns.edns
import dns.flags
import dns.message
import dns.rrset

from dns_fault_proxy import (
    DNSFormatError,
    Scenario,
    build_query,
    make_truncated_response,
    parse_question_name,
    recv_frame,
    scenario_for,
    send_frame,
    validate_health_response,
    Config,
    _make_server,
    _TCPHandler,
    _TCPServer,
    _UDPHandler,
)


class RecordingSocket:
    def __init__(self):
        self.calls = []

    def sendall(self, data):
        self.calls.append(bytes(data))


class ParserTests(unittest.TestCase):
    def test_parses_and_normalizes_question_name(self):
        query = build_query("Split-Prefix.Transport.Example.Test", transaction_id=0x1234)
        self.assertEqual(parse_question_name(query), "split-prefix.transport.example.test")

    def test_parses_root_question(self):
        self.assertEqual(parse_question_name(build_query(".")), ".")

    def test_accepts_63_byte_label(self):
        label = "a" * 63
        self.assertEqual(parse_question_name(build_query(f"{label}.example.test")), f"{label}.example.test")

    def test_rejects_short_header(self):
        with self.assertRaisesRegex(DNSFormatError, "header"):
            parse_question_name(b"\x00" * 11)

    def test_rejects_zero_questions(self):
        query = struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0)
        with self.assertRaisesRegex(DNSFormatError, "one question"):
            parse_question_name(query)

    def test_rejects_truncated_label(self):
        query = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x04abc"
        with self.assertRaisesRegex(DNSFormatError, "truncated"):
            parse_question_name(query)

    def test_rejects_compression_pointer_loop(self):
        query = (
            struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            + b"\xc0\x0c"
            + struct.pack("!HH", 1, 1)
        )
        with self.assertRaisesRegex(DNSFormatError, "loop"):
            parse_question_name(query)


class FramingTests(unittest.TestCase):
    def test_recv_frame_handles_one_byte_prefix_and_body_reads(self):
        reader, writer = socket.socketpair()
        payload = b"dns-payload"

        def write_bytes():
            for byte in struct.pack("!H", len(payload)) + payload:
                writer.sendall(bytes((byte,)))
            writer.close()

        thread = threading.Thread(target=write_bytes)
        thread.start()
        try:
            self.assertEqual(recv_frame(reader), payload)
        finally:
            reader.close()
            thread.join()

    def test_recv_frame_rejects_zero_length(self):
        reader, writer = socket.socketpair()
        writer.sendall(b"\x00\x00")
        writer.close()
        try:
            with self.assertRaisesRegex(DNSFormatError, "zero-length"):
                recv_frame(reader)
        finally:
            reader.close()

    def test_recv_frame_rejects_incomplete_payload(self):
        reader, writer = socket.socketpair()
        writer.sendall(b"\x00\x05abc")
        writer.close()
        try:
            with self.assertRaises(EOFError):
                recv_frame(reader)
        finally:
            reader.close()


class TruncatedResponseTests(unittest.TestCase):
    def test_truncated_response_preserves_id_question_and_rd(self):
        query = build_query("force-tcp.transport.example.test", transaction_id=0xBEEF)
        response = make_truncated_response(query)
        identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", response[:12]
        )
        self.assertEqual(identifier, 0xBEEF)
        self.assertEqual(flags & 0x8700, 0x8700)  # QR, AA, TC, RD
        self.assertEqual(flags & 0x0080, 0)  # no RA
        self.assertEqual((qdcount, ancount, nscount, arcount), (1, 0, 0, 0))
        self.assertEqual(response[12:], query[12:])


class ScenarioTests(unittest.TestCase):
    def test_scenario_mapping_is_exact(self):
        self.assertEqual(
            scenario_for("split-prefix.transport.example.test"), Scenario.SPLIT_PREFIX
        )
        self.assertEqual(scenario_for("bytewise.transport.example.test"), Scenario.BYTEWISE)
        self.assertEqual(scenario_for("prefix-split-prefix.transport.example.test"), Scenario.NORMAL)
        self.assertEqual(scenario_for("unknown.example.test"), Scenario.NORMAL)

    def test_normal_writes_one_complete_frame(self):
        sock = RecordingSocket()
        send_frame(sock, b"abcd", Scenario.NORMAL, delay_seconds=0)
        self.assertEqual(sock.calls, [b"\x00\x04abcd"])

    def test_split_prefix_writes_prefix_bytes_separately(self):
        sock = RecordingSocket()
        send_frame(sock, b"abcd", Scenario.SPLIT_PREFIX, delay_seconds=0)
        self.assertEqual(sock.calls, [b"\x00", b"\x04", b"abcd"])

    def test_split_body_writes_64_byte_chunks(self):
        sock = RecordingSocket()
        payload = b"x" * 130
        send_frame(sock, payload, Scenario.SPLIT_BODY, delay_seconds=0)
        self.assertEqual([len(call) for call in sock.calls], [2, 64, 64, 2])

    def test_bytewise_writes_every_frame_byte_separately(self):
        sock = RecordingSocket()
        send_frame(sock, b"abc", Scenario.BYTEWISE, delay_seconds=0)
        self.assertEqual(sock.calls, [b"\x00", b"\x03", b"a", b"b", b"c"])

    def test_close_scenarios_write_only_the_documented_prefix(self):
        before = RecordingSocket()
        send_frame(before, b"abcd", Scenario.CLOSE_BEFORE_RESPONSE, 0)
        self.assertEqual(before.calls, [])

        after_prefix = RecordingSocket()
        send_frame(after_prefix, b"abcd", Scenario.CLOSE_AFTER_PREFIX, 0)
        self.assertEqual(after_prefix.calls, [b"\x00\x04"])

        mid_body = RecordingSocket()
        send_frame(mid_body, b"abcdef", Scenario.CLOSE_MID_BODY, 0)
        self.assertEqual(mid_body.calls, [b"\x00\x06", b"abc"])

    def test_length_mismatch_declares_sixteen_extra_bytes(self):
        sock = RecordingSocket()
        send_frame(sock, b"abcdef", Scenario.LENGTH_MISMATCH, 0)
        self.assertEqual(sock.calls, [b"\x00\x16", b"abc"])

    def test_duplicate_and_trailing_scenarios_are_bounded(self):
        duplicate = RecordingSocket()
        send_frame(duplicate, b"ab", Scenario.DUPLICATE_RESPONSE, 0)
        self.assertEqual(duplicate.calls, [b"\x00\x02ab", b"\x00\x02ab"])

        trailing = RecordingSocket()
        send_frame(trailing, b"ab", Scenario.TRAILING_BYTES, 0)
        self.assertEqual(trailing.calls, [b"\x00\x02ab", b"DNSLAB-TRAILING"])


class HealthTests(unittest.TestCase):
    def test_health_response_requires_matching_id_qr_and_aa(self):
        query = build_query("normal.transport.example.test", transaction_id=0x6313)
        response = bytearray(make_truncated_response(query))
        response[2:4] = struct.pack("!H", 0x8500)  # QR, AA, RD; not truncated
        validate_health_response(bytes(response), 0x6313)

        with self.assertRaisesRegex(DNSFormatError, "transaction"):
            validate_health_response(bytes(response), 0x9999)

        response[2:4] = struct.pack("!H", 0x8100)  # QR and RD, no AA
        with self.assertRaisesRegex(DNSFormatError, "authoritative"):
            validate_health_response(bytes(response), 0x6313)


class OpcodeDispatchTests(unittest.TestCase):
    def test_zero_question_iquery_udp_reaches_upstream(self):
        query = dns.message.Message(700)
        query.set_opcode(1)
        query.answer.append(dns.rrset.from_text(".", 0, "IN", "A", "192.0.2.10"))
        response = dns.message.make_response(query)
        response.set_rcode(4)
        sent = []
        sock = SimpleNamespace(sendto=lambda payload, address: sent.append((payload, address)))
        server = SimpleNamespace(config=Config())
        client = ("127.0.0.1", 57000)
        with patch("dns_fault_proxy.forward_udp", return_value=response.to_wire()) as forward:
            _UDPHandler((query.to_wire(), sock), client, server)
        forward.assert_called_once_with(server.config, query.to_wire())
        self.assertEqual(sent, [(response.to_wire(), client)])

    def test_questionless_query_udp_preserves_upstream_cookie_response(self):
        query = dns.message.Message(702)
        query.use_edns(options=[dns.edns.CookieOption(b"12345678", b"")])
        response = dns.message.make_response(query)
        response.use_edns(options=[dns.edns.CookieOption(b"12345678", b"abcdefgh")])
        sent = []
        sock = SimpleNamespace(sendto=lambda payload, address: sent.append((payload, address)))
        server = SimpleNamespace(config=Config())
        client = ("127.0.0.1", 57001)
        with patch("dns_fault_proxy.forward_udp", return_value=response.to_wire()) as forward:
            _UDPHandler((query.to_wire(), sock), client, server)
        forward.assert_called_once_with(server.config, query.to_wire())
        self.assertEqual(sent, [(response.to_wire(), client)])


class ConnectionReuseTests(unittest.TestCase):
    """Exercise real framed socket I/O, including the proxy dispatch boundary."""

    zone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fresh.example.test."

    def setUp(self):
        class Backend(socketserver.BaseRequestHandler):
            def handle(self):
                query = dns.message.from_wire(recv_frame(self.request))
                response = dns.message.make_response(query)
                if query.opcode() != 0:
                    response.set_rcode(4)
                elif not query.question:
                    response.set_rcode(1)
                else:
                    response.flags |= dns.flags.AA
                    response.answer.append(dns.rrset.from_text(query.question[0].name, 0, "IN", "A", "192.0.2.99"))
                send_frame(self.request, response.to_wire(), Scenario.NORMAL, 0)

        self.backend = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Backend)
        config = Config(listen_host="127.0.0.1", listen_port=0, upstream_host="127.0.0.1",
                        upstream_port=self.backend.server_address[1], io_timeout_seconds=0.3,
                        chunk_delay_seconds=0)
        self.proxy = _make_server(_TCPServer, _TCPHandler, config, threading.BoundedSemaphore(4))
        self.threads = []
        for server in (self.backend, self.proxy):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            self.threads.append(thread)

    def tearDown(self):
        for server in (self.proxy, self.backend):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=1)

    def query(self, key, identifier):
        name = key if key.endswith(".") else f"{key}.{self.zone}"
        query = dns.message.make_query(name, "A")
        query.id = identifier
        return query

    def connect(self):
        return socket.create_connection(self.proxy.server_address, timeout=1)

    def framed(self, query):
        wire = query.to_wire()
        return struct.pack("!H", len(wire)) + wire

    def test_sequential_ordinary_queries_reuse_one_connection(self):
        with self.connect() as sock:
            for i, key in enumerate(("a", "normal.transport.example.test.", "persistent", "a")):
                query = self.query(key, i + 100)
                sock.sendall(self.framed(query))
                try:
                    response = dns.message.from_wire(recv_frame(sock))
                except (EOFError, ConnectionResetError):
                    self.fail(f"ordinary TCP connection closed before answering query {i + 1}")
                self.assertEqual(response.id, query.id)
                self.assertEqual(response.question, query.question)

    def test_pipelined_queries_work_in_both_dispatch_directions(self):
        for keys in (("a", "normal.transport.example.test.", "a"),
                     ("normal.transport.example.test.", "a", "normal.transport.example.test."),
                     ("persistent", "a", "a")):
            with self.subTest(keys=keys), self.connect() as sock:
                queries = [self.query(key, i + 200) for i, key in enumerate(keys)]
                sock.sendall(b"".join(self.framed(q) for q in queries))
                for query in queries:
                    try:
                        response = dns.message.from_wire(recv_frame(sock))
                    except (EOFError, ConnectionResetError):
                        self.fail(f"pipelined query {query.id} lost when TCP connection closed")
                    self.assertEqual(response.id, query.id)
                    self.assertEqual(response.question, query.question)

    def test_suffix_in_edns_option_does_not_misroute_legacy_question(self):
        query = self.query("normal.transport.example.test.", 300)
        query.use_edns(options=[dns.edns.GenericOption(65001, b"\x05fresh\x07example\x04test\x00")])
        with self.connect() as sock:
            sock.sendall(self.framed(query))
            response = dns.message.from_wire(recv_frame(sock))
            self.assertEqual(response.rcode(), 0)
            self.assertEqual(response.answer[0][0].address, "192.0.2.99")

    def test_fault_names_are_exact_and_close_scenarios_still_close(self):
        with self.connect() as sock:
            sock.sendall(self.framed(self.query("child.close-before", 400)))
            try:
                response = dns.message.from_wire(recv_frame(sock))
            except EOFError:
                self.fail("a descendant name accidentally triggered the close-before fault")
            self.assertEqual(response.id, 400)
        with self.connect() as sock:
            sock.sendall(self.framed(self.query("close-before", 401)))
            self.assertEqual(sock.recv(1), b"")
        with self.connect() as sock:
            sock.sendall(self.framed(self.query("close-prefix", 402)))
            prefix = sock.recv(2)
            self.assertEqual(len(prefix), 2)
            self.assertGreater(struct.unpack("!H", prefix)[0], 12)
            self.assertEqual(sock.recv(1), b"")

    def test_deliberate_duplicate_and_reordering_are_preserved(self):
        with self.connect() as sock:
            sock.sendall(self.framed(self.query("duplicate", 500)))
            self.assertEqual(recv_frame(sock), recv_frame(sock))
            self.assertEqual(sock.recv(1), b"")
        with self.connect() as sock:
            sock.sendall(b"".join(self.framed(self.query("reordered", i)) for i in (501, 502, 503)))
            self.assertEqual([dns.message.from_wire(recv_frame(sock)).id for _ in range(3)], [503, 502, 501])

    def test_split_request_framing_is_accepted(self):
        with self.connect() as sock:
            wire = self.framed(self.query("a", 600))
            for part in (wire[:1], wire[1:2], wire[2:11], wire[11:]):
                sock.sendall(part)
            self.assertEqual(dns.message.from_wire(recv_frame(sock)).id, 600)

    def test_zero_question_iquery_tcp_reaches_upstream(self):
        query = dns.message.Message(701)
        query.set_opcode(1)
        query.answer.append(dns.rrset.from_text(".", 0, "IN", "A", "192.0.2.10"))
        with self.connect() as sock:
            sock.sendall(self.framed(query))
            try:
                response = dns.message.from_wire(recv_frame(sock))
            except EOFError:
                self.fail("zero-question IQUERY was closed before reaching the upstream")
            self.assertEqual(response.id, query.id)
            self.assertEqual(response.opcode(), 1)
            self.assertEqual(response.rcode(), 4)
            self.assertEqual(response.question, [])

    def test_questionless_query_tcp_preserves_upstream_formerr(self):
        query = dns.message.Message(703)
        with self.connect() as sock:
            sock.sendall(self.framed(query))
            try:
                response = dns.message.from_wire(recv_frame(sock))
            except EOFError:
                self.fail("questionless QUERY was closed before reaching the upstream")
            self.assertEqual(response.id, query.id)
            self.assertEqual(response.opcode(), 0)
            self.assertEqual(response.rcode(), 1)
            self.assertEqual(response.question, [])


if __name__ == "__main__":
    unittest.main()
