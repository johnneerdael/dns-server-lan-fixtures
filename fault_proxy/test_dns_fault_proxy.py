import socket
import struct
import threading
import unittest

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


if __name__ == "__main__":
    unittest.main()
