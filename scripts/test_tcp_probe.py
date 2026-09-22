import importlib.util
import pathlib
import sys
import unittest


SCRIPT = pathlib.Path(__file__).with_name("tcp-probe.py")
SPEC = importlib.util.spec_from_file_location("tcp_probe", SCRIPT)


def load_probe():
    module = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = module
    SPEC.loader.exec_module(module)
    return module


class TcpProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_probe()

    def test_build_query_uses_requested_type_and_transaction(self):
        query = self.module.build_query("normal.transport.example.test", "TXT", 0x6313)
        self.assertEqual(query[:2], b"\x63\x13")
        self.assertEqual(query[-4:], b"\x00\x10\x00\x01")

    def test_parse_stream_extracts_two_complete_frames(self):
        data = b"\x00\x03one\x00\x03two"
        frames, trailing, expected = self.module.parse_frames(data)
        self.assertEqual(frames, [b"one", b"two"])
        self.assertEqual(trailing, b"")
        self.assertIsNone(expected)

    def test_parse_stream_reports_incomplete_declared_frame(self):
        frames, trailing, expected = self.module.parse_frames(b"\x00\x06abc")
        self.assertEqual(frames, [])
        self.assertEqual(trailing, b"\x00\x06abc")
        self.assertEqual(expected, 6)

    def test_evaluate_distinguishes_normal_duplicate_and_trailing(self):
        normal = self.module.Observation([b"one"], [5], True, False, b"", None, 10)
        duplicate = self.module.Observation(
            [b"one", b"one"], [5, 5], True, False, b"", None, 10
        )
        trailing = self.module.Observation(
            [b"one"], [5, 4], True, False, b"junk", 27_725, 10
        )
        self.module.evaluate(normal, "normal", 2)
        self.module.evaluate(duplicate, "duplicate-response", 2)
        self.module.evaluate(trailing, "trailing-bytes", 2)
        with self.assertRaisesRegex(AssertionError, "one frame"):
            self.module.evaluate(duplicate, "normal", 2)

    def test_evaluate_requires_visible_split_reads(self):
        split = self.module.Observation([b"one"], [1, 1, 3], True, False, b"", None, 20)
        self.module.evaluate(split, "split-prefix", 2)
        not_split = self.module.Observation([b"one"], [5], True, False, b"", None, 20)
        with self.assertRaisesRegex(AssertionError, "multiple reads"):
            self.module.evaluate(not_split, "split-prefix", 2)

    def test_evaluate_requires_timely_eof_after_complete_delivery(self):
        timed_out = self.module.Observation(
            [b"one"], [5], False, True, b"", None, 2_000
        )
        with self.assertRaisesRegex(AssertionError, "EOF"):
            self.module.evaluate(timed_out, "normal", 2)

        duplicate_timeout = self.module.Observation(
            [b"one", b"one"], [5, 5], False, True, b"", None, 2_000
        )
        with self.assertRaisesRegex(AssertionError, "EOF"):
            self.module.evaluate(duplicate_timeout, "duplicate-response", 2)

    def test_stall_requires_bounded_eof_instead_of_client_timeout(self):
        bounded = self.module.Observation([], [], True, False, b"", None, 2_050)
        self.module.evaluate(bounded, "stall", 2)
        timed_out = self.module.Observation([], [], False, True, b"", None, 4_000)
        with self.assertRaisesRegex(AssertionError, "EOF"):
            self.module.evaluate(timed_out, "stall", 2)

    def test_request_parts_cover_prefix_payload_and_bytewise_delivery(self):
        frame = b"\x00\x03abc"
        self.assertEqual(self.module.request_parts(frame, "whole"), [frame])
        self.assertEqual(
            self.module.request_parts(frame, "split-prefix"),
            [b"\x00", b"\x03", b"abc"],
        )
        self.assertEqual(
            self.module.request_parts(frame, "split-body"),
            [b"\x00\x03", b"a", b"bc"],
        )
        self.assertEqual(
            self.module.request_parts(frame, "bytewise"),
            [b"\x00", b"\x03", b"a", b"b", b"c"],
        )


if __name__ == "__main__":
    unittest.main()
