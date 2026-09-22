#!/usr/bin/env python3
"""Observe DNS-over-TCP framing, EOF, segmentation, and trailing bytes."""

from __future__ import annotations

import argparse
import dataclasses
import json
import socket
import struct
import time


QTYPE = {"A": 1, "TXT": 16}
EXPECTATIONS = {
    "normal",
    "split-prefix",
    "split-body",
    "bytewise",
    "delayed",
    "eof-before-response",
    "eof-after-prefix",
    "eof-mid-body",
    "length-mismatch",
    "stall",
    "duplicate-response",
    "trailing-bytes",
}
REQUEST_PATTERNS = {"whole", "split-prefix", "split-body", "bytewise"}


@dataclasses.dataclass(frozen=True)
class Observation:
    frames: list[bytes]
    read_sizes: list[int]
    eof: bool
    timed_out: bool
    trailing: bytes
    incomplete_expected: int | None
    elapsed_ms: int


def build_query(name: str, qtype: str, transaction_id: int) -> bytes:
    labels = name.rstrip(".").split(".") if name.rstrip(".") else []
    wire_name = bytearray()
    for label in labels:
        encoded = label.encode("ascii")
        if not 1 <= len(encoded) <= 63:
            raise ValueError("DNS labels must contain 1..63 ASCII bytes")
        wire_name.append(len(encoded))
        wire_name.extend(encoded)
    wire_name.append(0)
    if len(wire_name) > 255:
        raise ValueError("encoded DNS name exceeds 255 bytes")
    try:
        type_number = QTYPE[qtype.upper()]
    except KeyError as exc:
        raise ValueError(f"unsupported probe query type: {qtype}") from exc
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + bytes(wire_name)
        + struct.pack("!HH", type_number, 1)
    )


def parse_frames(data: bytes) -> tuple[list[bytes], bytes, int | None]:
    frames = []
    offset = 0
    while offset + 2 <= len(data):
        declared = struct.unpack("!H", data[offset : offset + 2])[0]
        frame_end = offset + 2 + declared
        if declared == 0 or frame_end > len(data):
            return frames, data[offset:], declared
        frames.append(data[offset + 2 : frame_end])
        offset = frame_end
    trailing = data[offset:]
    return frames, trailing, None if not trailing else None


def request_parts(frame: bytes, pattern: str) -> list[bytes]:
    if len(frame) < 3:
        raise ValueError("framed DNS request is too short")
    if pattern == "whole":
        return [frame]
    if pattern == "split-prefix":
        return [frame[:1], frame[1:2], frame[2:]]
    if pattern == "split-body":
        midpoint = 2 + max(1, (len(frame) - 2) // 2)
        return [frame[:2], frame[2:midpoint], frame[midpoint:]]
    if pattern == "bytewise":
        return [frame[index : index + 1] for index in range(len(frame))]
    raise ValueError(f"unknown request pattern: {pattern}")


def observe(
    host: str,
    port: int,
    query: bytes,
    timeout: float,
    request_pattern: str = "whole",
    request_delay: float = 0.01,
) -> Observation:
    framed_query = struct.pack("!H", len(query)) + query
    chunks = []
    read_sizes = []
    eof = False
    timed_out = False
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        parts = request_parts(framed_query, request_pattern)
        for index, part in enumerate(parts):
            connection.sendall(part)
            if request_delay and index + 1 < len(parts):
                time.sleep(request_delay)
        while True:
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                timed_out = True
                break
            if not chunk:
                eof = True
                break
            chunks.append(chunk)
            read_sizes.append(len(chunk))
    elapsed_ms = round((time.monotonic() - started) * 1000)
    frames, trailing, incomplete_expected = parse_frames(b"".join(chunks))
    return Observation(
        frames,
        read_sizes,
        eof,
        timed_out,
        trailing,
        incomplete_expected,
        elapsed_ms,
    )


def evaluate(observation: Observation, expectation: str, stall_seconds: float) -> None:
    if not observation.eof or observation.timed_out:
        raise AssertionError("expected EOF before the client timeout")
    if expectation == "normal":
        if len(observation.frames) != 1 or observation.trailing:
            raise AssertionError("normal response must contain exactly one frame and no trailing bytes")
    elif expectation in {"split-prefix", "split-body", "bytewise", "delayed"}:
        if len(observation.frames) != 1 or observation.trailing:
            raise AssertionError("split response must contain one complete frame")
        minimum_reads = 3 if expectation == "bytewise" else 2
        if len(observation.read_sizes) < minimum_reads:
            raise AssertionError("split response was not visible across multiple reads")
    elif expectation == "eof-before-response":
        if observation.frames or observation.trailing or not observation.eof:
            raise AssertionError("expected EOF before any response bytes")
    elif expectation == "eof-after-prefix":
        if observation.frames or len(observation.trailing) != 2 or not observation.eof:
            raise AssertionError("expected EOF immediately after the length prefix")
    elif expectation in {"eof-mid-body", "length-mismatch"}:
        if (
            observation.frames
            or len(observation.trailing) <= 2
            or observation.incomplete_expected is None
            or not observation.eof
        ):
            raise AssertionError("expected EOF with an incomplete declared payload")
    elif expectation == "stall":
        if observation.frames or observation.trailing:
            raise AssertionError("stall scenario must not return response bytes")
        if observation.elapsed_ms < stall_seconds * 900:
            raise AssertionError("stall scenario ended before its configured bound")
        if observation.elapsed_ms > stall_seconds * 1_500 + 500:
            raise AssertionError("stall scenario exceeded its configured bound")
    elif expectation == "duplicate-response":
        if len(observation.frames) != 2 or observation.trailing:
            raise AssertionError("duplicate scenario must return exactly two frames")
    elif expectation == "trailing-bytes":
        if len(observation.frames) != 1 or not observation.trailing:
            raise AssertionError("trailing scenario must return one frame plus bounded bytes")
    else:
        raise AssertionError(f"unknown expectation: {expectation}")


def as_json(observation: Observation) -> dict[str, object]:
    return {
        "elapsed_ms": observation.elapsed_ms,
        "eof": observation.eof,
        "frames": len(observation.frames),
        "incomplete_expected": observation.incomplete_expected,
        "payload_lengths": [len(frame) for frame in observation.frames],
        "read_sizes": observation.read_sizes,
        "timed_out": observation.timed_out,
        "trailing_bytes": len(observation.trailing),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--type", default="A")
    parser.add_argument("--expect", required=True, choices=sorted(EXPECTATIONS))
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--stall-seconds", type=float, default=2)
    parser.add_argument(
        "--request-pattern", default="whole", choices=sorted(REQUEST_PATTERNS)
    )
    parser.add_argument("--request-delay-ms", type=float, default=10)
    args = parser.parse_args()

    query = build_query(args.name, args.type, 0x6313)
    observation = observe(
        args.host,
        args.port,
        query,
        args.timeout,
        args.request_pattern,
        max(0, args.request_delay_ms) / 1000,
    )
    print(json.dumps(as_json(observation), sort_keys=True))
    try:
        evaluate(observation, args.expect, args.stall_seconds)
    except AssertionError as exc:
        raise SystemExit(f"probe expectation failed: {exc}") from exc


if __name__ == "__main__":
    main()
