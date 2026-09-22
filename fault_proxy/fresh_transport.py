"""Explicit fresh-fixture transport stimuli, independent of normal DNS data."""
import socket
import struct
import time

import dns.exception
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass

from fresh_fixtures import SUFFIX, answer_fresh, fresh_key


def is_fresh(query):
    # Route using the question name, never an incidental suffix in EDNS/RDATA.
    if len(query) < 12 or struct.unpack_from("!H", query, 4)[0] == 0:
        return False
    try:
        name, _ = dns.name.from_wire(query, 12)
    except dns.exception.DNSException:
        return False
    return tuple(label.lower() for label in name.labels[-4:]) == SUFFIX


def _frame(payload):
    return struct.pack("!H", len(payload)) + payload


def _read(sock, size):
    out = bytearray()
    while len(out) < size:
        part = sock.recv(size - len(out))
        if not part:
            raise EOFError
        out.extend(part)
    return bytes(out)


def _next(sock):
    length = struct.unpack("!H", _read(sock, 2))[0]
    if length < 12:
        raise EOFError
    return _read(sock, length)


def _scenario(query):
    try:
        message = dns.message.from_wire(query)
        parsed = fresh_key(query)
        if (parsed is not None and len(message.question) == 1
                and len(message.question[0].name.labels) == 6
                and message.question[0].rdclass == dns.rdataclass.IN
                and message.opcode() == dns.opcode.QUERY):
            return parsed[0]
    except dns.exception.DNSException:
        pass
    return "ordinary"


def serve_fresh_tcp(sock, query, delay=0.01, timeout=5):
    """Send one response (or a named batch fault); return whether to reuse TCP."""
    key = _scenario(query)
    reply = answer_fresh(query, tcp=True)
    if not reply:
        return False
    frame = _frame(reply)
    if key == "close-before":
        return False
    if key == "stall":
        time.sleep(min(4, timeout))
        return False
    if key in ("reordered", "coalesced"):
        queries = [query, _next(sock), _next(sock)]
        frames = [_frame(answer_fresh(item, tcp=True)) for item in queries]
        sock.sendall(b"".join(reversed(frames) if key == "reordered" else frames))
        return False
    if key == "mismatch-id":
        changed = bytearray(reply)
        changed[0:2] = ((int.from_bytes(changed[:2], "big") + 1) & 65535).to_bytes(2, "big")
        frame = _frame(changed)
    if key == "mismatch-question":
        changed = bytearray(reply)
        if len(changed) > 13:
            changed[13] = ord("z")
        frame = _frame(changed)
    if key == "close-prefix":
        sock.sendall(frame[:2])
        return False
    if key == "close-body":
        sock.sendall(frame[:2 + len(reply) // 2])
        return False
    if key == "length-mismatch":
        sock.sendall(struct.pack("!H", len(reply) + 16) + reply)
        return False
    if key == "split-prefix":
        parts = [frame[:1], frame[1:2], frame[2:]]
    elif key == "split-body":
        parts = [frame[:2]] + [frame[i:i + 16] for i in range(2, len(frame), 16)]
    elif key == "bytewise":
        parts = [bytes([byte]) for byte in frame]
    else:
        parts = [frame]
    for index, part in enumerate(parts):
        sock.sendall(part)
        if index + 1 < len(parts):
            time.sleep(min(delay, 0.01))
    if key == "duplicate":
        sock.sendall(frame)
        return False
    if key == "trailing":
        sock.sendall(b"\x00\x10garbage")
        return False
    return key not in ("mismatch-id", "mismatch-question")
