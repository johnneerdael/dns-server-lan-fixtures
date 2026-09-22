"""Bounded fresh-fixture stream scenarios; separate from the legacy proxy."""
import socket
import struct
import time
from fresh_fixtures import answer_fresh, fresh_key

def is_fresh(query):
    return b"\x05fresh\x07example\x04test\x00" in query.lower()

def _frame(payload):
    return struct.pack("!H", len(payload)) + payload

def _read(sock, size):
    out = bytearray()
    while len(out) < size:
        part = sock.recv(size-len(out))
        if not part:
            raise EOFError
        out.extend(part)
    return bytes(out)

def _next(sock):
    length = struct.unpack("!H", _read(sock,2))[0]
    if length < 12:
        raise EOFError
    return _read(sock,length)

def serve_fresh_tcp(sock, first_query, delay=0.01, timeout=5):
    deadline = time.monotonic() + min(timeout, 8)
    query = first_query
    for _ in range(8):
        sock.settimeout(max(0.001,deadline-time.monotonic()))
        try:
            parsed = fresh_key(query)
        except Exception:
            parsed = None
        key = parsed[0] if parsed else "malformed"
        reply = answer_fresh(query,tcp=True)
        frame = _frame(reply)
        if key == "close-before":
            return
        if key == "stall":
            time.sleep(min(4, max(0,deadline-time.monotonic())))
            return
        if key in ("reordered","coalesced"):
            queries = [query,_next(sock),_next(sock)]
            frames = [_frame(answer_fresh(q,tcp=True)) for q in queries]
            sock.sendall(b"".join(reversed(frames) if key=="reordered" else frames))
            return
        if key == "mismatch-id":
            changed = bytearray(reply)
            changed[0:2] = ((int.from_bytes(changed[:2],"big")+1)&65535).to_bytes(2,"big")
            frame = _frame(changed)
        if key == "mismatch-question":
            changed = bytearray(reply)
            if len(changed)>13:
                changed[13] = ord("z")
            frame = _frame(changed)
        if key == "close-prefix":
            sock.sendall(frame[:2]); return
        if key == "close-body":
            sock.sendall(frame[:2+len(reply)//2]); return
        if key == "length-mismatch":
            sock.sendall(struct.pack("!H",len(reply)+16)+reply); return
        if key == "split-prefix":
            parts = [frame[:1],frame[1:2],frame[2:]]
        elif key == "split-body":
            parts = [frame[:2]]+[frame[i:i+16] for i in range(2,len(frame),16)]
        elif key == "bytewise":
            parts = [bytes([b]) for b in frame]
        else:
            parts = [frame]
        for i,part in enumerate(parts):
            sock.sendall(part)
            if i+1<len(parts):
                time.sleep(min(delay,0.01))
        if key == "duplicate":
            sock.sendall(frame); return
        if key == "trailing":
            sock.sendall(b"\x00\x10garbage"); return
        if key in ("mismatch-id","mismatch-question"):
            return
        if key not in ("persistent","pipeline"):
            return
        try:
            query = _next(sock)
        except (EOFError,socket.timeout):
            return
