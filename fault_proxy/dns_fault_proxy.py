#!/usr/bin/env python3
"""Bounded DNS UDP/TCP forwarding proxy with deterministic transport faults."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import ipaddress
import json
import os
import signal
import socket
import socketserver
import struct
import threading
import time
from typing import Any


MAX_DNS_PAYLOAD = 65_535
MAX_TCP_QUERIES = 64
TRAILING_BYTES = b"DNSLAB-TRAILING"
LOOPBACK_CLIENTS = (ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128"))


class DNSFormatError(ValueError):
    pass


class Scenario(str, enum.Enum):
    NORMAL = "normal"
    FORCE_TCP = "force-tcp"
    SPLIT_PREFIX = "split-prefix"
    SPLIT_BODY = "split-body"
    BYTEWISE = "bytewise"
    DELAYED = "delayed"
    CLOSE_BEFORE_RESPONSE = "close-before-response"
    CLOSE_AFTER_PREFIX = "close-after-prefix"
    CLOSE_MID_BODY = "close-mid-body"
    LENGTH_MISMATCH = "length-mismatch"
    STALL = "stall"
    DUPLICATE_RESPONSE = "duplicate-response"
    TRAILING_BYTES = "trailing-bytes"


SCENARIO_BY_LABEL = {scenario.value: scenario for scenario in Scenario}


@dataclasses.dataclass(frozen=True)
class Config:
    listen_host: str = "::"
    listen_port: int = 5301
    upstream_host: str = "authoritative"
    upstream_port: int = 5353
    chunk_delay_seconds: float = 0.05
    stall_seconds: float = 2.0
    io_timeout_seconds: float = 5.0
    max_sessions: int = 64
    healthcheck_host: str = "::1"
    allowed_clients: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = LOOPBACK_CLIENTS

    @classmethod
    def from_env(cls) -> "Config":
        listen_host = os.getenv("LISTEN_HOST", "::")
        config = cls(
            listen_host=listen_host,
            listen_port=_bounded_int("LISTEN_PORT", 5301, 1, 65_535),
            upstream_host=os.getenv("UPSTREAM_HOST", "authoritative"),
            upstream_port=_bounded_int("UPSTREAM_PORT", 5353, 1, 65_535),
            chunk_delay_seconds=_bounded_float("CHUNK_DELAY_MS", 50, 0, 10_000)
            / 1000,
            stall_seconds=_bounded_float("STALL_SECONDS", 2, 0, 60),
            io_timeout_seconds=_bounded_float("IO_TIMEOUT_SECONDS", 5, 0.1, 60),
            max_sessions=_bounded_int("MAX_SESSIONS", 64, 1, 1024),
            healthcheck_host=os.getenv(
                "HEALTHCHECK_HOST", "::1" if ":" in listen_host else "127.0.0.1"
            ),
            allowed_clients=_allowed_clients(os.getenv("DNS_ALLOWED_CLIENTS", "127.0.0.1/32,::1/128")),
        )
        if not config.upstream_host:
            raise SystemExit("UPSTREAM_HOST must not be empty")
        return config


def _allowed_clients(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    try:
        networks = tuple(ipaddress.ip_network(item.strip(), strict=False) for item in value.split(","))
        if any(network.prefixlen == 0 for network in networks):
            raise ValueError("unrestricted networks are not allowed")
    except ValueError as exc:
        raise SystemExit("DNS_ALLOWED_CLIENTS must list explicit IP addresses or CIDRs, without /0 networks") from exc
    # Container-local health checks remain possible even when only remote clients are listed.
    return (*LOOPBACK_CLIENTS, *networks)


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise SystemExit(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}")
    return value


def build_query(qname: str, qtype: int = 1, transaction_id: int = 0x6313) -> bytes:
    if not 0 <= transaction_id <= 0xFFFF:
        raise DNSFormatError("transaction ID is out of range")
    if not 0 <= qtype <= 0xFFFF:
        raise DNSFormatError("query type is out of range")
    stripped = qname.rstrip(".")
    encoded_name = bytearray()
    if stripped:
        for label in stripped.split("."):
            try:
                encoded = label.encode("ascii")
            except UnicodeEncodeError as exc:
                raise DNSFormatError("query labels must be ASCII") from exc
            if not 1 <= len(encoded) <= 63:
                raise DNSFormatError("query label length must be 1..63")
            encoded_name.append(len(encoded))
            encoded_name.extend(encoded)
    encoded_name.append(0)
    if len(encoded_name) > 255:
        raise DNSFormatError("encoded query name exceeds 255 bytes")
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return header + bytes(encoded_name) + struct.pack("!HH", qtype, 1)


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    end_offset: int | None = None
    visited: set[int] = set()

    for _ in range(128):
        if cursor >= len(message):
            raise DNSFormatError("truncated DNS name")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                raise DNSFormatError("compression pointer is out of bounds")
            if pointer in visited or pointer == cursor:
                raise DNSFormatError("compression pointer loop")
            visited.add(pointer)
            if end_offset is None:
                end_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise DNSFormatError("invalid DNS label length")
        cursor += 1
        if length == 0:
            if end_offset is None:
                end_offset = cursor
            name = "." if not labels else ".".join(labels)
            return name.lower(), end_offset
        if cursor + length > len(message):
            raise DNSFormatError("truncated DNS label")
        try:
            labels.append(message[cursor : cursor + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise DNSFormatError("DNS label is not ASCII") from exc
        cursor += length
    raise DNSFormatError("compression pointer loop or excessive depth")


def _question_end(message: bytes) -> tuple[str, int]:
    if len(message) < 12:
        raise DNSFormatError("DNS header is truncated")
    _, _, qdcount, _, _, _ = struct.unpack("!HHHHHH", message[:12])
    if qdcount != 1:
        raise DNSFormatError("exactly one question is required")
    qname, name_end = _decode_name(message, 12)
    question_end = name_end + 4
    if question_end > len(message):
        raise DNSFormatError("truncated DNS question")
    return qname, question_end


def parse_question_name(message: bytes) -> str:
    return _question_end(message)[0]


def scenario_for(qname: str) -> Scenario:
    labels = qname.lower().rstrip(".").split(".")
    if len(labels) == 4 and labels[1:] == ["transport", "example", "test"]:
        return SCENARIO_BY_LABEL.get(labels[0], Scenario.NORMAL)
    return Scenario.NORMAL


def _query_scenario(query: bytes) -> Scenario:
    # IQUERY and questionless QUERY (e.g. DNS Cookies) have no scenario name.
    # Let the upstream handle the complete message without activating faults.
    if len(query) >= 12:
        flags, questions = struct.unpack_from("!HH", query, 2)
        if flags & 0x7800 or questions == 0:
            return Scenario.NORMAL
    return scenario_for(parse_question_name(query))


def make_truncated_response(query: bytes) -> bytes:
    if len(query) >= 12 and struct.unpack("!H", query[10:12])[0]:
        import dns.flags
        import dns.message
        response = dns.message.make_response(dns.message.from_wire(query))
        response.flags |= dns.flags.TC | dns.flags.AA
        return response.to_wire()
    _, question_end = _question_end(query)
    identifier, query_flags, _, _, _, _ = struct.unpack("!HHHHHH", query[:12])
    response_flags = 0x8600 | (query_flags & 0x0100)  # QR, AA, TC, optional RD
    header = struct.pack("!HHHHHH", identifier, response_flags, 1, 0, 0, 0)
    return header + query[12:question_end]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = sock.recv(size - len(received))
        if not chunk:
            raise EOFError(f"connection closed with {size - len(received)} bytes missing")
        received.extend(chunk)
    return bytes(received)


def recv_frame(sock: socket.socket) -> bytes:
    length = struct.unpack("!H", recv_exact(sock, 2))[0]
    if length == 0:
        raise DNSFormatError("zero-length DNS-over-TCP frame")
    return recv_exact(sock, length)


def _write_parts(sock: Any, parts: list[bytes], delay_seconds: float) -> None:
    for index, part in enumerate(parts):
        if part:
            sock.sendall(part)
        if delay_seconds and index + 1 < len(parts):
            time.sleep(delay_seconds)


def send_frame(
    sock: Any, payload: bytes, scenario: Scenario, delay_seconds: float
) -> None:
    if not 1 <= len(payload) <= MAX_DNS_PAYLOAD:
        raise DNSFormatError("response payload length is outside 1..65535")
    prefix = struct.pack("!H", len(payload))
    frame = prefix + payload

    if scenario in (Scenario.NORMAL, Scenario.FORCE_TCP):
        _write_parts(sock, [frame], delay_seconds)
    elif scenario == Scenario.SPLIT_PREFIX:
        _write_parts(sock, [prefix[:1], prefix[1:], payload], delay_seconds)
    elif scenario == Scenario.SPLIT_BODY:
        _write_parts(
            sock, [prefix] + [payload[i : i + 64] for i in range(0, len(payload), 64)], delay_seconds
        )
    elif scenario == Scenario.BYTEWISE:
        _write_parts(sock, [frame[i : i + 1] for i in range(len(frame))], delay_seconds)
    elif scenario == Scenario.DELAYED:
        _write_parts(
            sock, [prefix] + [payload[i : i + 256] for i in range(0, len(payload), 256)], delay_seconds
        )
    elif scenario in (Scenario.CLOSE_BEFORE_RESPONSE, Scenario.STALL):
        return
    elif scenario == Scenario.CLOSE_AFTER_PREFIX:
        _write_parts(sock, [prefix], delay_seconds)
    elif scenario == Scenario.CLOSE_MID_BODY:
        _write_parts(sock, [prefix, payload[: len(payload) // 2]], delay_seconds)
    elif scenario == Scenario.LENGTH_MISMATCH:
        declared_length = min(MAX_DNS_PAYLOAD, len(payload) + 16)
        _write_parts(
            sock,
            [struct.pack("!H", declared_length), payload[: len(payload) // 2]],
            delay_seconds,
        )
    elif scenario == Scenario.DUPLICATE_RESPONSE:
        _write_parts(sock, [frame, frame], delay_seconds)
    elif scenario == Scenario.TRAILING_BYTES:
        _write_parts(sock, [frame, TRAILING_BYTES], delay_seconds)
    else:
        raise DNSFormatError(f"unsupported scenario: {scenario}")


def validate_health_response(response: bytes, transaction_id: int) -> None:
    if len(response) < 12:
        raise DNSFormatError("health response header is truncated")
    identifier, flags, _, _, _, _ = struct.unpack("!HHHHHH", response[:12])
    if identifier != transaction_id:
        raise DNSFormatError("health response transaction ID does not match")
    if not flags & 0x8000:
        raise DNSFormatError("health response is not a response")
    if not flags & 0x0400:
        raise DNSFormatError("health response is not authoritative")


def _validate_upstream_response(query: bytes, response: bytes) -> None:
    if len(response) < 12:
        raise DNSFormatError("upstream response header is truncated")
    if response[:2] != query[:2]:
        raise DNSFormatError("upstream response transaction ID does not match")


def forward_tcp(config: Config, query: bytes) -> bytes:
    with socket.create_connection(
        (config.upstream_host, config.upstream_port), config.io_timeout_seconds
    ) as upstream:
        upstream.settimeout(config.io_timeout_seconds)
        upstream.sendall(struct.pack("!H", len(query)) + query)
        response = recv_frame(upstream)
    _validate_upstream_response(query, response)
    return response


def forward_udp(config: Config, query: bytes) -> bytes:
    addresses = socket.getaddrinfo(
        config.upstream_host,
        config.upstream_port,
        type=socket.SOCK_DGRAM,
    )
    last_error: OSError | None = None
    for family, socktype, protocol, _, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as upstream:
                upstream.settimeout(config.io_timeout_seconds)
                upstream.sendto(query, address)
                response, _ = upstream.recvfrom(MAX_DNS_PAYLOAD)
            _validate_upstream_response(query, response)
            return response
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError("no upstream UDP addresses available")


def log_event(event: str, transport: str, scenario: Scenario, reason: str = "") -> None:
    allowed_reasons = {
        "",
        "complete",
        "overload",
        "format",
        "timeout",
        "eof",
        "network",
        "shutdown",
        "access",
    }
    bounded_reason = reason if reason in allowed_reasons else "network"
    print(
        json.dumps(
            {
                "event": event,
                "reason": bounded_reason,
                "scenario": scenario.value,
                "transport": transport,
            },
            sort_keys=True,
        ),
        flush=True,
    )


class _BoundedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True

    def verify_request(self, request: Any, client_address: Any) -> bool:
        address = ipaddress.ip_address(client_address[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        permitted = any(address in network for network in self.config.allowed_clients)
        if not permitted:
            log_event("rejected", self.transport_name, Scenario.NORMAL, "access")
        return permitted

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.session_gate.acquire(blocking=False):
            log_event("rejected", self.transport_name, Scenario.NORMAL, "overload")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.session_gate.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.session_gate.release()


class _TCPServer(_BoundedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    transport_name = "tcp"


class _UDPServer(_BoundedThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    transport_name = "udp"


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        from fresh_transport import is_fresh, serve_fresh_tcp

        config: Config = self.server.config
        self.request.settimeout(config.io_timeout_seconds)
        scenario = Scenario.NORMAL
        try:
            for _ in range(MAX_TCP_QUERIES):
                query = recv_frame(self.request)
                if is_fresh(query):
                    if not serve_fresh_tcp(self.request, query, config.chunk_delay_seconds, config.io_timeout_seconds):
                        return
                    continue
                scenario = _query_scenario(query)
                if scenario == Scenario.CLOSE_BEFORE_RESPONSE:
                    return
                if scenario == Scenario.STALL:
                    time.sleep(config.stall_seconds)
                    return
                response = forward_tcp(config, query)
                send_frame(self.request, response, scenario, config.chunk_delay_seconds)
                log_event("completed", "tcp", scenario, "complete")
                if scenario not in (Scenario.NORMAL, Scenario.FORCE_TCP):
                    return
        except DNSFormatError:
            log_event("failed", "tcp", scenario, "format")
        except socket.timeout:
            log_event("failed", "tcp", scenario, "timeout")
        except EOFError:
            log_event("failed", "tcp", scenario, "eof")
        except OSError:
            log_event("failed", "tcp", scenario, "network")


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        from fresh_transport import is_fresh

        query, sock = self.request
        config: Config = self.server.config
        scenario = Scenario.NORMAL
        try:
            if is_fresh(query):
                from fresh_fixtures import answer_fresh
                response = answer_fresh(query)
                if response:
                    sock.sendto(response, self.client_address)
                return
            scenario = _query_scenario(query)
            if scenario in (Scenario.CLOSE_BEFORE_RESPONSE, Scenario.STALL):
                return
            if scenario == Scenario.FORCE_TCP:
                response = make_truncated_response(query)
            else:
                if scenario == Scenario.DELAYED:
                    time.sleep(config.chunk_delay_seconds)
                response = forward_udp(config, query)
            sock.sendto(response, self.client_address)
            log_event("completed", "udp", scenario, "complete")
        except DNSFormatError:
            log_event("failed", "udp", scenario, "format")
        except socket.timeout:
            log_event("failed", "udp", scenario, "timeout")
        except OSError:
            log_event("failed", "udp", scenario, "network")


def _make_server(
    server_class: type[socketserver.BaseServer],
    handler_class: type[socketserver.BaseRequestHandler],
    config: Config,
    gate: threading.BoundedSemaphore,
) -> socketserver.BaseServer:
    address_family = socket.AF_INET6 if ":" in config.listen_host else socket.AF_INET
    concrete_class = type(
        f"Configured{server_class.__name__}",
        (server_class,),
        {"address_family": address_family},
    )
    server = concrete_class((config.listen_host, config.listen_port), handler_class)
    server.config = config
    server.session_gate = gate
    if address_family == socket.AF_INET6:
        try:
            server.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
    return server


def run(config: Config) -> None:
    gate = threading.BoundedSemaphore(config.max_sessions)
    tcp_server = _make_server(_TCPServer, _TCPHandler, config, gate)
    udp_server = _make_server(_UDPServer, _UDPHandler, config, gate)
    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    threads = [
        threading.Thread(target=tcp_server.serve_forever, name="dns-tcp", daemon=True),
        threading.Thread(target=udp_server.serve_forever, name="dns-udp", daemon=True),
    ]
    for thread in threads:
        thread.start()
    print(
        json.dumps(
            {"event": "listening", "host": config.listen_host, "port": config.listen_port},
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        stop_event.wait()
    finally:
        tcp_server.shutdown()
        udp_server.shutdown()
        tcp_server.server_close()
        udp_server.server_close()
        for thread in threads:
            thread.join(timeout=config.io_timeout_seconds)
        log_event("stopped", "both", Scenario.NORMAL, "shutdown")


def run_healthcheck(config: Config) -> None:
    transaction_id = 0x6313
    query = build_query("normal.transport.example.test", transaction_id=transaction_id)
    addresses = socket.getaddrinfo(
        config.healthcheck_host,
        config.listen_port,
        type=socket.SOCK_DGRAM,
    )
    for family, socktype, protocol, _, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as health_socket:
                health_socket.settimeout(config.io_timeout_seconds)
                health_socket.sendto(query, address)
                response, _ = health_socket.recvfrom(4096)
            validate_health_response(response, transaction_id)
            return
        except (OSError, DNSFormatError):
            continue
    raise SystemExit("DNS fault proxy healthcheck failed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    config = Config.from_env()
    if args.healthcheck:
        run_healthcheck(config)
    else:
        run(config)


if __name__ == "__main__":
    main()
