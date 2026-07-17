#!/usr/bin/env python3
"""Deterministic, dependency-free harness for the private DNS-relay protocol.

The Docker fast path deliberately stops short of claiming a validated Urkel or
DNSSEC chain.  It exercises the cross-language wire format, Handshake framing
and capability negotiation, malicious-peer failover, connection reuse,
network-level port-53 isolation, raw DNS tuple checks, AD-bit distrust, a real
TLSA/certificate match, HTTPS, and the zero-contact legacy-DoH sentinel.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import contextlib
import dataclasses
import hashlib
import http.server
import json
import math
import os
import resource
import signal
import socket
import socketserver
import ssl
import statistics
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Iterable, Optional


REGTEST_MAGIC = 0xAE3895CF
PROTOCOL_VERSION = 3
NETWORK_SERVICE = 1
EXPERIMENTAL_DNS_RELAY_SERVICE = 0x40000000
VERSION_PACKET = 0
VERACK_PACKET = 1
PING_PACKET = 2
PONG_PACKET = 3
EXPERIMENTAL_GET_DNS_RELAY = 0xF0
EXPERIMENTAL_DNS_RELAY = 0xF1
MAX_FRAME = 8_000_000
MAX_QUERY = 4096
MAX_RESPONSE = 65_535

STATUS_OK = 0
STATUS_REFUSED = 1
STATUS_UNSUPPORTED = 2
STATUS_BUSY = 3
STATUS_INVALID_QUERY = 4
STATUS_RESOLVER_UNAVAILABLE = 5
STATUS_TIMEOUT = 6
STATUS_INTERNAL_ERROR = 7
KNOWN_STATUSES = set(range(8))

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_DNAME = 39
TYPE_DS = 43
TYPE_RRSIG = 46
TYPE_NSEC = 47
TYPE_DNSKEY = 48
TYPE_NSEC3 = 50
TYPE_NSEC3PARAM = 51
TYPE_TLSA = 52
TYPE_SVCB = 64
TYPE_HTTPS = 65
TYPE_CAA = 257
TYPE_OPT = 41
ALLOWED_QUERY_TYPES = {
    TYPE_A,
    TYPE_NS,
    TYPE_CNAME,
    TYPE_SOA,
    TYPE_MX,
    TYPE_TXT,
    TYPE_AAAA,
    TYPE_SRV,
    TYPE_DNAME,
    TYPE_DS,
    TYPE_RRSIG,
    TYPE_NSEC,
    TYPE_DNSKEY,
    TYPE_NSEC3,
    TYPE_NSEC3PARAM,
    TYPE_TLSA,
    TYPE_SVCB,
    TYPE_HTTPS,
    TYPE_CAA,
}

ARTIFACT_DIR = Path(os.environ.get("ARTIFACT_DIR", "/tmp/experimental-dns-relay"))
CERT_PATH = Path(os.environ.get("ORIGIN_CERT", ARTIFACT_DIR / "origin-cert.pem"))
KEY_PATH = Path(os.environ.get("ORIGIN_KEY", ARTIFACT_DIR / "origin-key.pem"))
SYNTHETIC_ROOT = "relaytest."


class HarnessError(Exception):
    """A deterministic test failure."""


class CodecError(HarnessError):
    """A malformed private relay packet."""


class DnsError(HarnessError):
    """A malformed or inadmissible DNS message."""


def _artifact_path(name: str) -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_DIR / name


def write_json(name: str, value: object) -> None:
    path = _artifact_path(name)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def append_event(role: str, event: str, **values: object) -> None:
    # Callers pass only aggregate/status data. Query names and raw DNS are never
    # accepted as fields in this helper.
    forbidden = {"qname", "query", "dns", "url", "headers"}
    if forbidden.intersection(values):
        raise HarnessError("privacy-sensitive event field rejected")
    record = {"time": round(time.time(), 3), "role": role, "event": event}
    record.update(values)
    with _artifact_path(f"{role}.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")


def mark_ready(role: str) -> None:
    _artifact_path(f"{role}.ready").write_text("ready\n", encoding="ascii")


def read_exact(stream: socket.socket, size: int) -> bytes:
    if size < 0:
        raise CodecError("negative read size")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(stream: socket.socket, packet_type: int, payload: bytes) -> None:
    if not 0 <= packet_type <= 0xFF:
        raise CodecError("packet type out of range")
    if len(payload) > MAX_FRAME:
        raise CodecError("frame too large")
    stream.sendall(struct.pack("<IBI", REGTEST_MAGIC, packet_type, len(payload)) + payload)


def receive_frame(stream: socket.socket) -> tuple[int, bytes]:
    header = read_exact(stream, 9)
    magic, packet_type, size = struct.unpack("<IBI", header)
    if magic != REGTEST_MAGIC:
        raise CodecError("wrong regtest frame magic")
    if size > MAX_FRAME:
        raise CodecError("frame length exceeds Handshake maximum")
    return packet_type, read_exact(stream, size)


def encode_version(services: int, agent: bytes = b"/relay-harness:1/") -> bytes:
    if len(agent) > 255:
        raise CodecError("version agent too long")
    now = int(time.time())
    remote = bytearray()
    remote += struct.pack("<QII", now, NETWORK_SERVICE, 0)
    remote += b"\x00"  # ordinary IP address, not an onion address
    remote += b"\x00" * 16
    remote += b"\x00" * 20
    remote += struct.pack("<H", 0)
    remote += b"\x00" * 33
    assert len(remote) == 88
    payload = bytearray(struct.pack("<IIIQ", PROTOCOL_VERSION, services, 0, now))
    payload += remote
    payload += b"HRNESST1"  # deterministic eight-byte nonce
    payload += bytes([len(agent)]) + agent
    payload += struct.pack("<IB", 1, 1)
    return bytes(payload)


def decode_version_services(payload: bytes) -> int:
    # Version's fixed prefix is 116 bytes followed by a one-byte agent length,
    # agent bytes, height, and no-relay byte.
    if len(payload) < 122:
        raise CodecError("truncated version")
    version, services, high_services = struct.unpack_from("<III", payload, 0)
    if version < 1:
        raise CodecError("unsupported version")
    if high_services != 0:
        raise CodecError("unexpected high service word")
    agent_length = payload[116]
    if len(payload) != 122 + agent_length:
        raise CodecError("malformed version length")
    return services


@dataclasses.dataclass(frozen=True)
class RelayRequest:
    request_id: int
    query: bytes

    def encode(self) -> bytes:
        if not 0 < self.request_id <= 0xFFFFFFFFFFFFFFFF:
            raise CodecError("request id must be nonzero u64")
        if len(self.query) > MAX_QUERY:
            raise CodecError("query too large")
        return struct.pack("<QH", self.request_id, len(self.query)) + self.query

    @staticmethod
    def decode(payload: bytes) -> "RelayRequest":
        if len(payload) < 10:
            raise CodecError("truncated relay request")
        request_id, size = struct.unpack_from("<QH", payload)
        if request_id == 0:
            raise CodecError("zero request id")
        if size > MAX_QUERY:
            raise CodecError("declared query too large")
        if len(payload) != 10 + size:
            raise CodecError("relay request length mismatch")
        return RelayRequest(request_id, payload[10:])


@dataclasses.dataclass(frozen=True)
class RelayResponse:
    request_id: int
    status: int
    response: bytes = b""

    def encode(self) -> bytes:
        if not 0 < self.request_id <= 0xFFFFFFFFFFFFFFFF:
            raise CodecError("response id must be nonzero u64")
        if self.status not in KNOWN_STATUSES:
            raise CodecError("unknown relay status")
        if len(self.response) > MAX_RESPONSE:
            raise CodecError("response too large")
        if self.status == STATUS_OK and not self.response:
            raise CodecError("OK response is empty")
        if self.status != STATUS_OK and self.response:
            raise CodecError("error response contains DNS bytes")
        return struct.pack("<QBH", self.request_id, self.status, len(self.response)) + self.response

    @staticmethod
    def decode(payload: bytes) -> "RelayResponse":
        if len(payload) < 11:
            raise CodecError("truncated relay response")
        request_id, status, size = struct.unpack_from("<QBH", payload)
        if request_id == 0:
            raise CodecError("zero response id")
        if status not in KNOWN_STATUSES:
            raise CodecError("unknown relay status")
        if size > MAX_RESPONSE:
            raise CodecError("declared response too large")
        if len(payload) != 11 + size:
            raise CodecError("relay response length mismatch")
        body = payload[11:]
        if status == STATUS_OK and not body:
            raise CodecError("OK response is empty")
        if status != STATUS_OK and body:
            raise CodecError("error response contains DNS bytes")
        return RelayResponse(request_id, status, body)


@dataclasses.dataclass(frozen=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int
    end: int


@dataclasses.dataclass(frozen=True)
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes


@dataclasses.dataclass(frozen=True)
class DnsMessage:
    identifier: int
    flags: int
    question: DnsQuestion
    answers: tuple[DnsRecord, ...]
    authorities: tuple[DnsRecord, ...]
    additionals: tuple[DnsRecord, ...]


def encode_name(name: str) -> bytes:
    canonical = name.rstrip(".")
    if not canonical:
        return b"\x00"
    result = bytearray()
    for label in canonical.split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise DnsError("invalid DNS label")
        result += bytes([len(encoded)]) + encoded
    result += b"\x00"
    if len(result) > 255:
        raise DnsError("DNS name too long")
    return bytes(result)


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset: Optional[int] = None
    visited: set[int] = set()
    jumps = 0
    wire_length = 1
    while True:
        if cursor >= len(message):
            raise DnsError("truncated DNS name")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise DnsError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message) or pointer in visited:
                raise DnsError("invalid compression pointer")
            visited.add(pointer)
            jumps += 1
            if jumps > 16:
                raise DnsError("too many compression jumps")
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise DnsError("unsupported DNS label kind")
        cursor += 1
        if length == 0:
            if next_offset is None:
                next_offset = cursor
            break
        if length > 63 or cursor + length > len(message):
            raise DnsError("invalid DNS label length")
        try:
            label = message[cursor : cursor + length].decode("ascii")
        except UnicodeDecodeError as error:
            raise DnsError("non-ASCII DNS label") from error
        labels.append(label.lower())
        cursor += length
        wire_length += length + 1
        if wire_length > 255:
            raise DnsError("expanded DNS name too long")
    return (".".join(labels) + "." if labels else "."), next_offset


def _read_record(message: bytes, offset: int) -> tuple[DnsRecord, int]:
    name, cursor = decode_name(message, offset)
    if cursor + 10 > len(message):
        raise DnsError("truncated DNS record")
    rtype, rclass, ttl, size = struct.unpack_from("!HHIH", message, cursor)
    cursor += 10
    if cursor + size > len(message):
        raise DnsError("truncated DNS rdata")
    record = DnsRecord(name, rtype, rclass, ttl, message[cursor : cursor + size])
    return record, cursor + size


def parse_dns_message(message: bytes) -> DnsMessage:
    if len(message) < 12:
        raise DnsError("truncated DNS header")
    identifier, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", message)
    if qd != 1:
        raise DnsError("DNS message must contain exactly one question")
    name, cursor = decode_name(message, 12)
    if cursor + 4 > len(message):
        raise DnsError("truncated DNS question")
    qtype, qclass = struct.unpack_from("!HH", message, cursor)
    cursor += 4
    question = DnsQuestion(name, qtype, qclass, cursor)
    sections: list[list[DnsRecord]] = [[], [], []]
    for section, count in zip(sections, (an, ns, ar)):
        for _ in range(count):
            record, cursor = _read_record(message, cursor)
            section.append(record)
    if cursor != len(message):
        raise DnsError("trailing DNS bytes")
    return DnsMessage(
        identifier,
        flags,
        question,
        tuple(sections[0]),
        tuple(sections[1]),
        tuple(sections[2]),
    )


def _validate_edns_options(rdata: bytes) -> None:
    cursor = 0
    while cursor < len(rdata):
        if cursor + 4 > len(rdata):
            raise DnsError("truncated EDNS option")
        option, size = struct.unpack_from("!HH", rdata, cursor)
        cursor += 4
        if cursor + size > len(rdata):
            raise DnsError("truncated EDNS option body")
        if option == 8:
            raise DnsError("EDNS Client Subnet is forbidden")
        cursor += size


def validate_relay_query(message: bytes) -> DnsMessage:
    if len(message) > MAX_QUERY:
        raise DnsError("DNS query too large")
    parsed = parse_dns_message(message)
    flags = parsed.flags
    if flags & 0x8000:
        raise DnsError("query has QR set")
    if (flags >> 11) & 0xF:
        raise DnsError("query opcode is not QUERY")
    if not flags & 0x0100:
        raise DnsError("recursive query requires RD")
    if not flags & 0x0010:
        raise DnsError("relay query requires CD")
    if parsed.question.qclass != 1:
        raise DnsError("query class is not IN")
    if parsed.question.qtype not in ALLOWED_QUERY_TYPES:
        raise DnsError("query type is not admitted")
    if parsed.answers or parsed.authorities:
        raise DnsError("query has answer or authority records")
    if not parsed.question.name.endswith(SYNTHETIC_ROOT):
        raise DnsError("query is not rooted in the synthetic HNS name")
    if parsed.question.name in {"localhost.", "local.", "invalid."}:
        raise DnsError("local infrastructure name refused")
    opt_records = [record for record in parsed.additionals if record.rtype == TYPE_OPT]
    if len(opt_records) != 1 or len(parsed.additionals) != 1:
        raise DnsError("exactly one EDNS OPT is required")
    opt = opt_records[0]
    if opt.name != "." or not opt.ttl & 0x8000:
        raise DnsError("EDNS DO is required")
    if opt.rclass > 4096:
        raise DnsError("EDNS UDP size too large")
    _validate_edns_options(opt.rdata)
    return parsed


def build_query(name: str, qtype: int, identifier: int = 0x1234, ecs: bool = False) -> bytes:
    flags = 0x0110  # RD + CD; local validation does not trust relay AD.
    question = encode_name(name) + struct.pack("!HH", qtype, 1)
    options = struct.pack("!HH", 8, 4) + b"\x00\x01\x00\x00" if ecs else b""
    opt = b"\x00" + struct.pack("!HHIH", TYPE_OPT, 1232, 0x8000, len(options)) + options
    return struct.pack("!HHHHHH", identifier, flags, 1, 0, 0, 1) + question + opt


def _answer_rdata(question: DnsQuestion) -> bytes:
    if question.qtype == TYPE_A:
        return socket.inet_aton(os.environ.get("ORIGIN_IP", "172.30.30.10"))
    if question.qtype == TYPE_TLSA:
        pem = CERT_PATH.read_text(encoding="ascii")
        der = ssl.PEM_cert_to_DER_cert(pem)
        digest = hashlib.sha256(der).digest()
        return b"\x03\x00\x01" + digest  # DANE-EE, full cert, SHA-256.
    return b"harness"


def build_dns_response(query: bytes, *, mismatch: bool = False, truncated: bool = False) -> bytes:
    parsed = validate_relay_query(query)
    qname = "wrong.relaytest." if mismatch else parsed.question.name
    question = encode_name(qname) + struct.pack("!HH", parsed.question.qtype, 1)
    # Deliberately preserve/set AD to prove the client does not use it as a
    # trust signal. TC is returned over UDP so the relay must retry over TCP.
    flags = 0x81B0 | (0x0200 if truncated else 0)
    answer_count = 0 if truncated else 1
    header = struct.pack("!HHHHHH", parsed.identifier, flags, 1, answer_count, 0, 1)
    answer = b""
    if not truncated:
        rdata = _answer_rdata(parsed.question)
        answer = b"\xc0\x0c" + struct.pack(
            "!HHIH", parsed.question.qtype, 1, 60, len(rdata)
        ) + rdata
    opt = b"\x00" + struct.pack("!HHIH", TYPE_OPT, 1232, 0x8000, 0)
    return header + question + answer + opt


def validate_dns_response(response: bytes, query: bytes) -> DnsMessage:
    if len(response) > MAX_RESPONSE:
        raise DnsError("DNS response too large")
    expected = validate_relay_query(query)
    actual = parse_dns_message(response)
    if actual.identifier != expected.identifier:
        raise DnsError("DNS response ID mismatch")
    if not actual.flags & 0x8000:
        raise DnsError("DNS response has QR clear")
    if (actual.flags >> 11) & 0xF:
        raise DnsError("DNS response opcode mismatch")
    if (
        actual.question.name,
        actual.question.qtype,
        actual.question.qclass,
    ) != (
        expected.question.name,
        expected.question.qtype,
        expected.question.qclass,
    ):
        raise DnsError("DNS response question mismatch")
    return actual


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class AuthoritativeState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.udp_queries = 0
        self.tcp_queries = 0
        self.invalid = 0

    def record(self, transport: str, valid: bool) -> None:
        with self.lock:
            if transport == "udp":
                self.udp_queries += 1
            else:
                self.tcp_queries += 1
            if not valid:
                self.invalid += 1
            write_json(
                "authoritative-dns.json",
                {
                    "udp_queries": self.udp_queries,
                    "tcp_queries": self.tcp_queries,
                    "invalid_queries": self.invalid,
                    "qnames_logged": 0,
                },
            )


def run_authoritative_dns() -> None:
    state = AuthoritativeState()
    port = int(os.environ.get("AUTH_DNS_PORT", "53"))

    class UdpHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            query, channel = self.request
            valid = True
            try:
                response = build_dns_response(query, truncated=True)
            except (DnsError, ValueError):
                valid = False
                response = b""
            state.record("udp", valid)
            if response:
                channel.sendto(response, self.client_address)

    class TcpHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            valid = True
            try:
                size = struct.unpack("!H", read_exact(self.request, 2))[0]
                query = read_exact(self.request, size)
                response = build_dns_response(query)
                self.request.sendall(struct.pack("!H", len(response)) + response)
            except (EOFError, OSError, DnsError, ValueError):
                valid = False
            state.record("tcp", valid)

    udp = ThreadingUDPServer(("0.0.0.0", port), UdpHandler)
    tcp = ThreadingTCPServer(("0.0.0.0", port), TcpHandler)
    write_json("authoritative-dns.json", {"udp_queries": 0, "tcp_queries": 0, "invalid_queries": 0, "qnames_logged": 0})
    mark_ready("authoritative-dns")
    append_event("authoritative-dns", "ready", udp_port=port, tcp_port=port)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    tcp.serve_forever()


class RelayState:
    def __init__(self, role: str) -> None:
        self.role = role
        self.lock = threading.Lock()
        self.pressure_condition = threading.Condition(self.lock)
        self.pressure_attempts: dict[str, int] = collections.defaultdict(int)
        self.tokens: dict[int, tuple[float, float]] = {}
        self.inflight: dict[int, int] = collections.defaultdict(int)
        self.global_inflight = 0
        self.max_global_inflight = 0
        self.max_peer_inflight = 0
        self.connections = 0
        self.requests = 0
        self.success = 0
        self.busy = 0
        self.concurrency_busy = 0
        self.rate_limited = 0
        self.rate_notices = 0
        self.rate_notice_suppressed = 0
        self.invalid = 0
        self.backend_udp = 0
        self.backend_tcp = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache: collections.OrderedDict[bytes, bytes] = collections.OrderedDict()
        self.cache_limit = int(os.environ.get("RELAY_CACHE_LIMIT", "128"))
        self.global_limit = int(os.environ.get("RELAY_GLOBAL_INFLIGHT", "32"))
        self.peer_limit = int(os.environ.get("RELAY_PEER_INFLIGHT", "16"))
        self.rate = float(os.environ.get("RELAY_RATE", "20"))
        self.burst = float(os.environ.get("RELAY_BURST", "40"))
        self.rate_notice_interval = float(os.environ.get("RELAY_RATE_NOTICE_INTERVAL", "1.0"))
        self.last_rate_notice: dict[int, float] = {}
        self.pressure_delay = float(os.environ.get("RELAY_PRESSURE_DELAY", "0"))
        self.pressure_gate_timeout = float(os.environ.get("RELAY_PRESSURE_GATE_TIMEOUT", "5"))

    def snapshot(self) -> dict[str, object]:
        return {
            "role": self.role,
            "connections": self.connections,
            "requests": self.requests,
            "success": self.success,
            "busy": self.busy,
            "concurrency_busy": self.concurrency_busy,
            "rate_limited": self.rate_limited,
            "rate_notices": self.rate_notices,
            "rate_notice_suppressed": self.rate_notice_suppressed,
            "rate_notice_interval": self.rate_notice_interval,
            "invalid": self.invalid,
            "backend_udp": self.backend_udp,
            "backend_tcp": self.backend_tcp,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_entries": len(self.cache),
            "cache_limit": self.cache_limit,
            "global_inflight": self.global_inflight,
            "max_global_inflight": self.max_global_inflight,
            "max_peer_inflight": self.max_peer_inflight,
            "global_limit": self.global_limit,
            "peer_limit": self.peer_limit,
            "qnames_logged": 0,
        }

    def persist(self) -> None:
        write_json(f"{self.role}-metrics.json", self.snapshot())

    def connection_opened(self) -> None:
        with self.lock:
            self.connections += 1
            self.persist()

    def connection_closed(self, connection: int) -> None:
        with self.lock:
            self.tokens.pop(connection, None)
            self.last_rate_notice.pop(connection, None)
            self.pressure_attempts.pop(f"peer:{connection}", None)
            self.inflight.pop(connection, None)
            self.persist()

    @staticmethod
    def pressure_spec(name: str, connection: int) -> Optional[tuple[str, int]]:
        # Fast-tier-only gates keep accepted workers live until the complete
        # pipelined batch has reached admission. Names remain in memory only.
        if name.startswith("peer-pressure-"):
            return (f"peer:{connection}", 24)
        if name.startswith("global-pressure-"):
            return ("global", 48)
        return None

    def begin(self, connection: int, name: str) -> str:
        now = time.monotonic()
        with self.lock:
            self.requests += 1
            pressure = self.pressure_spec(name, connection)
            if pressure is not None:
                key, expected = pressure
                self.pressure_attempts[key] += 1
                if self.pressure_attempts[key] >= expected:
                    self.pressure_condition.notify_all()
            tokens, previous = self.tokens.get(connection, (self.burst, now))
            tokens = min(self.burst, tokens + (now - previous) * self.rate)
            if tokens < 1:
                self.tokens[connection] = (tokens, now)
                self.rate_limited += 1
                last_notice = self.last_rate_notice.get(connection)
                if last_notice is None or now - last_notice >= self.rate_notice_interval:
                    self.last_rate_notice[connection] = now
                    self.rate_notices += 1
                    self.busy += 1
                    result = "rate-notice"
                else:
                    self.rate_notice_suppressed += 1
                    result = "rate-suppressed"
                self.persist()
                return result
            self.tokens[connection] = (tokens - 1, now)
            if self.inflight[connection] >= self.peer_limit or self.global_inflight >= self.global_limit:
                self.busy += 1
                self.concurrency_busy += 1
                self.persist()
                return "busy"
            self.inflight[connection] += 1
            self.global_inflight += 1
            self.max_peer_inflight = max(self.max_peer_inflight, self.inflight[connection])
            self.max_global_inflight = max(self.max_global_inflight, self.global_inflight)
            self.persist()
            return "accepted"

    def end(self, connection: int, success: bool = False, invalid: bool = False) -> None:
        with self.lock:
            self.inflight[connection] = max(0, self.inflight[connection] - 1)
            self.global_inflight = max(0, self.global_inflight - 1)
            self.success += int(success)
            self.invalid += int(invalid)
            self.persist()

    def resolve(self, query: bytes, connection: Optional[int] = None) -> bytes:
        question = validate_relay_query(query).question
        if connection is not None:
            pressure = self.pressure_spec(question.name, connection)
        else:
            pressure = None
        if pressure is not None:
            key, expected = pressure
            deadline = time.monotonic() + self.pressure_gate_timeout
            with self.pressure_condition:
                while self.pressure_attempts[key] < expected:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self.pressure_condition.wait(timeout=remaining)
        elif self.pressure_delay > 0 and question.name.startswith("failure-pressure-"):
            time.sleep(self.pressure_delay)
        with self.lock:
            cached = self.cache.get(query)
            if cached is not None:
                self.cache.move_to_end(query)
                self.cache_hits += 1
                self.persist()
                return cached
            self.cache_misses += 1
        address = (
            os.environ.get("AUTH_DNS_IP", "172.30.20.53"),
            int(os.environ.get("AUTH_DNS_PORT", "53")),
        )
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(float(os.environ.get("BACKEND_TIMEOUT", "1.0")))
        try:
            udp.sendto(query, address)
            response, _ = udp.recvfrom(MAX_RESPONSE)
            with self.lock:
                self.backend_udp += 1
        finally:
            udp.close()
        if len(response) < 4:
            raise DnsError("truncated backend UDP response")
        if struct.unpack_from("!H", response, 2)[0] & 0x0200:
            tcp = socket.create_connection(address, timeout=float(os.environ.get("BACKEND_TIMEOUT", "1.0")))
            try:
                tcp.settimeout(float(os.environ.get("BACKEND_TIMEOUT", "1.0")))
                tcp.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", read_exact(tcp, 2))[0]
                response = read_exact(tcp, size)
                with self.lock:
                    self.backend_tcp += 1
            finally:
                tcp.close()
        validate_dns_response(response, query)
        with self.lock:
            self.cache[query] = response
            self.cache.move_to_end(query)
            while len(self.cache) > self.cache_limit:
                self.cache.popitem(last=False)
            self.persist()
        return response


def _perform_server_handshake(stream: socket.socket, services: int) -> None:
    packet_type, payload = receive_frame(stream)
    if packet_type != VERSION_PACKET:
        raise CodecError("first packet is not version")
    decode_version_services(payload)
    send_frame(stream, VERACK_PACKET, b"")
    send_frame(stream, VERSION_PACKET, encode_version(services))
    packet_type, payload = receive_frame(stream)
    if packet_type != VERACK_PACKET or payload:
        raise CodecError("client did not complete handshake")


def _bad_mode_for(request_id: int) -> str:
    configured = os.environ.get("BAD_RELAY_MODE", "cycle")
    if configured != "cycle":
        return configured
    # The low byte is an explicit scripted selector. This keeps cases stable
    # even when the high request-ID bytes are randomized by a real client.
    return {0: "oversized", 1: "mismatch", 2: "disconnect", 3: "timeout", 4: "busy"}[(request_id & 0xFF) % 5]


def run_peer(role: str, port: int) -> None:
    capable = role in {"hsd-relay-good", "hsd-relay-bad"}
    services = NETWORK_SERVICE | (EXPERIMENTAL_DNS_RELAY_SERVICE if capable else 0)
    state = RelayState(role)

    class PeerHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            connection = id(self.request)
            send_lock = threading.Lock()
            worker_condition = threading.Condition()
            workers: set[threading.Thread] = set()
            live_request_ids: set[int] = set()

            def send(packet_type: int, payload: bytes) -> None:
                with send_lock:
                    send_frame(self.request, packet_type, payload)

            def release_request(request_id: int) -> None:
                with worker_condition:
                    live_request_ids.discard(request_id)

            def finish_worker(request_id: int) -> None:
                current = threading.current_thread()
                with worker_condition:
                    workers.discard(current)
                    live_request_ids.discard(request_id)
                    worker_condition.notify_all()

            def process_good_request(request: RelayRequest) -> None:
                success = False
                invalid = False
                try:
                    try:
                        response = state.resolve(request.query, connection)
                        relay = RelayResponse(request.request_id, STATUS_OK, response)
                        success = True
                    except (socket.timeout, TimeoutError):
                        relay = RelayResponse(request.request_id, STATUS_TIMEOUT)
                    except (DnsError, CodecError):
                        invalid = True
                        relay = RelayResponse(request.request_id, STATUS_INTERNAL_ERROR)
                    except OSError:
                        relay = RelayResponse(request.request_id, STATUS_RESOLVER_UNAVAILABLE)
                    except Exception:
                        invalid = True
                        relay = RelayResponse(request.request_id, STATUS_INTERNAL_ERROR)
                    finally:
                        state.end(connection, success=success, invalid=invalid)
                    with contextlib.suppress(OSError):
                        send(EXPERIMENTAL_DNS_RELAY, relay.encode())
                finally:
                    finish_worker(request.request_id)

            def start_worker(request: RelayRequest) -> None:
                worker = threading.Thread(
                    target=process_good_request,
                    args=(request,),
                    daemon=True,
                )
                with worker_condition:
                    workers.add(worker)
                try:
                    worker.start()
                except Exception:
                    with worker_condition:
                        workers.discard(worker)
                        live_request_ids.discard(request.request_id)
                        worker_condition.notify_all()
                    state.end(connection, invalid=True)
                    send(
                        EXPERIMENTAL_DNS_RELAY,
                        RelayResponse(request.request_id, STATUS_INTERNAL_ERROR).encode(),
                    )

            def drain_workers() -> None:
                with worker_condition:
                    while workers:
                        worker_condition.wait(timeout=0.1)

            self.request.settimeout(5)
            try:
                _perform_server_handshake(self.request, services)
                state.connection_opened()
                append_event(role, "handshake", relay_capable=capable)
                while True:
                    packet_type, payload = receive_frame(self.request)
                    if packet_type == PING_PACKET and len(payload) == 8:
                        send(PONG_PACKET, payload)
                        continue
                    if packet_type != EXPERIMENTAL_GET_DNS_RELAY:
                        append_event(role, "unknown_packet", packet_type=packet_type, size=len(payload))
                        continue
                    if not capable:
                        append_event(role, "accidental_relay_request", size=len(payload))
                        continue
                    try:
                        request = RelayRequest.decode(payload)
                        query_name = validate_relay_query(request.query).question.name
                    except (CodecError, DnsError):
                        request_id = struct.unpack_from("<Q", payload + b"\x00" * 8)[0] or 1
                        send(
                            EXPERIMENTAL_DNS_RELAY,
                            RelayResponse(request_id, STATUS_INVALID_QUERY).encode(),
                        )
                        continue
                    if role == "hsd-relay-bad":
                        mode = _bad_mode_for(request.request_id)
                        append_event(role, "scripted_failure", mode=mode)
                        if mode == "disconnect":
                            return
                        if mode == "timeout":
                            time.sleep(float(os.environ.get("BAD_TIMEOUT", "1.0")))
                            send(
                                EXPERIMENTAL_DNS_RELAY,
                                RelayResponse(request.request_id, STATUS_TIMEOUT).encode(),
                            )
                            continue
                        if mode == "busy":
                            send(
                                EXPERIMENTAL_DNS_RELAY,
                                RelayResponse(request.request_id, STATUS_BUSY).encode(),
                            )
                            continue
                        if mode == "oversized":
                            malformed = (
                                struct.pack("<QBH", request.request_id, STATUS_OK, MAX_RESPONSE)
                                + b"\x00" * MAX_RESPONSE
                                + b"\x00"
                            )
                            send(EXPERIMENTAL_DNS_RELAY, malformed)
                            continue
                        response = build_dns_response(request.query, mismatch=True)
                        send(
                            EXPERIMENTAL_DNS_RELAY,
                            RelayResponse(request.request_id, STATUS_OK, response).encode(),
                        )
                        continue
                    with worker_condition:
                        duplicate = request.request_id in live_request_ids
                        if not duplicate:
                            live_request_ids.add(request.request_id)
                    if duplicate:
                        send(
                            EXPERIMENTAL_DNS_RELAY,
                            RelayResponse(request.request_id, STATUS_INVALID_QUERY).encode(),
                        )
                        continue
                    admission = state.begin(connection, query_name)
                    if admission == "rate-suppressed":
                        release_request(request.request_id)
                        continue
                    if admission in {"busy", "rate-notice"}:
                        release_request(request.request_id)
                        send(
                            EXPERIMENTAL_DNS_RELAY,
                            RelayResponse(request.request_id, STATUS_BUSY).encode(),
                        )
                        continue
                    if admission != "accepted":
                        raise HarnessError("unknown relay admission result")
                    start_worker(request)
            except (EOFError, OSError, CodecError, socket.timeout):
                return
            finally:
                drain_workers()
                state.connection_closed(connection)

    if role == "hsd-relay-good":
        # Do not advertise readiness until both UDP and TCP backend access has
        # succeeded. The authoritative server intentionally truncates UDP.
        deadline = time.monotonic() + 20
        readiness_query = build_query("ready.relaytest.", TYPE_A, 0xBEEF)
        while True:
            try:
                state.resolve(readiness_query)
                break
            except (OSError, DnsError, socket.timeout):
                if time.monotonic() >= deadline:
                    raise HarnessError("good relay backend did not become ready")
                time.sleep(0.1)

    server = ThreadingTCPServer(("0.0.0.0", port), PeerHandler)
    state.persist()
    mark_ready(role)
    append_event(role, "ready", port=port, relay_capable=capable)
    server.serve_forever()


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        body = b"experimental-relay-origin-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        metrics = {"https_requests": 1, "request_paths_logged": 0, "request_headers_logged": 0}
        current = _artifact_path("origin-server.json")
        if current.exists():
            with contextlib.suppress(Exception):
                metrics["https_requests"] += json.loads(current.read_text())["https_requests"]
        write_json("origin-server.json", metrics)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def run_origin() -> None:
    port = int(os.environ.get("ORIGIN_PORT", "443"))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), OriginHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_PATH, KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    write_json("origin-server.json", {"https_requests": 0, "request_paths_logged": 0, "request_headers_logged": 0})
    mark_ready("origin-server")
    append_event("origin-server", "ready", port=port)
    server.serve_forever()


class SentinelState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.contacts = 0

    def contact(self) -> None:
        with self.lock:
            self.contacts += 1
            self.persist()

    def persist(self) -> None:
        write_json(
            "third-party-sentinel.json",
            {"contacts": self.contacts, "request_paths_logged": 0, "request_headers_logged": 0},
        )


def run_sentinel() -> None:
    state = SentinelState()
    port = int(os.environ.get("SENTINEL_PORT", "443"))

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            state.contact()
            with contextlib.suppress(OSError):
                self.request.sendall(b"HTTP/1.1 503 Sentinel\r\nContent-Length: 0\r\n\r\n")

    server = ThreadingTCPServer(("0.0.0.0", port), Handler)
    state.persist()
    mark_ready("third-party-sentinel")
    append_event("third-party-sentinel", "ready", port=port)
    server.serve_forever()


class RelayPeer:
    def __init__(self, host: str, port: int, timeout: float = 1.5) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket: Optional[socket.socket] = None
        self.services = 0
        self.pending: set[int] = set()
        self.requests = 0

    def connect(self) -> int:
        self.socket = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.socket.settimeout(self.timeout)
        send_frame(self.socket, VERSION_PACKET, encode_version(NETWORK_SERVICE, b"/relay-browser-test:1/"))
        got_version = False
        got_verack = False
        while not (got_version and got_verack):
            packet_type, payload = receive_frame(self.socket)
            if packet_type == VERACK_PACKET:
                if payload:
                    raise CodecError("verack payload is not empty")
                got_verack = True
            elif packet_type == VERSION_PACKET:
                self.services = decode_version_services(payload)
                got_version = True
                send_frame(self.socket, VERACK_PACKET, b"")
            else:
                raise CodecError("unexpected handshake packet")
        return self.services

    @property
    def relay_capable(self) -> bool:
        return bool(self.services & EXPERIMENTAL_DNS_RELAY_SERVICE)

    def exchange(self, request_id: int, query: bytes, timeout: Optional[float] = None) -> RelayResponse:
        responses = self.exchange_many([(request_id, query)], timeout=timeout)
        return responses[request_id]

    def exchange_many(
        self,
        requests: Iterable[tuple[int, bytes]],
        timeout: Optional[float] = None,
        *,
        allow_missing: bool = False,
        sent_event: Optional[threading.Event] = None,
    ) -> dict[int, RelayResponse]:
        if self.socket is None:
            raise HarnessError("peer is not connected")
        if not self.relay_capable:
            raise HarnessError("relay request withheld from incapable peer")
        batch = list(requests)
        request_ids = [request_id for request_id, _query in batch]
        if not batch:
            raise HarnessError("empty relay request batch")
        if (
            any(request_id == 0 or request_id in self.pending for request_id in request_ids)
            or len(set(request_ids)) != len(request_ids)
        ):
            raise HarnessError("request ID collision")
        self.pending.update(request_ids)
        self.requests += len(batch)
        previous_timeout = self.socket.gettimeout()
        self.socket.settimeout(timeout or self.timeout)
        responses: dict[int, RelayResponse] = {}
        exchange_complete = False
        try:
            for request_id, query in batch:
                send_frame(
                    self.socket,
                    EXPERIMENTAL_GET_DNS_RELAY,
                    RelayRequest(request_id, query).encode(),
                )
            if sent_event is not None:
                sent_event.set()
            while len(responses) < len(batch):
                try:
                    packet_type, payload = receive_frame(self.socket)
                except socket.timeout:
                    if allow_missing:
                        break
                    raise
                if packet_type != EXPERIMENTAL_DNS_RELAY:
                    raise CodecError("peer returned wrong packet type")
                response = RelayResponse.decode(payload)
                if response.request_id not in self.pending or response.request_id in responses:
                    raise CodecError("unsolicited or duplicate relay response")
                responses[response.request_id] = response
            if not allow_missing and len(responses) != len(batch):
                raise CodecError("relay response batch is incomplete")
            exchange_complete = len(responses) == len(batch)
            return responses
        finally:
            self.pending.difference_update(request_ids)
            if not exchange_complete:
                # A timed-out or malformed pipeline can still have replies in
                # flight.  Do not let those frames desynchronize a later batch
                # on the same connection.
                self.close()
            elif self.socket is not None:
                with contextlib.suppress(OSError):
                    self.socket.settimeout(previous_timeout)

    def close(self) -> None:
        if self.socket is not None:
            with contextlib.suppress(OSError):
                self.socket.close()
            self.socket = None

    def __enter__(self) -> "RelayPeer":
        self.connect()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def wait_for_ready(roles: Iterable[str], timeout: float = 30.0) -> None:
    pending = set(roles)
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        pending = {role for role in pending if not _artifact_path(f"{role}.ready").exists()}
        if pending:
            time.sleep(0.05)
    if pending:
        raise HarnessError("services not ready: " + ", ".join(sorted(pending)))


def probe_dns_blocked(host: str, query: bytes, timeout: float = 0.4) -> dict[str, bool]:
    udp_blocked = False
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    try:
        udp.sendto(query, (host, 53))
        udp.recvfrom(4096)
    except (OSError, socket.timeout):
        udp_blocked = True
    finally:
        udp.close()
    tcp_blocked = False
    try:
        channel = socket.create_connection((host, 53), timeout=timeout)
    except OSError:
        tcp_blocked = True
    else:
        channel.close()
    return {"udp53_blocked": udp_blocked, "tcp53_blocked": tcp_blocked}


def fetch_origin(address: str, tlsa_rdata: bytes) -> dict[str, object]:
    if len(tlsa_rdata) != 35 or tlsa_rdata[:3] != b"\x03\x00\x01":
        raise HarnessError("unexpected TLSA parameters")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((address, int(os.environ.get("ORIGIN_PORT", "443"))), timeout=2)
    try:
        tls = context.wrap_socket(raw, server_hostname="www.relaytest")
        certificate = tls.getpeercert(binary_form=True)
        if hashlib.sha256(certificate).digest() != tlsa_rdata[3:]:
            raise HarnessError("DANE TLSA certificate association mismatch")
        tls.sendall(b"GET / HTTP/1.1\r\nHost: www.relaytest\r\nConnection: close\r\n\r\n")
        response = bytearray()
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            response += chunk
    finally:
        raw.close()
    if not response.startswith(b"HTTP/1.1 200") or b"experimental-relay-origin-ok" not in response:
        raise HarnessError("HTTPS origin response was not successful")
    return {"tlsa_full_certificate_sha256_match": True, "https_status": 200}


def _answer_record(message: DnsMessage, rtype: int) -> DnsRecord:
    for record in message.answers:
        if record.rtype == rtype:
            return record
    raise HarnessError(f"DNS response omitted required type {rtype}")


def load_json_artifact(name: str) -> dict[str, object]:
    return json.loads(_artifact_path(name).read_text(encoding="utf-8"))


def run_e2e_client() -> None:
    roles = [
        "authoritative-dns",
        "origin-server",
        "third-party-sentinel",
        "hsd-proof",
        "hsd-relay-good",
        "hsd-relay-bad",
        "hsd-legacy",
    ]
    wait_for_ready(roles)
    query_a = build_query("www.relaytest.", TYPE_A)
    query_tlsa = build_query("_443._tcp.www.relaytest.", TYPE_TLSA, 0x1235)
    authoritative_ip = os.environ.get("AUTH_DNS_IP", "172.30.20.53")
    direct_started = time.perf_counter()
    authoritative_block = probe_dns_blocked(authoritative_ip, query_a)
    external_block = probe_dns_blocked(os.environ.get("EXTERNAL_DNS_PROBE", "1.1.1.1"), query_a)
    direct_failure_ms = (time.perf_counter() - direct_started) * 1000
    if not all(authoritative_block.values()):
        raise HarnessError("browser unexpectedly reached authoritative port 53")
    if not all(external_block.values()):
        raise HarnessError("browser unexpectedly reached external resolver egress")

    addresses = {
        "hsd-proof": (os.environ.get("PROOF_IP", "172.30.10.11"), 14038),
        "hsd-relay-good": (os.environ.get("GOOD_IP", "172.30.10.12"), 14039),
        "hsd-relay-bad": (os.environ.get("BAD_IP", "172.30.10.13"), 14040),
        "hsd-legacy": (os.environ.get("LEGACY_IP", "172.30.10.14"), 14041),
    }
    capability: dict[str, bool] = {}
    for role in ("hsd-proof", "hsd-legacy"):
        with RelayPeer(*addresses[role]) as peer:
            capability[role] = peer.relay_capable
            if peer.relay_capable:
                raise HarnessError(f"{role} unexpectedly advertised relay capability")
            if peer.requests != 0:
                raise HarnessError(f"relay request sent to {role}")

    bad_failure = ""
    with RelayPeer(*addresses["hsd-relay-bad"]) as bad:
        capability["hsd-relay-bad"] = bad.relay_capable
        if not bad.relay_capable:
            raise HarnessError("bad scripted peer did not advertise capability")
        response = bad.exchange(0x0102030405060701, query_a)
        if response.status != STATUS_OK:
            raise HarnessError("bad peer did not return the configured mismatched response")
        try:
            validate_dns_response(response.response, query_a)
        except DnsError as error:
            bad_failure = str(error)
        if bad_failure != "DNS response question mismatch":
            raise HarnessError("bad relay response was not rejected for question mismatch")

    relay_started = time.perf_counter()
    with RelayPeer(*addresses["hsd-relay-good"]) as good:
        capability["hsd-relay-good"] = good.relay_capable
        if not good.relay_capable:
            raise HarnessError("good peer did not advertise relay capability")
        a_response = good.exchange(0x0102030405060702, query_a)
        if a_response.status != STATUS_OK:
            raise HarnessError(f"good A relay failed with status {a_response.status}")
        a_message = validate_dns_response(a_response.response, query_a)
        address_record = _answer_record(a_message, TYPE_A)
        if len(address_record.rdata) != 4:
            raise HarnessError("malformed relayed A record")
        origin_address = socket.inet_ntoa(address_record.rdata)
        tlsa_response = good.exchange(0x0102030405060703, query_tlsa)
        if tlsa_response.status != STATUS_OK:
            raise HarnessError(f"good TLSA relay failed with status {tlsa_response.status}")
        tlsa_message = validate_dns_response(tlsa_response.response, query_tlsa)
        tlsa = _answer_record(tlsa_message, TYPE_TLSA)
        connection_reuse = good.requests == 2
        if not connection_reuse:
            raise HarnessError("good relay connection was not reused")
        if good.pending:
            raise HarnessError("pending relay request leaked")
    relay_latency_ms = (time.perf_counter() - relay_started) * 1000

    origin = fetch_origin(origin_address, tlsa.rdata)
    sentinel = load_json_artifact("third-party-sentinel.json")
    if sentinel.get("contacts") != 0:
        raise HarnessError("legacy third-party resolver sentinel was contacted")
    auth = load_json_artifact("authoritative-dns.json")
    relay_metrics = load_json_artifact("hsd-relay-good-metrics.json")
    if int(auth.get("udp_queries", 0)) < 1 or int(auth.get("tcp_queries", 0)) < 1:
        raise HarnessError("good relay did not exercise authoritative UDP and TCP")
    if int(relay_metrics.get("backend_udp", 0)) < 1 or int(relay_metrics.get("backend_tcp", 0)) < 1:
        raise HarnessError("good relay backend did not use UDP-to-TCP fallback")

    result = {
        "status": "pass",
        "tier": "deterministic-scripted-network",
        "protocol": {
            "regtest_magic": f"0x{REGTEST_MAGIC:08x}",
            "temporary_service": f"0x{EXPERIMENTAL_DNS_RELAY_SERVICE:08x}",
            "request_packet": f"0x{EXPERIMENTAL_GET_DNS_RELAY:02x}",
            "response_packet": f"0x{EXPERIMENTAL_DNS_RELAY:02x}",
        },
        "roles": {
            role: {"handshake_complete": True, "relay_capable": capability[role]}
            for role in sorted(capability)
        },
        "network_isolation": {
            "browser_to_authoritative": authoritative_block,
            "browser_external_resolver_egress": external_block,
            "good_relay_authoritative_udp_queries": auth["udp_queries"],
            "good_relay_authoritative_tcp_queries": auth["tcp_queries"],
        },
        "failover": {"bad_peer_rejection": bad_failure, "good_peer_selected": True},
        "transport": {
            "provenance": "p2p_dns_relay",
            "connection_reused": connection_reuse,
            "direct_failure_to_relay_ms": round(direct_failure_ms, 3),
            "relay_exchange_ms": round(relay_latency_ms, 3),
            "legacy_doh_sentinel_contacts": sentinel["contacts"],
        },
        "local_checks": {
            "dns_id_and_question_tuple": True,
            "relay_ad_observed": bool(a_message.flags & 0x0020),
            "relay_ad_trusted": False,
            **origin,
        },
        "full_stack_claims": {
            "current_hns_headers": False,
            "urkel_proof_validation": False,
            "delegated_dnssec_validation": False,
            "reason": "fast scripted tier has no deterministic regtest name-state snapshot",
        },
        "privacy": {
            "qnames_logged": 0,
            "raw_dns_logged": 0,
            "sentinel_request_paths_logged": sentinel["request_paths_logged"],
        },
    }
    write_json("e2e-result.json", result)
    print(json.dumps(result, sort_keys=True))


def percentile(samples: list[float], fraction: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def latency_summary(samples: list[float]) -> dict[str, float]:
    return {
        "median_ms": round(statistics.median(samples), 3) if samples else 0.0,
        "p95_ms": round(percentile(samples, 0.95), 3),
        "p99_ms": round(percentile(samples, 0.99), 3),
    }


def _one_good_request(request_id: int, name: str) -> tuple[float, int]:
    started = time.perf_counter()
    with RelayPeer(os.environ.get("GOOD_IP", "172.30.10.12"), 14039, timeout=1.5) as peer:
        response = peer.exchange(request_id, build_query(name, TYPE_A, request_id & 0xFFFF or 1))
        if response.status == STATUS_OK:
            validate_dns_response(response.response, build_query(name, TYPE_A, request_id & 0xFFFF or 1))
        if peer.pending:
            raise HarnessError("load client pending request leaked")
    return (time.perf_counter() - started) * 1000, response.status


def _pipelined_good_requests(
    name_prefix: str,
    first_request_id: int,
    count: int,
    sent_event: Optional[threading.Event] = None,
) -> tuple[float, list[int]]:
    batch: list[tuple[int, bytes]] = []
    queries: dict[int, bytes] = {}
    for number in range(count):
        request_id = first_request_id + number
        query = build_query(
            f"{name_prefix}-{number:03d}.relaytest.",
            TYPE_A,
            request_id & 0xFFFF or 1,
        )
        batch.append((request_id, query))
        queries[request_id] = query
    started = time.perf_counter()
    with RelayPeer(os.environ.get("GOOD_IP", "172.30.10.12"), 14039, timeout=7.0) as peer:
        responses = peer.exchange_many(batch, timeout=7.0, sent_event=sent_event)
        statuses = []
        for request_id, _query in batch:
            response = responses[request_id]
            statuses.append(response.status)
            if response.status == STATUS_OK:
                validate_dns_response(response.response, queries[request_id])
        if peer.pending:
            raise HarnessError("pipelined good-peer requests leaked pending state")
    return (time.perf_counter() - started) * 1000, statuses


def run_load_client() -> None:
    wait_for_ready(["hsd-relay-good", "hsd-relay-bad", "authoritative-dns"])
    before_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    scenarios: dict[str, object] = {}

    warm_latencies: list[float] = []
    with RelayPeer(os.environ.get("GOOD_IP", "172.30.10.12"), 14039) as peer:
        query = build_query("warm.relaytest.", TYPE_A, 0x2200)
        for number in range(16):
            started = time.perf_counter()
            response = peer.exchange(0x2000 + number, query)
            if response.status != STATUS_OK:
                raise HarnessError("warm-cache request failed")
            validate_dns_response(response.response, query)
            warm_latencies.append((time.perf_counter() - started) * 1000)
        if peer.pending:
            raise HarnessError("warm scenario pending request leaked")
    scenarios["warm_cache_identical"] = {"requests": 16, "connection_reused": True, **latency_summary(warm_latencies)}

    cold_latencies: list[float] = []
    cold_statuses: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(_one_good_request, 0x3000 + number, f"cold-{number:03d}.relaytest.")
            for number in range(24)
        ]
        for future in futures:
            latency, status = future.result()
            cold_latencies.append(latency)
            cold_statuses.append(status)
    if any(status != STATUS_OK for status in cold_statuses):
        raise HarnessError("cold-cache unique request failed")
    scenarios["cold_cache_unique"] = {"requests": 24, "concurrency": 8, **latency_summary(cold_latencies)}

    rate_before = load_json_artifact("hsd-relay-good-metrics.json")
    rate_batch_latencies: list[float] = []
    rate_statuses: list[int] = []
    rate_missing = 0
    with RelayPeer(os.environ.get("GOOD_IP", "172.30.10.12"), 14039) as peer:
        # Reuse the already-warm wire question. Five bounded pipelines consume
        # the deterministic 40-token burst without exercising concurrency
        # backpressure; the sixth observes one BUSY and seven suppressed replies.
        query = build_query("warm.relaytest.", TYPE_A, 0x2200)
        for batch_number in range(5):
            batch = [
                (0x4000 + batch_number * 8 + number, query)
                for number in range(8)
            ]
            started = time.perf_counter()
            responses = peer.exchange_many(batch)
            rate_batch_latencies.append((time.perf_counter() - started) * 1000)
            statuses = [responses[request_id].status for request_id, _query in batch]
            if any(status != STATUS_OK for status in statuses):
                raise HarnessError("rate-limit burst was exhausted before its documented bound")
            for request_id, _query in batch:
                validate_dns_response(responses[request_id].response, query)
            rate_statuses.extend(statuses)
        final_batch = [(0x4028 + number, query) for number in range(8)]
        started = time.perf_counter()
        final_responses = peer.exchange_many(final_batch, timeout=0.25, allow_missing=True)
        rate_batch_latencies.append((time.perf_counter() - started) * 1000)
        rate_statuses.extend(response.status for response in final_responses.values())
        rate_missing = len(final_batch) - len(final_responses)
        if peer.pending:
            raise HarnessError("rate-limit pipeline leaked pending state")
    rate_after = load_json_artifact("hsd-relay-good-metrics.json")
    rate_limited = int(rate_after["rate_limited"]) - int(rate_before["rate_limited"])
    rate_notices = int(rate_after["rate_notices"]) - int(rate_before["rate_notices"])
    rate_suppressed = int(rate_after["rate_notice_suppressed"]) - int(
        rate_before["rate_notice_suppressed"]
    )
    if (
        rate_statuses.count(STATUS_OK) != 40
        or rate_statuses.count(STATUS_BUSY) != 1
        or len(rate_statuses) != 41
        or rate_missing != 7
        or rate_limited != 8
        or rate_notices != 1
        or rate_suppressed != 7
    ):
        raise HarnessError("rate-limit notice suppression did not match the scripted bound")
    scenarios["bursty_single_client"] = {
        "requests": 48,
        "ok": 40,
        "busy_notices": 1,
        "suppressed_notices": 7,
        **latency_summary(rate_batch_latencies),
    }
    scenarios["rate_limit_abuse"] = {
        "burst": 40,
        "rate_limited": rate_limited,
        "busy_notices": rate_notices,
        "suppressed_notices": rate_suppressed,
        "notice_interval_seconds": rate_after["rate_notice_interval"],
    }

    many_latencies: list[float] = []
    many_statuses: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = [
            executor.submit(_one_good_request, 0x5000 + number, f"many-{number:03d}.relaytest.")
            for number in range(24)
        ]
        for future in futures:
            latency, status = future.result()
            many_latencies.append(latency)
            many_statuses.append(status)
    if any(status != STATUS_OK for status in many_statuses):
        raise HarnessError("ordinary concurrent-client request failed")
    scenarios["many_concurrent_clients"] = {
        "requests": 24,
        "ok": 24,
        "concurrency": 12,
        **latency_summary(many_latencies),
    }

    peer_pressure_ms, peer_pressure_statuses = _pipelined_good_requests(
        "peer-pressure", 0x7000, 24
    )
    if (
        peer_pressure_statuses.count(STATUS_OK) != 16
        or peer_pressure_statuses.count(STATUS_BUSY) != 8
    ):
        raise HarnessError("per-peer in-flight pressure did not reach the exact bound")
    scenarios["per_peer_inflight_pressure"] = {
        "requests": 24,
        "accepted": 16,
        "busy": 8,
        "limit_reached": 16,
        "elapsed_ms": round(peer_pressure_ms, 3),
    }

    global_pressure_statuses: list[int] = []
    global_pressure_latencies: list[float] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(
                _pipelined_good_requests,
                f"global-pressure-{client}",
                0x8000 + client * 0x100,
                12,
            )
            for client in range(4)
        ]
        for future in futures:
            elapsed, statuses = future.result()
            global_pressure_latencies.append(elapsed)
            global_pressure_statuses.extend(statuses)
    if (
        global_pressure_statuses.count(STATUS_OK) != 32
        or global_pressure_statuses.count(STATUS_BUSY) != 16
    ):
        raise HarnessError("global in-flight pressure did not reach the exact bound")
    scenarios["global_inflight_pressure"] = {
        "requests": 48,
        "accepted": 32,
        "busy": 16,
        "limit_reached": 32,
        **latency_summary(global_pressure_latencies),
    }

    bad_ip = os.environ.get("BAD_IP", "172.30.10.13")

    def wait_for_good_pressure(timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            metrics = load_json_artifact("hsd-relay-good-metrics.json")
            if int(metrics["global_inflight"]) > 0:
                return
            time.sleep(0.01)
        raise HarnessError("delayed good-peer pressure did not become active")

    def under_good_pressure(label: str, first_request_id: int, observer) -> dict[str, object]:
        sent = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            pressure = executor.submit(
                _pipelined_good_requests,
                f"failure-pressure-{label}",
                first_request_id,
                8,
                sent,
            )
            if not sent.wait(timeout=2.0):
                raise HarnessError("good-peer pressure pipeline was not sent")
            wait_for_good_pressure()
            observed = observer()
            pressure_elapsed, pressure_statuses = pressure.result()
        if any(status != STATUS_OK for status in pressure_statuses):
            raise HarnessError("good-peer pressure failed during bad-peer fault")
        return {
            **observed,
            "successful_pressure_requests": len(pressure_statuses),
            "pressure_elapsed_ms": round(pressure_elapsed, 3),
        }

    def observe_disconnect() -> dict[str, object]:
        peer = RelayPeer(bad_ip, 14040, timeout=0.5)
        observed = False
        try:
            peer.connect()
            try:
                peer.exchange(0x9002, build_query("disconnect.relaytest.", TYPE_A), timeout=0.5)
            except socket.timeout as error:
                raise HarnessError("disconnect scenario produced a timeout instead") from error
            except (EOFError, OSError):
                observed = True
        finally:
            peer.close()
        if not observed or peer.pending:
            raise HarnessError("scripted disconnect was not observed and cleaned up")
        return {"failure_observed": "disconnect", "pending_after_failure": 0}

    def observe_timeout() -> dict[str, object]:
        peer = RelayPeer(bad_ip, 14040, timeout=0.25)
        observed = False
        started = time.perf_counter()
        try:
            peer.connect()
            try:
                peer.exchange(0x9103, build_query("timeout.relaytest.", TYPE_A), timeout=0.25)
            except (socket.timeout, TimeoutError):
                observed = True
        finally:
            peer.close()
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not observed or elapsed_ms < 200 or peer.pending:
            raise HarnessError("scripted timeout was not observed and cleaned up")
        return {
            "failure_observed": "socket_timeout",
            "pending_after_failure": 0,
            "failure_elapsed_ms": round(elapsed_ms, 3),
        }

    def observe_oversized() -> dict[str, object]:
        peer = RelayPeer(bad_ip, 14040, timeout=1.0)
        observed = False
        try:
            peer.connect()
            try:
                peer.exchange(0x9205, build_query("oversized.relaytest.", TYPE_A))
            except CodecError:
                observed = True
        finally:
            peer.close()
        if not observed or peer.pending:
            raise HarnessError("scripted oversized response was not rejected and cleaned up")
        return {"failure_observed": "oversized_response", "pending_after_failure": 0}

    scenarios["relay_disconnect_under_load"] = under_good_pressure(
        "disconnect", 0xA000, observe_disconnect
    )
    scenarios["backend_timeout_under_load"] = under_good_pressure(
        "timeout", 0xA100, observe_timeout
    )
    scenarios["oversized_response_pressure"] = under_good_pressure(
        "oversized", 0xA200, observe_oversized
    )

    metrics = load_json_artifact("hsd-relay-good-metrics.json")
    if int(metrics["max_global_inflight"]) != int(metrics["global_limit"]):
        raise HarnessError("global in-flight bound was not reached exactly")
    if int(metrics["max_peer_inflight"]) != int(metrics["peer_limit"]):
        raise HarnessError("per-peer in-flight bound was not reached exactly")
    if int(metrics["global_inflight"]) != 0:
        raise HarnessError("good relay retained pending work after load")
    if int(metrics["cache_entries"]) > int(metrics["cache_limit"]):
        raise HarnessError("relay cache bound exceeded")
    after_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    rss_growth_kib = max(0, after_rss - before_rss)
    if rss_growth_kib > 64 * 1024:
        raise HarnessError("client RSS growth exceeded 64 MiB proof-of-concept guard")

    all_samples = warm_latencies + cold_latencies + many_latencies
    result = {
        "status": "pass",
        "tier": "scripted-load",
        "requests_measured": len(all_samples),
        "aggregate": latency_summary(all_samples),
        "rss_growth_kib": rss_growth_kib,
        "server_bounds": {
            "max_global_inflight": metrics["max_global_inflight"],
            "global_limit": metrics["global_limit"],
            "max_peer_inflight": metrics["max_peer_inflight"],
            "peer_limit": metrics["peer_limit"],
            "cache_entries": metrics["cache_entries"],
            "cache_limit": metrics["cache_limit"],
            "rate_notices": metrics["rate_notices"],
            "rate_notice_suppressed": metrics["rate_notice_suppressed"],
        },
        "scenarios": scenarios,
    }
    write_json("load-result.json", result)
    print(json.dumps(result, sort_keys=True))


def fixture_bytes(path: Path) -> bytes:
    try:
        return bytes.fromhex("".join(path.read_text(encoding="ascii").split()))
    except ValueError as error:
        raise HarnessError(f"fixture is not hex: {path}") from error


def fixture_codec_valid(name: str, payload: bytes) -> bool:
    try:
        if name.startswith("request-"):
            RelayRequest.decode(payload)
        elif name.startswith("response-"):
            RelayResponse.decode(payload)
        elif name in {"malformed-length.hex", "trailing-bytes.hex", "oversized-request.hex"}:
            RelayRequest.decode(payload)
        else:
            RelayResponse.decode(payload)
        return True
    except CodecError:
        return False


def run_selftest(browser_fixtures: Path, hsd_fixtures: Path) -> None:
    browser_manifest = json.loads((browser_fixtures / "manifest.json").read_text(encoding="utf-8"))
    hsd_manifest = json.loads((hsd_fixtures / "manifest.json").read_text(encoding="utf-8"))
    if browser_manifest != hsd_manifest:
        raise HarnessError("browser and hsd fixture manifests differ")
    if browser_manifest["temporary_service_bit"] != "0x40000000":
        raise HarnessError("fixture service bit differs from harness")
    if browser_manifest["temporary_request_packet"] != "0xf0" or browser_manifest["temporary_response_packet"] != "0xf1":
        raise HarnessError("fixture packet IDs differ from harness")
    checked = 0
    for item in browser_manifest["fixtures"]:
        name = item["file"]
        left = (browser_fixtures / name).read_bytes()
        right = (hsd_fixtures / name).read_bytes()
        if left != right:
            raise HarnessError(f"cross-repository fixture differs: {name}")
        payload = fixture_bytes(browser_fixtures / name)
        if len(payload) != item["wire_bytes"]:
            raise HarnessError(f"fixture length mismatch: {name}")
        if hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise HarnessError(f"fixture digest mismatch: {name}")
        if fixture_codec_valid(name, payload) != item["valid"]:
            raise HarnessError(f"fixture validity mismatch: {name}")
        checked += 1
    # Local protocol/admission checks supplement both language codec tests.
    query = build_query("www.relaytest.", TYPE_A)
    for query_type in ALLOWED_QUERY_TYPES:
        validate_relay_query(build_query("www.relaytest.", query_type))
    response = build_dns_response(query)
    parsed = validate_dns_response(response, query)
    if not parsed.flags & 0x0020:
        raise HarnessError("selftest response did not preserve untrusted AD")
    print(json.dumps({"status": "pass", "fixtures_checked": checked, "dns_admission": "pass"}, sort_keys=True))


def install_signal_exit() -> None:
    def stop(_signal: int, _frame: object) -> None:
        raise SystemExit(1)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    peer = subparsers.add_parser("peer")
    peer.add_argument("--role", required=True, choices=("hsd-proof", "hsd-relay-good", "hsd-relay-bad", "hsd-legacy"))
    peer.add_argument("--port", required=True, type=int)
    subparsers.add_parser("dns-auth")
    subparsers.add_parser("origin")
    subparsers.add_parser("sentinel")
    client = subparsers.add_parser("client")
    client.add_argument("--mode", choices=("e2e", "load"), default=os.environ.get("HARNESS_MODE", "e2e"))
    selftest = subparsers.add_parser("selftest")
    selftest.add_argument("--browser-fixtures", required=True, type=Path)
    selftest.add_argument("--hsd-fixtures", required=True, type=Path)
    args = parser.parse_args(argv)
    install_signal_exit()
    try:
        if args.command == "peer":
            run_peer(args.role, args.port)
        elif args.command == "dns-auth":
            run_authoritative_dns()
        elif args.command == "origin":
            run_origin()
        elif args.command == "sentinel":
            run_sentinel()
        elif args.command == "client":
            if args.mode == "load":
                run_load_client()
            else:
                run_e2e_client()
        elif args.command == "selftest":
            run_selftest(args.browser_fixtures, args.hsd_fixtures)
        return 0
    except (HarnessError, CodecError, DnsError, OSError, ssl.SSLError) as error:
        print(f"experimental DNS-relay harness failed: {error}", file=sys.stderr)
        write_json("harness-failure.json", {"status": "fail", "error": str(error)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
