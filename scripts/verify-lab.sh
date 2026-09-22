#!/usr/bin/env bash
set -euo pipefail
export DNS_BIND_IPV4=127.0.0.1 DNS_PORT=5530 DNS_FAULT_PORT=5531
export DNS_UPSTREAMS=${DNS_UPSTREAMS:-1.1.1.1}
export DNS_ALLOWED_CLIENTS=127.0.0.1/32,::1/128
fixture_project="dns-client-fixture-ci-${GITHUB_RUN_ID:-local}"
fixture_dir=${LAN_FIXTURE_DIR:-.}
compose_files=(-f "$fixture_dir/compose.yaml")
if [ -f "$fixture_dir/compose.build.yaml" ]; then compose_files+=(-f "$fixture_dir/compose.build.yaml"); fi
compose() { docker compose -p "$fixture_project" "${compose_files[@]}" "$@"; }
cleanup() {
  fixture_exit=$?
  trap - EXIT
  if [ "$fixture_exit" -ne 0 ]; then compose logs --no-color --tail=50; fi
  compose down --volumes
  exit "$fixture_exit"
}
trap cleanup EXIT
if [ -f "$fixture_dir/compose.build.yaml" ]; then
  compose build
else
  compose pull
fi
compose up -d --no-build --pull never --wait --wait-timeout 90
compose exec -T -e CHECK_RECURSION="${CHECK_RECURSION:-0}" fault-proxy python3 - <<'PY'
import os
import socket
import struct
import dns.edns
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

host = os.getenv('DNS_VERIFY_HOST', '127.0.0.1')
port = int(os.getenv('DNS_VERIFY_PORT', '5301'))
nonce = 'a1b2c3d4' * 4
zone_name = nonce + '.fresh.example.test.'

def ask(exchange, key, kind='A', **options):
    question = dns.message.make_query(key + '.' + zone_name, kind, **options)
    return exchange(question, host, port=port, timeout=5)

def records(response, kind, section='answer'):
    return [rr for rrset in getattr(response, section)
            if rrset.rdtype == dns.rdatatype.from_text(kind) for rr in rrset]

def read_exact(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        assert part, 'premature TCP EOF'
        result += part
    return result

def read_reply(sock):
    length = struct.unpack('!H', read_exact(sock, 2))[0]
    return dns.message.from_wire(read_exact(sock, length))

def raw_reply(wire, tcp):
    if tcp:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(struct.pack('!H', len(wire)) + wire)
            return read_reply(sock)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((host, port))
        sock.send(wire)
        return dns.message.from_wire(sock.recv(65535))

for exchange in (dns.query.udp, dns.query.tcp):
    response = ask(exchange, 'aaaa', 'AAAA')
    assert response.rcode() == dns.rcode.NOERROR
    assert [r.address for r in records(response, 'AAAA')] == ['2001:db8::10']
    assert not response.flags & dns.flags.AD

    mx = ask(exchange, 'mx', 'MX')
    assert [(r.preference, r.exchange.to_text()) for r in records(mx, 'MX')] == [(10, 'mail.' + zone_name)]
    assert [r.address for r in records(mx, 'A', 'additional')] == ['192.0.2.25']
    assert [r.address for r in records(ask(exchange, 'mail'), 'A')] == ['192.0.2.25']

    srv = ask(exchange, 'srv', 'SRV')
    assert [(r.priority, r.weight, r.port, r.target.to_text()) for r in records(srv, 'SRV')] == [(10, 60, 8443, 'service.' + zone_name)]
    for kind, address in (('A', '192.0.2.40'), ('AAAA', '2001:db8::40')):
        assert [r.address for r in records(srv, kind, 'additional')] == [address]
        assert [r.address for r in records(ask(exchange, 'service', kind), kind)] == [address]
    ns = ask(exchange, 'ns', 'NS')
    assert [r.address for r in records(ns, 'A', 'additional')] == ['192.0.2.53']
    assert [r.address for r in records(ask(exchange, 'ns'), 'A')] == ['192.0.2.53']

    chain = ask(exchange, 'cname-chain')
    assert [r.rdtype for r in chain.answer] == [5, 5, 1]
    assert [r.name.to_text() for r in chain.answer] == ['cname-chain.' + zone_name, 'chain-hop.' + zone_name, 'a.' + zone_name]
    assert [r.target.to_text() for r in records(chain, 'CNAME')] == ['chain-hop.' + zone_name, 'a.' + zone_name]
    assert [r.address for r in records(chain, 'A')] == ['192.0.2.10']
    assert [r.target.to_text() for r in records(ask(exchange, 'chain-hop', 'CNAME'), 'CNAME')] == ['a.' + zone_name]

    dname = ask(exchange, 'x.child.dname-child')
    assert [r.rdtype for r in dname.answer] == [39, 5, 1]
    assert dname.answer[0].name.to_text() == 'dname-child.' + zone_name
    assert records(dname, 'DNAME')[0].target.to_text() == 'target-tree.' + zone_name
    assert records(dname, 'CNAME')[0].target.to_text() == 'x.child.target-tree.' + zone_name
    assert [r.address for r in records(dname, 'A')] == ['192.0.2.30']
    assert [r.address for r in records(ask(exchange, 'x.child.target-tree'), 'A')] == ['192.0.2.30']

    absent_type = ask(exchange, 'large-512', 'A')
    assert absent_type.rcode() == dns.rcode.NOERROR and not absent_type.answer
    assert absent_type.authority[0].rdtype == dns.rdatatype.SOA
    negative = ask(exchange, 'negative', 'DNSKEY')
    assert negative.rcode() == dns.rcode.NXDOMAIN and negative.authority[0].ttl == 0
    assert negative.authority[0][0].minimum == 0
    upper = dns.message.make_query(('a.' + zone_name).upper(), 'A')
    upper_answer = exchange(upper, host, port=port, timeout=5)
    assert [r.address for r in records(upper_answer, 'A')] == ['192.0.2.10']
    refused = ask(exchange, 'a', rdclass='CH')
    assert refused.rcode() == dns.rcode.REFUSED and not refused.answer

    cert = records(ask(exchange, 'cert', 'CERT'), 'CERT')[0]
    assert (cert.certificate_type, cert.key_tag, cert.algorithm, cert.certificate) == (65280, 0, 0, b'\x01\x02\x03\x04')
    static_cert = exchange(dns.message.make_query('cert.example.test.', 'CERT'), host, port=port, timeout=5)
    cert = records(static_cert, 'CERT')[0]
    assert (cert.certificate_type, cert.key_tag, cert.algorithm, cert.certificate) == (65280, 0, 0, b'\x01\x02\x03\x04')

    good = dns.message.make_query('a.' + zone_name, 'A', use_edns=True)
    duplicate_opt = bytearray(good.to_wire())
    duplicate_opt[10:12] = struct.pack('!H', 2)
    duplicate_opt.extend(good.to_wire()[-11:])
    bad_option = dns.message.make_query('a.' + zone_name, 'A', use_edns=True,
        options=[dns.edns.GenericOption(8, b'\x00\x01')]).to_wire()
    for malformed in (bytes(duplicate_opt), bad_option):
        error = raw_reply(malformed, exchange is dns.query.tcp)
        assert error.rcode() == dns.rcode.FORMERR and error.edns == 0
        assert error.question == good.question
        assert struct.unpack('!H', error.to_wire()[10:12])[0] == 1

    for opcode, expected in ((0, dns.rcode.FORMERR), (1, dns.rcode.NOTIMP)):
        questionless = dns.message.Message(0x6200 + opcode)
        questionless.set_opcode(opcode)
        reply = exchange(questionless, host, port=port, timeout=5)
        assert reply.rcode() == expected and reply.opcode() == opcode and not reply.question
    cookie = dns.message.Message(0x6202)
    cookie.use_edns(options=[dns.edns.CookieOption(b'12345678', b'')])
    reply = exchange(cookie, host, port=port, timeout=5)
    assert reply.rcode() == dns.rcode.NOERROR and not reply.question
    assert any(isinstance(option, dns.edns.CookieOption) and option.client == b'12345678'
               and len(option.server) >= 8 for option in reply.options)
    print(exchange.__name__ + ': fixed record/alias/target, DNAME, class, case, negative, CERT, EDNS and questionless controls passed.')

# Exercise one connection across both local and forwarded query dispatch paths.
questions = [dns.message.make_query('a.' + zone_name, 'A'),
             dns.message.make_query('example.test.', 'SOA'),
             dns.message.make_query('a.' + zone_name, 'AAAA')]
for index, question in enumerate(questions):
    question.id = 0x6300 + index
with socket.create_connection((host, port), timeout=5) as sock:
    for question in questions:
        wire = question.to_wire()
        sock.sendall(struct.pack('!H', len(wire)) + wire)
    pending = {question.id: question for question in questions}
    for _ in questions:
        reply = read_reply(sock)
        expected = pending.pop(reply.id)
        assert reply.question == expected.question and reply.rcode() == dns.rcode.NOERROR
    assert not pending
print('Ordinary pipelined TCP connection across fresh and BIND names passed.')

zone = dns.query.udp(dns.message.make_query('example.test.', 'SOA', want_dnssec=True), host, port=port, timeout=5)
assert zone.rcode() == dns.rcode.NOERROR
assert any(rrset.rdtype == dns.rdatatype.SOA for rrset in zone.answer)
assert not any(rrset.rdtype in [dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY] for rrset in zone.answer)
print('Unsigned BIND zone passed.')
if os.getenv('CHECK_RECURSION') == '1':
    for exchange in (dns.query.udp, dns.query.tcp):
        public = exchange(dns.message.make_query('example.org.', 'A', want_dnssec=True), host, port=port, timeout=10)
        assert public.rcode() == dns.rcode.NOERROR and public.answer, public.to_text()
        assert public.flags & dns.flags.RA, public.to_text()
    keys = dns.query.tcp(dns.message.make_query('org.', 'DNSKEY', want_dnssec=True), host, port=port, timeout=10)
    assert keys.rcode() == dns.rcode.NOERROR and keys.flags & dns.flags.AD, keys.to_text()
    print('Configured upstream: UDP/TCP recursion and validated DNSKEY response passed.')
PY
# The sibling container is not in the client allowlist. Verify both ingress paths.
for transport in udp tcp; do
  tcp_option=+notcp
  if [ "$transport" = tcp ]; then tcp_option=+tcp; fi
  if compose exec -T authoritative dig @fault-proxy -p 5301 example.test SOA "$tcp_option" +time=1 +tries=1 >/dev/null 2>&1; then
    echo "Untrusted $transport client unexpectedly received DNS service" >&2
    exit 1
  fi
done
echo 'UDP/TCP client access restrictions passed.'
