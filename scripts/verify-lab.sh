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
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

name = 'aaaa.00000000000000000000000000000000.fresh.example.test.'
for exchange in [dns.query.udp, dns.query.tcp]:
    response = exchange(dns.message.make_query(name, 'AAAA'), '127.0.0.1', port=5301, timeout=5)
    assert response.rcode() == dns.rcode.NOERROR
    assert any(record.to_text() == '2001:db8::10' for rrset in response.answer for record in rrset)
    assert not response.flags & dns.flags.AD
chain = dns.query.tcp(dns.message.make_query('cname-chain.00000000000000000000000000000000.fresh.example.test.', 'A'), '127.0.0.1', port=5301, timeout=5)
assert sum(rrset.rdtype == dns.rdatatype.CNAME for rrset in chain.answer) == 2
zone = dns.query.udp(dns.message.make_query('example.test.', 'SOA', want_dnssec=True), '127.0.0.1', port=5301, timeout=5)
assert zone.rcode() == dns.rcode.NOERROR
assert any(rrset.rdtype == dns.rdatatype.SOA for rrset in zone.answer)
assert not any(rrset.rdtype in [dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY] for rrset in zone.answer)
print('Packaged LAN server: UDP/TCP AAAA, CNAME chain, and unsigned BIND zone passed.')
if os.getenv('CHECK_RECURSION') == '1':
    for exchange in [dns.query.udp, dns.query.tcp]:
        public = exchange(dns.message.make_query('example.org.', 'A', want_dnssec=True), '127.0.0.1', port=5301, timeout=10)
        assert public.rcode() == dns.rcode.NOERROR and public.answer, public.to_text()
        assert public.flags & dns.flags.RA, public.to_text()
    keys = dns.query.tcp(dns.message.make_query('org.', 'DNSKEY', want_dnssec=True), '127.0.0.1', port=5301, timeout=10)
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
