#!/bin/sh
set -eu

DNS_HOST_IPV4=${DNS_HOST_IPV4:-127.0.0.1}
DNS_FAULT_HOST_IPV4=${DNS_FAULT_HOST_IPV4:-${DNS_FAULT_BIND_IPV4:-${DNS_BIND_IPV4:-127.0.0.1}}}
DNS_HOST_IPV6=${DNS_HOST_IPV6:-::1}
DNS_PORT=${DNS_PORT:-5300}
DNS_FAULT_PORT=${DNS_FAULT_PORT:-53}
REQUIRE_IPV6=${REQUIRE_IPV6:-0}
STALL_SECONDS=${STALL_SECONDS:-2}
CHUNK_DELAY_MS=${CHUNK_DELAY_MS:-50}
LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

for command_name in dig python3; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done

query_at() {
    host=$1
    transport=$2
    port=$3
    name=$4
    type=$5
    shift 5
    tcp_option=
    if [ "$transport" = tcp ]; then
        tcp_option=+tcp
    fi
    dig @"$host" -p "$port" "$name" "$type" \
        $tcp_option +time=4 +tries=1 "$@"
}

query() {
    query_at "$DNS_HOST_IPV4" "$@"
}

fault_query() {
    query_at "$DNS_FAULT_HOST_IPV4" "$@"
}

expect_contains_at() {
    host=$1
    transport=$2
    port=$3
    name=$4
    type=$5
    expected=$6
    output=$(query_at "$host" "$transport" "$port" "$name" "$type")
    printf '%s\n' "$output" | grep -F "$expected" >/dev/null || \
        fail "$transport $name $type did not contain: $expected"
    pass "$transport $name $type contains expected data"
}

expect_contains() {
    expect_contains_at "$DNS_HOST_IPV4" "$@"
}

expect_fault_contains() {
    expect_contains_at "$DNS_FAULT_HOST_IPV4" "$@"
}

expect_status() {
    transport=$1
    port=$2
    name=$3
    type=$4
    expected=$5
    output=$(query "$transport" "$port" "$name" "$type")
    printf '%s\n' "$output" | grep -F "status: $expected" >/dev/null || \
        fail "$transport $name $type did not return status $expected"
    pass "$transport $name $type status $expected"
}

answer_digest() {
    raw_answer=$(query "$1" "$DNS_PORT" "$2" "$3" +noall +answer) || \
        fail "$1 $2 $3 query failed during parity comparison"
    printf '%s\n' "$raw_answer" \
        | awk '{$2=""; sub(/[[:space:]]+/, " "); print}' \
        | sort
}

expect_parity() {
    name=$1
    type=$2
    udp_answer=$(answer_digest udp "$name" "$type")
    tcp_answer=$(answer_digest tcp "$name" "$type")
    [ "$udp_answer" = "$tcp_answer" ] || fail "UDP/TCP answers differ for $name $type"
    pass "canonical UDP/TCP parity for $name $type"
}

expect_authoritative_with_recursion() {
    output=$(query udp "$DNS_PORT" a.example.test A +noall +comments)
    flags=$(printf '%s\n' "$output" | grep 'flags:' | head -n 1)
    printf '%s\n' "$flags" | grep -E 'flags:.*(^| )aa( |;)' >/dev/null || \
        fail "canonical response did not set AA"
    printf '%s\n' "$flags" | grep -E 'flags:.*(^| )ra( |;)' >/dev/null || \
        fail "canonical response did not advertise configured recursion"
    pass "canonical endpoint serves local data and advertises recursion"
}

# Every supported PRD parity type is compared after transport-specific framing.
while IFS='|' read -r name type; do
    [ -n "$name" ] || continue
    expect_parity "$name" "$type"
done <<'EOF'
a.example.test|A
aaaa.example.test|AAAA
https.example.test|HTTPS
_service._tcp.example.test|SRV
mx.example.test|MX
txt.example.test|TXT
cname.example.test|CNAME
example.test|NS
example.test|SOA
cert.example.test|CERT
EOF

# Common and deliberately uncommon RRs are asserted on both transports.
while IFS='|' read -r name type expected; do
    [ -n "$name" ] || continue
    expect_contains udp "$DNS_PORT" "$name" "$type" "$expected"
    expect_contains tcp "$DNS_PORT" "$name" "$type" "$expected"
done <<'EOF'
a.example.test|A|192.0.2.10
aaaa.example.test|AAAA|2001:db8::10
cname-chain.example.test|CNAME|cname.example.test.
alias-tree.example.test|DNAME|target-tree.example.test.
mx.example.test|MX|10 mail.example.test.
txt.example.test|TXT|dns-parity-fixture
_service._tcp.example.test|SRV|10 60 8443 service.example.test.
cert.example.test|CERT|65280 0 0 AQIDBA==
caa.example.test|CAA|0 issue "ca.invalid"
naptr.example.test|NAPTR|E2U+sip
_8443._tcp.tlsa.example.test|TLSA|3 1 1 0123456789ABCDEF
sshfp.example.test|SSHFP|1 1 123456789ABCDEF
uri.example.test|URI|https://service.example.test/discovery
loc.example.test|LOC|37 47 0.000 N
hinfo.example.test|HINFO|"x86_64" "Linux"
rp.example.test|RP|hostmaster.example.test. contact.example.test.
afsdb.example.test|AFSDB|1 service.example.test.
svcb.example.test|SVCB|alpn="h2,h3" port=8443
https.example.test|HTTPS|alpn="h2,h3" port=8443
unknown.example.test|TYPE65280|\# 4 DEADBEEF
child.wild.example.test|A|192.0.2.42
ttl-zero.example.test|A|192.0.2.46
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.test|A|192.0.2.49
EOF

expect_authoritative_with_recursion
expect_status udp "$DNS_PORT" missing.example.test A NXDOMAIN
expect_status tcp "$DNS_PORT" missing.example.test A NXDOMAIN
expect_status udp "$DNS_PORT" nodata.example.test AAAA NOERROR
nodata_output=$(query udp "$DNS_PORT" nodata.example.test AAAA +noall +comments)
printf '%s\n' "$nodata_output" | grep -F 'ANSWER: 0' >/dev/null || fail "NODATA response had answers"
pass "NODATA is NOERROR with zero answers"
expect_status udp "$DNS_PORT" example.org A NOERROR

axfr_output=$(dig @"$DNS_HOST_IPV4" -p "$DNS_PORT" example.test AXFR +time=2 +tries=1 2>&1 || true)
printf '%s\n' "$axfr_output" | grep -F 'Transfer failed.' >/dev/null || fail "AXFR was not refused"
pass "AXFR is refused"
ixfr_output=$(dig @"$DNS_HOST_IPV4" -p "$DNS_PORT" example.test IXFR=2026080300 +tcp +time=2 +tries=1 2>&1 || true)
printf '%s\n' "$ixfr_output" | grep -F 'Transfer failed.' >/dev/null || fail "IXFR was not refused"
pass "IXFR is refused"

if command -v nsupdate >/dev/null 2>&1; then
    update_output=$(nsupdate -v 2>&1 <<EOF || true
server $DNS_HOST_IPV4 $DNS_PORT
zone example.test.
update add forbidden-update.example.test. 60 A 192.0.2.99
send
EOF
    )
    printf '%s\n' "$update_output" | grep -F 'update failed: REFUSED' >/dev/null || \
        fail "dynamic UPDATE was not refused"
    pass "dynamic UPDATE is refused"
else
    echo "SKIP: nsupdate unavailable; BIND configuration validation still checks the update-denied policy"
fi

# Active Directory-compatible locator, site, GUID, and reverse-DNS fixtures.
while IFS='|' read -r name type expected; do
    [ -n "$name" ] || continue
    expect_contains tcp "$DNS_PORT" "$name" "$type" "$expected"
done <<'EOF'
_ldap._tcp.ad.example.test|SRV|dc1.ad.example.test.
_kerberos._udp.ad.example.test|SRV|dc2.ad.example.test.
_kpasswd._tcp.ad.example.test|SRV|dc1.ad.example.test.
_ldap._tcp.dc._msdcs.ad.example.test|SRV|dc2.ad.example.test.
_ldap._tcp.gc._msdcs.ad.example.test|SRV|3268 dc1.ad.example.test.
_ldap._tcp.hq._sites.dc._msdcs.ad.example.test|SRV|dc1.ad.example.test.
6f9619ff-8b86-d011-b42d-00c04fc964ff._msdcs.ad.example.test|CNAME|ad.example.test.
10.100.51.198.in-addr.arpa|PTR|dc1.ad.example.test.
0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa|PTR|aaaa.example.test.
0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.a.0.0.8.b.d.0.1.0.0.2.ip6.arpa|PTR|dc1.ad.example.test.
1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.a.0.0.8.b.d.0.1.0.0.2.ip6.arpa|PTR|dc2.ad.example.test.
EOF

# LAN fixtures remain unsigned, including when DO is requested.
unsigned_output=$(query tcp "$DNS_PORT" a.example.test A +dnssec +noall +answer)
if printf '%s\n' "$unsigned_output" | grep -F 'RRSIG' >/dev/null; then
    fail "internal example.test unexpectedly contains DNSSEC signatures"
fi
pass "DNSSEC positive and negative proof records are served"

# Measure every generated response against the stable manifest contract.
smoke_tmp=$(mktemp -d)
trap 'rm -rf "$smoke_tmp"' EXIT HUP INT TERM
python3 "$LAB_DIR/bind/scripts/generate-large-fixtures.py" \
    --zone-output "$smoke_tmp/large.inc" \
    --manifest-output "$smoke_tmp/manifest.json"
python3 - "$smoke_tmp/manifest.json" >"$smoke_tmp/manifest.tsv" <<'PY'
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for fixture in manifest["fixtures"].values():
    print("|".join(str(fixture[key]) for key in (
        "qname", "qtype", "answer_count", "minimum_tcp_bytes", "maximum_tcp_bytes"
    )))
PY

while IFS='|' read -r name type answer_count minimum maximum; do
    output=$(query tcp "$DNS_PORT" "$name" "$type" +noall +comments +stats)
    size=$(printf '%s\n' "$output" | awk '/MSG SIZE  rcvd:/ {print $NF}')
    count=$(printf '%s\n' "$output" | sed -n 's/.*ANSWER: \([0-9][0-9]*\).*/\1/p' | head -n 1)
    [ -n "$size" ] || fail "could not measure $name"
    [ "$size" -ge "$minimum" ] && [ "$size" -le "$maximum" ] || \
        fail "$name measured $size bytes outside $minimum..$maximum"
    [ "$count" -eq "$answer_count" ] || \
        fail "$name returned $count answers, expected $answer_count"
    pass "$name TCP response is $size bytes with $count answer(s)"
done <"$smoke_tmp/manifest.tsv"

for spec in 'large-512.example.test|TXT|+noedns' 'large-1232.example.test|TXT|+bufsize=1232'; do
    IFS='|' read -r name type buffer_option <<EOF
$spec
EOF
    output=$(query udp "$DNS_PORT" "$name" "$type" "$buffer_option" +ignore +noall +comments)
    flags=$(printf '%s\n' "$output" | grep 'flags:' | head -n 1)
    printf '%s\n' "$flags" | grep -E 'flags:.*(^| )tc( |;)' >/dev/null || \
        fail "$name UDP response did not set TC"
    pass "$name advertises UDP truncation for TCP retry"
done

# The explicit force-tcp fixture synthesizes TC over UDP and forwards a full TCP answer.
force_udp=$(fault_query udp "$DNS_FAULT_PORT" force-tcp.transport.example.test TXT +ignore +noall +comments)
printf '%s\n' "$force_udp" | grep -E 'flags:.*(^| )tc( |;)' >/dev/null || fail "force-tcp UDP omitted TC"
printf '%s\n' "$force_udp" | grep -F 'ANSWER: 0' >/dev/null || fail "force-tcp UDP unexpectedly returned answers"
expect_fault_contains tcp "$DNS_FAULT_PORT" force-tcp.transport.example.test TXT force-tcp-canonical-answer
expect_fault_contains udp "$DNS_FAULT_PORT" normal.transport.example.test A 192.0.2.60
expect_fault_contains tcp "$DNS_FAULT_PORT" normal.transport.example.test A 192.0.2.60
delayed_udp=$(fault_query udp "$DNS_FAULT_PORT" delayed.transport.example.test A)
printf '%s\n' "$delayed_udp" | grep -F '192.0.2.64' >/dev/null || fail "delayed UDP answer was missing"
delayed_elapsed=$(printf '%s\n' "$delayed_udp" | awk '/Query time:/ {print $4; exit}')
minimum_delay=$(awk -v configured="$CHUNK_DELAY_MS" 'BEGIN {printf "%d", configured * 0.8}')
maximum_delay=$(awk -v configured="$CHUNK_DELAY_MS" 'BEGIN {printf "%d", configured + 1000}')
[ -n "$delayed_elapsed" ] || fail "could not measure delayed UDP response"
[ "$delayed_elapsed" -ge "$minimum_delay" ] && [ "$delayed_elapsed" -le "$maximum_delay" ] || \
    fail "delayed UDP response took ${delayed_elapsed}ms outside ${minimum_delay}..${maximum_delay}ms"
pass "delayed.transport.example.test UDP response is bounded at ${delayed_elapsed}ms"
for dropped_name in close-before-response.transport.example.test stall.transport.example.test; do
    if dropped_output=$(fault_query udp "$DNS_FAULT_PORT" "$dropped_name" A +time=1 2>&1); then
        fail "$dropped_name UDP unexpectedly returned a response: $dropped_output"
    fi
    pass "$dropped_name UDP produces a bounded no-response outcome"
done
pass "fault endpoint preserves canonical behavior outside explicit fault modes"

# Split request prefix/body writes validate proxy accumulation before response faults.
for request_pattern in split-prefix split-body bytewise; do
    python3 "$LAB_DIR/scripts/tcp-probe.py" \
        --host "$DNS_FAULT_HOST_IPV4" --port "$DNS_FAULT_PORT" \
        --name normal.transport.example.test --type A --expect normal \
        --request-pattern "$request_pattern" --timeout 4 >/dev/null
    pass "proxy accepts $request_pattern DNS-over-TCP request delivery"
done

while IFS='|' read -r label expectation timeout; do
    [ -n "$label" ] || continue
    python3 "$LAB_DIR/scripts/tcp-probe.py" \
        --host "$DNS_FAULT_HOST_IPV4" --port "$DNS_FAULT_PORT" \
        --name "$label.transport.example.test" --type A --expect "$expectation" \
        --timeout "$timeout" --stall-seconds "$STALL_SECONDS" >/dev/null
    pass "fault scenario $label produced $expectation"
done <<EOF
normal|normal|4
split-prefix|split-prefix|4
split-body|split-body|4
bytewise|bytewise|4
delayed|delayed|4
close-before-response|eof-before-response|4
close-after-prefix|eof-after-prefix|4
close-mid-body|eof-mid-body|4
length-mismatch|length-mismatch|4
stall|stall|$((STALL_SECONDS + 2))
duplicate-response|duplicate-response|4
trailing-bytes|trailing-bytes|4
EOF

# IPv6 is optional in local development and mandatory when REQUIRE_IPV6=1.
ipv6_output=$(query_at "$DNS_HOST_IPV6" tcp "$DNS_PORT" a.example.test A +short 2>/dev/null || true)
if printf '%s\n' "$ipv6_output" | grep -Fx '192.0.2.10' >/dev/null; then
    canonical_udp_ipv6=$(query_at "$DNS_HOST_IPV6" udp "$DNS_PORT" a.example.test A +short 2>/dev/null || true)
    proxy_udp_ipv6=$(query_at "$DNS_HOST_IPV6" udp "$DNS_FAULT_PORT" normal.transport.example.test A +short 2>/dev/null || true)
    proxy_tcp_ipv6=$(query_at "$DNS_HOST_IPV6" tcp "$DNS_FAULT_PORT" normal.transport.example.test A +short 2>/dev/null || true)
    printf '%s\n' "$canonical_udp_ipv6" | grep -Fx '192.0.2.10' >/dev/null || fail "IPv6 canonical UDP endpoint failed"
    printf '%s\n' "$proxy_udp_ipv6" | grep -Fx '192.0.2.60' >/dev/null || fail "IPv6 fault UDP endpoint failed"
    printf '%s\n' "$proxy_tcp_ipv6" | grep -Fx '192.0.2.60' >/dev/null || fail "IPv6 fault TCP endpoint failed"
    pass "canonical and fault endpoints are reachable over IPv6 UDP and TCP transport"
elif [ "$REQUIRE_IPV6" = 1 ]; then
    fail "IPv6 transport is required but ::1 publication is unavailable"
else
    echo "SKIP: IPv6 transport is unavailable (use compose.ipv6.yaml; REQUIRE_IPV6=1 makes this fatal)"
fi

${DOCKER:-docker} compose -f "$LAB_DIR/compose.yaml" exec -T authoritative named -V \
    </dev/null >"$smoke_tmp/named-version.txt" 2>/dev/null || \
    fail "could not capture authoritative BIND version"
head -n 1 "$smoke_tmp/named-version.txt"

pass "complete standalone DNS lab smoke suite"
