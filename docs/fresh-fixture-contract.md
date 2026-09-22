# Fresh DNS fixture contract

The client-facing service answers generated names under `fresh.example.test` and
forwards other names to BIND. The lab is vendor-neutral: route `example.test` and
its descendants through the resolver, VPN, private-access gateway, or cloud DNS
path under test. Importing the static BIND zone alone does not install the fresh
fixtures or transport scenarios.

## Deployment and query paths

Use the published images with the default Compose file. Copy `.env.example` to
`.env`, then set `DNS_BIND_IPV4` to the host address, `DNS_ALLOWED_CLIENTS` to the
permitted client source IPs/CIDRs, and `DNS_UPSTREAMS` to reachable upstream
resolver IPs. The defaults allow loopback clients only; upstreams must be supplied.

```sh
docker compose config --quiet
docker compose pull
docker compose up -d --wait
```

The default client endpoint is UDP/TCP port **53** (`DNS_FAULT_PORT`). BIND's
host-local diagnostic endpoint is `127.0.0.1:5300` (`DNS_PORT`). Container ports
5301 and 5353 are internal implementation details. Use [the installation
guide](../SETUP_AND_VALIDATION.md) for host preparation and network integration.

Fresh names are answered locally without recursive lookup. BIND serves the
unsigned static LAN zones and provides DNSSEC-validating, forward-only recursion
for other names through `DNS_UPSTREAMS`. The client-facing service forwards those
non-fresh queries to BIND over the query's transport. Never configure an upstream
that routes queries back to this service. Internet fixtures are independent of
the LAN package; see [external fixtures](../external/README.md).

Source builds are for maintainers and require `compose.build.yaml`. A default
Compose deployment pulls images; changing zone files or Python source on the
host does not update a running published image.

## Names and records

A normal generated name is:

```text
<fixture>.<32 hexadecimal characters>.fresh.example.test.
```

Clients generate lowercase hexadecimal nonces; DNS lookup matching accepts
uppercase and mixed-case forms. Allocate a new nonce for each independent test.
Keep the same nonce for related alias/target lookups, TCP exchanges, and UDP-to-TCP
fallback. Fresh names and zero TTLs reduce cache reuse; they do not prove that an
intermediary has no cached state.

Each existing fixture has defined records. Answers select records by QTYPE;
requesting an absent type produces authoritative NOERROR/NODATA with an SOA.
Unrecognized fixture names and the `negative`/`dnssec-negative` subtrees produce
NXDOMAIN. IN records are returned for IN and ANY-class questions; other classes
are refused. The fresh responder rejects unsupported opcodes with NOTIMP and
refuses AXFR/IXFR. Non-fresh operations are passed to BIND, including obsolete
IQUERY messages with no question and questionless QUERY messages.

| Family | Behavior |
|---|---|
| Ordinary records | A, AAAA, NS, SOA, MX, TXT, PTR, SRV, SVCB, HTTPS, CERT, CAA, NAPTR, TLSA, SSHFP, URI, LOC, HINFO, RP, AFSDB, and private TYPE65280 fixtures |
| `cname`, `cname-a`, `ad-guid` | Alias to `a.<nonce>.fresh.example.test`; follow requested types at the target |
| `cname-chain` | Alias through `chain-hop` to `a`; each hop also works as a direct lookup |
| `dname`, `dname-child` | Fixed DNAME owner redirecting descendants to the corresponding prefix below `target-tree` |
| `svcb-alias`, `https-alias` | AliasMode records targeting `svc`, which has ServiceMode records and address data |
| `multi-a`, `multi-aaaa` | Two addresses in one RRset |
| `negative`, `dnssec-negative` | NXDOMAIN across QTYPEs, including DNSSEC types |
| `nodata`, `unsupported` | Existing A owners; the catalogue's AAAA and TYPE65400 questions receive NODATA |
| `referral` | Fixed delegation with NS and glue; descendant queries keep the same cut; DS at the cut receives parent-side unsigned denial |
| `refused` | Explicit policy-refusal fixture |
| `any` | A minimal answer containing an existing RRset, not an inventory of every type |
| `large-512`, `large-1232`, `near-max` | Large TXT RDATA, subject to transport size limits |
| `large-multi-a`, `large-multi-aaaa`, `large-srv` | Large A, AAAA, and SRV RRsets |

Additional MX, NS, and SRV addresses come from the same records as direct target
lookups. Alias and service targets retain the nonce. The ordinary record TTL is
zero; `ttl-normal` uses 60 seconds and `ttl-high` uses 86400 seconds. Negative SOA
TTL and MINIMUM are zero.

All fresh data is unsigned. DO does not create DNSSEC records, and fresh answers
clear AD. DNSSEC-type questions at existing owners receive NODATA; nonexistent
names still receive NXDOMAIN. BIND's recursive responses may contain validated
public DNSSEC data and AD independently of these unsigned local fixtures.

## DNAME questions

Query the owner for its DNAME record and a child name for substitution:

```text
dname.<nonce>.fresh.example.test.                DNAME
child.dname-child.<nonce>.fresh.example.test.    A
```

The second answer contains DNAME at `dname-child.<nonce>.fresh.example.test`, a
synthesized CNAME to `child.target-tree.<nonce>.fresh.example.test`, and the
requested target address. Additional leading labels survive substitution.
Querying the DNAME owner itself for A returns NODATA; the whole nonce zone is
not a DNAME owner. An overlong substituted name produces YXDOMAIN.

## EDNS and TCP

Without EDNS, UDP responses fit within 512 bytes and contain no OPT. EDNS0 UDP
responses respect the advertised size, treating values below 512 as 512 and
applying a local 4096-byte cap. Truncated answers set TC; TCP supports messages up
to 65535 bytes. Unsupported EDNS versions receive BADVERS with an EDNS0 OPT.
Unknown options and reserved flags are ignored, while DO is copied. Parseable
requests with duplicate OPT records or malformed options receive FORMERR with
one response OPT. Fresh multi-question QUERY requests receive FORMERR without
echoing multiple questions.

Ordinary TCP supports sequential queries and pipelining, including connections
that mix fresh and BIND-forwarded names. A connection handles at most 64 ordinary
queries and uses `IO_TIMEOUT_SECONDS` for socket inactivity. Responses use DNS
length framing; clients must correlate IDs and questions.

## Deliberate transport scenarios

These explicit fresh names are stimuli for observing client handling, not
ordinary DNS conformance results:

| Scenario keys | Stimulus |
|---|---|
| `split-prefix`, `split-body`, `bytewise` | Deliver a valid response frame in separate writes |
| `persistent`, `pipeline` | Exercise ordinary connection reuse; reuse also works for other normal names |
| `reordered`, `coalesced` | Read three requests, send three replies in reversed order or one combined write, then close |
| `close-before`, `close-prefix`, `close-body` | Close before a reply, after the prefix, or during the body |
| `length-mismatch`, `trailing`, `duplicate` | Send an incorrect declared length, trailing bytes, or a repeated response |
| `mismatch-id`, `mismatch-question` | Deliberately alter correlation fields |
| `stall` | Pause for a bounded interval and close |

Fault selection requires the exact scenario owner immediately before the nonce;
a name such as `child.close-before.<nonce>.fresh.example.test` does not trigger a
close fault. The legacy `transport.example.test` scenario names remain available.
Client-side tests may instead send a partial/zero-length frame or malformed DNS
request; their fixture labels do not instruct the server to manufacture that
request fault.

## Application-payload limits

CERT is an experimental DNS encoding/decoding specimen.
`CERT 65280 0 0 AQIDBA==` uses experimental certificate type 65280, zero key tag
and algorithm, and the four bytes `01 02 03 04`. It does not claim to contain a
PKIX certificate or test certificate parsing, trust, signatures, or expiry.
[RFC 4398 section 2.1](https://www.rfc-editor.org/rfc/rfc4398.html#section-2.1)
reserves certificate types 65280–65534 for experiments. This is distinct from
DNS RR TYPE65280.

TLSA and SSHFP data are synthetic values, not proofs about a running TLS or SSH
service. PTR at a generated owner tests record handling; it does not establish a
reverse-zone delegation. SRV/service addresses are fixture data, not deployed
application endpoints.

## Example observations

Set `DNS_SERVER` to the address on which the fixture endpoint is published. These
examples use the default loopback binding and client port:

```sh
DNS_SERVER=127.0.0.1
nonce=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
dig @"$DNS_SERVER" -p 53 "a.$nonce.fresh.example.test" A
dig @"$DNS_SERVER" -p 53 "cname-chain.$nonce.fresh.example.test" A +tcp
dig @"$DNS_SERVER" -p 53 "child.dname-child.$nonce.fresh.example.test" A +tcp
```

Compare normal responses against [the bounded RFC validation
coverage](rfc-validation.md). Record product/environment observations separately
from protocol requirements and intentionally faulty stimuli.
