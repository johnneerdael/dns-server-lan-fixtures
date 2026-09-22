# DNS protocol validation scope

The automated checks cover selected DNS semantics of the unsigned fresh-name DNS
responder and its forwarding/transport boundary. They establish regression
coverage, not full RFC certification, product certification, or application
payload validity. [The DNS test data contract](fresh-fixture-contract.md) defines the
specific names, records, deployment path, and deliberate faults.

## Covered semantics

| Area | Regression checks | Primary standard |
|---|---|---|
| Name matching | Mixed-case DNS test case, nonce and suffix match the same DNS name | [RFC 4343 section 3](https://www.rfc-editor.org/rfc/rfc4343.html#section-3): case matching is a MUST |
| Requested data | QTYPE selects matching records; unsupported classes are refused; additional addresses and alias targets agree with direct lookups | [RFC 1034 section 4.3.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-4.3.2) |
| Negative answers | NXDOMAIN is independent of QTYPE; existing missing types use NODATA; authoritative negatives carry the correct zero-TTL SOA | [RFC 2308 sections 3 and 5](https://www.rfc-editor.org/rfc/rfc2308.html#section-3): authoritative negative SOA inclusion is a MUST |
| CNAME/DNAME | Direct alias lookups, CNAME chains and requested target types; fixed DNAME owner; preserved prefix labels; owner NODATA; overlong substitution returns YXDOMAIN | [RFC 6672 sections 2 and 3](https://www.rfc-editor.org/rfc/rfc6672.html#section-2): includes required CNAME synthesis |
| Referrals | Descendants retain the same NS/glue cut; AA is clear; DS at the cut receives parent-side denial | [RFC 1034 section 4.3.2](https://www.rfc-editor.org/rfc/rfc1034.html#section-4.3.2) |
| Minimal ANY | Returned RRset also exists in a direct type-specific lookup | [RFC 8482 section 4.1](https://www.rfc-editor.org/rfc/rfc8482.html#section-4.1) permits a subset |
| EDNS | UDP size limits, unknown options/flags, DO handling and BADVERS; malformed/duplicate OPT gets FORMERR with one OPT | [RFC 6891 sections 6 and 7](https://www.rfc-editor.org/rfc/rfc6891.html#section-6): includes MUST requirements |
| Question count | Fresh QUERY with more than one question gets FORMERR without multiple echoed questions; questionless QUERY reaches BIND with its response preserved | [RFC 9619 section 4](https://www.rfc-editor.org/rfc/rfc9619.html#section-4): a MUST for OPCODE 0 |
| Other opcodes | Fresh unsupported opcodes return NOTIMP; zero-question IQUERY reaches the upstream over UDP/TCP | [RFC 3425 section 3](https://www.rfc-editor.org/rfc/rfc3425.html#section-3): NOTIMP for IQUERY is a SHOULD, not MUST |
| TCP | Real sockets test sequential/pipelined exchanges, mixed fresh/forwarded names, split requests and response correlation | [RFC 7766 sections 6.2 and 8](https://www.rfc-editor.org/rfc/rfc7766.html#section-6.2): reuse/pipelining are SHOULD recommendations |
| DNS test record consistency | Shipped record families, TTL boundaries, resolvable service-alias targets, and additional-data follow-ups | Local DNS test data contract; exact addresses and TTL choices are not universal RFC requirements |

The source tests parse complete DNS replies with dnspython and assert semantics
rather than treating the absence of a parser error as conformance. Socket tests
exercise dispatch and framing. Explicit fault tests separately check that close,
duplicate, and reorder stimuli remain available. A deliberately malformed
response cannot be counted as an ordinary protocol failure or success.

## Run the checks

Create a Python virtual environment, activate it, and install the pinned server
dependency. From the repository root:

```sh
python3 -m pip install -r fault_proxy/requirements.txt
python3 -m unittest discover -s fault_proxy
python3 -m unittest discover -s bind/scripts
python3 -m unittest discover -s scripts
```

The `fault_proxy` discovery command includes `test_fresh_fixtures.py` and the
real-socket/forwarding checks in `test_dns_fault_proxy.py`; no separate invocation
is needed to include them. The image publication workflow runs all three test
groups before its container verification step.

The maintainer container check builds the source with `compose.build.yaml`,
queries the packaged fresh/BIND services, and checks client access restrictions:

```sh
DNS_UPSTREAMS=1.1.1.1 CHECK_RECURSION=1 bash scripts/verify-lab.sh
```

Use an upstream reachable from the test environment. This command starts and
removes an isolated Compose project; recursion checks require network access.
The live smoke-stdin integration test is skipped in ordinary unit discovery. Run
it only against an intended live lab with `DNS_LAB_RUN_INTEGRATION=1`, following
[the installation guide](../SETUP_AND_VALIDATION.md).

## Limits and interpretation

- The fresh responder is an unsigned, finite DNS test data model. It does not implement
  a general authoritative server, DNSSEC signing/validation, zone transfer,
  dynamic update, or every EDNS extension. BIND handles configured recursion.
- CERT uses experimental certificate type 65280, not PKIX; `AQIDBA==` is an
  experimental record-encoding specimen. See [RFC 4398 section 2.1](https://www.rfc-editor.org/rfc/rfc4398.html#section-2.1).
  TLSA/SSHFP values and service targets are synthetic, with no application trust
  or live-service assertion.
- Coverage is bounded. It does not exhaust malformed-message inputs, compression
  graphs, DNS Cookie negotiation beyond transparent forwarding, DSO, TCP timing races,
  concurrent load, every delegation topology, or every DNSSEC failure mode.
- TCP query-count and socket-timeout limits are local resource policies. The
  tests do not prove behavior under arbitrary packet loss, latency, or attack.
- The configured-upstream check is a small recursion/DNSSEC smoke test, not an
  independent revalidation of BIND or of all public DNS test records.
- A recorded capture establishes what a particular image and network path
  returned. Record image digests and conditions when approving a new baseline;
  preserve historical evidence unchanged.
