# Recorded DNS references

The LAN reports in this directory use the published **0.4.0** Docker images
on a local macOS ARM64 host. The native DNS engine connects directly to loopback
IPv4/IPv6; it does not select system DNS or a private-access publisher. Host ports
are bound only to loopback. Docker Desktop gateway CIDRs are allowed for this
isolated capture, not as a recommended production allowlist.

The Internet report uses the machine's configured system-DNS endpoint. The operator
confirmed that the security intermediary was disabled. This is a **recursive resolver
observation**, not a direct-authoritative response or a proof that no cache was used.
Provider-managed DNSSEC records, TTLs and negative synthesis can vary.

- `lan-ipv4.json`: 176-case run; 163 completed exchanges, 11 deliberate transport
  errors, 2 IPv6-only cases unavailable on the IPv4 endpoint.
- `lan-ipv6.json`: 176-case run; 165 completed exchanges and 11 deliberate transport
  errors. This supplies reference evidence for the two IPv6-only cases.
- `internet-system-dns.json`: 92 completed Internet cases through configured system
  DNS, observed at `1.1.1.1:53` in this capture.
- `internet-authoritative-additional.json`: six completed additional-data controls
  directed explicitly at `108.162.192.65:53`. This is separate from system DNS.
- `manifest.json`: image digests, architecture, source revisions, run identities,
  timestamps, original-local and published-report SHA-256 hashes, and recheck hashes.
- `rechecks/`: four DNS-behavior comparisons against the immediately previous
  published references: **176 + 176 + 92 + 6 unchanged results**. These comparisons
  preserve the differing-catalogue warning and use the corrected nonce handling
  for legacy RP, AFSDB and DNAME presentation.

Every published capture sets `local_endpoint` to null and appends an explanatory
publication note. DNS request/response bytes, decoded content, remote endpoints,
timing and events remain unchanged. These captures retain their original **0.4.0**
metadata and decoding; they were not redecoded using the subsequent 0.4.1 changes.
See [the recheck provenance](../docs/reference-recheck-2026-09-23.md).

The app shows the actual original response text, including names, transaction IDs,
flags, TTLs and every record. It never rewrites the reference to look as though it
answered the current run's nonce. Requests, accepted and rejected packets, errors,
framing and transport events remain available in the full JSON. Previous reference
snapshots are omitted from these captures to prevent circular evidence.

## Operator acknowledgement metadata

All four current reports record
`target_provenance.security_intermediary_state=operator_confirmed_disabled`, based
on the operator's explicit confirmation before this recheck. This is not an
independent network-state check. The two LAN reports also explicitly identify
their loopback path. A socket destination alone does not prove the absence of
interception or other intermediaries.

New Internet captures default to `unverified`. The helper only records an
operator confirmation when invoked with `--confirm-intermediary-disabled`.
Reports without this structured acknowledgement remain unverified even if
older helper-generated notes claimed that the intermediary was disabled.

## Protocol checks and QA baselines

The independent packet controls test the app's checker. Source and live-container
checks test finite DNS test server semantics. The reports preserve observed data. These
are separate forms of evidence, none of which certifies compliance with every DNS
RFC or approves a product's address rewriting or access policy.

Review a working run through the intended network path and explicitly approve its
baseline before using comparison results as regression evidence. Missing optional
additional data and changed addresses are not automatically RFC violations.
See [RFC validation scope](../docs/rfc-validation.md).

## Historical evidence

The immediately previous 0.4.0 references remain at immutable revision
[`8e330aa`](https://github.com/johnneerdael/dns-server-lan-fixtures/tree/8e330aade76c84aac259f0d82004391c3e7789c3/reference-captures).
Those Internet reports recorded unverified intermediary state. The current
reports are new collections, not retroactive changes to that prior state.

The original 0.2.0 reports remain available at immutable revision
[`cbc9c73`](https://github.com/johnneerdael/dns-server-lan-fixtures/tree/cbc9c73/reference-captures).
That release predates the target-consistency, DNAME, EDNS and ordinary TCP corrections.
Its lack of findings under the earlier checker did **not** establish RFC compliance.

## Corrected Internet CERT records

The operator corrected the certificate type and algorithm in both existing
Cloudflare CERT records. Fixed and fresh wildcard lookups now return experimental
certificate type 65280, key tag 0, algorithm 0 and `AQIDBA==`; the key tag and payload
were already correct. The current Internet report was recaptured after verification.
This tests DNS transport of an experimental record, not PKIX certificate validity.

The earlier observation of the mislabeled PKIX payload remains in immutable
revision `13843cc` for traceability; it is not the current reference.

## Repeat the capture

Run the published images on isolated loopback ports with the IPv6 override and a
source allowlist appropriate for Docker's local NAT path. Use the app's explicit
loopback override only for this controlled DNS test server experiment. The application
repository provides `capture_lan_reference`, `capture_internet_reference`, and
`scripts/generate-fixture-references.py`. The latter makes no network calls or DNS
reply construction; it consumes completed, hash-verified reports.

Publish and review the original reports and their manifest before regenerating the
app's catalogue. The Internet helper uses normal system DNS without an override.
Record security/intermediary state and any remaining limitations with that report.
