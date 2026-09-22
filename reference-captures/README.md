# Recorded DNS references

The LAN reports in this directory use the corrected **0.2.1** published Docker images
on a local macOS ARM64 host. The native DNS engine connects directly to loopback
IPv4/IPv6; it does not select system DNS or a private-access publisher. Host ports
are bound only to loopback. Docker Desktop gateway CIDRs are allowed for this
isolated capture, not as a recommended production allowlist.

The Internet report uses the machine's configured system-DNS endpoint. The operator
confirmed that the security intermediary was disabled. This is a **recursive resolver
observation**, not a direct-authoritative response or a proof that no cache was used.
Provider-managed DNSSEC records, TTLs and negative synthesis can vary.

- `lan-ipv4.json`: 162-case run; 149 completed exchanges, 11 deliberate transport
  errors, 2 IPv6-only cases unavailable on the IPv4 endpoint.
- `lan-ipv6.json`: 162-case run; 151 completed exchanges and 11 deliberate transport
  errors. This supplies reference evidence for the two IPv6-only cases.
- `internet-system-dns.json`: 82 completed Internet cases. Only local socket endpoint
  metadata is omitted from the published copy; all DNS request/response bytes,
  decoded content, remote endpoints, timing and events remain unchanged.
- `manifest.json`: image digests, architecture, source revisions, run identities,
  timestamps and SHA-256 hashes of each published report.

The app shows the actual original response text, including names, transaction IDs,
flags, TTLs and every record. It never rewrites the reference to look as though it
answered the current run's nonce. Requests, accepted and rejected packets, errors,
framing and transport events remain available in the full JSON. Previous reference
snapshots are omitted from these captures to prevent circular evidence.

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
