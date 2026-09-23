# DNS reference recheck: 23 September 2026

The operator explicitly confirmed the client/security intermediary disabled before
these fresh collections. That acknowledgement is recorded in every report; it was
not independently detected. The test server remained on the published **0.4.0**
images. This update changes reference evidence and documentation only.

| Collection | Path | Inventory and execution | DNS-behavior comparison |
|---|---|---|---|
| LAN IPv4 | Direct `127.0.0.1:5531` | 176 tests: 163 completed, 11 deliberate transport errors, 2 IPv6-only unavailable | 176 unchanged |
| LAN IPv6 | Direct `[::1]:5531` | 176 tests: 165 completed, 11 deliberate transport errors | 176 unchanged |
| Internet | Configured system DNS, observed `1.1.1.1:53` | 92 completed tests | 92 unchanged |
| Public additional-data control | Explicit authoritative endpoint `108.162.192.65:53` | 6 completed tests | 6 unchanged |

All four comparisons have zero changed, added or removed tests. Their original
JSON reports are in [`reference-captures/rechecks`](../reference-captures/rechecks).
The prior references remain in Git at
[`8e330aa`](https://github.com/johnneerdael/dns-server-lan-fixtures/tree/8e330aade76c84aac259f0d82004391c3e7789c3/reference-captures).

## What the comparison establishes

The recheck uses **DNS behavior** comparison after correcting generated-name
normalization for RP, AFSDB and DNAME records whose older decoded presentation was
opaque. The comparator can account for the nonce carried in those records instead
of treating its fresh random value as a regression. It did not rewrite the DNS
captures or their decoded records.

“Unchanged” means equivalent under that bounded normalization. Run identifiers,
timings, local ports, generated nonces, positive TTL differences and selected
signature volatility are excluded as documented in each comparison. It does not
mean byte identity, an explicit TTL/latency expectation pass, full DNS RFC
certification, or QA approval of a product baseline. Deliberate faults and the two
IPv4-run unavailable cases remain visible; they are not reclassified as successes.
The catalogue-digest warning is retained because the old/new digests differ.

## Capture source and publication

The reports were collected as application **0.4.0**, catalogue **1.4.0**, from a
workspace based on GUI revision
[`719ad76`](https://github.com/johnneerdael/dns-client-gui/tree/719ad76f353d6fc41c7d7b4d3e1ab69f81c6b1ba)
with uncommitted work, including authoritative-control acknowledgement handling.
The capture predates the subsequent 0.4.1 Rust decoder changes.

The manifest retains the backed-up pre-recheck engine-file hashes. Each listed
hash was independently checked against the corresponding tracked file at
`719ad76`; current modified decoder source was **not** substituted. This identifies
the listed core files and does not claim to fingerprint every helper or build
input from the dirty workspace. The source server revision and published image
digests remain unchanged in the manifest.

Only local socket endpoint metadata is set to null for publication, plus an
explanatory provenance note. Original request/response bytes, IDs, nonces, flags,
section contents, timestamps, remote endpoints and run IDs are retained. Manifest
entries record both original-local and published-file hashes so the metadata
redaction is explicit. Full local originals remain with the operator.

The Internet system-DNS observation and the explicit authoritative control are
different paths. Neither a client-disabled acknowledgement nor a destination
address proves a cache-free or intermediary-free path. Establish a working,
approved baseline through the actual resolver/VPN/ZTNA environment before using
these observations for product regression decisions.
