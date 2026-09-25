# Recorded DNS references

These files are observed DNS evidence, not QA-approved resolver baselines or full RFC certification. The two current LAN reports were captured by DNS Client 0.5.0 in an isolated GitHub-hosted Ubuntu runner against the published, digest-pinned **0.5.1** LAN test-server images. The native engine queried `127.0.0.1:5531` and `[::1]:5531` directly; it did not select system DNS or a private-access publisher. No response data was synthesized.

The LAN zones are unsigned. `example.test` provides the wildcard controls and the main record catalogue. `exact-match.test` is a static exact-name zone with two TTL-60 owner names per test family, including A/AAAA answers, CNAME chains, MX and SRV targets, Active Directory LDAP SRV targets, NS answers and their same-zone Additional records, HTTPS hints and large TCP A RRsets. The reverse zones contain real PTR owners for the lab addresses. The NS answer case is separate from the dynamic delegation/referral-glue tests.

- `lan-ipv4.json`: 216 LAN cases; 203 completed, 11 deliberate transport faults recorded as network errors, and two IPv6-only cases unavailable on an IPv4 socket.
- `lan-ipv6.json`: 216 LAN cases; 205 completed and 11 deliberate transport faults recorded as network errors.
- `internet-system-dns.json`: 92 Internet cases through configured system DNS, observed at `1.1.1.1:53` in the original 0.4.0 capture.
- `internet-authoritative-additional.json`: six public Additional-section controls directed explicitly to `108.162.192.65:53`, separate from system DNS.
- `manifest.json`: source revisions, capture times/run identities, report hashes, image digests and available platform metadata.
- `rechecks/`: historical DNS-behavior comparisons from the 23 September 2026 recheck against the earlier 176/176/92/6-reference set. Those comparisons are not against the new 0.5.1 LAN captures.

Published reports set only the runner-local `local_endpoint` field to null and add a publication note. The original capture hash and published-report hash are both recorded. DNS requests and responses, section contents, raw bytes, flags, names, TTLs, remote endpoints, timings and run IDs remain in the reports. The current LAN reports are from app 0.5.0; the Internet reports retain their original 0.4.0 capture metadata and data.

## Network path and acknowledgement

The current LAN reports explicitly identify direct host-loopback overrides against the isolated Docker containers. They do not include an operator acknowledgement about the state of a client, VPN or ZTNA intermediary; those components are not part of the hosted runner path. The older Internet and authoritative-control reports retain the operator acknowledgement recorded when those observations were collected. A resolver address alone does not prove a cache-free or intermediary-free path.

## Protocol checks and QA baselines

The packet controls test the app's finite checker. Source and live-container checks test the finite behavior of this DNS test server. These are separate evidence types; none certifies compliance with every DNS RFC or approves an access product's address rewriting.

Review a working run through the intended resolver/access path and approve a baseline before using comparison results for product regression. Missing optional Additional data and changed answers are not automatically RFC violations. See [RFC validation scope](../docs/rfc-validation.md).

## Historical evidence

The references immediately before these 0.5.1 LAN captures remain at immutable server revision `ab6ee15`; the earlier recheck history and its source are described in [the 23 September recheck note](../docs/reference-recheck-2026-09-23.md). The original 0.2.0 reports remain available at immutable revision [`cbc9c73`](https://github.com/johnneerdael/dns-server-lan-fixtures/tree/cbc9c73/reference-captures). Their lack of findings under the earlier checker did not establish RFC compliance.

The Internet CERT records were corrected to experimental certificate type 65280, key tag 0, algorithm 0 and `AQIDBA==`. That tests DNS carriage of opaque experimental data, not PKIX certificate parsing or validity. The earlier mislabeled PKIX payload remains in the history for traceability.

## Repeat the LAN capture

Use the app repository's `capture-exact-match-lan-references.sh` or the manual `Capture direct LAN DNS references` GitHub Actions workflow. It runs the published images on isolated loopback ports and saves separate IPv4 and IPv6 reports. The capture-only Docker gateway allowlist is temporary; the normal DNS test-server package stays limited to its configured client networks. The app's `scripts/generate-fixture-references.py` consumes completed, hash-verified reports and makes no network requests or DNS response construction.

Publish and review raw captures and their manifest before regenerating the app's reference catalogue. Internet captures use the system DNS path; the separate public authoritative control must remain clearly labelled and must never be substituted for the regular Internet run.
