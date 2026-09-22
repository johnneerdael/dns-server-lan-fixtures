# Observed local LAN references

These reports were collected from the published `0.2.0` Docker images on a local macOS ARM64 host. The native DNS engine connected directly to `127.0.0.1:5531` and `[::1]:5531`; it did not discover or select system DNS or a private-access publisher. Only loopback host ports were published during capture. Docker Desktop gateway CIDRs were allowed for this isolated local test.

- `lan-ipv4.json`: complete 162-case run; 149 completed exchanges, 11 deliberate transport errors, 2 IPv6-only cases unavailable on the IPv4 endpoint.
- `lan-ipv6.json`: complete 162-case run; 151 completed exchanges and 11 deliberate transport errors. This supplies actual evidence for the two IPv6-only cases.
- `manifest.json`: image digests, architecture, run identities, capture timestamps and SHA-256 hashes.

The app generates each LAN fixture reference from the captured IPv4 result, using IPv6 evidence for IPv6-only cases. Original JSON preserves all request/response bytes and transport events. No prior fixture reference is embedded in these captures, avoiding circular evidence. The displayed reference templates replace random names with placeholders and shorten unusually large records for readability; the linked original evidence is unchanged.

These are observations of the controlled fixture service, not approved regression baselines for a DNS resolver, VPN or ZTNA product. Such a baseline must be reviewed independently on the intended network path. The Internet references remain explicitly identified as public-zone configuration examples; DNSSEC provider values are not invented from the zone file.

To reproduce, run the published images on isolated loopback ports, select LAN tests in DNS Client, and use an explicit loopback resolver override for this reference experiment. Export the original JSON for each address family. The application repository also provides `capture_lan_reference` and `scripts/generate-fixture-references.py` for repeatable maintainer collection and rendering.
