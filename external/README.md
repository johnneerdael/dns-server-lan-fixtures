# Public DNS fixtures: dns.quality-assurance.fyi

These files are independent of the unsigned `example.test` lab. The application
observes the returned records and DNSSEC evidence; QA chooses the baseline.
Documentation-range addresses are intentional DNS data, not web services.

## Parent-zone deployment (Cloudflare import example)

1. Open DNS records for **quality-assurance.fyi**, then Import/Export.
2. Import `cloudflare-records.zone`. Every owner is fully qualified beneath
   `dns.quality-assurance.fyi`; the file does not replace the root zone's records.
3. Keep every imported record **DNS only** (gray cloud). Proxying would change
   the DNS answers and hide several test behaviors.
4. Review duplicates before importing a second time. Apply only the intended
   additions/updates; do not remove existing unrelated records.
5. Enable/check DNSSEC for **quality-assurance.fyi** in Cloudflare and publish the DS at the
   registrar if Cloudflare requires it. Cloudflare generates the signatures;
   do not import locally generated DNSKEY, RRSIG, NSEC, or private keys.

This deployment layout keeps records in the quality-assurance.fyi parent zone;
it does not create a separate dns.quality-assurance.fyi delegation. DNSKEY
and DS metadata are therefore queried at quality-assurance.fyi. Use the actual
nameservers assigned by the DNS provider; the previous domain's nameservers
must not be copied. Verify delegation and DS publication before approving an
Internet baseline. These files prepare the migration; they do not prove that
the public zone is already deployed.

Use TTL 300 for Cloudflare compatibility. Independent ordinary queries use
`<random nonce>.<fixture>.dns.quality-assurance.fyi`. This avoids reusing exact question
names, but it cannot force a recursive resolver to bypass cached wildcard
data, CNAME targets, negative proofs, or DNSSEC metadata. The client records
the actual names and cache strategy. There is no DNS no-cache flag.

Cloudflare does not expose every BIND record type or server behavior. The
import intentionally excludes SOA, NS/delegation, HINFO, RP, AFSDB, and private
TYPE65280 fixtures. Those types can be observed in the independent BIND lab
or in the LAN suite; an absent public record is evidence, not automatically
an RFC failure. Cloudflare may synthesize minimal ANY/negative answers and
apply provider limits. Test framing faults and controlled pipelining against
the internal fixture service, not by trying to configure Cloudflare faults.

Verify after import, using a resolver on the QA endpoint:

```sh
dig a.dns.quality-assurance.fyi A +dnssec
dig example-run.a.dns.quality-assurance.fyi A +dnssec
dig example-run.cname-chain.dns.quality-assurance.fyi A +tcp +dnssec
dig quality-assurance.fyi DNSKEY +dnssec
dig quality-assurance.fyi DS +dnssec
dig no-such-run.negative.dns.quality-assurance.fyi A +dnssec
```

AD is resolver-reported validation evidence, not something that must be set
by an authoritative server. RRSIG presence alone does not prove a trusted
DNSSEC chain. The app preserves all flags and sections for inspection.

## Experimental CERT specimen

The CERT records now use `65280 0 0 AQIDBA==`: experimental certificate type
65280, key tag zero, algorithm zero, and the four bytes `01 02 03 04`.
[RFC 4398 section 2.1](https://www.rfc-editor.org/rfc/rfc4398.html#section-2.1)
reserves certificate types 65280–65534 for experiments. This is DNS record data
for encoding/decoding tests; it makes no PKIX, trust, or usable-certificate claim.
This certificate-type field is distinct from DNS RR TYPE65280.

Earlier imports used `CERT 1 0 8 AQIDBA==`, incorrectly labeling the placeholder
as PKIX. Update both `cert.dns.quality-assurance.fyi` and
`*.cert.dns.quality-assurance.fyi` when applying the revised import. Updating these
source files does not update Cloudflare or another deployed zone. Live captures
may still contain the earlier type-1 payload; preserve that evidence and record
the deployed-data limitation until a new lookup confirms the change.

## Independent BIND reference deployment

`db.dns.quality-assurance.fyi` is a complete standalone zone, including record types the
Cloudflare import cannot supply. `named.conf` serves only this public test
zone and uses BIND's DNSSEC policy with online signing. It does not load or
sign `example.test`.

For local validation:

```sh
docker compose -f external/compose.yaml up -d --build
dig @127.0.0.1 -p 5302 a.dns.quality-assurance.fyi A +dnssec
dig @127.0.0.1 -p 5302 dns.quality-assurance.fyi DNSKEY +dnssec
docker compose -f external/compose.yaml down
```

The external Compose project publishes only loopback port 5302. Signing keys
persist in its `external-zone` volume and are generated on startup. Do not
delete this volume casually. When updating the source zone, increase its SOA
serial before rebuilding/restarting. Startup checks the source zone before
copying it into BIND's writable signing directory; keys are retained.

This local signing configuration is a reference/QA authority. It does not
make the local BIND service authoritative on the Internet. A real BIND-hosted
deployment would require its own reachable authoritative nameservers,
delegation and DS publication. Do not publish those BIND DS values into the
current Cloudflare-managed parent setup.

## Files

| File | Purpose |
|---|---|
| `cloudflare-records.zone` | Additive public records for the existing Cloudflare zone |
| `db.dns.quality-assurance.fyi` | Complete standalone BIND reference zone |
| `named.conf` | Authoritative-only BIND with external-zone DNSSEC signing |
| `compose.yaml`, `Dockerfile`, `entrypoint.sh` | Local isolated validation with persistent signing keys |
