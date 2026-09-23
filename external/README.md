# Public DNS test records: dns.quality-assurance.fyi

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
`<random nonce>.<record-name>.dns.quality-assurance.fyi`. This avoids reusing exact question
names, but it cannot force a recursive resolver to bypass cached wildcard
data, CNAME targets, negative proofs, or DNSSEC metadata. The client records
the actual names and cache strategy. There is no DNS no-cache flag.

Cloudflare does not expose every BIND record type or server behavior. The
import intentionally excludes SOA, NS/delegation, HINFO, RP, AFSDB, and private
TYPE65280 fixtures. Those types can be observed in the independent BIND lab
or in the LAN suite; an absent public record is evidence, not automatically
an RFC failure. Cloudflare may synthesize minimal ANY/negative answers and
apply provider limits. Test framing faults and controlled pipelining against
the internal DNS test service, not by trying to configure Cloudflare faults.

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

## Additional-section observation records

Import **`cloudflare-additional-records.zone`** separately into the existing
`quality-assurance.fyi` zone. This file only adds eight new records; it does not
replace the existing import or change nameservers, DNSSEC, or existing answers.
Keep every record DNS only. Reimporting may produce duplicate warnings; review
the existing values before making any updates.

| Question owner | Type and target | Target address records |
|---|---|---|
| `<nonce>.additional-mx.dns.quality-assurance.fyi` | MX 10 `additional-mail.dns.quality-assurance.fyi` | A `192.0.2.25`, AAAA `2001:db8::25` |
| `<nonce>.additional-srv.dns.quality-assurance.fyi` | SRV 10 60 8443 `additional-service.dns.quality-assurance.fyi` | A `192.0.2.40`, AAAA `2001:db8::40` |

The exact `additional-mx` and `additional-srv` owners also exist. Wildcards allow
fresh question names, but their targets are static: target address lookups can
reuse cached responses. Both address families are DNS data, not working mail or
application servers. MX and SRV targets are address owners, not aliases.

Cloudflare controls its authoritative response contents, and recursive resolvers
can choose whether to return optional address records alongside MX/SRV answers.
Putting targets in the same zone does not by itself guarantee their inclusion
in every response. Missing or changed addresses relative to an approved capture
are a **test-data or path consistency difference**; classify an RFC violation
only when an applicable normative requirement is established. Direct target
lookups distinguish absent zone data from omitted optional additional data.
Neither a successful import nor a successful answer establishes an approved
baseline; collect and review fresh responses after deployment.

Public NS observations use the existing **`quality-assurance.fyi NS`** RRset.
There is no new NS import here. An NS owner below the Cloudflare zone apex would
create a delegation, and pointing it at documentation addresses would create
an unreachable child zone. A separate public referral/glue test needs reachable
authoritative child servers and a deliberate delegation. The controlled LAN
`additional-ns` answer and `additional-referral` tests cover those DNS response
forms without asserting that a public or Active Directory service was deployed.

After importing, query the same resolver/path that will supply the baseline:

```sh
dig baseline-run.additional-mx.dns.quality-assurance.fyi MX +dnssec
dig baseline-run.additional-mx.dns.quality-assurance.fyi MX +tcp +dnssec
dig additional-mail.dns.quality-assurance.fyi A
dig additional-mail.dns.quality-assurance.fyi AAAA
dig baseline-run.additional-srv.dns.quality-assurance.fyi SRV +dnssec
dig baseline-run.additional-srv.dns.quality-assurance.fyi SRV +tcp +dnssec
dig additional-service.dns.quality-assurance.fyi A
dig additional-service.dns.quality-assurance.fyi AAAA
dig quality-assurance.fyi NS +dnssec
```

Use a new `baseline-run` label for each independent collection. On macOS, `dig`
does not use the native resolver's per-domain routing in the same way as ordinary
applications; omitting `@server` alone does not prove that split DNS or a VPN's
normal path was used. Record the actual endpoint and use DNS Client's system DNS
mode for its normal collection workflow.

## OPENPGPKEY and SMIMEA observation records

Import **`cloudflare-security-records.zone`** into the existing
`quality-assurance.fyi` zone as a separate additive change, keeping records DNS
only. It contains four records: exact and wildcard owners for OPENPGPKEY and
SMIMEA. It changes no delegation, signing keys or existing records.

- `openpgpkey.dns.quality-assurance.fyi` and
  `*.openpgpkey.dns.quality-assurance.fyi` contain a real synthetic transferable
  OpenPGP public key with a valid self-signature.
- `smimea.dns.quality-assurance.fyi` and
  `*.smimea.dns.quality-assurance.fyi` contain `3 1 1` plus the SHA-256 digest of
  the actual SubjectPublicKeyInfo from a supplied synthetic public certificate.

No private key is shipped. These synthetic owner names are DNS transport probes,
not the hash-derived mailbox discovery names described by Experimental
[RFC 7929](https://www.rfc-editor.org/rfc/rfc7929.html) and
[RFC 8162](https://www.rfc-editor.org/rfc/rfc8162.html). They do not establish a
trusted mailbox, validate certificates, test an email client, or provide usable
encryption services. [Public-specimen provenance](../docs/test-records/README.md)
includes the key fingerprint and independent verification details.

After import, collect fresh UDP and TCP observations for both types, for example:

```sh
dig baseline-run.openpgpkey.dns.quality-assurance.fyi OPENPGPKEY +bufsize=1232 +dnssec
dig baseline-run.openpgpkey.dns.quality-assurance.fyi OPENPGPKEY +tcp +dnssec
dig baseline-run.smimea.dns.quality-assurance.fyi SMIMEA +dnssec
dig baseline-run.smimea.dns.quality-assurance.fyi SMIMEA +tcp +dnssec
```

Use a different `baseline-run` label for each collection and preserve the
actual resolver endpoint. Provider DNSSEC signatures can make a response larger
than the record itself; truncated UDP requires transport-aware interpretation.

## Provider-managed CAA answers

Cloudflare may add CAA values to support certificate issuance, including
automatically generated values that do not appear in the DNS dashboard. This is
documented for Universal SSL when CAA records are configured; see
[Cloudflare's CAA documentation](https://developers.cloudflare.com/ssl/edge-certificates/caa-records/).
An extra issuer returned alongside the configured `ca.invalid` test specimen
therefore does not by itself show an invalid CAA record or an intermediary defect.
Compare approved captures and check the zone's SSL/TLS configuration.

Those are extra **CAA records in the Answer section**, not address records in the
DNS **Additional section**. The DNS section names describe wire-message placement;
the ordinary word “additional” must not be used to confuse these two situations.
The `ca.invalid` value is synthetic DNS test data, not a usable certificate issuer
and not a guarantee that the provider will return only that value.

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
| `cloudflare-additional-records.zone` | Separate additive MX/SRV observations with dual-stack targets; no delegation changes |
| `cloudflare-security-records.zone` | Separate additive OPENPGPKEY/SMIMEA public specimens; no mailbox identity or trust claim |
| `db.dns.quality-assurance.fyi` | Complete standalone BIND reference zone |
| `named.conf` | Authoritative-only BIND with external-zone DNSSEC signing |
| `compose.yaml`, `Dockerfile`, `entrypoint.sh` | Local isolated validation with persistent signing keys |
