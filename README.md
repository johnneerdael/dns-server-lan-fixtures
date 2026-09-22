# DNS test lab

A vendor-neutral DNS fixture server for evaluating local resolvers, internal cloud DNS services, VPNs and ZTNA solutions. Observe expected DNS behavior and investigate regressions against a reviewed baseline.

One Docker Compose project runs BIND 9 and a Python fixture service. The client-facing service generates fresh names under `fresh.example.test`, related records and deliberate transport faults. BIND serves the static `example.test` zones and provides DNSSEC-validating, forward-only recursion through explicitly configured upstream DNS servers.

## Install

Read [Installation and validation](SETUP_AND_VALIDATION.md) for host preparation, network integration, baseline approval and troubleshooting.

```sh
cp .env.example .env
```

Set `DNS_BIND_IPV4` to the host's LAN address, `DNS_ALLOWED_CLIENTS` to the source IPs/CIDRs allowed to query the service, and `DNS_UPSTREAMS` to reachable upstream DNS IPs. The shipped client allowlist is loopback-only; empty upstreams prevent startup.

```sh
docker compose config --quiet
docker compose pull
docker compose up -d --wait
docker compose ps
```

Use UDP/TCP port **53** for client traffic. BIND port **5300** is published on host loopback only. Keep DNS Client on **system DNS**; configure the resolver or access path under test to route `example.test` and its descendants to the fixture service. Importing the static BIND records alone is insufficient for the fresh-name and transport suite.

## Public tests and interpretation

The LAN zones are intentionally unsigned. Internet tests use the independent `dns.quality-assurance.fyi` fixtures described in [external/README.md](external/README.md). The LAN package does not deploy the public zone.

A fixture is prepared DNS data or server behavior for a test. Fixture data, RFC requirements and an approved product/environment baseline are different things. The lab does not assume a particular vendor's answer rewriting or policy behavior is universally correct.

## Published images

- `ghcr.io/johnneerdael/dns-lab-bind:0.2.0`
- `ghcr.io/johnneerdael/dns-lab-fixtures:0.2.0`

Linux amd64 and arm64 images are published from release tags by GitHub Actions. End users only need Compose and `.env`; source builds are for maintainers.

## Development checks

```sh
docker compose -f compose.yaml -f compose.build.yaml up -d --build --wait
python3 -m pip install -r fault_proxy/requirements.txt
python3 -m unittest discover -s fault_proxy
python3 -m unittest discover -s bind/scripts
python3 -m unittest discover -s scripts
```

`docs/fresh-fixture-contract.md` describes generated answers. `scripts/smoke-test.sh` probes an existing deployment; configure its target variables for host-local BIND diagnostics and the client-facing fixture endpoint. The public images contain only the active unsigned LAN zones and fixture service; no signing keys or local credentials are included.

## Migrating

The previous local namespace was `npa.test`. Update forwarding and private-access rules to `example.test`, then establish new baselines. Preserve old evidence unchanged. Stop an older Compose project using its previous project name before starting `dns-client-lab` on the same ports. The installation guide contains the complete migration procedure.

The smoke-stdin integration test requires a running lab. Run it explicitly with `DNS_LAB_RUN_INTEGRATION=1` and the intended target/Compose environment; ordinary unit discovery skips this live-service test.

## Publishing

The release workflow verifies the source-built lab, then publishes both images for Linux amd64 and arm64 when a version tag such as `v0.2.0` is pushed. After publishing a new release tag, update the image tags and manifest digests in `compose.yaml`. The distributed Compose setup pins digests so a rebuilt tag cannot silently change a QA baseline. The first publication may create private packages; the package owner must set both package visibilities to public and verify anonymous pulls before distributing the Compose download.
