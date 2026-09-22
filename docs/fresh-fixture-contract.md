# Fresh LAN fixtures for DNS Client GUI

The new app uses fresh questions rather than expected-answer comparisons.
Deploy the complete updated repository, including `fault_proxy`, its Dockerfile
and requirements. Updating only BIND zone text will not install fresh fixtures.

The existing canonical BIND service remains on UDP/TCP 5300. The existing
bounded fixture/fault service on UDP/TCP **5301** now also answers
`<fixture>.<32 lowercase hex characters>.fresh.example.test`. Use that endpoint
directly or route `fresh.example.test` there through the test product/Publisher.
Existing `transport.example.test` names retain their previous behavior.

## Publisher DNS on a single server address

If the Publisher queries this host on standard DNS port 53, place the extended
fixture service on 53 and keep canonical BIND available separately on 5300.
For the user's current LAN deployment, `.env` is:

```dotenv
DNS_BIND_IPV4=172.31.46.71
DNS_FAULT_BIND_IPV4=172.31.46.71
DNS_PORT=5300
DNS_FAULT_PORT=53
```

Use the host's actual assigned LAN address in another deployment. Rebuild
with `docker compose up -d --build`; restarting containers without `--build`
does not install changed Python or BIND files into the existing images.

Ensure the private-app hostname definition covers `*.fresh.example.test`. Keep
the Publisher DNS destination at the host's address on port 53. Enable Use
Publisher DNS when collecting server-backed answers; other product settings
may intentionally produce rewritten answers, which the GUI records without
an expected-address verdict. Application service ports in the private-app
definition do not set the Publisher resolver's DNS destination port.

Keep `dns.quality-assurance.fyi` on the public DNS path for the Internet suite. Verify
the checked-out branch contains `fault_proxy/fresh_fixtures.py` before
rebuilding; fetching a new remote branch does not switch the checkout to it.

The fixture service provides ordinary records, alias chains, DNS service
locators, large answers, EDNS negotiation, and bounded TCP fault/persistence
scenarios. It has no recursion for Internet test names. When using the app's
single override to query 5301 directly, public tests may return REFUSED:
that is a direct-LAN diagnostic, not an Internet validation run.

All LAN fixtures are **unsigned**. BIND no longer starts the old signed child
zone or copies its test keys into the image. DNSSEC tests belong to the
independent `external/` configuration or Cloudflare's public zone.

Ordinary fresh records and negative-cache SOA values have TTL zero. Aliases
and service targets retain the nonce. Explicit TTL boundary cases use their
named TTL. Persistence, pipelining and fallback preserve names within the
scenario; independent tests allocate a new nonce. DNS has no universal cache
bypass flag, so the app reports this as cache avoidance rather than proof of
the intermediary's cache state.

PTR fixtures exercise PTR record handling at fresh owners; they are not
evidence that an IP-address reverse zone has been delegated. Legacy BIND
reverse fixtures remain available for conventional reverse lookups.

```sh
docker compose up -d --build
dig @127.0.0.1 -p 5301 a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fresh.example.test A
dig @127.0.0.1 -p 5301 cname-chain.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.fresh.example.test A +tcp
```

Use a different random label for each independent real test. These literal
names are examples only. Keep the existing loopback/private lab publication
and firewall controls; the service deliberately produces malformed transport
stimuli for some names and should not be exposed as a public resolver.

Run unit tests in a virtual environment with
`pip install -r fault_proxy/requirements.txt`, then
`python -m unittest discover -s fault_proxy -p 'test_*.py'`.
The regular `scripts/lab.sh smoke` validates the unsigned canonical service
and legacy transport contract.
