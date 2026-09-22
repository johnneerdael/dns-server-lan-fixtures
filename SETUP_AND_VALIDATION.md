# DNS test lab: installation and validation

A vendor-neutral environment for observing expected DNS behavior and investigating regressions.

## 1. What this lab is for

Use this lab with DNS Client to evaluate local DNS resolvers, internal cloud DNS services, VPNs and Zero Trust Network Access (ZTNA) solutions. It supplies controlled DNS answers so you can observe what a device receives through the network path you are testing: addresses, aliases, service records, flags, additional data, negative answers and UDP/TCP behavior.

A fixture is prepared test data or server behavior. It is a software-testing term, not a DNS record type. For example, our A fixture returns 192.0.2.10, while another fixture deliberately closes a TCP connection before sending a complete response. Those two tests require different interpretations.

This lab is independent of any DNS, VPN, cloud or ZTNA vendor. It does not assume that one product's address rewriting, policy decisions or connection handling is the correct behavior for another. Establish a reviewed, valid baseline for each scenario before using comparisons to identify regressions. RFC protocol checks and expected product behavior are separate assessments.

The documentation-range addresses in the answers are DNS test data, not application servers. A successful A or SRV lookup does not prove that HTTP, LDAP or another application can connect to the advertised address or port. The app sends explicit UDP/TCP DNS probes to system-discovered endpoints; this is not a simulation of every operating-system lookup API or encrypted DNS transport.

## 2. What the package contains

One Docker Compose project runs two services. The fixture service is the client-facing DNS endpoint on UDP and TCP port 53. It generates random-name answers, related CNAME/MX/SRV targets and controlled transport faults. BIND 9 serves static zones and resolves other names using the upstream DNS servers you configure.

The client-facing path is: DNS Client -> the resolver or access path under test -> fixture service -> BIND -> upstream DNS, where needed. Queries for fresh.example.test are answered by the fixture service itself. BIND is exposed on host loopback port 5300 only for local diagnostics; route normal tests to port 53.

The lab uses BIND 9, Python and dnspython. Public prebuilt images are published at ghcr.io/johnneerdael/dns-lab-bind and ghcr.io/johnneerdael/dns-lab-fixtures. The download contains the Compose configuration and instructions; users do not need source files, Python or local image builds. Docker Engine and the Compose plugin pull the images from GitHub Container Registry. The first installation requires registry access or an approved image mirror. No GitHub login is required for public pulls.

The local zone is example.test, beneath the reserved .test namespace. It is deliberately unsigned. Internet tests use the separately hosted dns.quality-assurance.fyi namespace; installing this LAN package does not deploy that public zone. DNSSEC validation is enabled in BIND for ordinary recursive lookups, independently of the unsigned local zones.

## 3. Prepare a reachable host

Use a dedicated Linux host or VM with a stable LAN/private address, Docker Engine and the Docker Compose plugin. Published images support Linux amd64 and arm64; Docker selects the matching architecture. The same Compose files can be used in a cloud VM. Ubuntu 24.04 LTS is a suitable installation target. Follow Docker's official installation instructions for your OS; verify both commands before continuing:

```sh
docker version
docker compose version
```

If your account requires elevated privileges, prefix Docker commands with sudo. Install unzip and a DNS client such as dig on the host used for setup checks. Ensure sufficient disk space for the downloaded container images. Docker Desktop can support local experiments, but its VM networking can change source addresses and LAN reachability; the reproducible reference deployment is a dedicated Linux host.

Reserve UDP and TCP port 53 on the chosen LAN address. A local resolver on a different loopback address need not conflict. Inspect existing listeners before changing them; do not disable your host's resolver blindly. Permit inbound UDP/TCP 53 from the intended client, resolver or VPN/ZTNA connector addresses. Permit outbound UDP/TCP 53 to your configured upstream DNS servers, plus HTTPS access to ghcr.io and its image-download endpoints for installation.

Cloud security groups and host networking must agree with the lab's client allowlist. Docker-published ports can bypass simple host firewall rules; use the appropriate Docker firewall controls and network perimeter rules. Do not expose this deliberate-fault lab as a public recursive DNS service.

## 4. Download, unpack and configure

In DNS Client, open Downloads and save the LAN fixture package and installation guide. Transfer the ZIP to the chosen host, then unpack it:

```sh
unzip dns-lan-fixtures.zip
cd DNS-Client-LAN-Fixtures
cp .env.example .env
```

Release downloads may be named DNS-Client-LAN-Fixtures.zip instead; use the name you saved. On Linux, verify the extracted package with sha256sum -c SHA256SUMS.txt before editing its files.

Edit the first three values in .env. The following values illustrate a lab on 192.168.10.53; replace them with your real host, source networks and upstream resolver. Do not paste these example addresses unchanged into a different network.

```ini
DNS_BIND_IPV4=192.168.10.53
DNS_ALLOWED_CLIENTS=192.168.10.0/24,10.20.30.40/32
DNS_UPSTREAMS=192.168.10.1
DNS_FAULT_PORT=53
DNS_PORT=5300
```

DNS_BIND_IPV4 is an address actually assigned to the host. DNS_ALLOWED_CLIENTS is a comma-separated list of the source IPs or networks the fixture service will see: this may be an intermediate resolver, cloud DNS endpoint, NAT gateway or VPN/ZTNA connector rather than the end-user device. Explicit /0 networks are rejected. Container-local health checks are always allowed. The shipped default permits loopback only until you configure the lab.

DNS_UPSTREAMS is a required comma-separated list of DNS resolver IP addresses. There is no automatic public-resolver fallback. BIND uses forward-only recursion and DNSSEC validation. Choose upstream servers reachable from the container and suitable for the public/private names in your scenario. Do not point an upstream back to this lab, or to a resolver that forwards all its queries back here.

The frontend enforces client access before forwarding; BIND sees proxied requests as originating from the fixture service. This is why a BIND-only allowlist cannot enforce the original client boundary. Host-local port 5300 is for administrators and has a separate container-local recursion policy.

## 5. Start and verify the services

Run from the extracted folder. Configuration validation must succeed before you start the services:

```sh
docker compose config --quiet
docker compose pull
docker compose up -d --wait
docker compose ps
```

Both services should become healthy. The health checks verify local DNS service availability, not the entire upstream recursion path, public DNSSEC chain or private-access routing. Check logs if startup fails:

```sh
docker compose logs --no-color --tail=100 authoritative fault-proxy
```

From an allowed client, query the LAN address directly over both transports. Replace 192.168.10.53 with your configured address:

```sh
dig @192.168.10.53 a.00000000000000000000000000000000.fresh.example.test A
dig @192.168.10.53 a.00000000000000000000000000000000.fresh.example.test A +tcp
dig @192.168.10.53 example.test SOA
```

The A probes should return NOERROR and A 192.0.2.10 at TTL 0. Zero TTL is valid: the answer is usable for the current transaction, without being retained for later cache reuse. The fresh response is authoritative and does not advertise recursion availability; an RD warning on this direct fixture response does not mean that BIND's separate recursion path is disabled. The SOA query confirms the static zone behind the fixture service.

Check recursive public resolution separately:

```sh
dig @192.168.10.53 example.org A +dnssec
dig @192.168.10.53 org DNSKEY +dnssec
```

Record the actual response, DNSSEC data and flags. DNSKEY/RRSIG presence alone is not proof of a validated chain, and AD is a resolver assertion. For internal-only environments, verify an approved name reachable through your chosen upstream instead. Also test from a client outside your allowlist: it must not obtain a DNS answer from the exposed service.

## 6. Route the scenario under test

Keep DNS Client on system DNS during normal collection. Choose one topology deliberately and record it in the baseline notes.

With an existing local resolver or internal cloud DNS service, configure conditional forwarding for example.test and its descendants to the lab's LAN address on UDP/TCP 53. Update any cloud outbound resolver endpoints, routes and access controls needed to reach the host. Do not create an empty authoritative example.test zone on the forwarding resolver: that can answer NXDOMAIN locally instead of forwarding.

For VPN or ZTNA testing, arrange the solution's DNS steering or private-DNS integration so the test namespace reaches this same endpoint. Include generated names under fresh.example.test, related alias/service targets, and both transports. Product-specific wildcard and split-DNS rules differ; verify the effective route rather than assuming a wildcard expression has identical meaning everywhere. A permitted SRV or MX query may still require a follow-up A/AAAA lookup of its returned target.

Alternatively, configure a dedicated test device's normal system DNS to use the lab endpoint. The service then answers lab names and forwards unrelated names upstream. This topology makes the lab a resolver for that device. Record the previous device DNS configuration so it can be restored after testing.

If a scenario queries static reverse zones directly, forward those test-only namespaces as well: 2.0.192.in-addr.arpa, 100.51.198.in-addr.arpa and 8.b.d.0.1.0.0.2.ip6.arpa. The app's current fresh-name PTR fixtures are reached beneath fresh.example.test.

From the test device, repeat a fresh question without an @server override and confirm the system path reaches the intended fixture. A displayed socket destination does not by itself identify which resolver or access intermediary generated the answer.

## 7. Collect evidence and approve a baseline

In DNS Client choose LAN tests only, Internet tests only or Full test. Full test needs both the private lab path and a functioning public-fixture path. Save the original PDF and JSON reports. Exporting a report does not approve it as a baseline.

Record the app/catalogue version, fixture revision and container image IDs, OS, resolver endpoints, network, forwarding rules and VPN/ZTNA policy and build. Verify the direct fixture responses first, then review what the normal client path returns. Repeat the run to identify stable behavior and expected variation. An address substituted by an access solution may be intentional; a preserved CNAME chain or additional record may be important even when the final address is unchanged.

Approve a baseline only after the scenario works as intended and its limitations are documented. Keep a separate baseline per materially different scenario. Compare a candidate run using Compare runs or the comparison CLI. Differences are review items, not automatically regressions. No Violation Observed means the implemented RFC checks found no violation in that evidence; it does not certify all DNS behavior or validate the answer data against the lab.

The headline RFC count excludes deliberate-stimulus tests. Inspect their individual findings too. Network errors, incomplete captures, unavailable cases and protocol findings need separate interpretation.

## 8. Transport and caching limits

Ordinary fresh-name tests generate random identifiers and related targets to reduce reuse of cached answers. Connection reuse, pipelining and fallback tests intentionally preserve questions inside their scenario. Static names, upstream metadata, wildcard data and negative proofs can still involve caches. DNS has no universal no-cache flag.

A recursive resolver usually creates its own upstream exchanges and reconstructs replies. It can change flags, omit optional additional records, retry over TCP or hide the exact split/closure behavior of the fixture service. Therefore a test through a resolver describes the end-to-end observation through that resolver, not a transparent copy of the server-side TCP stream.

Use a separately labelled direct-endpoint diagnostic when you need to isolate fixture behavior. Do not silently replace the system-DNS baseline with an override. Compare persistence and pipelining separately from ordinary UDP/TCP lookups and from application reachability.

## 9. Troubleshooting

If Compose says DNS_UPSTREAMS is missing, edit .env in the same folder as compose.yaml. Use only literal IP addresses, separated by commas. Container startup validates the generated BIND configuration. Do not edit an acl inside an options block; the packaged startup handles configuration for you.

If port 53 is already allocated or the address cannot be bound, inspect the host's listeners and interfaces. Use a dedicated host or another assigned interface. Publishing BIND on host-local 5300 does not make that port the correct endpoint for the app's fresh-name suite.

If direct UDP and TCP queries both time out, check allowed source addresses, security groups, routes and listeners. The fixture service logs rejected access requests; unauthorized UDP traffic is discarded and unauthorized TCP connections are closed before queries are processed. A Docker health check can pass while a remote client remains unauthorized.

If direct fixture queries work but system-DNS queries return NXDOMAIN, inspect forwarding, private DNS zones, negative caches and VPN/ZTNA steering. An NXDOMAIN from a public resolver or the .test namespace does not establish that the fixture server returned it.

If lab lookups succeed but public recursion fails, check DNS_UPSTREAMS, outbound UDP/TCP 53, forwarding loops and DNSSEC validation. Upstreams must return DNSSEC records when requested. An upstream that strips root DNSKEY signatures can cause SERVFAIL even though non-validating lookups succeed; select an appropriate upstream rather than silently disabling validation. Review BIND logs and the host clock. Do not disable validation merely to make a screenshot look successful; record any intentionally different validation policy as a separate scenario.

If Docker Desktop or NAT hides the original client behind a gateway address, an IP allowlist can only identify that gateway. Restrict access at the network boundary as well, or use the dedicated Linux deployment to retain useful source-address visibility.

## 10. Update, stop and migrate

Stop the lab when it is no longer needed:

```sh
docker compose down
```

Restore any device DNS settings and remove temporary forwarding or access rules after the experiment. BIND's recursive cache is ephemeral and is cleared when its container is recreated. Keep exported reports and baseline approvals outside the deployment folder.

For updates, extract a new package into a separate folder, review its .env.example and migration notes, then copy only your intended configuration values. Stop the previous project before starting the replacement on the same address and ports. Run docker compose pull followed by docker compose up -d --wait to use the image versions named in the new Compose file. The application package uses versioned images rather than latest; keep the previous Compose file and image versions for rollback. Preserve the previous package and .env for rollback.

Older versions used npa.test. New collection uses example.test, and Internet test names move from debug.ntsk.app to dns.quality-assurance.fyi. Update DNS forwarding, cloud private-zone rules and VPN/ZTNA definitions before testing the new app. Keep old reports intact: they describe the earlier namespace. Do not automatically compare across this migration as though only a product build changed; establish and approve new baselines.

For an older server deployment, run docker compose down using its previous Compose file/project name first. The new default project name is dns-client-lab. Leaving the old project running can hold port 53. The old unrestricted or manually configured frontend must not remain exposed beside the new restricted service.

## 11. Optional IPv6 publication

The base deployment publishes IPv4 and lets Docker allocate its private bridge subnet. To additionally publish on an assigned IPv6 address, set DNS_BIND_IPV6 and add the intended IPv6 client CIDRs to DNS_ALLOWED_CLIENTS. The IPv6 Docker bridge defaults to fd63:13::/64; set DNS_LAB_IPV6_SUBNET to a non-overlapping private /64 if that range is already in use. Use the supplied override consistently for start, status and stop:

```sh
docker compose -f compose.yaml -f compose.ipv6.yaml pull
docker compose -f compose.yaml -f compose.ipv6.yaml up -d --wait
docker compose -f compose.yaml -f compose.ipv6.yaml ps
docker compose -f compose.yaml -f compose.ipv6.yaml down
```

Verify UDP and TCP over IPv6 from an allowed remote client. Returning an AAAA record over IPv4 is different from testing DNS transport over IPv6. Docker host IPv6 support, routes and firewall behavior must be validated for the deployment. Host-local BIND diagnostics remain bound to loopback.

## 12. References and package provenance

Docker Engine installation: https://docs.docker.com/engine/install/ubuntu/

Docker Compose installation: https://docs.docker.com/compose/install/linux/

BIND recursion and access controls: https://bind9.readthedocs.io/en/v9.20.15/reference.html

Reserved test domains, RFC 2606: https://www.rfc-editor.org/rfc/rfc2606.html

TTL and DNS messages, RFC 1035: https://www.rfc-editor.org/rfc/rfc1035.html

DNS over TCP, RFC 7766: https://www.rfc-editor.org/rfc/rfc7766.html

The package includes UPSTREAM.json and SHA256SUMS.txt. These identify the source revision and packaged-file hashes. Signing keys, personal credentials, deployment-specific .env files and the public-zone signing volume are not included. Record the image tags and digests with your baseline. Source and publication workflows are available at https://github.com/johnneerdael/dns-server-lan-fixtures .
