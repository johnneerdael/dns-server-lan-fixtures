FROM python:3.12-alpine AS fixture-builder

WORKDIR /build
COPY scripts/generate-large-fixtures.py /build/generate-large-fixtures.py
RUN python3 /build/generate-large-fixtures.py \
    --zone-output /build/generated/db.large.inc \
    --manifest-output /build/generated/large-manifest.json

FROM internetsystemsconsortium/bind9:9.20

LABEL org.opencontainers.image.source="https://github.com/johnneerdael/dns-server-lan-fixtures"
LABEL org.opencontainers.image.description="BIND backend for the vendor-neutral example.test DNS QA lab"
USER root
COPY --chown=root:bind named.conf /etc/bind/named.conf
COPY --chown=root:bind zones/db.example.test zones/db.ad.example.test zones/db._msdcs.ad.example.test zones/db.192.0.2 zones/db.198.51.100 zones/db.2001.db8 /etc/bind/zones/
COPY --from=fixture-builder --chown=root:bind /build/generated/db.large.inc /etc/bind/zones/generated/db.large.inc
COPY --from=fixture-builder --chown=root:bind /build/generated/large-manifest.json /usr/local/share/dns-lab/large-manifest.json
COPY --chown=root:bind scripts/entrypoint.sh /usr/local/bin/dns-lab-entrypoint
COPY --chown=root:bind scripts/render-recursion.sh /usr/local/bin/dns-lab-render-recursion
RUN chmod 0555 /usr/local/bin/dns-lab-entrypoint /usr/local/bin/dns-lab-render-recursion \
    && find /etc/bind/zones -type d -exec chmod 0555 {} + \
    && find /etc/bind/zones -type f -exec chmod 0444 {} + \
    && chmod 0444 /etc/bind/named.conf \
    && mkdir -p /var/cache/bind/generated \
    && chown -R bind:bind /var/cache/bind

USER bind
EXPOSE 5353/tcp 5353/udp
ENTRYPOINT ["/usr/local/bin/dns-lab-entrypoint"]
