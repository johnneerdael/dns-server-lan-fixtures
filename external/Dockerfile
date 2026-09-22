FROM internetsystemsconsortium/bind9:9.20
USER root
COPY named.conf /etc/bind/named.conf
COPY db.dns.quality-assurance.fyi /opt/db.dns.quality-assurance.fyi
COPY entrypoint.sh /usr/local/bin/external-dns-entrypoint
RUN chmod 0555 /usr/local/bin/external-dns-entrypoint
ENTRYPOINT ["/usr/local/bin/external-dns-entrypoint"]
