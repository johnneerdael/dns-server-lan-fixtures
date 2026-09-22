#!/bin/sh
set -eu
mkdir -p /var/cache/bind/keys
named-checkzone dns.quality-assurance.fyi /opt/db.dns.quality-assurance.fyi
cp /opt/db.dns.quality-assurance.fyi /var/cache/bind/db.dns.quality-assurance.fyi
chown -R bind:bind /var/cache/bind
named-checkconf /etc/bind/named.conf
exec named -g -u bind -c /etc/bind/named.conf
