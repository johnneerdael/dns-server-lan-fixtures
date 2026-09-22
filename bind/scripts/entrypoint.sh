#!/bin/sh
set -eu

umask 077
# The LAN zones remain unsigned; validation applies to recursive lookups.
/usr/local/bin/dns-lab-render-recursion /var/cache/bind/recursion-options.conf
named-checkconf -z /etc/bind/named.conf

if [ "${1:-}" = "--check-only" ]; then
    exit 0
fi

exec named -g -c /etc/bind/named.conf
