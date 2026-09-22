#!/bin/sh
set -eu
set -f
umask 077

: "${DNS_UPSTREAMS:?Set DNS_UPSTREAMS to comma-separated resolver IP addresses}"
case "$DNS_UPSTREAMS" in
    ,*|*,|*,,*) echo "DNS_UPSTREAMS contains an empty address" >&2; exit 1 ;;
esac
forwarders=""
for address in $(printf '%s' "$DNS_UPSTREAMS" | tr ',' ' '); do
    case "$address" in
        *[!0-9a-fA-F:.]*) echo "DNS_UPSTREAMS accepts IP addresses only" >&2; exit 1 ;;
    esac
    forwarders="$forwarders $address;"
done
[ -n "$forwarders" ] || { echo "DNS_UPSTREAMS must not be empty" >&2; exit 1; }
destination=${1:?Output path required}
cat > "$destination.tmp" <<EOF
recursion yes;
dnssec-validation auto;
allow-recursion { localhost; localnets; };
allow-query-cache { localhost; localnets; };
forward only;
forwarders { $forwarders };
EOF
mv "$destination.tmp" "$destination"
