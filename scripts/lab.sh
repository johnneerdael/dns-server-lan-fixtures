#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB_DIR"

load_lab_environment() {
    env_file=${LAB_ENV_FILE:-$LAB_DIR/.env}
    [ -f "$env_file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            ''|'#'*) continue ;;
            *=*) ;;
            *) continue ;;
        esac
        key=${line%%=*}
        value=${line#*=}
        case $key in
            DNS_PORT) [ "${DNS_PORT+x}" ] || export DNS_PORT="$value" ;;
            DNS_FAULT_PORT) [ "${DNS_FAULT_PORT+x}" ] || export DNS_FAULT_PORT="$value" ;;
            DNS_BIND_IPV4) [ "${DNS_BIND_IPV4+x}" ] || export DNS_BIND_IPV4="$value" ;;
            DNS_FAULT_BIND_IPV4) [ "${DNS_FAULT_BIND_IPV4+x}" ] || export DNS_FAULT_BIND_IPV4="$value" ;;
            DNS_BIND_IPV6) [ "${DNS_BIND_IPV6+x}" ] || export DNS_BIND_IPV6="$value" ;;
            DNS_UPSTREAMS) [ "${DNS_UPSTREAMS+x}" ] || export DNS_UPSTREAMS="$value" ;;
            DNS_ALLOWED_CLIENTS) [ "${DNS_ALLOWED_CLIENTS+x}" ] || export DNS_ALLOWED_CLIENTS="$value" ;;
            CHUNK_DELAY_MS) [ "${CHUNK_DELAY_MS+x}" ] || export CHUNK_DELAY_MS="$value" ;;
            STALL_SECONDS) [ "${STALL_SECONDS+x}" ] || export STALL_SECONDS="$value" ;;
            IO_TIMEOUT_SECONDS) [ "${IO_TIMEOUT_SECONDS+x}" ] || export IO_TIMEOUT_SECONDS="$value" ;;
            MAX_SESSIONS) [ "${MAX_SESSIONS+x}" ] || export MAX_SESSIONS="$value" ;;
            REQUIRE_IPV6) [ "${REQUIRE_IPV6+x}" ] || export REQUIRE_IPV6="$value" ;;
        esac
    done <"$env_file"
}

load_lab_environment

effective_dns_bind_ipv4() {
    printf '%s\n' "${DNS_BIND_IPV4:-127.0.0.1}"
}

effective_dns_fault_bind_ipv4() {
    printf '%s\n' "${DNS_FAULT_BIND_IPV4:-${DNS_BIND_IPV4:-127.0.0.1}}"
}

validate_ipv4_publications() {
    authoritative_address=127.0.0.1
    fault_address=$(effective_dns_fault_bind_ipv4)
    authoritative_port=${DNS_PORT:-5300}
    fault_port=${DNS_FAULT_PORT:-53}
    if [ "$authoritative_address" = "$fault_address" ] && \
       [ "$authoritative_port" = "$fault_port" ]; then
        echo "configuration error: authoritative and fault proxy use the same IPv4 address and port: ${authoritative_address}:${authoritative_port}" >&2
        return 2
    fi
}

compose() {
    env_file=${LAB_ENV_FILE:-$LAB_DIR/.env}
    if [ -f "$env_file" ]; then
        ${DOCKER:-docker} compose --env-file "$env_file" "$@"
    else
        ${DOCKER:-docker} compose "$@"
    fi
}

unit() {
    python3 bind/scripts/test_generate_large_fixtures.py -v
    python3 -m unittest discover -s fault_proxy -v
    python3 scripts/test_tcp_probe.py -v
    python3 scripts/test_lab_env.py -v
}

print_environment() {
    echo "DNS_PORT=${DNS_PORT:-5300}"
    echo "DNS_FAULT_PORT=${DNS_FAULT_PORT:-53}"
    echo "DNS_UPSTREAMS=${DNS_UPSTREAMS:-}"
    echo "DNS_ALLOWED_CLIENTS=${DNS_ALLOWED_CLIENTS:-127.0.0.1/32,::1/128}"
    echo "DNS_BIND_IPV4=$(effective_dns_bind_ipv4)"
    echo "DNS_FAULT_BIND_IPV4=$(effective_dns_fault_bind_ipv4)"
    echo "DNS_BIND_IPV6=${DNS_BIND_IPV6:-::1}"
    echo "CHUNK_DELAY_MS=${CHUNK_DELAY_MS:-50}"
    echo "STALL_SECONDS=${STALL_SECONDS:-2}"
    echo "IO_TIMEOUT_SECONDS=${IO_TIMEOUT_SECONDS:-5}"
    echo "MAX_SESSIONS=${MAX_SESSIONS:-64}"
    echo "REQUIRE_IPV6=${REQUIRE_IPV6:-0}"
}

case ${1:-help} in
    unit)
        unit
        ;;
    static-check)
        DOCKER=${DOCKER:-docker} sh scripts/static-check.sh
        ;;
    up)
        validate_ipv4_publications
        compose up -d --wait
        ;;
    up-ipv6)
        validate_ipv4_publications
        compose -f compose.yaml -f compose.ipv6.yaml up -d --wait
        ;;
    smoke)
        sh scripts/smoke-test.sh
        ;;
    check)
        validate_ipv4_publications
        unit
        DOCKER=${DOCKER:-docker} sh scripts/static-check.sh
        compose up -d --wait
        sh scripts/smoke-test.sh
        ;;
    logs)
        compose logs --no-color
        ;;
    down)
        compose -f compose.yaml -f compose.ipv6.yaml down --remove-orphans
        ;;
    environment)
        print_environment
        ;;
    *)
        echo "usage: $0 {unit|static-check|up|up-ipv6|smoke|check|logs|down|environment}" >&2
        exit 2
        ;;
esac
