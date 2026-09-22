#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STATIC_PROJECT="dns-client-lab-static-$$"
export DNS_UPSTREAMS=${DNS_UPSTREAMS:-192.0.2.53}

cleanup() {
    ${DOCKER:-docker} compose --project-name "$STATIC_PROJECT" \
        -f "$LAB_DIR/compose.yaml" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

required_files="
$LAB_DIR/compose.yaml
$LAB_DIR/compose.ipv6.yaml
$LAB_DIR/bind/Dockerfile
$LAB_DIR/bind/named.conf
$LAB_DIR/bind/scripts/entrypoint.sh
$LAB_DIR/fault_proxy/dns_fault_proxy.py
$LAB_DIR/fault_proxy/test_dns_fault_proxy.py
$LAB_DIR/scripts/tcp-probe.py
$LAB_DIR/scripts/test_tcp_probe.py
$LAB_DIR/scripts/test_lab_env.py
$LAB_DIR/scripts/test_compose_config.py
$LAB_DIR/scripts/smoke-test.sh
$LAB_DIR/scripts/lab.sh
"

for required_file in $required_files; do
    if [ ! -f "$required_file" ]; then
        echo "missing required file: $required_file" >&2
        exit 1
    fi
done

python3 "$LAB_DIR/bind/scripts/test_generate_large_fixtures.py" -v
python3 "$LAB_DIR/fault_proxy/test_dns_fault_proxy.py" -v
python3 "$LAB_DIR/scripts/test_tcp_probe.py" -v
python3 "$LAB_DIR/scripts/test_lab_env.py" -v
python3 "$LAB_DIR/scripts/test_compose_config.py" -v
python3 -m py_compile \
    "$LAB_DIR/bind/scripts/generate-large-fixtures.py" \
    "$LAB_DIR/fault_proxy/dns_fault_proxy.py" \
    "$LAB_DIR/scripts/tcp-probe.py" \
    "$LAB_DIR/scripts/test_compose_config.py"
sh -n "$LAB_DIR/bind/scripts/entrypoint.sh"
sh -n "$LAB_DIR/scripts/static-check.sh"
sh -n "$LAB_DIR/scripts/smoke-test.sh"
sh -n "$LAB_DIR/scripts/lab.sh"

${DOCKER:-docker} compose -f "$LAB_DIR/compose.yaml" config --quiet
${DOCKER:-docker} compose \
    -f "$LAB_DIR/compose.yaml" \
    -f "$LAB_DIR/compose.ipv6.yaml" \
    config --quiet
${DOCKER:-docker} compose -f "$LAB_DIR/compose.yaml" -f "$LAB_DIR/compose.build.yaml" build authoritative fault-proxy
${DOCKER:-docker} compose --project-name "$STATIC_PROJECT" \
    -f "$LAB_DIR/compose.yaml" run --rm --no-deps authoritative --check-only
