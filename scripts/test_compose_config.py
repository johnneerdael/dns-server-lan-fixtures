#!/usr/bin/env python3
import json
import os
import pathlib
import shlex
import subprocess
import unittest


LAB_DIR = pathlib.Path(__file__).resolve().parent.parent
COMPOSE_FILE = LAB_DIR / "compose.yaml"
CONFIG_KEYS = {
    "DNS_BIND_IPV4",
    "DNS_FAULT_BIND_IPV4",
    "DNS_PORT",
    "DNS_FAULT_PORT",
    "DNS_UPSTREAMS",
    "DNS_ALLOWED_CLIENTS",
}


def render_compose(overrides=None):
    environment = os.environ.copy()
    for key in CONFIG_KEYS:
        environment.pop(key, None)
    environment["DNS_UPSTREAMS"] = "192.0.2.53"
    environment.update(overrides or {})
    docker = shlex.split(environment.get("DOCKER", "docker"))
    result = subprocess.run(
        [
            *docker,
            "compose",
            "--env-file",
            os.devnull,
            "-f",
            str(COMPOSE_FILE),
            "config",
            "--format",
            "json",
        ],
        cwd=LAB_DIR,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def publication_tuples(config, service):
    return {
        (entry["host_ip"], str(entry["published"]), entry["protocol"])
        for entry in config["services"][service]["ports"]
    }


class ComposePublicationTests(unittest.TestCase):
    def test_default_publications_share_loopback_with_distinct_ports(self):
        config = render_compose()
        self.assertEqual(
            publication_tuples(config, "authoritative"),
            {("127.0.0.1", "5300", "tcp"), ("127.0.0.1", "5300", "udp")},
        )
        self.assertEqual(
            publication_tuples(config, "fault-proxy"),
            {("127.0.0.1", "53", "tcp"), ("127.0.0.1", "53", "udp")},
        )

    def test_proxy_address_falls_back_to_custom_authoritative_address(self):
        for overrides in (
            {"DNS_BIND_IPV4": "192.0.2.10"},
            {"DNS_BIND_IPV4": "192.0.2.10", "DNS_FAULT_BIND_IPV4": ""},
        ):
            with self.subTest(overrides=overrides):
                config = render_compose(overrides)
                self.assertEqual(
                    {item[0] for item in publication_tuples(config, "fault-proxy")},
                    {"192.0.2.10"},
                )

    def test_backend_stays_loopback_even_when_frontend_is_on_the_lan(self):
        config = render_compose(
            {
                "DNS_BIND_IPV4": "192.0.2.10",
                "DNS_FAULT_BIND_IPV4": "192.0.2.11",
                "DNS_PORT": "53",
                "DNS_FAULT_PORT": "53",
            }
        )
        self.assertEqual(
            publication_tuples(config, "authoritative"),
            {("127.0.0.1", "53", "tcp"), ("127.0.0.1", "53", "udp")},
        )
        self.assertEqual(
            publication_tuples(config, "fault-proxy"),
            {("192.0.2.11", "53", "tcp"), ("192.0.2.11", "53", "udp")},
        )


if __name__ == "__main__":
    unittest.main()
