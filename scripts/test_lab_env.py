#!/usr/bin/env python3
import os
import pathlib
import subprocess
import tempfile
import unittest


LAB_SCRIPT = pathlib.Path(__file__).with_name("lab.sh")


class LabEnvironmentTests(unittest.TestCase):
    def test_environment_command_loads_only_supported_literal_dotenv_values(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = pathlib.Path(temporary_directory, "lab.env")
            env_file.write_text(
                "DNS_PORT=15300\n"
                "DNS_FAULT_PORT=15301\n"
                "DNS_BIND_IPV4=192.0.2.10\n"
                "DNS_FAULT_BIND_IPV4=192.0.2.11\n"
                "STALL_SECONDS=7\n"
                "UNSUPPORTED=value\n"
                "CHUNK_DELAY_MS=$(false)\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            for key in (
                "DNS_PORT",
                "DNS_FAULT_PORT",
                "DNS_BIND_IPV4",
                "DNS_FAULT_BIND_IPV4",
                "STALL_SECONDS",
                "CHUNK_DELAY_MS",
            ):
                environment.pop(key, None)
            environment["LAB_ENV_FILE"] = str(env_file)
            result = subprocess.run(
                [LAB_SCRIPT, "environment"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )

        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(values["DNS_PORT"], "15300")
        self.assertEqual(values["DNS_FAULT_PORT"], "15301")
        self.assertEqual(values["DNS_BIND_IPV4"], "192.0.2.10")
        self.assertEqual(values.get("DNS_FAULT_BIND_IPV4"), "192.0.2.11")
        self.assertEqual(values["STALL_SECONDS"], "7")
        self.assertEqual(values["CHUNK_DELAY_MS"], "$(false)")
        self.assertNotIn("UNSUPPORTED", values)

    def test_process_environment_takes_precedence_over_dotenv(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = pathlib.Path(temporary_directory, "lab.env")
            env_file.write_text("DNS_PORT=15300\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(LAB_ENV_FILE=str(env_file), DNS_PORT="25300")
            result = subprocess.run(
                [LAB_SCRIPT, "environment"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )

        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(values["DNS_PORT"], "25300")

    def test_fault_address_falls_back_to_authoritative_address(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = pathlib.Path(temporary_directory, "lab.env")
            env_file.write_text(
                "DNS_BIND_IPV4=192.0.2.10\nDNS_FAULT_BIND_IPV4=\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(LAB_ENV_FILE=str(env_file))
            environment.pop("DNS_BIND_IPV4", None)
            environment.pop("DNS_FAULT_BIND_IPV4", None)
            result = subprocess.run(
                [LAB_SCRIPT, "environment"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )

        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(values["DNS_BIND_IPV4"], "192.0.2.10")
        self.assertEqual(values.get("DNS_FAULT_BIND_IPV4"), "192.0.2.10")

    def test_fault_address_process_environment_precedes_dotenv(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = pathlib.Path(temporary_directory, "lab.env")
            env_file.write_text(
                "DNS_FAULT_BIND_IPV4=192.0.2.11\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                LAB_ENV_FILE=str(env_file),
                DNS_FAULT_BIND_IPV4="192.0.2.12",
            )
            result = subprocess.run(
                [LAB_SCRIPT, "environment"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )

        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(values.get("DNS_FAULT_BIND_IPV4"), "192.0.2.12")

    def test_same_address_and_port_are_rejected_before_compose(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            env_file = temporary / "lab.env"
            env_file.write_text(
                "DNS_BIND_IPV4=127.0.0.1\n"
                "DNS_PORT=53\n"
                "DNS_FAULT_PORT=53\n",
                encoding="utf-8",
            )
            fake_docker = temporary / "docker-wrapper"
            fake_docker.write_text(
                '#!/bin/sh\nprintf "docker-called\\n"\n', encoding="utf-8"
            )
            fake_docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                LAB_ENV_FILE=str(env_file),
                DOCKER=str(fake_docker),
            )
            for key in (
                "DNS_BIND_IPV4",
                "DNS_FAULT_BIND_IPV4",
                "DNS_PORT",
                "DNS_FAULT_PORT",
            ):
                environment.pop(key, None)
            result = subprocess.run(
                [LAB_SCRIPT, "up"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("same IPv4 address and port", result.stderr)
        self.assertNotIn("docker-called", result.stdout)

    def test_distinct_addresses_allow_the_same_port(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            env_file = temporary / "lab.env"
            env_file.write_text(
                "DNS_BIND_IPV4=192.0.2.10\n"
                "DNS_FAULT_BIND_IPV4=192.0.2.11\n"
                "DNS_PORT=53\n"
                "DNS_FAULT_PORT=53\n",
                encoding="utf-8",
            )
            fake_docker = temporary / "docker-wrapper"
            fake_docker.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*"\n', encoding="utf-8"
            )
            fake_docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                LAB_ENV_FILE=str(env_file),
                DOCKER=str(fake_docker),
            )
            for key in (
                "DNS_BIND_IPV4",
                "DNS_FAULT_BIND_IPV4",
                "DNS_PORT",
                "DNS_FAULT_PORT",
            ):
                environment.pop(key, None)
            result = subprocess.run(
                [LAB_SCRIPT, "up"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )

        self.assertIn("compose --env-file", result.stdout)
        self.assertIn("up -d --wait", result.stdout)

    def test_compose_receives_dotenv_path_even_through_command_wrapper(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = pathlib.Path(temporary_directory)
            env_file = temporary / "lab.env"
            env_file.write_text("DNS_PORT=15300\n", encoding="utf-8")
            fake_docker = temporary / "docker-wrapper"
            fake_docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n', encoding="utf-8")
            fake_docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                LAB_ENV_FILE=str(env_file),
                DOCKER=str(fake_docker),
            )
            result = subprocess.run(
                [LAB_SCRIPT, "down"],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )

        self.assertIn(f"compose --env-file {env_file}", result.stdout)
        self.assertIn("down --remove-orphans", result.stdout)


if __name__ == "__main__":
    unittest.main()
