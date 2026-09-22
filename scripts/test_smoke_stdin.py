#!/usr/bin/env python3
import os
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest


SMOKE_SCRIPT = pathlib.Path(__file__).with_name("smoke-test.sh")


class SmokeStdinTests(unittest.TestCase):
    @unittest.skipUnless(os.getenv("DNS_LAB_RUN_INTEGRATION") == "1", "requires a running lab; set DNS_LAB_RUN_INTEGRATION=1")
    def test_version_capture_does_not_inherit_terminal_input(self):
        real_docker = shutil.which("docker")
        self.assertIsNotNone(real_docker)

        with tempfile.TemporaryDirectory() as temporary_directory:
            docker_wrapper = pathlib.Path(temporary_directory, "docker-wrapper")
            docker_wrapper.write_text(
                "#!/bin/sh\n"
                "if IFS= read -r unexpected_input; then\n"
                "    echo inherited-stdin >&2\n"
                "    exit 88\n"
                "fi\n"
                f"exec {shlex.quote(real_docker)} \"$@\"\n",
                encoding="utf-8",
            )
            docker_wrapper.chmod(0o755)
            environment = os.environ.copy()
            environment.update(DOCKER=str(docker_wrapper), REQUIRE_IPV6="0")
            result = subprocess.run(
                [SMOKE_SCRIPT],
                input="terminal-sentinel\n",
                capture_output=True,
                text=True,
                env=environment,
                timeout=90,
            )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "PASS: complete standalone DNS lab smoke suite", result.stdout
        )


if __name__ == "__main__":
    unittest.main()
