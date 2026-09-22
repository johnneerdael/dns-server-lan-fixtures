import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("render-recursion.sh")


class RecursionConfigurationTests(unittest.TestCase):
    def render(self, value):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "recursion.conf"
            result = subprocess.run(["sh", str(SCRIPT), str(output)], env={**os.environ, "DNS_UPSTREAMS": value}, capture_output=True, text=True)
            return result, output.read_text() if output.exists() else ""

    def test_explicit_upstreams_enable_restricted_validating_forwarding(self):
        result, text = self.render("192.0.2.53,2001:db8::53")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("192.0.2.53; 2001:db8::53;", text)
        self.assertIn("forward only;", text)
        self.assertIn("dnssec-validation auto;", text)
        self.assertIn("allow-recursion { localhost; localnets; };", text)

    def test_empty_upstreams_and_config_injection_are_rejected(self):
        for value in ["", " ", "192.0.2.53,", "192.0.2.53,,192.0.2.54", "192.0.2.53; }; allow-recursion { any", "$(id)", "*.test"]:
            with self.subTest(value=value):
                result, text = self.render(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(text, "")


if __name__ == "__main__":
    unittest.main()
