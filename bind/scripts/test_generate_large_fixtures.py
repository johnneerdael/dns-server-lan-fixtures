import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("generate-large-fixtures.py")
SPEC = importlib.util.spec_from_file_location("generate_large_fixtures", SCRIPT)


def load_generator():
    module = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = module
    SPEC.loader.exec_module(module)
    return module


class LargeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_generator()

    def test_fixture_names_and_bounds_are_stable(self):
        fixtures = self.module.build_fixtures()
        self.assertEqual(
            set(fixtures),
            {
                "large-512",
                "large-1232",
                "large-multi-a",
                "large-multi-aaaa",
                "large-srv",
                "near-max-tcp",
            },
        )
        manifest = self.module.build_manifest(fixtures)
        entries = manifest["fixtures"]
        self.assertEqual(manifest["schema_version"], 1)
        self.assertGreater(entries["near-max-tcp"]["minimum_tcp_bytes"], 58_000)
        self.assertLessEqual(entries["near-max-tcp"]["maximum_tcp_bytes"], 65_535)
        self.assertEqual(entries["large-multi-a"]["answer_count"], 128)
        self.assertEqual(entries["large-multi-aaaa"]["answer_count"], 128)

    def test_zone_is_deterministic_and_contains_one_near_max_txt_rr(self):
        first = self.module.render_zone(self.module.build_fixtures())
        second = self.module.render_zone(self.module.build_fixtures())
        self.assertEqual(first, second)
        self.assertIn("$ORIGIN example.test.", first)
        self.assertEqual(first.count("near-max-tcp 60 IN TXT"), 1)
        self.assertIn("large-srv 60 IN SRV", first)

    def test_cli_writes_zone_and_json_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            zone = pathlib.Path(tmp, "large.inc")
            manifest = pathlib.Path(tmp, "manifest.json")
            subprocess.run(
                [
                    sys.executable,
                    SCRIPT,
                    "--zone-output",
                    zone,
                    "--manifest-output",
                    manifest,
                ],
                check=True,
            )
            self.assertTrue(zone.read_text(encoding="utf-8").endswith("\n"))
            parsed = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema_version"], 1)
            self.assertEqual(parsed["fixtures"]["large-512"]["qtype"], "TXT")

    def test_cli_rejects_identical_output_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp, "same-output")
            completed = subprocess.run(
                [
                    sys.executable,
                    SCRIPT,
                    "--zone-output",
                    output,
                    "--manifest-output",
                    output,
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("must be different", completed.stderr)


if __name__ == "__main__":
    unittest.main()
