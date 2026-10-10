import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("import_shadow_tool", HERE / "tool.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_pass_example(self):
        self.assertEqual(tool.audit(HERE / "examples/pass")["status"], "pass")

    def test_findings_example(self):
        answer = tool.audit(HERE / "examples/fail")
        self.assertEqual(answer["status"], "findings")
        self.assertEqual([f["module"] for f in answer["findings"]], ["email", "json"])

    def test_never_executes_target(self):
        marker = self.root / "executed"
        (self.root / "json.py").write_text(f"open({str(marker)!r}, 'w').write('bad')")
        self.assertEqual(tool.audit(self.root)["status"], "findings")
        self.assertFalse(marker.exists())

    def test_namespace_and_builtin_are_inventory(self):
        (self.root / "json").mkdir()
        (self.root / "sys.py").write_text("")
        findings = tool.audit(self.root)["findings"]
        self.assertEqual(findings[0]["kind"], "namespace_directory")
        self.assertTrue(findings[1]["builtin"])

    def test_only_immediate_children(self):
        (self.root / "nested").mkdir()
        (self.root / "nested/json.py").write_text("")
        self.assertEqual(tool.audit(self.root)["status"], "pass")

    def test_case_sensitive(self):
        (self.root / "JSON.py").write_text("")
        self.assertEqual(tool.audit(self.root)["status"], "pass")

    def test_symlink_not_followed(self):
        (self.root / "json.py").symlink_to("/not/a/real/target")
        answer = tool.audit(self.root)
        self.assertEqual(answer["status"], "findings")
        self.assertEqual(answer["findings"][0]["code"], "symlink_not_followed")

    def test_root_symlink_rejected(self):
        (self.root / "link").symlink_to(HERE / "examples/pass", target_is_directory=True)
        self.assertEqual(tool.audit(self.root / "link")["status"], "error")

    def test_package_init_symlink_not_followed(self):
        (self.root / "json").mkdir()
        (self.root / "json/__init__.py").symlink_to("/missing")
        self.assertEqual(tool.audit(self.root)["findings"][0]["code"], "symlink_not_followed")

    def test_entry_boundary(self):
        (self.root / "one").touch()
        self.assertEqual(tool.audit(self.root, max_entries=1)["status"], "pass")
        (self.root / "two").touch()
        self.assertEqual(tool.audit(self.root, max_entries=1)["status"], "error")

    def test_bad_input(self):
        for value in (0, -1, True, 100001, "10"):
            with self.subTest(value=value):
                self.assertEqual(tool.audit(self.root, max_entries=value)["status"], "error")
        self.assertEqual(tool.audit(self.root / "missing")["status"], "error")

    def test_stable_serialization(self):
        self.assertEqual(tool.audit(HERE / "examples/fail"), tool.audit(HERE / "examples/fail"))

    def test_cli_statuses_and_argument_error(self):
        for args, expected in (([str(HERE / "examples/pass")], 0),
                               ([str(HERE / "examples/fail")], 1),
                               ([str(self.root / "missing")], 2),
                               ([str(self.root), "--max-entries", "no"], 2), ([], 2)):
            with self.subTest(args=args):
                p = subprocess.run([sys.executable, "-I", str(HERE / "tool.py"), *args], capture_output=True, text=True)
                self.assertEqual(p.returncode, expected, p.stderr)
                self.assertEqual(json.loads(p.stdout)["schema_version"], 1)
                self.assertEqual(p.stderr, "")

    def test_parent_components_rejected_before_normalization(self):
        safe = self.root / "safe"; safe.mkdir()
        other = self.root / "other"; other.mkdir()
        (other / "sub").mkdir(); (other / "safe").mkdir()
        (other / "safe/json.py").write_text("raise RuntimeError('not imported')")
        (self.root / "link").symlink_to(other / "sub", target_is_directory=True)
        selected = str(self.root) + "/link/../safe"
        self.assertEqual(tool.audit(selected)["status"], "error")
        self.assertEqual(tool.audit(str(safe) + "/../safe")["status"], "error")
        self.assertEqual(tool.audit(safe)["status"], "pass")
        self.assertEqual(tool.audit(str(safe) + "/.")["status"], "pass")
        p = subprocess.run([sys.executable, "-I", str(HERE / "tool.py"), selected], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2); self.assertEqual(p.stderr, "")
        self.assertEqual(json.loads(p.stdout)["status"], "error")

    def test_cli_argument_errors_do_not_echo_input(self):
        secret = "PRIVATE_ARGUMENT_VALUE"
        process = subprocess.run([sys.executable, "-I", str(HERE / "tool.py"),
                                  "--unknown=" + secret], capture_output=True, text=True)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn(secret, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout)["errors"][0]["message"], "invalid command arguments")


if __name__ == "__main__":
    unittest.main()
