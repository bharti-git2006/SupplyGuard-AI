"""
Unit tests for SupplyGuard AI Node.js Dependency Scanner.
Tests version range checks, lockfile presence, external URLs, lifecycle hooks,
malformed JSON resilience, and ensures zero network or npm execution.
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
from core.scanners.dependencies import (
    scan_dependencies,
    count_declared_dependencies,
    DependencyScanner,
)


class TestDependencyScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="supplyguard_deps_test_")
        self.proj_path = Path(self.temp_dir)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def write_json(self, rel_path: str, data: dict) -> Path:
        target = self.proj_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return target

    def write_text(self, rel_path: str, content: str) -> Path:
        target = self.proj_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def test_1_package_json_dependency_detection(self):
        """Test 1: Basic dependency declaration is detected."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"fake-express": "4.18.2"},
        })
        self.write_json("package-lock.json", {"name": "sample-pkg", "lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        # Exact pinned version with lockfile should have 0 reproducibility findings
        self.assertEqual(len(findings), 0)

    def test_2_dependencies_count(self):
        """Test 2: Accurately counts dependencies section."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"dep-a": "1.0.0", "dep-b": "2.0.0"},
        })
        ctx = discover_directory(self.proj_path)
        counts = count_declared_dependencies(ctx)

        self.assertEqual(counts["dependencies"], 2)
        self.assertEqual(counts["devDependencies"], 0)
        self.assertEqual(counts["total"], 2)

    def test_3_dev_dependencies_count(self):
        """Test 3: Accurately counts devDependencies section."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"dep-prod": "1.0.0"},
            "devDependencies": {"dep-dev1": "1.0.0", "dep-dev2": "1.0.0", "dep-dev3": "1.0.0"},
        })
        ctx = discover_directory(self.proj_path)
        counts = count_declared_dependencies(ctx)

        self.assertEqual(counts["dependencies"], 1)
        self.assertEqual(counts["devDependencies"], 3)
        self.assertEqual(counts["total"], 4)

    def test_4_caret_version_range_detection(self):
        """Test 4: Detects caret (^) version range."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"fake-lib": "^1.2.3"},
        })
        self.write_json("package-lock.json", {"lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK)
        self.assertEqual(f.severity, SeverityLevel.LOW)
        self.assertIn("version range", f.title.lower())
        self.assertEqual(f.metadata.get("declared_version"), "^1.2.3")

    def test_5_tilde_version_range_detection(self):
        """Test 5: Detects tilde (~) version range."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"fake-utils": "~2.4.0"},
        })
        self.write_json("package-lock.json", {"lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.LOW)
        self.assertEqual(f.metadata.get("declared_version"), "~2.4.0")

    def test_6_wildcard_version_detection(self):
        """Test 6: Detects wildcard (*) version specifier."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"unstable-pkg": "*"},
        })
        self.write_json("package-lock.json", {"lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.DEPENDENCY_REPRODUCIBILITY_RISK)
        self.assertEqual(f.severity, SeverityLevel.MEDIUM)
        self.assertIn("wildcard", f.title.lower())

    def test_7_missing_package_lock_detection(self):
        """Test 7: Flags missing package-lock.json when dependencies exist."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"fake-core": "1.0.0"},
        })
        # Note: no package-lock.json written

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        lock_findings = [f for f in findings if "package-lock.json is missing" in f.title]
        self.assertEqual(len(lock_findings), 1)
        self.assertEqual(lock_findings[0].severity, SeverityLevel.MEDIUM)

    def test_8_existing_package_lock_detection(self):
        """Test 8: Presence of package-lock.json suppresses missing lockfile alert."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"fake-core": "1.0.0"},
        })
        self.write_json("package-lock.json", {"lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        lock_findings = [f for f in findings if "package-lock.json is missing" in f.title]
        self.assertEqual(len(lock_findings), 0)

    def test_9_direct_git_dependency_detection(self):
        """Test 9: Detects direct git repository dependency URL."""
        git_url = "git+https://github.com/example-org/fake-repo.git"
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"git-dep": git_url},
        })
        self.write_json("package-lock.json", {"lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.INFO)
        self.assertIn("external url", f.title.lower())
        self.assertEqual(f.metadata.get("risk_type"), "external_url_dependency")

    def test_10_direct_tarball_url_dependency_detection(self):
        """Test 10: Detects direct tarball URL dependency."""
        tar_url = "https://example.com/packages/custom-lib-1.0.0.tgz"
        self.write_json("package.json", {
            "name": "sample-pkg",
            "dependencies": {"tar-dep": tar_url},
        })
        self.write_json("package-lock.json", {"lockfileVersion": 3})

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.INFO)
        self.assertIn("external url", f.title.lower())

    def test_11_lifecycle_hook_detection(self):
        """Test 11: Detects single postinstall lifecycle hook."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "scripts": {
                "postinstall": "node ./scripts/build.js",
                "test": "jest",
            },
        })

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        hook_findings = [f for f in findings if f.category == FindingCategory.INSTALL_HOOK]
        self.assertEqual(len(hook_findings), 1)
        self.assertEqual(hook_findings[0].severity, SeverityLevel.INFO)
        self.assertEqual(hook_findings[0].metadata.get("hook_name"), "postinstall")
        self.assertEqual(hook_findings[0].metadata.get("script_command"), "node ./scripts/build.js")

    def test_12_multiple_lifecycle_hooks_detection(self):
        """Test 12: Detects multiple lifecycle hooks (preinstall, postinstall, prepare)."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "scripts": {
                "preinstall": "echo pre",
                "postinstall": "node setup.js",
                "prepare": "husky install",
                "start": "node index.js",
            },
        })

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        hook_findings = [f for f in findings if f.category == FindingCategory.INSTALL_HOOK]
        hook_names = {f.metadata.get("hook_name") for f in hook_findings}
        self.assertEqual(hook_names, {"preinstall", "postinstall", "prepare"})
        self.assertNotIn("start", hook_names)

    def test_13_no_dependencies_yields_no_missing_lockfile_alert(self):
        """Test 13: Project with zero dependencies does NOT trigger missing lockfile alert."""
        self.write_json("package.json", {
            "name": "zero-dep-tool",
            "version": "1.0.0",
        })

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 0)

    def test_14_malformed_package_json_handling(self):
        """Test 14: Invalid JSON in package.json produces CONFIG_ISSUE finding without crashing."""
        self.write_text("package.json", '{\n  "name": "broken-json",\n  "dependencies": {\n')  # Incomplete JSON

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.CONFIG_ISSUE)
        self.assertIn("malformed", f.title.lower())

    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_15_verify_no_npm_or_network_execution(self, mock_popen, mock_run):
        """Test 15: Confirms scanner never invokes subprocess or npm execution."""
        self.write_json("package.json", {
            "name": "sample-pkg",
            "scripts": {"postinstall": "malicious-cmd-that-must-never-run"},
            "dependencies": {"target-pkg": "^1.0.0"},
        })

        ctx = discover_directory(self.proj_path)
        findings = scan_dependencies(ctx)

        mock_run.assert_not_called()
        mock_popen.assert_not_called()
        self.assertTrue(len(findings) >= 1)


if __name__ == "__main__":
    unittest.main()
