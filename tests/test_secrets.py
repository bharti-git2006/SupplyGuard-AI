"""
Unit tests for SupplyGuard AI Secret Scanner.
Uses ONLY synthetic fake credentials to verify detections, masking, line numbers,
severity mapping, and complete absence of raw secrets in finding outputs.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from core.ingestion import discover_directory
from core.models import SeverityLevel, FindingCategory
from core.scanners.secrets import scan_secrets, mask_secret, is_placeholder


class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="supplyguard_secrets_test_")
        self.proj_path = Path(self.temp_dir)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def write_file(self, rel_path: str, content: str) -> Path:
        target = self.proj_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def test_1_aws_key_detection(self):
        """Test 1: Detects synthetic AWS Access Key ID."""
        raw_key = "AKIAFAKE1234567890AB"
        self.write_file(".env", f"AWS_ACCESS_KEY_ID={raw_key}\n")
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, FindingCategory.EXPOSED_SECRET)
        self.assertEqual(f.severity, SeverityLevel.HIGH)
        self.assertIn("AWS", f.title)
        self.assertIn(mask_secret(raw_key), f.snippet)

    def test_2_github_token_detection(self):
        """Test 2: Detects synthetic GitHub PAT."""
        raw_token = "ghp_SyntheticGitHubTokenForTest1234567"
        self.write_file("config.js", f'const token = "{raw_token}";\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.HIGH)
        self.assertIn("GitHub", f.title)
        self.assertIn(mask_secret(raw_token), f.snippet)

    def test_3_mongodb_connection_string_detection(self):
        """Test 3: Detects MongoDB URI with embedded credentials."""
        raw_pwd = "syntheticMongoPass123"
        uri = f"mongodb://admin:{raw_pwd}@cluster0.internal:27017/prod"
        self.write_file("database.js", f'const uri = "{uri}";\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.HIGH)
        self.assertIn("database", f.title.lower())
        self.assertNotIn(raw_pwd, f.snippet)
        self.assertIn(mask_secret(raw_pwd), f.snippet)

    def test_4_postgresql_connection_string_detection(self):
        """Test 4: Detects PostgreSQL URI with credentials."""
        raw_pwd = "syntheticPostgresPass456"
        uri = f"postgresql://dbuser:{raw_pwd}@postgres.internal:5432/app"
        self.write_file(".env.local", f"DATABASE_URL={uri}\n")
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.HIGH)
        self.assertNotIn(raw_pwd, f.snippet)

    def test_5_generic_api_key_detection(self):
        """Test 5: Detects generic API key assignment."""
        raw_val = "syntheticSecretApiKey998877"
        self.write_file("service.ts", f'const API_KEY = "{raw_val}";\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.MEDIUM)
        self.assertIn("API_KEY", f.title)

    def test_6_generic_password_detection(self):
        """Test 6: Detects static password assignment."""
        raw_pwd = "syntheticPasswordValue123456"
        self.write_file("settings.json", f'{{"PASSWORD": "{raw_pwd}"}}\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.MEDIUM)

    def test_7_private_key_block_detection(self):
        """Test 7: Detects private key block with CRITICAL severity."""
        content = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0syntheticKeyBlockForTestingOnly\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        self.write_file("id_rsa", content)
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, SeverityLevel.CRITICAL)
        self.assertIn("private key", f.title.lower())
        self.assertIn("[REDACTED KEY CONTENT]", f.snippet)

    def test_8_placeholder_exclusion(self):
        """Test 8: Ensures obvious placeholders and examples are NOT flagged."""
        content = (
            'API_KEY="YOUR_API_KEY"\n'
            'API_KEY="YOUR_API_KEY_HERE"\n'
            'TOKEN="CHANGE_ME"\n'
            'SECRET="<your-token>"\n'
            'PASSWORD="test-secret"\n'
            'KEY="dummy-secret"\n'
            'TEST_ID="00000000"\n'
            'PLACEHOLDER="xxxxxxxx"\n'
            'DB_URL="mongodb://example.com/test"\n'
        )
        self.write_file(".env", content)
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 0, f"Expected 0 findings for placeholders, got: {findings}")

    def test_9_normal_variable_and_function_usage_not_flagged(self):
        """Test 9: Verifies normal variable references or function calls are not flagged."""
        content = (
            'const apiKey = getApiKey();\n'
            'const token = process.env.API_KEY;\n'
            'function setPassword(password) { return true; }\n'
            'let userToken = fetchTokenFromVault();\n'
        )
        self.write_file("auth.js", content)
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 0)

    def test_10_correct_file_path(self):
        """Test 10: Reports exact relative file path."""
        self.write_file("nested/sub/config.js", 'const API_KEY = "syntheticTokenValue12345";\n')
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file_path, "nested/sub/config.js")

    def test_11_correct_line_number(self):
        """Test 11: Reports exact 1-indexed line number."""
        content = (
            "// Line 1: Header\n"
            "// Line 2: Comment\n"
            "// Line 3: Another comment\n"
            'const API_KEY = "syntheticTokenValueLine4";\n'
        )
        self.write_file("index.js", content)
        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_number, 4)

    def test_12_severity_assignment(self):
        """Test 12: Correct severity tiers across different credential types."""
        # 1. Private key -> CRITICAL
        self.write_file("key.pem", "-----BEGIN PRIVATE KEY-----\nMIIE...\n")
        # 2. AWS key -> HIGH
        self.write_file("aws.env", "AWS_ACCESS_KEY_ID=AKIAFAKE1234567890CD\n")
        # 3. Generic key -> MEDIUM
        self.write_file("gen.js", 'const API_KEY = "syntheticGenericKey99";\n')

        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        severity_map = {f.file_path: f.severity for f in findings}
        self.assertEqual(severity_map.get("key.pem"), SeverityLevel.CRITICAL)
        self.assertEqual(severity_map.get("aws.env"), SeverityLevel.HIGH)
        self.assertEqual(severity_map.get("gen.js"), SeverityLevel.MEDIUM)

    def test_13_secret_masking(self):
        """Test 13: Verifies mask_secret behavior for various lengths."""
        short_val = "secret"
        med_val = "abcdefgh1234"
        long_val = "AKIAFAKE1234567890AB"

        self.assertEqual(mask_secret(short_val), "******")
        self.assertEqual(mask_secret(med_val), "ab********34")
        self.assertEqual(mask_secret(long_val), "AKIA************90AB")

    def test_14_raw_secret_does_not_occur_in_finding_representation(self):
        """
        Test 14: Verifies raw secret NEVER occurs in snippet, title,
        description, metadata, or serialized dictionary.
        """
        raw_secret = "syntheticCriticalSecret98765"
        self.write_file(".env", f'API_KEY="{raw_secret}"\n')

        ctx = discover_directory(self.proj_path)
        findings = scan_secrets(ctx)

        self.assertEqual(len(findings), 1)
        f = findings[0]
        finding_dict = f.to_dict()
        finding_str = str(f)
        dict_str = str(finding_dict)

        self.assertNotIn(raw_secret, f.snippet)
        self.assertNotIn(raw_secret, f.title)
        self.assertNotIn(raw_secret, f.description)
        self.assertNotIn(raw_secret, f.explanation)
        self.assertNotIn(raw_secret, f.remediation)
        self.assertNotIn(raw_secret, finding_str)
        self.assertNotIn(raw_secret, dict_str)


if __name__ == "__main__":
    unittest.main()
