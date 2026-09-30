"""
Unit tests for SupplyGuard AI project ingestion and safe ZIP handling.
Validates security guards, resource limits, traversal prevention, and ecosystem discovery.
"""

import io
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from core.ingestion import (
    ingest_project,
    discover_directory,
    extract_zip_safely,
    is_binary_file,
    ZipSecurityError,
    ResourceLimitError,
    IngestionError,
    MAX_FILE_SIZE,
)


class TestIngestion(unittest.TestCase):
    def setUp(self):
        self.temp_dirs = []

    def tearDown(self):
        for d in self.temp_dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)

    def create_temp_dir(self) -> Path:
        d = tempfile.mkdtemp(prefix="supplyguard_test_")
        self.temp_dirs.append(d)
        return Path(d)

    def test_a_normal_zip_extraction(self):
        """Test A: Normal valid ZIP extracts properly and discovers project files."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("package.json", '{"name": "test-app", "version": "1.0.0"}')
            zf.writestr("src/index.js", 'console.log("hello");')
            zf.writestr(".env", "PORT=3000")

        zip_buffer.seek(0)
        ctx = ingest_project(zip_buffer, project_name="normal_app")
        try:
            self.assertEqual(ctx.project_name, "normal_app")
            self.assertIn("Node.js", ctx.detected_ecosystems)
            rel_paths = {p.as_posix() for p in ctx.relevant_files}
            self.assertIn("package.json", rel_paths)
            self.assertIn("src/index.js", rel_paths)
            self.assertIn(".env", rel_paths)
            self.assertEqual(ctx.relevant_file_count, 3)
        finally:
            ctx.cleanup()

    def test_b_zip_path_traversal_relative(self):
        """Test B: ZIP path traversal attempt (e.g. ../../evil.txt) is blocked."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../../evil.txt", "malicious payload")

        zip_buffer.seek(0)
        with self.assertRaises(ZipSecurityError) as cm:
            ingest_project(zip_buffer)
        self.assertIn("path traversal", str(cm.exception).lower())

    def test_c_absolute_path_zip_entries(self):
        """Test C: Absolute-path ZIP entries (/evil.txt or C:\\evil.txt) are blocked."""
        # Test leading forward slash
        zip_buffer1 = io.BytesIO()
        with zipfile.ZipFile(zip_buffer1, "w") as zf:
            zf.writestr("/evil.txt", "root attack")
        zip_buffer1.seek(0)
        with self.assertRaises(ZipSecurityError):
            ingest_project(zip_buffer1)

        # Test Windows drive letter
        zip_buffer2 = io.BytesIO()
        with zipfile.ZipFile(zip_buffer2, "w") as zf:
            zf.writestr("C:\\evil.txt", "drive letter attack")
        zip_buffer2.seek(0)
        with self.assertRaises(ZipSecurityError):
            ingest_project(zip_buffer2)

    def test_d_ignored_directories(self):
        """Test D: Ignored directories (.git, node_modules, etc.) are pruned."""
        test_dir = self.create_temp_dir()
        (test_dir / "package.json").write_text('{"name": "ignore-test"}', encoding="utf-8")
        (test_dir / "src").mkdir()
        (test_dir / "src" / "app.js").write_text('console.log("src");', encoding="utf-8")

        # Create ignored directories and files
        (test_dir / "node_modules" / "express").mkdir(parents=True)
        (test_dir / "node_modules" / "express" / "index.js").write_text("module.exports = {};", encoding="utf-8")
        (test_dir / ".git").mkdir()
        (test_dir / ".git" / "config").write_text("[core]", encoding="utf-8")
        (test_dir / "dist").mkdir()
        (test_dir / "dist" / "bundle.js").write_text("bundled", encoding="utf-8")

        ctx = discover_directory(test_dir)
        all_paths = [p.as_posix() for p in ctx.all_discovered_files]

        self.assertIn("package.json", all_paths)
        self.assertIn("src/app.js", all_paths)

        # None of the files in ignored directories should be discovered
        for p in all_paths:
            self.assertFalse(p.startswith("node_modules/"), f"Unexpected file in node_modules: {p}")
            self.assertFalse(p.startswith(".git/"), f"Unexpected file in .git: {p}")
            self.assertFalse(p.startswith("dist/"), f"Unexpected file in dist: {p}")

    def test_e_file_size_limits(self):
        """Test E: Exceeding individual extracted file size limit is blocked."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 5MB + 1024 bytes of zeroes compresses to only ~5 KB in DEFLATE
            payload = b"0" * (MAX_FILE_SIZE + 1024)
            zf.writestr("large_file.js", payload)

        zip_buffer.seek(0)
        with self.assertRaises(ResourceLimitError) as cm:
            ingest_project(zip_buffer)
        self.assertIn("exceeds limit", str(cm.exception).lower())

    def test_f_maximum_extracted_file_count(self):
        """Test F: Archive exceeding 10,000 entries is rejected gracefully."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            for i in range(10_001):
                zf.writestr(f"file_{i}.txt", "")

        zip_buffer.seek(0)
        with self.assertRaises(ResourceLimitError) as cm:
            ingest_project(zip_buffer)
        self.assertIn("entries", str(cm.exception).lower())

    def test_g_nodejs_ecosystem_detection(self):
        """Test G: Node.js ecosystem is detected when package.json is present."""
        test_dir = self.create_temp_dir()
        # Case 1: No package.json
        (test_dir / "README.md").write_text("Hello", encoding="utf-8")
        ctx1 = discover_directory(test_dir)
        self.assertEqual(ctx1.detected_ecosystems, [])

        # Case 2: With package.json
        (test_dir / "package.json").write_text("{}", encoding="utf-8")
        ctx2 = discover_directory(test_dir)
        self.assertIn("Node.js", ctx2.detected_ecosystems)

    def test_h_relevant_file_discovery(self):
        """Test H: Relevant files (.js, .ts, .json, .env, .yaml) vs non-code text files."""
        test_dir = self.create_temp_dir()
        (test_dir / "package.json").write_text("{}", encoding="utf-8")
        (test_dir / "index.js").write_text("code", encoding="utf-8")
        (test_dir / "service.ts").write_text("code", encoding="utf-8")
        (test_dir / "config.yaml").write_text("key: value", encoding="utf-8")
        (test_dir / ".env").write_text("PORT=8080", encoding="utf-8")
        (test_dir / "notes.txt").write_text("just some notes", encoding="utf-8")
        (test_dir / "README.md").write_text("# Readme", encoding="utf-8")

        ctx = discover_directory(test_dir)
        relevant = [p.as_posix() for p in ctx.relevant_files]
        all_discovered = [p.as_posix() for p in ctx.all_discovered_files]

        self.assertIn("package.json", relevant)
        self.assertIn("index.js", relevant)
        self.assertIn("service.ts", relevant)
        self.assertIn("config.yaml", relevant)
        self.assertIn(".env", relevant)

        # notes.txt and README.md are discovered in all_files but not in relevant_files
        self.assertNotIn("notes.txt", relevant)
        self.assertNotIn("README.md", relevant)
        self.assertIn("notes.txt", all_discovered)
        self.assertIn("README.md", all_discovered)

    def test_i_binary_file_handling(self):
        """Test I: Binary files are detected and excluded from relevant files."""
        test_dir = self.create_temp_dir()
        # Binary via extension (.png)
        png_path = test_dir / "logo.png"
        png_path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

        # Binary via null byte in disguised file (.js but has null bytes)
        null_byte_js = test_dir / "corrupted.js"
        null_byte_js.write_bytes(b"var x = 1;\x00\x00\x00secret")

        # Normal text JS
        normal_js = test_dir / "clean.js"
        normal_js.write_text("console.log('clean');", encoding="utf-8")

        self.assertTrue(is_binary_file(png_path))
        self.assertTrue(is_binary_file(null_byte_js))
        self.assertFalse(is_binary_file(normal_js))

        ctx = discover_directory(test_dir)
        relevant = [p.as_posix() for p in ctx.relevant_files]
        self.assertIn("clean.js", relevant)
        self.assertNotIn("logo.png", relevant)
        self.assertNotIn("corrupted.js", relevant)


if __name__ == "__main__":
    unittest.main()
