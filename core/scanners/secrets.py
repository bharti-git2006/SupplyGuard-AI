"""
Deterministic Secret & Credential Scanner for SupplyGuard AI.
Detects potential exposed AWS keys, GitHub tokens, database URIs, generic API keys,
and private key blocks in project source and config files.
Applies rigorous placeholder filtering and strict secret redaction.
"""

import re
from pathlib import Path
from typing import List, Optional, Set, Tuple

from core.models import ProjectContext, SecurityFinding, FindingCategory, SeverityLevel
from core.scanners.base import BaseScanner

# Obvious placeholder exact matches (case-insensitive)
EXACT_PLACEHOLDERS: Set[str] = {
    "your_api_key",
    "your_api_key_here",
    "your-api-key",
    "your-api-key-here",
    "change_me",
    "change-me",
    "changeme",
    "<token>",
    "<your-token>",
    "<key>",
    "<api_key>",
    "<password>",
    "<your-password>",
    "test-secret",
    "dummy-secret",
    "fake-secret",
    "placeholder",
    "xxxxxxxx",
    "00000000",
    "123456",
    "12345678",
    "password",
    "secret",
    "mysecret",
    "undefined",
    "null",
}

# Substring placeholders (case-insensitive)
SUBSTRING_PLACEHOLDERS: Set[str] = {
    "your_api_key",
    "your-api-key",
    "change_me",
    "change-me",
    "<token>",
    "<your-token>",
    "<api_key>",
    "<your-key>",
    "example.com",
    "example.org",
    "example.net",
    "test-secret",
    "dummy-secret",
    "fake-secret",
    "placeholder",
}

# Regex Patterns
RE_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
RE_GITHUB_TOKEN = re.compile(
    r"\b(ghp_[0-9a-zA-Z]{30,40}|github_pat_[0-9a-zA-Z_]{22,255}|gh[ousr]_[0-9a-zA-Z]{30,40})\b"
)
RE_DB_URI = re.compile(
    r"\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^\s'\"`;]+)",
    re.IGNORECASE,
)
RE_DB_WITH_CREDS = re.compile(
    r"^(?P<scheme>mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/(?P<user>[^:\s'\"`]+):(?P<password>[^@\s'\"`]+)@(?P<rest>[^\s'\"`]+)$",
    re.IGNORECASE,
)
RE_PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)
RE_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|jwt[_-]?secret|password|passwd|db[_-]?pass)['\"]?\s*[:=]\s*(?:(['\"])([^'\"\r\n]{8,})\2|([^\s#'\"`;]{8,}))"
)


def mask_secret(secret: str) -> str:
    """
    Masks sensitive credential strings so the raw secret is never exposed.
    Keeps a minimal prefix/suffix for identification while redacting the sensitive payload.
    """
    s = secret.strip()
    n = len(s)
    if n <= 6:
        return "*" * max(n, 6)
    if n <= 12:
        return f"{s[:2]}{'*' * (n - 4)}{s[-2:]}"
    # For strings > 12 chars, retain 4 chars on each end and replace middle with 12 asterisks
    return f"{s[:4]}************{s[-4:]}"


def mask_db_uri(uri: str) -> Tuple[str, bool]:
    """
    Masks credentials in database URIs if present.
    Returns (masked_uri, has_credentials).
    """
    match = RE_DB_WITH_CREDS.match(uri)
    if match:
        scheme = match.group("scheme")
        user = match.group("user")
        password = match.group("password")
        rest = match.group("rest")
        masked_pwd = mask_secret(password)
        return f"{scheme}://{user}:{masked_pwd}@{rest}", True
    return uri, False


def is_placeholder(value: str) -> bool:
    """Checks whether a string matches common placeholder, dummy, or template patterns."""
    v = value.strip().strip("'\"`").lower()
    if not v:
        return True
    if len(v) < 6:
        return True

    if v in EXACT_PLACEHOLDERS:
        return True

    for ph in SUBSTRING_PLACEHOLDERS:
        if ph in v:
            return True

    # Repeated identical characters like 'xxxxxxxxx' or '00000000'
    if len(set(v)) == 1:
        return True

    return False


def build_safe_snippet(line: str, raw_secret: str, masked_secret: str) -> str:
    """
    Builds a single-line evidence snippet where the exact raw secret is replaced
    by its masked counterpart.
    """
    sanitized_line = line.replace(raw_secret, masked_secret).strip()
    if len(sanitized_line) > 120:
        idx = sanitized_line.find(masked_secret)
        if idx != -1:
            start = max(0, idx - 30)
            end = min(len(sanitized_line), idx + len(masked_secret) + 30)
            prefix = "..." if start > 0 else ""
            suffix = "..." if end < len(sanitized_line) else ""
            return f"{prefix}{sanitized_line[start:end]}{suffix}"
        return sanitized_line[:120] + "..."
    return sanitized_line


class SecretScanner(BaseScanner):
    """Local-first deterministic secret and credential scanner."""

    def scan(self, context: ProjectContext) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        finding_id_counter = 1

        for rel_path in context.relevant_files:
            full_path = context.root_path / rel_path
            if not full_path.exists() or not full_path.is_file():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()

            for line_no, line in enumerate(lines, start=1):
                # 1. Private Key Block Detection (CRITICAL)
                pk_match = RE_PRIVATE_KEY_HEADER.search(line)
                if pk_match:
                    header = pk_match.group(0)
                    findings.append(
                        SecurityFinding(
                            id=f"SEC-{finding_id_counter:03d}",
                            category=FindingCategory.EXPOSED_SECRET,
                            severity=SeverityLevel.CRITICAL,
                            title="Potential exposed private key material detected",
                            description="An unencrypted private key header block was detected in the project.",
                            file_path=str(rel_path.as_posix()),
                            line_number=line_no,
                            snippet=f"{header} [REDACTED KEY CONTENT]",
                            explanation="Private keys in source control permit unauthorized access and identity impersonation.",
                            remediation="Immediately revoke and rotate this key. Remove the key file from git history.",
                            metadata={"secret_type": "private_key"},
                        )
                    )
                    finding_id_counter += 1
                    continue

                # 2. AWS Access Key ID Detection (HIGH)
                for aws_match in RE_AWS_KEY.finditer(line):
                    raw_key = aws_match.group(1)
                    if is_placeholder(raw_key):
                        continue
                    masked = mask_secret(raw_key)
                    snippet = build_safe_snippet(line, raw_key, masked)
                    findings.append(
                        SecurityFinding(
                            id=f"SEC-{finding_id_counter:03d}",
                            category=FindingCategory.EXPOSED_SECRET,
                            severity=SeverityLevel.HIGH,
                            title="Potential exposed AWS credential detected",
                            description="A token matching the pattern of an AWS Access Key ID was detected.",
                            file_path=str(rel_path.as_posix()),
                            line_number=line_no,
                            snippet=snippet,
                            explanation="Hardcoded AWS credentials can allow automated scrapers to access cloud services.",
                            remediation="Revoke the AWS access key in AWS IAM and inject credentials via environment variables.",
                            metadata={"secret_type": "aws_access_key"},
                        )
                    )
                    finding_id_counter += 1

                # 3. GitHub Token Detection (HIGH)
                for gh_match in RE_GITHUB_TOKEN.finditer(line):
                    raw_token = gh_match.group(1)
                    if is_placeholder(raw_token):
                        continue
                    masked = mask_secret(raw_token)
                    snippet = build_safe_snippet(line, raw_token, masked)
                    findings.append(
                        SecurityFinding(
                            id=f"SEC-{finding_id_counter:03d}",
                            category=FindingCategory.EXPOSED_SECRET,
                            severity=SeverityLevel.HIGH,
                            title="Potential exposed GitHub token detected",
                            description="A token matching GitHub Personal Access Token formats was detected.",
                            file_path=str(rel_path.as_posix()),
                            line_number=line_no,
                            snippet=snippet,
                            explanation="GitHub tokens grant programmatic API access to repositories, workflows, and organizations.",
                            remediation="Revoke the token in GitHub Developer Settings and rotate repository secrets.",
                            metadata={"secret_type": "github_token"},
                        )
                    )
                    finding_id_counter += 1

                # 4. Database Connection String Detection (HIGH if creds, MEDIUM otherwise)
                for db_match in RE_DB_URI.finditer(line):
                    raw_uri = db_match.group(1)
                    if is_placeholder(raw_uri):
                        continue
                    masked_uri, has_credentials = mask_db_uri(raw_uri)
                    snippet = build_safe_snippet(line, raw_uri, masked_uri)
                    severity = SeverityLevel.HIGH if has_credentials else SeverityLevel.MEDIUM
                    title = (
                        "Potential exposed database connection string with credentials detected"
                        if has_credentials
                        else "Potential database connection string detected"
                    )
                    findings.append(
                        SecurityFinding(
                            id=f"SEC-{finding_id_counter:03d}",
                            category=FindingCategory.EXPOSED_SECRET,
                            severity=severity,
                            title=title,
                            description="A database connection URI was identified in project files.",
                            file_path=str(rel_path.as_posix()),
                            line_number=line_no,
                            snippet=snippet,
                            explanation="Database URIs containing embedded passwords expose backend datastores to compromise.",
                            remediation="Externalize connection strings into environment variables outside the repository.",
                            metadata={"secret_type": "database_uri", "has_credentials": has_credentials},
                        )
                    )
                    finding_id_counter += 1

                # 5. Generic API Key / Secret / Password Assignment Detection (MEDIUM)
                for gen_match in RE_GENERIC_SECRET_ASSIGNMENT.finditer(line):
                    var_name = gen_match.group(1)
                    quoted_val = gen_match.group(3)
                    unquoted_val = gen_match.group(4)

                    # In code files (.js, .ts, .json), string literals must be quoted
                    is_code_file = rel_path.suffix.lower() in {".js", ".ts", ".mjs", ".cjs", ".json"}
                    if is_code_file and not quoted_val:
                        continue

                    raw_val = (quoted_val or unquoted_val or "").strip()
                    if not raw_val:
                        continue

                    # Filter out code expressions, function calls, and environment lookups
                    if (
                        raw_val.startswith("process.env.")
                        or "(" in raw_val
                        or ")" in raw_val
                        or raw_val.startswith(("get", "fetch", "load", "read", "require", "import"))
                    ):
                        continue

                    if is_placeholder(raw_val):
                        continue
                    # Ignore if the line already matched one of the higher-confidence checks
                    if any(p in raw_val for p in ("AKIA", "ghp_", "mongodb://", "postgres://", "mysql://")):
                        continue

                    masked_val = mask_secret(raw_val)
                    snippet = build_safe_snippet(line, raw_val, masked_val)
                    findings.append(
                        SecurityFinding(
                            id=f"SEC-{finding_id_counter:03d}",
                            category=FindingCategory.EXPOSED_SECRET,
                            severity=SeverityLevel.MEDIUM,
                            title=f"Potential exposed secret detected: {var_name}",
                            description=f"A static credential assignment for '{var_name}' was detected.",
                            file_path=str(rel_path.as_posix()),
                            line_number=line_no,
                            snippet=snippet,
                            explanation="Hardcoding sensitive tokens or passwords in source code increases risk of exposure.",
                            remediation=f"Store '{var_name}' in a secure vault or runtime environment variable.",
                            metadata={"secret_type": "generic_credential", "variable_name": var_name},
                        )
                    )
                    finding_id_counter += 1

        return findings


def scan_secrets(context: ProjectContext) -> List[SecurityFinding]:
    """Public helper function for scanning secrets from a ProjectContext."""
    scanner = SecretScanner()
    return scanner.scan(context)
