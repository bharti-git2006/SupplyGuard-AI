"""
Dangerous Execution & Code Pattern Scanner for SupplyGuard AI.
Analyzes JavaScript/TypeScript source files for:
- Process & command execution (child_process, exec, spawn)
- Outbound network requests and downloads (fetch, http, axios, curl)
- Sensitive environment variable access (AWS keys, secrets, tokens)
- Sensitive local file path references (~/.ssh, ~/.aws)
- Dynamic and encoded execution (eval, new Function, base64 exec)
Features line-level comment filtering and multi-indicator grouping.
Zero code execution, zero network requests.
"""

import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

from core.models import ProjectContext, SecurityFinding, FindingCategory, SeverityLevel
from core.scanners.base import BaseScanner

# Targeted extensions for JS/TS static pattern analysis
CODE_EXTENSIONS: Set[str] = {".js", ".ts", ".mjs", ".cjs"}

# Sensitive environment variable names that indicate credentials
SENSITIVE_ENV_VARS = re.compile(
    r"\bprocess\.env(?:\.(AWS_[A-Z0-9_]+|API[_-]?KEY|SECRET[_-]?KEY|TOKEN|PASSWORD|PASSWD|AUTH[_-]?TOKEN|PRIVATE_KEY|DATABASE_URL|DB_PASS|STRIPE_[A-Z0-9_]+|GITHUB_TOKEN)|\[['\"](AWS_[A-Z0-9_]+|API[_-]?KEY|SECRET[_-]?KEY|TOKEN|PASSWORD|PASSWD|AUTH[_-]?TOKEN|PRIVATE_KEY|DATABASE_URL|DB_PASS|STRIPE_[A-Z0-9_]+|GITHUB_TOKEN)['\"]\])",
    re.IGNORECASE,
)

# Common non-sensitive environment variables to explicitly avoid flagging
BENIGN_ENV_VARS = {"NODE_ENV", "PORT", "HOST", "DEBUG", "PATH", "HOME", "PWD", "PLATFORM", "TZ"}

# Command Execution Patterns
RE_COMMAND_EXEC = re.compile(
    r"\b(?:child_process\.(?:exec|execSync|spawn|spawnSync|fork)|(?:exec|execSync|spawn|spawnSync)\s*\([^\)]*|require\s*\(\s*['\"]child_process['\"]\s*\))\b"
)

# Outbound Network Request Patterns
RE_NETWORK_REQUEST = re.compile(
    r"\b(?:fetch\s*\(|https?\.get\s*\(|https?\.request\s*\(|axios(?:\.(?:get|post|put|request))?\s*\(|urllib(?:\.request)?\s*\(|curl\b|wget\b|Invoke-WebRequest\b)"
)

# Sensitive File System Locations
RE_SENSITIVE_PATHS = re.compile(
    r"(?:~|\/root|\/home\/[^\/\s'\"`]+|[A-Za-z]:\\[Users]+(?:\\[^\s'\"`\\]+)?)\/\.(?:ssh|aws|gnupg|netrc|bash_history)\b|\b(?:\.aws\/credentials|\.ssh\/id_rsa|\.ssh\/authorized_keys|\/etc\/shadow|\/etc\/passwd)\b"
)

# Obfuscated / Dynamic Execution
RE_DYNAMIC_EXEC = re.compile(
    r"\b(?:eval\s*\(|new\s+Function\s*\(|atob\s*\(|Buffer\.from\([^)]*,\s*['\"]base64['\"]\)[^;\n]*\.(?:toString|eval)|powershell(?:\.exe)?\s+.*-[eE](?:nc|ncodedcommand)\b|certutil(?:\.exe)?\s+.*-(?:decode|encode|urlcache)\b)"
)


def is_comment_line(line: str) -> bool:
    """Checks whether a line is a comment in JavaScript / TypeScript."""
    s = line.strip()
    return s.startswith("//") or s.startswith("/*") or s.startswith("*") or s.endswith("*/")


def check_line_indicators(line: str) -> List[Tuple[str, str, str]]:
    """
    Checks a single line for dangerous indicators.
    Returns list of tuples: (indicator_type, indicator_name, matched_pattern).
    """
    if is_comment_line(line):
        return []

    indicators: List[Tuple[str, str, str]] = []

    # 1. Command Execution
    m_cmd = RE_COMMAND_EXEC.search(line)
    if m_cmd:
        indicators.append(("command_execution", "Command Execution", m_cmd.group(0)))

    # 2. Outbound Network Requests
    m_net = RE_NETWORK_REQUEST.search(line)
    if m_net:
        indicators.append(("network_access", "Outbound Network Call", m_net.group(0)))

    # 3. Sensitive Environment Variable Access
    m_env = SENSITIVE_ENV_VARS.search(line)
    if m_env:
        matched_var = m_env.group(1) or m_env.group(2)
        if matched_var and matched_var.upper() not in BENIGN_ENV_VARS:
            indicators.append(("sensitive_env", f"Sensitive Environment Access ({matched_var})", m_env.group(0)))

    # 4. Sensitive File System Locations
    m_path = RE_SENSITIVE_PATHS.search(line)
    if m_path:
        indicators.append(("sensitive_file_path", "Sensitive File Path Reference", m_path.group(0)))

    # 5. Dynamic or Obfuscated Execution
    m_dyn = RE_DYNAMIC_EXEC.search(line)
    if m_dyn:
        indicators.append(("dynamic_execution", "Dynamic/Obfuscated Execution", m_dyn.group(0)))

    return indicators


def compute_severity_and_title(indicators: List[Tuple[str, str, str]]) -> Tuple[SeverityLevel, str, str]:
    """
    Determines composite severity and readable title by grouping indicators on the same line.
    """
    types = {ind[0] for ind in indicators}
    names = [ind[1] for ind in indicators]

    # HIGH combinations per requirements
    has_cmd = "command_execution" in types
    has_net = "network_access" in types
    has_env = "sensitive_env" in types
    has_dyn = "dynamic_execution" in types

    if (has_cmd and has_net) or (has_cmd and has_env) or (has_dyn and (has_cmd or has_net or has_env)):
        severity = SeverityLevel.HIGH
        title = f"Potentially dangerous execution chain: {' + '.join(names)}"
        desc = "Multiple high-risk behaviors combined on a single execution path."
    elif has_cmd:
        severity = SeverityLevel.MEDIUM
        title = "Potentially dangerous command execution detected"
        desc = "Process execution mechanism (child_process/exec/spawn) identified in source code."
    elif has_net:
        severity = SeverityLevel.MEDIUM
        title = "Potentially dangerous outbound network request detected"
        desc = "Outbound HTTP or download client identified in source code."
    elif has_env:
        severity = SeverityLevel.MEDIUM
        title = f"Sensitive credential environment access detected: {names[0]}"
        desc = "Direct runtime access to credential-bearing environment variables."
    elif has_dyn:
        severity = SeverityLevel.MEDIUM
        title = "Dynamic or obfuscated code execution detected"
        desc = "Use of eval, new Function, or base64 decode pattern detected."
    elif "sensitive_file_path" in types:
        severity = SeverityLevel.MEDIUM
        title = "Sensitive file path reference detected"
        desc = "Source references sensitive user directories such as SSH or cloud credentials."
    else:
        severity = SeverityLevel.LOW
        title = f"Suspicious execution pattern: {', '.join(names)}"
        desc = "Static pattern indicator detected."

    return severity, title, desc


class DangerousPatternScanner(BaseScanner):
    """Static pattern scanner for JavaScript/TypeScript files."""

    def scan(self, context: ProjectContext) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        finding_id_counter = 1

        for rel_path in context.relevant_files:
            if rel_path.suffix.lower() not in CODE_EXTENSIONS:
                continue

            full_path = context.root_path / rel_path
            if not full_path.exists() or not full_path.is_file():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = content.splitlines()

            for line_no, line in enumerate(lines, start=1):
                indicators = check_line_indicators(line)
                if not indicators:
                    continue

                severity, title, desc = compute_severity_and_title(indicators)
                snippet = line.strip()
                if len(snippet) > 120:
                    snippet = snippet[:117] + "..."

                matched_types = [ind[0] for ind in indicators]

                findings.append(
                    SecurityFinding(
                        id=f"EXEC-{finding_id_counter:03d}",
                        category=FindingCategory.DANGEROUS_EXECUTION,
                        severity=severity,
                        title=title,
                        description=desc,
                        file_path=str(rel_path.as_posix()),
                        line_number=line_no,
                        snippet=snippet,
                        explanation=(
                            "Static analysis detected dangerous code patterns. In supply-chain context, "
                            "these mechanisms can be leveraged for unauthorized process execution, "
                            "remote payload download, or credential exfiltration."
                        ),
                        remediation=(
                            "Inspect the code to verify that process execution, network calls, or credential "
                            "access are legitimate and strictly bounded."
                        ),
                        metadata={
                            "indicator_types": matched_types,
                            "raw_indicators": [ind[1] for ind in indicators],
                            "has_network": "network_access" in matched_types,
                            "has_command_exec": "command_execution" in matched_types,
                            "has_sensitive_env": "sensitive_env" in matched_types,
                        },
                    )
                )
                finding_id_counter += 1

        return findings


def scan_dangerous_patterns(context: ProjectContext) -> List[SecurityFinding]:
    """Public helper function for scanning dangerous code patterns."""
    scanner = DangerousPatternScanner()
    return scanner.scan(context)
