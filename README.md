# SupplyGuard AI

### Local-First Software Supply-Chain Risk Analyzer

SupplyGuard AI is a local-first security analyzer for Node.js projects that identifies potential software supply-chain risks such as exposed credentials, dependency reproducibility issues, installation lifecycle behavior, and suspicious command or network activity.

Instead of treating every static finding independently, SupplyGuard correlates technically related findings into higher-level **risk chains** and generates an actionable security assessment.

---

## Problem

Modern applications depend heavily on third-party packages and installation scripts. A project may contain individual warnings such as:

- exposed API credentials
- dependency version ranges
- missing lockfiles
- lifecycle installation hooks
- command execution
- outbound network behavior
- sensitive environment-variable access

Individually, these findings can be difficult to prioritize.

SupplyGuard AI connects related evidence to answer:

> **What was found, how are the findings related, and why does the combination matter?**

---

## Solution

SupplyGuard follows a multi-stage local analysis pipeline:

```text
Project ZIP
    │
    ▼
Safe Project Ingestion
    │
    ▼
Static Security Scanners
    ├── Secret Scanner
    ├── Dependency Analyzer
    ├── Installation Script Analyzer
    └── Dangerous Pattern Scanner
    │
    ▼
Risk Correlation Engine
    │
    ▼
SupplyGuard Risk Priority Score
    │
    ▼
Security Reasoning Layer
    │
    ▼
Structured Security Assessment
