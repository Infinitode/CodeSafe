# Security Policy

We take the security of CodeSafe seriously. Thank you for helping keep CodeSafe and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report them privately using one of the following channels:

1. **GitHub private vulnerability reporting (preferred):** open the [Security tab](https://github.com/Infinitode/CodeSafe/security) of this repository and choose **Report a vulnerability** (or go directly to https://github.com/Infinitode/CodeSafe/security/advisories/new). This creates a private advisory visible only to the maintainers, and allows us to collaborate on the fix and publish a coordinated disclosure.
2. **Email:** [infinitode.ltd@gmail.com](mailto:infinitode.ltd@gmail.com) with a subject line starting with `[SECURITY] CodeSafe`.

Please include as much of the following as you can:

- The package version(s) affected
- A description of the vulnerability and its impact
- Steps to reproduce / a proof of concept
- The environment (OS, Python version)
- Any suggested mitigations or fixes (optional)

## What to expect

- We aim to acknowledge your report within **7 days** (best effort; this is a small open-source project).
- We will assess the report, determine the severity (CVSS) and the affected version range, and keep you informed of progress.
- We will develop the fix privately, prepare a draft GitHub Security Advisory, and publish the advisory, the fix (a new release) and (if applicable) request a CVE ID when the release is out — following coordinated disclosure.
- With your permission, we will credit you in the advisory and changelog. If you prefer to remain anonymous, just say so.

We ask that you give us reasonable time to release a fix before any public disclosure.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 0.0.6 and later | ✅ Yes |
| 0.0.5 | ⚠️ Known issue — see [GHSA-m85r-gp57-6p5q](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-m85r-gp57-6p5q); upgrade to 0.0.6 |
| 0.0.1 – 0.0.4 | ❌ No — critical sandbox escape, [CVE-2026-133467](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8) |

Only the latest release receives fixes. Please upgrade rather than report issues that may already be fixed.

## Published advisories

| Advisory | CVE / GHSA | Affected | Fixed in |
| :--- | :--- | :--- | :--- |
| `safe_eval` sandbox escape via indirect subscript call | CVE-2026-133467 · [GHSA-7gp8-3j6q-v4h8](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-7gp8-3j6q-v4h8) | 0.0.1 - 0.0.4 | 0.0.5 |
| `safe_eval` sandbox escape via dunder attribute string-argument (`allow_attributes=True`) | [GHSA-m85r-gp57-6p5q](https://github.com/Infinitode/CodeSafe/security/advisories/GHSA-m85r-gp57-6p5q) · CVE pending | 0.0.3 - 0.0.5 | 0.0.6 |

See https://github.com/Infinitode/CodeSafe/security/advisories for the canonical list.

## Scope notes

CodeSafe contains two very different components, and reports are welcome for both, but keep in mind:

- **`safe_eval()`** is a best-effort sandbox, not a hard security boundary. Reports demonstrating escapes under documented usage are very much in scope. Reports that require you to defeat host-level isolation (containers, seccomp, etc.) are out of scope.
- **Encryption** protects code at rest. The built-in default key is public by design; only payloads encrypted with a user-supplied key can be confidential (see [Security Limitations & Notes](README.md#security-limitations--notes)). Reports of integrity/confidentiality failures in the v2 format (wrong key accepted, tampered payload decrypting successfully) are in scope; "the default key is public" is by design, not a vulnerability.

Thank you for helping make CodeSafe safer!
