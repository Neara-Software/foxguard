# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in foxguard itself (not in the rules it detects), please report it responsibly:

1. **Do not** open a public issue.
2. Email **doruk@doruk.ch** with a description of the vulnerability.
3. You'll receive a response within 48 hours.

## Scope

- Vulnerabilities in foxguard's own code (parser, CLI, output handling)
- Supply chain issues in dependencies
- False negatives in built-in rules (rules that should fire but don't)

## Out of Scope

- The intentionally vulnerable test fixtures in `tests/fixtures/`
- Vulnerabilities in repos you scan with foxguard
