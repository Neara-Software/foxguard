<p align="center">
  <img src="assets/logo.svg" width="80" alt="foxguard logo" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  <strong>Security scanner as fast as a linter.</strong>
  <br/>
  118 built-in rules &middot; 10 languages &middot; single Rust binary &middot; sub-second scans
  <br/><br/>
  <a href="https://foxguard.dev">foxguard.dev</a> &middot; <a href="https://www.npmjs.com/package/foxguard">npm</a> &middot; <a href="https://crates.io/crates/foxguard">crates.io</a>
</p>

<p align="center">
  <a href="https://github.com/peaktwilight/foxguard/actions/workflows/ci.yml"><img src="https://github.com/peaktwilight/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/peaktwilight/foxguard"><img src="https://img.shields.io/badge/foxguard-clean-2dd4bf?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTggOEwyMCAyOEwzMiAyMEw0NCAyOEw1NiA4TDUyIDMyTDQ0IDQ0TDM2IDUySDI4TDIwIDQ0TDEyIDMyTDggOFoiIGZpbGw9IiNGNTlFMEIiIGZpbGwtb3BhY2l0eT0iMC4zIiBzdHJva2U9IiNGNTlFMEIiIHN0cm9rZS13aWR0aD0iMyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjxjaXJjbGUgY3g9IjI0IiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjxjaXJjbGUgY3g9IjQwIiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjwvc3ZnPg==" alt="foxguard: clean" /></a>
  <a href="https://www.npmjs.com/package/foxguard"><img src="https://img.shields.io/npm/v/foxguard?color=d97706&label=npm" alt="npm" /></a>
</p>

---

<p align="center">
  <img src="assets/demo.gif" alt="foxguard demo" width="640" />
</p>

Most security scanners take 10–30 seconds. foxguard finishes in under one. Fast enough to run on every save, not just in CI.

```sh
npx foxguard .
```

```
src/auth/login.js
  14:5  CRITICAL  js/no-sql-injection (CWE-89)
        SQL query built with template literal interpolation

src/utils/config.py
   7:1  HIGH      py/no-hardcoded-secret (CWE-798)
        Hardcoded secret in 'api_key'

WARNING 2 issues found: 1 critical, 1 high, 0 medium, 0 low
```

## Why

- **Sub-second scans** — Rust + tree-sitter + rayon. No JVM, no Python runtime, no network calls.
- **118 built-in rules** — SQL injection, XSS, SSRF, command injection, hardcoded secrets, weak crypto, deserialization, and framework-specific checks.
- **10 languages** — JavaScript, TypeScript, Python, Go, Ruby, Java, PHP, Rust, C#, Swift.
- **Secrets scanning** — AWS keys, GitHub/GitLab/Slack/Stripe tokens, private keys. Redacted output.
- **Semgrep-compatible** — Load your existing YAML rules with `--rules`. No vendor lock-in.
- **Pre-commit ready** — `foxguard init` installs a hook. Scans only changed files with `--changed`.
- **CI-friendly** — Terminal, JSON, SARIF output. GitHub Code Scanning integration.

## Install

```sh
npx foxguard .          # no install needed
cargo install foxguard  # or via Rust
```

## Built-in coverage

| Language | Rules | Frameworks |
|----------|-------|------------|
| JavaScript/TypeScript | 24 | Express, JWT, cookies, XSS |
| Python | 26 | Flask, Django, CSRF, session |
| Go | 8 | Gin, net/http, TLS |
| Ruby | 10 | Rails, mass assignment, CSRF |
| Java | 10 | Spring, XXE, deserialization |
| PHP | 10 | Laravel, file inclusion, unserialize |
| Rust | 10 | unsafe, transmute, TLS |
| C# | 10 | .NET, LDAP, XXE, CORS |
| Swift | 10 | iOS keychain, transport, WebView |

## Usage

```sh
foxguard .                          # scan everything
foxguard --changed .                # scan only modified files
foxguard --severity high .          # filter by severity
foxguard secrets .                  # scan for leaked credentials
foxguard secrets --changed .        # secrets on changed files only
foxguard --format sarif .           # SARIF for GitHub Code Scanning
foxguard --rules ./my-rules .       # add Semgrep-compatible YAML rules
foxguard init                       # install pre-commit hook
```

## CI Integration

### GitHub Actions

```yaml
name: Security
on: [push, pull_request]
jobs:
  foxguard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: peaktwilight/foxguard/action@v0.2.1
        with:
          path: .
          severity: medium
          fail-on-findings: "true"
          upload-sarif: "true"
```

Findings show up in **Security → Code Scanning**.

### Any CI

```sh
npx foxguard@latest .                          # scan
npx foxguard@latest --format sarif . > out.sarif  # SARIF output
npx foxguard@latest secrets .                   # secrets scan
```

### Badge

```md
[![foxguard](https://img.shields.io/badge/foxguard-clean-2dd4bf)](https://github.com/peaktwilight/foxguard)
```

## Configuration

foxguard auto-discovers `.foxguard.yml` from the scan path upward.

```yaml
scan:
  baseline: .foxguard/baseline.json
  rules: ./semgrep-rules

secrets:
  baseline: .foxguard/secrets-baseline.json
  exclude_paths:
    - fixtures
    - testdata
  ignore_rules:
    - secret/github-token
```

## Semgrep compatibility

Load existing Semgrep/OpenGrep YAML rules with `--rules`. Supports `pattern`, `pattern-regex`, `pattern-either`, `pattern-not`, `pattern-inside`, `pattern-not-inside`, `metavariable-regex`, and `paths.include/exclude`. See [`COMPATIBILITY.md`](./COMPATIBILITY.md).

## Performance

foxguard built-ins vs Semgrep `auto` on real repos:

| Repo | foxguard | Semgrep | Speedup |
|------|----------|---------|---------|
| express (141 files) | 0.284s | 17.4s | **61x** |
| flask (83 files) | 0.084s | 7.3s | **87x** |
| gin (99 files) | 0.516s | 8.0s | **16x** |

Run `./benchmarks/run.sh` locally to reproduce.

---

*Built by [Peak Twilight](https://doruk.ch) — also building [pwnkit](https://pwnkit.com), [vibecheck](https://vibechecked.doruk.ch), [unfuck](https://unfcked.doruk.ch), [whatdiditdo](https://whatdiditdo.doruk.ch)*

## License

MIT
