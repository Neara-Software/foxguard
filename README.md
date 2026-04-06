<p align="center">
  <img src="assets/logo.svg" width="80" alt="foxguard logo" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  <strong>Security scanner as fast as a linter.</strong>
  <br/>
  100+ built-in rules &middot; 10 languages &middot; single Rust binary &middot; sub-second scans
  <br/><br/>
  <a href="https://foxguard.dev">foxguard.dev</a> &middot; <a href="https://www.npmjs.com/package/foxguard">npm</a> &middot; <a href="https://crates.io/crates/foxguard">crates.io</a>
</p>

<p align="center">
  <a href="https://github.com/peaktwilight/foxguard/actions/workflows/ci.yml"><img src="https://github.com/peaktwilight/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/peaktwilight/foxguard"><img src="https://img.shields.io/badge/foxguard-clean-2dd4bf?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTggOEwyMCAyOEwzMiAyMEw0NCAyOEw1NiA4TDUyIDMyTDQ0IDQ0TDM2IDUySDI4TDIwIDQ0TDEyIDMyTDggOFoiIGZpbGw9IiNGNTlFMEIiIGZpbGwtb3BhY2l0eT0iMC4zIiBzdHJva2U9IiNGNTlFMEIiIHN0cm9rZS13aWR0aD0iMyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjxjaXJjbGUgY3g9IjI0IiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjxjaXJjbGUgY3g9IjQwIiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjwvc3ZnPg==" alt="foxguard: clean" /></a>
  <a href="https://crates.io/crates/foxguard"><img src="https://img.shields.io/crates/v/foxguard?color=d97706&label=crates.io" alt="crates.io" /></a>
  <a href="https://www.npmjs.com/package/foxguard"><img src="https://img.shields.io/npm/v/foxguard?color=d97706&label=npm" alt="npm" /></a>
</p>

---

<p align="center">
  <img src="assets/demo.gif" alt="foxguard vs semgrep side-by-side" width="640" />
</p>

Security scanners are slow. 10 seconds, 30 seconds, sometimes a minute. So developers don't run them locally — they get pushed to CI, findings pile up in PRs, and nobody looks at them.

foxguard fixes this by being fast enough that you never notice it's there. Same scan, 0.03 seconds instead of 10. You can run it on every save, every commit, every push. Security feedback becomes instant.

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

WARNING 2 issues in 5 files (0.03s): 1 critical, 1 high, 0 medium, 0 low
```

## How

Rust + [tree-sitter](https://tree-sitter.github.io/) for AST parsing + [rayon](https://github.com/rayon-rs/rayon) for parallelism. No JVM startup, no Python interpreter, no network calls, no rule download step. Just a native binary that reads your files and reports findings.

100+ built-in rules across 10 languages. SQL injection, XSS, SSRF, command injection, hardcoded secrets, weak crypto, unsafe deserialization, log injection, and framework-specific checks for Express, Django, Rails, Spring, Laravel, Gin, .NET, and iOS.

Also scans for leaked credentials (AWS keys, GitHub/GitLab/Slack/Stripe tokens, private keys) with redacted output. Loads Semgrep-compatible YAML rules with `--rules` if you have existing ones. Outputs terminal, JSON, or SARIF for GitHub Code Scanning.

foxguard dogfoods itself — it scans its own Rust source in CI on every push.

## Install

```sh
npx foxguard .                         # no install needed
brew install peaktwilight/tap/foxguard # Homebrew (macOS/Linux)
cargo install foxguard                 # crates.io
```

**Editor:** Install the [VS Code extension](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard) — scans on save, shows findings as underlines.

## Performance

Real-world benchmarks on local codebases:

| Repo | Files | foxguard | Semgrep (cached) | Speedup |
|------|-------|----------|-------------------|---------|
| youtube-reader (Next.js) | 41 | **0.03s** | 4.6s | **153x** |
| doruk.ch (Astro) | 28 | **0.04s** | 5.4s | **134x** |
| SwissPriceScraper (Python) | 17 | **0.01s** | 4.8s | **482x** |
| express (framework) | 141 | **0.28s** | 17.4s | **61x** |
| flask (framework) | 83 | **0.08s** | 7.3s | **87x** |

Semgrep times measured with cached rules (second run). foxguard has no cache — it's just fast.

## Built-in coverage

| Language | Rules | Frameworks |
|----------|-------|------------|
| JavaScript/TypeScript | 25 | Express, JWT, cookies, XSS, log injection |
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
foxguard --changed .                # only modified files
foxguard --severity high .          # filter by severity
foxguard secrets .                  # leaked credentials
foxguard secrets --changed .        # secrets on changed files
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
      - uses: peaktwilight/foxguard/action@v0.3.2
        with:
          path: .
          severity: medium
          fail-on-findings: "true"
          upload-sarif: "true"
```

Findings show up in **Security → Code Scanning**.

### Any CI

```sh
npx foxguard@latest .                             # scan
npx foxguard@latest --format sarif . > out.sarif   # SARIF output
npx foxguard@latest secrets .                      # secrets
```

### Badge

```md
[![foxguard](https://img.shields.io/badge/foxguard-clean-2dd4bf?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSI+PHBhdGggZD0iTTggOEwyMCAyOEwzMiAyMEw0NCAyOEw1NiA4TDUyIDMyTDQ0IDQ0TDM2IDUySDI4TDIwIDQ0TDEyIDMyTDggOFoiIGZpbGw9IiNGNTlFMEIiIGZpbGwtb3BhY2l0eT0iMC4zIiBzdHJva2U9IiNGNTlFMEIiIHN0cm9rZS13aWR0aD0iMyIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCIvPjxjaXJjbGUgY3g9IjI0IiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjxjaXJjbGUgY3g9IjQwIiBjeT0iMzIiIHI9IjIuNSIgZmlsbD0iI0Y1OUUwQiIvPjwvc3ZnPg==)](https://github.com/peaktwilight/foxguard)
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/peaktwilight/foxguard
    rev: v0.3.2
    hooks:
      - id: foxguard
      - id: foxguard-secrets
```

Or run `foxguard init` to install a git hook directly.

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

## Contributing

Adding a rule is one struct implementing a trait. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

---

*Built by [Peak Twilight](https://doruk.ch)*

## Part of the open-source modern SOC

foxguard is one piece of a three-part open-source security stack:
- **[pwnkit](https://github.com/peaktwilight/pwnkit)** — AI agent pentester (detect)
- **[foxguard](https://github.com/peaktwilight/foxguard)** — Rust security scanner (prevent)
- **[opensoar](https://github.com/opensoar-hq/opensoar-core)** — Python-native SOAR platform (respond)

## License

MIT
