<p align="center">
  <img src="assets/logo.svg" width="80" alt="foxguard logo" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  Fast local security guard for changed files, built-in rules, and Semgrep-compatible YAML.
  <br/>
  <a href="https://foxguard.dev">foxguard.dev</a> | <a href="https://crates.io/crates/foxguard">crates.io</a> | <a href="https://www.npmjs.com/package/foxguard">npm</a>
</p>

<p align="center">
  <a href="https://github.com/peaktwilight/foxguard/actions/workflows/ci.yml"><img src="https://github.com/peaktwilight/foxguard/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/peaktwilight/foxguard"><img src="assets/badge.svg" alt="foxguard: clean" /></a>
  <a href="https://www.npmjs.com/package/foxguard"><img src="https://img.shields.io/npm/v/foxguard?color=d97706&label=npm" alt="npm" /></a>
</p>

> Fast local security guard for JS/TS, Python, and Go.

## What foxguard is

foxguard is a Rust security guard built for the edit-save-commit loop. It runs locally, scans quickly, emits terminal/JSON/SARIF output, includes a first-class secrets mode, and can load Semgrep-compatible YAML rules with `--rules`.

The point of the product is not "our opinionated rules vs everyone else's". The point is fast security feedback in a form teams can actually drop into existing workflows.

Use it:

- on a repo before commit
- in scripts and CI
- with the built-in rules
- with your own Semgrep-style or OpenGrep-style rules

## Install

```sh
cargo install foxguard
```

```sh
npx foxguard .
```

## Usage

```sh
foxguard .
```

```sh
foxguard --severity high .
foxguard --format json .
foxguard --format sarif .
foxguard secrets .
foxguard --rules ./rules .
foxguard --changed .
foxguard secrets --changed .
foxguard baseline --output .foxguard/baseline.json
foxguard init
foxguard secrets --exclude-path fixtures --ignore-rule secret/github-token .
foxguard --config .foxguard.yml .
```

```text
src/app.js
  12:5  CRITICAL  js/express-no-hardcoded-session-secret (CWE-798)
        Hardcoded session secret -- use environment variables
  45:3  HIGH      js/express-direct-response-write (CWE-79)
        res.send() called with user input -- risk of reflected XSS

WARNING 2 issues found: 1 critical, 1 high, 0 medium, 0 low
```

## Why foxguard

- Fast enough to run locally without becoming background noise
- Single binary, no JVM, no Python runtime, no network calls
- First-class secrets scan for common leaked credentials and key material
- Semgrep-compatible rule loading via `--rules`
- Built-in security coverage out of the box
- SARIF output for code scanning and CI systems

foxguard is best thought of as a fast security engine you can slot into your workflow, not as a closed rules product.

## Repo config

foxguard can auto-discover `./.foxguard.yml`, `./.foxguard.yaml`, `./foxguard.yml`, or `./foxguard.yaml` from the scan path upward. You can also point at an explicit file with `--config`.
Relative paths inside the config are resolved from the config file location.

Example:

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

CLI flags still win over config values.

## Local guard workflow

Install foxguard as a repo-local guard:

```sh
foxguard init
```

That installs a `pre-commit` hook and writes a starter `.foxguard.yml` when one does not already exist. By default, the generated config points at `.foxguard/baseline.json` and `.foxguard/secrets-baseline.json`, so the hook can stay on the clean `--config ... --changed` path.

Useful commands:

- `foxguard --changed .`
- `foxguard secrets --changed .`
- `foxguard --config .foxguard.yml .`
- `foxguard baseline --output .foxguard/baseline.json`
- `foxguard --baseline .foxguard/baseline.json .`

## Secrets mode

Use the built-in secrets scanner when you want fast local checks for obvious leaked credentials and key material:

```sh
foxguard secrets .
foxguard secrets --changed .
foxguard secrets --write-baseline .foxguard/secrets-baseline.json .
foxguard secrets --baseline .foxguard/secrets-baseline.json .
foxguard secrets --exclude-path fixtures --exclude-path-file .foxguard/secrets.ignore .
foxguard secrets --ignore-rule secret/github-token .
```

Current patterns include AWS access keys and secret access keys, GitHub, GitLab, npm, Slack, and Stripe tokens plus private key headers.
Secrets findings are redacted in output, secrets baselines store suppression fingerprints rather than raw secret values, and binary files are skipped.
Use `--exclude-path` for repo-relative file or directory prefixes, `--exclude-path-file` for a newline-delimited ignore list, and `--ignore-rule` when a specific secret pattern is intentionally present in test fixtures or examples.
The same defaults can live in `foxguard.yml` or `.foxguard.yml` for local hooks and CI runs.

## Bring your own rules

foxguard can load Semgrep-compatible YAML rules from a file or directory:

```sh
foxguard --rules ./semgrep-rules .
```

By default, foxguard runs its built-in rules. Use `--rules` to add external rules on top. Use `--no-builtins --rules ...` when you want an external-rules-only compatibility run.

foxguard currently supports a useful Semgrep-compatible subset for local rule loading. That makes it a good fit for teams already using Semgrep or OpenGrep-style rules, without claiming full drop-in compatibility.
That subset now includes regex clauses such as `pattern-regex` and `pattern-not-regex` in addition to the AST-style operators listed in [`COMPATIBILITY.md`](./COMPATIBILITY.md).
It also supports rule-level path scoping with `paths.include` and `paths.exclude`.
It now also supports `metavariable-regex` for regex-constraining bound metavariables inside `patterns`.
It also supports `pattern-not-inside` for excluding matches that appear inside known-safe wrapper contexts.

See [`COMPATIBILITY.md`](./COMPATIBILITY.md) for the supported subset and the intended built-ins-first workflow.

## Built-in coverage

foxguard currently ships with 118 built-in code rules across 9 languages:

| Language | Rules | Frameworks |
|----------|-------|------------|
| JavaScript/TypeScript | 24 | Express, JWT flows, outbound request checks |
| Python | 26 | Flask, Django, outbound request checks |
| Go | 8 | Gin, net/http, TLS transport checks |
| Ruby | 10 | Rails mass assignment, CSRF, deserialization |
| Java | 10 | Spring CSRF/CORS, XXE, deserialization |
| PHP | 10 | Laravel, file inclusion, unserialize, extract |
| Rust | 10 | unsafe blocks, transmute, TLS, unwrap |
| C# | 10 | .NET, ASP.NET CORS, LDAP, XXE |
| Swift | 10 | iOS keychain, transport security, WebView |

Examples of included checks:

- Hardcoded secrets and placeholder credentials
- SQL injection via string interpolation
- Command injection via exec/spawn/system
- XSS via unsafe response or DOM writes
- Weak crypto such as MD5 and SHA1
- SSRF via dynamic outbound requests and common client variants
- Path traversal across file and response-file operations
- Unsafe deserialization (pickle, Marshal, YAML, ObjectInputStream, unserialize)
- Auth, session, and framework misconfigurations
- Unsafe Rust patterns (unsafe blocks, transmute, unwrap)

## CI Integration

### GitHub Actions

The fastest way to add foxguard to CI. Scans your code, uploads SARIF to GitHub Code Scanning, and fails the check if issues are found.

```yaml
name: Security
on: [push, pull_request]

jobs:
  foxguard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # needed for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - uses: peaktwilight/foxguard/action@v0.1.0
        with:
          path: .
          severity: medium          # low | medium | high | critical
          format: sarif             # terminal | json | sarif
          fail-on-findings: "true"  # fail the check if issues exist
          upload-sarif: "true"      # push results to Code Scanning tab
```

Findings show up in the **Security → Code Scanning** tab on your repo.

#### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `severity` | `low` | Minimum severity to report |
| `format` | `sarif` | Output format (`terminal`, `json`, `sarif`) |
| `version` | `latest` | foxguard version (e.g. `v0.1.0`) |
| `fail-on-findings` | `true` | Fail the check if findings exist |
| `upload-sarif` | `true` | Upload SARIF to GitHub Code Scanning |
| `badge-label` | `foxguard` | Custom badge label |

#### Action outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Number of issues found |
| `sarif-file` | Path to the SARIF file |
| `badge-json` | Path to shields.io endpoint JSON |

### Any CI (npx)

Works anywhere Node.js is available. No install step needed.

```yaml
# GitLab CI
foxguard:
  image: node:20
  script:
    - npx foxguard@0.1.0 .
    - npx foxguard@0.1.0 secrets .

# CircleCI
- run: npx foxguard@0.1.0 --severity high .

# Generic
- npx foxguard@0.1.0 --format sarif . > results.sarif
```

### Pre-commit hook

```sh
foxguard init
```

Installs a `pre-commit` hook that runs `foxguard --changed` and `foxguard secrets --changed` on every commit. Also generates a starter `.foxguard.yml` if one doesn't exist.

### Badge

Add a foxguard badge to your README:

```md
[![foxguard](https://img.shields.io/badge/foxguard-clean-2dd4bf)](https://github.com/peaktwilight/foxguard)
```

Or generate a dynamic badge from the action output:

```yaml
- uses: peaktwilight/foxguard/action@v0.1.0
  id: scan

- run: |
    if [ "${{ steps.scan.outputs.findings-count }}" = "0" ]; then
      echo "STATUS=clean" >> $GITHUB_ENV
      echo "COLOR=2dd4bf" >> $GITHUB_ENV
    else
      echo "STATUS=${{ steps.scan.outputs.findings-count }} issues" >> $GITHUB_ENV
      echo "COLOR=f59e0b" >> $GITHUB_ENV
    fi
```

## Performance

The benchmark suite supports two modes:

- `default`: foxguard built-ins vs Semgrep/OpenGrep `auto`
- `compat`: the same Semgrep-compatible YAML rules across foxguard, Semgrep, and OpenGrep

Built-ins are the default product path. `compat` exists to answer the narrower same-rules question fairly.

Benchmark outputs are written locally as `benchmarks/results-default.md` and `benchmarks/results-compat.md`. Rust + tree-sitter + rayon. See [`benchmarks/README.md`](./benchmarks/README.md) for methodology, commands, and notes about missing competitor binaries.

For the homepage-style visual comparison, use `default` mode. For compatibility checks, use `compat`.

---

*Built by [Peak Twilight](https://doruk.ch) -- also building [pwnkit](https://pwnkit.com), [vibecheck](https://vibechecked.doruk.ch), [unfuck](https://unfcked.doruk.ch), [whatdiditdo](https://whatdiditdo.doruk.ch)*

## License

MIT
