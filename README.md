<p align="center">
  <img src="assets/logo.svg" width="80" alt="foxguard logo" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  Fast security linting for modern codebases.
  <br/>
  <a href="https://foxguard.dev">foxguard.dev</a> | <a href="https://crates.io/crates/foxguard">crates.io</a> | <a href="https://www.npmjs.com/package/foxguard">npm</a>
</p>

> Fast local security scanning for JS/TS, Python, and Go.

## What foxguard is

foxguard is a Rust security linter built for the edit-save-commit loop. It runs locally, scans quickly, emits terminal/JSON/SARIF output, and can load Semgrep-compatible YAML rules with `--rules`.

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
foxguard --rules ./rules .
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
- Semgrep-compatible rule loading via `--rules`
- Built-in security coverage out of the box
- SARIF output for code scanning and CI systems

foxguard is best thought of as a fast security engine you can slot into your workflow, not as a closed rules product.

## Bring your own rules

foxguard can load Semgrep-compatible YAML rules from a file or directory:

```sh
foxguard --rules ./semgrep-rules .
```

By default, foxguard runs its built-in rules. Use `--rules` to add external rules on top. Use `--no-builtins --rules ...` when you want an external-rules-only compatibility run.

foxguard currently supports a useful Semgrep-compatible subset for local rule loading. That makes it a good fit for teams already using Semgrep or OpenGrep-style rules, without claiming full drop-in compatibility.

See [`COMPATIBILITY.md`](./COMPATIBILITY.md) for the supported subset and the intended built-ins-first workflow.

## Built-in coverage

foxguard currently ships with 36 built-in rules across 3 languages:

| Language | Rules | Frameworks |
|----------|-------|------------|
| JavaScript/TypeScript | 16 | Express |
| Python | 13 | Flask, Django |
| Go | 7 | Gin, net/http |

Examples of included checks:

- Hardcoded secrets and placeholder credentials
- SQL injection via string interpolation
- Command injection via exec/spawn
- XSS via unsafe response or DOM writes
- Weak crypto such as MD5 and SHA1
- Unsafe deserialization
- Framework misconfigurations

## GitHub Action

```yaml
- uses: peaktwilight/foxguard/action@v1
  with:
    path: .
    severity: medium
```

## Performance

The benchmark suite supports two modes:

- `default`: foxguard built-ins vs Semgrep/OpenGrep `auto`
- `compat`: the same Semgrep-compatible YAML rules across foxguard, Semgrep, and OpenGrep

Built-ins are the default product path. `compat` exists to answer the narrower same-rules question fairly.

Benchmark outputs are written locally as `benchmarks/results-default.md` and `benchmarks/results-compat.md`. Rust + tree-sitter + rayon. See [`benchmarks/README.md`](./benchmarks/README.md) for methodology and commands.

For the homepage-style visual comparison, use `default` mode. For compatibility checks, use `compat`.

## License

MIT
