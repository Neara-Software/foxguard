# foxguard

Fast local security guard for changed files, built-in rules, and Semgrep-compatible YAML. Written in Rust.

This is the npm wrapper for foxguard. It downloads the correct prebuilt binary for your platform from GitHub Releases.

foxguard scans JS/TS, Python, and Go with built-in security rules by default and can load a useful Semgrep-compatible YAML subset with `--rules`.
Built-ins now cover local code risks like SSRF client variants, file/path traversal sinks, session/cookie misconfig, transport misconfig, and framework-specific auth issues.

Use `--rules` to add external rules on top of the built-ins. Use `--no-builtins --rules ...` for an external-rules-only compatibility run.

It also includes a dedicated `secrets` mode for common leaked credentials and private key material, with redacted output, binary-file skipping, and baseline-safe suppression data.
Secrets mode also supports path-scoped excludes and per-rule ignores for fixtures, generated files, or intentionally fake tokens.
foxguard can also auto-discover a repo config file such as `.foxguard.yml` for shared baselines, rule paths, and secrets defaults.
The Semgrep-compatible subset also supports regex clauses like `pattern-regex` and `pattern-not-regex`.
It also supports rule-level path filters like `paths.include` and `paths.exclude`.

Local-first workflow:

```sh
npx foxguard --changed .
npx foxguard secrets --changed .
npx foxguard baseline --output .foxguard/baseline.json
npx foxguard init
```

`foxguard init` also writes a starter `.foxguard.yml` when the repo does not already have one.

## Usage

```sh
npx foxguard .
```

Or install globally:

```sh
npm install -g foxguard
foxguard .
```

## How it works

1. If foxguard is installed via `cargo install foxguard`, the npm wrapper uses that binary directly.
2. Otherwise, it downloads the prebuilt binary for your platform from GitHub Releases.
3. The binary is cached in `node_modules/.cache/foxguard/` for subsequent runs.

## Supported platforms

- macOS (x64, arm64)
- Linux (x64, arm64)
- Windows (x64)

## Full documentation

See the [main repository](https://github.com/peaktwilight/foxguard) for full documentation, rules reference, and configuration options.
