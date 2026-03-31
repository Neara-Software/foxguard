# foxguard

Fast security linting for modern codebases. Written in Rust.

This is the npm wrapper for foxguard. It downloads the correct prebuilt binary for your platform from GitHub Releases.

foxguard scans JS/TS, Python, and Go with built-in security rules by default and can load a useful Semgrep-compatible YAML subset with `--rules`.

Use `--rules` to add external rules on top of the built-ins. Use `--no-builtins --rules ...` for an external-rules-only compatibility run.

Local-first workflow:

```sh
npx foxguard --changed .
npx foxguard baseline --output .foxguard/baseline.json
npx foxguard init
```

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
