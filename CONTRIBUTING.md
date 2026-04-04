# Contributing to foxguard

## Adding a rule

Each language has its own rule file in `src/rules/`. To add a new rule:

1. Add a struct implementing the `Rule` trait in the appropriate language file (e.g., `src/rules/javascript.rs`)
2. Register it in `src/rules/mod.rs` inside `RuleRegistry::new()`
3. Add a test case to the corresponding fixture in `tests/fixtures/`
4. Run `cargo test` and `cargo clippy -- -D warnings`

Look at any existing rule in `src/rules/go.rs` for the pattern — each rule is a struct with `id()`, `severity()`, `cwe()`, `description()`, `language()`, and `check()`.

## Adding a language

1. Add the tree-sitter grammar to `Cargo.toml`
2. Add a `Language` variant in `src/lib.rs`
3. Update `src/engine/parser.rs` and `src/engine/scanner.rs`
4. Update `src/rules/semgrep_compat.rs` language mapping
5. Create `src/rules/<language>.rs` with rules
6. Register in `src/rules/mod.rs`
7. Add a test fixture in `tests/fixtures/`

## Development

```sh
cargo build              # build
cargo test               # run tests
cargo clippy -- -D warnings  # lint
cargo fmt                # format
```

## Project structure

```
src/              # Rust source
  rules/          # One file per language (javascript.rs, python.rs, etc.)
  engine/         # Scanner, parser
  report/         # Terminal, JSON, SARIF output
  secrets.rs      # Secrets scanning
www/              # foxguard.dev (Astro)
  src/data/       # Rule data for the website
  src/content/    # Blog posts (markdown)
vscode-extension/ # VS Code extension
packages/npm/     # npm wrapper (downloads binary)
action/           # GitHub Action
demo/             # Remotion demo video
benchmarks/       # Benchmark suite
```

## Releasing

```sh
./scripts/release.sh 0.4.0
```

This bumps all versions (Cargo, npm, VS Code), builds, tests, commits, tags, pushes, and publishes to npm + VS Code Marketplace. GitHub Release builds binaries from the tag.

## Pull requests

- One feature or fix per PR
- Include tests for new rules
- Run `cargo fmt` and `cargo clippy` before submitting
- Update website data files if rule counts change (`www/src/data/`)
