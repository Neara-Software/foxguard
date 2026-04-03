# foxguard Benchmarks

Comparative benchmarks for foxguard against other security linters.

## Quick Start

```sh
# Build foxguard first
cargo build --release

# Product comparison: foxguard built-ins vs Semgrep/OpenGrep auto rules
./benchmarks/run.sh

# Same-rules engine comparison
BENCH_MODE=compat ./benchmarks/run.sh

# Pin tool paths explicitly if needed
SEMGREP=/opt/homebrew/bin/semgrep OPENGREP=/path/to/opengrep ./benchmarks/run.sh
```

## Methodology

The benchmark suite measures foxguard, Semgrep, and OpenGrep against three popular open-source repositories covering different languages:

| Repository | Language | Description |
|------------|----------|-------------|
| [express](https://github.com/expressjs/express) | JavaScript | Fast, unopinionated web framework for Node.js |
| [flask](https://github.com/pallets/flask) | Python | Lightweight WSGI web application framework |
| [gin](https://github.com/gin-gonic/gin) | Go | HTTP web framework written in Go |

### What is measured

- **Wall time** — Total elapsed time for the scan
- **Files scanned** — Count of source files in the repository (`.js`, `.ts`, `.py`, `.go`)
- **Findings count** — Number of findings reported by each tool

### Modes

- `default`
  foxguard built-in rules vs Semgrep/OpenGrep `auto`
- `compat`
  the same Semgrep-compatible YAML rules are used across foxguard, Semgrep, and OpenGrep

### How it works

1. Each repository is cloned at `--depth 1` into `benchmarks/repos/`
2. In `default` mode, foxguard runs its built-in rules and Semgrep/OpenGrep run `auto`
3. In `compat` mode, all three tools use the shared rules in `benchmarks/compat_rules/`
4. foxguard uses `--no-builtins --rules` in `compat` mode to keep the rule set aligned
5. Results are written to `benchmarks/results-default.md` or `benchmarks/results-compat.md`
6. If Semgrep or OpenGrep is missing locally, that tool is skipped and the results file records `N/A`

### Fairness

- All tools scan the same repository checkout
- `default` mode is a product comparison, not a same-rules comparison
- `compat` mode is the same-rules comparison
- Semgrep and OpenGrep use their default `auto` rulesets only in `default` mode
- Timing includes startup overhead
- Repos are cached after first clone; delete `benchmarks/repos/` to re-clone
- Results are local snapshots, not a hosted leaderboard

In `compat` mode, foxguard runs `--no-builtins --rules benchmarks/compat_rules` so the comparison stays explicitly focused on the same external YAML rules rather than foxguard's built-in coverage.

## Why only these competitors?

The default matrix focuses on cross-language tools that are reasonably comparable for foxguard's current scope.

Tools like Bandit or njsscan can still be useful, but they are language-specific and make the comparison less apples-to-apples across JavaScript, Python, and Go.

## Why these compat rules?

The shared rules in `benchmarks/compat_rules/` are intentionally small, narrow, and parser-aligned.

They are not meant to prove overall security coverage parity. They exist to answer a narrower question:

- how do foxguard, Semgrep, and OpenGrep compare when scanning the same repos with the same YAML rules?

That makes them closer to compatibility smoke tests than a comprehensive security suite.

## Results

After running `./benchmarks/run.sh`, see `results-default.md` or `results-compat.md` in this directory for the latest local snapshot.
