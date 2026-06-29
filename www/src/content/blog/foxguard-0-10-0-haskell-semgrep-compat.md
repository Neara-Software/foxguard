---
title: "foxguard 0.10: Haskell support and a bigger Semgrep bridge"
date: "2026-06-29"
description: "foxguard v0.10.0 adds Haskell parsing, built-in Cardano Haskell seed rules, a much broader Semgrep/OpenGrep compatibility layer, and cleaner GitHub App and VS Code workflows."
readTime: "6 min read"
---

foxguard 0.10 is out.

The headline change is Haskell. `.hs`, `.lhs`, and `.hsc` files now go through the scanner as first-class source files, and the release ships a small Cardano Haskell seed pack by default. The second change is less visible but larger: the Semgrep/OpenGrep compatibility layer now loads 2,066 of the 2,144 registry rules we track in our coverage harness, a 96.4% load rate.

```sh
npx foxguard@latest .
```

## Haskell is a scanned language now

Before 0.10, Haskell code was mostly invisible to foxguard. That was a problem for Cardano reviews: the interesting code often lives in multi-package Cabal trees, and starting a review with zero static leads is a bad use of both human and agent time.

0.10 adds the plumbing end to end:

- `Language::Haskell`
- `.hs`, `.lhs`, and `.hsc` extension detection
- tree-sitter Haskell parsing
- Semgrep-compatible `languages: [haskell]` mapping
- Haskell comment handling for inline suppressions
- generic and regex rule fan-out for Haskell files
- Haskell fixtures and parity tests in CI

The built-in Cardano pack is deliberately named as a seed layer, not a proof engine. It flags high-signal review sites: FFI boundaries, raw pointer offsets, unsafe escape hatches, partial functions, CBOR decoder edges, and lazy-evaluation DoS shapes. These are leads the reviewer should investigate first, not confirmed vulnerabilities.

Example rule IDs look like this:

```text
semgrep/cardano-haskell/ffi-foreign-import
semgrep/cardano-haskell/partial-function
semgrep/cardano-haskell/cbor-decoder-edge
```

The important product behavior is simple: a Cardano Haskell tree no longer enters the review with an empty scanner list.

## The compatibility bridge got much wider

foxguard is still a Rust-native scanner first. The built-in rules are reviewed and tested as code. But a lot of teams already have Semgrep or OpenGrep YAML, and a scanner that cannot load those rules is expensive to adopt.

0.10 pushes the YAML bridge forward in three ways.

First, generic mode is broader. `patterns`, `pattern-either`, `pattern-regex`, named regex captures, metavariable constraints, and PCRE-style lookahead/backreference fallbacks are all better covered. Rules that used to be skipped at parse time now compile into bounded text or AST matchers.

Second, taint-mode translation handles more shapes: parameter-as-source, focus-on-call-argument sinks, call-on-member, field/subscript/receiver-call sources, object and dict literal values, tainted return values, binary/string-format sinks, and metavariable-regex-bounded callees.

Third, external taint rules can target more language engines. Ruby, PHP, C#, Bash, Solidity, Scala, Apex, and Swift all have Semgrep-compatible taint bridges in this release. That does not mean every language has first-party built-in taint rules by default; it means imported taint-mode YAML has a much better chance of running instead of being dropped.

The current registry snapshot:

```text
Rules loaded OK: 2066 / 2144 (96.4%)
Rules skipped:      78 / 2144 (3.6%)
```

Most remaining skips are unsupported taint shapes, not missing language parsers.

## Cleaner integrations

Two workflow fixes landed with the release.

The GitHub App now produces less repetitive PR review noise on repeated scans. The goal is still to put findings where developers already review code, but not to turn every push into a wall of duplicate scanner comments.

The VS Code extension now routes config suppressions through the Rust CLI config editor instead of mutating YAML itself. That keeps suppression behavior in one implementation, gives the extension a safer JSON/process boundary, and avoids rewriting config files when the suppression already exists.

## Release provenance stays boring

The release workflow builds binaries for Linux, macOS, and Windows, generates `checksums.txt`, and publishes GitHub artifact attestations before creating the GitHub Release. The install docs and CI both keep those provenance instructions pinned so they do not drift.

Manual verification still looks like this:

```sh
gh attestation verify foxguard-linux-x86_64 \
  --repo 0sec-labs/foxguard
```

## Upgrade

```sh
npx foxguard@latest .
# or
curl -fsSL https://foxguard.dev/install.sh | sh
# or
cargo install foxguard
```

GitHub Action users can pin the release:

```yaml
- uses: 0sec-labs/foxguard/action@v0.10.0
```

pre-commit users can do the same:

```yaml
repos:
  - repo: https://github.com/0sec-labs/foxguard
    rev: v0.10.0
    hooks:
      - id: foxguard
```

Full release notes are on GitHub: [foxguard v0.10.0](https://github.com/0sec-labs/foxguard/releases/tag/v0.10.0).

---

*foxguard is an open-source security scanner written in Rust. [GitHub](https://github.com/0sec-labs/foxguard) · [foxguard.dev](https://foxguard.dev).*
