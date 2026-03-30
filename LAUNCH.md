# Foxguard Launch Content

Best posting time: **Tuesday 9:00 AM ET** (15:00 CET)

---

## Positioning

Use this framing consistently:

- foxguard is a **Rust security linter**
- it is built for **fast local feedback**
- it supports a **Semgrep-compatible YAML subset**
- it is best positioned as a **fast local complement** to Semgrep or OpenGrep
- AI-generated code is a **use case**, not the whole product category

Avoid these claims:

- "AI-only security scanner"
- "drop-in Semgrep replacement"
- "same syntax, full compatibility"
- benchmark numbers that are not in `benchmarks/results.md`

Current checked-in benchmark snapshot:

| Repository | Files | foxguard | Semgrep | Speedup |
|------------|-------|----------|---------|---------|
| express | 141 | 0.077s | 4.902s | 64x |
| flask | 83 | 0.049s | 4.805s | 98x |
| gin | 99 | 0.062s | 4.302s | 69x |

---

## 1. Show HN

### Title Options

- `Show HN: Foxguard – fast security linting in Rust with Semgrep-compatible rules`
- `Show HN: Foxguard – local-first security scanner for JS, Python, and Go`
- `Show HN: Foxguard – Rust security linter with Semgrep-compatible YAML support`

### First Comment

> Hey HN, I'm Doruk. I built Foxguard because I wanted security checks that are fast enough to run locally without getting skipped.
>
> Most security tooling is comfortable in CI, but a lot less comfortable in the edit-save-commit loop. Foxguard is a Rust security linter for JS/TS, Python, and Go that aims to close that gap.
>
> What it does today:
>
> - 36 built-in rules across JavaScript/TypeScript, Python, and Go
> - JSON and SARIF output
> - framework-aware checks for Express, Flask, Django, Gin, and `net/http`
> - Semgrep-compatible YAML rule loading with `--rules`
> - single binary, no JVM, no Python runtime, no network calls
>
> The important positioning point is that this is not meant to be "security tooling only for AI code", and it's not a claim of full Semgrep replacement either.
>
> The better way to think about it is:
>
> - Semgrep / OpenGrep: broad rule ecosystem and strong CI fit
> - Foxguard: fast local feedback on a Rust engine
>
> Checked-in benchmark numbers from the repo right now:
>
> | Repo | Files | Foxguard | Semgrep |
> |---|---:|---:|---:|
> | express | 141 | 0.077s | 4.902s |
> | flask | 83 | 0.049s | 4.805s |
> | gin | 99 | 0.062s | 4.302s |
>
> Install is:
>
> ```sh
> cargo install foxguard
> # or
> npx foxguard .
> ```
>
> Scan is:
>
> ```sh
> foxguard .
> foxguard --format sarif .
> foxguard --rules ./semgrep-rules .
> ```
>
> Repo: https://github.com/peaktwilight/foxguard
> Site: https://foxguard.dev
>
> If you're already using Semgrep or OpenGrep, the question I'd love feedback on is: what subset of rule compatibility matters most for local workflows?

---

## 2. Reddit

### r/rust

**Title:** `Foxguard: fast security linting in Rust with Semgrep-compatible YAML support`

**Body:**

I just released Foxguard, a Rust security linter for JS/TS, Python, and Go.

The pitch is simple: security checks that are fast enough to run locally, not just in CI.

What it has today:

- 36 built-in rules
- JSON and SARIF output
- framework-aware checks for Express, Flask, Django, Gin, and `net/http`
- Semgrep-compatible YAML loading via `--rules`
- single-binary distribution

I do not want to overstate it:

- it is not "security tooling only for AI code"
- it is not a full drop-in Semgrep replacement

The intended position is more like a local-first complement:

- Semgrep / OpenGrep for broad ecosystem coverage
- Foxguard for fast feedback in hooks, scripts, and the edit-save-commit loop

Current benchmark snapshot checked into the repo:

| Repo | Files | Foxguard | Semgrep |
|---|---:|---:|---:|
| express | 141 | 0.077s | 4.902s |
| flask | 83 | 0.049s | 4.805s |
| gin | 99 | 0.062s | 4.302s |

Would especially love feedback from Rust folks on the rule engine and packaging approach.

Repo: https://github.com/peaktwilight/foxguard

### r/netsec

**Title:** `Foxguard: open-source Rust security linter with SARIF output and Semgrep-compatible rules`

**Body:**

Released a small open-source security linter called Foxguard.

Current scope:

- JS/TS, Python, Go
- 36 built-in rules
- JSON and SARIF output
- Semgrep-compatible YAML subset loading
- local CLI usage first

Examples of built-in checks include hardcoded secrets, SQL injection via interpolation, command injection, XSS sinks, weak crypto, unsafe deserialization, and framework misconfiguration.

The main product idea is not "new rule universe". It is "fast engine that fits existing workflows better".

So the intended comparison is:

- Semgrep / OpenGrep: larger ecosystem, deeper coverage
- Foxguard: faster local feedback, smaller current scope

If you're already maintaining Semgrep rules, I'd be interested in which compatibility features matter most in practice.

Repo: https://github.com/peaktwilight/foxguard

### r/programming

**Title:** `Foxguard: Rust security linting with Semgrep-compatible YAML support`

**Body:**

Built a small security scanner in Rust called Foxguard.

The goal was not "replace all existing SAST". The goal was to make local security feedback fast enough that people actually run it before CI.

Current feature set:

- scans JS/TS, Python, and Go
- 36 built-in rules
- terminal, JSON, and SARIF output
- Semgrep-compatible YAML loading with `--rules`

Example usage:

```bash
cargo install foxguard
foxguard .
foxguard --severity high .
foxguard --format sarif .
foxguard --rules ./semgrep-rules .
```

The useful framing is probably:

- if you want a broad mature rule ecosystem, Semgrep / OpenGrep is the reference point
- if you want a fast local Rust scanner that can also load a useful Semgrep-style subset, that's where Foxguard fits

Repo: https://github.com/peaktwilight/foxguard

---

## 3. X / Twitter

### Tweet 1

Built `foxguard`, a Rust security linter for JS/TS, Python, and Go.

- 36 built-in rules
- JSON + SARIF
- Semgrep-compatible YAML loading
- fast enough for local workflows

Repo: https://github.com/peaktwilight/foxguard

### Tweet 2

The pitch for Foxguard is not "AI-only security tooling" and not "full Semgrep replacement".

It's:

- local-first security feedback
- Rust engine
- useful built-in rules
- Semgrep/OpenGrep-style workflow fit

### Tweet 3

Current checked-in benchmark snapshot for Foxguard vs Semgrep:

- express: `0.077s` vs `4.902s`
- flask: `0.049s` vs `4.805s`
- gin: `0.062s` vs `4.302s`

Fast enough to be reasonable in hooks and local scripts.

### Tweet 4

If your team already has Semgrep rules, the interesting part of Foxguard is `--rules`.

It supports a useful Semgrep-compatible subset today.

That means the story can be "bring part of your existing workflow", not "start over with a new tool."

---

## 4. Short Boilerplate

### One-liner

Foxguard is a Rust security linter for modern codebases with built-in rules, SARIF output, and Semgrep-compatible YAML rule loading.

### Two-liner

Foxguard is a fast local security scanner for JS/TS, Python, and Go. It ships with built-in checks and can load a useful Semgrep-compatible YAML subset, which makes it a good complement to Semgrep or OpenGrep in local workflows.

### Comparison Line

Semgrep and OpenGrep are the broader ecosystem reference points; Foxguard is the smaller Rust-native tool optimized for fast local feedback.

---

## 5. FAQ Angles

### Is this just for AI-generated code?

No. AI-generated code is one workflow where fast security feedback helps, but Foxguard is a general-purpose local security scanner.

### Is this a Semgrep replacement?

Not fully. Foxguard currently supports a useful Semgrep-compatible subset for local rule loading, but it should be presented as complementary rather than drop-in equivalent.

### Why not just use Semgrep or OpenGrep?

You probably should for broad ecosystem coverage. Foxguard is for cases where a smaller Rust-native scanner with faster local feedback is useful.

### Why Rust?

Predictable local performance, single-binary distribution, and straightforward parallel scanning.

---

## 6. Canonical Commands

```sh
cargo install foxguard
npx foxguard .
foxguard .
foxguard --severity high .
foxguard --format json .
foxguard --format sarif .
foxguard --rules ./semgrep-rules .
```
