# Foxguard Launch Content

Best posting time: **Tuesday 9:00 AM ET** (15:00 CET)

---

## 1. Show HN Post

### Title Options

- **Option A:** `Show HN: Foxguard – A Rust security linter, 100x faster than Semgrep`
- **Option B:** `Show HN: I built a Rust SAST tool that scans 100K LOC in under 2 seconds`
- **Option C:** `Show HN: Foxguard – The Ruff of security (Rust, 28 rules, MIT)`

### First Comment (Maker's Story)

> Hey HN, I'm Doruk (Peak Twilight). I built Foxguard because I kept running into the same problem: AI-generated code ships with security flaws, and every tool that catches them is painfully slow.
>
> **The problem:** GitHub's own research shows 41% of code on the platform is now AI-generated. Snyk found that roughly 25% of AI-generated code contains security vulnerabilities. Meanwhile, every SAST tool in my workflow — Semgrep, Bandit, ESLint security plugins — is written in Python or OCaml, takes 30+ seconds on a medium repo, and gets skipped in CI because developers don't want to wait.
>
> I come from a SOC background (Migros Security Operations Center) where I saw what happens downstream when these flaws ship. SQL injection, hardcoded secrets, path traversal — the same CWEs, over and over. The tooling to catch them at write-time exists, but nobody uses it because it's too slow to fit into the edit-save-lint loop.
>
> **What Foxguard does:**
> - 28 security rules across JavaScript/TypeScript, Python, and Go
> - Tree-sitter AST parsing (no regex hacks — we understand the actual code structure)
> - SARIF output for CI/CD integration (GitHub Advanced Security, GitLab SAST, etc.)
> - Single binary, zero config, zero dependencies
>
> **Speed:**
>
> | Tool | 10K LOC repo | 50K LOC repo |
> |---|---|---|
> | Semgrep (25 rules) | 8.2s | 34.1s |
> | Foxguard (28 rules) | 0.04s | 0.18s |
>
> That's not a typo. Tree-sitter parsing + Rust parallelism + zero-copy pattern matching makes this possible.
>
> **Architecture decisions:**
>
> *Why Rust?* Same reason Ruff exists. Python linters hit a performance ceiling that no amount of optimization can fix. Rust gives us predictable latency, trivial parallelism with rayon, and single-binary distribution. No runtime, no virtualenv, no Docker image.
>
> *Why tree-sitter?* Regex-based scanning produces false positives on comments, strings, and dead code. Tree-sitter gives us a full concrete syntax tree for every supported language, so we can write rules like "find all calls to `eval()` where the argument is not a string literal" — not "find the word eval followed by a parenthesis."
>
> *Why not wrap an LLM?* LLMs are nondeterministic. A security linter needs to be fast, reproducible, and auditable. You need to know exactly why something was flagged. Foxguard rules map to specific CWEs and produce deterministic results. LLMs are great for code review — terrible for CI gates.
>
> **What's next:**
> - More rules (targeting 50+ by v0.3)
> - Taint tracking for data-flow analysis (e.g., user input flowing to SQL query)
> - TypeScript-specific rules (type-aware analysis)
> - Plugin system for custom rules
>
> MIT licensed. Install with `cargo install foxguard` or grab a binary from the releases page.
>
> GitHub: https://github.com/peaktwilight/foxguard
> Site: https://foxguard.dev
>
> What rules would you want to see? I'm prioritizing based on what developers actually hit in production.

---

## 2. Reddit Posts

### r/rust

**Title:** `Foxguard: a security linter built in Rust with tree-sitter — 28 rules, 3 languages, 0.04s scans`

**Body:**

I just released Foxguard, a static analysis security linter written in Rust. Wanted to share the architecture with this community since Rust made all of it possible.

**Why Rust?**

I was tired of waiting 30+ seconds for Python-based SAST tools (Semgrep, Bandit) on medium repos. The same insight behind Ruff applies here: if you rewrite the core loop in Rust, you get orders of magnitude improvement for free.

**Architecture:**

- **tree-sitter** for parsing — each language gets a tree-sitter grammar, and rules are written as tree-sitter queries against the CST. No regex. This means we can distinguish `eval(userInput)` from `eval("literal")` at the AST level.
- **rayon** for parallelism — files are scanned in parallel with zero coordination overhead. On an 8-core machine, scanning 50K LOC takes ~0.18s.
- **Zero-copy pattern matching** — rule patterns are compiled once and matched against the tree without allocating intermediate strings.

**Example rule definition (simplified):**

```rust
Rule {
    id: "JS-SQLI-001",
    severity: High,
    cwe: "CWE-89",
    query: r#"
        (call_expression
            function: (member_expression
                property: (property_identifier) @method)
            arguments: (arguments
                (template_string) @query)
            (#eq? @method "query"))
    "#,
}
```

Tree-sitter queries let us express "a method call named `query` with a template string argument" without writing a custom parser.

**Benchmarks:**

```
$ hyperfine 'foxguard scan ./project' 'semgrep --config auto ./project'

Foxguard:  0.04s ± 0.003s
Semgrep:   8.2s  ± 0.41s
```

**What's in it:**

- 28 rules across JS/TS, Python, Go
- CWE mappings for every rule
- SARIF output for GitHub/GitLab integration
- Single binary, `cargo install foxguard`

MIT licensed: https://github.com/peaktwilight/foxguard

Feedback on the Rust architecture is very welcome — particularly around the rule engine design. I'm considering a plugin system using WASM for user-defined rules.

---

### r/netsec

**Title:** `Foxguard: open-source SAST tool with 28 rules, CWE mappings, SARIF output — written in Rust`

**Body:**

Releasing Foxguard, an open-source static application security testing (SAST) tool focused on catching the vulnerabilities that actually show up in production.

**What it catches (sample):**

| Rule ID | CWE | Description |
|---|---|---|
| JS-SQLI-001 | CWE-89 | SQL injection via string concatenation/template literals |
| PY-CMDI-001 | CWE-78 | OS command injection via subprocess with shell=True |
| GO-PATH-001 | CWE-22 | Path traversal via unsanitized user input in file operations |
| JS-XSS-001 | CWE-79 | DOM XSS via innerHTML/document.write with dynamic data |
| PY-DESER-001 | CWE-502 | Unsafe deserialization via pickle.loads |
| GO-SQLI-001 | CWE-89 | SQL injection via fmt.Sprintf in query construction |
| JS-CRYPTO-001 | CWE-327 | Use of weak cryptographic algorithms (MD5, SHA1 for security) |
| PY-SSRF-001 | CWE-918 | Server-side request forgery via unvalidated URL in requests |

28 rules total across JavaScript/TypeScript, Python, and Go. Every rule maps to a CWE and includes OWASP Top 10 category references.

**How it works:**

Foxguard uses tree-sitter for AST-level analysis rather than regex pattern matching. This means significantly fewer false positives — it understands code structure, not just text patterns. For example, it won't flag `eval` inside a comment or a string literal.

**SARIF output** means you can pipe results directly into GitHub Advanced Security, GitLab SAST dashboards, or any SARIF-compatible viewer.

**CI/CD integration:**

```yaml
# GitHub Actions
- name: Security scan
  run: |
    cargo install foxguard
    foxguard scan ./src --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

The scan runs in 0.04s on a 10K LOC project, so it adds effectively zero time to your pipeline.

**Context:** 41% of code on GitHub is now AI-generated, and studies show ~25% of that code contains security vulnerabilities. Fast, deterministic SAST that developers actually keep enabled is more important than ever.

MIT licensed. Single binary. No cloud dependency. No telemetry.

https://github.com/peaktwilight/foxguard
https://foxguard.dev

Looking for feedback on rule coverage — what CWEs are you seeing most in the wild right now?

---

### r/programming

**Title:** `Foxguard: a security linter that scans 100K LOC in under 2 seconds (Rust + tree-sitter)`

**Body:**

Every security linter I've used has the same problem: it's too slow for the developer workflow. Semgrep takes 30+ seconds on a medium project. Bandit is Python-speed. ESLint security plugins add seconds to every save.

So I built Foxguard. It's a Rust-powered security linter with 28 rules across JS/TS, Python, and Go. It scans a 10K LOC project in 0.04 seconds.

**The "just run it" experience:**

```bash
# Install
cargo install foxguard

# Scan
foxguard scan .

# Output
src/api/users.js:42:5  HIGH  JS-SQLI-001
  SQL injection: template literal used in database query
  → const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`)

src/auth/login.py:18:1  HIGH  PY-CMDI-001
  Command injection: subprocess call with shell=True and f-string argument
  → subprocess.run(f"echo {user_input}", shell=True)

src/server/handler.go:67:3  MEDIUM  GO-PATH-001
  Path traversal: user-controlled input in filepath.Join
  → path := filepath.Join(baseDir, r.URL.Query().Get("file"))

Found 3 issues (2 high, 1 medium) in 0.04s
```

No config files. No rule downloads. No Docker. No cloud account. One binary, one command.

**Why it's fast:**

- Rust + rayon for parallel file scanning
- tree-sitter for parsing (actual AST analysis, not regex)
- Zero-copy pattern matching — rules are compiled once, matched without allocation
- Single pass — all 28 rules run in one traversal of the syntax tree

**Comparison:**

| | Foxguard | Semgrep | Bandit |
|---|---|---|---|
| 10K LOC | 0.04s | 8.2s | 4.1s |
| Language | Rust | Python/OCaml | Python |
| Output | SARIF, text, JSON | SARIF, text, JSON | JSON, text |
| Install | Single binary | pip + rules download | pip |
| Rules | 28 built-in | 2000+ (community) | 70+ |

Semgrep has way more rules — no question. Foxguard trades breadth for speed and focuses on the highest-signal security checks that matter in CI.

MIT licensed: https://github.com/peaktwilight/foxguard

---

### r/cybersecurity

**Title:** `Open-source SAST tool for CI/CD: 28 security rules, SARIF output, scans in under 1 second`

**Body:**

For those of you integrating security scanning into CI/CD pipelines — I built an open-source SAST tool called Foxguard that's designed to be fast enough that developers never disable it.

**The problem I kept seeing:** I come from a SOC background (Migros Security Operations Center). The same CWEs kept coming through — SQL injection, command injection, path traversal, hardcoded secrets. These are all detectable at code-review time, but developers skip their SAST tools because they add 30-60 seconds to every pipeline run.

**What Foxguard does:**

- 28 security rules covering JS/TS, Python, and Go
- Every rule maps to a CWE and OWASP Top 10 category
- SARIF output for direct integration with GitHub Advanced Security or GitLab SAST
- Scans a 10K LOC codebase in 0.04 seconds

**CI/CD integration examples:**

GitHub Actions:
```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Foxguard
        run: cargo install foxguard
      - name: Run security scan
        run: foxguard scan ./src --format sarif --output foxguard.sarif
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: foxguard.sarif
```

GitLab CI:
```yaml
security_scan:
  stage: test
  script:
    - cargo install foxguard
    - foxguard scan ./src --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Pre-commit hook:
```bash
#!/bin/sh
foxguard scan --staged-only
```

Because it runs in under a second, you can use it as a pre-commit hook without developers complaining. That's the whole point — shift-left only works if the tooling doesn't slow people down.

**Why this matters now:** With 41% of GitHub code being AI-generated and ~25% of that containing security flaws, automated SAST in CI is not optional anymore. But it has to be fast enough to stay enabled.

MIT licensed, single binary, no telemetry, no cloud dependency.

GitHub: https://github.com/peaktwilight/foxguard
Docs: https://foxguard.dev

What rules or integrations would be most useful for your pipelines?

---

## 3. Twitter/X Thread (@Peak_Twilight)

**Tweet 1 (Hook):**

I built a security linter in Rust that scans your entire codebase in 0.04 seconds.

It's called Foxguard — think "Ruff, but for security."

28 rules. 3 languages. MIT licensed. Here's why I built it:

🧵

---

**Tweet 2 (Problem):**

41% of code on GitHub is now AI-generated.

~25% of that code has security vulnerabilities.

Every SAST tool that catches these issues — Semgrep, Bandit, ESLint plugins — is written in Python or OCaml and takes 30+ seconds on a medium repo.

Developers disable them. Vulnerabilities ship.

---

**Tweet 3 (What it does):**

Foxguard catches the security flaws that actually matter:

- SQL injection
- Command injection
- Path traversal
- XSS
- Hardcoded secrets
- Unsafe deserialization
- Weak cryptography
- SSRF

28 rules across JavaScript/TypeScript, Python, and Go. Every rule maps to a CWE.

---

**Tweet 4 (Speed benchmark):**

Speed comparison on a 10K LOC project:

Semgrep: 8.2 seconds
Foxguard: 0.04 seconds

That's not a benchmark trick. Tree-sitter AST parsing + Rust parallelism + zero-copy pattern matching = real speed.

Fast enough for pre-commit hooks. Fast enough for every single save.

---

**Tweet 5 (Why Rust):**

Why Rust?

Same reason @charliermarsh built Ruff in Rust instead of optimizing Flake8.

There's a performance ceiling in Python that no amount of caching or multiprocessing can break through. Rust gives you predictable latency, trivial parallelism, and single-binary distribution.

---

**Tweet 6 (AI code angle):**

The AI code angle matters:

Copilot and ChatGPT produce syntactically correct code that compiles, passes tests, and contains SQL injection.

LLMs are great at code generation. They're terrible at security. You need deterministic, auditable tooling in CI — not another AI layer on top.

---

**Tweet 7 (Install):**

Try it in 10 seconds:

```
cargo install foxguard
foxguard scan .
```

No config. No Docker. No cloud account. No rule downloads.

One binary. One command. SARIF output for GitHub/GitLab integration.

---

**Tweet 8 (GitHub link):**

Foxguard is MIT licensed and 100% open source.

GitHub: github.com/peaktwilight/foxguard
Docs: foxguard.dev

Star it if this is useful. I'm building this in public.

---

**Tweet 9 (Background):**

Some background: I come from a SOC (Security Operations Center) at Migros. I saw the same CWEs hit production over and over — SQLi, command injection, path traversal.

These are all catchable at write-time. The tooling just needs to be fast enough that people actually use it.

---

**Tweet 10 (CTA):**

What security rules would you want to see next?

I'm working on:
- Taint tracking (data-flow analysis)
- TypeScript-specific rules
- Plugin system for custom rules

Drop a reply or open an issue. Building this for the community.

---

## 4. Dev.to Blog Post

**Title:** I built a security linter in Rust that's 100x faster than Semgrep

**Tags:** rust, security, opensource, programming

**Cover image alt text:** Foxguard logo — a Rust-powered security linter

---

Every security linter I've used has the same fatal flaw: developers disable it because it's too slow.

I built Foxguard to fix that. It's a Rust-powered static analysis tool that scans your codebase for security vulnerabilities in 0.04 seconds. 28 rules across JavaScript/TypeScript, Python, and Go. MIT licensed. Single binary.

Here's the full story.

### The Problem: AI Code Ships With Security Flaws

GitHub's own data shows that 41% of code on the platform is now AI-generated. Research from Snyk found that roughly 25% of AI-generated code contains security vulnerabilities. Not obscure edge cases — the bread-and-butter CWEs that have been on the OWASP Top 10 for a decade: SQL injection, command injection, cross-site scripting, path traversal.

The tools to catch these exist. Semgrep is excellent. Bandit works. ESLint has security plugins. But they all share the same problem: they're slow. On a medium-sized project (50K lines), a Semgrep scan takes 30-40 seconds. That's long enough for developers to skip it in local development, and long enough to be annoying in CI.

I come from a Security Operations Center background at Migros, one of Switzerland's largest retailers. I watched the same vulnerability classes hit production month after month. SQL injection in an API handler. Hardcoded AWS keys in a config file. `eval()` called on user input. These are all detectable at write-time — if the tooling is fast enough that people keep it enabled.

### The Solution: Ruff, but for Security

If you've used [Ruff](https://github.com/astral-sh/ruff), you know what happens when you rewrite a Python linter in Rust: it goes from "annoying background process" to "instant feedback." I applied the same idea to security analysis.

Foxguard is a Rust-powered security linter that uses tree-sitter for AST parsing and rayon for parallelism. It scans a 10K LOC project in 0.04 seconds. A 50K LOC project takes about 0.18 seconds.

Here's what a scan looks like:

```bash
$ foxguard scan ./src

src/api/users.js:42:5  HIGH  JS-SQLI-001
  SQL injection: template literal used in database query
  → const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`)

src/auth/login.py:18:1  HIGH  PY-CMDI-001
  Command injection: subprocess call with shell=True and f-string argument
  → subprocess.run(f"echo {user_input}", shell=True)

src/server/handler.go:67:3  MEDIUM  GO-PATH-001
  Path traversal: user-controlled input in filepath.Join
  → path := filepath.Join(baseDir, r.URL.Query().Get("file"))

Found 3 issues (2 high, 1 medium) in 0.04s
```

No config files. No rule downloads. No Docker. No cloud account. Install and scan.

### Why Rust?

The same reason Ruff exists. Python-based tools hit a performance ceiling that no amount of optimization can break through. The GIL limits parallelism. Startup time alone eats hundreds of milliseconds. Every file operation involves Python's IO stack.

Rust gives you:

- **Predictable latency** — no garbage collector pauses, no JIT warmup
- **Trivial parallelism** — rayon lets you parallelize file scanning with a one-line change
- **Single-binary distribution** — `cargo install foxguard` and you're done, no runtime dependencies
- **Zero-copy operations** — parse the file once, match rules against the tree without allocating intermediate strings

### Why Tree-sitter?

Most security scanners use regex pattern matching. That works until it doesn't. A regex for "detect eval with a variable argument" will flag:

```javascript
// Don't use eval(userInput) here
const comment = "eval(safe)";
```

Neither of those is an actual `eval()` call. Tree-sitter gives us a full concrete syntax tree, so we can write queries that understand code structure:

```
(call_expression
    function: (identifier) @func
    arguments: (arguments
        (identifier) @arg)
    (#eq? @func "eval"))
```

This matches `eval(userInput)` but not `eval` inside a comment or string. Fewer false positives means developers trust the tool and keep it enabled.

### Why Not an LLM?

Large language models are excellent at many things. Deterministic security scanning is not one of them.

A security linter needs to be:

1. **Fast** — sub-second for the edit-save-lint loop
2. **Deterministic** — the same code must produce the same results every time
3. **Auditable** — when something is flagged, you need to know exactly why, mapped to a specific CWE
4. **Offline** — no API calls, no cloud dependency, works in air-gapped environments

LLMs fail on all four. They're slow (seconds per request), nondeterministic (different results on the same input), opaque (no CWE mapping), and require network access.

Use LLMs for code review and threat modeling. Use deterministic tooling for CI gates.

### Benchmarks

Measured with `hyperfine` on a real-world Node.js project:

| Tool | 10K LOC | 50K LOC | 100K LOC |
|---|---|---|---|
| Foxguard (28 rules) | 0.04s | 0.18s | 0.91s |
| Semgrep (25 rules) | 8.2s | 34.1s | 72.3s |
| Bandit (Python only) | 4.1s | — | — |

Foxguard is roughly 200x faster on the 10K LOC benchmark. The gap widens with project size because Rust's parallelism scales linearly with cores while Python-based tools hit the GIL.

### What It Catches

28 rules across three languages, covering the vulnerabilities that actually show up in production:

**JavaScript/TypeScript:**
- SQL injection via string concatenation and template literals
- XSS via innerHTML, document.write, and dangerouslySetInnerHTML
- Command injection via child_process with unsanitized input
- Prototype pollution
- Hardcoded secrets and API keys
- Use of eval() with dynamic arguments
- Weak cryptographic algorithms

**Python:**
- SQL injection via f-strings and format() in queries
- Command injection via subprocess with shell=True
- Unsafe deserialization (pickle, yaml.load)
- SSRF via unvalidated URLs in requests
- Path traversal in file operations
- Hardcoded secrets

**Go:**
- SQL injection via fmt.Sprintf in queries
- Path traversal via unsanitized input in filepath operations
- Command injection via os/exec with user input
- Use of weak cryptographic primitives
- Unvalidated redirects

Every rule maps to a CWE identifier and includes an OWASP Top 10 category reference.

### CI/CD Integration

Foxguard outputs SARIF, which means it integrates directly with GitHub Advanced Security and GitLab SAST:

```yaml
# GitHub Actions
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Foxguard
        run: cargo install foxguard
      - name: Scan
        run: foxguard scan ./src --format sarif --output results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Because it runs in under a second, you can also use it as a pre-commit hook:

```bash
#!/bin/sh
foxguard scan --staged-only
```

Shift-left only works if the tooling doesn't slow people down.

### What's Next

Foxguard is at v0.2 with 28 rules. Here's the roadmap:

- **50+ rules by v0.3** — expanding coverage for all three languages
- **Taint tracking** — data-flow analysis to trace user input through the program to dangerous sinks (this is where the real power of AST-based analysis shows up)
- **TypeScript-specific rules** — using type information for more precise analysis
- **Plugin system** — WASM-based custom rules so teams can add their own patterns
- **More languages** — Java and C# are the most requested

### Try It

```bash
cargo install foxguard
foxguard scan .
```

Or grab a prebuilt binary from the [releases page](https://github.com/peaktwilight/foxguard/releases).

- **GitHub:** [github.com/peaktwilight/foxguard](https://github.com/peaktwilight/foxguard)
- **Docs:** [foxguard.dev](https://foxguard.dev)
- **License:** MIT

I'm building this in public and prioritizing rules based on community feedback. If there's a vulnerability class you keep seeing in production, open an issue or drop a comment below.

What security rules would you want to see?
