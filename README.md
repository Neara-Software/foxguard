<p align="center">
  <img src="assets/logo.svg" width="80" alt="foxguard logo" />
</p>

<h1 align="center">foxguard</h1>

<p align="center">
  The security linter fast enough to sit between your AI and your codebase.
  <br/>
  <a href="https://foxguard.dev">foxguard.dev</a> | <a href="https://crates.io/crates/foxguard">crates.io</a> | <a href="https://www.npmjs.com/package/foxguard">npm</a>
</p>

> Your AI writes code. foxguard catches what it gets wrong.

## The Problem

80% of AI-generated code that passes functional tests still has security bugs ([SusVibes, 2025](https://arxiv.org/abs/2512.03559)). Existing SAST tools were built for human-written code -- they miss the patterns AI gets wrong: scaffold boilerplate with hardcoded secrets, over-permissive defaults, missing auth middleware, BaaS misconfigurations.

foxguard is purpose-built for the vibe coding era.

## Install

```sh
cargo install foxguard
```

```sh
npx foxguard
```

## Usage

```sh
foxguard .
```

```
src/app.js
  12:5  CRITICAL  js/express-no-hardcoded-session-secret (CWE-798)
        Hardcoded session secret -- use environment variables
  45:3  HIGH      js/express-direct-response-write (CWE-79)
        res.send() called with user input -- risk of reflected XSS

WARNING 2 issues found: 1 critical, 1 high, 0 medium, 0 low
```

## What It Catches

36 security rules across 3 languages, focused on what AI gets wrong:

**AI scaffold patterns**
- Hardcoded secrets and placeholder credentials (CWE-798)
- Debug mode left enabled (CWE-489)
- Missing cookie security flags (CWE-614, CWE-1004)
- CORS allow-all origins (CWE-942)

**Injection**
- SQL injection via string concatenation (CWE-89)
- Command injection via exec/spawn (CWE-78)
- XSS via innerHTML, document.write, res.send (CWE-79)
- Path traversal (CWE-22)

**Framework-specific (Express, Flask, Django, Gin)**
- Express hardcoded session secrets
- Express direct response write with user input
- Flask debug mode enabled
- Django SECRET_KEY hardcoded
- Gin missing trusted proxies
- net/http missing timeouts

**Crypto and data safety**
- Weak crypto (MD5, SHA1) (CWE-327)
- Unsafe deserialization: pickle, yaml.load (CWE-502)
- Prototype pollution (CWE-1321)
- SSRF via dynamic URLs (CWE-918)

## Languages

| Language | Rules | Frameworks |
|----------|-------|------------|
| JavaScript/TypeScript | 16 | Express |
| Python | 13 | Flask, Django |
| Go | 7 | Gin, net/http |

## Output Formats

```sh
foxguard .                    # Colored terminal output
foxguard --format json .      # JSON
foxguard --format sarif .     # SARIF (GitHub Code Scanning)
foxguard --severity high .    # Filter by severity
```

## GitHub Action

```yaml
- uses: peaktwilight/foxguard-action@v1
  with:
    path: .
    severity: medium
```

## Performance

| Repository | Files | foxguard | Semgrep | Speedup |
|------------|-------|----------|---------|---------|
| express | 141 | 0.57s | 5.3s | 9x |
| flask | 83 | 0.06s | 5.2s | 85x |
| gin | 99 | 0.08s | 4.7s | 60x |
| next.js | 14,777 | 4.5s | 229s | 51x |

Rust + tree-sitter + rayon. No JVM, no Python runtime, no network calls.

## License

MIT
