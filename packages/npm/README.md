# foxguard

Security scanner as fast as a linter. 100+ built-in rules, 10 languages, sub-second scans.

```sh
npx foxguard .
```

## What it does

Scans your code for security vulnerabilities — SQL injection, XSS, SSRF, hardcoded secrets, command injection, weak crypto, unsafe deserialization, and framework-specific checks.

**Languages:** JavaScript, TypeScript, Python, Go, Ruby, Java, PHP, Rust, C#, Swift.

## How it works

This is the npm wrapper. It downloads the correct prebuilt Rust binary for your platform from GitHub Releases and caches it locally.

```sh
npx foxguard .                    # scan everything
npx foxguard --changed .          # only modified files
npx foxguard secrets .            # leaked credentials
npx foxguard --format sarif .     # SARIF for GitHub Code Scanning
npx foxguard init                 # install pre-commit hook
```

## Supported platforms

- macOS (x64, arm64)
- Linux (x64, arm64)
- Windows (x64)

## More

- [GitHub](https://github.com/peaktwilight/foxguard)
- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=peaktwilight.foxguard)
- [foxguard.dev](https://foxguard.dev)
