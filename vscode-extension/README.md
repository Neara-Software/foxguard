# foxguard for VS Code

Security scanner as fast as a linter. Scans your code on save and shows findings as inline diagnostics.

## Features

- Runs `foxguard` on each file save
- Shows findings as VS Code diagnostics (error, warning, info squiggles)
- Supports JavaScript, TypeScript, Python, Go, Ruby, Java, PHP, Rust, C#, and Swift
- Manual scan via the **foxguard: Scan Current File** command

## Requirements

Install foxguard:

```sh
npm install -g foxguard
```

Or use [cargo](https://foxguard.dev):

```sh
cargo install foxguard
```

The extension auto-detects the binary from PATH, or falls back to `npx foxguard`.

## Configuration

| Setting             | Default | Description                          |
| ------------------- | ------- | ------------------------------------ |
| `foxguard.path`     | `""`    | Custom path to the foxguard binary   |
| `foxguard.severity` | `low`   | Minimum severity to show (low/medium/high/critical) |
