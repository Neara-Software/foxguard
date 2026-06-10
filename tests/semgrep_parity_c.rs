//! C Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity_java.rs` but uses
//! C-native sinks (`system()`, `printf()`) and `mode: taint` rule syntax.
//! Each test runs foxguard against the same temp directory + YAML rule and
//! asserts that foxguard produces findings in the expected locations.
//! When `semgrep` is on PATH, tests additionally compare `(file, line)` pairs.
//! Tests are skipped gracefully when `semgrep` is not on PATH so the suite
//! remains green in restricted environments.

mod common;

use common::semgrep_parity_harness::{foxguard_findings, skip_if_semgrep_missing, write_file};
use tempfile::TempDir;

/// `mode: taint` parity test for C: `getenv()` → `system()`.
///
/// foxguard must detect the taint flow from `getenv()` (environment variable
/// source) to `system()` (command-injection sink). Semgrep comparison is
/// performed when available, comparing only `(file, line)` pairs.
#[test]
fn test_parity_taint_mode_c_getenv_to_system() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/taint.yaml",
        r#"
rules:
  - id: c-taint-cmd-injection
    mode: taint
    languages: [c]
    severity: ERROR
    message: "Tainted env var flows to system()"
    pattern-sources:
      - pattern: getenv($X)
    pattern-sinks:
      - pattern: system($X)
"#,
    );
    // The fixture: getenv() result assigned to cmd, then passed to system().
    // The sink call is on line 5.
    write_file(
        repo.path(),
        "handler.c",
        "#include <stdlib.h>\nvoid handler() {\n    char *cmd = getenv(\"CMD\");\n    system(cmd);\n}\n",
    );

    // foxguard must emit at least one finding.
    let foxguard = foxguard_findings(repo.path(), &rules, "handler.c");
    assert!(
        !foxguard.is_empty(),
        "foxguard must detect the C taint flow (getenv → system); got no findings"
    );

    // foxguard should flag line 4 (the system() call).
    assert!(
        foxguard.iter().any(|f| f.line == 4),
        "foxguard finding should be on line 4 (the sink); got: {:?}",
        foxguard
    );

    // When semgrep is available, compare the set of (file, line) pairs.
    if skip_if_semgrep_missing() {
        return;
    }
    use common::semgrep_parity_harness::semgrep_findings;
    let semgrep = semgrep_findings(repo.path(), &rules, "handler.c");
    if !semgrep.is_empty() {
        let foxguard_lines: std::collections::BTreeSet<_> =
            foxguard.iter().map(|f| (&f.path, f.line)).collect();
        let semgrep_lines: std::collections::BTreeSet<_> =
            semgrep.iter().map(|f| (&f.path, f.line)).collect();
        assert_eq!(
            foxguard_lines, semgrep_lines,
            "foxguard and semgrep disagree on the C taint finding locations"
        );
    }
}
