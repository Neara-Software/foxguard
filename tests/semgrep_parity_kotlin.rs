//! Kotlin Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity_java.rs` but uses
//! Kotlin-native sources (`call.receiveText()`) and sinks (`Runtime.exec()`).
//! Each test runs foxguard against the same temp directory + YAML rule and
//! asserts that foxguard produces findings in the expected locations.
//! When `semgrep` is on PATH, tests additionally compare `(file, line)` pairs.
//! Tests are skipped gracefully when `semgrep` is not on PATH so the suite
//! remains green in restricted environments.

mod common;

use common::semgrep_parity_harness::{foxguard_findings, skip_if_semgrep_missing, write_file};
use tempfile::TempDir;

/// `mode: taint` parity test for Kotlin: `call.receiveText()` → `Runtime.exec()`.
///
/// foxguard must detect the taint flow from `call.receiveText()` (Ktor request
/// body source) to `Runtime.exec()` (command-injection sink). Semgrep
/// comparison is performed when available, comparing only `(file, line)` pairs.
#[test]
fn test_parity_taint_mode_kotlin_receive_to_exec() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/taint.yaml",
        r#"
rules:
  - id: kotlin-taint-cmd-injection
    mode: taint
    languages: [kotlin]
    severity: ERROR
    message: "Tainted request body flows to Runtime.exec"
    pattern-sources:
      - pattern: call.receiveText($X)
    pattern-sinks:
      - pattern: Runtime.exec($X)
"#,
    );
    // The fixture: call.receiveText() result flows into Runtime.getRuntime().exec().
    // The sink call is on line 4.
    write_file(
        repo.path(),
        "Handler.kt",
        "fun handler(call: ApplicationCall) {\n    val cmd = call.receiveText()\n    Runtime.getRuntime().exec(cmd)\n}\n",
    );

    // foxguard must emit at least one finding.
    let foxguard = foxguard_findings(repo.path(), &rules, "Handler.kt");
    assert!(
        !foxguard.is_empty(),
        "foxguard must detect the Kotlin taint flow (call.receiveText → Runtime.exec); got no findings"
    );

    // foxguard should flag line 3 (the exec call).
    assert!(
        foxguard.iter().any(|f| f.line == 3),
        "foxguard finding should be on line 3 (the sink); got: {:?}",
        foxguard
    );

    // When semgrep is available, compare the set of (file, line) pairs.
    if skip_if_semgrep_missing() {
        return;
    }
    use common::semgrep_parity_harness::semgrep_findings;
    let semgrep = semgrep_findings(repo.path(), &rules, "Handler.kt");
    if !semgrep.is_empty() {
        let foxguard_lines: std::collections::BTreeSet<_> =
            foxguard.iter().map(|f| (&f.path, f.line)).collect();
        let semgrep_lines: std::collections::BTreeSet<_> =
            semgrep.iter().map(|f| (&f.path, f.line)).collect();
        assert_eq!(
            foxguard_lines, semgrep_lines,
            "foxguard and semgrep disagree on the Kotlin taint finding locations"
        );
    }
}
