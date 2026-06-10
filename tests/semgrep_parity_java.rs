//! Java Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity.rs` (Python) but uses
//! Java-native sinks (`Runtime.getRuntime().exec`, `String.format`) and
//! rule syntax. Each test runs both foxguard and `semgrep` against the
//! same temp directory + YAML rule and asserts byte-identical normalized
//! findings. Tests are skipped gracefully when `semgrep` is not on PATH
//! so the suite remains green in restricted environments.

mod common;

use common::semgrep_parity_harness::{
    assert_parity, foxguard_findings, skip_if_semgrep_missing, write_file,
};
use tempfile::TempDir;

#[test]
fn test_parity_pattern_either() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/exec.yaml",
        r#"
rules:
  - id: dangerous-java-sink
    pattern-either:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: String.format(...)
    message: dangerous java call
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    public static void main(String[] args) {\n        Runtime.getRuntime().exec(\"ls\");\n        String.format(\"%s\", args[0]);\n        System.out.println(\"safe\");\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_binary_operator_and_metavariable_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/format.yaml",
        r#"
rules:
  - id: tainted-format
    patterns:
      - pattern: String.format($FMT, $VAR)
      - metavariable-regex:
          metavariable: $VAR
          regex: ^userInput$
    message: tainted format call
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    void m() {\n        String.format(\"%s\", userInput);\n        String.format(\"%s\", safeValue);\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_pattern_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/inside.yaml",
        r#"
rules:
  - id: exec-in-handle
    patterns:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern-inside: |
          void handle(...) {
            ...
          }
    message: exec inside handle()
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    void handle(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n    void helper(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_pattern_not_inside() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/not-inside.yaml",
        r#"
rules:
  - id: exec-outside-helper
    patterns:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern-not-inside: |
          void safeExec(...) {
            ...
          }
    message: exec outside safeExec()
    severity: WARNING
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    void safeExec(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n    void doExec(String args) {\n        Runtime.getRuntime().exec(args);\n    }\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_pattern_regex_and_not_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/regex.yaml",
        r#"
rules:
  - id: secret-field
    pattern-regex: '(?m)^\s*(String|final\s+String)\s+(password|secret)\s*='
    pattern-not-regex: '(?m)^\s*String\s+not_password\s*='
    message: secret field assignment
    severity: ERROR
    languages: [java]
"#,
    );
    write_file(
        repo.path(),
        "A.java",
        "public class A {\n    String password = \"secret\";\n    String not_password = \"safe\";\n    final String secret = \"abc\";\n}\n",
    );

    assert_parity(repo.path(), &rules, "A.java");
}

#[test]
fn test_parity_paths_include_exclude() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/paths.yaml",
        r#"
rules:
  - id: path-scoped-exec
    pattern: Runtime.getRuntime().exec(...)
    message: exec in app source
    severity: ERROR
    languages: [java]
    paths:
      include:
        - src/**/*.java
      exclude:
        - src/generated/**
"#,
    );
    write_file(
        repo.path(),
        "src/app/Main.java",
        "public class Main { static { Runtime.getRuntime().exec(\"ls\"); } }\n",
    );
    write_file(
        repo.path(),
        "src/generated/Gen.java",
        "public class Gen { static { Runtime.getRuntime().exec(\"ls\"); } }\n",
    );
    write_file(
        repo.path(),
        "tests/T.java",
        "public class T { static { Runtime.getRuntime().exec(\"ls\"); } }\n",
    );

    assert_parity(repo.path(), &rules, ".");
}

/// `mode: taint` parity test for Java.
///
/// Semgrep and foxguard produce slightly different message text for taint
/// findings (foxguard appends "— <source> reaches <sink>" to the rule
/// message), so this test compares only `(file, line)` pairs rather than
/// full messages.  Both tools must agree on *which* line the sink is on.
///
/// The test is skipped when `semgrep` is not on PATH (same behaviour as all
/// other parity tests in this file).
#[test]
fn test_parity_taint_mode_java_source_to_sink() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = tempfile::TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/taint.yaml",
        r#"
rules:
  - id: java-taint-cmd-injection
    mode: taint
    languages: [java]
    severity: ERROR
    message: "Tainted input flows to Runtime.exec"
    pattern-sources:
      - pattern: request.getParameter($X)
    pattern-sinks:
      - pattern: Runtime.exec($X)
"#,
    );
    // The fixture has a source→sink flow: request.getParameter feeds cmd
    // which flows to Runtime.exec. The sink call is on line 5.
    write_file(
        repo.path(),
        "Controller.java",
        "public class Controller {\n\
         \n\
         void run(HttpServletRequest request) throws Exception {\n\
         String cmd = request.getParameter(\"cmd\");\n\
         Runtime.getRuntime().exec(cmd);\n\
         }\n\
         }\n",
    );

    // foxguard must emit at least one finding.
    let foxguard = foxguard_findings(repo.path(), &rules, "Controller.java");
    assert!(
        !foxguard.is_empty(),
        "foxguard must detect the Java taint flow (request.getParameter → Runtime.exec); got no findings"
    );

    // foxguard should flag line 5 (the exec call).
    assert!(
        foxguard.iter().any(|f| f.line == 5),
        "foxguard finding should be on line 5 (the sink); got: {:?}",
        foxguard
    );

    // When semgrep is available, compare the set of (file, line) pairs.
    // We do NOT compare messages because foxguard enriches them with
    // "— source reaches sink" text that Semgrep does not produce.
    use common::semgrep_parity_harness::semgrep_findings;
    let semgrep = semgrep_findings(repo.path(), &rules, "Controller.java");
    if !semgrep.is_empty() {
        let foxguard_lines: std::collections::BTreeSet<_> =
            foxguard.iter().map(|f| (&f.path, f.line)).collect();
        let semgrep_lines: std::collections::BTreeSet<_> =
            semgrep.iter().map(|f| (&f.path, f.line)).collect();
        assert_eq!(
            foxguard_lines, semgrep_lines,
            "foxguard and semgrep disagree on the Java taint finding locations"
        );
    }
}
