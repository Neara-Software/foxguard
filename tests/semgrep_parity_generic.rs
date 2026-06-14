//! Parity tests for Semgrep `generic` mode (spacegrep / `languages: [generic]`).
//!
//! These diff foxguard against the real `semgrep` CLI on small generic rules.
//! Like the other parity suites, every test is gated on `semgrep` being on
//! PATH (`skip_if_semgrep_missing`) so it is skipped cleanly in environments
//! that do not have it installed.
//!
//! Targets are written under a recognized config path (`nginx/*.conf`) so
//! foxguard detects a language for the file and runs the generic rule against
//! its raw text — generic rules are AST-less and only execute on files
//! foxguard already recognizes.

mod common;

use common::semgrep_parity_harness::{assert_parity, skip_if_semgrep_missing, write_file};
use tempfile::TempDir;

#[test]
fn test_parity_generic_literal_and_ellipsis() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/ssl.yaml",
        r#"
rules:
  - id: weak-ssl-protocols
    pattern: ssl_protocols ...
    message: weak ssl_protocols directive
    severity: WARNING
    languages: [generic]
"#,
    );
    write_file(
        repo.path(),
        "nginx/site.conf",
        "server {\n  ssl_protocols TLSv1 TLSv1.1;\n  listen 80;\n}\n",
    );

    assert_parity(repo.path(), &rules, "nginx/site.conf");
}

#[test]
fn test_parity_generic_metavariable() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/secret.yaml",
        r#"
rules:
  - id: hardcoded-password-assign
    pattern: password = $VAL
    message: hardcoded password assignment
    severity: ERROR
    languages: [generic]
"#,
    );
    write_file(
        repo.path(),
        "nginx/app.conf",
        "password = secret123\napi_key = abcdef\nusername = admin\npassword = hunter2\n",
    );

    assert_parity(repo.path(), &rules, "nginx/app.conf");
}

#[test]
fn test_parity_generic_pattern_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/marker.yaml",
        r#"
rules:
  - id: deprecated-token-marker
    pattern-regex: 'DEPRECATED-[0-9]{4}'
    message: deprecated configuration marker
    severity: ERROR
    languages: [generic]
"#,
    );
    write_file(
        repo.path(),
        "nginx/markers.conf",
        "harmless = value\nlegacy = DEPRECATED-2021\n",
    );

    assert_parity(repo.path(), &rules, "nginx/markers.conf");
}
