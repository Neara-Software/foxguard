//! Haskell Semgrep parity micro-pattern suite.
//!
//! Exercises `languages: [haskell]` Semgrep-compatible regex rules against
//! Haskell sources. Semgrep 1.163.0 does not support Haskell yet, so these
//! cases document foxguard-only coverage until upstream parity is possible.

mod common;

use common::semgrep_parity_harness::{foxguard_findings, write_file};
use tempfile::TempDir;

fn assert_haskell_coverage(repo: &std::path::Path, rules: &std::path::Path, scan_target: &str) {
    let foxguard = foxguard_findings(repo, rules, scan_target);
    assert!(
        !foxguard.is_empty(),
        "foxguard must detect the Haskell pattern; got no findings"
    );
}

#[test]
fn test_parity_haskell_pattern_regex_foreign_import() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/haskell.yaml",
        r#"
rules:
  - id: haskell-ffi-boundary
    pattern-regex: '\bforeign\s+import\b'
    message: Review Haskell FFI boundary
    severity: ERROR
    languages: [haskell]
"#,
    );
    write_file(
        repo.path(),
        "Bindings.hs",
        "module Bindings where\n\nimport Foreign.Ptr (Ptr)\n\nforeign import ccall \"danger\" c_danger :: Ptr a -> IO ()\n",
    );

    assert_haskell_coverage(repo.path(), &rules, "Bindings.hs");
}

#[test]
fn test_parity_haskell_pattern_regex_partial_function() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/haskell.yaml",
        r#"
rules:
  - id: haskell-partial-function
    pattern-regex: '\b(head|fromJust|error|undefined)\b'
    message: Avoid partial functions on attacker-controlled input
    severity: WARNING
    languages: [haskell]
"#,
    );
    write_file(
        repo.path(),
        "Partial.hs",
        "module Partial where\n\nfirstItem :: [Int] -> Int\nfirstItem xs = head xs\n",
    );

    assert_haskell_coverage(repo.path(), &rules, "Partial.hs");
}
