//! HCL / Terraform Semgrep parity micro-pattern suite.
//!
//! Mirrors the structure of `tests/semgrep_parity.rs` (Python) but uses
//! Terraform-native constructs (`resource` blocks, attribute assignments)
//! and the `terraform` / `hcl` language selectors. Each test runs both
//! foxguard and `semgrep` against the same temp directory + YAML rule and
//! asserts identical normalized findings. Tests are skipped gracefully when
//! `semgrep` is not on PATH so the suite stays green in restricted
//! environments.
//!
//! The registry's HCL pack is dominated by `pattern-regex` rules (and
//! `pattern` + `metavariable-regex` combos), which is what these patterns
//! exercise.

mod common;

use common::semgrep_parity_harness::{assert_parity, skip_if_semgrep_missing, write_file};
use tempfile::TempDir;

const TERRAFORM_FIXTURE: &str = concat!(
    "resource \"aws_s3_bucket\" \"public\" {\n",
    "  acl = \"public-read\"\n",
    "}\n\n",
    "resource \"aws_s3_bucket\" \"private\" {\n",
    "  acl = \"private\"\n",
    "}\n",
);

#[test]
fn test_parity_public_acl_pattern_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/acl.yaml",
        r#"
rules:
  - id: s3-public-acl
    pattern-regex: 'acl\s*=\s*"(public-read|public-read-write)"'
    message: S3 bucket grants public ACL
    severity: ERROR
    languages: [terraform]
"#,
    );
    write_file(repo.path(), "main.tf", TERRAFORM_FIXTURE);

    assert_parity(repo.path(), &rules, "main.tf");
}

#[test]
fn test_parity_pattern_either_regex() {
    if skip_if_semgrep_missing() {
        return;
    }

    let repo = TempDir::new().expect("failed to create temp dir");
    let rules = write_file(
        repo.path(),
        "rules/either.yaml",
        r#"
rules:
  - id: insecure-bucket-acl
    pattern-either:
      - pattern-regex: 'acl\s*=\s*"public-read"'
      - pattern-regex: 'acl\s*=\s*"public-read-write"'
    message: insecure bucket ACL
    severity: ERROR
    languages: [hcl]
"#,
    );
    write_file(repo.path(), "main.tf", TERRAFORM_FIXTURE);

    assert_parity(repo.path(), &rules, "main.tf");
}
