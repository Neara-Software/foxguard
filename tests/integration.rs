use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn foxguard_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_foxguard"))
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn setup_git_repo(files: &[&str]) -> TempDir {
    let repo = TempDir::new().expect("failed to create temp repo");

    Command::new("git")
        .args(["init"])
        .current_dir(repo.path())
        .output()
        .expect("failed to initialize git repo");

    for file in files {
        let src = fixture_path(file);
        let dest = repo.path().join(file);
        fs::copy(src, dest).expect("failed to copy fixture");
    }

    repo
}

// ─── Vulnerable file detection ──────────────────────────────────────────────

#[test]
fn test_vulnerable_js_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "should exit non-zero when findings exist"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        18,
        "vulnerable.js should have 18 findings, got {}",
        findings.len()
    );

    // Verify all unique rule IDs are present
    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "js/no-eval",
        "js/no-hardcoded-secret",
        "js/no-sql-injection",
        "js/no-xss-innerhtml",
        "js/no-command-injection",
        "js/no-document-write",
        "js/no-open-redirect",
        "js/no-weak-crypto",
        "js/no-path-traversal",
        "js/no-prototype-pollution",
        "js/no-unsafe-regex",
        "js/no-cors-star",
        "js/express-no-hardcoded-session-secret",
        "js/express-cookie-no-secure",
        "js/express-cookie-no-httponly",
        "js/express-direct-response-write",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_py_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        16,
        "vulnerable.py should have 16 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "py/no-eval",
        "py/no-hardcoded-secret",
        "py/no-sql-injection",
        "py/no-command-injection",
        "py/no-path-traversal",
        "py/no-weak-crypto",
        "py/no-pickle",
        "py/no-yaml-load",
        "py/no-debug-true",
        "py/no-open-redirect",
        "py/no-cors-star",
        "py/flask-debug-mode",
        "py/django-secret-key-hardcoded",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

#[test]
fn test_vulnerable_go_finds_all_rules() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.go", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(
        findings.len(),
        8,
        "vulnerable.go should have 8 findings, got {}",
        findings.len()
    );

    let rule_ids: std::collections::HashSet<&str> = findings
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .collect();

    let expected_rules = [
        "go/no-sql-injection",
        "go/no-command-injection",
        "go/no-hardcoded-secret",
        "go/no-weak-crypto",
        "go/no-ssrf",
        "go/net-http-no-timeout",
    ];

    for rule in &expected_rules {
        assert!(rule_ids.contains(rule), "missing expected rule: {}", rule);
    }
}

// ─── Safe file detection ────────────────────────────────────────────────────

#[test]
fn test_safe_js_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(output.status.success(), "safe.js should exit zero");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "safe.js should have 0 findings");
}

#[test]
fn test_safe_py_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe.py", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(output.status.success(), "safe.py should exit zero");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "safe.py should have 0 findings");
}

#[test]
fn test_safe_go_no_findings() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/safe.go", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(output.status.success(), "safe.go should exit zero");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "safe.go should have 0 findings");
}

#[test]
fn test_invalid_path_exits_nonzero() {
    let output = foxguard_cmd()
        .args(["not_a_real_path_foxguard_test", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "invalid paths should exit non-zero"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist"),
        "expected missing path error, got: {}",
        stderr
    );
}

#[test]
fn test_no_builtins_without_external_rules_finds_nothing() {
    let output = foxguard_cmd()
        .args([
            "tests/fixtures/vulnerable.js",
            "-f",
            "json",
            "--no-builtins",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        output.status.success(),
        "no built-ins and no external rules should exit zero"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert_eq!(findings.len(), 0, "expected no findings without any rules");
}

#[test]
fn test_no_builtins_with_external_rules_still_finds_matches() {
    let output = foxguard_cmd()
        .args([
            "tests/fixtures/vulnerable.py",
            "-f",
            "json",
            "--no-builtins",
            "--rules",
            "tests/semgrep_rules",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "external rules should still report findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert!(
        !findings.is_empty(),
        "expected findings from external rules when built-ins are disabled"
    );
}

#[test]
fn test_write_and_apply_baseline() {
    let repo = TempDir::new().expect("failed to create temp dir");
    let source = fixture_path("vulnerable.js");
    let target = repo.path().join("vulnerable.js");
    fs::copy(source, &target).expect("failed to copy fixture");
    let baseline = repo.path().join("baseline.json");

    let initial = foxguard_cmd()
        .args([
            target.to_str().expect("non-utf8 path"),
            "-f",
            "json",
            "--write-baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !initial.status.success(),
        "writing a baseline should still report current findings"
    );
    assert!(baseline.exists(), "baseline file should be created");

    let suppressed = foxguard_cmd()
        .args([
            target.to_str().expect("non-utf8 path"),
            "-f",
            "json",
            "--baseline",
            baseline.to_str().expect("non-utf8 path"),
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(
        suppressed.status.success(),
        "baseline should suppress the existing findings"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&suppressed.stdout).expect("invalid JSON output");
    assert_eq!(findings.len(), 0, "expected no findings after baseline");
}

#[test]
fn test_changed_mode_scans_only_staged_files() {
    let repo = setup_git_repo(&["vulnerable.js", "safe.py"]);

    Command::new("git")
        .args(["add", "vulnerable.js"])
        .current_dir(repo.path())
        .output()
        .expect("failed to stage vulnerable.js");

    let output = foxguard_cmd()
        .args(["--changed", "-f", "json", "."])
        .current_dir(repo.path())
        .output()
        .expect("failed to execute foxguard");

    assert!(
        !output.status.success(),
        "changed-mode scan should report findings from staged vulnerable.js"
    );

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");
    assert!(
        findings.iter().all(|finding| finding["file"]
            .as_str()
            .unwrap_or_default()
            .ends_with("vulnerable.js")),
        "changed mode should only scan the staged file"
    );
}

#[test]
fn test_init_installs_hook_and_baseline() {
    let repo = setup_git_repo(&["vulnerable.js"]);

    let output = foxguard_cmd()
        .args(["init", "--path", ".", "--force"])
        .current_dir(repo.path())
        .output()
        .expect("failed to execute foxguard init");

    assert!(output.status.success(), "init should succeed");
    assert!(
        repo.path().join(".git/hooks/pre-commit").exists(),
        "pre-commit hook should be installed"
    );
    assert!(
        repo.path().join(".foxguard/baseline.json").exists(),
        "baseline should be created by default"
    );
}

// ─── Severity filtering ─────────────────────────────────────────────────────

#[test]
fn test_severity_filter_high() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "json", "-s", "high"])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    // High and Critical only
    assert_eq!(
        findings.len(),
        11,
        "high severity filter on vulnerable.js should yield 11 findings, got {}",
        findings.len()
    );

    // All findings should be High or Critical
    for finding in &findings {
        let severity = finding["severity"].as_str().unwrap();
        assert!(
            severity == "high" || severity == "critical",
            "expected high or critical, got: {}",
            severity
        );
    }
}

#[test]
fn test_severity_filter_critical() {
    let output = foxguard_cmd()
        .args([
            "tests/fixtures/vulnerable.js",
            "-f",
            "json",
            "-s",
            "critical",
        ])
        .output()
        .expect("failed to execute foxguard");

    assert!(!output.status.success());

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    // All findings should be Critical
    for finding in &findings {
        let severity = finding["severity"].as_str().unwrap();
        assert_eq!(severity, "critical", "expected critical, got: {}", severity);
    }
}

// ─── JSON output structure ──────────────────────────────────────────────────

#[test]
fn test_json_output_structure() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "json"])
        .output()
        .expect("failed to execute foxguard");

    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("invalid JSON output");

    assert!(!findings.is_empty());

    let first = &findings[0];

    // Verify all expected fields exist
    assert!(first["rule_id"].is_string(), "missing rule_id");
    assert!(first["severity"].is_string(), "missing severity");
    assert!(first["description"].is_string(), "missing description");
    assert!(first["file"].is_string(), "missing file");
    assert!(first["line"].is_number(), "missing line");
    assert!(first["column"].is_number(), "missing column");
    assert!(first["end_line"].is_number(), "missing end_line");
    assert!(first["end_column"].is_number(), "missing end_column");
    assert!(first["snippet"].is_string(), "missing snippet");
}

// ─── SARIF output ───────────────────────────────────────────────────────────

#[test]
fn test_sarif_output_valid() {
    let output = foxguard_cmd()
        .args(["tests/fixtures/vulnerable.js", "-f", "sarif"])
        .output()
        .expect("failed to execute foxguard");

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("invalid SARIF JSON");

    assert_eq!(sarif["version"].as_str(), Some("2.1.0"));
    assert!(sarif["runs"].is_array());
    assert!(sarif["$schema"].is_string());

    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("missing results array");
    assert!(!results.is_empty(), "SARIF results should not be empty");
}
