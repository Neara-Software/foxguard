use foxguard::engine::parser::parse_file;
use foxguard::rules::semgrep_compat::{load_semgrep_rules, parse_semgrep_file};
use foxguard::Language;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

const RULES_DIR: &str = "tests/semgrep_rules";
const FIXTURE: &str = "tests/fixtures/vulnerable.py";

#[test]
fn test_load_rules_from_directory() {
    let rules = load_semgrep_rules(Path::new(RULES_DIR));
    assert!(
        rules.len() >= 3,
        "Expected at least 3 rules, got {}",
        rules.len()
    );
}

#[test]
fn test_hardcoded_secret_rule() {
    let rules = parse_semgrep_file(Path::new("tests/semgrep_rules/hardcoded-secret.yaml")).unwrap();
    assert_eq!(rules.len(), 1);

    let source = std::fs::read_to_string(FIXTURE).unwrap();
    let tree = parse_file(&source, Language::Python).unwrap();
    let findings = rules[0].check(&source, &tree);

    assert!(
        !findings.is_empty(),
        "Should detect hardcoded password assignment"
    );
    // Should find `password = "supersecret123"` but not `api_key = "not_a_password"`
    assert!(findings.iter().any(|f| f.snippet.contains("password")));
}

#[test]
fn test_eval_usage_rule() {
    let rules = parse_semgrep_file(Path::new("tests/semgrep_rules/eval-usage.yaml")).unwrap();
    assert_eq!(rules.len(), 1);

    let source = std::fs::read_to_string(FIXTURE).unwrap();
    let tree = parse_file(&source, Language::Python).unwrap();
    let findings = rules[0].check(&source, &tree);

    assert!(
        findings.len() >= 2,
        "Should detect both eval() and exec(), got {} findings",
        findings.len()
    );
}

#[test]
fn test_sql_injection_rule() {
    let rules = parse_semgrep_file(Path::new("tests/semgrep_rules/sql-injection.yaml")).unwrap();
    assert_eq!(rules.len(), 1);

    let source = std::fs::read_to_string(FIXTURE).unwrap();
    let tree = parse_file(&source, Language::Python).unwrap();
    let findings = rules[0].check(&source, &tree);

    assert!(
        !findings.is_empty(),
        "Should detect SQL injection via string concatenation"
    );
}

#[test]
fn test_no_false_positives_on_safe_code() {
    let rules = parse_semgrep_file(Path::new("tests/semgrep_rules/hardcoded-secret.yaml")).unwrap();

    let source = "username = get_from_env('PASSWORD')\nx = 42\n";
    let tree = parse_file(source, Language::Python).unwrap();
    let findings = rules[0].check(source, &tree);

    assert!(
        findings.is_empty(),
        "Should not flag safe code, but got {} findings",
        findings.len()
    );
}

#[test]
fn test_semgrep_rule_metadata() {
    let rules = parse_semgrep_file(Path::new("tests/semgrep_rules/hardcoded-secret.yaml")).unwrap();
    let rule = &rules[0];

    assert_eq!(rule.id(), "semgrep/hardcoded-secret");
    assert_eq!(rule.cwe(), Some("CWE-798"));
    assert_eq!(rule.language(), Language::Python);
}

#[test]
fn test_pattern_regex_support_on_fixture() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        br#"
rules:
  - id: regex-secret-key
    pattern-regex: '(?m)^SECRET_KEY\s*='
    message: SECRET_KEY assigned in source
    severity: ERROR
    languages: [python]
"#,
    )
    .unwrap();

    let rules = parse_semgrep_file(file.path()).unwrap();
    let source = std::fs::read_to_string(FIXTURE).unwrap();
    let tree = parse_file(&source, Language::Python).unwrap();
    let findings = rules[0].check(&source, &tree);

    assert_eq!(findings.len(), 1, "expected one regex-based finding");
    assert!(findings[0].snippet.contains("SECRET_KEY"));
}

#[test]
fn test_mixed_ast_and_regex_patterns() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        br#"
rules:
  - id: eval-regex-overlap
    patterns:
      - pattern: eval(...)
      - pattern-regex: "eval"
    message: eval usage
    severity: ERROR
    languages: [python]
"#,
    )
    .unwrap();

    let rules = parse_semgrep_file(file.path()).unwrap();
    let source = std::fs::read_to_string(FIXTURE).unwrap();
    let tree = parse_file(&source, Language::Python).unwrap();
    let findings = rules[0].check(&source, &tree);

    assert_eq!(findings.len(), 1, "expected AST+regex rule to match eval()");
    assert!(findings[0].snippet.contains("eval"));
}

#[test]
fn test_rule_paths_include_exclude() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        br#"
rules:
  - id: path-scoped-eval
    pattern: eval(...)
    message: eval usage
    severity: ERROR
    languages: [python]
    paths:
      include:
        - src/**/*.py
      exclude:
        - src/generated/**
"#,
    )
    .unwrap();

    let rules = parse_semgrep_file(file.path()).unwrap();
    let rule = &rules[0];

    assert!(rule.applies_to_path(Path::new("src/app/main.py")));
    assert!(!rule.applies_to_path(Path::new("tests/main.py")));
    assert!(!rule.applies_to_path(Path::new("src/generated/main.py")));
}

#[test]
fn test_metavariable_regex_support_on_fixture() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        br#"
rules:
  - id: user-input-only
    patterns:
      - pattern: '"..." + $VAR'
      - metavariable-regex:
          metavariable: $VAR
          regex: ^user_input$
    message: user input only
    severity: ERROR
    languages: [python]
"#,
    )
    .unwrap();

    let rules = parse_semgrep_file(file.path()).unwrap();
    let source = "query = \"SELECT \" + user_input\nquery2 = \"SELECT \" + safe_value\n";
    let tree = parse_file(source, Language::Python).unwrap();
    let findings = rules[0].check(source, &tree);

    assert_eq!(
        findings.len(),
        1,
        "expected metavariable-regex to keep user_input only"
    );
    assert!(findings[0].snippet.contains("user_input"));
}

#[test]
fn test_pattern_not_inside_support_on_fixture() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        br#"
rules:
  - id: redirect-outside-helpers
    patterns:
      - pattern: redirect(...)
      - pattern-not-inside: |
          def safe_redirect(...):
            ...
    message: redirect outside helper
    severity: WARNING
    languages: [python]
"#,
    )
    .unwrap();

    let source = "def safe_redirect(url):\n    return redirect(url)\n\ndef do_redirect(url):\n    return redirect(url)\n";
    let tree = parse_file(source, Language::Python).unwrap();
    let rules = parse_semgrep_file(file.path()).unwrap();
    let findings = rules[0].check(source, &tree);

    assert_eq!(
        findings.len(),
        1,
        "expected pattern-not-inside to suppress helper-wrapped redirect"
    );
    assert_eq!(findings[0].line, 5);
}
