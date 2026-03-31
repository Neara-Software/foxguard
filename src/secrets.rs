use crate::{Finding, Severity};
use ignore::WalkBuilder;
use regex::Regex;
use std::path::{Path, PathBuf};

struct SecretPattern {
    rule_id: &'static str,
    severity: Severity,
    cwe: Option<&'static str>,
    description: &'static str,
    regex: Regex,
}

fn patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            rule_id: "secret/aws-access-key-id",
            severity: Severity::Critical,
            cwe: Some("CWE-798"),
            description: "Possible AWS access key ID detected",
            regex: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        },
        SecretPattern {
            rule_id: "secret/github-token",
            severity: Severity::Critical,
            cwe: Some("CWE-798"),
            description: "Possible GitHub personal access token detected",
            regex: Regex::new(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")
                .unwrap(),
        },
        SecretPattern {
            rule_id: "secret/slack-token",
            severity: Severity::High,
            cwe: Some("CWE-798"),
            description: "Possible Slack token detected",
            regex: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
        },
        SecretPattern {
            rule_id: "secret/stripe-live-key",
            severity: Severity::Critical,
            cwe: Some("CWE-798"),
            description: "Possible Stripe live secret key detected",
            regex: Regex::new(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b").unwrap(),
        },
        SecretPattern {
            rule_id: "secret/private-key",
            severity: Severity::Critical,
            cwe: Some("CWE-798"),
            description: "Private key material detected",
            regex: Regex::new(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
                .unwrap(),
        },
    ]
}

fn redact_match(line: &str, start: usize, end: usize) -> String {
    let mut redacted = String::with_capacity(line.len());
    redacted.push_str(&line[..start]);
    redacted.push_str("[REDACTED]");
    redacted.push_str(&line[end..]);
    redacted
}

pub fn scan_directory(root: &str) -> Vec<Finding> {
    let root_path = Path::new(root);
    let files: Vec<PathBuf> = if root_path.is_file() {
        vec![root_path.to_path_buf()]
    } else {
        WalkBuilder::new(root)
            .hidden(true)
            .git_ignore(true)
            .build()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_file()))
            .map(|entry| entry.into_path())
            .collect()
    };

    scan_paths(&files)
}

pub fn scan_paths(paths: &[PathBuf]) -> Vec<Finding> {
    let patterns = patterns();
    let mut findings = Vec::new();

    for path in paths {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };

        for (line_idx, line) in source.lines().enumerate() {
            for pattern in &patterns {
                for matched in pattern.regex.find_iter(line) {
                    findings.push(Finding {
                        rule_id: pattern.rule_id.to_string(),
                        severity: pattern.severity,
                        cwe: pattern.cwe.map(str::to_string),
                        description: pattern.description.to_string(),
                        file: path.display().to_string(),
                        line: line_idx + 1,
                        column: matched.start() + 1,
                        end_line: line_idx + 1,
                        end_column: matched.end() + 1,
                        snippet: redact_match(line, matched.start(), matched.end()),
                    });
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
    findings
}
