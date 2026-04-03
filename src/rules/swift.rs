use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use regex::Regex;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn get_source_line(source: &str, byte_offset: usize) -> String {
    let start = source[..byte_offset].rfind('\n').map_or(0, |p| p + 1);
    let end = source[byte_offset..]
        .find('\n')
        .map_or(source.len(), |p| byte_offset + p);
    source[start..end].to_string()
}

fn walk_tree(
    node: tree_sitter::Node,
    source: &str,
    callback: &mut dyn FnMut(tree_sitter::Node, &str),
) {
    callback(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, source, callback);
    }
}

fn make_finding(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    node: tree_sitter::Node,
    source: &str,
) -> Finding {
    let start = node.start_position();
    let end = node.end_position();
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line: start.row + 1,
        column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
        snippet: get_source_line(source, node.start_byte()),
    }
}

fn make_finding_from_offsets(
    rule_id: &str,
    severity: Severity,
    cwe: Option<&str>,
    description: &str,
    source: &str,
    start_byte: usize,
    end_byte: usize,
) -> Finding {
    let line = source[..start_byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = source[..start_byte].rfind('\n').map_or(0, |idx| idx + 1);
    let column = source[line_start..start_byte].chars().count() + 1;

    let end_line = source[..end_byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let end_line_start = source[..end_byte].rfind('\n').map_or(0, |idx| idx + 1);
    let end_column = source[end_line_start..end_byte].chars().count() + 1;

    Finding {
        rule_id: rule_id.to_string(),
        severity,
        cwe: cwe.map(|s| s.to_string()),
        description: description.to_string(),
        file: String::new(),
        line,
        column,
        end_line,
        end_column,
        snippet: get_source_line(source, start_byte),
    }
}

// ─── Rule 1: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "swift/no-hardcoded-secret"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-798")
    }
    fn description(&self) -> &str {
        "Hardcoded secret or credential detected"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Match property declarations: let password = "hardcoded"
            // or var apiKey = "secret123"
            if node.kind() == "property_declaration" {
                // Check if the name portion matches a secret pattern
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = &src[name_node.byte_range()];
                    if secret_pattern.is_match(name) {
                        // Walk children looking for a string_literal value
                        let mut has_string_value = false;
                        let mut string_val = String::new();
                        let mut cursor = node.walk();
                        for child in node.children(&mut cursor) {
                            if child.kind() == "line_string_literal"
                                || child.kind() == "string_literal"
                            {
                                has_string_value = true;
                                string_val = src[child.byte_range()].to_string();
                            }
                        }
                        if has_string_value {
                            let inner = string_val.trim_matches('"');
                            let line = node.start_position().row;
                            if inner.len() >= 4 && reported_lines.insert(line) {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    &format!(
                                        "Hardcoded secret in '{}' — use environment variables or Keychain",
                                        name
                                    ),
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }

            // Fallback: regex-based detection for patterns like `let password = "..."`
            // that may parse differently
            if node.kind() == "value_binding_pattern" || node.kind() == "pattern" {
                let name = &src[node.byte_range()];
                if secret_pattern.is_match(name) {
                    if let Some(parent) = node.parent() {
                        let line = parent.start_position().row;
                        if reported_lines.contains(&line) {
                            return;
                        }
                        let mut cursor = parent.walk();
                        for child in parent.children(&mut cursor) {
                            if child.kind() == "line_string_literal"
                                || child.kind() == "string_literal"
                            {
                                let val = &src[child.byte_range()];
                                let inner = val.trim_matches('"');
                                if inner.len() >= 4 && reported_lines.insert(line) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables or Keychain",
                                            name
                                        ),
                                        parent,
                                        src,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 2: no-command-injection ───────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "swift/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via Process or NSTask with dynamic arguments"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                if text.starts_with("Process(") || text.starts_with("NSTask(") {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "Process/NSTask created — ensure arguments are not user-controlled to prevent command injection",
                        node,
                        src,
                    ));
                }
            }

            // Detect .launchPath or .arguments assignment with non-literal values
            if node.kind() == "assignment" {
                let text = &src[node.byte_range()];
                if (text.contains(".launchPath") || text.contains(".arguments"))
                    && !text.contains('"')
                {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "Process arguments set with dynamic value — risk of command injection",
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 3: no-weak-crypto ────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "swift/no-weak-crypto"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-327")
    }
    fn description(&self) -> &str {
        "Use of weak cryptographic hash (MD5/SHA1)"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pattern =
            Regex::new(r"\b(CC_MD5|CC_SHA1|\.md5|\.sha1|Insecure\.MD5|Insecure\.SHA1)\b").unwrap();

        for matched in pattern.find_iter(source) {
            let algo = if matched.as_str().contains("MD5") || matched.as_str().contains("md5") {
                "MD5"
            } else {
                "SHA1"
            };
            findings.push(make_finding_from_offsets(
                self.id(),
                self.severity(),
                self.cwe(),
                &format!(
                    "{} is cryptographically weak — use SHA-256 or stronger",
                    algo
                ),
                source,
                matched.start(),
                matched.end(),
            ));
        }
        findings
    }
}

// ─── Rule 4: no-insecure-transport ─────────────────────────────────────────

pub struct NoInsecureTransport;

impl Rule for NoInsecureTransport {
    fn id(&self) -> &str {
        "swift/no-insecure-transport"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-319")
    }
    fn description(&self) -> &str {
        "Insecure HTTP URL detected — use HTTPS instead"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "line_string_literal" || node.kind() == "string_literal" {
                let text = &src[node.byte_range()];
                if text.contains("http://")
                    && !text.contains("http://localhost")
                    && !text.contains("http://127.0.0.1")
                {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "Insecure HTTP URL — use HTTPS to protect data in transit",
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 5: no-eval-js ────────────────────────────────────────────────────

pub struct NoEvalJs;

impl Rule for NoEvalJs {
    fn id(&self) -> &str {
        "swift/no-eval-js"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "WKWebView evaluateJavaScript with dynamic input enables code injection"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                if text.contains("evaluateJavaScript") {
                    // Check if the argument is a string literal or interpolated
                    let has_interpolation = text.contains("\\(");
                    let is_variable_arg =
                        !text.contains("evaluateJavaScript(\"") || has_interpolation;
                    if is_variable_arg {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "evaluateJavaScript called with dynamic input — risk of JavaScript injection in WKWebView",
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// ─── Rule 6: no-sql-injection ──────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "swift/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string interpolation in SQLite queries"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_keywords =
            Regex::new(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s").unwrap();

        // Detect SQL strings with interpolation: "SELECT ... \(variable) ..."
        let interp_string = Regex::new(r#""[^"]*\\\([^)]+\)[^"]*""#).unwrap();
        for matched in interp_string.find_iter(source) {
            let text = matched.as_str();
            if sql_keywords.is_match(text) {
                findings.push(make_finding_from_offsets(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "SQL query with string interpolation — use parameterized queries to prevent SQL injection",
                    source,
                    matched.start(),
                    matched.end(),
                ));
            }
        }

        // Detect execute/prepare calls with string concatenation
        let sql_concat = Regex::new(
            r#"(?i)(execute|prepare|sqlite3_exec)\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*\+\s*"#,
        )
        .unwrap();
        for matched in sql_concat.find_iter(source) {
            findings.push(make_finding_from_offsets(
                self.id(),
                self.severity(),
                self.cwe(),
                "SQL query built with string concatenation — use parameterized queries",
                source,
                matched.start(),
                matched.end(),
            ));
        }

        findings
    }
}

// ─── Rule 7: no-insecure-keychain ──────────────────────────────────────────

pub struct NoInsecureKeychain;

impl Rule for NoInsecureKeychain {
    fn id(&self) -> &str {
        "swift/no-insecure-keychain"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-311")
    }
    fn description(&self) -> &str {
        "Insecure Keychain accessibility level allows access when device is locked"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pattern =
            Regex::new(r"\b(kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly)\b")
                .unwrap();

        for matched in pattern.find_iter(source) {
            findings.push(make_finding_from_offsets(
                self.id(),
                self.severity(),
                self.cwe(),
                &format!(
                    "{} allows Keychain access when device is locked — use kSecAttrAccessibleWhenUnlocked",
                    matched.as_str()
                ),
                source,
                matched.start(),
                matched.end(),
            ));
        }
        findings
    }
}

// ─── Rule 8: no-tls-disabled ───────────────────────────────────────────────

pub struct NoTlsDisabled;

impl Rule for NoTlsDisabled {
    fn id(&self) -> &str {
        "swift/no-tls-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-295")
    }
    fn description(&self) -> &str {
        "TLS certificate validation disabled or weakened"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, _tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        let patterns = [
            (
                Regex::new(r"allowsExpiredCertificates\s*=\s*true").unwrap(),
                "allowsExpiredCertificates = true disables certificate expiry validation",
            ),
            (
                Regex::new(r"allowsExpiredRoots\s*=\s*true").unwrap(),
                "allowsExpiredRoots = true disables root certificate expiry validation",
            ),
            (
                Regex::new(r"\.disableEvaluation").unwrap(),
                ".disableEvaluation disables TLS server trust evaluation entirely",
            ),
        ];

        for (pattern, msg) in &patterns {
            for matched in pattern.find_iter(source) {
                findings.push(make_finding_from_offsets(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    msg,
                    source,
                    matched.start(),
                    matched.end(),
                ));
            }
        }
        findings
    }
}

// ─── Rule 9: no-path-traversal ─────────────────────────────────────────────

pub struct NoPathTraversal;

impl Rule for NoPathTraversal {
    fn id(&self) -> &str {
        "swift/no-path-traversal"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-22")
    }
    fn description(&self) -> &str {
        "Potential path traversal via FileManager with dynamic path"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];
                // Detect FileManager operations with non-literal paths
                let fm_ops = [
                    "contentsOfDirectory",
                    "createDirectory",
                    "removeItem",
                    "copyItem",
                    "moveItem",
                    "fileExists",
                    "contents(atPath",
                ];
                let has_fm_op = fm_ops.iter().any(|op| text.contains(op));
                if has_fm_op {
                    // Check if path argument is dynamic (not a string literal)
                    // Look for atPath: or path: arguments that are not string literals
                    let has_dynamic_path = (text.contains("atPath:") || text.contains("path:"))
                        && !text.contains("atPath: \"")
                        && !text.contains("path: \"");
                    if has_dynamic_path {
                        let line = node.start_position().row;
                        if reported_lines.insert(line) {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                "FileManager operation with dynamic path — validate and sanitize to prevent path traversal",
                                node,
                                src,
                            ));
                        }
                    }
                }
            }
        });

        findings
    }
}

// ─── Rule 10: no-ssrf ──────────────────────────────────────────────────────

pub struct NoSsrf;

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "swift/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via URLSession or URL with dynamic input"
    }
    fn language(&self) -> Language {
        Language::Swift
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut reported_lines = std::collections::HashSet::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                let text = &src[node.byte_range()];

                // Detect URL(string: variable)
                if text.starts_with("URL(string:") || text.starts_with("URL(string :") {
                    // Check if argument is not a string literal
                    let after_colon = text.split_once(':').map(|x| x.1).unwrap_or("");
                    let trimmed = after_colon.trim();
                    if !trimmed.starts_with('"') && !trimmed.starts_with("\"") {
                        let line = node.start_position().row;
                        if reported_lines.insert(line) {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                "URL(string:) called with dynamic value — validate and allowlist target hosts to prevent SSRF",
                                node,
                                src,
                            ));
                        }
                    }
                }

                // Detect URLSession.shared.dataTask with non-literal URL
                if text.contains("dataTask") && text.contains("url") {
                    // If the URL is from a variable (not inline literal)
                    let line = node.start_position().row;
                    if !text.contains("\"http") && reported_lines.insert(line) {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "URLSession.dataTask called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
                            node,
                            src,
                        ));
                    }
                }
            }
        });
        findings
    }
}
