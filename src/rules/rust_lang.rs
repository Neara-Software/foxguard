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

// ─── Rule 1: unsafe-block ─────────────────────────────────────────────────────

pub struct UnsafeBlock;

impl Rule for UnsafeBlock {
    fn id(&self) -> &str {
        "rs/unsafe-block"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-676")
    }
    fn description(&self) -> &str {
        "Use of unsafe block bypasses Rust memory safety guarantees"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "unsafe_block" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "unsafe block bypasses Rust memory safety — ensure correctness is manually verified",
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

// ─── Rule 2: transmute-usage ──────────────────────────────────────────────────

pub struct TransmuteUsage;

impl Rule for TransmuteUsage {
    fn id(&self) -> &str {
        "rs/transmute-usage"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-843")
    }
    fn description(&self) -> &str {
        "Use of std::mem::transmute can cause type confusion and undefined behavior"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.contains("transmute") {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "std::mem::transmute can cause type confusion and undefined behavior — prefer safe casts",
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

// ─── Rule 3: no-command-injection ─────────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "rs/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via Command::new with dynamic input"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.contains("Command::new") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() != "string_literal" {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "Command::new called with dynamic argument — risk of command injection",
                                        node,
                                        src,
                                    ));
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

// ─── Rule 4: no-sql-injection ─────────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "rs/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via format! macro in query argument"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_methods = Regex::new(r"(?i)\b(query|sql_query|execute|raw_sql)\b").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if sql_methods.is_match(func_text) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            // Check if any argument is a format! macro invocation
                            let mut arg_cursor = args.walk();
                            for arg in args.children(&mut arg_cursor) {
                                if arg.kind() == "macro_invocation" {
                                    let macro_text = &src[arg.byte_range()];
                                    if macro_text.starts_with("format!") {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
                                            "SQL query built with format! macro — use parameterized queries",
                                            node,
                                            src,
                                        ));
                                    }
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

// ─── Rule 5: no-weak-hash ────────────────────────────────────────────────────

pub struct NoWeakHash;

impl Rule for NoWeakHash {
    fn id(&self) -> &str {
        "rs/no-weak-hash"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-328")
    }
    fn description(&self) -> &str {
        "Use of weak cryptographic hash (MD5/SHA1)"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let weak_hash = Regex::new(r"\b(md5|sha1|Md5|Sha1|MD5|SHA1)\b").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect use declarations: use md5::..., use sha1::...
            if node.kind() == "use_declaration" {
                let text = &src[node.byte_range()];
                if weak_hash.is_match(text) {
                    let algo = if text.contains("md5") || text.contains("Md5") || text.contains("MD5") {
                        "MD5"
                    } else {
                        "SHA1"
                    };
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        &format!(
                            "Import of weak hash algorithm {} — use SHA-256 or stronger",
                            algo
                        ),
                        node,
                        src,
                    ));
                }
            }

            // Detect function calls: Md5::new(), Sha1::new(), md5::compute(), etc.
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if weak_hash.is_match(func_text) {
                        let algo = if func_text.contains("md5") || func_text.contains("Md5") || func_text.contains("MD5") {
                            "MD5"
                        } else {
                            "SHA1"
                        };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{} is cryptographically weak — use SHA-256 or stronger",
                                algo
                            ),
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

// ─── Rule 6: no-hardcoded-secret ──────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "rs/no-hardcoded-secret"
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
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // let password = "hardcoded";
            if node.kind() == "let_declaration" {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    let name = &src[pattern.byte_range()];
                    if secret_pattern.is_match(name) {
                        if let Some(value) = node.child_by_field_name("value") {
                            if value.kind() == "string_literal" {
                                let val = &src[value.byte_range()];
                                let inner = val.trim_matches('"');
                                if inner.len() >= 4 {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables",
                                            name.trim()
                                        ),
                                        node,
                                        src,
                                    ));
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

// ─── Rule 7: tls-verify-disabled ──────────────────────────────────────────────

pub struct TlsVerifyDisabled;

impl Rule for TlsVerifyDisabled {
    fn id(&self) -> &str {
        "rs/tls-verify-disabled"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-295")
    }
    fn description(&self) -> &str {
        "TLS certificate verification disabled with danger_accept_invalid_certs"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.contains("danger_accept_invalid_certs") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let arg_text = &src[first_arg.byte_range()];
                                if arg_text == "true" {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "danger_accept_invalid_certs(true) disables TLS verification — prefer proper CA validation",
                                        node,
                                        src,
                                    ));
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

// ─── Rule 8: no-ssrf ─────────────────────────────────────────────────────────

pub struct NoSsrf;

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "rs/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via reqwest with dynamic URL"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    // reqwest::get(url) or .get(url) style
                    if func_text == "reqwest::get"
                        || func_text.ends_with(".get")
                        || func_text.ends_with(".post")
                    {
                        // Only flag reqwest-related calls
                        if func_text.contains("reqwest") || src.contains("reqwest") {
                            if let Some(args) = node.child_by_field_name("arguments") {
                                if let Some(first_arg) = args.named_child(0) {
                                    if first_arg.kind() != "string_literal" {
                                        findings.push(make_finding(
                                            self.id(),
                                            self.severity(),
                                            self.cwe(),
                                            &format!(
                                                "{} called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
                                                func_text
                                            ),
                                            node,
                                            src,
                                        ));
                                    }
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

// ─── Rule 9: no-path-traversal ────────────────────────────────────────────────

pub struct NoPathTraversal;

impl Rule for NoPathTraversal {
    fn id(&self) -> &str {
        "rs/no-path-traversal"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-22")
    }
    fn description(&self) -> &str {
        "Potential path traversal via Path::new or PathBuf::from with dynamic input"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.contains("Path::new") || func_text.contains("PathBuf::from") {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                if first_arg.kind() != "string_literal" {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "{} called with dynamic path — validate input to prevent path traversal",
                                            func_text
                                        ),
                                        node,
                                        src,
                                    ));
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

// ─── Rule 10: no-unwrap-in-lib ────────────────────────────────────────────────

pub struct NoUnwrapInLib;

impl Rule for NoUnwrapInLib {
    fn id(&self) -> &str {
        "rs/no-unwrap-in-lib"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-248")
    }
    fn description(&self) -> &str {
        "Use of .unwrap() or .expect() can cause panics in production"
    }
    fn language(&self) -> Language {
        Language::Rust
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text.ends_with(".unwrap") || func_text.ends_with(".expect") {
                        let method = if func_text.ends_with(".unwrap") {
                            ".unwrap()"
                        } else {
                            ".expect()"
                        };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{} can panic at runtime — use proper error handling with ? or match",
                                method
                            ),
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
