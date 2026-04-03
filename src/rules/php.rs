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

// ─── Rule 1: no-eval ──────────────────────────────────────────────────────────

pub struct NoEval;

impl Rule for NoEval {
    fn id(&self) -> &str {
        "php/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Use of eval() allows arbitrary code execution"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "eval" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "eval() allows arbitrary code execution — avoid dynamic code evaluation",
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

// ─── Rule 2: no-command-injection ─────────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "php/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via shell execution function"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect dangerous shell functions
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if matches!(
                        func_text,
                        "exec" | "system" | "passthru" | "shell_exec" | "popen" | "proc_open"
                    ) {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}() executes shell commands — risk of command injection",
                                func_text
                            ),
                            node,
                            src,
                        ));
                    }
                }
            }

            // Detect backtick execution
            if node.kind() == "shell_command_expression" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Backtick operator executes shell commands — risk of command injection",
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

// ─── Rule 3: no-sql-injection ─────────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "php/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string interpolation or concatenation"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sql_funcs = ["mysqli_query", "pg_query", "mysql_query"];

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: mysqli_query($conn, "SELECT ... $var ...")
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if sql_funcs.contains(&func_text) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let arg_text = &src[args.byte_range()];
                            if Self::has_interpolation_or_concat(args) {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    &format!(
                                        "{}() with dynamic query — use parameterized queries",
                                        func_text
                                    ),
                                    node,
                                    src,
                                ));
                            } else if arg_text.contains('$') || arg_text.contains('.') {
                                // Rough heuristic for interpolated or concatenated strings
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    &format!(
                                        "{}() with dynamic query — use parameterized queries",
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

            // Detect: $stmt->query("SELECT ... $var ...")
            if node.kind() == "member_call_expression" {
                if let Some(name) = node.child_by_field_name("name") {
                    let name_text = &src[name.byte_range()];
                    if name_text == "query" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if Self::has_interpolation_or_concat(args) {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    "->query() with dynamic query — use parameterized queries",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }
        });
        findings
    }
}

impl NoSqlInjection {
    fn has_interpolation_or_concat(args_node: tree_sitter::Node) -> bool {
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if child.kind() == "encapsed_string" {
                return true;
            }
            if child.kind() == "binary_expression" {
                // Check for string concatenation with .
                let mut inner = child.walk();
                for c in child.children(&mut inner) {
                    if c.kind() == "." {
                        return true;
                    }
                }
            }
            // Recurse into nested nodes
            if Self::has_interpolation_or_concat(child) {
                return true;
            }
        }
        false
    }
}

// ─── Rule 4: no-unserialize ──────────────────────────────────────────────────

pub struct NoUnserialize;

impl Rule for NoUnserialize {
    fn id(&self) -> &str {
        "php/no-unserialize"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Use of unserialize() on untrusted data can lead to object injection"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "unserialize" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "unserialize() on untrusted data can lead to object injection — use json_decode instead",
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

// ─── Rule 5: no-file-inclusion ───────────────────────────────────────────────

pub struct NoFileInclusion;

impl Rule for NoFileInclusion {
    fn id(&self) -> &str {
        "php/no-file-inclusion"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-98")
    }
    fn description(&self) -> &str {
        "Dynamic file inclusion with variable argument enables remote/local file inclusion"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if matches!(
                node.kind(),
                "include_expression"
                    | "include_once_expression"
                    | "require_expression"
                    | "require_once_expression"
            ) {
                // Check if the argument is non-literal (contains a variable)
                let text = &src[node.byte_range()];
                let has_variable = Self::has_variable_child(node);
                if has_variable || text.contains('$') {
                    let keyword = node.kind().replace("_expression", "").replace('_', " ");
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        &format!(
                            "{} with variable argument — risk of file inclusion attack",
                            keyword
                        ),
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

impl NoFileInclusion {
    fn has_variable_child(node: tree_sitter::Node) -> bool {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "variable_name" {
                return true;
            }
            if child.kind() == "encapsed_string" {
                return true;
            }
            if Self::has_variable_child(child) {
                return true;
            }
        }
        false
    }
}

// ─── Rule 6: no-weak-crypto ─────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "php/no-weak-crypto"
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
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "md5" || func_text == "sha1" {
                        let algo = if func_text == "md5" { "MD5" } else { "SHA1" };
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}() is cryptographically weak — use hash('sha256', ...) or stronger",
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

// ─── Rule 7: no-hardcoded-secret ────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "php/no-hardcoded-secret"
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
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern = Regex::new(r"(?i)(password|secret|api_?key|token)").unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect: $password = "hardcoded";
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    let left_text = &src[left.byte_range()];
                    if left_text.starts_with('$') && secret_pattern.is_match(left_text) {
                        if let Some(right) = node.child_by_field_name("right") {
                            if right.kind() == "string"
                                || right.kind() == "encapsed_string"
                                || right.kind() == "string_value"
                            {
                                let val = &src[right.byte_range()];
                                let inner = val.trim_matches(|c| c == '"' || c == '\'');
                                if inner.len() >= 4 {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "Hardcoded secret in '{}' — use environment variables",
                                            left_text
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

// ─── Rule 8: no-ssrf ────────────────────────────────────────────────────────

pub struct NoSsrf;

impl Rule for NoSsrf {
    fn id(&self) -> &str {
        "php/no-ssrf"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-918")
    }
    fn description(&self) -> &str {
        "Potential SSRF via file_get_contents or curl_init with variable URL"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "file_get_contents" || func_text == "curl_init" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                // Flag if the argument is not a string literal
                                if first_arg.kind() != "string" {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        &format!(
                                            "{}() called with dynamic URL — validate and allowlist target hosts to prevent SSRF",
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

// ─── Rule 9: no-extract ─────────────────────────────────────────────────────

pub struct NoExtract;

impl Rule for NoExtract {
    fn id(&self) -> &str {
        "php/no-extract"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-621")
    }
    fn description(&self) -> &str {
        "Use of extract() can overwrite existing variables"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "extract" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "extract() imports variables into the current scope — risk of variable overwrite",
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

// ─── Rule 10: no-preg-eval ──────────────────────────────────────────────────

pub struct NoPregEval;

impl Rule for NoPregEval {
    fn id(&self) -> &str {
        "php/no-preg-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "preg_replace with /e modifier allows arbitrary code execution"
    }
    fn language(&self) -> Language {
        Language::Php
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let e_modifier = Regex::new(r#"['"][^'"]*/.*/[a-z]*e[a-z]*['"]"#).unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "function_call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let func_text = &src[func.byte_range()];
                    if func_text == "preg_replace" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(first_arg) = args.named_child(0) {
                                let arg_text = &src[first_arg.byte_range()];
                                if e_modifier.is_match(arg_text) {
                                    findings.push(make_finding(
                                        self.id(),
                                        self.severity(),
                                        self.cwe(),
                                        "preg_replace() with /e modifier executes code — use preg_replace_callback instead",
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
