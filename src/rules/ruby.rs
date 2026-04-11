use crate::rules::common::{make_finding, walk_tree};
use crate::rules::Rule;
use crate::{Finding, Language, Severity};
use regex::Regex;

// ─── Rule 1: no-eval ──────────────────────────────────────────────────────────

pub struct NoEval;

impl Rule for NoEval {
    fn id(&self) -> &str {
        "rb/no-eval"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-95")
    }
    fn description(&self) -> &str {
        "Use of eval or similar dynamic code execution"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                // Only flag eval and instance_eval — class_eval/module_eval are
                // standard Ruby metaprogramming patterns used by every framework
                if name == "eval" || name == "instance_eval" {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        &format!(
                            "{} executes arbitrary code — avoid dynamic evaluation",
                            name
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

// ─── Rule 2: no-command-injection ─────────────────────────────────────────────

pub struct NoCommandInjection;

impl Rule for NoCommandInjection {
    fn id(&self) -> &str {
        "rb/no-command-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-78")
    }
    fn description(&self) -> &str {
        "Potential command injection via system/exec/spawn or backtick execution"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect backtick/subshell execution
            if node.kind() == "subshell" {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "Backtick/subshell command execution — risk of command injection",
                    node,
                    src,
                ));
                return;
            }

            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                if name == "system" || name == "exec" || name == "spawn" {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        &format!(
                            "{} called — risk of command injection with dynamic arguments",
                            name
                        ),
                        node,
                        src,
                    ));
                }
            }

            // Detect %x strings (parsed as subshell or string node with %x prefix)
            if node.kind() == "string" {
                let text = &src[node.byte_range()];
                if text.starts_with("%x") {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "%x command execution — risk of command injection",
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 3: no-sql-injection ─────────────────────────────────────────────────

pub struct NoSqlInjection;

impl Rule for NoSqlInjection {
    fn id(&self) -> &str {
        "rb/no-sql-injection"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-89")
    }
    fn description(&self) -> &str {
        "Potential SQL injection via string interpolation in query methods"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                if name == "where" || name == "find_by_sql" || name == "execute" {
                    // Check if any argument contains string interpolation
                    let node_text = &src[node.byte_range()];
                    if node_text.contains("#{") {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "String interpolation in {} — use parameterized queries to prevent SQL injection",
                                name
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

// ─── Rule 4: no-mass-assignment ───────────────────────────────────────────────

pub struct NoMassAssignment;

impl Rule for NoMassAssignment {
    fn id(&self) -> &str {
        "rb/no-mass-assignment"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-915")
    }
    fn description(&self) -> &str {
        "Mass assignment via permit! allows all parameters"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let Some(method) = node.child_by_field_name("method") {
                    let name = &src[method.byte_range()];
                    if name == "permit!" {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "permit! allows all parameters — use permit(:field1, :field2) to whitelist",
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

// ─── Rule 5: no-unsafe-deserialization ────────────────────────────────────────

pub struct NoUnsafeDeserialization;

impl Rule for NoUnsafeDeserialization {
    fn id(&self) -> &str {
        "rb/no-unsafe-deserialization"
    }
    fn severity(&self) -> Severity {
        Severity::Critical
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-502")
    }
    fn description(&self) -> &str {
        "Unsafe deserialization via Marshal.load or YAML.load"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            if node.kind() == "call" {
                if let (Some(receiver), Some(method)) = (
                    node.child_by_field_name("receiver"),
                    node.child_by_field_name("method"),
                ) {
                    let recv = &src[receiver.byte_range()];
                    let meth = &src[method.byte_range()];

                    if (recv == "Marshal" && meth == "load")
                        || (recv == "YAML" && (meth == "load" || meth == "unsafe_load"))
                    {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            &format!(
                                "{}.{} can execute arbitrary code — use YAML.safe_load or safer alternatives",
                                recv, meth
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

// ─── Rule 6: no-open-redirect ─────────────────────────────────────────────────

pub struct NoOpenRedirect;

impl Rule for NoOpenRedirect {
    fn id(&self) -> &str {
        "rb/no-open-redirect"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-601")
    }
    fn description(&self) -> &str {
        "Potential open redirect via redirect_to with dynamic argument"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let is_redirect = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()] == "redirect_to")
                    .unwrap_or(false),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()] == "redirect_to")
                    .unwrap_or(false),
                _ => false,
            };

            if is_redirect {
                // Check if the argument is a string literal (safe) or dynamic (unsafe)
                let node_text = &src[node.byte_range()];
                // If it contains variable interpolation or is not a simple string, flag it
                let has_literal_only = node_text.contains("redirect_to \"")
                    || node_text.contains("redirect_to '")
                    || node_text.contains("redirect_to(\"")
                    || node_text.contains("redirect_to('");

                if !has_literal_only {
                    findings.push(make_finding(
                        self.id(),
                        self.severity(),
                        self.cwe(),
                        "redirect_to with dynamic argument — validate URL to prevent open redirect",
                        node,
                        src,
                    ));
                }
            }
        });
        findings
    }
}

// ─── Rule 7: no-csrf-skip ────────────────────────────────────────────────────

pub struct NoCsrfSkip;

impl Rule for NoCsrfSkip {
    fn id(&self) -> &str {
        "rb/no-csrf-skip"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-352")
    }
    fn description(&self) -> &str {
        "CSRF protection disabled via skip_before_action"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            let method_name = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()]),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()]),
                _ => None,
            };

            if let Some(name) = method_name {
                if name == "skip_before_action" {
                    let text = &src[node.byte_range()];
                    if text.contains("verify_authenticity_token") {
                        findings.push(make_finding(
                            self.id(),
                            self.severity(),
                            self.cwe(),
                            "skip_before_action :verify_authenticity_token disables CSRF protection",
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

// ─── Rule 8: no-html-safe ─────────────────────────────────────────────────────

pub struct NoHtmlSafe;

impl Rule for NoHtmlSafe {
    fn id(&self) -> &str {
        "rb/no-html-safe"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cwe(&self) -> Option<&str> {
        Some("CWE-79")
    }
    fn description(&self) -> &str {
        "Potential XSS via html_safe or raw()"
    }
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect .html_safe on non-literal receivers
            if node.kind() == "call" {
                if let Some(method) = node.child_by_field_name("method") {
                    let name = &src[method.byte_range()];
                    if name == "html_safe" {
                        if let Some(receiver) = node.child_by_field_name("receiver") {
                            // Only flag non-string-literal receivers
                            if receiver.kind() != "string" {
                                findings.push(make_finding(
                                    self.id(),
                                    self.severity(),
                                    self.cwe(),
                                    ".html_safe on dynamic content — risk of XSS",
                                    node,
                                    src,
                                ));
                            }
                        }
                    }
                }
            }

            // Detect raw() calls
            let is_raw = match node.kind() {
                "call" => node
                    .child_by_field_name("method")
                    .map(|m| &src[m.byte_range()] == "raw")
                    .unwrap_or(false),
                "command" => node
                    .child_by_field_name("name")
                    .map(|m| &src[m.byte_range()] == "raw")
                    .unwrap_or(false),
                _ => false,
            };

            if is_raw {
                findings.push(make_finding(
                    self.id(),
                    self.severity(),
                    self.cwe(),
                    "raw() bypasses HTML escaping — risk of XSS",
                    node,
                    src,
                ));
            }
        });
        findings
    }
}

// ─── Rule 9: no-hardcoded-secret ──────────────────────────────────────────────

pub struct NoHardcodedSecret;

impl Rule for NoHardcodedSecret {
    fn id(&self) -> &str {
        "rb/no-hardcoded-secret"
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
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();
        let secret_pattern =
            Regex::new(r"(?i)(password|secret|api_?key|token|auth|credential|private_?key)")
                .unwrap();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // assignment: variable = "hardcoded"
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let left_text = &src[left.byte_range()];
                    if secret_pattern.is_match(left_text) && right.kind() == "string" {
                        let val = &src[right.byte_range()];
                        // Strip quotes and check length
                        let inner = val
                            .trim_start_matches(['"', '\''])
                            .trim_end_matches(['"', '\'']);
                        if inner.len() >= 4 {
                            findings.push(make_finding(
                                self.id(),
                                self.severity(),
                                self.cwe(),
                                &format!(
                                    "Hardcoded secret in '{}' — use environment variables",
                                    left_text.trim()
                                ),
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

// ─── Rule 10: no-weak-crypto ──────────────────────────────────────────────────

pub struct NoWeakCrypto;

impl Rule for NoWeakCrypto {
    fn id(&self) -> &str {
        "rb/no-weak-crypto"
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
        Language::Ruby
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        let mut findings = Vec::new();

        walk_tree(tree.root_node(), source, &mut |node, src| {
            // Detect Digest::MD5, Digest::SHA1 via scope_resolution nodes
            if node.kind() == "scope_resolution" {
                let text = &src[node.byte_range()];
                if text == "Digest::MD5" || text == "Digest::SHA1" {
                    let algo = if text.contains("MD5") { "MD5" } else { "SHA1" };
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
        });
        findings
    }
}
