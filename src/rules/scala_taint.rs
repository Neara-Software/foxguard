//! Intraprocedural, flow-insensitive taint analysis for Scala.
//!
//! # Scope
//!
//! Mirrors the other language engines (`ruby_taint`, `php_taint`):
//!
//! - **Per function.** Each `function_definition` body is analyzed
//!   independently; taint does not cross function boundaries.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order.
//!
//! # Scala grammar node kinds used here (tree-sitter-scala)
//!
//! - `function_definition` — fields: `name`, `parameters` (`parameters` →
//!   `parameter` with a `name` field), `body` (the expression after `=`,
//!   often a `call_expression` like `Action { ... }`).
//! - `val_definition` / `var_definition` — fields: `pattern` (the bound name),
//!   `value` (the initializer expression).
//! - `assignment_expression` — `x += y` / `x = y`: fields `left`, `right`.
//! - `infix_expression` — fields `left`, `operator` (`operator_identifier`),
//!   `right` (e.g. `"SELECT ..." + name`).
//! - `interpolated_string_expression` — `s"...$x..."`: `interpolator`
//!   identifier + `interpolated_string` with `interpolation` children.
//! - `call_expression` — fields `function` (`identifier` or `field_expression`)
//!   and `arguments`.
//! - `field_expression` — fields `value` (receiver) and `field`.
//!
//! # Matcher interpretation
//!
//! The Semgrep bridge compiles the Scala rules to:
//!
//! - A **source** [`NodeMatcher::ParamName`] whose name is a Semgrep
//!   metavariable (begins with `$`, e.g. `$REQ`, `$PARAM`). The engine seeds
//!   **every** parameter of the enclosing function as tainted.
//! - **Sink** [`NodeMatcher::BinopFormat`] for the SQL string-building
//!   patterns (`"$SQL" + ...`), matched against an `infix_expression` whose
//!   operator is `+`/`+=` with a string-literal operand and a tainted operand,
//!   or an `interpolated_string_expression` with a tainted interpolation.
//! - **Sink** [`NodeMatcher::MethodName`] (`eval`, `append`, `overrideSql`,
//!   `execute`) matched against a call whose method name equals it with a
//!   tainted argument or receiver.
//! - **Sink** [`NodeMatcher::Call`] (`Html.apply`, `Ok`) matched against a call
//!   whose callee equals it with a tainted argument.

use crate::rules::common::AliasTable;
use crate::rules::taint_engine::{node_text, taint_finding_for_node, TaintState};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Run the Scala taint engine over every `function_definition` inside `root`,
/// returning one [`TaintFinding`] per source→sink flow.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func| {
        let mut state = TaintState::default();
        seed_params(func, source, spec, &mut state);
        if let Some(body) = func.child_by_field_name("body") {
            walk(body, source, spec, &mut state, &mut findings);
        }
    });
    findings
}

// ─── Seeding ────────────────────────────────────────────────────────────────

/// Seed taint from function parameters. A metavariable `ParamName` source
/// (name beginning with `$`) seeds every parameter; a concrete list seeds only
/// matching names.
fn seed_params(func: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let seed_all = spec.sources.iter().any(|m| {
        matches!(m, NodeMatcher::ParamName { names, .. } if names.iter().any(|n| n.starts_with('$')))
    });

    let Some(params) = func.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let pname = node_text(name_node, source);
        let line = name_node.start_position().row + 1;

        if seed_all {
            state.taint(
                pname.to_string(),
                "untrusted request parameter".to_string(),
                line,
            );
            continue;
        }
        for matcher in &spec.sources {
            if let NodeMatcher::ParamName { names, description } = matcher {
                if names.iter().any(|n| n == pname) {
                    state.taint(pname.to_string(), description.clone(), line);
                    break;
                }
            }
        }
    }
}

// ─── Walk ───────────────────────────────────────────────────────────────────

fn walk(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    // Skip nested function definitions — analyzed as their own scope.
    if node.kind() == "function_definition" {
        return;
    }

    match node.kind() {
        "val_definition" | "var_definition" => handle_val_def(node, source, spec, state),
        "assignment_expression" => handle_assignment(node, source, spec, state),
        "call_expression" => handle_call(node, source, spec, state, findings),
        "infix_expression" | "interpolated_string_expression" => {
            handle_binop_format(node, source, spec, state, findings)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, spec, state, findings);
    }
}

/// `val x = <expr>` / `var x = <expr>`.
fn handle_val_def(node: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let (Some(pattern), Some(value)) = (
        node.child_by_field_name("pattern"),
        node.child_by_field_name("value"),
    ) else {
        return;
    };
    if pattern.kind() != "identifier" {
        return;
    }
    let lhs = node_text(pattern, source).to_string();
    if let Some((desc, line)) = expression_taint(value, source, spec, state) {
        state.taint(lhs, desc, line);
    } else {
        state.clear(&lhs);
    }
}

/// `x = expr` / `x += expr`.
fn handle_assignment(node: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let lhs = node_text(left, source).to_string();
    // `+=` accumulates taint; `=` replaces.
    if let Some((desc, line)) = expression_taint(right, source, spec, state) {
        state.taint(lhs, desc, line);
    } else if state.info(&lhs).is_none() {
        state.clear(&lhs);
    }
}

/// A `call_expression`: `MethodName` and `Call` sinks fire when an argument or
/// receiver is tainted.
fn handle_call(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let callee = resolve_callee(node, source);
    let final_segment = callee.rsplit('.').next().unwrap_or(&callee);

    let sink_desc = spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if canonical == &callee => Some(description.clone()),
        NodeMatcher::MethodName {
            method,
            description,
        } if method == final_segment => Some(description.clone()),
        _ => None,
    });

    let Some(sink_desc) = sink_desc else {
        return;
    };

    // Tainted argument?
    if let Some((src_desc, src_line)) = first_tainted_arg(node, source, spec, state) {
        findings.push(taint_finding_for_node(
            node, src_desc, sink_desc, src_line, None, 1,
        ));
        return;
    }
    // Tainted receiver? (e.g. `taintedBuilder.append(...)`)
    if let Some(func) = node.child_by_field_name("function") {
        if func.kind() == "field_expression" {
            if let Some(recv) = func.child_by_field_name("value") {
                if let Some((src_desc, src_line)) = expression_taint(recv, source, spec, state) {
                    findings.push(taint_finding_for_node(
                        node, src_desc, sink_desc, src_line, None, 1,
                    ));
                }
            }
        }
    }
}

/// String-building sink: an `infix_expression` (`"SELECT ..." + name`) or an
/// `interpolated_string_expression` (`s"...$name..."`) carrying tainted data.
fn handle_binop_format(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let has_binop_sink = spec
        .sinks
        .iter()
        .any(|m| matches!(m, NodeMatcher::BinopFormat { .. }));
    if !has_binop_sink {
        return;
    }
    let desc = spec
        .sinks
        .iter()
        .find_map(|m| match m {
            NodeMatcher::BinopFormat { description } => Some(description.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "string-building sink".to_string());

    match node.kind() {
        "infix_expression" => {
            // Require a string-literal operand AND a tainted operand — avoids
            // firing on plain numeric or variable-only expressions.
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let has_string = [left, right]
                .iter()
                .flatten()
                .any(|n| n.kind() == "string" || n.kind() == "interpolated_string_expression");
            if !has_string {
                return;
            }
            for operand in [left, right].into_iter().flatten() {
                if let Some((src_desc, src_line)) = expression_taint(operand, source, spec, state) {
                    findings.push(taint_finding_for_node(
                        node, src_desc, desc, src_line, None, 1,
                    ));
                    return;
                }
            }
        }
        "interpolated_string_expression" => {
            if let Some((src_desc, src_line)) = interpolation_taint(node, source, spec, state) {
                findings.push(taint_finding_for_node(
                    node, src_desc, desc, src_line, None, 1,
                ));
            }
        }
        _ => {}
    }
}

/// First tainted argument of a `call_expression`.
fn first_tainted_arg(
    call: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        if let Some(r) = expression_taint(arg, source, spec, state) {
            return Some(r);
        }
    }
    None
}

// ─── Taint evaluation ──────────────────────────────────────────────────────

fn expression_taint(
    expr: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    match expr.kind() {
        "identifier" => {
            let name = node_text(expr, source);
            state
                .info(name)
                .map(|info| (info.description.clone(), info.line))
        }
        "infix_expression" => {
            if let Some(left) = expr.child_by_field_name("left") {
                if let Some(r) = expression_taint(left, source, spec, state) {
                    return Some(r);
                }
            }
            if let Some(right) = expr.child_by_field_name("right") {
                if let Some(r) = expression_taint(right, source, spec, state) {
                    return Some(r);
                }
            }
            None
        }
        "interpolated_string_expression" => interpolation_taint(expr, source, spec, state),
        "field_expression" => expr
            .child_by_field_name("value")
            .and_then(|v| expression_taint(v, source, spec, state)),
        "call_expression" => {
            if call_is_sanitizer(expr, source, spec) {
                return None;
            }
            if let Some(r) = first_tainted_arg(expr, source, spec, state) {
                return Some(r);
            }
            if let Some(func) = expr.child_by_field_name("function") {
                if func.kind() == "field_expression" {
                    if let Some(recv) = func.child_by_field_name("value") {
                        return expression_taint(recv, source, spec, state);
                    }
                }
            }
            None
        }
        _ => {
            // Descend into wrapper nodes (parenthesized, etc.).
            let mut cursor = expr.walk();
            for child in expr.named_children(&mut cursor) {
                if let Some(r) = expression_taint(child, source, spec, state) {
                    return Some(r);
                }
            }
            None
        }
    }
}

/// Taint inside an `interpolated_string_expression`'s `interpolation` children.
fn interpolation_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "interpolated_string" {
            let mut inner = child.walk();
            for piece in child.named_children(&mut inner) {
                if piece.kind() == "interpolation" {
                    let mut ic = piece.walk();
                    for e in piece.named_children(&mut ic) {
                        if let Some(r) = expression_taint(e, source, spec, state) {
                            return Some(r);
                        }
                    }
                }
            }
        }
    }
    None
}

fn call_is_sanitizer(call: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    let callee = resolve_callee(call, source);
    let final_segment = callee.rsplit('.').next().unwrap_or(&callee);
    spec.sanitizers.iter().any(|m| match m {
        NodeMatcher::Call { canonical, .. } => canonical == &callee,
        NodeMatcher::MethodName { method, .. } => method == final_segment,
        _ => false,
    })
}

// ─── AST helpers ────────────────────────────────────────────────────────────

/// Resolve the callee of a `call_expression` to a dotted string.
/// `db.execute(q)` → `db.execute`; `Action(...)` → `Action`;
/// `Html.apply(...)` → `Html.apply`.
fn resolve_callee(call: Node<'_>, source: &str) -> String {
    let Some(func) = call.child_by_field_name("function") else {
        return String::new();
    };
    match func.kind() {
        "identifier" => node_text(func, source).to_string(),
        "field_expression" => {
            let recv = func
                .child_by_field_name("value")
                .map(|n| node_text(n, source))
                .unwrap_or("");
            let field = func
                .child_by_field_name("field")
                .map(|n| node_text(n, source))
                .unwrap_or("");
            format!("{}.{}", recv, field)
        }
        _ => node_text(func, source).to_string(),
    }
}

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

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Scala).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn param_source() -> NodeMatcher {
        NodeMatcher::ParamName {
            names: vec!["$PARAM".into()],
            description: "untrusted request parameter".into(),
        }
    }

    fn sql_spec() -> TaintSpec {
        TaintSpec {
            sources: vec![param_source()],
            sinks: vec![NodeMatcher::BinopFormat {
                description: "SQL string concatenation".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn eval_spec() -> TaintSpec {
        TaintSpec {
            sources: vec![param_source()],
            sinks: vec![NodeMatcher::MethodName {
                method: "eval".into(),
                description: "eval()".into(),
            }],
            sanitizers: vec![],
        }
    }

    #[test]
    fn sql_concat_of_param_fires() {
        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = "SELECT * FROM t WHERE n = " + name
    db.run(q)
  }
}
"#;
        let f = run(src, &sql_spec());
        assert_eq!(f.len(), 1, "SQL concat of param must fire, got {:?}", f);
    }

    #[test]
    fn interpolated_sql_of_param_fires() {
        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = s"SELECT $name"
    db.run(q)
  }
}
"#;
        let f = run(src, &sql_spec());
        assert_eq!(f.len(), 1, "interpolated SQL must fire, got {:?}", f);
    }

    #[test]
    fn eval_of_param_fires() {
        let src = r#"
object Ctrl {
  def index(name: String) = {
    js.eval(name)
  }
}
"#;
        let f = run(src, &eval_spec());
        assert_eq!(f.len(), 1, "eval of param must fire, got {:?}", f);
    }

    #[test]
    fn literal_only_concat_no_finding() {
        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = "SELECT * FROM t WHERE n = " + "admin"
    db.run(q)
  }
}
"#;
        let f = run(src, &sql_spec());
        assert_eq!(f.len(), 0, "literal-only concat must not fire, got {:?}", f);
    }

    #[test]
    fn eval_of_literal_no_finding() {
        let src = r#"
object Ctrl {
  def index(name: String) = {
    js.eval("safe")
  }
}
"#;
        let f = run(src, &eval_spec());
        assert_eq!(f.len(), 0, "eval of literal must not fire");
    }
}
