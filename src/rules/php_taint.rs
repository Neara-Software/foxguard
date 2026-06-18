//! Intraprocedural, flow-insensitive taint analysis for PHP.
//!
//! # Scope
//!
//! Mirrors `ruby_taint` in structure:
//!
//! - **Per function.** Each `function_definition` / `method_declaration` body
//!   is analyzed independently; taint does not cross function boundaries.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order. Taint
//!   observed in one branch of an `if` is treated as taint in the fall-through.
//! - **No container sensitivity.** `$_GET['key']` is tainted when `$_GET` is
//!   tainted; individual keys are not tracked separately.
//!
//! # PHP grammar notes (tree-sitter-php v0.24)
//!
//! Key node kinds and their field layout (confirmed by AST probe):
//!
//! - `program` — file root.
//! - `function_definition` — fields: `name` (function name string), `parameters`
//!   (`formal_parameters`), `body` (`compound_statement`).
//! - `method_declaration` — same field layout as `function_definition`.
//! - `assignment_expression` — fields: `left` (LHS expr), `right` (RHS expr).
//! - `variable_name` — a PHP variable (`$foo`); `node_text` returns the full
//!   text including `$` (e.g. `"$_GET"`, `"$cmd"`).
//! - `subscript_expression` — `$arr[$key]`; no named fields; first named_child
//!   is the array expression, second is the key.
//! - `function_call_expression` — fields: `function` (callee name/expr),
//!   `arguments` (argument list). NOTE: the field is `"function"` NOT `"name"`.
//! - `member_call_expression` — `$obj->method(args)`; fields: `object`
//!   (receiver `variable_name`), `name` (method name string), `arguments`.
//! - `echo_statement` — `echo $x;`; first named child is the expression.
//! - `encapsed_string` — double-quoted string with inline variable interpolation.
//!
//! # Critical lesson (the ParamName bridge bug)
//!
//! The Semgrep bridge compiles bare-identifier patterns like `$_GET` into
//! `GenericMatcher::ParamName`. Naively consuming `ParamName` only at
//! param-seeding time causes it to never fire in expression position via the
//! bridge (the CLI path). This implementation matches `ParamName` sources in
//! expression position too (bare `variable_name`, `subscript_expression`
//! receiver, etc.) — exactly as the Ruby engine does.

use crate::rules::common::AliasTable;
use crate::rules::taint_engine::{
    analyze_function_generic, attribution_hint_for_sink, match_call_sink, node_text,
    taint_finding_for_node, AnalysisContext, TaintLanguageAdapter, TaintState,
};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

type PhpCtx<'a> = AnalysisContext<'a, ()>;

/// Run the PHP taint engine over every function/method definition inside `root`
/// and return one [`TaintFinding`] per source→sink flow discovered.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let empty_summary = crate::rules::taint_engine::ReturnSummary::new();
    let ctx = AnalysisContext {
        source,
        spec,
        aliases: None,
        summaries: &empty_summary,
        cross_file: None,
        sink_to_rules: None,
    };
    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func_node| {
        analyze_function_generic::<PhpTaintAdapter, ()>(func_node, &ctx, &mut findings);
    });
    findings
}

/// Canonical set of untrusted-input sources for PHP.
pub fn php_taint_sources() -> Vec<NodeMatcher> {
    vec![
        // ─── HTTP superglobals ─────────────────────────────────────────────
        NodeMatcher::ParamName {
            names: vec![
                "$_GET".into(),
                "$_POST".into(),
                "$_REQUEST".into(),
                "$_COOKIE".into(),
                "$_SERVER".into(),
                "$_FILES".into(),
                "$_ENV".into(),
            ],
            description: "HTTP superglobal".into(),
        },
        // ─── Raw input ────────────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "file_get_contents".into(),
            description: "file_get_contents()".into(),
        },
        NodeMatcher::Call {
            canonical: "fread".into(),
            description: "fread()".into(),
        },
        NodeMatcher::Call {
            canonical: "stream_get_contents".into(),
            description: "stream_get_contents()".into(),
        },
    ]
}

/// Canonical set of dangerous sinks for PHP.
pub fn php_taint_sinks() -> Vec<NodeMatcher> {
    vec![
        // ─── OS command execution ─────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "system".into(),
            description: "system()".into(),
        },
        NodeMatcher::Call {
            canonical: "exec".into(),
            description: "exec()".into(),
        },
        NodeMatcher::Call {
            canonical: "shell_exec".into(),
            description: "shell_exec()".into(),
        },
        NodeMatcher::Call {
            canonical: "passthru".into(),
            description: "passthru()".into(),
        },
        NodeMatcher::Call {
            canonical: "popen".into(),
            description: "popen()".into(),
        },
        NodeMatcher::Call {
            canonical: "proc_open".into(),
            description: "proc_open()".into(),
        },
        // ─── Dynamic evaluation ───────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "eval".into(),
            description: "eval()".into(),
        },
        NodeMatcher::Call {
            canonical: "preg_replace".into(),
            description: "preg_replace()".into(),
        },
        // ─── File inclusion (LFI/RFI) ────────────────────────────────────
        NodeMatcher::Call {
            canonical: "include".into(),
            description: "include".into(),
        },
        NodeMatcher::Call {
            canonical: "require".into(),
            description: "require".into(),
        },
        NodeMatcher::Call {
            canonical: "include_once".into(),
            description: "include_once".into(),
        },
        NodeMatcher::Call {
            canonical: "require_once".into(),
            description: "require_once".into(),
        },
        // ─── SQL injection ────────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "mysqli_query".into(),
            description: "mysqli_query()".into(),
        },
        NodeMatcher::Call {
            canonical: "mysql_query".into(),
            description: "mysql_query()".into(),
        },
        NodeMatcher::MethodName {
            method: "query".into(),
            description: "->query()".into(),
        },
        NodeMatcher::MethodName {
            method: "exec".into(),
            description: "->exec()".into(),
        },
        NodeMatcher::MethodName {
            method: "prepare".into(),
            description: "->prepare()".into(),
        },
        // ─── XSS (output) ─────────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "echo".into(),
            description: "echo".into(),
        },
        NodeMatcher::Call {
            canonical: "print".into(),
            description: "print()".into(),
        },
        NodeMatcher::Call {
            canonical: "printf".into(),
            description: "printf()".into(),
        },
        NodeMatcher::Call {
            canonical: "die".into(),
            description: "die()".into(),
        },
        // ─── File write ──────────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "file_put_contents".into(),
            description: "file_put_contents()".into(),
        },
        NodeMatcher::Call {
            canonical: "fwrite".into(),
            description: "fwrite()".into(),
        },
    ]
}

/// Canonical set of sanitizers for PHP.
pub fn php_taint_sanitizers() -> Vec<NodeMatcher> {
    vec![
        // ─── Shell sanitizers ─────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "escapeshellarg".into(),
            description: "escapeshellarg()".into(),
        },
        NodeMatcher::Call {
            canonical: "escapeshellcmd".into(),
            description: "escapeshellcmd()".into(),
        },
        // ─── HTML sanitizers ──────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "htmlspecialchars".into(),
            description: "htmlspecialchars()".into(),
        },
        NodeMatcher::Call {
            canonical: "htmlentities".into(),
            description: "htmlentities()".into(),
        },
        NodeMatcher::Call {
            canonical: "strip_tags".into(),
            description: "strip_tags()".into(),
        },
        // ─── SQL sanitizers ───────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "mysqli_real_escape_string".into(),
            description: "mysqli_real_escape_string()".into(),
        },
        NodeMatcher::Call {
            canonical: "mysql_real_escape_string".into(),
            description: "mysql_real_escape_string()".into(),
        },
        NodeMatcher::MethodName {
            method: "quote".into(),
            description: "->quote()".into(),
        },
        // ─── Integer / type coercion ──────────────────────────────────────
        NodeMatcher::Call {
            canonical: "intval".into(),
            description: "intval()".into(),
        },
        NodeMatcher::Call {
            canonical: "floatval".into(),
            description: "floatval()".into(),
        },
        NodeMatcher::Call {
            canonical: "abs".into(),
            description: "abs()".into(),
        },
        // ─── Regex sanitizer ─────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "preg_quote".into(),
            description: "preg_quote()".into(),
        },
        // ─── Path sanitizer ───────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "basename".into(),
            description: "basename()".into(),
        },
        NodeMatcher::Call {
            canonical: "realpath".into(),
            description: "realpath()".into(),
        },
    ]
}

// ─── Language adapter ─────────────────────────────────────────────────────

struct PhpTaintAdapter;

impl TaintLanguageAdapter<()> for PhpTaintAdapter {
    fn is_nested_scope(kind: &str) -> bool {
        // Nested function/method defs create new scopes.
        matches!(
            kind,
            "function_definition" | "method_declaration" | "arrow_function"
        )
    }

    fn get_body(func_node: Node<'_>) -> Option<Node<'_>> {
        func_node.child_by_field_name("body")
    }

    fn seed_params(func_node: Node<'_>, ctx: &PhpCtx<'_>, state: &mut TaintState) {
        if let Some(params) = func_node.child_by_field_name("parameters") {
            seed_param_sources(params, ctx.source, ctx.spec, state);
        }
    }

    fn dispatch_walk_node(
        node: Node<'_>,
        ctx: &PhpCtx<'_>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
    ) {
        if node.kind() == "assignment_expression" {
            handle_assignment(node, ctx, state);
        }
        if node.kind() == "function_call_expression" {
            handle_function_call(node, ctx, state, findings);
        }
        if node.kind() == "member_call_expression" {
            handle_member_call(node, ctx, state, findings);
        }
        // echo is a statement in PHP grammar, not a function call node
        if node.kind() == "echo_statement" {
            handle_echo(node, ctx, state, findings);
        }
    }

    fn dispatch_summary_node(
        node: Node<'_>,
        ctx: &PhpCtx<'_>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
        return_taint: &mut Option<String>,
    ) {
        Self::dispatch_walk_node(node, ctx, state, findings);
        if node.kind() == "return_statement" && return_taint.is_none() {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if let Some((desc, _line)) = expression_taint(child, ctx, state) {
                    *return_taint = Some(desc);
                    break;
                }
            }
        }
    }

    fn expression_taint(
        expr: Node<'_>,
        ctx: &PhpCtx<'_>,
        state: &TaintState,
    ) -> Option<(String, usize)> {
        expression_taint(expr, ctx, state)
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

fn collect_function_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if matches!(node.kind(), "function_definition" | "method_declaration") {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_defs(child, visit);
    }
}

fn seed_param_sources(params: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        // PHP parameter nodes: `simple_parameter`, `variadic_parameter`, etc.
        // The variable is a `variable_name` child inside the parameter node.
        let var_node = if child.kind() == "variable_name" {
            Some(child)
        } else {
            // Look for variable_name inside the parameter node.
            let mut found = None;
            let mut inner = child.walk();
            for n in child.named_children(&mut inner) {
                if n.kind() == "variable_name" {
                    found = Some(n);
                    break;
                }
            }
            found
        };

        if let Some(v) = var_node {
            let name = node_text(v, source);
            for matcher in &spec.sources {
                if let NodeMatcher::ParamName { names, description } = matcher {
                    if names.iter().any(|n| n == name)
                        || crate::rules::taint_engine::param_names_are_wildcard(names)
                    {
                        let line = v.start_position().row + 1;
                        state.taint(name.to_string(), description.clone(), line);
                        break;
                    }
                }
            }
        }
    }
}

/// Get the callee name from a `function_call_expression` node.
///
/// In tree-sitter-php, the callee field is named `"function"` (not `"name"`).
fn function_call_callee<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.child_by_field_name("function")
        .map(|n| node_text(n, source))
        .unwrap_or("")
}

/// Handle an `assignment_expression` node: propagate taint from RHS to LHS.
///
/// In tree-sitter-php, `assignment_expression` has `left` and `right` fields.
fn handle_assignment(node: Node<'_>, ctx: &PhpCtx<'_>, state: &mut TaintState) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };

    // Only track simple `variable_name` on the LHS.
    if left.kind() != "variable_name" {
        return;
    }
    let lhs_name = node_text(left, ctx.source).to_string();
    if let Some((desc, src_line)) = expression_taint(right, ctx, state) {
        state.taint(lhs_name, desc, src_line);
    } else {
        state.clear(&lhs_name);
    }
}

/// Handle a `function_call_expression`: check for tainted args reaching a sink.
///
/// Field layout: `function` = callee, `arguments` = arg list.
fn handle_function_call(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let callee = function_call_callee(node, ctx.source);
    if callee.is_empty() {
        return;
    }

    if let Some(sink) = match_call_sink(ctx.spec, callee, ctx.sink_to_rules) {
        check_args_for_sink(node, ctx, state, findings, sink);
    }
}

/// Handle a `member_call_expression`: `$obj->method(args)`.
///
/// Field layout: `object` = receiver, `name` = method name, `arguments` = args.
fn handle_member_call(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let method_name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.source))
        .unwrap_or("");

    // Track how many findings we had before to avoid double-firing.
    let before = findings.len();

    // Check MethodName sinks first.
    let method_sink_desc = ctx.spec.sinks.iter().find_map(|m| {
        if let NodeMatcher::MethodName {
            method,
            description,
        } = m
        {
            if method.as_str() == method_name {
                Some(description.clone())
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(desc) = method_sink_desc {
        check_args_for_sink_by_desc(node, ctx, state, findings, desc);
    }

    // Only check dotted callee if MethodName didn't already fire.
    if findings.len() == before {
        if let Some(obj) = node.child_by_field_name("object") {
            let obj_text = node_text(obj, ctx.source).trim_start_matches('$');
            let callee = format!("{}.{}", obj_text, method_name);
            if let Some(sink) = match_call_sink(ctx.spec, &callee, ctx.sink_to_rules) {
                check_args_for_sink(node, ctx, state, findings, sink);
            }
        }
    }
}

/// Handle `echo_statement`: `echo $x;` is an XSS sink.
fn handle_echo(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    // Find the `echo` sink matcher.
    let echo_sink_desc = ctx.spec.sinks.iter().find_map(|m| {
        if let NodeMatcher::Call {
            canonical,
            description,
        } = m
        {
            if canonical == "echo" {
                Some(description.clone())
            } else {
                None
            }
        } else {
            None
        }
    });
    let Some(sink_desc) = echo_sink_desc else {
        return;
    };

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some((source_desc, src_line)) = expression_taint(child, ctx, state) {
            findings.push(taint_finding_for_node(
                node,
                source_desc,
                sink_desc.clone(),
                src_line,
                None,
                1,
            ));
            return;
        }
    }
}

/// Check `arguments` of a call/method node for tainted arguments reaching a sink.
fn check_args_for_sink(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    sink: crate::rules::taint_engine::MatchedSink,
) {
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        // Each `argument` node wraps the actual expression.
        let expr = if arg.kind() == "argument" {
            arg.named_child(0).unwrap_or(arg)
        } else {
            arg
        };
        if let Some((source_desc, src_line)) = expression_taint(expr, ctx, state) {
            let rule_hint = attribution_hint_for_sink(&sink);
            findings.push(taint_finding_for_node(
                node,
                source_desc,
                sink.description.clone(),
                src_line,
                rule_hint,
                1,
            ));
            return;
        }
    }
}

fn check_args_for_sink_by_desc(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    sink_desc: String,
) {
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let mut cursor = args.walk();
    for arg in args.named_children(&mut cursor) {
        let expr = if arg.kind() == "argument" {
            arg.named_child(0).unwrap_or(arg)
        } else {
            arg
        };
        if let Some((source_desc, src_line)) = expression_taint(expr, ctx, state) {
            findings.push(taint_finding_for_node(
                node,
                source_desc,
                sink_desc.clone(),
                src_line,
                None,
                1,
            ));
            return;
        }
    }
}

/// Returns `(description, source_line)` if `expr` is or references a tainted value.
fn expression_taint(
    expr: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &TaintState,
) -> Option<(String, usize)> {
    let expr_line = expr.start_position().row + 1;

    // ── Direct source match ────────────────────────────────────────────────
    if let Some(desc) = match_source(expr, ctx.source, ctx.spec) {
        return Some((desc, expr_line));
    }

    // ── Tainted variable reference ─────────────────────────────────────────
    // PHP variables are `variable_name` nodes; their full text includes `$`.
    if expr.kind() == "variable_name" {
        let name = node_text(expr, ctx.source);
        if let Some(info) = state.info(name) {
            return Some((info.description.clone(), info.line));
        }
    }

    // ── Subscript on a tainted receiver: `$arr[$key]` ─────────────────────
    // `subscript_expression` has no named fields; first named_child is the receiver.
    if expr.kind() == "subscript_expression" {
        if let Some(receiver) = expr.named_child(0) {
            if let Some(result) = expression_taint(receiver, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── Encapsed string (double-quoted with interpolation): `"ls $cmd"` ────
    // Variables embedded inline in an `encapsed_string` are direct named children.
    if expr.kind() == "encapsed_string" {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(result) = expression_taint(child, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── String concatenation: `"prefix" . $tainted` ───────────────────────
    // PHP uses `.` for string concatenation, which is a `binary_expression`.
    if expr.kind() == "binary_expression" {
        // Named children: [0] = left, [1] = right
        for i in 0..2 {
            if let Some(child) = expr.named_child(i) {
                if let Some(result) = expression_taint(child, ctx, state) {
                    return Some(result);
                }
            }
        }
    }

    // ── Function call result propagation ──────────────────────────────────
    if expr.kind() == "function_call_expression" {
        if is_sanitizer_function_call(expr, ctx.source, ctx.spec) {
            return None;
        }
        // Check arguments
        if let Some(args) = expr.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                let inner = if arg.kind() == "argument" {
                    arg.named_child(0).unwrap_or(arg)
                } else {
                    arg
                };
                if let Some(result) = expression_taint(inner, ctx, state) {
                    return Some(result);
                }
            }
        }
    }

    // ── Member call result propagation: `$obj->method($tainted)` ──────────
    if expr.kind() == "member_call_expression" {
        // Check if it's a sanitizer method.
        if is_sanitizer_method_call(expr, ctx.source, ctx.spec) {
            return None;
        }
        // Check arguments.
        if let Some(args) = expr.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                let inner = if arg.kind() == "argument" {
                    arg.named_child(0).unwrap_or(arg)
                } else {
                    arg
                };
                if let Some(result) = expression_taint(inner, ctx, state) {
                    return Some(result);
                }
            }
        }
        // Also check if the receiver is tainted: `$taintedObj->method()`.
        if let Some(receiver) = expr.child_by_field_name("object") {
            if let Some(result) = expression_taint(receiver, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── Conditional expression: `$tainted ?: "default"` ───────────────────
    if expr.kind() == "conditional_expression" {
        let mut cursor = expr.walk();
        for child in expr.named_children(&mut cursor) {
            if let Some(result) = expression_taint(child, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── Cast expression: `(string)$tainted` ──────────────────────────────
    // Int/bool casts are sanitizers; string/array casts propagate taint.
    if expr.kind() == "cast_expression" && !is_sanitizer_cast(expr, ctx.source) {
        // The expression being cast is the last named child.
        if let Some(inner) = expr.named_child(expr.named_child_count().saturating_sub(1)) {
            return expression_taint(inner, ctx, state);
        }
    }

    None
}

/// Check if the function_call_expression is a sanitizer call.
fn is_sanitizer_function_call(call_node: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    if call_node.kind() != "function_call_expression" {
        return false;
    }
    let callee = function_call_callee(call_node, source);
    spec.sanitizers.iter().any(|m| {
        if let NodeMatcher::Call { canonical, .. } = m {
            canonical.as_str() == callee
        } else {
            false
        }
    })
}

/// Check if the member_call_expression is a sanitizer method call.
fn is_sanitizer_method_call(call_node: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    if call_node.kind() != "member_call_expression" {
        return false;
    }
    let method = call_node
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    spec.sanitizers.iter().any(|m| match m {
        NodeMatcher::MethodName { method: m_name, .. } => m_name.as_str() == method,
        NodeMatcher::Call { canonical, .. } => canonical.as_str() == method,
        _ => false,
    })
}

/// Check if a cast expression is a sanitizing cast (int, bool, float).
fn is_sanitizer_cast(cast_node: Node<'_>, source: &str) -> bool {
    let text = node_text(cast_node, source).to_lowercase();
    text.starts_with("(int)")
        || text.starts_with("(integer)")
        || text.starts_with("(bool)")
        || text.starts_with("(boolean)")
        || text.starts_with("(float)")
        || text.starts_with("(double)")
}

/// Match a node against the spec's sources.
///
/// # Key design: ParamName in expression position
///
/// The Semgrep bridge compiles bare identifier patterns (e.g. `$_GET`) to
/// `GenericMatcher::ParamName`. We must match these in expression position too
/// (not just at param-seeding time), otherwise bridge/CLI rules will silently
/// produce no findings even when `analyze_tree` unit tests pass.
///
/// Shapes matched for PHP:
/// - `variable_name` node whose text matches a name in the `ParamName` list
///   (e.g. `"$_GET"` matches `names: ["$_GET"]`)
/// - `subscript_expression` whose first named_child is a matching `variable_name`
///   (e.g. `$_GET['cmd']`)
/// - `function_call_expression` whose callee matches a `Call` canonical
fn match_source(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    for matcher in &spec.sources {
        match matcher {
            NodeMatcher::ParamName { names, description } => {
                let matches_name = |n: &str| names.iter().any(|name| name == n);

                match node.kind() {
                    "variable_name" => {
                        let var = node_text(node, source);
                        if matches_name(var) {
                            return Some(description.clone());
                        }
                    }
                    "subscript_expression" => {
                        // `$_GET['cmd']` — first named_child is the receiver.
                        if let Some(receiver) = node.named_child(0) {
                            if receiver.kind() == "variable_name" {
                                let var = node_text(receiver, source);
                                if matches_name(var) {
                                    return Some(description.clone());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            NodeMatcher::Call {
                canonical,
                description,
            } => {
                if node.kind() == "function_call_expression" {
                    let callee = function_call_callee(node, source);
                    if callee == canonical.as_str() {
                        return Some(description.clone());
                    }
                }
            }
            NodeMatcher::Attribute {
                root,
                field,
                description,
            } => {
                // `$obj->field` is a `member_access_expression` (not a call) in PHP.
                // E.g. `$request->body` for attribute-style access.
                if node.kind() == "member_access_expression" {
                    let recv_text = node
                        .child_by_field_name("object")
                        .map(|n| node_text(n, source).trim_start_matches('$'))
                        .unwrap_or("");
                    let member_text = node
                        .child_by_field_name("member")
                        .or_else(|| node.child_by_field_name("name"))
                        .map(|n| node_text(n, source))
                        .unwrap_or("");
                    if recv_text == root.as_str() && member_text == field.as_str() {
                        return Some(description.clone());
                    }
                }
            }
            NodeMatcher::FieldName { field, description } => {
                // Any-receiver property READ: `<anything>->field`. In PHP this
                // is a `member_access_expression`. Match whose member/name
                // equals `field`, regardless of the object. Covers
                // `$request->body`, `$req->query`, etc.
                if node.kind() == "member_access_expression" {
                    let member_text = node
                        .child_by_field_name("member")
                        .or_else(|| node.child_by_field_name("name"))
                        .map(|n| node_text(n, source))
                        .unwrap_or("");
                    if member_text == field.as_str() {
                        return Some(description.clone());
                    }
                }
            }
            NodeMatcher::Subscript { base, description } => {
                // Index access `base[...]` → `subscript_expression`. Matches
                // when the indexed receiver's final segment equals `base` (or
                // any when `base` is None). The receiver is the first named
                // child. `$_GET[...]` is a `variable_name`; `$req->q[...]` is
                // a `member_access_expression`.
                if node.kind() == "subscript_expression" {
                    let Some(receiver) = node.named_child(0) else {
                        continue;
                    };
                    let Some(want) = base.as_deref() else {
                        // Metavariable base → match any subscript.
                        return Some(description.clone());
                    };
                    let final_seg = match receiver.kind() {
                        "variable_name" => {
                            Some(node_text(receiver, source).trim_start_matches('$'))
                        }
                        "member_access_expression" => receiver
                            .child_by_field_name("member")
                            .or_else(|| receiver.child_by_field_name("name"))
                            .map(|n| node_text(n, source)),
                        "name" => Some(node_text(receiver, source)),
                        _ => None,
                    };
                    if final_seg == Some(want) {
                        return Some(description.clone());
                    }
                }
            }
            NodeMatcher::MethodName { .. }
            | NodeMatcher::CallRegex { .. }
            | NodeMatcher::MethodNameRegex { .. }
            | NodeMatcher::ReceiverCall { .. }
            | NodeMatcher::MemberAssign { .. }
            | NodeMatcher::BinopFormat { .. }
            | NodeMatcher::ObjectLiteralValue { .. }
            | NodeMatcher::ReturnValue { .. } => {
                // Sink-only matchers; BinopFormat is carried but not yet matched
                // in the PHP engine (no-op).
            }
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Php).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn spec_get_to_system() -> TaintSpec {
        TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["$_GET".into()],
                description: "$_GET".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn spec_get_to_system_with_sanitizer() -> TaintSpec {
        TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["$_GET".into()],
                description: "$_GET".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![NodeMatcher::Call {
                canonical: "escapeshellarg".into(),
                description: "escapeshellarg()".into(),
            }],
        }
    }

    // ── Test 1: superglobal subscript → system via variable ──────────────────
    #[test]
    fn get_subscript_to_system_via_assignment() {
        let src = "<?php\nfunction handle() {\n  $c = $_GET['cmd'];\n  system($c);\n}\n";
        let f = run(src, &spec_get_to_system());
        assert_eq!(f.len(), 1, "expected finding, got {:?}", f);
        assert!(f[0].source_description.contains("$_GET"));
        assert!(f[0].sink_description.contains("system"));
    }

    // ── Test 2: direct superglobal subscript → system ─────────────────────────
    #[test]
    fn get_subscript_directly_to_system() {
        let src = "<?php\nfunction handle() {\n  system($_GET['cmd']);\n}\n";
        let f = run(src, &spec_get_to_system());
        assert_eq!(f.len(), 1, "expected direct finding, got {:?}", f);
    }

    // ── Test 3: no source → no finding ──────────────────────────────────────
    #[test]
    fn literal_cmd_no_finding() {
        let src = "<?php\nfunction handle() {\n  $c = 'ls -la';\n  system($c);\n}\n";
        let f = run(src, &spec_get_to_system());
        assert_eq!(f.len(), 0, "literal must produce no finding");
    }

    // ── Test 4: sanitizer kills taint ────────────────────────────────────────
    #[test]
    fn escapeshellarg_sanitizes() {
        let src =
            "<?php\nfunction handle() {\n  $c = escapeshellarg($_GET['cmd']);\n  system($c);\n}\n";
        let f = run(src, &spec_get_to_system_with_sanitizer());
        assert_eq!(f.len(), 0, "escapeshellarg must sanitize taint");
    }

    // ── Test 5: near-miss (tainted var not passed to sink) ───────────────────
    #[test]
    fn taint_not_reaching_sink() {
        let src = "<?php\nfunction handle() {\n  $tainted = $_GET['cmd'];\n  $safe = 'ls';\n  system($safe);\n}\n";
        let f = run(src, &spec_get_to_system());
        assert_eq!(f.len(), 0, "safe arg must produce no finding");
    }

    // ── Test 6: chained assignment propagates taint ──────────────────────────
    #[test]
    fn chained_assignment_propagates() {
        let src = "<?php\nfunction handle() {\n  $a = $_GET['x'];\n  $b = $a;\n  $c = $b;\n  system($c);\n}\n";
        let f = run(src, &spec_get_to_system());
        assert_eq!(f.len(), 1, "chained assignment must propagate taint");
    }

    // ── Test 7: reassignment to literal kills taint ──────────────────────────
    #[test]
    fn reassignment_to_literal_kills_taint() {
        let src =
            "<?php\nfunction handle() {\n  $c = $_GET['cmd'];\n  $c = 'ls';\n  system($c);\n}\n";
        let f = run(src, &spec_get_to_system());
        assert_eq!(f.len(), 0, "reassignment kills taint");
    }

    // ── Test 8: POST superglobal ──────────────────────────────────────────────
    #[test]
    fn post_superglobal_is_source() {
        let spec = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["$_POST".into()],
                description: "$_POST".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![],
        };
        let src = "<?php\nfunction handle() {\n  $c = $_POST['cmd'];\n  system($c);\n}\n";
        let f = run(src, &spec);
        assert_eq!(f.len(), 1, "$_POST must be a source");
    }

    // ── Test 9: method call sink (->query) ───────────────────────────────────
    #[test]
    fn method_name_sink_fires_on_query() {
        let spec = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["$_GET".into()],
                description: "$_GET".into(),
            }],
            sinks: vec![NodeMatcher::MethodName {
                method: "query".into(),
                description: "->query()".into(),
            }],
            sanitizers: vec![],
        };
        let src = "<?php\nfunction handle() {\n  $q = $_GET['q'];\n  $pdo->query($q);\n}\n";
        let f = run(src, &spec);
        assert_eq!(f.len(), 1, "->query() must be a sink, got {:?}", f);
    }

    // ── Test 10: sanitizer on different var doesn't clear original ─────────
    #[test]
    fn sanitizer_on_other_var_does_not_block_original() {
        let src = "<?php\nfunction handle() {\n  $raw = $_GET['cmd'];\n  $safe = escapeshellarg($raw);\n  system($raw);\n}\n";
        let f = run(src, &spec_get_to_system_with_sanitizer());
        assert_eq!(f.len(), 1, "sanitizing to $safe must not clear $raw taint");
    }
}
