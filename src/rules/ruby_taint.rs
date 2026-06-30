//! Intraprocedural, flow-insensitive taint analysis for Ruby.
//!
//! # Scope
//!
//! Mirrors `python_taint` in structure and limitations:
//!
//! - **Per method.** Each `method` body is analyzed independently; taint does
//!   not cross method boundaries.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order. Taint
//!   observed in one branch of an `if` is treated as taint in the fall-through.
//! - **No container sensitivity.** `params[:key]` is tainted when `params` is
//!   tainted; individual keys are not tracked.
//!
//! # Ruby grammar differences from Python
//!
//! Key tree-sitter-ruby node kinds used here:
//!
//! - `method` — a method definition; fields: `name`, `parameters`
//!   (`method_parameters`), `body` (`body_statement`).
//! - `call` — a method call; fields: `receiver` (optional), `method`,
//!   `arguments` (`argument_list`, may be absent for bare calls like `gets`).
//! - `assignment` — `left` / `right` fields.
//! - `element_reference` — subscript (`params[:q]`, `ENV["X"]`); `object`
//!   field for the receiver.
//! - `subshell` — backtick / `%x{…}` execution; carries `interpolation`
//!   children when interpolated.
//! - `string` — string literal; carries `interpolation` children for `"#{…}"`.
//! - `return` — a return statement; first named child is an `argument_list`.
//!
//! Unlike Python, Ruby method calls store arguments in an `argument_list` node
//! accessed via `node.child_by_field_name("arguments")` (same field name as
//! Python's `argument_list`, but the node kind is `argument_list` not
//! `argument_list`). Both parenthesized and space-style calls
//! (`system(x)` and `system x`) parse identically as `call` + `argument_list`.

use crate::rules::common::AliasTable;
use crate::rules::taint_engine::{
    analyze_function_generic, attribution_hint_for_sink, match_call_sink, node_text,
    taint_finding_for_node, AnalysisContext, TaintLanguageAdapter, TaintState,
};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Type alias for the Ruby-specific analysis context.
/// Ruby has no cross-file info yet (None is always passed).
type RubyCtx<'a> = AnalysisContext<'a, ()>;

/// Run the Ruby taint engine over every method definition inside `root`
/// and return one [`TaintFinding`] per source→sink flow discovered.
///
/// The root can be a whole file tree. The engine finds every `method`
/// node inside it (including nested class/module definitions) and
/// analyzes each independently.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    // Build a trivial (empty) return summary — Ruby engine does not do
    // cross-method return tracking in v1. This matches the simplest version
    // used by Kotlin/C/Java engines.
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
    collect_method_defs(root, &mut |method_node| {
        analyze_function_generic::<RubyTaintAdapter, ()>(method_node, &ctx, &mut findings);
    });
    findings
}

// ─── Built-in specs ──────────────────────────────────────────────────────────

/// All Ruby first-party taint rule IDs paired with their specs.
///
/// Mirrors `csharp_taint_rule_specs` in shape: each entry pairs a
/// `rb/taint-*` rule id with a `TaintSpec` built from the shared
/// [`ruby_taint_sources`] / [`ruby_taint_sanitizers`] and a rule-specific
/// subset of [`ruby_taint_sinks`].
pub fn ruby_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("rb/taint-command-injection", command_injection_spec()),
        ("rb/taint-sql-injection", sql_injection_spec()),
        ("rb/taint-xss", xss_spec()),
        (
            "rb/taint-unsafe-deserialization",
            unsafe_deserialization_spec(),
        ),
        ("rb/taint-open-redirect", open_redirect_spec()),
    ]
}

/// Return the subset of [`ruby_taint_sinks`] whose callee (for `Call`) or
/// method name (for `MethodName`) appears in `keys`. This lets each rule
/// below reuse the centralized sink catalog without duplicating matcher
/// definitions (and drifting out of sync with the Semgrep bridge).
fn pick_sinks(keys: &[&str]) -> Vec<NodeMatcher> {
    ruby_taint_sinks()
        .into_iter()
        .filter(|m| match m {
            NodeMatcher::Call { canonical, .. } => keys.contains(&canonical.as_str()),
            NodeMatcher::MethodName { method, .. } => keys.contains(&method.as_str()),
            _ => false,
        })
        .collect()
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: ruby_taint_sources(),
        // OS command execution + dynamic code evaluation: `system`, `exec`,
        // `spawn` (bare and `Kernel.*`), plus `eval` / `instance_eval`.
        sinks: pick_sinks(&[
            "system",
            "exec",
            "spawn",
            "Kernel.system",
            "Kernel.exec",
            "Kernel.spawn",
            "eval",
            "instance_eval",
        ]),
        sanitizers: ruby_taint_sanitizers(),
    }
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: ruby_taint_sources(),
        // ActiveRecord / connection SQL sinks: `where`, `find_by_sql`,
        // `connection.execute`.
        sinks: pick_sinks(&["where", "find_by_sql", "execute"]),
        sanitizers: ruby_taint_sanitizers(),
    }
}

fn xss_spec() -> TaintSpec {
    TaintSpec {
        sources: ruby_taint_sources(),
        // HTML-escaping bypasses: `raw(...)` and `.html_safe`. NOTE: the
        // intraprocedural engine only checks sink *arguments*, so `raw(x)`
        // (argument taint) fires end-to-end; `.html_safe` is receiver-taint
        // (`x.html_safe`) and is matched as a sink but its receiver is not
        // inspected by `handle_call`, so the receiver-taint form does not
        // produce a finding in v1 (documented precision limitation).
        sinks: pick_sinks(&["html_safe", "raw"]),
        sanitizers: ruby_taint_sanitizers(),
    }
}

fn unsafe_deserialization_spec() -> TaintSpec {
    TaintSpec {
        sources: ruby_taint_sources(),
        // Ruby deserialization gadgets: `Marshal.load`, `YAML.load`,
        // `YAML.unsafe_load`.
        sinks: pick_sinks(&["Marshal.load", "YAML.load", "YAML.unsafe_load"]),
        sanitizers: ruby_taint_sanitizers(),
    }
}

fn open_redirect_spec() -> TaintSpec {
    TaintSpec {
        sources: ruby_taint_sources(),
        // Rails `redirect_to`.
        sinks: pick_sinks(&["redirect_to"]),
        sanitizers: ruby_taint_sanitizers(),
    }
}

/// Canonical set of untrusted-input sources for Ruby web handlers.
///
/// Covers Rails/Sinatra/Rack request parameters, environment variables,
/// and the `gets` I/O function.
pub fn ruby_taint_sources() -> Vec<NodeMatcher> {
    vec![
        // ─── params / request.params (Rails/Sinatra) ─────────────────
        // `params[:key]` → element_reference on `params` identifier
        NodeMatcher::ParamName {
            names: vec!["params".into()],
            description: "request params".into(),
        },
        // `request.params` attribute
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "params".into(),
            description: "request.params".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "body".into(),
            description: "request.body".into(),
        },
        NodeMatcher::Attribute {
            root: "request".into(),
            field: "env".into(),
            description: "request.env".into(),
        },
        // ─── gets / $stdin (CLI / scripts) ───────────────────────────
        NodeMatcher::Call {
            canonical: "gets".into(),
            description: "gets()".into(),
        },
        NodeMatcher::Call {
            canonical: "STDIN.gets".into(),
            description: "STDIN.gets".into(),
        },
        NodeMatcher::Call {
            canonical: "STDIN.read".into(),
            description: "STDIN.read".into(),
        },
        NodeMatcher::Call {
            canonical: "STDIN.readline".into(),
            description: "STDIN.readline".into(),
        },
        // ─── ENV (environment variables) ─────────────────────────────
        // `ENV["X"]` → element_reference whose object is the `ENV` constant.
        // Covered by Attribute { root: "ENV", ... } via the element_reference
        // path in match_source.
        NodeMatcher::Attribute {
            root: "ENV".into(),
            field: "[]".into(),
            description: "ENV[...]".into(),
        },
        // `ENV.fetch("X")` as a call.
        NodeMatcher::Call {
            canonical: "ENV.fetch".into(),
            description: "ENV.fetch".into(),
        },
        // ─── Handler parameter convention ────────────────────────────
        NodeMatcher::ParamName {
            names: vec!["request".into(), "req".into()],
            description: "untrusted request parameter".into(),
        },
    ]
}

/// Canonical set of dangerous sinks for Ruby.
pub fn ruby_taint_sinks() -> Vec<NodeMatcher> {
    vec![
        // ─── OS command execution ─────────────────────────────────────
        NodeMatcher::Call {
            canonical: "system".into(),
            description: "system()".into(),
        },
        NodeMatcher::Call {
            canonical: "exec".into(),
            description: "exec()".into(),
        },
        NodeMatcher::Call {
            canonical: "spawn".into(),
            description: "spawn()".into(),
        },
        NodeMatcher::Call {
            canonical: "Kernel.system".into(),
            description: "Kernel.system()".into(),
        },
        NodeMatcher::Call {
            canonical: "Kernel.exec".into(),
            description: "Kernel.exec()".into(),
        },
        NodeMatcher::Call {
            canonical: "Kernel.spawn".into(),
            description: "Kernel.spawn()".into(),
        },
        // ─── Dynamic evaluation ───────────────────────────────────────
        NodeMatcher::Call {
            canonical: "eval".into(),
            description: "eval()".into(),
        },
        NodeMatcher::Call {
            canonical: "instance_eval".into(),
            description: "instance_eval()".into(),
        },
        NodeMatcher::Call {
            canonical: "send".into(),
            description: "send()".into(),
        },
        NodeMatcher::Call {
            canonical: "public_send".into(),
            description: "public_send()".into(),
        },
        // ─── Deserialization ──────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "Marshal.load".into(),
            description: "Marshal.load()".into(),
        },
        NodeMatcher::Call {
            canonical: "YAML.load".into(),
            description: "YAML.load()".into(),
        },
        NodeMatcher::Call {
            canonical: "YAML.unsafe_load".into(),
            description: "YAML.unsafe_load()".into(),
        },
        // ─── SQL (ActiveRecord) ───────────────────────────────────────
        NodeMatcher::MethodName {
            method: "where".into(),
            description: "ActiveRecord.where()".into(),
        },
        NodeMatcher::MethodName {
            method: "find_by_sql".into(),
            description: "find_by_sql()".into(),
        },
        NodeMatcher::MethodName {
            method: "execute".into(),
            description: "connection.execute()".into(),
        },
        // ─── HTTP redirect (open redirect) ────────────────────────────
        NodeMatcher::MethodName {
            method: "redirect_to".into(),
            description: "redirect_to()".into(),
        },
        // ─── HTML rendering (XSS via raw/html_safe) ───────────────────
        NodeMatcher::MethodName {
            method: "html_safe".into(),
            description: "html_safe".into(),
        },
        NodeMatcher::MethodName {
            method: "raw".into(),
            description: "raw()".into(),
        },
    ]
}

/// Canonical set of sanitizers for Ruby.
pub fn ruby_taint_sanitizers() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::Call {
            canonical: "Shellwords.escape".into(),
            description: "Shellwords.escape".into(),
        },
        NodeMatcher::Call {
            canonical: "ERB::Util.html_escape".into(),
            description: "ERB::Util.html_escape".into(),
        },
        NodeMatcher::Call {
            canonical: "CGI.escapeHTML".into(),
            description: "CGI.escapeHTML".into(),
        },
        NodeMatcher::Call {
            canonical: "sanitize".into(),
            description: "sanitize()".into(),
        },
    ]
}

// ─── Language adapter ─────────────────────────────────────────────────────

/// Zero-sized marker type for the Ruby taint language adapter.
struct RubyTaintAdapter;

impl TaintLanguageAdapter<()> for RubyTaintAdapter {
    fn is_nested_scope(kind: &str) -> bool {
        // Nested method defs create a new scope; each is analyzed independently.
        kind == "method" || kind == "singleton_method"
    }

    fn get_body(func_node: Node<'_>) -> Option<Node<'_>> {
        // Ruby methods use `body_statement` not `body`.
        func_node.child_by_field_name("body")
    }

    fn seed_params(func_node: Node<'_>, ctx: &RubyCtx<'_>, state: &mut TaintState) {
        // Ruby method parameters are in `method_parameters` (field name "parameters").
        if let Some(params) = func_node.child_by_field_name("parameters") {
            seed_param_sources(params, ctx.source, ctx.spec, state);
        }
    }

    fn dispatch_walk_node(
        node: Node<'_>,
        ctx: &RubyCtx<'_>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
    ) {
        if node.kind() == "assignment" {
            handle_assignment(node, ctx, state);
        }
        if node.kind() == "call" {
            handle_call(node, ctx, state, findings);
        }
        // Backtick/subshell: `cmd` or %x{cmd} — taint if interpolation is tainted.
        if node.kind() == "subshell" {
            handle_subshell(node, ctx, state, findings);
        }
    }

    fn dispatch_summary_node(
        node: Node<'_>,
        ctx: &RubyCtx<'_>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
        return_taint: &mut Option<String>,
    ) {
        Self::dispatch_walk_node(node, ctx, state, findings);
        // Check return statements.
        if node.kind() == "return" && return_taint.is_none() {
            // The return statement in Ruby has an `argument_list` as its first
            // named child (even for `return params[:key]` — it wraps the expr).
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                // The child might be argument_list or a bare expression.
                if child.kind() == "argument_list" {
                    let mut inner = child.walk();
                    for expr in child.named_children(&mut inner) {
                        if let Some((desc, _line)) = expression_taint(expr, ctx, state) {
                            *return_taint = Some(desc);
                            break;
                        }
                    }
                } else if let Some((desc, _line)) = expression_taint(child, ctx, state) {
                    *return_taint = Some(desc);
                }
            }
        }
    }

    fn expression_taint(
        expr: Node<'_>,
        ctx: &RubyCtx<'_>,
        state: &TaintState,
    ) -> Option<(String, usize)> {
        expression_taint(expr, ctx, state)
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────

/// Collect all `method` (and `singleton_method`) nodes in the tree,
/// calling `visit` on each.
fn collect_method_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if node.kind() == "method" || node.kind() == "singleton_method" {
        visit(node);
    }
    // Still recurse to pick up methods defined inside class/module bodies.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_method_defs(child, visit);
    }
}

/// Seed taint state from method parameters whose name matches a source matcher.
fn seed_param_sources(params: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        // In Ruby, direct parameters are `identifier` nodes. Optional params,
        // splat params, keyword params, and block params use other kinds —
        // we only track simple identifier params for v1.
        if child.kind() != "identifier" {
            continue;
        }
        let param_name = node_text(child, source);
        for matcher in &spec.sources {
            if let NodeMatcher::ParamName { names, description } = matcher {
                if names.iter().any(|n| n == param_name)
                    || crate::rules::taint_engine::param_names_are_wildcard(names)
                {
                    let line = child.start_position().row + 1;
                    state.taint(param_name.to_string(), description.clone(), line);
                    break;
                }
            }
        }
    }
}

/// Handle an `assignment` node: propagate taint from RHS to LHS identifier.
fn handle_assignment(node: Node<'_>, ctx: &RubyCtx<'_>, state: &mut TaintState) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };

    // Only track simple identifier LHS (local variable assignment).
    if left.kind() != "identifier" {
        return;
    }
    let lhs_name = node_text(left, ctx.source).to_string();
    if let Some((desc, src_line)) = expression_taint(right, ctx, state) {
        state.taint(lhs_name, desc, src_line);
    } else {
        state.clear(&lhs_name);
    }
}

/// Handle a `call` node: check if arguments are tainted and the callee is a sink.
fn handle_call(
    node: Node<'_>,
    ctx: &RubyCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    // Resolve the callee. Ruby calls can be:
    //   1. Bare: `system(cmd)` — method field is an identifier
    //   2. With receiver: `Kernel.exec(cmd)` — receiver + method fields
    let callee = resolve_callee(node, ctx.source);

    if let Some(sink) = match_call_sink(ctx.spec, &callee, ctx.sink_to_rules) {
        // Check each argument for taint.
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                if let Some((source_desc, src_line)) = expression_taint(arg, ctx, state) {
                    let rule_hint = attribution_hint_for_sink(&sink);
                    findings.push(taint_finding_for_node(
                        node,
                        source_desc,
                        sink.description,
                        src_line,
                        rule_hint,
                        1,
                    ));
                    // One finding per sink call is enough.
                    break;
                }
            }
        }
    }
}

/// Handle a `subshell` (backtick) node: if any interpolated expression is
/// tainted, report a command injection finding.
fn handle_subshell(
    node: Node<'_>,
    ctx: &RubyCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    // A subshell is a sink. Check if any interpolation is tainted.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "interpolation" {
            continue;
        }
        let mut inner = child.walk();
        for expr in child.named_children(&mut inner) {
            if let Some((source_desc, src_line)) = expression_taint(expr, ctx, state) {
                // No spec-driven sink for subshell — it's always a sink.
                findings.push(taint_finding_for_node(
                    node,
                    source_desc,
                    "subshell/backtick execution".to_string(),
                    src_line,
                    None,
                    1,
                ));
                return;
            }
        }
    }
}

/// Resolve the callee of a `call` node to a canonical dotted string.
///
/// - Bare call `system(x)` → `"system"`
/// - Receiver call `Kernel.exec(x)` → `"Kernel.exec"`
/// - Chained: `obj.method(x)` → `"obj.method"` (only one level)
fn resolve_callee(node: Node<'_>, source: &str) -> String {
    let method = node
        .child_by_field_name("method")
        .map(|n| node_text(n, source))
        .unwrap_or("");

    if let Some(recv) = node.child_by_field_name("receiver") {
        let recv_text = node_text(recv, source);
        format!("{}.{}", recv_text, method)
    } else {
        method.to_string()
    }
}

/// Returns `(description, line)` if `expr` is or references a tainted value.
fn expression_taint(
    expr: Node<'_>,
    ctx: &RubyCtx<'_>,
    state: &TaintState,
) -> Option<(String, usize)> {
    let expr_line = expr.start_position().row + 1;

    // ── Direct source match ───────────────────────────────────────────────
    if let Some(desc) = match_source(expr, ctx.source, ctx.spec) {
        return Some((desc, expr_line));
    }

    // ── Tainted identifier reference ───────────────────────────────────────
    if expr.kind() == "identifier" {
        let name = node_text(expr, ctx.source);
        if let Some(info) = state.info(name) {
            return Some((info.description.clone(), info.line));
        }
    }

    // ── Attribute access on a tainted root: `x.field` ─────────────────────
    // Ruby: call node with receiver + method, no arguments = attribute access.
    // e.g. `request.params` is parsed as `call [receiver="request", method="params"]`.
    if expr.kind() == "call" && expr.child_by_field_name("arguments").is_none() {
        if let Some(recv) = expr.child_by_field_name("receiver") {
            if let Some(result) = expression_taint(recv, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── Subscript/element_reference on a tainted root: `params[:q]` ───────
    // `element_reference` with `object` field. Tainted if object is tainted.
    if expr.kind() == "element_reference" {
        if let Some(object) = expr.child_by_field_name("object") {
            if let Some(result) = expression_taint(object, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── String interpolation: `"ls #{cmd}"` ───────────────────────────────
    if expr.kind() == "string" {
        let mut cursor = expr.walk();
        for child in expr.children(&mut cursor) {
            if child.kind() == "interpolation" {
                let mut inner = child.walk();
                for inner_child in child.named_children(&mut inner) {
                    if let Some(result) = expression_taint(inner_child, ctx, state) {
                        return Some(result);
                    }
                }
            }
        }
    }

    // ── Method call result propagation: `tainted.method()` or `func(tainted)` ──
    // If the call is not a sanitizer, check:
    //   a) If any argument is tainted (wrapping call preserves taint)
    //   b) If the receiver is tainted (method call on tainted object)
    if expr.kind() == "call" {
        if is_sanitizer_call(expr, ctx.source, ctx.spec) {
            return None;
        }

        // Check arguments.
        if let Some(args) = expr.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for arg in args.named_children(&mut cursor) {
                if let Some(result) = expression_taint(arg, ctx, state) {
                    return Some(result);
                }
            }
        }

        // Check receiver.
        if let Some(recv) = expr.child_by_field_name("receiver") {
            if let Some(result) = expression_taint(recv, ctx, state) {
                return Some(result);
            }
        }
    }

    // ── Binary operator propagation ─────────────────────────────────────────
    // `"prefix" + tainted` or `tainted + "suffix"` → tainted.
    if expr.kind() == "binary" {
        if let Some(left) = expr.child_by_field_name("left") {
            if let Some(result) = expression_taint(left, ctx, state) {
                return Some(result);
            }
        }
        if let Some(right) = expr.child_by_field_name("right") {
            if let Some(result) = expression_taint(right, ctx, state) {
                return Some(result);
            }
        }
    }

    None
}

/// Check if the call node is a sanitizer call.
fn is_sanitizer_call(call_node: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    if call_node.kind() != "call" {
        return false;
    }
    let callee = resolve_callee(call_node, source);
    for matcher in &spec.sanitizers {
        if let NodeMatcher::Call { canonical, .. } = matcher {
            if callee == canonical.as_str() {
                return true;
            }
        }
    }
    false
}

/// Match a node against the spec's sources.
///
/// Ruby AST note: bare no-arg calls like `gets` parse as `identifier` nodes
/// (not `call` nodes), since tree-sitter-ruby does not wrap them in a call
/// node when there are no parentheses and no arguments. We therefore match
/// `identifier` nodes against `Call { canonical }` matchers when the
/// canonical has no dot (bare function name). This is safe because such
/// matchers are only ever in the sources list when the user explicitly
/// declared them as sources.
///
/// Similarly, `ENV["X"]` parses as `element_reference { object: constant "ENV" }`.
/// We match it when the spec contains an `Attribute { root: "ENV", ... }` matcher
/// OR a `Call` matcher whose canonical starts with `"ENV"`.
fn match_source(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    for matcher in &spec.sources {
        match matcher {
            NodeMatcher::Attribute {
                root,
                field,
                description,
            } => {
                // Case 1: `request.params` → `call [receiver, method, no-args]`
                if node.kind() == "call" && node.child_by_field_name("arguments").is_none() {
                    if let (Some(recv), Some(method)) = (
                        node.child_by_field_name("receiver"),
                        node.child_by_field_name("method"),
                    ) {
                        let recv_text = node_text(recv, source);
                        let method_text = node_text(method, source);
                        if recv_text == root.as_str() && method_text == field.as_str() {
                            return Some(description.clone());
                        }
                        // Also match when receiver is a longer chain: use leftmost.
                        if method_text == field.as_str() {
                            if let Some(leftmost) = leftmost_receiver_text(recv, source) {
                                if leftmost == root.as_str() {
                                    return Some(description.clone());
                                }
                            }
                        }
                    }
                }
                // Case 2: `ENV["X"]` → `element_reference { object: constant "ENV" }`
                // When root is a constant (e.g. "ENV") and the node is an element_reference
                // whose object text equals root, treat it as a source access.
                if node.kind() == "element_reference" {
                    if let Some(object) = node.child_by_field_name("object") {
                        let obj_text = node_text(object, source);
                        if obj_text == root.as_str() {
                            return Some(description.clone());
                        }
                    }
                }
            }
            NodeMatcher::Call {
                canonical,
                description,
            } => {
                // Case 1: `gets(...)` or `Kernel.exec(...)` → `call` node.
                if node.kind() == "call" {
                    let callee = resolve_callee(node, source);
                    if callee == canonical.as_str() {
                        return Some(description.clone());
                    }
                }
                // Case 2: bare `gets` with no args → `identifier` node.
                // Match when the canonical is a simple name (no dot) and
                // the identifier text equals it.
                if node.kind() == "identifier"
                    && !canonical.contains('.')
                    && node_text(node, source) == canonical.as_str()
                {
                    return Some(description.clone());
                }
            }
            NodeMatcher::ParamName { names, description } => {
                // Bare-identifier sources (`params`, `gets`, `ENV`, …) are
                // compiled by the Semgrep bridge to `ParamName`. In Ruby these
                // most often denote a method call / accessor rather than a
                // formal parameter (Rails `params`, `Kernel#gets`, the `ENV`
                // constant), so we match them in expression position too — not
                // just at param-seeding time (which still happens separately in
                // `seed_params`).
                //
                // Shapes matched:
                //   - bare `identifier` / `constant`: `params`, `gets`, `ENV`
                //   - `element_reference` receiver: `params[:cmd]`, `ENV["X"]`
                //   - `call` whose leftmost receiver is a name: `params.require`
                //   - bare `call` whose method is a name: `gets()`
                let matches_name = |n: &str| names.iter().any(|name| name == n);

                match node.kind() {
                    "identifier" | "constant" => {
                        if matches_name(node_text(node, source)) {
                            return Some(description.clone());
                        }
                    }
                    "element_reference" => {
                        if let Some(object) = node.child_by_field_name("object") {
                            // Only match a *bare* receiver (`params[:cmd]`),
                            // not a dotted chain, so we don't double-fire on
                            // the inner access.
                            if matches!(object.kind(), "identifier" | "constant")
                                && matches_name(node_text(object, source))
                            {
                                return Some(description.clone());
                            }
                        }
                    }
                    "call" => {
                        // `params.require(:x)` / `gets` parsed as a call.
                        // Match when the bare method name (no receiver) is one
                        // of the names, or the leftmost receiver is.
                        if node.child_by_field_name("receiver").is_none() {
                            if let Some(method) = node.child_by_field_name("method") {
                                if matches_name(node_text(method, source)) {
                                    return Some(description.clone());
                                }
                            }
                        } else if let Some(recv) = node.child_by_field_name("receiver") {
                            if let Some(leftmost) = leftmost_receiver_text(recv, source) {
                                if matches_name(leftmost) {
                                    return Some(description.clone());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            NodeMatcher::FieldName { field, description } => {
                // Any-receiver attribute READ: `<anything>.field`. In Ruby a
                // no-arg accessor like `request.params` parses as a `call`
                // with a receiver and a method but no arguments. Match such a
                // node whose method equals `field`, regardless of receiver.
                if node.kind() == "call"
                    && node.child_by_field_name("receiver").is_some()
                    && node.child_by_field_name("arguments").is_none()
                {
                    if let Some(method) = node.child_by_field_name("method") {
                        if node_text(method, source) == field.as_str() {
                            return Some(description.clone());
                        }
                    }
                }
            }
            NodeMatcher::Subscript { base, description } => {
                // Index access `base[...]` → `element_reference` in Ruby
                // (`params[:cmd]`, `request.GET["x"]`). Matches when the
                // object's final segment equals `base` (or any if None).
                if node.kind() == "element_reference" {
                    if let Some(object) = node.child_by_field_name("object") {
                        match base.as_deref() {
                            None => return Some(description.clone()),
                            Some(want) => match object.kind() {
                                "identifier" | "constant" => {
                                    if node_text(object, source) == want {
                                        return Some(description.clone());
                                    }
                                }
                                "call" => {
                                    // `request.GET` accessor parsed as a call.
                                    if let Some(method) = object.child_by_field_name("method") {
                                        if node_text(method, source) == want {
                                            return Some(description.clone());
                                        }
                                    }
                                }
                                _ => {}
                            },
                        }
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
                // in the Ruby engine (no-op).
            }
        }
    }
    None
}

/// Walk a receiver chain leftward and return the leftmost receiver text.
/// For `request.params`, returns `Some("request")`.
/// For a bare identifier `params`, returns `Some("params")`.
fn leftmost_receiver_text<'a>(mut node: Node<'_>, source: &'a str) -> Option<&'a str> {
    loop {
        match node.kind() {
            "identifier" | "constant" => return Some(node_text(node, source)),
            "call" => {
                // Attribute access: call with receiver but no arguments.
                if let Some(recv) = node.child_by_field_name("receiver") {
                    node = recv;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn spec_gets_to_system() -> TaintSpec {
        TaintSpec {
            sources: vec![NodeMatcher::Call {
                canonical: "gets".into(),
                description: "gets()".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn spec_params_to_system() -> TaintSpec {
        TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["params".into()],
                description: "request params".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn spec_params_to_eval() -> TaintSpec {
        TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["params".into()],
                description: "request params".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "eval".into(),
                description: "eval()".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn spec_with_shellwords_sanitizer() -> TaintSpec {
        let mut spec = spec_gets_to_system();
        spec.sanitizers = vec![NodeMatcher::Call {
            canonical: "Shellwords.escape".into(),
            description: "Shellwords.escape".into(),
        }];
        spec
    }

    fn run(source: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(source, Language::Ruby).expect("parse");
        analyze_tree(tree.root_node(), source, spec, None)
    }

    // ── Test 1: direct source→sink via intermediate variable ────────────────
    #[test]
    fn gets_to_system_via_assignment() {
        let src = r#"
def run
  cmd = gets
  system(cmd)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(
            f.len(),
            1,
            "expected finding for gets -> system, got {:?}",
            f
        );
        assert!(f[0].source_description.contains("gets"));
        assert!(f[0].sink_description.contains("system"));
        // sink should be on the `system(cmd)` line
        assert_eq!(f[0].sink_line, 4);
        // source line should be on `cmd = gets` line
        assert_eq!(f[0].source_line, 3);
    }

    // ── Test 2: direct (no intermediate) ────────────────────────────────────
    #[test]
    fn gets_directly_to_system() {
        let src = r#"
def run
  system(gets)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(f.len(), 1, "expected direct gets->system finding");
    }

    // ── Test 3: chained assignment propagates taint ──────────────────────────
    #[test]
    fn chained_assignment_propagates_taint() {
        let src = r#"
def run
  a = gets
  b = a
  c = b
  system(c)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(
            f.len(),
            1,
            "taint must propagate through chained assignments"
        );
    }

    // ── Test 4: reassignment to literal kills taint ──────────────────────────
    #[test]
    fn reassignment_to_literal_kills_taint() {
        let src = r#"
def run
  cmd = gets
  cmd = "ls -la"
  system(cmd)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(f.len(), 0, "reassignment to literal must kill taint");
    }

    // ── Test 5: params param name seed ──────────────────────────────────────
    #[test]
    fn params_param_seeds_taint() {
        let src = r#"
def handle(params)
  cmd = params[:id]
  system(cmd)
end
"#;
        let f = run(src, &spec_params_to_system());
        assert_eq!(f.len(), 1, "params param -> system must fire, got {:?}", f);
        assert!(f[0].source_description.contains("params"));
    }

    // ── Test 6: subscript on tainted root is tainted ─────────────────────────
    #[test]
    fn subscript_on_tainted_root_is_tainted() {
        let src = r#"
def handle(params)
  val = params[:q]
  eval(val)
end
"#;
        let f = run(src, &spec_params_to_eval());
        assert_eq!(f.len(), 1, "params[:q] must propagate taint to eval");
    }

    // ── Test 7: no source → no finding ────────────────────────────────────────
    #[test]
    fn no_source_no_finding() {
        let src = r#"
def run
  cmd = "ls -la"
  system(cmd)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(f.len(), 0, "clean literal must produce no finding");
    }

    // ── Test 8: sanitizer kills taint ──────────────────────────────────────────
    #[test]
    fn sanitizer_kills_taint() {
        let src = r#"
def run
  raw = gets
  clean = Shellwords.escape(raw)
  system(clean)
end
"#;
        let f = run(src, &spec_with_shellwords_sanitizer());
        assert_eq!(f.len(), 0, "Shellwords.escape must sanitize taint");
    }

    // ── Test 9: sanitizer on different variable does not block original ──────
    #[test]
    fn sanitizer_on_other_var_does_not_block_original() {
        let src = r#"
def run
  raw = gets
  _safe = Shellwords.escape(raw)
  system(raw)
end
"#;
        let f = run(src, &spec_with_shellwords_sanitizer());
        assert_eq!(
            f.len(),
            1,
            "sanitizing 'raw' into '_safe' must not clear 'raw' taint"
        );
    }

    // ── Test 10: ENV subscript is a source ────────────────────────────────────
    #[test]
    fn env_subscript_is_source() {
        let src = r#"
def run
  val = ENV["PATH"]
  system(val)
end
"#;
        // Without a source matcher for ENV, the engine should NOT fire.
        // Build a spec with `gets` only — ENV["X"] must NOT match it.
        let spec_with_env = TaintSpec {
            sources: vec![NodeMatcher::Call {
                canonical: "gets".into(),
                description: "gets".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![],
        };
        // With just `gets` as source, ENV["PATH"] should NOT fire (different source)
        let f_no_env = run(src, &spec_with_env);
        assert_eq!(
            f_no_env.len(),
            0,
            "ENV should not match gets spec; got {:?}",
            f_no_env
        );
        // Now test with full ruby sources that include ENV.fetch:
        let spec_full = TaintSpec {
            sources: ruby_taint_sources(),
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: ruby_taint_sanitizers(),
        };
        let f_full = run(src, &spec_full);
        assert_eq!(
            f_full.len(),
            1,
            "ENV[...] must be tainted with full ruby sources, got {:?}",
            f_full
        );
    }

    // ── Test 11: string interpolation propagates taint ───────────────────────
    #[test]
    fn string_interpolation_propagates_taint() {
        let src = r#"
def run
  user_input = gets
  cmd = "ls #{user_input}"
  system(cmd)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(
            f.len(),
            1,
            "string interpolation must propagate taint, got {:?}",
            f
        );
    }

    // ── Test 12: Kernel.exec with receiver ───────────────────────────────────
    #[test]
    fn kernel_exec_is_sink() {
        let src = r#"
def run
  cmd = gets
  Kernel.exec(cmd)
end
"#;
        let spec = TaintSpec {
            sources: vec![NodeMatcher::Call {
                canonical: "gets".into(),
                description: "gets()".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "Kernel.exec".into(),
                description: "Kernel.exec()".into(),
            }],
            sanitizers: vec![],
        };
        let f = run(src, &spec);
        assert_eq!(f.len(), 1, "Kernel.exec must be recognized as sink");
    }

    // ── Test 13: method_name sink (MethodName matcher) ───────────────────────
    #[test]
    fn method_name_sink_fires_on_where() {
        let src = r#"
def search(params)
  User.where("name = '#{params[:name]}'")
end
"#;
        let spec = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec!["params".into()],
                description: "params".into(),
            }],
            sinks: vec![NodeMatcher::MethodName {
                method: "where".into(),
                description: "where()".into(),
            }],
            sanitizers: vec![],
        };
        let f = run(src, &spec);
        assert_eq!(
            f.len(),
            1,
            "MethodName sink must fire for .where, got {:?}",
            f
        );
    }

    // ── Test 14: near-miss (taint not reaching sink) ─────────────────────────
    #[test]
    fn taint_not_reaching_sink_no_finding() {
        let src = r#"
def run
  tainted = gets
  safe_cmd = "echo hello"
  system(safe_cmd)
end
"#;
        let f = run(src, &spec_gets_to_system());
        assert_eq!(f.len(), 0, "safe_cmd is a literal; tainted is not the arg");
    }

    // ── Test 15: request.params attribute source ──────────────────────────────
    #[test]
    fn request_params_attribute_source() {
        let src = r#"
def handle(request)
  val = request.params[:q]
  system(val)
end
"#;
        let spec = TaintSpec {
            sources: vec![NodeMatcher::Attribute {
                root: "request".into(),
                field: "params".into(),
                description: "request.params".into(),
            }],
            sinks: vec![NodeMatcher::Call {
                canonical: "system".into(),
                description: "system()".into(),
            }],
            sanitizers: vec![],
        };
        let f = run(src, &spec);
        assert_eq!(
            f.len(),
            1,
            "request.params must be tainted as Attribute source, got {:?}",
            f
        );
    }
}
