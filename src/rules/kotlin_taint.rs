//! Intraprocedural, flow-insensitive taint analysis for Kotlin.
//!
//! This is the fourth sibling to `python_taint`, `javascript_taint`,
//! and `go_taint`. It exposes the same public surface — `TaintSpec`,
//! `NodeMatcher`, `TaintFinding`, `analyze_tree` — so callers can write
//! declarative `(sources, sinks, sanitizers)` specs the same way they
//! do for the other languages.
//!
//! The internals are Kotlin-grammar-aware (`call_expression`,
//! `navigation_expression`, `property_declaration`, `simple_identifier`,
//! `function_value_parameters`, …). Like the other engines, the file
//! deliberately keeps grammar quirks local rather than trying to share
//! a polymorphic walker.
//!
//! # Scope (mirrors the other engines)
//!
//! - **Per function / lambda.** Each `function_declaration` and
//!   `lambda_literal` body is analyzed independently. Lambdas matter
//!   because Ktor routes use `routing { get("/path") { … } }` blocks.
//! - **Per file.** No cross-file analysis (v1).
//! - **Flow-insensitive.** Two propagation passes; sources seed a name
//!   set, the analyzer transitively taints any `property_declaration` or
//!   `assignment` whose initializer/RHS references a tainted name or a
//!   tainted source expression.
//! - **String-template interpolation** (`"…${x}…"`) propagates taint.
//! - **No sanitizers.** Kotlin's spec carries an empty sanitizer list;
//!   the engine threads the field through for forward compatibility.
//!
//! # NodeMatcher interpretation
//!
//! Kotlin's grammar means a couple of `NodeMatcher` variants need a
//! Kotlin-flavoured reading. The interpretation is chosen to preserve
//! the exact behaviour the bespoke `run_kt_taint()` harness had before
//! the unified-engine refactor — see `kotlin_taint_rule_specs()` for
//! the rule specs that drive it.
//!
//! - **`Call { canonical }`**
//!   - If `canonical` has no `.`, matches a constructor-style call
//!     `Foo(args)` (a `call_expression` whose callee is a bare
//!     `simple_identifier` equal to `canonical`).
//!   - If `canonical` is `Receiver.method`, matches a method call where
//!     the call's receiver text *contains* `Receiver` and the method
//!     name equals `method`. The receiver-substring rule (rather than
//!     exact-equals) is required to recognise both `Runtime.getRuntime()`
//!     and `getRuntime()` style chains, and `call.request.queryParameters`
//!     style nested navigation — same fuzz the bespoke harness used.
//! - **`MethodName { method }`** — matches any `call_expression` whose
//!   method name (last segment of the navigation chain) equals `method`,
//!   regardless of receiver. Used for sinks like `executeQuery` that
//!   live on many receiver bindings (`db`, `conn`, `tx`, `stmt`…).
//! - **`ParamName { names }`** — matches function parameters by name.
//!   For Kotlin, the `names` list may contain bare identifiers
//!   (`request`, `req`) which behave like Python/JS, OR Spring-style
//!   annotation strings (`@RequestParam`, `@RequestBody`, …). When a
//!   parameter carries one of the annotation strings in its
//!   `parameter_modifiers`, that parameter is treated as a source.
//! - **`Attribute { root, field }`** — not currently used by any
//!   Kotlin rule; reserved for forward compatibility.
//! - **`MemberAssign { … }`** — JS-specific; ignored.

use crate::rules::common::{walk_tree, AliasTable};
use crate::rules::cross_file::{CrossFileSummaryMap, FunctionTaintSummary, ParamSinkFlow};
use crate::rules::taint_engine::cross_file_taint_finding;
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashSet;
use std::path::PathBuf;
use tree_sitter::Node;

// ─── Public API ────────────────────────────────────────────────────────────

/// Run the Kotlin taint engine over every function declaration and
/// lambda body inside `root` and return one [`TaintFinding`] per
/// source→sink flow discovered.
///
/// The `aliases` argument is currently unused — Kotlin imports use
/// fully qualified names at sink sites (`Runtime.getRuntime()`,
/// `javax.script.ScriptEngineManager()`), so a per-file alias table
/// would not change matching today. The parameter is kept for shape
/// parity with the other engines.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "function_declaration" || node.kind() == "lambda_literal" {
            analyze_scope(node, src, spec, &mut findings);
        }
    });
    findings
}

/// All Kotlin taint rule IDs paired with their specs.
///
/// Mirrors `go_taint_rule_specs()` / `python_taint_rule_specs()`.
/// Consumed by [`crate::rules::builtin_taint_specs_for_language`] so
/// taint rules show up as `RegistryTaintSpec` entries the same way the
/// other languages do.
pub fn kotlin_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("kt/taint-sql-injection", sql_injection_spec()),
        ("kt/taint-command-injection", command_injection_spec()),
        ("kt/taint-ssrf", ssrf_spec()),
    ]
}

/// Shared sources for every Kotlin taint rule. Recognises:
///
/// - Ktor `call.receiveText()`, `call.receive<T>()`
/// - Ktor `request.queryParameters[...]`, `call.request.queryParameters[...]`
/// - Ktor `request.header(...)`, `call.request.header(...)`,
///   `request.queryParameter(...)`
/// - Spring annotations `@RequestParam`, `@RequestBody`, `@PathVariable`,
///   `@RequestHeader` on a function parameter
///
/// The annotation entries use `ParamName` with the `@`-prefixed names
/// the engine recognises specially (see module-level docs).
pub fn kotlin_taint_sources() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::Call {
            canonical: "call.receiveText".into(),
            description: "call.receiveText()".into(),
        },
        NodeMatcher::Call {
            canonical: "call.receive".into(),
            description: "call.receive()".into(),
        },
        NodeMatcher::Call {
            canonical: "request.header".into(),
            description: "request.header()".into(),
        },
        NodeMatcher::Call {
            canonical: "request.queryParameter".into(),
            description: "request.queryParameter()".into(),
        },
        // Indexing sources (request.queryParameters["x"]) are matched by
        // `is_indexing_source` directly — they have no NodeMatcher form
        // today but are baked into the engine for behaviour preservation.
        NodeMatcher::ParamName {
            names: vec![
                "@RequestParam".into(),
                "@RequestBody".into(),
                "@PathVariable".into(),
                "@RequestHeader".into(),
            ],
            description: "Spring annotation parameter".into(),
        },
    ]
}

// ─── Rule specs ────────────────────────────────────────────────────────────

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: kotlin_taint_sources(),
        sinks: vec![
            NodeMatcher::MethodName {
                method: "executeQuery".into(),
                description: "executeQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "execute".into(),
                description: "execute() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "createQuery".into(),
                description: "createQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "createNativeQuery".into(),
                description: "createNativeQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "rawQuery".into(),
                description: "rawQuery() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "execSQL".into(),
                description: "execSQL() with tainted argument".into(),
            },
            NodeMatcher::MethodName {
                method: "prepareStatement".into(),
                description: "prepareStatement() with tainted argument".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: kotlin_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "Runtime.exec".into(),
                description: "Runtime.exec() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "ProcessBuilder".into(),
                description: "ProcessBuilder() with tainted argument".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn ssrf_spec() -> TaintSpec {
    TaintSpec {
        sources: kotlin_taint_sources(),
        sinks: vec![
            // URL/URI constructor-style calls.
            NodeMatcher::Call {
                canonical: "URL".into(),
                description: "URL() with tainted argument".into(),
            },
            NodeMatcher::Call {
                canonical: "URI".into(),
                description: "URI() with tainted argument".into(),
            },
            // RestTemplate convenience methods — match by method name on
            // any receiver. The bespoke harness matched these regardless
            // of receiver, so `MethodName` is the right shape.
            NodeMatcher::MethodName {
                method: "getForObject".into(),
                description: "getForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "getForEntity".into(),
                description: "getForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForObject".into(),
                description: "postForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForEntity".into(),
                description: "postForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "exchange".into(),
                description: "exchange() with tainted URL".into(),
            },
        ],
        sanitizers: vec![],
    }
}

// ─── Internals ─────────────────────────────────────────────────────────────

/// Describes a taint source matched inside a function body.
struct TaintSource {
    var_name: Option<String>,
    description: String,
    line: usize,
}

/// Describes a taint sink match.
struct TaintSink {
    start_byte: usize,
    end_byte: usize,
    description: String,
}

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_function_body(scope_node).unwrap_or(scope_node);

    // Collect sources from the body (Ktor `call.*`, indexing) and from
    // the function's own parameter list (Spring annotations / param
    // names). For lambda_literal nodes there is no parameter list to
    // scan separately.
    let mut sources = collect_body_sources(body, source, spec);
    if matches!(scope_node.kind(), "function_declaration") {
        collect_param_sources(scope_node, source, spec, &mut sources);
    }
    if sources.is_empty() {
        return;
    }

    let tainted = build_tainted_set(body, source, &sources);
    if tainted.is_empty() {
        return;
    }

    let sinks = find_sinks(body, source, spec, &tainted);
    if sinks.is_empty() {
        return;
    }

    // Pick a representative source for the finding's source_description.
    // Mirrors the bespoke harness's "first source wins" rule.
    let (source_desc, source_line) = sources
        .first()
        .map(|s| (s.description.clone(), s.line))
        .unwrap_or_else(|| ("user input".to_string(), 0));

    for sink in sinks {
        let start = byte_to_position(source, sink.start_byte);
        let end = byte_to_position(source, sink.end_byte);
        out.push(TaintFinding {
            sink_start_byte: sink.start_byte,
            sink_end_byte: sink.end_byte,
            sink_line: start.0,
            sink_column: start.1,
            sink_end_line: end.0,
            sink_end_column: end.1,
            source_description: source_desc.clone(),
            sink_description: sink.description,
            source_line,
            source_range: None,
            rule_id_hint: None,
            // The Kotlin engine does not yet track hops; report 0 so the
            // reporting layer leaves confidence at the engine-default and
            // does not emit a `taint_hops` field, matching the bespoke
            // harness's prior output.
            hops: 0,
        });
    }
}

/// Walk a function or lambda body and collect taint sources expressed
/// as Ktor request reads (call.receiveText(), request.queryParameters[…])
/// captured inside `property_declaration` or `assignment` initialisers.
fn collect_body_sources(scope: Node<'_>, source: &str, spec: &TaintSpec) -> Vec<TaintSource> {
    let mut sources = Vec::new();
    walk_tree(scope, source, &mut |n, s| {
        if n.kind() == "property_declaration" {
            let var = extract_property_var_name(n, s);
            let initializer = extract_property_initializer(n);
            if let (Some(var_name), Some(init)) = (var, initializer) {
                if let Some(desc) = classify_source_expr(init, s, spec) {
                    sources.push(TaintSource {
                        var_name: Some(var_name),
                        description: desc,
                        line: n.start_position().row + 1,
                    });
                }
            }
        }
        if n.kind() == "assignment" {
            if let (Some(left), Some(right)) =
                (n.child(0), n.child(n.child_count().saturating_sub(1)))
            {
                if left.kind() == "simple_identifier" {
                    let left_text = &s[left.byte_range()];
                    if let Some(desc) = classify_source_expr(right, s, spec) {
                        sources.push(TaintSource {
                            var_name: Some(left_text.to_string()),
                            description: desc,
                            line: n.start_position().row + 1,
                        });
                    }
                }
            }
        }
    });
    sources
}

/// Return a source description if `node` is a taint source expression
/// recognised by `spec`. Implements the Kotlin-specific interpretation
/// of `NodeMatcher::Call` (receiver-substring + method) and the baked-in
/// `request.queryParameters[…]` indexing pattern.
fn classify_source_expr(node: Node<'_>, src: &str, spec: &TaintSpec) -> Option<String> {
    // Try every spec source that is a Call matcher.
    if node.kind() == "call_expression" {
        if let Some(method) = call_method_name(node, src) {
            if let Some(receiver) = call_receiver_text(node, src) {
                for matcher in &spec.sources {
                    if let NodeMatcher::Call { canonical, .. } = matcher {
                        if let Some(desc) = match_kotlin_call_canonical(canonical, receiver, method)
                        {
                            return Some(desc);
                        }
                    }
                }
            }
        }
    }

    // Indexing pattern: `request.queryParameters["x"]`, baked in for
    // parity with the bespoke harness.
    if is_indexing_source(node, src) {
        return Some(src[node.byte_range()].to_string());
    }

    None
}

/// Check whether a node looks like a Ktor request-indexing source.
fn is_indexing_source(node: Node<'_>, src: &str) -> bool {
    let text = &src[node.byte_range()];
    (node.kind() == "indexing_expression"
        || text.contains("queryParameters[")
        || text.contains("parameters["))
        && (text.contains("request") || text.contains("call"))
        && (text.contains("queryParameters")
            || text.contains("parameters[")
            || text.contains("header"))
}

/// Apply the Kotlin-flavoured interpretation of `NodeMatcher::Call`.
/// See the module-level docs for the rules.
fn match_kotlin_call_canonical(canonical: &str, receiver: &str, method: &str) -> Option<String> {
    if let Some((expected_recv, expected_method)) = canonical.split_once('.') {
        if method == expected_method && receiver.contains(expected_recv) {
            return Some(format!("{}.{}()", receiver, method));
        }
    }
    None
}

/// Apply the Kotlin-flavoured interpretation of `NodeMatcher::Call` to
/// sink call sites. Returns `true` if the call matches the canonical
/// shape (constructor or `Receiver.method`).
fn match_kotlin_sink_call(
    canonical: &str,
    receiver: Option<&str>,
    method: Option<&str>,
    ctor_name: Option<&str>,
) -> bool {
    if let Some((expected_recv, expected_method)) = canonical.split_once('.') {
        // Method-on-receiver form: `Runtime.exec`.
        if let (Some(recv), Some(m)) = (receiver, method) {
            return m == expected_method && recv.contains(expected_recv);
        }
        return false;
    }
    // Constructor-style: `ProcessBuilder`, `URL`, …
    if let Some(ctor) = ctor_name {
        return ctor == canonical;
    }
    false
}

/// Collect Spring annotation-based parameter sources plus bare
/// `ParamName` matches from a function declaration. Pushes into the
/// caller's source list.
fn collect_param_sources(
    func_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintSource>,
) {
    // Collect annotation strings and bare names from the spec once.
    let mut annotation_names: Vec<&str> = Vec::new();
    let mut bare_names: Vec<&str> = Vec::new();
    // `$`-prefixed name (`$PARAM`) is the any-parameter wildcard: seed every
    // parameter of the function (compiled from a Semgrep
    // `pattern-inside: fun(...,$ARG,...) + focus-metavariable: $ARG` block).
    let mut wildcard = false;
    for matcher in &spec.sources {
        if let NodeMatcher::ParamName { names, .. } = matcher {
            for name in names {
                if let Some(rest) = name.strip_prefix('@') {
                    annotation_names.push(rest);
                } else if name == crate::rules::taint_engine::ANY_PARAM_WILDCARD {
                    wildcard = true;
                } else {
                    bare_names.push(name.as_str());
                }
            }
        }
    }

    let mut cursor = func_node.walk();
    for child in func_node.children(&mut cursor) {
        if child.kind() != "function_value_parameters" {
            continue;
        }
        let mut c2 = child.walk();
        let children: Vec<_> = child.children(&mut c2).collect();
        let mut pending_annotation: Option<&str> = None;

        for ch in &children {
            if ch.kind() == "parameter_modifiers" {
                let mod_text = &source[ch.byte_range()];
                for ann in &annotation_names {
                    if mod_text.contains(ann) {
                        pending_annotation = Some(ann);
                        break;
                    }
                }
            } else if ch.kind() == "parameter" {
                // Extract the parameter name (first simple_identifier).
                let mut c3 = ch.walk();
                let mut param_name: Option<&str> = None;
                for pc in ch.children(&mut c3) {
                    if pc.kind() == "simple_identifier" {
                        param_name = Some(&source[pc.byte_range()]);
                        break;
                    }
                }
                if let Some(name) = param_name {
                    if let Some(ann) = pending_annotation.take() {
                        out.push(TaintSource {
                            var_name: Some(name.to_string()),
                            description: format!("@{} parameter '{}'", ann, name),
                            line: ch.start_position().row + 1,
                        });
                    } else if bare_names.contains(&name) || wildcard {
                        out.push(TaintSource {
                            var_name: Some(name.to_string()),
                            description: format!("parameter '{}'", name),
                            line: ch.start_position().row + 1,
                        });
                    }
                }
                pending_annotation = None;
            } else if ch.kind() != "," && ch.kind() != "(" && ch.kind() != ")" {
                pending_annotation = None;
            }
        }
    }
}

/// Seed the tainted-name set with source variables and transitively
/// taint locals through simple assignment and string concatenation /
/// interpolation. Two passes to handle a single level of chained
/// assignment (`val a = source; val b = a; val c = b + …`).
fn build_tainted_set(scope: Node<'_>, source: &str, sources: &[TaintSource]) -> HashSet<String> {
    let mut tainted: HashSet<String> = HashSet::new();
    for s in sources {
        if let Some(ref name) = s.var_name {
            tainted.insert(name.clone());
        }
    }
    if tainted.is_empty() {
        return tainted;
    }

    for _ in 0..2 {
        walk_tree(scope, source, &mut |n, s| {
            if n.kind() == "property_declaration" {
                let var = extract_property_var_name(n, s);
                let init = extract_property_initializer(n);
                if let (Some(var_name), Some(init_node)) = (var, init) {
                    if !tainted.contains(&var_name) && expr_uses_tainted(init_node, s, &tainted) {
                        tainted.insert(var_name);
                    }
                }
            }
            if n.kind() == "assignment" {
                if let (Some(left), Some(right)) =
                    (n.child(0), n.child(n.child_count().saturating_sub(1)))
                {
                    if left.kind() == "simple_identifier" {
                        let left_text = s[left.byte_range()].to_string();
                        if !tainted.contains(&left_text) && expr_uses_tainted(right, s, &tainted) {
                            tainted.insert(left_text);
                        }
                    }
                }
            }
        });
    }
    tainted
}

/// Recursively check whether `node` references any tainted variable.
/// Picks up `simple_identifier` references and `"…${tainted}…"`
/// string-template interpolations.
fn expr_uses_tainted(node: Node<'_>, src: &str, tainted: &HashSet<String>) -> bool {
    if node.kind() == "simple_identifier" {
        let name = &src[node.byte_range()];
        return tainted.contains(name);
    }
    if node.kind() == "string_literal" {
        let text = &src[node.byte_range()];
        for t in tainted {
            if text.contains(&format!("${{{}}}", t)) || text.contains(&format!("${}", t)) {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if expr_uses_tainted(child, src, tainted) {
            return true;
        }
    }
    false
}

/// Walk `scope` and emit a sink for every call expression whose callee
/// matches the spec's sink list AND whose arguments reference a tainted
/// variable.
fn find_sinks(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    tainted: &HashSet<String>,
) -> Vec<TaintSink> {
    let mut sinks = Vec::new();
    walk_tree(scope, source, &mut |n, s| {
        if n.kind() != "call_expression" {
            return;
        }
        let method = call_method_name(n, s);
        let receiver = call_receiver_text(n, s);
        let ctor = call_constructor_name(n, s);

        let Some(args) = call_arguments(n) else {
            return;
        };

        // Parameterized-binding setters bind their value to a placeholder
        // (`?`) in an already-prepared statement; they are NOT injection
        // sinks. Treat them as taint-stopping no-ops so a tainted value
        // passed to e.g. `setString(1, tainted)` does not flag.
        if matches!(method, Some("setString" | "setInt" | "setObject")) {
            return;
        }

        // `prepareStatement(sql, ...)` only executes its FIRST (SQL)
        // argument; trailing arguments (e.g. result-set type flags) are
        // not part of the query. Only treat it as a sink when the SQL
        // string itself is tainted.
        if method == Some("prepareStatement") {
            let first_tainted = first_argument(args)
                .map(|first| expr_uses_tainted(first, s, tainted))
                .unwrap_or(false);
            if first_tainted {
                sinks.push(TaintSink {
                    start_byte: n.start_byte(),
                    end_byte: n.end_byte(),
                    description: "prepareStatement() with tainted argument".into(),
                });
            }
            return;
        }

        if !expr_uses_tainted(args, s, tainted) {
            return;
        }

        for matcher in &spec.sinks {
            match matcher {
                NodeMatcher::MethodName {
                    method: expected,
                    description,
                } if method == Some(expected.as_str()) => {
                    sinks.push(TaintSink {
                        start_byte: n.start_byte(),
                        end_byte: n.end_byte(),
                        description: description.clone(),
                    });
                    return;
                }
                NodeMatcher::Call {
                    canonical,
                    description,
                } if match_kotlin_sink_call(canonical, receiver, method, ctor) => {
                    sinks.push(TaintSink {
                        start_byte: n.start_byte(),
                        end_byte: n.end_byte(),
                        description: description.clone(),
                    });
                    return;
                }
                _ => {}
            }
        }
    });
    sinks
}

// ─── Kotlin AST helpers ────────────────────────────────────────────────────

/// Extract the method name from a `call_expression` whose callee is a
/// `navigation_expression`. Returns the last `simple_identifier` inside
/// the trailing `navigation_suffix`.
fn call_method_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "navigation_expression" {
        let nav_suffix = callee.child(callee.child_count().checked_sub(1)?)?;
        if nav_suffix.kind() == "navigation_suffix" {
            let mut cursor = nav_suffix.walk();
            for child in nav_suffix.children(&mut cursor) {
                if child.kind() == "simple_identifier" {
                    return Some(&src[child.byte_range()]);
                }
            }
        }
    }
    None
}

/// Receiver text for a `call_expression` whose callee is a
/// `navigation_expression`: everything before the trailing `.method`.
fn call_receiver_text<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "navigation_expression" {
        let receiver = callee.child(0)?;
        return Some(&src[receiver.byte_range()]);
    }
    None
}

/// Constructor-style callee: for `Foo(args)` returns `Foo`.
fn call_constructor_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let callee = node.child(0)?;
    if callee.kind() == "simple_identifier" {
        return Some(&src[callee.byte_range()]);
    }
    None
}

/// Locate the `value_arguments` node inside a `call_expression`.
fn call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "call_expression" {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "call_suffix" {
            let mut c2 = child.walk();
            for grandchild in child.children(&mut c2) {
                if grandchild.kind() == "value_arguments" {
                    return Some(grandchild);
                }
            }
        }
    }
    None
}

/// First actual argument expression from a `value_arguments` node.
fn first_argument(args_node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = args_node.walk();
    for child in args_node.children(&mut cursor) {
        if child.kind() == "value_argument" {
            return child.child(0);
        }
    }
    None
}

/// Variable name of a `property_declaration` (`val x = …`).
fn extract_property_var_name(node: Node<'_>, src: &str) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declaration" {
            let mut c2 = child.walk();
            for gc in child.children(&mut c2) {
                if gc.kind() == "simple_identifier" {
                    return Some(src[gc.byte_range()].to_string());
                }
            }
        }
    }
    None
}

/// Initializer expression of a `property_declaration` (after the `=`).
fn extract_property_initializer(node: Node<'_>) -> Option<Node<'_>> {
    if node.child_count() < 3 {
        return None;
    }
    let mut found_eq = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if found_eq && child.kind() != "=" {
            return Some(child);
        }
        if child.kind() == "=" {
            found_eq = true;
        }
    }
    None
}

/// Body node of a `function_declaration` / `lambda_literal`, if any.
fn find_function_body(func_node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = func_node.walk();
    let body = func_node
        .children(&mut cursor)
        .find(|child| child.kind() == "function_body");
    body
}

/// Convert a byte offset into the source to a `(line, column)` pair,
/// matching the conventions used by `make_finding_from_offsets`.
fn byte_to_position(source: &str, byte: usize) -> (usize, usize) {
    let byte = byte.min(source.len());
    let line = source[..byte].bytes().filter(|b| *b == b'\n').count() + 1;
    let line_start = source[..byte].rfind('\n').map_or(0, |idx| idx + 1);
    let column = source[line_start..byte].chars().count() + 1;
    (line, column)
}

// ─── Cross-file (interprocedural across files) taint ─────────────────────
//
// Scope of the Kotlin cross-file pass (deliberately narrow; mirrors the C#,
// Ruby, Java, and Go engines):
//
// * **Resolution is NAME + ARITY based, not type-based.** A top-level or
//   member `function_declaration` (`fun run(x)`) is summarized by its bare
//   function name. A call site resolves to a summary whenever the invoked
//   name matches a summarized function in a sibling file of the same
//   directory (used as a same-package proxy, the way the Go/Java/C# engines
//   treat same-directory files). Only the argument *count* gates a
//   per-parameter flow (`param_index >= arg count` is skipped); the
//   receiver's type is never consulted. This intentionally
//   over-approximates: `run(x)`, `helper.run(x)`, and `Helper.run(x)` all
//   resolve to *any* same-package `run` summary regardless of the receiver.
// * **Bounded multi-hop IS modeled.** A helper `f` that forwards its parameter
//   into another same-directory helper `g` which sinks it (`A → f → g → sink`)
//   is captured by [`compose_cross_file_summaries`], the per-file step of the
//   scanner's bounded multi-hop fixpoint (see `docs/taint-tracking.md`).
// * **What is NOT modeled:** companion-object vs instance dispatch,
//   extension functions (the receiver type before the name is ignored),
//   function overloads discriminated by parameter *type* (only positional
//   arity is honored), `import`-based resolution across directories,
//   default/named/vararg argument reordering (only the first
//   `simple_identifier` of each positional `parameter` is summarized), and
//   cross-file chains deeper than the hop cap. These need a Kotlin symbol table
//   the engine does not build.

/// Extract cross-file taint summaries for every `function_declaration` in
/// `root`.
///
/// Pass 1 of the two-pass scanner. For each function, every positional
/// parameter is treated as a synthetic taint source; a parameter that reaches
/// a sink records a [`ParamSinkFlow`], and a parameter that flows to a
/// `return` records a `params_to_return` index. Summaries are keyed by the
/// bare function name (last-write-wins on name collisions, mirroring the C#
/// engine).
pub fn extract_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    _aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Vec<FunctionTaintSummary> {
    let mut summaries = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() != "function_declaration" {
            return;
        }
        let Some(name) = kotlin_function_name(node, src) else {
            return;
        };
        let param_names = kotlin_function_param_names(node, src);
        if let Some(summary) = summarize_kotlin_function(node, name, &param_names, src, rule_specs)
        {
            summaries.push(summary);
        }
    });
    summaries
}

/// The bare name of a `function_declaration`: the first `simple_identifier`
/// child. For an extension function (`fun Application.module()`) the receiver
/// type precedes the name, so this over-approximates by taking the leftmost
/// identifier — extension functions are documented as not-modeled.
fn kotlin_function_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "simple_identifier" {
            return Some(&src[child.byte_range()]);
        }
    }
    None
}

/// Positional parameter names of a `function_declaration`, in order. Only the
/// first `simple_identifier` of each `parameter` is taken, matching the subset
/// that [`collect_param_sources`] seeds.
fn kotlin_function_param_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "function_value_parameters" {
            continue;
        }
        let mut c2 = child.walk();
        for param in child.children(&mut c2) {
            if param.kind() != "parameter" {
                continue;
            }
            let mut c3 = param.walk();
            for pc in param.children(&mut c3) {
                if pc.kind() == "simple_identifier" {
                    names.push(source[pc.byte_range()].to_string());
                    break;
                }
            }
        }
    }
    names
}

/// Build a [`FunctionTaintSummary`] for a single function, or `None` if no
/// parameter reaches a sink or a return value. Reuses the intra-file
/// [`analyze_scope`] with a synthetic per-parameter source spec, exactly like
/// the C# engine's `summarize_csharp_method`.
fn summarize_kotlin_function(
    func_node: Node<'_>,
    func_name: &str,
    param_names: &[String],
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
) -> Option<FunctionTaintSummary> {
    if param_names.is_empty() {
        return None;
    }

    let mut params_to_sink: Vec<ParamSinkFlow> = Vec::new();
    let mut params_to_return: Vec<usize> = Vec::new();

    for (param_idx, param_name) in param_names.iter().enumerate() {
        if kotlin_param_flows_to_return(func_node, param_name, source) {
            params_to_return.push(param_idx);
        }

        for (rule_id, rule_spec) in rule_specs {
            let synthetic = TaintSpec {
                sources: vec![NodeMatcher::ParamName {
                    names: vec![param_name.clone()],
                    description: format!("parameter '{param_name}'"),
                }],
                sinks: rule_spec.sinks.clone(),
                sanitizers: rule_spec.sanitizers.clone(),
            };
            let mut findings = Vec::new();
            analyze_scope(func_node, source, &synthetic, &mut findings);
            if let Some(finding) = findings.first() {
                params_to_sink.push(ParamSinkFlow {
                    param_index: param_idx,
                    sink_rule_id: rule_id.to_string(),
                    sink_description: finding.sink_description.clone(),
                });
            }
        }
    }

    if params_to_sink.is_empty() && params_to_return.is_empty() {
        return None;
    }

    Some(FunctionTaintSummary {
        name: func_name.to_string(),
        params_to_return,
        params_to_sink,
    })
}

/// Does `param_name`, treated as a taint source, reach a `return` expression?
///
/// Best-effort: seed the parameter as a source, propagate through the tainted
/// set, then look for a `jump_expression` (`return <expr>`) whose expression
/// references a tainted name. `params_to_return` is recorded for parity with
/// the C#/Ruby summaries but is not consumed by pass 2 (single-hop only), so
/// an imperfect result here cannot produce or suppress a finding.
fn kotlin_param_flows_to_return(func_node: Node<'_>, param_name: &str, source: &str) -> bool {
    let synthetic = TaintSpec {
        sources: vec![NodeMatcher::ParamName {
            names: vec![param_name.to_string()],
            description: format!("parameter '{param_name}'"),
        }],
        sinks: vec![],
        sanitizers: vec![],
    };
    let body = find_function_body(func_node).unwrap_or(func_node);
    let mut sources = collect_body_sources(body, source, &synthetic);
    collect_param_sources(func_node, source, &synthetic, &mut sources);
    let tainted = build_tainted_set(body, source, &sources);
    if tainted.is_empty() {
        return false;
    }

    let mut flows = false;
    walk_tree(body, source, &mut |node, src| {
        if flows || node.kind() != "jump_expression" {
            return;
        }
        if src[node.byte_range()].trim_start().starts_with("return")
            && expr_uses_tainted(node, src, &tainted)
        {
            flows = true;
        }
    });
    flows
}

/// Cross-file resolution info for the Kotlin engine. Mirrors
/// `csharp_taint::CrossFileInfo`.
///
/// `same_package_paths` are the canonical paths of sibling Kotlin files in the
/// same directory (the same-package proxy); `summaries` is the pass-1 map keyed
/// by canonical path; `allowed_rule_ids` gates which rules may emit cross-file
/// findings in the current run.
pub struct CrossFileInfo<'a> {
    pub same_package_paths: &'a [PathBuf],
    pub summaries: &'a CrossFileSummaryMap,
    pub allowed_rule_ids: &'a HashSet<String>,
}

/// Pass 2 cross-file resolution: walk every function / lambda scope, compute
/// its intra-file tainted-name set, and for each helper call that resolves to
/// a sibling summary emit a finding when a tainted argument lands on a
/// parameter with a recorded sink flow.
///
/// Returns findings whose `rule_id_hint` carries the attributed rule id.
pub fn extract_cross_file_findings(
    root: Node<'_>,
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Vec<TaintFinding> {
    // The caller-side taint state is driven by the real sources (shared across
    // the built-in Kotlin rules); union them so an inline source argument like
    // `helper(call.receiveText())` is recognized.
    let mut source_spec = TaintSpec::default();
    for (_, spec) in rule_specs {
        source_spec.sources.extend(spec.sources.iter().cloned());
        source_spec
            .sanitizers
            .extend(spec.sanitizers.iter().cloned());
    }

    let mut out = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() == "function_declaration" || node.kind() == "lambda_literal" {
            resolve_cross_file_scope(node, src, &source_spec, cross_file, &mut out);
        }
    });
    out
}

fn resolve_cross_file_scope(
    scope_node: Node<'_>,
    source: &str,
    source_spec: &TaintSpec,
    cross_file: &CrossFileInfo<'_>,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_function_body(scope_node).unwrap_or(scope_node);
    let mut sources = collect_body_sources(body, source, source_spec);
    if matches!(scope_node.kind(), "function_declaration") {
        collect_param_sources(scope_node, source, source_spec, &mut sources);
    }
    let tainted = build_tainted_set(body, source, &sources);

    walk_tree(body, source, &mut |node, src| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(callee) = call_callee_name(node, src) else {
            return;
        };
        let Some(summary) = lookup_cross_file_summary(cross_file, callee) else {
            return;
        };
        let Some(args) = call_arguments(node) else {
            return;
        };
        let arg_nodes: Vec<Node<'_>> = {
            let mut cursor = args.walk();
            let mut v = Vec::new();
            for child in args.children(&mut cursor) {
                if child.kind() == "value_argument" {
                    if let Some(expr) = child.child(0) {
                        v.push(expr);
                    }
                }
            }
            v
        };

        for flow in &summary.params_to_sink {
            if !cross_file.allowed_rule_ids.contains(&flow.sink_rule_id) {
                continue;
            }
            if flow.param_index >= arg_nodes.len() {
                continue;
            }
            let arg = arg_nodes[flow.param_index];
            if let Some((desc, line)) = caller_arg_taint(arg, src, &sources, &tainted, source_spec)
            {
                out.push(cross_file_taint_finding(
                    node,
                    desc,
                    line,
                    &flow.sink_description,
                    callee,
                    &flow.sink_rule_id,
                ));
            }
        }
    });
}

/// The resolvable callee name of a `call_expression`: the method name for a
/// `receiver.method(...)` navigation call, or the bare identifier for a
/// `run(...)` / `Helper(...)` constructor-style call.
fn call_callee_name<'a>(node: Node<'a>, src: &'a str) -> Option<&'a str> {
    call_method_name(node, src).or_else(|| call_constructor_name(node, src))
}

/// Return `(source_description, source_line)` if a call argument carries taint:
/// either an inline direct source (`helper(call.receiveText())`) or a reference
/// to a tainted local (`helper(cmd)`). Uses the caller scope's first source as
/// the representative attribution, matching [`analyze_scope`]'s "first source
/// wins" rule.
fn caller_arg_taint(
    arg: Node<'_>,
    src: &str,
    sources: &[TaintSource],
    tainted: &HashSet<String>,
    source_spec: &TaintSpec,
) -> Option<(String, usize)> {
    if let Some(desc) = classify_source_expr(arg, src, source_spec) {
        return Some((desc, arg.start_position().row + 1));
    }
    if !tainted.is_empty() && expr_uses_tainted(arg, src, tainted) {
        if let Some(s) = sources.first() {
            return Some((s.description.clone(), s.line));
        }
        return Some(("user input".to_string(), arg.start_position().row + 1));
    }
    None
}

fn lookup_cross_file_summary<'a>(
    cross_file: &'a CrossFileInfo<'_>,
    callee_name: &str,
) -> Option<&'a FunctionTaintSummary> {
    for path in cross_file.same_package_paths {
        if let Some(file_summaries) = cross_file.summaries.get(path) {
            if let Some(summary) = file_summaries.iter().find(|s| s.name == callee_name) {
                return Some(summary);
            }
        }
    }
    None
}

/// Re-derive a file's cross-file summaries with same-directory call resolution
/// enabled, composing the current summary map one hop deeper.
///
/// This is the Kotlin counterpart of
/// [`crate::rules::java_taint::compose_cross_file_summaries`] and the per-file
/// step of the scanner's **bounded multi-hop** fixpoint.
///
/// Kotlin uses its OWN name-based, same-directory summary machinery (not the
/// shared `TaintLanguageAdapter` path Python/Go/JS use), so composition is
/// implemented directly here, mirroring the C#/Java engines. For each function
/// we seed one parameter at a time as a synthetic source and build the intra-file
/// tainted-name set. We then resolve every helper call that lands in a sibling
/// summary: when a tainted argument hits a param the sibling records in
/// `params_to_sink`, THIS parameter reaches that sink one hop deeper — e.g.
/// `forward(p)` whose body is `runQuery(p)` where the sibling `runQuery` sinks
/// its argument gains `forward`'s `params_to_sink` entry.
///
/// The scanner unions the returned flows into the existing summaries via
/// [`FunctionTaintSummary::merge_from`] and repeats until a fixpoint (no change)
/// or the hop bound is reached. `summaries` is a read-only snapshot from the
/// previous round, so each round adds exactly one hop; monotone growth over a
/// finite lattice guarantees termination, and the scanner's round cap is a hard
/// backstop against mutually-recursive helpers.
///
/// # Taint-sensitivity note
///
/// The Kotlin engine's tainted-name set ([`build_tainted_set`]) is add-only —
/// it does not model clean reassignment (Kotlin params are `val`) or
/// sanitizers (the built-in Kotlin rules ship none). Composition is therefore
/// taint-sensitive by *value*: a middle helper that forwards its parameter into
/// a cross-file sink composes the flow, while one that passes a clean constant
/// (a fresh non-tainted local) does not.
pub fn compose_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    _aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
    same_package_paths: &[PathBuf],
    summaries: &CrossFileSummaryMap,
    allowed_rule_ids: &HashSet<String>,
) -> Vec<FunctionTaintSummary> {
    let cross_file = CrossFileInfo {
        same_package_paths,
        summaries,
        allowed_rule_ids,
    };

    let mut out = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() != "function_declaration" {
            return;
        }
        let Some(name) = kotlin_function_name(node, src) else {
            return;
        };
        let param_names = kotlin_function_param_names(node, src);
        if let Some(summary) =
            compose_kotlin_function(node, name, &param_names, src, rule_specs, &cross_file)
        {
            out.push(summary);
        }
    });
    out
}

/// Compose one function's cross-file `params_to_sink` flows: seed each parameter
/// as a source, build the tainted-name set, and record a flow whenever a tainted
/// argument reaches a sibling helper's recorded sink. Returns `None` when no
/// parameter reaches a cross-file sink.
fn compose_kotlin_function(
    func_node: Node<'_>,
    func_name: &str,
    param_names: &[String],
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Option<FunctionTaintSummary> {
    if param_names.is_empty() {
        return None;
    }
    let body = find_function_body(func_node).unwrap_or(func_node);

    // Sanitizers are unioned for parity with the other engines; the built-in
    // Kotlin rules ship none and the tainted-set does not consult them.
    let mut sanitizers = Vec::new();
    for (_, rule_spec) in rule_specs {
        sanitizers.extend(rule_spec.sanitizers.iter().cloned());
    }

    let mut params_to_sink: Vec<ParamSinkFlow> = Vec::new();
    for (param_idx, param_name) in param_names.iter().enumerate() {
        let synthetic = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec![param_name.clone()],
                description: format!("parameter '{param_name}'"),
            }],
            sinks: vec![],
            sanitizers: sanitizers.clone(),
        };

        let mut sources = collect_body_sources(body, source, &synthetic);
        collect_param_sources(func_node, source, &synthetic, &mut sources);
        let tainted = build_tainted_set(body, source, &sources);
        if tainted.is_empty() {
            continue;
        }

        walk_tree(body, source, &mut |node, src| {
            if node.kind() != "call_expression" {
                return;
            }
            let Some(callee) = call_callee_name(node, src) else {
                return;
            };
            let Some(summary) = lookup_cross_file_summary(cross_file, callee) else {
                return;
            };
            let Some(args) = call_arguments(node) else {
                return;
            };
            let arg_nodes: Vec<Node<'_>> = {
                let mut cursor = args.walk();
                let mut v = Vec::new();
                for child in args.children(&mut cursor) {
                    if child.kind() == "value_argument" {
                        if let Some(expr) = child.child(0) {
                            v.push(expr);
                        }
                    }
                }
                v
            };

            for flow in &summary.params_to_sink {
                if !cross_file.allowed_rule_ids.contains(&flow.sink_rule_id) {
                    continue;
                }
                if flow.param_index >= arg_nodes.len() {
                    continue;
                }
                let arg = arg_nodes[flow.param_index];
                if caller_arg_taint(arg, src, &sources, &tainted, &synthetic).is_none() {
                    continue;
                }
                let dup = params_to_sink
                    .iter()
                    .any(|f| f.param_index == param_idx && f.sink_rule_id == flow.sink_rule_id);
                if !dup {
                    params_to_sink.push(ParamSinkFlow {
                        param_index: param_idx,
                        sink_rule_id: flow.sink_rule_id.clone(),
                        sink_description: flow.sink_description.clone(),
                    });
                }
            }
        });
    }

    if params_to_sink.is_empty() {
        return None;
    }
    Some(FunctionTaintSummary {
        name: func_name.to_string(),
        params_to_return: Vec::new(),
        params_to_sink,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn analyze(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Kotlin).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    #[test]
    fn sql_injection_via_ktor_receive() {
        let src = r#"
fun Application.module() {
    routing {
        post("/users") {
            val body = call.receiveText()
            val query = "SELECT * FROM users WHERE name = '" + body + "'"
            db.executeQuery(query)
        }
    }
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect tainted SQL via call.receiveText(): {:?}",
            findings
        );
    }

    #[test]
    fn command_injection_via_request_param() {
        let src = r#"
@PostMapping("/exec")
fun execute(@RequestBody input: String) {
    val args = input.split(" ")
    ProcessBuilder(args).start()
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect tainted ProcessBuilder via @RequestBody: {:?}",
            findings
        );
    }

    #[test]
    fn ssrf_transitive_flow() {
        let src = r#"
fun Application.module() {
    routing {
        post("/fetch") {
            val body = call.receiveText()
            val target = body
            val endpoint = "https://internal/" + target
            val url = URL(endpoint)
        }
    }
}
"#;
        let findings = analyze(src, &ssrf_spec());
        assert!(
            !findings.is_empty(),
            "should detect SSRF via transitive flow: {:?}",
            findings
        );
    }

    #[test]
    fn clean_literal_no_finding() {
        let src = r#"
fun handler(call: ApplicationCall) {
    val data = call.receiveText()
    Runtime.getRuntime().exec("ls -la")
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            findings.is_empty(),
            "literal command should not trigger taint: {:?}",
            findings
        );
    }

    #[test]
    fn prepared_statement_with_binding_is_clean() {
        // Tainted value bound via setString to a placeholder is safe; the
        // prepareStatement SQL string itself is a constant literal.
        let src = r#"
fun handler(call: ApplicationCall, conn: Connection) {
    val id = call.request.queryParameters["id"]
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, id)
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            findings.is_empty(),
            "parameterized prepared statement should not flag: {:?}",
            findings
        );
    }

    #[test]
    fn prepared_statement_with_tainted_sql_flags() {
        // Tainted value concatenated directly into the SQL string passed to
        // prepareStatement must still flag.
        let src = r#"
fun handler(call: ApplicationCall, conn: Connection) {
    val id = call.request.queryParameters["id"]
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = " + id)
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "tainted SQL in prepareStatement should flag: {:?}",
            findings
        );
    }

    // ── Cross-file (pass 1) summaries ─────────────────────────────────────

    fn summaries(src: &str) -> Vec<FunctionTaintSummary> {
        let tree = parse_file(src, Language::Kotlin).expect("parse");
        let specs = kotlin_taint_rule_specs();
        extract_cross_file_summaries(tree.root_node(), src, None, &specs)
    }

    #[test]
    fn cross_file_summary_records_param_to_sink() {
        let src = r#"
object CommandHelper {
    fun run(term: String) {
        Runtime.getRuntime().exec(term)
    }
}
"#;
        let found = summaries(src);
        let helper = found
            .iter()
            .find(|s| s.name == "run")
            .expect("run should be summarized");
        let flow = helper
            .params_to_sink
            .iter()
            .find(|f| f.param_index == 0)
            .expect("param 0 should reach a sink");
        assert_eq!(flow.sink_rule_id, "kt/taint-command-injection");
    }

    #[test]
    fn cross_file_summary_skips_functions_with_no_flow() {
        // `log` neither sinks nor returns its parameter, so it must not be
        // summarized at all.
        let src = r#"
object Plain {
    fun log(message: String) {
        println("constant")
    }
}
"#;
        let found = summaries(src);
        assert!(
            found.iter().all(|s| s.name != "log"),
            "function with no param flow should not be summarized: {found:?}"
        );
    }

    #[test]
    fn cross_file_findings_resolve_helper_call() {
        // Caller passes a tainted local into a same-package helper whose
        // parameter reaches a command sink; the call site must produce a
        // cross-file finding.
        let helper_src = r#"
object CommandHelper {
    fun run(term: String) {
        Runtime.getRuntime().exec(term)
    }
}
"#;
        let caller_src = r#"
fun handle(call: ApplicationCall) {
    val cmd = call.receiveText()
    CommandHelper.run(cmd)
}
"#;
        let specs = kotlin_taint_rule_specs();
        let helper_tree = parse_file(helper_src, Language::Kotlin).expect("parse helper");
        let helper_summaries =
            extract_cross_file_summaries(helper_tree.root_node(), helper_src, None, &specs);
        let helper_path = PathBuf::from("CommandHelper.kt");
        let mut summary_map = CrossFileSummaryMap::new();
        summary_map.insert(helper_path.clone(), helper_summaries);

        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let paths = vec![helper_path];
        let cross = CrossFileInfo {
            same_package_paths: &paths,
            summaries: &summary_map,
            allowed_rule_ids: &allowed,
        };
        let caller_tree = parse_file(caller_src, Language::Kotlin).expect("parse caller");
        let findings =
            extract_cross_file_findings(caller_tree.root_node(), caller_src, &specs, &cross);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one cross-file finding: {findings:?}"
        );
        assert_eq!(
            findings[0].rule_id_hint.as_deref(),
            Some("kt/taint-command-injection")
        );
        assert!(findings[0]
            .sink_description
            .contains("via cross-file call to run"));
    }

    // ── bounded multi-hop composition ────────────────────────────────────

    const COMPOSE_SINK_SRC: &str = r#"
fun runQuery(term: String) {
    db.executeQuery("SELECT * FROM users WHERE name = '" + term + "'")
}
"#;

    #[test]
    fn compose_lifts_forwarded_param_to_cross_file_sink() {
        // Middle helper `forward` forwards its parameter into a same-directory
        // helper `runQuery` that sinks it; composing against `runQuery`'s
        // summary must lift the cross-file sink into `forward`'s params_to_sink.
        let middle_src = r#"
fun forward(term: String) {
    runQuery(term)
}
"#;
        let specs = kotlin_taint_rule_specs();
        let sink_tree = parse_file(COMPOSE_SINK_SRC, Language::Kotlin).expect("parse sink");
        let sink_path = PathBuf::from("QueryHelper.kt");
        let mut map = CrossFileSummaryMap::new();
        map.insert(
            sink_path.clone(),
            extract_cross_file_summaries(sink_tree.root_node(), COMPOSE_SINK_SRC, None, &specs),
        );

        let mid_tree = parse_file(middle_src, Language::Kotlin).expect("parse mid");
        assert!(
            extract_cross_file_summaries(mid_tree.root_node(), middle_src, None, &specs)
                .iter()
                .find(|s| s.name == "forward")
                .is_none_or(|s| s.params_to_sink.is_empty()),
            "base summary of forward must not record a sink flow"
        );

        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let composed = compose_cross_file_summaries(
            mid_tree.root_node(),
            middle_src,
            None,
            &specs,
            std::slice::from_ref(&sink_path),
            &map,
            &allowed,
        );
        let forward = composed
            .iter()
            .find(|s| s.name == "forward")
            .expect("forward should gain a composed summary");
        assert!(
            forward
                .params_to_sink
                .iter()
                .any(|f| f.param_index == 0 && f.sink_rule_id == "kt/taint-sql-injection"),
            "param 0 should reach the cross-file sink: {forward:?}"
        );
    }

    #[test]
    fn compose_is_taint_sensitive_across_the_hop() {
        // The middle helper passes a clean constant to the cross-file call, so
        // the composed summary must NOT record a sink flow.
        let middle_src = r#"
fun forward(term: String) {
    val safe = "constant"
    runQuery(safe)
}
"#;
        let specs = kotlin_taint_rule_specs();
        let sink_tree = parse_file(COMPOSE_SINK_SRC, Language::Kotlin).expect("parse sink");
        let sink_path = PathBuf::from("QueryHelper.kt");
        let mut map = CrossFileSummaryMap::new();
        map.insert(
            sink_path.clone(),
            extract_cross_file_summaries(sink_tree.root_node(), COMPOSE_SINK_SRC, None, &specs),
        );

        let mid_tree = parse_file(middle_src, Language::Kotlin).expect("parse mid");
        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let composed = compose_cross_file_summaries(
            mid_tree.root_node(),
            middle_src,
            None,
            &specs,
            std::slice::from_ref(&sink_path),
            &map,
            &allowed,
        );
        assert!(
            composed.iter().all(|s| s.params_to_sink.is_empty()),
            "a clean (constant) argument must not compose a sink flow: {composed:?}"
        );
    }
}
