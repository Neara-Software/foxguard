//! Intraprocedural, flow-insensitive taint analysis for Java.
//!
//! Java is the next enterprise-heavy language after the existing
//! Python, JavaScript/TypeScript, Go, Kotlin, and C engines. This engine
//! intentionally mirrors the Kotlin implementation shape: grammar-specific
//! source/sink matching stays local, while the public surface reuses the
//! shared `TaintSpec`, `NodeMatcher`, and `TaintFinding` types.
//!
//! Scope:
//! - Per method / constructor / lambda body. Nested lambdas are analyzed
//!   independently and skipped by their parent scope.
//! - Per file. No Java cross-file or type-resolution pass yet.
//! - Flow-insensitive within source order. Clean reassignment clears a name.
//! - String concatenation, method calls on tainted receivers, constructor
//!   wrappers, and direct nested source calls propagate taint.
//! - Sanitizer calls listed on the `TaintSpec` produce clean values.

use crate::rules::common::{walk_tree, AliasTable};
use crate::rules::cross_file::{CrossFileSummaryMap, FunctionTaintSummary, ParamSinkFlow};
use crate::rules::taint_engine::cross_file_taint_finding;
pub use crate::rules::taint_engine::{NodeMatcher, Propagator, TaintFinding, TaintSpec};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tree_sitter::Node;

#[derive(Clone, Debug)]
struct TaintInfo {
    description: String,
    line: usize,
    hops: u8,
}

#[derive(Default)]
struct TaintState {
    tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    fn taint(&mut self, name: String, info: TaintInfo) {
        self.tainted.insert(name, info);
    }

    fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

/// Run the Java taint engine over every method, constructor, and lambda
/// inside `root`.
///
/// The alias table parameter is reserved for future import-aware Java
/// matching. Java source/sink specs today match simple receiver and type
/// names because the built-in rules target common servlet and Spring shapes.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    analyze_tree_with_propagators(root, source, spec, aliases, &[])
}

/// Like [`analyze_tree`] but also applies a list of taint [`Propagator`]s
/// during each function's walk. Used by the Semgrep YAML bridge to honor
/// `pattern-propagators` (e.g. `(StringBuilder $SB).append($X)`); the built-in
/// Java rules call [`analyze_tree`] with no propagators.
pub fn analyze_tree_with_propagators(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
    propagators: &[Propagator],
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
            analyze_scope(node, src, spec, propagators, &mut findings);
        }
    });
    findings
}

/// All Java taint rule IDs paired with their specs.
pub fn java_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("java/taint-sql-injection", sql_injection_spec()),
        ("java/taint-command-injection", command_injection_spec()),
        ("java/taint-ssrf", ssrf_spec()),
        (
            "java/taint-unsafe-deserialization",
            unsafe_deserialization_spec(),
        ),
    ]
}

/// Shared sources for Java taint rules.
///
/// Covers servlet request reads, Spring MVC annotated handler parameters,
/// and environment variables for CLI/service entry points.
pub fn java_taint_sources() -> Vec<NodeMatcher> {
    let mut sources = Vec::new();
    for receiver in ["request", "req"] {
        for method in [
            "getParameter",
            "getParameterMap",
            "getParameterValues",
            "getHeader",
            "getHeaders",
            "getQueryString",
            "getInputStream",
            "getReader",
            "getCookies",
        ] {
            sources.push(NodeMatcher::Call {
                canonical: format!("{receiver}.{method}"),
                description: format!("HttpServletRequest.{method}()"),
            });
        }
    }
    sources.push(NodeMatcher::Call {
        canonical: "System.getenv".into(),
        description: "System.getenv()".into(),
    });
    sources.push(NodeMatcher::ParamName {
        names: vec![
            "@RequestParam".into(),
            "@RequestBody".into(),
            "@PathVariable".into(),
            "@RequestHeader".into(),
            "@CookieValue".into(),
            "@ModelAttribute".into(),
        ],
        description: "Spring MVC annotated parameter".into(),
    });
    sources
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::MethodName {
                method: "executeQuery".into(),
                description: "executeQuery() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "execute".into(),
                description: "execute() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "createQuery".into(),
                description: "createQuery() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "createNativeQuery".into(),
                description: "createNativeQuery() with tainted query".into(),
            },
            NodeMatcher::MethodName {
                method: "prepareStatement".into(),
                description: "prepareStatement() with tainted query".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
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
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "URL".into(),
                description: "URL() with tainted target".into(),
            },
            NodeMatcher::Call {
                canonical: "URI".into(),
                description: "URI() with tainted target".into(),
            },
            NodeMatcher::MethodName {
                method: "getForObject".into(),
                description: "RestTemplate.getForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "getForEntity".into(),
                description: "RestTemplate.getForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForObject".into(),
                description: "RestTemplate.postForObject() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "postForEntity".into(),
                description: "RestTemplate.postForEntity() with tainted URL".into(),
            },
            NodeMatcher::MethodName {
                method: "exchange".into(),
                description: "RestTemplate.exchange() with tainted URL".into(),
            },
        ],
        sanitizers: vec![],
    }
}

fn unsafe_deserialization_spec() -> TaintSpec {
    TaintSpec {
        sources: java_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "ObjectInputStream".into(),
                description: "ObjectInputStream() with tainted stream".into(),
            },
            NodeMatcher::Call {
                canonical: "XMLDecoder".into(),
                description: "XMLDecoder() with tainted stream".into(),
            },
            NodeMatcher::MethodName {
                method: "load".into(),
                description: "Yaml.load() with tainted data".into(),
            },
        ],
        sanitizers: vec![],
    }
}

// ─── Cross-file (interprocedural across files) taint ─────────────────────
//
// Scope of the Java cross-file pass (deliberately narrow; see
// `docs/taint-tracking.md`):
//
// * **Resolution is NAME-based, not type-based.** A method declaration is
//   summarized by its bare method name. A call site resolves to a summary
//   whenever the invoked method name matches a summarized method in a
//   sibling file of the same directory (used as a same-package proxy, the
//   way the Go engine treats same-directory `.go` files). This intentionally
//   over-approximates: `helper.process(x)`, `Helper.process(x)`, and a bare
//   `process(x)` all resolve to *any* same-package `process` summary,
//   regardless of the receiver's declared type.
// * **What is NOT modeled:** instance-method dispatch through interfaces or
//   subclasses, method overloads (same name, different arity/types — only
//   arity is checked via the argument count), `import`-based class resolution
//   across packages/directories, and multi-hop chains (a helper that itself
//   calls another cross-file helper). These need a Java type/symbol table the
//   engine does not build.

/// Extract cross-file taint summaries for every method declaration in `root`.
///
/// Pass 1 of the two-pass scanner. For each method, every parameter is
/// treated as a synthetic taint source; a parameter that reaches a sink
/// records a [`ParamSinkFlow`], and a parameter that flows to a `return`
/// records a `params_to_return` index. Summaries are keyed by the bare
/// method name (last-write-wins on name collisions, mirroring Go).
pub fn extract_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    _aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Vec<FunctionTaintSummary> {
    let mut summaries = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() != "method_declaration" {
            return;
        }
        let Some(method_name) = node
            .child_by_field_name("name")
            .map(|n| node_text(n, src).to_string())
        else {
            return;
        };
        let param_names = method_param_names(node, src);
        if let Some(summary) =
            summarize_java_method(node, &method_name, &param_names, src, rule_specs)
        {
            summaries.push(summary);
        }
    });
    summaries
}

/// The parameter names of a method/constructor/lambda scope, in order.
fn method_param_names(scope_node: Node<'_>, source: &str) -> Vec<String> {
    scope_parameter_nodes(scope_node)
        .into_iter()
        .filter_map(|node| formal_parameter_name(node, source).map(|s| s.to_string()))
        .collect()
}

/// Build a [`FunctionTaintSummary`] for a single method, or `None` if no
/// parameter reaches a sink or a return value.
fn summarize_java_method(
    method_node: Node<'_>,
    method_name: &str,
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
        if java_param_flows_to_return(method_node, param_name, source) {
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
            analyze_scope(method_node, source, &synthetic, &[], &mut findings);
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
        name: method_name.to_string(),
        params_to_return,
        params_to_sink,
    })
}

/// Does `param_name`, treated as a taint source, reach a `return` statement?
fn java_param_flows_to_return(method_node: Node<'_>, param_name: &str, source: &str) -> bool {
    let synthetic = TaintSpec {
        sources: vec![NodeMatcher::ParamName {
            names: vec![param_name.to_string()],
            description: format!("parameter '{param_name}'"),
        }],
        sinks: vec![],
        sanitizers: vec![],
    };
    let body = find_scope_body(method_node).unwrap_or(method_node);
    let mut state = TaintState::default();
    collect_param_sources(method_node, source, &synthetic, &mut state);
    for _ in 0..3 {
        propagate_assignments(body, source, &synthetic, &mut state);
    }

    let mut flows = false;
    walk_scope_nodes(body, source, &mut |node, src| {
        if flows || node.kind() != "return_statement" {
            return;
        }
        if let Some(expr) = node.named_child(0) {
            if expression_taint(expr, src, &synthetic, &state).is_some() {
                flows = true;
            }
        }
    });
    flows
}

/// Cross-file resolution info for the Java engine.
///
/// `same_package_paths` are the canonical paths of sibling Java files in the
/// same directory (the same-package proxy); `summaries` is the pass-1 map
/// keyed by canonical path; `allowed_rule_ids` gates which rules may emit
/// cross-file findings in the current run.
pub struct CrossFileInfo<'a> {
    pub same_package_paths: &'a [PathBuf],
    pub summaries: &'a CrossFileSummaryMap,
    pub allowed_rule_ids: &'a HashSet<String>,
}

/// Pass 2 cross-file resolution: walk every scope, compute its intra-file
/// taint state, and for each helper-method call that resolves to a sibling
/// summary, emit a finding when a tainted argument lands on a parameter with
/// a recorded sink flow.
///
/// Returns findings whose `rule_id_hint` carries the attributed rule id.
pub fn extract_cross_file_findings(
    root: Node<'_>,
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Vec<TaintFinding> {
    // The caller-side taint state is driven by the real sources (shared
    // across the built-in Java rules); union them so an inline source
    // argument like `helper(request.getParameter("x"))` is recognized.
    let mut source_spec = TaintSpec::default();
    for (_, spec) in rule_specs {
        source_spec.sources.extend(spec.sources.iter().cloned());
        source_spec
            .sanitizers
            .extend(spec.sanitizers.iter().cloned());
    }

    let mut out = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
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
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();
    collect_param_sources(scope_node, source, source_spec, &mut state);
    for _ in 0..3 {
        propagate_assignments(body, source, source_spec, &mut state);
    }

    walk_scope_nodes(body, source, &mut |node, src| {
        if node.kind() != "method_invocation" {
            return;
        }
        let Some(method_name) = call_method_name(node, src) else {
            return;
        };
        let Some(summary) = lookup_cross_file_summary(cross_file, method_name) else {
            return;
        };
        let Some(args) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = args.walk();
        let arg_nodes: Vec<Node<'_>> = args.named_children(&mut cursor).collect();

        for flow in &summary.params_to_sink {
            if !cross_file.allowed_rule_ids.contains(&flow.sink_rule_id) {
                continue;
            }
            if flow.param_index >= arg_nodes.len() {
                continue;
            }
            let arg = arg_nodes[flow.param_index];
            if let Some(info) = expression_taint(arg, src, source_spec, &state) {
                out.push(cross_file_taint_finding(
                    node,
                    info.description,
                    info.line,
                    &flow.sink_description,
                    method_name,
                    &flow.sink_rule_id,
                ));
            }
        }
    });
}

fn lookup_cross_file_summary<'a>(
    cross_file: &'a CrossFileInfo<'_>,
    method_name: &str,
) -> Option<&'a FunctionTaintSummary> {
    for path in cross_file.same_package_paths {
        if let Some(file_summaries) = cross_file.summaries.get(path) {
            if let Some(summary) = file_summaries.iter().find(|s| s.name == method_name) {
                return Some(summary);
            }
        }
    }
    None
}

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    propagators: &[Propagator],
    out: &mut Vec<TaintFinding>,
) {
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();
    collect_param_sources(scope_node, source, spec, &mut state);

    // Three passes cover the common `source -> local -> derived -> sink`
    // chain without adding a fixed-point loop to this deliberately small
    // intraprocedural engine. Propagators run inside the loop so a chain like
    // `source -> local -> sb.append(local) -> stmt.execute(sb.toString())`
    // resolves as taint flows through the body.
    for _ in 0..3 {
        propagate_assignments(body, source, spec, &mut state);
        apply_propagators(body, source, spec, propagators, &mut state);
    }
    find_sinks(body, source, spec, &state, out);
}

/// Apply "argument taints receiver" [`Propagator`]s: for each
/// `receiver.method(args)` call whose method matches a propagator and one of
/// whose arguments is tainted, mark the receiver variable tainted.
///
/// Confined to the tractable subset: the receiver must be a plain identifier
/// (`sb.append(x)`), not a nested member/index expression, so we never
/// over-taint a whole receiver chain. New taint is collected during the walk
/// and applied afterward to keep the read/write phases separate.
fn apply_propagators(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    propagators: &[Propagator],
    state: &mut TaintState,
) {
    if propagators.is_empty() {
        return;
    }
    let mut pending: Vec<(String, TaintInfo)> = Vec::new();
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() != "method_invocation" {
            return;
        }
        let Some(recv) = node.child_by_field_name("object") else {
            return;
        };
        if recv.kind() != "identifier" {
            return;
        }
        let Some(method) = call_method_name(node, src) else {
            return;
        };
        let method_matches = propagators
            .iter()
            .any(|p| p.method.as_deref().is_none_or(|m| m == method));
        if !method_matches {
            return;
        }
        let recv_name = node_text(recv, src);
        // Already tainted — keep the existing (earlier/better) taint info.
        if state.info(recv_name).is_some() {
            return;
        }
        if let Some(info) = sink_argument_taint(node, src, spec, state) {
            pending.push((recv_name.to_string(), bump_hops(info)));
        }
    });
    for (name, info) in pending {
        state.taint(name, info);
    }
}

fn collect_param_sources(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
) {
    let mut annotation_names: Vec<&str> = Vec::new();
    let mut bare_names: Vec<&str> = Vec::new();
    // `$`-prefixed name (`$PARAM`) is the any-parameter wildcard compiled from a
    // Semgrep `pattern-inside: function(...,$ARG,...) + focus-metavariable: $ARG`
    // source block: seed *every* parameter of the enclosing scope.
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

    for node in scope_parameter_nodes(scope_node) {
        let Some(name) = formal_parameter_name(node, source) else {
            continue;
        };
        let text = node_text(node, source);
        let matched_annotation = annotation_names
            .iter()
            .find(|annotation| text.contains(&format!("@{annotation}")));

        // Typed-metavariable source `(HttpServletRequest $REQ)`: seed the
        // parameter when its DECLARED TYPE matches, regardless of name.
        let typed_desc = formal_parameter_type(node, source)
            .and_then(|ty| typed_source_description(spec, ty).map(|d| (d, name)));

        if let Some(annotation) = matched_annotation {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("@{annotation} parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                },
            );
        } else if let Some((description, name)) = typed_desc {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description,
                    line: node.start_position().row + 1,
                    hops: 0,
                },
            );
        } else if bare_names.contains(&name) || wildcard {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("parameter '{name}'"),
                    line: node.start_position().row + 1,
                    hops: 0,
                },
            );
        }
    }
}

fn propagate_assignments(scope: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() == "variable_declarator" {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, src).to_string();
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            match expression_taint(value, src, spec, state) {
                Some(info) => state.taint(name, bump_hops(info)),
                None => {
                    // Typed-metavariable source `(HttpServletRequest $REQ)`
                    // applied to a local: `HttpServletRequest req = ...;`
                    // seeds `req` by its DECLARED TYPE even when the
                    // initializer is not itself tainted. Re-applied every
                    // propagation pass, so it survives the clean-reassignment
                    // clear above.
                    match local_declarator_type(node, src)
                        .and_then(|ty| typed_source_description(spec, ty))
                    {
                        Some(description) => state.taint(
                            name,
                            TaintInfo {
                                description,
                                line: node.start_position().row + 1,
                                hops: 0,
                            },
                        ),
                        None => state.clear(&name),
                    }
                }
            }
        }

        if node.kind() == "assignment_expression" {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(name) = assignment_target_name(left, src) else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            match expression_taint(right, src, spec, state) {
                Some(info) => state.taint(name.to_string(), bump_hops(info)),
                None => state.clear(name),
            }
        }
    });
}

fn find_sinks(
    scope: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
    out: &mut Vec<TaintFinding>,
) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        if node.kind() != "method_invocation" && node.kind() != "object_creation_expression" {
            return;
        }
        let Some(sink_description) = match_sink(node, src, spec) else {
            return;
        };
        let taint = sink_argument_taint(node, src, spec, state)
            .or_else(|| read_object_receiver_taint(node, src, state));
        if let Some(info) = taint {
            out.push(taint_finding_for_node(node, info, sink_description));
        }
    });
}

fn expression_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }

    if node.kind() == "identifier" {
        return state.info(text).cloned();
    }

    if is_sanitizer_call(node, source, spec) {
        return None;
    }

    if let Some(description) = classify_source_expr(node, source, spec) {
        return Some(TaintInfo {
            description,
            line: node.start_position().row + 1,
            hops: 0,
        });
    }

    if node.kind() == "method_invocation" {
        if let Some(receiver) = node.child_by_field_name("object") {
            if let Some(info) = expression_taint(receiver, source, spec, state) {
                return Some(bump_hops(info));
            }
        }
    }

    if let Some(args) = call_arguments(node) {
        if let Some(info) = expression_taint(args, source, spec, state) {
            return Some(bump_hops(info));
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint(child, source, spec, state) {
            return Some(info);
        }
    }
    None
}

fn classify_source_expr(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    if node.kind() != "method_invocation" {
        return None;
    }
    let method = call_method_name(node, source)?;
    let receiver = call_receiver_text(node, source)?;
    spec.sources.iter().find_map(|matcher| {
        if let NodeMatcher::Call {
            canonical,
            description,
        } = matcher
        {
            if match_java_method_canonical(canonical, receiver, method) {
                return Some(description.clone());
            }
        }
        None
    })
}

fn is_sanitizer_call(node: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    spec.sanitizers
        .iter()
        .any(|matcher| matcher_matches_call(matcher, node, source))
}

fn match_sink(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|matcher| {
        if matcher_matches_call(matcher, node, source) {
            Some(matcher.description().to_string())
        } else {
            None
        }
    })
}

fn matcher_matches_call(matcher: &NodeMatcher, node: Node<'_>, source: &str) -> bool {
    match matcher {
        NodeMatcher::MethodName { method, .. } => {
            node.kind() == "method_invocation"
                && call_method_name(node, source).is_some_and(|actual| actual == method)
        }
        NodeMatcher::Call { canonical, .. } if node.kind() == "method_invocation" => {
            let Some(method) = call_method_name(node, source) else {
                return false;
            };
            let Some(receiver) = call_receiver_text(node, source) else {
                return false;
            };
            match_java_method_canonical(canonical, receiver, method)
        }
        NodeMatcher::Call { canonical, .. } if node.kind() == "object_creation_expression" => {
            object_creation_type(node, source).is_some_and(|actual| actual == canonical)
        }
        _ => false,
    }
}

fn match_java_method_canonical(canonical: &str, receiver: &str, method: &str) -> bool {
    let Some((expected_receiver, expected_method)) = canonical.rsplit_once('.') else {
        return false;
    };
    if method != expected_method {
        return false;
    }
    let receiver_lower = receiver.to_ascii_lowercase();
    let expected_lower = expected_receiver.to_ascii_lowercase();
    receiver_lower.contains(&expected_lower)
        || (expected_lower == "request" && receiver_lower.contains("request"))
        || (expected_lower == "runtime" && receiver_lower.contains("runtime"))
}

fn sink_argument_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    call_arguments(node).and_then(|args| expression_taint(args, source, spec, state))
}

fn read_object_receiver_taint(
    node: Node<'_>,
    source: &str,
    state: &TaintState,
) -> Option<TaintInfo> {
    if node.kind() != "method_invocation" {
        return None;
    }
    if call_method_name(node, source) != Some("readObject") {
        return None;
    }
    let receiver = node.child_by_field_name("object")?;
    expression_taint_without_sources(receiver, source, state)
}

fn expression_taint_without_sources(
    node: Node<'_>,
    source: &str,
    state: &TaintState,
) -> Option<TaintInfo> {
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint_without_sources(child, source, state) {
            return Some(info);
        }
    }
    None
}

fn bump_hops(mut info: TaintInfo) -> TaintInfo {
    info.hops = info.hops.saturating_add(1);
    info
}

fn taint_finding_for_node(
    node: Node<'_>,
    source_info: TaintInfo,
    sink_description: String,
) -> TaintFinding {
    let start = node.start_position();
    let end = node.end_position();
    TaintFinding {
        sink_start_byte: node.start_byte(),
        sink_end_byte: node.end_byte(),
        sink_line: start.row + 1,
        sink_column: start.column + 1,
        sink_end_line: end.row + 1,
        sink_end_column: end.column + 1,
        source_description: source_info.description,
        sink_description,
        source_line: source_info.line,
        rule_id_hint: None,
        hops: source_info.hops.max(1),
    }
}

fn walk_scope_nodes(scope: Node<'_>, source: &str, visitor: &mut impl FnMut(Node<'_>, &str)) {
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        walk_scope_node(child, source, visitor);
    }
}

fn walk_scope_node(node: Node<'_>, source: &str, visitor: &mut impl FnMut(Node<'_>, &str)) {
    if is_scope_node(node.kind()) {
        return;
    }
    visitor(node, source);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_scope_node(child, source, visitor);
    }
}

fn is_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration" | "constructor_declaration" | "lambda_expression"
    )
}

fn scope_parameter_nodes<'a>(scope_node: Node<'a>) -> Vec<Node<'a>> {
    if let Some(parameters) = scope_node.child_by_field_name("parameters") {
        return direct_formal_parameters(parameters);
    }

    let mut params = Vec::new();
    let mut cursor = scope_node.walk();
    for child in scope_node.children(&mut cursor) {
        match child.kind() {
            "formal_parameter" | "spread_parameter" => params.push(child),
            "formal_parameters" | "inferred_parameters" => {
                params.extend(direct_formal_parameters(child));
            }
            _ => {}
        }
    }
    params
}

fn direct_formal_parameters<'a>(parameters: Node<'a>) -> Vec<Node<'a>> {
    let mut params = Vec::new();
    let mut cursor = parameters.walk();
    for child in parameters.children(&mut cursor) {
        match child.kind() {
            "formal_parameter" | "spread_parameter" => params.push(child),
            "formal_parameters" | "inferred_parameters" => {
                params.extend(direct_formal_parameters(child));
            }
            _ => {}
        }
    }
    params
}

fn find_scope_body(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("body").or_else(|| {
        let mut cursor = node.walk();
        let body = node
            .children(&mut cursor)
            .find(|child| child.kind() == "block");
        body
    })
}

fn call_method_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("name")
        .map(|name| node_text(name, source))
}

fn call_receiver_text<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "method_invocation" {
        return None;
    }
    node.child_by_field_name("object")
        .map(|object| node_text(object, source))
}

fn object_creation_type<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "object_creation_expression" {
        return None;
    }
    node.child_by_field_name("type")
        .map(|ty| node_text(ty, source))
}

fn call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_invocation" && node.kind() != "object_creation_expression" {
        return None;
    }
    node.child_by_field_name("arguments")
}

fn assignment_target_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "field_access" => Some(node_text(node, source)),
        _ => None,
    }
}

fn formal_parameter_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(node_text(name, source));
    }
    let mut last_identifier = None;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            last_identifier = Some(node_text(child, source));
        }
    }
    last_identifier
}

/// The declared type text of a `formal_parameter` / `spread_parameter`, e.g.
/// `HttpServletRequest`, `javax.servlet.http.HttpServletRequest`, `String[]`.
fn formal_parameter_type<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("type")
        .map(|ty| node_text(ty, source))
}

/// The declared type text of the `local_variable_declaration` that owns a
/// `variable_declarator`, or `None` when the declarator is not a local (e.g.
/// a field). Used to seed typed-metavariable sources on locals.
fn local_declarator_type<'a>(declarator: Node<'a>, source: &'a str) -> Option<&'a str> {
    let parent = declarator.parent()?;
    if parent.kind() != "local_variable_declaration" {
        return None;
    }
    parent
        .child_by_field_name("type")
        .map(|ty| node_text(ty, source))
}

/// If `decl_type` matches a `TypedName` source in `spec` (by final `.`-segment,
/// so both `HttpServletRequest` and `javax.servlet.http.HttpServletRequest`
/// match `HttpServletRequest`), return that source's description.
fn typed_source_description(spec: &TaintSpec, decl_type: &str) -> Option<String> {
    let seg = type_final_segment(decl_type);
    spec.sources.iter().find_map(|matcher| match matcher {
        NodeMatcher::TypedName {
            type_name,
            description,
        } if type_name == seg => Some(description.clone()),
        _ => None,
    })
}

/// The final `.`-segment of a declared type, with array/generic suffixes
/// stripped: `javax.servlet.http.HttpServletRequest` and `HttpServletRequest`
/// both yield `HttpServletRequest`; `Cookie[]` yields `Cookie`.
fn type_final_segment(type_text: &str) -> &str {
    let mut base = type_text.trim();
    if base.ends_with('>') {
        if let Some(lt) = base.find('<') {
            base = base[..lt].trim_end();
        }
    }
    while let Some(stripped) = base.strip_suffix("[]") {
        base = stripped.trim_end();
    }
    base.rsplit('.').next().unwrap_or(base).trim()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn analyze(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let Some(tree) = parse_file(src, Language::Java) else {
            panic!("Java fixture should parse");
        };
        analyze_tree(tree.root_node(), src, spec, None)
    }

    #[test]
    fn sql_injection_via_spring_request_param() {
        let src = r#"
class Controller {
    void find(@RequestParam String name, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.executeQuery(query);
    }
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect Spring param into SQL: {findings:?}"
        );
    }

    #[test]
    fn command_injection_via_servlet_request() {
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect servlet request into Runtime.exec: {findings:?}"
        );
    }

    #[test]
    fn ssrf_transitive_flow() {
        let src = r#"
class Controller {
    void fetch(HttpServletRequest req) throws Exception {
        String raw = req.getParameter("url");
        String target = "https://internal/" + raw;
        new URL(target);
    }
}
"#;
        let findings = analyze(src, &ssrf_spec());
        assert!(
            !findings.is_empty(),
            "should detect transitive servlet SSRF: {findings:?}"
        );
    }

    #[test]
    fn unsafe_deserialization_constructor_sink() {
        let src = r#"
class Controller {
    void load(HttpServletRequest request) throws Exception {
        InputStream input = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(input);
        ois.readObject();
    }
}
"#;
        let findings = analyze(src, &unsafe_deserialization_spec());
        assert!(
            findings
                .iter()
                .any(|finding| finding.sink_description.contains("ObjectInputStream")),
            "should detect tainted ObjectInputStream constructor: {findings:?}"
        );
    }

    #[test]
    fn clean_literal_no_command_finding() {
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec("id");
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            findings.is_empty(),
            "literal command should not trigger taint: {findings:?}"
        );
    }

    fn summaries(src: &str) -> Vec<FunctionTaintSummary> {
        let Some(tree) = parse_file(src, Language::Java) else {
            panic!("Java fixture should parse");
        };
        let specs = java_taint_rule_specs();
        extract_cross_file_summaries(tree.root_node(), src, None, &specs)
    }

    #[test]
    fn cross_file_summary_records_param_to_sink() {
        let src = r#"
class QueryHelper {
    static Statement stmt;
    public static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
"#;
        let found = summaries(src);
        let helper = found
            .iter()
            .find(|s| s.name == "runQuery")
            .expect("runQuery should be summarized");
        let flow = helper
            .params_to_sink
            .iter()
            .find(|f| f.param_index == 0)
            .expect("param 0 should reach a sink");
        assert_eq!(flow.sink_rule_id, "java/taint-sql-injection");
    }

    #[test]
    fn cross_file_summary_records_param_to_return() {
        let src = r#"
class Passthrough {
    public static String clean(String value) {
        return value.trim();
    }
}
"#;
        let found = summaries(src);
        let helper = found
            .iter()
            .find(|s| s.name == "clean")
            .expect("clean should be summarized");
        assert!(
            helper.params_to_return.contains(&0),
            "param 0 should flow to the return value: {helper:?}"
        );
    }

    #[test]
    fn cross_file_summary_skips_methods_with_no_flow() {
        // `log` neither sinks nor returns its parameter, so it must not be
        // summarized at all.
        let src = r#"
class Plain {
    public static void log(String message) {
        System.out.println("constant");
    }
}
"#;
        let found = summaries(src);
        assert!(
            found.iter().all(|s| s.name != "log"),
            "method with no param flow should not be summarized: {found:?}"
        );
    }

    #[test]
    fn nested_lambda_parameter_does_not_taint_parent_scope() {
        let src = r#"
class Controller {
    private String name = "https://example.com";

    void fetch() throws Exception {
        Function<String, String> normalize = (@RequestParam String name) -> name.trim();
        new URL(name);
    }
}
"#;
        let findings = analyze(src, &ssrf_spec());
        assert!(
            findings.is_empty(),
            "nested lambda parameter should not taint parent scope: {findings:?}"
        );
    }
}
