//! Intraprocedural, flow-insensitive taint analysis for C#.
//!
//! Mirrors `java_taint.rs` in shape. C# is a statically-typed, OO language
//! with similar method-invocation AST structure. The tree-sitter-c-sharp
//! grammar uses different node kinds than Java; key ones used here:
//!
//! - `method_declaration` / `constructor_declaration` / `local_function_statement` —
//!   scope boundaries for intraprocedural analysis.
//! - `invocation_expression` — a method/function call; has `function` (callee)
//!   and `argument_list` children.
//! - `object_creation_expression` — `new SqlCommand(...)`, etc.; has `type`
//!   and `argument_list` children.
//! - `member_access_expression` — `Request.QueryString`, `Process.Start(...)`;
//!   has `expression` (receiver) and `name` children.
//! - `element_access_expression` — `Request.QueryString["key"]`; has
//!   `expression` and `subscript_argument_list` children.
//! - `assignment_expression` — `left = right`.
//! - `variable_declarator` — `string x = expr`.
//! - `binary_expression` — string concatenation `left + right`.
//!
//! # End-to-end correctness (bridge lesson from Ruby)
//!
//! The Semgrep bridge compiles a bare-identifier `pattern:` source to
//! `GenericMatcher::ParamName`. For C#, the primary sources are DOTTED
//! (`Request.QueryString`, `Request.Form`, `Console.ReadLine()`) so they
//! arrive as `Attribute` or `Call` matchers through the bridge. The engine
//! must match these in `match_source` against `member_access_expression` and
//! `invocation_expression` nodes respectively, not just as identifier
//! references. The bridge path therefore fires end-to-end on the real CLI.

use crate::rules::common::{walk_tree, AliasTable};
use crate::rules::cross_file::{CrossFileSummaryMap, FunctionTaintSummary, ParamSinkFlow};
use crate::rules::taint_engine::cross_file_taint_finding;
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tree_sitter::Node;

// ─── Internal taint state ─────────────────────────────────────────────────────

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

// ─── Public API ───────────────────────────────────────────────────────────────

/// Run the C# taint engine over every method, constructor, and local function
/// inside `root` and return one [`TaintFinding`] per source→sink flow.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if is_scope_node(node.kind()) {
            analyze_scope(node, src, spec, &mut findings);
        }
    });
    findings
}

// ─── Built-in specs ──────────────────────────────────────────────────────────

/// All C# taint rule IDs paired with their specs.
pub fn csharp_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("csharp/taint-sql-injection", sql_injection_spec()),
        ("csharp/taint-command-injection", command_injection_spec()),
        ("csharp/taint-xss", xss_spec()),
        ("csharp/taint-open-redirect", open_redirect_spec()),
        ("csharp/taint-xxe", xxe_spec()),
        ("csharp/taint-unsafe-load", unsafe_load_spec()),
    ]
}

/// Shared sources for C# taint rules — ASP.NET / System.Web request inputs.
pub fn csharp_taint_sources() -> Vec<NodeMatcher> {
    vec![
        // ─── ASP.NET classic (HttpRequest / HttpContext) ───────────────────
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "QueryString".into(),
            description: "Request.QueryString".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "Form".into(),
            description: "Request.Form".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "Params".into(),
            description: "Request.Params".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "Cookies".into(),
            description: "Request.Cookies".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "Headers".into(),
            description: "Request.Headers".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "RawUrl".into(),
            description: "Request.RawUrl".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "Url".into(),
            description: "Request.Url".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "Path".into(),
            description: "Request.Path".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "UserAgent".into(),
            description: "Request.UserAgent".into(),
        },
        NodeMatcher::Attribute {
            root: "Request".into(),
            field: "ServerVariables".into(),
            description: "Request.ServerVariables".into(),
        },
        NodeMatcher::Attribute {
            root: "HttpContext".into(),
            field: "Request".into(),
            description: "HttpContext.Request".into(),
        },
        // ─── Console / stdin ──────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "Console.ReadLine".into(),
            description: "Console.ReadLine()".into(),
        },
        NodeMatcher::Call {
            canonical: "Console.Read".into(),
            description: "Console.Read()".into(),
        },
        NodeMatcher::Call {
            canonical: "Console.ReadKey".into(),
            description: "Console.ReadKey()".into(),
        },
        // ─── Environment / CLI args ───────────────────────────────────────
        NodeMatcher::Call {
            canonical: "Environment.GetEnvironmentVariable".into(),
            description: "Environment.GetEnvironmentVariable()".into(),
        },
        NodeMatcher::Attribute {
            root: "Environment".into(),
            field: "GetCommandLineArgs".into(),
            description: "Environment.GetCommandLineArgs()".into(),
        },
    ]
}

/// Shared sanitizers for C# taint rules.
pub fn csharp_taint_sanitizers() -> Vec<NodeMatcher> {
    vec![
        // ─── HTML encoding ────────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "HttpUtility.HtmlEncode".into(),
            description: "HttpUtility.HtmlEncode".into(),
        },
        NodeMatcher::Call {
            canonical: "HttpUtility.HtmlAttributeEncode".into(),
            description: "HttpUtility.HtmlAttributeEncode".into(),
        },
        NodeMatcher::Call {
            canonical: "HttpUtility.UrlEncode".into(),
            description: "HttpUtility.UrlEncode".into(),
        },
        NodeMatcher::Call {
            canonical: "HtmlEncoder.Default.Encode".into(),
            description: "HtmlEncoder.Default.Encode".into(),
        },
        NodeMatcher::MethodName {
            method: "HtmlEncode".into(),
            description: "HtmlEncode".into(),
        },
        // ─── SQL parameterization ─────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "SqlParameter".into(),
            description: "SqlParameter (parameterized query)".into(),
        },
        // ─── Type conversion (taint-killing) ─────────────────────────────
        NodeMatcher::Call {
            canonical: "int.Parse".into(),
            description: "int.Parse (numeric conversion)".into(),
        },
        NodeMatcher::Call {
            canonical: "Convert.ToInt32".into(),
            description: "Convert.ToInt32 (numeric conversion)".into(),
        },
        NodeMatcher::Call {
            canonical: "Convert.ToInt64".into(),
            description: "Convert.ToInt64 (numeric conversion)".into(),
        },
        // ─── Path sanitizers ─────────────────────────────────────────────
        NodeMatcher::Call {
            canonical: "Path.GetFileName".into(),
            description: "Path.GetFileName (path sanitizer)".into(),
        },
        NodeMatcher::Call {
            canonical: "Path.GetFullPath".into(),
            description: "Path.GetFullPath (path canonicalization)".into(),
        },
    ]
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: csharp_taint_sources(),
        sinks: vec![
            // SqlCommand constructor with dynamic SQL
            NodeMatcher::Call {
                canonical: "SqlCommand".into(),
                description: "SqlCommand() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "OleDbCommand".into(),
                description: "OleDbCommand() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "MySqlCommand".into(),
                description: "MySqlCommand() with tainted query (SQL injection)".into(),
            },
            // Execute methods
            NodeMatcher::MethodName {
                method: "ExecuteReader".into(),
                description: "ExecuteReader() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "ExecuteNonQuery".into(),
                description: "ExecuteNonQuery() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "ExecuteScalar".into(),
                description: "ExecuteScalar() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "ExecuteXmlReader".into(),
                description: "ExecuteXmlReader() with tainted query (SQL injection)".into(),
            },
            // Entity Framework / Dapper
            NodeMatcher::MethodName {
                method: "FromSqlRaw".into(),
                description: "FromSqlRaw() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "ExecuteSqlRaw".into(),
                description: "ExecuteSqlRaw() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "Query".into(),
                description: "Dapper.Query() with tainted SQL (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "Execute".into(),
                description: "Dapper.Execute() with tainted SQL (SQL injection)".into(),
            },
        ],
        sanitizers: csharp_taint_sanitizers(),
    }
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: csharp_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "Process.Start".into(),
                description: "Process.Start() with tainted argument (command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "ProcessStartInfo".into(),
                description: "ProcessStartInfo() with tainted argument (command injection)".into(),
            },
            NodeMatcher::Attribute {
                root: "ProcessStartInfo".into(),
                field: "Arguments".into(),
                description: "ProcessStartInfo.Arguments tainted (command injection)".into(),
            },
            NodeMatcher::Attribute {
                root: "ProcessStartInfo".into(),
                field: "FileName".into(),
                description: "ProcessStartInfo.FileName tainted (command injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "Start".into(),
                description: "Process.Start() with tainted argument (command injection)".into(),
            },
        ],
        sanitizers: csharp_taint_sanitizers(),
    }
}

fn xss_spec() -> TaintSpec {
    TaintSpec {
        sources: csharp_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "Response.Write".into(),
                description: "Response.Write() with tainted content (XSS)".into(),
            },
            NodeMatcher::MethodName {
                method: "Write".into(),
                description: "Response.Write() with tainted content (XSS)".into(),
            },
        ],
        sanitizers: csharp_taint_sanitizers(),
    }
}

fn open_redirect_spec() -> TaintSpec {
    TaintSpec {
        sources: csharp_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "Response.Redirect".into(),
                description: "Response.Redirect() with tainted URL (open redirect)".into(),
            },
            NodeMatcher::MethodName {
                method: "Redirect".into(),
                description: "Response.Redirect() with tainted URL (open redirect)".into(),
            },
        ],
        sanitizers: csharp_taint_sanitizers(),
    }
}

fn xxe_spec() -> TaintSpec {
    TaintSpec {
        sources: csharp_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "XmlReader.Create".into(),
                description: "XmlReader.Create() with tainted input (XXE)".into(),
            },
            NodeMatcher::MethodName {
                method: "LoadXml".into(),
                description: "XmlDocument.LoadXml() with tainted input (XXE)".into(),
            },
            // Receiver-constrained. A bare `MethodName { method: "Load" }` matches
            // ANY `.Load(tainted)` call — e.g. `Assembly.Load`, already covered by
            // unsafe-load — producing a false XXE. Constrain to the XML receivers.
            // `XDocument.Load` is a static call; `XmlDocument.Load` instance calls on
            // a local (`doc.Load`) aren't textually distinguishable from other
            // `.Load` calls without type info, so the programmatic XmlDocument vector
            // is covered by the `LoadXml` sink above instead.
            NodeMatcher::Call {
                canonical: "XmlDocument.Load".into(),
                description: "XmlDocument.Load() with tainted input (XXE)".into(),
            },
            NodeMatcher::Call {
                canonical: "XDocument.Load".into(),
                description: "XDocument.Load() with tainted input (XXE)".into(),
            },
        ],
        sanitizers: csharp_taint_sanitizers(),
    }
}

fn unsafe_load_spec() -> TaintSpec {
    TaintSpec {
        sources: csharp_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "Assembly.Load".into(),
                description: "Assembly.Load() with tainted name (unsafe load)".into(),
            },
            NodeMatcher::Call {
                canonical: "Assembly.LoadFrom".into(),
                description: "Assembly.LoadFrom() with tainted path (unsafe load)".into(),
            },
            NodeMatcher::Call {
                canonical: "Activator.CreateInstance".into(),
                description: "Activator.CreateInstance() with tainted type (unsafe load)".into(),
            },
            NodeMatcher::Call {
                canonical: "Type.GetType".into(),
                description: "Type.GetType() with tainted type name (reflection injection)".into(),
            },
        ],
        sanitizers: csharp_taint_sanitizers(),
    }
}

// ─── Scope analysis ───────────────────────────────────────────────────────────

fn analyze_scope(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    out: &mut Vec<TaintFinding>,
) {
    let body = find_scope_body(scope_node).unwrap_or(scope_node);
    let mut state = TaintState::default();

    // Seed parameter sources (`ParamName` matchers) so bare-identifier
    // parameter taint is recognized. The built-in C# specs use dotted sources,
    // so this only fires for synthetic per-parameter specs (cross-file pass 1)
    // or bridge-compiled `pattern: SomeName` sources.
    collect_param_sources(scope_node, source, spec, &mut state);

    // Three passes cover `source -> local -> derived -> sink` chains without
    // a fixed-point loop.
    for _ in 0..3 {
        propagate_assignments(body, source, spec, &mut state);
    }
    find_sinks(body, source, spec, &state, out);
}

/// Seed taint state from parameters whose name matches a `ParamName` source.
///
/// The C# `expression_taint` resolves a bare identifier purely through the
/// taint state (it does not re-classify identifiers as sources), so a
/// parameter used directly as a tainted value must be present in `state`.
/// `$<any-param>` (the wildcard) seeds every parameter.
fn collect_param_sources(
    scope_node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
) {
    let mut bare_names: Vec<&str> = Vec::new();
    let mut wildcard = false;
    for matcher in &spec.sources {
        if let NodeMatcher::ParamName { names, .. } = matcher {
            if crate::rules::taint_engine::param_names_are_wildcard(names) {
                wildcard = true;
            }
            for name in names {
                bare_names.push(name.as_str());
            }
        }
    }
    if bare_names.is_empty() && !wildcard {
        return;
    }

    for param in scope_parameter_nodes(scope_node) {
        let Some(name_node) = param.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name_node, source);
        if wildcard || bare_names.contains(&name) {
            state.taint(
                name.to_string(),
                TaintInfo {
                    description: format!("parameter '{name}'"),
                    line: param.start_position().row + 1,
                    hops: 0,
                },
            );
        }
    }
}

fn propagate_assignments(scope: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    walk_scope_nodes(scope, source, &mut |node, src| {
        // `var x = expr;`  or  `Type x = expr;`
        //
        // AST structure (tree-sitter-c-sharp):
        //   variable_declarator
        //     name: identifier ("x")
        //     <anon>: "="
        //     <anon>: <value_expr>   ← NO `value` field name
        //
        // We detect the value as the last named child that is NOT the name identifier.
        if node.kind() == "variable_declarator" {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let name = node_text(name_node, src).to_string();
            // Find the value: the last child that is not the `=` token and not the name.
            if let Some(value) = variable_declarator_value(node) {
                match expression_taint(value, src, spec, state) {
                    Some(info) => state.taint(name, bump_hops(info)),
                    None => state.clear(&name),
                }
            }
        }

        // `left = right`
        if node.kind() == "assignment_expression" {
            let Some(left) = node.child_by_field_name("left") else {
                return;
            };
            let Some(right) = node.child_by_field_name("right") else {
                return;
            };
            let name = assignment_target_name(left, src);
            if let Some(name) = name {
                match expression_taint(right, src, spec, state) {
                    Some(info) => state.taint(name.to_string(), bump_hops(info)),
                    None => state.clear(name),
                }
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
        let is_call = node.kind() == "invocation_expression";
        let is_new = node.kind() == "object_creation_expression";
        if !is_call && !is_new {
            return;
        }
        let Some(sink_desc) = match_sink(node, src, spec) else {
            return;
        };
        if let Some(info) = sink_argument_taint(node, src, spec, state) {
            out.push(taint_finding_for_node(node, info, sink_desc));
        }
    });
}

// ─── Expression taint ────────────────────────────────────────────────────────

fn expression_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    // Whole-expression text lookup in state first (catches `x` identifiers).
    let text = node_text(node, source);
    if let Some(info) = state.info(text) {
        return Some(info.clone());
    }

    // Bare identifier.
    if node.kind() == "identifier" {
        return state.info(text).cloned();
    }

    // Sanitizer check before source check.
    if is_sanitizer_call(node, source, spec) {
        return None;
    }

    // Direct source match.
    if let Some(desc) = classify_source_expr(node, source, spec) {
        return Some(TaintInfo {
            description: desc,
            line: node.start_position().row + 1,
            hops: 0,
        });
    }

    // Propagation: member_access on a tainted receiver.
    // e.g. `tainted.ToString()` or `tainted.field`
    if node.kind() == "member_access_expression" {
        if let Some(recv) = node.child_by_field_name("expression") {
            if let Some(info) = expression_taint(recv, source, spec, state) {
                return Some(bump_hops(info));
            }
        }
    }

    // Propagation: element_access on a tainted receiver.
    // `Request.QueryString["key"]` or `tainted[x]`
    // AST: element_access_expression { expression: <recv>, subscript: bracketed_argument_list }
    if node.kind() == "element_access_expression" {
        if let Some(expr) = node.child_by_field_name("expression") {
            if let Some(info) = expression_taint(expr, source, spec, state) {
                return Some(bump_hops(info));
            }
        }
    }

    // Propagation through arguments of a method call.
    if node.kind() == "invocation_expression" {
        if let Some(args) = call_arguments(node) {
            if let Some(info) = argument_list_taint(args, source, spec, state) {
                return Some(bump_hops(info));
            }
        }
    }

    // Propagation: binary_expression (string concat: `"SELECT * FROM " + id`).
    if node.kind() == "binary_expression" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Skip the operator token ("+", etc.)
            if !child.is_named() {
                continue;
            }
            if let Some(info) = expression_taint(child, source, spec, state) {
                return Some(info);
            }
        }
    }

    // Propagation: interpolated_string_expression `$"...{expr}..."`.
    if node.kind() == "interpolated_string_expression" {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "interpolation" {
                let mut icursor = child.walk();
                for inner in child.children(&mut icursor) {
                    if let Some(info) = expression_taint(inner, source, spec, state) {
                        return Some(info);
                    }
                }
            }
        }
    }

    // Generic recursive scan for other container node kinds.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(info) = expression_taint(child, source, spec, state) {
            return Some(info);
        }
    }
    None
}

/// Try to classify `node` as a known source expression.
///
/// Handles:
/// - `member_access_expression`: `Request.QueryString`, `Request.Form`, etc.
/// - `invocation_expression`: `Console.ReadLine()`, `Environment.GetEnvironmentVariable()`
/// - `element_access_expression`: `Request.QueryString["x"]` (wraps the member access)
/// - `ParamName` sources matched as bare identifiers (bridge path).
fn classify_source_expr(node: Node<'_>, source: &str, spec: &TaintSpec) -> Option<String> {
    for matcher in &spec.sources {
        match matcher {
            NodeMatcher::Attribute {
                root,
                field,
                description,
            } => {
                // `Request.QueryString` → member_access_expression { expression=Request, name=QueryString }
                if node.kind() == "member_access_expression" {
                    let recv = node.child_by_field_name("expression");
                    let name_node = node.child_by_field_name("name");
                    if let (Some(recv), Some(name_node)) = (recv, name_node) {
                        let recv_text = node_text(recv, source);
                        let name_text = node_text(name_node, source);
                        if recv_text == root.as_str() && name_text == field.as_str() {
                            return Some(description.clone());
                        }
                    }
                }
                // `Request.QueryString["key"]` → element_access_expression { expression=member_access }
                // Propagate the inner expression's matched source description rather
                // than this (outer) matcher's — otherwise the first Attribute matcher
                // (e.g. `Request.QueryString`) claims every `Request.<field>[…]` access.
                if node.kind() == "element_access_expression" {
                    if let Some(expr) = node.child_by_field_name("expression") {
                        if let Some(found) = classify_source_expr(expr, source, spec) {
                            return Some(found);
                        }
                    }
                }
            }
            NodeMatcher::Call {
                canonical,
                description,
            } => {
                // `Console.ReadLine()` → invocation_expression { function=member_access { … } }
                if node.kind() == "invocation_expression" {
                    if let Some(func) = node.child_by_field_name("function") {
                        let resolved = resolve_callee(func, source);
                        if resolved == canonical.as_str() {
                            return Some(description.clone());
                        }
                    }
                }
                // Also match `new SomeType()` with a plain canonical type name.
                if node.kind() == "object_creation_expression" {
                    if let Some(type_node) = node.child_by_field_name("type") {
                        if node_text(type_node, source) == canonical.as_str() {
                            return Some(description.clone());
                        }
                    }
                }
            }
            NodeMatcher::ParamName { names, description } => {
                // Bare identifier compiled from a bridge `pattern: SomeName` source.
                // In C# these fire on identifiers (local variables, parameters).
                if node.kind() == "identifier" {
                    let text = node_text(node, source);
                    if names.iter().any(|n| n == text) {
                        return Some(description.clone());
                    }
                }
                // Also match member_access_expression whose leftmost receiver name
                // appears in the list (e.g. `Request.QueryString` when `Request`
                // is listed as a ParamName source).
                if node.kind() == "member_access_expression"
                    || node.kind() == "element_access_expression"
                {
                    if let Some(root_name) = leftmost_receiver_name(node, source) {
                        if names.iter().any(|n| n == root_name) {
                            return Some(description.clone());
                        }
                    }
                }
            }
            NodeMatcher::FieldName { field, description } => {
                // Any-receiver property READ: `<anything>.field`. Matches a
                // `member_access_expression` whose `name` equals `field`,
                // regardless of the receiver. Covers `req.Body`, `ctx.Request`.
                if node.kind() == "member_access_expression" {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        if node_text(name_node, source) == field.as_str() {
                            return Some(description.clone());
                        }
                    }
                }
            }
            NodeMatcher::Subscript { base, description } => {
                // Index access `base[...]` → `element_access_expression`.
                // Matches when the indexed expression's final segment equals
                // `base` (or any when `base` is None).
                if node.kind() == "element_access_expression" {
                    if let Some(expr) = node.child_by_field_name("expression") {
                        match base.as_deref() {
                            None => return Some(description.clone()),
                            Some(want) => {
                                let final_seg = match expr.kind() {
                                    "identifier" => Some(node_text(expr, source)),
                                    "member_access_expression" => expr
                                        .child_by_field_name("name")
                                        .map(|n| node_text(n, source)),
                                    _ => None,
                                };
                                if final_seg == Some(want) {
                                    return Some(description.clone());
                                }
                            }
                        }
                    }
                }
            }
            NodeMatcher::MethodName { .. }
            | NodeMatcher::CallRegex { .. }
            | NodeMatcher::MethodNameRegex { .. }
            | NodeMatcher::ReceiverCall { .. }
            | NodeMatcher::MemberAssign { .. } => {
                // Sink-only matchers, never a source.
            }
            NodeMatcher::BinopFormat { .. }
            | NodeMatcher::ObjectLiteralValue { .. }
            | NodeMatcher::ReturnValue { .. } => {
                // Sink-only; carried for spec completeness but the C# engine
                // does not match it as a source.
            }
        }
    }
    None
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

/// Check whether `matcher` matches the given call / construction node.
fn matcher_matches_call(matcher: &NodeMatcher, node: Node<'_>, source: &str) -> bool {
    match matcher {
        NodeMatcher::MethodName { method, .. } => {
            // Match any invocation whose final method name equals `method`.
            if node.kind() == "invocation_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    if let Some(method_name) = final_name_segment(func, source) {
                        return method_name == method.as_str();
                    }
                }
            }
            false
        }
        NodeMatcher::Call { canonical, .. } => {
            if node.kind() == "invocation_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let resolved = resolve_callee(func, source);
                    return resolved == canonical.as_str();
                }
            }
            if node.kind() == "object_creation_expression" {
                if let Some(type_node) = node.child_by_field_name("type") {
                    return node_text(type_node, source) == canonical.as_str();
                }
            }
            false
        }
        NodeMatcher::ReceiverCall { receiver, .. } => {
            // Match any invocation whose callee root identifier equals
            // `receiver`, e.g. `Process.$METHOD(...)`.
            if node.kind() == "invocation_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let resolved = resolve_callee(func, source);
                    return resolved.contains('.')
                        && resolved.split('.').next() == Some(receiver.as_str());
                }
            }
            false
        }
        NodeMatcher::CallRegex { regex, .. } => {
            // `$F(...)` + metavariable-regex on `$F`: callee text matches regex.
            if node.kind() == "invocation_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let resolved = resolve_callee(func, source);
                    return regex.is_match(resolved);
                }
            }
            false
        }
        NodeMatcher::MethodNameRegex { regex, .. } => {
            // `$OBJ.$M(...)` + metavariable-regex on `$M`: final method name
            // matches regex, any receiver.
            if node.kind() == "invocation_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    if let Some(method_name) = final_name_segment(func, source) {
                        return regex.is_match(method_name);
                    }
                }
            }
            false
        }
        NodeMatcher::Attribute { root, field, .. } => {
            // Match a member-assignment sink: e.g. `psi.Arguments = tainted`
            // arrives as the LHS of an assignment_expression, not a call.
            // For symmetry we also accept a `member_access_expression` node directly.
            if node.kind() == "member_access_expression" {
                let recv = node.child_by_field_name("expression");
                let name_node = node.child_by_field_name("name");
                if let (Some(recv), Some(name_node)) = (recv, name_node) {
                    let recv_text = node_text(recv, source);
                    let name_text = node_text(name_node, source);
                    return recv_text == root.as_str() && name_text == field.as_str();
                }
            }
            false
        }
        NodeMatcher::FieldName { .. }
        | NodeMatcher::Subscript { .. }
        | NodeMatcher::ParamName { .. }
        | NodeMatcher::MemberAssign { .. }
        | NodeMatcher::BinopFormat { .. }
        | NodeMatcher::ObjectLiteralValue { .. }
        | NodeMatcher::ReturnValue { .. } => false,
    }
}

fn sink_argument_taint(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    call_arguments(node).and_then(|args| argument_list_taint(args, source, spec, state))
}

// ─── C# AST helpers ──────────────────────────────────────────────────────────

fn is_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "anonymous_method_expression"
    )
}

fn find_scope_body(node: Node<'_>) -> Option<Node<'_>> {
    // C# methods have a `body` field (block) or an expression body after `=>`.
    if let Some(body) = node.child_by_field_name("body") {
        return Some(body);
    }
    let mut cursor = node.walk();
    let result = node
        .children(&mut cursor)
        .find(|child| matches!(child.kind(), "block" | "arrow_expression_clause"));
    result
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

/// Resolve a callee `function` node to a canonical dotted name.
///
/// Examples:
/// - `Console.ReadLine`  → `"Console.ReadLine"`
/// - `Process.Start`     → `"Process.Start"`
/// - `myObj.DoSomething` → `"myObj.DoSomething"`
fn resolve_callee<'a>(func_node: Node<'a>, source: &'a str) -> &'a str {
    // For `member_access_expression`, the full text is the dotted chain.
    // For a bare `identifier`, it's just the name.
    node_text(func_node, source)
}

/// Return the final identifier segment of a callee node.
/// `Console.ReadLine` → `"ReadLine"`.
fn final_name_segment<'a>(func_node: Node<'a>, source: &'a str) -> Option<&'a str> {
    if func_node.kind() == "member_access_expression" {
        return func_node
            .child_by_field_name("name")
            .map(|n| node_text(n, source));
    }
    if func_node.kind() == "identifier" {
        return Some(node_text(func_node, source));
    }
    None
}

/// Walk a receiver chain leftward and return the leftmost receiver name.
fn leftmost_receiver_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" => Some(node_text(node, source)),
        "member_access_expression" => {
            if let Some(recv) = node.child_by_field_name("expression") {
                leftmost_receiver_name(recv, source)
            } else {
                None
            }
        }
        "element_access_expression" => {
            if let Some(recv) = node.child_by_field_name("expression") {
                leftmost_receiver_name(recv, source)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the value expression from a `variable_declarator` node.
///
/// In tree-sitter-c-sharp, `variable_declarator` has NO `value` field.
/// The structure is: `name "=" <value_expr>` where all children are anonymous
/// except the `name` field. The value is the last child that is not `=`.
fn variable_declarator_value(node: Node<'_>) -> Option<Node<'_>> {
    let count = node.child_count();
    if count < 3 {
        // Need at least: name, "=", value
        return None;
    }
    // The value is the last child (index count-1).
    let last = node.child(count - 1)?;
    // Sanity: it should not be "=" or the name identifier's position.
    if last.kind() == "=" {
        return None;
    }
    Some(last)
}

fn call_arguments(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "invocation_expression" || node.kind() == "object_creation_expression" {
        return node.child_by_field_name("arguments");
    }
    None
}

/// Check taint in the argument_list of a call node.
///
/// The argument_list contains `argument` wrapper nodes. Each `argument` has one
/// unnamed child that is the actual expression. We must unwrap the `argument`
/// nodes to get to the real expression for taint checking.
fn argument_list_taint(
    arg_list: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<TaintInfo> {
    let mut cursor = arg_list.walk();
    for child in arg_list.children(&mut cursor) {
        if child.kind() == "argument" {
            // Unwrap the `argument` wrapper — check all its children.
            let mut acursor = child.walk();
            for expr in child.children(&mut acursor) {
                if expr.is_named() {
                    if let Some(info) = expression_taint(expr, source, spec, state) {
                        return Some(info);
                    }
                }
            }
        } else if child.is_named() {
            // Fallback for non-argument children.
            if let Some(info) = expression_taint(child, source, spec, state) {
                return Some(info);
            }
        }
    }
    None
}

fn assignment_target_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" => Some(node_text(node, source)),
        "member_access_expression" => Some(node_text(node, source)),
        _ => None,
    }
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

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

// ─── Cross-file (interprocedural across files) taint ─────────────────────
//
// Scope of the C# cross-file pass (deliberately narrow; mirrors the Java and
// Go engines — see `docs/taint-tracking.md`):
//
// * **Resolution is NAME-based, not type-based.** A method (or local function)
//   declaration is summarized by its bare method name. A call site resolves to
//   a summary whenever the invoked method name matches a summarized method in a
//   sibling file of the same directory (used as a same-namespace/same-package
//   proxy, the way the Go engine treats same-directory `.go` files). This
//   intentionally over-approximates: `Helper.Run(x)`, `helper.Run(x)`, and a
//   bare `Run(x)` all resolve to *any* same-directory `Run` summary, regardless
//   of the receiver's declared type. Argument count is only used as a positional
//   bound (the flow's parameter index must be a valid argument index), not as a
//   strict overload discriminator.
// * **What is NOT modeled:** `using`/namespace resolution across directories,
//   type-based instance dispatch through interfaces or subclasses, overload
//   resolution by parameter *type* (only positional arity is honored), partial
//   classes split across files, extension methods, and multi-hop chains (a
//   helper that itself calls another cross-file helper). These need a C#
//   type/symbol table the engine does not build.

/// Extract cross-file taint summaries for every method / local function in
/// `root`.
///
/// Pass 1 of the two-pass scanner. For each method, every parameter is treated
/// as a synthetic taint source; a parameter that reaches a sink records a
/// [`ParamSinkFlow`], and a parameter that flows to a `return` records a
/// `params_to_return` index. Summaries are keyed by the bare method name
/// (last-write-wins on name collisions, mirroring Go/Java).
pub fn extract_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    _aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Vec<FunctionTaintSummary> {
    let mut summaries = Vec::new();
    walk_tree(root, source, &mut |node, src| {
        if node.kind() != "method_declaration" && node.kind() != "local_function_statement" {
            return;
        }
        let Some(method_name) = node
            .child_by_field_name("name")
            .map(|n| node_text(n, src).to_string())
        else {
            return;
        };
        let param_names = csharp_method_param_names(node, src);
        if let Some(summary) =
            summarize_csharp_method(node, &method_name, &param_names, src, rule_specs)
        {
            summaries.push(summary);
        }
    });
    summaries
}

/// The `parameter` nodes of a method / local-function scope, in order.
fn scope_parameter_nodes(scope_node: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    if let Some(plist) = scope_node.child_by_field_name("parameters") {
        let mut cursor = plist.walk();
        for child in plist.named_children(&mut cursor) {
            if child.kind() == "parameter" {
                out.push(child);
            }
        }
    }
    out
}

/// The parameter names of a method / local-function scope, in order.
fn csharp_method_param_names(scope_node: Node<'_>, source: &str) -> Vec<String> {
    scope_parameter_nodes(scope_node)
        .into_iter()
        .filter_map(|node| {
            node.child_by_field_name("name")
                .map(|n| node_text(n, source).to_string())
        })
        .collect()
}

/// Build a [`FunctionTaintSummary`] for a single method, or `None` if no
/// parameter reaches a sink or a return value.
fn summarize_csharp_method(
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
        if csharp_param_flows_to_return(method_node, param_name, source) {
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
            analyze_scope(method_node, source, &synthetic, &mut findings);
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
///
/// The C# intra engine seeds parameter sources implicitly (a bare identifier
/// equal to a `ParamName` source matches in `classify_source_expr`), so we do
/// not pre-populate the state — propagation through assignments plus the
/// expression check on the returned value is sufficient.
fn csharp_param_flows_to_return(method_node: Node<'_>, param_name: &str, source: &str) -> bool {
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

/// Cross-file resolution info for the C# engine.
///
/// `same_package_paths` are the canonical paths of sibling C# files in the same
/// directory (the same-namespace proxy); `summaries` is the pass-1 map keyed by
/// canonical path; `allowed_rule_ids` gates which rules may emit cross-file
/// findings in the current run.
pub struct CrossFileInfo<'a> {
    pub same_package_paths: &'a [PathBuf],
    pub summaries: &'a CrossFileSummaryMap,
    pub allowed_rule_ids: &'a HashSet<String>,
}

/// Pass 2 cross-file resolution: walk every scope, compute its intra-file taint
/// state, and for each helper-method call that resolves to a sibling summary,
/// emit a finding when a tainted argument lands on a parameter with a recorded
/// sink flow.
///
/// Returns findings whose `rule_id_hint` carries the attributed rule id.
pub fn extract_cross_file_findings(
    root: Node<'_>,
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Vec<TaintFinding> {
    // The caller-side taint state is driven by the real sources (shared across
    // the built-in C# rules); union them so an inline source argument like
    // `Helper.Run(Request.QueryString["x"])` is recognized.
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
        if node.kind() != "invocation_expression" {
            return;
        }
        let Some(func) = node.child_by_field_name("function") else {
            return;
        };
        let Some(method_name) = final_name_segment(func, src) else {
            return;
        };
        let Some(summary) = lookup_cross_file_summary(cross_file, method_name) else {
            return;
        };
        let Some(args) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = args.walk();
        let arg_nodes: Vec<Node<'_>> = args
            .named_children(&mut cursor)
            .filter(|n| n.kind() == "argument")
            .collect();

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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn analyze(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let Some(tree) = parse_file(src, Language::CSharp) else {
            panic!("C# fixture should parse");
        };
        analyze_tree(tree.root_node(), src, spec, None)
    }

    #[test]
    #[ignore]
    fn dump_ast_for_debug() {
        let src = r#"
class Controller {
    public void Handle() {
        string cmd = Request.QueryString["cmd"];
        Process.Start(cmd);
    }
}
"#;
        let Some(tree) = parse_file(src, Language::CSharp) else {
            panic!("should parse");
        };
        fn dump(node: tree_sitter::Node, source: &str, depth: usize) {
            let indent = "  ".repeat(depth);
            let text = &source[node.byte_range()];
            let text_short: String = text.chars().take(50).collect();
            // Print field names for children via cursor
            let mut cursor = node.walk();
            let has_fields = cursor.goto_first_child();
            if has_fields {
                loop {
                    let field_name = cursor.field_name().unwrap_or("<anon>");
                    eprintln!(
                        "{}{}.{} = {:?}",
                        indent,
                        node.kind(),
                        field_name,
                        cursor.node().kind()
                    );
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
            eprintln!("{}{} = {:?}", indent, node.kind(), text_short);
            let mut c = node.walk();
            for child in node.children(&mut c) {
                dump(child, source, depth + 1);
            }
        }
        dump(tree.root_node(), src, 0);
        panic!("dump complete — check stderr");
    }

    // ── direct-unit tests (analyze_tree) ─────────────────────────────────

    #[test]
    fn command_injection_request_querystring_to_process_start() {
        let src = r#"
using System.Diagnostics;
using System.Web;

class Controller {
    public void Handle() {
        string cmd = Request.QueryString["cmd"];
        Process.Start(cmd);
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect Request.QueryString -> Process.Start: {findings:?}"
        );
    }

    #[test]
    fn sql_injection_request_form_to_execute_reader() {
        let src = r#"
using System.Data.SqlClient;
using System.Web;

class Dao {
    public void Query() {
        string id = Request.Form["id"];
        string sql = "SELECT * FROM Users WHERE Id = " + id;
        var cmd = new SqlCommand(sql);
        cmd.ExecuteReader();
    }
}
"#;
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect Request.Form -> ExecuteReader: {findings:?}"
        );
    }

    #[test]
    fn sanitizer_htmlencode_blocks_xss() {
        let src = r#"
using System.Web;

class Controller {
    public void Handle() {
        string raw = Request.QueryString["q"];
        string safe = HttpUtility.HtmlEncode(raw);
        Response.Write(safe);
    }
}
"#;
        let findings = analyze(src, &xss_spec());
        assert!(
            findings.is_empty(),
            "HtmlEncode must block XSS finding: {findings:?}"
        );
    }

    #[test]
    fn xss_direct_response_write_no_sanitizer() {
        let src = r#"
using System.Web;

class Controller {
    public void Handle() {
        string raw = Request.QueryString["q"];
        Response.Write(raw);
    }
}
"#;
        let findings = analyze(src, &xss_spec());
        assert!(!findings.is_empty(), "should detect XSS: {findings:?}");
    }

    #[test]
    fn console_readline_to_process_start() {
        let src = r#"
using System;
using System.Diagnostics;

class App {
    static void Main() {
        string cmd = Console.ReadLine();
        Process.Start(cmd);
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            !findings.is_empty(),
            "should detect Console.ReadLine -> Process.Start: {findings:?}"
        );
    }

    #[test]
    fn clean_literal_no_finding() {
        let src = r#"
using System.Diagnostics;

class App {
    static void Main() {
        string _ = Console.ReadLine();
        Process.Start("notepad.exe");
    }
}
"#;
        let findings = analyze(src, &command_injection_spec());
        assert!(
            findings.is_empty(),
            "literal argument must not trigger taint: {findings:?}"
        );
    }

    #[test]
    fn int_parse_sanitizes_numeric_sql_injection() {
        let src = r#"
using System.Data.SqlClient;
using System.Web;

class Dao {
    void Query() {
        string rawId = Request.QueryString["id"];
        int safeId = int.Parse(rawId);
        string sql = "SELECT * FROM Users WHERE Id = " + safeId;
        var cmd = new SqlCommand(sql);
        cmd.ExecuteReader();
    }
}
"#;
        // int.Parse is a sanitizer that kills the taint.
        let findings = analyze(src, &sql_injection_spec());
        assert!(
            findings.is_empty(),
            "int.Parse should sanitize SQL injection: {findings:?}"
        );
    }

    // ── cross-file summary + resolution ──────────────────────────────────

    #[test]
    fn cross_file_summary_records_param_to_sink() {
        let helper = r#"
using System.Data.SqlClient;
class QueryHelper {
    public static void RunQuery(string term) {
        string sql = "SELECT * FROM users WHERE name = '" + term + "'";
        var cmd = new SqlCommand(sql);
        cmd.ExecuteReader();
    }
}
"#;
        let tree = parse_file(helper, Language::CSharp).expect("parse");
        let specs = csharp_taint_rule_specs();
        let summaries = extract_cross_file_summaries(tree.root_node(), helper, None, &specs);
        let run = summaries
            .iter()
            .find(|s| s.name == "RunQuery")
            .expect("RunQuery should be summarized");
        assert!(
            run.params_to_sink
                .iter()
                .any(|f| f.param_index == 0 && f.sink_rule_id == "csharp/taint-sql-injection"),
            "param 0 must reach the SQL sink: {run:?}"
        );
    }

    #[test]
    fn cross_file_findings_resolve_helper_call() {
        use std::path::PathBuf;
        let helper = r#"
using System.Data.SqlClient;
class QueryHelper {
    public static void RunQuery(string term) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + term + "'");
        cmd.ExecuteReader();
    }
}
"#;
        let caller = r#"
using System.Web;
class Handler {
    public void Search() {
        string name = Request.QueryString["name"];
        QueryHelper.RunQuery(name);
    }
}
"#;
        let specs = csharp_taint_rule_specs();
        let helper_tree = parse_file(helper, Language::CSharp).expect("parse helper");
        let helper_path = PathBuf::from("QueryHelper.cs");
        let helper_summaries =
            extract_cross_file_summaries(helper_tree.root_node(), helper, None, &specs);
        let mut summary_map = CrossFileSummaryMap::new();
        summary_map.insert(helper_path.clone(), helper_summaries);

        let allowed: HashSet<String> = ["csharp/taint-sql-injection".to_string()]
            .into_iter()
            .collect();
        let paths = vec![helper_path];
        let cross = CrossFileInfo {
            same_package_paths: &paths,
            summaries: &summary_map,
            allowed_rule_ids: &allowed,
        };
        let caller_tree = parse_file(caller, Language::CSharp).expect("parse caller");
        let findings = extract_cross_file_findings(
            caller_tree.root_node(),
            caller,
            &specs
                .iter()
                .map(|(id, s)| (*id, s.clone()))
                .collect::<Vec<_>>(),
            &cross,
        );
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one cross-file finding: {findings:?}"
        );
        assert!(findings[0]
            .sink_description
            .contains("via cross-file call to RunQuery"));
    }

    #[test]
    fn open_redirect_via_request_params() {
        let src = r#"
using System.Web;

class Controller {
    void Redirect() {
        string url = Request.Params["returnUrl"];
        Response.Redirect(url);
    }
}
"#;
        let findings = analyze(src, &open_redirect_spec());
        assert!(
            !findings.is_empty(),
            "should detect open redirect: {findings:?}"
        );
    }
}
