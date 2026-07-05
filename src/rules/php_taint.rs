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
use crate::rules::cross_file::{CrossFileSummaryMap, FunctionTaintSummary};
use crate::rules::taint_engine::{
    analyze_function_generic, attribution_hint_for_sink, cross_file_taint_finding,
    extract_cross_file_summary_for_function, match_call_sink, node_text, taint_finding_for_node,
    AnalysisContext, ReturnSummary, TaintLanguageAdapter, TaintState,
};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use std::collections::HashSet;
use std::path::PathBuf;
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Cross-file resolution info for the PHP engine.
///
/// `same_package_paths` are the canonical paths of sibling PHP files in the
/// same directory (the same-package proxy, mirroring the Go and Java engines);
/// `summaries` is the pass-1 map keyed by canonical path; `allowed_rule_ids`
/// gates which rules may emit cross-file findings in the current run.
///
/// # Scope and limitations (honest over-approximation)
///
/// Resolution is **name-based within the same directory**: a call to
/// `run_cmd($x)` resolves to *any* function or method named `run_cmd` defined
/// in a sibling file, regardless of namespace, declaring class, or how the
/// file would actually be loaded at runtime. Argument arity is only checked
/// loosely — a recorded `ParamSinkFlow` fires when the call supplies an
/// argument at that parameter index. This intentionally over-approximates,
/// the same way the Go/Java/Ruby cross-file passes do.
///
/// **Not modeled:** PHP namespaces (`\App\Helpers\run_cmd`), Composer
/// autoloading / `require`/`include` across directories, instance dispatch by
/// declared class type, method overriding, and multi-hop chains (a helper that
/// itself calls another cross-file helper). These need a PHP symbol/namespace
/// table the engine does not build.
pub struct CrossFileInfo<'a> {
    pub same_package_paths: &'a [PathBuf],
    pub summaries: &'a CrossFileSummaryMap,
    pub allowed_rule_ids: &'a HashSet<String>,
}

type PhpCtx<'a> = AnalysisContext<'a, CrossFileInfo<'a>>;

/// Run the PHP taint engine over every function/method definition inside `root`
/// and return one [`TaintFinding`] per source→sink flow discovered.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let empty_summary = ReturnSummary::new();
    let ctx = AnalysisContext {
        source,
        spec,
        aliases: None,
        summaries: &empty_summary,
        cross_file: None,
        sink_to_rules: None,
        label_policy: None,
    };
    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func_node| {
        analyze_function_generic::<PhpTaintAdapter, CrossFileInfo<'_>>(
            func_node,
            &ctx,
            &mut findings,
        );
    });
    findings
}

// ─── Cross-file (interprocedural across files) API ─────────────────────────

/// Extract cross-file taint summaries for every function/method declaration
/// in `root`.
///
/// Pass 1 of the two-pass scanner. For each function/method, every parameter
/// is treated as a synthetic taint source; a parameter that reaches a sink
/// records a [`crate::rules::cross_file::ParamSinkFlow`], and a parameter that
/// flows to a `return` records a `params_to_return` index. Summaries are keyed
/// by the bare function/method name (last-write-wins on name collisions,
/// mirroring Go/Java).
pub fn extract_cross_file_summaries(
    root: Node<'_>,
    source: &str,
    aliases: Option<&AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Vec<FunctionTaintSummary> {
    let mut summaries = Vec::new();
    collect_function_defs(root, &mut |func_node| {
        let Some(name_node) = func_node.child_by_field_name("name") else {
            return;
        };
        let func_name = node_text(name_node, source).to_string();
        let param_names = collect_param_names(func_node, source);

        if let Some(summary) =
            extract_cross_file_summary_for_function::<PhpTaintAdapter, CrossFileInfo<'_>>(
                func_node,
                &func_name,
                &param_names,
                source,
                aliases,
                rule_specs,
            )
        {
            summaries.push(summary);
        }
    });
    summaries
}

/// Collect the parameter names (the `$var` text, `$` included) of a
/// function/method definition, in order.
fn collect_param_names(func_node: Node<'_>, source: &str) -> Vec<String> {
    let Some(params) = func_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        let var_node = if child.kind() == "variable_name" {
            Some(child)
        } else {
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
            names.push(node_text(v, source).to_string());
        }
    }
    names
}

/// Pass 2 cross-file resolution: re-run the intra-file taint walk over every
/// function/method with the sibling summaries available, emitting a finding
/// when a tainted argument lands on a parameter that the callee's summary says
/// reaches a sink.
///
/// The walk uses a *source-only* spec (real sources + sanitizers, **no
/// sinks**) so that intra-file sink findings — already produced by the
/// per-rule [`analyze_tree`] pass — are not duplicated here; only cross-file
/// flows emerge. Findings carry their attributed `rule_id_hint`.
pub fn extract_cross_file_findings(
    root: Node<'_>,
    source: &str,
    rule_specs: &[(&str, TaintSpec)],
    cross_file: &CrossFileInfo<'_>,
) -> Vec<TaintFinding> {
    // The caller-side taint state is driven by the real sources (shared
    // across the built-in PHP rules); union them so an inline source argument
    // like `run_cmd($_GET['x'])` is recognized. Sanitizers are unioned too so
    // a sanitized argument does not produce a cross-file finding.
    let mut source_spec = TaintSpec::default();
    for (_, spec) in rule_specs {
        source_spec.sources.extend(spec.sources.iter().cloned());
        source_spec
            .sanitizers
            .extend(spec.sanitizers.iter().cloned());
    }

    let empty_summary = ReturnSummary::new();
    let ctx = AnalysisContext {
        source,
        spec: &source_spec,
        aliases: None,
        summaries: &empty_summary,
        cross_file: Some(cross_file),
        sink_to_rules: None,
        label_policy: None,
    };
    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func_node| {
        analyze_function_generic::<PhpTaintAdapter, CrossFileInfo<'_>>(
            func_node,
            &ctx,
            &mut findings,
        );
    });
    findings
}

/// Resolve a call's callee name to a sibling-file summary and, for each
/// tainted argument landing on a parameter with a recorded sink flow, push a
/// cross-file finding. Shared by function, member, and scoped call handlers.
fn handle_cross_file_call(
    node: Node<'_>,
    callee_name: &str,
    ctx: &PhpCtx<'_>,
    state: &TaintState,
    findings: &mut Vec<TaintFinding>,
    cross_file: &CrossFileInfo<'_>,
) {
    if callee_name.is_empty() {
        return;
    }

    // Search all same-package (same-directory) files for a function/method
    // with this name. Name-based, first-match-wins — see CrossFileInfo docs.
    let mut resolved: Option<&FunctionTaintSummary> = None;
    for pkg_path in cross_file.same_package_paths {
        if let Some(file_summaries) = cross_file.summaries.get(pkg_path) {
            if let Some(summary) = file_summaries.iter().find(|s| s.name == callee_name) {
                resolved = Some(summary);
                break;
            }
        }
    }
    let Some(summary) = resolved else {
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
        // Each `argument` node wraps the actual expression.
        let expr = if arg.kind() == "argument" {
            arg.named_child(0).unwrap_or(arg)
        } else {
            arg
        };
        if let Some((source_desc, src_line)) = expression_taint(expr, ctx, state) {
            findings.push(cross_file_taint_finding(
                node,
                source_desc,
                src_line,
                &flow.sink_description,
                callee_name,
                &flow.sink_rule_id,
            ));
            // One finding per cross-file call is enough.
            return;
        }
    }
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

// ─── Built-in rule specs ───────────────────────────────────────────────────

/// All PHP taint rule IDs paired with their specs.
///
/// Consumed by [`crate::rules::builtin_taint_specs_for_language`]. Each rule
/// reuses the shared [`php_taint_sources`] and [`php_taint_sanitizers`]
/// aggregates and curates the subset of [`php_taint_sinks`] relevant to that
/// vulnerability class. The five highest-value PHP flows are covered:
/// command injection, SQL injection, XSS (output), local/remote file
/// inclusion, and unsafe deserialization.
pub fn php_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        ("php/taint-command-injection", command_injection_spec()),
        ("php/taint-sql-injection", sql_injection_spec()),
        ("php/taint-xss", xss_spec()),
        ("php/taint-file-inclusion", file_inclusion_spec()),
        (
            "php/taint-unsafe-deserialization",
            unsafe_deserialization_spec(),
        ),
    ]
}

fn command_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: php_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "system".into(),
                description: "system() with tainted argument (OS command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "exec".into(),
                description: "exec() with tainted argument (OS command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "shell_exec".into(),
                description: "shell_exec() with tainted argument (OS command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "passthru".into(),
                description: "passthru() with tainted argument (OS command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "popen".into(),
                description: "popen() with tainted argument (OS command injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "proc_open".into(),
                description: "proc_open() with tainted argument (OS command injection)".into(),
            },
        ],
        sanitizers: php_taint_sanitizers(),
    }
}

fn sql_injection_spec() -> TaintSpec {
    TaintSpec {
        sources: php_taint_sources(),
        sinks: vec![
            // Procedural MySQL APIs.
            NodeMatcher::Call {
                canonical: "mysqli_query".into(),
                description: "mysqli_query() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::Call {
                canonical: "mysql_query".into(),
                description: "mysql_query() with tainted query (SQL injection)".into(),
            },
            // PDO method calls: $pdo->query / ->exec / ->prepare.
            NodeMatcher::MethodName {
                method: "query".into(),
                description: "->query() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "exec".into(),
                description: "->exec() with tainted query (SQL injection)".into(),
            },
            NodeMatcher::MethodName {
                method: "prepare".into(),
                description: "->prepare() with tainted query (SQL injection)".into(),
            },
        ],
        sanitizers: php_taint_sanitizers(),
    }
}

fn xss_spec() -> TaintSpec {
    TaintSpec {
        sources: php_taint_sources(),
        sinks: vec![
            // `echo` is an `echo_statement`; `print` is a `print_intrinsic`;
            // `printf` is a `function_call_expression`. All three are
            // dispatched in `dispatch_walk_node`.
            NodeMatcher::Call {
                canonical: "echo".into(),
                description: "echo of tainted value (reflected XSS)".into(),
            },
            NodeMatcher::Call {
                canonical: "print".into(),
                description: "print of tainted value (reflected XSS)".into(),
            },
            NodeMatcher::Call {
                canonical: "printf".into(),
                description: "printf() of tainted value (reflected XSS)".into(),
            },
        ],
        sanitizers: php_taint_sanitizers(),
    }
}

fn file_inclusion_spec() -> TaintSpec {
    TaintSpec {
        sources: php_taint_sources(),
        sinks: vec![
            // PHP `include`/`require` (+`_once`) are language constructs
            // parsed as `include_expression` / `require_expression` /
            // `include_once_expression` / `require_once_expression`, NOT
            // `function_call_expression`. They are dispatched separately in
            // `dispatch_walk_node` (see `handle_include_require`).
            NodeMatcher::Call {
                canonical: "include".into(),
                description: "include of tainted path (local/remote file inclusion)".into(),
            },
            NodeMatcher::Call {
                canonical: "require".into(),
                description: "require of tainted path (local/remote file inclusion)".into(),
            },
            NodeMatcher::Call {
                canonical: "include_once".into(),
                description: "include_once of tainted path (local/remote file inclusion)".into(),
            },
            NodeMatcher::Call {
                canonical: "require_once".into(),
                description: "require_once of tainted path (local/remote file inclusion)".into(),
            },
        ],
        sanitizers: php_taint_sanitizers(),
    }
}

fn unsafe_deserialization_spec() -> TaintSpec {
    TaintSpec {
        sources: php_taint_sources(),
        sinks: vec![NodeMatcher::Call {
            canonical: "unserialize".into(),
            description: "unserialize() of tainted data (unsafe deserialization)".into(),
        }],
        // No broadly-accepted sanitizer for unserialize() — gadget chains
        // bypass `allowed_classes` filtering in practice, so a tainted
        // reaches-sink is always reported. Users should replace the sink
        // with `json_decode` rather than sanitize the input.
        sanitizers: vec![],
    }
}

// ─── Language adapter ─────────────────────────────────────────────────────

pub(super) struct PhpTaintAdapter;

impl<'a> TaintLanguageAdapter<CrossFileInfo<'a>> for PhpTaintAdapter {
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
        // `Class::method(args)` — a static/scoped method call. Cross-file
        // resolution only (intra-file scoped sinks are not modeled here, so
        // intra behavior is unchanged when `cross_file` is `None`).
        if node.kind() == "scoped_call_expression" {
            handle_scoped_call(node, ctx, state, findings);
        }
        // echo is a statement in PHP grammar, not a function call node
        if node.kind() == "echo_statement" {
            handle_echo(node, ctx, state, findings);
        }
        // `print` is a language construct parsed as `print_intrinsic`.
        if node.kind() == "print_intrinsic" {
            handle_print(node, ctx, state, findings);
        }
        // `include`/`require` (+`_once`) are language constructs parsed as
        // `*_expression` nodes, not function calls.
        if matches!(
            node.kind(),
            "include_expression"
                | "include_once_expression"
                | "require_expression"
                | "require_once_expression"
        ) {
            handle_include_require(node, ctx, state, findings);
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

    // Cross-file: a bare call `run_cmd($x)` may resolve to a helper defined in
    // a sibling file of the same directory (same-package proxy).
    if let Some(cross_file) = ctx.cross_file {
        handle_cross_file_call(node, callee, ctx, state, findings, cross_file);
    }
}

/// Handle a `scoped_call_expression`: `Class::method(args)`. Cross-file
/// resolution by method name only.
fn handle_scoped_call(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let Some(cross_file) = ctx.cross_file else {
        return;
    };
    let method_name = node
        .child_by_field_name("name")
        .map(|n| node_text(n, ctx.source))
        .unwrap_or("");
    handle_cross_file_call(node, method_name, ctx, state, findings, cross_file);
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

    // Cross-file: `$obj->method($x)` may resolve to a helper method of the
    // same name defined in a sibling file (instance dispatch by declared type
    // is not modeled — see CrossFileInfo docs).
    if let Some(cross_file) = ctx.cross_file {
        handle_cross_file_call(node, method_name, ctx, state, findings, cross_file);
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

/// Handle `print_intrinsic`: `print $x;` / `print($x);` is an XSS sink.
///
/// Mirrors [`handle_echo`]. `print` is a PHP language construct parsed as a
/// `print_intrinsic` node whose single named child is the printed expression
/// (either a bare expression or a `parenthesized_expression`).
fn handle_print(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let print_sink_desc = ctx.spec.sinks.iter().find_map(|m| {
        if let NodeMatcher::Call {
            canonical,
            description,
        } = m
        {
            if canonical == "print" {
                Some(description.clone())
            } else {
                None
            }
        } else {
            None
        }
    });
    let Some(sink_desc) = print_sink_desc else {
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

/// Handle `include`/`require` (+`_once`) language constructs: a tainted
/// included path is a local/remote file inclusion sink.
///
/// PHP parses these as `include_expression` / `include_once_expression` /
/// `require_expression` / `require_once_expression`. The canonical sink name
/// is derived by stripping the trailing `_expression` from the node kind
/// (e.g. `include_once_expression` → `include_once`), matching the
/// `NodeMatcher::Call` canonicals in [`file_inclusion_spec`]. The included
/// expression is the sole named child.
fn handle_include_require(
    node: Node<'_>,
    ctx: &PhpCtx<'_>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let kind = node.kind();
    let canonical = kind.strip_suffix("_expression").unwrap_or(kind);
    let sink_desc = ctx.spec.sinks.iter().find_map(|m| {
        if let NodeMatcher::Call {
            canonical: c,
            description,
        } = m
        {
            if c.as_str() == canonical {
                Some(description.clone())
            } else {
                None
            }
        } else {
            None
        }
    });
    let Some(sink_desc) = sink_desc else {
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

    // ── Parenthesized expression: `($tainted)` ────────────────────────────
    // Parens are semantically transparent — recurse into the sole named child.
    // Covers parenthesized forms such as `print($x)`, `include($x)`, and
    // `system(($x))`.
    if expr.kind() == "parenthesized_expression" {
        if let Some(inner) = expr.named_child(0) {
            if let Some(result) = expression_taint(inner, ctx, state) {
                return Some(result);
            }
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
            | NodeMatcher::ReturnValue { .. }
            // Java-only typed-metavariable source; PHP has no declared-type
            // seeding, so it is a no-op here.
            | NodeMatcher::TypedName { .. }
            // Java-only typed-assignment sink; no-op in source position here.
            | NodeMatcher::TypedAssignTarget { .. } => {
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

    // ── Cross-file: summary extraction ────────────────────────────────────
    fn summaries(src: &str) -> Vec<FunctionTaintSummary> {
        let tree = parse_file(src, Language::Php).expect("parse");
        let specs = php_taint_rule_specs();
        extract_cross_file_summaries(tree.root_node(), src, None, &specs)
    }

    #[test]
    fn cross_file_summary_records_param_to_sink() {
        let src = "<?php\nfunction run_cmd($arg) {\n  system($arg);\n}\n";
        let found = summaries(src);
        let helper = found
            .iter()
            .find(|s| s.name == "run_cmd")
            .expect("run_cmd should be summarized");
        let flow = helper
            .params_to_sink
            .iter()
            .find(|f| f.param_index == 0)
            .expect("param 0 should reach a sink");
        assert_eq!(flow.sink_rule_id, "php/taint-command-injection");
    }

    #[test]
    fn cross_file_summary_skips_functions_with_no_flow() {
        // `log_it` neither sinks nor returns its parameter, so it must not be
        // summarized at all.
        let src = "<?php\nfunction log_it($message) {\n  echo \"constant\";\n}\n";
        let found = summaries(src);
        assert!(
            found.iter().all(|s| s.name != "log_it"),
            "function with no param flow should not be summarized: {found:?}"
        );
    }

    // ── Cross-file: findings resolution ───────────────────────────────────
    #[test]
    fn cross_file_findings_resolve_helper_in_sibling_summary() {
        use std::collections::HashSet;
        use std::path::PathBuf;

        // Caller passes a tainted argument into a same-package helper.
        let caller = "<?php\nfunction handle() {\n  $cmd = $_GET['cmd'];\n  run_cmd($cmd);\n}\n";
        let helper = "<?php\nfunction run_cmd($arg) {\n  system($arg);\n}\n";

        let helper_tree = parse_file(helper, Language::Php).expect("parse helper");
        let specs = php_taint_rule_specs();
        let helper_summaries =
            extract_cross_file_summaries(helper_tree.root_node(), helper, None, &specs);

        let helper_path = PathBuf::from("/pkg/helper.php");
        let mut summary_map = CrossFileSummaryMap::new();
        summary_map.insert(helper_path.clone(), helper_summaries);

        let same_package = vec![helper_path];
        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let cross = CrossFileInfo {
            same_package_paths: &same_package,
            summaries: &summary_map,
            allowed_rule_ids: &allowed,
        };

        let caller_tree = parse_file(caller, Language::Php).expect("parse caller");
        let findings = extract_cross_file_findings(caller_tree.root_node(), caller, &specs, &cross);
        assert_eq!(
            findings.len(),
            1,
            "tainted arg into run_cmd must produce one cross-file finding: {findings:?}"
        );
        assert_eq!(
            findings[0].rule_id_hint.as_deref(),
            Some("php/taint-command-injection")
        );
        assert!(findings[0]
            .sink_description
            .contains("via cross-file call to run_cmd"));
    }

    #[test]
    fn cross_file_findings_clean_arg_does_not_fire() {
        use std::collections::HashSet;
        use std::path::PathBuf;

        // A literal argument (no taint) must not produce a cross-file finding.
        let caller = "<?php\nfunction handle() {\n  run_cmd('ls -la');\n}\n";
        let helper = "<?php\nfunction run_cmd($arg) {\n  system($arg);\n}\n";

        let helper_tree = parse_file(helper, Language::Php).expect("parse helper");
        let specs = php_taint_rule_specs();
        let helper_summaries =
            extract_cross_file_summaries(helper_tree.root_node(), helper, None, &specs);

        let helper_path = PathBuf::from("/pkg/helper.php");
        let mut summary_map = CrossFileSummaryMap::new();
        summary_map.insert(helper_path.clone(), helper_summaries);

        let same_package = vec![helper_path];
        let allowed: HashSet<String> = specs.iter().map(|(id, _)| id.to_string()).collect();
        let cross = CrossFileInfo {
            same_package_paths: &same_package,
            summaries: &summary_map,
            allowed_rule_ids: &allowed,
        };

        let caller_tree = parse_file(caller, Language::Php).expect("parse caller");
        let findings = extract_cross_file_findings(caller_tree.root_node(), caller, &specs, &cross);
        assert!(
            findings.is_empty(),
            "clean literal argument must not fire cross-file: {findings:?}"
        );
    }
}
