//! Shared types and utilities for the JS/Python/Go taint engines.
//!
//! Each language-specific engine (`javascript_taint`, `python_taint`,
//! `go_taint`) re-exports these types so existing consumers are
//! unaffected.

use crate::rules::cross_file::{FunctionTaintSummary, ParamSinkFlow};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

// ─── Core types ──────────────────────────────────────────────────────────

/// A pattern that matches an AST node for taint analysis.
#[derive(Debug, Clone)]
pub enum NodeMatcher {
    /// Match a member-expression access like `req.body` or `request.query`.
    ///
    /// Triggers whenever the *leftmost* identifier in a chain equals `root`
    /// and the *final* property segment equals `field`.
    Attribute {
        root: String,
        field: String,
        description: String,
    },

    /// Match a call whose callee resolves (raw or via the alias table) to
    /// `canonical`.
    Call {
        canonical: String,
        description: String,
    },

    /// Match any use of a function parameter whose name is in this list.
    ParamName {
        names: Vec<String>,
        description: String,
    },

    /// Match any method call whose final property name equals `method`,
    /// regardless of receiver. Only meaningful as a sink matcher.
    MethodName { method: String, description: String },

    /// Match a call whose *callee text* matches a compiled regex. Compiled
    /// from a taint source/sink/sanitizer `patterns:` AND-block pairing a
    /// bare-metavariable callee pattern (`$F(...)`) with a `metavariable-regex`
    /// pinning that metavariable, e.g.
    ///
    /// ```yaml
    /// - pattern: $EXEC(...)
    /// - metavariable-regex: { metavariable: $EXEC, regex: ^(system|exec)$ }
    /// ```
    ///
    /// The regex (NOT a dropped constraint) is what bounds the match: without
    /// it the bare-metavar callee would match every call (universal → FP) and
    /// is refused. The matcher fires only for calls whose callee name matches
    /// the regex, so it is name-constrained and FP-safe. The full callee text
    /// is tested (so dotted alternatives such as `IO.popen` match), matching
    /// Semgrep's binding of the callee metavariable to the whole callee.
    /// Sink/sanitizer only — a call argument is a destination, not an origin.
    CallRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Match any method call whose *final method name* matches a compiled
    /// regex, regardless of receiver. Compiled from a `patterns:` AND-block
    /// pairing a `$OBJ.$M(...)` pattern with a `metavariable-regex` pinning the
    /// method metavariable `$M`, e.g.
    ///
    /// ```yaml
    /// - pattern: $WRITER.$WRITE(...)
    /// - metavariable-regex: { metavariable: $WRITE, regex: ^(writerow)$ }
    /// ```
    ///
    /// The any-receiver analogue of [`NodeMatcher::CallRegex`], bounded by the
    /// method-name regex. Sink/sanitizer only.
    MethodNameRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Match any call whose callee's leftmost/root identifier equals
    /// `receiver`, regardless of the method name — e.g. `os.$METHOD(...)`,
    /// `subprocess.$FUNC(...)`, `Kernel.$X(...)`. Compiled from a Semgrep
    /// callee of the form `receiver.$METAVAR` where `receiver` is a concrete
    /// identifier and the method is a metavariable. Sink/sanitizer only.
    ReceiverCall {
        receiver: String,
        description: String,
    },

    /// Match a member/property/attribute READ `<anything>.field` regardless
    /// of receiver — e.g. `req.body`, `request.query`, `ctx.headers`.
    /// Compiled from Semgrep patterns of the form `$METAVAR.field` (a
    /// metavariable receiver and a plain identifier field).
    ///
    /// This is the any-receiver analogue of [`NodeMatcher::Attribute`]
    /// (which requires a concrete `root`). Meaningful for object/property
    /// languages (Python, JS/TS, Go, Java, Kotlin, Ruby, PHP, C#); for C the
    /// matcher is carried in the spec but the engine no-ops it (no
    /// property-read sources exist in plain C).
    FieldName { field: String, description: String },

    /// Match a subscript / index access `base[...]`.
    ///
    /// `base = Some(name)` matches a subscript whose indexed operand's final
    /// segment equals `name` (e.g. `params[...]`, `request.POST[...]` →
    /// `POST`, `flask.request.args[...]` → `args`). `base = None` matches any
    /// subscript regardless of base (compiled from a metavariable base like
    /// `$VALS[$INDEX]`).
    ///
    /// Meaningful for object/property languages; the C engine no-ops it.
    Subscript {
        base: Option<String>,
        description: String,
    },

    /// Match an assignment where the LHS is a member expression whose
    /// property name equals `field`. JS-specific: covers the
    /// `element.innerHTML = tainted` pattern, which is not a call and so
    /// cannot be expressed as `Call`.
    MemberAssign { field: String, description: String },

    /// Match a string-building SINK: a binary `+`/`%` concatenation, an
    /// interpolated/format string (`f"...{x}..."`), or a format call
    /// (`fmt.Sprintf("...", x)`, `sprintf("...", x)`) where one operand is a
    /// string literal/format AND a tainted value flows into another operand.
    ///
    /// Compiled from Semgrep sink patterns such as `"$SQL" + $EXPR`,
    /// `$M % $M`, `$A + $B`, `f"...{$X}..."`, `Kernel::sprintf("$FMT", ...)`.
    /// This maps to SQL-injection / command-string sinks. To avoid false
    /// positives the engine only treats a node as a `BinopFormat` sink when one
    /// operand is a string literal/format; a plain numeric or variable-only
    /// concatenation never fires. Sink/sanitizer only.
    BinopFormat { description: String },

    /// Match an object/dictionary literal *construction* one of whose value
    /// positions is a tainted expression — e.g. the JS object literal
    /// `{ role: "system", content: tainted }` or the Python dict
    /// `{"role": "system", "content": tainted}`.
    ///
    /// Compiled from Semgrep sink patterns such as
    /// `{role: "system", content: $SINK}` (LLM system-prompt-injection rules).
    /// The bridge drops the literal key/value constraints (`role: "system"`),
    /// so the compiled sink fires whenever an object/dict literal is built with
    /// a tainted value in any field. Only meaningful as a sink/sanitizer shape
    /// for JavaScript/TypeScript (`object`) and Python (`dictionary`); for all
    /// other engines the matcher is carried in the spec but never queried.
    ObjectLiteralValue { description: String },

    /// Match a `return` statement whose returned expression is tainted — e.g.
    /// `return tainted`. Compiled from Semgrep sink patterns of the form
    /// `return $METAVAR` (LLM "unsanitized return" / directly-returned-format
    /// rules where the sink is the function's return value).
    ///
    /// The bridge drops the surrounding `pattern-inside` constraints, so the
    /// compiled sink fires whenever a `return` statement returns a tainted
    /// value. Bounded to return position (not a universal bare-metavar sink).
    /// Only meaningful as a sink/sanitizer shape for Python; for other engines
    /// the matcher is carried in the spec but never queried.
    ReturnValue { description: String },
}

impl NodeMatcher {
    pub fn description(&self) -> &str {
        match self {
            NodeMatcher::Attribute { description, .. } => description,
            NodeMatcher::Call { description, .. } => description,
            NodeMatcher::ParamName { description, .. } => description,
            NodeMatcher::MethodName { description, .. } => description,
            NodeMatcher::CallRegex { description, .. } => description,
            NodeMatcher::MethodNameRegex { description, .. } => description,
            NodeMatcher::ReceiverCall { description, .. } => description,
            NodeMatcher::FieldName { description, .. } => description,
            NodeMatcher::Subscript { description, .. } => description,
            NodeMatcher::MemberAssign { description, .. } => description,
            NodeMatcher::BinopFormat { description, .. } => description,
            NodeMatcher::ObjectLiteralValue { description, .. } => description,
            NodeMatcher::ReturnValue { description, .. } => description,
        }
    }
}

/// Declarative taint specification consumed by the engine.
///
/// Sanitizers collapse to "clean" — the engine does not track a separate
/// "sanitized" state.
#[derive(Debug, Clone, Default)]
pub struct TaintSpec {
    pub sources: Vec<NodeMatcher>,
    pub sinks: Vec<NodeMatcher>,
    pub sanitizers: Vec<NodeMatcher>,
}

/// A single source→sink flow reported by the engine.
#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub sink_start_byte: usize,
    pub sink_end_byte: usize,
    pub sink_line: usize,
    pub sink_column: usize,
    pub sink_end_line: usize,
    pub sink_end_column: usize,
    pub source_description: String,
    pub sink_description: String,
    /// 1-indexed line where the taint source was introduced.
    pub source_line: usize,
    /// Optional rule id hint set by the batched analyzer so callers can
    /// dispatch a finding back to the correct rule.
    pub rule_id_hint: Option<String>,
    /// Approximate number of hops along the source→sink flow.
    pub hops: u8,
}

/// How cross-file findings should be attributed to rules.
#[derive(Clone)]
pub enum RuleFilter<'a> {
    /// Only emit cross-file findings whose `sink_rule_id` equals the
    /// given value.
    Single(&'a str),
    /// Emit cross-file findings whose `sink_rule_id` appears in the
    /// given set.
    Any(&'a HashSet<String>),
}

impl<'a> RuleFilter<'a> {
    pub fn allows(&self, rule_id: &str) -> bool {
        match self {
            RuleFilter::Single(id) => *id == rule_id,
            RuleFilter::Any(set) => set.contains(rule_id),
        }
    }
}

/// Compact same-file return-taint summary keyed by function symbol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReturnTaintSummary {
    /// Return value is tainted by a source found inside the function body,
    /// independent of caller arguments.
    pub direct_source: Option<String>,
    /// Caller argument indices that taint the return value.
    pub params_to_return: Vec<usize>,
}

/// Return-taint summary map keyed by a function symbol.
pub type ReturnSummary = HashMap<String, ReturnTaintSummary>;

/// Inputs to the batched taint analyzer.
pub struct BatchedRule<'a> {
    pub rule_id: &'a str,
    pub spec: &'a TaintSpec,
}

/// A merged sanitizer-compatible batch of taint rules.
pub(super) struct BatchedTaintGroup {
    pub spec: TaintSpec,
    pub sink_to_rules: HashMap<String, Vec<String>>,
    pub allowed_rule_ids: HashSet<String>,
}

/// Sink matcher result with the optional owning rule id used in batched mode.
pub(super) struct MatchedSink {
    pub description: String,
    pub attribution_key: Option<String>,
    pub rule_ids: Vec<String>,
}

// ─── Internal types (pub(super) for language engines) ────────────────────

#[derive(Clone, Debug)]
pub(super) struct TaintInfo {
    pub description: String,
    pub line: usize,
}

#[derive(Default)]
pub(super) struct TaintState {
    pub tainted: HashMap<String, TaintInfo>,
}

impl TaintState {
    pub fn taint(&mut self, name: String, description: String, line: usize) {
        self.tainted.insert(name, TaintInfo { description, line });
    }

    pub fn clear(&mut self, name: &str) {
        self.tainted.remove(name);
    }

    pub fn info(&self, name: &str) -> Option<&TaintInfo> {
        self.tainted.get(name)
    }
}

/// Bundles the read-only context that every internal walker needs,
/// replacing the repeated `(source, spec, aliases, summaries)` tuple.
///
/// Generic over `CF`, the language-specific cross-file info type:
/// - JS/TS: `javascript_taint::CrossFileInfo`
/// - Python: `python_taint::CrossFileInfo`
/// - Go:    `go_taint::CrossFileInfo`
pub(super) struct AnalysisContext<'a, CF> {
    pub source: &'a str,
    pub spec: &'a TaintSpec,
    pub aliases: Option<&'a super::common::AliasTable>,
    pub summaries: &'a ReturnSummary,
    /// Cross-file info for resolving imported / same-package function calls.
    pub cross_file: Option<&'a CF>,
    /// When the batched analyzer merges sinks from multiple rules into a
    /// single `TaintSpec`, this map attributes each matched sink back to
    /// its owning rule id. `None` in single-rule mode.
    pub sink_to_rules: Option<&'a HashMap<String, Vec<String>>>,
}

// ─── Language adapter trait ──────────────────────────────────────────────

/// Trait implemented by each language-specific taint engine.
///
/// Generic over `CF`, the language-specific cross-file info type.
/// The generic walk/analyze functions call into this trait to dispatch to
/// language-specific AST handling. Each language implements the trait on a
/// zero-sized marker type (e.g. `JsTaintAdapter`, `PyTaintAdapter`,
/// `GoTaintAdapter`) parameterized by its `CrossFileInfo`.
pub(super) trait TaintLanguageAdapter<CF> {
    /// Returns `true` if `kind` is a nested function scope that should be
    /// skipped during the walk (each scope is analyzed independently).
    fn is_nested_scope(kind: &str) -> bool;

    /// Dispatch a single AST node to language-specific handlers during the
    /// main analysis walk. Implementations should match on `node.kind()`
    /// and call their assignment/declaration/call handlers as appropriate.
    fn dispatch_walk_node(
        node: Node<'_>,
        ctx: &AnalysisContext<'_, CF>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
    );

    /// Dispatch a single AST node during the summary walk (pass 1).
    /// Same as `dispatch_walk_node` but also handles `return_statement`
    /// for return-taint detection.
    fn dispatch_summary_node(
        node: Node<'_>,
        ctx: &AnalysisContext<'_, CF>,
        state: &mut TaintState,
        findings: &mut Vec<TaintFinding>,
        return_taint: &mut Option<String>,
    );

    /// Evaluate whether `expr` is tainted. Returns `(description, line)` or `None`.
    #[allow(dead_code)]
    fn expression_taint(
        expr: Node<'_>,
        ctx: &AnalysisContext<'_, CF>,
        state: &TaintState,
    ) -> Option<(String, usize)>;

    /// Seed taint state from function parameters that match source matchers.
    fn seed_params(func_node: Node<'_>, ctx: &AnalysisContext<'_, CF>, state: &mut TaintState);

    /// Get the function body node. Returns `None` if the function has no body.
    fn get_body(func_node: Node<'_>) -> Option<Node<'_>> {
        func_node.child_by_field_name("body")
    }
}

// ─── Generic walk functions ─────────────────────────────────────────────

/// Generic body walker for the main analysis pass (pass 2).
///
/// Skips nested scopes (as determined by `T::is_nested_scope`),
/// dispatches to language-specific handlers, then recurses into children.
pub(super) fn walk_body_generic<T: TaintLanguageAdapter<CF>, CF>(
    node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    if T::is_nested_scope(node.kind()) {
        return;
    }
    T::dispatch_walk_node(node, ctx, state, findings);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body_generic::<T, CF>(child, ctx, state, findings);
    }
}

/// Generic body walker for the summary pass (pass 1).
///
/// Same as `walk_body_generic` but also detects return-taint.
pub(super) fn walk_body_for_summary_generic<T: TaintLanguageAdapter<CF>, CF>(
    node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
    return_taint: &mut Option<String>,
) {
    if T::is_nested_scope(node.kind()) {
        return;
    }
    T::dispatch_summary_node(node, ctx, state, findings, return_taint);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_body_for_summary_generic::<T, CF>(child, ctx, state, findings, return_taint);
    }
}

/// Generic per-function analysis (pass 2).
///
/// Seeds parameter taint, gets the body, and walks it with the main walker.
pub(super) fn analyze_function_generic<T: TaintLanguageAdapter<CF>, CF>(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    findings: &mut Vec<TaintFinding>,
) {
    let mut state = TaintState::default();
    T::seed_params(func_node, ctx, &mut state);
    let Some(body) = T::get_body(func_node) else {
        return;
    };
    walk_body_generic::<T, CF>(body, ctx, &mut state, findings);
}

/// Generic pass-1 summarizer: seed params, walk body, detect return taint.
///
/// Returns `Option<String>` -- the first tainted return expression's
/// description, or `None` if the function returns clean.
pub(super) fn summarize_function_generic<T, CF>(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
) -> Option<String>
where
    T: TaintLanguageAdapter<CF>,
{
    let mut state = TaintState::default();
    T::seed_params(func_node, ctx, &mut state);
    let body = T::get_body(func_node)?;
    let mut scratch: Vec<TaintFinding> = Vec::new();
    let mut return_taint: Option<String> = None;
    walk_body_for_summary_generic::<T, CF>(body, ctx, &mut state, &mut scratch, &mut return_taint);
    return_taint
}

/// Generic return-taint summary builder.
///
/// Computes:
/// 1. `direct_source`: does the function body contain a tainted return
///    independent of caller arguments?
/// 2. `params_to_return`: which parameter indices flow to a return value?
pub(super) fn summarize_function_return_generic<T, CF>(
    func_node: Node<'_>,
    ctx: &AnalysisContext<'_, CF>,
    collect_param_names: impl Fn(Node<'_>, &str) -> Vec<String>,
) -> ReturnTaintSummary
where
    T: TaintLanguageAdapter<CF>,
{
    let direct_source = summarize_function_generic::<T, CF>(func_node, ctx);
    let mut summary = ReturnTaintSummary {
        direct_source,
        params_to_return: Vec::new(),
    };

    let empty_summary = ReturnSummary::new();
    for (param_idx, param_name) in collect_param_names(func_node, ctx.source)
        .into_iter()
        .enumerate()
    {
        let synthetic_spec = TaintSpec {
            sources: vec![NodeMatcher::ParamName {
                names: vec![param_name.clone()],
                description: format!("parameter '{}'", param_name),
            }],
            sinks: vec![],
            sanitizers: ctx.spec.sanitizers.clone(),
        };
        let param_ctx = AnalysisContext {
            source: ctx.source,
            spec: &synthetic_spec,
            aliases: ctx.aliases,
            summaries: &empty_summary,
            cross_file: None,
            sink_to_rules: None,
        };
        if summarize_function_generic::<T, CF>(func_node, &param_ctx).is_some() {
            summary.params_to_return.push(param_idx);
        }
    }

    summary
}

/// Extract cross-file taint summaries for a single function.
///
/// For each parameter, treat it as a synthetic taint source and test
/// whether it flows to any sink (producing `ParamSinkFlow` entries) or
/// to a return value (producing `params_to_return` entries).
///
/// This is the shared inner loop of `extract_cross_file_summaries` for
/// JS, Python, and Go. Callers provide the function node, its name,
/// its parameter names, rule specs, aliases, source, and the adapter type.
pub(super) fn extract_cross_file_summary_for_function<T, CF>(
    func_node: Node<'_>,
    func_name: &str,
    param_names: &[String],
    source: &str,
    aliases: Option<&super::common::AliasTable>,
    rule_specs: &[(&str, TaintSpec)],
) -> Option<FunctionTaintSummary>
where
    T: TaintLanguageAdapter<CF>,
{
    if param_names.is_empty() {
        return None;
    }

    let mut params_to_sink: Vec<ParamSinkFlow> = Vec::new();
    let mut params_to_return: Vec<usize> = Vec::new();

    // Partition rules: those without sanitizers can be batched into a
    // single analyze_function call per parameter; rules with sanitizers
    // must run individually to avoid incorrect taint clearing.
    let mut batched_sinks: Vec<NodeMatcher> = Vec::new();
    let mut sink_desc_to_rule: HashMap<&str, &str> = HashMap::new();
    let mut sanitizer_rules: Vec<(&str, &TaintSpec)> = Vec::new();
    for (rule_id, rule_spec) in rule_specs {
        if rule_spec.sanitizers.is_empty() {
            for sink in &rule_spec.sinks {
                sink_desc_to_rule.insert(sink.description(), rule_id);
                batched_sinks.push(sink.clone());
            }
        } else {
            sanitizer_rules.push((rule_id, rule_spec));
        }
    }

    let empty_summary = ReturnSummary::new();

    // Pre-build reusable specs outside the per-param loop.
    let placeholder_source = NodeMatcher::ParamName {
        names: vec![],
        description: String::new(),
    };
    let mut return_spec = TaintSpec {
        sources: vec![placeholder_source.clone()],
        sinks: vec![],
        sanitizers: vec![],
    };
    let mut batched_spec = TaintSpec {
        sources: vec![placeholder_source.clone()],
        sinks: batched_sinks,
        sanitizers: vec![],
    };
    let mut sanitizer_specs: Vec<TaintSpec> = sanitizer_rules
        .iter()
        .map(|(_, rule_spec)| TaintSpec {
            sources: vec![placeholder_source.clone()],
            sinks: rule_spec.sinks.clone(),
            sanitizers: rule_spec.sanitizers.clone(),
        })
        .collect();

    for (param_idx, param_name) in param_names.iter().enumerate() {
        let synthetic_source = NodeMatcher::ParamName {
            names: vec![param_name.clone()],
            description: format!("parameter '{}'", param_name),
        };

        // Check return-taint: does this parameter flow to a return value?
        return_spec.sources[0] = synthetic_source.clone();
        let return_ctx = AnalysisContext {
            source,
            spec: &return_spec,
            aliases,
            summaries: &empty_summary,
            cross_file: None,
            sink_to_rules: None,
        };
        let mut return_findings = Vec::new();
        let mut return_state = TaintState::default();
        T::seed_params(func_node, &return_ctx, &mut return_state);
        if let Some(body) = T::get_body(func_node) {
            let mut return_taint: Option<String> = None;
            walk_body_for_summary_generic::<T, CF>(
                body,
                &return_ctx,
                &mut return_state,
                &mut return_findings,
                &mut return_taint,
            );
            if return_taint.is_some() && !params_to_return.contains(&param_idx) {
                params_to_return.push(param_idx);
            }
        }

        let mut seen: HashSet<(usize, &str)> = HashSet::new();

        // Batched pass: one call for all no-sanitizer rules.
        if !batched_spec.sinks.is_empty() {
            batched_spec.sources[0] = synthetic_source.clone();
            let batched_ctx = AnalysisContext {
                source,
                spec: &batched_spec,
                aliases,
                summaries: &empty_summary,
                cross_file: None,
                sink_to_rules: None,
            };
            let mut findings = Vec::new();
            analyze_function_generic::<T, CF>(func_node, &batched_ctx, &mut findings);
            for f in &findings {
                if let Some(&rule_id) = sink_desc_to_rule.get(f.sink_description.as_str()) {
                    if seen.insert((param_idx, rule_id)) {
                        params_to_sink.push(ParamSinkFlow {
                            param_index: param_idx,
                            sink_rule_id: rule_id.to_string(),
                            sink_description: f.sink_description.clone(),
                        });
                    }
                }
            }
        }

        // Individual pass: rules with sanitizers run separately.
        for (idx, (rule_id, _)) in sanitizer_rules.iter().enumerate() {
            sanitizer_specs[idx].sources[0] = synthetic_source.clone();
            let sink_ctx = AnalysisContext {
                source,
                spec: &sanitizer_specs[idx],
                aliases,
                summaries: &empty_summary,
                cross_file: None,
                sink_to_rules: None,
            };
            let mut findings = Vec::new();
            analyze_function_generic::<T, CF>(func_node, &sink_ctx, &mut findings);
            if !findings.is_empty() && seen.insert((param_idx, rule_id)) {
                params_to_sink.push(ParamSinkFlow {
                    param_index: param_idx,
                    sink_rule_id: rule_id.to_string(),
                    sink_description: findings[0].sink_description.clone(),
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

// ─── Utilities ───────────────────────────────────────────────────────────

pub(super) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

/// Sentinel name used by the bridge to compile an "any function parameter"
/// taint source. Chosen to be a string no real identifier (including a PHP
/// `$`-variable like `$_GET`) can equal, so the use-site matchers never fire
/// on it — only `seed_params` interprets it (via [`param_names_are_wildcard`]).
pub const ANY_PARAM_WILDCARD: &str = "$<any-param>";

/// True when a `ParamName` matcher's name list designates the
/// "any function parameter" wildcard — i.e. it contains the
/// [`ANY_PARAM_WILDCARD`] sentinel.
///
/// This is the seed-time semantics for the Semgrep taint source shape
///
/// ```yaml
/// pattern-sources:
///   - patterns:
///       - pattern-inside: |
///           function ... (..., $ARG, ...) { ... }
///       - focus-metavariable: $ARG
/// ```
///
/// which means "every parameter of the enclosing function is a taint source".
/// The bridge ([`semgrep_taint`]) compiles such a block to
/// `ParamName { names: ["$PARAM"], .. }`; each engine's `seed_params` calls
/// this helper so a `$`-prefixed name seeds *all* parameters of the function
/// being analyzed, rather than only a literally-named one.
///
/// Discipline: the wildcard fires ONLY at parameter-seeding time. Use-site
/// matchers (`match_source`) compare against the literal name `$PARAM`, which
/// no real identifier equals, so the wildcard never broadens an expression-
/// position match — only function parameters become sources.
pub(super) fn param_names_are_wildcard(names: &[String]) -> bool {
    names.iter().any(|n| n == ANY_PARAM_WILDCARD)
}

pub(super) fn build_batched_taint_groups(rules: &[BatchedRule<'_>]) -> Vec<BatchedTaintGroup> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        let mut placed = false;
        for g in groups.iter_mut() {
            let rep = rules[g[0]].spec;
            if sanitizer_fingerprints_eq(&rep.sanitizers, &r.spec.sanitizers) {
                g.push(i);
                placed = true;
                break;
            }
        }
        if !placed {
            groups.push(vec![i]);
        }
    }

    let mut out = Vec::new();
    for group in groups {
        let mut merged_sources: Vec<NodeMatcher> = Vec::new();
        let mut merged_sinks: Vec<NodeMatcher> = Vec::new();
        let mut seen_source_keys: HashSet<String> = HashSet::new();
        let mut seen_sink_keys: HashSet<String> = HashSet::new();
        let mut sink_to_rules: HashMap<String, Vec<String>> = HashMap::new();
        let mut allowed_rule_ids: HashSet<String> = HashSet::new();

        for idx in &group {
            let rule = &rules[*idx];
            allowed_rule_ids.insert(rule.rule_id.to_string());
            for src in &rule.spec.sources {
                let source_key = matcher_fingerprint(src);
                if seen_source_keys.insert(source_key) {
                    merged_sources.push(src.clone());
                }
            }
            for sink in &rule.spec.sinks {
                let sink_key = matcher_fingerprint(sink);
                let rule_ids = sink_to_rules.entry(sink_key.clone()).or_default();
                if !rule_ids.iter().any(|id| id == rule.rule_id) {
                    rule_ids.push(rule.rule_id.to_string());
                }
                if seen_sink_keys.insert(sink_key) {
                    merged_sinks.push(sink.clone());
                }
            }
        }

        out.push(BatchedTaintGroup {
            spec: TaintSpec {
                sources: merged_sources,
                sinks: merged_sinks,
                sanitizers: rules[group[0]].spec.sanitizers.clone(),
            },
            sink_to_rules,
            allowed_rule_ids,
        });
    }
    out
}

pub(super) fn match_call_sink(
    spec: &TaintSpec,
    resolved_callee: &str,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    let final_segment = resolved_callee
        .rsplit('.')
        .next()
        .unwrap_or(resolved_callee);
    let root_segment = resolved_callee.split('.').next().unwrap_or(resolved_callee);
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::Call { canonical, .. } if canonical.as_str() == resolved_callee => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        NodeMatcher::MethodName { method, .. } if method == final_segment => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        // `$F(...)` + `metavariable-regex` on `$F`: match any call whose full
        // callee text matches the pinning regex (so dotted callee alternatives
        // such as `IO.popen` match against the whole `IO.popen` text).
        NodeMatcher::CallRegex { regex, .. } if regex.is_match(resolved_callee) => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        // `$OBJ.$M(...)` + `metavariable-regex` on `$M`: match any method call
        // whose final method name matches the pinning regex, any receiver.
        NodeMatcher::MethodNameRegex { regex, .. } if regex.is_match(final_segment) => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        // `os.$METHOD(...)` etc.: match any call whose callee root identifier
        // equals `receiver`. Requires a dotted callee (`receiver.method`) so a
        // bare call to a function literally named `receiver` does not match.
        NodeMatcher::ReceiverCall { receiver, .. }
            if root_segment == receiver.as_str() && resolved_callee.contains('.') =>
        {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        _ => None,
    })
}

pub(super) fn match_member_assign_sink(
    spec: &TaintSpec,
    field_name: &str,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::MemberAssign { field, .. } if field == field_name => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        _ => None,
    })
}

/// Return the first `BinopFormat` sink matcher in `spec`, if any. The engine
/// calls this when it has already confirmed (by inspecting the AST node) that a
/// string-building concatenation/format with a literal operand and a tainted
/// operand is present.
pub(super) fn match_binop_format_sink(
    spec: &TaintSpec,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::BinopFormat { .. } => Some(matched_sink_for_matcher(matcher, sink_to_rules)),
        _ => None,
    })
}

/// Return the first `ObjectLiteralValue` sink matcher in `spec`, if any. The
/// engine calls this when it has already confirmed (by inspecting the AST node)
/// that an object/dict literal is being constructed with at least one tainted
/// value position.
pub(super) fn match_object_literal_sink(
    spec: &TaintSpec,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::ObjectLiteralValue { .. } => {
            Some(matched_sink_for_matcher(matcher, sink_to_rules))
        }
        _ => None,
    })
}

/// Return the first `ReturnValue` sink matcher in `spec`, if any. The engine
/// calls this when it has confirmed (by inspecting the AST node) that a
/// `return` statement returns a tainted value.
pub(super) fn match_return_value_sink(
    spec: &TaintSpec,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> Option<MatchedSink> {
    spec.sinks.iter().find_map(|matcher| match matcher {
        NodeMatcher::ReturnValue { .. } => Some(matched_sink_for_matcher(matcher, sink_to_rules)),
        _ => None,
    })
}

fn matched_sink_for_matcher(
    matcher: &NodeMatcher,
    sink_to_rules: Option<&HashMap<String, Vec<String>>>,
) -> MatchedSink {
    let key = matcher_fingerprint(matcher);
    let rule_ids = sink_to_rules
        .and_then(|map| map.get(&key).cloned())
        .unwrap_or_default();
    MatchedSink {
        attribution_key: if rule_ids.is_empty() { None } else { Some(key) },
        description: matcher.description().to_string(),
        rule_ids,
    }
}

pub(super) fn attribution_hint_for_sink(sink: &MatchedSink) -> Option<String> {
    match &sink.attribution_key {
        Some(key) => Some(key.clone()),
        None => match sink.rule_ids.as_slice() {
            [rule_id] => Some(rule_id.clone()),
            _ => None,
        },
    }
}

pub(super) fn push_attributed_findings(
    out: &mut Vec<(String, TaintFinding)>,
    findings: Vec<TaintFinding>,
    sink_to_rules: &HashMap<String, Vec<String>>,
) {
    for finding in findings {
        let Some(hint) = finding.rule_id_hint.clone() else {
            continue;
        };
        if let Some(rule_ids) = sink_to_rules.get(&hint) {
            for rule_id in rule_ids {
                let mut attributed = finding.clone();
                attributed.rule_id_hint = Some(rule_id.clone());
                out.push((rule_id.clone(), attributed));
            }
        } else {
            let mut attributed = finding;
            attributed.rule_id_hint = Some(hint.clone());
            out.push((hint, attributed));
        }
    }
}

pub(super) fn taint_finding_for_node(
    node: Node<'_>,
    source_description: String,
    sink_description: String,
    source_line: usize,
    rule_id_hint: Option<String>,
    hops: u8,
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
        source_description,
        sink_description,
        source_line,
        rule_id_hint,
        hops,
    }
}

pub(super) fn cross_file_taint_finding(
    node: Node<'_>,
    source_description: String,
    source_line: usize,
    sink_description: &str,
    callee_name: &str,
    sink_rule_id: &str,
) -> TaintFinding {
    taint_finding_for_node(
        node,
        source_description,
        format!("{sink_description} (via cross-file call to {callee_name})"),
        source_line,
        Some(sink_rule_id.to_string()),
        2,
    )
}

pub(super) fn sanitizer_fingerprints_eq(a: &[NodeMatcher], b: &[NodeMatcher]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let fingerprint = |matchers: &[NodeMatcher]| -> Vec<String> {
        let mut v: Vec<String> = matchers.iter().map(matcher_fingerprint).collect();
        v.sort();
        v
    };
    fingerprint(a) == fingerprint(b)
}

pub(super) fn matcher_fingerprint(m: &NodeMatcher) -> String {
    match m {
        NodeMatcher::Attribute {
            root,
            field,
            description,
        } => format!("A|{root}|{field}|{description}"),
        NodeMatcher::Call {
            canonical,
            description,
        } => format!("C|{canonical}|{description}"),
        NodeMatcher::ParamName { names, description } => {
            format!("P|{}|{description}", names.join(","))
        }
        NodeMatcher::MethodName {
            method,
            description,
        } => {
            format!("M|{method}|{description}")
        }
        NodeMatcher::CallRegex { regex, description } => {
            format!("CR|{}|{description}", regex.as_str())
        }
        NodeMatcher::MethodNameRegex { regex, description } => {
            format!("MR|{}|{description}", regex.as_str())
        }
        NodeMatcher::ReceiverCall {
            receiver,
            description,
        } => {
            format!("R|{receiver}|{description}")
        }
        NodeMatcher::FieldName { field, description } => {
            format!("F|{field}|{description}")
        }
        NodeMatcher::Subscript { base, description } => {
            format!("S|{}|{description}", base.as_deref().unwrap_or("*"))
        }
        NodeMatcher::MemberAssign { field, description } => {
            format!("MA|{field}|{description}")
        }
        NodeMatcher::BinopFormat { description } => {
            format!("BF|{description}")
        }
        NodeMatcher::ObjectLiteralValue { description } => {
            format!("OL|{description}")
        }
        NodeMatcher::ReturnValue { description } => {
            format!("RV|{description}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_spec(source: NodeMatcher, sink: NodeMatcher) -> TaintSpec {
        TaintSpec {
            sources: vec![source],
            sinks: vec![sink],
            sanitizers: vec![],
        }
    }

    fn param_source(name: &str, description: &str) -> NodeMatcher {
        NodeMatcher::ParamName {
            names: vec![name.to_string()],
            description: description.to_string(),
        }
    }

    fn call_sink(canonical: &str, description: &str) -> NodeMatcher {
        NodeMatcher::Call {
            canonical: canonical.to_string(),
            description: description.to_string(),
        }
    }

    #[test]
    fn batched_group_keeps_distinct_matchers_with_same_description() {
        let spec_a = rule_spec(
            param_source("request", "input"),
            call_sink("a.exec", "exec"),
        );
        let spec_b = rule_spec(param_source("ctx", "input"), call_sink("b.exec", "exec"));
        let rules = [
            BatchedRule {
                rule_id: "rule-a",
                spec: &spec_a,
            },
            BatchedRule {
                rule_id: "rule-b",
                spec: &spec_b,
            },
        ];

        let groups = build_batched_taint_groups(&rules);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].spec.sources.len(), 2);
        assert_eq!(groups[0].spec.sinks.len(), 2);

        let matched = match_call_sink(&groups[0].spec, "a.exec", Some(&groups[0].sink_to_rules))
            .expect("a.exec should match");
        assert_eq!(matched.rule_ids, vec!["rule-a".to_string()]);
    }

    #[test]
    fn batched_group_fans_out_identical_sink_matchers_to_all_owner_rules() {
        let spec_a = rule_spec(param_source("request", "input"), call_sink("exec", "exec"));
        let spec_b = rule_spec(param_source("request", "input"), call_sink("exec", "exec"));
        let rules = [
            BatchedRule {
                rule_id: "rule-a",
                spec: &spec_a,
            },
            BatchedRule {
                rule_id: "rule-b",
                spec: &spec_b,
            },
        ];

        let groups = build_batched_taint_groups(&rules);
        let group = &groups[0];
        assert_eq!(group.spec.sources.len(), 1);
        assert_eq!(group.spec.sinks.len(), 1);

        let matched = match_call_sink(&group.spec, "exec", Some(&group.sink_to_rules))
            .expect("exec should match");
        assert_eq!(
            matched.rule_ids,
            vec!["rule-a".to_string(), "rule-b".to_string()]
        );

        let finding = TaintFinding {
            sink_start_byte: 0,
            sink_end_byte: 4,
            sink_line: 1,
            sink_column: 1,
            sink_end_line: 1,
            sink_end_column: 5,
            source_description: "input".to_string(),
            sink_description: "exec".to_string(),
            source_line: 1,
            rule_id_hint: attribution_hint_for_sink(&matched),
            hops: 1,
        };
        let mut out = Vec::new();
        push_attributed_findings(&mut out, vec![finding], &group.sink_to_rules);

        let rule_ids: Vec<String> = out.into_iter().map(|(rule_id, _)| rule_id).collect();
        assert_eq!(rule_ids, vec!["rule-a".to_string(), "rule-b".to_string()]);
    }
}
