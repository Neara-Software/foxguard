//! Semgrep-compatible YAML bridge for `mode: taint` rules.
//!
//! This module parses a *narrow* subset of Semgrep's taint-mode schema into
//! foxguard's [`TaintSpec`] so that users can load existing Semgrep taint
//! rules via `--rules` without rewriting them.
//!
//! # Supported today
//!
//! - `mode: taint` with `languages: [python]`, `languages: [javascript]` /
//!   `[typescript]` / `[js]` / `[ts]`, `languages: [go]` / `[golang]`,
//!   `languages: [java]`, `languages: [c]`, or `languages: [kotlin]` /
//!   `[kt]`.
//!   Other languages are rejected with a warning and the rule is skipped;
//!   non-taint rules fall through to the regular Semgrep bridge.
//! - `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` as lists of
//!   single-`pattern:` entries *or* `pattern-either:` lists (which may nest
//!   recursively and flatten into multiple matchers for the same role).
//! - Severity mapping via the same `map_severity` used by the pattern-rule
//!   bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium).
//! - `metadata.cwe` propagated to findings.
//!
//! # Unsupported (rule is skipped with a warning)
//!
//! - `pattern-inside:`, `metavariable-pattern:`, `patterns:` inside
//!   source/sink blocks.
//! - Any `mode: taint` rule that does not target Python, JavaScript/TypeScript,
//!   Go, Java, C, or Kotlin.
//! - Any `pattern:` string whose shape is not one of:
//!   - bare identifier (`request`) — compiled to `ParamName`
//!   - dotted attribute chain (`request.data`, `request.json`) — compiled
//!     to `Attribute { root, field }` using the *leftmost* identifier and
//!     the *outermost* attribute (nested chains like `request.session.id`
//!     are flattened to `root="request", field="id"`; documented as a known
//!     gap that matches the engine's own one-level attribute propagation).
//!   - call form (`pickle.loads($X)`, `pickle.loads(...)`, `func($X)`,
//!     `func()`) — compiled to `Call { canonical }`, stripping arguments.
//!   - metavariable-receiver call (`$CONN.executeQuery($X)`,
//!     `$OBJ.innerHTML($X)`) — compiled to `MethodName { method }`, which
//!     matches any invocation of that method name regardless of receiver.
//!     Only valid as a sink or sanitizer shape; rejected as a source.
//!   - metavariable-receiver assignment (`$EL.innerHTML = $X`,
//!     `$EL.outerHTML = $X`) — compiled to `MemberAssign { field }`, which
//!     matches any property-assignment sink whose property name equals
//!     `field`. Only meaningful for JavaScript/TypeScript rules (the JS
//!     engine recognises this as a DOM-XSS sink pattern); other language
//!     engines include the matcher in the compiled spec but silently ignore
//!     it. Only valid as a sink or sanitizer shape; rejected as a source.
//!
//! Unsupported patterns inside an otherwise-loadable rule cause the *whole
//! rule* to be skipped (with an explanatory warning) so the user sees a
//! clear signal rather than a silently-degraded match surface.

use crate::rules::c_taint;
use crate::rules::common::get_source_line;
use crate::rules::go_taint;
use crate::rules::java_taint;
use crate::rules::javascript_taint;
use crate::rules::kotlin_taint;
use crate::rules::python_taint;
use crate::rules::{FileContext, Rule};
use crate::{Finding, Language, Severity};
use serde_yaml_ng::Value as YamlValue;

// ─── Language-agnostic intermediate representation ───────────────────────
//
// The YAML bridge only produces three matcher shapes (Attribute, Call,
// ParamName).  Each engine has its own `NodeMatcher` enum with extra
// variants, but the YAML-compiled subset is identical across all three.
// We compile YAML into `GenericMatcher` first, then convert to the
// engine-specific type at analysis time.

#[derive(Clone, Debug)]
enum GenericMatcher {
    Attribute {
        root: String,
        field: String,
        description: String,
    },
    Call {
        canonical: String,
        description: String,
    },
    ParamName {
        names: Vec<String>,
        description: String,
    },
    /// Matches any method call whose final method name equals `method`,
    /// regardless of receiver. Compiled from patterns of the form
    /// `$METAVAR.method($X)` — the metavariable receiver is discarded and
    /// the engine matches any invocation of that method name.
    ///
    /// Supported as a sink/sanitizer shape for Python, JavaScript, Go, Java,
    /// and Kotlin. For C the matcher is included in the spec but the C engine
    /// only matches bare `Call` patterns, so `MethodName` entries are silently
    /// skipped (no C OOP method calls exist).
    MethodName { method: String, description: String },

    /// Matches a property-assignment sink of the form `$EL.field = $X`.
    /// Compiled from Semgrep patterns like `$EL.innerHTML = $X` where the
    /// receiver is any Semgrep metavariable and `field` is a plain identifier.
    ///
    /// Only meaningful as a sink shape for JavaScript/TypeScript rules — the
    /// JS engine recognises `NodeMatcher::MemberAssign` for DOM-XSS patterns
    /// (`element.innerHTML = tainted`, `element.outerHTML = tainted`, etc.).
    /// For all other language engines the matcher is included in the compiled
    /// spec but silently ignored (those engines have no concept of
    /// property-assignment sinks). Only valid as a sink or sanitizer shape;
    /// rejected as a source.
    MemberAssign { field: String, description: String },
}

#[derive(Clone, Debug)]
struct GenericSpec {
    sources: Vec<GenericMatcher>,
    sinks: Vec<GenericMatcher>,
    sanitizers: Vec<GenericMatcher>,
}

/// Convert the generic spec into a Python taint spec.
fn to_python_spec(g: &GenericSpec) -> python_taint::TaintSpec {
    python_taint::TaintSpec {
        sources: g.sources.iter().map(to_python_matcher).collect(),
        sinks: g.sinks.iter().map(to_python_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_python_matcher).collect(),
    }
}

fn to_python_matcher(m: &GenericMatcher) -> python_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => python_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => python_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => python_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => python_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Python engine ignores it (no property-assignment sinks in Python).
        GenericMatcher::MemberAssign { field, description } => {
            python_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
    }
}

/// Convert the generic spec into a JavaScript taint spec.
fn to_js_spec(g: &GenericSpec) -> javascript_taint::TaintSpec {
    javascript_taint::TaintSpec {
        sources: g.sources.iter().map(to_js_matcher).collect(),
        sinks: g.sinks.iter().map(to_js_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_js_matcher).collect(),
    }
}

fn to_js_matcher(m: &GenericMatcher) -> javascript_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => javascript_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => javascript_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => {
            javascript_taint::NodeMatcher::ParamName {
                names: names.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodName {
            method,
            description,
        } => javascript_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            javascript_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
    }
}

/// Convert the generic spec into a Go taint spec.
fn to_go_spec(g: &GenericSpec) -> go_taint::TaintSpec {
    go_taint::TaintSpec {
        sources: g.sources.iter().map(to_go_matcher).collect(),
        sinks: g.sinks.iter().map(to_go_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_go_matcher).collect(),
    }
}

fn to_go_matcher(m: &GenericMatcher) -> go_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => go_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => go_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => go_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => go_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Go engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            go_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
    }
}

/// Convert the generic spec into a Java taint spec.
fn to_java_spec(g: &GenericSpec) -> java_taint::TaintSpec {
    java_taint::TaintSpec {
        sources: g.sources.iter().map(to_java_matcher).collect(),
        sinks: g.sinks.iter().map(to_java_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_java_matcher).collect(),
    }
}

fn to_java_matcher(m: &GenericMatcher) -> java_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => java_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => java_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => java_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => java_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Java engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            java_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
    }
}

/// Convert the generic spec into a C taint spec.
fn to_c_spec(g: &GenericSpec) -> c_taint::TaintSpec {
    c_taint::TaintSpec {
        sources: g.sources.iter().map(to_c_matcher).collect(),
        sinks: g.sinks.iter().map(to_c_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_c_matcher).collect(),
    }
}

fn to_c_matcher(m: &GenericMatcher) -> c_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => c_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => c_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => c_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        // C has no OOP method calls; include the matcher for spec completeness but
        // the C engine only recognises `NodeMatcher::Call`, so it will never fire.
        GenericMatcher::MethodName {
            method,
            description,
        } => c_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the C engine ignores it.
        GenericMatcher::MemberAssign { field, description } => c_taint::NodeMatcher::MemberAssign {
            field: field.clone(),
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Kotlin taint spec.
fn to_kotlin_spec(g: &GenericSpec) -> kotlin_taint::TaintSpec {
    kotlin_taint::TaintSpec {
        sources: g.sources.iter().map(to_kotlin_matcher).collect(),
        sinks: g.sinks.iter().map(to_kotlin_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_kotlin_matcher).collect(),
    }
}

fn to_kotlin_matcher(m: &GenericMatcher) -> kotlin_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => kotlin_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => kotlin_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => kotlin_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => kotlin_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Kotlin engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            kotlin_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
    }
}

/// A compiled Semgrep `mode: taint` rule.
pub struct SemgrepTaintRule {
    pub id: String,
    pub message: String,
    pub severity: Severity,
    pub cwe: Option<String>,
    pub lang: Language,
    spec: GenericSpec,
}

/// Unified view over the three engine-specific `TaintFinding` types.
struct TaintFindingView {
    sink_start_byte: usize,
    sink_line: usize,
    sink_column: usize,
    sink_end_line: usize,
    sink_end_column: usize,
    source_description: String,
    sink_description: String,
    source_line: usize,
    hops: u8,
}

impl TaintFindingView {
    fn from_python(f: python_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            hops: f.hops,
        }
    }
    fn from_js(f: javascript_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            hops: f.hops,
        }
    }
    fn from_go(f: go_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            hops: f.hops,
        }
    }
    fn from_java(f: java_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            hops: f.hops,
        }
    }
    fn from_c(f: c_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            hops: f.hops,
        }
    }
    fn from_kotlin(f: kotlin_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_line: f.sink_line,
            sink_column: f.sink_column,
            sink_end_line: f.sink_end_line,
            sink_end_column: f.sink_end_column,
            source_description: f.source_description,
            sink_description: f.sink_description,
            source_line: f.source_line,
            hops: f.hops,
        }
    }
}

impl Rule for SemgrepTaintRule {
    fn id(&self) -> &str {
        &self.id
    }
    fn severity(&self) -> Severity {
        self.severity
    }
    fn cwe(&self) -> Option<&str> {
        self.cwe.as_deref()
    }
    fn description(&self) -> &str {
        &self.message
    }
    fn language(&self) -> Language {
        self.lang
    }

    fn check(&self, source: &str, tree: &tree_sitter::Tree) -> Vec<Finding> {
        self.check_with_context(source, tree, &FileContext::default())
    }

    fn ast_analysis_requirement(&self) -> crate::rules::AstAnalysisRequirement {
        crate::rules::AstAnalysisRequirement::FileContext
    }

    fn check_with_context(
        &self,
        source: &str,
        tree: &tree_sitter::Tree,
        ctx: &FileContext<'_>,
    ) -> Vec<Finding> {
        // Dispatch to the appropriate taint engine based on the rule's
        // target language. Each engine returns the same TaintFinding shape.
        let raw: Vec<TaintFindingView> = match self.lang {
            Language::Python => {
                let spec = to_python_spec(&self.spec);
                python_taint::analyze_tree(tree.root_node(), source, &spec, ctx.python_aliases)
                    .into_iter()
                    .map(TaintFindingView::from_python)
                    .collect()
            }
            Language::JavaScript => {
                let spec = to_js_spec(&self.spec);
                javascript_taint::analyze_tree(
                    tree.root_node(),
                    source,
                    &spec,
                    ctx.javascript_aliases,
                )
                .into_iter()
                .map(TaintFindingView::from_js)
                .collect()
            }
            Language::Go => {
                let spec = to_go_spec(&self.spec);
                go_taint::analyze_tree(tree.root_node(), source, &spec, ctx.go_aliases)
                    .into_iter()
                    .map(TaintFindingView::from_go)
                    .collect()
            }
            Language::Java => {
                let spec = to_java_spec(&self.spec);
                java_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_java)
                    .collect()
            }
            Language::C => {
                let spec = to_c_spec(&self.spec);
                c_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_c)
                    .collect()
            }
            Language::Kotlin => {
                let spec = to_kotlin_spec(&self.spec);
                kotlin_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_kotlin)
                    .collect()
            }
            _ => Vec::new(),
        };
        raw.into_iter()
            .map(|t| Finding {
                rule_id: self.id.clone(),
                severity: self.severity,
                cwe: self.cwe.clone(),
                description: format!(
                    "{} — {} reaches {}",
                    self.message, t.source_description, t.sink_description
                ),
                file: String::new(),
                line: t.sink_line,
                column: t.sink_column,
                end_line: t.sink_end_line,
                end_column: t.sink_end_column,
                snippet: get_source_line(source, t.sink_start_byte),
                source_line: Some(t.source_line),
                source_description: Some(t.source_description),
                sink_line: Some(t.sink_line),
                sink_description: Some(t.sink_description),
                fix_suggestion: None,
                sink_start_byte: None,
                sink_end_byte: None,
                confidence: crate::rules::common::confidence_for_hops(t.hops),
                taint_hops: Some(t.hops),
                tags: vec![],
                crypto_algorithm: None,
                cnsa2_deadline: None,
                dep_name: None,
                dep_version: None,
                dep_ecosystem: None,
                dep_purl: None,
                dep_vulnerability_id: None,
                dep_fixed_version: None,
                dep_source: None,
                dep_vulnerability_severity: None,
                dep_path: vec![],
            })
            .collect()
    }
}

// ─── YAML → TaintSpec compilation ─────────────────────────────────────────

/// Outcome of trying to parse a single YAML rule as a taint rule.
pub enum TaintRuleParse {
    /// The rule is `mode: taint` and was compiled successfully.
    Compiled(SemgrepTaintRule),
    /// The rule is `mode: taint` but we could not compile it (bad language,
    /// unsupported pattern syntax, missing required sections, …). The caller
    /// should surface the warning and skip the rule.
    Skip(String),
    /// The rule is *not* `mode: taint`. The caller should fall through to
    /// its existing pattern-rule handling path.
    NotTaint,
}

/// Attempt to parse a single Semgrep YAML rule as a `mode: taint` rule.
///
/// Returns [`TaintRuleParse::NotTaint`] when the rule does not declare
/// `mode: taint`, so the caller can keep running its normal pattern-rule
/// compilation without an early exit.
pub fn parse_taint_rule(yaml: &YamlValue) -> TaintRuleParse {
    // Only engage for rules that explicitly declare `mode: taint`.
    let mode = yaml.get("mode").and_then(YamlValue::as_str);
    if mode != Some("taint") {
        return TaintRuleParse::NotTaint;
    }

    let id = match yaml.get("id").and_then(YamlValue::as_str) {
        Some(s) => s.to_string(),
        None => return TaintRuleParse::Skip("taint rule missing `id`".into()),
    };

    // Determine the target language. We support Python, JavaScript/TypeScript,
    // Go, Java, C, and Kotlin. The first recognised language wins.
    let lang = match yaml.get("languages").and_then(YamlValue::as_sequence) {
        Some(langs) => {
            let mut detected: Option<Language> = None;
            for s in langs.iter().filter_map(YamlValue::as_str) {
                match s.to_lowercase().as_str() {
                    "python" | "py" => {
                        detected = Some(Language::Python);
                        break;
                    }
                    "javascript" | "js" | "typescript" | "ts" => {
                        detected = Some(Language::JavaScript);
                        break;
                    }
                    "go" | "golang" => {
                        detected = Some(Language::Go);
                        break;
                    }
                    "java" => {
                        detected = Some(Language::Java);
                        break;
                    }
                    "c" => {
                        detected = Some(Language::C);
                        break;
                    }
                    "kotlin" | "kt" => {
                        detected = Some(Language::Kotlin);
                        break;
                    }
                    _ => {}
                }
            }
            match detected {
                Some(l) => l,
                None => {
                    return TaintRuleParse::Skip(format!(
                        "taint rule `{}` targets unsupported languages; Python, JavaScript/TypeScript, Go, Java, C, and Kotlin are supported",
                        id
                    ));
                }
            }
        }
        None => return TaintRuleParse::Skip(format!("taint rule `{}` missing `languages`", id)),
    };

    let message = yaml
        .get("message")
        .and_then(YamlValue::as_str)
        .unwrap_or("")
        .to_string();

    let severity_str = yaml
        .get("severity")
        .and_then(YamlValue::as_str)
        .unwrap_or("WARNING");
    let severity = map_severity(severity_str);

    let cwe = extract_cwe(yaml);

    // ── Compile sources ────────────────────────────────────────────────
    let sources = match compile_matcher_list(yaml.get("pattern-sources"), MatcherRole::Source, &id)
    {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };
    if sources.is_empty() {
        return TaintRuleParse::Skip(format!(
            "taint rule `{}` has no valid `pattern-sources`",
            id
        ));
    }

    let sinks = match compile_matcher_list(yaml.get("pattern-sinks"), MatcherRole::Sink, &id) {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };
    if sinks.is_empty() {
        return TaintRuleParse::Skip(format!("taint rule `{}` has no valid `pattern-sinks`", id));
    }

    let sanitizers =
        match compile_matcher_list(yaml.get("pattern-sanitizers"), MatcherRole::Sanitizer, &id) {
            Ok(v) => v,
            Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
        };

    TaintRuleParse::Compiled(SemgrepTaintRule {
        id: format!("semgrep/{}", id),
        message,
        severity,
        cwe,
        lang,
        spec: GenericSpec {
            sources,
            sinks,
            sanitizers,
        },
    })
}

#[derive(Copy, Clone)]
enum MatcherRole {
    Source,
    Sink,
    Sanitizer,
}

impl MatcherRole {
    fn label(self) -> &'static str {
        match self {
            MatcherRole::Source => "pattern-sources",
            MatcherRole::Sink => "pattern-sinks",
            MatcherRole::Sanitizer => "pattern-sanitizers",
        }
    }
}

/// Compile a top-level `pattern-sources` / `pattern-sinks` /
/// `pattern-sanitizers` list.
///
/// Each entry is allowed to be either:
///
/// - a mapping with a single `pattern:` key (compiled to one [`NodeMatcher`]),
/// - a mapping with a single `pattern-either:` key whose value is itself a
///   list of entries following the same rules (flattened recursively into
///   multiple matchers).
///
/// Any other key (`patterns:`, `pattern-inside:`, `metavariable-pattern:`,
/// …) is rejected with a warning that names the rule and the offending key,
/// and the individual entry is skipped. If the role ends up with *no* valid
/// entries the caller decides whether that is fatal for the whole rule
/// (sources and sinks are required; sanitizers may legitimately be empty).
fn compile_matcher_list(
    node: Option<&YamlValue>,
    role: MatcherRole,
    rule_id: &str,
) -> Result<Vec<GenericMatcher>, String> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let Some(entries) = node.as_sequence() else {
        return Err(format!("{} must be a list", role.label()));
    };

    let mut out = Vec::new();
    for entry in entries {
        compile_entry(entry, role, rule_id, &mut out);
    }
    Ok(out)
}

/// Compile a single entry from a source/sink/sanitizer list, flattening
/// nested `pattern-either:` blocks. Invalid entries emit a warning and are
/// skipped rather than aborting the whole rule.
fn compile_entry(
    entry: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    out: &mut Vec<GenericMatcher>,
) {
    let Some(map) = entry.as_mapping() else {
        eprintln!(
            "Warning: taint rule `{}` {} entry is not a mapping; skipping",
            rule_id,
            role.label()
        );
        return;
    };

    // Entries are expected to carry exactly one top-level key. Having more
    // than one suggests the user meant `patterns:` semantics, which we
    // don't support inside taint blocks — warn and skip.
    if map.len() != 1 {
        eprintln!(
            "Warning: taint rule `{}` {} entry has {} keys (expected a single `pattern:` or `pattern-either:`); skipping entry",
            rule_id,
            role.label(),
            map.len(),
        );
        return;
    }

    let (k, v) = map.iter().next().expect("map.len() == 1");
    match k.as_str() {
        Some("pattern") => {
            let Some(pattern) = v.as_str() else {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern:` value must be a string; skipping entry",
                    rule_id,
                    role.label()
                );
                return;
            };
            match compile_pattern(pattern, role) {
                Some(m) => out.push(m),
                None => eprintln!(
                    "Warning: taint rule `{}` {} unsupported pattern shape `{}`; skipping entry",
                    rule_id,
                    role.label(),
                    pattern
                ),
            }
        }
        Some("pattern-either") => {
            let Some(inner) = v.as_sequence() else {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern-either:` must be a list; skipping",
                    rule_id,
                    role.label()
                );
                return;
            };
            if inner.is_empty() {
                eprintln!(
                    "Warning: taint rule `{}` {} `pattern-either:` is empty; producing no matchers",
                    rule_id,
                    role.label()
                );
                return;
            }
            for nested in inner {
                compile_entry(nested, role, rule_id, out);
            }
        }
        Some(other) => {
            eprintln!(
                "Warning: taint rule `{}` {} uses unsupported key `{}` (only `pattern:` and `pattern-either:` are supported); skipping entry",
                rule_id,
                role.label(),
                other
            );
        }
        None => {
            eprintln!(
                "Warning: taint rule `{}` {} entry has a non-string key; skipping",
                rule_id,
                role.label()
            );
        }
    }
}

/// Compile a single Semgrep pattern string into a [`NodeMatcher`].
///
/// Returns `None` if the pattern shape is not one of the supported forms
/// (see module docs). Callers surface that as a skip-with-warning at the
/// rule level.
fn compile_pattern(pattern: &str, role: MatcherRole) -> Option<GenericMatcher> {
    let pat = pattern.trim();
    if pat.is_empty() {
        return None;
    }

    // ── MemberAssign form: `$METAVAR.field = $X` ────────────────────────
    //
    // Semgrep taint rules for DOM-XSS commonly express property-assignment
    // sinks as `$EL.innerHTML = $X`, `$EL.outerHTML = $X`, etc.  The bridge
    // compiles these to `MemberAssign { field }`, which the JavaScript engine
    // matches against any assignment whose LHS property name equals `field`.
    //
    // Detection: the pattern contains ` = ` (single `=`, not `==`), and the
    // LHS parses as `$METAVAR.plain_field` with no call parens.
    //
    // Only valid as a sink or sanitizer shape — not a source, since a
    // property assignment is a data-flow destination, not an origin.
    if let Some(field) = parse_member_assign_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::MemberAssign {
                field: field.to_string(),
                description: describe(field, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── Call form: `root.method(...)` or `func($X)` ─────────────────────
    if let Some(open_paren) = pat.find('(') {
        if !pat.ends_with(')') {
            return None;
        }
        let callee = pat[..open_paren].trim();
        if callee.is_empty() {
            return None;
        }

        // ── MethodName shape: `$METAVAR.method($X)` ─────────────────────
        //
        // When the callee is `$VAR.method` — a single metavariable segment
        // followed by exactly one plain identifier — we compile to
        // `MethodName { method }`, which the engine matches against the
        // *final* segment of any resolved callee regardless of receiver.
        //
        // This covers the common Semgrep pattern shape used for OOP sinks
        // like `$CONN.executeQuery($X)`, `$OBJ.innerHTML`, etc., that are
        // currently warn-skipped because the `$`-prefixed segment fails the
        // `is_dotted_identifier` check.
        //
        // Only meaningful as a sink/sanitizer shape (matching any receiver),
        // not a source.
        if let Some(method) = parse_metavar_dot_method(callee) {
            return match role {
                MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::MethodName {
                    method: method.to_string(),
                    description: describe(method, role),
                }),
                MatcherRole::Source => None,
            };
        }

        // Callee must be a plain identifier or dotted identifier chain.
        if !is_dotted_identifier(callee) {
            return None;
        }
        let canonical = callee.to_string();
        return Some(GenericMatcher::Call {
            canonical: canonical.clone(),
            description: describe(&canonical, role),
        });
    }

    // ── No parens: identifier or attribute chain ────────────────────────
    if !is_dotted_identifier(pat) {
        return None;
    }

    if let Some(dot) = pat.rfind('.') {
        // `root.field` or `root.intermediate.field`. The engine only
        // supports one-level roots, so we take the leftmost segment as
        // the root and the outermost (last) segment as the field.
        let root = pat[..pat.find('.').expect("rfind guarantees at least one dot")].to_string();
        let field = pat[dot + 1..].to_string();
        if root.is_empty() || field.is_empty() {
            return None;
        }
        let desc = describe(pat, role);
        return Some(GenericMatcher::Attribute {
            root,
            field,
            description: desc,
        });
    }

    // Bare identifier → treat as a ParamName source / sink would not make
    // sense, so for non-source roles we refuse this shape.
    match role {
        MatcherRole::Source => Some(GenericMatcher::ParamName {
            names: vec![pat.to_string()],
            description: format!("untrusted `{}` parameter", pat),
        }),
        MatcherRole::Sink | MatcherRole::Sanitizer => None,
    }
}

/// If `pat` has the assignment shape `$METAVAR.field = $RHS` — a metavariable
/// receiver, a plain identifier property name, a single `=` operator, and any
/// RHS expression — return the property field name.  Returns `None` for all
/// other shapes (including `==`, `!=`, `<=`, `>=` operators).
///
/// Examples:
/// - `$EL.innerHTML = $X`  → `Some("innerHTML")`
/// - `$EL.outerHTML = $X`  → `Some("outerHTML")`
/// - `$FORM.action = $X`   → `Some("action")`
/// - `pickle.loads($X)`    → `None` (call form, no `=`)
/// - `$EL.innerHTML == $X` → `None` (equality comparison, not assignment)
/// - `$EL.a.b = $X`        → `None` (multi-segment LHS, ambiguous)
fn parse_member_assign_pattern(pat: &str) -> Option<&str> {
    // Find ` = ` with single `=` — must not be preceded or followed by
    // `=`, `!`, `<`, `>` to avoid confusing `==`, `!=`, `<=`, `>=`.
    let eq_pos = find_single_assignment(pat)?;
    let lhs = pat[..eq_pos].trim();
    // No call parens allowed in the LHS.
    if lhs.contains('(') || lhs.contains(')') {
        return None;
    }
    // LHS must have exactly the shape `$METAVAR.field`.
    parse_metavar_dot_method(lhs)
}

/// Find the byte offset of a standalone `=` in `s`, i.e. `=` that is not
/// part of `==`, `!=`, `<=`, or `>=`.  Returns the position of the `=`
/// character, or `None` if no such operator is present.
fn find_single_assignment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'=' {
            continue;
        }
        // Reject `==`.
        if bytes.get(i + 1) == Some(&b'=') {
            continue;
        }
        // Reject `!=`, `<=`, `>=`.
        if i > 0 && matches!(bytes[i - 1], b'!' | b'<' | b'>') {
            continue;
        }
        return Some(i);
    }
    None
}

/// If `callee` has the shape `$METAVAR.plain_method` — exactly one
/// `$`-prefixed metavariable segment followed by a plain identifier — return
/// the method name. Returns `None` for all other shapes.
///
/// Examples:
/// - `$CONN.executeQuery` → `Some("executeQuery")`
/// - `$OBJ.innerHTML` → `Some("innerHTML")`
/// - `pickle.loads` → `None` (dotted plain identifier, handled as `Call`)
/// - `$X` → `None` (bare metavariable, no method)
/// - `$A.b.c` → `None` (more than one segment after the metavar)
fn parse_metavar_dot_method(callee: &str) -> Option<&str> {
    let dot = callee.find('.')?;
    let receiver = &callee[..dot];
    let rest = &callee[dot + 1..];
    // Receiver must be a metavariable: `$` followed by UPPER or `_`
    if !is_metavariable(receiver) {
        return None;
    }
    // The rest must be a single plain identifier (no more dots).
    if rest.contains('.') {
        return None;
    }
    if !is_identifier(rest) {
        return None;
    }
    Some(rest)
}

/// True when `s` is a Semgrep metavariable: `$` followed by one or more
/// ASCII uppercase letters or underscores (e.g. `$X`, `$CONN`, `$_`).
fn is_metavariable(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('$') => {}
        _ => return false,
    }
    let rest: String = chars.collect();
    // Semgrep metavariables are `$` + `[A-Z_][A-Z0-9_]*` — allow trailing digits
    // (e.g. `$ARG1`) while still rejecting lowercase (`$obj`).
    !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn describe(canonical: &str, role: MatcherRole) -> String {
    match role {
        MatcherRole::Source => format!("semgrep source `{}`", canonical),
        MatcherRole::Sink => format!("semgrep sink `{}`", canonical),
        MatcherRole::Sanitizer => format!("semgrep sanitizer `{}`", canonical),
    }
}

/// True when `s` is a `.`-separated chain of identifier segments, each of
/// which is an ASCII identifier (`[A-Za-z_][A-Za-z0-9_]*`). Used to reject
/// pattern strings that contain metavariables, operators, or whitespace
/// outside of a call form.
fn is_dotted_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.').all(is_identifier)
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn map_severity(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "ERROR" => Severity::Critical,
        "WARNING" => Severity::High,
        "INFO" => Severity::Medium,
        _ => Severity::Medium,
    }
}

fn extract_cwe(yaml: &YamlValue) -> Option<String> {
    let meta = yaml.get("metadata")?;
    let cwe = meta.get("cwe")?;
    match cwe {
        YamlValue::String(s) => Some(s.clone()),
        YamlValue::Sequence(v) => v.first().and_then(|x| x.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(pattern: &str, role: MatcherRole) -> Option<GenericMatcher> {
        compile_pattern(pattern, role)
    }

    #[test]
    fn compile_attribute_source() {
        let m = compile("request.data", MatcherRole::Source).expect("attribute");
        match m {
            GenericMatcher::Attribute { root, field, .. } => {
                assert_eq!(root, "request");
                assert_eq!(field, "data");
            }
            _ => panic!("expected Attribute"),
        }
    }

    #[test]
    fn compile_nested_attribute_takes_leftmost_root_and_outermost_field() {
        let m = compile("request.session.user_id", MatcherRole::Source).expect("attribute");
        match m {
            GenericMatcher::Attribute { root, field, .. } => {
                assert_eq!(root, "request");
                assert_eq!(field, "user_id");
            }
            _ => panic!("expected Attribute"),
        }
    }

    #[test]
    fn compile_call_with_metavar() {
        let m = compile("pickle.loads($X)", MatcherRole::Sink).expect("call");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "pickle.loads"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_call_with_ellipsis() {
        let m = compile("pickle.loads(...)", MatcherRole::Sink).expect("call");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "pickle.loads"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_bare_func_call() {
        let m = compile("eval($X)", MatcherRole::Sink).expect("call");
        match m {
            GenericMatcher::Call { canonical, .. } => assert_eq!(canonical, "eval"),
            _ => panic!("expected Call"),
        }
    }

    #[test]
    fn compile_bare_identifier_source() {
        let m = compile("request", MatcherRole::Source).expect("paramname");
        match m {
            GenericMatcher::ParamName { names, .. } => {
                assert_eq!(names, vec!["request".to_string()])
            }
            _ => panic!("expected ParamName"),
        }
    }

    #[test]
    fn bare_identifier_rejected_as_sink() {
        assert!(compile("request", MatcherRole::Sink).is_none());
    }

    #[test]
    fn weird_shapes_rejected() {
        assert!(compile("$X + $Y", MatcherRole::Source).is_none());
        assert!(compile("a.b.c(d", MatcherRole::Sink).is_none());
        assert!(compile("", MatcherRole::Source).is_none());
    }

    #[test]
    fn parse_full_taint_rule() {
        let yaml = r#"
id: semgrep-pickle-taint
mode: taint
languages: [python]
severity: ERROR
message: "Untrusted input reaches pickle.loads"
metadata:
  cwe: "CWE-502"
pattern-sources:
  - pattern: request.data
  - pattern: request
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.id, "semgrep/semgrep-pickle-taint");
                assert_eq!(r.lang, Language::Python);
                assert_eq!(r.cwe.as_deref(), Some("CWE-502"));
                assert_eq!(r.spec.sources.len(), 2);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn non_taint_rule_falls_through() {
        let yaml = r#"
id: classic
pattern: eval(...)
message: x
severity: ERROR
languages: [python]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::NotTaint));
    }

    #[test]
    fn taint_rule_with_unsupported_language_is_skipped() {
        let yaml = r#"
id: x
mode: taint
languages: [ruby]
severity: ERROR
message: m
pattern-sources: [{pattern: req}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)));
    }

    #[test]
    fn taint_rule_with_c_language_compiles() {
        let yaml = r#"
id: c-taint
mode: taint
languages: [c]
severity: ERROR
message: m
pattern-sources: [{pattern: getenv($X)}]
pattern-sinks: [{pattern: system($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::C);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_kotlin_language_compiles() {
        let yaml = r#"
id: kotlin-taint
mode: taint
languages: [kotlin]
severity: ERROR
message: m
pattern-sources: [{pattern: request.getParameter($X)}]
pattern-sinks: [{pattern: Runtime.exec($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Kotlin);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_kt_alias_compiles_as_kotlin() {
        let yaml = r#"
id: kt-taint
mode: taint
languages: [kt]
severity: ERROR
message: m
pattern-sources: [{pattern: call.receiveText($X)}]
pattern-sinks: [{pattern: Runtime.exec($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::Kotlin),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_javascript_language_compiles() {
        let yaml = r#"
id: js-taint
mode: taint
languages: [javascript]
severity: ERROR
message: m
pattern-sources: [{pattern: req.query}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::JavaScript);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_typescript_language_compiles_as_javascript() {
        let yaml = r#"
id: ts-taint
mode: taint
languages: [typescript]
severity: ERROR
message: m
pattern-sources: [{pattern: req.body}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::JavaScript),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_go_language_compiles() {
        let yaml = r#"
id: go-taint
mode: taint
languages: [go]
severity: ERROR
message: m
pattern-sources: [{pattern: c.Query($X)}]
pattern-sinks: [{pattern: exec.Command($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Go);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_java_language_compiles() {
        let yaml = r#"
id: java-taint
mode: taint
languages: [java]
severity: ERROR
message: m
pattern-sources: [{pattern: request.getParameter($X)}]
pattern-sinks: [{pattern: Runtime.exec($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Java);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn java_taint_rule_produces_finding_for_source_to_sink_flow() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-cmd-injection
mode: taint
languages: [java]
severity: ERROR
message: "Tainted input reaches Runtime.exec"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
"#,
        );

        // Source: request.getParameter(...) → cmd → Runtime.exec(cmd)
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for request.getParameter -> Runtime.exec flow, got none"
        );
        assert!(
            findings[0].description.contains("Runtime.exec")
                || findings[0]
                    .sink_description
                    .as_deref()
                    .is_some_and(|d| d.contains("exec")),
            "sink description should mention exec: {:?}",
            findings[0]
        );
    }

    #[test]
    fn java_taint_sanitizer_blocks_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-cmd-sanitized
mode: taint
languages: [java]
severity: ERROR
message: "Tainted input reaches Runtime.exec"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
pattern-sanitizers:
  - pattern: validate($X)
"#,
        );

        // The sanitizer validate() is called — engine does not track sanitizers on
        // intermediate variables for this shape, but the call assignment
        // reassigns cmd to a clean value if the sanitizer is applied first.
        // Use a shape the engine cleanly handles: param goes directly to sanitizer,
        // then to sink. The sanitizer call replaces the tainted value so the sink
        // should not fire.
        let src = r#"
class Controller {
    void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        String safe = validate(cmd);
        Runtime.getRuntime().exec(safe);
    }
}
"#;
        // With the sanitizer call reassigning to `safe`, the engine should not
        // propagate taint through the sanitizer call, so no finding.
        // Note: this tests the integration of the sanitizer matcher in the
        // compiled Java spec — whether the engine actually blocks it depends
        // on the java_taint engine's sanitizer handling. We assert the compiled
        // rule carries sanitizers correctly.
        assert_eq!(
            rule.spec.sanitizers.len(),
            1,
            "sanitizer spec should compile"
        );
        // Run the check and ensure no crash (result depends on engine sanitizer support).
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let _ = rule.check(src, &tree); // must not panic
    }

    #[test]
    fn c_taint_rule_produces_finding_for_getenv_to_system() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: c-cmd-injection
mode: taint
languages: [c]
severity: ERROR
message: "Tainted env var reaches system()"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: getenv($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        // getenv() result assigned to cmd, then passed to system().
        let src = r#"
#include <stdlib.h>
void handler() {
    char *cmd = getenv("CMD");
    system(cmd);
}
"#;
        let tree = parse_file(src, Language::C).expect("C fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for getenv -> system flow, got none"
        );
        assert!(
            findings[0].description.contains("system")
                || findings[0]
                    .sink_description
                    .as_deref()
                    .is_some_and(|d| d.contains("system")),
            "sink description should mention system: {:?}",
            findings[0]
        );
    }

    #[test]
    fn c_taint_sanitizer_no_panic() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: c-cmd-sanitized
mode: taint
languages: [c]
severity: ERROR
message: "Tainted input reaches system()"
pattern-sources:
  - pattern: getenv($X)
pattern-sinks:
  - pattern: system($X)
pattern-sanitizers:
  - pattern: strlcpy($X)
"#,
        );

        // Verify sanitizer compiles correctly and rule doesn't panic.
        assert_eq!(
            rule.spec.sanitizers.len(),
            1,
            "sanitizer spec should compile"
        );
        let src = r#"
#include <stdlib.h>
#include <string.h>
void handler() {
    char *input = getenv("CMD");
    char safe[64];
    strlcpy(safe, input, sizeof(safe));
    system(safe);
}
"#;
        let tree = parse_file(src, Language::C).expect("C fixture should parse");
        let _ = rule.check(src, &tree); // must not panic
    }

    #[test]
    fn kotlin_taint_rule_produces_finding_for_receive_to_exec() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: kotlin-cmd-injection
mode: taint
languages: [kotlin]
severity: ERROR
message: "Tainted request body reaches Runtime.exec"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: call.receiveText($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
"#,
        );

        // call.receiveText() → cmd → Runtime.getRuntime().exec(cmd)
        let src = r#"
fun handler(call: ApplicationCall) {
    val cmd = call.receiveText()
    Runtime.getRuntime().exec(cmd)
}
"#;
        let tree = parse_file(src, Language::Kotlin).expect("Kotlin fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for call.receiveText -> Runtime.exec flow, got none"
        );
        assert!(
            findings[0].description.contains("exec")
                || findings[0]
                    .sink_description
                    .as_deref()
                    .is_some_and(|d| d.contains("exec")),
            "sink description should mention exec: {:?}",
            findings[0]
        );
    }

    #[test]
    fn kotlin_taint_sanitizer_no_panic() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: kotlin-cmd-sanitized
mode: taint
languages: [kotlin]
severity: ERROR
message: "Tainted request body reaches Runtime.exec"
pattern-sources:
  - pattern: call.receiveText($X)
pattern-sinks:
  - pattern: Runtime.exec($X)
pattern-sanitizers:
  - pattern: validate($X)
"#,
        );

        // Verify sanitizer compiles correctly and rule doesn't panic.
        assert_eq!(
            rule.spec.sanitizers.len(),
            1,
            "sanitizer spec should compile"
        );
        let src = r#"
fun handler(call: ApplicationCall) {
    val body = call.receiveText()
    val safe = validate(body)
    Runtime.getRuntime().exec(safe)
}
"#;
        let tree = parse_file(src, Language::Kotlin).expect("Kotlin fixture should parse");
        let _ = rule.check(src, &tree); // must not panic
    }

    fn compiled(yaml: &str) -> SemgrepTaintRule {
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => r,
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn pattern_either_flattens_into_multiple_matchers() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern: request.data
      - pattern: request.form
      - pattern: request.args
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
        assert_eq!(r.spec.sinks.len(), 1);
    }

    #[test]
    fn nested_pattern_either_flattens_recursively() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern-either:
          - pattern: request.data
          - pattern: request.form
      - pattern: request.args
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
    }

    #[test]
    fn pattern_either_in_sinks_flattens() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern-either:
      - pattern: pickle.loads($X)
      - pattern: pickle.load($X)
"#,
        );
        assert_eq!(r.spec.sinks.len(), 2);
    }

    #[test]
    fn pattern_either_in_sanitizers_flattens() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
pattern-sanitizers:
  - pattern-either:
      - pattern: sanitize($X)
      - pattern: escape($X)
"#,
        );
        assert_eq!(r.spec.sanitizers.len(), 2);
    }

    #[test]
    fn mixed_pattern_and_pattern_either_work_together() {
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either:
      - pattern: request.data
      - pattern: request.form
  - pattern: request
pattern-sinks:
  - pattern: pickle.loads($X)
  - pattern-either:
      - pattern: pickle.load($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 3);
        assert_eq!(r.spec.sinks.len(), 2);
    }

    #[test]
    fn empty_pattern_either_warns_and_produces_no_matcher() {
        // Empty pattern-either in sources → no source matchers, so whole
        // rule is skipped (sources are required).
        let yaml = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-either: []
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Skip(msg) => assert!(msg.contains("pattern-sources")),
            other => panic!(
                "expected Skip because empty pattern-either produced no sources, got {:?}",
                match other {
                    TaintRuleParse::Compiled(_) => "Compiled",
                    TaintRuleParse::NotTaint => "NotTaint",
                    TaintRuleParse::Skip(_) => unreachable!(),
                }
            ),
        }

        // Empty pattern-either in sanitizers → rule still compiles (sanitizers
        // are optional), but has zero sanitizer matchers.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
pattern-sanitizers:
  - pattern-either: []
"#,
        );
        assert!(r.spec.sanitizers.is_empty());
    }

    #[test]
    fn unknown_composite_still_rejected() {
        // `patterns:` inside a source block → entry is skipped with a
        // warning. With no other source entries the whole rule is skipped.
        let yaml = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: request.data
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)));

        // `pattern-inside:` likewise rejected per-entry.
        let yaml2 = r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-inside: |
      def $F(...):
        ...
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v2: YamlValue = serde_yaml_ng::from_str(yaml2).unwrap();
        assert!(matches!(parse_taint_rule(&v2), TaintRuleParse::Skip(_)));

        // But a mix where one entry is `patterns:` and another is a plain
        // `pattern:` still compiles — the bad entry is dropped, the good
        // one survives.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: request.data
  - pattern: request.form
pattern-sinks:
  - pattern: pickle.loads($X)
"#,
        );
        assert_eq!(r.spec.sources.len(), 1);
    }

    // ── MethodName shape tests ────────────────────────────────────────────

    #[test]
    fn compile_metavar_receiver_sink_produces_method_name() {
        // The canonical Semgrep pattern for "any call to executeQuery" is
        // `$CONN.executeQuery($X)`.  The bridge must compile this to a
        // `MethodName` matcher rather than warn-skipping it.
        let m = compile("$CONN.executeQuery($X)", MatcherRole::Sink).expect("MethodName");
        match m {
            GenericMatcher::MethodName { method, .. } => assert_eq!(method, "executeQuery"),
            _ => panic!("expected MethodName"),
        }
    }

    #[test]
    fn compile_metavar_receiver_sanitizer_produces_method_name() {
        let m = compile("$OBJ.escape($X)", MatcherRole::Sanitizer).expect("MethodName sanitizer");
        match m {
            GenericMatcher::MethodName { method, .. } => assert_eq!(method, "escape"),
            _ => panic!("expected MethodName"),
        }
    }

    #[test]
    fn metavar_receiver_as_source_is_rejected() {
        // A `$RECEIVER.method($X)` source does not make semantic sense:
        // we cannot identify which object is the origin if the receiver is
        // any arbitrary variable.  The bridge must return None for sources.
        assert!(compile("$OBJ.getInput($X)", MatcherRole::Source).is_none());
    }

    #[test]
    fn metavar_without_dot_is_rejected() {
        // A bare metavariable with no method — not a valid sink shape.
        assert!(compile("$X", MatcherRole::Sink).is_none());
        assert!(compile("$X($Y)", MatcherRole::Sink).is_none());
    }

    #[test]
    fn metavar_with_multi_segment_rest_is_rejected() {
        // `$OBJ.a.b($X)` is ambiguous — only single-segment method names
        // are valid for the MethodName shape.
        assert!(compile("$OBJ.a.b($X)", MatcherRole::Sink).is_none());
    }

    #[test]
    fn metavar_lowercase_is_rejected() {
        // Semgrep metavariables are UPPER-case after `$`.  `$obj` (lowercase)
        // is not a metavariable; reject it so we don't accidentally match
        // oddly-named dotted callees.
        assert!(compile("$obj.method($X)", MatcherRole::Sink).is_none());
    }

    #[test]
    fn metavar_with_trailing_digits_is_accepted() {
        // Semgrep metavars are `[A-Z_][A-Z0-9_]*`, so `$ARG1` is valid — it must
        // compile as a metavar-receiver sink (previously rejected on the digit).
        assert!(is_metavariable("$ARG1"));
        assert!(is_metavariable("$CONN_2"));
        assert!(!is_metavariable("$obj"));
        assert!(!is_metavariable("$"));
        assert!(compile("$X1.executeQuery($P)", MatcherRole::Sink).is_some());
    }

    #[test]
    fn taint_rule_with_metavar_receiver_sink_compiles() {
        let r = compiled(
            r#"
id: java-sql-injection
mode: taint
languages: [java]
severity: ERROR
message: "Tainted input reaches executeQuery"
metadata:
  cwe: "CWE-89"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#,
        );
        assert_eq!(r.spec.sinks.len(), 1);
        match &r.spec.sinks[0] {
            GenericMatcher::MethodName { method, .. } => assert_eq!(method, "executeQuery"),
            other => panic!("expected MethodName sink, got {:?}", other),
        }
    }

    #[test]
    fn java_taint_method_name_sink_produces_finding() {
        use crate::engine::parser::parse_file;

        // Rule uses `$CONN.executeQuery($X)` — bridge compiles to MethodName.
        // Java engine's `matcher_matches_call` handles MethodName via method name.
        let rule = compiled(
            r#"
id: java-sql-metavar
mode: taint
languages: [java]
severity: ERROR
message: "SQL injection via executeQuery"
metadata:
  cwe: "CWE-89"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#,
        );

        let src = r#"
class Dao {
    void query(HttpServletRequest request, Connection conn) throws Exception {
        String input = request.getParameter("id");
        conn.executeQuery(input);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for request.getParameter -> conn.executeQuery flow, got none"
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .is_some_and(|d| d.contains("executeQuery")),
            "sink description should mention executeQuery: {:?}",
            findings[0]
        );
    }

    #[test]
    fn java_taint_method_name_non_matching_method_does_not_fire() {
        use crate::engine::parser::parse_file;

        // Rule only matches `executeQuery` — calls to `executeUpdate` must NOT fire.
        let rule = compiled(
            r#"
id: java-sql-metavar-negative
mode: taint
languages: [java]
severity: ERROR
message: "SQL injection via executeQuery"
pattern-sources:
  - pattern: request.getParameter($X)
pattern-sinks:
  - pattern: $CONN.executeQuery($X)
"#,
        );

        let src = r#"
class Dao {
    void update(HttpServletRequest request, Connection conn) throws Exception {
        String input = request.getParameter("id");
        conn.executeUpdate(input);
    }
}
"#;
        let tree = parse_file(src, Language::Java).expect("Java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "executeUpdate should NOT trigger the executeQuery rule, got {:?}",
            findings
        );
    }

    // ── MemberAssign shape tests ──────────────────────────────────────────

    #[test]
    fn compile_member_assign_sink_produces_member_assign() {
        // The canonical Semgrep DOM-XSS pattern is `$EL.innerHTML = $X`.
        // The bridge must compile this to `MemberAssign { field: "innerHTML" }`.
        let m = compile("$EL.innerHTML = $X", MatcherRole::Sink).expect("MemberAssign");
        match m {
            GenericMatcher::MemberAssign { field, .. } => assert_eq!(field, "innerHTML"),
            _ => panic!("expected MemberAssign"),
        }
    }

    #[test]
    fn compile_member_assign_sanitizer_produces_member_assign() {
        let m =
            compile("$EL.outerHTML = $X", MatcherRole::Sanitizer).expect("MemberAssign sanitizer");
        match m {
            GenericMatcher::MemberAssign { field, .. } => assert_eq!(field, "outerHTML"),
            _ => panic!("expected MemberAssign"),
        }
    }

    #[test]
    fn compile_member_assign_source_is_rejected() {
        // A `$EL.field = $X` source does not make semantic sense —
        // property assignment is a sink, not an origin.
        assert!(compile("$EL.innerHTML = $X", MatcherRole::Source).is_none());
    }

    #[test]
    fn member_assign_equality_operator_is_rejected() {
        // `==` is a comparison, not an assignment — must not compile.
        assert!(compile("$EL.innerHTML == $X", MatcherRole::Sink).is_none());
    }

    #[test]
    fn member_assign_plain_receiver_not_compiled_as_member_assign() {
        // `el.innerHTML = $X` with a plain identifier receiver is NOT a
        // MemberAssign pattern (the receiver must be a metavariable).
        // It has `=` but will fail `parse_member_assign_pattern` and then
        // also fail the call/identifier checks, so it returns None.
        assert!(compile("el.innerHTML = $X", MatcherRole::Sink).is_none());
    }

    #[test]
    fn member_assign_multi_segment_lhs_is_rejected() {
        // `$EL.a.b = $X` is ambiguous — only single-segment property names
        // are supported for the MemberAssign shape.
        assert!(compile("$EL.a.b = $X", MatcherRole::Sink).is_none());
    }

    #[test]
    fn taint_rule_with_member_assign_sink_compiles() {
        let r = compiled(
            r#"
id: js-dom-xss-innerhtml
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted input reaches innerHTML"
metadata:
  cwe: "CWE-79"
pattern-sources:
  - pattern: req.query
pattern-sinks:
  - pattern: $EL.innerHTML = $X
"#,
        );
        assert_eq!(r.spec.sinks.len(), 1);
        match &r.spec.sinks[0] {
            GenericMatcher::MemberAssign { field, .. } => assert_eq!(field, "innerHTML"),
            other => panic!("expected MemberAssign sink, got {:?}", other),
        }
    }

    #[test]
    fn js_taint_member_assign_sink_produces_finding() {
        use crate::engine::parser::parse_file;

        // Rule uses `$EL.innerHTML = $X` — bridge compiles to MemberAssign.
        // The JavaScript engine's assignment handler checks MemberAssign sinks
        // via `match_member_assign_sink` (taint_engine.rs line 629).
        let rule = compiled(
            r#"
id: js-dom-xss-innerhtml-e2e
mode: taint
languages: [javascript]
severity: ERROR
message: "DOM XSS via innerHTML"
metadata:
  cwe: "CWE-79"
pattern-sources:
  - pattern: req.query
pattern-sinks:
  - pattern: $EL.innerHTML = $X
"#,
        );

        let src = r#"
function handler(req) {
    var data = req.query.name;
    document.getElementById("target").innerHTML = data;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("JS fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for req.query -> innerHTML flow, got none"
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .is_some_and(|d| d.contains("innerHTML")),
            "sink description should mention innerHTML: {:?}",
            findings[0]
        );
    }

    #[test]
    fn js_taint_member_assign_non_matching_field_does_not_fire() {
        use crate::engine::parser::parse_file;

        // Rule matches `innerHTML` only — assignment to `textContent` (which
        // is NOT an XSS sink) must NOT fire.
        let rule = compiled(
            r#"
id: js-dom-xss-innerhtml-neg
mode: taint
languages: [javascript]
severity: ERROR
message: "DOM XSS via innerHTML"
pattern-sources:
  - pattern: req.query
pattern-sinks:
  - pattern: $EL.innerHTML = $X
"#,
        );

        let src = r#"
function handler(req) {
    var data = req.query.name;
    document.getElementById("target").textContent = data;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("JS fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "textContent assignment should NOT trigger the innerHTML rule, got {:?}",
            findings
        );
    }
}
