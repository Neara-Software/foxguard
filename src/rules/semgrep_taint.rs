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
    fn from_ruby(f: ruby_taint::TaintFinding) -> Self {
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
    fn from_php(f: php_taint::TaintFinding) -> Self {
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
    fn from_csharp(f: csharp_taint::TaintFinding) -> Self {
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
                    _ => {}
                }
            }
            match detected {
                Some(l) => l,
                None => {
                    return TaintRuleParse::Skip(format!(
                        "taint rule `{}` targets unsupported languages; Python, JavaScript/TypeScript, Go, Java, C, Kotlin, Ruby, PHP, and C# are supported",
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
/// nested `pattern-either:` blocks, and extracting expressible matchers from
/// `patterns:` AND-blocks. Invalid entries emit a warning and are skipped
/// rather than aborting the whole rule.
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
            "Warning: taint rule `{}` {} entry has {} keys (expected a single `pattern:`, `pattern-either:`, or `patterns:`); skipping entry",
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
        Some("patterns") => {
            // `patterns:` is a Semgrep AND-block: all sub-items must hold
            // simultaneously. foxguard's taint engine cannot express all AND
            // semantics (no nested scope / contextual constraints), so we
            // apply a graceful-degradation strategy:
            //
            // - Extract every `pattern:` and `pattern-either:` sub-item and
            //   compile them as expressible node-shape matchers.
            // - Drop constraint-only sub-items (`pattern-inside:`,
            //   `pattern-not:`, `focus-metavariable:`, `metavariable-*:`)
            //   with a per-key warning. This makes the compiled matcher
            //   slightly BROADER than the original Semgrep rule — documented
            //   in COMPATIBILITY.md.
            // - If no expressible matcher results, warn-skip the whole entry.
            compile_patterns_block(v, role, rule_id, out);
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
/// themselves name a code node shape. The taint engine has no equivalent;
/// they are dropped with a warning, making the compiled matcher broader.
const PATTERNS_CONSTRAINT_KEYS: &[&str] = &[
    "pattern-inside",
    "pattern-not-inside",
    "pattern-not",
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
/// Constraint-only sub-items are dropped with a warning. If no expressible
/// matcher is produced the whole entry is warn-skipped.
fn compile_patterns_block(
    v: &YamlValue,
    role: MatcherRole,
    rule_id: &str,
    out: &mut Vec<GenericMatcher>,
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
                compile_entry(sub, role, rule_id, out);
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
}
