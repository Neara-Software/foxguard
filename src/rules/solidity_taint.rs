//! Intraprocedural, flow-insensitive taint analysis for Solidity.
//!
//! # Scope
//!
//! Mirrors the other language engines (`ruby_taint`, `php_taint`):
//!
//! - **Per function.** Each `function_definition` body is analyzed
//!   independently; taint does not cross function boundaries.
//! - **Per file.** No cross-file analysis.
//! - **Flow-insensitive.** Statements are processed in source order.
//!
//! # Solidity grammar node kinds used here (tree-sitter-solidity)
//!
//! - `function_definition` — fields: `name` (`identifier`), `body`
//!   (`function_body`); parameters are repeated `parameter` children (each
//!   with a `type` and a `name` `identifier`), NOT in a named container.
//! - `variable_declaration_statement` — `variable_declaration` (`type` +
//!   `name`), `=`, `expression`.
//! - `call_expression` — field `function` (an `expression` wrapping an
//!   `identifier` or `member_expression`), plus repeated `call_argument`
//!   children.
//! - `member_expression` — fields `object` and `property` (both `identifier`).
//! - `binary_expression` — fields `left`, `operator`, `right`.
//! - `expression` — a wrapper around the concrete expression node.
//!
//! # Matcher interpretation
//!
//! The Semgrep bridge compiles the Solidity rules to:
//!
//! - A **source** [`NodeMatcher::ParamName`] whose name is a Semgrep
//!   metavariable (begins with `$`), compiled from a `function $F(..., type
//!   $X, ...) public {...}` signature. The engine seeds **every** parameter of
//!   the enclosing function as tainted — matching Semgrep's any-parameter
//!   semantics.
//! - A **sink** [`NodeMatcher::MethodName`] (`delegatecall`), matched against
//!   a call whose final method name equals it **and whose receiver is
//!   tainted** (the attacker-controlled `address`), or
//!   [`NodeMatcher::Call`] (`selfdestruct`, `suicide`) matched against a call
//!   with a tainted argument.

use crate::rules::common::AliasTable;
use crate::rules::taint_engine::{node_text, taint_finding_for_node, TaintState};
pub use crate::rules::taint_engine::{NodeMatcher, TaintFinding, TaintSpec};
use tree_sitter::Node;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Run the Solidity taint engine over every `function_definition` inside
/// `root`, returning one [`TaintFinding`] per source→sink flow.
pub fn analyze_tree(
    root: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    _aliases: Option<&AliasTable>,
) -> Vec<TaintFinding> {
    let mut findings = Vec::new();
    collect_function_defs(root, &mut |func| {
        let mut state = TaintState::default();
        seed_params(func, source, spec, &mut state);
        if let Some(body) = func.child_by_field_name("body") {
            walk(body, source, spec, &mut state, &mut findings);
        }
    });
    findings
}

// ─── Built-in specs ──────────────────────────────────────────────────────────

/// All Solidity taint rule IDs paired with their specs.
pub fn solidity_taint_rule_specs() -> Vec<(&'static str, TaintSpec)> {
    vec![
        (
            "solidity/taint-arbitrary-delegatecall",
            arbitrary_delegatecall_spec(),
        ),
        (
            "solidity/taint-unprotected-selfdestruct",
            unprotected_selfdestruct_spec(),
        ),
        ("solidity/taint-unchecked-call", unchecked_call_spec()),
    ]
}

/// Shared sources for the Solidity taint rules.
///
/// The intraprocedural engine only seeds taint from function parameters
/// (`seed_params`); the `$`-prefixed name triggers the any-parameter
/// semantics so *every* parameter of the enclosing function is treated as
/// attacker-controlled. Solidity "global" inputs such as `msg.sender`,
/// `msg.data`, or `tx.origin` are intentionally NOT modeled here because
/// `analyze_tree`/`expression_taint` has no global-variable source classifier
/// — adding them would be inert (never fire) and, for the low-level-call rule,
/// would cause false positives on the ubiquitous `msg.sender.call{value:..}("")`
/// refund pattern.
pub fn solidity_taint_sources() -> Vec<NodeMatcher> {
    vec![NodeMatcher::ParamName {
        names: vec!["$PARAM".into()],
        description: "untrusted function parameter".into(),
    }]
}

/// Shared sanitizers for the Solidity taint rules.
///
/// `require(...)` / `assert(...)` are the idiomatic Solidity guard calls. The
/// engine consults these via `call_is_sanitizer` when taint would otherwise
/// propagate through a call expression. (Access-control *modifiers* such as
/// `onlyOwner` are not call expressions in the tree-sitter-solidity AST, so
/// they are deliberately omitted — the engine could never match them.)
pub fn solidity_taint_sanitizers() -> Vec<NodeMatcher> {
    vec![
        NodeMatcher::Call {
            canonical: "require".into(),
            description: "require() guard".into(),
        },
        NodeMatcher::Call {
            canonical: "assert".into(),
            description: "assert() guard".into(),
        },
    ]
}

/// `target.delegatecall(data)` / `target.callcode(data)` where the call
/// *target* (receiver address) is attacker-controlled — the classic arbitrary
/// delegatecall (CWE-829).
fn arbitrary_delegatecall_spec() -> TaintSpec {
    TaintSpec {
        sources: solidity_taint_sources(),
        sinks: vec![
            NodeMatcher::MethodName {
                method: "delegatecall".into(),
                description: "delegatecall() to an attacker-controlled address".into(),
            },
            NodeMatcher::MethodName {
                method: "callcode".into(),
                description: "callcode() to an attacker-controlled address".into(),
            },
        ],
        sanitizers: solidity_taint_sanitizers(),
    }
}

/// `selfdestruct(target)` / `suicide(target)` with an attacker-controlled
/// recipient — unprotected self-destruct (SWC-106 / CWE-284). The engine fires
/// when a *tainted argument* reaches the call.
fn unprotected_selfdestruct_spec() -> TaintSpec {
    TaintSpec {
        sources: solidity_taint_sources(),
        sinks: vec![
            NodeMatcher::Call {
                canonical: "selfdestruct".into(),
                description: "selfdestruct() with an attacker-controlled recipient".into(),
            },
            NodeMatcher::Call {
                canonical: "suicide".into(),
                description: "suicide() with an attacker-controlled recipient".into(),
            },
        ],
        sanitizers: solidity_taint_sanitizers(),
    }
}

/// `target.call(data)` where the call *target* (receiver address) is
/// attacker-controlled — a low-level external call to an arbitrary address
/// (enables reentrancy / fund theft, CWE-829). `send`/`transfer` are
/// intentionally excluded: forwarding ETH to a parameter-supplied recipient is
/// frequently intended (e.g. user withdrawals) and would be noisy.
fn unchecked_call_spec() -> TaintSpec {
    TaintSpec {
        sources: solidity_taint_sources(),
        sinks: vec![NodeMatcher::MethodName {
            method: "call".into(),
            description: "low-level .call() to an attacker-controlled address".into(),
        }],
        sanitizers: solidity_taint_sanitizers(),
    }
}

// ─── Seeding ────────────────────────────────────────────────────────────────

/// Seed taint from function parameters.
///
/// If the spec contains a metavariable `ParamName` source (name beginning with
/// `$`), *every* parameter is seeded (any-parameter semantics). Otherwise only
/// parameters whose name appears in a concrete `ParamName` list are seeded.
fn seed_params(func: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    let seed_all = spec.sources.iter().any(|m| {
        matches!(m, NodeMatcher::ParamName { names, .. } if names.iter().any(|n| n.starts_with('$')))
    });

    let mut cursor = func.walk();
    for child in func.children(&mut cursor) {
        if child.kind() != "parameter" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let pname = node_text(name_node, source);
        let line = name_node.start_position().row + 1;

        if seed_all {
            state.taint(
                pname.to_string(),
                "untrusted function parameter".to_string(),
                line,
            );
            continue;
        }
        for matcher in &spec.sources {
            if let NodeMatcher::ParamName { names, description } = matcher {
                if names.iter().any(|n| n == pname) {
                    state.taint(pname.to_string(), description.clone(), line);
                    break;
                }
            }
        }
    }
}

// ─── Walk ───────────────────────────────────────────────────────────────────

fn walk(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    // Skip nested function definitions — analyzed as their own scope.
    if node.kind() == "function_definition" {
        return;
    }

    match node.kind() {
        "variable_declaration_statement" => handle_var_decl(node, source, spec, state),
        "call_expression" => handle_call(node, source, spec, state, findings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, spec, state, findings);
    }
}

/// `type name = <expr>;` — propagate taint from the initializer to the LHS.
fn handle_var_decl(node: Node<'_>, source: &str, spec: &TaintSpec, state: &mut TaintState) {
    // `variable_declaration` is a child node (not a named field).
    let mut cursor = node.walk();
    let Some(decl) = node
        .children(&mut cursor)
        .find(|c| c.kind() == "variable_declaration")
    else {
        return;
    };
    let Some(name_node) = decl.child_by_field_name("name") else {
        return;
    };
    let lhs = node_text(name_node, source).to_string();

    // The initializer is the `value` field on the statement.
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    if let Some((desc, line)) = expression_taint(value, source, spec, state) {
        state.taint(lhs, desc, line);
    } else {
        state.clear(&lhs);
    }
}

/// A `call_expression`. Two sink shapes:
///   1. `MethodName` (`x.delegatecall(...)`): fires when the *receiver* is
///      tainted (attacker-controlled `address`).
///   2. `Call` (`selfdestruct(...)`): fires when an *argument* is tainted.
fn handle_call(
    node: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &mut TaintState,
    findings: &mut Vec<TaintFinding>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let callee = unwrap_expression(func);

    // Member call `receiver.method(...)`.
    if callee.kind() == "member_expression" {
        if let (Some(object), Some(property)) = (
            callee.child_by_field_name("object"),
            callee.child_by_field_name("property"),
        ) {
            let method = node_text(property, source);
            if let Some(desc) = method_sink(method, spec) {
                // `x.delegatecall(...)` is dangerous when the *receiver*
                // (the call target address) is attacker-controlled. We fire on
                // a tainted receiver only — a hard-coded receiver such as
                // `address(this).delegatecall(data)` is safe even with tainted
                // arguments.
                if let Some((src_desc, src_line)) = expression_taint(object, source, spec, state) {
                    findings.push(taint_finding_for_node(
                        node, src_desc, desc, src_line, None, 1,
                    ));
                }
            }
        }
        return;
    }

    // Bare call `selfdestruct(...)` / `suicide(...)`.
    if callee.kind() == "identifier" {
        let name = node_text(callee, source);
        if let Some(desc) = call_sink(name, spec) {
            if let Some((src_desc, src_line)) = first_tainted_arg(node, source, spec, state) {
                findings.push(taint_finding_for_node(
                    node, src_desc, desc, src_line, None, 1,
                ));
            }
        }
    }
}

/// First tainted `call_argument` of a `call_expression`, if any.
fn first_tainted_arg(
    call: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    let mut cursor = call.walk();
    for child in call.children(&mut cursor) {
        if child.kind() == "call_argument" {
            if let Some(r) = expression_taint(child, source, spec, state) {
                return Some(r);
            }
        }
    }
    None
}

// ─── Taint evaluation ──────────────────────────────────────────────────────

/// Returns `(description, line)` if `expr` is or references a tainted value.
fn expression_taint(
    expr: Node<'_>,
    source: &str,
    spec: &TaintSpec,
    state: &TaintState,
) -> Option<(String, usize)> {
    let expr = unwrap_expression(expr);

    match expr.kind() {
        "identifier" => {
            let name = node_text(expr, source);
            state
                .info(name)
                .map(|info| (info.description.clone(), info.line))
        }
        // `a - b`, `a + b`, etc.: tainted if either operand is tainted.
        "binary_expression" => {
            if let Some(left) = expr.child_by_field_name("left") {
                if let Some(r) = expression_taint(left, source, spec, state) {
                    return Some(r);
                }
            }
            if let Some(right) = expr.child_by_field_name("right") {
                if let Some(r) = expression_taint(right, source, spec, state) {
                    return Some(r);
                }
            }
            None
        }
        // `obj.field`: tainted if the receiver is tainted.
        "member_expression" => expr
            .child_by_field_name("object")
            .and_then(|o| expression_taint(o, source, spec, state)),
        // Any call expression: propagate taint from its arguments (and receiver)
        // unless the callee is a sanitizer.
        "call_expression" => {
            if call_is_sanitizer(expr, source, spec) {
                return None;
            }
            if let Some(r) = first_tainted_arg(expr, source, spec, state) {
                return Some(r);
            }
            if let Some(func) = expr.child_by_field_name("function") {
                let callee = unwrap_expression(func);
                if callee.kind() == "member_expression" {
                    if let Some(object) = callee.child_by_field_name("object") {
                        return expression_taint(object, source, spec, state);
                    }
                }
            }
            None
        }
        // Generic: descend into children (covers `tuple_expression`,
        // `parenthesized_expression`, etc.).
        _ => {
            let mut cursor = expr.walk();
            for child in expr.children(&mut cursor) {
                if let Some(r) = expression_taint(child, source, spec, state) {
                    return Some(r);
                }
            }
            None
        }
    }
}

fn call_is_sanitizer(call: Node<'_>, source: &str, spec: &TaintSpec) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let callee = unwrap_expression(func);
    let name = match callee.kind() {
        "identifier" => node_text(callee, source),
        "member_expression" => callee
            .child_by_field_name("property")
            .map(|p| node_text(p, source))
            .unwrap_or(""),
        _ => return false,
    };
    spec.sanitizers.iter().any(|m| match m {
        NodeMatcher::Call { canonical, .. } => canonical == name,
        NodeMatcher::MethodName { method, .. } => method == name,
        _ => false,
    })
}

fn method_sink(method: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::MethodName {
            method: want,
            description,
        } if want == method => Some(description.clone()),
        _ => None,
    })
}

fn call_sink(name: &str, spec: &TaintSpec) -> Option<String> {
    spec.sinks.iter().find_map(|m| match m {
        NodeMatcher::Call {
            canonical,
            description,
        } if canonical == name => Some(description.clone()),
        _ => None,
    })
}

// ─── AST helpers ────────────────────────────────────────────────────────────

/// Unwrap a tree-sitter-solidity `expression` wrapper to its inner concrete
/// node (the grammar wraps most expressions in an `expression` node).
fn unwrap_expression(node: Node<'_>) -> Node<'_> {
    let mut n = node;
    while n.kind() == "expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

fn collect_function_defs<'tree, F>(node: Node<'tree>, visit: &mut F)
where
    F: FnMut(Node<'tree>),
{
    if node.kind() == "function_definition" {
        visit(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_defs(child, visit);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::parser::parse_file;
    use crate::Language;

    fn run(src: &str, spec: &TaintSpec) -> Vec<TaintFinding> {
        let tree = parse_file(src, Language::Solidity).expect("parse");
        analyze_tree(tree.root_node(), src, spec, None)
    }

    fn param_source() -> NodeMatcher {
        NodeMatcher::ParamName {
            names: vec!["$PARAM".into()],
            description: "untrusted function parameter".into(),
        }
    }

    fn delegatecall_spec() -> TaintSpec {
        TaintSpec {
            sources: vec![param_source()],
            sinks: vec![NodeMatcher::MethodName {
                method: "delegatecall".into(),
                description: "delegatecall()".into(),
            }],
            sanitizers: vec![],
        }
    }

    fn selfdestruct_spec() -> TaintSpec {
        TaintSpec {
            sources: vec![param_source()],
            sinks: vec![NodeMatcher::Call {
                canonical: "selfdestruct".into(),
                description: "selfdestruct()".into(),
            }],
            sanitizers: vec![],
        }
    }

    #[test]
    fn delegatecall_to_param_address_fires() {
        let src = r#"
contract C {
  function run(address target, bytes data) public {
    target.delegatecall(data);
  }
}
"#;
        let f = run(src, &delegatecall_spec());
        assert_eq!(f.len(), 1, "delegatecall to param must fire, got {:?}", f);
        assert!(f[0].sink_description.contains("delegatecall"));
    }

    #[test]
    fn selfdestruct_of_param_fires() {
        let src = r#"
contract C {
  function kill(address payable target) public {
    selfdestruct(target);
  }
}
"#;
        let f = run(src, &selfdestruct_spec());
        assert_eq!(f.len(), 1, "selfdestruct of param must fire, got {:?}", f);
    }

    #[test]
    fn delegatecall_to_constant_no_finding() {
        // Receiver is a hard-coded constant, not a parameter — must not fire.
        let src = r#"
contract C {
  function run(bytes data) public {
    address(this).delegatecall(data);
  }
}
"#;
        let f = run(src, &delegatecall_spec());
        assert_eq!(
            f.len(),
            0,
            "delegatecall to address(this) must not fire, got {:?}",
            f
        );
    }

    #[test]
    fn selfdestruct_of_local_constant_no_finding() {
        let src = r#"
contract C {
  function kill() public {
    selfdestruct(owner);
  }
}
"#;
        let f = run(src, &selfdestruct_spec());
        assert_eq!(f.len(), 0, "selfdestruct of non-param must not fire");
    }

    #[test]
    fn taint_propagates_through_local() {
        let src = r#"
contract C {
  function run(address target) public {
    address t = target;
    t.delegatecall(data);
  }
}
"#;
        let f = run(src, &delegatecall_spec());
        assert_eq!(f.len(), 1, "taint must propagate through local assignment");
    }
}
