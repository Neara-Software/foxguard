//! Regression tests for Semgrep taint-bridge precision gaps.
//!
//! Each test encodes a case where the bridge silently BROADENED a written
//! rule (see docs/taint-precision-gaps.md). They are written against the
//! public rule-loading API so they exercise the same path a user's
//! `--rules dir/` hits.

use foxguard::engine::parser::parse_file;
use foxguard::rules::semgrep_compat::parse_semgrep_str;
use foxguard::rules::Rule;
use foxguard::Language;
use std::path::Path;

fn taint_rule(yaml: &str) -> Box<dyn Rule> {
    let mut rules = parse_semgrep_str(yaml, "inline-test").expect("rule should parse");
    assert_eq!(rules.len(), 1, "expected exactly one compiled rule");
    rules.remove(0)
}

fn findings(rule: &dyn Rule, src: &str) -> Vec<foxguard::Finding> {
    let tree = parse_file(src, Language::Java).expect("fixture parses");
    rule.check(src, &tree)
}

// ── Gap 1: `paths:` include/exclude must apply to taint rules ────────────

const PATHS_RULE: &str = r#"
rules:
  - id: test/taint-paths-filter
    languages: [java]
    severity: ERROR
    mode: taint
    message: tainted value reaches sink
    paths:
      include: ["src/handlers/"]
      exclude: ["**/SafeStore.java"]
    pattern-sources:
      - pattern: req.getQueryParam(...)
    pattern-sinks:
      - pattern: new File(...)
"#;

#[test]
fn taint_rule_honors_paths_include() {
    let rule = taint_rule(PATHS_RULE);
    assert!(
        rule.applies_to_path(Path::new("src/handlers/Upload.java")),
        "file under include dir must be in scope"
    );
    assert!(
        !rule.applies_to_path(Path::new("src/model/Upload.java")),
        "file outside include dir must be filtered out"
    );
}

#[test]
fn taint_rule_honors_paths_exclude() {
    let rule = taint_rule(PATHS_RULE);
    assert!(
        !rule.applies_to_path(Path::new("src/handlers/SafeStore.java")),
        "excluded file must be filtered out even under an included dir"
    );
}

// ── Gap 2: concrete-receiver source must not substring-match ─────────────

const RECEIVER_RULE: &str = r#"
rules:
  - id: test/receiver-token-match
    languages: [java]
    severity: ERROR
    mode: taint
    message: request path reaches filesystem
    pattern-sources:
      - pattern: rq.getPath()
    pattern-sinks:
      - pattern: Paths.get(...)
"#;

#[test]
fn receiver_source_fires_on_exact_receiver() {
    let rule = taint_rule(RECEIVER_RULE);
    let src = r#"
class H {
  void a(Req rq) {
    String p = rq.getPath();
    java.nio.file.Paths.get(p);
  }
}
"#;
    assert_eq!(findings(rule.as_ref(), src).len(), 1);
}

#[test]
fn receiver_source_does_not_substring_match_unrelated_receiver() {
    let rule = taint_rule(RECEIVER_RULE);
    // "parquetUri" contains "rq" as a substring but is not the receiver `rq`.
    let src = r#"
class H {
  void a(java.net.URI parquetUri) {
    String p = parquetUri.getPath();
    java.nio.file.Paths.get(p);
  }
}
"#;
    assert!(
        findings(rule.as_ref(), src).is_empty(),
        "substring receiver (parquetUri ⊃ rq) must not match"
    );
}

#[test]
fn receiver_source_does_not_suffix_match_unrelated_receiver() {
    let rule = taint_rule(&RECEIVER_RULE.replace("rq.getPath()", "req.getPath()"));
    // "freq" ends with "req" but is not the receiver `req`.
    let src = r#"
class H {
  void a(Frequency freq) {
    String p = freq.getPath();
    java.nio.file.Paths.get(p);
  }
}
"#;
    assert!(
        findings(rule.as_ref(), src).is_empty(),
        "suffix receiver (freq ⊃ req) must not match"
    );
}

#[test]
fn receiver_source_still_matches_camel_case_qualified_receiver() {
    // The reason the old substring match existed: `request.getParameter`
    // should match a receiver named `httpServletRequest`. Token-boundary
    // matching must preserve that.
    let rule = taint_rule(
        &RECEIVER_RULE
            .replace("rq.getPath()", "request.getParameter(...)")
            .replace("Paths.get(...)", "new File(...)"),
    );
    let src = r#"
class H {
  void a(HttpServletRequest httpServletRequest) {
    String p = httpServletRequest.getParameter("f");
    new File(p);
  }
}
"#;
    assert_eq!(
        findings(rule.as_ref(), src).len(),
        1,
        "camelCase-qualified receiver (httpServletRequest) must still match `request`"
    );
}

// ── Gap 3: chained-call sink must keep its trailing receiver segment ─────

const CHAINED_SINK_RULE: &str = r#"
rules:
  - id: test/chained-call-sink
    languages: [java]
    severity: ERROR
    mode: taint
    message: caller-supplied id reaches by-id predicate
    pattern-sources:
      - patterns:
          - pattern-inside: "$RET $M(..., DbKey<$T> $ID, ...) { ... }"
          - pattern: $ID
    pattern-sinks:
      - patterns:
          - focus-metavariable: $SINK
          - pattern-either:
              - pattern: $TBL.id().eq($SINK)
"#;

#[test]
fn chained_sink_fires_on_matching_chain() {
    let rule = taint_rule(CHAINED_SINK_RULE);
    let src = r#"
class S {
  void a(Context ctx, DbKey<Team> id) {
    ctx.list(TEAM.select().where(TEAM.id().eq(id)));
  }
}
"#;
    assert_eq!(findings(rule.as_ref(), src).len(), 1);
}

#[test]
fn chained_sink_does_not_fire_on_different_chain() {
    let rule = taint_rule(CHAINED_SINK_RULE);
    // `.name().eq(...)` — same final method, different chain segment.
    let src = r#"
class S {
  void a(Context ctx, DbKey<Team> id) {
    ctx.list(TEAM.select().where(TEAM.name().eq(id)));
  }
}
"#;
    assert!(
        findings(rule.as_ref(), src).is_empty(),
        "`$TBL.id().eq($SINK)` must not degrade to any `.eq(tainted)`"
    );
}

#[test]
fn chained_sink_plain_pattern_entry_compiles_and_fires() {
    // The same sink written as a plain `pattern:` entry used to compile to
    // NOTHING (silently emptying the sink list). Both spellings must agree.
    let rule = taint_rule(
        r#"
rules:
  - id: test/chained-call-sink-plain
    languages: [java]
    severity: ERROR
    mode: taint
    message: caller-supplied id reaches by-id predicate
    pattern-sources:
      - patterns:
          - pattern-inside: "$RET $M(..., DbKey<$T> $ID, ...) { ... }"
          - pattern: $ID
    pattern-sinks:
      - pattern: $TBL.id().eq($SINK)
"#,
    );
    let hit = r#"
class S {
  void a(Context ctx, DbKey<Team> id) {
    ctx.list(TEAM.select().where(TEAM.id().eq(id)));
  }
}
"#;
    let miss = r#"
class S {
  void a(Context ctx, DbKey<Team> id) {
    ctx.list(TEAM.select().where(TEAM.name().eq(id)));
  }
}
"#;
    assert_eq!(
        findings(rule.as_ref(), hit).len(),
        1,
        "plain spelling must fire"
    );
    assert!(
        findings(rule.as_ref(), miss).is_empty(),
        "plain spelling must keep the chain constraint"
    );
}

// ── Gap 4: signature co-parameter types must gate typed-param sources ────

const CO_PARAM_RULE: &str = r#"
rules:
  - id: test/co-param-gate
    languages: [java]
    severity: ERROR
    mode: taint
    message: unchecked id from authenticated entry point
    pattern-sources:
      - patterns:
          - pattern-inside: "$RET $M(..., AuthContext $AC, ..., DbKey<$T> $ID, ...) { ... }"
          - pattern: $ID
    pattern-sinks:
      - pattern: $TBL.delete($CTX, $SINK)
"#;

#[test]
fn typed_param_source_fires_when_co_param_present() {
    let rule = taint_rule(CO_PARAM_RULE);
    let src = r#"
class S {
  void del(AuthContext ac, Context ctx, DbKey<Team> id) {
    TEAM.delete(ctx, id);
  }
}
"#;
    assert_eq!(
        findings(rule.as_ref(), src).len(),
        1,
        "method taking AuthContext AND DbKey must seed the DbKey param"
    );
}

#[test]
fn typed_param_source_skips_method_without_co_param() {
    let rule = taint_rule(CO_PARAM_RULE);
    // No AuthContext parameter — the signature `pattern-inside` does not
    // match this method, so its DbKey param must NOT be seeded.
    let src = r#"
class S {
  void del(Context ctx, DbKey<Team> id) {
    TEAM.delete(ctx, id);
  }
}
"#;
    assert!(
        findings(rule.as_ref(), src).is_empty(),
        "method without the AuthContext co-param must not be seeded"
    );
}
