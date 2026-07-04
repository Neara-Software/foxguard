// Integration test for the realistic test corpus (issue #35).
//
// Each fixture under `tests/fixtures/realistic/` is a small-but-complete
// vulnerable application for one supported framework. We pin the exact
// total finding count and the exact count per taint rule. Any rule
// addition or engine change will break these counts, which is the whole
// point: it forces explicit acknowledgment of precision shifts.
//
// The fixtures also contain NEAR-MISS functions whose line ranges must
// not contain any `*/taint-*` findings. We check that indirectly by
// pinning the total taint-finding count per file — if a NEAR-MISS
// function started firing, the total would change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    // `--config /dev/null` isolates the test from any developer-local
    // `.foxguard.yml` in CARGO_MANIFEST_DIR. The repo's own baseline
    // suppresses dozens of findings in tests/fixtures/* for self-scan
    // hygiene, which would otherwise leak into every realistic-fixture
    // "expected_total" assertion.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("realistic")
        .join(name)
}

fn scan_json_findings(stdout: &[u8], file: &str) -> Vec<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|e| panic!("invalid JSON output for {}: {}", file, e));
    report["findings"]
        .as_array()
        .cloned()
        .expect("JSON report missing findings array")
}

/// Scan a realistic fixture and assert exact total finding count and
/// exact per-taint-rule counts. `taint_counts` lists every taint rule
/// that must fire, with the expected count. Any taint rule observed in
/// the output that is not in `taint_counts` (or with a different count)
/// fails the test — this catches accidental false positives on the
/// NEAR-MISS sections.
fn assert_fixture(file: &str, expected_total: usize, taint_counts: &[(&str, usize)]) {
    let path = fixture_path(file);
    let output = foxguard_cmd()
        .args([path.to_str().unwrap(), "-f", "json"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run foxguard on {}: {}", file, e));

    let findings = scan_json_findings(&output.stdout, file);

    assert_eq!(
        findings.len(),
        expected_total,
        "{}: expected {} total findings, got {}. findings={:?}",
        file,
        expected_total,
        findings.len(),
        findings
            .iter()
            .map(|f| f["rule_id"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );

    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in &findings {
        if let Some(rule) = f["rule_id"].as_str() {
            *counts.entry(rule).or_insert(0) += 1;
        }
    }

    // Every expected taint rule must fire exactly the expected number
    // of times.
    for (rule, want) in taint_counts {
        let got = counts.get(rule).copied().unwrap_or(0);
        assert_eq!(
            got, *want,
            "{}: taint rule {} expected {} times, got {}. counts={:?}",
            file, rule, want, got, counts
        );
    }

    // Any taint finding for a rule NOT in `taint_counts` is an
    // unexpected false positive — likely on the NEAR-MISS section.
    let expected_rules: std::collections::HashSet<&str> =
        taint_counts.iter().map(|(r, _)| *r).collect();
    for (rule, count) in &counts {
        if rule.contains("/taint-") && !expected_rules.contains(rule) {
            panic!(
                "{}: unexpected taint rule {} fired {} times (likely NEAR-MISS false positive). counts={:?}",
                file, rule, count, counts
            );
        }
    }
}

#[test]
fn realistic_flask_app() {
    assert_fixture(
        "flask_app.py",
        14,
        &[
            ("py/taint-pickle-deserialization", 1),
            ("py/taint-eval", 1),
            ("py/taint-command-injection", 2),
            ("py/taint-ssrf", 1),
            ("py/taint-yaml-load", 1),
            ("py/taint-sql-injection", 1),
        ],
    );
}

#[test]
fn realistic_django_views() {
    assert_fixture(
        "django_views.py",
        9,
        &[
            ("py/taint-command-injection", 2),
            ("py/taint-sql-injection", 1),
            ("py/taint-ssrf", 1),
            ("py/taint-pickle-deserialization", 1),
        ],
    );
}

#[test]
fn realistic_fastapi_app() {
    assert_fixture(
        "fastapi_app.py",
        8,
        &[
            ("py/taint-eval", 1),
            ("py/taint-pickle-deserialization", 1),
            ("py/taint-ssrf", 1),
        ],
    );
}

#[test]
fn realistic_cli_tool() {
    assert_fixture(
        "cli_tool.py",
        9,
        &[("py/taint-command-injection", 2), ("py/taint-eval", 2)],
    );
}

#[test]
fn realistic_express_app() {
    assert_fixture("express_app.js", 12, &[("js/taint-xss-innerhtml", 5)]);
}

#[test]
fn realistic_nextjs_handlers() {
    assert_fixture("nextjs_handlers.ts", 7, &[("js/taint-xss-innerhtml", 3)]);
}

#[test]
fn realistic_hono_app() {
    assert_fixture("hono_app.ts", 7, &[("js/taint-xss-innerhtml", 3)]);
}

#[test]
fn realistic_java_spring_controller() {
    assert_fixture(
        "java_spring_controller.java",
        4,
        &[
            ("java/taint-command-injection", 1),
            ("java/taint-sql-injection", 1),
            ("java/taint-ssrf", 1),
            ("java/taint-unsafe-deserialization", 1),
        ],
    );
}

/// Multi-file Django fixture (issue #48). Cross-file taint analysis
/// (issue #46) propagates taint from `views.py` into `queries.py`
/// helpers via function taint summaries. In-file flows fire as before,
/// plus two new cross-file flows:
///   - `py/taint-sql-injection`: request.GET["name"] → queries.run_query → cur.execute
///   - `py/taint-pickle-deserialization`: request.body → queries.load_blob → pickle.loads
#[test]
fn realistic_django_shop_multifile() {
    assert_fixture(
        "django_shop",
        8,
        &[
            ("py/taint-command-injection", 1),
            ("py/taint-ssrf", 1),
            ("py/taint-sql-injection", 1),
            ("py/taint-pickle-deserialization", 1),
        ],
    );
}

/// Multi-file Express fixture (issue #48). In-file SQL injection in
/// `routes.js::/user` fires under `js/taint-sql-injection`. Cross-file
/// flows via `services.runQuery` and `services.evalExpression` fire after
/// issue #46 (cross-file summaries).
#[test]
fn realistic_express_api_multifile() {
    assert_fixture(
        "express_api",
        10,
        &[
            ("js/taint-sql-injection", 2),
            ("js/taint-command-injection", 1),
            ("js/taint-eval", 2),
        ],
    );
}

/// Multi-file Next.js App Router fixture (issue #48). Same shape as
/// the Express fixture: in-file SQL injection via `request.nextUrl`
/// → `db.query` fires; cross-file flows into `actions.ts` do not
/// fire yet and will light up after issue #46.
#[test]
fn realistic_next_app_multifile() {
    assert_fixture("next_app", 4, &[("js/taint-sql-injection", 1)]);
}

/// Multi-file Gin fixture (issue #48). `handlers.go` holds request
/// sources, `store.go` holds a SQL execute helper tainted across the
/// file boundary. In-file taint flows fire (command injection in the
/// closure, SSRF in `proxyFetch`). Cross-file flow via
/// `runQuery(name)` in `handlers.go` → `db.Query` in `store.go`
/// fires as `go/taint-sql-injection` after issue #46.
#[test]
fn realistic_gin_service_multifile() {
    assert_fixture(
        "gin_service",
        6,
        &[
            ("go/taint-command-injection", 1),
            ("go/taint-sql-injection", 1),
            ("go/taint-ssrf", 1),
        ],
    );
}

/// Multi-hop chain fixture (issue #175). Three-file Python chain:
/// views.py (source) → middleware.py (passthrough) → queries.py (sink).
/// Return-taint propagation through middleware.transform() enables the
/// taint to flow from request.GET through the passthrough and into
/// queries.run_query's SQL sink.
#[test]
fn realistic_django_chain_multihop() {
    assert_fixture("django_chain", 2, &[("py/taint-sql-injection", 1)]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// cross-file call. Three-file Python chain:
/// views.py (source) → service.handle() → db.run_query() (sink), where
/// `service.handle` forwards its argument to `db.run_query` in a THIRD file.
/// Unlike `django_chain` (caller orchestrates both hops), this chain is only
/// found once `service.handle`'s summary is composed one hop deeper against
/// `db.run_query`'s summary (the scanner's bounded multi-hop fixpoint).
#[test]
fn realistic_python_multihop_composed() {
    assert_fixture("python_multihop", 2, &[("py/taint-sql-injection", 1)]);
}

/// The chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (the sink file still trips
/// the single-file regex heuristic `py/no-sql-injection`, but no `*/taint-*`
/// rule fires because no source is present in any single file).
#[test]
fn realistic_python_multihop_single_file_finds_no_taint() {
    assert_fixture("python_multihop/views.py", 0, &[]);
    assert_fixture("python_multihop/service.py", 0, &[]);
    assert_fixture("python_multihop/db.py", 1, &[]);
}

/// Negative multi-hop: identical shape to `python_multihop` but the middle
/// helper runs the value through `escape_string()` (a configured SQL
/// sanitizer) before forwarding it. The sanitizer collapses the value to
/// clean, so the composed summary records no sink flow and the chain BREAKS —
/// no taint finding on a directory scan (only the sink file's regex hit).
#[test]
fn realistic_python_multihop_sanitizer_breaks_chain() {
    assert_fixture("python_multihop_sanitized", 1, &[]);
}

/// Multi-hop chain fixture (issue #175). Three-file JS chain:
/// routes.js (source) → transform.js (passthrough) → services.js (sink).
#[test]
fn realistic_express_chain_multihop() {
    assert_fixture("express_chain", 2, &[("js/taint-sql-injection", 1)]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the
/// cross-file call. Three-file JS chain:
/// routes.js (source) → service.handle() → store.runQuery() (sink), where
/// `service.handle` forwards its argument to `store.runQuery` in a THIRD file.
/// Unlike `express_chain` (caller orchestrates both hops), this chain is only
/// found once `service.handle`'s summary is composed one hop deeper against
/// `store.runQuery`'s summary (the scanner's bounded multi-hop fixpoint).
#[test]
fn realistic_js_multihop_composed() {
    assert_fixture("js_multihop", 2, &[("js/taint-sql-injection", 1)]);
}

/// The JS chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding (the sink file still trips
/// the single-file regex heuristic `js/no-sql-injection`, but no `*/taint-*`
/// rule fires because no source is present in any single file).
#[test]
fn realistic_js_multihop_single_file_finds_no_taint() {
    assert_fixture("js_multihop/routes.js", 0, &[]);
    assert_fixture("js_multihop/service.js", 0, &[]);
    assert_fixture("js_multihop/store.js", 1, &[]);
}

/// Negative multi-hop: identical shape to `js_multihop` but the middle helper
/// runs the value through `mysql.escape()` (a configured SQL sanitizer) before
/// forwarding it. The sanitizer collapses the value to clean, so the composed
/// summary records no sink flow and the chain BREAKS — no taint finding on a
/// directory scan (only the sink file's regex hit).
#[test]
fn realistic_js_multihop_sanitizer_breaks_chain() {
    assert_fixture("js_multihop_sanitized", 1, &[]);
}

/// Multi-hop chain fixture (issue #175). Three-file Go chain:
/// handlers.go (source) → transform.go (passthrough) → store.go (sink).
#[test]
fn realistic_gin_chain_multihop() {
    assert_fixture("gin_chain", 2, &[("go/taint-sql-injection", 1)]);
}

/// Bounded multi-hop chain where the MIDDLE helper itself makes the same-package
/// cross-file call. Three-file Go chain:
/// handlers.go (source) → loadFile() → readData() (os.ReadFile sink), where
/// `loadFile` forwards its argument to `readData` in a THIRD file of the same
/// package. Only found once `loadFile`'s summary is composed one hop deeper
/// against `readData`'s summary (the scanner's bounded multi-hop fixpoint). Uses
/// `go/taint-path-traversal` because that Go rule has a configured sanitizer
/// (`filepath.Clean`), which the negative variant below uses to break the chain
/// (`go/taint-sql-injection` has no sanitizer to test that path with).
#[test]
fn realistic_go_multihop_composed() {
    assert_fixture("go_multihop", 1, &[("go/taint-path-traversal", 1)]);
}

/// The Go chain above must only resolve on a full-directory scan: scanning any
/// single file in isolation finds no taint finding, since no source is present
/// in any single file and `name` is only ever a bare parameter.
#[test]
fn realistic_go_multihop_single_file_finds_no_taint() {
    assert_fixture("go_multihop/handlers.go", 0, &[]);
    assert_fixture("go_multihop/service.go", 0, &[]);
    assert_fixture("go_multihop/store.go", 0, &[]);
}

/// Negative multi-hop: identical shape to `go_multihop` but the middle helper
/// runs the value through `filepath.Clean()` (a configured path-traversal
/// sanitizer) before forwarding it. The sanitizer collapses the value to clean,
/// so the composed summary records no sink flow and the chain BREAKS — no
/// finding at all on a directory scan.
#[test]
fn realistic_go_multihop_sanitizer_breaks_chain() {
    assert_fixture("go_multihop_sanitized", 0, &[]);
}

#[test]
fn realistic_gin_app() {
    // Three planted vulnerabilities (command injection, SQL
    // injection, SSRF) — one per go/taint-* rule. The conservative
    // go/no-* counterparts coexist on the same lines, plus the
    // go/gin-no-trusted-proxies rule fires on gin.Default() in
    // main(). Total = 3 taint + 3 conservative injection + 1
    // gin-no-trusted-proxies = 7.
    assert_fixture(
        "gin_app.go",
        7,
        &[
            ("go/taint-command-injection", 1),
            ("go/taint-sql-injection", 1),
            ("go/taint-ssrf", 1),
        ],
    );
}
