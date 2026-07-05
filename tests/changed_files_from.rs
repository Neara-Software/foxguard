// Integration tests for the `--changed-files-from <FILE>` scan flag.
//
// This flag diff-scopes a scan to a newline-delimited, root-relative file
// list while keeping the scan path as the analysis root, so the GitHub App
// can scan only a PR's changed files instead of the whole cloned tree.
//
// IMPORTANT ENGINE NOTE (verified, diverges from the original design memo):
// "root context" does NOT pull *unlisted* sibling files into taint analysis.
// `scan_paths_with_root` builds cross-file taint summaries only from the
// files actually passed in; `scan_root` is used for path attribution and
// exclude matching, not for discovering additional context files. Concretely:
// a cross-file flow is resolved only when BOTH the source file and the sink
// file are in the listed subset. If the source (or sink) lives in an unlisted
// file, the flow is lost. The tests below pin exactly this behavior.

use std::path::{Path, PathBuf};
use std::process::Command;

fn foxguard_cmd() -> Command {
    // `--config /dev/null` isolates from any developer-local `.foxguard.yml`
    // and the repo baseline (which suppresses tests/fixtures findings).
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_foxguard"));
    cmd.args(["--config", "/dev/null"]);
    cmd
}

fn django_chain_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("realistic")
        .join("django_chain")
}

/// Run a scan against `root` with the given `--changed-files-from` list
/// contents. Returns (exit_success, rule_ids-with-basenames).
fn scan_with_list(
    root: &Path,
    list_contents: &str,
    extra: &[&str],
) -> (bool, Vec<(String, String)>) {
    let list_file = tempfile::NamedTempFile::new().expect("create temp list file");
    std::fs::write(list_file.path(), list_contents).expect("write list file");

    let output = foxguard_cmd()
        .arg(root)
        .arg("--changed-files-from")
        .arg(list_file.path())
        .args(extra)
        .args(["-f", "json"])
        .output()
        .expect("run foxguard");

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON report");
    let findings = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| {
            let rule = f["rule_id"].as_str().unwrap_or("").to_string();
            let file = f["file"]
                .as_str()
                .unwrap_or("")
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();
            (rule, file)
        })
        .collect();

    (output.status.success(), findings)
}

/// Gate #1: cross-file taint is preserved when scanning a *subset* of a larger
/// tree, as long as both the source and sink files are listed. django_chain is
/// a 3-file tree (views.py -> middleware.py -> queries.py); we list only two of
/// them (views.py, queries.py) and still resolve the SQL-injection flow — the
/// unlisted middleware.py passthrough hop does not break it. This proves the
/// subset scan analyzes the listed files together (root context for path
/// attribution), not each file in isolation.
#[test]
fn changed_files_from_preserves_cross_file_taint_among_listed_files() {
    let (ok, findings) = scan_with_list(&django_chain_dir(), "views.py\nqueries.py\n", &[]);
    assert!(ok || !findings.is_empty(), "scan should run");
    assert!(
        findings
            .iter()
            .any(|(rule, file)| rule == "py/taint-sql-injection" && file == "views.py"),
        "cross-file taint flow should resolve across listed files; got {findings:?}"
    );
}

/// Gate #1 corollary + engine limitation: listing ONLY the sink file (source
/// unlisted) does NOT resolve the cross-file flow. This directly contradicts
/// the original design memo's claim that root context preserves a flow whose
/// source is in an unlisted file. The subset scan still returns only the
/// listed file's own findings.
#[test]
fn changed_files_from_returns_only_listed_files_findings() {
    let (_ok, findings) = scan_with_list(&django_chain_dir(), "queries.py\n", &[]);
    // queries.py's own single-file finding is present...
    assert!(
        findings.iter().any(|(_, file)| file == "queries.py"),
        "listed file's own findings should be present; got {findings:?}"
    );
    // ...but nothing from unlisted files, and the cross-file taint (attributed
    // to the unlisted views.py source) is absent.
    assert!(
        findings.iter().all(|(_, file)| file == "queries.py"),
        "only listed files should appear; got {findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|(rule, _)| rule == "py/taint-sql-injection"),
        "cross-file taint must NOT resolve when the source file is unlisted; got {findings:?}"
    );
}

/// Gate #2: an empty list scans nothing and exits 0 with zero findings — no
/// fall-back to a full-tree scan.
#[test]
fn changed_files_from_empty_list_scans_nothing() {
    let (ok, findings) = scan_with_list(&django_chain_dir(), "", &[]);
    assert!(ok, "empty list should exit 0");
    assert!(
        findings.is_empty(),
        "empty list should yield no findings; got {findings:?}"
    );
}

/// Gate #2: a list whose entries are all missing (e.g. files a PR deleted) is
/// treated the same as an empty list — zero findings, exit 0, no full-tree
/// fall-back. Blank lines and `#` comments are ignored.
#[test]
fn changed_files_from_all_missing_paths_scans_nothing() {
    let (ok, findings) = scan_with_list(
        &django_chain_dir(),
        "# a comment\n\ndoes/not/exist.py\nalso_missing.py\n",
        &[],
    );
    assert!(ok, "all-missing list should exit 0");
    assert!(
        findings.is_empty(),
        "all-missing list should yield no findings; got {findings:?}"
    );
}

/// Gate #4: `--exclude` composes with `--changed-files-from` and actually
/// excludes matching paths. Listing queries.py yields its single-file finding;
/// adding `--exclude queries.py` removes it.
#[test]
fn changed_files_from_respects_exclude() {
    let (_ok, baseline) = scan_with_list(&django_chain_dir(), "queries.py\n", &[]);
    assert!(
        baseline.iter().any(|(_, file)| file == "queries.py"),
        "baseline should include queries.py finding; got {baseline:?}"
    );

    let (ok, excluded) = scan_with_list(
        &django_chain_dir(),
        "queries.py\n",
        &["--exclude", "queries.py"],
    );
    assert!(ok, "excluded scan should exit 0");
    assert!(
        excluded.is_empty(),
        "excluding queries.py should drop its finding; got {excluded:?}"
    );
}
