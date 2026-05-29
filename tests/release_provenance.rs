const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const README: &str = include_str!("../README.md");
const NPM_README: &str = include_str!("../packages/npm/README.md");
const PROVENANCE_DOCS: &str = include_str!("../docs/release-provenance.md");

fn index_of(haystack: &str, needle: &str) -> usize {
    match haystack.find(needle) {
        Some(index) => index,
        None => panic!("missing expected release provenance text: {needle}"),
    }
}

#[test]
fn release_workflow_attests_binaries_before_publishing_release() {
    assert!(RELEASE_WORKFLOW.contains("id-token: write"));
    assert!(RELEASE_WORKFLOW.contains("attestations: write"));
    assert!(RELEASE_WORKFLOW.contains("contents: write"));

    assert_eq!(
        RELEASE_WORKFLOW
            .matches("uses: actions/attest-build-provenance@v2")
            .count(),
        2
    );
    assert!(RELEASE_WORKFLOW.contains("subject-checksums: release/checksums.txt"));
    assert!(RELEASE_WORKFLOW.contains("subject-path: release/checksums.txt"));

    let checksum_step = index_of(RELEASE_WORKFLOW, "name: Generate checksums");
    let attest_step = index_of(RELEASE_WORKFLOW, "name: Attest release binaries");
    let release_step = index_of(RELEASE_WORKFLOW, "uses: softprops/action-gh-release@v2");

    assert!(checksum_step < attest_step);
    assert!(attest_step < release_step);
}

#[test]
fn installer_docs_explain_checksum_and_provenance_behavior() {
    for docs in [README, NPM_README, PROVENANCE_DOCS] {
        assert!(docs.contains("checksums.txt"));
        assert!(docs.contains("gh attestation verify"));
    }

    assert!(PROVENANCE_DOCS.contains("SHA-256"));
    assert!(PROVENANCE_DOCS.contains("Failure modes"));
    assert!(PROVENANCE_DOCS.contains("Trust model"));
}
