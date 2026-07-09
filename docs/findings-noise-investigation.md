# Investigation: 827-findings/PR noise — scope + noisy-rule breakdown

> **RESOLVED (2026-07-09).** The P0/P1 recommendations below shipped and are
> deployed in production:
> - **Scan scoping** ([#544](https://github.com/0sec-labs/foxguard/pull/544)):
>   full-tree scan first (whole-repo cross-file taint preserved), with a
>   **diff-scoped fallback** (`--changed-files-from`) only on timeout, plus
>   noise-path `--exclude` globs.
> - **Configurable timeout** ([#543](https://github.com/0sec-labs/foxguard/pull/543)):
>   `FOXGUARD_SCAN_TIMEOUT_SECS`, deployed at 180.
>
> Measured effect after deploy: the scan **timeout rate dropped from 20.5%
> (468/2285 over 41 days) to 0% (0/125 over the following ~3.6 days)** — the
> raised timeout + exclusions let even the large monorepos finish the full scan,
> so the fallback isn't currently exercised and full cross-file coverage is
> retained. The analysis below is kept as the record of the original diagnosis.

Read-only investigation. **No detection logic was changed.** Goal: explain why
the GitHub App reports a median of **827 findings/PR** (p90 972, max 1,834) with
**~20% of scans hitting the 60s timeout**, and recommend concrete fixes.

Code paths cited are on current `main` at the time of writing (2026-07-05).

---

## 1. Scope question — full-tree or diff? (THE key finding)

**The scan is full-tree. The posted output is diff-scoped.** These are two
different stages, and conflating them is the source of the confusion.

### The scan runs over the entire checked-out working tree

`src/bin/foxguard_github_app.rs`:

- `run_pull_request_scan` clones the PR head and checks out the **full head
  SHA working tree** — `git_clone_head(...)` then `git checkout --detach <sha>`
  (lines 506-511). There is no path/diff restriction.
- It then calls `run_scanner(&checkout)` (line 520). `run_scanner`
  (lines 686-695) invokes:

  ```
  foxguard <checkout> --format json
  ```

  i.e. it points the CLI at the **whole repo root** with **no `--severity`,
  no `--changed`, no path filter**. The CLI default `severity: Option<...>` is
  `None`, and `src/app.rs:327` only filters when it is `Some`, so **every
  finding of Low severity and above, across the entire repository, is
  collected** — pre-existing issues included.
- The resulting count is what gets logged as the per-PR `findings` number:
  `findings = result.findings.len()` at `foxguard_github_app.rs:306`.

So the "827 findings per PR" figure is the **whole-repo scan count**, not the
number of comments posted to the PR. A repo with 827 pre-existing issues
reports 827 on *every* PR regardless of what the PR changed.

### The *posted* output IS filtered to the PR diff

`process_pull_request_delivery` (`foxguard_github_app.rs:449-477`) computes the
PR's changed lines and passes them into both surfaces:

- `post_pull_request_review` (`src/github_app/review.rs:75`) ->
  `filter_findings_to_changed_lines` (review.rs:109) **and** a second
  changed-line filter in `review_comment_payloads` (review.rs:628). Only
  findings whose file **and** exact line are in the PR's added lines become
  inline comments.
- `post_check_run` (review.rs:135) -> same `filter_findings_to_changed_lines`
  (review.rs:144). Annotations and the pass/fail conclusion reflect only
  PR-introduced findings, and annotations are capped at 50 (review.rs:580).

Path matching is consistent: scan findings are made repo-relative
(`relative_path(&finding.file, Some(&checkout))`, foxguard_github_app.rs:523),
and `changed_lines` is keyed by GitHub's repo-relative `file.filename`
(review.rs:250-256). The filter fails *safe* (a path mismatch would post
**fewer** comments, never more).

### Consequences

1. **The 60s timeouts are caused by the full-tree scan.** Every PR re-scans the
   entire repository from scratch; on large repos this blows the
   `PULL_REQUEST_SCAN_TIMEOUT` of 60s (`foxguard_github_app.rs:48`). A timeout
   returns `Err` from `run_command_with_timeout`, which aborts
   `process_pull_request_delivery` — so **those ~20% of PRs get no review at
   all**. Timeouts correlate with high finding counts because big repos both
   produce more findings and take longer to scan.
2. **The 827 metric measures the wrong thing.** It is the raw whole-repo scan
   count (`result.findings.len()`), *not* comments posted. Actual reviewer-facing
   noise (`posted_comments`) is a diff-scoped subset. Two possibilities, both
   worth confirming against prod:
   - the dashboards are reading `findings` (the raw count) instead of
     `posted_comments` — measuring noise that reviewers never see; or
   - **prod is running a build that predates the changed-line filter**, in which
     case all 827 really are posted. The filter and its tests are well
     established on `main`, so a version check on the deployed image is the
     fastest way to rule this in or out.

Either way, the full-tree scan is pure waste for PR review: since the output is
line-filtered anyway, scanning the whole tree buys nothing for the reviewer and
costs the timeout.

---

## 2. Rule-frequency breakdown (reproduced locally)

Built `target/release/foxguard` from this worktree and ran
`foxguard <repo> --format json` (same invocation the app uses — no severity
filter) on three repos: the foxguard repo itself, and two public repos the app
scans in prod. These are clean shallow clones, so totals are smaller than
prod's large-repo median of 827, but **the rule-level Pareto is identical**: a
tiny number of rules produce the overwhelming majority of findings.

### foxguard (self-scan) — 98 findings, 563 ms

Severity: **59 critical, 16 high, 23 medium, 0 low**.

| count | rule_id | severity |
|------:|---------|----------|
| 17 | `rs/no-unwrap-in-lib` | medium |
| 6 | `bash/taint-command-injection` | high |
| 4 | `rs/no-path-traversal` | high |
| 4 | `apex/taint-soql-injection` | critical |
| 3 | `solidity/taint-arbitrary-delegatecall` | critical |
| 3 | `rb/taint-command-injection` | critical |
| 3 | `rb/no-command-injection` | high |
| 3 | `php/taint-command-injection` | critical |
| 3 | `php/no-command-injection` | high |
| 3 | `csharp/taint-sql-injection` | critical |

**46 of 98 findings (47%) are in `tests/fixtures/`** — foxguard's own
intentionally-vulnerable test corpus. Self-scanning a SAST tool detonates its
own fixtures; this alone explains most of the "critical" volume in the
dogfooding number.

### danielbodnar/web-ai-demos — 50 findings, 333 ms

Severity: **3 critical, 47 high, 0 medium, 0 low**.

| count | rule_id | severity |
|------:|---------|----------|
| 24 | `js/no-xss-innerhtml` | high |
| 19 | `js/no-ssrf` | high |
| 3 | `js/no-command-injection` | high |
| 1 | `manifest/npm-pq-vulnerable-dep` | critical |
| 1 | `js/taint-ssrf` | high |
| 1 | `js/no-prototype-pollution` | high |

**Two rules (`js/no-xss-innerhtml` + `js/no-ssrf`) = 43/50 (86%)**. They cluster
in a handful of demo scripts, and include hits in a **minified vendored file
(`FileProxyCache-min.js`)** and test tooling (`sync-wpt.js`).

### Darkroom4364/eidolon — 66 findings, 238 ms

Severity: **0 critical, 63 high, 3 medium, 0 low**.

| count | rule_id | severity |
|------:|---------|----------|
| 55 | `bash/taint-path-traversal` | high |
| 8 | `bash/taint-ssrf` | high |
| 2 | `rs/no-unwrap-in-lib` | medium |
| 1 | `rs/no-path-traversal` | high |

**A single rule, `bash/taint-path-traversal`, is 55/66 (83%)** — all HIGH, all
firing on example/smoke shell scripts (`examples/.../*.sh`). Two bash taint rules
account for 63/66 (95%).

### Combined top rules (all three repos, 214 findings)

| count | rule_id |
|------:|---------|
| 57 | `bash/taint-path-traversal` |
| 24 | `js/no-xss-innerhtml` |
| 19 | `rs/no-unwrap-in-lib` |
| 19 | `js/no-ssrf` |
| 11 | `bash/taint-ssrf` |
| 6 | `bash/taint-command-injection` |
| 5 | `rs/no-path-traversal` |

The top 5 rules produce **130/214 (61%)** of all findings.

---

## 3. Noise vs signal diagnosis

- **This is not INFO/LOW spam.** Across all three repos there are **zero Low
  findings**; the volume is HIGH and CRITICAL. The severity floor is already
  effectively medium+. **A severity gate alone will barely dent the count** —
  the noisy rules are all HIGH/CRITICAL.
- **The noise is concentrated (Pareto) and comes from two structural sources:**
  1. **Files that should never be in a PR security review**: test/vuln fixtures
     (47% of foxguard's findings), `examples/*.sh` (all of eidolon's top rule),
     minified/vendored JS (`*-min.js`), and generated/test tooling
     (`sync-wpt.js`). The scanner has no scan-time exclusion for these.
  2. **A few FP-prone rules firing en masse**: `bash/taint-path-traversal`
     (variable-in-path in shell scripts), `bash/taint-ssrf`,
     `js/no-xss-innerhtml` (any `innerHTML =` is notoriously FP-heavy), and
     `js/no-ssrf`. `rs/no-unwrap-in-lib` is a pure **code-quality lint**
     (`.unwrap()` usage) that does not belong in a PR *security* review at all.
- **The app posts every severity** that lands on a changed line — there is no
  HIGH+ gate before posting (review.rs makes no severity cut when building
  comments; it only filters by changed line).

---

## 4. Recommendations (prioritized by impact)

### P0 — Scope the *scan* to changed files, not the whole tree
The output is already diff-scoped, so a full-tree scan is wasted work that
directly causes the 60s timeouts (and the ~20% of PRs that consequently get **no
review**). Restrict what the scanner reads to the PR's changed files.
- **Where:** `run_pull_request_scan` / `run_scanner`
  (`src/bin/foxguard_github_app.rs:496-534, 686-695`). The changed-file set is
  already fetched (`pull_request_changed_lines`, review.rs:63) — pass those
  paths as scan targets instead of `&checkout`, or use the CLI's existing
  `--changed`/diff mode against the PR base. This shrinks scan time by
  orders of magnitude on large repos and eliminates most timeouts.

### P0 — Fix / verify the metric and the deployed build
- Confirm whether the "827/PR" dashboard reads `findings` (raw whole-repo count,
  `foxguard_github_app.rs:306`) or `posted_comments`. Report `posted_comments`
  as the user-facing noise number.
- **Verify the prod image contains the changed-line filter**
  (`filter_findings_to_changed_lines`, review.rs). If prod predates it, all 827
  really are being posted and shipping the current build is the single biggest
  fix.

### P1 — Add scan-time path exclusions
Skip directories/files that are never meaningful in PR review:
`**/tests/fixtures/**`, `**/test/**`, `**/examples/**`, `**/*-min.js`,
`**/*.min.js`, vendored/generated dirs. In the three sample repos this removes
the large majority of findings (47% of foxguard's, 83% of eidolon's top rule,
plus the minified-JS hits in web-ai-demos).

### P1 — Reclassify / gate the top noisy rules
Ordered by observed volume, with the counts that justify each:
1. `bash/taint-path-traversal` — 57 (83% of eidolon). Highest FP-per-fire; tune
   sanitizer/source model or downgrade for the PR-review profile.
2. `js/no-xss-innerhtml` — 24. Downgrade or require a tighter source condition;
   raw `innerHTML =` is extremely FP-prone.
3. `js/no-ssrf` / `bash/taint-ssrf` — 19 + 11. Same tuning.
4. `rs/no-unwrap-in-lib` — 19. A **code-quality lint**, not a vulnerability.
   Exclude it (and other `no-unwrap`/style lints) from the GitHub App's security
   review profile entirely.

### P2 — Add a severity gate for the App (defense in depth)
Have the app post only HIGH+ by default (`--severity high` in `run_scanner`, or
a severity cut in `post_pull_request_review`). Lower impact than the above
because the noisy rules are already HIGH — but it cleanly removes the medium
lint tier (e.g. `rs/no-unwrap-in-lib`) and gives operators a single dial.

### P2 — Timeout
The 60s cap (`PULL_REQUEST_SCAN_TIMEOUT`, foxguard_github_app.rs:48) is a symptom
mask. Once the scan is diff-scoped (P0) it should rarely be approached; keep the
cap but the fix is scope, not a longer timeout.

---

## Appendix — reproduction

```
cargo build --release --bin foxguard
foxguard <repo> --format json | jq '.finding_counts, (.findings[].rule_id)'
```

Repos: this worktree; `github.com/danielbodnar/web-ai-demos`;
`github.com/Darkroom4364/eidolon` (both `--depth 1`). No `--severity` flag,
matching the app's invocation.
