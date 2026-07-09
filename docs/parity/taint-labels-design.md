# Taint-labels (`label:` / `requires:`) feasibility assessment

> **Update (2026-07-09): re-examined `react-href-var`, `raw-html-format`, and
> `grpc-server-insecure-connection` against the current `LabelPolicy` machinery
> — all three stay DEFERRED, each on an independent hard blocker that is NOT
> just "boolean `requires:` algebra" (that part the engine now has). The
> `RequiresExpr` parser already accepts each rule's sink expression verbatim
> (`TAINTED and not CONCAT and not CLEAN`,
> `(EXPRESS and not CLEAN) or (EXPRESSTS and not CLEAN)`); the blockers are
> elsewhere and are per-rule distinct:**
>
> - **`react-href-var` (TS/JS)** — deferred on FOUR compounding gaps, any one
>   fatal: (1) **the JS/TS engine is not label-aware at all.** `LabelPolicy` is
>   threaded and consumed only by the Go and Java engines (`analyze_tree_labeled`
>   / `expression_labels` / `source_labels` in `go_taint.rs`; the Java engine's
>   per-value label set). Every `AnalysisContext` the JS engine builds in
>   `javascript_taint.rs` passes `label_policy: None`, and it runs the unlabeled
>   `analyze_tree`. Loading this rule needs ~600 lines of Go-equivalent label
>   machinery ported into the JS engine's different AST handling. (2) **`CLEAN`
>   is a `by-side-effect: true` source with NO `requires:`**, so
>   `detect_label_policy` classifies it as a *second primary label* (alongside
>   `TAINTED`) → refused (`primary_labels.len() != 1`). A faithful load needs
>   `detect_label_policy` extended to recognize a no-`requires` `by-side-effect`
>   sanitizer source (whose label appears only under `not` in the sink) as a
>   sanitizer *relabel*, not a primary — a new detect shape. (3) **The `CONCAT`
>   relabel is not the generic string-building relabel the engine models.** Its
>   trigger is a template-literal / JSX-concat with explicit `pattern-not`
>   carve-outs (fires on `` `...${$X}...` `` and `$SAN + <...$X...>` but NOT on a
>   leading-interpolation `` `${$X}...` `` nor `$X + ...`); the engine's `Relabel`
>   carries only `{from, to}` and hard-codes the string-building trigger, with no
>   way to express these exclusions. (4) **The sink shapes do not exist in the JS
>   engine**: a JSX `href={$X}` attribute sink, a `React.createElement($EL,{href:$X})`
>   object-argument sink with a `metavariable-pattern $EL !~ button`, AND an
>   object-property *indirection* (`$PARAMS = {href:$X}; …; React.createElement($EL,$PARAMS)`
>   — the rule's only positive fixture) that requires object-field taint flow.
>   `grep` confirms zero `jsx`/`href`/`createElement` sink handling in
>   `javascript_taint.rs`.
>
> - **`raw-html-format` (JS/express)** — deferred, and **the over-match is
>   unavoidable even if the JS engine were made label-aware.** The sink's HTML-tag
>   discriminator — the thing that separates the rule's positives
>   (`"<h1>" + req.query.message`, `` `<h1>…${req.query.message}…` ``) from its own
>   `ok` cases (`"message: " + req.query.message`, `` `message: ${req.query.message}` ``)
>   — is a `metavariable-pattern` (generic `<$TAG ...`) on the concatenated literal
>   plus a `pattern-regex: .*<\w+.*` on the template-literal branch. The loader
>   reports both as unenforceable inside a taint sink: *"pattern-sinks `patterns:`
>   block contains `metavariable-pattern` which foxguard cannot enforce … dropping
>   constraint (matcher will be broader than the original rule)"* and *"unknown key
>   `pattern-regex`; skipping sub-item"*. Dropping the HTML-tag constraint makes the
>   sink fire on the non-HTML `ok` concatenations → **over-match on the rule's own
>   negative fixtures**, which the parity bar forbids. Independently: the sink
>   shapes `util.format($HTMLSTR, …)`, `"$HTMLSTR".concat(…)`, and a bare
>   template-literal `` `...` `` sink are all reported *unsupported pattern shape*;
>   and the sources are two primaries (`EXPRESS` + `EXPRESSTS`) plus the same
>   no-`requires` `by-side-effect` `CLEAN` → three primaries → `detect_label_policy`
>   refuses. (The two express-input primaries *would* collapse cleanly — the sink
>   `(EXPRESS and not CLEAN) or (EXPRESSTS and not CLEAN)` is exactly
>   `(EXPRESS ∨ EXPRESSTS) ∧ ¬CLEAN` — but the unenforceable HTML-tag sink
>   discriminator is the fatal blocker regardless.)
>
> - **`grpc-server-insecure-connection` (Go)** — deferred (as pre-flagged
>   likely-defer). It is a **structural predicate, not a dataflow**, with THREE
>   distinct primary labels (`OPTIONS`/`CREDS`/`EMPTY_CONSTRUCTOR`) and **two sinks
>   carrying DIFFERENT `requires:`** (`OPTIONS and not CREDS` vs
>   `EMPTY_CONSTRUCTOR`). `detect_label_policy` models exactly one primary label
>   and one shared sink gate; both invariants are violated. Dropping the `not CREDS`
>   gate on the first sink fires on the secure `ok` case
>   `grpc.NewServer(grpc.Creds(credentials.NewClientTLSFromCert(...)))` → over-match.
>   The `OPTIONS` source `grpc.ServerOption{ ... }` (struct-literal) does not even
>   match the fixture's `[]grpc.ServerOption{ ... }` (slice-literal), so the first
>   sink has no positive fixture and could not be validated even if modeled. Only
>   the bare `grpc.NewServer()` empty-constructor sink is trivially expressible
>   (a plain zero-arg-call structural pattern), but loading just that abandons the
>   `OPTIONS and not CREDS` sink and misrepresents the rule — half a rule under a
>   whole rule's id. Defer as a unit.
>
> **Net: load-rate delta 0 rules (3 Go/JS/TS still skipped).** The negation-tier
> `LabelPolicy` (2026-07-05) covers these rules' *sink boolean algebra* but none
> of them is blocked *only* on that; the remaining blockers are (a) JS/TS engine
> label-awareness, (b) `detect_label_policy` support for no-`requires`
> `by-side-effect` sanitizer relabels + collapsing equivalent express-input
> primaries, (c) taint-sink `metavariable-pattern`/`pattern-regex` enforcement
> (raw-html-format's HTML-tag discriminator), (d) JSX-attribute / object-property
> sink shapes (react-href-var), and (e) multi-primary / per-sink-differing-`requires`
> for the structural gRPC rule. Each is a separate, larger feature.
>
> **Update (2026-07-05): the negation tier (`not`/`and`/`or` in `requires:`) is
> now IMPLEMENTED in the engine.** `LabelPolicy` is generalized to a single
> primary `source_label`, a list of conditional string-building `Relabel`s
> (`from → to`, e.g. `INPUT → CLEAN`), and a boolean `RequiresExpr` sink gate
> (`Label` / `Not` / `And` / `Or`, parenthesized) parsed by `parse_requires_expr`
> in the bridge. `detect_label_policy` now recognizes the single-primary-label
> negation shape (`INPUT and not CLEAN`) in addition to the positive `CONCAT`
> family, and refuses (keeps skipping) shapes with *multiple distinct primary
> labels* (the TS/JS `react-href-var` / `raw-html-format` rules) or *per-sink
> differing requires* (the Go gRPC rule's two sinks). Both the **Java** engine
> (already label-aware) and the **Go** engine (labels newly threaded onto the
> shared `TaintInfo`/`AnalysisContext`) evaluate the boolean gate. The HARD
> faithfulness gate is proven end-to-end through the real `parse_taint_rule` →
> `check` path: `INPUT and not CLEAN` **fires** on `input → redirect(input)` and
> **does NOT fire** on `input → clean(input) → redirect(cleaned)` (the value that
> flowed through a `"url" + input` / `fmt.Sprintf` relabel acquires `CLEAN` and
> is suppressed) — for both Go and Java fixtures. Over-firing (ignoring
> `not CLEAN`) never happens: the relabel over-approximates `CLEAN` (we drop the
> URL-shaped `metavariable-regex` on the relabel literal), which only ever
> *suppresses* a `not CLEAN` sink — the safe, false-negative direction.
>
> **Registry load-rate delta from the negation tier: 0 rules.** The two Go
> registry rules (`open-redirect`, `tainted-url-host`) reach the label machinery
> but remain skipped for an **independent source-compat gap**: their source
> `($REQUEST : *http.Request).$ANYTHING` is a Go typed-metavariable receiver with
> a metavariable field pinned by `metavariable-regex`. The Go engine has no
> typed-metavariable source support and refuses to broaden the source by dropping
> the type/regex (which would seed *any* `.Host`/`.URL` read as user input — an
> over-match at the gated sink), so the source compiles to no matcher →
> `has no valid pattern-sources`. Un-skipping those two rules needs Go
> typed-source + metavariable-regex-field compilation (a separate matcher-compat
> feature with Go type tracking), not more label algebra. The TS/JS multi-primary
> rules stay deferred (multiple distinct primary source labels are not modeled by
> the single-primary policy). The gRPC rule stays deferred (two differently-gated
> sinks).
>
> **Update (2026-07-04): the Java `CONCAT` family is IMPLEMENTED** (the
> single-positive-label slice recommended below). `formatted-sql-string` and
> `tainted-system-command` now load and match faithfully — a tainted value that
> flows through a string concatenation/format into the sink fires, while the
> same value reaching the sink WITHOUT a concat (e.g. a parameterized query)
> does not (the `requires: CONCAT` discrimination). Mechanism: a per-value label
> set on the Java engine's `TaintInfo`, a `LabelPolicy` compiled by
> `detect_label_policy` in the bridge, a string-building conditional relabel
> (`requires INPUT → emit CONCAT`), and a sink label gate. `tainted-html-string`
> still skips: its `ResponseEntity` focus-metavariable sink shape does not
> compile to a matcher (a sink-compat gap, independent of labels). The rest of
> this note is the original assessment.

Status: **assessment-only — nothing implemented.** The faithfully-loadable
subset is empty; every registry rule that uses taint-labels needs the full
labeled-taint algebra (per-value label *sets*, conditional relabeling
propagators, and `not`/`and`/`or` `requires:` evaluation over a join lattice).
A partial "load the rule but ignore `requires:`" would over-match, which the
parity bar explicitly forbids (over-matching is worse than skipping).

Audited against the registry snapshot on branch `taint-expansion`
(measurement date 2026-07-04), verified with `registry_coverage`.

## What taint-labels are

Semgrep's advanced taint mode lets each source emit a named **label**. Sinks
(and label-emitting sources/propagators) gate on a `requires:` boolean over
labels. A finding fires only when the taint *reaching* the sink satisfies the
sink's `requires:` expression, evaluated over the set of labels the flow
carries.

```yaml
pattern-sources:
  - pattern: get_user_input()
    label: USER_INPUT
  - pattern: get_admin_flag()
    label: IS_ADMIN
pattern-sinks:
  - patterns: [{pattern: dangerous($X)}]
    requires: USER_INPUT and not IS_ADMIN
```

## Enumeration: every registry rule using taint-labels

Grepping the snapshot for `label:` / `requires:` yields **12 files**, but 4 are
`yaml/docker-compose/**` rules that merely *match* literal `labels:` service
config — not taint-labels. The **8 genuine taint-label rules**:

| # | Rule | Lang | Sink `requires:` (the gating expr) | Relabel source/propagator? |
|---|------|------|------------------------------------|----------------------------|
| 1 | `go/lang/.../injection/open-redirect` | Go | `INPUT and not CLEAN` | `CLEAN` source `requires: INPUT` |
| 2 | `go/lang/.../injection/tainted-url-host` | Go | `INPUT and not CLEAN` | `CLEAN` source `requires: INPUT` |
| 3 | `go/grpc/.../grpc-server-insecure-connection` | Go | `OPTIONS and not CREDS` **and** a 2nd sink `EMPTY_CONSTRUCTOR` | none (3 primary labels) |
| 4 | `java/lang/.../audit/formatted-sql-string` | Java | `CONCAT` | `CONCAT` source `requires: INPUT` + 2 `pattern-propagators` |
| 5 | `java/spring/.../injection/tainted-html-string` | Java | `CONCAT` | `CONCAT` source `requires: INPUT` + propagators |
| 6 | `java/spring/.../injection/tainted-system-command` | Java | `CONCAT` | `CONCAT` **propagator** `requires: INPUT` |
| 7 | `typescript/react/.../audit/react-href-var` | TS | `TAINTED and not CONCAT and not CLEAN` | `CONCAT` source `requires: TAINTED` |
| 8 | `javascript/express/.../injection/raw-html-format` | JS | `(EXPRESS and not CLEAN) or (EXPRESSTS and not CLEAN)` | none (3 primary labels) |

### `requires:` complexity histogram (sink gating expression)

| Tier | Shape | Count | Rules |
|------|-------|-------|-------|
| A | single label from an **unconditional** primary source | **0** | — |
| B | single label that is a **relabel** (source/propagator with `requires:`) | 3 | java ×3 (`CONCAT`) |
| C | `A and not B` (negation) | 3 | go open-redirect, go tainted-url-host, go grpc (`OPTIONS and not CREDS`; 2nd sink is single primary `EMPTY_CONSTRUCTOR`) |
| D | `A and not B and not C` | 1 | ts react-href-var |
| E | `(A and not B) or (C and not B)` (parens + or + and + not) | 1 | js raw-html-format |

Source/propagator-side `requires:` (the relabeling mechanic) is always the
single-label form `requires: INPUT` / `requires: TAINTED` (6 of 8 rules use it).

**Key finding:** Tier A is empty. There is *no* rule whose sink requires a
single label emitted unconditionally by a primary source. Every rule needs at
least one of:
- **negation** in the sink `requires:` (6 rules: 1,2,3,7,8), or
- a **conditional relabeling** source/propagator — a node that emits label L2
  only when it consumes a value already carrying label L1 (6 rules: 1,2,4,5,6,7).

The two "simplest looking" families still fail the tractable bar:
- The **Java `requires: CONCAT`** rules look like a single positive label, but
  `CONCAT` is emitted by a source/propagator `requires: INPUT` — i.e. a
  concatenation/format node is labeled `CONCAT` *only if* an `INPUT`-tainted
  operand flows into it. Firing on any `INPUT` reaching the sink over-matches
  (it would flag safe non-concatenated queries).
- The **gRPC** rule's `EMPTY_CONSTRUCTOR` sink is a single primary label, but the
  same rule's other sink is `OPTIONS and not CREDS`; a rule loads as a unit, so
  the negation must be handled to load it faithfully.

## Current behavior (verified, safe)

All 8 rules are **skipped today** with `has no valid pattern-sources`. The
`compile_entry` loader requires each source/sink list entry to carry exactly one
key; a `label:`/`requires:` alongside `patterns:` makes the entry multi-key, so
it is warn-dropped, the source list empties, and the rule is rejected. This is
**safe (no over-matching)** — confirmed via `registry_coverage` on each file:
`1 rules, 0 loaded, 1 skipped` for all eight.

## Why this cannot be cleanly bolted onto the current engine

The engine (`src/rules/taint_engine.rs`) is a single-pass, forward,
**boolean** may-taint tracker:

- `TaintState.tainted: HashMap<String, TaintInfo>` — a variable is tainted or
  not. `TaintInfo` carries a description + line, **no label set**.
- `TaintSpec { sources, sinks, sanitizers }` — flat `Vec<NodeMatcher>` with **no
  label attached to a matcher and no `requires:` attached to a sink**.
- `Propagator` is the unconditional "argument taints receiver" subset — no
  `requires:` gate, no relabeling (it adds the *same* boolean taint).
- Sinks fire the instant any tainted value reaches them; there is no join
  lattice, so "value carries CLEAN on one branch but not another" is
  inexpressible.

A faithful implementation requires, at minimum:

1. **Per-value label sets.** Change `TaintInfo` to carry `HashSet<Label>` and
   thread it through **all 15 language adapter engines** (js, python, go, java,
   c, kotlin, ruby, php, csharp, bash, solidity, scala, apex, swift + generic)
   at every `taint()`/`info()` site — a wide, cross-cutting change.
2. **Labeled matchers.** Attach a label to each source matcher and a parsed
   `requires:` expression (a small boolean AST over labels: `and`/`or`/`not`/
   parens) to each sink.
3. **Conditional relabeling propagators.** Model "match node N; if a sub-operand
   already carries label L1, add L2 to the value N produces and propagate L2
   onward." Sources are unconditional origins today; this is a genuinely new
   matcher kind (a source that reads incoming taint).
4. **A join lattice + fixpoint.** Negation (`not CLEAN`) is a *must-not* property
   over all paths. Answering it correctly needs per-reaching-def label sets
   merged at control-flow joins and iterated to fixpoint. The current
   single-forward-pass name→bool map has no join semantics.
5. **`requires:` evaluation at the sink** over the reaching label set, replacing
   the current unconditional "any taint reaches sink → fire".

## Recommendation

**Do not implement now, and do not fake a subset.** The whole point of
taint-labels is the algebra; the tractable single-positive-label subset the
loader could add cheaply is *empty* in the registry. Any shortcut that loads
these rules while ignoring `requires:` / the relabel condition over-matches and
regresses precision — worse than the current honest skip.

If pursued later, treat it as a scoped engine feature (est. multi-day):
label sets on `TaintInfo` + a `requires:` boolean-AST parser/evaluator +
conditional relabeling propagators + a per-branch label-set join. Sequencing by
value/effort:

1. **Java `CONCAT` family (3 rules)** — no negation in the sink; needs only
   label sets + conditional relabel (`requires: INPUT` → emit `CONCAT`) +
   positive `requires:` eval. The smallest self-contained slice; a good first
   milestone that unlocks 3 rules without the negation lattice.
2. **Go `INPUT and not CLEAN` (2 rules) + gRPC + TS + JS** — add negation, which
   pulls in the join lattice / must-not analysis. The larger, riskier half.

Total addressable: **8 registry rules** (3 Go, 3 Java, 1 TS, 1 JS). Load-rate
delta from the tractable-today subset: **0 rules** (nothing can be un-skipped
faithfully without the engine work above).
