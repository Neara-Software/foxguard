# Taint-labels (`label:` / `requires:`) feasibility assessment

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
