# Go `mode: taint` skip shapes

> Status: 2026-07-05. Investigation of the four Go `mode: taint` registry rules
> the `semgrep_taint.rs` bridge skipped, grouped by the exact source/sink shape
> that blocked each. The hard rule throughout: a rule that loads must **match
> what Semgrep matches, not more** — a rule that can only be approximated by
> over-seeding / over-matching (firing on the rule's own negative fixtures) is
> left skipped rather than shipped broad.

Neither `context-source-shapes.md` (Python) nor `php-csharp-skip-shapes.md`
(PHP/C#) covers Go, so Go skip shapes are tracked here.

Outcome: **2 of 4 implemented** (`hardcoded-jwt-key`, `gorm-dangerous-method-usage`),
2 deferred with the concrete engine primitive each needs.

## Summary matrix

| Rule | Source shape | Sink shape | Blocker | Status |
|---|---|---|---|---|
| `hardcoded-jwt-key` | `[]byte("$F")` (hardcoded byte-slice literal) | `$TOKEN.SignedString($F)` (`MethodName`) | needed a byte-slice-literal source | **IMPLEMENTED** |
| `gorm-dangerous-method-usage` | `($REQ : *http.Request).$ANYTHING` (typed receiver) | `$GORM. ... .$METHOD($VALUE)` deep-chain, `$METHOD ∈ {Order,Exec,Raw,Group,Having,Distinct,Select,Pluck}` | needed deep-wildcard method-name-regex sink + boolean-comparison taint stop | **IMPLEMENTED** |
| `grpc-server-insecure-connection` | labeled `label: OPTIONS/CREDS/EMPTY_CONSTRUCTOR` (2-key entries) | `grpc.NewServer($OPT,...)` gated by `requires: OPTIONS and not CREDS` | multiple distinct primary labels + structural (non-dataflow) predicates | deferred |
| `handler-assignment-from-multiple-sources` | `$R.query` off `$R *http.Request` | multi-statement `store.Get(...)` → `$VAR := $Y.Values[...]` → `$VAR = $R` | multi-statement sink with cross-statement metavariable unification | deferred |

## Implemented — `hardcoded-jwt-key`

**Shape.** Source `pattern-inside: []byte("$F")` (a hardcoded byte-slice signing
key); sink `$TOKEN.SignedString($F)` with `focus-metavariable: $F`. The sink
already compiled to `MethodName{SignedString}`; only the source was blocked
(a `pattern-inside`-only byte-slice literal compiled to no matcher).

**How it loads faithfully.**
- The bridge recognizes `[]byte("$F")` (`is_go_bytes_string_literal_source` /
  `try_compile_go_bytes_literal_source_block`) and compiles it to
  `LiteralString`.
- The Go engine's `LiteralString` arm is scoped to the `[]byte("<literal>")`
  shape: it seeds a `type_conversion_expression` whose target type is `[]byte`
  **and** whose operand is a string literal — **not** every string literal.
  This is the whole point: `[]byte(os.Getenv("JWT_KEY"))` must stay silent (its
  inner `"JWT_KEY"` is an env-var *name*, the canonical near-miss), which
  seeding every literal would over-match. Taint then propagates through the
  conversion / a `var` binding to the `SignedString` sink.
- Faithfulness gate (all green): compiles to `LiteralString` + `MethodName{
  SignedString}`; fires on both the var-bound and inline `[]byte("secret")`
  positives; silent on `[]byte(os.Getenv(...))` and unrelated literals.

## Implemented — `gorm-dangerous-method-usage`

**Shape.** Source `($REQUEST : *http.Request).$ANYTHING` (typed-receiver, request
accessor methods); sink is a deep field-access chain `$GORM. ... .$METHOD($VALUE)`
with `$METHOD` pinned by `metavariable-regex` to
`Order|Exec|Raw|Group|Having|Distinct|Select|Pluck` and `focus-metavariable:
$VALUE`, wrapped in nested `pattern-inside` (`import gorm`, `func(... $GORM
*gorm.DB ...)`). Sanitizers `strconv.Atoi(...)` and `($X: bool)`.

**How it loads faithfully.**
- The source already compiled to `TypedName{http.Request}` (Go typed-receiver
  support); the Go engine seeds `*http.Request` parameters.
- The sink's deep-wildcard callee `$GORM. ... .$METHOD(...)` was unhandled
  (`compile_focus_call_callee` only knew `$RECV.$METH`). It now extracts the
  final metavariable method of a `. ... .` chain and enumerates the anchored
  `metavariable-regex` alternation into one `MethodName` per name
  (`Order`, `Exec`, …) — a method-name-bounded sink that fires only for those
  names with a tainted argument. The intervening chain is any receiver.
- The `($X: bool)` sanitizer is inexpressible as a matcher, but its *intent* —
  taint does not survive a boolean comparison — is now enforced generally: the
  Go engine's `binary_expression` propagation stops at comparison / logical
  operators (`==`, `!=`, `<`, …, `&&`, `||`), which yield a `bool` predicate,
  not the operand's data. This is what keeps `table.Order((param != "param") +
  " " + "ASC")` (the rule's own `testNoInjection3` negative) silent.
- Faithfulness gate (all green): source `TypedName{http.Request}`, sinks the 8
  enumerated `MethodName`s (and never `Find`/`Table`); fires on `.Order(param)`
  and `.Order(param + " " + "ASC")`; silent on the constant, local-var, and
  bool-comparison negatives.

Documented broadening (bounded, no fixture regression): the sink's `pattern-
inside` (`import gorm`, `func(... *gorm.DB ...)`) is dropped, so the enumerated
`MethodName{Order|Exec|…}` sinks are not gorm-scoped — but they fire only on a
**request-tainted** argument to one of those specific SQL method names, which has
no benign case in practice.

## Deferred — `grpc-server-insecure-connection`

**Shape.**
```yaml
pattern-sinks:
  - requires: OPTIONS and not CREDS
    pattern: grpc.NewServer($OPT, ...)
  - requires: EMPTY_CONSTRUCTOR
    pattern: grpc.NewServer()
pattern-sources:
  - label: OPTIONS          # 2-key entry: label + pattern
    pattern: grpc.ServerOption{ ... }
  - label: CREDS
    pattern: grpc.Creds(...)
  - label: EMPTY_CONSTRUCTOR
    pattern: grpc.NewServer()
```

**Blockers.**
1. **(decisive) Multiple distinct primary source labels.** foxguard's
   `LabelPolicy` (see `taint-labels-design.md`) models a *single* primary
   `source_label` plus conditional relabels; `detect_label_policy` refuses a rule
   that needs several distinct primary labels. This rule needs `OPTIONS`,
   `CREDS`, and `EMPTY_CONSTRUCTOR` as independent primary labels so the
   `requires: OPTIONS and not CREDS` boolean can distinguish which label a value
   carries. The bridge already rejects the labeled source entries earlier still:
   each is a **2-key** `label:`+`pattern:` map, which `compile_entry` reports as
   "entry has 2 keys" and skips (labels are only consumed when a `LabelPolicy` is
   active, which it never becomes here).
2. **(structural, not data-flow)** These "sources" are not taint origins that
   propagate to a sink — they are structural predicates over the *same*
   `grpc.NewServer(...)` construction (does it have a `ServerOption` arg? a
   `Creds` arg? is it the empty constructor?). The rule is really "a
   `grpc.NewServer` with options but no credentials", which foxguard's
   source→sink dataflow model does not express.

Dropping `requires` and firing on every `grpc.NewServer(...)` would flag a
correctly-secured `grpc.NewServer(grpc.Creds(tls))` — over-match on the rule's
own secure form. No faithful middle without multi-primary-label support.

## Deferred — `handler-assignment-from-multiple-sources`

**Shape.** Source `$R.query` off a `func $H(..., $R *http.Request, ...)`
parameter (`focus $R`). Sink (CWE-289, "variable assigned from two different
sources"):
```yaml
- pattern: |
    $Y, err := store.Get(...)
    ...
    $VAR := $Y.Values[...]
    ...
    $VAR = $R
  focus-metavariable: $R
```
(plus a typed-assertion `var $VAR $INT = $Y.Values["..."].($INT)` variant.) The
finding is that the same `$VAR` is assigned first from the session store `$Y`
and then re-assigned from the request `$R`.

**Blockers.**
1. **(decisive) Multi-statement sink with cross-statement metavariable
   unification.** foxguard's sink matchers are single-node shapes (call / method
   / member-assign / return / …). This sink is a three-statement *sequence*
   whose meaning lives entirely in the unification: `$Y` bound by `store.Get`
   in statement 1 must be the receiver of `$Y.Values[...]` in statement 2, whose
   result binds `$VAR`, which must be the same variable re-assigned from `$R` in
   statement 3. The engine cannot express "these N statements, sharing these
   metavariables, in this order". The bridge already reports the
   `$Y, err := store.Get(...)` block as an "unsupported pattern shape".
2. **(over-match if reduced)** Collapsing the sink to just its final line
   (`$VAR = $R`, i.e. "a request value is assigned to a variable") would fire on
   every ordinary `x = r.query...` in every handler — the normal, correct
   pattern. The whole signal (CWE-289) is the *double* assignment from two
   distinct origins, which is exactly the sequence + unification foxguard lacks.
