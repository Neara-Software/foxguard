# Context-gated / construction source shapes — Python taint parity

Assessment of eight Python `mode: taint` registry rules that the
`semgrep_taint.rs` bridge skipped, grouped by the exact source/sink shape that
blocked them. The hard rule throughout: a rule that loads must **match what
Semgrep matches, not more** — a source that can only be approximated by
over-seeding (firing everywhere) is left skipped rather than shipped broad.

Outcome: **1 of 8 implemented** (`avoid-sqlalchemy-text`), 7 deferred with the
concrete engine primitive each needs. The task framed these as "context-gated
source shapes"; the investigation shows the real blockers are more varied
(string-literal-regex seeding, list-literal seeding, keyword-argument focus,
source-side `pattern-inside` enforcement) — only the two Pyramid rules are
genuinely context-gated sources.

## Summary matrix

| Rule | Source shape | Sink shape | Blocker | Status |
|---|---|---|---|---|
| `avoid-sqlalchemy-text` | string CONSTRUCTION (`$X+$Y`, `$X%$Y`, `f"..."`, `$X.format(...)`) | `sqlalchemy.text(...)` (`Call`) | needed a construction source | **IMPLEMENTED** |
| `request-with-http` | string LITERAL matching regex `http://` (not localhost/127.0.0.1) | `requests.$W($SINK,...)` + `focus $SINK` | string-literal-regex source primitive | deferred |
| `request-session-with-http` | same string-literal-regex | `requests.Session(...).$W($SINK,...)` + focus | string-literal-regex source + chained-call sink | deferred |
| `request-session-http-in-with-context` | same string-literal-regex | `pattern-inside: with requests.Session() as $S` + `$S.$W($SINK,...)` | string-literal-regex source + bound-receiver context sink | deferred |
| `pyramid-direct-use-of-response` | `$REQ.$ANYTHING` **inside** `@view_config def $V($REQ)` (`pattern-not: $REQ.dbsession`) | `$REQ.response.body = $SINK`, `Response($SINK)`, … | source-side `pattern-inside` enforcement | deferred |
| `pyramid-sqlalchemy-sql-injection` | same context-gated `$REQ.$ANYTHING` | `pattern-inside: $Q = $REQ.dbsession.query(...)` + `$Q.$SQLFUNC("...".$FMT(...,$SINK,...))` + neg-lookahead regex | source-side `pattern-inside` + nested-format sink | deferred |
| `tainted-html-response` | param `event` inside `def $H(event, context)` | bare `$BODY` inside `{...,"Content-Type":"text/html",...,"body":$BODY,...}` | structured dict-literal sink containment | deferred |
| `wildcard-cors` | list literal `[..., "*", ...]` | `add_middleware(CORSMiddleware, allow_origins=$ORIGIN,...)` + `focus $ORIGIN` | list-literal source + keyword-argument focus | deferred |

## Implemented — `avoid-sqlalchemy-text`

**Shape.** Five `pattern-sources` alternatives, each a dynamically *constructed*
string, each narrowed by `metavariable-type: string`; sink is
`sqlalchemy.text(...)`. Semgrep's point: the assembled SQL is itself the untrusted
origin (raw-SQL construction), regardless of whether a tracked source flowed in.

**Why it was tractable within the existing vocabulary.**
- Sink `sqlalchemy.text(...)` already compiles to `Call { canonical:
  "sqlalchemy.text" }` and matches through the import-alias table (`from
  sqlalchemy import text`).
- The source reuses the existing `BinopFormat` matcher — **already carried by
  every language engine's `NodeMatcher`**, so no new enum variant and no other
  language's engine is touched. `compile_pattern` now emits `BinopFormat` for a
  Python **source** when the pattern is a string construction
  (`is_python_string_construction_source`), and `python_taint::match_source`
  seeds a construction node (`node_is_python_string_construction`: an interpolated
  f-string, a `+`/`%` binop with a string-literal operand, or a `"...".format()`
  on a string-literal receiver). Assignment propagation (`x = "a"+p; text(x)`)
  and inline args both fire via the existing `expression_taint` walk.

**Faithfulness.** The `metavariable-type: string` narrowing is dropped, but we
replace it with a **stricter** requirement — a concrete string-literal operand /
f-string / literal `.format` receiver — so we never seed pure numeric arithmetic
or non-string values. That means:
- fires: `"a"+p`, `p+"b"`, `f"..{p}.."`, `"..".format(p)`, `".." % p` → `text(...)`
- silent (correct): `text("SELECT 1")` (plain literal), `text(param)` (bare var),
  `text(a+b)` (numeric).

The only divergence is *under*-matching (a string-**typed variable** with no
literal, e.g. `a + b` where both are `str`, which Semgrep's type inference would
catch), which is FP-safe and never over-fires. Tests exercise the full
`parse_taint_rule → compiled() → check()` path (load, fire on each of the five
shapes, fire through the import alias, and the plain-literal/bare-var/numeric
near-miss).

Side benefit: `twilio/twiml-injection` (already loading via its parameter
source) now also picks up its three construction sources (`f"..."`, `"..." %
...`, `"...".format(...)`), improving its recall toward the Semgrep original
without new over-match (Semgrep has those same sources).

## Deferred — and the primitive each needs

### `request-with-http`, `request-session-with-http`, `request-session-http-in-with-context`

All three share one blocking **source**: a string literal whose *content* matches
`pattern-regex: http://` and not `.*://localhost` / `.*://127\.0\.0\.1`
(`metavariable-pattern` in `language: regex`). foxguard has **no
string-literal-as-source primitive** and no `metavariable-pattern` regex on a
literal. Building it requires (a) a new `StringLiteralRegex` source matcher and
(b) taint propagation from a **parameter default** (`def f(url="http://..")`) —
the tests seed via `url = "http://.."`, an assignment (works with today's
propagation), *and* via param defaults (not propagated today). The default-value
path would need engine-core work; without it we'd under-cover 3 of 5 test cases.

Sinks add a second tier of work: `request-session-with-http` needs a chained-call
sink (`requests.Session(...).$W(...)`), and `request-session-http-in-with-context`
needs a sink whose receiver metavariable `$SESSION` is **bound by a
`pattern-inside: with requests.Session() as $SESSION`** and reused in the sink
pattern — a cross-clause metavariable binding the `Call`/`MethodName` vocabulary
cannot express. (Sink-side `pattern-inside` containment *is* enforced today, but
it can't bind and thread a receiver metavariable.)

**Needs:** a string-literal-regex source primitive + literal/param-default
propagation (engine core). Deferred.

### `pyramid-direct-use-of-response`, `pyramid-sqlalchemy-sql-injection`

These are the genuinely **context-gated sources**: `$REQ.$ANYTHING`
(any attribute read off the view request), valid **only inside** a
`pattern-inside: @view_config def $VIEW($REQ): ...`, with `$REQ` bound to the
view's parameter and `pattern-not: $REQ.dbsession`.

**Update (source-side `pattern-inside` enforcement — now IMPLEMENTED).** The
first of the two blocking primitives is done. Findings now carry the originating
source node's byte range (`TaintInfo::source_range` →
`TaintFinding::source_range`, threaded through Python's assignment/with/
destructuring propagation), so the `semgrep_taint.rs` post-filter enforces
source-side `pattern-inside` **and** source-side `pattern-not` as the exact
analog of the sink-side filters. A finding is kept only when its source node is
contained by a source `pattern-inside` region (and not matched by a source
`pattern-not`). Proven faithful by tests
(`source_side_pattern_inside_fires_inside_view_only`,
`source_without_pattern_inside_fires_in_both_functions`): with an attribute-read
source gated by `@view_config def $V(...): ...`, the read inside the view fires
and the identical read in a plain function does not; without the gate both fire.

**Still deferred — the second blocking primitive:** the `$REQ.$ANYTHING` source
shape itself does not compile. `$X.$Y` (a metavariable receiver AND a
metavariable field) has no source matcher — it is dropped, and the rule skips
with "no valid pattern-sources". A faithful compile needs a **bound-parameter
attribute-read source**: `$REQ` bound to the view's parameter (from the
`pattern-inside` signature) so that `$REQ.<any>` seeds ONLY attribute reads off
that parameter. A naive "any attribute read" (wildcard-field `FieldName`) gated
only by the now-working `pattern-inside` would still over-match *inside* the view
(`os.getcwd`, `self.x`, … are attribute reads off non-request receivers), so the
receiver metavariable must be bound — a cross-clause binding the
`Call`/`FieldName` vocabulary cannot express. The enforcement half is shipped;
this binding half remains.

`pyramid-sqlalchemy-sql-injection` additionally needs a nested-format sink
(`$Q.$SQLFUNC("...".$FMT(...,$SINK,...))` with a `metavariable-regex` alternation
on `$SQLFUNC` and a negative-lookahead `(?!bindparams)` on `$FMT`), itself gated
by another `pattern-inside` — so even with both source primitives it stays
sink-blocked.

**Needs:** ~~source-side `pattern-inside` enforcement~~ (DONE) + bound-parameter
attribute-read metavariable source (both rules) + nested-format sink
(`pyramid-sqlalchemy-sql-injection` only). Deferred.

### `tainted-html-response`

Source is nearly tractable — the parameter `event` inside `def $HANDLER(event,
context)`. The `try_compile_param_source_block` recognizer only accepts a
`$`-metavariable seed today; extending it to a concrete parameter *name* and
seeding `ParamName { names: ["event"] }` would be faithful.

The **sink** is the blocker: a bare `$BODY` gated by
`pattern-inside: {..., "headers": {..., "Content-Type": "text/html", ...},
"body": $BODY, ...}`. Compiling `$BODY` to `ObjectLiteralValue` (dict-with-tainted-value)
over-matches — the test's `{"data": event['foo']}` dict (no `text/html` headers)
is explicitly `ok`. Faithfulness needs the sink-side `pattern-inside` to enforce
the *nested dict structure* (Content-Type text/html + a `body` key). That depends
on `semgrep_compat` compiling a Python dict pattern with `...` ellipsis and a
nested `{...}` into a containment `CompiledAstPattern`, and on synthesizing an
`ObjectLiteralValue` positive matcher from a bare-metavar sink — two unverified
pieces. High-risk; deferred pending a spike on nested-dict `pattern-inside`
compilation.

### `wildcard-cors`

Two blockers. Source `[..., "*", ...]` is a **list literal containing a value** —
no list-literal source primitive exists. Sink
`add_middleware(CORSMiddleware, allow_origins=$ORIGIN, ...)` with `focus $ORIGIN`
requires **keyword-argument-position focus**: the test's `ok` cases carry
`allow=["*"]` in the *same* `add_middleware` call, so a sink of "taint reaches
any argument of add_middleware" would fire on `allow=["*"]` → false positive. The
existing focus-call sink recognizer fires on any tainted argument and cannot pin
the match to a named keyword.

**Needs:** a list-literal (contains-value) source primitive + keyword-argument
focus sink. Deferred.

## Bottom line

The one clean, provably-faithful win (`avoid-sqlalchemy-text`) is shipped by
reusing `BinopFormat`. **Source-side `pattern-inside`/`pattern-not` enforcement
is now also shipped** (a general capability: findings carry the source node's
byte range, so the containment/exclusion post-filter runs on sources as it does
on sinks). That removes one of the two blocking primitives for the Pyramid
rules, but they stay skipped because `$REQ.$ANYTHING` still needs a
bound-parameter attribute-read source to compile without over-matching (and
`pyramid-sqlalchemy-sql-injection` also needs the nested-format sink). The
remaining shapes each need a real new engine primitive (string-literal-regex
seeding, bound-parameter attribute-read source, nested-dict sink containment,
list-literal source, keyword-argument focus) or engine-core propagation work —
none is a one-recognizer extension, and each would over-match if forced into
today's vocabulary.
