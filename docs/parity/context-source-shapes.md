# Context-gated / construction source shapes — Python taint parity

Assessment of eight Python `mode: taint` registry rules that the
`semgrep_taint.rs` bridge skipped, grouped by the exact source/sink shape that
blocked them. The hard rule throughout: a rule that loads must **match what
Semgrep matches, not more** — a source that can only be approximated by
over-seeding (firing everywhere) is left skipped rather than shipped broad.

Outcome (original assessment): **1 of 8 implemented** (`avoid-sqlalchemy-text`),
7 deferred with the concrete engine primitive each needs. (As of 2026-07-05,
**4 of 8 load** — the three `requests` cleartext rules have since shipped; see
the update note below.) The task framed these as "context-gated
source shapes"; the investigation shows the real blockers are more varied
(string-literal-regex seeding, list-literal seeding, keyword-argument focus,
source-side `pattern-inside` enforcement) — only the two Pyramid rules are
genuinely context-gated sources.

> **Update (2026-07-05):** re-verified against the current snapshot with
> `registry_coverage --list-skips python`. The three `requests` cleartext rules
> below — `request-with-http`, `request-session-with-http`, and
> `request-session-http-in-with-context` — **now load** and are no longer
> skipped: the string-literal-regex source primitive they needed shipped
> (`try_compile_string_literal_regex_source_block` in `semgrep_taint.rs`). Their
> matrix rows are updated; the per-rule write-ups are kept as the record of the
> original blocker. Still deferred: `pyramid-direct-use-of-response`,
> `pyramid-sqlalchemy-sql-injection`, `tainted-html-response`, `wildcard-cors`.

> **Re-sweep (2026-07-09):** the 6 deferred Python taint rules
> (`pyramid-direct-use-of-response`, `pyramid-sqlalchemy-sql-injection`,
> `tainted-html-response`, `subprocess-list-passed-as-string`, `wildcard-cors`,
> `hardcoded-token`) were re-examined against the grown primitive set
> (`MethodArgSink`, `ConstructorArgSink`, `CallArgSource`, `LiteralArgCall`,
> `TypedName`, `FirstParamSource`, `PropertyAssignSink`, `ReceiverProvenanceCall`).
> **None flip** — each blocker is a shape the new primitives do not cover:
> - `subprocess-list-passed-as-string` — source `" ".join($LIST)` is a call whose
>   **receiver** is the literal `" "`. `CallArgSource{method,arg_index}` keys the
>   *argument*, `LiteralArgCall{method,arg}` keys the *first argument literal*
>   (JS-only) — neither expresses a literal-**receiver** method-call source.
> - `wildcard-cors` — source `[..., "*", ...]` is a list-literal-contains-value
>   (no such source); sink `add_middleware(CORSMiddleware, allow_origins=$ORIGIN,
>   ...)` + focus is **keyword-position**, whereas `MethodArgSink` is positional
>   and Java-only. The `ok` cases carry `allow=["*"]` in the *same* call, so an
>   any-arg / positional sink over-matches.
> - `hardcoded-token` — `FirstParamSource`/`LiteralString` cover the bare-string
>   source, but the whole discriminator is the dropped sink constraints
>   (`metavariable-regex` keyword name + `metavariable-pattern` value regex +
>   `metavariable-analysis` Shannon entropy); no primitive enforces those inside
>   a taint sink, so it would fire on every `ok` line.
> - `tainted-html-response` — `FirstParamSource` could seed `event`, but it is
>   wired only through the C#-signature recognizer (Java/C# engines); more
>   decisively the sink is a nested-dict `pattern-inside`
>   (`"Content-Type":"text/html"` sibling + `"body":$BODY`) that no primitive
>   compiles — unchanged blocker.
> - `pyramid-*` — still need the bound-parameter attribute-read source
>   (`$REQ.$ANYTHING` with `$REQ` bound to the view param); source-side
>   `pattern-inside` enforcement shipped, but the receiver-metavariable binding
>   does not, and `pyramid-sqlalchemy-sql-injection` also needs the nested-format
>   sink. Unchanged. All 6 stay deferred.

## Summary matrix

| Rule | Source shape | Sink shape | Blocker | Status |
|---|---|---|---|---|
| `avoid-sqlalchemy-text` | string CONSTRUCTION (`$X+$Y`, `$X%$Y`, `f"..."`, `$X.format(...)`) | `sqlalchemy.text(...)` (`Call`) | needed a construction source | **IMPLEMENTED** |
| `request-with-http` | string LITERAL matching regex `http://` (not localhost/127.0.0.1) | `requests.$W($SINK,...)` + `focus $SINK` | string-literal-regex source primitive | **loaded (2026-07-05)** |
| `request-session-with-http` | same string-literal-regex | `requests.Session(...).$W($SINK,...)` + focus | string-literal-regex source + chained-call sink | **loaded (2026-07-05)** |
| `request-session-http-in-with-context` | same string-literal-regex | `pattern-inside: with requests.Session() as $S` + `$S.$W($SINK,...)` | string-literal-regex source + bound-receiver context sink | **loaded (2026-07-05)** |
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

### `tainted-html-string` (Java)

A taint-**labels** XSS rule (`INPUT` → `CONCAT`, sink `requires: CONCAT`). Two
blockers, either alone fatal:

1. **The `CONCAT` relabel must be gated on an HTML-literal regex.** The `CONCAT`
   source is a string-building expression (`"$HTMLSTR" + ...`, `.concat`,
   `StringBuilder.append`, `+=`, `String.format`) whose literal operand matches
   `metavariable-regex: $HTMLSTR ^<\w+` — i.e. the built string must START with
   an HTML tag. The Java engine's string-building relabel
   (`is_string_building_node`) applies `INPUT → CONCAT` to *any* concatenation,
   NOT only HTML-tag-prefixed ones. The fixture's discriminator
   `getVulnerablePayloadLevelSecure3ok` builds `"not html" += imageLocation` and
   returns it — explicitly `ok`. With the ungated relabel that value acquires
   `CONCAT` and the sink fires → **false positive**. Faithfulness needs a
   regex-gated relabel primitive (only relabel when the string-building node's
   literal operand matches `^<\w+`), which `LabelPolicy`/`Relabel` cannot express
   today.

2. **The sinks are `ResponseEntity` shapes no recognizer handles.**
   `new ResponseEntity<>($PAYLOAD, ...)`, `new ResponseEntity<$ERROR>($PAYLOAD,
   ...)`, `ResponseEntity. ... .body($PAYLOAD)`, and `ResponseEntity.ok($PAYLOAD).
   ...` with `focus: $PAYLOAD`. These are a constructor-argument-focus sink and a
   chained-builder `.body(...)` sink; the focus-call sink recognizer does not
   cover a `new C<>($X, ...)` object-creation focus or a `Response. ... .body($X)`
   ellipsis-chain, so every sink arm skips (`has no valid pattern-sinks`).

**Needs:** a regex-gated string-building relabel (label side) + a
constructor-argument / builder-chain focus sink primitive (sink side). Deferred.

> **Re-sweep (2026-07-09).** The sink half is now *partially* expressible: the
> `ConstructorArgSink{class_names, arg_index}` primitive (shipped for `csharp-sqli`,
> also compiled Java-side) could cover the `new ResponseEntity<>($PAYLOAD, ...)` /
> `new ResponseEntity<$ERROR>($PAYLOAD, ...)` arms as a class-name / arg-0 focus
> sink. But blocker #1 remains **fatal and unchanged**: `requires: CONCAT` gates
> the whole sink on the `INPUT → CONCAT` relabel, and that relabel must fire only
> when the string-building literal matches `metavariable-regex $HTMLSTR ^<\w+`.
> The fixture's discriminator is decisive — `getVulnerablePayloadLevelSecure3ok`
> (`String … = "not html"; … += imageLocation; return new ResponseEntity<>(…)`,
> marked **ok**) is byte-for-byte identical to the firing
> `getVulnerablePayloadLevelSecure2` (`… = "<img …>"`) except for whether the
> literal starts with an HTML tag. foxguard's `is_string_building_node` relabel
> applies `INPUT → CONCAT` to **any** concatenation, so the `ok` case acquires
> `CONCAT` and fires → false positive (gate #3 fails). A regex-gated relabel is
> not expressible by `LabelPolicy`/`Relabel`. The `ResponseEntity.ok(...)` /
> `ResponseEntity. ... .body(...)` builder-chain arms also still need an
> ellipsis-chain focus sink `ConstructorArgSink` does not provide. Deferred.

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

## MCP decorated-parameter sources (2026-07 pass) — IMPLEMENTED

Two additional Python `mode: taint` skips — `mcp-ssrf-python` and
`mcp-command-injection-python` — share one source shape: a parameter of a
function **decorated by `@$SERVER.tool()`**:

```yaml
pattern-sources:
  - patterns:
      - pattern: |
          @$SERVER.tool()
          def $FUNC(..., $PARAM, ...):
              ...
      - focus-metavariable: $PARAM
```

The decorator is the whole discriminator: an MCP tool handler's parameters are
untrusted, a plain helper's are not. The any-parameter wildcard
(`ParamName[ANY_PARAM_WILDCARD]`) would DROP the decorator gate and seed every
function's parameters (over-match); the source-side `pattern-inside` post-filter
cannot rescue it either, because seeded parameters carry no `source_range` and
the filter drops range-less findings.

**Primitive added: `NodeMatcher::DecoratedParamSource { decorator }`.** The
Python engine's `seed_param_sources` now seeds a parameter only when its
enclosing `function_definition` is wrapped in a `decorated_definition` carrying a
`@<recv>.<decorator>(...)` **call** decorator whose final method segment equals
`decorator` (e.g. `tool`). `decorator_method_names` reads the decorators off the
def's parent; `try_compile_decorated_param_source_block` recognises the shape and
extracts the concrete method name (`decorator_method_from_signature`), scanning
the `def`'s parameter list past the decorator's own `()`
(`decorated_def_has_param`). The variant is source-only: carried by every
engine's shared `NodeMatcher` but no-op outside Python.

**Faithfulness (proven by tests in `semgrep_taint.rs`):**
- `mcp_ssrf_fires_on_decorated_handler_param` — `@mcp.tool()` param → `requests.get`
  fires.
- `mcp_ssrf_silent_on_undecorated_function` — the identical body without `@…tool()`
  is silent (the discriminator).
- `mcp_ssrf_silent_on_wrong_decorator` — `@app.route(...)` (not `.tool()`) is silent.
- `mcp_ssrf_silent_on_sanitized_and_hardcoded` — `urllib.parse.urlparse` sanitizer
  and a no-param hardcoded fetch are silent.
- `mcp_cmdinj_fires_on_os_system_and_eval` / `mcp_cmdinj_silent_on_sanitized_and_undecorated`
  — `os.system`/`eval` fire; `shlex.quote` sanitizer and undecorated helper silent.

**`mcp-command-injection-python` sink note (broader-but-precedented).** Its
`os.system($SINK)`, `eval($SINK)`, `exec($SINK)` sinks are exact. Its
`subprocess.run($SINK, ..., shell=True, ...)` (and `.call`/`.Popen`) arms compile
to a broad `Call { subprocess.run }` that **drops the `shell=True` keyword
constraint** — a tainted `subprocess.run(param, shell=False)` would also fire.
This is NOT a new imprecision: the already-shipped, loaded sibling rule
`llm-output-to-exec-python` uses the identical `subprocess.run($SINK, ...,
shell=True)` focus-call sink with the same broadening. No `ok`-marked fixture
line is a tainted subprocess call, so the broadening never contradicts the rule's
own test fixture. A per-arm `shell=True` keyword-value enforcement would make it
exact, but that is a global focus-call-sink change that would also narrow the
shipped `llm-output-to-exec-python` — out of scope here.

## Still deferred (this pass)

### `subprocess-list-passed-as-string`

Source `" ".join($LIST)` is a **method call on a specific string-literal
receiver** (`" "`, a single space) with method `join`. No matcher expresses
"call whose receiver is the string literal `" "` and whose method is `join`", and
the receiver literal is the discriminator: the fixture's `ok` line passes the
list directly (`subprocess.run([...], shell=True)`), and a `",".join(...)` (comma,
not space) is likewise not the target. A generic "any `.join()` call" source would
over-match. **Needs:** a literal-receiver method-call source primitive
(`"<lit>".<method>(...)`). Deferred.

### `hardcoded-token`

Source is a bare string literal (`"..."` → foxguard's `LiteralString`), which
alone is expressible. The whole discriminator lives in the **sink's dropped
constraints**: the boto3 keyword name must match
`(aws_session_token|aws_access_key_id|aws_secret_access_key)`
(`metavariable-regex` on `$TOKEN`), and the value must look like a real key —
`^AKI…` / `^[A-Za-z0-9/+=]+$` (`metavariable-pattern`) **and** pass an
`entropy` analyzer (`metavariable-analysis`). The fixture's `ok` cases turn
entirely on these: `aws_access_key_id="this-is-not-a-key"` (hyphens fail the
value regex), `"XXXXXXXX"` / `"<your token here>"` (low entropy). foxguard drops
`metavariable-regex`/`metavariable-pattern`/`metavariable-analysis` inside a taint
sink, so a compiled sink would be "any keyword argument that is a string literal"
— firing on every `ok` line → false positives. **Needs:** keyword-name-regex +
value-regex + Shannon-entropy analysis enforceable inside a taint sink. Deferred.

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

---

# Ruby `mode: taint` registry skips

Assessment of the seven Ruby `mode: taint` registry rules the bridge skipped.
Same hard rule: a loaded rule must match what Semgrep matches, **not more**.

Outcome: **2 of 7 implemented** (`avoid-tainted-http-request`,
`md5-used-as-password`), 5 deferred with the concrete blocker each carries. Ruby
load rate moves **85 → 87 / 92 (92.4% → 94.6%)**; overall **2100 → 2102 / 2144**.

> **Re-sweep (2026-07-09):** the 5 deferred Ruby taint rules
> (`avoid-tainted-ftp-call`, `check-redirect-to`,
> `check-render-local-file-include`, `divide-by-zero`,
> `rails-no-render-after-save`) were re-examined against the *grown* primitive
> set — `MethodArgSink{methods,arg_index}`, `ConstructorArgSink`,
> `ReceiverProvenanceCall`, `CallArgSource`, `CallArgConcat`, `TypedName`,
> `FirstParamSource`, `PropertyAssignSink`. **None flip.** The two that looked
> newly-plausible fail on a shape mismatch, not merely a missing feature:
> - `avoid-tainted-ftp-call` — the `ReceiverProvenanceCall` primitive is a
>   **source** with a *fixed* `init_arg` literal and a *fixed* `method`
>   (`MessageDigest.getInstance("MD5"); … $MD.digest(...)`), compiled solely for
>   the Java engine. The FTP rule needs the **sink** dual with a *wildcard*
>   method (`$FTP.$METHOD(...)`) and a receiver bound by
>   `$FTP = Net::FTP.$OPEN(...)` — a receiver-TYPE-provenance sink that neither
>   the primitive's shape nor the Ruby engine expresses. (Its first arm,
>   `Net::FTP.$X(...)`, is a metavariable-method call that still does not compile
>   to a concrete `Call`, and alone would catch only 2 of 15 fixture positives —
>   a severe under-match even if forced.)
> - `check-render-local-file-include` — `MethodArgSink{methods,arg_index}` is a
>   **positional** arg-index sink (Java-only). The `render` sink keys on a
>   **keyword** value (`file:`/`inline:`/`template:`/`action:`) *or* the first
>   positional, and the `ok` discriminator
>   `render :update, locals: { username: params[:username] }` puts taint in a
>   *non-target* keyword — so a positional-index or any-arg sink over-matches it.
>   A faithful compile needs a keyword-argument-value sink (not positional),
>   plus the `metavariable-pattern`-gated `$MAP[...]` subscript sanitizer.
>
> `check-redirect-to` (metavariable-regex-gated sanitizer + `(?<!permit)`
> lookbehind the Rust regex crate rejects), `divide-by-zero` (numeric-literal
> source + `^\d*(?!\.)$` lookahead + divide-by-zero arithmetic predicate, a
> non-dataflow shape), and `rails-no-render-after-save` (cross-pattern
> metavariable UNIFICATION + ordering) are unchanged by the new primitives.
> All 5 stay deferred.

## Summary matrix

| Rule | Source shape | Sink shape | Blocker | Status |
|---|---|---|---|---|
| `avoid-tainted-http-request` | `params` / `cookies` / `request.env` | `Net::HTTP.$X(...)` / `Net::HTTP::$METHOD.new(...)` + `metavariable-pattern` method enums | enumerate the `metavariable-pattern` alternation into concrete `Call`s | **IMPLEMENTED** |
| `md5-used-as-password` | `Digest::MD5` (constant scope path) | `$FUNCTION(...)` + `metavariable-regex (?i).*password.*` | recognize a Ruby `Const::Const` source | **IMPLEMENTED** |
| `avoid-tainted-ftp-call` | `params` / `cookies` / `request.env` | `Net::FTP.$X(...)` **and** `$FTP.$METHOD(...)` gated by `pattern-inside: $FTP = Net::FTP.$OPEN(...)` | receiver-TYPE provenance on a SINK | deferred |
| `check-redirect-to` | `params` / `cookies` / `request.env` | `redirect_to $X` focus, minus a `metavariable-regex`-gated `permit` sanitizer | metavariable-regex-gated sanitizer | deferred |
| `check-render-local-file-include` | `params[...]` | `render` with focus on the `file:`/`inline:`/`template:`/`action:` kwarg or first positional | keyword-argument-position sink | deferred |
| `divide-by-zero` | integer-literal metavariable (`$VAR` + `metavariable-regex ^\d*(?!\.)$`) | `$NUMER` inside `pattern-inside: $NUMER / 0` | numeric-literal source + arithmetic-predicate sink | deferred |
| `rails-no-render-after-save` | `$T` inside `pattern-inside: $T.save` | `$T` inside `pattern-inside: render $T` | cross-pattern metavariable UNIFICATION + ordering | deferred |

## Implemented — `avoid-tainted-http-request`

**Shape.** Sources are the bare request accessors (already compile to
`ParamName`/`Attribute`). The sink is a `pattern-either` of two `patterns:`
AND-blocks, each a call whose callee carries ONE metavariable
(`Net::HTTP.$X(...)`, `Net::HTTP::$METHOD.new(...)`) paired with a
`metavariable-pattern` that ENUMERATES that metavariable into a fixed list of
method / constant names via a nested `pattern-either:` of `pattern:` leaves.

**Why tractable within the existing vocabulary.** The method/constant lists are
finite and concrete, so we **enumerate** them: for each listed name we substitute
it textually into the callee template and emit a concrete
`Call { canonical }` (`Net::HTTP.get`, `Net::HTTP::Get.new`, …). Every canonical
resolves through the Ruby engine's existing `resolve_callee` (a `scope_resolution`
receiver stringifies to `Net::HTTP` / `Net::HTTP::Get`), so **no new
`NodeMatcher` variant** and no engine change are needed — only a new bridge
recognizer (`try_compile_ruby_metavar_pattern_enum_call_block`), gated Ruby +
sink. The receiver AND method are both pinned, so the compiled sink is strictly
≤ what Semgrep's bounded `metavariable-pattern` matches.

**Faithfulness.** Fires on all 9 tainted `Net::HTTP` calls in the fixture (via
the existing tainted-argument check); silent on the two literal-URL negatives
(`Net::HTTP.get("example.com", …)`, `Net::HTTP::Get.new(uri)` with a literal
`uri`). A bare `http.request(...)` on a block variable does NOT match (receiver
is not `Net::HTTP`). Tests:
`ruby_tainted_http_request_enumerates_concrete_call_sinks`,
`ruby_tainted_http_request_fires_on_positives_only`.

## Implemented — `md5-used-as-password`

**Shape.** Source `Digest::MD5` (a bare `Const::Const` scope-resolution
reference); sink `$FUNCTION(...)` gated by `metavariable-regex (?i).*password.*`
(already compiles to a `CallRegex`). Only the SOURCE was blocking:
`is_dotted_identifier` rejects the `::`.

**Why tractable.** `compile_pattern` now recognizes a pure Ruby constant scope
path (`is_ruby_constant_path`) as a Ruby SOURCE and compiles it to
`Call { canonical: "Digest::MD5" }`; the Ruby engine's `match_source` matches a
`scope_resolution` node by EXACT text. Taint then propagates through the
constant's method reads (`Digest::MD5.hexdigest`, `md5 = Digest::MD5.new; dig =
md5.hexdigest`) via the existing receiver-propagation path, reaching the
password-named sink.

**Faithfulness.** The exact-text discriminator keeps other digests silent:
`Digest::SHA256.hexdigest`-derived values never taint, so the two SHA256
negatives stay clean while both MD5 positives fire. Tests:
`ruby_md5_used_as_password_compiles_to_intended_shapes`,
`ruby_md5_used_as_password_fires_on_md5_only`.

## Deferred — and the primitive each needs

### `avoid-tainted-ftp-call`

The `Net::FTP.$X(...)` arm alone would load (any method on the `Net::FTP`
constant), but that catches only 2 of the 15 fixture positives. The other 13
(`ftp.get(...)`, `ftp.put(...)`, `ftp.connect(...)`, …) come from the second
sink `$FTP.$METHOD(...)` — a **metavariable receiver AND metavariable method**
call, i.e. EVERY method call — gated ONLY by
`pattern-inside: $FTP = Net::FTP.$OPEN(...)` (the receiver `$FTP` is an FTP
instance). foxguard's Ruby engine has no receiver-TYPE provenance for sinks:
without it, the sink degrades to "any method call with a tainted argument"
(`puts(params[:x])` → false positive) — a catastrophic over-match. **Needs:**
sink-side receiver provenance (`$FTP` bound to a `Net::FTP.open/new` result),
the sink analogue of the Java `ReceiverProvenanceCall` source. Deferred.

### `check-redirect-to`

The sink (`redirect_to $X` focus) is expressible, but faithfulness turns on a
`pattern-sanitizers` entry that the engine cannot express: `params.permit(...,
$X, ...)` is a sanitizer **only when** a `metavariable-regex` on `$X` does NOT
match `(host|port|(sub)?domain)`. The fixture's `ok` case
`redirect_to params.permit(:page, :sort)` is sanitized (no host/port/domain)
while the `ruleid` case `redirect_to params.permit(:domain)` is not — dropping
the metavariable-regex-gated sanitizer fires on the `ok` case → over-match.
(The sink's own `pattern-not-regex` also uses a negative lookbehind
`(?<!permit)` the Rust regex crate rejects.) **Needs:** a metavariable-regex-gated
sanitizer. Deferred.

### `check-render-local-file-include`

Source `params[...]` compiles (`Subscript`). The sink is a `render` call where
the tainted value must sit in a SPECIFIC argument position — the `file:` /
`inline:` / `template:` / `action:` keyword, or the first positional — with
`focus-metavariable: $X`. The fixture's `ok` case
`render :update, locals: { username: params[:username] }` puts tainted input in
`locals:`, so a "tainted value in any `render` argument" sink over-matches it.
`parse_command_call` deliberately refuses keyworded calls for exactly this
reason. **Needs:** a keyword-argument-position sink matcher (fire on the value of
named kwargs `file`/`inline`/`template`/`action` or the first positional only).
Deferred.

### `divide-by-zero`

Not a dataflow shape. The "source" is an integer LITERAL
(`$VAR` + `metavariable-regex ^\d*(?!\.)$` — itself a lookahead the Rust regex
crate rejects) and the "sink" is a bare `$NUMER` gated by
`pattern-inside: $NUMER / 0` — a syntactic "denominator is zero" arithmetic
predicate misusing taint mode. foxguard has neither numeric-literal source
seeding nor a binary-operator divide-by-zero sink node shape. Deferred.

### `rails-no-render-after-save`

A statement-ordering correctness rule. The source binds `$T` to the RECEIVER of
a `$T.save` call; the sink binds the SAME `$T` inside `render $T`. Firing
faithfully requires cross-pattern **metavariable unification** (the render target
must be the exact object that was saved) plus **ordering** (render after save).
foxguard's flow-insensitive taint engine has neither receiver-of-method-call
source seeding nor metavariable unification across source/sink patterns:
approximating it (taint any `.save` receiver, fire on any render whose argument
references it) over-matches `render $T.attr` and render-before-save. Deferred.


# JavaScript `mode: taint` skip shapes — parity investigation

Assessment of the 13 JavaScript `mode: taint` registry rules the
`semgrep_taint.rs` bridge skipped. Same hard rule as above: a rule that loads
must **match what Semgrep matches, not more** — over-matching is worse than
skipping. A definitive per-rule verdict was required.

Outcome: **2 of 13 implemented** (`md5-used-as-password`,
`react-unsanitized-property`), 11 deferred with the concrete primitive each
needs. JavaScript coverage 230 → 232 loaded (13 → 11 taint skips).

## Summary matrix

| Rule | Source shape | Sink shape | Blocker | Status |
|---|---|---|---|---|
| `md5-used-as-password` | `$CRYPTO.createHash("md5")` (inline literal-arg call) | `$FN(...)` + `metavariable-regex $FN =~ .*password.*` (`CallRegex`) | inline literal-arg call source | **IMPLEMENTED** (`LiteralArgCall`) |
| `react-unsanitized-property` | any function parameter (`ParamName` wildcard) → `$X.$Y` | `$BODY.$HTML = $SINK` + `metavariable-regex $HTML =~ (innerHTML\|outerHTML)` + focus `$SINK` | metavariable-property DOM-assign sink w/ regex enumeration | **IMPLEMENTED** (enumerated `MemberAssign`) |
| `hardcoded-jwt-secret` | `$X = '...'` (assignment-of-literal) | `pattern-inside: $JWT.sign($DATA,$VALUE,...)` + focus `$VALUE` | assignment-literal source **and** a sink expressed only via `pattern-inside`+focus (needs positional `MethodArgSink` matched by the JS engine, which it does not) | deferred |
| `hardcoded-passport-secret` | string literal in a specific object property (`{clientSecret:"..."}` / `secretOrKey` / `consumerSecret`) | `new $F($VALUE,...)` where `$F` derives from a `require("passport-*")` (metavariable-regex on the import module) + focus `$VALUE` | object-property-keyed literal source + import-provenance constructor-class sink — neither expressible; a broad `LiteralString`+`new $F(...)` would fire on every hardcoded string reaching any constructor | deferred |
| `unsafe-formatstring` | syntactic computed-string (`$X + $Y`, `$X.concat($Y)`, `` `...${...}...` ``), *not* two literals | `console.$LOG($STR,$PARAM,...)` / `util.format($STR,$PARAM,...)` + focus `$STR` | source is a "computed-string-is-source" syntactic form (no data provenance); sink requires arg0 focus **with a mandatory 2nd argument** — no arg-count-constrained sink exists, a bare arg0 sink fires on the single-arg `console.log("..."+user)` ok-case | deferred |
| `react-href-var` | multi-label `TAINTED`/`CONCAT`/`CLEAN` with `by-side-effect` CLEAN | JSX `<$EL href={$X}/>` / `React.createElement($EL,{href:$X})` (+ object-property indirection `$PARAMS={href:$X}`), `requires: TAINTED and not CONCAT and not CLEAN` | the sink boolean `requires:` now parses, but four independent gaps remain (see taint-labels-design.md 2026-07-09): (1) the JS/TS engine is not label-aware (`LabelPolicy` consumed only by Go/Java; JS passes `label_policy: None` and runs unlabeled `analyze_tree`); (2) `CLEAN` is a no-`requires` `by-side-effect` source → counts as a 2nd primary → `detect_label_policy` refuses; (3) the `CONCAT` relabel needs template-literal `pattern-not` carve-outs the `{from,to}` `Relabel` cannot express; (4) no JSX-attribute / `React.createElement` object-arg / object-property-flow sink shapes exist | deferred |
| `raw-html-format` | `EXPRESS`/`EXPRESSTS` express-req input + no-`requires` `by-side-effect` `CLEAN` | string-building expr containing an HTML tag (`"<tag…" + $EXPR`, `"$HTMLSTR".concat(…)`, `util.format(…)`, `` `…<tag…` ``), `requires: (EXPRESS and not CLEAN) or (EXPRESSTS and not CLEAN)` | over-match unavoidable: the HTML-tag discriminator is a taint-sink `metavariable-pattern`(generic `<$TAG ...`)/`pattern-regex` that foxguard cannot enforce → dropping it fires on the rule's own non-HTML `ok` concats; also JS engine not label-aware, 3 primaries, and `util.format`/`.concat`/template-literal sink shapes unsupported | deferred |
| `remote-property-injection` | `$REQ.query`/`body`/… (`FieldName`) | `$OBJ[$INDEX] = ...` w/ tainted **key** (`$INDEX`), minus concat forms | tainted-subscript-KEY assignment sink for a metavariable base is not compiled for JS; and the fire/ok discriminator is a sanitizer `var $X = ...` / `pattern-not: var $X = $REQ.$ANY` ("assignment from a non-direct-request cleans"), inexpressible | deferred |
| `express-libxml-noent` | `$REQ.query`/`body`/… (`FieldName`) | `$XML.$FUNC($QUERY,{...,noent:true,...})` + import-regex + func-regex + focus `$QUERY` | the fire/ok discriminator is the call-argument option-object field value `{noent:true}` vs `{noent:false}` — foxguard cannot constrain a call-argument object-literal field value | deferred |
| `express-wkhtmltopdf-injection` | `$REQ.query`/`body`/… (`FieldName`) | `$WK($SINK,...)` where `$WK` is bound only by `pattern-inside: $WK = require('wkhtmltopdf')` | sink callee is a metavariable bound by require-provenance; foxguard has no require-provenance callee binding, and a bare `$WK(...)` metavariable-callee sink is universal (fires on every call) | deferred |
| `detect-angular-trust-as-method` | `$scope.$X` (member read off the `$scope` parameter bound via `pattern-inside: app.controller(...,function($scope,$sce){...})`) | `$sce.trustAs(...)` / `$sce.trustAsHtml(...)` (`MethodName`) | source is a specific-receiver / any-field read off a `pattern-inside`-bound parameter; no such source exists, and keying by the literal name `scope` is unfaithful (it is a metavariable) | deferred |
| `tainted-html-response` | first param `event` of the Lambda handler (`ParamName` wildcard) | object-literal `body:` property whose SIBLING must be `headers:{'Content-Type':'text/html'}` | only object-literal sink is `ObjectLiteralValue` (fires on ANY tainted value position — would fire on the `data: event.foo` ok-case) and cannot key on the `body` field nor enforce the sibling-header discriminator | deferred |
| `unsafe-argon2-config` | object literal `{type: ...}` inside a `require('argon2')` context | 2nd arg of `$ARGON.hash(...,$Y)` | source is an object-literal config provenance and the safe/unsafe discriminator is a `pattern-sanitizer` on the object field value (`{type: $ARGON.argon2id}`); foxguard expresses neither object-literal-as-source nor object-field-value sanitizers | deferred |

## Implemented

### `md5-used-as-password` — inline literal-argument call source

**Shape.** Source `$CRYPTO.createHash("md5")`; sink `$FN(...)` pinned by
`metavariable-regex $FN =~ (?i)(.*password.*)`.

**Primitive added.** `NodeMatcher::LiteralArgCall { method, arg }` — a method
call whose final method name equals `method` (`createHash`) and whose first
argument is a string literal equal to `arg` (`md5`) seeds the call result
tainted; the JS engine's existing method-chain propagation carries the taint
through `.update(...).digest(...)` to the sink (a `CallRegex` that already
compiled). Faithful: the literal-arg discriminator keeps `createHash("sha256")`
clean; a md5 digest into a non-`*password*` sink stays silent.

### `react-unsanitized-property` — metavariable DOM-property-assign sink

**Shape.** Sink `$BODY.$HTML = $SINK` (also deep-member and
`ReactDOM.findDOMNode(...).$HTML = $SINK`) with `metavariable-regex $HTML =~
(innerHTML|outerHTML)` + focus `$SINK`; source is any function parameter
(compiles to the existing wildcard `ParamName`).

**Recognizer added.** `try_compile_js_member_assign_regex_block` enumerates the
anchored `(innerHTML|outerHTML)` alternation into one concrete
`MemberAssign { field }` per name (mirroring the C# `PropertyAssignSink`
enumeration). The JS engine already matches `MemberAssign` with a tainted RHS.
Faithful: fires only on `<expr>.innerHTML|outerHTML = tainted`, silent on a
constant RHS and on any other (non-enumerated) property.

### Java XXE factory rules — `by-side-effect` sanitizer / typestate (DEFERRED 2026-07-05)

**Rules.** `transformerfactory-dtds-not-disabled`,
`documentbuilderfactory-disallow-doctype-decl-missing`,
`saxparserfactory-disallow-doctype-decl-missing` — the three Java XXE `mode: taint`
registry rules. All three model an XML parser **factory** as a typestate object:
it is created (`DocumentBuilderFactory.newInstance()`), optionally **hardened**
(`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` /
`setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")`), then **used**
(`.newDocumentBuilder()` / `.newSAXParser()` / `.newTransformer(...)`). The finding
should fire iff the factory reaches its `.new*()` use **without** an intervening
hardening call.

**Semgrep shape.** `pattern-sources: { by-side-effect: true, pattern: $FACTORY = …newInstance(); }`
(plus a `pattern-not-inside` excluding factories hardened in a `static {}` block);
`pattern-sanitizers: { by-side-effect: true, … setFeature/setAttribute … }`;
`pattern-sinks: $FACTORY.new*()`. The whole precision of the rules is the
safe/unsafe discrimination: their own fixtures document the hardened
`Good*Factory*` variants as **ok** and the bare `Bad*Factory*` variants as
**ruleid**.

**Why deferred — the `by-side-effect` sanitizer is the missing typestate
primitive.** foxguard treats the `by-side-effect: true` flag as a **no-op marker**
(`semgrep_taint.rs`, `~L4638`) and compiles the companion `pattern:` through the
ordinary **value-passing** path. That path can only express "a value that flows
*through* a sanitizer expression is clean" (`java_taint.rs::expression_taint` returns
`None` when the node itself is a sanitizer call). It has **no** way to express
"executing statement `factory.setFeature(…)` clears the taint on the *variable*
`factory` from here on": a hardening call is a standalone statement, not an
assignment, so it never touches the variable's entry in `TaintState`. `TaintState::clear`
fires **only** on clean re-assignment (`x = cleanValue`), never for a side-effecting
method call on `x`. Furthermore the Java engine accumulates taint over three fixed
passes and *then* scans sinks against a single final state
(`analyze_scope`) — it is **not statement-order flow-sensitive** for sanitization,
so even a hypothetical "clear on hardening call" would still need lexical
before/after ordering the architecture does not track.

Net effect if forced: a hardened factory stays tainted, so the `.new*()` sink fires
on **both** the safe fixture (`GoodDocumentBuilderFactory`, hardening present) and
the unsafe one (`BadDocumentBuilderFactory`) — over-matching the rules' own
documented negatives (faithfulness gate #3 fails). Over-matching is worse than
skipping, so the rules stay skipped.

Secondary blockers (each independently prevents even loading, but subordinate to
the sanitizer gap): the source `$FACTORY = X.newInstance();` (assignment-form
`by-side-effect` source) does not compile, and the sink `$FACTORY.newDocumentBuilder();`
(metavariable receiver + concrete method + no args) does not compile — reported as
"unsupported pattern shape" / "no expressible matchers". The engine *does* already
gate a sink on a tainted **receiver** (`find_sinks` →
`read_object_receiver_taint`), so receiver-taint sink semantics are present; the
receiver-clearing **sanitizer** is the piece that is absent.

**Needs.** A `by-side-effect` sanitizer primitive that removes a variable from the
tainted state at the point of a hardening call, applied **flow-sensitively** (only
sinks lexically after the hardening call are cleared) — i.e. the same
typestate/object-configuration machinery the C# XXE rules need (see
`php-csharp-skip-shapes.md`), plus an assignment-form `by-side-effect` source and a
metavar-receiver/concrete-method/no-arg sink shape. All genuinely missing. Deferred.

## Bottom line

The two clean, provably-faithful wins are shipped (one new source primitive,
one new sink recognizer reusing an existing engine matcher). The 11 deferred
rules each need a real new primitive — boolean taint-label algebra, a
call-argument object-field-value constraint, require-provenance callee binding,
a `pattern-inside`-bound parameter attribute-read source, an assignment-form
sanitizer, an object-field-value sanitizer, a sibling-keyed object-literal sink,
or an arg-count-constrained format-string sink — none a one-recognizer
extension, and each would over-match if forced into today's vocabulary.
