# PHP / C# taint skip-shape assessment

> Status: 2026-07-05. Deep-dive on the remaining PHP (7) and C# (6) `mode: taint`
> registry rules foxguard could not load. One rule (`md5-loose-equality`) was
> implemented; the other twelve are diagnosed below with the exact primitive
> each needs.

## Method

Each rule was run through the real loader (`parse_semgrep_str` per single-rule
document) and its per-role compile warnings captured, then cross-referenced
against the recognizers in `semgrep_taint.rs`. A rule loads iff it compiles at
least one **source** AND one **sink** matcher.

The HARD gate: a rule that loads must match *no more* than Semgrep. Where the
only path to loading is to drop a `pattern-inside` / `focus` / typing constraint
that genuinely bounds the match, the rule is left skipped (over-matching is
worse than skipping).

## Result

- **Implemented: 3** — `md5-loose-equality` (`LooseEquality` sink primitive),
  `tainted-object-instantiation` (`TaintedCallee` sink primitive),
  `tainted-session` (`TaintedSubscriptKey` sink primitive).
- **Deferred: 10** — each needs a genuinely new primitive or would over-match.

PHP load rate (this snapshot): 58 → 60 / 64 (93.8%) after adding the tainted
class-name and subscript-key sinks (a clean +2 PHP delta). The overall registry
total shifts with each fresh `semgrep-rules` clone (gitignored); the per-language
PHP delta is the stable measure.

---

## Implemented

### `md5-loose-equality` (PHP) — comparison-equality sink ✅

- **Source**: `md5(...)`, `hash(...)`, `sha1(...)`, … → compile fine (`Call`).
  (`$PHAR->getSignature()` / `$RARENTRY->getCrc()` drop — PHP `->` method-call
  sources — but the many function-call sources remain, so sources are non-empty.)
- **Sink (was the blocker)**: `$VAR1 == $VAR2` / `$VAR1 != $VAR2` — a *loose*
  equality comparison whose operand is tainted. No existing matcher expressed a
  comparison sink.
- **Primitive added**: `NodeMatcher::LooseEquality` (shared enum in
  `taint_engine.rs`; carried + no-op'd by every non-PHP engine via their
  existing catch-all/explicit no-op arms). `compile_pattern` recognizes
  `$A == $B` / `$A != $B` (both metavariables), **gated to PHP + sink/sanitizer**,
  and refuses the strict `===`/`!==`. The PHP engine matches a `binary_expression`
  whose operator token kind is exactly `==`/`!=` (grammar-distinct from
  `===`/`!==`) with one tainted operand.
- **Faithfulness proven** (tests in `semgrep_taint.rs`): fires on `md5($u) == $u`
  and inline `md5($u) == "0"`; **stays silent** on the strict `===` form (the
  safe comparison the rule recommends), on untainted `$a == $b`, and on the
  `strlen(...)`-sanitized operand.
- Note: the PHP taint engine analyzes function/method bodies, so a comparison at
  PHP top-level file scope (as in the registry's own `.php` fixture) is not
  reached — a pre-existing engine-scope limitation, not specific to this sink.

### `tainted-object-instantiation` (PHP) — tainted **class-name** sink ✅

- **Source**: `$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST`/`$_SERVER` → `ParamName`.
- **Sink (was the blocker)**: `pattern-inside: new $SINK(...)` + `pattern: $SINK`
  — the taint is the **class-name selector** of an object creation (unsafe
  reflection, CWE-470), NOT a constructor argument.
- **Primitive added**: `NodeMatcher::TaintedCallee` (shared enum; carried +
  no-op'd by every non-PHP engine). The `patterns:`-block recognizer
  `try_compile_tainted_callee_sink_block` (**PHP-gated, sink/sanitizer**) fires
  only when the focus/bare `pattern: $SINK` names the **class-name metavariable**
  of a `new $SINK(...)` `pattern-inside`; a constructor-argument focus
  (`new C($ARG)` + `pattern: $ARG`) is refused so the ordinary argument-sink path
  keeps ownership. The PHP engine inspects the first named child (class-name
  position) of an `object_creation_expression` only.
- **Faithfulness proven** (tests in `semgrep_taint.rs`): fires on
  `new $tainted('safe')`; **stays silent** on `new SafeController($_GET['c'])`
  (tainted argument, concrete class name) and `$a = 'MyController'; new $a()`
  (literal class-name variable).

### `tainted-session` (PHP) — tainted **subscript-key** assignment sink ✅

- **Source**: `$_GET`/`$_POST`/`$_COOKIE`/`$_REQUEST` → `ParamName`.
  Sanitizers (`md5(...)`, `bin2hex(...)`, …) compile as `Call` sanitizers; the
  one non-call sanitizer `$A . $B` (string concat) does not compile — the same
  documented dropped-sanitizer graceful degradation as every other rule, a slight
  broadening only on that concat form.
- **Sink (was the blocker)**: `pattern-inside: $_SESSION[$KEY] = $VAL;` +
  `pattern: $KEY` — the taint is the **index/KEY** of a `$_SESSION` write
  (session poisoning, CWE-284), NOT the assigned value.
- **Primitive added**: `NodeMatcher::TaintedSubscriptKey { base }` (shared enum;
  carried + no-op'd by every non-PHP engine). The recognizer
  `try_compile_subscript_key_sink_block` (**PHP-gated, sink/sanitizer**) fires
  only when the focus/bare `pattern: $KEY` names the **KEY metavariable** of a
  `$BASE[$KEY] = $VAL` `pattern-inside`, recording the concrete superglobal base
  (`_SESSION`); a value focus (`pattern: $VAL`) is refused. The PHP engine
  inspects the KEY operand of an assignment-LHS `subscript_expression` whose base
  is the configured superglobal only.
- **Faithfulness proven** (tests in `semgrep_taint.rs`): fires on
  `$_SESSION[$_POST['input']] = true` and the propagated
  `$k = $_POST['input']; $_SESSION[$k] = true`; **stays silent** on
  `$_SESSION['key'] = $_POST['input']` (tainted VALUE, literal key),
  `$_SESSION['prefix'][$_POST['input']] = true` (nested base, not `$_SESSION`),
  and the `md5(...)`-sanitized key.

---

## Deferred — PHP

> **2026-07-05 re-investigation (focus-call-sink w/ pattern-inside).** Both rules
> were re-examined end-to-end (recognizer feasibility + empirical probing of the
> sink-side `pattern-inside` post-filter). The `->`/`::` lexical gap is indeed
> trivial; the faithful scoping is **not achievable**, for a newly-pinned-down
> and decisive reason: **foxguard has no working AST `pattern:` search matching
> for PHP at all**, and every `pattern-inside` enforcement path is built on top
> of it. Both remain deferred; the precise blockers are sharpened below.

#### THE decisive shared blocker — PHP AST search matching is a no-op
The *only* mechanism that could enforce a sink-side `pattern-inside` is the
post-filter in `semgrep_taint.rs` (`self.insides.sink` + `CompiledAstPattern::
contains_range`). That containment test calls `match_single_pattern` — the same
generic AST search matcher used by SEARCH-mode `pattern:` rules. **That matcher
returns zero matches for every PHP pattern.** Verified through the proven public
loader (`parse_semgrep_str`) + `Rule::check`:

| language | rule `pattern:` | source | findings |
|---|---|---|---|
| php | `system($x)` | `system($x);` | **0** |
| php | `system(...)` | `system($x);` | **0** |
| php | `$O->whereRaw($A)` | `$foo->whereRaw($y);` | **0** |
| php | `DB::table(...)->whereRaw($A, ...)` | `DB::table('o')->whereRaw($t);` | **0** |
| python (control) | `system(...)` | `system(x)` | **1** |

Root cause: `prepare_pattern_for_grammar` (`semgrep_compat.rs`) wraps Go patterns
in a synthetic package/func but leaves every other language — PHP included —
**bare**. A bare PHP pattern (`system($x)`, no `<?php`) is parsed by
tree-sitter-php as inline **text/HTML**, so `first_meaningful_node` yields a
`text` node that matches no real code node. PHP is supported today only via (a)
its dedicated taint engine (`php_taint.rs`, which never routes through the AST
search matcher) and (b) `pattern-regex` rules — **not** AST `pattern:`/`pattern-
inside` matching.

Consequence for any focus-call-sink recognizer that captures the `pattern-inside`
into `insides.sink`: the post-filter keeps a finding only when its sink is
*contained* by a matched region, and **no PHP region ever matches**, so it
suppresses **every** finding — the rule would load but fire **never** (a useless
under-match). The alternative — dropping the `pattern-inside` — makes the generic
`MethodName{where|select|from|join|set|…}` sinks fire on every object in any
codebase (catastrophic over-match). There is no faithful middle. Enforcing the
scoping first requires **PHP AST search-pattern support** (wrap PHP patterns in
`<?php`, verify metavariable/ellipsis handling, re-validate the whole PHP search
surface) — a large, cross-cutting infrastructure primitive, categorically beyond
the `->`/`::` lexical gap.

### `doctrine-orm-dangerous-query` — focus arg in `$QUERY->METHOD(...)` + scope
Sink is `focus-metavariable: $SINK` over a `pattern-either` of ~25
`$QUERY->where(...,$SINK,...)` / `->select(...)` / `->join(...)` QueryBuilder
methods, **bounded** by two `pattern-inside`s: `$Q = $X->createQueryBuilder();
...` and `$Q = new QueryBuilder(...); ...`. Note `$Q` is **not** unified with the
`$QUERY` receiver — the bound is merely "somewhere earlier in this scope a query
builder was created". The `...,$SINK,...` focus IS faithful as "any argument", so
arg-position is *not* a blocker here (unlike Laravel). Blockers, in order:
1. **(decisive)** The `createQueryBuilder` `pattern-inside` is the *only* thing
   tying these otherwise-universal method names to Doctrine, and it cannot be
   enforced — see the shared blocker above (PHP AST search is a no-op, so
   `contains_range` never fires). Without it the compiled sinks
   `MethodName{where}`, `MethodName{select}`, `MethodName{from}`,
   `MethodName{set}`, `MethodName{join}`, … match **every** `->where()/->select()/
   …` on any object anywhere. Catastrophic over-match.
2. **(second-order, only relevant if #1 is fixed)** The bound is **multi-
   statement** (`$Q = …createQueryBuilder();` *then* `...`) and the sink call sits
   in a *later* statement of the same block (see the rule's own `.php` fixture:
   the `->where('email = '.$input)` is chained several statements after the
   assignment). Even with working PHP AST search, a statement-sequence pattern
   with a trailing `...` whose matched *region must span through subsequent
   statements* is a separate, unproven containment shape.
3. **(source side)** The taint source is `sprintf(...)` (compiles as `Call`) OR
   `"...".$SMTH` — a **string concatenation whose left operand is a literal**, as
   a *source*. There is no concat-literal source matcher; only the `sprintf` arm
   would compile, under-matching the `'email = '.$input` positive.
**Needs**: PHP AST search-pattern support (unlocks the `pattern-inside`) + a
multi-statement trailing-`...` containment region + a concat-literal source. All
three are genuinely missing. Deferred.

### `laravel-sql-injection` — focus `$SQL`/`$COLUMN`/… bounded by `DB::table(...)` chain
Sink is a `pattern-either` of nested `patterns:` binding `$SQL`/`$EXPRESSION`/
`$COLUMNS`/`$COLUMN`/`$QUERY`, each bounded by
`pattern-inside: DB::table(...)->whereRaw($SQL, ...)` (and ~90 sibling
Query-Builder methods). **Two independent, each-decisive blockers:**
1. **Pattern-inside unenforceable** — same shared blocker (PHP AST search no-op).
   The bound `DB::table(...)->METHOD(...)` is the only thing distinguishing these
   from generic `->get()/->where()/->min()/->value()/…` calls; it cannot be
   enforced, and these method names are ubiquitous. Over-match.
2. **Arg-position precision missing — blocks even if #1 were fixed.** The focus is
   pinned to a *specific argument position* (`whereRaw($SQL, ...)` = arg 0;
   `find($ID, $COLUMNS)` = arg 1; `where($COLUMN, ...)` = arg 0), and the rule's
   own `.php` fixture encodes this as its negatives:
   `DB::table('users')->where('name', $tainted)` (**ok** — taint in arg 1) and
   `->selectRaw('… ? …', [$tainted])` (**ok** — taint in the bindings arg). The
   only sink primitive available is `MethodName`, which fires on taint in **any**
   argument — so it flags **both documented negatives**. There is no
   `CallArgSink{method, arg_index}` (the sink-side dual of the existing
   `CallArgSource`). And a working `pattern-inside: DB::table(...)->where($COLUMN,
   ...)` would **not** rescue this: that region also *contains*
   `->where('name', $tainted)`, so `contains_range` keeps it. Faithful arg-position
   requires the engine to check *which* argument carries taint against a required
   index — a new primitive + engine change.
**Needs**: PHP AST search-pattern support **and** an arg-position-aware
`CallArgSink{method, arg_index}` sink primitive. Deferred (would over-match on the
rule's own negatives otherwise).

### `laravel-unsafe-validator` — multi-part typed/property source + `::` sink
Source is a union of a typed param `Request $R` (focus), a `$this->$PROPERTY`
read constrained by `metavariable-pattern` (`query|request|headers|…`), all
`pattern-inside` a `class … extends Illuminate\…\FormRequest {…}`. Sink is
`Illuminate\Validation\Rule::unique(...)->ignore(...,$IGNORE,...)` (focus
`$IGNORE`). Blocks on: PHP typed-param sources, `metavariable-pattern`-narrowed
property sources, and a chained `::`-static → `->ignore` focus sink. **Multiple
new primitives**; deferred.

### `laravel-api-route-sql-injection` — closure-param source + `::` static sink
Source is `focus: $ARG` inside `Route::$METHOD($ROUTE_NAME, function(...,$ARG,...){...})`
— a parameter of a **closure argument** to a `::` static call, which the
param-source recognizer (function-*definition* signatures only) does not match.
Sink is `DB::raw(...)`, a `::` scoped call whose callee `DB::raw` fails
`is_dotted_identifier` (contains `::`), so it compiles to nothing. **Needs**:
PHP `::` scoped-call `Call` support + closure-parameter source seeding. Deferred.

---

## Deferred — C#

### `use_weak_rng_for_keygeneration` — focus-arg **source** can't be expressed
Source is `focus: $KEY` inside `pattern-inside: (System.Random $RNG).NextBytes($KEY); ...`
— "the buffer filled by `Random.NextBytes`". There is no *focus-argument-of-a-call*
**source** recognizer (only the sink-side analog exists), so `$KEY` compiles to a
vacuous `ParamName{["$KEY"]}` that matches no real identifier — the rule would
load but never fire. The sinks are tractable: the 3 `new AesGcm(...)` /
`new AesCcm(...)` / `new ChaCha20Poly1305(...)` arms compile as constructor
`Call` sinks (the C# engine already matches `object_creation_expression` by type
name), and the `($KEYTYPE $CIPHER).Key = $SINK` arm is a droppable under-match.
**Blocked on the source.** Needs a *focus-arg-of-call source* primitive (the
source-side dual of `try_compile_focus_call_sink_block`). Deferred rather than
ship a rule that loads but can never fire.

### `xpath-injection` — function-signature source (no focus) + concat-in-call sink
Source is bare `pattern: $T $M($INPUT,...) {...}` / a local `string $INPUT;`
inside a method — a function-signature *without* a `focus-metavariable`, so the
param-source recognizer (which keys off `patterns:` + focus) does not engage, and
`compile_pattern` has no "typed/positional parameter of this signature is the
source" shape outside a `patterns:` block. Sinks are `$NAV.Compile("..."+$INPUT+"...")`
(a method call whose argument is a tainted string concat) — a nested
binop-format-inside-a-call the `BinopFormat` matcher does not reach. Needs both a
signature-param source (bare form) and a concat-argument sink. Deferred.

### `xmldocument-unsafe-parser-override` / `xmlreadersettings-unsafe-parser-override` / `xmltextreader-unsafe-defaults` — typestate sinks
All three share a compiling **source** (`focus: $ARG` inside
`public $T $M(...,string $ARG,...){...}` → param-source recognizer). All three
block on a **sink that is a universal method call bounded only by a multi-statement
`pattern-inside`**:
- `$XMLDOCUMENT.$METHOD(...)` bounded by `XmlDocument x = new…; … x.XmlResolver = new XmlUrlResolver(); …`
- `XmlReader.Create(...,$RS,...)` bounded by `XmlReaderSettings rs = new…; … rs.DtdProcessing = DtdProcessing.Parse; …`
- `$READER.$METHOD(...)` bounded by `XmlTextReader r = new…; …` and `pattern-not-inside: … DtdProcessing.Prohibit; …`

The sink node itself is `$OBJ.$METHOD(...)` (metavariable receiver AND method) —
a universal "any method call". foxguard has no any-call sink matcher, and the
only bound is a **typestate** setup (an unsafe resolver / DTD setting established
earlier on the same object). Synthesizing an any-call sink gated solely by a
captured multi-statement `pattern-inside` region would over-match badly. **Needs
a typestate/object-configuration primitive** ("a call on an object previously
configured unsafely"). Deferred.

### `csharp-sqli` — typed-string source ✅ + two regex-pinned sink forms ✗ (STILL SKIPPED — sink is the blocker)
Source is `patterns: [pattern: (string $X), pattern-not: "..."]` — a C# **typed
metavariable** source ("any non-literal string is tainted"). The C# `(Type $MV)`
typed-source recognizer (`TypedName`, C#-gated) **landed 2026-07-05** and the
source now compiles. **But the rule is still skipped** — the SINK is the real
blocker (verified via `--list-skips csharp`: "pattern-sinks produced no
expressible matchers"). The sink is a `pattern-either` of two `patterns:` blocks,
both gated by `metavariable-regex $PATTERN = ^(SqlCommand|CommandText|OleDbCommand|
OdbcCommand|OracleCommand)$`:
- **Block 1** `new $PATTERN($CMD,...)` + `focus: $CMD` — constructor-arg sink at
  position 0, where the **class name** ∈ the enumerated set. Needs: enumerate the
  regex alternation to concrete constructor sinks (`new SqlCommand(focus arg 0)`,
  …). foxguard has `new Type(...)`→`Call{canonical}` (C#-gated, from use_weak_rng)
  but NOT a focus-on-constructor-arg + class-name-regex-enumeration sink.
- **Block 2** `$CMD.$PATTERN = $VALUE;` + `focus: $VALUE` — assignment-to-property
  sink where the **property name** ∈ the enumerated set (`CommandText`). Needs a
  property-assignment sink primitive (focus on RHS, LHS property name pinned).

**Needs** (sink side): (a) constructor-arg sink with class-name enumeration, and
(b) property-assignment sink with property-name enumeration — the two focus forms
enumerated from the shared `metavariable-regex`. Both are the same "focus +
metavariable-regex either-block" family already used for Python
dangerous-spawn-process, but on an arg/assignment target rather than the call
name. The `StringBuilder` propagator (`(StringBuilder $B).$ANY(...,(string $X),...)`)
also drops. Note "every string is tainted" is a very broad source that leans on
the sink regex + sanitizers to stay precise — so a faithful sink is essential
(a loose sink here would over-match badly). **Still deferred; next candidate.**

---

## Primitive backlog (what would unlock the deferred twelve)

| Primitive | Unlocks | Notes |
|---|---|---|
| ~~Focus-arg-of-call **source**~~ ✅ DONE 2026-07-05 | `use_weak_rng_for_keygeneration` (loaded) | `NodeMatcher::CallArgSource{method,arg_index}`; sink via C#-gated `new Type(...)`→`Call{canonical}` |
| ~~C# `(Type $MV)` typed-metavariable source~~ ✅ DONE 2026-07-05 | (source primitive only — reused by `xpath-injection`) | `TypedName`, C#-gated. NB: `csharp-sqli` itself is **still skipped** — its sink is the blocker (see below) |
| ~~Signature-param source + concat-in-call sink~~ ✅ DONE 2026-07-05 | `xpath-injection` (loaded) | `FirstParamSource` + `CallArgConcat{method}`, C#-gated; concat-only enforced at sink |
| Constructor-arg + property-assignment sinks w/ metavariable-regex enumeration | `csharp-sqli` | source already compiles; sink is the only blocker — `new SqlCommand(focus arg)` / `$cmd.CommandText = focus` enumerated from `^(SqlCommand\|CommandText\|…)$` |
| Typestate / object-configuration sink | 3 C# XXE rules | "call on an object configured unsafely earlier" |
| **PHP AST `pattern:`/`pattern-inside` search matching** (prerequisite) | `doctrine-orm`, `laravel-sql-injection`, `laravel-api-route`, `laravel-unsafe-validator` | **The real blocker.** PHP patterns are never wrapped in `<?php` by `prepare_pattern_for_grammar`, so they parse as inline text and match nothing (verified: `pattern: system($x)` → 0 findings on `system($x);`; Python identical → 1). Every sink-side `pattern-inside` post-filter (`contains_range`) is a no-op for PHP, so QueryBuilder scoping is unenforceable. The `->`/`::` lexical gap is trivial by comparison. |
| Arg-position-aware `CallArgSink{method, arg_index}` sink | `laravel-sql-injection` (also needed) | Sink-side dual of `CallArgSource`. Laravel pins the focus to a specific arg position (`whereRaw($SQL,...)`=0, `find($ID,$COLUMNS)`=1); `MethodName` fires on taint in *any* arg and flags the rule's own `where('name',$tainted)` / `selectRaw(…,[$tainted])` negatives. |
| Multi-statement trailing-`...` containment region | `doctrine-orm` (also needed) | Doctrine's `pattern-inside: $Q = $X->createQueryBuilder(); ...` binds a *later* sink statement; needs a region that spans subsequent statements. |
| Concat-literal source (`"...".$SMTH`) | `doctrine-orm` (also needed) | A string concat whose left operand is a literal, as a taint *source*. |
| Signature-param source (bare, no focus) + concat-argument sink | `xpath-injection` | |
