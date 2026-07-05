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

### `doctrine-orm-dangerous-query` — focus arg in `$QUERY->METHOD(...)` + scope
Sink is `focus-metavariable: $SINK` over a `pattern-either` of ~25
`$QUERY->where(...,$SINK,...)` / `->select(...)` / `->join(...)` QueryBuilder
methods, **bounded** by `pattern-inside: $Q = $X->createQueryBuilder(); ...`.
Two blockers: (1) the focus-call-sink recognizer only handles `.`-dotted method
receivers, not PHP `->`; (2) even with a `->` extension the compiled sinks would
be `MethodName{where}`, `MethodName{select}`, `MethodName{from}`, … which fire on
**any** object's `->select(...)` — the `createQueryBuilder` `pattern-inside` (the
only thing tying it to Doctrine) is dropped by that recognizer path, and the
focused arg-position relaxes to "any tainted arg". **Would over-match → deferred.**
Needs: PHP `->` focus-call support *plus* faithful sink-side `pattern-inside`
scoping for that recognizer (not just the graceful-degradation path).

### `laravel-sql-injection` — focus `$SQL` bounded by chained-receiver call
Sink is nested `patterns:` binding `$SQL`/`$COLUMN`/… each bounded by
`pattern-inside: DB::table(...)->whereRaw($SQL, ...)` (and ~90 sibling
Query-Builder methods). The bounding context is a **chained** static-call
receiver `DB::table(...)->whereRaw(...)`, which the focus-call recognizer
explicitly rejects (it refuses chained receivers so it never mistakes the inner
call for the sink). Dropping the `pattern-inside` leaves a bare `$SQL` metavar =
universal sink. **Needs**: chained-receiver focus-call sink support with faithful
`pattern-inside` scoping. Deferred (would over-match otherwise).

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

### `csharp-sqli` — typed-string source + two regex-pinned sink forms + propagator
Source is `patterns: [pattern: (string $X), pattern-not: "..."]` — a C# **typed
metavariable** source ("any non-literal string is tainted"). foxguard's
`TypedName` typed-source is Java/Go-only; C# has no `(Type $MV)` typed-source
recognizer. (The sinks — `new $PATTERN($CMD,...)` / `$CMD.$PATTERN = $VALUE` with
`metavariable-regex $PATTERN = ^(SqlCommand|CommandText|…)$` — and the
`StringBuilder` propagator are closer to expressible, but the rule can't load
without the source.) **Needs**: C# `(Type $MV)` typed-metavariable source. Also
note "every string is tainted" is a very broad source that leans on the sink
regex + sanitizers to stay precise. Deferred.

---

## Primitive backlog (what would unlock the deferred twelve)

| Primitive | Unlocks | Notes |
|---|---|---|
| ~~Focus-arg-of-call **source**~~ ✅ DONE 2026-07-05 | `use_weak_rng_for_keygeneration` (loaded) | `NodeMatcher::CallArgSource{method,arg_index}`; sink via C#-gated `new Type(...)`→`Call{canonical}` |
| ~~C# `(Type $MV)` typed-metavariable source~~ ✅ DONE 2026-07-05 | `csharp-sqli` (loaded) | `TypedName`, C#-gated |
| Typestate / object-configuration sink | 3 C# XXE rules | "call on an object configured unsafely earlier" |
| PHP `->` + `::` call support in focus-call sink w/ faithful `pattern-inside` scoping | `doctrine-orm`, `laravel-sql-injection`, `laravel-api-route`, `laravel-unsafe-validator` | the `->`/`::` lexical gap is easy; the faithful scoping is the hard part |
| Signature-param source (bare, no focus) + concat-argument sink | `xpath-injection` | |
