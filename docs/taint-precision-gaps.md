# Semgrep taint-bridge precision gaps

Status of four precision gaps in the Semgrep-compat taint bridge
(`src/rules/semgrep_taint.rs`) and the Java taint engine
(`src/rules/java_taint.rs`), found by triaging a large real-world Java
codebase scan where a 4-rule custom pack produced ~150 findings of which
the overwhelming majority were false positives caused by the engine
silently *broadening* the written rules.

Each gap below has a regression test in
`tests/semgrep_taint_precision.rs`. "Before" describes the behaviour at
the time the tests were written; all four are now fixed.

---

## Gap 1 — `paths:` include/exclude is ignored for `mode: taint` rules

**Before:** `PathFilter` was compiled and enforced for structural
(`SemgrepRule`), generic-mode, and regex-mode rules, but
`SemgrepTaintRule` carried no filter and used the trait's default
`applies_to_path() -> true`. A taint rule with

```yaml
paths:
  include: ["src/handlers/"]
  exclude: ["**/SafeStore.java"]
```

scanned every file. Rule authors who scoped a noisy heuristic to a
directory, or excluded the files that *implement* the access-check
helpers (which otherwise self-report), silently got neither.

**Impact:** on the triaged codebase, a tenant-isolation rule excluded
its own chokepoint implementations (`AccessCheckServiceImpl`, `crud/**`)
— the excludes did nothing and those files self-reported.

**Fix:** `SemgrepTaintRule` now carries the same `PathFilter` and
implements `applies_to_path`, sharing `PathFilter::from_yaml` with the
structural path.

---

## Gap 2 — dotted-canonical receiver matching was substring-based

**Before:** a compiled `Call { canonical: "req.getQueryParam" }` matched
a `method_invocation` when the receiver text merely *contained* the
canonical receiver, case-insensitively:

```rust
receiver_lower.contains(&expected_lower)
```

So canonical `rq.getPath` matched `parquetUri.getPath()` (`parquetUri`
contains `rq`), and canonical `req.getQueryParam` matched
`freq.getQueryParam()` (`freq` contains `req`). Any short receiver name
in a rule was a landmine.

The substring behaviour existed for a good reason — `request.getParameter`
should match a receiver named `httpServletRequest`, and `Runtime.exec`
should match `Runtime.getRuntime()` — but it lacked token boundaries.

**Impact:** rules that pin a source to a conventional receiver name
(`req.getPath()`) also fired on unrelated receivers (`uri.getPath()`
via `parquetUri`, etc.), producing false request-derived taint.

**Fix:** the receiver comparison is now word-boundary aware: the
canonical receiver must appear in the actual receiver text as a whole
token, where token boundaries are non-alphanumeric characters or
camelCase transitions. `httpServletRequest` still matches `request`
(camel boundary before `Request`); `parquetUri` no longer matches `rq`,
`freq` no longer matches `req`.

---

## Gap 3 — chained-call sinks lose their receiver chain

**Before:** a sink whose callee is itself a call chain, e.g.

```yaml
pattern-sinks:
  - patterns:
      - focus-metavariable: $SINK
      - pattern-either:
          - pattern: $TBL.id().eq($SINK)
```

compiled to `MethodName { method: "eq" }` — the `.id()` link was
discarded, so **any** `.eq(tainted)` fired (`TEAM.name().eq(id)`,
`TEAM_USER.userId().eq(userId)`, join predicates, …). Worse, the same
pattern written as a plain `pattern:` entry compiled to *nothing* (the
chained callee was unrecognised), silently emptying the sink.

**Impact:** on the triaged codebase this one degradation accounted for
~100 false positives — every by-*any*-column query touching a tainted
id was reported as a by-id query.

**Fix:** a chained callee now compiles to
`Call { canonical: "id().eq" }` (the trailing receiver segment plus the
final method), and the Java canonical matcher understands a
parenthesised trailing segment: the receiver text must *end with* the
`id()` call segment. `TEAM.id().eq(x)` matches; `TEAM.name().eq(x)`
does not. The plain-`pattern:` path recognises the same shape, so both
spellings now compile identically instead of one over-matching and the
other silently vanishing.

---

## Gap 4 — signature `pattern-inside` co-parameter constraints dropped

**Before:** the parameter-as-source shape

```yaml
pattern-sources:
  - patterns:
      - pattern-inside: "$RET $M(..., AuthContext $AC, ..., DbKey<$T> $ID, ...) { ... }"
      - pattern: $ID
```

compiled the seed's declared type (`DbKey`) — good — but dropped the
rest of the signature. The rule says "a DbKey parameter *of a method
that also takes an AuthContext*"; the engine seeded every DbKey
parameter of every method. A whole tenant-agnostic store layer (whose
methods take `DbKey` but no `AuthContext`, by design) self-reported.

**Impact:** the majority of the remaining tenant-isolation false
positives: methods that are *below* the authorization boundary and
never see an AuthContext were treated as authenticated entry points.

**Fix:** the compiler now collects the other concretely-typed
parameters of the same signature and encodes them into the type
sentinel (`type:DbKey&AuthContext`). The Java engine seeds a typed
parameter only when the enclosing method's parameter list also declares
every required co-parameter type. Signatures whose co-params are all
metavariable-typed or `...` behave as before.

---

## Still open (known, documented)

- `pattern-not-inside` / `pattern-not` inside taint sink blocks are
  still dropped with a warning (sink-side structural exclusion — e.g.
  "unless the enclosing WHERE also constrains the tenant" — has no
  engine support).
- Request-derived expression sources written as bare
  `$REQ.getQueryParam(...)` (metavariable receiver, no signature
  context) are still rejected as universal.
- Cross-file (interfile) taint remains limited to the dedicated Java
  cross-file summaries; `options: interfile: true` is ignored.
