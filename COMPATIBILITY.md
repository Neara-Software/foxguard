# foxguard Compatibility

Fast local security guard for changed files, built-in rules, Semgrep-compatible YAML, and Coccinelle semantic patches.

foxguard supports a focused Semgrep-compatible YAML subset for local rule loading and an additive Coccinelle bridge for C semantic patches.

That supported subset is regression-tested in-repo and parity-checked in CI against the real `semgrep` CLI.

The product default is still built-in rules. Compatibility mode exists to help teams adopt foxguard without throwing away existing rule work on day one.

## Recommended usage

Built-ins first:

```sh
foxguard .
foxguard secrets .
foxguard --rules ./rules .
foxguard --changed .
```

External-rules-only compatibility run:

```sh
foxguard --no-builtins --rules ./rules .
```

Coccinelle-backed C rule:

```sh
foxguard --rules ./kernel-rules .
```

Adoption baseline:

```sh
foxguard baseline --output .foxguard/baseline.json
foxguard --baseline .foxguard/baseline.json .
```

## Supported today

Top-level structure:

- `rules`
- `id`
- `message`
- `severity`
- `languages`
- `metadata.cwe`

Pattern operators:

- `pattern`
- `pattern-regex`
- `pattern-either`
- `pattern-not`
- `pattern-not-regex`
- `pattern-not-inside`
- `pattern-inside`
- `patterns`

Rule scoping:

- `paths.include`
- `paths.exclude`

Metavariable filtering:

- `metavariable-regex`

Taint rules (`mode: taint`):

- `mode: taint` on Python rules only; non-Python taint rules are skipped with a warning
- `pattern-sources`, `pattern-sinks`, `pattern-sanitizers` — each entry must be either a single `pattern:` string or a `pattern-either:` list (nested `pattern-either:` is supported and flattens recursively)
- Supported `pattern:` shapes:
  - bare identifier (`request`) — a source-only shape compiled to a parameter-name match
  - dotted attribute chain (`request.data`, `request.json`) — nested chains flatten to `leftmost root + outermost field` (matches the engine's one-level attribute propagation)
  - call forms with any arguments (`pickle.loads($X)`, `pickle.loads(...)`, `pickle.loads()`, `eval($X)`) — arguments are stripped, the dotted callee path is what matches
- Severity mapping matches the pattern-rule bridge (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium) and `metadata.cwe` is propagated to findings
- Rules that use anything outside this subset (`patterns:` / `pattern-inside:` / `metavariable-pattern:` inside a source/sink/sanitizer block, unsupported pattern shapes, non-Python languages, missing sources or sinks) are skipped with a warning — other rules in the same file still load. Entries with unsupported keys are dropped individually so a single bad entry will not disable sibling entries in the same block.

Language mapping:

- JavaScript / TypeScript (`.ts` and `.tsx` use dedicated TypeScript/TSX parsers, then map onto the JavaScript-compatible rule surface)
- Python
- Go

Rule loading:

- load a single YAML file
- load a directory recursively
- deduplicate language aliases that map to the same foxguard parser

## Generic mode (`languages: [generic]`)

Semgrep's `generic` mode (a.k.a. spacegrep) is AST-less: it matches a tokenized
pattern against the raw text of a file. foxguard routes any rule whose
`languages` includes `generic` (or the `regex` alias) to a dedicated text
matcher (`src/rules/generic_mode.rs`), separate from the tree-sitter pattern
bridge. This is what lets the config-file rule packs (nginx, apache, dockerfile,
generic secret patterns) actually match.

```yaml
rules:
  - id: weak-ssl-protocols
    pattern: ssl_protocols ...
    message: weak ssl_protocols directive
    severity: WARNING
    languages: [generic]
```

Supported in generic mode:

- `pattern` — tokenized literal matching
- `pattern-either` — OR over multiple generic patterns
- `pattern-not` — drops candidates whose span overlaps a negative match
- `pattern-regex` — passthrough regex match against the raw text
- `...` ellipsis — matches any run of tokens, including across whitespace and newlines
- `$METAVAR` — binds a single token span, with equality enforcement (the same metavariable must bind the same text)
- `paths.include` / `paths.exclude` — same path scoping as the AST bridge
- `metadata.cwe` and `severity` mapping (`ERROR` → Critical, `WARNING` → High, `INFO` → Medium)

Limits (parity-honest):

- Tokenization is word/punctuation based (a "word" is a run of ASCII alphanumerics and underscores; every other non-whitespace character is its own token). It is close to, but not byte-identical with, spacegrep's tokenizer.
- `metavariable-comparison` and `metavariable-pattern` are not applied in generic mode.
- `pattern-inside` / `pattern-not-inside` are not applied in generic mode (generic mode treats the file as a flat token stream, not a brace-nested structure).
- A generic rule only runs on files foxguard already recognizes (the languages above plus the config formats). Files with no detected language are not scanned, so a generic rule will not fire on an arbitrary extension the way upstream `semgrep` would. Scope generic rules with `paths:` and target recognized files.
- Match line numbers are parity-checked against upstream `semgrep` in CI (`tests/semgrep_parity_generic.rs`, gated on `semgrep` being installed); exact end-column spans may differ because ellipsis greediness is approximated.

## Coccinelle bridge

Rules with `engine: coccinelle` are loaded from the same `--rules` YAML files or directories as Semgrep-compatible rules:

```yaml
rules:
  - id: kernel/dirty-frag-inplace-crypto-no-cow
    engine: coccinelle
    severity: high
    languages: [c]
    metadata:
      cwe: CWE-362
    message: In-place crypto on skb data without a preceding copy-on-write gate.
    script_path: dirty-frag-inplace-crypto-no-cow.cocci
```

Supported Coccinelle rule keys:

- `id`
- `engine: coccinelle`
- `message`
- `severity` (`critical`, `high`, `medium`, `low`, plus Semgrep-style `ERROR`, `WARNING`, `INFO`)
- `languages: [c]`
- `metadata.cwe`
- `script` for inline SmPL
- `script_path` for a `.cocci` file relative to the YAML file

Execution model:

- foxguard shells out to upstream `spatch`; whatever SmPL surface your installed `spatch` accepts is the supported SmPL surface.
- Coccinelle currently scans `.c` and `.h` files.
- Findings are normalized into the same `Finding` shape used by built-in and Semgrep-compatible rules, so terminal, JSON, SARIF, CBOM, and baselines work through the existing report path.
- If `spatch` is missing, foxguard emits one warning and skips Coccinelle rules while continuing the rest of the scan.

## CodeQL bridge

Rules with `engine: codeql` are loaded from the same `--rules` YAML files or directories as Semgrep-compatible rules. foxguard expects a pre-built CodeQL database and shells out to the installed `codeql` CLI:

```yaml
rules:
  - id: kernel/codeql-dirty-frag
    engine: codeql
    severity: high
    metadata:
      cwe: CWE-362
    message: CodeQL query matched dirty-frag behavior.
    query: queries/dirty-frag.ql
```

Supported CodeQL rule keys:

- `id`
- `engine: codeql`
- `message`
- `severity` (`critical`, `high`, `medium`, `low`, plus Semgrep-style `ERROR`, `WARNING`, `INFO`)
- `metadata.cwe`
- `query` for a `.ql` file relative to the YAML file
- `database` for a per-rule pre-built CodeQL database path, optionally `${FOXGUARD_CODEQL_DB}`

Database selection priority is:

1. rule-level `database`
2. CLI `--codeql-db /path/to/database`
3. environment `FOXGUARD_CODEQL_DB`
4. **Auto-build**: if `codeql` is on PATH and none of the above are set, foxguard creates an ephemeral database scoped to the scan target via `codeql database create --language=<lang> --source-root=<target> --overwrite`. The temp DB is cleaned up when the scan exits. Query language is inferred from the top-level `import <lang>` line in the `.ql` file, falling back to source-root file extensions.

Example:

```bash
# Auto-build path (codeql on PATH, no DB flag):
foxguard --rules ./kernel-rules /path/to/linux

# Manual DB path (still supported):
foxguard --rules ./kernel-rules --codeql-db /path/to/linux.codeql .
```

Execution model:

- foxguard runs `codeql database analyze <db> <query.ql> --format=sarif-latest --output <tmp>.sarif`.
- SARIF results are normalized into the same `Finding` shape used by built-in, Semgrep-compatible, and Coccinelle rules.
- If `codeql` is missing from PATH, foxguard emits a single warning and skips CodeQL rules while continuing the rest of the scan.
- If `codeql database create` fails (e.g. no compilable source under the scan target, or the qlpack language family isn't installed), foxguard emits a per-rule warning and continues. Set `FOXGUARD_CODEQL_CREATE_TIMEOUT_SECS` to override the default 15-minute build timeout.
- `foxguard diff` does not run the CodeQL bridge yet. Accurate diffing needs a base/current database strategy rather than a single current database.

## Important limitations

foxguard does **not** claim full Semgrep or OpenGrep compatibility.

If a feature is not listed in the supported section above, assume it is either unsupported or only partially supported today.

That includes more advanced Semgrep/OpenGrep capabilities such as:

- the broader rule syntax beyond the subset above
- the full ecosystem of published registry rules
- engine behaviors that depend on features foxguard does not implement yet

## Product stance

The intended model is:

- foxguard built-ins are the default product
- external YAML is the adoption bridge
- Semgrep and OpenGrep remain the reference tools for the broadest rule ecosystems

This keeps the promise clear:

- use foxguard for fast local feedback
- bring in compatible YAML where it helps
- do not assume full drop-in equivalence
