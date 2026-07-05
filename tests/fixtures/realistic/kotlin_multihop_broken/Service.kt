// Middle helper (fileB) for the kotlin_multihop_broken fixture.
//
// Unlike the positive fixture, forward() does NOT forward its tainted
// parameter. It passes a clean constant to runQuery() instead, so the
// composition (which is taint-flow-sensitive) records no params_to_sink flow
// and the chain BREAKS: no taint finding on a directory scan. The built-in
// Kotlin rules ship NO configured sanitizers, and the engine's tainted-name set
// is add-only (Kotlin parameters are `val`), so a fresh clean local passed to
// the helper is the break mechanism (a sanitizer call cannot be used here).

fun forward(term: String) {
    val safe = "constant"
    runQuery(safe)
}
