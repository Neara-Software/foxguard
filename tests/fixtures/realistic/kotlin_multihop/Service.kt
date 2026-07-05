// Middle helper (fileB) for the kotlin_multihop fixture.
//
// forward() does NOT contain a sink itself — it forwards its argument to
// runQuery() in ANOTHER file (fileC). Its single-file summary therefore records
// no params_to_sink; only after the bounded multi-hop composition (which
// resolves the same-directory call to runQuery and sees that helper sink its
// param) does forward's summary gain params_to_sink = [0]. That composed
// summary is what lets the caller in SearchHandler fire.

fun forward(term: String) {
    runQuery(term)
}
