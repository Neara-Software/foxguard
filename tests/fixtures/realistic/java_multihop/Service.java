// Middle helper (fileB) for the java_multihop fixture.
//
// process() does NOT contain a sink itself — it forwards its argument to
// QueryHelper.runQuery() in ANOTHER file (fileC). Its single-file summary
// therefore records no params_to_sink; only after the bounded multi-hop
// composition (which resolves the same-package call to runQuery and sees that
// helper sink its param) does process's summary gain params_to_sink = [0].
// That composed summary is what lets the caller in SearchHandler fire.

class Service {
    static void process(String term) throws Exception {
        QueryHelper.runQuery(term);
    }
}
