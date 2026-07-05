// Middle helper (fileB) for the csharp_multihop fixture.
//
// Forward() does NOT contain a sink itself — it forwards its argument to
// QueryHelper.RunQuery() in ANOTHER file (fileC). Its single-file summary
// therefore records no params_to_sink; only after the bounded multi-hop
// composition (which resolves the same-directory call to RunQuery and sees that
// helper sink its param) does Forward's summary gain params_to_sink = [0]. That
// composed summary is what lets the caller in SearchHandler fire.

class Service {
    public static void Forward(string term) {
        QueryHelper.RunQuery(term);
    }
}
