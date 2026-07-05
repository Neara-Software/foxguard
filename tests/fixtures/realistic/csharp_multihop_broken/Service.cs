// Middle helper (fileB) for the csharp_multihop_broken fixture.
//
// Unlike the positive fixture, Forward() does NOT forward its tainted
// parameter. It passes a clean constant to QueryHelper.RunQuery() instead, so
// the composition (which is taint-flow-sensitive) records no params_to_sink
// flow and the chain BREAKS: no taint finding on a directory scan. C#'s rules
// DO ship sanitizers (e.g. int.Parse, HttpUtility.HtmlEncode), so a sanitizer
// call would break the chain equally; a clean value is used here for symmetry
// with the other multi-hop negatives.

class Service {
    public static void Forward(string term) {
        string safe = "constant";
        QueryHelper.RunQuery(safe);
    }
}
