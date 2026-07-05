// Middle helper (fileB) for the java_multihop_broken fixture.
//
// Unlike the positive fixture, process() does NOT forward its tainted
// parameter. It replaces the value with a constant before calling
// QueryHelper.runQuery(), so the composed summary must NOT record a
// params_to_sink flow and the chain breaks: no taint finding on a directory
// scan. (Java ships no configured sanitizer rules, so a clean reassignment
// stands in for the sanitizer-call break used by the other languages.)

class Service {
    static void process(String term) throws Exception {
        String safe = "constant";
        QueryHelper.runQuery(safe);
    }
}
