// Negative multi-hop fixture (fileA — the source).
//
// Identical shape to java_multihop, but the MIDDLE helper drops the tainted
// value before forwarding (see Service.java). The multi-hop chain must
// therefore BREAK: no java/taint-sql-injection finding may be emitted on a
// directory scan.
//
// Java's built-in taint rules ship NO configured sanitizers (every TaintSpec
// has `sanitizers: vec![]`), so — unlike the Python/JS/Go negative fixtures,
// which route the value through a real sanitizer call (escape_string /
// mysql.escape / filepath.Clean) — this fixture breaks the chain the only way
// available without a custom rule: the middle helper replaces its tainted
// parameter with a constant before the cross-file call. The composition is
// taint-flow-sensitive, so a clean argument records no params_to_sink and the
// chain does not resolve. See docs/taint-tracking.md.
//
// Expected findings on a directory scan:
//   (no java/taint-* rule)
//   java/no-sql-injection : 1  (regex hit on the concatenation in QueryHelper)

import javax.servlet.http.HttpServletRequest;

class SearchHandler {
    void search(HttpServletRequest request) throws Exception {
        String q = request.getParameter("q");
        Service.process(q);
    }
}
