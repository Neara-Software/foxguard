// Bounded multi-hop taint chain fixture (fileA — the source).
//
// Three-file Java chain where the MIDDLE helper itself makes the cross-file
// call:
//
//   SearchHandler.search()  ->  Service.process()  ->  QueryHelper.runQuery()
//        fileA (source)             fileB                   fileC (sink)
//
// Unlike java_spring_controller (where one handler orchestrates the whole
// flow), here fileB's `process` calls fileC's `runQuery` directly — so the
// chain A->f->g->sink is only found once fileB's summary is composed one hop
// deeper against fileC's summary. Scanning any single file finds no taint
// finding; only the full-directory scan resolves the chain.
//
// Expected findings on a directory scan:
//   java/taint-sql-injection : 1  (multi-hop: SearchHandler -> Service -> QueryHelper)
//   java/no-sql-injection    : 1  (regex hit on the concatenation in QueryHelper)

import javax.servlet.http.HttpServletRequest;

class SearchHandler {
    void search(HttpServletRequest request) throws Exception {
        String q = request.getParameter("q");
        Service.process(q);
    }
}
