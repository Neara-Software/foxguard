// Bounded multi-hop taint chain fixture (fileA — the source).
//
// Three-file C# chain where the MIDDLE helper itself makes the cross-file
// call:
//
//   SearchHandler.Search()  ->  Service.Forward()  ->  QueryHelper.RunQuery()
//        fileA (source)             fileB                    fileC (sink)
//
// fileB's `Forward` calls fileC's `RunQuery` directly — so the chain
// A->f->g->sink is only found once fileB's summary is composed one hop deeper
// against fileC's summary. Scanning any single file finds no taint finding;
// only the full-directory scan resolves the chain.

using System.Web;

class SearchHandler {
    public void Search() {
        string name = Request.QueryString["name"];
        Service.Forward(name);
    }
}
