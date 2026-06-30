// Cross-file taint fixture for the C# taint engine (taint-expansion).
//
// Two-file chain: Handler.cs (source) -> QueryHelper.cs (sink).
//
// Flow:
//   1. Request.QueryString["name"] in Handler.Search (source)
//   2. -> QueryHelper.RunQuery(name): the pass-1 summary records that
//      parameter 0 of RunQuery reaches a SqlCommand SQL sink, so passing a
//      tainted argument into it produces a cross-file finding here in
//      Handler.cs.
//
// Expected when scanning the directory:
//   csharp/taint-sql-injection : 1   (cross-file, reported in Handler.cs)
//
// Scanning Handler.cs ALONE must produce 0 csharp/taint-sql-injection
// findings: the helper body is unseen and `RunQuery` is not itself a sink.

using System.Web;

namespace Example.Chain
{
    public class Handler
    {
        public void Search()
        {
            string name = Request.QueryString["name"];
            QueryHelper.RunQuery(name);
        }
    }
}
