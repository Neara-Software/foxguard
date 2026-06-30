// Sink helper for the C# cross-file taint fixture.
//
// RunQuery() takes a parameter and passes it into a SqlCommand SQL sink. The
// pass-1 cross-file summary records params_to_sink for parameter 0 with rule
// csharp/taint-sql-injection. `term` is a plain parameter (not a taint
// source), so this file on its own produces no taint finding — the flow only
// exists once a tainted argument is passed in from Handler.cs.

using System.Data.SqlClient;

namespace Example.Chain
{
    public class QueryHelper
    {
        public static void RunQuery(string term)
        {
            string sql = "SELECT * FROM users WHERE name = '" + term + "'";
            var cmd = new SqlCommand(sql);
            cmd.ExecuteReader();
        }
    }
}
