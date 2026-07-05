// Sink helper (fileC) for the csharp_multihop fixture.
//
// RunQuery() concatenates its parameter into a SQL string and passes it to a
// SqlCommand sink. Its single-file summary records params_to_sink for param 0
// with rule csharp/taint-sql-injection. Scanned alone, `term` is just a
// parameter (not a source), so no taint finding fires here.

using System.Data.SqlClient;

class QueryHelper {
    public static void RunQuery(string term) {
        string sql = "SELECT * FROM users WHERE name = '" + term + "'";
        var cmd = new SqlCommand(sql);
        cmd.ExecuteReader();
    }
}
