// Sink helper (fileC) for the java_multihop fixture.
//
// runQuery() concatenates its parameter into a SQL string and passes it to an
// executeQuery sink. Its single-file summary records params_to_sink for param 0
// with rule java/taint-sql-injection. Scanned alone, `term` is just a parameter
// (not a source), so no taint finding fires here — only the conservative
// java/no-sql-injection regex heuristic trips on the concatenation.

import java.sql.Statement;

class QueryHelper {
    static Statement stmt;

    static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
