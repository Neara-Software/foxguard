// Sink helper (fileC) for the java_multihop_broken fixture.
//
// Same sink as the positive fixture. The chain is broken upstream (in
// Service.process), so the only finding here is the single-file
// java/no-sql-injection regex heuristic on the concatenation.

import java.sql.Statement;

class QueryHelper {
    static Statement stmt;

    static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
