// Sink helper for the Java cross-file taint fixture.
//
// runQuery() takes a parameter and passes it into a JDBC SQL sink. The
// pass-1 cross-file summary records params_to_sink for parameter 0 with
// rule java/taint-sql-injection. `term` is a plain parameter (not a taint
// source), so this file on its own produces no taint finding — the flow
// only exists once a tainted argument is passed in from Handler.java.

package com.example.chain;

import java.sql.Statement;

public class QueryHelper {
    static Statement stmt;

    public static void runQuery(String term) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + term + "'");
    }
}
