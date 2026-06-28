// Query helpers for the java_spring_shop fixture (package com.example.shop.data).
//
// `runQuery` takes a parameter that is tainted when called from the controller
// in UserController.java and concatenates it directly into a SQL string passed
// to Statement.executeQuery. Scanned in isolation this file has no request
// source, so only the cross-file caller produces a taint finding.

package com.example.shop.data;

import java.sql.Statement;

public class UserQueries {

    private static Statement stmt;

    public static String runQuery(String name) throws Exception {
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        return stmt.executeQuery(query).toString();
    }
}
