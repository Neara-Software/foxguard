// Multi-file Spring shop fixture (Java cross-file taint).
//
// Request sources live here in the web controller; the SQL sink lives in
// UserQueries.java (package com.example.shop.data). The controller imports
// UserQueries and calls its static helper, so cross-file taint analysis must
// trace the @RequestParam value into the callee's executeQuery sink.
//
// Hand-counted expected taint findings:
//   java/taint-sql-injection : 1  (cross-file: search -> UserQueries.runQuery)
//
// The NEAR-MISS handler passes a string literal and must not fire.

package com.example.shop.web;

import com.example.shop.data.UserQueries;

public class UserController {

    // Cross-file flow: tainted `name` is passed into UserQueries.runQuery,
    // which concatenates it into SQL and calls Statement.executeQuery.
    public String search(@RequestParam String name) throws Exception {
        return UserQueries.runQuery(name);
    }

    // NEAR MISS: the argument is a fixed literal, so no taint reaches the sink.
    public String searchAll() throws Exception {
        return UserQueries.runQuery("all");
    }
}
