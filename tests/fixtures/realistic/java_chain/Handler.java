// Cross-file taint fixture for the Java taint engine (taint-expansion).
//
// Two-file chain: Handler.java (source) -> QueryHelper.java (sink).
//
// Flow:
//   1. @RequestParam String name in Handler.search (source)
//   2. -> QueryHelper.runQuery(name): the pass-1 summary records that
//      parameter 0 of runQuery reaches an executeQuery sink, so passing a
//      tainted argument into it produces a cross-file finding here in
//      Handler.java.
//
// Expected when scanning the directory:
//   java/taint-sql-injection : 1   (cross-file, reported in Handler.java)
//
// Scanning Handler.java ALONE must produce 0 java/taint-sql-injection
// findings: the helper body is unseen and `runQuery` is not itself a sink.

package com.example.chain;

import org.springframework.web.bind.annotation.RequestParam;

public class Handler {
    public void search(@RequestParam String name) throws Exception {
        QueryHelper.runQuery(name);
    }
}
