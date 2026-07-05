// Sink helper (fileC) for the kotlin_multihop fixture.
//
// runQuery() concatenates its parameter into a SQL string and passes it to an
// executeQuery sink. Its single-file summary records params_to_sink for param 0
// with rule kotlin/taint-sql-injection. Scanned alone, `term` is just a
// parameter (not a source), so no taint finding fires here.

fun runQuery(term: String) {
    db.executeQuery("SELECT * FROM users WHERE name = '" + term + "'")
}
