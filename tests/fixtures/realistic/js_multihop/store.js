// Sink helper (fileC) for the js_multihop fixture.
//
// runQuery() concatenates its parameter into a SQL string and passes it to a
// db.query sink. Its single-file summary records params_to_sink for param 0
// with rule js/taint-sql-injection. Scanned alone, `term` is just a parameter
// (not a source), so no taint finding fires here.

const db = { query(_q) { return []; } };

function runQuery(term) {
    return db.query("SELECT * FROM users WHERE name = '" + term + "'");
}

module.exports = { runQuery };
