// Sink helper for the express_chain fixture.
//
// runQuery() takes a parameter and passes it into a SQL sink.
// Cross-file summary should record params_to_sink for param 0
// with rule js/taint-sql-injection.

const db = { query(_q) { return []; } };

function runQuery(term) {
    return db.query("SELECT * FROM users WHERE name = '" + term + "'");
}

module.exports = { runQuery };
