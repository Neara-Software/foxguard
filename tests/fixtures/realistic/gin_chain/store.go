// Sink helper for the gin_chain fixture.
//
// runQuery() takes a parameter and passes it into a SQL sink.
// Cross-file summary should record params_to_sink for param 0
// with rule go/taint-sql-injection.

package gin_chain

import "database/sql"

var db *sql.DB

func runQuery(term string) []string {
	_, _ = db.Query("SELECT * FROM users WHERE name = '" + term + "'")
	return nil
}
