// Multi-hop taint chain fixture (issue #175).
//
// Three-file chain: handlers.go (source) -> transform.go (passthrough) -> store.go (sink)
//
// The taint flows:
//   1. c.Query("q") in handlers.go (source)
//   2. -> normalize(q) in transform.go returns the tainted value (passthrough)
//   3. -> runQuery(result) in store.go sinks into db.Query (sink)
//
// Expected findings:
//   go/taint-sql-injection : 1  (multi-hop via transform passthrough)

package gin_chain

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func search(c *gin.Context) {
	q := c.Query("q")
	cleaned := normalize(q)
	rows := runQuery(cleaned)
	_ = rows
	c.String(http.StatusOK, "ok")
}
