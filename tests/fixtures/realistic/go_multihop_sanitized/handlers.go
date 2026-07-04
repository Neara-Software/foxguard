// Negative multi-hop fixture (fileA — the source).
//
// Identical shape to go_multihop, but the MIDDLE helper sanitizes the tainted
// value before forwarding it. The multi-hop chain must therefore BREAK: no
// go/taint-path-traversal finding may be emitted on a directory scan.
//
// Expected findings on a directory scan:
//   (no taint rule)

package go_multihop

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func search(c *gin.Context) {
	name := c.Query("name")
	data := loadFile(name)
	_ = data
	c.String(http.StatusOK, "ok")
}
