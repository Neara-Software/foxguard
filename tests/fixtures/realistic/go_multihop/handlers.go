// Bounded multi-hop taint chain fixture (fileA — the source).
//
// Three-file, same-package Go chain where the MIDDLE helper itself makes the
// cross-file call:
//
//   handlers.go (source)  ->  loadFile()  ->  readData() (sink)
//      fileA                    fileB              fileC
//
// Unlike gin_chain (where the caller orchestrates both hops in one handler),
// here fileB's `loadFile` calls fileC's `readData` directly — so the chain
// A->f->g->sink is only found once fileB's summary is composed one hop deeper
// against fileC's summary (the scanner's bounded multi-hop fixpoint). Scanning
// any single file finds no taint finding; only the full-directory scan resolves
// the chain.
//
// The chain uses go/taint-path-traversal (not sql-injection) because that rule
// has a configured sanitizer (filepath.Clean), which the negative variant
// (go_multihop_sanitized) uses to break the chain.
//
// Expected findings on a directory scan:
//   go/taint-path-traversal : 1  (multi-hop: handlers -> loadFile -> readData)

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
