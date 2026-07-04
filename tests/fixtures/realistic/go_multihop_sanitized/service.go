// Middle helper (fileB) for the go_multihop_sanitized fixture.
//
// Unlike the positive fixture, loadFile() runs the tainted value through
// filepath.Clean() — a configured sanitizer for go/taint-path-traversal —
// before forwarding it to readData(). The sanitizer collapses the value to
// "clean", so the composed summary must NOT record a params_to_sink flow, and
// the chain breaks: no taint finding on a directory scan.

package go_multihop

import "path/filepath"

func loadFile(name string) []byte {
	safe := filepath.Clean(name)
	return readData(safe)
}
