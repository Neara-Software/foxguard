// Sink helper (fileC) for the go_multihop fixture.
//
// readData() passes its parameter straight into os.ReadFile — a path-traversal
// sink. Its single-file summary records params_to_sink for param 0 with rule
// go/taint-path-traversal. Scanned alone, `name` is just a parameter (not a
// source), so no taint finding fires here.

package go_multihop

import "os"

func readData(name string) []byte {
	data, _ := os.ReadFile(name)
	return data
}
