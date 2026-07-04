// Sink helper (fileC) for the go_multihop_sanitized fixture.
//
// Same sink as the positive fixture. The chain is broken upstream (in
// loadFile via filepath.Clean), so no taint finding fires on a directory scan.

package go_multihop

import "os"

func readData(name string) []byte {
	data, _ := os.ReadFile(name)
	return data
}
