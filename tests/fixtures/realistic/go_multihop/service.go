// Middle helper (fileB) for the go_multihop fixture.
//
// loadFile() does NOT contain a sink itself — it forwards its argument to
// readData() in ANOTHER file (fileC) of the same package. Its single-file
// summary therefore records nothing; only after the bounded multi-hop
// composition (which resolves the same-package call to readData and sees that
// helper sink its param) does loadFile's summary gain params_to_sink = [0].
// That composed summary is what lets the caller in handlers.go fire.

package go_multihop

func loadFile(name string) []byte {
	return readData(name)
}
