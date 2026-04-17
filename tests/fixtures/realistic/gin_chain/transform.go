// Passthrough transform for the gin_chain fixture.
//
// normalize() receives a value and returns it after a trivial
// transformation. The cross-file summary should record
// params_to_return = [0] so callers see the return value as tainted.

package gin_chain

import "strings"

func normalize(value string) string {
	return strings.TrimSpace(value)
}
