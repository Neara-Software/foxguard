// Passthrough transform for the express_chain fixture.
//
// normalize() receives a value and returns it after a trivial
// transformation. The cross-file summary should record
// params_to_return = [0] so callers see the return value as tainted.

function normalize(value) {
    return value.trim();
}

module.exports = { normalize };
