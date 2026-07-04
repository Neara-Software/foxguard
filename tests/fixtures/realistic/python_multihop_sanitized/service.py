# Middle helper (fileB) for the python_multihop_sanitized fixture.
#
# Unlike the positive fixture, handle() runs the tainted value through
# escape_string() — a configured sanitizer for py/taint-sql-injection — before
# forwarding it to db.run_query(). The sanitizer collapses the value to "clean",
# so the composed summary must NOT record a params_to_sink flow, and the chain
# breaks: no taint finding on a directory scan.

from . import db


def handle(term):
    safe = escape_string(term)
    return db.run_query(safe)
