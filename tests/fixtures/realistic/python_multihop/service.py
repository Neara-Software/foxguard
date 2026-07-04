# Middle helper (fileB) for the python_multihop fixture.
#
# handle() does NOT contain a sink itself — it forwards its argument to
# db.run_query() in ANOTHER file (fileC). Its single-file summary therefore
# records nothing; only after the bounded multi-hop composition (which resolves
# the cross-file call to db.run_query and sees that helper sink its param) does
# handle's summary gain params_to_sink = [0]. That composed summary is what lets
# the caller in views.py fire.

from . import db


def handle(term):
    return db.run_query(term)
