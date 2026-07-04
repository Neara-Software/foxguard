# Sink helper (fileC) for the python_multihop_sanitized fixture.
#
# Same sink as the positive fixture. The chain is broken upstream (in
# service.handle), so the only finding here is the single-file regex heuristic.

import sqlite3


def run_query(term):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + term + "'")
    return cur.fetchall()
