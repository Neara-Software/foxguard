# Sink helper (fileC) for the python_multihop fixture.
#
# run_query() concatenates its parameter into a SQL string and passes it to a
# cursor.execute sink. Its single-file summary records params_to_sink for
# param 0 with rule py/taint-sql-injection. Scanned alone, `term` is just a
# parameter (not a source), so no taint finding fires here.

import sqlite3


def run_query(term):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + term + "'")
    return cur.fetchall()
