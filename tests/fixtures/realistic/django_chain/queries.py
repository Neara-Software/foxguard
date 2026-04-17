# Sink helper for the django_chain fixture.
#
# run_query() takes a parameter and passes it into a SQL sink.
# Cross-file summary should record params_to_sink for param 0
# with rule py/taint-sql-injection.

import sqlite3


def run_query(term):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + term + "'")
    return cur.fetchall()
