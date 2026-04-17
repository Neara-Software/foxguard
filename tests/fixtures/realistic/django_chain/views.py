# Multi-hop taint chain fixture (issue #175).
#
# Three-file chain: views.py (source) -> middleware.py (passthrough) -> queries.py (sink)
#
# The taint flows:
#   1. request.GET["q"] in views.py (source)
#   2. -> middleware.transform(q) returns the tainted value (passthrough)
#   3. -> queries.run_query(cleaned) sinks into cur.execute (sink)
#
# Expected findings:
#   py/taint-sql-injection : 1  (multi-hop via middleware passthrough)

from django.http import JsonResponse

from . import middleware
from . import queries


def search(request):
    q = request.GET["q"]
    cleaned = middleware.transform(q)
    rows = queries.run_query(cleaned)
    return JsonResponse({"rows": rows})
