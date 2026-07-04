# Negative multi-hop fixture (fileA — the source).
#
# Identical shape to python_multihop, but the MIDDLE helper sanitizes the
# tainted value before forwarding it. The multi-hop chain must therefore BREAK:
# no py/taint-sql-injection finding may be emitted on a directory scan.
#
# Expected findings on a directory scan:
#   (no taint rule)
#   py/no-sql-injection : 1  (regex hit on the concatenation in db.py)

from django.http import JsonResponse

from . import service


def search(request):
    q = request.GET["q"]
    rows = service.handle(q)
    return JsonResponse({"rows": rows})
