# Bounded multi-hop taint chain fixture (fileA — the source).
#
# Three-file chain where the MIDDLE helper itself makes the cross-file call:
#
#   views.py (source)  ->  service.handle()  ->  db.run_query() (sink)
#      fileA                    fileB                  fileC
#
# Unlike django_chain (where the caller orchestrates both hops in one
# function), here fileB's `handle` calls fileC's `run_query` directly — so
# the chain A->f->g->sink is only found once fileB's summary is composed one
# hop deeper against fileC's summary. Scanning any single file finds no taint
# finding; only the full-directory scan resolves the chain.
#
# Expected findings on a directory scan:
#   py/taint-sql-injection : 1  (multi-hop: views -> service -> db)
#   py/no-sql-injection    : 1  (regex hit on the concatenation in db.py)

from django.http import JsonResponse

from . import service


def search(request):
    q = request.GET["q"]
    rows = service.handle(q)
    return JsonResponse({"rows": rows})
