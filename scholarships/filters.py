"""Server-side filtering for the scholarship board.

The frontend used to download every scholarship and filter in the browser.
Filtering happens here now, so the database does the work with index support
and the client only transfers the page it renders.
"""

import re

from django.db.models import Q
from django.utils import timezone

from .cache import NS_SCHOLARSHIPS, TTL_FACETS, cached, make_key

# A parenthesised list, e.g. "Multiple countries (France, Malta, Germany)".
_LIST_IN_PARENS = re.compile(r"\(([^)]*,[^)]*)\)")
_SEPARATORS = re.compile(r"[,/;]|\band\b|&", re.IGNORECASE)


def split_terms(value):
    """Break a stored field into the individual terms it actually represents.

    Scholarships store these as free text, so one row may cover several values:
    ``"Graduate, Postgraduate"`` or
    ``"Multiple countries (France, Malta, Germany)"``. Treating those strings as
    single options gave the filter dropdowns overlapping entries that matched
    only part of the rows they should.
    """
    text = (value or "").strip()
    if not text:
        return []

    inner = _LIST_IN_PARENS.search(text)
    if inner:
        text = inner.group(1)

    terms = []
    seen = set()
    for part in _SEPARATORS.split(text):
        term = part.strip(" .\t")
        key = term.casefold()
        if term and key not in seen:
            seen.add(key)
            terms.append(term)
    return terms


def _term_map(field):
    """Map each parsed term to the raw column values that contain it.

    Built over the whole table from one distinct query and cached in the
    versioned scholarship namespace, so a filtered request costs zero extra
    queries. Values coming from rows the current visibility filter excludes
    simply match nothing, so one table-wide map serves every view. Any write
    bumps the version and the map rebuilds.
    """
    from .models import Scholarship

    key = make_key(NS_SCHOLARSHIPS, "term-map", field=field)

    def build():
        mapping = {}
        rows = Scholarship.objects.values_list(field, flat=True).distinct()
        for raw in rows:
            for term in split_terms(raw):
                mapping.setdefault(term.casefold(), []).append(raw)
        return mapping

    return cached(key, TTL_FACETS, build)


def _rows_matching_term(field, wanted):
    """Raw column values whose parsed terms include ``wanted``.

    Matching on the parsed terms keeps "Graduate" from selecting
    "Postgraduate" the way a substring match would, while still matching the
    rows stored as "Graduate, Postgraduate". The list is small, and filtering
    on it stays a single indexed ``IN`` query.
    """
    return _term_map(field).get(wanted.casefold(), [])

ORDERING_FIELDS = {
    "newest": ("-created_at",),
    "oldest": ("created_at",),
    "deadline": ("deadline", "-created_at"),
    "name": ("name",),
}
DEFAULT_ORDERING = "newest"

# What slice of the catalogue a request sees.
#   live     - active AND the deadline has not passed; the only view the
#              public board ever gets.
#   archived - hidden by an admin OR past its deadline; the admin archive.
#   all      - everything; used by the admin client to build its local index.
VIEWS = {"live", "archived", "all"}
DEFAULT_VIEW = "live"


def normalize_params(params, *, allow_privileged=False):
    """Reduce raw query params to the canonical set we filter and cache on.

    Normalising first means ``?q=Chevening`` and ``?q=chevening&page=1`` share a
    cache entry instead of producing two identical-but-separate results.
    ``view`` is coerced back to "live" for unprivileged callers *before*
    caching, so an anonymous ``?view=archived`` cannot mint extra cache keys.
    """
    ordering = str(params.get("ordering", "")).strip().lower()
    if ordering not in ORDERING_FIELDS:
        ordering = DEFAULT_ORDERING

    view = str(params.get("view", "")).strip().lower()
    if view not in VIEWS or not allow_privileged:
        view = DEFAULT_VIEW

    try:
        page = max(1, int(params.get("page", 1)))
    except (TypeError, ValueError):
        page = 1

    page_size = params.get("page_size")
    try:
        page_size = min(100, max(1, int(page_size))) if page_size else None
    except (TypeError, ValueError):
        page_size = None

    return {
        "q": str(params.get("q", "")).strip()[:120],
        "country": str(params.get("country", "")).strip()[:100],
        "degree": str(params.get("degree", "")).strip()[:100],
        "view": view,
        "ordering": ordering,
        "page": page,
        "page_size": page_size,
    }


def apply_view(queryset, view):
    """Restrict a queryset to one of the three catalogue views."""
    today = timezone.now().date()
    if view == "archived":
        return queryset.filter(Q(is_active=False) | Q(deadline__lt=today))
    if view == "all":
        return queryset
    return queryset.active().filter(deadline__gte=today)


def apply_filters(queryset, params):
    """Apply normalized params to a Scholarship queryset."""
    queryset = apply_view(queryset, params["view"])

    if params["q"]:
        term = params["q"]
        queryset = queryset.filter(
            Q(name__icontains=term)
            | Q(host_country__icontains=term)
            | Q(degree_level__icontains=term)
        )

    if params["country"]:
        matches = _rows_matching_term("host_country", params["country"])
        queryset = queryset.filter(host_country__in=matches) if matches else queryset.none()

    if params["degree"]:
        matches = _rows_matching_term("degree_level", params["degree"])
        queryset = queryset.filter(degree_level__in=matches) if matches else queryset.none()

    return queryset.order_by(*ORDERING_FIELDS[params["ordering"]])
