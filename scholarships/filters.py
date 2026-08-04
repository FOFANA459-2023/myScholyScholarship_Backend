"""Server-side filtering for the scholarship board.

The frontend used to download every scholarship and filter in the browser.
Filtering happens here now, so the database does the work with index support
and the client only transfers the page it renders.
"""

import re

from django.db.models import Q
from django.utils import timezone

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


def _rows_matching_term(queryset, field, wanted):
    """Raw column values whose parsed terms include ``wanted``.

    Matching on the parsed terms keeps "Graduate" from selecting
    "Postgraduate" the way a substring match would, while still matching the
    rows stored as "Graduate, Postgraduate". The distinct list is small, and
    filtering on it stays a single indexed ``IN`` query.
    """
    target = wanted.casefold()
    return [
        raw
        for raw in queryset.values_list(field, flat=True).distinct()
        if any(term.casefold() == target for term in split_terms(raw))
    ]

ORDERING_FIELDS = {
    "newest": ("-created_at",),
    "oldest": ("created_at",),
    "deadline": ("deadline", "-created_at"),
    "name": ("name",),
}
DEFAULT_ORDERING = "newest"

TRUTHY = {"1", "true", "yes", "on"}


def _flag(params, key):
    return str(params.get(key, "")).strip().lower() in TRUTHY


def normalize_params(params):
    """Reduce raw query params to the canonical set we filter and cache on.

    Normalising first means ``?q=Chevening`` and ``?q=chevening&page=1`` share a
    cache entry instead of producing two identical-but-separate results.
    """
    ordering = str(params.get("ordering", "")).strip().lower()
    if ordering not in ORDERING_FIELDS:
        ordering = DEFAULT_ORDERING

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
        "ongoing": _flag(params, "ongoing"),
        "include_inactive": _flag(params, "include_inactive"),
        "ordering": ordering,
        "page": page,
        "page_size": page_size,
    }


def apply_filters(queryset, params, *, allow_inactive=False):
    """Apply normalized params to a Scholarship queryset."""
    if not (allow_inactive and params["include_inactive"]):
        queryset = queryset.active()

    if params["q"]:
        term = params["q"]
        queryset = queryset.filter(
            Q(name__icontains=term)
            | Q(host_country__icontains=term)
            | Q(degree_level__icontains=term)
        )

    if params["country"]:
        matches = _rows_matching_term(queryset, "host_country", params["country"])
        queryset = queryset.filter(host_country__in=matches) if matches else queryset.none()

    if params["degree"]:
        matches = _rows_matching_term(queryset, "degree_level", params["degree"])
        queryset = queryset.filter(degree_level__in=matches) if matches else queryset.none()

    if params["ongoing"]:
        queryset = queryset.filter(deadline__gte=timezone.now().date())

    return queryset.order_by(*ORDERING_FIELDS[params["ordering"]])
