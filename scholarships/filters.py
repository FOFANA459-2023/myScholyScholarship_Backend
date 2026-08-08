"""Server-side filtering for the scholarship board.

The frontend used to download every scholarship and filter in the browser.
Filtering happens here now, so the database does the work with index support
and the client only transfers the page it renders.
"""

import re

from django.db.models import Count, Q
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


# ---------------------------------------------------------------------------
# Canonical filter categories
# ---------------------------------------------------------------------------
# The board's dropdowns offer a fixed set of options rather than every
# distinct string an admin has ever typed. Rows keep their free-text values;
# each parsed term is *classified* into a category, so "MSc in Data Science"
# still lands under Graduate and "Multiple countries (France, Malta)" under
# Europe. Anything the classifier does not recognise simply stays reachable
# through search and the unfiltered board.

DEGREE_LEVELS = ("Undergraduate", "Graduate", "Postgraduate", "Non-degree")

# Terms that mean "every level" rather than one specific level.
_ALL_LEVEL_TERMS = {"any", "any level", "all", "all levels", "all degree levels"}


def classify_degree(term):
    """Degree categories a single parsed term belongs to.

    Substring checks are ordered so "graduate" never swallows
    "undergraduate"/"postgraduate", and anything that names no recognised
    degree (certificates, diplomas, exchanges, training...) falls through to
    Non-degree.
    """
    text = term.casefold()
    if text in _ALL_LEVEL_TERMS:
        return {"Undergraduate", "Graduate", "Postgraduate"}

    categories = set()
    if "undergraduate" in text or "undergrad" in text or "bachelor" in text:
        categories.add("Undergraduate")
    if (
        "postgraduate" in text
        or "post-graduate" in text
        or "postdoc" in text
        or "post-doc" in text
        or "phd" in text
        or "ph.d" in text
        or "doctor" in text
        or "dphil" in text
    ):
        categories.add("Postgraduate")
    if (
        "master" in text
        or "msc" in text
        or "m.sc" in text
        or "mba" in text
        or "mphil" in text
        or (
            "graduate" in text
            and "undergraduate" not in text
            and "postgraduate" not in text
            and "post-graduate" not in text
        )
    ):
        categories.add("Graduate")
    return categories or {"Non-degree"}


REGIONS = ("Africa", "Europe", "Australia", "Asia", "United States", "Canada")

_REGION_COUNTRIES = {
    "Africa": (
        "algeria", "angola", "benin", "botswana", "burkina faso", "burundi",
        "cabo verde", "cape verde", "cameroon", "central african republic",
        "chad", "comoros", "congo", "democratic republic of the congo",
        "dr congo", "djibouti", "egypt", "equatorial guinea", "eritrea",
        "eswatini", "swaziland", "ethiopia", "gabon", "gambia", "the gambia",
        "ghana", "guinea", "guinea-bissau", "ivory coast", "cote d'ivoire",
        "côte d'ivoire", "kenya", "lesotho", "liberia", "libya", "madagascar",
        "malawi", "mali", "mauritania", "mauritius", "morocco", "mozambique",
        "namibia", "niger", "nigeria", "rwanda", "sao tome and principe",
        "senegal", "seychelles", "sierra leone", "somalia", "south africa",
        "south sudan", "sudan", "tanzania", "togo", "tunisia", "uganda",
        "zambia", "zimbabwe",
    ),
    "Europe": (
        "albania", "andorra", "austria", "belarus", "belgium",
        "bosnia and herzegovina", "bulgaria", "croatia", "cyprus",
        "czech republic", "czechia", "denmark", "estonia", "finland",
        "france", "germany", "greece", "hungary", "iceland", "ireland",
        "italy", "kosovo", "latvia", "liechtenstein", "lithuania",
        "luxembourg", "malta", "moldova", "monaco", "montenegro",
        "netherlands", "the netherlands", "north macedonia", "norway",
        "poland", "portugal", "romania", "russia", "san marino", "serbia",
        "slovakia", "slovenia", "spain", "sweden", "switzerland", "ukraine",
        "united kingdom", "uk", "great britain", "england", "scotland",
        "wales", "northern ireland",
    ),
    "Australia": (
        "australia", "new zealand", "fiji", "papua new guinea", "samoa",
        "solomon islands", "tonga", "vanuatu",
    ),
    "Asia": (
        "afghanistan", "armenia", "azerbaijan", "bahrain", "bangladesh",
        "bhutan", "brunei", "cambodia", "china", "georgia", "hong kong",
        "india", "indonesia", "iran", "iraq", "israel", "japan", "jordan",
        "kazakhstan", "kuwait", "kyrgyzstan", "laos", "lebanon", "macau",
        "malaysia", "maldives", "mongolia", "myanmar", "nepal", "north korea",
        "oman", "pakistan", "palestine", "philippines", "qatar",
        "saudi arabia", "singapore", "south korea", "korea", "sri lanka",
        "syria", "taiwan", "tajikistan", "thailand", "timor-leste", "turkey",
        "türkiye", "turkiye", "turkmenistan", "united arab emirates", "uae",
        "uzbekistan", "vietnam", "yemen",
    ),
    "United States": (
        "united states", "united states of america", "usa", "us", "u.s.",
        "u.s.a.", "america",
    ),
    "Canada": ("canada",),
}

_COUNTRY_TO_REGION = {
    country: region
    for region, countries in _REGION_COUNTRIES.items()
    for country in countries
}

# Terms that mean "everywhere" rather than one place: those rows should be
# discoverable under every region rather than under none.
_GLOBAL_TERMS = {
    "worldwide", "global", "international", "any", "any country", "various",
    "various countries", "all countries", "multiple countries", "anywhere",
    "online", "remote",
}


def classify_region(term):
    """Regions a single parsed country term belongs to."""
    text = term.casefold().strip(" .")
    if text in _GLOBAL_TERMS:
        return set(REGIONS)

    region = _COUNTRY_TO_REGION.get(text)
    if region:
        return {region}

    # Free text like "Countries across Europe" names the region itself.
    found = set()
    for name, keyword in (
        ("Africa", "africa"),
        ("Europe", "europe"),
        ("Asia", "asia"),
        ("Australia", "australia"),
        ("Australia", "oceania"),
        ("United States", "united states"),
        ("Canada", "canada"),
    ):
        if keyword in text:
            found.add(name)
    return found


_CLASSIFIERS = {
    "host_country": classify_region,
    "degree_level": classify_degree,
}


def _category_map(field):
    """Map each canonical category to the raw column values it covers.

    Same shape and caching as ``_term_map``: built once from a distinct query,
    stored in the versioned scholarship namespace, invalidated by any write.
    """
    from .models import Scholarship

    classifier = _CLASSIFIERS[field]
    key = make_key(NS_SCHOLARSHIPS, "category-map", field=field)

    def build():
        mapping = {}
        rows = Scholarship.objects.values_list(field, flat=True).distinct()
        for raw in rows:
            categories = set()
            for term in split_terms(raw):
                categories |= classifier(term)
            for category in categories:
                mapping.setdefault(category.casefold(), []).append(raw)
        return mapping

    return cached(key, TTL_FACETS, build)


def _rows_matching_filter(field, wanted):
    """Raw column values a filter value selects.

    Canonical categories (the fixed dropdown options) resolve through the
    classifier; anything else - old bookmarked URLs, hand-typed queries -
    falls back to exact term matching so it keeps working.
    """
    rows = _category_map(field).get(wanted.casefold())
    if rows is not None:
        return rows
    return _rows_matching_term(field, wanted)


def category_facets(queryset, field, categories):
    """Counts per canonical category, in the fixed dropdown order.

    A row spanning several categories ("Masters, PhD") counts towards each,
    but only once per category.
    """
    classifier = _CLASSIFIERS[field]
    counts = {category: 0 for category in categories}
    rows = queryset.values(field).annotate(count=Count("id"))
    for row in rows:
        matched = set()
        for term in split_terms(row[field]):
            matched |= classifier(term)
        for category in matched:
            if category in counts:
                counts[category] += row["count"]
    return [{"value": category, "count": counts[category]} for category in categories]


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
        matches = _rows_matching_filter("host_country", params["country"])
        queryset = queryset.filter(host_country__in=matches) if matches else queryset.none()

    if params["degree"]:
        matches = _rows_matching_filter("degree_level", params["degree"])
        queryset = queryset.filter(degree_level__in=matches) if matches else queryset.none()

    return queryset.order_by(*ORDERING_FIELDS[params["ordering"]])
