"""Ranking for the "similar scholarships" strip on the detail page.

Pure Python over the live board rather than SQL: the board holds tens of
rows, every candidate has to be scored against the one being viewed, and the
result is cached in the version-scoped namespace anyway. Signals:

* same host country - the strongest predictor a student can actually apply
* overlapping degree levels ("Masters, PhD" shares a token with "Masters")
* shared meaningful words in the name, after stripping boilerplate that
  appears in almost every posting ("scholarship", "fully funded", years, ...)

Deadline proximity breaks ties, so among equals the most urgent one leads.
"""

import re

# Words that say nothing about what a scholarship actually is.
STOPWORDS = {
    "a", "an", "and", "at", "based", "fellowship", "for", "fully", "funded",
    "in", "international", "merit", "need", "of", "opportunities",
    "opportunity", "program", "programme", "scholarship", "scholarships",
    "the", "university",
}

_TOKEN_RE = re.compile(r"[a-z]+")


def _name_tokens(name):
    return {
        token
        for token in _TOKEN_RE.findall(name.lower())
        if len(token) > 2 and token not in STOPWORDS
    }


def _degree_tokens(degree_level):
    return set(_TOKEN_RE.findall(degree_level.lower()))


def score(target, candidate):
    """Similarity of ``candidate`` to ``target``. Higher is more similar."""
    points = 0
    if (
        target.host_country
        and target.host_country.strip().lower()
        == candidate.host_country.strip().lower()
    ):
        points += 3
    if _degree_tokens(target.degree_level) & _degree_tokens(candidate.degree_level):
        points += 2
    shared_words = _name_tokens(target.name) & _name_tokens(candidate.name)
    points += min(len(shared_words), 3)
    return points


def rank_similar(target, candidates, limit=4):
    """The ``limit`` most similar live scholarships, most similar first.

    Zero-score candidates still rank (a sparse board should never show an
    empty strip); they simply sort last, ordered by nearest deadline.
    """
    scored = sorted(
        (candidate for candidate in candidates if candidate.pk != target.pk),
        key=lambda c: (-score(target, c), c.deadline, -c.pk),
    )
    return scored[:limit]
