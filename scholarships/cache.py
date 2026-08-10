"""Caching helpers.

Everything cacheable in this app hangs off a *namespace version*: a plain
integer stored in the cache. Cache keys embed that version, so bumping it
invalidates every derived key at once. That avoids having to enumerate the
(unbounded) set of filter/pagination permutations we may have cached, and it
works identically on LocMemCache in development and Redis in production.
"""

import hashlib
import json
import time

from django.core.cache import cache

# Namespaces that can be invalidated independently.
NS_SCHOLARSHIPS = "scholarships"
NS_USERS = "users"

# Time-to-live, in seconds.
TTL_LIST = 300  # public scholarship listings
TTL_DETAIL = 600  # a single scholarship
TTL_FACETS = 900  # distinct countries / degree levels
TTL_STATISTICS = 120  # admin dashboard numbers
TTL_ROSTER = 30  # admin user roster; short so direct DB edits surface fast
TTL_PERMISSION = 300  # "is this user an admin?" lookups

_VERSION_TTL = None  # never expire the version counter itself


def _version_key(namespace):
    return f"v:{namespace}"


def _seed_version():
    """Initial version for a namespace whose counter is missing.

    Seeded from the clock rather than a constant: on LocMemCache the counter
    vanishes on every restart, and reseeding to a fixed number would reissue
    ETags from before the restart. Browsers holding a response from an earlier
    deploy would then revalidate to a 304 and keep a stale body indefinitely
    (until the next write happened to bump the version past the old one). A
    time-based seed makes every restart a cache bust instead. On Redis the
    counter persists, so this only runs on the very first boot.
    """
    return int(time.time())


def get_version(namespace):
    """Current version of a namespace, seeding it on first use."""
    key = _version_key(namespace)
    version = cache.get(key)
    if version is None:
        version = _seed_version()
        cache.set(key, version, _VERSION_TTL)
    return version


def bump_version(namespace):
    """Invalidate every key in a namespace. Called from model signals."""
    key = _version_key(namespace)
    try:
        return cache.incr(key)
    except ValueError:
        # Key had expired or was never set - reseed it.
        version = _seed_version()
        cache.set(key, version, _VERSION_TTL)
        return version


def make_key(namespace, name, **params):
    """Build a stable, version-scoped cache key.

    Params are hashed rather than interpolated so that long search strings and
    unicode input can never blow past a memcached key length limit or contain
    illegal characters.
    """
    version = get_version(namespace)
    if params:
        payload = json.dumps(params, sort_keys=True, default=str)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return f"{namespace}:{version}:{name}:{digest}"
    return f"{namespace}:{version}:{name}"


def cached(key, ttl, producer):
    """Return the cached value for ``key``, computing it via ``producer`` on miss."""
    value = cache.get(key)
    if value is None:
        value = producer()
        cache.set(key, value, ttl)
    return value


def etag_for(namespace, **params):
    """Weak ETag derived from the namespace version plus request params.

    Any write bumps the version, so the ETag changes exactly when the
    underlying data could have changed.
    """
    payload = json.dumps(
        {"v": get_version(namespace), **params}, sort_keys=True, default=str
    )
    return '"%s"' % hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def invalidate_scholarships():
    bump_version(NS_SCHOLARSHIPS)


def invalidate_users():
    bump_version(NS_USERS)
