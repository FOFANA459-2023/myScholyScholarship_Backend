"""Quota throttles for the AI endpoints.

Rolling 20-hour windows rather than calendar days, per the product rule:
whenever a visitor hits their limit, everything resets 20 hours after the
request that used it up.

Identification:
- Authenticated users are keyed by user id (their JWT proves who they are).
- Anonymous visitors are keyed by client IP. With ``NUM_PROXIES`` configured
  in settings, DRF derives the IP from the address our own reverse proxy
  appended to X-Forwarded-For - a client cannot spoof someone else's bucket
  by sending forged headers.

The cache keys hold only timestamps; no question text or personal data is
ever stored.
"""

from rest_framework.throttling import SimpleRateThrottle

TWENTY_HOURS = 20 * 3600


class QuotaThrottle(SimpleRateThrottle):
    """N requests per rolling 20-hour window, higher N for logged-in users."""

    window_seconds = TWENTY_HOURS
    anon_limit = 1
    user_limit = 5
    scope = "quota"

    def __init__(self):
        # Limits are decided per request (anon vs authenticated) in
        # get_cache_key, so skip SimpleRateThrottle's rate-string parsing.
        self.num_requests = None
        self.duration = self.window_seconds
        self.rate = "custom"

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            self.num_requests = self.user_limit
            ident = f"u{request.user.pk}"
        else:
            self.num_requests = self.anon_limit
            ident = self.get_ident(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}


class AssessmentQuotaThrottle(QuotaThrottle):
    """1 personalized assessment per 20h anonymously, 5 when logged in."""

    scope = "assessment_quota"
    anon_limit = 1
    user_limit = 5


class ChatQuotaThrottle(QuotaThrottle):
    """3 chat turns per 20h anonymously, 10 when logged in."""

    scope = "chat_quota"
    anon_limit = 3
    user_limit = 10
