"""Project-wide DRF exception handling.

Turns throttle rejections into intentional, professional messages (no
contractions) instead of DRF's default "Request was throttled. Expected
available in 71997 seconds." Each audience gets its own message:

- Guests are told they have reached the guest limit and invited to log in,
  because logging in genuinely unlocks a higher allowance.
- Logged-in users are told when their allowance resets, because there is
  nothing further to unlock.
"""

import math

from rest_framework.exceptions import Throttled
from rest_framework.views import exception_handler


def _when(wait_seconds):
    if wait_seconds >= 3600:
        hours = math.ceil(wait_seconds / 3600)
        return f"in about {hours} hour{'s' if hours != 1 else ''}"
    if wait_seconds >= 60:
        minutes = math.ceil(wait_seconds / 60)
        return f"in about {minutes} minute{'s' if minutes != 1 else ''}"
    return "in a moment"


def friendly_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if isinstance(exc, Throttled) and response is not None:
        wait = int(exc.wait or 0)
        request = context.get("request")
        is_anonymous = not (
            request and request.user and request.user.is_authenticated
        )

        if is_anonymous:
            message = (
                "You have reached the limit for guests. Please log in to "
                "continue - registered users receive a higher daily allowance."
            )
        else:
            message = (
                "You have reached your daily limit. It resets automatically - "
                f"please check back {_when(wait)}."
            )

        response.data = {
            "error": message,
            "requires_login": is_anonymous,
            "retry_after_seconds": wait,
        }

    return response
