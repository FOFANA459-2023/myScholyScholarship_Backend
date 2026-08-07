"""Project-wide DRF exception handling.

Turns throttle rejections into a friendly, non-technical message that tells
the visitor when to come back, instead of DRF's default
"Request was throttled. Expected available in 71997 seconds."
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
        message = (
            "You've reached your usage limit for now. It resets automatically - "
            f"please check back {_when(wait)}."
        )
        if is_anonymous:
            message += " Tip: logging in gives you a higher daily limit."
        response.data = {
            "error": message,
            "retry_after_seconds": wait,
        }

    return response
