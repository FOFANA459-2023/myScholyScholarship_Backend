"""Settings for CI and local end-to-end runs.

Everything stays on the local disk: sqlite database, local-memory cache,
console email. Throttling is disabled because Playwright signs in repeatedly
and rate limits would make the suite flaky. Never deploy with this module.

Run the stack the e2e suite expects with:

    python manage.py migrate --noinput  --settings=scholarship_backend.settings_ci
    python manage.py seed_e2e           --settings=scholarship_backend.settings_ci
    python manage.py runserver 8001     --settings=scholarship_backend.settings_ci
"""

from .settings import *  # noqa: F401,F403
from .settings import BASE_DIR, REST_FRAMEWORK

DEBUG = True
ALLOWED_HOSTS = ["*"]

# settings.py evaluates its hardening block against the DEBUG value it derived
# from the environment, which on a fresh CI checkout (no .env) is False. That
# leaves SECURE_SSL_REDIRECT on even though DEBUG is overridden to True above,
# and Playwright drives this stack over plain http://localhost - every request
# would answer 301. Pin the values the local stack needs.
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "e2e.sqlite3",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "myscholy-e2e",
    }
}

REST_FRAMEWORK = {**REST_FRAMEWORK, "DEFAULT_THROTTLE_CLASSES": []}

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
RESEND_API_KEY = ""

# No AI in the e2e stack: the assistant widget hides, extraction reports
# unavailable, and the post-time duplicate check is skipped.
GEMINI_API_KEY = ""
GROQ_API_KEY = ""

# The Vite preview server the Playwright suite drives.
CORS_ALLOWED_ORIGINS = [
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]
