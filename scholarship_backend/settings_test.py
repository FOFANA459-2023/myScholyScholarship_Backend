"""Test settings.

The main settings module calls ``load_dotenv(override=True)``, so shell
environment variables cannot redirect the database. Tests therefore import the
real settings and override afterwards, which keeps the suite off the Supabase
instance entirely.

Run with:  python manage.py test --settings=scholarship_backend.settings_test
"""

from .settings import *  # noqa: F401,F403

# Pinned explicitly rather than inherited: DEBUG follows DJANGO_DEBUG, which
# is absent on CI but present in a developer's .env, so leaving these implicit
# made the suite behave differently depending on whether a .env file existed.
# With DEBUG off the production hardening block turns SECURE_SSL_REDIRECT on,
# and the test client speaks http:// - every request would answer 301.
DEBUG = False
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "myscholy-test",
    }
}

# Fast, deterministic hashing so account-creation tests are not CPU bound.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# Never talk to the real AI providers from tests; individual tests opt in
# with self.settings(GEMINI_API_KEY="test-key") around a mocked call.
GEMINI_API_KEY = ""
GROQ_API_KEY = ""

# Throttling would make repeated login/contact assertions flaky.
REST_FRAMEWORK = {**REST_FRAMEWORK, "DEFAULT_THROTTLE_CLASSES": []}  # noqa: F405

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
