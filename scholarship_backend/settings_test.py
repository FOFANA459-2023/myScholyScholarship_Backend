"""Test settings.

The main settings module calls ``load_dotenv(override=True)``, so shell
environment variables cannot redirect the database. Tests therefore import the
real settings and override afterwards, which keeps the suite off the Supabase
instance entirely.

Run with:  python manage.py test --settings=scholarship_backend.settings_test
"""

from .settings import *  # noqa: F401,F403

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

# Throttling would make repeated login/contact assertions flaky.
REST_FRAMEWORK = {**REST_FRAMEWORK, "DEFAULT_THROTTLE_CLASSES": []}  # noqa: F405

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
