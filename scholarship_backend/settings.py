"""Django settings for the myScholy backend."""

import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env from BASE_DIR, falling back to the project root.
#
# override=False so a real environment variable always beats the file. The
# file used to win, which meant a deployment could not correct a setting
# without editing the file itself - a host whose .env said DJANGO_DEBUG=True
# stayed in debug no matter what its dashboard was configured to say.
if not load_dotenv(BASE_DIR / ".env", override=False):
    load_dotenv(BASE_DIR.parent / ".env", override=False)


def env_bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "changeme-in-dev")

# Secure by default: debug must be opted INTO, never inherited. Defaulting to
# True meant any host that simply had no DJANGO_DEBUG variable served Django's
# technical error pages publicly - source snippets, local variables, settings
# and the full URL map. Local development opts in through .env (see
# .env.example) and the e2e stack through settings_ci.
DEBUG = env_bool("DJANGO_DEBUG", False)

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS") or [
    "myscholyscholarship-backend.onrender.com",
    "localhost",
    "127.0.0.1",
    ".vercel.app",
    ".netlify.app",
]

CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS") or [
    "https://myscholyscholarship-backend.onrender.com",
    "https://myscholy.vercel.app",
    "https://*.pages.dev",
    "https://*.vercel.app",
    "https://*.netlify.app",
    "http://localhost:8000",
]

# Honour the X-Forwarded-Proto header set by Render's proxy.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
# Previously CORS_ALLOW_ALL_ORIGINS was combined with CORS_ALLOW_CREDENTIALS,
# which browsers reject and which would expose credentialed endpoints to any
# origin if it did work. Origins are now an explicit allow-list.

CORS_ALLOWED_ORIGINS = env_list("DJANGO_CORS_ALLOWED_ORIGINS") or [
    "https://myscholy.vercel.app",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]
# Cloudflare Pages previews/production plus the older Vercel/Netlify hosts.
# A custom domain (e.g. https://myscholy.com) must be added explicitly via the
# DJANGO_CORS_ALLOWED_ORIGINS env var on Render.
CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^https://.*\.pages\.dev$",
    r"^https://.*\.vercel\.app$",
    r"^https://.*\.netlify\.app$",
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "if-none-match",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]
# Let the browser read the validators it needs for conditional requests.
CORS_EXPOSE_HEADERS = ["ETag", "Cache-Control", "Content-Disposition"]
CORS_PREFLIGHT_MAX_AGE = 86400

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "scholarships",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    # Compresses JSON responses; list payloads shrink by roughly 70%.
    "django.middleware.gzip.GZipMiddleware",
    # Turns a matching ETag into a 304 with no body.
    "django.middleware.http.ConditionalGetMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "scholarship_backend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "scholarship_backend.wsgi.application"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Supabase's transaction pooler (PgBouncer) cannot hold server-side cursors or
# reuse connections across requests, so CONN_MAX_AGE stays 0 in that mode.

DB_PORT = os.environ.get("DB_PORT", "5432")
DB_POOL_MODE = os.environ.get("DB_POOL_MODE", "").lower()
# Port 6543 is Supabase's transaction pooler, so detect it even when
# DB_POOL_MODE has not been set explicitly.
USING_TRANSACTION_POOLER = DB_POOL_MODE == "transaction" or DB_PORT == "6543"

DATABASES = {
    "default": {
        "ENGINE": os.environ.get("DB_ENGINE", "django.db.backends.postgresql"),
        "NAME": os.environ.get("DB_NAME", "postgres"),
        "USER": os.environ.get("DB_USER", "postgres"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": DB_PORT,
        "CONN_MAX_AGE": 0 if USING_TRANSACTION_POOLER else env_int("DB_CONN_MAX_AGE", 60),
        "CONN_HEALTH_CHECKS": not USING_TRANSACTION_POOLER,
        "DISABLE_SERVER_SIDE_CURSORS": USING_TRANSACTION_POOLER,
        "OPTIONS": {
            "sslmode": os.environ.get("DB_SSLMODE", "require"),
            "connect_timeout": 10,
        },
    },
}

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
# Set REDIS_URL in production for a cache shared across workers. Without it we
# fall back to per-process local memory, which still removes the repeated
# database work within a worker.

REDIS_URL = os.environ.get("REDIS_URL", "").strip()

if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "KEY_PREFIX": "myscholy",
            "TIMEOUT": 300,
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "myscholy-local",
            "TIMEOUT": 300,
            "OPTIONS": {"MAX_ENTRIES": 5000, "CULL_FREQUENCY": 4},
        }
    }

# ---------------------------------------------------------------------------
# REST framework
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    # Behind Caddy (Oracle) / Render's proxy REMOTE_ADDR is the proxy, not the
    # visitor. One trusted proxy means DRF reads the client IP our proxy
    # appended to X-Forwarded-For - forged headers from clients cannot spoof
    # another visitor's throttle bucket.
    "NUM_PROXIES": 1,
    # Friendly throttle messages ("check back in about N hours").
    "EXCEPTION_HANDLER": "scholarships.exceptions.friendly_exception_handler",
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PAGINATION_CLASS": "scholarships.pagination.DefaultPagination",
    "PAGE_SIZE": 24,
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.AnonRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "120/min",
        "login": "10/min",
        "contact": "5/min",
        "password_reset": "5/min",
        # Keeps the Gemini free tier from being drained by one visitor.
        "assistant": "8/min",
    },
    # The browsable API renderer is convenient locally but adds noticeable
    # overhead and surface area in production.
    "DEFAULT_RENDERER_CLASSES": (
        [
            "rest_framework.renderers.JSONRenderer",
            "rest_framework.renderers.BrowsableAPIRenderer",
        ]
        if DEBUG
        else ["rest_framework.renderers.JSONRenderer"]
    ),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
}

# ---------------------------------------------------------------------------
# Email (Resend + templates) / password reset
# ---------------------------------------------------------------------------
# Production email goes through the Resend API (scholarships/emails.py).
# RESEND_API_KEY is a secret: set it only in the server-side environment
# (.env locally, the Render dashboard in production) - it is gitignored and
# must never reach the frontend or version control. With Resend,
# DEFAULT_FROM_EMAIL must use a domain verified in the Resend dashboard
# (resend.com/domains); "onboarding@resend.dev" works for testing only.
#
# Without a Resend key the app falls back to the SMTP settings below, and
# without SMTP credentials emails print to the runserver console (local dev).

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()

EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = env_int("EMAIL_PORT", 587)
EMAIL_USE_TLS = env_bool("EMAIL_USE_TLS", True)
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "myscholy@gmail.com")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "myScholy <myscholy@gmail.com>")
# Where public contact-form submissions are delivered.
CONTACT_INBOX = os.environ.get("CONTACT_INBOX", "myscholy@gmail.com")
EMAIL_BACKEND = (
    "django.core.mail.backends.smtp.EmailBackend"
    if EMAIL_HOST_PASSWORD
    else "django.core.mail.backends.console.EmailBackend"
)

# Reset links die after an hour rather than Django's default three days.
PASSWORD_RESET_TIMEOUT = env_int("PASSWORD_RESET_TIMEOUT", 3600)

# ---------------------------------------------------------------------------
# Site assistant (Google Gemini)
# ---------------------------------------------------------------------------
# SECRET - server-side only, like RESEND_API_KEY. Without a key the assistant
# endpoints report themselves disabled and the frontend hides the widget
# entirely (which also keeps it out of the e2e suite's way).

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
# "gemini-flash-lite-latest" is Google's rolling alias for the current
# low-latency flash-lite model: it survives model deprecations without a code
# change and answers in ~1-2s, where the full flash models' "thinking" phase
# can blow past the request timeout.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest").strip()

# SECRET - fallback provider. When Gemini answers 429 the assistant fails
# over to Groq for a minute and back again; with no Groq key configured the
# assistant simply reports busy instead.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile").strip()

# Where reset links point; the deployed frontend origin in production.
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:5173").rstrip("/")

# ---------------------------------------------------------------------------
# Auth / i18n / static
# ---------------------------------------------------------------------------

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 8},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}
WHITENOISE_MAX_AGE = 31536000  # hashed filenames, safe to cache for a year

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Production hardening
# ---------------------------------------------------------------------------

if not DEBUG:
    SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", True)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = env_int("DJANGO_HSTS_SECONDS", 31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_REFERRER_POLICY = "same-origin"
    X_FRAME_OPTIONS = "DENY"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"simple": {"format": "{levelname} {name} {message}", "style": "{"}},
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "simple"},
    },
    "root": {"handlers": ["console"], "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO")},
}
