# myScholy — Backend

[![CI](https://github.com/FOFANA459-2023/myScholyScholarship_Backend/actions/workflows/ci.yml/badge.svg)](https://github.com/FOFANA459-2023/myScholyScholarship_Backend/actions/workflows/ci.yml)

The Django REST API behind [myscholy.pages.dev](https://myscholy.pages.dev) — a scholarship board that helps students, starting with students across Africa, find opportunities they would otherwise miss. The frontend lives in its own repo: [myScholy](https://github.com/FOFANA459-2023/myScholy).

This API is the single source of truth for data and authentication. Supabase is used purely as the Postgres host and is never called from the browser. I built and operate the whole stack myself; it runs in production on an Oracle Cloud VM (Gunicorn behind Caddy, managed by systemd) with a warm standby on Render sharing the same database.

## What's in here

- Scholarship CRUD with filtering, pagination, cached list/detail reads, and streamed CSV exports
- JWT auth with rotating refresh tokens and role-based permissions (student, admin, super admin) backed by cached lookups
- AI features on the Gemini API with automatic Groq failover: a site assistant, a scholarship fit assessment, and an admin auto-fill that extracts a posting form from pasted text, a link, or a PDF (with an SSRF guard on the URL fetch)
- Transactional email (React Email templates via Resend/SMTP) and a scholarship digest that emails every student 5 live scholarships every 15 hours — guarded by a database record so two servers can never double-send
- A version-scoped cache design where one write invalidates every derived key at once (details below), plus ETags so repeat requests get a bodyless `304`
- CI on every push: Ruff, the full Django test suite with coverage, and automatic checks before anything deploys

## Getting started

```bash
pip install -r requirements.txt
cp .env.example .env      # fill in the database credentials
python manage.py migrate
python manage.py runserver
```

Tests run against in-memory SQLite and never touch the configured database:

```bash
python manage.py test --settings=scholarship_backend.settings_test
```

> The main settings module calls `load_dotenv(override=True)`, so shell
> environment variables cannot redirect the database. Always pass
> `--settings=scholarship_backend.settings_test` when running tests, otherwise
> Django will create a `test_postgres` database on the real server.

## Layout

| File | Purpose |
| --- | --- |
| `models.py` | Models, indexes, and the `ScholarshipQuerySet` helpers |
| `views.py` | Endpoints |
| `serializers.py` | Separate list/detail serializers plus validation |
| `filters.py` | Query-param normalisation and filtering |
| `pagination.py` | Page-number pagination with client-adjustable size |
| `permissions.py` | Cached role lookups (`IsAdmin`, `IsSuperAdmin`, …) |
| `cache.py` | Version-scoped cache keys, TTLs, ETag helpers |
| `signals.py` | Cache invalidation on writes |

## Caching

Cached reads live in a *namespace* whose version is an integer in the cache.
Keys embed that version, so a write bumps it and invalidates every derived key
at once — no need to enumerate the unbounded set of filter/page combinations.

```
scholarships:7:list:a91f2c...      <- version 7
                                      admin posts a scholarship -> version 8
scholarships:8:list:a91f2c...      <- recomputed on next read
```

`signals.py` bumps `scholarships` on any `Scholarship` write and `users` on any
`User`/`Student`/`Admin` write. Responses are therefore cached but never stale.

Cached endpoints also send an `ETag` derived from the same version, so
`ConditionalGetMiddleware` answers repeat requests with a `304` and no body.

| Endpoint | TTL |
| --- | --- |
| `GET /api/scholarships/` | 5 min |
| `GET /api/scholarships/{id}/` | 10 min |
| `GET /api/scholarships/facets/` | 15 min |
| `GET /api/admin/statistics/` | 2 min |
| role lookups (per request) | 5 min |

Set `REDIS_URL` in production to share the cache across Gunicorn workers.
Without it the app falls back to per-process local memory, which still removes
repeated database work within a worker.

## Endpoints

### Public

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/scholarships/` | Paginated, filterable, cached |
| GET | `/api/scholarships/{id}/` | Full record, cached |
| GET | `/api/scholarships/facets/` | Distinct countries and levels with counts |
| POST | `/api/contact/` | Contact form, 5/min per IP |
| POST | `/api/auth/login/` | Accepts a username or an email, 10/min per IP |
| POST | `/api/auth/student/register/` | Returns tokens so signup logs the user straight in |
| POST | `/api/auth/token/refresh/` | Rotating refresh tokens |

List query parameters: `q`, `country`, `degree`, `ongoing`, `ordering`
(`newest` \| `oldest` \| `deadline` \| `name`), `page`, `page_size` (max 100).

### Authenticated

| Method | Path | Requires |
| --- | --- | --- |
| GET | `/api/auth/profile/` | any signed-in user |
| POST | `/api/auth/logout/` | any signed-in user (blacklists the refresh token) |

### Admin

| Method | Path | Requires |
| --- | --- | --- |
| GET / POST | `/api/admin/scholarships/` | admin |
| GET / PUT / PATCH / DELETE | `/api/admin/scholarships/{id}/` | admin |
| GET | `/api/admin/statistics/` | admin |
| GET | `/api/admin/scholarships/export/` | admin (streamed CSV) |
| GET | `/api/admin/users/export/` | admin (streamed CSV) |
| GET | `/api/admin/contact/` | admin |
| GET / POST | `/api/admins/` | admin; creating a super admin requires super admin |
| PATCH / DELETE | `/api/admins/{user_id}/` | super admin |
| POST | `/api/auth/admin/register/` | admin |

## Deployment notes

- `DJANGO_DEBUG=False` switches on HSTS, secure cookies, the SSL redirect, and
  drops DRF's browsable API renderer.
- CORS uses an explicit allow-list. `CORS_ALLOW_ALL_ORIGINS` is deliberately not
  set — combining it with `CORS_ALLOW_CREDENTIALS` is rejected by browsers and
  would expose credentialed endpoints to any origin.
- `ETag` and `Cache-Control` are added to `CORS_EXPOSE_HEADERS` so the browser
  can use them.
- CORS allows `*.pages.dev` (Cloudflare Pages) out of the box. A custom
  frontend domain must be added via `DJANGO_CORS_ALLOWED_ORIGINS` on Render.

## Data hosting

The only database is the Supabase Postgres instance configured in `.env` —
there is no local SQLite database. Supabase is used purely as the Postgres
host: the browser never talks to it, all reads and writes go through this API,
and users live in Django's `auth_user` table with Django password hashing.
