# Backend CI/CD setup (Oracle Cloud primary, Render secondary)

Workflows in this repo:

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | every PR + push to main | ruff lint, Django tests with coverage, pip-audit; deploys **only from main** after all gates pass — Render (deploy hook) and the Oracle Cloud VM (SSH: pull, migrate, collectstatic, restart, health check) |
| `pr-review.yml` | every PR | dependency review (active now) + Claude automated review (activates when `ANTHROPIC_API_KEY` is added; skips quietly until then) |
| `codeql.yml` | PRs, main, weekly | Python static security analysis |

## One-time repository configuration

Add these at
<https://github.com/FOFANA459-2023/myScholyScholarship_Backend/settings/secrets/actions>.
**GitHub Actions cannot read a `.env` file** - your local `backend/.env` is
only a personal record; the values must be entered here.

**Secrets** (Secrets tab → "New repository secret")

| Secret | Value |
| --- | --- |
| `RENDER_DEPLOY_HOOK_URL` | the deploy hook URL in your local `backend/.env` |
| `RENDER_API_KEY` | a Render API key (dashboard.render.com → Account Settings → API Keys). Without it the pipeline still deploys, but only warns instead of verifying that the build succeeded |
| `ORACLE_HOST` | the Oracle instance's public IP (`168.138.202.139`) |
| `ORACLE_SSH_KEY` | full contents of the instance's **private** SSH key file (the one *without* `.pub`), including the BEGIN/END lines |
| `ANTHROPIC_API_KEY` | *(later - the Claude PR review stays skipped until this exists)* |

## Why the deploy job waits

Firing Render's deploy hook only proves Render **accepted** the request - the
build result arrives minutes later. Before `RENDER_API_KEY` existed, a failed
Render build still left CI green, so "deploy failed" emails could arrive while
the pipeline reported success. The deploy job now polls Render's API until the
build reaches a terminal state and fails on `build_failed` / `update_failed`.

A `canceled` deploy is reported as a warning rather than a failure: it means
another deploy superseded this one, which is exactly what happens when Render's
Auto-Deploy races the hook. If that warning appears on every push, Auto-Deploy
is still on - see below.

## Python version

`backend/.python-version` pins the interpreter to 3.13, matching CI and local
development. Without it Render picks its own default and may change it during
any rebuild, which breaks packages that have no wheels for the new version
(`psycopg2-binary` is the usual casualty).

## Render: turn Auto-Deploy OFF (completely)

Render dashboard → your service → Settings → Build & Deploy → **Auto-Deploy:
No**. The pipeline's deploy job *is* the "deploy after CI passes" mechanism -
it calls the deploy hook only from main and only after lint, tests and the
security audit are green. Leaving Render's own auto-deploy on would deploy
every push immediately, bypassing the entire gate (and if your Render plan
offers "After CI Checks Pass", using it *together with* the hook would deploy
twice - pick the hook, keep auto-deploy off).

## Branch protection (one-time)

Settings → Rules → Rulesets → New branch ruleset targeting `main`:
require a pull request (1 approval, dismiss stale approvals), require these
status checks (strict): **Backend / lint (ruff)**, **Backend / unit tests**,
**Security / dependency audit**; require conversation resolution; block force
pushes and deletions.

## Local equivalents

```bash
venv/Scripts/python -m ruff check .
venv/Scripts/python manage.py test --settings=scholarship_backend.settings_test
```

## Note on the full-stack e2e suite

The Playwright end-to-end suite lives in the frontend repo
(FOFANA459-2023/myScholy) and its CI job automatically checks this repo out
alongside the frontend - no configuration needed here. Keep in mind: the e2e
suite tests whatever is on this repo's default branch, so breaking API
changes should land here before (or together with) the frontend change that
depends on them.
