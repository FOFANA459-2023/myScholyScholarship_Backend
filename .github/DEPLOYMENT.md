# Backend CI/CD setup (Render)

Workflows in this repo:

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | every PR + push to main | ruff lint, Django tests with coverage, pip-audit; triggers the Render deploy **only from main** after all gates pass |
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
| `ANTHROPIC_API_KEY` | *(later - the Claude PR review stays skipped until this exists)* |

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
