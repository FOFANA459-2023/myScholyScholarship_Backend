# Deploying the MyScholy backend on Oracle Cloud (OCI)

Target architecture: **Oracle Cloud is the primary backend** the frontend
talks to; **Render stays deployed as the secondary** (staging / testing /
backup). The database stays on Supabase and email stays on Resend — both
servers share them, so nothing moves except where the Django app runs.

Stack on the VM: **Gunicorn** (app server, already in requirements.txt) behind
**Caddy** (reverse proxy with automatic HTTPS), managed by **systemd**, with an
optional local **Redis** for the shared cache. Config files for the last steps
are in [`deploy/oracle/`](deploy/oracle/).

---

## 1. Pick where it runs

**You do not need a new VCN, subnet, or security list** — those are shared
network resources, and one of each serves any number of instances.

**Option A — reuse the existing instance (recommended on the free tier).**
If you already run another backend on an OCI VM, host MyScholy on the same
machine: Caddy routes by hostname, so both apps can share ports 80/443. Skip
to step 3, and note the port remarks in steps 8–9. The Always Free ARM
allowance (4 OCPUs / 24 GB) is a *total* across all your instances, so
consolidating is usually the better deal.

**Option B — create a second VM.** Compute → Instances → Create instance:

- **Image**: Ubuntu 24.04 (or 22.04).
- **Shape**: `VM.Standard.A1.Flex` — whatever OCPUs/RAM remain of your free
  allowance after the existing instance. 1 OCPU / 6 GB is plenty for this app.
  - If you get "Out of capacity" errors (common on the free tier), retry at a
    different time, try another availability domain, or fall back to the
    `VM.Standard.E2.1.Micro` x86 shape (1 GB RAM — still enough).
- **Networking**: select your **existing VCN and subnet**, assign a public IP.
- **SSH key**: upload/generate one and save the private key.

Note the instance's **public IP** once it's running.

## 2. Open ports 80 and 443

Two firewalls must both allow traffic — this is the #1 OCI gotcha.

**a) VCN security list** — since your subnet's security list already has 80
and 443 open for the other backend, there is **nothing to do here**: the rules
apply to every instance in the subnet. (Only if they're missing: Networking →
Virtual Cloud Networks → your VCN → Security Lists → **Add Ingress Rules** for
TCP 80 and 443 from 0.0.0.0/0.)

**b) The VM's own iptables** — this one is per-machine and must be repeated on
every *new* instance (Oracle's Ubuntu images ship with reject rules
preloaded). Already done if you're reusing the existing VM and it serves HTTPS
today. Otherwise, SSH in (`ssh -i <key> ubuntu@<public-ip>`) and run:

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save
```

## 3. Point a domain at the VM

Caddy needs a hostname to issue a free HTTPS certificate. Any of these works:

- **Own domain**: add an `A` record, e.g. `api.myscholy.com → <public-ip>`.
- **No domain**: create a free subdomain at [duckdns.org](https://www.duckdns.org)
  (e.g. `myscholy.duckdns.org`) pointing at the public IP.

The hostname you pick is referred to as `api.yourdomain.com` below.

## 4. Install system packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv python3-dev git libpq-dev caddy redis-server
```

**On a 1 GB shape (E2.1.Micro), add a 2 GB swap file first** so `pip install`
and `collectstatic` can't be killed by the OOM reaper:

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

(`redis-server` is optional but free here — it gives you the shared cache that
needed a paid add-on on Render. It listens on 127.0.0.1 only by default.)

## 5. Clone the app and install dependencies

```bash
cd ~
git clone <your-backend-repo-url> myscholy-backend
cd myscholy-backend
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

## 6. Create the production `.env`

`nano ~/myscholy-backend/.env` — copy the values you currently have in the
Render dashboard (Environment tab), with these changes:

```ini
# Core — DEBUG must be off in production.
DJANGO_DEBUG=False
DJANGO_SECRET_KEY=<generate a fresh one, command below>

# Replace the Render hostname with the Oracle one.
DJANGO_ALLOWED_HOSTS=api.yourdomain.com,localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=https://api.yourdomain.com,https://myscholy.vercel.app
DJANGO_CORS_ALLOWED_ORIGINS=https://myscholy.vercel.app

# Database — same Supabase values as on Render.
DB_NAME=postgres
DB_USER=...
DB_PASSWORD=...
DB_HOST=...
DB_PORT=6543
DB_SSLMODE=require

# Email — same as on Render.
RESEND_API_KEY=...
DEFAULT_FROM_EMAIL=MyScholy <no-reply@yourdomain.com>
CONTACT_INBOX=myscholy@gmail.com
FRONTEND_URL=https://myscholy.vercel.app

# Cache — local Redis on this VM (replaces the Render Redis URL).
REDIS_URL=redis://127.0.0.1:6379/0
```

Generate a fresh secret key:

```bash
venv/bin/python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

## 7. Migrate and collect static files

```bash
cd ~/myscholy-backend
venv/bin/python manage.py migrate
venv/bin/python manage.py collectstatic --noinput
```

## 8. Run Gunicorn under systemd

> **Sharing the VM with another app?** If something else already listens on
> local port 8000, edit the `--bind` line in the service file to
> `127.0.0.1:8001` first (and use the same port in the Caddyfile below).

```bash
sudo cp deploy/oracle/myscholy.service /etc/systemd/system/myscholy.service
sudo systemctl daemon-reload
sudo systemctl enable --now myscholy
systemctl status myscholy        # should say "active (running)"
```

## 9. Put Caddy in front

Edit `deploy/oracle/Caddyfile`, replace `api.yourdomain.com` with your real
hostname, then:

```bash
sudo cp deploy/oracle/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

> **Sharing the VM with another app?** Don't overwrite the existing
> `/etc/caddy/Caddyfile` — append the MyScholy site block to it instead (Caddy
> serves any number of hostnames from one file). If the other app uses nginx
> rather than Caddy, add an nginx `server` block for the new hostname
> proxying to `127.0.0.1:8001`, and get its certificate with
> `sudo certbot --nginx -d api.yourdomain.com`.

Caddy fetches the HTTPS certificate automatically (the domain must already
resolve to the VM for this to work).

## 10. Verify

```bash
curl -I https://api.yourdomain.com/api/scholarships/
```

Expect `HTTP/2 200` (or `301` → `200`). Also check `https://api.yourdomain.com/admin/`
loads with styling (proves collectstatic + WhiteNoise are working).

## 11. Make Oracle the primary

1. In Vercel: set `VITE_BACKEND_URL=https://api.yourdomain.com/api` and
   redeploy.
2. In the frontend repo, update the `preconnect`/`dns-prefetch` links in
   `index.html` and the default in `.github/workflows/ci.yml` from the
   `onrender.com` URL to the new one.
3. Test signup, login, password reset, and the contact form end-to-end
   against the Oracle URL.

## 12. Keep Render as the secondary

Render stays deployed — don't change anything in its dashboard. Its env vars
already carry the Render hostname, so both servers coexist; each deployment's
`.env`/dashboard covers only its own hostname.

How the two roles work:

- **Backup / failover**: both servers point at the same Supabase database, so
  Render always has current data. If Oracle goes down, switching the site
  over is one change: set `VITE_BACKEND_URL` back to
  `https://myscholyscholarship-backend.onrender.com/api` in Vercel and
  redeploy (2–3 minutes). Keep the `onrender.com` entries in
  `DJANGO_CORS_ALLOWED_ORIGINS`/`CSRF_TRUSTED_ORIGINS` on Render so the
  frontend is accepted when that happens.
- **Staging / testing**: deploy a branch or new commit to Render first, test
  it against `https://myscholyscholarship-backend.onrender.com`, then
  `git pull` + restart on Oracle once it looks good (see "Updating the app"
  below). **Caution:** Render shares the production database, so anything you
  create/edit while testing is real data. For risky experiments (migrations,
  destructive changes), point Render at a separate database first — a second
  free Supabase project works.
- **Caches are independent**: each server has its own Redis/local cache, and
  cache invalidation runs on the server where the write happened. If an admin
  edits data via Oracle, Render's cached lists can lag by up to the 5-minute
  cache TTL. Fine for a passive backup; just don't be surprised during
  side-by-side testing.
- **Migrations run once**: both servers share the schema, so run
  `manage.py migrate` from one server only (whichever deploys the new code
  first) — the other picks the schema up automatically. Deploy
  migration-bearing code to both servers promptly, since old code on new
  schema is only safe for backward-compatible migrations.

---

## Updating the app later

```bash
cd ~/myscholy-backend
git pull
venv/bin/pip install -r requirements.txt
venv/bin/python manage.py migrate
venv/bin/python manage.py collectstatic --noinput
sudo systemctl restart myscholy
```

## Troubleshooting

- **Site unreachable**: 9 times out of 10 it's the double firewall — re-check
  step 2 (both the VCN security list *and* iptables).
- **App errors**: `journalctl -u myscholy -n 100 --no-pager`
- **Caddy/TLS errors**: `journalctl -u caddy -n 100 --no-pager` — usually the
  DNS record isn't pointing at the VM yet.
- **400 Bad Request from Django**: the hostname is missing from
  `DJANGO_ALLOWED_HOSTS` in `.env` (restart with
  `sudo systemctl restart myscholy` after editing).
