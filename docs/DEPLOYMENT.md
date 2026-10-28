# Deployment guide

API Fortress deploys as two processes: the **gateway** (public) and the
**protected API** (private). The gateway is the only thing users reach; the
protected API rejects any request that does not carry the gateway's shared secret.

| Option | Cost | Persistence | Effort | Best for |
|---|---|---|---|---|
| A. Render | Free tier | Resets on redeploy unless you add Postgres | 15 min | Submitting a public URL |
| B. VPS + Docker Compose + Caddy | ~₹400–800/month (or free credits) | Full | 45 min | A "real" production-style deployment |
| C. Tunnel from your laptop | Free | Your laptop | 5 min | A live demo during a presentation |

---

## Step 0 — prepare (all options)

1. Install **Git** (<https://git-scm.com/download/win>) and create a free **GitHub** account.
2. Generate production secrets:
   ```bash
   python scripts/generate_secrets.py
   ```
   Keep the output somewhere safe (a password manager). Never commit it.
3. Put the project on GitHub (the `.gitignore` already excludes `.env` and databases):
   ```bash
   git init
   git add .
   git commit -m "API Fortress"
   git branch -M main
   git remote add origin https://github.com/<your-user>/api-fortress.git
   git push -u origin main
   ```

Production environment variables (all options):

| Variable | Value |
|---|---|
| `APP_ENV` | `production` |
| `ADMIN_PASSWORD` | 12+ characters |
| `ADMIN_SESSION_SECRET`, `JWT_SECRET`, `GATEWAY_SHARED_SECRET` | generated values |
| `INGEST_TOKEN` | generated value (enables log shipping) |
| `COOKIE_SECURE` | `true` (HTTPS) |
| `TRUST_PROXY_HEADERS` | `true` when behind Render/Caddy/Nginx |

---

## Option A — Render (free HTTPS URL)

The repository includes a `Dockerfile` that runs both processes in one container
(the protected API binds to `127.0.0.1` only) and a `render.yaml` Blueprint.

1. Sign in at <https://render.com> with GitHub.
2. **New → Blueprint** → select your `api-fortress` repository → **Apply**.
3. Render generates `JWT_SECRET`, `GATEWAY_SHARED_SECRET`, `ADMIN_SESSION_SECRET`
   and `INGEST_TOKEN` automatically and asks you for:
   - `ADMIN_PASSWORD` — 12+ characters.
   - `DATABASE_URL` — leave empty for now (see "Persistence" below).
4. Wait for the build (3–5 minutes). Your URL looks like
   `https://api-fortress-xxxx.onrender.com`.
5. Verify:
   - `https://<your-url>/gateway/health` → `{"status":"ok",...}`
   - `https://<your-url>/dashboard` → sign in as `admin`.
   - From your laptop: `python scripts/simulate_attacks.py --url https://<your-url>` → all checks pass.
6. To find `INGEST_TOKEN` later: service → **Environment**.

**Persistence.** The free web service has an ephemeral disk: events reset on each
redeploy or restart. For persistent storage create a free Postgres database
(Render → **New → PostgreSQL**, or <https://neon.tech>), copy its *External
Database URL*, and set it as `DATABASE_URL` on the web service. Tables are
created automatically.

**Free-tier note.** Free services sleep after ~15 minutes idle; the first request
afterwards takes ~30–50 seconds. Open the URL a minute before you demo.

---

## Option B — VPS with Docker Compose and automatic HTTPS

Any Ubuntu 22.04/24.04 server with 1 GB RAM works (DigitalOcean, Hetzner,
AWS Lightsail, Azure/GCP student credits, Oracle Cloud free tier).

### B.1 Server setup

```bash
ssh root@<server-ip>
apt update && apt -y upgrade
curl -fsSL https://get.docker.com | sh
ufw allow OpenSSH && ufw allow 80 && ufw allow 443 && ufw --force enable
```

### B.2 Get the code and configure

```bash
git clone https://github.com/<your-user>/api-fortress.git
cd api-fortress
cp .env.example .env
nano .env
```

Set at least: `APP_ENV=production`, the generated secrets, `ADMIN_PASSWORD`,
`INGEST_TOKEN`, `COOKIE_SECURE=true`, `TRUST_PROXY_HEADERS=true`, and add
`DOMAIN=fortress.yourdomain.com`.

### B.3 Domain (for HTTPS)

Create a DNS **A record** for `fortress.yourdomain.com` pointing at the server IP.
No domain? Use a free one from <https://www.duckdns.org>.

### B.4 Start

```bash
docker compose --profile https up -d --build
docker compose ps          # gateway and backend "healthy", caddy "running"
docker compose logs -f gateway
```

Caddy obtains a Let's Encrypt certificate automatically. Open
`https://fortress.yourdomain.com/dashboard`.

Without a domain (HTTP only, testing): `docker compose up -d --build`, then open
`http://<server-ip>:8000/dashboard` (set `COOKIE_SECURE=false` and `ufw allow 8000`).

### B.5 Verify the backend is not exposed

```bash
curl -m 5 http://<server-ip>:9000/health      # must time out / refuse
python scripts/simulate_attacks.py --url https://fortress.yourdomain.com
```

The backend has no published port and sits on an `internal: true` Docker network.

### B.6 Operations

| Task | Command |
|---|---|
| Update after `git push` | `git pull && docker compose --profile https up -d --build` |
| Logs | `docker compose logs -f gateway` |
| Restart | `docker compose restart gateway` |
| Back up events | `docker compose cp gateway:/app/data/fortress.db ./fortress-backup.db` |
| Stop | `docker compose --profile https down` (data volumes are kept) |

---

## Option C — public URL from your laptop (live demo)

1. Start the project normally: `start.bat`.
2. Install cloudflared: <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/>
   (Windows: `winget install --id Cloudflare.cloudflared`).
3. In a second terminal:
   ```bash
   cloudflared tunnel --url http://127.0.0.1:8000
   ```
4. Share the printed `https://<random>.trycloudflare.com/dashboard` URL. It works while your laptop and the terminal stay open.

For this option set `TRUST_PROXY_HEADERS=true` in `.env` so client IPs are recorded correctly, and use a strong `ADMIN_PASSWORD`.

---

## Running locally with Docker Desktop (optional)

```bash
copy .env.example .env
docker compose up -d --build
```

Open <http://127.0.0.1:8000/dashboard>. Stop with `docker compose down`.

---

## Production checklist

- [ ] `APP_ENV=production` and all secrets generated (startup fails otherwise)
- [ ] HTTPS in front (Render, Caddy) and `COOKIE_SECURE=true`
- [ ] `TRUST_PROXY_HEADERS=true` only when behind a proxy you control
- [ ] Protected API not reachable directly (step B.5)
- [ ] `DATABASE_URL` set to Postgres, or a persistent volume for SQLite
- [ ] `INGEST_TOKEN` set if you ship logs; rotate it if it leaks
- [ ] Gateway runs with **one** worker (in-memory rate limiter)
- [ ] `python scripts/simulate_attacks.py --url <public-url>` passes

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Refusing to start in production with insecure settings` | Set the listed variables to strong values |
| Dashboard login works then immediately logs out | `COOKIE_SECURE=true` while using plain HTTP — set it to `false` or use HTTPS |
| All API calls return `502 upstream_unavailable` | Protected API not running or `BACKEND_URL` wrong |
| API calls return `403 Direct access is not permitted` | `GATEWAY_SHARED_SECRET` differs between gateway and backend |
| Every token rejected with AUTH-002 | `JWT_SECRET` differs between gateway and backend |
| All requests show client IP of the proxy | Set `TRUST_PROXY_HEADERS=true` |
| Render first request very slow | Free instance waking from sleep |
