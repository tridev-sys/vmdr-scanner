# VMDR: Vulnerability Management Dashboard and Scanner

A 24x7 scanner daemon that runs ProjectDiscovery Nuclei against a growing list of web and API endpoints, deduplicates the findings into a database, and shows them in a dashboard.

```
frontend (React + Tailwind)  ──/api──▶  web-api (FastAPI)  ──┐
                                                             ├── SQLite (WAL) on shared volume
scanner-worker (APScheduler + queue) ────────────────────────┘
        │
        └── nuclei (host binary, host template cache)
```

- **web-api** serves the REST API. It never runs Nuclei.
- **scanner-worker** runs the daily full scan (cron), the template sync (every 24h), and queued scans, one at a time. Non-blocking for the UI because the API only inserts rows.
- Scan requests are rows in the `scan_runs` table. The worker polls for them, so the same design works across containers and systemd.

## Layout

```
backend/
  app/
    config.py            VMDR_* settings
    db.py                SQLite engine (WAL, FKs, busy timeout); create_all on start
    models.py            targets, vulnerabilities, scan_runs, scan_logs, worker_state, webhooks
    schemas.py           request/response models
    utils.py             URL normalization, domain grouping, fingerprint, bulk parser
    seed_data.py         initial endpoints
    seed.py              idempotent seeder: python -m app.seed
    worker.py            daemon: APScheduler + template sync + queue consumer
    services/
      nuclei.py          command builder, template update, JSONL parser
      ingest.py          dedup + two-cycle auto-resolution
      scanner.py         executes one ScanRun end to end
      webhooks.py        Slack / Teams / generic alerts for new critical/high
      status.py          worker status for the API
    routers/             targets, vulnerabilities, scans, stats, webhooks
  tests/                 unit, API, and worker pipeline tests (fake nuclei)
frontend/                Vite + React + TypeScript + Tailwind (Overview, Targets, Vulnerabilities)
deploy/
  systemd/               vmdr-api.service, vmdr-worker.service, vmdr.env.example
  nginx/vmdr.conf        native reverse-proxy config
docker-compose.yml       web-api, scanner-worker, web-frontend
```

## Data model and rules

- **Targets** have a status of `ACTIVE`, `PAUSED`, or `ARCHIVED`. Each scan reads the `ACTIVE` set at execution time, writes it to `targets_active.txt` in the run's work directory, and passes that file to Nuclei. New targets are picked up by the next scan with no restart.
- **Findings** are deduplicated on `sha256(target_url | template_id | matcher_name)`. A re-detection updates `last_seen_at` and refreshes the metadata. It never creates a second row.
- **Resolution:** a finding that is missing from two consecutive *completed* scans of its target is set to `RESOLVED`. A finding seen again is reopened. Failed or timed-out runs never resolve anything. `FALSE_POSITIVE` and `ACCEPTED_RISK` are never changed automatically.
- **Triage:** `OPEN`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, or `RESOLVED` via `PATCH /api/vulnerabilities/{id}`.
- **Alerts:** a new `critical` or `high` finding triggers every enabled webhook whose threshold it meets.

Scan command (defaults; all configurable):

```
nuclei -list <workdir>/targets_active.txt -severity critical,high,medium \
  -rate-limit 50 -concurrency 10 -retries 1 -timeout 5 -jsonl -o <workdir>/scan_output.jsonl -silent -no-color
```

## Quick start (local development)

```bash
# Backend
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.seed                       # loads the initial endpoints (idempotent)
uvicorn app.main:app --reload --port 8000
# in a second shell, same venv:
python -m app.worker                     # needs nuclei at VMDR_NUCLEI_BIN

# Frontend
cd frontend
npm ci
npm run dev                              # http://localhost:5173 (proxies /api to :8000)
```

Run tests: `cd backend && python -m pytest -q`

## Deployment option A: Docker Compose (recommended)

Requirements: a Linux host with Docker, and Nuclei installed (`/usr/local/bin/nuclei`).

```bash
cp .env.example .env                     # set VMDR_API_KEY, NUCLEI_TEMPLATES_DIR, port
docker compose up -d --build
```

- The dashboard is at `http://<host>:8080`.
- The Nuclei binary is mounted read-only from the host. The template cache is mounted from `NUCLEI_TEMPLATES_DIR` so `nuclei -update-templates` results persist.
- Seed the initial endpoints once: `docker compose exec web-api python -m app.seed`.

## Deployment option B: native Ubuntu with systemd

```bash
# 1. Users and directories
sudo useradd --system --home /var/lib/vmdr --shell /usr/sbin/nologin vmdr
sudo mkdir -p /opt/vmdr /etc/vmdr /var/lib/vmdr/scans /var/lib/vmdr/home
sudo chown -R vmdr:vmdr /var/lib/vmdr

# 2. Code and Python env
sudo cp -r backend /opt/vmdr/backend
sudo python3 -m venv /opt/vmdr/venv
sudo /opt/vmdr/venv/bin/pip install -r /opt/vmdr/backend/requirements.txt

# 3. Frontend build
(cd frontend && npm ci && npm run build)
sudo mkdir -p /opt/vmdr/frontend && sudo cp -r frontend/dist /opt/vmdr/frontend/dist

# 4. Config (set VMDR_API_KEY!)
sudo cp deploy/systemd/vmdr.env.example /etc/vmdr/vmdr.env
sudo chown root:vmdr /etc/vmdr/vmdr.env && sudo chmod 640 /etc/vmdr/vmdr.env

# 5. Nuclei (if not installed)
#    Download the release for linux_amd64 from github.com/projectdiscovery/nuclei/releases
#    and install it to /usr/local/bin/nuclei.

# 6. Seed and start
sudo -u vmdr bash -c 'set -a; . /etc/vmdr/vmdr.env; set +a; cd /opt/vmdr/backend && /opt/vmdr/venv/bin/python -m app.seed'
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vmdr-api vmdr-worker

# 7. Reverse proxy
sudo cp deploy/nginx/vmdr.conf /etc/nginx/sites-available/vmdr
sudo ln -s /etc/nginx/sites-available/vmdr /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Verification

```bash
# API is up
curl -s http://localhost:8000/api/health            # {"status":"ok"}

# Worker is alive and its heartbeat is fresh
curl -s http://localhost:8000/api/scans/status | jq '{state, worker_online, queue_length, templates}'

# Targets loaded and grouped by domain
curl -s http://localhost:8000/api/targets/domains | jq
curl -s 'http://localhost:8000/api/targets?page_size=1' | jq .total

# Add a target and scan just that one now
curl -s -X POST http://localhost:8000/api/targets \
  -H 'Content-Type: application/json' -H "X-API-Key: $VMDR_API_KEY" \
  -d '{"url":"https://new.example.com","tags":["prod"]}'
curl -s -X POST http://localhost:8000/api/scans/trigger \
  -H 'Content-Type: application/json' -H "X-API-Key: $VMDR_API_KEY" \
  -d '{"scope":"target","target_id":<id from above>}'

# Watch progress (live_findings counts lines in scan_output.jsonl)
watch -n 3 'curl -s http://localhost:8000/api/scans/status | jq "{state, live_findings, current_run: .current_run.status}"'

# Findings and stats
curl -s 'http://localhost:8000/api/vulnerabilities?severity=critical,high' | jq .total
curl -s http://localhost:8000/api/stats | jq '{active_critical, active_high, severity_distribution, mttr_hours}'
```

Systemd: `journalctl -u vmdr-worker -f` shows the scheduler, template syncs, and each scan's summary.

## API summary

| Method | Path | Notes |
|---|---|---|
| GET | `/api/targets` | Paginated; `q`, `status`, `domain`, `tag`; includes open-vuln counts and risk |
| GET | `/api/targets/domains` | Domain-root groups with counts |
| POST | `/api/targets` | `url`, `urls[]`, or `text` (newline/CSV, `url,tag1;tag2`); duplicates and invalid lines reported |
| GET / PATCH / DELETE | `/api/targets/{id}` | PATCH toggles `ACTIVE`/`PAUSED`; DELETE archives (`?hard=true` removes) |
| POST | `/api/scans/trigger` | `{scope:"all"}` or `{scope:"target", target_id}`; optional `severities` |
| GET | `/api/scans/status` | Worker state, heartbeat, queue length, live progress, recent runs, logs |
| GET | `/api/scans/runs` | Run history |
| POST | `/api/scans/templates/update` | Requests a template sync on the next worker loop |
| GET | `/api/vulnerabilities` | `q`, `severity`, `status`, `cve_id`, `domain`, `target_id`; paginated |
| GET / PATCH | `/api/vulnerabilities/{id}` | Detail and triage |
| GET | `/api/stats` | Dashboard cards, severity distribution, 7-day trend, spike flag, MTTR |
| GET / POST / DELETE | `/api/webhooks` | Slack, Teams, or generic alert destinations |

Write endpoints require `X-API-Key` when `VMDR_API_KEY` is set. Reads are open, so keep the API on a private network or behind your SSO proxy.

## Notes and deliberate choices

- **Scan working directory:** `VMDR_SCAN_WORKDIR` defaults to `data/scans`, not `/tmp`. The API reads live output from this directory, and `/tmp` is private per service under systemd and per container, so it has to be shared storage.
- **Seed count:** the supplied list contains 91 endpoints, not 95. The seeder loads all 91 and is idempotent.
- **Domain grouping** uses the last two labels (`app.koala.cx` → `koala.cx`). Multi-part public suffixes such as `.co.uk` would need the Public Suffix List.
- **MTTR** is the mean of `resolved_at − first_seen_at` over findings resolved in the last 90 days.
- **Database migration:** set `VMDR_DATABASE_URL` to a PostgreSQL URL (for example `postgresql+psycopg://…`) and add the `psycopg` driver. Replace `create_all` with Alembic migrations before going to production.
- **Not included yet:** continuous staggered scans (only the daily full scan plus on-demand scans), user accounts (only the shared API key), and a Next.js frontend (Vite + React was chosen as the lighter option the spec allowed).
