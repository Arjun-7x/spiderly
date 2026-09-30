# SPIDERLY

**Network Reconnaissance & Intelligence Platform**

SPIDERLY is a full-stack authorized-security-testing tool: a real async TCP
connect-scanner, service/banner identification, passive HTTP metadata
collection, a rule-based findings engine, scan history, and HTML report
generation — with a live dashboard driven by real backend events over
WebSocket.

> ⚠️ **Only run SPIDERLY against systems you own or are explicitly
> authorized to test.** It performs real network connections. It does not
> perform exploitation, credential attacks, or destructive testing, but an
> unauthorized port scan can still violate the law or a network's
> acceptable-use policy.

---

## What's actually real here

Every number on the dashboard comes from a real network operation, not a
mock:

- **Port scanning** — `backend/app/scanner/port_scanner.py` performs a real
  asyncio TCP three-way-handshake connect scan, bounded by a semaphore and a
  per-connection timeout. No raw sockets, no root required.
- **Host reachability** — `host_discovery.py` probes a handful of common
  ports (no root-only ICMP dependency).
- **Service ID & banners** — `service_detector.py` connects to each open
  port and reads whatever the service actually sends (or nudges silent
  services with a newline), then cross-references a well-known-ports table.
- **HTTP metadata** — `http_enum.py` performs one real GET per HTTP-like
  port and records status code, `Server` header, page title, content type,
  and TLS usage. No crawling, no forms submitted.
- **Findings** — `findings.py` is a rule engine that only fires on things it
  actually observed (an open port, a banner string, a missing-TLS
  connection). Nothing is labeled a "vulnerability" without evidence, and
  severities are deliberately conservative.
- **Storage & history** — every scan, host, port, HTTP record, finding, and
  timeline event is written to SQLite (`backend/app/database/database.py`).
- **Real-time UI** — the dashboard connects over WebSocket
  (`/api/ws/scans/{id}`) and animates as events actually arrive from the
  scanner, not on a timer.

### Simplifications made for this build

- The frontend is a single-page vanilla HTML/CSS/JS app rather than a full
  React + Vite project, to keep the deliverable dependency-free and easy to
  just open. The API surface matches what the spec described, so a React
  frontend could be swapped in without backend changes.
- Nmap integration is not wired in — the
  architecture (a `scanner/` package with swappable modules) supports adding
  it as an optional module later.
- Accessibility and responsive polish are implemented at a basic level
  (semantic structure, `prefers-reduced-motion` support, mobile stacking)
  rather than a full audit.

---

## Interface features

Beyond the live dashboard basics, the frontend includes a few small
usability touches — all driven by real backend state, nothing simulated:

- **Search, sort, and expandable rows** on the open-ports table — filter by
  port/service/banner text, sort by port or service name, and click a row
  to expand its full banner and any findings tied to that port.
- **System status panel** (sidebar) showing live Backend / Database /
  WebSocket connectivity, polled from `/api/status` and the scan socket
  itself.
- **Network graph pan & zoom** — scroll to zoom, drag to pan, click a node
  for a quick summary, with a small legend and a reset-view button.
- **WebSocket auto-reconnect** with exponential backoff if the live-event
  connection drops mid-scan.
- **Toast notifications** for scan start/completion/failure, plus copy-to-
  clipboard for the current scan ID.
- **Scan History search** to filter previous scans by target, with
  skeleton loading while history is fetched.
- A confirmation prompt before starting a new scan while one is already
  running, since the old one keeps running in the background.

---

## Project layout

```
spiderly/
  backend/
    app/
      main.py                # FastAPI app entrypoint
      api/scans.py            # /api/scans, /api/scans/{id}, WebSocket events
      api/reports.py          # /api/reports/{id}
      core/config.py          # tunables (timeouts, concurrency, port limits)
      core/security.py        # input validation (no shell commands, ever)
      scanner/
        host_discovery.py
        port_scanner.py
        service_detector.py
        http_enum.py
        findings.py
      services/scan_manager.py  # orchestrates a full scan, emits events
      database/database.py    # SQLite schema + accessors
      reports/generator.py    # HTML report renderer
    tests/                     # pytest suite (validation + findings rules)
    requirements.txt
    .env.example               # documented, secret-free env var reference
  frontend/
    index.html
    app.js
    styles.css
  .gitignore
  README.md
```

---

## Running it

### 1. Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate     # optional but recommended
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The API is now at `http://127.0.0.1:8000`. Interactive API docs are auto-
generated at `http://127.0.0.1:8000/docs`.

### 2. Frontend

The frontend is static — just serve or open it:

```bash
cd frontend
python3 -m http.server 5500
```

Then open `http://127.0.0.1:5500` in a browser. If your backend isn't at
`http://127.0.0.1:8000`, set the correct URL in the **Settings** tab.

### 3. Run a scan

1. Go to **Scanner**, enter a target you're authorized to test (e.g. a VM
   on your own isolated lab network) and pick a scan mode.
2. Click **Start Scan** — you'll be taken to the live dashboard, where the
   network graph, event stream, port table, and findings populate in real
   time as the backend actually scans.
3. Click **Generate Report** for a shareable HTML report.
4. Previous scans are available under **Scan History**.

---

## API reference

| Method | Path | Description |
|---|---|---|
| POST | `/api/scans` | Start a scan. Body: `{target, scan_mode, port_spec?}` |
| GET | `/api/scans` | List scan history |
| GET | `/api/scans/{id}` | Scan metadata |
| GET | `/api/scans/{id}/results` | Full results (hosts, ports, http, findings) |
| GET | `/api/scans/{id}/events` | Full event timeline |
| WS | `/api/ws/scans/{id}` | Live event stream |
| GET | `/api/reports/{id}` | Rendered HTML report |
| GET | `/api/status` | Backend/engine health |

`scan_mode` is one of `quick` (a curated list of common ports), `standard`
(ports 1–1024), or `custom` (requires `port_spec`, e.g. `"22,80,1000-2000"`).

---

## Security notes

- All target and port input is validated in `core/security.py` before it
  touches anything else — shell metacharacters are rejected outright, and
  SPIDERLY never constructs or executes shell commands from user input.
- Port ranges are capped (`MAX_PORT_RANGE_SIZE`, default 5000) and scan
  concurrency is bounded (`MAX_CONCURRENT_PORT_SCANS`, default 200) to keep
  scans from overwhelming the local machine or the target.
- CORS is wide open (`*`) by default for local development — tighten
  `ALLOWED_ORIGINS` in `core/config.py` before deploying anywhere shared.
- No secrets are hardcoded; all tunables come from environment variables
  with sane defaults. Copy `backend/.env.example` to `backend/.env` and
  export its values (e.g. `export $(grep -v '^#' .env | xargs)`) if you
  want to override them — SPIDERLY has no API keys or credentials to
  configure, only safety limits.
- `.gitignore` keeps virtualenvs, `__pycache__`, the local SQLite file,
  logs, and IDE/OS clutter out of version control, so the repo stays clean
  to `git init` and push.

---

## Testing

```bash
cd backend
pytest -q
```

Covers input validation (target/port parsing, injection rejection) and the
findings engine's severity rules. For scanner-level testing, point SPIDERLY
at an isolated lab environment you control — e.g. Metasploitable2 or a
throwaway VM on a host-only VirtualBox network — never at a shared or
production network.

---

## Configuration & safety controls

All settings are environment variables (or `backend/.env`; see `.env.example`).

| Variable | Default | Purpose |
|---|---|---|
| `SPIDERLY_API_KEY` | *(unset)* | Shared **admin** key. When any key is set, every `/api` route except `/api/status` requires `X-API-Key` (or `?api_key=` for report links / WebSockets). |
| `SPIDERLY_API_KEYS` | *(unset)* | Per-user keys, `alice:key1,bob:key2`. Each user sees, reads, reports on and cancels **only their own scans** (someone else's scan returns 404). |
| `SPIDERLY_ADMIN_USERS` | *(unset)* | Named users from the list above who may see every scan. |
| `SPIDERLY_REQUIRE_AUTH` | `false` | If `true` and no key is configured, a random key is generated at startup and logged once. **The Docker image sets this**, so it is never open by default. |
| `SPIDERLY_SCAN_RATE_LIMIT` / `_WINDOW` | `10` / `60` | Max scans started per identity (or client IP when auth is off) per window; 429 + `Retry-After` beyond it. `0` disables. |
| `SPIDERLY_AUTH_FAIL_LIMIT` / `_WINDOW` | `10` / `60` | Failed-key attempts per client before it is locked out (429). |
| `SPIDERLY_ALLOW_PRIVATE` | `true` | Set `false` to refuse loopback and RFC1918 targets. |
| `SPIDERLY_ALLOWED_TARGETS` | *(unset)* | Comma-separated CIDRs; if set, only these networks can be scanned. |
| `SPIDERLY_MAX_ACTIVE_SCANS` | `3` | Concurrent scan cap (HTTP 429 beyond it). |
| `SPIDERLY_ALLOWED_ORIGINS` | `*` | CORS origins. |

Regardless of settings, link-local (including the cloud metadata address
`169.254.169.254`), multicast, unspecified and reserved addresses are always
refused. The policy is enforced on the **resolved** IP, so a hostname cannot
be used to smuggle in a blocked address. Running scans can be stopped with
`POST /api/scans/{id}/cancel` (or the *Cancel Scan* button).

## Running with Docker

```bash
docker build -t spiderly .
docker run --rm -p 8000:8000 -e SPIDERLY_API_KEY=change-me spiderly
# or omit the key: one is generated and printed in `docker logs`
# open http://localhost:8000  (backend serves the frontend on the same origin;
# enter the key under Settings)
```

## Deploying to Render

`render.yaml` is a Blueprint (Render dashboard -> New -> Blueprint -> pick your repo).

Before you go live, read these; they are the difference between a demo and an incident:

1. **Only scan what you own.** SPIDERLY sends real connection attempts from Render's
   IP addresses. Render's [penetration testing policy](https://render.com/docs/penetration-testing)
   allows testing your *own* services, but forbids testing other Render users' infrastructure
   or Render's own without consent, and its [Acceptable Use Policy](https://render.com/acceptable-use)
   applies to everything you run. Scanning third-party hosts without authorization can also be
   illegal. Set `SPIDERLY_ALLOWED_TARGETS` to the IPs/CIDRs you own (the Blueprint prompts for it).
2. **Keep `SPIDERLY_ALLOW_PRIVATE=false`** (the Blueprint does). Otherwise an authenticated
   user could scan Render's private network and your other services.
3. **A persistent disk needs a paid instance.** Without one, SQLite lives on an ephemeral
   filesystem and scan history vanishes on every deploy/restart. Free instances also spin down when
   idle, which kills running scans and drops WebSockets.
4. **Set `SPIDERLY_API_KEY` explicitly** (the Blueprint generates one; read it under
   *Environment*). If none is set the app makes a random one **per start**, so it would change
   on every restart.
5. **`FORWARDED_ALLOW_IPS=*`** is correct behind Render's proxy (rate limits and lockouts then use
   the real client IP) but unsafe if the container is ever directly reachable, since clients could
   spoof `X-Forwarded-For`.

API keys sent as `?api_key=` (WebSocket and report links) are redacted from application logs,
but they can still appear in browser history and in any proxy that logs full URLs, so treat keys as
rotatable and prefer per-user keys (`SPIDERLY_API_KEYS`).

The container listens on `$PORT` (Render sets it), starts as root only long enough to fix
ownership of the mounted disk, then runs as an unprivileged user.

## Tests

```bash
# Backend: unit + end-to-end tests (real localhost listener, WebSocket, cancel, auth, users, migrations)
cd backend && pip install -r requirements-dev.txt && pytest -q

# Frontend: headless jsdom tests against a fake backend + fake WebSocket
cd frontend-tests && npm install && npm test
```

The frontend is native ES modules (`frontend/js/*.js`), so it must be served
over HTTP (the backend does this at `/`, or use `python -m http.server` in
`frontend/`); opening `index.html` via `file://` is blocked by browsers.

## Changelog

**0.2.0** — Fixed a WebSocket replay/subscribe race and live events carrying
string instead of object `data`; malformed port specs now return 422 instead
of 500; per-port detection is bounded and drained before a scan completes (no
late findings); scans can be cancelled; interrupted scans are recovered at
startup; target policy + optional API key + scan concurrency cap; CORS no
longer combines `*` with credentials; anchored banner detection (no
substring mislabeling); baseline "open port" finding no longer duplicates
specific findings; report responses carry a strict CSP; dependency pins,
Dockerfile, CI, and an end-to-end test suite (16 -> 58 tests).

**0.3.0** — Frontend split from one 690-line file into ES modules with a
jsdom test suite (10 tests); named per-user API keys with scan ownership
(other users' scans 404); sliding-window rate limits on scan creation and
failed auth; auto-generated key when `SPIDERLY_REQUIRE_AUTH=true` (Docker
default); banner-derived product/version shown in the UI (never guessed);
findings now persist their port (the expanded-row "Findings" list was always
empty after a refresh before); viewing a running scan from History attaches
the live stream; `cancelled`/`interrupted` statuses styled; in-place DB
migrations. Tests: 58 -> 78 backend + 10 frontend.

**0.3.1** — Render-ready: honours `$PORT`, drops privileges after fixing
mounted-disk ownership, `render.yaml` Blueprint, frontend auto-detects a
same-origin API (previously it only did so on port 8000, which broke any
HTTPS host), and `api_key` values are redacted from uvicorn logs.

## Future improvements

- Nmap integration as an optional module for deeper service/version fingerprinting
- PDF export of reports (currently HTML, which prints cleanly to PDF from a browser)
- Cytoscape.js/React Flow topology view with pan/zoom/clustering for large scans
- UDP scanning and OS fingerprinting (TCP connect scan only today)
- Persistent/shared rate limiting (limits are in-memory, per process)
- Login sessions / SSO (today: static API keys)
