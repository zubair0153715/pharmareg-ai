# PharmaReg Audit Cloud — full app source

Live: https://pharmareg-ai.fastapicloud.dev

## Kya hai is me
- `app/main.py` — FastAPI app, saare routers yahan judte hain
- `app/audit_engine.py` — free DRAP self-audit (48 sawal, scoring, report)
- `app/audit_frameworks.py` — 3 frameworks: DRAP (48q), SFDA (51q), EDE (51q)
- `app/portal.py` — accounts (signup/login, pbkdf2), dashboard, plans
  (Free 3 audits / Pro $49 / Enterprise $199), shareable report links,
  manual billing (WhatsApp), admin panel
- `app/qms.py` — QMS Lite: document control, deviations, CAPA,
  change control, training records, hash-chained audit trail
- `templates/` — saare HTML pages (Jinja2)
- `static/` — CSS
- `pyproject.toml` — dependencies (`fastapi[standard]`, `jinja2`, `python-multipart`)

## Chalane ke liye
```bash
pip install "fastapi[standard]" jinja2 python-multipart
uvicorn app.main:app --port 8000
```
`data/` folder runtime par khud ban jata hai (users, audits, QMS records).

## Deploy (FastAPI Cloud)
```bash
fastapi cloud deploy --app-id 2d837fae-09a0-454a-b415-076582bffc19
```

## Zaroori notes
- Admin panel: `/portal/admin` (key `data/portal_admin_key.txt` me banti hai — prod wali key sirf owner ke paas)
- Leads (free audit): `/audit/leads` — unlisted, publish mat karna
- Deployed imports `from app.x` use karte hain (local test me sys.path se farq parta hai)
- Locking ke liye `threading.RLock` (Lock deadlock karta hai)
