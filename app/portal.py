"""PharmaReg Audit Cloud — SaaS portal.

Accounts (pbkdf2 + token sessions), multi-framework audits (DRAP/SFDA/EDE),
dashboard with history, shareable report links, plans with manual billing,
and an owner admin panel. Data lives in JSON files under data/.
"""
import hashlib
import hmac
import json
import os
import secrets
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.audit_frameworks import FRAMEWORKS, get_questions, get_domains, build_report

router = APIRouter()
templates = Jinja2Templates(directory="templates")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = DATA_DIR / "portal_users.json"
AUDITS_FILE = DATA_DIR / "portal_audits.json"
SESSIONS_FILE = DATA_DIR / "portal_sessions.json"
ADMIN_KEY_FILE = DATA_DIR / "portal_admin_key.txt"

WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "923116925020")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8000").rstrip("/")

PLANS = {
    "free": {"name": "Free", "monthly": 0, "audit_limit": 3, "share": False,
             "blurb": "3 audits · all 3 frameworks · scored reports"},
    "pro": {"name": "Professional", "monthly": 49, "audit_limit": None, "share": True,
            "blurb": "Unlimited audits · shareable report links · QMS Lite · priority support"},
    "enterprise": {"name": "Enterprise", "monthly": 199, "audit_limit": None, "share": True,
                   "blurb": "Everything in Pro · QMS Lite · 5 team seats · multi-facility tracking"},
}

SESSION_DAYS = 30


# ---------------- storage helpers ----------------
def _load_json(path, default):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return default
    return default


def _save_json(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def _users():
    return _load_json(USERS_FILE, {})


def _save_users(u):
    _save_json(USERS_FILE, u)


def _audits():
    return _load_json(AUDITS_FILE, {})


def _save_audits(a):
    _save_json(AUDITS_FILE, a)


def _sessions():
    return _load_json(SESSIONS_FILE, {})


def _save_sessions(s):
    _save_json(SESSIONS_FILE, s)


# ---------------- passwords & sessions ----------------
def _hash_pw(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return salt, dk.hex()


def _verify_pw(password, salt, pw_hash):
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return hmac.compare_digest(dk.hex(), pw_hash)


def _now():
    return datetime.now(timezone.utc)


def _new_session(uid):
    token = secrets.token_urlsafe(32)
    s = _sessions()
    s[token] = {"uid": uid, "exp": int(_now().timestamp()) + SESSION_DAYS * 86400}
    # prune expired
    now_ts = int(_now().timestamp())
    s = {t: v for t, v in s.items() if v.get("exp", 0) > now_ts}
    _save_sessions(s)
    return token


def _current_user(request: Request):
    token = request.cookies.get("pra_session")
    if not token:
        return None
    s = _sessions().get(token)
    if not s or s.get("exp", 0) < int(_now().timestamp()):
        return None
    return _users().get(s["uid"])


def _login_redirect():
    return RedirectResponse("/portal/login", status_code=303)


def _ctx(request, user=None, **kw):
    base = {"request": request, "public_url": PUBLIC_URL,
            "whatsapp_number": WHATSAPP_NUMBER, "user": user,
            "plans": PLANS, "frameworks": FRAMEWORKS}
    base.update(kw)
    return base


# ---------------- public portal pages ----------------
@router.get("/portal", response_class=HTMLResponse)
def portal_home(request: Request):
    return templates.TemplateResponse(request, "portal.html",
                                      _ctx(request, _current_user(request)))


@router.get("/portal/signup", response_class=HTMLResponse)
def signup_form(request: Request):
    if _current_user(request):
        return RedirectResponse("/portal/dashboard", status_code=303)
    return templates.TemplateResponse(request, "portal_signup.html",
                                      _ctx(request, error=None))


@router.post("/portal/signup", response_class=HTMLResponse)
async def signup(request: Request):
    form = await request.form()
    name = (form.get("name") or "").strip()[:120]
    email = (form.get("email") or "").strip().lower()[:160]
    company = (form.get("company") or "").strip()[:160]
    password = form.get("password") or ""
    err = None
    if not name or "@" not in email or len(password) < 8:
        err = "Name, a valid email, and a password of at least 8 characters are required."
    users = _users()
    if not err and any(u["email"] == email for u in users.values()):
        err = "This email is already registered. Please log in."
    if err:
        return templates.TemplateResponse(request, "portal_signup.html",
                                          _ctx(request, error=err))
    salt, pw_hash = _hash_pw(password)
    uid = "u" + secrets.token_hex(6)
    users[uid] = {"id": uid, "name": name, "email": email, "company": company,
                  "salt": salt, "pw_hash": pw_hash, "plan": "free",
                  "active": True, "created": _now().isoformat(timespec="seconds")}
    _save_users(users)
    resp = RedirectResponse("/portal/dashboard", status_code=303)
    resp.set_cookie("pra_session", _new_session(uid), max_age=SESSION_DAYS * 86400,
                    httponly=True, samesite="lax")
    return resp


@router.get("/portal/login", response_class=HTMLResponse)
def login_form(request: Request):
    if _current_user(request):
        return RedirectResponse("/portal/dashboard", status_code=303)
    return templates.TemplateResponse(request, "portal_login.html",
                                      _ctx(request, error=None))


@router.post("/portal/login", response_class=HTMLResponse)
async def login(request: Request):
    form = await request.form()
    email = (form.get("email") or "").strip().lower()
    password = form.get("password") or ""
    user = next((u for u in _users().values() if u["email"] == email), None)
    if not user or not user.get("active", True) or not _verify_pw(password, user["salt"], user["pw_hash"]):
        return templates.TemplateResponse(request, "portal_login.html",
                                          _ctx(request, error="Invalid email or password."))
    resp = RedirectResponse("/portal/dashboard", status_code=303)
    resp.set_cookie("pra_session", _new_session(user["id"]), max_age=SESSION_DAYS * 86400,
                    httponly=True, samesite="lax")
    return resp


@router.get("/portal/logout")
def logout():
    resp = RedirectResponse("/portal", status_code=303)
    resp.delete_cookie("pra_session")
    return resp


# ---------------- dashboard & audits ----------------
def _user_audits(uid):
    return sorted((a for a in _audits().values() if a["uid"] == uid),
                  key=lambda a: a["ts"], reverse=True)


@router.get("/portal/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    audits = _user_audits(user["id"])
    return templates.TemplateResponse(request, "dashboard.html",
                                      _ctx(request, user, plan=plan, audits=audits))


@router.get("/portal/audit/new", response_class=HTMLResponse)
def audit_new(request: Request):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    return templates.TemplateResponse(request, "audit_new.html", _ctx(request, user))


@router.get("/portal/audit/start", response_class=HTMLResponse)
def audit_start(request: Request, fw: str = "drap"):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    fw = fw if fw in FRAMEWORKS else "drap"
    meta = FRAMEWORKS[fw]
    questions = get_questions(fw)
    qbd = {}
    for did, _, _ in get_domains(fw):
        qbd[did] = [q for q in questions if q[1] == did]
    return templates.TemplateResponse(
        request, "audit.html",
        _ctx(request, user, domains=get_domains(fw), questions_by_domain=qbd,
             total=len(questions), form_action="/portal/audit/submit",
             framework=fw, fw_meta=meta,
             page_kicker=f"{meta['flag']} {meta['name']} · {meta['country']} · {len(questions)} questions",
             page_title=f"{meta['name']} GMP Self-Audit",
             page_lead=f"Answer {len(questions)} questions across 10 GMP domains aligned with {meta['full']} expectations. Your scored report is saved to your dashboard."))


@router.post("/portal/audit/submit", response_class=HTMLResponse)
async def audit_submit(request: Request):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    form = await request.form()
    fw = (form.get("framework") or "drap")
    fw = fw if fw in FRAMEWORKS else "drap"
    # plan limit
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    if plan["audit_limit"] is not None and len(_user_audits(user["id"])) >= plan["audit_limit"]:
        return templates.TemplateResponse(
            request, "audit_new.html",
            _ctx(request, user, error=f"Your {plan['name']} plan includes {plan['audit_limit']} audits. Upgrade to Professional for unlimited audits."))
    questions = get_questions(fw)
    answers = {}
    for q in questions:
        v = (form.get(f"q_{q[0]}") or "na").strip().lower()
        answers[q[0]] = v if v in ("yes", "partial", "no") else "na"
    company = {
        "company": (form.get("company") or "").strip()[:120],
        "contact": (form.get("contact") or "").strip()[:120],
        "email": (form.get("email") or "").strip()[:120],
        "phone": (form.get("phone") or "").strip()[:40],
        "facility_type": (form.get("facility_type") or "").strip()[:80],
        "city": (form.get("city") or "").strip()[:80],
    }
    report = build_report(company, answers, fw)
    now = _now()
    aid = "a" + secrets.token_hex(6)
    audits = _audits()
    audits[aid] = {"id": aid, "uid": user["id"], "framework": fw,
                   "report_id": f"PRA-{now:%Y%m%d}-{secrets.token_hex(2).upper()}",
                   "ts": now.isoformat(timespec="seconds"),
                   "company": company, "report": report,
                   "share_token": secrets.token_urlsafe(16)}
    _save_audits(audits)
    return RedirectResponse(f"/portal/audit/{aid}", status_code=303)


@router.get("/portal/audit/{aid}", response_class=HTMLResponse)
def audit_view(request: Request, aid: str):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    a = _audits().get(aid)
    if not a or a["uid"] != user["id"]:
        return templates.TemplateResponse(request, "portal.html",
                                          _ctx(request, user, error="Audit not found."))
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    share_url = f"{PUBLIC_URL}/r/{a['share_token']}" if plan["share"] else None
    return templates.TemplateResponse(
        request, "portal_report.html",
        _ctx(request, user, report=a["report"], company=a["company"],
             report_id=a["report_id"],
             report_date=datetime.fromisoformat(a["ts"]).strftime("%d %b %Y"),
             share_url=share_url, aid=aid, owner=True))


@router.post("/portal/audit/{aid}/delete")
def audit_delete(request: Request, aid: str):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    audits = _audits()
    a = audits.get(aid)
    if a and a["uid"] == user["id"]:
        del audits[aid]
        _save_audits(audits)
    return RedirectResponse("/portal/dashboard", status_code=303)


@router.get("/r/{token}", response_class=HTMLResponse)
def shared_report(request: Request, token: str):
    a = next((x for x in _audits().values() if x.get("share_token") == token), None)
    if not a:
        return templates.TemplateResponse(request, "portal.html",
                                          _ctx(request, _current_user(request),
                                               error="Report link not found or expired."))
    owner = _users().get(a["uid"], {})
    plan = PLANS.get(owner.get("plan", "free"), PLANS["free"])
    if not plan["share"]:
        return templates.TemplateResponse(
            request, "portal.html",
            _ctx(request, _current_user(request),
                 error="This shared report is unavailable on the owner's current plan."))
    return templates.TemplateResponse(
        request, "portal_report.html",
        _ctx(request, _current_user(request), report=a["report"], company=a["company"],
             report_id=a["report_id"],
             report_date=datetime.fromisoformat(a["ts"]).strftime("%d %b %Y"),
             share_url=None, aid=a["id"], owner=False))


@router.get("/portal/upgrade", response_class=HTMLResponse)
def upgrade(request: Request):
    user = _current_user(request)
    if not user:
        return _login_redirect()
    plan = (user.get("plan") or "free")
    msg = (f"Assalam-o-Alaikum, I'm {user['name']} ({user['email']}). "
           f"I want to upgrade my PharmaReg Audit Cloud account from {PLANS[plan]['name']} "
           f"to Professional ($49/mo). Please share bank transfer details.")
    wa = "https://wa.me/" + WHATSAPP_NUMBER + "?text=" + urllib.parse.quote(msg)
    # Paddle checkout config — inert until dashboard values are set via env.
    # When PADDLE_CLIENT_TOKEN + price IDs exist, the template's Paddle.js
    # stub becomes a live checkout; until then buttons show "coming soon".
    paddle_cfg = {
        "enabled": bool(os.environ.get("PADDLE_CLIENT_TOKEN")
                        and os.environ.get("PADDLE_PRO_PRICE_ID")),
        "pro_price_id": os.environ.get("PADDLE_PRO_PRICE_ID", ""),
        "ent_price_id": os.environ.get("PADDLE_ENT_PRICE_ID", ""),
        "client_token": os.environ.get("PADDLE_CLIENT_TOKEN", ""),
        "user_id": user["id"],
    }
    return templates.TemplateResponse(request, "upgrade.html",
                                      _ctx(request, user, wa_link=wa, paddle=paddle_cfg))


# ---------------- admin ----------------
def _admin_key():
    key = os.environ.get("PORTAL_ADMIN_KEY")
    if key:
        return key
    if ADMIN_KEY_FILE.exists():
        return ADMIN_KEY_FILE.read_text(encoding="utf-8").strip()
    key = "pra-" + secrets.token_hex(16)
    ADMIN_KEY_FILE.write_text(key, encoding="utf-8")
    print(f"[portal] PORTAL_ADMIN_KEY not set — generated: {key} (saved to {ADMIN_KEY_FILE})", flush=True)
    return key


def _is_admin(request: Request):
    return hmac.compare_digest(request.cookies.get("pra_admin", ""), _admin_key())


@router.get("/portal/admin", response_class=HTMLResponse)
def admin_home(request: Request):
    if not _is_admin(request):
        return templates.TemplateResponse(request, "admin_login.html",
                                          _ctx(request, error=None))
    users = _users()
    audits = _audits()
    return templates.TemplateResponse(request, "admin.html",
                                      _ctx(request, users=users, audits=audits,
                                           plans=PLANS))


@router.post("/portal/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request):
    form = await request.form()
    if not hmac.compare_digest((form.get("key") or ""), _admin_key()):
        return templates.TemplateResponse(request, "admin_login.html",
                                          _ctx(request, error="Wrong admin key."))
    resp = RedirectResponse("/portal/admin", status_code=303)
    resp.set_cookie("pra_admin", _admin_key(), httponly=True, samesite="lax")
    return resp


@router.post("/portal/admin/plan")
async def admin_set_plan(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    form = await request.form()
    uid, plan = form.get("uid"), form.get("plan")
    users = _users()
    if uid in users and plan in PLANS:
        users[uid]["plan"] = plan
        _save_users(users)
    return RedirectResponse("/portal/admin", status_code=303)


@router.post("/portal/admin/toggle")
async def admin_toggle(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    form = await request.form()
    uid = form.get("uid")
    users = _users()
    if uid in users:
        users[uid]["active"] = not users[uid].get("active", True)
        _save_users(users)
    return RedirectResponse("/portal/admin", status_code=303)
