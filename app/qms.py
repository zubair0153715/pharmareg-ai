"""PharmaReg QMS Lite — lightweight electronic Quality Management System.

Modules: documents (versioned SOP control), deviations, CAPA, change control,
training records, and a tamper-evident hash-chained audit trail.
Pro/Enterprise feature. E-signatures = password-confirmed approvals with
name/timestamp/meaning recorded (Part-11-style pattern, not a validated claim).
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates

from app.portal import (_current_user, _verify_pw, _ctx as _portal_ctx,
                        PLANS, WHATSAPP_NUMBER, PUBLIC_URL)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
FILES_DIR = DATA_DIR / "qms_files"
FILES_DIR.mkdir(exist_ok=True)

DOC_STATUSES = ["draft", "in_review", "effective", "obsolete"]
DEV_STATUSES = ["open", "investigating", "closed"]
CAPA_STATUSES = ["open", "in_progress", "pending_verification", "closed"]
CHG_STATUSES = ["requested", "assessing", "approved", "implementing", "rejected", "closed"]

MAX_FILE_MB = 15


# ---------------- storage ----------------
def _load(path, default):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return default
    return default


def _save(path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


def _store(name):
    return DATA_DIR / f"qms_{name}.json"


def _get(name):
    return _load(_store(name), {})


def _put(name, obj):
    _save(_store(name), obj)


def _now():
    return datetime.now(timezone.utc)


def _ts():
    return _now().isoformat(timespec="seconds")


def _new_id(prefix):
    return prefix + secrets.token_hex(6)


# ---------------- tamper-evident audit trail ----------------
TRAIL_FILE = DATA_DIR / "qms_trail.jsonl"


def trail(uid, user_name, action, entity, entity_id, details=""):
    prev_hash = "GENESIS"
    if TRAIL_FILE.exists():
        try:
            last = TRAIL_FILE.read_text(encoding="utf-8").strip().splitlines()[-1]
            prev_hash = json.loads(last).get("hash", "GENESIS")
        except (IndexError, json.JSONDecodeError, OSError):
            pass
    entry = {"ts": _ts(), "uid": uid, "user": user_name, "action": action,
             "entity": entity, "entity_id": entity_id, "details": details[:500],
             "prev_hash": prev_hash}
    entry["hash"] = hashlib.sha256(
        (prev_hash + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
    with open(TRAIL_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def recent_trail(limit=25):
    if not TRAIL_FILE.exists():
        return []
    try:
        lines = TRAIL_FILE.read_text(encoding="utf-8").strip().splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return list(reversed(out))


# ---------------- guards ----------------
def _ctx(request, user=None, **kw):
    base = _portal_ctx(request, user, **kw)
    base["qms_nav"] = True
    return base


def _require_pro(request):
    user = _current_user(request)
    if not user:
        return None, RedirectResponse("/portal/login", status_code=303)
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    if plan["monthly"] == 0:
        # Browser page loads get a designed lock page; form posts / API callers keep the redirect.
        accept = request.headers.get("accept", "")
        if request.method == "GET" and "text/html" in accept:
            msg = (f"Assalam-o-Alaikum, I'm {user['name']} ({user['email']}). "
                   f"I want to upgrade my PharmaReg Audit Cloud account to Professional ($49/mo) "
                   f"for QMS Lite access. Please share bank transfer details.")
            wa = "https://wa.me/" + WHATSAPP_NUMBER + "?text=" + urllib.parse.quote(msg)
            return None, templates.TemplateResponse(
                request, "qms_lock.html", _ctx(request, user, wa_link=wa), status_code=403)
        return None, RedirectResponse("/portal/upgrade", status_code=303)
    if not user.get("active", True):
        return None, RedirectResponse("/portal/login", status_code=303)
    return user, None


def _esign_ok(user, password):
    return bool(password) and _verify_pw(password, user["salt"], user["pw_hash"])


def _safe_filename(name):
    name = os.path.basename(name or "file")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "file"


# ---------------- QMS home / dashboard ----------------
@router.get("/portal/qms", response_class=HTMLResponse)
def qms_home(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    docs = _get("docs"); devs = _get("deviations"); capas = _get("capas")
    chgs = _get("changes"); trs = _get("training")
    mine = lambda d: [x for x in d.values() if x.get("uid") == user["id"]]
    kpis = {
        "docs_effective": sum(1 for x in mine(docs) if x["status"] == "effective"),
        "docs_review": sum(1 for x in mine(docs) if x["status"] == "in_review"),
        "dev_open": sum(1 for x in mine(devs) if x["status"] != "closed"),
        "capa_open": sum(1 for x in mine(capas) if x["status"] not in ("closed",)),
        "chg_open": sum(1 for x in mine(chgs) if x["status"] not in ("closed", "rejected")),
        "tr_pending": sum(1 for x in mine(trs) if not x.get("completed_at")),
    }
    return templates.TemplateResponse(request, "qms_dashboard.html",
                                      _ctx(request, user, kpis=kpis, trail=recent_trail(15)))

# ---------------- Documents ----------------
@router.get("/portal/qms/docs", response_class=HTMLResponse)
def docs_list(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    docs = sorted((d for d in _get("docs").values() if d["uid"] == user["id"]),
                  key=lambda d: d["updated"], reverse=True)
    return templates.TemplateResponse(request, "qms_docs.html", _ctx(request, user, docs=docs))


@router.post("/portal/qms/docs/new")
async def docs_new(request: Request, title: str = Form(""), dtype: str = Form("SOP"),
                   note: str = Form(""), file: UploadFile = File(None)):
    user, redir = _require_pro(request)
    if redir:
        return redir
    title = title.strip()[:160]
    if not title:
        return RedirectResponse("/portal/qms/docs", status_code=303)
    if not file or not file.filename:
        return templates.TemplateResponse(
            request, "qms_docs.html",
            _ctx(request, user, docs=sorted(
                (d for d in _get("docs").values() if d["uid"] == user["id"]),
                key=lambda d: d["updated"], reverse=True),
                error="Please attach the document file (PDF, DOCX, etc.) — a document needs at least one version before it can go for review."))
    doc_id = _new_id("d")
    versions = []
    if file and file.filename:
        content = await file.read()
        if len(content) > MAX_FILE_MB * 1024 * 1024:
            return templates.TemplateResponse(
                request, "qms_docs.html",
                _ctx(request, user, docs=[], error=f"File too large (max {MAX_FILE_MB} MB)."))
        fname = _safe_filename(file.filename)
        dest = FILES_DIR / doc_id
        dest.mkdir(exist_ok=True)
        (dest / f"v1_{fname}").write_bytes(content)
        versions.append({"v": 1, "filename": fname, "by": user["name"], "at": _ts(),
                         "note": note.strip()[:300]})
    docs = _get("docs")
    docs[doc_id] = {"id": doc_id, "uid": user["id"], "title": title, "type": dtype[:40],
                    "status": "draft", "versions": versions, "current_v": 1 if versions else 0,
                    "approvals": [], "created": _ts(), "updated": _ts()}
    _put("docs", docs)
    trail(user["id"], user["name"], "document_created", "document", doc_id, title)
    return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)


@router.get("/portal/qms/docs/{doc_id}", response_class=HTMLResponse)
def doc_detail(request: Request, doc_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    doc = _get("docs").get(doc_id)
    if not doc or doc["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/docs", status_code=303)
    return templates.TemplateResponse(request, "qms_doc.html", _ctx(request, user, doc=doc))


@router.post("/portal/qms/docs/{doc_id}/submit")
async def doc_submit(request: Request, doc_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    docs = _get("docs")
    doc = docs.get(doc_id)
    if doc and doc["uid"] == user["id"] and doc["status"] == "draft" and doc["versions"]:
        doc["status"] = "in_review"; doc["updated"] = _ts()
        _put("docs", docs)
        trail(user["id"], user["name"], "document_submitted", "document", doc_id, doc["title"])
    return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)


@router.post("/portal/qms/docs/{doc_id}/approve")
async def doc_approve(request: Request, doc_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    docs = _get("docs")
    doc = docs.get(doc_id)
    if not doc or doc["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/docs", status_code=303)
    if doc["status"] != "in_review":
        return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)
    if not _esign_ok(user, form.get("password")):
        return templates.TemplateResponse(request, "qms_doc.html",
                                          _ctx(request, user, doc=doc,
                                               error="E-signature failed: wrong password."))
    doc["status"] = "effective"
    doc["approvals"].append({"by": user["name"], "email": user["email"], "at": _ts(),
                             "meaning": "Approved as effective", "version": doc["current_v"]})
    doc["updated"] = _ts()
    _put("docs", docs)
    trail(user["id"], user["name"], "document_approved_esign", "document", doc_id,
          f"v{doc['current_v']} effective")
    return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)


@router.post("/portal/qms/docs/{doc_id}/reject")
async def doc_reject(request: Request, doc_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    docs = _get("docs")
    doc = docs.get(doc_id)
    if doc and doc["uid"] == user["id"] and doc["status"] == "in_review":
        doc["status"] = "draft"; doc["updated"] = _ts()
        _put("docs", docs)
        trail(user["id"], user["name"], "document_rejected", "document", doc_id,
              (form.get("reason") or "")[:200])
    return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)


@router.post("/portal/qms/docs/{doc_id}/obsolete")
async def doc_obsolete(request: Request, doc_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    docs = _get("docs")
    doc = docs.get(doc_id)
    if not doc or doc["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/docs", status_code=303)
    if not _esign_ok(user, form.get("password")):
        return templates.TemplateResponse(request, "qms_doc.html",
                                          _ctx(request, user, doc=doc,
                                               error="E-signature failed: wrong password."))
    doc["status"] = "obsolete"; doc["updated"] = _ts()
    _put("docs", docs)
    trail(user["id"], user["name"], "document_obsoleted_esign", "document", doc_id, doc["title"])
    return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)


@router.post("/portal/qms/docs/{doc_id}/new-version")
async def doc_new_version(request: Request, doc_id: str, note: str = Form(""),
                          file: UploadFile = File(None)):
    user, redir = _require_pro(request)
    if redir:
        return redir
    docs = _get("docs")
    doc = docs.get(doc_id)
    if not doc or doc["uid"] != user["id"] or not (file and file.filename):
        return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)
    content = await file.read()
    if len(content) > MAX_FILE_MB * 1024 * 1024:
        return templates.TemplateResponse(request, "qms_doc.html",
                                          _ctx(request, user, doc=doc,
                                               error=f"File too large (max {MAX_FILE_MB} MB)."))
    v = doc["current_v"] + 1
    fname = _safe_filename(file.filename)
    dest = FILES_DIR / doc_id
    dest.mkdir(exist_ok=True)
    (dest / f"v{v}_{fname}").write_bytes(content)
    doc["versions"].append({"v": v, "filename": fname, "by": user["name"], "at": _ts(),
                            "note": note.strip()[:300]})
    doc["current_v"] = v
    doc["status"] = "draft"
    doc["updated"] = _ts()
    _put("docs", docs)
    trail(user["id"], user["name"], "document_new_version", "document", doc_id, f"v{v}")
    return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)


@router.get("/portal/qms/files/{doc_id}/{version}")
def doc_file(request: Request, doc_id: str, version: int):
    user, redir = _require_pro(request)
    if redir:
        return redir
    doc = _get("docs").get(doc_id)
    if not doc or doc["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/docs", status_code=303)
    ver = next((v for v in doc["versions"] if v["v"] == version), None)
    if not ver:
        return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)
    path = FILES_DIR / doc_id / f"v{version}_{ver['filename']}"
    if not path.exists():
        return RedirectResponse(f"/portal/qms/docs/{doc_id}", status_code=303)
    return FileResponse(path, filename=ver["filename"])

# ---------------- Deviations ----------------
@router.get("/portal/qms/deviations", response_class=HTMLResponse)
def devs_list(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    devs = sorted((d for d in _get("deviations").values() if d["uid"] == user["id"]),
                  key=lambda d: d["created"], reverse=True)
    return templates.TemplateResponse(request, "qms_deviations.html", _ctx(request, user, devs=devs))


@router.post("/portal/qms/deviations/new")
async def dev_new(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    title = (form.get("title") or "").strip()[:160]
    if not title:
        return RedirectResponse("/portal/qms/deviations", status_code=303)
    dev_id = _new_id("dv")
    devs = _get("deviations")
    devs[dev_id] = {"id": dev_id, "uid": user["id"], "title": title,
                    "description": (form.get("description") or "").strip()[:2000],
                    "department": (form.get("department") or "").strip()[:80],
                    "severity": (form.get("severity") or "minor")[:20],
                    "detected": (form.get("detected") or _ts()[:10]),
                    "status": "open", "investigation": "", "root_cause": "",
                    "capa_id": "", "created": _ts(), "updated": _ts(),
                    "raised_by": user["name"]}
    _put("deviations", devs)
    trail(user["id"], user["name"], "deviation_raised", "deviation", dev_id, title)
    return RedirectResponse(f"/portal/qms/deviations/{dev_id}", status_code=303)


@router.get("/portal/qms/deviations/{dev_id}", response_class=HTMLResponse)
def dev_detail(request: Request, dev_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    dev = _get("deviations").get(dev_id)
    if not dev or dev["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/deviations", status_code=303)
    capa = _get("capas").get(dev.get("capa_id") or "")
    return templates.TemplateResponse(request, "qms_deviation.html",
                                      _ctx(request, user, dev=dev, capa=capa))


@router.post("/portal/qms/deviations/{dev_id}/investigate")
async def dev_investigate(request: Request, dev_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    devs = _get("deviations")
    dev = devs.get(dev_id)
    if dev and dev["uid"] == user["id"] and dev["status"] == "open":
        dev["investigation"] = (form.get("investigation") or "").strip()[:3000]
        dev["root_cause"] = (form.get("root_cause") or "").strip()[:1000]
        dev["status"] = "investigating"; dev["updated"] = _ts()
        _put("deviations", devs)
        trail(user["id"], user["name"], "deviation_investigated", "deviation", dev_id, dev["title"])
    return RedirectResponse(f"/portal/qms/deviations/{dev_id}", status_code=303)


@router.post("/portal/qms/deviations/{dev_id}/close")
async def dev_close(request: Request, dev_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    devs = _get("deviations")
    dev = devs.get(dev_id)
    if not dev or dev["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/deviations", status_code=303)
    if not _esign_ok(user, form.get("password")):
        capa = _get("capas").get(dev.get("capa_id") or "")
        return templates.TemplateResponse(request, "qms_deviation.html",
                                          _ctx(request, user, dev=dev, capa=capa,
                                               error="E-signature failed: wrong password."))
    dev["status"] = "closed"; dev["updated"] = _ts()
    dev["closure_note"] = (form.get("closure_note") or "").strip()[:1000]
    _put("deviations", devs)
    trail(user["id"], user["name"], "deviation_closed_esign", "deviation", dev_id, dev["title"])
    return RedirectResponse(f"/portal/qms/deviations/{dev_id}", status_code=303)


# ---------------- CAPA ----------------
@router.get("/portal/qms/capas", response_class=HTMLResponse)
def capas_list(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    capas = sorted((c for c in _get("capas").values() if c["uid"] == user["id"]),
                   key=lambda c: c["created"], reverse=True)
    return templates.TemplateResponse(request, "qms_capas.html", _ctx(request, user, capas=capas))


@router.post("/portal/qms/capas/new")
async def capa_new(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    title = (form.get("title") or "").strip()[:160]
    if not title:
        return RedirectResponse("/portal/qms/capas", status_code=303)
    capa_id = _new_id("ca")
    capas = _get("capas")
    capas[capa_id] = {"id": capa_id, "uid": user["id"], "title": title,
                      "description": (form.get("description") or "").strip()[:2000],
                      "source": (form.get("source") or "manual")[:40],
                      "source_ref": (form.get("source_ref") or "").strip()[:40],
                      "owner": (form.get("owner") or user["name"]).strip()[:120],
                      "due": (form.get("due") or "")[:10],
                      "status": "open", "actions": [], "effectiveness": "",
                      "created": _ts(), "updated": _ts(), "created_by": user["name"]}
    _put("capas", capas)
    # link back to deviation if created from one
    if capas[capa_id]["source"] == "deviation" and capas[capa_id]["source_ref"]:
        devs = _get("deviations")
        dv = devs.get(capas[capa_id]["source_ref"])
        if dv and dv["uid"] == user["id"]:
            dv["capa_id"] = capa_id; dv["updated"] = _ts()
            _put("deviations", devs)
    trail(user["id"], user["name"], "capa_created", "capa", capa_id, title)
    return RedirectResponse(f"/portal/qms/capas/{capa_id}", status_code=303)


@router.get("/portal/qms/capas/{capa_id}", response_class=HTMLResponse)
def capa_detail(request: Request, capa_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    capa = _get("capas").get(capa_id)
    if not capa or capa["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/capas", status_code=303)
    return templates.TemplateResponse(request, "qms_capa.html", _ctx(request, user, capa=capa))


@router.post("/portal/qms/capas/{capa_id}/action")
async def capa_action_add(request: Request, capa_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    capas = _get("capas")
    capa = capas.get(capa_id)
    text = (form.get("text") or "").strip()[:500]
    if capa and capa["uid"] == user["id"] and text and capa["status"] in ("open", "in_progress"):
        capa["actions"].append({"text": text, "done": False, "done_at": "", "by": user["name"]})
        if capa["status"] == "open":
            capa["status"] = "in_progress"
        capa["updated"] = _ts()
        _put("capas", capas)
        trail(user["id"], user["name"], "capa_action_added", "capa", capa_id, text[:100])
    return RedirectResponse(f"/portal/qms/capas/{capa_id}", status_code=303)


@router.post("/portal/qms/capas/{capa_id}/action/{idx}/done")
async def capa_action_done(request: Request, capa_id: str, idx: int):
    user, redir = _require_pro(request)
    if redir:
        return redir
    capas = _get("capas")
    capa = capas.get(capa_id)
    if capa and capa["uid"] == user["id"] and 0 <= idx < len(capa["actions"]):
        a = capa["actions"][idx]
        a["done"] = not a["done"]
        a["done_at"] = _ts() if a["done"] else ""
        capa["updated"] = _ts()
        _put("capas", capas)
    return RedirectResponse(f"/portal/qms/capas/{capa_id}", status_code=303)


@router.post("/portal/qms/capas/{capa_id}/verify")
async def capa_verify(request: Request, capa_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    capas = _get("capas")
    capa = capas.get(capa_id)
    if capa and capa["uid"] == user["id"] and capa["status"] == "in_progress":
        capa["effectiveness"] = (form.get("effectiveness") or "").strip()[:2000]
        capa["status"] = "pending_verification"; capa["updated"] = _ts()
        _put("capas", capas)
        trail(user["id"], user["name"], "capa_effectiveness_recorded", "capa", capa_id, capa["title"])
    return RedirectResponse(f"/portal/qms/capas/{capa_id}", status_code=303)


@router.post("/portal/qms/capas/{capa_id}/close")
async def capa_close(request: Request, capa_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    capas = _get("capas")
    capa = capas.get(capa_id)
    if not capa or capa["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/capas", status_code=303)
    if not _esign_ok(user, form.get("password")):
        return templates.TemplateResponse(request, "qms_capa.html",
                                          _ctx(request, user, capa=capa,
                                               error="E-signature failed: wrong password."))
    capa["status"] = "closed"; capa["updated"] = _ts()
    _put("capas", capas)
    trail(user["id"], user["name"], "capa_closed_esign", "capa", capa_id, capa["title"])
    return RedirectResponse(f"/portal/qms/capas/{capa_id}", status_code=303)

# ---------------- Change control ----------------
@router.get("/portal/qms/changes", response_class=HTMLResponse)
def chgs_list(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    chgs = sorted((c for c in _get("changes").values() if c["uid"] == user["id"]),
                  key=lambda c: c["created"], reverse=True)
    return templates.TemplateResponse(request, "qms_changes.html", _ctx(request, user, chgs=chgs))


@router.post("/portal/qms/changes/new")
async def chg_new(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    title = (form.get("title") or "").strip()[:160]
    if not title:
        return RedirectResponse("/portal/qms/changes", status_code=303)
    ch_id = _new_id("cc")
    chgs = _get("changes")
    chgs[ch_id] = {"id": ch_id, "uid": user["id"], "title": title,
                   "description": (form.get("description") or "").strip()[:2000],
                   "ctype": (form.get("ctype") or "process")[:40],
                   "impact": "", "decision": "",
                   "status": "requested", "created": _ts(), "updated": _ts(),
                   "requested_by": user["name"]}
    _put("changes", chgs)
    trail(user["id"], user["name"], "change_requested", "change", ch_id, title)
    return RedirectResponse(f"/portal/qms/changes/{ch_id}", status_code=303)


@router.get("/portal/qms/changes/{ch_id}", response_class=HTMLResponse)
def chg_detail(request: Request, ch_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    ch = _get("changes").get(ch_id)
    if not ch or ch["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/changes", status_code=303)
    return templates.TemplateResponse(request, "qms_change.html", _ctx(request, user, ch=ch))


def _chg_transition(user, ch_id, frm, to, form, need_esign=False, impact=""):
    chgs = _get("changes")
    ch = chgs.get(ch_id)
    if not ch or ch["uid"] != user["id"] or ch["status"] != frm:
        return None, "invalid"
    if need_esign and not _esign_ok(user, form.get("password")):
        return ch, "esign"
    if impact:
        ch["impact"] = impact[:2000]
    ch["status"] = to; ch["updated"] = _ts()
    _put("changes", chgs)
    trail(user["id"], user["name"], f"change_{to}", "change", ch_id, ch["title"])
    return ch, "ok"


@router.post("/portal/qms/changes/{ch_id}/assess")
async def chg_assess(request: Request, ch_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    ch, res = _chg_transition(user, ch_id, "requested", "assessing", form,
                             impact=(form.get("impact") or ""))
    return RedirectResponse(f"/portal/qms/changes/{ch_id}", status_code=303)


@router.post("/portal/qms/changes/{ch_id}/approve")
async def chg_approve(request: Request, ch_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    ch, res = _chg_transition(user, ch_id, "assessing", "approved", form, need_esign=True)
    if res == "esign":
        return templates.TemplateResponse(request, "qms_change.html",
                                          _ctx(request, user, ch=ch,
                                               error="E-signature failed: wrong password."))
    return RedirectResponse(f"/portal/qms/changes/{ch_id}", status_code=303)


@router.post("/portal/qms/changes/{ch_id}/reject")
async def chg_reject(request: Request, ch_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    chgs = _get("changes")
    ch = chgs.get(ch_id)
    if ch and ch["uid"] == user["id"] and ch["status"] == "assessing":
        ch["status"] = "rejected"
        ch["decision"] = (form.get("decision") or "").strip()[:1000]
        ch["updated"] = _ts()
        _put("changes", chgs)
        trail(user["id"], user["name"], "change_rejected", "change", ch_id, ch["title"])
    return RedirectResponse(f"/portal/qms/changes/{ch_id}", status_code=303)


@router.post("/portal/qms/changes/{ch_id}/implement")
async def chg_implement(request: Request, ch_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    ch, res = _chg_transition(user, ch_id, "approved", "implementing", await request.form())
    return RedirectResponse(f"/portal/qms/changes/{ch_id}", status_code=303)


@router.post("/portal/qms/changes/{ch_id}/close")
async def chg_close(request: Request, ch_id: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    ch, res = _chg_transition(user, ch_id, "implementing", "closed", form, need_esign=True)
    if res == "esign":
        return templates.TemplateResponse(request, "qms_change.html",
                                          _ctx(request, user, ch=ch,
                                               error="E-signature failed: wrong password."))
    return RedirectResponse(f"/portal/qms/changes/{ch_id}", status_code=303)


# ---------------- Training ----------------
@router.get("/portal/qms/training", response_class=HTMLResponse)
def training_home(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    staff = sorted((s for s in _get("staff").values() if s["uid"] == user["id"]),
                   key=lambda s: s["name"])
    trs = [t for t in _get("training").values() if t["uid"] == user["id"]]
    docs = {d["id"]: d for d in _get("docs").values()
            if d["uid"] == user["id"] and d["status"] == "effective"}
    staff_map = {s["id"]: s for s in staff}
    return templates.TemplateResponse(request, "qms_training.html",
                                      _ctx(request, user, staff=staff, trs=trs,
                                           docs=docs, staff_map=staff_map))


@router.post("/portal/qms/staff/new")
async def staff_new(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    name = (form.get("name") or "").strip()[:120]
    if not name:
        return RedirectResponse("/portal/qms/training", status_code=303)
    staff = _get("staff")
    sid = _new_id("st")
    staff[sid] = {"id": sid, "uid": user["id"], "name": name,
                  "role": (form.get("role") or "").strip()[:80],
                  "email": (form.get("email") or "").strip()[:120],
                  "created": _ts()}
    _put("staff", staff)
    trail(user["id"], user["name"], "staff_added", "staff", sid, name)
    return RedirectResponse("/portal/qms/training", status_code=303)


@router.post("/portal/qms/training/assign")
async def training_assign(request: Request):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    staff = _get("staff").get(form.get("staff_id") or "")
    doc = _get("docs").get(form.get("doc_id") or "")
    if not staff or staff["uid"] != user["id"] or not doc or doc["uid"] != user["id"]:
        return RedirectResponse("/portal/qms/training", status_code=303)
    trs = _get("training")
    tid = _new_id("tr")
    trs[tid] = {"id": tid, "uid": user["id"], "staff_id": staff["id"],
                "staff_name": staff["name"], "doc_id": doc["id"],
                "doc_title": doc["title"], "version": doc["current_v"],
                "assigned_at": _ts()[:10], "completed_at": "", "esign": {}}
    _put("training", trs)
    trail(user["id"], user["name"], "training_assigned", "training", tid,
          f"{staff['name']} <- {doc['title']} v{doc['current_v']}")
    return RedirectResponse("/portal/qms/training", status_code=303)


@router.post("/portal/qms/training/{tid}/complete")
async def training_complete(request: Request, tid: str):
    user, redir = _require_pro(request)
    if redir:
        return redir
    form = await request.form()
    trs = _get("training")
    tr = trs.get(tid)
    if not tr or tr["uid"] != user["id"] or tr.get("completed_at"):
        return RedirectResponse("/portal/qms/training", status_code=303)
    if not _esign_ok(user, form.get("password")):
        staff = sorted((s for s in _get("staff").values() if s["uid"] == user["id"]),
                       key=lambda s: s["name"])
        docs = {d["id"]: d for d in _get("docs").values()
                if d["uid"] == user["id"] and d["status"] == "effective"}
        return templates.TemplateResponse(
            request, "qms_training.html",
            _ctx(request, user, staff=staff,
                 trs=[t for t in trs.values() if t["uid"] == user["id"]],
                 docs=docs, staff_map={s["id"]: s for s in staff},
                 error="E-signature failed: wrong password."))
    tr["completed_at"] = _ts()
    tr["esign"] = {"by": user["name"], "email": user["email"], "at": _ts(),
                   "meaning": f"Training completed: {tr['doc_title']} v{tr['version']}"}
    _put("training", trs)
    trail(user["id"], user["name"], "training_completed_esign", "training", tid,
          f"{tr['staff_name']} <- {tr['doc_title']}")
    return RedirectResponse("/portal/qms/training", status_code=303)
