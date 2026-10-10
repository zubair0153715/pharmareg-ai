"""PharmaReg Remediation — document fix workflow.

A client links one of their audit findings, uploads the faulty document,
an AI draft is generated (Gemini), and our regulatory specialist reviews
and approves it before the client downloads the corrected version.
An AI draft is NEVER delivered without explicit human approval.

Pricing model (no rebuild needed to change):
    FREE_FIX_QUOTA (env, default 1) — each account gets this many free fix
    requests. Beyond the quota, only Pro/Enterprise plans may submit; Free
    users see their remaining quota and an upsell when it is exhausted.
"""
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates

from app.portal import (_current_user, _ctx as _portal_ctx, _is_admin,
                        PLANS)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
FILES_DIR = DATA_DIR / "remediation_files"
FILES_DIR.mkdir(exist_ok=True)
FIXES_FILE = DATA_DIR / "remediation_fixes.json"

# Configurable without a rebuild: set FREE_FIX_QUOTA in the environment.
FREE_FIX_QUOTA = int(os.environ.get("FREE_FIX_QUOTA", "1"))
MAX_FILE_MB = 15
ALLOWED_EXTS = {".pdf", ".docx", ".doc", ".txt"}

# submitted -> in_review -> ready -> downloaded
STATUSES = ["submitted", "in_review", "ready", "downloaded"]
STATUS_LABELS = {
    "submitted": "Submitted",
    "in_review": "In review",
    "ready": "Fixed document ready",
    "downloaded": "Downloaded",
}


# ---------------- AI draft engine (Gemini, human approval gate) ----------------
# Reads GEMINI_API_KEY from the environment at call time. If the key is
# missing (or the call fails), the flow falls back to fully manual fixing —
# the specialist uploads the corrected document directly. An AI draft is
# NEVER sent to the client without the owner's explicit approval.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
MAX_DOC_CHARS = 12000


def _gemini_generate(prompt, api_key, model=GEMINI_MODEL, timeout=120):
    """Call the Gemini REST API. Returns the generated text.

    Uses a browser User-Agent: some egress filters block python-urllib's
    default UA (WAF 403).
    """
    import urllib.request
    import urllib.error
    url = ("https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent")
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 8192},
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0",
                 "x-goog-api-key": api_key},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Gemini API HTTP {e.code}") from e
    except Exception as e:
        raise RuntimeError(f"Gemini API call failed: {e}") from e
    try:
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError("Unexpected Gemini response shape") from e
    if not text:
        raise RuntimeError("Gemini returned an empty draft")
    return text


def _extract_pdf_plumber(path):
    """PDF -> markdown-ish text with tables preserved (pdfplumber).

    Tables become GitHub-style markdown tables so downstream AI drafting
    sees complete rows instead of pypdf's mangled column soup.
    Raises on any failure so the caller can fall back to pypdf.
    """
    import pdfplumber

    chunks = []
    with pdfplumber.open(str(path)) as pdf:
        for page in pdf.pages:
            text = (page.extract_text() or "").strip()
            tables = page.extract_tables() or []
            if text:
                chunks.append(text)
            for tbl in tables:
                rows = [[(c or "").strip() for c in r] for r in tbl if any(c for c in r)]
                if not rows:
                    continue
                # first row = header
                header, body = rows[0], rows[1:]
                md = ["| " + " | ".join(header) + " |",
                      "| " + " | ".join("---" for _ in header) + " |"]
                md += ["| " + " | ".join(r) + " |" for r in body]
                chunks.append("\n".join(md))
    out = "\n\n".join(c for c in chunks if c.strip())
    if not out.strip():
        raise ValueError("pdfplumber extracted nothing")
    return out


def _extract_doc_text(path, filename):
    """Best-effort text extraction for txt/pdf/docx. Returns "" if none."""
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext == ".txt":
            return path.read_text(encoding="utf-8", errors="replace")
        if ext == ".pdf":
            # pdfplumber first: real table structure as markdown (pypdf mangles
            # tables in regulatory PDFs). Falls back to pypdf plain text.
            try:
                return _extract_pdf_plumber(path)
            except Exception:
                pass
            try:
                from pypdf import PdfReader
            except ImportError:
                return ""
            reader = PdfReader(str(path))
            return "\n".join((page.extract_text() or "") for page in reader.pages)
        if ext in (".docx", ".doc"):
            # docx is a zip of XML; pull <w:t> runs with stdlib only.
            import zipfile
            import xml.etree.ElementTree as ET
            with zipfile.ZipFile(path) as z:
                xml_bytes = z.read("word/document.xml")
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            root = ET.fromstring(xml_bytes)
            texts = [t.text for t in root.iterfind(".//w:t", ns) if t.text]
            # crude paragraph breaks
            paras = []
            for p in root.iterfind(".//w:p", ns):
                pt = "".join(t.text for t in p.iterfind(".//w:t", ns) if t.text)
                if pt.strip():
                    paras.append(pt)
            return "\n".join(paras) if paras else " ".join(texts)
    except Exception:
        return ""
    return ""


def _draft_prompt(fix, doc_text):
    fw = (fix.get("audit_framework") or "GMP").upper()
    doc_part = (doc_text[:MAX_DOC_CHARS]
                if doc_text else "[original document text could not be extracted; work from the finding below]")
    return (
        "You are a pharmaceutical regulatory compliance specialist assisting with "
        f"{fw} GMP documentation.\n\n"
        "A client submitted a document with the following audit finding:\n---\n"
        f"{fix.get('finding', '')}\n---\n"
        + (f"Client's extra notes:\n{fix.get('fix_notes', '')}\n---\n" if fix.get("fix_notes") else "") +
        "Original document text (may be truncated):\n---\n"
        f"{doc_part}\n---\n\n"
        "Task: produce a CORRECTED version of the document that resolves the finding, "
        f"following {fw} GMP documentation expectations. Keep the original structure and "
        "formatting as much as possible; mark every changed or added section with a "
        "[REVISED] tag at the start of the section.\n\n"
        "Output ONLY the corrected document text — no preamble, no explanations, "
        "no commentary outside the document itself."
    )


def generate_fix_draft(fix):
    """Generate an AI draft of the corrected document for a fix request.

    fix: the fix-request record (dict). Returns the draft text.
    Raises RuntimeError if GEMINI_API_KEY is missing or the call fails —
    callers must fall back to the manual flow.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured")
    path = FILES_DIR / fix["id"] / f"original_{fix['original_filename']}"
    doc_text = _extract_doc_text(path, fix["original_filename"]) if path.exists() else ""
    prompt = _draft_prompt(fix, doc_text)
    return _gemini_generate(prompt, api_key)


def _draft_worker(fid):
    """Background thread: generate the AI draft after a client submits."""
    import threading
    try:
        fixes = _load_fixes()
        fix = fixes.get(fid)
        if not fix or fix.get("ai_draft_status") not in (None, "pending"):
            return
        try:
            draft = generate_fix_draft(fix)
        except RuntimeError as e:
            fixes = _load_fixes()
            if fid in fixes:
                fixes[fid]["ai_draft_status"] = (
                    "skipped" if "not configured" in str(e) else "failed")
                fixes[fid]["ai_draft_error"] = str(e)[:300]
                fixes[fid]["updated"] = _ts()
                _save_fixes(fixes)
            return
        fixes = _load_fixes()
        if fid in fixes:
            fixes[fid]["ai_draft"] = draft
            fixes[fid]["ai_draft_status"] = "ready"
            fixes[fid]["ai_draft_error"] = ""
            fixes[fid]["updated"] = _ts()
            _save_fixes(fixes)
    except Exception:
        pass  # never crash the worker on a draft failure


def _start_draft_thread(fid):
    import threading
    t = threading.Thread(target=_draft_worker, args=(fid,), daemon=True)
    t.start()


# ---------------- storage ----------------
def _load_fixes():
    if FIXES_FILE.exists():
        try:
            return json.loads(FIXES_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_fixes(fixes):
    tmp = FIXES_FILE.with_suffix(FIXES_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(fixes, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    tmp.replace(FIXES_FILE)


def _now():
    return datetime.now(timezone.utc)


def _ts():
    return _now().isoformat(timespec="seconds")


def _ctx(request, user=None, **kw):
    base = _portal_ctx(request, user, **kw)
    base["free_fix_quota"] = FREE_FIX_QUOTA
    base["status_labels"] = STATUS_LABELS
    return base


def _safe_filename(name):
    name = os.path.basename(name or "file")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "file"


def _used_fixes(uid):
    return sum(1 for f in _load_fixes().values() if f.get("uid") == uid)


def _my_fixes(uid):
    return sorted(
        (f for f in _load_fixes().values() if f.get("uid") == uid),
        key=lambda f: f["created"], reverse=True)


def _free_left(user):
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    if plan["monthly"] > 0:
        return None
    return max(0, FREE_FIX_QUOTA - _used_fixes(user["id"]))


def _can_submit(user):
    """(allowed, reason). Free plan gets FREE_FIX_QUOTA fixes; then upsell."""
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    if plan["monthly"] > 0:
        return True, None
    used = _used_fixes(user["id"])
    if used < FREE_FIX_QUOTA:
        return True, None
    return False, (
        f"You have used your {FREE_FIX_QUOTA} free fix "
        f"{'request' if FREE_FIX_QUOTA == 1 else 'requests'}. "
        "Upgrade to Professional for unlimited document fixes.")


def _audits_for(user):
    from app.portal import _audits
    return sorted(
        (a for a in _audits().values() if a.get("uid") == user["id"]),
        key=lambda a: a.get("ts", ""), reverse=True)


async def _read_upload(file: UploadFile):
    """Returns (filename, bytes) or raises ValueError."""
    if not file or not file.filename:
        raise ValueError("Please attach your document.")
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTS:
        raise ValueError(
            f"Only {', '.join(sorted(ALLOWED_EXTS))} files are accepted.")
    content = await file.read()
    if len(content) > MAX_FILE_MB * 1024 * 1024:
        raise ValueError(f"File too large (max {MAX_FILE_MB} MB).")
    if not content:
        raise ValueError("The uploaded file is empty.")
    return _safe_filename(file.filename), content


# ---------------- client ----------------
@router.get("/portal/remediation", response_class=HTMLResponse)
def remediation_home(request: Request):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/portal/login", status_code=303)
    fixes = _my_fixes(user["id"])
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    used = _used_fixes(user["id"])
    return templates.TemplateResponse(
        request, "remediation.html",
        _ctx(request, user, fixes=fixes, plan=plan,
             used=used, free_left=_free_left(user)))


@router.get("/portal/remediation/new", response_class=HTMLResponse)
def remediation_new_form(request: Request):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/portal/login", status_code=303)
    ok, reason = _can_submit(user)
    audits = _audits_for(user)
    return templates.TemplateResponse(
        request, "remediation_new.html",
        _ctx(request, user, audits=audits, eligible=ok, reason=reason,
             error=None))


@router.post("/portal/remediation/new", response_class=HTMLResponse)
async def remediation_new(request: Request,
                          audit_id: str = Form(""),
                          finding: str = Form(""),
                          fix_notes: str = Form(""),
                          file: UploadFile = File(None)):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/portal/login", status_code=303)
    ok, reason = _can_submit(user)
    audits = _audits_for(user)
    if not ok:
        return templates.TemplateResponse(
            request, "remediation_new.html",
            _ctx(request, user, audits=audits, eligible=False, reason=reason,
                 error=reason))
    finding = finding.strip()[:2000]
    fix_notes = fix_notes.strip()[:2000]
    if not finding:
        return templates.TemplateResponse(
            request, "remediation_new.html",
            _ctx(request, user, audits=audits, eligible=True, reason=None,
                 error="Please describe the finding you want fixed."))
    audit = next((a for a in audits if a["id"] == audit_id), None)
    try:
        fname, content = await _read_upload(file)
    except ValueError as e:
        return templates.TemplateResponse(
            request, "remediation_new.html",
            _ctx(request, user, audits=audits, eligible=True, reason=None,
                 error=str(e)))
    fid = "f" + secrets.token_hex(6)
    dest = FILES_DIR / fid
    dest.mkdir(exist_ok=True)
    (dest / f"original_{fname}").write_bytes(content)
    fixes = _load_fixes()
    fixes[fid] = {
        "id": fid,
        "uid": user["id"],
        "user_email": user["email"],
        "user_name": user.get("name", ""),
        "company": user.get("company", ""),
        "audit_id": audit["id"] if audit else "",
        "audit_report_id": audit.get("report_id", "") if audit else "",
        "audit_framework": audit.get("framework", "") if audit else "",
        "finding": finding,
        "fix_notes": fix_notes,
        "original_filename": fname,
        "original_size": len(content),
        "status": "submitted",
        "specialist_note": "",
        "fixed_filename": "",
        "ai_draft": "",
        "ai_draft_status": "pending",
        "ai_draft_error": "",
        "created": _ts(),
        "updated": _ts(),
    }
    _save_fixes(fixes)
    # AI draft generates in the background; the client page never waits.
    _start_draft_thread(fid)
    return RedirectResponse(f"/portal/remediation/{fid}", status_code=303)


@router.get("/portal/remediation/{fid}", response_class=HTMLResponse)
def remediation_detail(request: Request, fid: str):
    user = _current_user(request)
    if not user:
        return RedirectResponse("/portal/login", status_code=303)
    fix = _load_fixes().get(fid)
    if not fix or fix["uid"] != user["id"]:
        return templates.TemplateResponse(
            request, "remediation.html",
            _ctx(request, user, fixes=_my_fixes(user["id"]),
                 plan=PLANS.get(user.get("plan", "free"), PLANS["free"]),
                 used=_used_fixes(user["id"]), free_left=_free_left(user),
                 error="Fix request not found."))
    return templates.TemplateResponse(
        request, "remediation_detail.html", _ctx(request, user, fix=fix))


@router.get("/portal/remediation/files/{fid}/{kind}")
def remediation_file(request: Request, fid: str, kind: str):
    user = _current_user(request)
    fix = _load_fixes().get(fid)
    if kind not in ("original", "fixed"):
        return RedirectResponse("/portal/remediation", status_code=303)
    allowed = False
    if user and fix and fix["uid"] == user["id"]:
        allowed = True
    if _is_admin(request):
        allowed = True
    if not allowed or not fix:
        return RedirectResponse("/portal/login", status_code=303)
    if kind == "original":
        path = FILES_DIR / fid / f"original_{fix['original_filename']}"
        filename = fix["original_filename"]
    else:
        if not fix.get("fixed_filename"):
            return RedirectResponse(f"/portal/remediation/{fid}",
                                    status_code=303)
        path = FILES_DIR / fid / f"fixed_{fix['fixed_filename']}"
        filename = fix["fixed_filename"]
    if not path.exists():
        return RedirectResponse(f"/portal/remediation/{fid}", status_code=303)
    if kind == "fixed" and user and fix["uid"] == user["id"] \
            and fix["status"] == "ready":
        fixes = _load_fixes()
        fixes[fid]["status"] = "downloaded"
        fixes[fid]["updated"] = _ts()
        _save_fixes(fixes)
    return FileResponse(path, filename=filename)


# ---------------- owner / admin ----------------
@router.get("/portal/admin/fixes", response_class=HTMLResponse)
def admin_fixes(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    fixes = sorted(_load_fixes().values(), key=lambda f: f["created"],
                   reverse=True)
    open_fixes = [f for f in fixes if f["status"] in ("submitted", "in_review")]
    return templates.TemplateResponse(
        request, "admin_fixes.html",
        _ctx(request, fixes=fixes, open_fixes=open_fixes))


@router.get("/portal/admin/fix/{fid}", response_class=HTMLResponse)
def admin_fix_detail(request: Request, fid: str):
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    fix = _load_fixes().get(fid)
    if not fix:
        return RedirectResponse("/portal/admin/fixes", status_code=303)
    return templates.TemplateResponse(
        request, "admin_fix.html", _ctx(request, fix=fix, error=None))


@router.post("/portal/admin/fix/{fid}/review")
def admin_fix_review(request: Request, fid: str):
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    fixes = _load_fixes()
    fix = fixes.get(fid)
    if fix and fix["status"] == "submitted":
        fix["status"] = "in_review"
        fix["updated"] = _ts()
        _save_fixes(fixes)
    return RedirectResponse(f"/portal/admin/fix/{fid}", status_code=303)


@router.post("/portal/admin/fix/{fid}/approve-draft", response_class=HTMLResponse)
async def admin_fix_approve_draft(request: Request, fid: str,
                                  draft_text: str = Form(""),
                                  specialist_note: str = Form("")):
    """Owner reviews/edits the AI draft, then approves it as the deliverable.

    The human-approval gate: a draft is never sent to the client without
    this explicit step.
    """
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    fixes = _load_fixes()
    fix = fixes.get(fid)
    if not fix:
        return RedirectResponse("/portal/admin/fixes", status_code=303)
    draft_text = (draft_text or "").strip()
    if not draft_text:
        return templates.TemplateResponse(
            request, "admin_fix.html",
            _ctx(request, fix=fix, error="Draft text is empty — nothing to approve."))
    dest = FILES_DIR / fid
    dest.mkdir(exist_ok=True)
    stem = _safe_filename(os.path.splitext(fix["original_filename"])[0] or "document")
    fname = f"draft_{stem}.txt"
    (dest / f"fixed_{fname}").write_text(draft_text, encoding="utf-8")
    fix["fixed_filename"] = fname
    fix["specialist_note"] = specialist_note.strip()[:2000]
    fix["status"] = "ready"
    fix["updated"] = _ts()
    _save_fixes(fixes)
    return RedirectResponse("/portal/admin/fixes", status_code=303)


@router.post("/portal/admin/fix/{fid}/regenerate")
def admin_fix_regenerate(request: Request, fid: str):
    """Retry AI draft generation (e.g. after a failure or key was added)."""
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    fixes = _load_fixes()
    fix = fixes.get(fid)
    if fix and fix["status"] in ("submitted", "in_review"):
        fix["ai_draft"] = ""
        fix["ai_draft_status"] = "pending"
        fix["ai_draft_error"] = ""
        fix["updated"] = _ts()
        _save_fixes(fixes)
        _start_draft_thread(fid)
    return RedirectResponse(f"/portal/admin/fix/{fid}", status_code=303)


@router.post("/portal/admin/fix/{fid}/complete", response_class=HTMLResponse)
async def admin_fix_complete(request: Request, fid: str,
                             specialist_note: str = Form(""),
                             file: UploadFile = File(None)):
    if not _is_admin(request):
        return RedirectResponse("/portal/admin", status_code=303)
    fixes = _load_fixes()
    fix = fixes.get(fid)
    if not fix:
        return RedirectResponse("/portal/admin/fixes", status_code=303)
    try:
        fname, content = await _read_upload(file)
    except ValueError as e:
        return templates.TemplateResponse(
            request, "admin_fix.html", _ctx(request, fix=fix, error=str(e)))
    dest = FILES_DIR / fid
    dest.mkdir(exist_ok=True)
    (dest / f"fixed_{fname}").write_bytes(content)
    fix["fixed_filename"] = fname
    fix["specialist_note"] = specialist_note.strip()[:2000]
    fix["status"] = "ready"
    fix["updated"] = _ts()
    _save_fixes(fixes)
    return RedirectResponse("/portal/admin/fixes", status_code=303)
