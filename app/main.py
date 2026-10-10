"""PharmaReg AI marketing + lead-capture website.

Lead capture is WhatsApp-based; self-audit submissions are also stored as
JSONL leads for owner follow-up (unlisted /audit/leads page).
PUBLIC_URL is used for canonical links.
"""
import json
import os
import secrets
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.audit_frameworks import (FRAMEWORKS, get_questions, get_domains,
                                  build_report as fw_build_report)
from app import portal as portal_mod
from app import qms as qms_mod
from app import remediation as remediation_mod
from app import billing as billing_mod
from app.portal import _is_admin

PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8000").rstrip("/")
# Business WhatsApp in international format without '+'. Change via env if needed.
WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "923116925020")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
LEADS_FILE = DATA_DIR / "audit_leads.jsonl"
ECTD_LEADS_FILE = DATA_DIR / "ectd_leads.jsonl"

LLMS_TXT = """# PharmaReg AI

> AI-assisted regulatory compliance audits for pharmaceutical manufacturers.
> Founded by Zubair Ahmed, Pharm-D.

## What we do

PharmaReg AI reviews draft registration dossiers, product labels, and patient
information leaflets against pharmaceutical regulatory requirements and returns
a deficiency report plus a corrected, submission-ready draft in days.

## Regulatory frameworks covered

- Saudi Arabia: SFDA registration and labeling requirements
- UAE: Emirates Drug Establishment (EDE) requirements
- United States: FDA 21 CFR Part 201 labeling, PLR format (21 CFR 201.57)
- United Kingdom: MHRA labeling and Patient Information Leaflet requirements
- Cross-cutting: WHO cGMP documentation expectations

## Services and pricing

- PharmaReg Audit Cloud (SaaS): multi-framework GMP self-audits — DRAP (Pakistan),
  SFDA (Saudi Arabia), EDE (UAE) — with accounts, audit history, scored gap reports
  and shareable report links. Free / $49/mo Professional / $199/mo Enterprise:
  https://pharmareg-ai.fastapicloud.dev/portal
- QMS Lite (Professional & Enterprise): lightweight electronic Quality Management
  System — versioned document control with e-signatures, deviation investigation,
  CAPA with effectiveness checks, change control, training records, tamper-evident
  audit trail: https://pharmareg-ai.fastapicloud.dev/qms
- Free DRAP GMP self-audit tool: 48 questions across 10 WHO-GMP domains, instant
  scored gap report with prioritized findings and corrective actions:
  https://pharmareg-ai.fastapicloud.dev/audit
- Document Fixes (first fix free): upload a faulty document from any audit
  finding — AI-assisted draft, reviewed by a regulatory specialist before
  delivery. Unlimited fixes on Professional & Enterprise:
  https://pharmareg-ai.fastapicloud.dev/portal/remediation
- Free sample audit: 2-page audit of one label, leaflet, or dossier section,
  deficiency list with rule citations, delivered in 48 hours.
- Single audit: USD 800-1,200. Full audit of one dossier, label set, or leaflet;
  deficiency report plus corrected submission-ready draft; one revision round;
  3-5 business day turnaround.
- Quarterly retainer: USD 3,000-5,000 per quarter. Up to 4 audits per quarter,
  priority 48-hour turnaround, quarterly regulatory-update briefing.

## How to start

Request a free sample audit at https://pharmareg-ai.fastapicloud.dev/request-audit
or see an example at https://pharmareg-ai.fastapicloud.dev/sample-audit

## Guides

- 7 labeling deficiencies that delay SFDA & EDE approvals:
  https://pharmareg-ai.fastapicloud.dev/guides/labeling-deficiencies

## Note

PharmaReg AI provides advisory reviews based on publicly available regulatory
frameworks. It does not replace legal or regulatory counsel; the manufacturer
retains full responsibility for final submissions.

## Related business

- 24/7 AI Receptionist for Gulf clinics (dental, dermatology, physio, eye):
  WhatsApp appointment booking, missed-call capture, reminders, English & Arabic.
  https://clinic-demo.fastapicloud.dev
"""

app = FastAPI(title="PharmaReg AI")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(portal_mod.router)
app.include_router(qms_mod.router)
app.include_router(remediation_mod.router)
app.include_router(billing_mod.router)
templates = Jinja2Templates(directory="templates")


def _ctx(request: Request, **kw):
    base = {
        "request": request,
        "public_url": PUBLIC_URL,
        "whatsapp_number": WHATSAPP_NUMBER,
    }
    base.update(kw)
    return base


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/llms.txt", response_class=PlainTextResponse)
def llms_txt():
    return LLMS_TXT


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    return (
        "User-agent: *\nAllow: /\n\n"
        "User-agent: GPTBot\nAllow: /\n\n"
        "User-agent: PerplexityBot\nAllow: /\n\n"
        "User-agent: Google-Extended\nAllow: /\n\n"
        f"Sitemap: {PUBLIC_URL}/sitemap.xml\n"
    )


@app.get("/sitemap.xml")
def sitemap():
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"<url><loc>{PUBLIC_URL}/</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/request-audit</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/sample-audit</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/audit</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/portal</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/portal/remediation</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/qms</loc></url>\n"
        f"<url><loc>{PUBLIC_URL}/guides/labeling-deficiencies</loc></url>\n"
        "</urlset>"
    )
    return Response(xml, media_type="application/xml")


_PWA_DIR = Path(__file__).resolve().parent.parent / "static"


@app.get("/manifest.json")
def pwa_manifest():
    return Response((_PWA_DIR / "manifest.json").read_bytes(),
                    media_type="application/manifest+json")


@app.get("/sw.js")
def pwa_sw():
    return Response((_PWA_DIR / "sw.js").read_bytes(),
                    media_type="application/javascript")


@app.get("/icon-192.png")
def pwa_icon192():
    return Response((_PWA_DIR / "icon-192.png").read_bytes(), media_type="image/png")


@app.get("/icon-512.png")
def pwa_icon512():
    return Response((_PWA_DIR / "icon-512.png").read_bytes(), media_type="image/png")


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(request))


@app.get("/request-audit", response_class=HTMLResponse)
def request_audit(request: Request):
    return templates.TemplateResponse(request, "request.html", _ctx(request))


@app.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return templates.TemplateResponse(request, "terms.html", _ctx(request))


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request):
    return templates.TemplateResponse(request, "privacy.html", _ctx(request))


@app.get("/refunds", response_class=HTMLResponse)
def refunds_page(request: Request):
    return templates.TemplateResponse(request, "refunds.html", _ctx(request))


@app.get("/guides/labeling-deficiencies", response_class=HTMLResponse)
def guide_deficiencies(request: Request):
    return templates.TemplateResponse(request, "guides/deficiencies.html", _ctx(request))


@app.get("/sample-audit", response_class=HTMLResponse)
def sample_audit(request: Request, download: int = 0):
    resp = templates.TemplateResponse(request, "sample.html", _ctx(request))
    if download:
        return Response(
            resp.body,
            media_type="text/html",
            headers={"Content-Disposition": 'attachment; filename="pharmareg-ai-sample-audit.html"'},
        )
    return resp


def _questions_by_domain():
    # legacy helper, kept for reference; public flow now uses get_questions("drap")
    out = {}
    for did, _, _ in get_domains("drap"):
        out[did] = [q for q in get_questions("drap") if q[1] == did]
    return out


@app.get("/qms", response_class=HTMLResponse)
def qms_page(request: Request):
    return templates.TemplateResponse(request, "qms_page.html", _ctx(request))


@app.get("/audit", response_class=HTMLResponse)
def audit_intro(request: Request):
    questions = get_questions("drap")
    qbd = {}
    for did, _, _ in get_domains("drap"):
        qbd[did] = [q for q in questions if q[1] == did]
    return templates.TemplateResponse(
        request, "audit.html",
        _ctx(request, domains=get_domains("drap"), questions_by_domain=qbd,
             total=len(questions)))


@app.post("/audit/report", response_class=HTMLResponse)
async def audit_report(request: Request):
    form = await request.form()
    answers = {}
    for q in get_questions("drap"):
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
    report = fw_build_report(company, answers, "drap")
    now = datetime.now(timezone.utc)
    report_id = f"PRA-{now:%Y%m%d}-{secrets.token_hex(2).upper()}"
    report_date = now.strftime("%d %b %Y")
    # store lead (owner follow-up)
    lead = {"ts": now.isoformat(timespec="seconds"), "report_id": report_id,
            **company, "overall": report["overall"], "grade": report["grade_label"],
            "critical": report["counts"]["critical"], "major": report["counts"]["major"],
            "minor": report["counts"]["minor"], "answered": report["answered"]}
    with open(LEADS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(lead, ensure_ascii=False) + "\n")
    wa_text = (f"Assalam-o-Alaikum, I completed the free DRAP GMP self-audit "
               f"({report_id}) for {company['company'] or 'our facility'}. "
               f"Score: {report['overall']}% ({report['grade_label']}), "
               f"{len(report['findings'])} findings. I'd like to discuss a full professional audit.")
    wa_link = f"https://wa.me/{WHATSAPP_NUMBER}?text=" + urllib.parse.quote(wa_text)
    return templates.TemplateResponse(
        request, "audit_report.html",
        _ctx(request, report=report, company=company, report_id=report_id,
             report_date=report_date, wa_link=wa_link))


@app.get("/ectd-check", response_class=HTMLResponse)
def ectd_check_form(request: Request):
    """Public free lead magnet: 12-point eCTD PDF readiness check."""
    return templates.TemplateResponse(request, "ectd_check.html", _ctx(request))


@app.post("/ectd-check/report", response_class=HTMLResponse)
async def ectd_check_report(request: Request):
    from app import ectd_check as ectd
    form = await request.form()
    upload = form.get("pdf")
    company = {
        "company": (form.get("company") or "").strip()[:120],
        "email": (form.get("email") or "").strip()[:120],
    }
    filename = getattr(upload, "filename", "") or "upload.pdf"
    pdf_bytes = await upload.read() if upload else b""
    if not pdf_bytes or len(pdf_bytes) > 15 * 1024 * 1024:
        return templates.TemplateResponse(
            request, "ectd_check.html",
            _ctx(request, error="Please upload a PDF under 15 MB."), status_code=400)
    results = ectd.run_ectd_checks(pdf_bytes, filename)
    summary = ectd.summarize(results)
    now = datetime.now(timezone.utc)
    report_id = f"ECTD-{now:%Y%m%d}-{secrets.token_hex(2).upper()}"
    lead = {"ts": now.isoformat(timespec="seconds"), "report_id": report_id,
            **company, "filename": filename[:120],
            "grade": summary["grade"], "label": summary["label"],
            "fails": summary["fails"], "warnings": summary["warnings"]}
    with open(ECTD_LEADS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(lead, ensure_ascii=False) + "\n")
    wa_text = (f"Assalam-o-Alaikum, I ran the free eCTD PDF readiness check "
               f"({report_id}) for {company['company'] or 'our facility'}. "
               f"Grade: {summary['grade']}/100 ({summary['label']}), "
               f"{summary['fails']} failed checks. I'd like to discuss a full professional audit.")
    wa_link = f"https://wa.me/{WHATSAPP_NUMBER}?text=" + urllib.parse.quote(wa_text)
    return templates.TemplateResponse(
        request, "ectd_report.html",
        _ctx(request, results=results, summary=summary, company=company,
             filename=filename[:120], report_id=report_id,
             report_date=now.strftime("%d %b %Y"), wa_link=wa_link))


@app.get("/audit/leads", response_class=HTMLResponse)
def audit_leads(request: Request):
    """Owner-only, unlisted, admin-key gated. Do not link publicly."""
    if not _is_admin(request):
        # Reuse the portal owner login; sets pra_admin cookie on success.
        return templates.TemplateResponse(
            request, "admin_login.html",
            _ctx(request, error="Owner login required."))
    leads = []
    if LEADS_FILE.exists():
        for line in LEADS_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    leads.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return templates.TemplateResponse(request, "audit_leads.html", _ctx(request, leads=leads))
