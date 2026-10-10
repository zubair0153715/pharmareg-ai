
# ---------------------------------------------------------------------------
# Multi-framework support: DRAP (Pakistan) + SFDA (Saudi Arabia) + EDE (UAE)
# The 41 WHO-GMP core questions are universal. Each framework adds its own
# "reg" (Regulatory specifics) module replacing the DRAP licensing block.
# ---------------------------------------------------------------------------

from app.audit_engine import QUESTIONS, DOMAINS, ANSWER_SCORES, SEV_ORDER, grade

FRAMEWORKS = {    "drap": {"name": "DRAP", "country": "Pakistan", "flag": "🇵🇰",
             "full": "Drug Regulatory Authority of Pakistan",
             "reg_name": "DRAP Licensing & Regulatory",
             "reg_desc": "DRAP manufacturing licence, approved sections, qualified persons, registrations, pharmacovigilance."},
    "sfda": {"name": "SFDA", "country": "Saudi Arabia", "flag": "🇸🇦",
             "full": "Saudi Food & Drug Authority",
             "reg_name": "SFDA Regulatory Specifics",
             "reg_desc": "SFDA establishment licensing, eSDR registration, mandatory Arabic labelling, GVP-KSA pharmacovigilance."},
    "ede": {"name": "EDE", "country": "United Arab Emirates", "flag": "🇦🇪",
            "full": "Emirates Drug Establishment",
            "reg_name": "EDE Regulatory Specifics",
            "reg_desc": "EDE facility licensing & GMP certification, marketing authorizations, key personnel, UAE pharmacovigilance."},
}


def _reg(qid, sev, text, fix):
    return (qid, "reg", sev, text, fix)


FRAMEWORK_MODULES = {
    # DRAP: the original 5 licensing questions (remapped to "reg") + 2 extras
    "drap": [
        _reg("L1", "critical", "Valid DRAP Drug Manufacturing Licence held, current, and displayed (not expired or suspended).",
             "Renew immediately via DRAP; halt regulated activities until the licence is valid. Track expiry with a compliance calendar."),
        _reg("L2", "critical", "Licensed manufacturing sections match actual production (no unlicensed dosage forms or activities).",
             "Apply for section variation/extension before manufacturing; segregate any non-conforming activity immediately."),
        _reg("L3", "major", "Qualified technical staff (production/QC pharmacists) approved by DRAP and currently employed.",
             "Appoint DRAP-approvable qualified persons; file personnel variations; maintain approval letters on file."),
        _reg("L4", "major", "Every manufactured product holds a valid DRAP registration (no unregistered batches).",
             "Cross-check production plan against registration certificates monthly; quarantine anything unregistered."),
        _reg("L5", "minor", "Licence renewals and variations are filed before expiry with documented tracking.",
             "Create a regulatory calendar with 90-day advance alerts and a named owner per filing."),
        _reg("DR6", "major", "Product labelling complies with DRAP labelling requirements (English; Urdu where required).",
             "Audit all labels against the approved registration dossier; file labelling variations for gaps."),
        _reg("DR7", "minor", "Price notifications/fixations filed with the DRAP pricing section as applicable.",
             "Reconcile current prices with DRAP notifications; file before any price change."),
    ],
    # SFDA — grounded in SFDA GMP guide (PIC/S-aligned), eSDR registration, Arabic labelling guide, GVP-KSA
    "sfda": [
        _reg("SF1", "critical", "Valid SFDA establishment/manufacturer licence held (local site), or a GMP certificate recognised by SFDA (foreign site).",
             "Obtain the SFDA licence / recognised GMP certificate before commercial activity; track expiry."),
        _reg("SF2", "critical", "Every product holds a valid SFDA marketing authorization via the eSDR system (renewed every 5 years).",
             "Register via eSDR in CTD/eCTD format; calendar the 5-year renewals with advance preparation."),
        _reg("SF3", "critical", "Mandatory Arabic labelling on outer and inner packs (trade + scientific name, strength, dosage form, pack size, storage, manufacturer, MA holder) per the SFDA labelling guide.",
             "Implement bilingual Arabic/English artwork; verify every SKU against the SFDA labelling guide."),
        _reg("SF4", "major", "Label changes submitted to SFDA for prior approval via variation applications before implementation.",
             "Route all artwork changes through regulatory affairs; never implement unapproved labels."),
        _reg("SF5", "major", "Local pharmacovigilance system per GVP-KSA with a qualified PV responsible person; ICSRs and PSURs submitted to the SFDA NPC.",
             "Establish the local PV system, appoint the QPPV, and meet SFDA reporting timelines."),
        _reg("SF6", "major", "Products under additional monitoring (NCEs, biologicals, biosimilars) carry the black triangle symbol and statement in SPC/PIL.",
             "Identify listed products; add the symbol and statement; file the variation with SFDA."),
        _reg("SF7", "major", "Stability data covers ICH Zone IVa (hot/humid) conditions applicable to Saudi Arabia.",
             "Run long-term studies at Zone IVa conditions; justify any bracketing/matrixing scientifically."),
        _reg("SF8", "major", "Registration dossiers (CTD/eCTD) kept current; variations filed for site, process, and labelling changes.",
             "Maintain a living dossier per product; file variations before implementing changes."),
        _reg("SF9", "minor", "Key personnel trained on SFDA-specific requirements (labelling, vigilance, variations).",
             "Add SFDA modules to the training matrix for regulatory, QA, and QC staff."),
        _reg("SF10", "minor", "GMP inspection readiness: PIC/S-aligned QMS evidence available for SFDA inspection (local or foreign site).",
             "Run a mock SFDA inspection annually against the SFDA GMP guide; close gaps with CAPA."),
    ],
    # EDE — grounded in the federal decree-law, MOHAP/EDE licensing procedures, EDE portal services
    "ede": [
        _reg("ED1", "critical", "Valid EDE pharmaceutical manufacturing facility licence held, with a GMP certificate issued by EDE.",
             "Complete EDE licensing (drawings approval → GMP inspection → licence); track both certificates' expiry."),
        _reg("ED2", "critical", "Renewal file kept ready: industrial licence, professional licences of technical personnel, GMP certificate, environmental permit, Civil Defence certificate.",
             "Maintain a renewal dossier per requirement; file before expiry — operating unlicensed risks fines up to AED 1,000,000."),
        _reg("ED3", "critical", "Every product holds an EDE marketing authorization (registered medical product).",
             "Register products via the EDE portal; never manufacture or market unregistered products."),
        _reg("ED4", "major", "Key technical personnel appointed and licensed: Technical Manager, Production Manager, QA Manager, QC Manager.",
             "Appoint and licence all four roles; file appointment letters and professional licences with EDE."),
        _reg("ED5", "major", "Bilingual Arabic/English labelling per UAE requirements on all packs and leaflets.",
             "Verify artwork bilingually; control translations under document control."),
        _reg("ED6", "major", "Pharmacovigilance system per the UAE federal decree-law; adverse reactions reported as required.",
             "Implement the PV system, define reporting timelines, and train staff on UAE vigilance obligations."),
        _reg("ED7", "major", "Import/export permits obtained via EDE for raw materials, finished products, and controlled substances.",
             "Route every cross-border movement through EDE permits; keep a permit register."),
        _reg("ED8", "minor", "Medicine price lists comply with EDE Pharmaceutical Policies Committee pricing.",
             "Reconcile prices with EDE price lists; obtain pricing certificates where required."),
        _reg("ED9", "minor", "Advertising, promotion, and marketing approvals obtained from EDE where required.",
             "Submit promotional material for EDE approval before release; archive approvals."),
        _reg("ED10", "minor", "Facility and product data ready for EDE national databases (products, facilities, traceability).",
             "Keep master data accurate and formatted for EDE database submissions."),
    ],
}

CORE_QUESTIONS = [q for q in QUESTIONS if q[1] != "lic"]


def get_questions(framework="drap"):
    fw = framework if framework in FRAMEWORK_MODULES else "drap"
    return FRAMEWORK_MODULES[fw] + CORE_QUESTIONS


def get_domains(framework="drap"):
    fw = framework if framework in FRAMEWORKS else "drap"
    meta = FRAMEWORKS[fw]
    reg = ("reg", meta["reg_name"], meta["reg_desc"])
    return [reg] + [d for d in DOMAINS if d[0] != "lic"]


def _qmap_for(framework):
    return {q[0]: q for q in get_questions(framework)}


def score_answers_fw(answers, framework="drap"):
    questions = get_questions(framework)
    domains = get_domains(framework)
    qmap = _qmap_for(framework)
    out = {}
    for did, name, desc in domains:
        qs = [q for q in questions if q[1] == did]
        got, maxv, answered = 0, 0, 0
        for q in qs:
            a = answers.get(q[0], "na")
            if a == "na":
                continue
            answered += 1
            maxv += 2
            got += ANSWER_SCORES.get(a, 0)
        pct = round(100 * got / maxv) if maxv else None
        out[did] = {"name": name, "desc": desc, "score": pct,
                    "answered": answered, "total": len(qs)}
    scored = [d["score"] for d in out.values() if d["score"] is not None]
    overall = round(sum(scored) / len(scored)) if scored else 0
    return {"domains": out, "overall": overall}


def build_findings_fw(answers, framework="drap"):
    questions = get_questions(framework)
    domains = get_domains(framework)
    dnames = {d: n for d, n, _ in domains}
    out = []
    for qid, did, sev, text, fix in questions:
        a = answers.get(qid, "na")
        if a in ("yes", "na"):
            continue
        eff_sev = sev if a == "no" else {"critical": "major", "major": "minor", "minor": "minor"}[sev]
        status = "Non-compliant" if a == "no" else "Partially compliant"
        out.append({"qid": qid, "domain": dnames.get(did, did), "severity": eff_sev,
                    "status": status, "observation": text, "recommendation": fix})
    out.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["qid"]))
    return out


def build_report(company, answers, framework="drap"):
    """Full report dict for rendering + lead storage (framework-aware)."""
    fw = framework if framework in FRAMEWORKS else "drap"
    questions = get_questions(fw)
    scoring = score_answers_fw(answers, fw)
    findings = build_findings_fw(answers, fw)
    label, color, summary = grade(scoring["overall"], findings)
    counts = {"critical": 0, "major": 0, "minor": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return {"company": company, "framework": fw, "framework_meta": FRAMEWORKS[fw],
            "overall": scoring["overall"], "domains": scoring["domains"],
            "findings": findings, "counts": counts,
            "grade_label": label, "grade_color": color, "grade_summary": summary,
            "total_questions": len(questions),
            "answered": sum(1 for q in questions if answers.get(q[0], "na") != "na")}
