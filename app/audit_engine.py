"""PharmaReg AI — DRAP/WHO-GMP self-audit engine.

Pure-Python, no web dependencies: score answers, build prioritized findings,
grade readiness. Unit-testable in isolation.
"""
from __future__ import annotations

DOMAINS = [
    ("lic", "Licensing & Regulatory Compliance",
     "DRAP manufacturing licence, approved sections, qualified persons, product registrations."),
    ("qms", "Quality Management System",
     "Quality manual, change control, deviations, CAPA, product quality reviews."),
    ("doc", "Documentation & SOPs",
     "Batch records, SOP control, good documentation practices, archiving."),
    ("per", "Personnel & Training",
     "Organisation, GMP training, hygiene, job descriptions."),
    ("pre", "Premises & Facilities",
     "Cleanrooms/HVAC, purified water, material flow, pest control."),
    ("equ", "Equipment",
     "Qualification (IQ/OQ/PQ), calibration, maintenance, cleaning validation."),
    ("pro", "Production & Process Control",
     "Process validation, line clearance, in-process controls, rework."),
    ("qcl", "Quality Control Laboratory",
     "Specifications, OOS handling, stability program, reference standards."),
    ("sto", "Storage & Distribution (GDP)",
     "Temperature mapping, cold chain, FEFO/FIFO, traceability."),
    ("pvr", "Pharmacovigilance, Complaints & Recalls",
     "Recall procedure, complaint investigation, ADR reporting to DRAP."),
]

# Each question: id, domain, severity (critical/major/minor), text, fix (corrective action).
QUESTIONS = [
 # --- 1. Licensing & Regulatory ---
 ("L1", "lic", "critical", "Valid DRAP Drug Manufacturing Licence held, current, and displayed (not expired or suspended).",
  "Renew immediately via DRAP; halt regulated activities until the licence is valid. Track expiry with a compliance calendar."),
 ("L2", "lic", "critical", "Licensed manufacturing sections match actual production (no unlicensed dosage forms or activities).",
  "Apply for section variation/extension before manufacturing; segregate any non-conforming activity immediately."),
 ("L3", "lic", "major", "Qualified technical staff (production/QC pharmacists) approved by DRAP and currently employed.",
  "Appoint DRAP-approvable qualified persons; file personnel variations; maintain approval letters on file."),
 ("L4", "lic", "major", "Every manufactured product holds a valid DRAP registration (no unregistered batches).",
  "Cross-check production plan against registration certificates monthly; quarantine anything unregistered."),
 ("L5", "lic", "minor", "Licence renewals and variations are filed before expiry with documented tracking.",
  "Create a regulatory calendar with 90-day advance alerts and a named owner per filing."),
 # --- 2. QMS ---
 ("Q1", "qms", "critical", "Documented Quality Manual and QMS covering change control, deviations, and CAPA.",
  "Draft and approve a Quality Manual aligned with WHO GMP; train all staff on it."),
 ("Q2", "qms", "critical", "Every deviation is investigated with root cause analysis and a documented CAPA.",
  "Implement a deviation log with investigation timelines, root-cause tools (5-Why/Fishbone), and CAPA effectiveness checks."),
 ("Q3", "qms", "major", "Change control procedure covers equipment, process, supplier, and document changes.",
  "Write a change-control SOP with QA approval gates and impact assessment before implementation."),
 ("Q4", "qms", "major", "Annual Product Quality Reviews (APQR/PQR) are performed for all products.",
  "Schedule APQRs per product per year covering batches, deviations, OOS, complaints, and stability trends."),
 ("Q5", "qms", "minor", "Management review of the QMS is conducted at least annually, with minutes and actions.",
  "Hold a formal annual management review; track actions to closure."),
 # --- 3. Documentation ---
 ("D1", "doc", "critical", "Batch Manufacturing Records are completed contemporaneously, signed, and reviewed by QA before batch release.",
  "Enforce contemporaneous BMR completion; add a QA pre-release checklist; retrain operators on ALCOA principles."),
 ("D2", "doc", "major", "SOPs are current, approved, available at point of use; obsolete versions removed.",
  "Run a document-control sweep: withdraw obsolete copies, index current versions, assign periodic review dates."),
 ("D3", "doc", "major", "Good Documentation Practices followed (no pencil, no overwriting; corrections signed and dated).",
  "Issue a GDP SOP with examples; audit records monthly until compliance is sustained."),
 ("D4", "doc", "minor", "Document retention meets DRAP requirements with secure, retrievable archiving.",
  "Define retention periods per record type; store in access-controlled archive with a retrieval log."),
 # --- 4. Personnel ---
 ("P1", "per", "major", "Organisation chart is current; Production/QC/QA heads are independent with no conflicts of interest.",
  "Redraw the org chart; separate QA release authority from production; document reporting lines."),
 ("P2", "per", "major", "Training program covers GMP induction, SOP training, and ongoing training, with complete records.",
  "Build a training matrix per role; record attendance and assessments; retrain on SOP revisions."),
 ("P3", "per", "major", "Personnel hygiene procedures enforced (gowning, health checks, restricted access to clean areas).",
  "Write and enforce a hygiene SOP; log gowning qualification and periodic health checks."),
 ("P4", "per", "minor", "Job descriptions documented for all GMP-relevant positions.",
  "Write job descriptions listing GMP responsibilities; have staff acknowledge them in writing."),
 # --- 5. Premises ---
 ("F1", "pre", "critical", "Cleanroom grades qualified and monitored; HVAC validated with pressure differentials maintained.",
  "Qualify HVAC and room grades; trend pressure/particle data; alarm on excursions with investigations."),
 ("F2", "pre", "critical", "Purified water / WFI system validated, with routine microbial and chemical monitoring.",
  "Validate the water system (3-phase approach); set alert/action limits; investigate excursions with CAPA."),
 ("F3", "pre", "major", "Premises designed for logical material and personnel flow preventing cross-contamination and mix-ups.",
  "Map flows; add airlocks, status labelling, and segregated staging where gaps exist."),
 ("F4", "pre", "major", "Pest control program documented, with no evidence of infestation in production/storage areas.",
  "Contract a licensed pest-control provider; keep site maps of traps and trend reports."),
 ("F5", "pre", "minor", "Lighting, drainage, and surfaces are suitable for pharmaceutical manufacturing and cleaning.",
  "Remediate surfaces/drainage that trap contamination; verify lux levels in inspection areas."),
# --- 6. Equipment ---
("E1", "equ", "critical", "Equipment qualified (IQ/OQ/PQ) before routine GMP use.",
 "Prepare qualification protocols; execute IQ/OQ/PQ; approve summary reports before use."),
("E2", "equ", "major", "Calibration program covers all critical instruments; no overdue calibrations.",
 "List all critical instruments with intervals; schedule and track; quarantine equipment past due date."),
("E3", "equ", "major", "Preventive maintenance performed per schedule, with records.",
 "Create maintenance schedules per equipment; log completion; review breakdown trends."),
("E4", "equ", "major", "Cleaning validation/verification for shared equipment prevents cross-contamination.",
 "Validate worst-case cleaning procedures; set residue limits based on toxicological data."),
("E5", "equ", "minor", "Equipment logbooks are in use and up to date.",
 "Issue bound logbooks per equipment; QA reviews entries weekly."),
# --- 7. Production ---
("R1", "pro", "critical", "Process validation completed for all commercial products (or concurrent validation scientifically justified).",
 "Execute prospective process validation (3 batches); document the validation master plan."),
("R2", "pro", "critical", "Line clearance performed and documented between products and batches.",
 "Use a line-clearance checklist signed by production and verified by QA before start-up."),
("R3", "pro", "major", "In-process controls performed with defined acceptance criteria.",
 "Define IPC tests and limits in the BMR; trend results; investigate out-of-trend data."),
("R4", "pro", "major", "Reprocessing/rework only per approved procedure with QA approval.",
 "Write a rework SOP requiring QA risk assessment and approval; validate reworked processes."),
("R5", "pro", "minor", "Yield reconciliations performed; out-of-limit yields investigated.",
 "Set yield limits per product stage; investigate deviations with documented conclusions."),
# --- 8. QC Laboratory ---
("C1", "qcl", "critical", "Finished products released only against approved specifications with complete testing.",
 "Lock release to a QA checklist: full testing, reviewed data, approved spec, no open deviations."),
("C2", "qcl", "critical", "OOS results investigated per written procedure (no retesting into compliance).",
 "Implement the FDA/WHO OOS investigation phases (lab investigation then full investigation); prohibit testing into compliance."),
("C3", "qcl", "major", "Stability program covers all products per ICH/WHO conditions, with ongoing studies.",
 "Enroll every product/strength/pack in long-term and accelerated studies; review data on schedule."),
("C4", "qcl", "major", "Reference and working standards qualified, properly stored, and within expiry.",
 "Qualify working standards against pharmacopoeial references; control storage and expiry."),
("C5", "qcl", "minor", "Laboratory instruments qualified; analytical methods validated or verified.",
 "Qualify instruments (IQ/OQ/PQ); validate non-pharmacopoeial methods, verify pharmacopoeial ones."),
# --- 9. Storage & Distribution ---
("S1", "sto", "critical", "Temperature mapping completed for warehouses; monitoring with alarms in controlled areas.",
 "Map all storage areas seasonally; install calibrated monitoring with alert/alarm and excursion handling."),
("S2", "sto", "major", "Cold chain maintained and documented for temperature-sensitive products.",
 "Qualify shippers/routes; use calibrated data loggers; review profiles before acceptance."),
("S3", "sto", "major", "FEFO/FIFO stock rotation practiced; expired and rejected goods segregated and secured.",
 "Enforce FEFO in the WMS/manual system; lock rejected/expired areas with QA-controlled access."),
("S4", "sto", "minor", "Distribution records allow full traceability of each batch (recall-ready).",
 "Record consignee, quantity, and batch for every dispatch; test traceability in the mock recall."),
# --- 10. Pharmacovigilance / Complaints / Recalls ---
("V1", "pvr", "critical", "Written recall procedure exists; a mock recall was performed within the last 2 years.",
 "Write the recall SOP with classification and DRAP notification steps; run and document a mock recall."),
("V2", "pvr", "major", "Market complaints investigated with root cause and CAPA; complaint trends reviewed periodically.",
 "Log every complaint; investigate with timelines; trend quarterly and feed into APQR."),
("V3", "pvr", "major", "Adverse drug reactions reported to the DRAP pharmacovigilance centre.",
 "Appoint a pharmacovigilance responsible person; set reporting timelines per DRAP requirements."),
("V4", "pvr", "minor", "Returned goods procedure prevents re-entry into saleable stock without a QA decision.",
 "Quarantine all returns; QA dispositions each return with documented rationale."),
]

ANSWER_SCORES = {"yes": 2, "partial": 1, "no": 0}
SEV_ORDER = {"critical": 0, "major": 1, "minor": 2}


def _qmap():
   return {q[0]: q for q in QUESTIONS}


def score_answers(answers):
   """answers: {qid: 'yes'|'partial'|'no'|'na'} -> per-domain and overall results."""
   qmap = _qmap()
   domains = {}
   for did, name, desc in DOMAINS:
       qs = [q for q in QUESTIONS if q[1] == did]
       got, maxv, answered = 0, 0, 0
       for q in qs:
           a = answers.get(q[0], "na")
           if a == "na":
               continue
           answered += 1
           maxv += 2
           got += ANSWER_SCORES.get(a, 0)
       pct = round(100 * got / maxv) if maxv else None
       domains[did] = {"name": name, "desc": desc, "score": pct,
                       "answered": answered, "total": len(qs)}
   scored = [d["score"] for d in domains.values() if d["score"] is not None]
   overall = round(sum(scored) / len(scored)) if scored else 0
   return {"domains": domains, "overall": overall}


def build_findings(answers):
   """Prioritized findings for every 'no' / 'partial' answer."""
   out = []
   for qid, did, sev, text, fix in QUESTIONS:
       a = answers.get(qid, "na")
       if a in ("yes", "na"):
           continue
       # a 'partial' on a critical question is still major; 'no' keeps full severity
       eff_sev = sev if a == "no" else {"critical": "major", "major": "minor", "minor": "minor"}[sev]
       status = "Non-compliant" if a == "no" else "Partially compliant"
       dname = next(n for d, n, _ in DOMAINS if d == did)
       out.append({"qid": qid, "domain": dname, "severity": eff_sev,
                   "status": status, "observation": text, "recommendation": fix})
   out.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["qid"]))
   return out


def grade(overall, findings):
   crit_no = sum(1 for f in findings if f["severity"] == "critical")
   if overall >= 85 and crit_no == 0:
       return ("Inspection-ready", "green",
               "Strong compliance posture. Close remaining minor gaps and keep the QMS trending.")
   if overall >= 70:
       return ("Minor gaps", "lime",
               "Good foundation. Remediate the listed findings — none should block a routine inspection for long.")
   if overall >= 50:
       return ("Major gaps — remediation advised", "amber",
               "Significant gaps exist. Prioritize critical and major findings before any regulatory inspection.")
   return ("Critical gaps — not inspection-ready", "red",
           "Do not invite inspection in this state. Critical findings need immediate corrective action.")


def build_report(company, answers):
   """Full report dict for rendering + lead storage."""
   scoring = score_answers(answers)
   findings = build_findings(answers)
   label, color, summary = grade(scoring["overall"], findings)
   counts = {"critical": 0, "major": 0, "minor": 0}
   for f in findings:
       counts[f["severity"]] += 1
   return {"company": company, "overall": scoring["overall"],
           "domains": scoring["domains"], "findings": findings,
           "counts": counts, "grade_label": label, "grade_color": color,
           "grade_summary": summary,
           "total_questions": len(QUESTIONS),
           "answered": sum(1 for q in QUESTIONS if answers.get(q[0], "na") != "na")}
