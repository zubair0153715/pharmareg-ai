"""
eCTD PDF readiness check — clean-room implementation.

Checks a PDF against the PUBLIC FDA eCTD PDF criteria
("Providing Regulatory Submissions in Electronic Format" guidance):
no JavaScript, no encryption, fonts embedded, page size, text-searchable,
file naming, etc.

Deliberately pypdf-only (BSD licence, already a dependency).
PyMuPDF-based validators exist but are AGPL — not used here.
Each rule is written from the public FDA criteria, not copied from any repo.
"""
import io
import os
import re

PASS, FAIL, WARNING = "PASS", "FAIL", "WARNING"

# eCTD-acceptable PDF versions per FDA guidance
OK_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}
# Letter / A4 in points, ±4pt tolerance
PAGE_SIZES = {"Letter": (612, 792), "A4": (595, 842)}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-\.]*$")


def _reader(pdf_bytes):
    from pypdf import PdfReader
    return PdfReader(io.BytesIO(pdf_bytes))


def _fonts_embedded(page):
    """Walk /Font resources; every font must have an embedded /FontFile*."""
    try:
        resources = page.get("/Resources")
        if not resources:
            return True, []
        fonts = resources.get("/Font")
        if not fonts:
            return True, []
        bad = []
        for fkey in list(fonts.keys()):
            try:
                font = fonts[fkey].get_object()
            except Exception:
                continue
            # Type3 fonts are inherently embedded
            if str(font.get("/Subtype", "")) == "/Type3":
                continue
            desc = font.get("/FontDescriptor")
            if not desc:
                bad.append(str(font.get("/BaseFont", fkey)))
                continue
            try:
                desc = desc.get_object()
            except Exception:
                pass
            has_file = any(k in desc for k in
                           ("/FontFile", "/FontFile2", "/FontFile3"))
            if not has_file:
                bad.append(str(font.get("/BaseFont", fkey)))
        return (len(bad) == 0), bad
    except Exception:
        return True, []


def run_ectd_checks(pdf_bytes, filename):
    """Run all rules. Returns list of dicts: rule_id, name, status, detail."""
    results = []

    def add(rid, name, status, detail):
        results.append({"rule_id": rid, "name": name,
                        "status": status, "detail": detail})

    # --- ECTD-11 file naming (no PDF parse needed) ---
    base = os.path.basename(filename or "")
    if len(base) > 64:
        add("ECTD-11", "File naming", FAIL,
            f"Filename is {len(base)} chars (eCTD limit: 64).")
    elif not NAME_RE.match(base):
        add("ECTD-11", "File naming", FAIL,
            "Use only lowercase a-z, 0-9, hyphen, underscore, dot. "
            "No spaces or uppercase (eCTD requirement).")
    else:
        add("ECTD-11", "File naming", PASS,
            "Filename follows eCTD naming rules.")

    # --- parse ---
    try:
        reader = _reader(pdf_bytes)
        n = len(reader.pages)
        if n == 0:
            raise ValueError("no pages")
    except Exception as e:
        add("ECTD-02", "Document integrity", FAIL,
            f"PDF could not be parsed: {e}")
        return results
    add("ECTD-02", "Document integrity", PASS, f"{n} page(s), parses cleanly.")

    # --- ECTD-01 version ---
    header = (reader.pdf_header or "").strip()
    ver = header.replace("%PDF-", "")
    if ver in OK_VERSIONS:
        add("ECTD-01", "PDF version", PASS,
            f"PDF {ver} — within eCTD range 1.4–1.7.")
    elif ver.startswith("2."):
        add("ECTD-01", "PDF version", FAIL,
            f"PDF {ver} — eCTD does not accept PDF 2.0. Save as 1.4–1.7.")
    else:
        add("ECTD-01", "PDF version", WARNING,
            f"PDF {ver} — eCTD expects 1.4–1.7; verify with your publisher.")

    # --- ECTD-03 encryption ---
    try:
        if reader.is_encrypted:
            add("ECTD-03", "No encryption/password", FAIL,
                "PDF is encrypted or password-protected — eCTD forbids this.")
        else:
            add("ECTD-03", "No encryption/password", PASS,
                "No document security restrictions.")
    except Exception:
        add("ECTD-03", "No encryption/password", WARNING,
            "Could not determine encryption state.")

    # --- ECTD-04 JavaScript / ECTD-05 embedded files (catalog scan) ---
    try:
        root = reader.trailer["/Root"]
        names = root.get("/Names")
        has_js = False
        has_files = False
        try:
            names = names.get_object() if names else {}
            has_js = "/JavaScript" in (names or {})
            has_files = "/EmbeddedFiles" in (names or {})
        except Exception:
            pass
        # also check /OpenAction for JS actions
        try:
            oa = root.get("/OpenAction")
            if oa:
                oa = oa.get_object() if hasattr(oa, "get_object") else oa
                if "/JS" in str(oa) or "/JavaScript" in str(oa):
                    has_js = True
        except Exception:
            pass
        add("ECTD-04", "No JavaScript", FAIL if has_js else PASS,
            "JavaScript actions found — prohibited in eCTD."
            if has_js else "No JavaScript detected.")
        add("ECTD-05", "No embedded files", FAIL if has_files else PASS,
            "Embedded file attachments found — not allowed in eCTD."
            if has_files else "No embedded attachments.")
    except Exception:
        add("ECTD-04", "No JavaScript", WARNING, "Could not scan catalog.")
        add("ECTD-05", "No embedded files", WARNING, "Could not scan catalog.")

    # --- ECTD-06 linearized (fast web view) ---
    try:
        head = pdf_bytes[:2048].decode("latin-1", errors="ignore")
        add("ECTD-06", "Fast Web View (linearized)", PASS if "/Linearized" in head else WARNING,
            "PDF is linearized for fast web view."
            if "/Linearized" in head else
            "Not linearized — FDA prefers Fast Web View; most publishers linearize on save.")
    except Exception:
        add("ECTD-06", "Fast Web View (linearized)", WARNING, "Could not check.")

    # --- ECTD-07 fonts embedded (sample first 5 pages) ---
    try:
        bad_all = []
        for p in reader.pages[:5]:
            ok, bad = _fonts_embedded(p)
            bad_all += bad
        bad_all = sorted(set(bad_all))
        add("ECTD-07", "Fonts embedded", FAIL if bad_all else PASS,
            "Non-embedded fonts: " + ", ".join(bad_all[:5])
            if bad_all else "All fonts embedded (sampled pages).")
    except Exception:
        add("ECTD-07", "Fonts embedded", WARNING, "Could not inspect fonts.")

    # --- ECTD-08 page size ---
    try:
        odd = 0
        for p in reader.pages:
            box = p.mediabox
            w, h = float(box.width), float(box.height)
            w, h = (min(w, h), max(w, h))
            match = any(abs(w - sw) <= 4 and abs(h - sh) <= 4
                        for sw, sh in
                        [(min(a, b), max(a, b)) for a, b in PAGE_SIZES.values()])
            if not match:
                odd += 1
        add("ECTD-08", "Page size (Letter/A4)", FAIL if odd else PASS,
            f"{odd} page(s) are not Letter/A4 — eCTD expects one consistent size."
            if odd else "All pages Letter/A4.")
    except Exception:
        add("ECTD-08", "Page size (Letter/A4)", WARNING, "Could not measure pages.")

    # --- ECTD-09 annotations ---
    try:
        n_ann = 0
        for p in reader.pages[:20]:
            ann = p.get("/Annots")
            if ann:
                n_ann += len(ann)
        add("ECTD-09", "Annotations", WARNING if n_ann else PASS,
            f"{n_ann} annotation(s) found — eCTD discourages annotations; remove if not essential."
            if n_ann else "No annotations.")
    except Exception:
        add("ECTD-09", "Annotations", WARNING, "Could not inspect annotations.")

    # --- ECTD-10 text searchable (image-only scan) ---
    try:
        img_only = 0
        for p in reader.pages[:20]:
            txt = (p.extract_text() or "").strip()
            if len(txt) < 20:
                # has images? check XObject
                try:
                    res = p.get("/Resources") or {}
                    xo = res.get("/XObject")
                    if xo:
                        img_only += 1
                except Exception:
                    pass
        checked = min(20, n)
        add("ECTD-10", "Text searchable", FAIL if img_only == checked and checked else
            (WARNING if img_only else PASS),
            f"{img_only}/{checked} sampled page(s) appear image-only — eCTD requires searchable text (OCR them)."
            if img_only else "Pages contain extractable text.")
    except Exception:
        add("ECTD-10", "Text searchable", WARNING, "Could not check text layer.")

    # --- ECTD-12 initial view (informational) ---
    try:
        root = reader.trailer["/Root"]
        pm = str(root.get("/PageMode", "/UseNone"))
        add("ECTD-12", "Initial view", PASS if "UseOutlines" in pm else WARNING,
            f"PageMode is {pm} — FDA prefers the bookmarks panel visible on open."
            if "UseOutlines" not in pm else
            "Bookmarks panel set as initial view.")
    except Exception:
        add("ECTD-12", "Initial view", WARNING, "Could not read viewer preferences.")

    return results


def summarize(results):
    fails = sum(1 for r in results if r["status"] == FAIL)
    warns = sum(1 for r in results if r["status"] == WARNING)
    if fails == 0 and warns == 0:
        grade, label = 100, "eCTD-READY"
    elif fails == 0:
        grade, label = 80, "NEEDS POLISH"
    elif fails <= 2:
        grade, label = 55, "NEEDS FIXES"
    else:
        grade, label = 25, "NOT READY"
    return {"fails": fails, "warnings": warns, "grade": grade, "label": label}
