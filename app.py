import asyncio
import re
import time
from urllib.parse import urljoin, urlparse
import csv
import io
import os

import streamlit as st
import httpx
import dns.resolver
import smtplib
from email.utils import parseaddr

# ===== Config =====
CRAWL_TIMEOUT = 15                     # seconds per page fetch
PER_DOMAIN_PAGE_LIMIT = 5              # pages max to visit per domain
GLOBAL_REQUESTS_PER_MINUTE = 60        # polite global rate limit
USER_AGENT = "MinpackEmailFinder/1.0 (+https://www.minpack.com)"
EMAIL_REGEX = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

# Autosave paths (Streamlit Cloud allows writes to /tmp)
PARTIAL_DIR = "/tmp/minpack_email_finder"
PARTIAL_VALIDATE = os.path.join(PARTIAL_DIR, "emails_validated_partial.csv")
PARTIAL_DOMAIN = os.path.join(PARTIAL_DIR, "emails_found_checked_partial.csv")
PARTIAL_URL = os.path.join(PARTIAL_DIR, "emails_from_urls_partial.csv")
# Track which domains are finished even if 0 emails found
PARTIAL_DOMAIN_DONE = os.path.join(PARTIAL_DIR, "domains_done_partial.csv")
# Generated contacts partial (evidence-based + guesses)
PARTIAL_GEN_PARTIAL = os.path.join(PARTIAL_DIR, "generated_contacts_partial.csv")

# ===== Rate limiter =====
_last_reset = time.time()
_tokens = GLOBAL_REQUESTS_PER_MINUTE
def rate_limit():
    """Simple token bucket for polite global rate limiting."""
    global _last_reset, _tokens
    now = time.time()
    if now - _last_reset >= 60:
        _last_reset = now
        _tokens = GLOBAL_REQUESTS_PER_MINUTE
    while _tokens <= 0:
        time.sleep(0.25)
        now = time.time()
        if now - _last_reset >= 60:
            _last_reset = now
            _tokens = GLOBAL_REQUESTS_PER_MINUTE
    _tokens -= 1

# ===== Small utilities =====
def ensure_dir():
    os.makedirs(PARTIAL_DIR, exist_ok=True)

def delete_file(path: str):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass

def append_rows_csv(path: str, rows: list[dict], field_order: list[str]):
    ensure_dir()
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=field_order, extrasaction="ignore")
        if write_header:
            w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in field_order})

def read_rows_csv(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []

def list_to_csv_bytes(rows: list[dict], field_order: list[str]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=field_order, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in field_order})
    return buf.getvalue().encode("utf-8")

def dedupe_rows(rows: list[dict], key: str) -> list[dict]:
    seen = set()
    out = []
    for r in rows:
        v = str(r.get(key, "")).strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(r)
    return out

async def run_with_timeout(coro, seconds: int):
    """Await a coroutine with a hard timeout; return None on timeout."""
    try:
        return await asyncio.wait_for(coro, timeout=seconds)
    except asyncio.TimeoutError:
        return None

# ---- Persisted upload + partial download helpers ----
def get_uploaded_file(uploaded, state_key="upload_cache"):
    """Return a BytesIO for the uploaded file that survives reruns."""
    if uploaded is not None:
        b = uploaded.getvalue()
        st.session_state[state_key] = {"bytes": b, "name": uploaded.name}
        return io.BytesIO(b), uploaded.name
    cache = st.session_state.get(state_key)
    if cache:
        return io.BytesIO(cache["bytes"]), cache["name"]
    return None, None

def download_partial_button(path: str, label: str, filename: str, fields: list[str]):
    """Show a download button for whatever is saved so far."""
    if os.path.exists(path):
        rows = read_rows_csv(path)
        if rows:
            st.download_button(label, list_to_csv_bytes(rows, fields), file_name=filename, mime="text/csv")
        else:
            st.caption("No partial rows yet.")
    else:
        st.caption("No partial file yet.")

def progress_safe(pbar, done: int, total: int):
    if total <= 0:
        value = 0.0
    else:
        value = done / total
    value = max(0.0, min(1.0, value))
    pbar.progress(value)

# ===== DNS & SMTP with tight timeouts =====
def has_mx(domain: str, timeout=2) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "MX")
        return len(answers) > 0
    except Exception:
        return False

def smtp_soft_check(email: str, helo_domain: str = "minpack.com", use_smtp=True, timeout=3) -> str:
    """
    Returns: "likely", "unknown", "unlikely"
    """
    name, addr = parseaddr(email)
    if not addr or "@" not in addr:
        return "unlikely"
    _, _, dom = addr.partition("@")
    dom = dom.strip().lower()

    if not has_mx(dom, timeout=2):
        return "unlikely"
    if not use_smtp:
        return "likely"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        mx_records = resolver.resolve(dom, "MX")
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")

        import socket as _socket
        _socket.setdefaulttimeout(timeout)
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.helo(helo_domain)
            smtp.mail("probe@" + helo_domain)
            code, _ = smtp.rcpt(addr)
            if code in (250, 251):
                return "likely"
            if code in (450, 451, 452):
                return "unknown"
            return "unlikely"
    except Exception:
        return "unknown"

def extract_emails(html: str) -> set:
    return set(EMAIL_REGEX.findall(html or ""))

def looks_junky(email: str) -> bool:
    local, _, domain = email.lower().partition("@")
    if not domain or "." not in domain:
        return True
    if "%" in email or sum(ch.isdigit() for ch in local) > 6:
        return True
    return False

# ===== HTTP helpers =====
async def fetch(client: httpx.AsyncClient, url: str) -> str:
    rate_limit()
    try:
        resp = await client.get(url, timeout=CRAWL_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
            return resp.text
    except Exception:
        return ""
    return ""

async def robots_allows(client: httpx.AsyncClient, base: str, path: str) -> bool:
    try:
        robots_url = urljoin(base, "/robots.txt")
        txt = await fetch(client, robots_url)
        if not txt:
            return True
        disallows = []
        current_group_is_all = False
        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, val = line.partition(":")
            key, val = key.strip().lower(), val.strip()
            if key == "user-agent":
                current_group_is_all = (val == "*")
            elif key == "disallow" and current_group_is_all:
                disallows.append(val)
        for d in disallows:
            if d and path.startswith(d):
                return False
        return True
    except Exception:
        return True

async def crawl_domain(client: httpx.AsyncClient, base_url: str, max_pages=PER_DOMAIN_PAGE_LIMIT) -> set:
    seen = set()
    queue = []
    emails = set()

    queue.append(base_url)
    for path in ["/contact", "/contact-us", "/about", "/about-us", "/team", "/our-team", "/leadership", "/management", "/company", "/staff", "/news", "/blog"]:
        queue.append(urljoin(base_url, path))

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if not await robots_allows(client, base, parsed.path or "/"):
            continue
        html = await fetch(client, url)
        if not html:
            continue
        for e in extract_emails(html):
            if not looks_junky(e):
                emails.add(e)

        # Shallow internal link discovery
        for href in re.findall(r'href=[\"\'](.*?)[\"\']', html, re.I):
            href_abs = urljoin(url, href)
            p = urlparse(href_abs)
            if p.netloc == urlparse(base_url).netloc:
                if href_abs not in seen and len(seen) + len(queue) < max_pages:
                    queue.append(href_abs)

    return emails

# ===== Robust CSV reader =====
def read_csv_simple(file_like):
    raw = file_like.read()
    text = raw.decode("utf-8-sig", errors="ignore").replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    if not text:
        return [], set()

    delimiters = [",", ";", "\t", "|"]
    for delim in delimiters:
        try:
            rdr = csv.DictReader(io.StringIO(text), delimiter=delim)
            if rdr.fieldnames and any(h is not None for h in rdr.fieldnames):
                rows_list = list(rdr)
                norm_rows = []
                for r in rows_list:
                    d = {}
                    for k, v in r.items():
                        key = (k or "").strip().lower()
                        if key in {"emails", "e-mail", "mail"}:
                            key = "email"
                        if key in {"website", "site"}:
                            key = "website"
                        if key in {"link", "page"}:
                            key = "url"
                        d[key] = (v or "").strip()
                    norm_rows.append(d)
                cols = set(norm_rows[0].keys()) if norm_rows else set()
                return norm_rows, cols
        except Exception:
            continue

    lines = [ln.strip() for ln in text.split("\n")]
    rows = [{"email": ln} for ln in lines if ln]
    return rows, {"email"}

# ===== Name extraction, pattern inference, generation =====
NAME_RE = re.compile(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b")
COMMON_BAD_TOKENS = {
    "Privacy", "Policy", "Terms", "Contact", "About", "Team", "Careers", "Blog",
    "Email", "Support", "Downloads", "Press", "Investors", "Leadership", "Staff",
    "Menu", "Submit", "Subscribe", "Cookie", "Manager", "Director", "Engineer",
    "Home", "Services", "Solutions", "News"
}
def extract_candidate_names(html: str) -> list[str]:
    raw = NAME_RE.findall(html or "")
    out = []
    seen = set()
    for full in raw:
        full = " ".join(w.strip() for w in full.split())
        parts = full.split()
        if len(parts) < 2:
            continue
        if any(p in COMMON_BAD_TOKENS for p in parts):
            continue
        if not all(p.isalpha() and 2 <= len(p) <= 20 for p in parts):
            continue
        key = full.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(full)
    return out

def _first(n):  return n.split()[0].lower()
def _last(n):   return n.split()[-1].lower()
def _fi(n):     return n.split()[0][0].lower()
def _li(n):     return n.split()[-1][0].lower()

PATTERNS = {
    "first.last":      lambda n: f"{_first(n)}.{_last(n)}",
    "firstlast":       lambda n: f"{_first(n)}{_last(n)}",
    "flast":           lambda n: f"{_fi(n)}{_last(n)}",
    "firstl":          lambda n: f"{_first(n)}{_li(n)}",
    "f.last":          lambda n: f"{_fi(n)}.{_last(n)}",
    "first_last":      lambda n: f"{_first(n)}_{_last(n)}",
    "first-last":      lambda n: f"{_first(n)}-{_last(n)}",
    "first":           lambda n: _first(n),
    "last":            lambda n: _last(n),
    "lastf":           lambda n: f"{_last(n)}{_fi(n)}",
}

def infer_pattern_for_domain(domain: str, found_emails: set[str], candidate_names: list[str]):
    """
    Returns (best_pattern_key, confidence_float [0..1], matches_count, tested_names_count)
    Evidence-based only.
    """
    locals_on_domain = set()
    for e in found_emails:
        e = e.strip().lower()
        if "@" not in e:
            continue
        local, _, dom = e.partition("@")
        if dom == domain.lower():
            locals_on_domain.add(local)

    tested_total = 0
    best_key = None
    best_hits = -1
    best_tested = 0

    for key, fn in PATTERNS.items():
        hits = 0
        checked = 0
        for name in candidate_names:
            try:
                lp = fn(name)
            except Exception:
                continue
            checked += 1
            if lp in locals_on_domain:
                hits += 1
        if checked > 0 and hits > best_hits:
            best_hits = hits
            best_key = key
            best_tested = checked
        tested_total = max(tested_total, checked)

    if best_key is None or tested_total == 0:
        return None, 0.0, 0, 0

    confidence = best_hits / max(3, best_tested)
    return best_key, confidence, best_hits, best_tested

def generate_emails(names: list[str], domain: str, pattern_key: str) -> list[dict]:
    res = []
    fn = PATTERNS.get(pattern_key)
    if not fn:
        return res
    for n in names:
        try:
            local = fn(n)
            res.append({"name": n, "email": f"{local}@{domain.lower()}", "pattern": pattern_key})
        except Exception:
            continue
    return res

# ===== Fallback guessing =====
COMMON_PATTERN_ORDER = [
    "first.last", "flast", "firstlast", "f.last", "first", "last", "lastf", "first_last", "first-last"
]
ROLE_ALIASES = ["info", "contact", "support", "sales", "hello", "careers", "press", "admin", "office"]

def infer_separators_from_locals(local_parts: set[str]) -> set[str]:
    seps = set()
    for lp in local_parts:
        if "." in lp: seps.add(".")
        if "_" in lp: seps.add("_")
        if "-" in lp: seps.add("-")
    return seps

def guess_top_patterns_for_domain(found_emails: set[str], top_k: int = 2) -> list[str]:
    # Prefer patterns that match separators seen on-domain
    local_parts = set()
    for e in found_emails:
        e = e.lower().strip()
        if "@" in e:
            lp = e.split("@", 1)[0]
            local_parts.add(lp)
    seps = infer_separators_from_locals(local_parts)
    ordered = COMMON_PATTERN_ORDER[:]

    if seps:
        # Simple scoring: boost patterns using observed separators
        def score(p):
            s = 0
            if "." in p and "." in "".join(local_parts): s += 2
            if "_" in p and "_" in "".join(local_parts): s += 2
            if "-" in p and "-" in "".join(local_parts): s += 2
            # mild bias to very common corporate patterns
            if p == "first.last": s += 1
            if p == "flast": s += 1
            return -s
        ordered.sort(key=score)

    return ordered[:top_k]

# ===== UI =====
st.set_page_config(page_title="Email Finder + Soft Checker", page_icon="📧", layout="wide")
st.title("Email Finder + Soft Checker")
st.write("Upload a CSV with either:")
st.write("1) `domain` or `website` column to crawl and find emails")
st.write("2) `url` column of pages to scan")
st.write("3) `email` column to validate")

uploaded = st.file_uploader("Upload CSV", type=["csv"])
file_buf, filename = get_uploaded_file(uploaded)  # persist across reruns
use_smtp = st.toggle("Use SMTP soft check", value=True, help="Turns on a light RCPT handshake; can be slow")
limit_per_domain = st.slider("Max pages per domain", 2, 15, PER_DOMAIN_PAGE_LIMIT)
rpm = st.slider("Requests per minute", 20, 120, GLOBAL_REQUESTS_PER_MINUTE)
resume_partial = st.checkbox("Resume from previous partial", value=True)
clear_partial = st.checkbox("Clear partial before run", value=False)
enable_fallback = st.checkbox("Enable fallback guessing (when no evidence)", value=True)
fallback_top_k = st.slider("Fallback: number of patterns to try", 1, 3, 2)
enable_guess_without_names = st.checkbox("If no names found, guess role emails (info@, sales@, ...)", value=True)

if file_buf:
    # apply UI-configured limits
    GLOBAL_REQUESTS_PER_MINUTE = rpm
    PER_DOMAIN_PAGE_LIMIT = limit_per_domain

    rows, cols = read_csv_simple(file_buf)

    # ===== EMAIL VALIDATION MODE =====
    if "email" in cols:
        st.subheader("Validating provided emails")

        if clear_partial:
            delete_file(PARTIAL_VALIDATE)

        input_list = [str(r.get("email", "")).strip().lower() for r in rows if str(r.get("email", "")).strip()]
        total = len(input_list)

        partial_rows = read_rows_csv(PARTIAL_VALIDATE) if resume_partial else []
        processed = {r.get("email", "").strip().lower() for r in partial_rows if r.get("email", "").strip().lower() in set(input_list)}

        pbar = st.progress(0.0)
        row_status = st.empty()
        done_status = st.empty()
        already_done = len(processed)
        progress_safe(pbar, already_done, total)
        done_status.markdown(f"**Done {already_done} of {total}** (resuming)" if already_done else f"**Done 0 of {total}**")

        done = already_done
        st.markdown("### Download current partial")
        download_partial_button(PARTIAL_VALIDATE, "Download current partial (validation)", "emails_validated_partial.csv", ["email","domain","mx","status"])

        for i, e in enumerate(input_list, start=1):
            row_status.markdown(f"**Row {i} of {total}** → {e}")
            if e in processed or looks_junky(e):
                # skip, but do not double count if already_done covered it
                if e not in processed:
                    processed.add(e)
                    done += 1
                progress_safe(pbar, done, total)
                done_status.markdown(f"**Done {done} of {total}**")
                time.sleep(0.05)
                continue

            dom = e.split("@")[-1]
            mx = has_mx(dom, timeout=2)
            status_str = smtp_soft_check(e, use_smtp=use_smtp, timeout=3) if mx else "unlikely"
            append_rows_csv(PARTIAL_VALIDATE, [{"email": e, "domain": dom, "mx": mx, "status": status_str}], ["email", "domain", "mx", "status"])
            processed.add(e)
            done += 1
            progress_safe(pbar, done, total)
            done_status.markdown(f"**Done {done} of {total}**")
            time.sleep(0.05)

        final_rows = [r for r in read_rows_csv(PARTIAL_VALIDATE) if r.get("email","").strip().lower() in set(input_list)]
        final_rows = dedupe_rows(final_rows, "email")
        if not final_rows:
            st.warning("No valid-looking emails provided.")
        else:
            st.dataframe(final_rows, use_container_width=True)
            st.download_button("Download results CSV", list_to_csv_bytes(final_rows, ["email", "domain", "mx", "status"]), file_name="emails_validated.csv", mime="text/csv")

    # ===== DOMAIN CRAWL MODE =====
    elif ("domain" in cols) or ("website" in cols):
        st.subheader("Crawling domains to find emails")

        if clear_partial:
            delete_file(PARTIAL_DOMAIN)
            delete_file(PARTIAL_DOMAIN_DONE)
            delete_file(PARTIAL_GEN_PARTIAL)

        url_col = "domain" if "domain" in cols else "website"

        def to_base(u: str | None):
            if not u:
                return None
            u = str(u).strip()
            if not u:
                return None
            if not u.startswith("http"):
                u = "https://" + u
            return u

        bases = [to_base(r.get(url_col)) for r in rows]
        bases = [b for b in bases if b]
        total = len(bases)

        partial_done = read_rows_csv(PARTIAL_DOMAIN_DONE) if resume_partial else []
        processed_done = {r.get("source","").strip() for r in partial_done if r.get("source","").strip() in set(bases)}

        pbar = st.progress(0.0)
        status = st.empty()
        row_status = st.empty()
        done_status = st.empty()
        already_done = len(processed_done)
        progress_safe(pbar, already_done, total)
        done_status.markdown(f"**Done {already_done} of {total}** (resuming)" if already_done else f"**Done 0 of {total}**")

        st.markdown("### Download current partial")
        download_partial_button(PARTIAL_DOMAIN, "Download current partial (domain crawl)", "emails_found_checked_partial.csv", ["source","email","domain","mx","status"])
        download_partial_button(PARTIAL_GEN_PARTIAL, "Download current partial (generated contacts)", "generated_contacts_partial.csv",
                                ["domain","pattern","confidence","name","email","evidence_emails_seen","names_tested","names_matched","guessed","guess_reason"])

        state = {"done": already_done}

        async def run_crawl():
            async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
                # process in strict CSV order
                for i, base in enumerate(bases, start=1):
                    row_status.markdown(f"**Row {i} of {total}** → {base}")

                    if resume_partial and base in processed_done:
                        # already accounted for in 'already_done'; skip without increment
                        continue

                    status.markdown(f"**Done {state['done']} of {total}**  \nScanning: {base}")
                    emails = await run_with_timeout(crawl_domain(client, base, max_pages=PER_DOMAIN_PAGE_LIMIT), seconds=20)
                    emails = emails or set()

                    out_rows = []
                    for e in sorted(emails):
                        if looks_junky(e):
                            continue
                        dom = e.split("@")[-1]
                        mx = has_mx(dom, timeout=2)
                        status_str = smtp_soft_check(e, use_smtp=use_smtp, timeout=3) if mx else "unlikely"
                        out_rows.append({"source": base, "email": e, "domain": dom, "mx": mx, "status": status_str})

                    if out_rows:
                        append_rows_csv(PARTIAL_DOMAIN, out_rows, ["source", "email", "domain", "mx", "status"])

                    # mark domain done (even if 0 emails)
                    append_rows_csv(PARTIAL_DOMAIN_DONE, [{"source": base, "done": 1}], ["source", "done"])
                    processed_done.add(base)

                    # ---- On-the-fly pattern inference + generation per domain ----
                    people_paths = ["/about", "/about-us", "/team", "/our-team", "/leadership", "/management", "/company", "/staff", "/news", "/blog", "/contact", "/contact-us"]
                    dom = urlparse(base).netloc.lower()

                    # evidence emails found so far on this domain
                    emls = {r.get("email","").strip().lower()
                            for r in read_rows_csv(PARTIAL_DOMAIN)
                            if r.get("domain","").strip().lower() == dom}

                    # mine names
                    names_pool = []
                    for pth in people_paths:
                        try:
                            html = await run_with_timeout(fetch(client, f"{base.rstrip('/')}{pth}"), seconds=10)
                            if not html:
                                continue
                            names_pool.extend(extract_candidate_names(html))
                            if len(names_pool) >= 60:
                                break
                        except Exception:
                            continue

                    # top 7 unique names
                    seen_n = set()
                    uniq_names = []
                    for nm in names_pool:
                        key = nm.lower()
                        if key in seen_n:
                            continue
                        seen_n.add(key)
                        uniq_names.append(nm)
                        if len(uniq_names) >= 7:
                            break

                    pattern, conf, hits, tested = infer_pattern_for_domain(dom, emls, uniq_names)

                    gen_rows = []
                    if pattern and conf >= 0.34 and uniq_names:
                        # evidence-based generation
                        for g in generate_emails(uniq_names, dom, pattern):
                            gen_rows.append({
                                "domain": dom, "pattern": pattern, "confidence": f"{conf:.2f}",
                                "name": g["name"], "email": g["email"],
                                "evidence_emails_seen": len(emls), "names_tested": tested, "names_matched": hits,
                                "guessed": "no", "guess_reason": ""
                            })
                    else:
                        # not enough evidence for a confident pattern
                        if enable_fallback and uniq_names:
                            # guess top-k personal patterns using any observed separators
                            guess_patterns = guess_top_patterns_for_domain(emls, top_k=fallback_top_k)
                            reason = "no evidence; guessed via common patterns"
                            if emls:
                                locs = {e.split("@",1)[0] for e in emls if "@" in e}
                                seps = infer_separators_from_locals(locs)
                                if seps:
                                    reason = f"no matches; guessed using observed separator(s): {' '.join(sorted(seps))}"
                            for pk in guess_patterns:
                                for g in generate_emails(uniq_names, dom, pk):
                                    gen_rows.append({
                                        "domain": dom, "pattern": pk, "confidence": "0.00",
                                        "name": g["name"], "email": g["email"],
                                        "evidence_emails_seen": len(emls), "names_tested": tested, "names_matched": hits,
                                        "guessed": "yes", "guess_reason": reason
                                    })
                        elif enable_guess_without_names and not uniq_names:
                            # No names mined at all -> guess role aliases (up to 7)
                            added = 0
                            for role in ROLE_ALIASES:
                                gen_rows.append({
                                    "domain": dom, "pattern": "(role-alias)", "confidence": "0.00",
                                    "name": "", "email": f"{role}@{dom}",
                                    "evidence_emails_seen": len(emls), "names_tested": 0, "names_matched": 0,
                                    "guessed": "yes", "guess_reason": "no names visible; generated common role aliases"
                                })
                                added += 1
                                if added >= 7:
                                    break
                        else:
                            # record attempt (no guessing)
                            gen_rows.append({
                                "domain": dom, "pattern": "(insufficient evidence)", "confidence": f"{conf:.2f}",
                                "name": "", "email": "",
                                "evidence_emails_seen": len(emls), "names_tested": tested, "names_matched": hits,
                                "guessed": "no", "guess_reason": ""
                            })

                    if gen_rows:
                        append_rows_csv(
                            PARTIAL_GEN_PARTIAL, gen_rows,
                            ["domain","pattern","confidence","name","email","evidence_emails_seen","names_tested","names_matched","guessed","guess_reason"]
                        )

                    # increment done (only for newly processed domain)
                    state["done"] += 1
                    progress_safe(pbar, state["done"], total)
                    done_status.markdown(f"**Done {state['done']} of {total}**")
                    await asyncio.sleep(0.05)

        with st.spinner("Crawling and checking..."):
            asyncio.run(run_crawl())

        # Show final evidence-based results for this run's bases
        final_rows = [r for r in read_rows_csv(PARTIAL_DOMAIN) if r.get("source","") in set(bases)]
        final_rows = dedupe_rows(final_rows, "email")
        if not final_rows:
            st.warning("No emails found. Try raising page limit or include more specific pages like /about or /team.")
        else:
            st.dataframe(final_rows, use_container_width=True)
            st.download_button("Download results CSV",
                               list_to_csv_bytes(final_rows, ["source", "email", "domain", "mx", "status"]),
                               file_name="emails_found_checked.csv", mime="text/csv")

        # Show generated contacts (evidence-based and/or guesses)
        gen_rows_now = read_rows_csv(PARTIAL_GEN_PARTIAL)
        if gen_rows_now:
            st.subheader("Generated contacts (evidence + guesses)")
            st.dataframe(gen_rows_now, use_container_width=True)
            st.download_button(
                "Download generated contacts CSV",
                list_to_csv_bytes(gen_rows_now, ["domain","pattern","confidence","name","email","evidence_emails_seen","names_tested","names_matched","guessed","guess_reason"]),
                file_name="generated_contacts.csv", mime="text/csv",
            )
        else:
            st.info("No generated contacts yet.")

    # ===== SPECIFIC URL SCAN MODE =====
    elif "url" in cols:
        st.subheader("Scanning specific URLs for emails")

        if clear_partial:
            delete_file(PARTIAL_URL)

        urls = [str(r.get("url", "")).strip() for r in rows if str(r.get("url", "")).strip().startswith("http")]
        total = len(urls)

        partial_rows = read_rows_csv(PARTIAL_URL) if resume_partial else []
        processed_sources = {r.get("source","").strip() for r in partial_rows if r.get("source","").strip() in set(urls)}

        pbar = st.progress(0.0)
        row_status = st.empty()
        done_status = st.empty()
        already_done = len(processed_sources)
        progress_safe(pbar, already_done, total)
        done_status.markdown(f"**Done {already_done} of {total}** (resuming)" if already_done else f"**Done 0 of {total}**")

        st.markdown("### Download current partial")
        download_partial_button(PARTIAL_URL, "Download current partial (URL scan)", "emails_from_urls_partial.csv", ["source","email","domain","mx","status"])

        state = {"done": already_done}

        async def run_pages():
            async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
                for i, u in enumerate(urls, start=1):
                    row_status.markdown(f"**Row {i} of {total}** → {u}")

                    if resume_partial and u in processed_sources:
                        continue

                    html = await run_with_timeout(fetch(client, u), seconds=15)
                    html = html or ""

                    found = []
                    for e in sorted(extract_emails(html)):
                        if looks_junky(e):
                            continue
                        dom = e.split("@")[-1]
                        mx = has_mx(dom, timeout=2)
                        status_str = smtp_soft_check(e, use_smtp=use_smtp, timeout=3) if mx else "unlikely"
                        found.append({"source": u, "email": e, "domain": dom, "mx": mx, "status": status_str})

                    if found:
                        append_rows_csv(PARTIAL_URL, found, ["source", "email", "domain", "mx", "status"])

                    state["done"] += 1
                    progress_safe(pbar, state["done"], total)
                    done_status.markdown(f"**Done {state['done']} of {total}**")
                    await asyncio.sleep(0.05)

        with st.spinner("Fetching and checking..."):
            asyncio.run(run_pages())

        final_rows = [r for r in read_rows_csv(PARTIAL_URL) if r.get("source","") in set(urls)]
        final_rows = dedupe_rows(final_rows, "email")
        if not final_rows:
            st.warning("No emails found on provided pages.")
        else:
            st.dataframe(final_rows, use_container_width=True)
            st.download_button("Download results CSV",
                               list_to_csv_bytes(final_rows, ["source", "email", "domain", "mx", "status"]),
                               file_name="emails_from_urls.csv", mime="text/csv")

    else:
        st.error("Your CSV must have one of these columns: email, domain or website, url")
