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
    for path in ["/contact", "/contact-us", "/about", "/team"]:
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
        for href in re.findall(r'href=["\'](.*?)["\']', html, re.I):
            href_abs = urljoin(url, href)
            p = urlparse(href_abs)
            if p.netloc == urlparse(base_url).netloc:
                if href_abs not in seen and len(seen) + len(queue) < max_pages:
                    queue.append(href_abs)

    return emails

# ===== Robust CSV reader (BOM + odd delimiters + headerless single-column) =====
def read_csv_simple(file):
    raw = file.read()
    text = raw.decode("utf-8-sig", errors="ignore").replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    if not text:
        return [], set()

    # Try DictReader with common delimiters
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

    # Fallback: one value per line, treat as 'email' list
    lines = [ln.strip() for ln in text.split("\n")]
    rows = [{"email": ln} for ln in lines if ln]
    return rows, {"email"}

# ===== UI =====
st.set_page_config(page_title="Email Finder + Soft Checker", page_icon="📧", layout="wide")
st.title("Email Finder + Soft Checker")
st.write("Upload a CSV with either:")
st.write("1) `domain` or `website` column to crawl and find emails")
st.write("2) `url` column of pages to scan")
st.write("3) `email` column to validate")

uploaded = st.file_uploader("Upload CSV", type=["csv"])
use_smtp = st.toggle("Use SMTP soft check", value=True, help="Turns on a light RCPT handshake; can be slow")
limit_per_domain = st.slider("Max pages per domain", 2, 15, PER_DOMAIN_PAGE_LIMIT)
rpm = st.slider("Requests per minute", 20, 120, GLOBAL_REQUESTS_PER_MINUTE)
resume_partial = st.checkbox("Resume from previous partial", value=True)
clear_partial = st.checkbox("Clear partial before run", value=False)

if uploaded:
    # apply UI-configured limits
    GLOBAL_REQUESTS_PER_MINUTE = rpm
    PER_DOMAIN_PAGE_LIMIT = limit_per_domain

    rows, cols = read_csv_simple(uploaded)

    # ===== EMAIL VALIDATION MODE =====
    if "email" in cols:
        st.subheader("Validating provided emails")

        if clear_partial:
            delete_file(PARTIAL_VALIDATE)

        partial_rows = read_rows_csv(PARTIAL_VALIDATE) if resume_partial else []
        processed = {r.get("email", "").strip().lower() for r in partial_rows}

        input_list = [str(r.get("email", "")).strip().lower() for r in rows if str(r.get("email", "")).strip()]
        total = len(input_list)
        pbar = st.progress(0.0)
        done_state = {"done": 0}

        for e in input_list:
            done_state["done"] += 1
            # quick filters / skip already processed
            if looks_junky(e) or e in processed:
                pbar.progress(done_state["done"] / max(total, 1))
                continue

            dom = e.split("@")[-1]
            mx = has_mx(dom, timeout=2)
            status = smtp_soft_check(e, use_smtp=use_smtp, timeout=3) if mx else "unlikely"

            append_rows_csv(PARTIAL_VALIDATE, [{"email": e, "domain": dom, "mx": mx, "status": status}],
                            ["email", "domain", "mx", "status"])
            processed.add(e)
            pbar.progress(done_state["done"] / max(total, 1))

        final_rows = [r for r in read_rows_csv(PARTIAL_VALIDATE) if r.get("email","").strip().lower() in set(input_list)]
        final_rows = dedupe_rows(final_rows, "email")
        if not final_rows:
            st.warning("No valid-looking emails provided.")
        else:
            st.dataframe(final_rows, use_container_width=True)
            st.download_button("Download results CSV",
                               list_to_csv_bytes(final_rows, ["email", "domain", "mx", "status"]),
                               file_name="emails_validated.csv",
                               mime="text/csv")

    # ===== DOMAIN CRAWL MODE =====
    elif ("domain" in cols) or ("website" in cols):
        st.subheader("Crawling domains to find emails")

        if clear_partial:
            delete_file(PARTIAL_DOMAIN)

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

        partial_rows = read_rows_csv(PARTIAL_DOMAIN) if resume_partial else []
        processed_sources = {r.get("source","").strip() for r in partial_rows}

        total = len(bases)
        state = {"done": 0}
        pbar = st.progress(0.0)

        async def run_crawl():
            async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
                for base in bases:
                    state["done"] += 1
                    if resume_partial and base in processed_sources:
                        pbar.progress(state["done"] / max(total, 1))
                        continue

                    st.write(f"Scanning: {base}")
                    emails = await run_with_timeout(
                        crawl_domain(client, base, max_pages=PER_DOMAIN_PAGE_LIMIT),
                        seconds=20  # hard stop per domain
                    )
                    emails = emails or set()

                    out_rows = []
                    for e in sorted(emails):
                        if looks_junky(e):
                            continue
                        dom = e.split("@")[-1]
                        mx = has_mx(dom, timeout=2)
                        status = smtp_soft_check(e, use_smtp=use_smtp, timeout=3) if mx else "unlikely"
                        out_rows.append({"source": base, "email": e, "domain": dom, "mx": mx, "status": status})

                    if out_rows:
                        append_rows_csv(PARTIAL_DOMAIN, out_rows, ["source", "email", "domain", "mx", "status"])
                    pbar.progress(state["done"] / max(total, 1))

        with st.spinner("Crawling and checking..."):
            asyncio.run(run_crawl())

        final_rows = [r for r in read_rows_csv(PARTIAL_DOMAIN) if r.get("source","") in set(bases)]
        final_rows = dedupe_rows(final_rows, "email")
        if not final_rows:
            st.warning("No emails found. Try raising page limit or add more specific URLs like /contact.")
        else:
            st.dataframe(final_rows, use_container_width=True)
            st.download_button("Download results CSV",
                               list_to_csv_bytes(final_rows, ["source", "email", "domain", "mx", "status"]),
                               file_name="emails_found_checked.csv",
                               mime="text/csv")

    # ===== SPECIFIC URL SCAN MODE =====
    elif "url" in cols:
        st.subheader("Scanning specific URLs for emails")

        if clear_partial:
            delete_file(PARTIAL_URL)

        urls = [str(r.get("url", "")).strip() for r in rows if str(r.get("url", "")).strip().startswith("http")]

        partial_rows = read_rows_csv(PARTIAL_URL) if resume_partial else []
        processed_sources = {r.get("source","").strip() for r in partial_rows}

        total = len(urls)
        state = {"done": 0}
        pbar = st.progress(0.0)

        async def run_pages():
            async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
                for u in urls:
                    state["done"] += 1
                    if resume_partial and u in processed_sources:
                        pbar.progress(state["done"] / max(total, 1))
                        continue

                    st.write(f"Scanning: {u}")
                    html = await run_with_timeout(fetch(client, u), seconds=15)
                    html = html or ""

                    found = []
                    for e in sorted(extract_emails(html)):
                        if looks_junky(e):
                            continue
                        dom = e.split("@")[-1]
                        mx = has_mx(dom, timeout=2)
                        status = smtp_soft_check(e, use_smtp=use_smtp, timeout=3) if mx else "unlikely"
                        found.append({"source": u, "email": e, "domain": dom, "mx": mx, "status": status})

                    if found:
                        append_rows_csv(PARTIAL_URL, found, ["source", "email", "domain", "mx", "status"])
                    pbar.progress(state["done"] / max(total, 1))

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
                               file_name="emails_from_urls.csv",
                               mime="text/csv")

    else:
        st.error("Your CSV must have one of these columns: email, domain or website, url")
