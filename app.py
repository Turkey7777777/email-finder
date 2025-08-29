import asyncio
import re
import time
from urllib.parse import urljoin, urlparse
import csv
import io

import streamlit as st
import httpx
import idna
import dns.resolver
import smtplib
from email.utils import parseaddr

# --- Config ---
CRAWL_TIMEOUT = 15  # seconds per page
PER_DOMAIN_PAGE_LIMIT = 5
GLOBAL_REQUESTS_PER_MINUTE = 60  # polite limit
USER_AGENT = "MinpackEmailFinder/1.0 (+https://www.minpack.com)"
EMAIL_REGEX = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

# --- Simple rate limiter ---
_last_reset = time.time()
_tokens = GLOBAL_REQUESTS_PER_MINUTE
def rate_limit():
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

# --- Helpers ---
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

def normalize_domain(domain: str) -> str:
    try:
        return idna.encode(domain.strip().lower()).decode("ascii")
    except Exception:
        return domain.strip().lower()

def extract_emails(html: str) -> set:
    return set(EMAIL_REGEX.findall(html or ""))

def looks_junky(email: str) -> bool:
    local, _, domain = email.lower().partition("@")
    if not domain or "." not in domain:
        return True
    if "%" in email or sum(ch.isdigit() for ch in local) > 6:
        return True
    return False

def has_mx(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except Exception:
        return False

def smtp_soft_check(email: str, helo_domain: str = "minpack.com", use_smtp=True, timeout=6) -> str:
    # Returns: "likely", "unknown", "unlikely"
    name, addr = parseaddr(email)
    if not addr or "@" not in addr:
        return "unlikely"
    _, _, dom = addr.partition("@")
    dom = dom.strip().lower()
    if not has_mx(dom):
        return "unlikely"
    if not use_smtp:
        return "likely"
    try:
        mx_records = dns.resolver.resolve(dom, "MX")
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")
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
        for href in re.findall(r'href=["\'](.*?)["\']', html, re.I):
            href_abs = urljoin(url, href)
            p = urlparse(href_abs)
            if p.netloc == urlparse(base_url).netloc:
                if href_abs not in seen and len(seen) + len(queue) < max_pages:
                    queue.append(href_abs)
    return emails

def read_csv_simple(file) -> list[dict]:
    text = file.read().decode("utf-8", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    rows = [dict(r) for r in reader]
    return rows

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

def list_to_csv_bytes(rows: list[dict], field_order: list[str]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=field_order, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in field_order})
    return buf.getvalue().encode("utf-8")

# --- UI ---
st.set_page_config(page_title="Email Finder + Soft Checker", page_icon="📧", layout="wide")
st.title("Email Finder + Soft Checker")

st.write("Upload a CSV with either:")
st.write("1) `domain` or `website` column to crawl and find emails")
st.write("2) `url` column of pages to scan")
st.write("3) `email` column to validate")

uploaded = st.file_uploader("Upload CSV", type=["csv"])
use_smtp = st.toggle("Use SMTP soft check", value=True, help="Turns on a light RCPT handshake. Some servers tarp it. Turn off if too slow.")
limit_per_domain = st.slider("Max pages per domain", 2, 15, PER_DOMAIN_PAGE_LIMIT)
rpm = st.slider("Requests per minute", 20, 120, GLOBAL_REQUESTS_PER_MINUTE)

if uploaded:
    GLOBAL_REQUESTS_PER_MINUTE = rpm
    PER_DOMAIN_PAGE_LIMIT = limit_per_domain

    rows = read_csv_simple(uploaded)
    cols = {c.lower().strip() for c in (rows[0].keys() if rows else [])}

    # EMAIL VALIDATION MODE
    if "email" in cols:
        st.subheader("Validating provided emails")
        clean = []
        for r in rows:
            email = str(r.get("email", "")).strip().lower()
            if not email or "@" not in email or looks_junky(email):
                continue
            dom = email.split("@")[-1]
            mx = has_mx(dom)
            status = smtp_soft_check(email, use_smtp=use_smtp) if mx else "unlikely"
            clean.append({"email": email, "domain": dom, "mx": mx, "status": status})
        clean = dedupe_rows(clean, "email")
        if not clean:
            st.warning("No valid-looking emails provided.")
        else:
            st.dataframe(clean, use_container_width=True)
            st.download_button(
                "Download results CSV",
                list_to_csv_bytes(clean, ["email", "domain", "mx", "status"]),
                file_name="emails_validated.csv",
                mime="text/csv",
            )

    # DOMAIN CRAWL MODE
    elif ("domain" in cols) or ("website" in cols):
        st.subheader("Crawling domains to find emails")
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

        async def run_crawl():
            found_rows = []
            async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
                for base in bases:
                    st.write(f"Scanning: {base}")
                    emails = await crawl_domain(client, base, max_pages=PER_DOMAIN_PAGE_LIMIT)
                    for e in sorted(emails):
                        dom = e.split("@")[-1]
                        mx = has_mx(dom)
                        status = smtp_soft_check(e, use_smtp=use_smtp) if mx else "unlikely"
                        found_rows.append({"source": base, "email": e, "domain": dom, "mx": mx, "status": status})
            return found_rows

        with st.spinner("Crawling and checking..."):
            out = asyncio.run(run_crawl())

        out = [r for r in out if not looks_junky(r["email"])]
        out = dedupe_rows(out, "email")
        if not out:
            st.warning("No emails found. Try raising page limit or add more specific URLs like /contact.")
        else:
            st.dataframe(out, use_container_width=True)
            st.download_button(
                "Download results CSV",
                list_to_csv_bytes(out, ["source", "email", "domain", "mx", "status"]),
                file_name="emails_found_checked.csv",
                mime="text/csv",
            )

    # SPECIFIC URL SCAN MODE
    elif "url" in cols:
        st.subheader("Scanning specific URLs for emails")
        urls = [str(r.get("url", "")).strip() for r in rows if str(r.get("url", "")).startswith("http")]

        async def run_pages():
            found_rows = []
            async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
                for u in urls:
                    st.write(f"Scanning: {u}")
                    html = await fetch(client, u)
                    emails = extract_emails(html)
                    for e in sorted(emails):
                        if looks_junky(e):
                            continue
                        dom = e.split("@")[-1]
                        mx = has_mx(dom)
                        status = smtp_soft_check(e, use_smtp=use_smtp) if mx else "unlikely"
                        found_rows.append({"source": u, "email": e, "domain": dom, "mx": mx, "status": status})
            return found_rows

        with st.spinner("Fetching and checking..."):
            out = asyncio.run(run_pages())

        out = dedupe_rows(out, "email")
        if not out:
            st.warning("No emails found on provided pages.")
        else:
            st.dataframe(out, use_container_width=True)
            st.download_button(
                "Download results CSV",
                list_to_csv_bytes(out, ["source", "email", "domain", "mx", "status"]),
                file_name="emails_from_urls.csv",
                mime="text/csv",
            )

    else:
        st.error("Your CSV must have one of these columns: email, domain or website, url")
