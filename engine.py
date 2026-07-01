"""
engine.py — LinkDecoder AI  ·  URL analysis engine

Checks performed:
  1. Redirect chain      — how many hops before reaching the destination
  2. Homograph attack    — punycode / look-alike Unicode characters in domain
  3. Brand impersonation — Levenshtein distance against Nigerian brands
  4. Domain age          — newly registered domains are a major red flag
  5. HTTPS / SSL         — HTTP-only is a warning sign for sensitive-looking URLs
  6. Suspicious keywords — "login", "verify", "secure", "update" in path/query
  7. IP-as-hostname      — raw IP addresses are always suspicious

Bugs fixed vs. original:
  ❌ requests.compat.urljoin (deprecated) → urllib.parse.urljoin
  ❌ WHOIS timezone crash on tz-aware datetimes → safe tzinfo check
  ❌ whois imported inside function → top-level import with try/except
  ❌ No URL input validation → validate_url() called before scanning
"""

import re
import socket
import requests
import tldextract
import Levenshtein
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse   # ← FIX 1: replaces requests.compat.urljoin

# Top-level import so missing package surfaces immediately at startup
try:
    import whois as _whois_lib
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

# ── CONFIGURATION ─────────────────────────────────────────────────────────────

# Nigerian brands to protect against impersonation
PROTECTED_BRANDS = [
    "gtbank", "gtworld", "paystack", "flutterwave", "opay", "kuda",
    "zenithbank", "accessbank", "firstbank", "uba", "moniepoint",
    "palmpay", "interswitch", "remita", "nibss", "wema", "union",
    "polaris", "fidelitybank", "sterling", "jaiz", "coronation",
]

# Keywords that appear in phishing URLs targeting Nigerian users
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "update", "confirm", "secure", "security", "account",
    "banking", "transfer", "payment", "recover", "unlock",
    "suspended", "limited", "validate", "urgent", "alert",
]

SEVERITY_WEIGHTS = {"none": 0, "low": 15, "medium": 35, "high": 60}

# ── INPUT VALIDATION ──────────────────────────────────────────────────────────

_URL_PATTERN = re.compile(
    r"^(https?://)?"
    r"([a-zA-Z0-9\-\.]+)"
    r"(\.[a-zA-Z]{2,})"
    r"(/[^\s]*)?$",
    re.IGNORECASE,
)

def validate_url(url: str) -> str:
    """Raise ValueError for inputs that are clearly not URLs."""
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if len(url) > 2000:
        raise ValueError("URL is too long.")
    if not _URL_PATTERN.match(url):
        raise ValueError(f"'{url}' does not appear to be a valid URL.")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

# ── CHECK FUNCTIONS ───────────────────────────────────────────────────────────

def follow_redirects(url: str, max_hops: int = 10):
    chain = []
    current = url
    try:
        for _ in range(max_hops):
            resp = requests.head(current, allow_redirects=False, timeout=5)
            chain.append(current)
            if resp.status_code in (301, 302, 303, 307, 308):
                nxt = resp.headers.get("Location")
                if not nxt:
                    break
                # FIX 1: urllib.parse.urljoin instead of requests.compat.urljoin
                current = nxt if nxt.startswith("http") else urljoin(current, nxt)
            else:
                break
    except requests.RequestException:
        pass
    return chain, current


def check_redirects(chain):
    hops = max(0, len(chain) - 1)
    if not chain:
        status, sev = "warn", "low"
        detail = "Could not resolve the URL — destination unreachable."
    elif hops == 0:
        status, sev = "pass", "none"
        detail = "No redirects — link goes straight to its destination."
    elif hops <= 1:
        status, sev = "warn", "low"
        detail = f"URL redirects {hops} time before reaching its destination."
    else:
        status, sev = "warn", "medium"
        detail = f"URL redirects {hops} times before reaching its destination."
    return {
        "id": "redirect_chain", "name": "Redirect Chain",
        "status": status, "severity": sev, "detail": detail,
        "data": {"hops": hops, "chain": chain},
    }


def check_homograph(final_url: str):
    ext = tldextract.extract(final_url)
    domain = ext.domain
    is_puny = domain.startswith("xn--")
    try:
        decoded = domain.encode().decode("idna") if is_puny else domain
    except Exception:
        decoded = domain
    if is_puny:
        status, sev = "fail", "high"
        detail = f"Domain uses punycode — possible character spoofing (decodes to '{decoded}')."
    else:
        status, sev = "pass", "none"
        detail = "No character-spoofing detected in the domain."
    return {
        "id": "homograph", "name": "Punycode / Homograph",
        "status": status, "severity": sev, "detail": detail,
        "data": {"is_punycode": is_puny, "decoded_domain": decoded},
    }


def check_typosquat(final_url: str):
    ext = tldextract.extract(final_url)
    domain = ext.domain.lower()
    best_brand, best_dist = None, 99
    for brand in PROTECTED_BRANDS:
        if brand == domain:
            best_brand, best_dist = brand, 0
            break
        if brand in domain:
            best_brand, best_dist = brand, 1
            break
        d = Levenshtein.distance(domain, brand)
        if d < best_dist:
            best_brand, best_dist = brand, d
    if best_brand and best_dist == 0:
        status, sev = "pass", "none"
        detail = "Domain matches a known brand exactly."
    elif best_brand and best_dist <= 2:
        status, sev = "fail", "high"
        detail = f"Domain closely mimics '{best_brand}' (Nigerian brand). High phishing risk."
    elif best_brand and best_dist == 3:
        status, sev = "warn", "low"
        detail = f"Domain slightly resembles '{best_brand}' — could be coincidental."
    else:
        status, sev = "pass", "none"
        detail = "No brand impersonation detected."
    return {
        "id": "typosquat", "name": "Brand Impersonation",
        "status": status, "severity": sev, "detail": detail,
        "data": {"matched_brand": best_brand, "levenshtein_distance": best_dist},
    }


def check_domain_age(final_url: str):
    if not _WHOIS_AVAILABLE:
        return {
            "id": "domain_age", "name": "Domain Age",
            "status": "warn", "severity": "low",
            "detail": "python-whois is not installed — domain age check skipped.",
            "data": {"age_days": None, "error": "python-whois not installed"},
        }
    try:
        ext = tldextract.extract(final_url)
        domain = f"{ext.domain}.{ext.suffix}"
        # Timeout the WHOIS call — it hangs forever on some domains/subdomains
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_whois_lib.whois, domain)
            try:
                w = future.result(timeout=12)
            except concurrent.futures.TimeoutError:
                raise ValueError("WHOIS lookup timed out after 6s")
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            raise ValueError("No creation date returned by WHOIS.")

        # FIX 2: only add tzinfo if the datetime is naive (not already tz-aware)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - created).days

        if age_days < 30:
            status, sev = "fail", "high"
            detail = f"Domain registered only {age_days} days ago — newly registered domains are a major red flag."
        elif age_days < 180:
            status, sev = "warn", "medium"
            detail = f"Domain is {age_days} days old — relatively new, proceed with caution."
        else:
            status, sev = "pass", "none"
            detail = f"Domain is well-established ({age_days} days old)."

        return {
            "id": "domain_age", "name": "Domain Age",
            "status": status, "severity": sev, "detail": detail,
            "data": {"age_days": age_days, "created": str(created)},
        }
    except Exception as e:
        # severity "none" = 0 points, so a timeout does not inflate the risk score
        return {
            "id": "domain_age", "name": "Domain Age",
            "status": "warn", "severity": "none",
            "detail": "Domain age could not be verified — WHOIS lookup failed or timed out.",
            "data": {"age_days": None, "error": str(e)},
        }


def check_https(final_url: str):
    """NEW: HTTP-only sites are a warning sign, especially for anything finance-related."""
    is_https = final_url.startswith("https://")
    if is_https:
        status, sev = "pass", "none"
        detail = "Connection is encrypted (HTTPS)."
    else:
        status, sev = "warn", "medium"
        detail = "Site uses plain HTTP — your data is not encrypted. Never enter credentials here."
    return {
        "id": "https_check", "name": "HTTPS / Encryption",
        "status": status, "severity": sev, "detail": detail,
        "data": {"is_https": is_https},
    }


def check_suspicious_keywords(final_url: str):
    """NEW: Phishing URLs often contain keywords like 'login', 'verify', 'secure'."""
    parsed = urlparse(final_url)
    path_query = (parsed.path + "?" + parsed.query).lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_query]
    if len(found) >= 3:
        status, sev = "fail", "high"
        detail = f"URL path contains {len(found)} phishing-related keywords: {', '.join(found)}."
    elif found:
        status, sev = "warn", "low"
        detail = f"URL path contains suspicious keyword(s): {', '.join(found)}."
    else:
        status, sev = "pass", "none"
        detail = "No suspicious keywords detected in the URL path."
    return {
        "id": "suspicious_keywords", "name": "Suspicious Keywords",
        "status": status, "severity": sev, "detail": detail,
        "data": {"found_keywords": found},
    }


def check_ip_hostname(final_url: str):
    """NEW: URLs using raw IP addresses as hostname are almost always malicious."""
    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""
    # IPv4 pattern
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    if not is_ip:
        # Try resolving — if it fails, still not an IP-hostname
        try:
            socket.inet_aton(hostname)
            is_ip = True
        except (socket.error, OSError):
            is_ip = False
    if is_ip:
        status, sev = "fail", "high"
        detail = f"URL uses a raw IP address ({hostname}) instead of a domain name — strong indicator of a phishing or malware site."
    else:
        status, sev = "pass", "none"
        detail = "URL uses a proper domain name, not a raw IP address."
    return {
        "id": "ip_hostname", "name": "IP as Hostname",
        "status": status, "severity": sev, "detail": detail,
        "data": {"hostname": hostname, "is_ip": is_ip},
    }


# ── AGGREGATION ───────────────────────────────────────────────────────────────

def aggregate(checks):
    score = min(100, sum(SEVERITY_WEIGHTS[c["severity"]] for c in checks))
    if score >= 60:
        verdict = "dangerous"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return score, verdict


# ── MAIN SCAN FUNCTION ────────────────────────────────────────────────────────

def scan(url: str) -> dict:
    """
    Run all checks on a URL and return a structured report.
    Raises ValueError for invalid input.
    """
    # FIX 4: validate before doing any network work
    url = validate_url(url)

    chain, final = follow_redirects(url)

    checks = [
        check_redirects(chain),
        check_https(final),              # new
        check_homograph(final),
        check_typosquat(final),
        check_suspicious_keywords(final), # new
        check_ip_hostname(final),         # new
        check_domain_age(final),
    ]

    score, verdict = aggregate(checks)

    return {
        "input_url":  url,
        "final_url":  final,
        "verdict":    verdict,
        "risk_score": score,
        "checks":     checks,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    url = input("Paste a URL to scan: ").strip()
    try:
        print(json.dumps(scan(url), indent=2))
    except ValueError as e:
        print(f"Invalid URL: {e}")