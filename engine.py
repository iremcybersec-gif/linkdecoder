import requests
import tldextract
import Levenshtein
from datetime import datetime, timezone

# Nigerian brands to protect against impersonation — expand this list
PROTECTED_BRANDS = [
    "gtbank", "gtworld", "paystack", "flutterwave", "opay", "kuda",
    "zenithbank", "accessbank", "firstbank", "uba", "moniepoint",
    "palmpay", "interswitch", "remita", "nibss",
]

SEVERITY_WEIGHTS = {"none": 0, "low": 15, "medium": 35, "high": 60}


def follow_redirects(url, max_hops=10):
    chain = []
    current = url if url.startswith("http") else "http://" + url
    try:
        for _ in range(max_hops):
            resp = requests.head(current, allow_redirects=False, timeout=5)
            chain.append(current)
            if resp.status_code in (301, 302, 303, 307, 308):
                nxt = resp.headers.get("Location")
                if not nxt:
                    break
                current = nxt if nxt.startswith("http") else \
                    requests.compat.urljoin(current, nxt)
            else:
                break
    except requests.RequestException:
        pass
    return chain, current


def check_redirects(chain):
    hops = len(chain) - 1
    if hops == 0:
        status, sev = "pass", "none"
        detail = "No redirects — link goes straight to its destination."
    elif hops <= 1:
        status, sev = "warn", "low"
        detail = f"URL redirects {hops} time before reaching its destination."
    else:
        status, sev = "warn", "medium"
        detail = f"URL redirects {hops} times before reaching its destination."
    return {"id": "redirect_chain", "name": "Redirect Chain",
            "status": status, "severity": sev, "detail": detail,
            "data": {"hops": hops, "chain": chain}}


def check_homograph(final_url):
    ext = tldextract.extract(final_url)
    domain = ext.domain
    is_puny = domain.startswith("xn--")
    try:
        decoded = domain.encode().decode("idna") if is_puny else domain
    except Exception:
        decoded = domain
    if is_puny:
        status, sev = "fail", "high"
        detail = f"Domain uses punycode encoding — possible character spoofing (decodes to '{decoded}')."
    else:
        status, sev = "pass", "none"
        detail = "No character-spoofing detected in the domain."
    return {"id": "homograph", "name": "Punycode / Homograph",
            "status": status, "severity": sev, "detail": detail,
            "data": {"is_punycode": is_puny, "decoded_domain": decoded}}


def check_typosquat(final_url):
    ext = tldextract.extract(final_url)
    domain = ext.domain.lower()
    best_brand, best_dist = None, 99
    for brand in PROTECTED_BRANDS:
        if brand in domain and brand != domain:
            best_brand, best_dist = brand, 1
            break
        d = Levenshtein.distance(domain, brand)
        if d < best_dist:
            best_brand, best_dist = brand, d
    if best_brand and best_dist == 0:
        status, sev, detail = "pass", "none", "Domain matches a known brand exactly."
    elif best_brand and best_dist <= 2:
        status, sev = "fail", "high"
        detail = f"Domain closely mimics '{best_brand}' (Nigerian brand)."
    elif best_brand and best_dist <= 4:
        status, sev = "warn", "medium"
        detail = f"Domain loosely resembles '{best_brand}'."
    else:
        status, sev, detail = "pass", "none", "No brand impersonation detected."
    return {"id": "typosquat", "name": "Brand Impersonation",
            "status": status, "severity": sev, "detail": detail,
            "data": {"matched_brand": best_brand, "distance": best_dist}}


def check_domain_age(final_url):
    try:
        import whois
        ext = tldextract.extract(final_url)
        domain = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            raise ValueError("no creation date")
        age_days = (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc)).days
        if age_days < 30:
            status, sev = "fail", "high"
            detail = f"Domain was registered only {age_days} days ago — scam domains are usually very new."
        elif age_days < 180:
            status, sev = "warn", "medium"
            detail = f"Domain is {age_days} days old — relatively new."
        else:
            status, sev = "pass", "none"
            detail = f"Domain is well-established ({age_days} days old)."
        return {"id": "domain_age", "name": "Domain Age",
                "status": status, "severity": sev, "detail": detail,
                "data": {"age_days": age_days, "created": str(created)}}
    except Exception as e:
        return {"id": "domain_age", "name": "Domain Age",
                "status": "warn", "severity": "low",
                "detail": "Could not determine domain age (WHOIS lookup failed).",
                "data": {"age_days": None, "error": str(e)}}


def aggregate(checks):
    score = min(100, sum(SEVERITY_WEIGHTS[c["severity"]] for c in checks))
    if score >= 60:
        verdict = "dangerous"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return score, verdict


def scan(url):
    chain, final = follow_redirects(url)
    checks = [
        check_redirects(chain),
        check_homograph(final),
        check_typosquat(final),
        check_domain_age(final),
    ]
    score, verdict = aggregate(checks)
    return {
        "input_url": url,
        "final_url": final,
        "verdict": verdict,
        "risk_score": score,
        "checks": checks,
    }


if __name__ == "__main__":
    import json
    url = input("Paste a URL: ").strip()
    print(json.dumps(scan(url), indent=2))