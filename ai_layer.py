import os
from dotenv import load_dotenv

load_dotenv()

try:
    from google import genai
    _client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    _AI_AVAILABLE = bool(os.getenv("GEMINI_API_KEY"))
except Exception:
    _AI_AVAILABLE = False
    _client = None


def explain(scan_result):
    """Turn a scan result into a friendly plain-English verdict."""
    if not _AI_AVAILABLE:
        return _fallback(scan_result)

    findings = "\n".join(
        f"- {c['name']}: {c['detail']}" for c in scan_result["checks"]
    )
    prompt = f"""You are a friendly security assistant helping everyday Nigerian users.
Based on these findings, write a short, plain-English explanation (2-3 sentences)
telling the user whether this link is safe and why. Avoid jargon. Be direct about risk.
Do not use markdown or bullet points, just plain sentences.

Verdict: {scan_result['verdict']}
Risk score: {scan_result['risk_score']}/100
Findings:
{findings}"""

    try:
        resp = _client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return resp.text.strip()
    except Exception as e:
        print(f"GEMINI ERROR: {e}")
        return _fallback(scan_result)


def _fallback(scan_result):
    """If the AI call fails, still return something sensible."""
    v = str(scan_result["verdict"]).lower()
    if "safe" in v:
        return "This link looks safe based on our checks. No major red flags were found."
    elif "high" in v or "danger" in v:
        return "Warning: this link shows serious signs of being a scam. Do not enter any personal or bank details."
    return "This link shows some suspicious signs. Be careful before clicking or entering any information."