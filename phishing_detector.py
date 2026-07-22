import argparse
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

URGENT_PHRASES = [
    "act now",
    "urgent",
    "immediately",
    "account suspended",
    "verify your account",
    "confirm your identity",
    "limited time",
    "payment failed",
    "unusual activity",
    "click below",
    "final warning",
]

SENSITIVE_PHRASES = [
    "password",
    "credit card",
    "bank details",
    "social security",
    "one-time password",
    "otp",
    "login credentials",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
    ".ps1", ".jar", ".msi", ".hta", ".iso", ".img",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "is.gd", "buff.ly", "cutt.ly",
}

def extract_urls(text: str) -> list[str]:
    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text, flags=re.IGNORECASE)

def get_domain(value: str) -> str:
    if not value:
        return ""
    if "@" in value and not value.startswith("http"):
        return value.split("@")[-1].strip(" >").lower()
    parsed = urlparse(value)
    return parsed.netloc.lower().split(":")[0]

def parse_email(file_path: Path) -> dict:
    with file_path.open("rb") as f:
        message = BytesParser(policy=policy.default).parse(f)

    body_parts = []
    attachments = []

    if message.is_multipart():
        for part in message.walk():
            content_disposition = part.get_content_disposition()
            filename = part.get_filename()

            if content_disposition == "attachment" and filename:
                attachments.append(filename)
            elif part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(message.get_content())
        except Exception:
            body_parts.append("")

    return {
        "subject": str(message.get("subject", "")),
        "from": str(message.get("from", "")),
        "reply_to": str(message.get("reply-to", "")),
        "return_path": str(message.get("return-path", "")),
        "authentication_results": str(message.get("authentication-results", "")),
        "body": "\n".join(body_parts),
        "attachments": attachments,
    }

def analyse_email(email_data: dict) -> dict:
    score = 0
    indicators = []

    combined_text = (
        email_data["subject"] + "\n" + email_data["body"]
    ).lower()

    # Urgency indicators
    urgent_matches = sorted({
        phrase for phrase in URGENT_PHRASES if phrase in combined_text
    })
    if urgent_matches:
        points = min(25, 5 * len(urgent_matches))
        score += points
        indicators.append({
            "indicator": "Urgent or threatening language",
            "points": points,
            "details": urgent_matches,
        })

    # Sensitive information requests
    sensitive_matches = sorted({
        phrase for phrase in SENSITIVE_PHRASES if phrase in combined_text
    })
    if sensitive_matches:
        points = min(20, 5 * len(sensitive_matches))
        score += points
        indicators.append({
            "indicator": "Requests sensitive information",
            "points": points,
            "details": sensitive_matches,
        })

    # Sender and reply-to mismatch
    sender_domain = get_domain(email_data["from"])
    reply_domain = get_domain(email_data["reply_to"])
    if sender_domain and reply_domain and sender_domain != reply_domain:
        score += 20
        indicators.append({
            "indicator": "Sender and Reply-To domains do not match",
            "points": 20,
            "details": [sender_domain, reply_domain],
        })

    # Authentication failures
    auth = email_data["authentication_results"].lower()
    auth_failures = []
    for item in ("spf=fail", "dkim=fail", "dmarc=fail"):
        if item in auth:
            auth_failures.append(item)

    if auth_failures:
        points = min(30, 10 * len(auth_failures))
        score += points
        indicators.append({
            "indicator": "Email authentication failure",
            "points": points,
            "details": auth_failures,
        })

    # URL checks
    urls = extract_urls(email_data["body"])
    suspicious_urls = []
    for url in urls:
        domain = get_domain(url)
        reasons = []

        if url.lower().startswith("http://"):
            reasons.append("Uses HTTP instead of HTTPS")
        if domain in SHORTENERS:
            reasons.append("Uses a shortened URL")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
            reasons.append("Uses an IP address instead of a domain")
        if domain.count(".") >= 3:
            reasons.append("Contains many subdomains")
        if any(word in domain for word in ("login", "verify", "secure", "account", "update")):
            reasons.append("Contains suspicious account-related words")

        if reasons:
            suspicious_urls.append({"url": url, "reasons": reasons})

    if suspicious_urls:
        points = min(30, 10 * len(suspicious_urls))
        score += points
        indicators.append({
            "indicator": "Suspicious URL characteristics",
            "points": points,
            "details": suspicious_urls,
        })

    # Attachment checks
    suspicious_attachments = []
    for filename in email_data["attachments"]:
        suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
        final_suffix = suffixes[-1] if suffixes else ""

        if final_suffix in SUSPICIOUS_EXTENSIONS:
            suspicious_attachments.append(filename)
        elif len(suffixes) >= 2 and suffixes[-1] in SUSPICIOUS_EXTENSIONS:
            suspicious_attachments.append(filename)

    if suspicious_attachments:
        score += 30
        indicators.append({
            "indicator": "Potentially dangerous attachment",
            "points": 30,
            "details": suspicious_attachments,
        })

    score = min(score, 100)

    if score >= 70:
        risk = "High"
        recommendation = "Treat as likely phishing. Do not click links or open attachments."
    elif score >= 40:
        risk = "Medium"
        recommendation = "Review carefully and verify the sender through a trusted channel."
    else:
        risk = "Low"
        recommendation = "No major indicators detected, but manual verification is still recommended."

    return {
        "risk_score": score,
        "risk_level": risk,
        "recommendation": recommendation,
        "indicators": indicators,
        "email_summary": {
            "subject": email_data["subject"],
            "from": email_data["from"],
            "reply_to": email_data["reply_to"],
            "attachments": email_data["attachments"],
            "urls_found": urls,
        },
    }

def print_report(report: dict) -> None:
    print("\n=== Phishing Email Analysis Report ===")
    print(f"Risk score: {report['risk_score']}/100")
    print(f"Risk level: {report['risk_level']}")
    print(f"Recommendation: {report['recommendation']}\n")

    print("Email summary:")
    for key, value in report["email_summary"].items():
        print(f"  {key}: {value}")

    print("\nIndicators:")
    if not report["indicators"]:
        print("  No major indicators detected.")
    else:
        for item in report["indicators"]:
            print(f"  [+{item['points']}] {item['indicator']}")
            print(f"      Details: {item['details']}")

    print("\nImportant: This is a learning tool, not a replacement for professional email security systems.")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse a local .eml file for common phishing indicators."
    )
    parser.add_argument("email_file", help="Path to an .eml email file")
    parser.add_argument("--json", dest="json_file", help="Save the report as JSON")
    args = parser.parse_args()

    email_path = Path(args.email_file)

    if not email_path.exists():
        print(f"Error: File not found: {email_path}")
        return 1

    if email_path.suffix.lower() != ".eml":
        print("Error: Please provide an .eml file.")
        return 1

    try:
        email_data = parse_email(email_path)
        report = analyse_email(email_data)
        print_report(report)

        if args.json_file:
            Path(args.json_file).write_text(
                json.dumps(report, indent=2),
                encoding="utf-8",
            )
            print(f"\nJSON report saved to: {args.json_file}")

        return 0
    except Exception as exc:
        print(f"Error while analysing the email: {exc}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
