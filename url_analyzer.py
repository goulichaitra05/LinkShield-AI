
from urllib.parse import urlparse
import re
import validators
import tldextract


def analyze_url(url):
    url = url.strip()
    findings = []
    score = 0

    if not url:
        return {
            "score": 0,
            "risk": "Invalid URL",
            "findings": ["Please enter a URL."]
        }

    # Check URL format
    if not validators.url(url):
        return {
            "score": 0,
            "risk": "Invalid URL",
            "findings": [
                "Enter a complete URL, such as https://example.com"
            ]
        }

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    # Check for possible brand impersonation
    lookalike_patterns = {
        "paypal": ["paypa1", "pay-pal", "paypall"],
        "google": ["g00gle", "googIe"],
        "amazon": ["amaz0n", "arnazon"],
        "microsoft": ["micros0ft"]
    }

    for brand, patterns in lookalike_patterns.items():
        if any(pattern in hostname_lower for pattern in patterns):
            score += 35
            findings.append(
                f"Possible {brand.title()} brand impersonation detected."
            )
            break

    # Check for suspicious billing-alert wording
    if "billing" in hostname_lower and "alert" in hostname_lower:
        score += 30
        findings.append(
            "Suspicious billing-alert wording in the hostname. "
            "Verify the sender and domain independently."
        )

    # Extract domain information
    domain_info = tldextract.extract(url)
    domain = domain_info.domain
    suffix = domain_info.suffix

    # Check HTTPS
    if parsed.scheme.lower() != "https":
        score += 15
        findings.append("The URL does not use HTTPS.")

    # Check for IP address instead of a domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 25
        findings.append("The hostname uses an IP address.")

    # Check for suspicious words in the URL
    suspicious_words = [
        "login", "verify", "password", "banking",
        "update", "secure", "account", "confirm"
    ]

    matches = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if matches:
        score += min(len(matches) * 10, 30)
        findings.append(
            "Sensitive words found: " + ", ".join(matches)
        )

    # Check for unusually long URLs
    if len(url) > 100:
        score += 15
        findings.append("The URL is unusually long.")

    # Check for '@' in the URL authority section
    if "@" in parsed.netloc:
        score += 25
        findings.append(
            "The URL contains '@' in its authority section."
        )

    # Check for punycode domains
    if "xn--" in hostname_lower:
        score += 20
        findings.append(
            "The domain contains encoded international characters."
        )

    # Check for many subdomains
    if hostname.count(".") >= 4:
        score += 15
        findings.append(
            "The hostname contains many subdomains."
        )

    # Keep score between 0 and 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    # Default finding when no rules are triggered
    if not findings:
        findings.append(
            "No configured warning signs were detected."
        )

    return {
        "score": score,
        "risk": risk,
        "findings": findings,
        "domain": hostname,
        "registered_domain": (
            f"{domain}.{suffix}" if suffix else domain
        )
    }
