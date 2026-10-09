
import requests
import streamlit as st
import base64


def check_url_with_virustotal(url):
    api_key = st.secrets.get("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "status": "ERROR",
            "message": "VirusTotal API key is not configured."
        }

    headers = {"x-apikey": api_key}

    # Convert URL into VirusTotal's URL identifier
    url_id = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious > 0:
                return {
                    "status": "PHISHING DETECTED",
                    "message": f"{malicious} security engines flagged this URL.",
                    "stats": stats
                }

            if suspicious > 0:
                return {
                    "status": "SUSPICIOUS",
                    "message": f"{suspicious} security engines marked it suspicious.",
                    "stats": stats
                }

            if total == 0:
                return {
                    "status": "UNKNOWN",
                    "message": "No completed analysis results are available."
                }

            return {
                "status": "NO KNOWN THREAT",
                "message": "No engines flagged this URL in the available results.",
                "stats": stats
            }

        if response.status_code == 404:
            return {
                "status": "NOT FOUND",
                "message": "VirusTotal has no report for this URL yet. A scan can be submitted next."
            }

        if response.status_code == 401:
            return {
                "status": "ERROR",
                "message": "API key is invalid or unauthorized."
            }

        if response.status_code == 429:
            return {
                "status": "ERROR",
                "message": "VirusTotal API quota or rate limit reached."
            }

        return {
            "status": "ERROR",
            "message": f"VirusTotal returned HTTP {response.status_code}."
        }

    except requests.RequestException:
        return {
            "status": "ERROR",
            "message": "Could not connect to VirusTotal. Check your internet connection."
        }
