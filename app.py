
import streamlit as st
import pandas as pd
from datetime import datetime

from url_analyzer import analyze_url
from virustotal_checker import check_url_with_virustotal


# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="LinkShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ---------------- SESSION STATE ----------------
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "vt_api_responded" not in st.session_state:
    st.session_state.vt_api_responded = False


# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>
/* Main dashboard background */
.stApp {
    background: linear-gradient(135deg, #0b1020, #17152f);
    color: #f8fafc;
}

/* Main text */
h1, h2, h3, h4, p, li, label {
    color: #f8fafc;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #111827;
    border-right: 1px solid #374151;
}

section[data-testid="stSidebar"] * {
    color: #f9fafb;
}

/* White text input fields */
.stTextInput input,
.stTextArea textarea,
.stNumberInput input {
    background-color: #ffffff !important;
    color: #111827 !important;
    -webkit-text-fill-color: #111827 !important;
    border: 2px solid #8b5cf6 !important;
    border-radius: 8px !important;
    caret-color: #111827 !important;
}

/* Placeholder text */
.stTextInput input::placeholder,
.stTextArea textarea::placeholder {
    color: #6b7280 !important;
    -webkit-text-fill-color: #6b7280 !important;
    opacity: 1 !important;
}

/* Input focus */
.stTextInput input:focus,
.stTextArea textarea:focus {
    border-color: #c4b5fd !important;
    box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2) !important;
}

/* Buttons */
.stButton button,
.stDownloadButton button {
    background-color: #7c3aed !important;
    color: #ffffff !important;
    border: 1px solid #a78bfa !important;
    border-radius: 9px !important;
    font-weight: 600 !important;
}

.stButton button p,
.stDownloadButton button p {
    color: #ffffff !important;
}

.stButton button:hover,
.stDownloadButton button:hover {
    background-color: #6d28d9 !important;
    border-color: #c4b5fd !important;
}

/* Dashboard cards */
div[data-testid="stMetric"] {
    background-color: #1e293b;
    padding: 16px;
    border: 1px solid #475569;
    border-radius: 12px;
}

div[data-testid="stMetric"] label,
div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #ffffff !important;
}

/* Containers */
div[data-testid="stExpander"] {
    background-color: #172033;
    border: 1px solid #475569;
    border-radius: 10px;
}

/* Alerts and result text */
div[data-testid="stAlert"] {
    border-radius: 10px;
}

/* Dataframe */
div[data-testid="stDataFrame"] {
    background-color: #ffffff;
    border-radius: 8px;
}

/* Divider */
hr {
    border-color: #374151;
}

/* Small caption */
.stCaption {
    color: #cbd5e1 !important;
}
</style>
""", unsafe_allow_html=True)


# ---------------- HELPER FUNCTIONS ----------------
def get_api_key():
    try:
        return st.secrets.get("VIRUSTOTAL_API_KEY", "")
    except Exception:
        return ""


def validate_url(url):
    url = url.strip()

    if not url:
        return False, "Please enter a URL."

    if any(character.isspace() for character in url):
        return False, "The URL cannot contain spaces."

    if not url.startswith(("http://", "https://")):
        return False, "Enter a complete URL starting with http:// or https://."

    return True, ""


def scan_website(url):
    # Local rule-based analysis
    try:
        local_result = analyze_url(url)
    except Exception as error:
        return {
            "url": url,
            "verdict": "SCAN ERROR",
            "score": 0,
            "risk": "Unknown",
            "findings": [f"Local analysis failed: {error}"],
            "vt_status": "ERROR",
            "vt_message": "VirusTotal was not checked."
        }

    # VirusTotal report lookup
    try:
        vt_result = check_url_with_virustotal(url)
    except Exception:
        vt_result = {
            "status": "ERROR",
            "message": "VirusTotal lookup failed."
        }

    vt_status = vt_result.get("status", "ERROR")
    vt_message = vt_result.get("message", "No report details available.")

    st.session_state.vt_api_responded = vt_status in {
        "PHISHING DETECTED",
        "SUSPICIOUS",
        "NO KNOWN THREAT",
        "NOT FOUND",
        "UNKNOWN"
    }

    risk = str(local_result.get("risk", "Unknown"))
    score = int(local_result.get("score", 0))
    findings = local_result.get("findings", [])

    if not isinstance(findings, list):
        findings = [str(findings)]

    # Combine evidence without claiming certainty
    if vt_status == "PHISHING DETECTED":
        verdict = "MALICIOUS LINK DETECTED"
        risk = "High"

    elif vt_status == "SUSPICIOUS":
        verdict = "SUSPICIOUS LINK DETECTED"
        risk = "High"

    elif risk.lower() == "high":
        verdict = "HIGH-RISK LINK DETECTED"

    elif vt_status == "NO KNOWN THREAT" and risk.lower() == "low":
        verdict = "NO KNOWN THREAT DETECTED"

    else:
        verdict = "UNCERTAIN — USE CAUTION"

    return {
        "url": url,
        "verdict": verdict,
        "score": score,
        "risk": risk,
        "findings": findings,
        "vt_status": vt_status,
        "vt_message": vt_message,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }


def display_result(result):
    st.subheader("🔎 Scan Results")

    verdict = result["verdict"]

    if verdict == "MALICIOUS LINK DETECTED":
        st.error("🚨 " + verdict)

    elif verdict in {
        "SUSPICIOUS LINK DETECTED",
        "HIGH-RISK LINK DETECTED"
    }:
        st.warning("⚠️ " + verdict)

    elif verdict == "NO KNOWN THREAT DETECTED":
        st.success("✅ " + verdict)

    else:
        st.info("ℹ️ " + verdict)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Risk Score", f'{result["score"]}/100')

    with col2:
        st.metric("Risk Level", result["risk"])

    with col3:
        st.metric("VirusTotal Status", result["vt_status"])

    st.markdown("### 🌐 Scanned URL")
    st.code(result["url"], language=None)

    st.markdown("### 🧠 Local Analysis Findings")

    if result["findings"]:
        for finding in result["findings"]:
            st.write("•", finding)
    else:
        st.write("No configured warning signs were detected.")

    st.markdown("### 🛡️ VirusTotal Report")
    st.write(result["vt_message"])

    st.caption(
        "A missing report or a low risk score does not prove that a URL is safe. "
        "Use caution before entering passwords or payment details."
    )


# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.title("🛡️ LinkShield AI")
    st.caption("AI-assisted URL threat analysis")

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "URL Scanner",
            "Scan History",
            "About"
        ]
    )

    st.divider()

    st.subheader("System Status")

    api_key = get_api_key()

    if api_key:
        st.success("VirusTotal API key configured")
    else:
        st.warning("VirusTotal API key missing")

    if st.session_state.vt_api_responded:
        st.success("Threat intelligence: API responded")
    else:
        st.info("Threat intelligence: Not yet verified")

    st.caption(
        "VirusTotal is queried when you scan a URL. "
        "This is not a continuous live threat feed."
    )


# ---------------- DASHBOARD ----------------
if page == "Dashboard":
    st.title("🛡️ LinkShield AI")
    st.subheader("Intelligent Phishing & Malicious URL Detection")

    st.write(
        "Analyze suspicious links using local URL heuristics "
        "and available VirusTotal reports."
    )

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Total Scans",
            len(st.session_state.scan_history)
        )

    with col2:
        risky_scans = sum(
            1 for item in st.session_state.scan_history
            if item["risk"].lower() == "high"
        )
        st.metric("High-Risk Scans", risky_scans)

    with col3:
        st.metric(
            "VirusTotal",
            "Configured" if api_key else "Not configured"
        )

    st.divider()

    st.markdown("### 🔍 Quick URL Scan")

    with st.form("dashboard_scan_form"):
        url_input = st.text_input(
            "Enter website URL",
            placeholder="https://example.com",
            help="Enter a complete URL including http:// or https://"
        )

        scan_button = st.form_submit_button(
            "🔎 Scan Website",
            use_container_width=True
        )

    if scan_button:
        valid, message = validate_url(url_input)

        if not valid:
            st.error(message)
        else:
            with st.spinner("Analyzing URL and checking VirusTotal..."):
                result = scan_website(url_input.strip())

            result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.last_result = result
            st.session_state.scan_history.insert(0, result)

    if st.session_state.last_result:
        display_result(st.session_state.last_result)


# ---------------- URL SCANNER ----------------
elif page == "URL Scanner":
    st.title("🔎 URL Scanner")

    st.write(
        "Check a suspicious URL using local rules and VirusTotal's "
        "existing analysis report, when available."
    )

    with st.form("scanner_form"):
        url_input = st.text_input(
            "Website URL",
            placeholder="https://example.com"
        )

        submitted = st.form_submit_button(
            "Scan URL",
            use_container_width=True
        )

    if submitted:
        valid, message = validate_url(url_input)

        if not valid:
            st.error(message)
        else:
            with st.spinner("Scanning URL..."):
                result = scan_website(url_input.strip())

            result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.last_result = result
            st.session_state.scan_history.insert(0, result)

    if st.session_state.last_result:
        display_result(st.session_state.last_result)


# ---------------- SCAN HISTORY ----------------
elif page == "Scan History":
    st.title("📜 Scan History")

    history = st.session_state.scan_history

    if not history:
        st.info("No URLs scanned yet. Open Dashboard or URL Scanner to begin.")
    else:
        rows = []

        for item in history:
            rows.append({
                "Time": item.get("time", ""),
                "URL": item.get("url", ""),
                "Verdict": item.get("verdict", ""),
                "Risk": item.get("risk", ""),
                "Score": item.get("score", 0),
                "VirusTotal": item.get("vt_status", "")
            })

        df = pd.DataFrame(rows)

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )

        csv_data = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "⬇️ Download Scan History CSV",
            data=csv_data,
            file_name="linkshield_scan_history.csv",
            mime="text/csv",
            use_container_width=True
        )

        if st.button("🗑️ Clear Scan History"):
            st.session_state.scan_history = []
            st.session_state.last_result = None
            st.rerun()


# ---------------- ABOUT ----------------
elif page == "About":
    st.title("ℹ️ About LinkShield AI")

    st.markdown("""
    ### What does LinkShield AI do?

    LinkShield AI helps identify potentially suspicious URLs through:

    - **URL heuristic analysis:** Looks for configured warning signs such as
      suspicious keywords, unusual URL structure, and IP-based hostnames.
    - **VirusTotal report lookup:** Checks whether VirusTotal has an existing
      report for the submitted URL.
    - **Risk scoring:** Displays the score generated by the local analyzer.
    - **Scan history:** Keeps a session-level history of scans and allows CSV export.

    ### Important limitations

    - A suspicious URL can be dangerous even if no existing report is found.
    - HTTPS does not guarantee that a website is legitimate.
    - A low risk score is not proof that a URL is safe.
    - VirusTotal checks depend on API access, report availability, and usage limits.
    - This application does not continuously monitor live threat feeds.
    """)
