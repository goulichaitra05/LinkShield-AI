
import html
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from url_analyzer import analyze_url
from ml_detector import predict_url


# ---------------- PAGE CONFIG ----------------

st.set_page_config(
    page_title="LinkShield AI | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------- SESSION STATE ----------------

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None


# ---------------- CUSTOM FRONTEND ----------------

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    :root {
        --background: #07111f;
        --panel: #101e30;
        --border: #22364d;
        --blue: #43b7ff;
        --text: #edf5ff;
        --muted: #9cb0c8;
    }

    .stApp {
        background: linear-gradient(145deg, #07111f 0%, #0a1728 55%, #07111f 100%);
        color: var(--text);
        font-family: 'Inter', sans-serif;
    }

    [data-testid="stHeader"] {
        background: rgba(7, 17, 31, 0.9);
    }

    [data-testid="stSidebar"] {
        background: #0b1727;
        border-right: 1px solid #22364d;
    }

    [data-testid="stSidebar"] * {
        color: #edf5ff;
    }

    .block-container {
        max-width: 1400px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    h1, h2, h3 {
        color: #edf5ff !important;
        letter-spacing: -0.5px;
    }

    p, label, .stCaption {
        color: #b7c8dc;
    }

    .hero {
        background: linear-gradient(120deg, #102640, #112f48 60%, #123d51);
        border: 1px solid #245273;
        border-radius: 22px;
        padding: 30px;
        margin: 8px 0 26px 0;
        position: relative;
        overflow: hidden;
    }

    .hero-label {
        display: inline-block;
        background: #153d55;
        border: 1px solid #276b91;
        color: #70d1ff;
        border-radius: 30px;
        padding: 6px 12px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 1px;
    }

    .hero h1 {
        font-size: clamp(30px, 4vw, 46px);
        margin: 16px 0 8px 0;
        font-weight: 800;
    }

    .hero p {
        font-size: 15px;
        max-width: 680px;
        line-height: 1.7;
        color: #bfd1e5;
    }

    .section-label {
        color: #63c8ff;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 1.7px;
        text-transform: uppercase;
        margin-bottom: 8px;
    }

    .panel {
        background: #101e30;
        border: 1px solid #22364d;
        border-radius: 17px;
        padding: 20px;
        margin-bottom: 16px;
    }

    .metric-card {
        background: linear-gradient(145deg, #12243a, #0e1b2d);
        border: 1px solid #223d58;
        border-radius: 16px;
        padding: 19px;
        min-height: 118px;
    }

    .metric-label {
        color: #a9bdd4;
        font-size: 13px;
        font-weight: 600;
    }

    .metric-value {
        color: #f2f7ff;
        font-size: 29px;
        font-weight: 800;
        margin-top: 12px;
    }

    .metric-note {
        color: #7f9ab6;
        font-size: 11px;
        margin-top: 5px;
    }

    .risk-pill {
        display: inline-block;
        border-radius: 25px;
        padding: 7px 13px;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 0.6px;
    }

    .risk-high {
        background: #451d2b;
        color: #ff8293;
        border: 1px solid #9c364d;
    }

    .risk-medium {
        background: #45351b;
        color: #ffd16b;
        border: 1px solid #886727;
    }

    .risk-low {
        background: #153a32;
        color: #74e5bb;
        border: 1px solid #287760;
    }

    .small-muted {
        color: #8fa8c2;
        font-size: 12px;
    }

    div.stButton > button,
    div.stFormSubmitButton > button {
        border-radius: 10px;
        border: 1px solid #3b9fd3;
        font-weight: 700;
        min-height: 44px;
    }

    div.stButton > button[kind="primary"],
    div.stFormSubmitButton > button[kind="primary"] {
        background: linear-gradient(90deg, #087db5, #16a8cf);
        color: white;
    }

    div[data-testid="stTextInput"] input {
        background: #0b1727;
        color: #f3f8ff;
        border: 1px solid #2a4561;
        border-radius: 10px;
        min-height: 48px;
    }

    div[data-testid="stTextInput"] input:focus {
        border-color: #43b7ff;
        box-shadow: 0 0 0 1px #43b7ff;
    }

    div[data-testid="stMetric"] {
        background: #101e30;
        border: 1px solid #22364d;
        padding: 14px;
        border-radius: 13px;
    }

    div[data-testid="stMetricLabel"] {
        color: #9cb0c8;
    }

    div[data-testid="stMetricValue"] {
        color: #edf5ff;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #22364d;
        border-radius: 12px;
        overflow: hidden;
    }

    div[data-baseweb="tab-list"] {
        gap: 8px;
    }

    button[data-baseweb="tab"] {
        color: #a9bdd4;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        color: #5bc6ff;
    }

    hr {
        border-color: #22364d;
    }

    .footer {
        border-top: 1px solid #22364d;
        margin-top: 30px;
        padding-top: 18px;
        color: #7f96af;
        font-size: 12px;
        text-align: center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------- HELPERS ----------------

def metric_card(label, value, note):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{html.escape(str(label))}</div>
            <div class="metric-value">{html.escape(str(value))}</div>
            <div class="metric-note">{html.escape(str(note))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def risk_pill(risk):
    css_class = {
        "High": "risk-high",
        "Medium": "risk-medium",
        "Low": "risk-low",
    }.get(risk, "risk-medium")

    st.markdown(
        f'<span class="risk-pill {css_class}">'
        f'{html.escape(str(risk).upper())} RISK'
        f'</span>',
        unsafe_allow_html=True,
    )


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown("## 🛡️ LinkShield AI")
    st.caption("URL SECURITY CENTER")
    st.divider()

    st.markdown("### Navigation")
    st.markdown("🔎 **URL Scanner**")
    st.markdown("📊 **Security Dashboard**")
    st.markdown("🕘 **Scan History**")
    st.markdown("ℹ️ **About the Project**")

    st.divider()

    st.markdown("### System information")
    st.markdown("**Engine:** Rule-based analysis")
    st.markdown("**ML module:** Experimental")
    st.markdown("**Interface:** Streamlit")

    st.info(
        "This prototype analyzes URL text only. "
        "It does not open or visit the submitted website."
    )


# ---------------- HERO ----------------

st.markdown(
    """
    <div class="hero">
        <span class="hero-label">● AI-ASSISTED URL ANALYSIS</span>
        <h1>Protect every click.</h1>
        <p>
            Inspect suspicious links, review potential phishing warning
            signs, and understand URL risk indicators from one
            cybersecurity dashboard.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------- DASHBOARD METRICS ----------------

history = st.session_state.scan_history

total_scans = len(history)
high_risk = sum(
    item["Rule Risk"] == "High" for item in history
)
medium_risk = sum(
    item["Rule Risk"] == "Medium" for item in history
)
low_risk = sum(
    item["Rule Risk"] == "Low" for item in history
)

st.markdown('<div class="section-label">Security overview</div>',
            unsafe_allow_html=True)
st.subheader("Your scanning activity")

m1, m2, m3, m4 = st.columns(4)

with m1:
    metric_card("RECENT SCANS", total_scans, "Latest 10 scans")

with m2:
    metric_card("HIGH RISK", high_risk, "Rule-based classification")

with m3:
    metric_card("MEDIUM RISK", medium_risk, "Rule-based classification")

with m4:
    metric_card("LOW RISK", low_risk, "Not proof of safety")

st.caption("Counts cover the latest 10 scans in this browser session.")

st.divider()


# ---------------- MAIN TABS ----------------

scanner_tab, history_tab, about_tab = st.tabs(
    ["🔎 URL Scanner", "🕘 Scan History", "ℹ️ About"]
)


# ---------------- URL SCANNER ----------------

with scanner_tab:
    st.markdown('<div class="section-label">Threat inspection</div>',
                unsafe_allow_html=True)
    st.subheader("Analyze a suspicious link")
    st.write(
        "Paste the complete URL below. The application checks "
        "configured warning signs and runs an experimental ML prediction."
    )

    with st.container(border=True):
        with st.form("url_scanner", clear_on_submit=False):
            url = st.text_input(
                "Website URL",
                placeholder="https://example.com",
                help="Enter a complete URL beginning with http:// or https://.",
            )

            submitted = st.form_submit_button(
                "🔍  Analyze URL",
                type="primary",
                use_container_width=True,
            )

    if submitted:
        if not url.strip():
            st.error("Please enter a URL first.")
        else:
            rule_result = analyze_url(url)
            ml_result = predict_url(url)

            if rule_result["risk"] == "Invalid URL":
                st.error(rule_result["findings"][0])
            elif ml_result["prediction"] == "Invalid URL":
                st.error(ml_result["warning"])
            else:
                st.session_state.last_result = {
                    "url": url.strip(),
                    "rules": rule_result,
                    "ml": ml_result,
                }

                st.session_state.scan_history.insert(
                    0,
                    {
                        "URL": url.strip(),
                        "Rule Score": rule_result["score"],
                        "Rule Risk": rule_result["risk"],
                        "ML Prediction": ml_result["prediction"],
                        "ML Confidence (%)": ml_result["confidence"],
                    },
                )

                st.session_state.scan_history = (
                    st.session_state.scan_history[:10]
                )

    if st.session_state.last_result is not None:
        saved = st.session_state.last_result
        result = saved["rules"]
        ml_result = saved["ml"]

        st.divider()
        st.markdown(
            '<div class="section-label">Analysis report</div>',
            unsafe_allow_html=True,
        )
        st.subheader("Latest scan results")

        left, center, right = st.columns([1, 1, 1.2])

        with left:
            metric_card(
                "RULE-BASED SCORE",
                f"{result['score']}/100",
                "Higher means more configured warning signs",
            )

        with center:
            st.markdown("#### Rule-based risk")
            risk_pill(result["risk"])
            st.write("")
            st.progress(result["score"] / 100)

        with right:
            metric_card(
                "EXPERIMENTAL ML",
                ml_result["prediction"].title(),
                f"Model output: {ml_result['confidence']}%",
            )

        if result["risk"] == "High":
            st.error(
                "High risk: the configured checks found multiple "
                "or significant warning signs."
            )
        elif result["risk"] == "Medium":
            st.warning(
                "Medium risk: review the warning signs before "
                "interacting with this link."
            )
        else:
            st.success(
                "Few configured warning signs were detected. "
                "This does not prove that the URL is safe."
            )

        st.markdown("### 🔍 Detected warning signs")

        for finding in result["findings"]:
            st.markdown(f"- {finding}")

        with st.expander("🌐 Technical URL details"):
            st.write("**Submitted URL:**", saved["url"])
            st.write(
                "**Hostname:**",
                result.get("domain", "Unavailable"),
            )
            st.write(
                "**Registered domain estimate:**",
                result.get("registered_domain", "Unavailable"),
            )
            st.write(
                "**Protocol:**",
                urlparse(saved["url"]).scheme.upper(),
            )
            st.write(
                "**URL length:**",
                f"{len(saved['url'])} characters",
            )

        with st.expander("🤖 Experimental model details"):
            st.write("**Prediction:**", ml_result["prediction"])
            st.write("**Model confidence:**", f"{ml_result['confidence']}%")
            st.warning(ml_result["warning"])
            st.caption(
                "The model uses a tiny synthetic demonstration dataset. "
                "Its confidence is not a verified probability of maliciousness."
            )

        st.markdown("### 🛡️ Recommended precautions")
        st.markdown(
            """
            - Verify the domain through the organization's official website.
            - Never share passwords, payment details, or OTPs with an
              unverified page.
            - Be cautious with unexpected account alerts and payment requests.
            - When uncertain, do not click the link.
            """
        )

    else:
        st.markdown(
            """
            <div class="panel">
                <h3>Ready to inspect a URL?</h3>
                <p>
                    Your report will show the rule-based risk score,
                    detected warning signs, experimental ML output,
                    and useful safety precautions.
                </p>
                <p class="small-muted">
                    Tip: Try a known test URL first. Never use a live
                    malicious link just to test the interface.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ---------------- HISTORY ----------------

with history_tab:
    st.markdown('<div class="section-label">Activity log</div>',
                unsafe_allow_html=True)
    st.subheader("Recent scan history")

    if st.session_state.scan_history:
        history_df = pd.DataFrame(st.session_state.scan_history)

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

        csv_data = history_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            "📥 Download scan report (CSV)",
            data=csv_data,
            file_name="linkshield_scan_report.csv",
            mime="text/csv",
            use_container_width=True,
        )

        if st.button("🗑️ Clear scan history"):
            st.session_state.scan_history = []
            st.session_state.last_result = None
            st.rerun()
    else:
        st.info("No scans recorded yet. Analyze a URL to populate this page.")


# ---------------- ABOUT ----------------

with about_tab:
    st.markdown('<div class="section-label">Project information</div>',
                unsafe_allow_html=True)
    st.subheader("About LinkShield AI")

    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            st.markdown("### 🎯 Project goal")
            st.write(
                "Help users understand potential phishing warning signs "
                "in URLs through an accessible security interface."
            )

            st.markdown("### 🔎 Rule-based engine")
            st.write(
                "Checks configured URL characteristics such as suspicious "
                "words, unusual length, non-HTTPS schemes, and possible "
                "brand-lookalike patterns."
            )

    with col2:
        with st.container(border=True):
            st.markdown("### 🤖 Machine learning")
            st.write(
                "Uses a demonstration text-classification pipeline to "
                "produce an experimental prediction. It requires a larger, "
                "representative labeled dataset and independent evaluation."
            )

            st.markdown("### 🧰 Technology stack")
            st.write(
                "Python, Streamlit, pandas, scikit-learn, validators, "
                "and tldextract."
            )

    st.warning(
        "This is a hackathon prototype, not a production security service. "
        "A low risk score or legitimate ML prediction cannot guarantee "
        "that a website is safe."
    )


# ---------------- FOOTER ----------------

st.markdown(
    """
    <div class="footer">
        LINKSHIELD AI &nbsp;•&nbsp; CYBERSECURITY HACKATHON PROTOTYPE
        <br><br>
        Analyze carefully. Verify independently. Protect every click.
    </div>
    """,
    unsafe_allow_html=True,
)
