# LinkShield AI

A Streamlit cybersecurity prototype that analyzes URL patterns, shows rule-based risk indicators, and displays an experimental machine-learning classification.

## Features
- Dark security-report dashboard
- Rule-based URL analysis and score
- Experimental ML prediction (not production-grade)
- Risk indicator explanations and safety guidance
- Scan history and CSV export
- Advanced options for DNS hostname resolution and report detail visibility
- Honest placeholders for integrations not yet implemented

## Run locally (Windows / VS Code)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Keep `url_analyzer.py` and `ml_detector.py` in the same folder as `app.py`.

## Limitations
This is a hackathon prototype, not a production security service. The ML model uses a small synthetic demonstration dataset. It does not provide verified threat intelligence, live website screenshots, regional probes, port scanning, or a guarantee that a URL is safe.
