
import re
import pandas as pd

from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# Small demonstration dataset.
# Replace with a real, labeled dataset before claiming
# real-world phishing detection performance.
TRAINING_DATA = [
    ("https://example.com", "legitimate"),
    ("https://www.wikipedia.org", "legitimate"),
    ("https://www.python.org", "legitimate"),
    ("https://www.microsoft.com", "legitimate"),
    ("https://www.apple.com", "legitimate"),
    ("https://github.com", "legitimate"),
    ("https://www.openai.com", "legitimate"),
    ("https://www.nasa.gov", "legitimate"),
    ("https://docs.python.org/3/", "legitimate"),
    ("https://www.bbc.com", "legitimate"),
    ("http://login-verify-account.example", "phishing"),
    ("http://secure-banking-update.example", "phishing"),
    ("http://paypal-login-confirm.example", "phishing"),
    ("http://account-password-reset.example", "phishing"),
    ("http://verify-payment-details.example", "phishing"),
    ("http://microsoft-security-alert.example", "phishing"),
    ("http://amazon-account-verify.example", "phishing"),
    ("http://banking-login-confirm.example", "phishing"),
    ("http://update-your-password.example", "phishing"),
    ("http://urgent-billing-alert.example", "phishing"),
]


def extract_features(url):
    """Extract simple text features from a URL."""
    parsed = urlparse(url.strip())
    hostname = parsed.hostname or ""

    return " ".join([
        url.lower(),
        hostname.lower(),
        f"length_{len(url)}",
        f"dots_{hostname.count('.')}",
        f"hyphens_{hostname.count('-')}",
        f"digits_{sum(c.isdigit() for c in hostname)}",
        f"https_{int(parsed.scheme.lower() == 'https')}",
        f"at_symbol_{int('@' in parsed.netloc)}",
    ])


def build_model():
    """Train a demonstration text-classification model."""
    data = pd.DataFrame(
        TRAINING_DATA,
        columns=["url", "label"]
    )

    X = data["url"].apply(extract_features)
    y = data["label"]

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 5),
                lowercase=True
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                random_state=42
            )
        )
    ])

    model.fit(X, y)
    return model


MODEL = build_model()


def predict_url(url):
    """Return a demonstration model prediction."""
    if not isinstance(url, str) or not url.strip():
        return {
            "prediction": "Invalid URL",
            "confidence": 0.0,
            "warning": "Please enter a URL."
        }

    url = url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        return {
            "prediction": "Invalid URL",
            "confidence": 0.0,
            "warning": "Enter a URL starting with http:// or https://."
        }

    features = extract_features(url)
    probabilities = MODEL.predict_proba([features])[0]
    classes = MODEL.classes_

    best_index = probabilities.argmax()
    prediction = classes[best_index]
    confidence = float(probabilities[best_index])

    return {
        "prediction": prediction,
        "confidence": round(confidence * 100, 2),
        "warning": (
            "Demonstration model only. Its confidence is not a "
            "verified probability of whether the URL is malicious."
        )
    }


if __name__ == "__main__":
    test_url = "https://example.com"
    print("Test URL:", test_url)
    print(predict_url(test_url))
