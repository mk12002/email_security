import sys
import joblib
from email_security.preprocessing.feature_pipeline import URL_FEATURE_COLUMNS, extract_url_lexical_features, normalize_url
import pandas as pd

bundle = joblib.load("../models/url_agent/model.joblib")
model = bundle["model"]

urls = [
    "https://google.com",
    "https://amazon.com",
    "http://amazon.com",
    "http://wikipedia.org",
    "http://w88.club/",
    "http://layarindo21.com/",
    "http://johnfuauto.com/",
    "https://trb.org/login",
]

for raw_url in urls:
    norm = normalize_url(raw_url)
    feat = extract_url_lexical_features(norm)
    df = pd.DataFrame([feat])[URL_FEATURE_COLUMNS]
    proba = model.predict_proba(df)[0,1]
    print(f"{raw_url:<40} -> {proba:.4f}")
