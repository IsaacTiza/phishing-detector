from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import traceback
import os

from feature_extractor import extract_features

# ─── LOAD MODEL ─────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, '..', 'model', 'phishing_detector.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, '..', 'model', 'feature_names.pkl')

rf_model = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)

# ─── APP SETUP ──────────────────────────────────────────

app = FastAPI(
    title="Phishing Detector API",
    description="Detects malicious and phishing URLs using Random Forest",
    version="1.0.0"
)

# Allow browser extension to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── REQUEST MODEL ──────────────────────────────────────

class URLRequest(BaseModel):
    url: str

# ─── ROUTES ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "Phishing Detector API is running"}


@app.post("/check-url")
def check_url(request: URLRequest):
    url = request.url.strip()

    if not url.startswith("http"):
        url = "http://" + url

    try:
        # Extract features from the URL
        features = extract_features(url)

        # Build feature vector in correct order
        feature_vector = pd.DataFrame([features])[feature_names]

        # Predict
        prediction = rf_model.predict(feature_vector)[0]
        probability = rf_model.predict_proba(feature_vector)[0]

        phishing_prob = round(float(probability[0]) * 100, 2)
        legitimate_prob = round(float(probability[1]) * 100, 2)
        confidence = round(float(max(probability)) * 100, 2)

        verdict = "LEGITIMATE" if prediction == 1 else "PHISHING"

        return {
            "url": url,
            "verdict": verdict,
            "confidence": confidence,
            "phishing_probability": phishing_prob,
            "legitimate_probability": legitimate_prob,
            "features": features
        }

    except Exception as e:
        return {
            "url": url,
            "verdict": "ERROR",
            "error": str(e),
            "trace": traceback.format_exc()
        }


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": rf_model is not None}