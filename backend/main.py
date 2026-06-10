from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import traceback
import os
import sys

# ─── AUTO TRAIN IF MODEL MISSING ────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, '..', 'model', 'phishing_detector.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, '..', 'model', 'feature_names.pkl')
DATASET_PATH = os.path.join(BASE_DIR, '..', 'dataset', 'Training Dataset.arff')

def train_model():
    print("Model not found. Training now...")
    import arff
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score

    with open(DATASET_PATH, 'r') as f:
        dataset = arff.load(f)

    df = pd.DataFrame(
        dataset['data'],
        columns=[attr[0] for attr in dataset['attributes']]
    )
    df = df.apply(pd.to_numeric)

    X = df.drop('Result', axis=1)
    y = df['Result']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    accuracy = accuracy_score(y_test, model.predict(X_test)) * 100
    print(f"Model trained. Accuracy: {accuracy:.2f}%")

    os.makedirs(os.path.join(BASE_DIR, '..', 'model'), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(X.columns.tolist(), FEATURES_PATH)
    print("Model saved.")
    return model, X.columns.tolist()

# Load or train model
if os.path.exists(MODEL_PATH) and os.path.exists(FEATURES_PATH):
    rf_model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    print("Model loaded from disk.")
else:
    rf_model, feature_names = train_model()

# ─── APP SETUP ──────────────────────────────────────────

from feature_extractor import extract_features

app = FastAPI(
    title="Phishing Detector API",
    description="Detects malicious and phishing URLs using Random Forest",
    version="1.0.0"
)

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
        features = extract_features(url)
        feature_vector = pd.DataFrame([features])[feature_names]
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