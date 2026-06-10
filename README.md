# Phishing Detector — Random Forest Based Malicious URL & Website Detection System

## Project Overview
A browser extension that detects malicious and phishing websites in real time
using a Random Forest machine learning algorithm. The system analyzes 30 features
extracted from the URL structure, webpage content, and domain information to
classify websites as Legitimate or Phishing.

---

## System Architecture
Browser Extension (Chrome)
↕ HTTP REST API
FastAPI Backend (Python)
↕
Feature Extraction Pipeline
↕
Random Forest Model (scikit-learn)

---

## Features Analyzed (30 Total)

### Address Bar Based (12)
- IP address usage, URL length, URL shortening services
- @ symbol, double slash redirecting, prefix/suffix with dash
- Subdomains, SSL state, domain registration length
- Favicon source, port, HTTPS token in domain

### Content Based (6)
- Request URL, anchor URL, links in meta/script/link tags
- Server form handler, email submission, abnormal URL

### HTML & JavaScript Based (5)
- Page redirects, mouseover events, right-click disabling
- Popup windows, iframe usage

### Domain Based (7)
- Domain age, DNS record, web traffic
- PageRank, Google index, links pointing to page
- Statistical reports (PhishTank)

---

## Model Performance

| Metric | Score |
|---|---|
| Accuracy | 97.42% |
| Phishing Precision | 98% |
| Phishing Recall | 96% |
| F1 Score | 97% |

- Dataset: UCI Phishing Websites Dataset (11,055 samples)
- Algorithm: Random Forest (100 estimators)
- Train/Test Split: 80/20

---

## Tech Stack

| Layer | Technology |
|---|---|
| Browser Extension | JavaScript, Chrome Manifest V3 |
| Backend API | Python, FastAPI |
| Web Crawling | requests, BeautifulSoup4 |
| Machine Learning | scikit-learn, Random Forest |
| Domain Analysis | python-whois, dnspython |
| Data Processing | pandas, numpy |

---

## Project Structure
phishing-detector/
├── dataset/
│   └── Training Dataset.arff
├── model/
│   ├── phishing_detector.pkl
│   └── feature_names.pkl
├── backend/
│   ├── main.py
│   └── feature_extractor.py
├── extension/
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── styles.css
│   ├── background.js
│   ├── content.js
│   └── icons/
├── notebooks/
│   └── 01_data_exploration.ipynb
└── README.md

---

## How to Run

### 1. Install dependencies
```bash
pip install fastapi uvicorn scikit-learn pandas numpy requests
pip install beautifulsoup4 python-whois dnspython joblib matplotlib
```

### 2. Start the backend
```bash
cd backend
uvicorn main:app --reload --port 8000
```

### 3. Load the extension
- Open Chrome → `chrome://extensions`
- Enable Developer Mode
- Click "Load unpacked"
- Select the `extension/` folder

### 4. Use it
- Navigate to any website
- Click the Phishing Detector extension icon
- View the real-time verdict and confidence score

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | / | API status |
| POST | /check-url | Analyze a URL |
| GET | /health | Health check |

### Example Request
```json
POST /check-url
{
  "url": "https://www.example.com"
}
```

### Example Response
```json
{
  "url": "https://www.example.com",
  "verdict": "LEGITIMATE",
  "confidence": 76.0,
  "phishing_probability": 24.0,
  "legitimate_probability": 76.0,
  "features": { ... }
}
```

---

## Known Limitations
- Backend must be running locally for the extension to work
- Web traffic feature uses approximation (Alexa API deprecated)
- PageRank feature uses neutral value (API deprecated)
- WHOIS lookups may timeout on some domains

---

## References
- Mohammad, R., Thabtah, F., McCluskey, L. (2014). Predicting Phishing Websites
  Based on Self-Structuring Neural Network. Neural Computing and Applications.
- UCI ML Repository: Phishing Websites Dataset
- PhishTank: https://www.phishtank.com