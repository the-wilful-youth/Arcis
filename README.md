# Arcis — SaaS Phishing Detection Suite

Arcis is a real-time, explainable threat intelligence, URL verification, and email classification suite. Powered by a custom-tuned **LightGBM Classifier** (for URLs) and an **XGBoost ONNX Classifier** (for emails), Arcis translates complex network and lexical telemetry into human-readable risk assessments.

The suite comprises a rate-limited Flask REST API node, a premium glassmorphic web dashboard, and a Manifest V3 Google Chrome extension.

---

## 🚀 Key Features

*   **Dual-Model Intelligence**: Features dedicated ML classifiers for URL and Email risk assessment.
*   **Lexical Telemetry Extraction**: Analyzes character distributions, suspicious keywords, folder depth, query parameters, and domain structure.
*   **Live DNS & Reputation Verification**: Resolves active IPv4 addresses, Nameservers, and MX mail servers with real-time response latency checks.
*   **Autonomous IP-to-ASN Translation**: Executes local DNS TXT lookups against the Cymru DNS network to resolve Autonomous System Numbers (ASN) with zero HTTP API overhead.
*   **WHOIS Registry Verifier**: Parses creation times and days remaining until expiration to detect newly registered domains typical of phishing campaigns.
*   **Explainable ML Verdicts**: Employs directional feature analysis to pinpoint precisely which features influenced a domain's threat classification.

---

## 📁 Repository Structure

The codebase is structured cleanly into logical backend, frontend, and extension components:

```
Arcis/
├── backend/
│   ├── app.py                      # Flask REST API server (Rate-limited, CORS-enabled)
│   ├── models/
│   │   ├── url_phishing_bundle.joblib # LightGBM classifier binary (URLs)
│   │   └── xgboost_model.onnx         # XGBoost classifier binary (Emails)
│   ├── services/
│   │   ├── url_classifier.py       # Feature extraction & classification service (URLs)
│   │   └── email_classifier.py     # Feature extraction & classification service (Emails)
│   └── test_phishing.py            # Local backend verification test suite
├── frontend/
│   ├── index.html                  # Premium glassmorphic dashboard UI
│   ├── style.css                   # Dynamic stylesheet with floating background glows
│   └── app.js                      # Integration script & history state management
├── extension/                      # Manifest V3 Google Chrome Extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   └── background.js
├── requirements.txt                # Python backend dependencies
└── README.md
```

---

## 🛠️ Installation & Setup

### 1. Initialize the Environment & Install Dependencies

Run the following commands from your project root:

```bash
# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`

# Install required packages
pip install -r requirements.txt
```

### 2. Run the Backend API Server

Start the API server on its default port (`5001`):

```bash
# Activate virtual environment if not already active
source .venv/bin/activate

# Start the Flask API
python backend/app.py
```

*For production workloads, consider using **Gunicorn** to handle concurrent operations:*
```bash
gunicorn -w 4 -b 0.0.0.0:5001 --chdir backend app:app
```

### 3. Running Backend Tests

Verify that feature extraction and classification pipelines are working:

```bash
.venv/bin/python backend/test_phishing.py
```

### 4. Launch the Web Application

Simply open the [index.html](file:///Users/Anurag/Anurag/Projects/Arcis/frontend/index.html) file located in the `frontend/` directory directly in any modern browser.

### 5. Install the Chrome Extension

1. Navigate to `chrome://extensions/` in your Chrome browser.
2. Enable **Developer mode** using the toggle in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the `extension/` directory of this project.
5. Pin the **Arcis Phishing Detector** extension, and analyze active tabs on demand.

---

## 🔌 API Specification

### 1. Analyze URL
* **Endpoint**: `/api/analyze/url`
* **Method**: `POST`
* **Content-Type**: `application/json`
* **Payload**:
  ```json
  { "url": "https://example.com" }
  ```
* **Response**:
  ```json
  {
    "url": "https://example.com",
    "is_phishing": false,
    "risk_score_pct": 0.98,
    "brand_alert": {
      "brand": null,
      "impersonated": false
    },
    "features": {
      "directory_length": 1,
      "domain_length": 11,
      "qty_slash_url": 3
    },
    "top_features": [
      {
        "direction": "decreases",
        "feature": "time_domain_activation",
        "impact": -0.15,
        "value": 1024
      }
    ]
  }
  ```

### 2. Analyze Email Sender
* **Endpoint**: `/api/analyze/email`
* **Method**: `POST`
* **Content-Type**: `application/json`
* **Payload**:
  ```json
  {
    "email": "paypal-support@gmail.com",
    "subject": "Urgent Action Required",
    "body": "Please click here to verify your details.",
    "reply_to": "attacker@evil.com",
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  }
  ```
* **Response**:
  ```json
  {
    "email": "paypal-support@gmail.com",
    "is_phishing": true,
    "risk_score_pct": 70.0,
    "details": {
      "is_free_provider": true,
      "ml_classifier_used": false,
      "reasons": [
        "Contains 2 urgency/phishing-related keywords.",
        "Sender domain and Reply-To domain do not match.",
        "SPF verification failed."
      ]
    },
    "dns_checks": {
      "has_mx": true,
      "has_spf": true,
      "has_dmarc": true
    }
  }
  ```
