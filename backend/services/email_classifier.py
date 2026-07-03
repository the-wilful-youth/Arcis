import re
import os
import threading
import time
import dns.resolver
import joblib
import numpy as np
import onnxruntime as ort

# Resolve model paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "xgboost_model.onnx")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "vectorizer.pkl")

# Initialize models globally
session = None
vectorizer = None

if os.path.exists(MODEL_PATH):
    try:
        # Tuning SessionOptions for low latency single-row inference
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        session = ort.InferenceSession(MODEL_PATH, sess_options=opts)
    except Exception as e:
        print(f"Error loading ONNX model: {e}")

if os.path.exists(VECTORIZER_PATH):
    try:
        vectorizer = joblib.load(VECTORIZER_PATH)
    except Exception as e:
        print(f"Error loading vectorizer: {e}")

class EmailDomainCache:
    """Thread-safe TTL cache for domain lookup metrics."""
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.lock = threading.Lock()
        self.ttl = ttl_seconds
        
    def get(self, domain):
        with self.lock:
            if domain in self.cache:
                entry = self.cache[domain]
                if time.time() - entry["timestamp"] < self.ttl:
                    return entry["data"]
                else:
                    del self.cache[domain]
        return None
        
    def set(self, domain, data):
        with self.lock:
            self.cache[domain] = {
                "timestamp": time.time(),
                "data": data
            }

email_dns_cache = EmailDomainCache(ttl_seconds=3600)  # 1 hour cache

def verify_email_dns(domain: str) -> dict:
    """Perform DNS checks to verify sender domain safety configuration."""
    results = {
        "has_mx": False,
        "has_spf": False,
        "has_dmarc": False
    }
    if not domain:
        return results

    # 1. Check MX Records
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        results["has_mx"] = len(mx_answers) > 0
    except Exception:
        pass

    # 2. Check SPF Record (TXT record starting with v=spf1)
    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for txt in txt_answers:
            txt_str = txt.to_text().lower()
            if "v=spf1" in txt_str:
                results["has_spf"] = True
                break
    except Exception:
        pass

    # 3. Check DMARC Record (TXT record at _dmarc.<domain>)
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for txt in dmarc_answers:
            txt_str = txt.to_text().lower()
            if "v=dmarc1" in txt_str:
                results["has_dmarc"] = True
                break
    except Exception:
        pass

    return results

def predict_sender_email(
    email_address: str,
    subject: str = "",
    body: str = "",
    reply_to: str = "",
    spf: str = "none",
    dkim: str = "none",
    dmarc: str = "none"
) -> dict:
    """
    Checks email legitimacy using a combination of:
    1. Active domain DNS security configuration (MX, SPF, DMARC records).
    2. Handcrafted heuristics (urgency words, mismatch in domains, formatting).
    3. Machine Learning (XGBoost ONNX model trained on TF-IDF features).
    """
    email = str(email_address).strip()
    
    # 1. Basic formatting check
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return {
            "email": email,
            "is_phishing": True,
            "risk_score_pct": 100.0,
            "verdict": "Invalid email formatting",
            "details": {
                "is_free_provider": False,
                "reasons": ["The email address format is invalid."]
            },
            "dns_checks": {}
        }
        
    parts = email.split('@')
    local_part = parts[0]
    domain = parts[1].lower()

    # Free email provider list
    free_providers = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'mail.com', 'protonmail.com'}
    is_free_provider = domain in free_providers

    # 2. Run DNS verification metrics (with caching)
    cached_dns = email_dns_cache.get(domain)
    if cached_dns:
        dns_status = cached_dns
    else:
        dns_status = verify_email_dns(domain)
        email_dns_cache.set(domain, dns_status)

    # 3. Hand-crafted Heuristic Scoring & Boosts
    features = {}
    phishing_boost = 0.0
    reasons = []

    # Urgency words detection
    urgency_words = ['urgent', 'verify', 'confirm', 'click', 'immediately', 
                     'suspended', 'expired', 'update', 'action', 'required',
                     'act now', 'claim', 'congratulations', 'won', 'free']
    
    combined_text = (subject + " " + body).lower()
    urgency_count = sum(1 for word in urgency_words if word in combined_text)

    if urgency_count > 0:
        features['urgency_words'] = urgency_count
        phishing_boost += 0.1 * urgency_count
        reasons.append(f"Contains {urgency_count} urgency/phishing-related keywords.")

    # Sender vs Reply-To Mismatch
    sender_domain = domain
    reply_to_domain = reply_to.split('@')[1].lower() if (reply_to and '@' in reply_to) else ""

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        features['sender_reply_mismatch'] = True
        phishing_boost += 0.15
        reasons.append("Sender domain and Reply-To domain do not match.")

    # Email header failures
    auth_failures = 0
    if spf == "fail":
        auth_failures += 1
        features['spf_failed'] = True
        reasons.append("SPF verification failed.")
    if dkim == "fail":
        auth_failures += 1
        features['dkim_failed'] = True
        reasons.append("DKIM verification failed.")
    if dmarc == "fail":
        auth_failures += 1
        features['dmarc_failed'] = True
        reasons.append("DMARC verification failed.")
    
    if auth_failures > 0:
        phishing_boost += 0.2 * auth_failures

    # Suspicious patterns
    if body:
        caps_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
        if caps_ratio > 0.3:
            features['high_cap_ratio'] = True
            phishing_boost += 0.05
            reasons.append("High ratio of uppercase letters in body.")

    exclamation_count = combined_text.count('!')
    if exclamation_count > 5:
        features['excessive_exclamation'] = True
        phishing_boost += 0.05
        reasons.append("Excessive exclamation marks in text.")

    link_count = combined_text.count('https://') + combined_text.count('http://')
    if link_count > 3:
        features['multiple_links'] = True
        phishing_boost += 0.05
        reasons.append("Contains multiple HTTP/HTTPS links.")

    # Standard DNS-based checks fallback / helper
    if not is_free_provider:
        if not dns_status["has_mx"]:
            phishing_boost += 0.4
            reasons.append("Sender domain has no active MX mail server records.")
        if not dns_status["has_spf"] and spf == "none":
            phishing_boost += 0.15
            reasons.append("Sender domain lacks SPF authentication record.")
        if not dns_status["has_dmarc"] and dmarc == "none":
            phishing_boost += 0.15
            reasons.append("Sender domain lacks DMARC configuration policy.")
    else:
        # For free providers, check if local part contains brand names/suspicious keywords
        suspicious_words = ['secure', 'support', 'service', 'verify', 'update', 'login', 'admin', 'billing', 'paypal', 'bank']
        flagged_words = [w for w in suspicious_words if w in local_part.lower()]
        if flagged_words:
            phishing_boost += 0.35
            reasons.append(f"Free email local part contains suspicious keywords: {', '.join(w.upper() for w in flagged_words)}")

    # Limit boost influence
    phishing_boost = min(phishing_boost, 0.5)

    # 4. Machine Learning Inference (XGBoost ONNX)
    model_score = 0.0
    ml_used = False
    
    if session is not None and vectorizer is not None and (subject or body):
        try:
            email_text = subject + " " + body
            email_vector = vectorizer.transform([email_text])
            email_vector_dense = email_vector.toarray().astype(np.float32)
            
            # Run session
            input_name = session.get_inputs()[0].name
            raw_pred = session.run(None, {input_name: email_vector_dense})
            
            # Extract probability for phishing class
            model_score = float(raw_pred[1][0][1])
            ml_used = True
        except Exception as e:
            reasons.append(f"ML Classifier failed during inference: {e}")

    # 5. Blend Scores (70% model, 30% heuristics if ML used, otherwise heuristics * 100)
    if ml_used:
        final_score = 0.7 * model_score + 0.3 * phishing_boost
        final_score_pct = min(max(final_score * 100.0, 0.0), 100.0)
        reasons.insert(0, f"XGBoost ONNX Classifier calculated phishing probability: {model_score*100.0:.1f}%")
    else:
        # Fallback to heuristics only
        if not reasons:
            reasons.append("Email matches standard sender authentication patterns.")
        final_score_pct = min(max(phishing_boost * 200.0, 0.0), 100.0)  # Scale heuristic boost to 100 max
        if session is None or vectorizer is None:
            reasons.append("ML Classifier is currently unavailable because the companion vectorizer.pkl is missing. Falling back to DNS and heuristic checks.")

    is_phishing = final_score_pct >= 50.0

    return {
        "email": email,
        "is_phishing": is_phishing,
        "risk_score_pct": float(final_score_pct),
        "details": {
            "is_free_provider": is_free_provider,
            "reasons": reasons,
            "ml_classifier_used": ml_used
        },
        "dns_checks": dns_status
    }
