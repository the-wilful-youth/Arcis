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

try:
    from services.url_classifier import predict_url
    from services.confidence_scorer import score_analysis_confidence
except ImportError:
    from url_classifier import predict_url
    from confidence_scorer import score_analysis_confidence

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
    3. Real-time embedded URL analysis.
    4. NLP/Heuristic risk categorization.
    5. Machine Learning (XGBoost ONNX model trained on TF-IDF features).
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

    # 3. Urgency / Heuristic Check
    urgency_words = ['urgent', 'verify', 'confirm', 'click', 'immediately', 
                     'suspended', 'expired', 'update', 'action', 'required',
                     'act now', 'claim', 'congratulations', 'won', 'free']
    
    combined_text = (subject + " " + body).lower()
    urgency_count = sum(1 for word in urgency_words if word in combined_text)
    reasons = []

    # 4. URL Analysis Extraction & Scoring
    urls = re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', body)
    # Deduplicate and limit to first 5 to prevent performance bottlenecks
    unique_urls = list(dict.fromkeys(urls))[:5]
    suspicious_urls = 0
    high_risk_urls = 0
    scanned_url_details = []

    for u in unique_urls:
        try:
            url_res = predict_url(u)
            url_score = url_res.get("risk_score_pct", 0)
            scanned_url_details.append(url_res)
            if url_score >= 70:
                high_risk_urls += 1
            elif url_score >= 30:
                suspicious_urls += 1
        except Exception as e:
            # Graceful degradation of individual URL checking
            pass

    url_analysis_data = {
        'summary': {
            'total_urls': len(unique_urls),
            'safe_urls': len(unique_urls) - (suspicious_urls + high_risk_urls),
            'suspicious_urls': suspicious_urls,
            'high_risk_urls': high_risk_urls
        }
    }

    if high_risk_urls > 0:
        reasons.append(f"Embedded URLs contain {high_risk_urls} high-risk/phishing links.")
    elif suspicious_urls > 0:
        reasons.append(f"Embedded URLs contain {suspicious_urls} suspicious/unverified links.")

    # 5. Machine Learning Inference (XGBoost ONNX)
    model_score = 0.0
    ml_used = False
    
    if session is not None and vectorizer is not None and (subject or body):
        try:
            email_text = subject + " " + body
            email_vector = vectorizer.transform([email_text])
            email_vector_dense = email_vector.toarray().astype(np.float32)
            
            input_name = session.get_inputs()[0].name
            raw_pred = session.run(None, {input_name: email_vector_dense})
            model_score = float(raw_pred[1][0][1])
            ml_used = True
        except Exception as e:
            reasons.append(f"ML Classifier failed during inference: {e}")

    ml_classifier_data = {
        'classification': 'phishing' if model_score >= 0.5 else 'legitimate',
        'confidence': model_score
    }

    # 6. NLP Heuristics / Request Analysis
    # A. Sensitive request detection
    sensitive_keywords = ['password', 'credential', 'login', 'bank', 'ssn', 'payment', 'card', 'transfer', 'social security', 'identity', 'verification']
    has_sensitive = any(w in combined_text for w in sensitive_keywords)
    sensitive_request_data = {
        'is_sensitive_request': has_sensitive,
        'risk_level': 'high' if (has_sensitive and (urgency_count > 0 or len(unique_urls) > 0)) else ('medium' if has_sensitive else 'none')
    }
    if sensitive_request_data['risk_level'] in ['high', 'medium']:
        reasons.append("Email contains requests for sensitive information (credentials, payment, or identity).")

    # B. Polite/Deceptive request detection (generic greetings combined with action request)
    polite_greetings = ['dear customer', 'valued customer', 'respected sir', 'respected madam', 'dear user', 'greetings']
    has_polite = any(w in combined_text for w in polite_greetings)
    polite_request_data = {
        'is_polite_request': has_polite,
        'risk_level': 'medium' if (has_polite and (urgency_count > 0 or len(unique_urls) > 0)) else ('low' if has_polite else 'none')
    }
    if polite_request_data['risk_level'] == 'medium':
        reasons.append("Use of generic formal greeting combined with a call to action.")

    # C. Short Email Risk
    short_email_risk_data = {
        'is_short': len(body) < 150,
        'risk_level': 'high' if (len(body) < 150 and (urgency_count > 0 or len(unique_urls) > 0)) else 'none'
    }
    if short_email_risk_data['risk_level'] == 'high':
        reasons.append("Short email containing high urgency markers or embedded links (common phishing template).")

    # Sender vs Reply-To Mismatch
    sender_domain = domain
    reply_to_domain = reply_to.split('@')[1].lower() if (reply_to and '@' in reply_to) else ""
    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        reasons.append("Sender domain and Reply-To domain do not match.")

    # DNS checks fallback reasons
    if not is_free_provider:
        if not dns_status["has_mx"]:
            reasons.append("Sender domain has no active MX mail server records.")
        if not dns_status["has_spf"] and spf == "none":
            reasons.append("Sender domain lacks SPF authentication record.")
        if not dns_status["has_dmarc"] and dmarc == "none":
            reasons.append("Sender domain lacks DMARC configuration policy.")
    else:
        # For free providers, check if local part contains brand names/suspicious keywords
        suspicious_words = ['secure', 'support', 'service', 'verify', 'update', 'login', 'admin', 'billing', 'paypal', 'bank']
        flagged_words = [w for w in suspicious_words if w in local_part.lower()]
        if flagged_words:
            reasons.append(f"Free email local part contains suspicious keywords: {', '.join(w.upper() for w in flagged_words)}")

    # Email header failures
    if spf == "fail":
        reasons.append("SPF verification failed.")
    if dkim == "fail":
        reasons.append("DKIM verification failed.")
    if dmarc == "fail":
        reasons.append("DMARC verification failed.")

    # 7. Aggregate Scores using mnc-grade ConfidenceScorer
    scoring_payload = {
        'ml_classifier': ml_classifier_data,
        'url_analysis': url_analysis_data,
        'sensitive_request': sensitive_request_data,
        'polite_request': polite_request_data,
        'short_email_risk': short_email_risk_data
    }

    score_result = score_analysis_confidence(scoring_payload)

    # 8. Calculate Sender Reputation/Authentication Threat Score
    sender_risk = 0.0
    if not is_free_provider:
        if not dns_status.get("has_mx", True):
            sender_risk = max(sender_risk, 0.8)
        if not dns_status.get("has_spf", True) and spf == "none":
            sender_risk = max(sender_risk, 0.4)
        if not dns_status.get("has_dmarc", True) and dmarc == "none":
            sender_risk = max(sender_risk, 0.4)
    else:
        # Check local part suspicious keywords
        suspicious_words = ['secure', 'support', 'service', 'verify', 'update', 'login', 'admin', 'billing', 'paypal', 'bank']
        flagged_words = [w for w in suspicious_words if w in local_part.lower()]
        if flagged_words:
            sender_risk = max(sender_risk, 0.7)

    # Header authentication status
    auth_fails = sum(1 for status_val in [spf, dkim, dmarc] if status_val == "fail")
    if auth_fails > 0:
        sender_risk = max(sender_risk, 0.3 * auth_fails)
        
    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        sender_risk = max(sender_risk, 0.5)

    # Blend overall confidence with sender/header-level risk
    final_score = max(score_result.overall_confidence, sender_risk)
    final_score_pct = round(final_score * 100, 2)
    is_phishing = final_score_pct >= 50.0
    
    # Prepend classifier info
    if ml_used:
        reasons.insert(0, f"XGBoost ONNX Classifier calculated phishing probability: {model_score*100.0:.1f}%")
    else:
        if session is None or vectorizer is None:
            reasons.append("ML Classifier is currently unavailable. Falling back to heuristics and link verification.")

    if not reasons:
        reasons.append("Email matches standard sender authentication patterns and contains no suspicious signals.")

    return {
        "email": email,
        "is_phishing": is_phishing,
        "risk_score_pct": final_score_pct,
        "details": {
            "is_free_provider": is_free_provider,
            "reasons": reasons,
            "ml_classifier_used": ml_used,
            "component_scores": score_result.component_scores,
            "reasoning": score_result.reasoning,
            "scanned_urls": scanned_url_details
        },
        "dns_checks": dns_status
    }


