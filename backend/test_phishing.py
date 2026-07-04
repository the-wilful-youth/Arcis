import time
import sys
import os

# Add services folder to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.url_classifier import predict_url
from services.email_classifier import predict_sender_email

# Test cases
url_test_cases = [
    {"url": "https://www.google.com", "expected": False},
    {"url": "https://www.paypa1.com/login", "expected": True},
    {"url": "http://paypal.com.secure-update.com", "expected": True}
]

email_test_cases = [
    {"email": "billing@microsoft.com", "expected": False},
    {"email": "paypal-support@gmail.com", "expected": True}
]

print("="*60)
print("ARCIS MULTI-MODEL BACKEND RESTRICTURED UNIT TESTS")
print("="*60)

# 1. Test URL Model
print("\n[Testing URL Model]")
for case in url_test_cases:
    t0 = time.time()
    res = predict_url(case["url"])
    print(f"  URL: {case['url']} -> Risk: {res['risk_score_pct']}% | Phishing: {res['is_phishing']} (Expected: {case['expected']}) | Time: {time.time()-t0:.4f}s")

# 2. Test Email Model
print("\n[Testing Email Model]")
for case in email_test_cases:
    t0 = time.time()
    res = predict_sender_email(case["email"])
    print(f"  Email: {case['email']} -> Risk: {res['risk_score_pct']}% | Phishing: {res['is_phishing']} (Expected: {case['expected']}) | Time: {time.time()-t0:.4f}s")

print("="*60)
