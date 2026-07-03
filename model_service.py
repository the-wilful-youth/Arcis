import os
import re
import socket
import time
from datetime import datetime
from urllib.parse import urlparse
import joblib
import pandas as pd
import numpy as np
import dns.resolver
import tldextract
import whois

# Load the model bundle
BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "phishing_model_bundle.joblib")
if not os.path.exists(BUNDLE_PATH):
    raise FileNotFoundError(f"Model bundle not found at {BUNDLE_PATH}")

bundle = joblib.load(BUNDLE_PATH)
model = bundle["model"]
scaler = bundle["scaler"]
features_list = bundle["feature_names"]

SUSPICIOUS_CHARS = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
CHAR_NAMES = ['dot','hyphen','underline','slash','questionmark','equal','at','and',
              'exclamation','space','tilde','comma','plus','asterisk','hashtag','dollar','percent']

def get_asn(ip):
    """Retrieve ASN using Cymru DNS TXT record lookup."""
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            reversed_ip = '.'.join(reversed(parts))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            answers = dns.resolver.resolve(query, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                asn_str = txt.split('|')[0].strip()
                if asn_str.isdigit():
                    return int(asn_str)
    except Exception:
        pass
    return -1

def extract_features(raw_url: str) -> dict:
    """Extract 60 features from a raw URL matching the dataset columns."""
    url = str(raw_url).strip()
    
    # 1. Ensure scheme is present
    if not re.match(r'^[a-zA-Z]+://', url):
        url_full = 'http://' + url
    else:
        url_full = url

    parsed = urlparse(url_full)
    ext = tldextract.extract(url_full)
    domain = ext.domain + ('.' + ext.suffix if ext.suffix else '')
    
    # 2. Parse Path, Directory, File, Query Params
    path = parsed.path
    query = parsed.query
    
    # Directory & File logic
    if not path or path == '/':
        directory = None
        file_part = None
    else:
        if path.endswith('/'):
            directory = path
            file_part = None
        else:
            if '/' in path:
                last_slash = path.rfind('/')
                directory = path[:last_slash+1]
                file_part = path[last_slash+1:]
            else:
                directory = "/"
                file_part = path

    feats = {}
    
    # URL level features
    feats["length_url"] = len(url)
    feats["qty_dot_url"] = url.count('.')
    feats["qty_slash_url"] = url.count('/')
    feats["qty_hyphen_url"] = url.count('-')

    # Domain features
    feats["domain_length"] = len(domain)
    feats["qty_dot_domain"] = domain.count('.')
    feats["qty_vowels_domain"] = sum(domain.lower().count(v) for v in "aeiou")
    
    # Directory features
    if directory is not None:
        feats["directory_length"] = len(directory)
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_directory"] = directory.count(ch)
    else:
        feats["directory_length"] = -1
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_directory"] = -1

    # File features
    if file_part is not None:
        feats["file_length"] = len(file_part)
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_file"] = file_part.count(ch)
    else:
        feats["file_length"] = -1
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_file"] = -1

    # Parameter features
    if query:
        feats["qty_params"] = len(query.split('&'))
        feats["params_length"] = len(query)
        # Check if TLD is present in params
        tld_found = 0
        for p in query.split('&'):
            if '=' in p:
                _, val = p.split('=', 1)
                val_ext = tldextract.extract(val)
                if val_ext.suffix:
                    tld_found = 1
                    break
        feats["tld_present_params"] = tld_found
        
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_params"] = query.count(ch)
    else:
        feats["qty_params"] = -1
        feats["params_length"] = -1
        feats["tld_present_params"] = -1
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_params"] = -1

    # 3. Resolve DNS & Network features
    resolved_ip = None
    qty_ip_resolved = -1
    ttl_hostname = -1
    qty_nameservers = -1
    qty_mx_servers = -1
    time_response = -1.0
    
    hostname = parsed.hostname
    if hostname:
        # Measure response time
        t0 = time.time()
        try:
            # Quick ping/HEAD connection test
            s = socket.create_connection((hostname, 80), timeout=1.5)
            time_response = time.time() - t0
            s.close()
        except Exception:
            pass

        # DNS lookups
        try:
            answers = dns.resolver.resolve(hostname, 'A')
            ips = [ip.address for ip in answers]
            qty_ip_resolved = len(ips)
            ttl_hostname = answers.rrset.ttl
            if ips:
                resolved_ip = ips[0]
        except Exception:
            pass

        try:
            ext_ns = dns.resolver.resolve(hostname, 'NS')
            qty_nameservers = len(ext_ns)
        except Exception:
            try:
                # Try parent domain if sub-domain NS query fails
                parent_domain = ext.registered_domain
                if parent_domain and parent_domain != hostname:
                    ext_ns = dns.resolver.resolve(parent_domain, 'NS')
                    qty_nameservers = len(ext_ns)
            except Exception:
                qty_nameservers = -1

        try:
            ext_mx = dns.resolver.resolve(hostname, 'MX')
            qty_mx_servers = len(ext_mx)
        except Exception:
            try:
                parent_domain = ext.registered_domain
                if parent_domain and parent_domain != hostname:
                    ext_mx = dns.resolver.resolve(parent_domain, 'MX')
                    qty_mx_servers = len(ext_mx)
            except Exception:
                qty_mx_servers = -1

    feats["qty_ip_resolved"] = qty_ip_resolved
    feats["ttl_hostname"] = ttl_hostname
    feats["qty_nameservers"] = qty_nameservers
    feats["qty_mx_servers"] = qty_mx_servers
    feats["time_response"] = time_response
    feats["asn_ip"] = get_asn(resolved_ip) if resolved_ip else -1

    # WHOIS features
    time_domain_activation = -1
    time_domain_expiration = -1
    if hostname:
        try:
            # Perform WHOIS lookup (with 3-second timeout)
            # Use registered_domain to avoid subdomain failures
            registered = ext.registered_domain
            if registered:
                w = whois.whois(registered)
                c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                e_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                
                # Make timezone naive
                now = datetime.utcnow()
                if c_date:
                    c_naive = c_date.replace(tzinfo=None)
                    time_domain_activation = (now - c_naive).days
                if e_date:
                    e_naive = e_date.replace(tzinfo=None)
                    time_domain_expiration = (e_naive - now).days
        except Exception:
            pass

    feats["time_domain_activation"] = time_domain_activation
    feats["time_domain_expiration"] = time_domain_expiration

    # Fill any remaining missing selected features
    for f in features_list:
        if f not in feats:
            feats[f] = 0

    return feats

def predict_url(url: str) -> dict:
    """Predict if a URL is phishing and return risk metrics and feature importances."""
    # 1. Feature extraction
    feats = extract_features(url)
    
    # 2. Format as a single row DataFrame matching training columns exactly
    df_row = pd.Series(feats).reindex(features_list).fillna(0)
    
    # 3. Standardize features
    scaled_df = pd.DataFrame([df_row], columns=features_list)
    scaled = scaler.transform(scaled_df)
    
    # 4. Predict probability
    prob = model.predict_proba(scaled_df)[0, 1]
    is_phishing = bool(prob >= 0.5)
    
    # 5. Local explainability: Identify key contributors
    importances = model.feature_importances_
    contributions = scaled[0] * importances
    
    indices = np.argsort(np.abs(contributions))[::-1]
    
    reasons = []
    for idx in indices[:5]:
        feat_name = features_list[idx]
        val = df_row[feat_name]
        contrib = contributions[idx]
        direction = "increases" if contrib > 0 else "decreases"
        reasons.append({
            "feature": feat_name,
            "value": val,
            "impact": float(contrib),
            "direction": direction
        })
        
    return {
        "url": url,
        "is_phishing": is_phishing,
        "risk_score_pct": round(prob * 100, 2),
        "features": {k: float(v) for k, v in feats.items() if k in features_list},
        "top_features": reasons
    }

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-login-secure-verification.support-login.com/webscr?cmd=_login-run"
    ]
    for tu in test_urls:
        print(f"\nAnalyzing: {tu}")
        res = predict_url(tu)
        print("Result:", res["is_phishing"], "| Risk:", res["risk_score_pct"], "%")
        print("Top indicators:")
        for r in res["top_features"]:
            print(f"  - {r['feature']} = {r['value']} ({r['direction']} risk)")
