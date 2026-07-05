import os
import re
import socket
import time
import threading
from datetime import datetime
from urllib.parse import urlparse
import joblib
import pandas as pd
import numpy as np
import dns.resolver
import tldextract
import whois
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import ipaddress

def is_private_ip(ip_str):
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return False

# Load the model bundle
BUNDLE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "url_phishing_bundle.joblib")
if not os.path.exists(BUNDLE_PATH):
    raise FileNotFoundError(f"Model bundle not found at {BUNDLE_PATH}")

bundle = joblib.load(BUNDLE_PATH)
model = bundle["model"]
scaler = bundle["scaler"]
features_list = bundle["feature_names"]

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = 1.0
dns_resolver.lifetime = 1.5

SUSPICIOUS_CHARS = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
CHAR_NAMES = ['dot','hyphen','underline','slash','questionmark','equal','at','and',
              'exclamation','space','tilde','comma','plus','asterisk','hashtag','dollar','percent']

# --- Levenshtein Distance for Typosquatting Check ---
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        try:
            from urllib.parse import urlparse
            import socket
            parsed = urlparse(newurl)
            if parsed.scheme not in ('http', 'https'):
                raise urllib.error.HTTPError(newurl, 400, "SSRF: Blocked unsafe scheme", hdrs, fp)
            hostname = parsed.hostname
            if hostname:
                ips = socket.getaddrinfo(hostname, None)
                for item in ips:
                    ip = item[4][0]
                    if is_private_ip(ip):
                        raise urllib.error.HTTPError(newurl, 400, f"SSRF: Blocked redirection to private IP {ip}", hdrs, fp)
        except Exception as e:
            # Block redirection
            raise urllib.error.HTTPError(newurl, 400, f"SSRF: Redirect validation failed: {str(e)}", hdrs, fp)
        
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)

def resolve_redirects(url: str, timeout=1.0) -> str:
    """Resolve redirecting/shortened URLs to their final destination URL securely, blocking SSRF."""
    if not url:
        return url
    url_to_check = url.strip()
    if not re.match(r'^[a-zA-Z]+://', url_to_check):
        url_to_check = 'http://' + url_to_check
    
    # Restrict scheme to http/https to prevent local file disclosure (SSRF)
    try:
        from urllib.parse import urlparse
        import socket
        parsed = urlparse(url_to_check)
        if parsed.scheme not in ('http', 'https'):
            return url
            
        # Prevent SSRF on initial request before fetch
        hostname = parsed.hostname
        if hostname:
            ips = socket.getaddrinfo(hostname, None)
            for item in ips:
                ip = item[4][0]
                if is_private_ip(ip):
                    return url
    except Exception:
        return url

    try:
        # Use a secure opener that intercepts redirect responses
        opener = urllib.request.build_opener(SafeRedirectHandler())
        req = urllib.request.Request(
            url_to_check,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ArcisLinkChecker/1.0'}
        )
        with opener.open(req, timeout=timeout) as response:
            return response.geturl()
    except Exception:
        return url

def check_brand_impersonation(hostname: str, domain: str, registered_domain: str) -> dict:
    """Check if the domain is impersonating trusted brand names (typosquatting or keyword hijacking)."""
    if domain and domain.startswith("xn--"):
        return {"impersonated": True, "brand": "Punycode (IDN)", "type": "IDN Homograph Attack"}

    if not registered_domain:
        return {"impersonated": False, "brand": None}
        
    brand_domains = {
        'paypal': 'paypal.com', 'google': 'google.com', 'github': 'github.com',
        'microsoft': 'microsoft.com', 'netflix': 'netflix.com', 'amazon': 'amazon.com',
        'apple': 'apple.com', 'facebook': 'facebook.com', 'instagram': 'instagram.com',
        'twitter': 'twitter.com', 'linkedin': 'linkedin.com', 'yahoo': 'yahoo.com',
        'dropbox': 'dropbox.com', 'adobe': 'adobe.com', 'zoom': 'zoom.us',
        'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com', 'bankofamerica': 'bankofamerica.com',
        'citi': 'citi.com', 'capitalone': 'capitalone.com', 'americanexpress': 'americanexpress.com',
        'binance': 'binance.com', 'coinbase': 'coinbase.com', 'kraken': 'kraken.com',
        'steam': 'steampowered.com', 'discord': 'discord.com', 'epicgames': 'epicgames.com',
        'dhl': 'dhl.com', 'fedex': 'fedex.com', 'usps': 'usps.com', 'ups': 'ups.com',
        'salesforce': 'salesforce.com', 'slack': 'slack.com', 'okta': 'okta.com',
        'office365': 'office.com', 'outlook': 'outlook.com', 'onedrive': 'onedrive.live.com',
        'whatsapp': 'whatsapp.com', 'telegram': 'telegram.org', 'snapchat': 'snapchat.com',
        'tiktok': 'tiktok.com', 'roblox': 'roblox.com', 'spotify': 'spotify.com',
        'icloud': 'icloud.com', 'xfinity': 'xfinity.com', 'att': 'att.com', 'verizon': 'verizon.com',
        'paytm': 'paytm.com', 'flipkart': 'flipkart.com', 'deutschebank': 'db.com',
        'hdfc': 'hdfcbank.com', 'sbi': 'sbi.co.in', 'icici': 'icicibank.com',
        'grab': 'grab.com', 'lazada': 'lazada.com', 'mercadolibre': 'mercadolibre.com'
    }
    
    reg_parts = registered_domain.split('.')
    reg_name = reg_parts[0] if reg_parts else ""
    hostname_lower = (hostname or domain or "").lower()
    
    ext = tldextract.extract(hostname_lower)
    
    # 1. Exact Match to official domain or subdomain of it
    for brand, official in brand_domains.items():
        if hostname_lower == official or hostname_lower.endswith('.' + official):
            return {"impersonated": False, "brand": brand, "official": True}
            
        # Check for regional variants (e.g. google.co.in, amazon.in)
        # only if the official domain is a standard domain (has no subdomains)
        off_ext = tldextract.extract(official)
        if not off_ext.subdomain:
            if ext.domain.lower() == off_ext.domain.lower():
                safe_suffixes = {
                    'com', 'co', 'in', 'co.in', 'co.uk', 'org', 'net', 'de', 'fr', 'co.jp', 
                    'jp', 'ca', 'com.br', 'br', 'com.mx', 'mx', 'com.au', 'au', 'ru', 'nl', 
                    'se', 'pl', 'ch', 'at', 'be', 'co.za', 'za', 'sg', 'com.sg', 'it', 'es', 
                    'ie', 'co.nz', 'nz', 'hk', 'com.hk', 'tw', 'com.tw', 'kr', 'co.kr',
                    'us', 'me', 'tv', 'cc', 'info', 'biz', 'asia', 'eu'
                }
                if ext.suffix.lower() in safe_suffixes:
                    return {"impersonated": False, "brand": brand, "official": True}

    # 1b. Check for short domain aliases (e.g. amzn.to, amzn.in, msft.it)
    brand_short_domains = {
        'amazon': {'amzn.to', 'amzn.in', 'amzn.eu', 'amzn.com', 'amzn.co.uk', 'amzn.de', 'amzn.fr', 'amzn.jp', 'amzn.ca'},
        'microsoft': {'msft.it', 'msft.net', 'msft.education'},
        'google': {'g.co', 'goo.gl', 'youtu.be'},
        'facebook': {'fb.me', 'fb.com'},
        'twitter': {'t.co'},
        'linkedin': {'lnk.in', 'lnkd.in'}
    }
    for brand, short_set in brand_short_domains.items():
        if registered_domain.lower() in short_set or hostname_lower in short_set:
            return {"impersonated": False, "brand": brand, "official": True}
        
        # Support dynamic suffixes for known abbreviations
        if brand == 'amazon' and ext.domain.lower() == 'amzn':
            safe_suffixes = {'to', 'in', 'com', 'eu', 'co.uk', 'de', 'fr', 'jp', 'ca'}
            if ext.suffix.lower() in safe_suffixes:
                return {"impersonated": False, "brand": "amazon", "official": True}
        elif brand == 'microsoft' and ext.domain.lower() == 'msft':
            safe_suffixes = {'it', 'net', 'com', 'co.uk', 'de', 'fr', 'jp', 'ca'}
            if ext.suffix.lower() in safe_suffixes:
                return {"impersonated": False, "brand": "microsoft", "official": True}

    # 2. Contains brand name but is not official/legitimate regional
    for brand, official in brand_domains.items():
        if brand in hostname_lower:
            return {"impersonated": True, "brand": brand, "type": "Keyword Impersonation"}
            
    # 3. Typosquatting / edit distance (dist is 1 or 2)
    for brand, official in brand_domains.items():
        if len(reg_name) < 4:
            continue
        # Pre-filter: if length difference is greater than 2, Levenshtein distance cannot be <= 2.
        if abs(len(reg_name) - len(brand)) > 2:
            continue
        dist = levenshtein_distance(reg_name.lower(), brand)
        if 0 < dist <= 2:
            return {"impersonated": True, "brand": brand, "type": "Typosquatting / Fake Domain"}
            
    return {"impersonated": False, "brand": None}

# --- Cache Implementation ---
class DomainResolverCache:
    """Thread-safe LRU/FIFO TTL cache for domain lookup metrics."""
    def __init__(self, ttl_seconds=3600, max_size=10000):
        self.cache = {}
        self.lock = threading.Lock()
        self.ttl = ttl_seconds
        self.max_size = max_size
        
    def get(self, domain):
        with self.lock:
            if domain in self.cache:
                entry = self.cache[domain]
                if time.time() - entry["timestamp"] < self.ttl:
                    # Move to end (LRU behavior)
                    self.cache[domain] = self.cache.pop(domain)
                    return entry["data"]
                else:
                    del self.cache[domain]
        return None
        
    def set(self, domain, data):
        with self.lock:
            if domain in self.cache:
                del self.cache[domain]
            elif len(self.cache) >= self.max_size:
                oldest = next(iter(self.cache))
                del self.cache[oldest]
            self.cache[domain] = {
                "timestamp": time.time(),
                "data": data
            }

domain_cache = DomainResolverCache(ttl_seconds=3600, max_size=10000)  # 1 hour cache, max 10k entries

def get_asn(ip):
    """Retrieve ASN using Cymru DNS TXT record lookup."""
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            reversed_ip = '.'.join(reversed(parts))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            answers = dns_resolver.resolve(query, 'TXT')
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                asn_str = txt.split('|')[0].strip()
                if asn_str.isdigit():
                    return int(asn_str)
    except Exception:
        pass
    return -1



# --- Concurrent Lookups ---
def lookup_response_time(hostname, resolved_ip=None):
    if resolved_ip and is_private_ip(resolved_ip):
        return -1.0
    t0 = time.time()
    try:
        s = socket.create_connection((resolved_ip or hostname, 80), timeout=1.0)
        res_time = time.time() - t0
        s.close()
        return res_time
    except Exception:
        return -1.0

def lookup_dns_a(hostname):
    try:
        answers = dns_resolver.resolve(hostname, 'A')
        ips = [ip.address for ip in answers]
        resolved_ip = ips[0] if ips else None
        asn = get_asn(resolved_ip) if resolved_ip else -1
        return {
            "resolved_ip": resolved_ip,
            "qty_ip_resolved": len(ips),
            "ttl_hostname": answers.rrset.ttl if answers.rrset else -1,
            "asn_ip": asn
        }
    except Exception:
        return {"resolved_ip": None, "qty_ip_resolved": -1, "ttl_hostname": -1, "asn_ip": -1}

def lookup_dns_ns(hostname, registered_domain):
    try:
        ext_ns = dns_resolver.resolve(hostname, 'NS')
        return len(ext_ns)
    except Exception:
        try:
            if registered_domain and registered_domain != hostname:
                ext_ns = dns_resolver.resolve(registered_domain, 'NS')
                return len(ext_ns)
        except Exception:
            pass
    return -1

def lookup_dns_mx(hostname, registered_domain):
    try:
        ext_mx = dns_resolver.resolve(hostname, 'MX')
        return len(ext_mx)
    except Exception:
        try:
            if registered_domain and registered_domain != hostname:
                ext_mx = dns_resolver.resolve(registered_domain, 'MX')
                return len(ext_mx)
        except Exception:
            pass
    return -1

def lookup_whois(registered_domain):
    time_domain_activation = -1
    time_domain_expiration = -1
    if registered_domain:
        try:
            w = whois.whois(registered_domain)
            c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            e_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            
            now = datetime.utcnow()
            if c_date:
                c_naive = c_date.replace(tzinfo=None)
                time_domain_activation = (now - c_naive).days
            if e_date:
                e_naive = e_date.replace(tzinfo=None)
                time_domain_expiration = (e_naive - now).days
        except Exception:
            pass
    return time_domain_activation, time_domain_expiration

# Create global thread pools to avoid thread creation overhead and isolate fast/slow lookups
dns_executor = ThreadPoolExecutor(max_workers=8)
whois_executor = ThreadPoolExecutor(max_workers=4)

def resolve_domain_metrics(hostname, registered_domain):
    results = {}
    
    # Resolve DNS A first (has short timeout) to supply IP to response_time
    a_res = lookup_dns_a(hostname)
    resolved_ip = a_res["resolved_ip"]
    
    future_time = dns_executor.submit(lookup_response_time, hostname, resolved_ip)
    future_ns = dns_executor.submit(lookup_dns_ns, hostname, registered_domain)
    future_mx = dns_executor.submit(lookup_dns_mx, hostname, registered_domain)
    future_whois = whois_executor.submit(lookup_whois, registered_domain)
    
    results["time_response"] = future_time.result()
    results["resolved_ip"] = resolved_ip
    results["qty_ip_resolved"] = a_res["qty_ip_resolved"]
    results["ttl_hostname"] = a_res["ttl_hostname"]
    results["asn_ip"] = a_res["asn_ip"]
    results["qty_nameservers"] = future_ns.result()
    results["qty_mx_servers"] = future_mx.result()
    
    # Strict WHOIS timeout (increased to 6.0 for more robust lookups)
    try:
        act, exp = future_whois.result(timeout=6.0)
    except Exception:
        act, exp = -1, -1
        
    results["time_domain_activation"] = act
    results["time_domain_expiration"] = exp
    return results

def extract_features(raw_url: str) -> dict:
    url = str(raw_url).strip()
    
    if not re.match(r'^[a-zA-Z]+://', url):
        url_full = 'http://' + url
    else:
        url_full = url

    parsed = urlparse(url_full)
    ext = tldextract.extract(url_full)
    domain = ext.domain + ('.' + ext.suffix if ext.suffix else '')
    registered_domain = ext.registered_domain
    
    path = parsed.path
    query = parsed.query
    
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
    
    feats["length_url"] = len(url)
    feats["qty_dot_url"] = url.count('.')
    feats["qty_slash_url"] = url.count('/')
    feats["qty_hyphen_url"] = url.count('-')

    feats["domain_length"] = len(domain)
    feats["qty_dot_domain"] = domain.count('.')
    feats["qty_vowels_domain"] = sum(domain.lower().count(v) for v in "aeiou")
    
    if directory is not None:
        feats["directory_length"] = len(directory)
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_directory"] = directory.count(ch)
    else:
        feats["directory_length"] = -1
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_directory"] = -1

    if file_part is not None:
        feats["file_length"] = len(file_part)
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_file"] = file_part.count(ch)
    else:
        feats["file_length"] = -1
        for ch, name in zip(SUSPICIOUS_CHARS, CHAR_NAMES):
            feats[f"qty_{name}_file"] = -1

    if query:
        feats["qty_params"] = len(query.split('&'))
        feats["params_length"] = len(query)
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

    hostname = parsed.hostname
    if hostname:
        cached_metrics = domain_cache.get(hostname)
        if cached_metrics:
            metrics = cached_metrics
        else:
            metrics = resolve_domain_metrics(hostname, registered_domain)
            domain_cache.set(hostname, metrics)
            
        feats["qty_ip_resolved"] = metrics["qty_ip_resolved"]
        feats["ttl_hostname"] = metrics["ttl_hostname"]
        feats["qty_nameservers"] = metrics["qty_nameservers"]
        feats["qty_mx_servers"] = metrics["qty_mx_servers"]
        feats["time_response"] = metrics["time_response"]
        feats["asn_ip"] = metrics["asn_ip"]
        feats["time_domain_activation"] = metrics["time_domain_activation"]
        feats["time_domain_expiration"] = metrics["time_domain_expiration"]
    else:
        feats["qty_ip_resolved"] = -1
        feats["ttl_hostname"] = -1
        feats["qty_nameservers"] = -1
        feats["qty_mx_servers"] = -1
        feats["time_response"] = -1.0
        feats["asn_ip"] = -1
        feats["time_domain_activation"] = -1
        feats["time_domain_expiration"] = -1

    for f in features_list:
        if f not in feats:
            feats[f] = 0

    return feats

def predict_url(url: str) -> dict:
    """Predict if a URL is phishing and return risk metrics and feature importances."""
    resolved_url = resolve_redirects(url)
    feats = extract_features(resolved_url)
    
    # Check Brand Impersonation / Typosquatting on both original and resolved URLs
    parsed_orig = urlparse(url if "://" in url else "http://" + url)
    ext_orig = tldextract.extract(url if "://" in url else "http://" + url)
    domain_orig = ext_orig.domain + ('.' + ext_orig.suffix if ext_orig.suffix else '')
    brand_check_orig = check_brand_impersonation(parsed_orig.hostname, domain_orig, ext_orig.registered_domain)
    
    parsed_res = urlparse(resolved_url if "://" in resolved_url else "http://" + resolved_url)
    ext_res = tldextract.extract(resolved_url if "://" in resolved_url else "http://" + resolved_url)
    domain_res = ext_res.domain + ('.' + ext_res.suffix if ext_res.suffix else '')
    brand_check_res = check_brand_impersonation(parsed_res.hostname, domain_res, ext_res.registered_domain)
    
    # Combine brand checks: prioritize impersonated over official
    if brand_check_orig.get("impersonated") or brand_check_res.get("impersonated"):
        brand_check = brand_check_orig if brand_check_orig.get("impersonated") else brand_check_res
    elif brand_check_orig.get("official") or brand_check_res.get("official"):
        brand_check = brand_check_orig if brand_check_orig.get("official") else brand_check_res
    else:
        brand_check = brand_check_orig
        
    df_row = pd.Series(feats).reindex(features_list).fillna(0)
    scaled_df = pd.DataFrame([df_row], columns=features_list)
    scaled = scaler.transform(scaled_df)
    prob = model.predict_proba(scaled_df)[0, 1]
    
    # Wise combination of heuristics & ML:
    # 1. If brand verification matches official brand assets, trust it.
    # 2. If brand verification finds typosquatting/impersonation, flag it.
    # 3. Otherwise, use ML prediction refined by domain age (older domains scaled down).
    is_phishing = bool(prob >= 0.5)
    age_adjusted = False
    
    if brand_check.get("official"):
        is_phishing = False
        prob = min(prob, 0.05)
    elif brand_check.get("impersonated"):
        is_phishing = True
        prob = max(prob, 0.95)
    else:
        domain_age = feats.get("time_domain_activation", -1)
        if domain_age > 365:
            prob = prob * 0.05
            age_adjusted = True
            is_phishing = bool(prob >= 0.5)

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
        "resolved_url": resolved_url,
        "is_phishing": is_phishing,
        "risk_score_pct": round(prob * 100, 2),
        "brand_alert": brand_check,
        "age_adjusted": age_adjusted,
        "features": {k: float(v) for k, v in feats.items() if k in features_list},
        "top_features": reasons
    }
