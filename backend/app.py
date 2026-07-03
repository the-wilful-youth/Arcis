import os
import sys
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pythonjsonlogger import jsonlogger

# Add parent directory of services to path if running directly
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.url_classifier import predict_url
from services.email_classifier import predict_sender_email

# Configure logging
# Configure JSON structured logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

app = Flask(__name__)

# Enable CORS for all routes (including chrome extensions)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Setup Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["120 per minute", "5 per second"],
    storage_uri="memory://"
)

@app.route('/api/analyze/url', methods=['POST'])
@limiter.limit("60 per minute")
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' parameter in request body"}), 400
    
    url = data['url'].strip()
    if not url:
        return jsonify({"error": "Empty URL provided"}), 400
    
    logger.info(f"Analyzing URL: {url} from client {get_remote_address()}")
    try:
        result = predict_url(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing URL {url}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error during URL analysis", "details": str(e)}), 500

@app.route('/api/analyze/email', methods=['POST'])
@limiter.limit("60 per minute")
def analyze_email():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing request body"}), 400
    
    # Support both single-field payload or full analysis payload
    email = data.get('email', data.get('sender', '')).strip()
    if not email:
        return jsonify({"error": "Missing or empty 'email' / 'sender' parameter in request body"}), 400
        
    subject = data.get('subject', '')
    body = data.get('body', '')
    reply_to = data.get('reply_to', '')
    spf = data.get('spf', 'none')
    dkim = data.get('dkim', 'none')
    dmarc = data.get('dmarc', 'none')
    
    logger.info(f"Analyzing Email: {email} from client {get_remote_address()}")
    try:
        result = predict_sender_email(
            email_address=email,
            subject=subject,
            body=body,
            reply_to=reply_to,
            spf=spf,
            dkim=dkim,
            dmarc=dmarc
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing Email {email}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error during Email analysis", "details": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy", 
        "node": "US-EAST-1",
        "models": {
            "url_classifier": "LightGBM_Tuned",
            "email_classifier": "Heuristics_Dns_Verifier"
        }
    }), 200

# Customize Rate Limit error response to return clean JSON
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded. Please wait a moment before trying again.",
        "description": e.description
    }), 429

# Add security headers response hook
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Starting Arcis Multi-Model API Node on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
