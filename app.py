import os
import sys
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from model_service import predict_url

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Enable CORS for all routes (including chrome extensions)
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' parameter in request body"}), 400
    
    url = data['url'].strip()
    if not url:
        return jsonify({"error": "Empty URL provided"}), 400
    
    logger.info(f"Analyzing URL: {url}")
    try:
        result = predict_url(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error analyzing URL {url}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error during URL analysis", "details": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "model": "LightGBM_Tuned"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    logger.info(f"Starting Phishing Detection API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
