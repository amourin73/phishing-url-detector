from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_model.simple_classifier import SimplePhishingClassifier

app = Flask(__name__)
CORS(app)

# Initialize classifier
classifier = SimplePhishingClassifier()


@app.route('/')
def home():
    return jsonify({
        "message": "Phishing URL Detection API",
        "status": "active",
        "version": "1.0",
        "type": "Rule-based Classifier",
        "endpoints": {
            "predict": "/predict?url=YOUR_URL",
            "health": "/health"
        }
    })


@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "rules_loaded": len(classifier.rules) > 0,
        "total_rules": len(classifier.rules)
    })


@app.route('/predict')
def predict_url():
    url = request.args.get('url', '')

    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    try:
        result = classifier.predict(url)
        return jsonify({
            "url": url,
            "result": result
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/batch-predict', methods=['POST'])
def batch_predict():
    data = request.get_json()

    if not data or 'urls' not in data:
        return jsonify({"error": "URLs array is required"}), 400

    urls = data['urls']
    results = []

    for url in urls:
        try:
            result = classifier.predict(url)
            results.append({
                "url": url,
                "result": result
            })
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e)
            })

    return jsonify({"results": results})


def start_server():
    print("🚀 Starting Phishing URL Detection API...")
    print("🔧 Using Rule-based Classifier (No ML dependencies)")

    # Load rules
    classifier._load_model()

    print(f"✅ Loaded {len(classifier.rules)} detection rules")
    print("🌐 Server starting on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    start_server()