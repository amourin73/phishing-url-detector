from flask import Flask, render_template, request, jsonify
import os
import sys

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from model_trainer import PhishingModelTrainer

app = Flask(__name__)

# Initialize the trained model
classifier = None

try:
    classifier = PhishingModelTrainer()
    classifier.load_model()
    print("✅ Phishing detection model loaded successfully!")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    print("🔄 Please train the model first by running: python model_trainer.py")


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_url():
    if classifier is None:
        return jsonify({'error': 'Model not loaded. Please train the model first.', 'success': False}), 500

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided', 'success': False}), 400

        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL is required', 'success': False}), 400

        # Add http:// if no protocol specified
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        result = classifier.predict(url)
        result['url'] = url

        # Ensure all numeric values are properly formatted
        if 'confidence' in result:
            result['confidence'] = float(result['confidence'])
        if 'probability' in result:
            result['probability'] = float(result['probability'])
        if 'triggered_rules' in result:
            result['triggered_rules'] = int(result['triggered_rules'])
        if 'total_rules' in result:
            result['total_rules'] = int(result['total_rules'])

        return jsonify(result)

    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'error': f'Server error: {str(e)}', 'success': False}), 500


@app.route('/batch-check', methods=['POST'])
def batch_check():
    if classifier is None:
        return jsonify({'error': 'Model not loaded. Please train the model first.', 'success': False}), 500

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        urls = data.get('urls', [])

        if not urls:
            return jsonify({'error': 'URLs array is required'}), 400

        results = []
        for url in urls:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            result = classifier.predict(url)
            result['url'] = url

            # Ensure all numeric values are properly formatted
            if 'confidence' in result:
                result['confidence'] = float(result['confidence'])
            if 'probability' in result:
                result['probability'] = float(result['probability'])

            results.append(result)

        return jsonify({'results': results, 'success': True})

    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy' if classifier else 'unhealthy',
        'model_loaded': classifier is not None
    })
# Add this endpoint to your existing web_app.py

@app.route('/batch-check-urls', methods=['POST'])
def batch_check_urls():
    """Check multiple URLs for phishing"""
    if classifier is None:
        return jsonify({'error': 'Model not loaded. Please train the model first.', 'success': False}), 500

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        urls = data.get('urls', [])
        if not urls:
            return jsonify({'error': 'URLs array is required'}), 400

        results = []
        for url in urls:
            url = url.strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            result = classifier.predict(url)
            result['url'] = url
            result['confidence'] = float(result.get('confidence', 0.5))
            result['probability'] = float(result.get('probability', 0.5))
            results.append(result)

        return jsonify({
            'results': results,
            'total_checked': len(results),
            'phishing_count': sum(1 for r in results if r['is_phishing']),
            'success': True
        })

    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500


if __name__ == '__main__':
    print("🚀 Starting Phishing URL Detector")
    print("📍 Access at: http://localhost:5000")
    print("🤖 Using trained Machine Learning model")
    app.run(debug=True, host='0.0.0.0', port=5000)