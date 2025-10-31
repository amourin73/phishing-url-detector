import re
import joblib
import os
from urllib.parse import urlparse
import tldextract
import math


class SimplePhishingClassifier:
    def __init__(self):
        self.rules = []
        self.model_path = 'simple_model.joblib'
        self._create_rules()

    def _create_rules(self):
        """Create phishing detection rules"""
        self.rules = [
            # High risk rules (score = 2)
            {'name': 'random_domain', 'check': self.is_random_domain, 'score': 2},
            {'name': 'has_ip', 'check': self.has_ip_address, 'score': 2},
            {'name': 'suspicious_tld', 'check': self.has_suspicious_tld, 'score': 2},
            {'name': 'short_url', 'check': self.is_short_url, 'score': 2},

            # Medium risk rules (score = 1.5)
            {'name': 'no_https', 'check': self.has_no_https, 'score': 1.5},
            {'name': 'brand_impersonation', 'check': self.has_brand_impersonation, 'score': 1.5},
            {'name': 'suspicious_keywords', 'check': self.has_suspicious_keywords, 'score': 1.5},

            # Normal risk rules (score = 1)
            {'name': 'long_url', 'check': self.is_long_url, 'score': 1},
            {'name': 'many_subdomains', 'check': self.has_many_subdomains, 'score': 1},
            {'name': 'many_hyphens', 'check': self.has_many_hyphens, 'score': 1},
            {'name': 'has_at_symbol', 'check': self.has_at_symbol, 'score': 1},
            {'name': 'has_redirect', 'check': self.has_redirect, 'score': 1},
        ]

    def is_random_domain(self, url):
        """Check if domain looks randomly generated"""
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain

            if len(domain) < 8:
                return False

            # Check entropy
            entropy = self.calculate_entropy(domain)
            vowel_ratio = self.calculate_vowel_ratio(domain)

            # High entropy and low vowel ratio suggests randomness
            return entropy > 3.5 and vowel_ratio < 0.3
        except:
            return False

    def has_ip_address(self, url):
        """Check if URL contains IP address"""
        return bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))

    def has_suspicious_tld(self, url):
        """Check for suspicious TLDs"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.gq']
        extracted = tldextract.extract(url)
        return any(tld in extracted.suffix for tld in suspicious_tlds)

    def is_short_url(self, url):
        """Check if URL uses shortening service"""
        short_services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'ow.ly']
        return any(service in url for service in short_services)

    def has_no_https(self, url):
        """Check if URL doesn't use HTTPS"""
        return not url.startswith('https')

    def has_brand_impersonation(self, url):
        """Check for brand names in suspicious contexts"""
        brands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal']
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()

        for brand in brands:
            if brand in url.lower() and brand not in domain:
                return True
        return False

    def has_suspicious_keywords(self, url):
        """Check for suspicious keywords"""
        keywords = ['login', 'verify', 'account', 'secure', 'banking', 'update', 'confirm']
        return any(keyword in url.lower() for keyword in keywords)

    def is_long_url(self, url):
        """Check if URL is unusually long"""
        return len(url) > 75

    def has_many_subdomains(self, url):
        """Check for many subdomains"""
        extracted = tldextract.extract(url)
        return len(extracted.subdomain.split('.')) > 3 if extracted.subdomain else False

    def has_many_hyphens(self, url):
        """Check for many hyphens"""
        return url.count('-') > 3

    def has_at_symbol(self, url):
        """Check for @ symbol"""
        return '@' in url

    def has_redirect(self, url):
        """Check for redirects"""
        return '//' in url[7:]  # After protocol

    def calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if len(text) <= 1:
            return 0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p_x = count / len(text)
            entropy += -p_x * math.log2(p_x)
        return entropy

    def calculate_vowel_ratio(self, text):
        """Calculate vowel ratio"""
        vowels = 'aeiouAEIOU'
        vowel_count = sum(1 for char in text if char in vowels)
        return vowel_count / len(text) if text else 0

    def predict(self, url):
        """Predict if URL is phishing using rule-based approach"""
        try:
            total_score = 0
            max_score = sum(rule['score'] for rule in self.rules)
            triggered_rules = []

            for rule in self.rules:
                if rule['check'](url):
                    total_score += rule['score']
                    triggered_rules.append(rule['name'])

            probability = total_score / max_score if max_score > 0 else 0
            is_phishing = probability > 0.3  # Threshold
            confidence = min(probability * 1.5, 1.0)

            return {
                'is_phishing': is_phishing,
                'probability': probability,
                'confidence': confidence,
                'safe': not is_phishing,
                'triggered_rules': triggered_rules,
                'total_score': total_score,
                'max_score': max_score,
                'success': True
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'is_phishing': False,
                'probability': 0.0,
                'confidence': 0.0,
                'safe': True,
                'error': str(e),
                'success': False
            }

    def save_model(self):
        """Save the model (rules)"""
        joblib.dump(self.rules, self.model_path)
        print(f"💾 Model saved to {self.model_path}")

    def load_model(self):
        """Load the model"""
        if os.path.exists(self.model_path):
            self.rules = joblib.load(self.model_path)
            print("🔍 Model loaded successfully")
        else:
            print("❌ Model not found. Creating new rules...")
            self._create_rules()


def main():
    print("🚀 Simple Phishing URL Detection")
    print("=" * 50)

    classifier = SimplePhishingClassifier()

    print(f"✅ Created {len(classifier.rules)} detection rules")

    # Test with examples
    test_urls = [
        "https://www.google.com",
        "http://ghjkljbqnmlw.com",
        "http://secure-login-facebook.xyz",
        "http://bit.ly/suspicious123",
        "https://github.com"
    ]

    print("\n🧪 Testing with sample URLs:")
    for url in test_urls:
        result = classifier.predict(url)
        status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
        print(f"{status}: {url}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Score: {result['total_score']:.1f}/{result['max_score']}")
        print(f"   Rules triggered: {len(result['triggered_rules'])}")
        print()


if __name__ == "__main__":
    main()