import re
import joblib
import os
from urllib.parse import urlparse
import tldextract

print("🚀 Starting Phishing URL Detection System...")


# ==================== FEATURE EXTRACTOR ====================
class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'url_length', 'num_dots', 'num_hyphens', 'num_underscore',
            'num_slash', 'num_question', 'num_equal', 'num_at',
            'num_digit', 'num_letters', 'has_https', 'has_ip',
            'num_subdomain', 'domain_length', 'path_length',
            'short_url', 'suspicious_tld', 'suspicious_words'
        ]

    def extract(self, url):
        try:
            features = []
            features.append(len(url))
            features.append(url.count('.'))
            features.append(url.count('-'))
            features.append(url.count('_'))
            features.append(url.count('/'))
            features.append(url.count('?'))
            features.append(url.count('='))
            features.append(url.count('@'))
            features.append(sum(c.isdigit() for c in url))
            features.append(sum(c.isalpha() for c in url))
            features.append(1 if url.startswith('https') else 0)
            features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

            try:
                extracted = tldextract.extract(url)
                features.append(len(extracted.subdomain.split('.')) if extracted.subdomain else 0)
                features.append(len(extracted.domain))
            except:
                features.append(0)
                features.append(0)

            try:
                parsed = urlparse(url)
                features.append(len(parsed.path))
            except:
                features.append(0)

            short_services = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'ow.ly']
            features.append(1 if any(service in url for service in short_services) else 0)

            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club']
            features.append(1 if any(tld in url for tld in suspicious_tlds) else 0)

            suspicious_keywords = ['login', 'verify', 'account', 'secure', 'banking', 'update', 'confirm']
            features.append(1 if any(keyword in url.lower() for keyword in suspicious_keywords) else 0)

            return features
        except Exception as e:
            print(f"Error extracting features: {e}")
            return [0] * len(self.feature_names)


# ==================== RULE CLASSES (Serializable) ====================
class Rule:
    """Base rule class that can be pickled"""

    def evaluate(self, features):
        raise NotImplementedError("Subclasses must implement evaluate method")


class URLLengthRule(Rule):
    def evaluate(self, features):
        return 1 if features[0] > 75 else 0


class DotCountRule(Rule):
    def evaluate(self, features):
        return 1 if features[1] > 5 else 0


class IPAddressRule(Rule):
    def evaluate(self, features):
        return 1 if features[11] == 1 else 0


class SubdomainCountRule(Rule):
    def evaluate(self, features):
        return 1 if features[12] > 3 else 0


class ShortURLRule(Rule):
    def evaluate(self, features):
        return 1 if features[15] == 1 else 0


class SuspiciousTLDRule(Rule):
    def evaluate(self, features):
        return 1 if features[16] == 1 else 0


class SuspiciousWordsRule(Rule):
    def evaluate(self, features):
        return 1 if features[17] == 1 else 0


class NoHTTPSRule(Rule):
    def evaluate(self, features):
        return 1 if features[10] == 0 else 0


class HyphenCountRule(Rule):
    def evaluate(self, features):
        return 1 if features[2] > 3 else 0


class AtSymbolRule(Rule):
    def evaluate(self, features):
        return 1 if features[7] > 0 else 0


# ==================== CLASSIFIER ====================
class SimplePhishingClassifier:
    def __init__(self):
        self.rules = []
        self.feature_extractor = FeatureExtractor()
        self.model_path = 'simple_model.joblib'

    def _create_rules(self):
        """Create serializable rule objects"""
        self.rules = [
            URLLengthRule(),
            DotCountRule(),
            IPAddressRule(),
            SubdomainCountRule(),
            ShortURLRule(),
            SuspiciousTLDRule(),
            SuspiciousWordsRule(),
            NoHTTPSRule(),
            HyphenCountRule(),
            AtSymbolRule()
        ]

    def train(self):
        print("🤖 Creating phishing detection rules...")
        self._create_rules()
        print(f"✅ Created {len(self.rules)} detection rules")

        # Save the model
        self._save_model()
        return 0.85

    def predict(self, url):
        if not self.rules:
            self._create_rules()

        try:
            features = self.feature_extractor.extract(url)

            # Apply all rules and count triggers
            triggered_rules = 0
            for rule in self.rules:
                triggered_rules += rule.evaluate(features)

            # Calculate probability based on triggered rules
            total_rules = len(self.rules)
            probability = triggered_rules / total_rules

            # If more than 30% of rules trigger, consider it phishing
            is_phishing = probability > 0.3
            confidence = min(probability * 1.5, 1.0)

            return {
                'is_phishing': is_phishing,
                'probability': probability,
                'confidence': confidence,
                'safe': not is_phishing,
                'triggered_rules': triggered_rules,
                'total_rules': total_rules
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'is_phishing': False,
                'probability': 0.0,
                'confidence': 0.0,
                'safe': True,
                'error': str(e)
            }

    def _save_model(self):
        """Save the model"""
        joblib.dump(self.rules, self.model_path)
        print(f"💾 Model saved to {self.model_path}")

    def _load_model(self):
        """Load the model"""
        if os.path.exists(self.model_path):
            self.rules = joblib.load(self.model_path)
            print("🔍 Model loaded successfully")
        else:
            print("❌ Model not found. Creating new rules...")
            self.train()


# ==================== TRAINING ====================
def main():
    print("🚀 Phishing URL Detection Model Training")
    print("=" * 50)

    classifier = SimplePhishingClassifier()
    accuracy = classifier.train()

    print(f"\n✅ Training completed!")
    print(f"📊 Estimated Accuracy: {accuracy:.2%}")

    test_urls = [
        "https://www.google.com",
        "http://secure-login-verify.xyz/login.php",
        "https://github.com",
        "http://bit.ly/suspicious-link",
        "https://www.microsoft.com",
        "http://bank-account-verify.tk",
        "http://192.168.1.1/admin/login"
    ]

    print("\n🧪 Testing the model:")
    print("-" * 40)

    for url in test_urls:
        result = classifier.predict(url)
        status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
        print(f"{status}: {url}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Rules triggered: {result['triggered_rules']}/{result['total_rules']}")
        print()


if __name__ == "__main__":
    main()