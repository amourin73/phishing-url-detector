import sys
import os

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_model.simple_classifier import SimplePhishingClassifier


def main():
    print("🚀 Phishing URL Detection Model Training")
    print("=" * 50)

    # Initialize and train classifier
    classifier = SimplePhishingClassifier()
    accuracy = classifier.train()

    print(f"\n✅ Training completed!")
    print(f"📊 Estimated Accuracy: {accuracy:.2%}")

    # Test the model
    print("\n🧪 Testing the model:")
    print("-" * 40)

    test_urls = [
        "https://www.google.com",
        "http://secure-login-verify.xyz/login.php",
        "https://github.com",
        "http://bit.ly/suspicious-link",
        "https://www.microsoft.com",
        "http://bank-account-verify.tk",
        "http://192.168.1.1/admin/login"
    ]

    for url in test_urls:
        result = classifier.predict(url)
        status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
        print(f"{status}: {url}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Rules triggered: {result['triggered_rules']}/{result['total_rules']}")
        print()


if __name__ == "__main__":
    main()