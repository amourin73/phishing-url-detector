import csv
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from feature_extractor import AdvancedFeatureExtractor


class PhishingModelTrainer:
    def __init__(self):
        self.model = None
        self.feature_extractor = AdvancedFeatureExtractor()
        self.model_path = 'phishing_model.joblib'

    def load_dataset(self, csv_path='phishing_dataset.csv'):
        """Load dataset from CSV"""
        if not os.path.exists(csv_path):
            print("❌ Dataset not found. Please run create_dataset.py first.")
            return None

        urls = []
        labels = []

        with open(csv_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                urls.append(row['url'])
                labels.append(int(row['label']))

        print(f"📊 Loaded dataset with {len(urls)} URLs")
        return urls, labels

    def prepare_features(self, urls, labels):
        """Extract features from URLs"""
        print("🔧 Extracting features...")
        features = []
        processed_labels = []

        for i, url in enumerate(urls):
            feature_vector = self.feature_extractor.extract(url)
            features.append(feature_vector)
            processed_labels.append(labels[i])

            if (i + 1) % 20 == 0:
                print(f"Processed {i + 1}/{len(urls)} URLs")

        print(f"✅ Feature extraction complete: {len(features)} samples")
        return features, processed_labels

    def train(self):
        """Train the phishing detection model"""
        # Load dataset
        data = self.load_dataset()
        if data is None:
            return None

        urls, labels = data

        # Prepare features
        X, y = self.prepare_features(urls, labels)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")

        # Train Random Forest
        print("🤖 Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=50,  # Reduced for faster training
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        )

        self.model.fit(X_train, y_train)

        # Evaluate
        print("📊 Evaluating model...")
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"🎯 Model Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        # Save model
        self.save_model()

        return accuracy

    def predict(self, url):
        """Predict if URL is phishing"""
        if self.model is None:
            self.load_model()

        try:
            features = self.feature_extractor.extract(url)
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0]

            return {
                'is_phishing': bool(prediction),
                'probability': float(probability[1]),  # Probability of being phishing
                'confidence': float(max(probability)),
                'safe': not bool(prediction),
                'features_used': len(features),
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
        """Save trained model"""
        joblib.dump(self.model, self.model_path)
        print(f"💾 Model saved to {self.model_path}")

    def load_model(self):
        """Load trained model"""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print("🔍 Model loaded successfully")
        else:
            print("❌ Model not found. Please train the model first.")
            raise FileNotFoundError("Model not found")


def main():
    print("🚀 Phishing URL Detection Model Training")
    print("=" * 50)

    trainer = PhishingModelTrainer()
    accuracy = trainer.train()

    if accuracy is not None:
        print(f"\n✅ Training completed!")
        print(f"📊 Final Accuracy: {accuracy:.4f}")

        # Test with some examples
        print("\n🧪 Testing with sample URLs:")
        test_urls = [
            "https://www.google.com",
            "http://hujklwefq.com",
            "http://secure-login-facebook.xyz",
            "http://bit.ly/suspicious123",
            "https://github.com"
        ]

        for url in test_urls:
            result = trainer.predict(url)
            status = "🚨 PHISHING" if result['is_phishing'] else "✅ SAFE"
            print(f"{status}: {url}")
            print(f"   Confidence: {result['confidence']:.2%}")
            print(f"   Probability: {result['probability']:.2%}")
            print()


if __name__ == "__main__":
    main()