import subprocess
import sys


def install_requirements():
    """Install all required packages"""
    print("📦 Installing requirements...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])


def main():
    print("🚀 Setting up Phishing URL Detector...")

    # Install requirements
    install_requirements()

    # Create dataset
    print("📊 Creating training dataset...")
    from create_dataset import create_dataset
    create_dataset()

    # Train model
    print("🤖 Training machine learning model...")
    from model_trainer import main as train_main
    train_main()

    print("\n✅ Setup completed successfully!")
    print("🌐 Run: python app.py to start the web application")
    print("📍 Access at: http://localhost:5000")


if __name__ == "__main__":
    main()