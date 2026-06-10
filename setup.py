"""
Phishing Detector — Automated Setup Script
Run this script once on a new machine to set up the entire project.
Usage: python setup.py
"""

import subprocess
import sys
import os

def run(command):
    print(f"\n>>> {command}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"ERROR: Command failed: {command}")
        sys.exit(1)

def main():
    print("=" * 60)
    print("  Phishing Detector — Setup Script")
    print("=" * 60)

    # 1. Install dependencies
    print("\n[1/3] Installing dependencies...")
    run(f"{sys.executable} -m pip install "
        "fastapi uvicorn scikit-learn pandas numpy "
        "requests beautifulsoup4 python-whois dnspython "
        "joblib matplotlib liac-arff scipy pillow")

    # 2. Train the model
    print("\n[2/3] Training the Random Forest model...")
    
    # Check dataset exists
    dataset_path = os.path.join("dataset", "Training Dataset.arff")
    if not os.path.exists(dataset_path):
        print("\nERROR: Dataset not found.")
        print("Please download the UCI Phishing Dataset and place")
        print("'Training Dataset.arff' inside the dataset/ folder.")
        print("Download from: https://archive.ics.uci.edu/dataset/327/phishing+websites")
        sys.exit(1)

    # Run training script
    run(f"{sys.executable} train_model.py")

    # 3. Generate icons
    print("\n[3/3] Generating extension icons...")
    run(f"{sys.executable} generate_icons.py")

    print("\n" + "=" * 60)
    print("  Setup Complete!")
    print("=" * 60)
    print("\nTo start the backend server, run:")
    print("  cd backend")
    print("  uvicorn main:app --reload --port 8000")
    print("\nTo load the Chrome extension:")
    print("  1. Open Chrome → chrome://extensions")
    print("  2. Enable Developer Mode")
    print("  3. Click 'Load unpacked'")
    print("  4. Select the extension/ folder")
    print("\nBackend API will be available at:")
    print("  http://127.0.0.1:8000")
    print("=" * 60)

if __name__ == "__main__":
    main()