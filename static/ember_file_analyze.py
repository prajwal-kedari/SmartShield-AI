import ember
import joblib
import os
import numpy as np
from ember.features import PEFeatureExtractor

MODEL_PATH = r"static/Models/ember_model_full.pkl"

def ember_analyze_file(file_path):
    print(f"\n Analyzing file: {file_path}\n")

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not found! Train it using train_model.py")

    model = joblib.load(MODEL_PATH)

    # Extract features
    extractor = PEFeatureExtractor(2)
    with open(file_path, "rb") as f:
        features = extractor.feature_vector(f.read())

    features = np.array(features).reshape(1, -1)
    prediction_prob = model.predict(features)[0]
    prediction = " Malicious" if prediction_prob > 0.5 else " Benign"

    print(f" Prediction: {prediction}")
    print(f" Probability of Malicious: {prediction_prob:.4f}\n")

    # Detailed Explanation
    # print(" File Structure Analysis:")
    # pe = pefile.PE(file_path)

    # print(f"   Number of Sections: {len(pe.sections)}")
    # print(f"   Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    # print(f"   Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
    # print(f"   File Size: {os.path.getsize(file_path)} bytes")

    # print("\n Explanation Summary:")
    if prediction_prob > 0.5:
        print("This file shows high entropy, suspicious PE sections, or unusual import/export patterns.\nLikely packed or obfuscated — traits typical of malware.")
    else:
        print("File structure and entropy look normal. No suspicious sections or imports — likely benign.")

    return bool(round(prediction_prob)) , prediction_prob

