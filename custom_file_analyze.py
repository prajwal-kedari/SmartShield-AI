import pickle
import static.feature_extract

with open(r'./static/models/smartshield-V1.pkl', 'rb') as file:
    model = pickle.load(file)

def custom_analyze_file(file_path):
    dataV = static.feature_extract.extract_features(file_path)
    return (model.predict(dataV))
