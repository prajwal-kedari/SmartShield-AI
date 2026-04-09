import pickle

with open('smartshield-V1.pkl', 'rb') as file:
    model = pickle.load(file)

import feature_extract
datVS = feature_extract.extract_features("Vscode.exe")
print(datVS.to_string())
datV1 = feature_extract.extract_features("outside.exe")
datV2 = feature_extract.extract_features("outside1.exe")
# print(model.predict(datVS))
print(model.predict(datVS))
print(model.predict(datV1))
print(model.predict(datV2))