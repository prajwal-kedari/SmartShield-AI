import requests
from static.hash_file import *
from ember.features import PEFeatureExtractor
import static.feature_extract
import numpy as np


def Remote_Server_Engine(FilePath, vt=True, mb=True, cust=False, ember=False, ApiAdress="http://127.0.0.1:8000/analyze"):

    result_dic = {}

    
    hashValue = hash_file(FilePath)

    #  Custom features
    dataV = static.feature_extract.extract_features(FilePath)

    #  EMBER features
    extractor = PEFeatureExtractor(2)
    with open(FilePath, "rb") as f:
        features = extractor.feature_vector(f.read())

    features = np.array(features).tolist()  # convert to JSON serializable

    #  Send to server
    payload = {
        "hash": hashValue,
        "features": features,
        "use_vt": vt,
        "use_mb": mb,
        "use_cust": cust,
        "use_ember": ember
    }

    try:
        response = requests.post(ApiAdress, json=payload)

        if response.status_code == 200:
            result_dic = response.json()
        else:
            result_dic["error"] = response.text

    except Exception as e:
        result_dic["error"] = str(e)

    return result_dic
