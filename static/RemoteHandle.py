from static.hash_file import *
from ember.features import PEFeatureExtractor
import static.feature_extract
import numpy as np


def Remote_Server_Engine(FilePath,vt,mb,cust,ember,ApiAdress):
    # print(f"Starting static analysis for: {FilePath}")
    result_dic=dict()
    hashValue= hash_file(FilePath)
    dataV = static.feature_extract.extract_features(FilePath)
    extractor = PEFeatureExtractor(2)
    with open(FilePath, "rb") as f:
        features = extractor.feature_vector(f.read())
    features = np.array(features).reshape(1, -1)

    return result_dic