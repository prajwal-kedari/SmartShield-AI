import requests

API_KEY = ""  # replace with your VT API key
BASE_URL = "https://www.virustotal.com/api/v3/files/{}"

def vt_check_hash(sha256_hash):
    headers = {"x-apikey": API_KEY}
    url = BASE_URL.format(sha256_hash)
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        vt_data =r.json()
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        print("VirusTotal analysis:")
        print(stats)
        return vt_data
    elif r.status_code == 404:
        return None  # not found in VT
    else:
        raise Exception(f"VT error {r.status_code}: {r.text}")




def check_hash_malwarebazaar(sha256_hash):
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {
        "User-Agent": "MalwareLookupScript/1.0",
        "Auth-Key": ""
    }
    payload = {
        "query": "get_info",
        "hash": sha256_hash
    }

    try:
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        response.raise_for_status()
        result = response.json()

        if result.get("query_status") == "ok":
            print(f"[+] Hash found in MalwareBazaar:")
            file_info = result.get("data", [])[0]
            print(f"    SHA256:   {file_info.get('sha256_hash')}")
            print(f"    File Type:{file_info.get('file_type')}")
            print(f"    Signature:{file_info.get('signature')}")
            print(f"    First Seen:{file_info.get('first_seen')}")
            print(f"    Reporter: {file_info.get('reporter')}")
        else:
            print("[SAFE] Hash not found in MalwareBazaar database.")

    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP Error: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")



# check_hash_malwarebazaar("0f81bee03e15e394a587be71726b59670b8482ddb4c9aa87b91cce1cf8a40d17")


# vt_data = vt_check_hash("dbeec44f45e3bcf0b1da9f51b2be8dcc2d1777e88b39b087e724238d865e5514")
# if vt_data is None:
#     print("Hash not found on VirusTotal.")
# else:
#     # Get detection stats
#     stats = vt_data["data"]["attributes"]["last_analysis_stats"]
#     print("VirusTotal analysis:")
#     print(stats)