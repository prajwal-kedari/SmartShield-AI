import requests
from pathlib import Path
db_file=[
    "https://github.com/aaryanrlondhe/Malware-Hash-Database/raw/refs/heads/main/SHA256/sha256_hashes_1.txt",
    "https://github.com/aaryanrlondhe/Malware-Hash-Database/raw/refs/heads/main/SHA256/sha256_hashes_2.txt",
    "https://github.com/aaryanrlondhe/Malware-Hash-Database/raw/refs/heads/main/SHA256/sha256_hashes_3.txt",
    "https://github.com/aaryanrlondhe/Malware-Hash-Database/raw/refs/heads/main/SHA256/sha256_hashes_4.txt"
]

if not Path("./static/DataBase/sha256_hashes_1.txt").exists:
    print("downloading Malware Hash DataBase.............")
    for files in db_file:
        response =requests.get(files,stream=True)
        with open("./static/DataBase/"+files.split("/")[-1], mode="wb") as file:
            for chunk in response.iter_content(chunk_size=10 * 1024):
                file.write(chunk)
# h_set = set()
def hash_to_set():
    h_set = set()
    print("Hash Loading....")
    with open("./static/DataBase/sha256_hash_sample.txt", "r") as f:
        for line in f:
            h = line.strip().lower()
            h_set.add(h)
    return h_set

def check_hash(hash_value):
    h_set= hash_to_set()
    # h_set = set()
    if hash in h_set :
        print("It is Virus @@")
        return True
    else :
        print("its Hash Not Found #Offline#")
        return False

# check_hash("4931e5d3811a460f47678631f4bdc82c9c6e9176ae3940403e690bc82e3714a9")