import hashlib


def hash_file(path, chunk_size=8192):
    # h_md5 = hashlib.md5()
    # h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h_sha256.update(chunk)
                # h_md5.update(chunk)
                # h_sha1.update(chunk)
        return h_sha256.hexdigest()
        return {
            "md5": h_md5.hexdigest(),
            "sha1": h_sha1.hexdigest(),
            "sha256": h_sha256.hexdigest(),
        }
    except (PermissionError, FileNotFoundError) as e:
        return {"error": str(e)}
    
# print(hash_file("c:\\Users\\Prajwal\\Desktop\\IDM_6.4x_Crack_v19.7.exe"))