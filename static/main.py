from hash_file import *
from system_base import *
from cloud_based import *
import sys
import io


global FilePath 

# Reconfigure stdout to UTF-8
# sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def work_step(FilePath):
    print(FilePath)
    hashValue= hash_file(FilePath)
    if check_hash(hashValue): #offline
        return 
    vt_check_hash(hashValue)
    check_hash_malwarebazaar(hashValue)

if __name__ == "__main__" :
    FilePath = input("Enter File Path :")
    work_step(FilePath)
