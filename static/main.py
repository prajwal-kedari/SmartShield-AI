from static.hash_file import *
from static.system_base import *
from static.cloud_based import *
from static.custom_file_analyze import *
from static.ember_file_analyze import *
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

def static_checker(FilePath,vt=True,mb=True,cust=False,ember=False):
    result_dic=dict()
    hashValue= hash_file(FilePath)
    if (vt or mb):
        hashValue= hash_file(FilePath)
    if vt:
        result_dic["vt"]=vt_check_hash(hashValue)
    if mb:
        result_dic["mb"]=check_hash_malwarebazaar(hashValue)
    if cust:
        result_dic["cust"]=custom_analyze_file(FilePath)
    if ember:
        result_dic["ember"]=ember_analyze_file(FilePath)
    return result_dic

if __name__ == "__main__" :
    print(static_checker(r"C:\Users\SARVESH/Downloads\ed8fa7b7b1fbd7fa1100d52617db6c07c9a23b39f834b497f28b2633766d8a4c.exe",1,1,1,1))
    # print(static_checker("Extra Virus1/25000.exe",1,1,1,1))
    
    FilePath = input("Enter File Path :")
    work_step(FilePath)
