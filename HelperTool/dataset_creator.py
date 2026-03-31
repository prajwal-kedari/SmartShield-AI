import os
import pefile
import pandas as pd
from tqdm import tqdm

# 📂 Folder containing your .exe files
FOLDER_PATH = r"./malware-samples"   # change to your folder
OUTPUT_CSV = "pe_features1.csv"

# ✅ Feature order (exact as you requested)
FEATURE_ORDER = [
    "MajorLinkerVersion",
    "MinorOperatingSystemVersion",
    "MajorSubsystemVersion",
    "SizeOfStackReserve",
    "TimeDateStamp",
    "MajorOperatingSystemVersion",
    "Characteristics",
    "ImageBase",
    "Subsystem",
    "MinorImageVersion",
    "MinorSubsystemVersion",
    "SizeOfInitializedData",
    "DllCharacteristics",
    "DirectoryEntryExport",
    "ImageDirectoryEntryExport",
    "CheckSum",
    "DirectoryEntryImportSize",
    "SectionMaxChar",
    "MajorImageVersion",
    "AddressOfEntryPoint",
    "SectionMinEntropy",
    "SizeOfHeaders",
    "SectionMinVirtualsize"
]

# 🧰 Function to extract features safely
def extract_pe_features(filepath):
    features = {}
    try:
        pe = pefile.PE(filepath)

        # --- PE Header fields ---
        features["MajorLinkerVersion"] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        features["MinorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        features["MajorSubsystemVersion"] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        features["SizeOfStackReserve"] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        features["TimeDateStamp"] = pe.FILE_HEADER.TimeDateStamp
        features["MajorOperatingSystemVersion"] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        features["Characteristics"] = pe.FILE_HEADER.Characteristics
        features["ImageBase"] = pe.OPTIONAL_HEADER.ImageBase
        features["Subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        features["MinorImageVersion"] = pe.OPTIONAL_HEADER.MinorImageVersion
        features["MinorSubsystemVersion"] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        features["SizeOfInitializedData"] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features["DllCharacteristics"] = pe.OPTIONAL_HEADER.DllCharacteristics
        features["CheckSum"] = getattr(pe.OPTIONAL_HEADER, "CheckSum", 0)
        features["MajorImageVersion"] = pe.OPTIONAL_HEADER.MajorImageVersion
        features["AddressOfEntryPoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        features["SizeOfHeaders"] = pe.OPTIONAL_HEADER.SizeOfHeaders

        # --- Derived features ---
        features["DirectoryEntryExport"] = 1 if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0
        features["ImageDirectoryEntryExport"] = (
            len(getattr(pe, "DIRECTORY_ENTRY_EXPORT", {}).get("symbols", []))
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0
        )
        features["DirectoryEntryImportSize"] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0

        # --- Section-based features ---
        section_chars = [s.Characteristics for s in pe.sections]
        section_entropy = [s.get_entropy() for s in pe.sections]
        section_vsize = [s.Misc_VirtualSize for s in pe.sections]

        features["SectionMaxChar"] = max(section_chars) if section_chars else 0
        features["SectionMinEntropy"] = min(section_entropy) if section_entropy else 0
        features["SectionMinVirtualsize"] = min(section_vsize) if section_vsize else 0

        pe.close()

    except Exception:
        # If any error, fill with None
        features = {key: None for key in FEATURE_ORDER}

    return features


# 🗂️ Collect .exe files





exe_files = ["outside.exe","outside1.exe"] #,'.\\Extra Virus1\\0.exe', '.\\Extra Virus1\\1.exe', '.\\Extra Virus1\\123.exe', '.\\Extra Virus1\\1_1.exe', '.\\Extra Virus1\\25000.exe', '.\\Extra Virus1\\2d.exe', '.\\Extra Virus1\\3.exe', '.\\Extra Virus1\\311.exe', '.\\Extra Virus1\\340s.exe', '.\\Extra Virus1\\360sb.exe', '.\\Extra Virus1\\711.exe', '.\\Extra Virus1\\854137.exe', '.\\Extra Virus1\\bjyk.exe', '.\\Extra Virus1\\Bombermania.exe', '.\\Extra Virus1\\bx89.exe', '.\\Extra Virus1\\ceshi.exe', '.\\Extra Virus1\\ddos.exe', '.\\Extra Virus1\\dhl.exe', '.\\Extra Virus1\\ExeBinder.exe', '.\\Extra Virus1\\Google_Adobe_FlashPlayer.exe', '.\\Extra Virus1\\Inte.exe', '.\\Extra Virus1\\mcpatcher.exe', '.\\Extra Virus1\\Mh.exe', '.\\Extra Virus1\\Mh1.exe', '.\\Extra Virus1\\Mh2.exe', '.\\Extra Virus1\\mh3.exe', '.\\Extra Virus1\\newbos2.exe', '.\\Extra Virus1\\proxyt.exe', '.\\Extra Virus1\\proxyt_1.exe', '.\\Extra Virus1\\se.exe', '.\\Extra Virus1\\server.exe', '.\\Extra Virus1\\SETUP.exe', '.\\Extra Virus1\\smss.exe', '.\\Extra Virus1\\TekDefense.exe', '.\\Extra Virus1\\vip.exe', '.\\Extra Virus1\\xiaoqi.exe', '.\\Extra Virus1\\xiaose.exe', '.\\Extra Virus1\\yitaly.exe', '.\\Extra Virus1\\yk.exe', '.\\kapi2.0peys-malwares\\Bitmap2.exe', '.\\kapi2.0peys-malwares\\Bitmap2_GDIOnly.exe', '.\\kapi2.0peys-malwares\\bmp.exe', '.\\kapi2.0peys-malwares\\bmp_GDIOnly.exe', '.\\kapi2.0peys-malwares\\ColorCs.exe', '.\\kapi2.0peys-malwares\\coore32.exe', '.\\kapi2.0peys-malwares\\Dead Fish.exe', '.\\kapi2.0peys-malwares\\ico.exe', '.\\kapi2.0peys-malwares\\intdust.exe', '.\\kapi2.0peys-malwares\\jfif.exe', '.\\kapi2.0peys-malwares\\Laplace.exe', '.\\kapi2.0peys-malwares\\M0dules.exe', '.\\kapi2.0peys-malwares\\mawaru1.2.exe', '.\\kapi2.0peys-malwares\\Mocq Epic.exe', '.\\kapi2.0peys-malwares\\png.exe', '.\\kapi2.0peys-malwares\\png_GDIOnly.exe', '.\\kapi2.0peys-malwares\\png_Win8-11_GDIOnly.exe', '.\\kapi2.0peys-malwares\\Profect.exe', '.\\kapi2.0peys-malwares\\Scribble.exe', '.\\kapi2.0peys-malwares\\Sustain Epic.exe', '.\\kapi2.0peys-malwares\\tendows.exe', '.\\kapi2.0peys-malwares\\Tera Bonus.exe', '.\\kapi2.0peys-malwares\\bmp.exe-sourcecode-main\\bmp\\bmp\\bin\\Debug\\bmp.exe', '.\\kapi2.0peys-malwares\\bmp.exe-sourcecode-main\\bmp\\bmp\\bin\\Release\\bmp.exe', '.\\kapi2.0peys-malwares\\bmp.exe-sourcecode-main\\bmp\\bmp\\obj\\Debug\\bmp.exe', '.\\kapi2.0peys-malwares\\bmp.exe-sourcecode-main\\bmp\\bmp\\obj\\Release\\bmp.exe', '.\\kapi2.0peys-malwares\\ico.exe-sourcecode-main\\ico\\ico\\bin\\Debug\\ico.exe', '.\\kapi2.0peys-malwares\\ico.exe-sourcecode-main\\ico\\ico\\obj\\Debug\\ico.exe', '.\\kapi2.0peys-malwares\\ico.exe-sourcecode-main\\ico\\ico\\obj\\Release\\ico.exe', '.\\kapi2.0peys-malwares\\ico.exe-sourcecode-main\\ico\\ico\\Resources\\wwwww.exe', '.\\kapi2.0peys-malwares1\\gif.exe', '.\\kapi2.0peys-malwares1\\jpg.exe', '.\\kapi2.0peys-malwares1\\kaelmemniw.exe', '.\\kapi2.0peys-malwares1\\Narcosis_Remade.exe', '.\\kapi2.0peys-malwares1\\pid.kvai.exe', '.\\kapi2.0peys-malwares1\\tif.exe', '.\\kapi2.0peys-malwares1\\tif_GDIOnly.exe', '.\\kapi2.0peys-malwares1\\coore32.exe-main\\coore32\\coore32\\bin\\Debug\\coore32.exe', '.\\kapi2.0peys-malwares1\\coore32.exe-main\\coore32\\coore32\\bin\\Release\\coore32.exe', '.\\kapi2.0peys-malwares1\\coore32.exe-main\\coore32\\coore32\\obj\\Debug\\coore32.exe', '.\\kapi2.0peys-malwares1\\coore32.exe-main\\coore32\\coore32\\obj\\Release\\coore32.exe', '.\\kapi2.0peys-malwares1\\Dead-Fish.exe-by-kapi2.0peys-main\\Dead Fish.exe', '.\\kapi2.0peys-malwares1\\Dead-Fish.exe-by-kapi2.0peys-main\\Dead Fish\\Dead Fish\\bin\\Release\\Dead Fish.exe', '.\\kapi2.0peys-malwares1\\Dead-Fish.exe-by-kapi2.0peys-main\\Dead Fish\\Dead Fish\\obj\\Release\\Dead Fish.exe', '.\\kapi2.0peys-malwares1\\EternalBlue.exe-by-kapi2.0peys-main\\EternalBlue.exe', '.\\kapi2.0peys-malwares1\\m0dules.exe-source-code-main\\m0dules\\m0dules\\bin\\Debug\\m0dules.exe', '.\\kapi2.0peys-malwares1\\m0dules.exe-source-code-main\\m0dules\\m0dules\\obj\\Debug\\m0dules.exe', '.\\kapi2.0peys-malwares1\\m0dules.exe-source-code-main\\m0dules\\m0dules\\obj\\Release\\m0dules.exe', '.\\kapi2.0peys-malwares1\\m0dules.exe-source-code-main\\m0dules\\m0dules\\Resources\\mal.exe', '.\\kapi2.0peys-malwares1\\mawaru.exe-Malware-main\\mawaru.exe', '.\\kapi2.0peys-malwares1\\Tera-Bonus.exe-Fixed-Random-main\\Tera Bonus.exe', '.\\kapi2.0peys-malwares1\\Tera-Bonus.exe-Fixed-Random-main\\Tera Bonus\\Tera Bonus\\bin\\Debug\\Tera Bonus.exe', '.\\kapi2.0peys-malwares1\\Tera-Bonus.exe-Fixed-Random-main\\Tera Bonus\\Tera Bonus\\bin\\Release\\Tera Bonus.exe', '.\\kapi2.0peys-malwares1\\Tera-Bonus.exe-Fixed-Random-main\\Tera Bonus\\Tera Bonus\\obj\\Debug\\Tera Bonus.exe', '.\\kapi2.0peys-malwares1\\Tera-Bonus.exe-Fixed-Random-main\\Tera Bonus\\Tera Bonus\\obj\\Release\\Tera Bonus.exe', '.\\kapi2.0peys-malwares1\\Tera-Bonus.exe-Fixed-Random-main\\Tera Bonus\\Tera Bonus\\Resources\\end.exe', '.\\malware-samples1\\Downloader-CUZ\\smb-7teux2sm.exe', '.\\malware-samples1\\Ransomware\\Wannacry\\smb-0e89k3id.exe', '.\\malware-samples1\\Ransomware\\Wannacry\\smb-fvd4o59p.exe', '.\\malware-samples1\\Ransomware\\Wannacry\\smb-oat1c4ef.exe', '.\\malware-samples1\\Ransomware\\Wannacry\\smb-z7uhqxx6.exe', '.\\malware-samples1\\unknown\\smb-nt7kaalt.exe']


# 📊 Extract all features
rows = []
for file_path in tqdm(exe_files, desc="Extracting features"):
    feats = extract_pe_features(file_path)
    feats["Name"] = os.path.basename(file_path)
    rows.append(feats)

# 🧾 Save DataFrame with ordered columns
columns = ["Name"] + FEATURE_ORDER
df = pd.DataFrame(rows, columns=columns)
df.to_csv(OUTPUT_CSV, index=False)