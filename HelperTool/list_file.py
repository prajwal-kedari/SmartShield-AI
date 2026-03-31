import os
print(
os.walk("malware-samples"))

start_directory = './' 
_7zipLocation = "C://Program Files//7-Zip//7z.exe"

all_files = [] 
_7zip_file =[]
zip_file=[]

for root, dirs, files in os.walk(start_directory):
    for file_name in files:
        full_file_path = os.path.join(root, file_name)
        all_files.append(full_file_path)


for file_path in all_files:
    if str(file_path).endswith(".zip"): 
        print(file_path)
        zip_file.append(file_path)


    if str(file_path).endswith(".7z"): 
        print(file_path)
        _7zip_file.append(file_path)
print(len(all_files))
print(len(_7zip_file))
print(len(zip_file))

import subprocess


PASSWORD = 'infected' # The password for the archive

def unzip(ZIP_FILE):

    seven_zip_command = [
        _7zipLocation,
        'x',
        ZIP_FILE,
        f'-o {os.path.dirname(ZIP_FILE)}',
        f'-p{PASSWORD}',        # Password flag
        '-y'                    # Assume Yes on all queries
    ]

    # --- 1. Unzip the file using 7-Zip ---
    try:
        print(f"Starting 7-Zip extraction of '{ZIP_FILE}'...")
        print(seven_zip_command)
        
        # Run the 7z command
        result = subprocess.run(
            seven_zip_command,
            check=True,  # Raise an exception for non-zero exit codes (meaning failure)
            capture_output=True,
            text=True
        )
        print(result)
        # Check if the extraction was successful (7-Zip returns 0 on success)
        if result.returncode == 0:
            print("7-Zip extraction complete and successful.")
        else:
            # This part is technically covered by check=True, but serves as extra safety/logging
            print(f"7-Zip command failed with code {result.returncode}.")
            print(f"Error output:\n{result.stderr}")
            exit()

    except subprocess.CalledProcessError as e:
        print(f"\nError: 7-Zip extraction failed.")
        print(f"Check if 7z.exe is in your PATH, or if the password/file is correct.")
        print(f"Details:\n{e.stderr}")
        exit()
    except FileNotFoundError:
        print("\nError: The '7z' command was not found.")
        print("Please ensure the 7-Zip installation directory is added to your system PATH.")
        exit()

    # --- 2. Delete the original zip file ---
    try:
        print(f"Deleting the original archive '{ZIP_FILE}'...")
        os.remove(ZIP_FILE)
        print(f"Successfully deleted '{ZIP_FILE}'.")
    except OSError as e:
        print(f"Error deleting file {ZIP_FILE}: {e}")
# for zip
for i in zip_file[:]:
    print(i)
    unzip(str(i))
for i in _7zip_file[:]:
    print(i)
    unzip(str(i))

excute_win_file =[]
for root, dirs, files in os.walk("."):
    for file_name in files:
        # print(file_name.endswith(".exe"))
        if file_name.endswith(".exe"):
            full_file_path = os.path.join(root, file_name)
            excute_win_file.append(full_file_path)
            print(full_file_path)

print((excute_win_file))

# smb-nt7kaalt.exe , 
# Mh.exe,,,,,,,,,,,,,,,,,,,,,,,
# Mh1.exe,,,,,,,,,,,,,,,,,,,,,,,
# Mh2.exe,,,,,,,,,,,,,,,,,,,,,,,
# bx89.exe,,,,,,,,,,,,,,,,,,,,,,,