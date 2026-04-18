import os
import sys
import subprocess

PROJECT_PATH = r"C:\Project\SmartShield-AI"
REPO_URL = "https://github.com/prajwal-kedari/SmartShield-AI.git"

def install_project():
    print(" Cloning project...")
    
    if not os.path.exists(PROJECT_PATH):
        subprocess.run(["git", "clone", REPO_URL, PROJECT_PATH])
    else:
        print(" Project already exists")

def install_requirements():
    print(" Installing requirements...")
    
    subprocess.run([
        "python", "-m", "pip", "install", "-r",
        os.path.join(PROJECT_PATH, "requirements.txt")
    ])

def create_shortcut():
    print("Creating desktop shortcut...")

    import winshell
    from win32com.client import Dispatch

    desktop = winshell.desktop()
    shortcut_path = os.path.join(desktop, "SmartShield AI.lnk")

    target = sys.executable  # python.exe
    print("Python executable:", target)
    print("Python executable:", target)
    target = "python"
    script = os.path.join(PROJECT_PATH, "main.py")
    icon = os.path.join(PROJECT_PATH, "Interface", "icon.ico")  
    print("Script path:", icon)
    shell = Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(shortcut_path)

    shortcut.Targetpath = target
    shortcut.Arguments = f'"{script}"'
    shortcut.WorkingDirectory = PROJECT_PATH
    shortcut.IconLocation = icon

    shortcut.save()

def run_project():
    print(" Launching SmartShield AI...")
    print([sys.executable,  "python C:\\Project\\SmartShield-AI\\welcome.py"])
    subprocess.Popen(
        ["python",  "C:\\Project\\SmartShield-AI\\welcome.py"],
        cwd=PROJECT_PATH
    )

def main():
    install_project()
    install_requirements()
    create_shortcut()
    run_project()

if __name__ == "__main__":
    main()