import subprocess
import os
import ctypes 


global process 
process= None  # global reference

def start_pm():
    global process
    
    cmd = r'/k cd /d "C:\Project\SmartShield-AI" && python -m dynamic.process_monitor'
    
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",              # 🔥 triggers UAC
        "cmd.exe",            # program
        cmd,                  # arguments
        None,
        1                     # show window
    )
def stop_pm():
    global process

    subprocess.run(
        'taskkill /F /IM cmd.exe /FI "WINDOWTITLE eq dynamic.process_monitor*"',
        shell=True
    )
    print("Force Stopped")

# start_pm()
