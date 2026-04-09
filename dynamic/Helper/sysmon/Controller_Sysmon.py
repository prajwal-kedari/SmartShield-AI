import ctypes
import subprocess
import time
import os
base_dir = os.getcwd()  # current project root

exe_path = os.path.abspath(
    os.path.join(base_dir, "dynamic", "Helper", "sysmon", "Sysmon64.exe")
)

config_path = os.path.abspath(
    os.path.join(base_dir, "dynamic", "Helper", "sysmon", "sysmonconfig-dev.xml")
)
def start_sysmon():
   

    # PowerShell command → run Sysmon + save output
    ps_command = (
        f'-NoProfile -ExecutionPolicy Bypass -Command '
        f'"& \'{exe_path}\' -accepteula -i \'{config_path}\' '
        # f'*> \'{output_file}\'"'
    )

    # Run as admin (UAC)
    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        "powershell.exe",
        ps_command,
        None,
        0  # hidden window (fast)
    )


def is_sysmon_running():
    try:
        result = subprocess.run(
            ["sc.exe", "query", "Sysmon64"],
            capture_output=True,
            text=True
        )

        if "RUNNING" in result.stdout:
            return True
        elif "STOPPED" in result.stdout:
            return False
        else:
            return False  # service not found / not installed

    except Exception as e:
        print("Error:", e)
        return False

def stop_sysmon():
    exe_path = os.path.abspath(
        os.path.join("dynamic", "Helper", "sysmon", "Sysmon64.exe")
    )

    ps_command = (
        f'-NoProfile -ExecutionPolicy Bypass -Command '
        f'"& \'{exe_path}\' -u"'
    )

    ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",   # UAC popup
        "powershell.exe",
        ps_command,
        None,
        0
    )
if __name__ == "__main__":
    start_sysmon()
    print("Sysmon started. Waiting for it to initialize...")
    time.sleep(5)  # wait for Sysmon to start
    if is_sysmon_running():
        print("Sysmon is running.")
    else:
        print("Sysmon failed to start.")
    # stop_sysmon()
    # print("Sysmon stopped.")
    if not is_sysmon_running():
        print("Sysmon is stopped.")
    print(is_sysmon_running())