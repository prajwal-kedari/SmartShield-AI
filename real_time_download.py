import time
import os
from datetime import datetime
from watchdog.observers import Observer
from static.main import static_checker
from watchdog.events import FileSystemEventHandler
import webview

# 📂 Folder to watch (change if needed)
WATCH_FOLDER = os.path.expanduser("~/Downloads")
LOG_FILE = "file_download_log.txt"

# ❌ Temporary extensions to ignore
TEMP_EXTENSIONS = (".crdownload", ".tmp", ".part")

class DownloadHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            file_name = os.path.basename(file_path)

            # Ignore temporary download files
            if file_name.lower().endswith(TEMP_EXTENSIONS):
                return

            # Wait until file finishes writing
            time.sleep(2)
            self.log_final_file(file_path, file_name)

    def on_moved(self, event):
        """Detect when temp file is renamed to real file"""
        if not event.is_directory:
            final_name = os.path.basename(event.dest_path)
            if not final_name.lower().endswith(TEMP_EXTENSIONS):
                self.log_final_file(event.dest_path, final_name)

    def log_final_file(self, path, name):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("\n==============================")
        print(f"📁 New File Detected: {name}")
        print(f"🕒 Time: {timestamp}")
        print(f"📍 Location: {path}")
        if path.endswith(".exe"):
            pred_value=static_checker(path,1,1,0,0)
            if(pred_value.get("vt",[0,0])[1] or pred_value.get("mb",[0,0])[0] or pred_value.get("cust",[0,0])[0] or pred_value.get("ember",[0,0])[0]):
                print("Malware")
                # import main_ui
                # main_ui.warning_ui()
        else:
            print( "Clean")
            
        print("==============================")

        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(f"[{timestamp}] {name} | {path}\n")

def monitor_folder():
    event_handler = DownloadHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_FOLDER, recursive=False)
    observer.start()

    print(f"👀 Monitoring started on: {WATCH_FOLDER}")
    print("Waiting for new files...\n")

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
        print("\n🛑 Monitoring stopped.")
    observer.join()

if __name__ == "__main__":
    monitor_folder()

