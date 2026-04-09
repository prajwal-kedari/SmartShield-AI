import webview
import os
from tkinter import filedialog
from static.main import static_checker
# class Api:
#     def buttonunderscoreclick(self,a):
#         print("hello",a)
#         return "scanned"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Api:
    def __init__(self):
        # Initialize scanning engines as None (you can set them later)
        self.vt = None
        self.mb = None
        self.cust = None
        self.ember = None

    # pywebweb.api.select_files()
    def select_files(self):
        Files = filedialog.askopenfilenames(title="Select Python", filetypes=[("EXE Files", "*.exe"), ("All Files", "*.*")])
        print("Selected files:", Files)
        return Files
    def start_scan(self,vt,mb,cust,ember):
        self.vt = vt
        self.mb = mb
        self.cust = cust
        self.ember = ember
        print(f"Start Scaning......\nvt:{vt},mb:{mb},cust:{cust},ember:{ember}")
    def fileScanner(self,filepath):
        pred_value= static_checker(filepath.get("path"),self.vt,self.mb,self.cust,self.ember)
        print(filepath,"============================================================>",pred_value)
        if(pred_value.get("vt",[0,0])[1] or pred_value.get("mb",[0,0])[0] or pred_value.get("cust",[0,0])[0] or pred_value.get("ember",[0,0])[0]):
            return "Malicious"
        else:
            return "Clean"


api = Api()
html_file = os.path.join(BASE_DIR, "Interface/main_ui.html")
if __name__ == '__main__':
    # Create the pywebview window
    # The second argument is the URL. 
    # 'index.html' is a relative URL that pywebview will find.
    webview.create_window(
        'SmartShild-AI',   # Window title
        url=f'file://{html_file}',        # The URL to the local HTML file
        width=980,               # Window width
        height=630,              # Window height
        resizable=False,js_api=api        # Lock the window size for a clean look
    )
    webview.start()
    
def warning_ui():

    html_file = os.path.abspath("interface/warning.html")
    webview.create_window(
    'SmartShild-AI',   # Window title
        url=f'file://{html_file}',        # The URL to the local HTML file
    width=980,               # Window width
    height=630,              # Window height
    resizable=False)       # Lock the window size for a clean look
    webview.start()
