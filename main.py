import json

import webview
import os
from tkinter import filedialog
from static.main import static_checker, Remote_Server_EngineA
from dynamic.Helper.sysmon.Controller_Sysmon import start_sysmon, is_sysmon_running, stop_sysmon
from dynamic.control_Procee_Monitor import start_pm, stop_pm


# set cwh to project root dir 
os.chdir(os.path.dirname(os.path.abspath(__file__)))
data = json.load(open("SaveControl.json","r"))
# from dynamic.process_monitor import ProcessMonitor
# ProcessMonitor()

class Api:
    def __init__(self,data=None):
        self.data = data
        # Initialize scanning engines as None (you can set them later)
        self.vt = None
        self.mb = None
        self.cust = None
        self.ember = None
        self.ai_engine_local = False
        self.ai_engine_server_api = None
        self.real_time_protection_enabled = False
        self.CIC2v = None
        self.MALm = None

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
        if data.AIEngine :
            print("Running AI Engine for file analysis...")
            pred_value = Remote_Server_EngineA(filepath.get("path"),self.vt,self.mb,self.cust,self.ember,data.AIEngineServerApi)
            print("AI Engine Result:", pred_value)
        else :
             pred_value= static_checker(filepath.get("path"),self.vt,self.mb,self.cust,self.ember)
        print(filepath,"============================================================>",pred_value)
        if(pred_value.get("vt",[0,0])[1] or pred_value.get("mb",[0,0])[0] or pred_value.get("cust",[0,0])[0] or pred_value.get("ember",[0,0])[0]):
            return "Malicious"
        else:
            return "Clean"
    def AiEngine(self,LocalRun: bool,  ServerApi: str  =None):
        if LocalRun:
            data["AIEngine"] = True
            json.dump(data, open("SaveControl.json","w"),indent=4)
            print("Running AI Engine Locally...")
            # Implement local AI engine logic here
            return "AI Engine running locally"
        elif ServerApi:
            data["AIEngine"] = True
            data["AIEngineServerApi"] = ServerApi
            json.dump(data, open("SaveControl.json","w"),indent=4)

            print(f"Connecting to AI Engine at {ServerApi}...")
            # Implement server API connection logic here
            return f"Connected to AI Engine at {ServerApi}"
        else:
            print("No AI Engine configuration provided.")
            data["AIEngine"] = False
            data["AIEngineServerApi"] = None
            json.dump(data, open("SaveControl.json","w"),indent=4)
            return "No AI Engine configuration provided."

    def RealTimeProtection(self, enable: bool):
        # apply on changes on ui 
        if enable:
            print("Real-time protection enabled.")
            data["RealTimeProtection"] = True
            json.dump(data, open("SaveControl.json","w"),indent=4)
            start_sysmon()
            return "Real-time protection enabled"
        else:
            print("Real-time protection disabled.")
            data["RealTimeProtection"] = False
            json.dump(data, open("SaveControl.json","w"),indent=4)
            stop_sysmon()
            return "Real-time protection disabled"
    def onChangeBtn(self,CIC2v,MALm):
        self.CIC2v = CIC2v
        # data["gate1"]=bool(CIC2v)
        data["gate2"]=bool(CIC2v)
        self.MALm = MALm
        if(CIC2v):
            start_pm()
        else:
            stop_pm()
        print(f"CIC2v set to: {CIC2v}, MALm set to: {MALm}")
    def get_url_data(self):
        return self.data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SmartShieldapi = Api()
html_file = os.path.join(BASE_DIR, "Interface/SmartShield.html")
if __name__ == '__main__':

    webview.create_window(
        'SmartShild-AI',   
        url=f'file://{html_file}',       
        width=1080,               
        height=630,              
        # resizable=False,
        js_api=SmartShieldapi        
    )
    webview.start()



