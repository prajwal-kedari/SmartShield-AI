import webview
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))



class Api:
    def __init__(self,data=None):
        self.data = data
    def Send_Data(self):
        return self.data


# url_threat_ui(data)
def url_threat_ui(data):
    api = Api(data)
    webview.create_window(
        'SmartShild-AI',   
        url=f'file://{os.path.join(BASE_DIR, "Interface/url_threat.html")}',       
        width=980,               
        height=630,              
        # resizable=False,
        js_api=api        
    )

    webview.start()

def file_threat_ui(data):
    api = Api(data)
    webview.create_window(
        'SmartShild-AI',   
        url=f'file://{os.path.join(BASE_DIR, "Interface/file_threat.html")}',       
        width=980,               
        height=630,              
        # resizable=False,
        js_api=api        
    )
    webview.start()
def live_behaviour_ui(data):
    api = Api(data)
    webview.create_window(
        'SmartShild-AI',   
        url=f'file://{os.path.join(BASE_DIR, "Interface/live_behaviour.html")}',       
        width=980,               
        height=630,              
        # resizable=False,
        js_api=api        
    )
    webview.start()
# data = {
#     "url": "win-prize-dddddnow.com",
#     "malicious": 3,
#     "suspicious": 2,
#     "undetected": 31,
#     "harmless": 58,
#     "timeout": 0,
#     "risk": "Medium"
# }

data ={
            "time": "2026-04-09T21:01:12",
            "pid": 1122,
            "path": "C:\\Users\\Prajwal\\OneDrive\\Desktop\\360sb.exe",
            "prob": 50.0,
            "threshold":0.55
            }
# data ={'fileName': '123.exe', 'filePath': 'C:\\Users\\Prajwal\\OneDrive\\Desktop\\123.exe', 'vt': "false", 'vtScore': 'True/62', 'malwareDb': "false", 'family': 'None', 'custom': "false" , 'ember': "false", 'emberScore': 7.0, 'prob': '50'}
# data ={'fileName': '360sb.exe', 'filePath': 'C:\\Users\\Prajwal\\OneDrive\\Desktop\\360sb.exe', 'vt': 'true', 'vtScore': '75/True', 'malwareDb': 0, 'family': 'None', 'custom': '1', 'ember': '1', 'emberScore': 0.6992049004297671, 'prob': '69.92'}
# url_threat_ui(data)
# url_threat_ui(data)
# file_threat_ui(data)
# live_behaviour_ui(data)

