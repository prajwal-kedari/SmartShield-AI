import webview
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
html_file = os.path.join(BASE_DIR, "Interface/welcom_me.html")

webview.create_window(
    'SmartShild-AI',   
    url=f'file://{html_file}',       
    width=1080,               
    height=630,              
    # resizable=False,
)

webview.start()
