import webview
import os

class Api:
    def button_clicked(self):
        print("Button was clicked from JavaScript!")

api=Api()
# Path to your dashboard HTML file
html_file = os.path.abspath("interface/index.html")

# Create a desktop window
window = webview.create_window(
    title="SecureGuard Pro",
    url=f"file://{html_file}",
    width=1324,
    height=675,
    resizable=False
,js_api=api)

# Start webview
webview.start()
