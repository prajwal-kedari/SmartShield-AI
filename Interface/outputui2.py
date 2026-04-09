import webview

if __name__ == '__main__':
    # Create the pywebview window
    # The second argument is the URL. 
    # 'index.html' is a relative URL that pywebview will find.
    webview.create_window(
        'SmartShild-AI',   # Window title
        url='output1.html',      # The URL to the local HTML file
        # url="SmartShield.html",
        width=980,               # Window width
        height=630,              # Window height
        # resizable=False          # Lock the window size for a clean look
    )
    
    # Start the application
    webview.start()