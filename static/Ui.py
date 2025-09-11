import tkinter as tk
from tkinter import filedialog

import sys
import io

# Reconfigure stdout to UTF-8
# sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def CheckMal():
    import main
    main.work_step(file_path)

def browse_file():
    global file_path
    file_path = filedialog.askopenfilename()  # opens file dialog
    if file_path:  # if a file was selected
        entry.delete(0, tk.END)
        entry.insert(0, file_path)
    checker = tk.Button(root, text="Continue", command=CheckMal)
    checker.pack()
    

# Create main window
root = tk.Tk()
root.title("File Selector")
root.geometry("400x120")

# Entry to show file path
entry = tk.Entry(root, width=50)
entry.pack(pady=10)

# Button to browse files
browse_button = tk.Button(root, text="Browse File", command=browse_file)
browse_button.pack()

# Start GUI loop
root.mainloop()
