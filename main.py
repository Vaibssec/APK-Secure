import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from analyzer import analyze_apk


def select_apk():
    file_path = filedialog.askopenfilename(
        title="Select APK File",
        filetypes=[
            ("Android APK files", "*.apk"),
            ("All files", "*.*")
        ]
    )

    if not file_path:
        return

    try:
        result = analyze_apk(file_path)

        output.delete("1.0", tk.END)

        output.insert(tk.END, "APK-SECURE ANALYSIS REPORT\n")
        output.insert(tk.END, "=" * 45 + "\n\n")

        output.insert(tk.END, f"Application Name : {result['app_name']}\n")
        output.insert(tk.END, f"Package Name     : {result['package_name']}\n")
        output.insert(tk.END, f"Version          : {result['version']}\n\n")

        output.insert(tk.END, "SHA-256 HASH\n")
        output.insert(tk.END, "-" * 45 + "\n")
        output.insert(tk.END, f"{result['sha256']}\n\n")

        output.insert(tk.END, "SUSPICIOUS PERMISSIONS\n")
        output.insert(tk.END, "-" * 45 + "\n")

        if result["suspicious_permissions"]:
            for permission in result["suspicious_permissions"]:
                output.insert(tk.END, f"• {permission}\n")
        else:
            output.insert(tk.END, "No suspicious permissions detected.\n")

        output.insert(tk.END, "\n")

        output.insert(tk.END, "RISK ASSESSMENT\n")
        output.insert(tk.END, "-" * 45 + "\n")
        output.insert(
            tk.END,
            f"Risk Score : {result['risk_score']}/100\n"
        )
        output.insert(
            tk.END,
            f"Verdict    : {result['verdict']}\n"
        )

        output.insert(tk.END, "\n")
        output.insert(tk.END, "NOTE:\n")
        output.insert(
            tk.END,
            "This tool performs static APK analysis. "
            "Suspicious permissions alone do not confirm malware."
        )

    except Exception as error:
        messagebox.showerror(
            "Analysis Error",
            f"Unable to analyze APK.\n\n{error}"
        )


# Create application window
root = tk.Tk()
root.title("APK-Secure – Android Malware Analysis Tool")
root.geometry("800x600")

title = tk.Label(
    root,
    text="APK-SECURE",
    font=("Arial", 22, "bold")
)
title.pack(pady=15)

subtitle = tk.Label(
    root,
    text="Static Android APK Malware Analysis Tool",
    font=("Arial", 11)
)
subtitle.pack(pady=5)

select_button = tk.Button(
    root,
    text="Select APK and Analyze",
    command=select_apk,
    font=("Arial", 12, "bold"),
    padx=20,
    pady=10
)
select_button.pack(pady=15)

output = ScrolledText(
    root,
    width=90,
    height=25,
    font=("Consolas", 10)
)
output.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()