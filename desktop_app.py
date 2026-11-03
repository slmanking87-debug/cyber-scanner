"""Tkinter desktop interface using the same scanner.py engine as the website."""
import os
import tkinter as tk
from tkinter import ttk
from scanner import scan_input, save_history, HISTORY_FILE


def scan():
    value = entry.get().strip()
    result_data = scan_input(value)
    if result_data["kind"] == "invalid":
        result_label.config(text=result_data["details"], fg="orange")
        return

    save_history(value, result_data)
    lines = [result_data["details"]]
    if result_data.get("ip"):
        lines.insert(0, "عنوان IP: " + result_data["ip"])
    if result_data.get("risk"):
        lines.insert(1, "مستوى الخطورة: " + result_data["risk"])
    if result_data.get("reasons"):
        lines.append("المؤشرات:\n• " + "\n• ".join(result_data["reasons"]))
    color = {"مرتفع": "red", "متوسط": "darkorange", "منخفض": "green"}.get(result_data.get("risk"), "green")
    result_label.config(text="\n\n".join(lines), fg=color)


def clear():
    entry.delete(0, tk.END)
    result_label.config(text="نتيجة الفحص ستظهر هنا", fg="black")


def open_history():
    if os.path.exists(HISTORY_FILE):
        os.startfile(os.path.abspath(HISTORY_FILE))
    else:
        result_label.config(text="لا يوجد سجل بعد. نفّذ فحصًا أولًا.", fg="blue")


window = tk.Tk()
window.title("نظام كشف الروابط والمواقع المشبوهة")
window.geometry("720x560")
window.resizable(False, False)

ttk.Label(window, text="نظام كشف الروابط والمواقع المشبوهة", font=("Arial", 18, "bold")).pack(pady=25)
ttk.Label(window, text="أدخل رابط موقع أو بريدًا إلكترونيًا لفحصه", font=("Arial", 12)).pack(pady=10)
entry = ttk.Entry(window, width=60, font=("Arial", 12))
entry.pack(pady=15)
ttk.Button(window, text="فحص الآن", command=scan).pack(pady=8)
ttk.Button(window, text="مسح", command=clear).pack(pady=5)
ttk.Button(window, text="فتح سجل الفحوصات", command=open_history).pack(pady=5)
result_label = tk.Label(window, text="نتيجة الفحص ستظهر هنا", font=("Arial", 11), wraplength=640, justify="center")
result_label.pack(pady=22)

window.mainloop()
