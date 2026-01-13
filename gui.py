import tkinter as tk
import threading
from packet_sniffer import start_sniffing
from logger import fetch_attacks
from config import GUI_REFRESH_INTERVAL

def start_monitoring():
    status_label.config(text="Monitoring Active", fg="green")
    threading.Thread(target=start_sniffing, daemon=True).start()

def refresh_logs():
    log_box.delete(0, tk.END)
    for ip, attack, time in fetch_attacks():
        color = "red" if "DoS" in attack else "orange"
        log_box.insert(tk.END, f"{time} | {ip} | {attack}")
        log_box.itemconfig(tk.END, fg=color)
    root.after(GUI_REFRESH_INTERVAL, refresh_logs)

root = tk.Tk()
root.title("Network Attack Detection System")
root.geometry("850x500")

tk.Label(root, text="Real-Time Network Attack Detection",
         font=("Arial", 18, "bold")).pack(pady=10)

status_label = tk.Label(root, text="Idle", fg="blue", font=("Arial", 12))
status_label.pack()

tk.Button(root, text="Start Monitoring",
          font=("Arial", 11),
          command=start_monitoring).pack(pady=5)

log_box = tk.Listbox(root, width=120, height=20)
log_box.pack(pady=10)

refresh_logs()
root.mainloop()
