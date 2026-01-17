import tkinter as tk
import threading
from packet_sniffer import start_sniffing, stop_sniffer
from logger import fetch_attacks
from config import GUI_REFRESH_INTERVAL

sniffing_thread = None
monitoring = False

def start_monitoring():
    global sniffing_thread, monitoring
    if monitoring:
        return  # 🔴 FIX: prevent multiple sniffers

    status_label.config(text="Monitoring Active", fg="green")
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()
    monitoring = True

def stop_monitoring():
    global monitoring
    stop_sniffer()
    status_label.config(text="Monitoring Stopped", fg="red")
    monitoring = False

def refresh_logs():
    log_box.delete(0, tk.END)
    attacks = fetch_attacks()
    total_label.config(text=f"Total Alerts: {len(attacks)}")

    for ip, attack, time in attacks:
        color = "red" if "HIGH" in attack else "orange"
        log_box.insert(tk.END, f"{time} | {ip} | {attack}")
        log_box.itemconfig(tk.END, fg=color)

    root.after(GUI_REFRESH_INTERVAL, refresh_logs)

root = tk.Tk()
root.title("Network Attack Detection System")
root.geometry("950x550")

tk.Label(root, text="Real-Time Network Attack Detection",
         font=("Arial", 18, "bold")).pack(pady=10)

status_label = tk.Label(root, text="Idle", fg="blue", font=("Arial", 12))
status_label.pack()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

tk.Button(btn_frame, text="▶ Start Monitoring",
          bg="green", fg="white",
          font=("Arial", 11),
          command=start_monitoring).pack(side=tk.LEFT, padx=10)

tk.Button(btn_frame, text="⏹ Stop Monitoring",
          bg="red", fg="white",
          font=("Arial", 11),
          command=stop_monitoring).pack(side=tk.LEFT, padx=10)

total_label = tk.Label(root, text="Total Alerts: 0", font=("Arial", 11))
total_label.pack(pady=5)

log_box = tk.Listbox(root, width=130, height=20)
log_box.pack(pady=10)

refresh_logs()
root.mainloop()
