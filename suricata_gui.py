import json
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import time
import os

# Suricata log file
EVE_FILE = "/var/log/suricata/eve.json"

SEVERITY_MAP = {
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW"
}


class SuricataMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Suricata IDS Dashboard")
        self.root.geometry("1000x600")

        self.alert_count = 0

        self.stats_label = tk.Label(
            root,
            text="Total Alerts: 0",
            font=("Arial", 12, "bold")
        )
        self.stats_label.pack(pady=5)

        self.log_box = ScrolledText(root, wrap=tk.WORD)
        self.log_box.pack(fill=tk.BOTH, expand=True)

        self.log_box.tag_config("CRITICAL", foreground="red")
        self.log_box.tag_config("HIGH", foreground="orange")
        self.log_box.tag_config("MEDIUM", foreground="blue")
        self.log_box.tag_config("LOW", foreground="green")

        threading.Thread(
            target=self.monitor_eve,
            daemon=True
        ).start()

    def add_alert(self, text, severity_name):
        self.log_box.insert(tk.END, text, severity_name)
        self.log_box.see(tk.END)

        self.alert_count += 1
        self.stats_label.config(
            text=f"Total Alerts: {self.alert_count}"
        )

    def monitor_eve(self):
        while not os.path.exists(EVE_FILE):
            time.sleep(2)

        with open(EVE_FILE, "r") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.2)
                    continue

                try:
                    data = json.loads(line)

                    if data.get("event_type") != "alert":
                        continue

                    timestamp = data.get("timestamp", "Unknown")

                    src_ip = data.get("src_ip", "Unknown")
                    dest_ip = data.get("dest_ip", "Unknown")

                    proto = data.get("proto", "Unknown")

                    signature = (
                        data.get("alert", {})
                        .get("signature", "Unknown Alert")
                    )

                    severity = (
                        data.get("alert", {})
                        .get("severity", 3)
                    )

                    severity_name = SEVERITY_MAP.get(
                        severity,
                        "MEDIUM"
                    )

                    alert_text = (
                        f"\n[{severity_name}] "
                        f"{timestamp}\n"
                        f"Protocol : {proto}\n"
                        f"Source   : {src_ip}\n"
                        f"Destination : {dest_ip}\n"
                        f"Alert    : {signature}\n"
                        f"{'-'*60}\n"
                    )

                    self.root.after(
                        0,
                        lambda t=alert_text,
                        s=severity_name:
                        self.add_alert(t, s)
                    )

                except Exception as e:
                    print("Error:", e)


if __name__ == "__main__":
    root = tk.Tk()
    app = SuricataMonitor(root)
    root.mainloop()
