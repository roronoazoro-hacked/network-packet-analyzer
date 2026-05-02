import csv
import os
from datetime import datetime


class PacketLogger:
    def __init__(self):
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename   = f"capture_{timestamp}.csv"
        self.path  = os.path.join("logs", filename)

        self.file   = open(self.path, "w", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(
            self.file,
            fieldnames=["time", "proto", "src", "dst", "dst_port",
                        "level", "info", "alert", "location"],
            extrasaction="ignore"   # ← silently ignore any extra fields
        )
        self.writer.writeheader()
        self.count = 0
        print(f"[*] Logging to: {self.path}\n")

    def log(self, packet_data):
        if packet_data:
            try:
                self.writer.writerow(packet_data)
                self.file.flush()
                self.count += 1
            except Exception:
                pass   # never let a log error kill the sniffer

    def close(self):
        self.file.close()
        print(f"\n[*] Capture complete. {self.count} packets saved to {self.path}")