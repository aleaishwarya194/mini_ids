from datetime import datetime
import random

alerts = []

def detect_intrusion(packet):
    # Example detection rule: flag local broadcast or suspicious IP
    if packet["dst"].startswith("255.") or random.random() < 0.01:
        alerts.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "alert": f"Suspicious activity detected from {packet['src']}"
        })
        if len(alerts) > 50:
            alerts.pop(0)

def get_recent_alerts():
    return alerts[-10:]
