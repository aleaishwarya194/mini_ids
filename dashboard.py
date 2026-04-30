from flask import Flask, jsonify, render_template
from threading import Thread
from sniffer import start_sniffer, get_recent_packets
from ids_engine import detect_intrusion, get_recent_alerts
import time

app = Flask(__name__)

# global traffic data for chart
traffic_stats = []

def track_traffic():
    """Counts packets every few seconds for chart visualization."""
    while True:
        count = len(get_recent_packets())
        traffic_stats.append({"time": time.strftime("%H:%M:%S"), "count": count})
        if len(traffic_stats) > 30:  # keep last 30 data points
            traffic_stats.pop(0)
        time.sleep(3)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/data")
def data():
    return jsonify(get_recent_packets())

@app.route("/alerts")
def alerts():
    return jsonify(get_recent_alerts())

@app.route("/traffic")
def traffic():
    return jsonify(traffic_stats)

if __name__ == "__main__":
    # Run background threads
    sniffer_thread = Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    traffic_thread = Thread(target=track_traffic, daemon=True)
    traffic_thread.start()

    print("🚀 IDS Dashboard running at http://127.0.0.1:5000")
    app.run(debug=True)
