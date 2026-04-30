"""
Simple HTTP server for the AI Log Monitor Dashboard.
Run: python serve_dashboard.py
Then open: http://localhost:8000
"""
import http.server
import socketserver
import os
import webbrowser
import threading

PORT = 8000
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # quiet mode

def open_browser():
    import time; time.sleep(0.5)
    webbrowser.open(f"http://localhost:{PORT}/dashboard/index.html")

print(f"AI Log Monitor Dashboard")
print(f"  URL : http://localhost:{PORT}/dashboard/index.html")
print(f"  Data: data/monitoring_output.json (auto-reloaded every 60s)")
print(f"  Stop: Ctrl+C\n")

threading.Thread(target=open_browser, daemon=True).start()
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
