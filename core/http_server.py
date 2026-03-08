"""
HTTP Server for Dashboard - Serves from project root
"""
import http.server
import socketserver
import os
import threading
from pathlib import Path

def serve_dashboard_http(port=9000):
    """Serve dashboard from project root"""
    
    # Change to project root
    project_root = Path(__file__).parent.parent
    os.chdir(str(project_root))
    
    class CustomHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress logs
        
        def end_headers(self):
            # Add CORS headers
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
            super().end_headers()
    
    try:
        with socketserver.TCPServer(("", port), CustomHandler) as httpd:
            print(f"[+] Dashboard server: http://localhost:{port}/reports/acase_dashboard_complete.html")
            httpd.serve_forever()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {port} already in use - dashboard may already be running")
        else:
            print(f"[!] Server error: {e}")

def start_dashboard_server():
    """Start server in background thread"""
    thread = threading.Thread(target=serve_dashboard_http, daemon=True)
    thread.start()
