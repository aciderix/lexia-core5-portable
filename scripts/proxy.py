#!/usr/bin/env python3
"""
HTTPS Proxy for Lexia Core5 AMFPHP.
Handles SSL on port 443 and forwards all requests to PHP on port 8080.
Does NOT touch the AMF content - PHP/AMFPHP handles all encoding.
"""
import http.server
import ssl
import os
import subprocess
import datetime
import urllib.request

LOG_FILE = "C:\\amf-log.txt"

def log(msg):
    ts = datetime.datetime.now().isoformat()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")
    print(f"[{ts}] {msg}", flush=True)

def generate_self_signed_cert():
    cert_dir = "C:\\certs"
    os.makedirs(cert_dir, exist_ok=True)
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "365", "-nodes",
        "-subj", "/CN=student.mylexia.com",
        "-addext", "subjectAltName=DNS:student.mylexia.com,DNS:localhost"
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        log("Generated self-signed cert for student.mylexia.com")
        return cert_file, key_file
    except Exception as e:
        log(f"Failed to generate cert: {e}")
        return None, None

PHP_BACKEND = "http://127.0.0.1:8080/index.php"

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        log(f"=== PROXY: POST {self.path} ({content_length} bytes) -> {PHP_BACKEND} ===")
        
        # Forward to PHP/AMFPHP backend
        req = urllib.request.Request(
            PHP_BACKEND,
            data=post_data,
            headers={
                'Content-Type': self.headers.get('Content-Type', 'application/x-amf'),
                'Content-Length': str(content_length),
            },
            method='POST'
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                res_data = response.read()
                self.send_response(200)
                self.send_header('Content-Type', response.headers.get('Content-Type', 'application/x-amf'))
                self.send_header('Content-Length', len(res_data))
                self.end_headers()
                self.wfile.write(res_data)
                log(f"  PHP responded: {len(res_data)} bytes, type={response.headers.get('Content-Type')}")
                log(f"  Response hex (first 100): {res_data[:100].hex()}")
        except urllib.error.URLError as e:
            log(f"  PHP ERROR: {e}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b'Proxy error: PHP backend unavailable')
        except Exception as e:
            log(f"  PROXY ERROR: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Proxy error: {e}'.encode())
    
    def do_GET(self):
        log(f"PROXY: GET {self.path}")
        resp = b'{"status":"ok","proxy":"running"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(resp))
        self.end_headers()
        self.wfile.write(resp)
    
    def log_message(self, format, *args):
        pass

def main():
    with open(LOG_FILE, "w") as f:
        f.write(f"HTTPS Proxy starting at {datetime.datetime.now().isoformat()}\n")
    
    log("HTTPS Proxy (443 -> PHP 8080) starting...")
    cert_file, key_file = generate_self_signed_cert()
    
    if cert_file and os.path.exists(cert_file) and os.path.exists(key_file):
        log(f"Using cert: {cert_file}")
        try:
            subprocess.run(["certutil", "-addstore", "-f", "Root", cert_file],
                         check=True, capture_output=True)
            log("Cert installed in Windows Root trust store")
        except Exception as e:
            log(f"Cert install warning: {e}")
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server = http.server.HTTPServer(('0.0.0.0', 443), ProxyHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        log("Proxy listening on https://0.0.0.0:443 -> http://127.0.0.1:8080")
        server.serve_forever()
    else:
        log("ERROR: Could not generate SSL certificate.")
        sys.exit(1)

if __name__ == "__main__":
    main()
