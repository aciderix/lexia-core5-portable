#!/usr/bin/env python3
"""
HTTPS Proxy for Lexia Core5 AMFPHP.
Handles SSL on port 443 and forwards AMF requests to PHP on port 8080.
Also serves static content files (MP3, SWF, XML) from the local filesystem.
"""
import http.server
import ssl
import os
import sys
import subprocess
import datetime
import urllib.request
import mimetypes
import urllib.parse

LOG_FILE = "C:\\amf-log.txt"
CONTENT_ROOT = "C:\\Program Files (x86)\\Lexia Core5"

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

# AMFPHP 2.x gateway - index.php is in the Amfphp subdirectory
PHP_BACKEND = "http://127.0.0.1:8080/Amfphp/index.php"

# MIME types for content files
MIME_OVERRIDES = {
    '.mp3': 'audio/mpeg',
    '.swf': 'application/x-shockwave-flash',
    '.xml': 'application/xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
}

CROSSDOMAIN_XML = (
    b'<?xml version="1.0"?>\n'
    b'<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n'
    b'<cross-domain-policy>\n'
    b'  <allow-access-from domain="*" headers="*" secure="false" />\n'
    b'  <site-control permitted-cross-domain-policies="all" />\n'
    b'</cross-domain-policy>\n'
)

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, HEAD')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        log(f"=== PROXY: POST {self.path} ({content_length} bytes) -> {PHP_BACKEND} ===")
        
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
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(res_data)
                log(f"  PHP responded: {len(res_data)} bytes, type={response.headers.get('Content-Type')}")
                log(f"  Response hex (first 100): {res_data[:100].hex()}")
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='replace') if e.fp else ''
            log(f"  PHP HTTP ERROR {e.code}: {e.reason}")
            log(f"  PHP error body: {error_body[:500]}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b'Proxy error: PHP backend error')
        except urllib.error.URLError as e:
            log(f"  PHP URL ERROR: {e}")
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b'Proxy error: PHP backend unavailable')
        except Exception as e:
            log(f"  PROXY ERROR: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Proxy error: {e}'.encode())
    
    def do_GET(self, head_only=False):
        log(f"=== PROXY: GET {self.path} ===")
        
        # Parse the path
        parsed = urllib.parse.urlparse(self.path)
        req_path = urllib.parse.unquote(parsed.path)
        
        # Flash crossdomain.xml request
        if req_path in ('/crossdomain.xml', 'crossdomain.xml'):
            log("  Serving crossdomain.xml for Flash Security Policy")
            self.send_response(200)
            self.send_header('Content-Type', 'text/x-cross-domain-policy')
            self.send_header('Content-Length', str(len(CROSSDOMAIN_XML)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if not head_only:
                self.wfile.write(CROSSDOMAIN_XML)
            return

        # Skip AMF gateway requests
        if req_path.startswith('/clientapi/'):
            resp = b'{"status":"ok","proxy":"running"}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(resp)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if not head_only:
                self.wfile.write(resp)
            return
        
        # Try to serve content files from the local filesystem
        clean_path = req_path[1:] if req_path.startswith('/') else req_path
        file_path = os.path.join(CONTENT_ROOT, clean_path.replace('/', '\\'))
        
        if not os.path.isfile(file_path):
            appdata = os.environ.get('APPDATA', '')
            if appdata:
                appdata_path = os.path.join(appdata, 'com.lexiareading.core5.desktop.us', 'Local Store', clean_path.replace('/', '\\'))
                if os.path.isfile(appdata_path):
                    file_path = appdata_path

        if not os.path.isfile(file_path):
            filename = os.path.basename(clean_path)
            if filename:
                for search_base in [CONTENT_ROOT, os.environ.get('APPDATA', '')]:
                    if search_base and os.path.exists(search_base):
                        for root, dirs, files in os.walk(search_base):
                            if filename in files:
                                file_path = os.path.join(root, filename)
                                log(f"  Found file via recursive search: {file_path}")
                                break
                        if os.path.isfile(file_path):
                            break
        
        ext = os.path.splitext(clean_path)[1].lower()
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                content_type = MIME_OVERRIDES.get(ext, mimetypes.guess_type(file_path)[0] or 'application/octet-stream')
                
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(file_data)))
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                if not head_only:
                    self.wfile.write(file_data)
                log(f"  Served file: {file_path} ({len(file_data)} bytes, {content_type})")
            except Exception as e:
                log(f"  File serve error: {e}")
                self.send_response(500)
                self.end_headers()
                if not head_only:
                    self.wfile.write(f'File serve error: {e}'.encode())
        elif ext == '.mp3':
            log(f"  Missing MP3 file ({req_path}) - serving silent MP3 fallback")
            # Minimal 1-frame valid MP3 silence buffer (MPEG-1 Layer 3, 128 kbps, 44.1 kHz, stereo)
            silent_mp3 = b'\xff\xfb\x90\xc4' + b'\x00' * 413
            self.send_response(200)
            self.send_header('Content-Type', 'audio/mpeg')
            self.send_header('Content-Length', str(len(silent_mp3)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if not head_only:
                self.wfile.write(silent_mp3)
        else:
            log(f"  File not found: {file_path}")
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if not head_only:
                self.wfile.write(b'Not found')
    
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
        log("Proxy listening on https://0.0.0.0:443 -> " + PHP_BACKEND)
        server.serve_forever()
    else:
        log("ERROR: Could not generate SSL certificate.")
        sys.exit(1)

if __name__ == "__main__":
    main()
