#!/usr/bin/env python3
"""
Mock AMFPHP server for Lexia Core5.
Handles HTTPS AMF requests on port 443.
Logs all incoming data and returns minimal AMF responses.
"""
import http.server
import ssl
import os
import sys
import json
import struct
import datetime
import subprocess

LOG_FILE = "C:\\amf-log.txt"

def log(msg):
    ts = datetime.datetime.now().isoformat()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")
    print(f"[{ts}] {msg}", flush=True)

def generate_self_signed_cert():
    """Generate a self-signed SSL certificate for student.mylexia.com"""
    cert_dir = "C:\\certs"
    os.makedirs(cert_dir, exist_ok=True)
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    
    # Use openssl to generate the cert
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file,
        "-out", cert_file,
        "-days", "365",
        "-nodes",
        "-subj", "/CN=student.mylexia.com",
        "-addext", "subjectAltName=DNS:student.mylexia.com,DNS:localhost"
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        log(f"Generated self-signed cert for student.mylexia.com")
        return cert_file, key_file
    except Exception as e:
        log(f"Failed to generate cert with openssl: {e}")
        # Fallback: use Python's ssl module to generate a cert
        # This is a fallback - may not work perfectly
        try:
            # Try with PowerShell
            ps_cmd = f'''
            $cert = New-SelfSignedCertificate -DnsName "student.mylexia.com" -CertStoreLocation "Cert:\\LocalMachine\\My" -FriendlyName "Lexia Mock" -NotAfter (Get-Date).AddYears(1)
            $pwd = ConvertTo-SecureString -String "password" -Force -AsPlainText
            Export-PfxCertificate -Cert $cert -FilePath "{cert_dir}\\cert.pfx" -Password $pwd
            '''
            subprocess.run(["powershell", "-Command", ps_cmd], check=True, capture_output=True)
            log("Generated cert via PowerShell")
            return cert_file, key_file
        except Exception as e2:
            log(f"PowerShell cert generation also failed: {e2}")
            return None, None

# AMF parsing helpers
def parse_amf0(data, offset=0):
    """Parse a simple AMF0 value"""
    if offset >= len(data):
        return None, offset
    type_marker = data[offset]
    offset += 1
    
    if type_marker == 0x02:  # string
        length = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        value = data[offset:offset+length].decode('utf-8', errors='replace')
        offset += length
        return value, offset
    elif type_marker == 0x00:  # number
        value = struct.unpack(">d", data[offset:offset+8])[0]
        offset += 8
        return value, offset
    elif type_marker == 0x01:  # boolean
        value = data[offset] != 0
        offset += 1
        return value, offset
    elif type_marker == 0x03:  # object
        obj = {}
        while offset < len(data):
            key_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            if key_len == 0 and data[offset] == 0x09:  # end of object
                offset += 1
                break
            key = data[offset:offset+key_len].decode('utf-8', errors='replace')
            offset += key_len
            value, offset = parse_amf0(data, offset)
            obj[key] = value
        return obj, offset
    elif type_marker == 0x05:  # null
        return None, offset
    elif type_marker == 0x06:  # undefined
        return None, offset
    elif type_marker == 0x0A:  # array
        count = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        arr = []
        for _ in range(count):
            value, offset = parse_amf0(data, offset)
            arr.append(value)
        return arr, offset
    elif type_marker == 0x0B:  # date
        ms = struct.unpack(">d", data[offset:offset+8])[0]
        offset += 8
        tz = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        return ms, offset
    else:
        return f"<unknown type 0x{type_marker:02X}>", offset

def parse_amf_message(data):
    """Parse an AMF request message"""
    try:
        # AMF packet header
        version = struct.unpack(">H", data[0:2])[0]
        header_count = struct.unpack(">H", data[2:4])[0]
        offset = 4
        
        log(f"AMF version: {version}, headers: {header_count}")
        
        # Skip headers
        for _ in range(header_count):
            # Header name
            name_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            name = data[offset:offset+name_len].decode('utf-8', errors='replace')
            offset += name_len
            # must understand flag
            offset += 1
            # Value length
            value_len = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            value, offset = parse_amf0(data, offset)
            log(f"  Header: {name} = {value}")
        
        # Body count
        body_count = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        log(f"Bodies: {body_count}")
        
        bodies = []
        for i in range(body_count):
            # Target URI
            target_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            target = data[offset:offset+target_len].decode('utf-8', errors='replace')
            offset += target_len
            
            # Response URI
            response_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            response = data[offset:offset+response_len].decode('utf-8', errors='replace')
            offset += response_len
            
            # Data length
            data_len = struct.unpack(">I", data[offset:offset+4])[0]
            offset += 4
            
            # Parse the data
            body_data = data[offset:offset+data_len]
            body_value, _ = parse_amf0(body_data, 0)
            
            log(f"  Body {i}: target='{target}', response='{response}', data_len={data_len}")
            log(f"    Value: {body_value}")
            
            bodies.append({
                'target': target,
                'response': response,
                'data': body_value
            })
            offset += data_len
        
        return {'version': version, 'bodies': bodies}
    except Exception as e:
        log(f"AMF parse error: {e}")
        log(f"Raw data (first 200 bytes): {data[:200].hex()}")
        return None

def build_amf0_string(s):
    """Build an AMF0 string"""
    return struct.pack(">B", 0x02) + struct.pack(">H", len(s)) + s.encode('utf-8')

def build_amf0_number(n):
    """Build an AMF0 number"""
    return struct.pack(">B", 0x00) + struct.pack(">d", n)

def build_amf0_bool(b):
    """Build an AMF0 boolean"""
    return struct.pack(">B", 0x01) + struct.pack(">B", 1 if b else 0)

def build_amf0_null():
    """Build an AMF0 null"""
    return struct.pack(">B", 0x05)

def build_amf0_object(obj):
    """Build an AMF0 object"""
    result = struct.pack(">B", 0x03)  # object marker
    for key, value in obj.items():
        key_bytes = key.encode('utf-8')
        result += struct.pack(">H", len(key_bytes)) + key_bytes
        if isinstance(value, str):
            result += build_amf0_string(value)
        elif isinstance(value, (int, float)):
            result += build_amf0_number(value)
        elif isinstance(value, bool):
            result += build_amf0_bool(value)
        elif value is None:
            result += build_amf0_null()
        elif isinstance(value, dict):
            result += build_amf0_object(value)
    result += struct.pack(">H", 0) + struct.pack(">B", 0x09)  # end of object
    return result

def build_amf_response(target_uri, response_data):
    """Build a minimal AMF0 response packet"""
    # Version 0
    packet = struct.pack(">H", 0)
    # 0 headers
    packet += struct.pack(">H", 0)
    # 1 body
    packet += struct.pack(">H", 1)
    
    # Response URI (append /onResult to the request's response URI)
    response_uri = response_data.get('response_uri', '') + '/onResult'
    response_bytes = response_uri.encode('utf-8')
    packet += struct.pack(">H", len(response_bytes)) + response_bytes
    
    # Empty target URI for response
    packet += struct.pack(">H", 0)
    
    # Build the response value
    if isinstance(response_data.get('value'), dict):
        value_bytes = build_amf0_object(response_data['value'])
    elif isinstance(response_data.get('value'), str):
        value_bytes = build_amf0_string(response_data['value'])
    elif isinstance(response_data.get('value'), (int, float)):
        value_bytes = build_amf0_number(response_data['value'])
    elif response_data.get('value') is None:
        value_bytes = build_amf0_null()
    else:
        value_bytes = build_amf0_null()
    
    # Data length
    packet += struct.pack(">I", len(value_bytes))
    packet += value_bytes
    
    return packet

class AMFHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        log(f"POST {self.path}")
        log(f"Content-Type: {self.headers.get('Content-Type', 'unknown')}")
        log(f"Content-Length: {content_length}")
        log(f"Headers: {dict(self.headers)}")
        log(f"Raw (first 500 hex): {body[:500].hex()}")
        
        # Try to parse as AMF
        parsed = parse_amf_message(body)
        
        if parsed and parsed['bodies']:
            for b in parsed['bodies']:
                target = b['target']
                log(f"Processing target: {target}")
                
                # Handle different AMF targets
                response_value = None
                
                if 'handshake' in target.lower():
                    # Handshake response
                    response_value = {
                        'success': True,
                        'status': 'ok',
                        'version': '1.0',
                        'siteId': '12345',
                        'siteName': 'Test School',
                        'message': 'Handshake successful'
                    }
                elif 'login' in target.lower() or 'auth' in target.lower():
                    # Login response
                    response_value = {
                        'success': True,
                        'status': 'ok',
                        'sessionId': 'mock-session-12345',
                        'userId': '1',
                        'userName': 'Student',
                        'message': 'Login successful'
                    }
                elif 'site' in target.lower() or 'verify' in target.lower():
                    # Site verification response
                    response_value = {
                        'success': True,
                        'status': 'ok',
                        'siteId': '12345',
                        'siteName': 'Test School',
                        'isValid': True
                    }
                else:
                    # Generic response
                    response_value = {
                        'success': True,
                        'status': 'ok',
                        'message': 'OK'
                    }
                
                response_packet = build_amf_response(target, {
                    'response_uri': b['response'],
                    'value': response_value
                })
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-amf')
                self.send_header('Content-Length', len(response_packet))
                self.end_headers()
                self.wfile.write(response_packet)
                log(f"Sent AMF response for {target}")
                return
        
        # If not AMF or no bodies, return a generic response
        response = b'{"success": true, "status": "ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
        log("Sent generic JSON response")
    
    def do_GET(self):
        log(f"GET {self.path}")
        log(f"Headers: {dict(self.headers)}")
        response = b'{"status": "ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

def main():
    # Clear previous log
    with open(LOG_FILE, "w") as f:
        f.write(f"AMF Mock Server starting at {datetime.datetime.now().isoformat()}\n")
    
    log("AMF Mock Server (HTTPS) starting on port 443...")
    
    # Generate self-signed cert
    cert_file, key_file = generate_self_signed_cert()
    
    if cert_file and os.path.exists(cert_file) and os.path.exists(key_file):
        log(f"Using cert: {cert_file}")
        
        # Install cert in Windows trust store
        try:
            subprocess.run(["certutil", "-addstore", "-f", "Root", cert_file], 
                         check=True, capture_output=True)
            log("Cert installed in Windows Root trust store")
        except Exception as e:
            log(f"Cert install warning: {e}")
        
        # Create HTTPS server
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        
        server = http.server.HTTPServer(('0.0.0.0', 443), AMFHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        
        log("Server listening on https://0.0.0.0:443")
        server.serve_forever()
    else:
        log("ERROR: Could not generate SSL certificate. Falling back to HTTP on port 443.")
        server = http.server.HTTPServer(('0.0.0.0', 443), AMFHandler)
        log("Server listening on http://0.0.0.0:443 (no SSL)")
        server.serve_forever()

if __name__ == "__main__":
    main()
