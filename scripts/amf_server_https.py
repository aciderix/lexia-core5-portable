#!/usr/bin/env python3
"""
Mock AMFPHP server for Lexia Core5.
Handles HTTPS AMF requests on port 443.
Parses AMF3 requests and responds with AMF0 responses (version 0).

AMF0 is simpler than AMF3 - no string tables, no traits, no references.
This matches the original AMFPHP server behavior more closely.
"""
import http.server
import ssl
import os
import sys
import struct
import datetime
import subprocess
import uuid
import json

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

# ==================== AMF3 U29 encoding (for parsing requests) ====================

def encode_u29(value):
    if value < 0x80:
        return bytes([value])
    elif value < 0x4000:
        return bytes([(value >> 7) | 0x80, value & 0x7F])
    elif value < 0x200000:
        return bytes([(value >> 14) | 0x80, (value >> 7) | 0x80, value & 0x7F])
    else:
        return bytes([(value >> 22) | 0x80, (value >> 14) | 0x80, (value >> 7) | 0x80, value & 0x7F])

def decode_u29(data, offset):
    val = 0
    for i in range(4):
        if offset + i >= len(data):
            return val, offset + i
        byte = data[offset + i]
        if i == 3:
            val = (val << 8) | byte
            return val & 0x1FFFFFFF, offset + 4
        val = (val << 7) | (byte & 0x7F)
        if byte < 0x80:
            return val, offset + i + 1
    return val, offset + 4

def encode_u29s_string(s):
    if s == "":
        return bytes([0x01])
    data = s.encode('utf-8')
    return encode_u29((len(data) << 1) | 1) + data

def decode_u29s_string(data, offset, string_table):
    val, offset = decode_u29(data, offset)
    if (val & 1) == 0:
        idx = val >> 1
        if idx < len(string_table):
            return string_table[idx], offset
        return f"<invalid str ref {idx}>", offset
    else:
        length = val >> 1
        s = data[offset:offset+length].decode('utf-8', errors='replace')
        offset += length
        if length > 0:
            string_table.append(s)
        return s, offset

# ==================== AMF3 decoders (for parsing requests) ====================

def decode_amf3_value(data, offset, string_table, object_table, traits_table):
    if offset >= len(data):
        return None, offset
    marker = data[offset]
    offset += 1
    
    if marker == 0x00: return None, offset
    elif marker == 0x01: return None, offset
    elif marker == 0x02: return False, offset
    elif marker == 0x03: return True, offset
    elif marker == 0x04:
        val, offset = decode_u29(data, offset)
        if val >= 0x10000000: val -= 0x20000000
        return val, offset
    elif marker == 0x05:
        val = struct.unpack(">d", data[offset:offset+8])[0]
        return val, offset + 8
    elif marker == 0x06:
        return decode_u29s_string(data, offset, string_table)
    elif marker == 0x08:
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0: return f"<date ref {val>>1}>", offset
        ms = struct.unpack(">d", data[offset:offset+8])[0]
        return ms, offset + 8
    elif marker == 0x09:
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0: return f"<array ref {val>>1}>", offset
        count = val >> 1
        result = {}
        while True:
            key, offset = decode_u29s_string(data, offset, string_table)
            if key == "": break
            value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
            result[key] = value
        for i in range(count):
            value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
            result[f"[{i}]"] = value
        return result, offset
    elif marker == 0x0A:
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0:
            idx = val >> 1
            if idx < len(object_table): return object_table[idx], offset
            return f"<obj ref {idx}>", offset
        if (val & 2) == 0:
            traits_idx = val >> 2
            traits = traits_table[traits_idx] if traits_idx < len(traits_table) else {}
        else:
            externalizable = (val & 4) != 0
            is_dynamic = (val & 8) != 0
            count = val >> 4
            class_name, offset = decode_u29s_string(data, offset, string_table)
            sealed_names = []
            for _ in range(count):
                name, offset = decode_u29s_string(data, offset, string_table)
                sealed_names.append(name)
            traits = {'class_name': class_name, 'sealed_names': sealed_names,
                      'externalizable': externalizable, 'dynamic': is_dynamic}
            traits_table.append(traits)
        obj = {'__class__': traits.get('class_name', '')}
        for name in traits.get('sealed_names', []):
            value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
            obj[name] = value
        if traits.get('dynamic'):
            while True:
                key, offset = decode_u29s_string(data, offset, string_table)
                if key == "": break
                value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
                obj[key] = value
        object_table.append(obj)
        return obj, offset
    elif marker == 0x0C:
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0: return f"<barray ref {val>>1}>", offset
        length = val >> 1
        return data[offset:offset+length], offset + length
    else:
        return f"<unknown 0x{marker:02X}>", offset

# ==================== AMF packet parsing ====================

def parse_amf_packet(data):
    version = struct.unpack(">H", data[0:2])[0]
    header_count = struct.unpack(">H", data[2:4])[0]
    offset = 4
    headers = []
    for _ in range(header_count):
        name_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        name = data[offset:offset+name_len].decode('utf-8', errors='replace')
        offset += name_len
        offset += 1  # must_understand
        value_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        offset += value_len
    body_count = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    bodies = []
    for _ in range(body_count):
        target_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        target = data[offset:offset+target_len].decode('utf-8', errors='replace')
        offset += target_len
        response_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        response = data[offset:offset+response_len].decode('utf-8', errors='replace')
        offset += response_len
        data_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        body_data = data[offset:offset+data_len]
        offset += data_len
        bodies.append({'target': target, 'response': response, 'data': body_data})
    return {'version': version, 'headers': headers, 'bodies': bodies}

def parse_body_data(data):
    results = []
    offset = 0
    if offset >= len(data): return results
    marker = data[offset]
    offset += 1
    if marker == 0x0A:  # AMF0 strict array
        count = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        for _ in range(count):
            if offset >= len(data): break
            m = data[offset]
            if m == 0x11:  # AMF3 switch
                offset += 1
                st, ot, tt = [], [], []
                value, offset = decode_amf3_value(data, offset, st, ot, tt)
                results.append(value)
            else:
                break
    elif marker == 0x11:  # Direct AMF3 switch
        st, ot, tt = [], [], []
        value, offset = decode_amf3_value(data, offset, st, ot, tt)
        results.append(value)
    elif marker in (0x09, 0x0A, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00):  # Direct AMF3 value
        offset -= 1
        st, ot, tt = [], [], []
        value, offset = decode_amf3_value(data, offset, st, ot, tt)
        results.append(value)
    return results

# ==================== AMF0 encoders (for responses) ====================

def amf0_str(s):
    """AMF0 string: UI16 length + UTF-8 bytes"""
    data = s.encode('utf-8')
    return struct.pack(">H", len(data)) + data

def amf0_null():
    return bytes([0x05])  # null marker

def amf0_bool(b):
    return bytes([0x01, 0x01 if b else 0x00])

def amf0_number(n):
    return bytes([0x00]) + struct.pack(">d", float(n))

def amf0_string(s):
    """AMF0 string value: marker + UI16 length + UTF-8"""
    return bytes([0x02]) + amf0_str(s)

def amf0_typed_object(class_name, props):
    """AMF0 typed object: 0x03 + class_name + key-value pairs + end"""
    result = bytes([0x03]) + amf0_str(class_name)
    for key, value_bytes in props:
        result += amf0_str(key) + value_bytes
    result += struct.pack(">H", 0)  # empty key = end of properties
    result += bytes([0x09])  # object end marker
    return result

def amf0_ecma_array(props):
    """AMF0 ECMA array: 0x08 + UI32 count + key-value pairs + end"""
    result = bytes([0x08]) + struct.pack(">I", len(props))
    for key, value_bytes in props:
        result += amf0_str(key) + value_bytes
    result += struct.pack(">H", 0)  # empty key
    result += bytes([0x09])  # end
    return result

def amf0_strict_array(values):
    """AMF0 strict array: 0x0A + UI32 count + values"""
    return bytes([0x0A]) + struct.pack(">I", len(values)) + b''.join(values)

# ==================== Response builders (AMF0) ====================

def build_ack_message(correlation_id, body_value=None):
    """Build AMF0 AcknowledgeMessage."""
    if body_value is None:
        body_value = amf0_null()
    
    msg_id = str(uuid.uuid4()).upper()
    
    headers = amf0_ecma_array([
        ("DSMessagingVersion", amf0_number(1)),
        ("DSId", amf0_string("mock-server-001")),
    ])
    
    props = [
        ("correlationId", amf0_string(correlation_id)),
        ("body", body_value),
        ("clientId", amf0_null()),
        ("destination", amf0_string("")),
        ("headers", headers),
        ("messageId", amf0_string(msg_id)),
        ("timestamp", amf0_number(0)),
        ("timeToLive", amf0_number(0)),
    ]
    
    return amf0_typed_object("flex.messaging.messages.AcknowledgeMessage", props)

def build_handshake_vo():
    """Build AMF0 HandshakeResponseVO: errorCode=0, errorMessage=null"""
    return amf0_typed_object("com.lexialearning.lrs.api.HandshakeResponseVO", [
        ("errorCode", amf0_number(0)),
        ("errorMessage", amf0_null()),
    ])

def build_login_vo():
    """Build AMF0 LoginResponseVO with fake auth."""
    auth_token = "MOCK-AUTH-" + str(uuid.uuid4()).upper()[:8]
    return amf0_typed_object("com.lexialearning.lrs.api.LoginResponseVO", [
        ("authToken", amf0_string(auth_token)),
        ("studentId", amf0_number(1)),
        ("personName", amf0_string("Student")),
        ("language", amf0_string("english")),
        ("region", amf0_string("us")),
        ("purpose", amf0_string("course")),
        ("currentPhaseId", amf0_string("phase1")),
        ("currentUnitIdList", amf0_strict_array([])),
        ("isAuditMode", amf0_bool(False)),
        ("isUnhidePassword", amf0_bool(False)),
        ("irtForm", amf0_string("")),
        ("startUnit", amf0_string("")),
        ("classList", amf0_null()),
        ("grade", amf0_string("Grade 2")),
        ("teacher", amf0_string("Teacher")),
        ("showWarmup", amf0_bool(False)),
        ("secondsSinceLastLogin", amf0_number(0)),
        ("warmupHighScore", amf0_number(0)),
        ("errorCode", amf0_number(0)),
        ("errorMessage", amf0_null()),
    ])

def build_generic_vo():
    """Build AMF0 ResponseVO: errorCode=0, errorMessage=null"""
    return amf0_typed_object("com.lexialearning.lrs.api.ResponseVO", [
        ("errorCode", amf0_number(0)),
        ("errorMessage", amf0_null()),
    ])

def build_amf0_packet(response_uri, ack_bytes, version=0):
    """Build AMF0 response packet."""
    packet = struct.pack(">H", version)
    packet += struct.pack(">H", 0)       # 0 headers
    packet += struct.pack(">H", 1)       # 1 body
    
    target = response_uri + "/onResult"
    target_bytes = target.encode("utf-8")
    packet += struct.pack(">H", len(target_bytes)) + target_bytes
    packet += struct.pack(">H", 0)  # empty response URI
    
    body_data = amf0_strict_array([ack_bytes])
    packet += struct.pack(">I", len(body_data))
    packet += body_data
    
    return packet

# ==================== HTTP Handler ====================

request_count = 0

class AMFHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global request_count
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        request_count += 1
        
        log(f"=== REQUEST #{request_count}: POST {self.path} ({content_length} bytes) ===")
        
        try:
            packet = parse_amf_packet(body)
            log(f"AMF version: {packet['version']}, bodies: {len(packet['bodies'])}")
            
            for i, b in enumerate(packet['bodies']):
                log(f"Body {i}: target='{b['target']}', response='{b['response']}', data_len={len(b['data'])}")
                
                messages = parse_body_data(b['data'])
                
                for msg in messages:
                    # The message might be wrapped in array key [0]
                    if isinstance(msg, dict) and '[0]' in msg and '__class__' not in msg:
                        msg = msg['[0]']
                    
                    class_name = msg.get('__class__', '') if isinstance(msg, dict) else str(type(msg))
                    log(f"  Class: {class_name}")
                    
                    if 'CommandMessage' in class_name:
                        operation = msg.get('operation', -1)
                        msg_id = msg.get('messageId', '')
                        log(f"  CommandMessage operation={operation}, messageId={msg_id}")
                        
                        # CONNECT operation → simple ack with null body
                        ack = build_ack_message(msg_id)
                        resp = build_amf0_packet(b['response'], ack, version=0)
                        
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/x-amf')
                        self.send_header('Content-Length', len(resp))
                        self.end_headers()
                        self.wfile.write(resp)
                        log(f"  Sent AMF0 AcknowledgeMessage for CONNECT ({len(resp)} bytes)")
                        log(f"  Response hex: {resp.hex()}")
                        return
                    
                    elif 'RemotingMessage' in class_name:
                        operation = msg.get('operation', '')
                        msg_id = msg.get('messageId', '')
                        destination = msg.get('destination', '')
                        source = msg.get('source', '')
                        msg_body = msg.get('body', None)
                        log(f"  RemotingMessage: dest={destination}, op={operation}, source={source}")
                        log(f"  Body: {msg_body}")
                        
                        if operation == 'handshake':
                            vo = build_handshake_vo()
                            ack = build_ack_message(msg_id, vo)
                            resp = build_amf0_packet(b['response'], ack, version=0)
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/x-amf')
                            self.send_header('Content-Length', len(resp))
                            self.end_headers()
                            self.wfile.write(resp)
                            log(f"  Sent AMF0 HandshakeResponseVO ({len(resp)} bytes)")
                            log(f"  Response hex: {resp.hex()}")
                            return
                        
                        elif operation == 'login':
                            vo = build_login_vo()
                            ack = build_ack_message(msg_id, vo)
                            resp = build_amf0_packet(b['response'], ack, version=0)
                            
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/x-amf')
                            self.send_header('Content-Length', len(resp))
                            self.end_headers()
                            self.wfile.write(resp)
                            log(f"  Sent AMF0 LoginResponseVO ({len(resp)} bytes)")
                            log(f"  Response hex: {resp.hex()}")
                            return
                        
                        else:
                            vo = build_generic_vo()
                            ack = build_ack_message(msg_id, vo)
                            resp = build_amf0_packet(b['response'], ack, version=0)
                            self.send_response(200)
                            self.send_header('Content-Type', 'application/x-amf')
                            self.send_header('Content-Length', len(resp))
                            self.end_headers()
                            self.wfile.write(resp)
                            log(f"  Sent AMF0 generic ResponseVO for {operation} ({len(resp)} bytes)")
                            log(f"  Response hex: {resp.hex()}")
                            return
                    
                    else:
                        log(f"  Unknown message type: {class_name}")
                        msg_id = msg.get('messageId', '') if isinstance(msg, dict) else ''
                        ack = build_ack_message(msg_id)
                        resp = build_amf0_packet(b['response'], ack, version=0)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/x-amf')
                        self.send_header('Content-Length', len(resp))
                        self.end_headers()
                        self.wfile.write(resp)
                        log(f"  Sent AMF0 generic ack ({len(resp)} bytes)")
                        return
            
            # Fallback
            resp = b'{"success":true}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(resp))
            self.end_headers()
            self.wfile.write(resp)
            
        except Exception as e:
            log(f"ERROR: {e}")
            import traceback
            log(traceback.format_exc())
            self.send_response(500)
            self.end_headers()
    
    def do_GET(self):
        log(f"GET {self.path}")
        resp = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(resp))
        self.end_headers()
        self.wfile.write(resp)
    
    def log_message(self, format, *args):
        pass

def main():
    with open(LOG_FILE, "w") as f:
        f.write(f"AMF Mock Server starting at {datetime.datetime.now().isoformat()}\n")
    
    log("AMF Mock Server (HTTPS, AMF0 responses) starting on port 443...")
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
        server = http.server.HTTPServer(('0.0.0.0', 443), AMFHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        log("Server listening on https://0.0.0.0:443")
        server.serve_forever()
    else:
        log("ERROR: Could not generate SSL certificate.")
        server = http.server.HTTPServer(('0.0.0.0', 443), AMFHandler)
        log("Server listening on http://0.0.0.0:443 (no SSL)")
        server.serve_forever()

if __name__ == "__main__":
    main()
