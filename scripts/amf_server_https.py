#!/usr/bin/env python3
"""
Mock AMFPHP server for Lexia Core5.
Handles HTTPS AMF requests on port 443.
Parses AMF3 requests (Flex CommandMessage) and responds with valid AMF3 AcknowledgeMessage.
"""
import http.server
import ssl
import os
import sys
import struct
import datetime
import subprocess
import uuid

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

# ==================== AMF3 U29 encoding ====================

def encode_u29(value):
    """Encode a U29 value"""
    if value < 0x80:
        return bytes([value])
    elif value < 0x4000:
        return bytes([(value >> 7) | 0x80, value & 0x7F])
    elif value < 0x200000:
        return bytes([(value >> 14) | 0x80, (value >> 7) | 0x80, value & 0x7F])
    else:
        return bytes([(value >> 22) | 0x80, (value >> 14) | 0x80, (value >> 7) | 0x80, value & 0x7F])

def decode_u29(data, offset):
    """Decode a U29 value. Returns (value, new_offset)"""
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
    """Encode a U29S string (U29 length + UTF-8 data). Empty string = 0x01."""
    if s == "":
        return bytes([0x01])
    data = s.encode('utf-8')
    return encode_u29((len(data) << 1) | 1) + data

def decode_u29s_string(data, offset, string_table):
    """Decode a U29S string. Returns (string, new_offset). May use/add to string_table."""
    val, offset = decode_u29(data, offset)
    if (val & 1) == 0:
        # Reference to string table
        idx = val >> 1
        if idx < len(string_table):
            return string_table[idx], offset
        return f"<invalid string ref {idx}>", offset
    else:
        length = val >> 1
        s = data[offset:offset+length].decode('utf-8', errors='replace')
        offset += length
        if length > 0:
            string_table.append(s)
        return s, offset

# ==================== AMF3 type encoders ====================

def encode_amf3_null():
    return bytes([0x01])

def encode_amf3_bool(b):
    return bytes([0x03 if b else 0x02])

def encode_amf3_integer(val):
    if val < 0 or val > 0x1FFFFFFF:
        return encode_amf3_double(float(val))
    return bytes([0x04]) + encode_u29(val)

def encode_amf3_double(val):
    return bytes([0x05]) + struct.pack(">d", val)

def encode_amf3_string(s, string_table=None):
    """Encode a string. If string_table provided, check for references."""
    if string_table and s in string_table:
        ref_idx = string_table.index(s)
        return bytes([0x06]) + encode_u29(ref_idx << 1)  # reference
    if string_table:
        string_table.append(s)
    return bytes([0x06]) + encode_u29s_string(s)

def encode_amf3_object(class_name, sealed_props, dynamic_props, string_table=None):
    """Encode an AMF3 object with traits.
    sealed_props: list of (name, value_bytes) 
    dynamic_props: dict of name -> value_bytes (or None for no dynamic)
    """
    if string_table is None:
        string_table = []
    
    result = bytes([0x0A])  # object marker
    
    num_sealed = len(sealed_props)
    is_dynamic = dynamic_props is not None
    is_externalizable = False
    
    # U29 traits: (count << 4) | (dynamic ? 8 : 0) | 4 | 1
    traits_u29 = (num_sealed << 4) | (8 if is_dynamic else 0) | 4 | 1
    result += encode_u29(traits_u29)
    
    # Class name
    result += encode_u29s_string(class_name)
    
    # Sealed property names
    for name, _ in sealed_props:
        result += encode_u29s_string(name)
    
    # Sealed property values
    for _, value_bytes in sealed_props:
        result += value_bytes
    
    # Dynamic properties
    if is_dynamic:
        for name, value_bytes in dynamic_props.items():
            result += encode_u29s_string(name)
            result += value_bytes
        result += bytes([0x01])  # empty string to end dynamic props
    
    return result

# ==================== AMF3 type decoders ====================

def decode_amf3_value(data, offset, string_table, object_table, traits_table):
    """Decode any AMF3 value. Returns (value, new_offset)."""
    if offset >= len(data):
        return None, offset
    
    marker = data[offset]
    offset += 1
    
    if marker == 0x00:  # undefined
        return None, offset
    elif marker == 0x01:  # null
        return None, offset
    elif marker == 0x02:  # false
        return False, offset
    elif marker == 0x03:  # true
        return True, offset
    elif marker == 0x04:  # integer
        val, offset = decode_u29(data, offset)
        if val >= 0x10000000:
            val -= 0x20000000  # signed
        return val, offset
    elif marker == 0x05:  # double
        val = struct.unpack(">d", data[offset:offset+8])[0]
        return val, offset + 8
    elif marker == 0x06:  # string
        return decode_u29s_string(data, offset, string_table)
    elif marker == 0x08:  # date
        val, offset = decode_u29(data, offset)
        # val is reference or new date
        if (val & 1) == 0:
            return f"<date ref {val>>1}>", offset
        ms = struct.unpack(">d", data[offset:offset+8])[0]
        return ms, offset + 8
    elif marker == 0x09:  # array
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0:
            return f"<array ref {val>>1}>", offset
        count = val >> 1
        # Associative part
        result = {}
        while True:
            key, offset = decode_u29s_string(data, offset, string_table)
            if key == "":
                break
            value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
            result[key] = value
        # Dense part
        for i in range(count):
            value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
            result[f"[{i}]"] = value
        return result, offset
    elif marker == 0x0A:  # object
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0:
            # Object reference
            idx = val >> 1
            if idx < len(object_table):
                return object_table[idx], offset
            return f"<object ref {idx}>", offset
        
        if (val & 2) == 0:
            # Traits reference
            traits_idx = val >> 2
            traits = traits_table[traits_idx] if traits_idx < len(traits_table) else {}
        else:
            # New traits
            externalizable = (val & 4) != 0
            is_dynamic = (val & 8) != 0
            count = val >> 4
            class_name, offset = decode_u29s_string(data, offset, string_table)
            
            sealed_names = []
            for _ in range(count):
                name, offset = decode_u29s_string(data, offset, string_table)
                sealed_names.append(name)
            
            traits = {
                'class_name': class_name,
                'sealed_names': sealed_names,
                'externalizable': externalizable,
                'dynamic': is_dynamic
            }
            traits_table.append(traits)
        
        obj = {'__class__': traits.get('class_name', '')}
        
        # Sealed properties
        for name in traits.get('sealed_names', []):
            value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
            obj[name] = value
        
        # Dynamic properties
        if traits.get('dynamic'):
            while True:
                key, offset = decode_u29s_string(data, offset, string_table)
                if key == "":
                    break
                value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
                obj[key] = value
        
        object_table.append(obj)
        return obj, offset
    elif marker == 0x0C:  # byte-array
        val, offset = decode_u29(data, offset)
        if (val & 1) == 0:
            return f"<bytearray ref {val>>1}>", offset
        length = val >> 1
        return data[offset:offset+length], offset + length
    else:
        return f"<unknown AMF3 marker 0x{marker:02X}>", offset

# ==================== AMF packet parsing ====================

def parse_amf_packet(data):
    """Parse an AMF packet (may contain AMF0 with AMF3 switch)."""
    version = struct.unpack(">H", data[0:2])[0]
    header_count = struct.unpack(">H", data[2:4])[0]
    offset = 4
    
    headers = []
    for _ in range(header_count):
        name_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        name = data[offset:offset+name_len].decode('utf-8', errors='replace')
        offset += name_len
        must_understand = data[offset]
        offset += 1
        value_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        value_data = data[offset:offset+value_len]
        offset += value_len
        headers.append({'name': name, 'data': value_data})
    
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
    """Parse body data. In AMFPHP, body is typically an AMF0 strict array
    containing AMF3 values (via 0x11 switch marker)."""
    results = []
    offset = 0
    
    if offset >= len(data):
        return results
    
    marker = data[offset]
    offset += 1
    
    if marker == 0x0A:  # AMF0 Strict Array
        count = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        
        for _ in range(count):
            if offset >= len(data):
                break
            m = data[offset]
            if m == 0x11:  # AMF3 switch
                offset += 1
                # Parse AMF3 value
                string_table = []
                object_table = []
                traits_table = []
                value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
                results.append(value)
            else:
                # AMF0 value - skip for now
                break
    elif marker == 0x11:  # Direct AMF3
        offset += 0  # already consumed the marker
        # Actually marker was consumed, so offset is already past 0x11
        string_table = []
        object_table = []
        traits_table = []
        value, offset = decode_amf3_value(data, offset, string_table, object_table, traits_table)
        results.append(value)
    else:
        log(f"Unknown body marker: 0x{marker:02X}")
    
    return results

# ==================== AMF3 response builder ====================

def build_acknowledge_message(correlation_id, message_id=None, body=None, headers=None):
    """Build an AMF3 AcknowledgeMessage."""
    if message_id is None:
        message_id = "ID" + str(uuid.uuid4()).upper()
    
    st = []  # string table for the response
    
    # Build sealed property values
    sealed_props = [
        ("correlationId", encode_amf3_string(correlation_id, st)),
        ("messageId", encode_amf3_string(message_id, st)),
        ("timestamp", encode_amf3_double(0)),  # 0 timestamp
        ("timeToLive", encode_amf3_integer(0)),
        ("body", encode_amf3_null() if body is None else body),
        ("clientId", encode_amf3_null()),
    ]
    
    dynamic_props = {}
    if headers:
        for k, v in headers.items():
            dynamic_props[k] = encode_amf3_string(str(v), st)
    
    return encode_amf3_object("flex.messaging.messages.AcknowledgeMessage", sealed_props, dynamic_props, st)

def build_amf3_response(target_uri, response_uri, amf3_value):
    """Build a complete AMF response packet.
    The body is an AMF0 strict array containing an AMF3 value (via 0x11 marker).
    """
    # Version 0 (AMF0 packet, with AMF3 content)
    packet = struct.pack(">H", 0)  # version 0
    packet += struct.pack(">H", 0)  # 0 headers
    packet += struct.pack(">H", 1)  # 1 body
    
    # Target URI: response target (empty for response)
    target_bytes = target_uri.encode('utf-8')
    packet += struct.pack(">H", len(target_bytes)) + target_bytes
    
    # Response URI: "/onResult" + response_uri
    resp_uri = response_uri + "/onResult"
    resp_bytes = resp_uri.encode('utf-8')
    packet += struct.pack(">H", len(resp_bytes)) + resp_bytes
    
    # Body data: AMF0 strict array with 1 element, AMF3 via 0x11
    body_data = bytes([0x0A])  # AMF0 strict array
    body_data += struct.pack(">I", 1)  # 1 element
    body_data += bytes([0x11])  # AMF3 switch
    body_data += amf3_value  # AMF3 AcknowledgeMessage
    
    packet += struct.pack(">I", len(body_data))
    packet += body_data
    
    return packet

# ==================== HTTP Handler ====================

class AMFHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        log(f"POST {self.path} (Content-Length: {content_length})")
        
        # Parse AMF packet
        packet = parse_amf_packet(body)
        log(f"AMF version: {packet['version']}, bodies: {len(packet['bodies'])}")
        
        for i, b in enumerate(packet['bodies']):
            log(f"Body {i}: target='{b['target']}', response='{b['response']}', data_len={len(b['data'])}")
            
            # Parse the body data (AMF0 strict array with AMF3 values)
            messages = parse_body_data(b['data'])
            
            for msg in messages:
                class_name = msg.get('__class__', '') if isinstance(msg, dict) else str(type(msg))
                log(f"  Message class: {class_name}")
                
                if 'CommandMessage' in class_name:
                    operation = msg.get('operation', -1)
                    msg_id = msg.get('messageId', '')
                    log(f"  CommandMessage: operation={operation}, messageId={msg_id}")
                    log(f"  Full message: {msg}")
                    
                    # Build AcknowledgeMessage response
                    ack = build_acknowledge_message(
                        correlation_id=msg_id,
                        headers={
                            'DSMessagingVersion': '1',
                            'DSId': 'mock-server-001'
                        }
                    )
                    
                    response_packet = build_amf3_response(b['target'], b['response'], ack)
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-amf')
                    self.send_header('Content-Length', len(response_packet))
                    self.end_headers()
                    self.wfile.write(response_packet)
                    log(f"  Sent AcknowledgeMessage response ({len(response_packet)} bytes)")
                    return
                
                elif 'RemotingMessage' in class_name:
                    operation = msg.get('operation', '')
                    msg_id = msg.get('messageId', '')
                    destination = msg.get('destination', '')
                    source = msg.get('source', '')
                    log(f"  RemotingMessage: destination={destination}, operation={operation}, source={source}")
                    log(f"  Full message: {msg}")
                    
                    # Build response based on the operation
                    response_body = build_acknowledge_message(
                        correlation_id=msg_id,
                        body=encode_amf3_string("OK", None),
                    )
                    
                    response_packet = build_amf3_response(b['target'], b['response'], response_body)
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-amf')
                    self.send_header('Content-Length', len(response_packet))
                    self.end_headers()
                    self.wfile.write(response_packet)
                    log(f"  Sent AcknowledgeMessage for {operation} ({len(response_packet)} bytes)")
                    return
        
        # Generic fallback
        log("No recognized message type, sending generic response")
        response = b'{"success": true}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def do_GET(self):
        log(f"GET {self.path}")
        response = b'{"status": "ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)
    
    def log_message(self, format, *args):
        pass

def main():
    with open(LOG_FILE, "w") as f:
        f.write(f"AMF Mock Server starting at {datetime.datetime.now().isoformat()}\n")
    
    log("AMF Mock Server (HTTPS) starting on port 443...")
    
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
