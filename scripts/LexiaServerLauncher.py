#!/usr/bin/env python3
"""
Lexia Core5 Standalone Private Server & Launcher
Single-file portable server for Lexia Core5.

Features:
- Requests Admin rights automatically on Windows
- Modifies C:\\Windows\\System32\\drivers\\etc\\hosts for redirection
- Places CORE5.sol in Flash #SharedObjects directory
- Generates & trusts self-signed SSL cert via certutil
- Runs HTTPS AMF Mock Server on port 443
- Cleans up hosts file on exit
"""

import os
import sys
import time
import ssl
import glob
import ctypes
import shutil
import struct
import datetime
import tempfile
import threading
import subprocess
import http.server
import uuid
import atexit
import signal

HOSTS_ENTRIES = [
    "127.0.0.1 student.mylexia.com # LexiaPrivateServer",
    "127.0.0.1 dev10.lexialearning.com # LexiaPrivateServer",
    "127.0.0.1 qa10.lexialearning.com # LexiaPrivateServer",
    "127.0.0.1 www.mylexia.com # LexiaPrivateServer",
    "127.0.0.1 mylexia.com # LexiaPrivateServer",
    "127.0.0.1 api.lexialearning.com # LexiaPrivateServer",
    "127.0.0.1 student.lexialearning.com # LexiaPrivateServer"
]

SOL_BYTES = b'TCSO\x00\x04\x00\x00\x00\x00\x00\x05CORE5\x00\x00\x00\x00\x00\x00\x00\x03\x00\x04data\x03\x00\x06siteId\x02\x00\x011\x00\tsiteUsage\x02\x00\tPARAMETER\x00\x00\x00\x00'

def is_admin():
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else True

def request_admin():
    if os.name == 'nt' and not is_admin():
        print("[i] Demande des privilèges Administrateur pour modifier les redirections réseau...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

def get_hosts_path():
    if os.name == 'nt':
        return r"C:\Windows\System32\drivers\etc\hosts"
    return "/etc/hosts"

def apply_hosts_redirection():
    hosts_path = get_hosts_path()
    if not os.path.exists(hosts_path):
        print(f"[!] Fichier hosts introuvable : {hosts_path}")
        return False
    
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        lines_to_add = [entry for entry in HOSTS_ENTRIES if entry.split()[1] not in content]
        if lines_to_add:
            with open(hosts_path, "a", encoding="utf-8") as f:
                f.write("\n# === Lexia Private Server Redirections ===\n")
                for entry in lines_to_add:
                    f.write(entry + "\n")
            print("[✓] Redirections DNS (hosts) appliquées avec succès.")
        else:
            print("[✓] Redirections DNS (hosts) déjà présentes.")
        return True
    except Exception as e:
        print(f"[!] Erreur lors de l'écriture dans le fichier hosts : {e}")
        return False

def remove_hosts_redirection():
    hosts_path = get_hosts_path()
    if not os.path.exists(hosts_path):
        return
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        new_lines = [line for line in lines if "# LexiaPrivateServer" not in line and "=== Lexia Private Server" not in line]
        with open(hosts_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print("[✓] Redirections DNS nettoyées du fichier hosts.")
    except Exception as e:
        print(f"[!] Erreur lors du nettoyage du fichier hosts : {e}")

def place_sol_file():
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return
    
    so_dirs = []
    for root, dirs, files in os.walk(os.path.join(appdata, "Macromedia", "Flash Player", "#SharedObjects")):
        if "com.lexiareading" in root:
            so_dirs.append(root)
    
    # Also check direct appdata location
    lexia_appdata = os.path.join(appdata, "com.lexiareading.core5.desktop.us", "Local Store", "#SharedObjects")
    if os.path.exists(lexia_appdata):
        so_dirs.append(lexia_appdata)
        
    for d in so_dirs:
        try:
            sol_dest = os.path.join(d, "CORE5.sol")
            with open(sol_dest, "wb") as f:
                f.write(SOL_BYTES)
            print(f"[✓] Fichier CORE5.sol placé dans : {sol_dest}")
        except Exception as e:
            print(f"[!] Impossible d'écrire CORE5.sol dans {d} : {e}")

def generate_cert(cert_dir):
    os.makedirs(cert_dir, exist_ok=True)
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file, "-out", cert_file,
        "-days", "3650", "-nodes",
        "-subj", "/CN=student.mylexia.com",
        "-addext", "subjectAltName=DNS:student.mylexia.com,DNS:localhost,DNS:*.lexialearning.com"
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("[✓] Certificat SSL généré pour student.mylexia.com")
        return cert_file, key_file
    except Exception as e:
        # Fallback to python self-signed generator if openssl binary is missing
        print(f"[i] OpenSSL non trouvé, génération avec Python crypto fallback...")
        return generate_cert_python(cert_dir)

def generate_cert_python(cert_dir):
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "student.mylexia.com")])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("student.mylexia.com"),
                x509.DNSName("localhost"),
                x509.DNSName("*.lexialearning.com")
            ]),
            critical=False
        ).sign(key, hashes.SHA256())
        
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return cert_file, key_file
    except Exception as e:
        print(f"[!] Erreur génération certificat Python : {e}")
        return None, None

def trust_cert(cert_file):
    if os.name == 'nt' and cert_file and os.path.exists(cert_file):
        try:
            subprocess.run(["certutil", "-addstore", "-f", "Root", cert_file], check=True, capture_output=True)
            print("[✓] Certificat ajouté au magasin de confiance Windows (Root)")
        except Exception as e:
            print(f"[!] Avertissement certificat trust : {e}")

# ==================== AMF SERVER ENCODERS & DECODERS ====================

def encode_u29(value):
    if value < 0x80:
        return bytes([value])
    elif value < 0x4000:
        return bytes([(value >> 7) | 0x80, value & 0x7F])
    elif value < 0x200000:
        return bytes([(value >> 14) | 0x80, (value >> 7) | 0x80, value & 0x7F])
    else:
        return bytes([(value >> 22) | 0x80, (value >> 14) | 0x80, (value >> 7) | 0x80, value & 0x7F])

def encode_u29s_string(s):
    if s == "":
        return bytes([0x01])
    data = s.encode('utf-8')
    return encode_u29((len(data) << 1) | 1) + data

def enc_null(): return bytes([0x01])
def enc_bool(b): return bytes([0x03 if b else 0x02])
def enc_int(val):
    if val < 0 or val > 0x1FFFFFFF: return enc_double(float(val))
    return bytes([0x04]) + encode_u29(val)
def enc_double(val): return bytes([0x05]) + struct.pack(">d", val)
def enc_string(s): return bytes([0x06]) + encode_u29s_string(s)

def enc_object(class_name, sealed_props, dynamic_props=None):
    result = bytes([0x0A])
    num_sealed = len(sealed_props)
    is_dynamic = dynamic_props is not None
    traits_u29 = (num_sealed << 4) | (8 if is_dynamic else 0) | 3
    result += encode_u29(traits_u29)
    result += encode_u29s_string(class_name)
    for name, _ in sealed_props: result += encode_u29s_string(name)
    for _, value_bytes in sealed_props: result += value_bytes
    if is_dynamic:
        for name, value_bytes in dynamic_props.items():
            result += encode_u29s_string(name) + value_bytes
        result += bytes([0x01])
    return result

def enc_array(values):
    result = bytes([0x09]) + encode_u29((len(values) << 1) | 1) + bytes([0x01])
    for v in values: result += v
    return result

def build_ack_message(correlation_id, body_value=None):
    if body_value is None: body_value = enc_null()
    msg_id = str(uuid.uuid4()).upper()
    header_obj = enc_object("", [], {"DSMessagingVersion": enc_int(1), "DSId": enc_string("lexia-portable-001")})
    sealed = [
        ("correlationId", enc_string(correlation_id)),
        ("body", body_value),
        ("clientId", enc_null()),
        ("destination", enc_string("")),
        ("headers", header_obj),
        ("messageId", enc_string(msg_id)),
        ("timestamp", enc_double(0)),
        ("timeToLive", enc_int(0)),
    ]
    return enc_object("flex.messaging.messages.AcknowledgeMessage", sealed)

def build_handshake_vo():
    return enc_object("com.lexialearning.lrs.api.HandshakeResponseVO", [], {
        "errorCode": enc_double(0),
        "errorMessage": enc_null(),
    })

def build_login_vo():
    auth = "MOCK-AUTH-" + str(uuid.uuid4()).upper()[:8]
    return enc_object("com.lexialearning.lrs.api.LoginResponseVO", [], {
        "authToken": enc_string(auth),
        "studentId": enc_int(1),
        "personName": enc_string("Student"),
        "language": enc_string("english"),
        "region": enc_string("us"),
        "purpose": enc_string("course"),
        "currentPhaseId": enc_string("phase1"),
        "currentUnitIdList": enc_array([]),
        "isAuditMode": enc_bool(False),
        "isUnhidePassword": enc_bool(False),
        "irtForm": enc_string(""),
        "startUnit": enc_string(""),
        "classList": enc_null(),
        "grade": enc_string("Grade 2"),
        "teacher": enc_string("Teacher"),
        "showWarmup": enc_bool(False),
        "secondsSinceLastLogin": enc_int(0),
        "warmupHighScore": enc_int(0),
        "errorCode": enc_double(0),
        "errorMessage": enc_null(),
    })

def build_generic_vo():
    return enc_object("com.lexialearning.lrs.api.ResponseVO", [], {
        "errorCode": enc_double(0),
        "errorMessage": enc_null(),
    })

def build_response(response_uri, amf3_value, version=3):
    packet = struct.pack(">H", version) + struct.pack(">H", 0) + struct.pack(">H", 1)
    target = (response_uri + "/onResult").encode("utf-8")
    packet += struct.pack(">H", len(target)) + target + struct.pack(">H", 0)
    packet += struct.pack(">I", len(amf3_value)) + amf3_value
    return packet

def parse_amf_packet(data):
    version = struct.unpack(">H", data[0:2])[0]
    header_count = struct.unpack(">H", data[2:4])[0]
    offset = 4
    for _ in range(header_count):
        nl = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2 + nl + 1
        vl = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4 + vl
    body_count = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
    bodies = []
    for _ in range(body_count):
        tl = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
        target = data[offset:offset+tl].decode('utf-8', errors='replace'); offset += tl
        rl = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
        response = data[offset:offset+rl].decode('utf-8', errors='replace'); offset += rl
        dl = struct.unpack(">I", data[offset:offset+4])[0]; offset += 4
        body_data = data[offset:offset+dl]; offset += dl
        bodies.append({'target': target, 'response': response, 'data': body_data})
    return {'version': version, 'bodies': bodies}

class AMFHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            packet = parse_amf_packet(body)
            for b in packet['bodies']:
                ack = build_ack_message("MOCK-CORRELATION-ID", build_generic_vo())
                if b'handshake' in b['data']:
                    ack = build_ack_message("MOCK-CORRELATION-ID", build_handshake_vo())
                elif b'login' in b['data']:
                    ack = build_ack_message("MOCK-CORRELATION-ID", build_login_vo())
                resp = build_response(b['response'], ack)
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-amf')
                self.send_header('Content-Length', len(resp))
                self.end_headers()
                self.wfile.write(resp)
                return
        except Exception:
            resp = b'{"success":true}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(resp))
            self.end_headers()
            self.wfile.write(resp)

    def do_GET(self):
        resp = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(resp))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args): pass

def run_server(cert_file, key_file):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        server = http.server.HTTPServer(('0.0.0.0', 443), AMFHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print("[✓] Serveur HTTPS écoute sur le port 443")
        server.serve_forever()
    except Exception as e:
        print(f"[!] Erreur démarrage serveur HTTPS 443 : {e}")

def main():
    print("=" * 64)
    print("      LEXIA CORE5 - SERVEUR PRIVÉ AUTONOME (PORTABLE)")
    print("=" * 64)
    
    request_admin()
    
    atexit.register(remove_hosts_redirection)
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    
    apply_hosts_redirection()
    place_sol_file()
    
    cert_dir = os.path.join(tempfile.gettempdir(), "lexia_certs")
    cert_file, key_file = generate_cert(cert_dir)
    if cert_file:
        trust_cert(cert_file)
    
    print("-" * 64)
    print(" >>> SERVEUR PRIVÉ PRÊT ! <<<")
    print(" 1. Gardez cette fenêtre ouverte.")
    print(" 2. Lancez l'application 'Lexia Reading Core5' sur votre PC.")
    print(" 3. Pour vous connecter dans l'application :")
    print("    - Email enseignant : n'importe quel email (ex: test@school.edu)")
    print("    - Identifiant       : student")
    print("    - Mot de passe      : password")
    print("-" * 64)
    print(" [Appuyez sur Entrée ou fermez cette fenêtre pour tout arrêter]")
    print("=" * 64)

    t = threading.Thread(target=run_server, args=(cert_file, key_file), daemon=True)
    t.start()

    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass
    
    print("\n[i] Arrêt du serveur et nettoyage des redirections DNS...")
    remove_hosts_redirection()
    print("[✓] Terminé.")

if __name__ == "__main__":
    main()
