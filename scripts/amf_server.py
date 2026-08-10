import struct, sys, os, json, ssl, traceback
from http.server import HTTPServer, BaseHTTPRequestHandler

AMF0_NUMBER=0x00; AMF0_BOOLEAN=0x01; AMF0_STRING=0x02; AMF0_OBJECT=0x03
AMF0_NULL=0x05; AMF0_UNDEFINED=0x06; AMF0_OBJECT_END=0x09
AMF0_STRICT_ARRAY=0x0A; AMF0_DATE=0x0B; AMF0_LONG_STRING=0x0C
AMF0_TYPED_OBJECT=0x10; AMF0_AMF3=0x11

class AMFReader:
    def __init__(self, data):
        self.data = data; self.pos = 0; self.strings = []
    def read_byte(self):
        b = self.data[self.pos]; self.pos += 1; return b
    def read_short(self):
        v = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]; self.pos += 2; return v
    def read_long(self):
        v = struct.unpack('>I', self.data[self.pos:self.pos+4])[0]; self.pos += 4; return v
    def read_double(self):
        v = struct.unpack('>d', self.data[self.pos:self.pos+8])[0]; self.pos += 8; return v
    def read_utf8(self):
        length = self.read_short()
        s = self.data[self.pos:self.pos+length].decode('utf-8', errors='replace')
        self.pos += length; return s
    def read_amf0(self):
        marker = self.read_byte()
        if marker == AMF0_NUMBER: return self.read_double()
        elif marker == AMF0_BOOLEAN: return self.read_byte() != 0
        elif marker == AMF0_STRING: return self.read_utf8()
        elif marker == AMF0_OBJECT:
            obj = {}
            while True:
                key = self.read_utf8()
                if key == '': self.pos += 1; break
                obj[key] = self.read_amf0()
            return obj
        elif marker == AMF0_NULL: return None
        elif marker == AMF0_UNDEFINED: return None
        elif marker == AMF0_STRICT_ARRAY:
            count = self.read_long(); return [self.read_amf0() for _ in range(count)]
        elif marker == AMF0_DATE: self.read_double(); return None
        elif marker == AMF0_TYPED_OBJECT:
            cn = self.read_utf8(); obj = {'_class': cn}
            while True:
                key = self.read_utf8()
                if key == '': self.pos += 1; break
                obj[key] = self.read_amf0()
            return obj
        elif marker == AMF0_LONG_STRING:
            length = self.read_long()
            s = self.data[self.pos:self.pos+length].decode('utf-8', errors='replace')
            self.pos += length; return s
        elif marker == AMF0_AMF3:
            return self.read_amf3()
        return "<0x{:02x}>".format(marker)
    def read_u29(self):
        result = 0
        for i in range(3):
            b = self.read_byte(); result = (result << 7) | (b & 0x7F)
            if not (b & 0x80): return result
        b = self.read_byte(); return (result << 8) | b
    def read_amf3(self):
        marker = self.read_byte()
        if marker in (0x00, 0x01): return None
        elif marker == 0x02: return False
        elif marker == 0x03: return True
        elif marker == 0x04: return self.read_u29()
        elif marker == 0x05: return self.read_double()
        elif marker == 0x06:
            ref = self.read_u29()
            if ref & 1:
                length = ref >> 1
                s = self.data[self.pos:self.pos+length].decode('utf-8', errors='replace')
                self.pos += length; return s
            return "<str{}>".format(ref >> 1)
        elif marker == 0x0A:
            ref = self.read_u29()
            if ref & 1:
                cn_ref = self.read_u29()
                if cn_ref & 1:
                    cn_len = cn_ref >> 1
                    cn = self.data[self.pos:self.pos+cn_len].decode('utf-8', errors='replace')
                    self.pos += cn_len
                else:
                    cn = "<cls{}>".format(cn_ref >> 1)
                obj = {'_class': cn}
                try:
                    while True:
                        mref = self.read_u29()
                        if mref & 1:
                            mlen = mref >> 1
                            mn = self.data[self.pos:self.pos+mlen].decode('utf-8', errors='replace')
                            self.pos += mlen
                            if mn == '': break
                        else:
                            break
                except:
                    pass
                return obj
            return "<obj{}>".format(ref >> 1)
        return "<amf3-0x{:02x}>".format(marker)
    def parse(self):
        version = self.read_short()
        hc = self.read_short(); headers = []
        for _ in range(hc):
            n = self.read_utf8(); mu = self.read_byte(); dl = self.read_long()
            headers.append({'name': n, 'value': self.read_amf0()})
        bc = self.read_short(); bodies = []
        for _ in range(bc):
            t = self.read_utf8(); r = self.read_utf8(); dl = self.read_long()
            bodies.append({'target': t, 'response': r, 'data': self.read_amf0()})
        return {'version': version, 'headers': headers, 'bodies': bodies}

class AMFWriter:
    def __init__(self): self.data = bytearray()
    def wb(self, v): self.data.append(v & 0xFF)
    def ws(self, v): self.data.extend(struct.pack('>H', v))
    def wl(self, v): self.data.extend(struct.pack('>I', v))
    def wd(self, v): self.data.extend(struct.pack('>d', v))
    def wstr(self, s):
        e = s.encode('utf-8'); self.ws(len(e)); self.data.extend(e)
    def w_num(self, v): self.wb(0); self.wd(v)
    def w_str(self, v): self.wb(2); self.wstr(v)
    def w_bool(self, v): self.wb(1); self.wb(1 if v else 0)
    def w_null(self): self.wb(5)
    def w_obj(self, obj):
        self.wb(3)
        for k, v in obj.items():
            self.wstr(k)
            if isinstance(v, bool): self.w_bool(v)
            elif isinstance(v, (int, float)): self.w_num(v)
            elif isinstance(v, str): self.w_str(v)
            elif v is None: self.w_null()
            elif isinstance(v, dict): self.w_obj(v)
            elif isinstance(v, list): self.w_arr(v)
            else: self.w_str(str(v))
        self.wstr(''); self.wb(9)
    def w_arr(self, arr):
        self.wb(0x0A); self.wl(len(arr))
        for i in arr:
            if isinstance(i, bool): self.w_bool(i)
            elif isinstance(i, (int, float)): self.w_num(i)
            elif isinstance(i, str): self.w_str(i)
            elif i is None: self.w_null()
            elif isinstance(i, dict): self.w_obj(i)
            else: self.w_str(str(i))
    def w_typed(self, cn, obj):
        self.wb(0x10); self.wstr(cn)
        for k, v in obj.items():
            self.wstr(k)
            if isinstance(v, bool): self.w_bool(v)
            elif isinstance(v, (int, float)): self.w_num(v)
            elif isinstance(v, str): self.w_str(v)
            elif v is None: self.w_null()
            elif isinstance(v, dict): self.w_obj(v)
            elif isinstance(v, list): self.w_arr(v)
            else: self.w_str(str(v))
        self.wstr(''); self.wb(9)
    def build(self, response_uri, result):
        self.ws(0); self.ws(0); self.ws(1)
        self.wstr(response_uri); self.wstr(''); self.wl(0)
        if isinstance(result, dict) and '_class' in result:
            cn = result.pop('_class'); self.w_typed(cn, result)
        elif isinstance(result, dict): self.w_obj(result)
        elif isinstance(result, str): self.w_str(result)
        elif isinstance(result, (int, float)): self.w_num(result)
        else: self.w_null()
        return bytes(self.data)

def mock_response(method):
    if method == 'handshake':
        return {'_class': 'com.lexialearning.lrs.api.HandshakeResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'login':
        return {'_class': 'com.lexialearning.lrs.api.LoginResponseVO', 'errorCode': 0, 'errorMessage': None,
                'authToken': 'mock_auth_token_12345', 'studentId': 1, 'personName': 'Test Student',
                'language': 'english', 'region': 'us', 'purpose': 'course', 'currentPhaseId': 'a01',
                'currentUnitIdList': [], 'isAuditMode': False, 'isUnhidePassword': False,
                'irtForm': '', 'startUnit': 'a01A_bascateg_01', 'classList': [], 'grade': 'K',
                'teacher': 'Teacher', 'showWarmup': True, 'secondsSinceLastLogin': 0, 'warmupHighScore': 0}
    elif method == 'verifySiteId':
        return {'_class': 'com.lexialearning.lrs.api.VerifySiteIdResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'unitStatus':
        return {'_class': 'com.lexialearning.lrs.api.UnitStatusResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'stepEnd':
        return {'_class': 'com.lexialearning.lrs.api.StepEndResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'saveUnitData':
        return {'_class': 'com.lexialearning.lrs.api.ResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'saveWarmupScore':
        return {'_class': 'com.lexialearning.lrs.api.SaveWarmupScoreResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'logout':
        return {'_class': 'com.lexialearning.lrs.api.LogoutResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'logEvent':
        return {'_class': 'com.lexialearning.lrs.api.LoggingResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'getCustomerFromTeacher':
        return {'_class': 'com.lexialearning.lrs.api.TeacherResponseVO', 'errorCode': 0, 'errorMessage': None}
    elif method == 'resetStudent':
        return {'_class': 'com.lexialearning.lrs.api.ResponseVO', 'errorCode': 0, 'errorMessage': None}
    return {'_class': 'com.lexialearning.lrs.api.ResponseVO', 'errorCode': 0, 'errorMessage': None}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def do_POST(self):
        cl = int(self.headers.get('Content-Length', 0)); body = self.rfile.read(cl)
        method = 'unknown'
        try:
            r = AMFReader(body); p = r.parse()
            if p['bodies']:
                t = p['bodies'][0]['target']; method = t.split('.')[-1]
            print("[AMF] Method: {}, Body: {}".format(method, json.dumps(p, default=str)[:500]))
        except Exception as e:
            print("[AMF] Parse error: {}".format(e))
        mock = mock_response(method)
        w = AMFWriter(); resp = w.build('/1/onResult', mock)
        with open('C:\\amf-log.txt', 'a') as f:
            f.write("\n=== {} ===\nReq: {}\nResp: {}\n".format(method, body[:200].hex(), resp[:200].hex()))
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-amf')
        self.send_header('Content-Length', len(resp))
        self.end_headers(); self.wfile.write(resp)
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type', 'text/html'); self.end_headers()
        self.wfile.write(b"AMF Mock Server Running")

if __name__ == '__main__':
    port = 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('C:\\cert.pem', 'C:\\key.pem')
    s = HTTPServer(('0.0.0.0', port), Handler)
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    print("AMF Mock Server on https://0.0.0.0:{}".format(port))
    s.serve_forever()
