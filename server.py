import sqlite3, time, json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
thedb_file = "totally_not_my_privateKeys.db"
theport = 8080
def theinit_db(): #create the table
    theconn = sqlite3.connect(thedb_file)
    thecursor = theconn.cursor()
    thecursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    thecursor.execute("SELECT COUNT(*) FROM keys")
    thecount = thecursor.fetchone()[0]
    if thecount == 0: #generate the key
        thecurrent_time = int(time.time())
        for theoffset in (-3600, 3600):
            thepriv_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            thepem_data = thepriv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            theexp_time = thecurrent_time + theoffset
            thecursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (sqlite3.Binary(thepem_data), theexp_time)
            )
        theconn.commit()
    theconn.close()
class TheServerHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path.startswith("/auth"):
            theparsed_path = urlparse(self.path)
            thequery_params = parse_qs(theparsed_path.query)
            theis_expired = 'expired' in thequery_params
            theconn = sqlite3.connect(thedb_file)
            thecursor = theconn.cursor()
            thecurrent_time = int(time.time())
            #select the expired or vaild
            if theis_expired:
                thecursor.execute("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (thecurrent_time,))
            else:
                thecursor.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (thecurrent_time,))
            therow = thecursor.fetchone()
            theconn.close()
            if not therow:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"No matching key found")
                return
                
            thekid, thekey_blob = therow
            theprivate_key_obj = serialization.load_pem_private_key(thekey_blob, password=None)
            
            thepayload = { #make JWT wth time
                "user": "userABC",
                "iat": thecurrent_time,
                "exp": thecurrent_time + 300
            }            
            thetoken = jwt.encode(
                thepayload,
                theprivate_key_obj,
                algorithm="RS256",
                headers={"kid": str(thekid)}
            )            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(thetoken.encode('utf-8'))
        else:
            self.send_response(405)
            self.end_headers()
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            theconn = sqlite3.connect(thedb_file)
            thecursor = theconn.cursor()
            thecurrent_time = int(time.time())
            thecursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (thecurrent_time,)) #retrieve the only keys
            therows = thecursor.fetchall()
            theconn.close()
            thekeys_list = []
            for thekid, thekey_blob in therows:
                thepriv_key_obj = serialization.load_pem_private_key(thekey_blob, password=None)
                thepub_key_obj = thepriv_key_obj.public_key()
                thepub_numbers = thepub_key_obj.public_numbers()
                import base64
                def int_to_base64url(n): #convert rsa numbers to base form
                    byte_length = (n.bit_length() + 7) // 8
                    b = n.to_bytes(byte_length or 1, 'big')
                    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')
                thekeys_list.append({
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": str(thekid),
                    "n": int_to_base64url(thepub_numbers.n),
                    "e": int_to_base64url(thepub_numbers.e)
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": thekeys_list}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
if __name__ == "__main__":
    theinit_db()
    theserver = HTTPServer(("localhost", theport), TheServerHandler)
    print(f"Server started on port {theport}...")
    theserver.serve_forever()



