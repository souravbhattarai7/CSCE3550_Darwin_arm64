import unittest
import threading
import time
import http.client
import sqlite3
import os
from server import theinit_db, TheServerHandler, thedb_file
from http.server import HTTPServer
class TestJWKSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #fresh database and start the test server
        if os.path.exists(thedb_file):
            os.remove(thedb_file)
        theinit_db()
        cls.server = HTTPServer(("localhost", 8080), TheServerHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()#stop the server/remove the test 
        cls.server.server_close()
        if os.path.exists(thedb_file):
            os.remove(thedb_file)
    def test_get_jwks(self):
        conn = http.client.HTTPConnection("localhost", 8080) #check the KWKS endpoint
        conn.request("GET", "/.well-known/jwks.json")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read().decode('utf-8')
        self.assertIn("keys", data)
    def test_post_auth_valid(self):
        conn = http.client.HTTPConnection("localhost", 8080)#check that authen and return
        conn.request("POST", "/auth")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        token = response.read().decode('utf-8')
        self.assertTrue(len(token) > 0)
    def test_post_auth_expired(self):
        conn = http.client.HTTPConnection("localhost", 8080) # check that it can use exp key
        conn.request("POST", "/auth?expired=true")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        token = response.read().decode('utf-8')
        self.assertTrue(len(token) > 0)
    def test_invalid_endpoints(self):
        conn = http.client.HTTPConnection("localhost", 8080) #check that invaild get and pst endpoiunts
        conn.request("GET", "/invalid")
        response = conn.getresponse()
        self.assertEqual(response.status, 404)
        conn.request("POST", "/invalid")
        response = conn.getresponse()
        self.assertEqual(response.status, 405)
if __name__ == "__main__":
    unittest.main()
