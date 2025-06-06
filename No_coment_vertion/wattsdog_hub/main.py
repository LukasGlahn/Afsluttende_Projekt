import socket
import json
import re
import sqlite3
import ssl
import bcrypt
import os


class WatssDogHub():
    
    def __init__(self):
        self.database = 'wattsdog.db'
    
    def make_db(self, admin_password="admin"):
        
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hg_integrity (
            id             INTEGER     PRIMARY KEY AUTOINCREMENT
                        UNIQUE
                        NOT NULL,
            ssid           TEXT        UNIQUE
                        NOT NULL,
            db_hash        TEXT,
            structure_hash TEXT,
            refresh        INTEGER (2) 
        );
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT
                    NOT NULL
                    UNIQUE,
            user     TEXT    UNIQUE
                    NOT NULL,
            password TEXT    NOT NULL
        );
        ''')
        
        cursor.execute('''
            INSERT OR IGNORE INTO users (user, password) VALUES (?, ?)
        ''', ("admin", bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')))

        conn.commit()
        conn.close()
    
    
    def check_database_hash_mach(self, hg_ssid, db_hash, structure_hash):
        try:
            if re.match(r"^[a-zA-Z0-9_]+$", hg_ssid) is None and len(hg_ssid) == 64:
                return json.dumps({"status" : "bad ssid"})
            if re.match(r"^[a-zA-Z0-9_]+$", db_hash) is None:
                return json.dumps({"status" : "bad db_hash"})
            if re.match(r"^[a-zA-Z0-9_]+$", structure_hash) is None:
                return json.dumps({"status" : "bad structure_hash"})
            
            conn = sqlite3.connect(self.database)
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM hg_integrity WHERE ssid=?", (hg_ssid,))
            row = cursor.fetchone()

            if row:
                if row[4] == 1:
                    return json.dumps({"status" : "update"})
                
                elif row[2] == db_hash and row[3] == structure_hash:
                    return json.dumps({"status" : "good"})
                else:
                    return json.dumps({"status" : "hash did not mach"})
            else:
                return json.dumps({"status" : "ssid not in db"})
        except Exception as e:
            print(e)
            return json.dumps({"status" : "hash did not mach"})
    
    
    def get_hash_report(self, hg_ssid, db_hash, structure_hash):
        try:
            
            if re.match(r"^[a-zA-Z0-9_]+$", hg_ssid) is None and len(hg_ssid) == 64:
                return json.dumps({"status" : "bad ssid"})
            if re.match(r"^[a-zA-Z0-9_]+$", db_hash) is None:
                return json.dumps({"status" : "bad db_hash"})
            if re.match(r"^[a-zA-Z0-9_]+$", structure_hash) is None:
                return json.dumps({"status" : "bad structure_hash"})
            
            conn = sqlite3.connect(self.database)
            cursor = conn.cursor()

            cursor.execute("SELECT refresh FROM hg_integrity WHERE ssid=?", (hg_ssid,))
            row = cursor.fetchone()

            if row:
                
                if row[0] == 1:
                    cursor.execute("UPDATE hg_integrity SET refresh = 0, db_hash = ?, structure_hash = ? WHERE ssid=?", (db_hash, structure_hash, hg_ssid))
                    conn.commit()
                    return json.dumps({"status" : "good"})
                else:
                    return json.dumps({"status" : "Failed"})
            else:
                cursor.execute("INSERT INTO hg_integrity (ssid, db_hash, structure_hash, refresh) VALUES (?, ?, ?, 0)", (hg_ssid, db_hash, structure_hash))
                conn.commit()
                return json.dumps({"status" : "good"})
        except Exception as e:
            print(e)
            return json.dumps({"status" : "Failed"})
          
    
    def set_reset_order(self, password, unit):
        try:
            
            if re.match(r"^[a-zA-Z0-9_]+$", unit) is None:
                return json.dumps({"status" : "unit"})
            
            conn = sqlite3.connect(self.database)
            cursor = conn.cursor()
            
            
            cursor.execute("SELECT password FROM users WHERE user=?", ("admin",))
            row = cursor.fetchone()
            if bcrypt.checkpw(password.encode('utf-8'), row[0].encode('utf-8')) == False:
                return json.dumps({"status" : "bad password"})

            if unit == "all":
                cursor.execute("UPDATE hg_integrity SET refresh = 1")
            else:
                cursor.execute("UPDATE hg_integrity SET refresh = 1 WHERE ssid=?", (unit,))
            
            conn.commit()
            conn.close()

            return json.dumps({"status" : "good"})
        except Exception as e:
            print(e)
            return json.dumps({"status" : "Failed"})
        
    
    def main(self):
        host = "0.0.0.0"
        port = 5125  

        server_socket = socket.socket()  
        server_socket.bind((host, port))  

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        server_socket = context.wrap_socket(server_socket, server_side=True)

        server_socket.listen(2)
        
        while True:
            try:
                conn, address = server_socket.accept()  
                print("Connection from: " + str(address))
                
                data = conn.recv(1024).decode()
                
                data = json.loads(data)
                
                if data["protocol"] == "db_check":
                    server_response = self.check_database_hash_mach(data["hg_ssid"], data["db_hash"], data["structure_hash"])
                if data["protocol"] == "db_hash_report":
                    server_response = self.get_hash_report(data["hg_ssid"], data["db_hash"], data["structure_hash"])
                if data["protocol"] == "reset_order":
                    server_response = self.set_reset_order(data["password"], data["unit"])

                conn.send(server_response.encode())  
            except Exception as e:
                print(e)
            finally:
                conn.close()  




if __name__ == "__main__":
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin")
    hub = WatssDogHub()
    hub.make_db(admin_password=admin_password)
    hub.main()
