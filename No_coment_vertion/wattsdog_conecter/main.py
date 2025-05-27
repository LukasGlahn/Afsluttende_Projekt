import socket
import json
import re
import ssl
import os


class Proxy():
    
    def __init__(self, server):
        self.server = server
    
    def check_database_mach(self, hg_ssid, db_hash, structure_hash):
        try:
            
            if re.match(r"^[a-zA-Z0-9_]+$", hg_ssid) is None and len(hg_ssid) == 64:
                return json.dumps({"status" : "bad ssid"})
            if re.match(r"^[a-zA-Z0-9_]+$", db_hash) is None:
                return json.dumps({"status" : "bad db_hash"})
            if re.match(r"^[a-zA-Z0-9_]+$", structure_hash) is None:
                return json.dumps({"status" : "bad structure_hash"})
            
            host = self.server  
            port = 5125  

            client_socket = socket.socket()  

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False  
            context.verify_mode = ssl.CERT_NONE  
            client_socket = context.wrap_socket(client_socket, server_hostname=host)

            client_socket.connect((host, port))  

            devise_info = {
                "protocol": "db_check",
                "hg_ssid": hg_ssid,
                "db_hash": db_hash,
                "structure_hash" : structure_hash
            }
            
            message = json.dumps(devise_info)

            client_socket.send(message.encode())  
            data = client_socket.recv(1024).decode()  

            response = json.loads(data)
            client_socket.close()  
            
            if response["status"] == "good":
                return json.dumps({"status": "good"})
            elif response["status"] == "ssid not in db":
                return json.dumps({"status": "ssid not in db"})
            elif response["status"] == "update":
                return json.dumps({"status": "update"})
            else:
                return json.dumps({"status": "Hash did not match"})
        except Exception as e:
            print(f"failed to contact server: {e}")
            return json.dumps({"status": "Failed"})
    
    def db_hash_report(self, hg_ssid, db_hash, structure_hash):
        try:
            if re.match(r"^[a-zA-Z0-9_]+$", hg_ssid) is None and len(hg_ssid) == 64:
                return json.dumps({"status" : "bad ssid"})
            if re.match(r"^[a-zA-Z0-9_]+$", db_hash) is None:
                return json.dumps({"status" : "bad db_hash"})
            if re.match(r"^[a-zA-Z0-9_]+$", structure_hash) is None:
                return json.dumps({"status" : "bad structure_hash"})
            
            host = self.server  
            port = 5125  

            client_socket = socket.socket()  

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False  
            context.verify_mode = ssl.CERT_NONE  
            client_socket = context.wrap_socket(client_socket, server_hostname=host)

            client_socket.connect((host, port))  

            devise_info = {
                "protocol": "db_hash_report",
                "hg_ssid": hg_ssid,
                "db_hash": db_hash,
                "structure_hash" : structure_hash
            }
            
            message = json.dumps(devise_info)

            client_socket.send(message.encode())  
            data = client_socket.recv(1024).decode()  

            response = json.loads(data)
            client_socket.close()  

            if response["status"] == "good":
                return json.dumps({"status": "good"})
            else:
                return json.dumps({"status": "Failed"})
        except Exception as e:
            print(f"failed to contact server: {e}")
            return json.dumps({"status": "Failed"})
    
    
    def main(self):
        
        host = "0.0.0.0"
        port = 5050  

        server_socket = socket.socket()  
        server_socket.bind((host, port))  
        
        server_socket.listen(2)
        
        while True:
            try:
                conn, address = server_socket.accept()  
                print("Connection from: " + str(address))
                
                data = conn.recv(1024).decode()
                
                data = json.loads(data)
                
                print(data)
                
                if data["protocol"] == "db_check":
                    server_response = self.check_database_mach(data["hg_ssid"], data["db_hash"], data["structure_hash"])
                if data["protocol"] == "db_hash_report":
                    server_response = self.db_hash_report(data["hg_ssid"], data["db_hash"], data["structure_hash"])
                
                
                conn.send(server_response.encode())  
                
            except Exception as e:
                print(e)
            
            finally:
                print("good end")
                conn.close()  


if __name__ == '__main__':
    ip = os.environ.get("SERVER_IP", "127.0.0.1")
    proxy = Proxy(ip)
    
    proxy.main()