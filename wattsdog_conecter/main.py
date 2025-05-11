import socket
import json
import re
import ssl


class Proxy():
    
    def __init__(self, server):
        self.server = server
    
    def check_database_mach(self, hg_ssid, db_hash):
        # Check if the ssid and db_hash are valid
        if re.match(r"^[a-zA-Z0-9_]+$", hg_ssid) is None and len(hg_ssid) == 64:
            return "bad ssid"
        if re.match(r"^[a-zA-Z0-9_]+$", db_hash) is None:
            return "bad db_hash"
        
        host = self.server  # Loopback address to hit the docker container
        port = 5125  # socket server port number

        client_socket = socket.socket()  # instantiate

        # Wrap the socket with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Disable hostname verification
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
        client_socket = context.wrap_socket(client_socket, server_hostname=host)

        client_socket.connect((host, port))  # connect to the server

        # Info for the server
        devise_info = {
            "protocol": "db_check",
            "hg_ssid": hg_ssid,
            "db_hash": db_hash
        }
        
        # Make the dir into a JSON string for easy sending
        message = json.dumps(devise_info)

        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        response = json.loads(data)
        client_socket.close()  # close the connection
        
        # Check the response if good to indicate that the hash matched
        if response["status"] == "good":
            return json.dumps({"status": "good"})
        elif response["status"] == "ssid not in db":
            return json.dumps({"status": "ssid not in db"})
        elif response["status"] == "update":
            return json.dumps({"status": "update"})
        else:
            return json.dumps({"status": "Hash did not match"})
    
    def db_hash_report(self, hg_ssid, db_hash):
        # Check if the ssid and db_hash are valid
        if re.match(r"^[a-zA-Z0-9_]+$", hg_ssid) is None and len(hg_ssid) == 64:
            return "bad ssid"
        if re.match(r"^[a-zA-Z0-9_]+$", db_hash) is None:
            return "bad db_hash"
        
        host = self.server  # Loopback address to hit the docker container
        port = 5125  # socket server port number

        client_socket = socket.socket()  # instantiate

        # Wrap the socket with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Disable hostname verification
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
        client_socket = context.wrap_socket(client_socket, server_hostname=host)

        client_socket.connect((host, port))  # connect to the server

        # Info for the server
        devise_info = {
            "protocol": "db_hash_report",
            "hg_ssid": hg_ssid,
            "db_hash": db_hash
        }
        
        # Make the dir into a JSON string for easy sending
        message = json.dumps(devise_info)

        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        response = json.loads(data)
        client_socket.close()  # close the connection
        
        # Check the response if good to indicate that the hash matched
        if response["status"] == "good":
            return json.dumps({"status": "good"})
        else:
            return json.dumps({"status": "Failed"})
    
    
    def main(self):
        # get the hostname
        host = "0.0.0.0"
        port = 5050  # initiate port no above 1024

        server_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        server_socket.bind((host, port))  # bind host address and port together

        # configure how many client the server can listen simultaneously
        server_socket.listen(2)
        
        while True:
            conn, address = server_socket.accept()  # accept new connection
            print("Connection from: " + str(address))
            
            # receive data stream. it won't accept data packet greater than 1024 bytes
            data = conn.recv(1024).decode()
            
            data = json.loads(data)
            
            if data["protocol"] == "db_check":
                server_response = self.check_database_mach(data["hg_ssid"], data["db_hash"])
            if data["protocol"] == "db_hash_report":
                server_response = self.db_hash_report(data["hg_ssid"], data["db_hash"])
            
            
            conn.send(server_response.encode())  # send data to the client

            conn.close()  # close the connection


if __name__ == '__main__':
    proxy = Proxy("127.0.0.1")
    
    proxy.main()