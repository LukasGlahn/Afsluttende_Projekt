#!/usr/bin/env python3

import socket
import ssl
import json
import getpass

def check_database_mach(unit, password, server = "192.168.0.61"):
    try:
        host = server  
        port = 5125  

        client_socket = socket.socket()  


        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  
        context.verify_mode = ssl.CERT_NONE  
        client_socket = context.wrap_socket(client_socket, server_hostname=host)

        client_socket.connect((host, port))  

        devise_info = {
            "protocol": "reset_order",
            "unit": unit,
            "password": password,
        }
        
        message = json.dumps(devise_info)

        client_socket.send(message.encode())  
        data = client_socket.recv(1024).decode()  

        response = json.loads(data)
        client_socket.close()  
        
        return response
    except Exception as e:
        print(f"failed to contact server: {e}")
        return json.dumps({"status": "Failed"})
    
    
if __name__ == "__main__":
    unit = input("give unit ssid or all for all ssids in system: ")
    password = getpass.getpass("give password: ")

    response = check_database_mach(unit, password)
    print(response["status"])