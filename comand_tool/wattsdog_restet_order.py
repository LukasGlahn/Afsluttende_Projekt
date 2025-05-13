#!/usr/bin/env python3

import socket
import ssl
import json

def check_database_mach(unit, password, server = "127.0.0.1"):
    try:
        host = server  # Loopback address to hit the docker container
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
            "protocol": "reset_order",
            "unit": unit,
            "password": password,
        }
        
        # Make the dir into a JSON string for easy sending
        message = json.dumps(devise_info)

        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        response = json.loads(data)
        client_socket.close()  # close the connection
        
        # Check the response if good to indicate that the hash matched
        return response
    except Exception as e:
        print(f"failed to contact server: {e}")
        return json.dumps({"status": "Failed"})
    
    
if __name__ == "__main__":
    unit = input("give unit ssid or all for all ssids in system: ")
    password = input("give password: ")

    response = check_database_mach(unit, password)
    print(response["status"])