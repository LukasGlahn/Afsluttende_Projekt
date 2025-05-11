import socket
import json

import subprocess
import socket
import json


## Loging fungtion using subprosess to make a log entry if a inconsistensy is found
def log(info,priority=7):
    identifier = "Watts Dog"

    subprocess.run(
        ["systemd-cat", "--identifier=" + identifier, f"--priority={priority}"],
        input=info.encode(),
        check=True
    )

#####################################################################################
# Main class to handel all info

class System_Checker():
    def __init__(self):
        self.database = "database1.db"
        
    def file_exsists(self,file):
        # check if the file exsists in the system

        return True

    
    def warn(self, info, severity):
        print(info)
        #log(info, loging_score)
    
    def get_file_hase(self, file):
        
        
        return "asdasdasdas23ferr"
    
    def get_ssid(self):
        ssid = "b55670b41083d7828e19520d5bbc9df0e99ded8c78366a0426bc2f53b720772e"
        return ssid
      
    #####################################################################################
    ## Self reporting
    
    def cross_check_database(self):
        # Get the sha256 hash of the database
        db_hash = self.get_file_hase(self.database)
        
        # Get the ssid of the controler
        hg_ssid = self.get_ssid()
        
        
        host = "127.0.0.1"  # Loopback adress to hit the docker container
        port = 5050  # socket server port number

        client_socket = socket.socket()  # instantiate
        client_socket.connect((host, port))  # connect to the server

        # Info for the server
        devise_info = {
            "protocol" : "db_check",
            "hg_ssid" : hg_ssid,
            "db_hash" : db_hash
        }
        
        # Make the dir in to a json string for eazy sending
        message = json.dumps(devise_info)

        
        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        response = json.loads(data)
        
        client_socket.close()  # close the connection
        
        # Chesk the response if good to indicate that the hash mached
        if response["status"] == "good":
            return "good"
        elif response["status"] == "ssid not in db":
            self.report_db_hash()
            return "updated db hash"
        elif response["status"] == "update":
            self.report_db_hash()
            return "updated db hash"
        else:
            print(response)
            self.warn("database dose not mach", 4)
            return None

    
    def report_db_hash(self):
        # Get the sha256 hash of the database
        db_hash = self.get_file_hase(self.database)
        
        # Get the ssid of the controler
        hg_ssid = self.get_ssid()
        
        
        host = "127.0.0.1"  # Loopback adress to hit the docker container
        port = 5050  # socket server port number

        client_socket = socket.socket()  # instantiate
        client_socket.connect((host, port))  # connect to the server

        # Info for the server
        devise_info = {
            "protocol" : "db_hash_report",
            "hg_ssid" : hg_ssid,
            "db_hash" : db_hash
        }
        
        # Make the dir in to a json string for eazy sending
        message = json.dumps(devise_info)

        
        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        response = json.loads(data)
        
        client_socket.close()  # close the connection
        
        # Chesk the response if good to indicate that the hash mached
        if response["status"] == "good":
            print("good")
            return "good"
        else:
            self.warn("Not alowed", 4)
            print("Not alowed")
            return None
    

        
    
    



if __name__ == "__main__":

    system_test = System_Checker()
    
    
    print(system_test.cross_check_database())