import subprocess
from system_file_checker import SystemFileChecker
from firewall import FireWallChecker
import sys
import socket
import hashlib
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
        self.system_file_checker = SystemFileChecker(self.database)
        self.fire_wall_checker = FireWallChecker()
        
    def file_exsists(self,file):
        # check if the file exsists in the system
        try:
            with open(file, 'r') as f:
                return True
        except FileNotFoundError:
            return False
    
    def warn(self, info, severity):
        loging_score = 5 - severity
        
        if loging_score < 0:
            loging_score = 0
        
        print(info, " at level ", loging_score)
        ## Warning about a insdent to the systemlog to be send to server
        # If in testing keep comented out wnen not needed to stop spam to watts 
        print(info)
        #log(info, loging_score)
    
    def get_file_hase(self, file):
        # Compute the hash of a file using the specified algorithm.
        hash_func = hashlib.new('sha256')
        # Open the file in binary mode
        
        with open(file, 'rb') as file:
            # Read the file in chunks of 8192 bytes
            while chunk := file.read(8192):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def get_ssid(self):
        with open("/mnt/config/hems_*","r") as file:
            ids = file.read()
            ids = ids.split("\n")
            ssid = ids[0]
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
    
    #####################################################################################
    ## Scan types
    
    # build all databases for the system to fungtion
    def build_database(self):
        # make the database
        self.system_file_checker.build_db()
        
        # fille te database with all files requerd
        self.system_file_checker.build_system_db()
        
    
    ## Full scan weary resouse intesiv and takes a while to do
    def full_scan(self):
        ## Check if the database exsists
        if self.file_exsists(self.database):
            #check that the database is unchanged
            system_checker.cross_check_database()
        else:
            self.build_database()
            return
        
        ## Scan the system
        firewall_vialations = self.fire_wall_checker.check_difrense()
        
        changed_files = self.system_file_checker.check_system_for_changes()
        
        ## warn about all found problems
        # changed_files
        for vialation in changed_files:
            self.warn(vialation["file content"], vialation["severity"])
        
        # firewall_vialations
        for vialation in firewall_vialations:
            self.warn(vialation["info"], vialation["severity"])
    
    ## smaller scan that can be run offen as it dos not take to much too run
    def small_scan(self):
        ## Scan the system
        firewall_vialations = self.fire_wall_checker.check_difrense()

        # firewall_vialations
        for vialation in firewall_vialations:
            self.warn(vialation["info"], vialation["severity"])
    



if __name__ == "__main__":
    system_checker = System_Checker()

    #system_checker.cross_check_database()
    arguments = sys.argv
    
    scan_type = None
    if "full_scan" in arguments:
        scan_type = "full_scan"
    if "small_scan" in arguments:
        scan_type = "small_scan"
    if "build_db" in arguments:
        scan_type = "build_db"
    
    if scan_type == "full_scan":
        system_checker.full_scan()
    elif scan_type == "small_scan":
        system_checker.small_scan()
    elif scan_type == "build_db":
        system_checker.build_database()
    else:
        exit()
    