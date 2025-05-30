import subprocess
from system_file_checker import SystemFileChecker
from firewall import FireWallChecker
from av import VirusScaner
import sys
import socket
import hashlib
import json
import os
import sqlite3


def get_folder_path(append=''):
    
    script_path = os.path.abspath(sys.argv[0])
    folder_path = os.path.dirname(script_path)
    return os.path.join(folder_path, append)


def log(info,priority=7):
    identifier = "Watts_Dog"

    subprocess.run(
        ["systemd-cat", "--identifier=" + identifier, f"--priority={priority}"],
        input=info.encode(),
        check=True
    )


class System_Checker():
    def __init__(self):
        self.database = get_folder_path("database1.db")
        self.system_file_checker = SystemFileChecker(self.database)
        self.fire_wall_checker = FireWallChecker(self.database)
        self.virus_scaner = VirusScaner()
        
    def db_exsists(self, file):

        if not os.path.isfile(file):
            return False
        if os.path.getsize(file) == 0:
            return False

        try:
            conn = sqlite3.connect(file)
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='file_hashes';")
            file_hashes_exists = cursor.fetchone() is not None

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_rules';")
            firewall_rules_exists = cursor.fetchone() is not None
            conn.close()
            return file_hashes_exists and firewall_rules_exists
        except Exception:
            return False
    
    def warn(self, info, severity):
        loging_score = 5 - severity
        
        if loging_score < 0:
            loging_score = 0
        
        print(info, " at level ", loging_score)

        print(info)

    
    def get_file_hase(self, file):

        hash_func = hashlib.new('sha256')
        
        with open(file, 'rb') as file:

            while chunk := file.read(8192):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def get_ssid(self):
        with open("/mnt/config/hems_registration_id","r") as file:
            ssid = file.read()
            return ssid
      
    
    def cross_check_database(self):
        db_hash = self.get_file_hase(self.database)
        structure = get_folder_path("structure.json")
        structure_hash = self.get_file_hase(structure)
        
        hg_ssid = self.get_ssid()
          
        host = "127.0.0.1"  
        port = 5050  

        client_socket = socket.socket()  
        client_socket.connect((host, port))  

        devise_info = {
            "protocol" : "db_check",
            "hg_ssid" : hg_ssid,
            "db_hash" : db_hash,
            "structure_hash" : structure_hash
        }
       
        message = json.dumps(devise_info)

        client_socket.send(message.encode())  
        data = client_socket.recv(1024).decode()  

        response = json.loads(data)
        
        client_socket.close()  
        
        if response["status"] == "good":
            return "good"
        elif response["status"] == "ssid not in db":
            self.report_db_hash()
            return "updated db hash"
        elif response["status"] == "update":
            print("update")
            os.remove(self.database)
            self.build_database()
            exit()
            return "updated db hash"
        else:
            print(response)
            self.warn("Database does not match", 4)
            return None

    
    def report_db_hash(self):

        db_hash = self.get_file_hase(self.database)
        
        structure_hash = self.get_file_hase("structure.json")
        
        
        hg_ssid = self.get_ssid()
        
        
        host = "127.0.0.1"  
        port = 5050  

        client_socket = socket.socket()  
        client_socket.connect((host, port))  

        devise_info = {
            "protocol" : "db_hash_report",
            "hg_ssid" : hg_ssid,
            "db_hash" : db_hash,
            "structure_hash" : structure_hash
        }
        
        message = json.dumps(devise_info)

        
        client_socket.send(message.encode())  
        data = client_socket.recv(1024).decode()  

        response = json.loads(data)
        
        client_socket.close()  
        
        if response["status"] == "good":
            print("good")
            return "good"
        else:
            self.warn("Not alowed", 3)
            print("Not alowed")
            return None
    
    

    def build_database(self):
        
        self.system_file_checker.build_db()
        
       
        self.system_file_checker.build_system_db()
        
        self.fire_wall_checker.duild_db()
        
        self.report_db_hash()
        
    
    def full_scan(self):
        
        if self.db_exsists(self.database):

            system_checker.cross_check_database()
        else:
            print("no db building first setup")
            self.build_database()
            return
        
        print("full scan starting")

        firewall_vialations = self.fire_wall_checker.check_system_rules()
        
        changed_files = self.system_file_checker.check_system_for_changes()
        
        viruses_found = self.virus_scaner.scan_all_directories()
        

        for file_vialation in changed_files:
            for vialation in file_vialation["vialations"]:
                self.warn(vialation["file content"], vialation["severity"])
        

        for vialation in firewall_vialations:
            self.warn(vialation["info"], vialation["severity"])
            

        for vialation in viruses_found:
            self.warn(vialation["info"], vialation["severity"])
    

    def small_scan(self):
        if self.file_exsists(self.database):

            system_checker.cross_check_database()
        else:
            self.build_database()
            return

        firewall_vialations = self.fire_wall_checker.check_system_rules()


        for vialation in firewall_vialations:
            self.warn(vialation["info"], vialation["severity"])
    



if __name__ == "__main__":
    system_checker = System_Checker()


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
