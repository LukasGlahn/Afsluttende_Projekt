import sqlite3
import os
import hashlib
import stat
import json
import sys


def get_folder_path(append=''):
    
    script_path = os.path.abspath(sys.argv[0])
    folder_path = os.path.dirname(script_path)
    return os.path.join(folder_path, append)


class SystemFileChecker:
    def __init__(self, database_name):
        self.db = database_name
        with open(get_folder_path("structure.json"), "r") as file:
            json_structure = file.read()
        self.structure = json.loads(json_structure)

    def build_db(self):
        
        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE file_hashes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT
                                NOT NULL
                                UNIQUE,
            name        TEXT    NOT NULL,
            path        TEXT    NOT NULL,
            hash        TEXT,
            permissions TEXT,
            users       TEXT,
            severity    INTEGER NOT NULL
        );
        ''')
        conn.commit()
        conn.close()
    
    def add_file_to_db(self, file):

        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_hashes (name, path, hash, permissions, users, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', file)
        conn.commit()
        conn.close()
        
    def get_file_hase(self, file):

        hash_func = hashlib.new('md5')

        
        with open(file, 'rb') as file:

            while chunk := file.read(8192):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()

    
    def get_file_info(self, file, severity, checks = "hpu"):

        file_info = os.lstat(file)
        
  
        if "p" in checks:

            permissions = oct(file_info.st_mode)[-3:]
        else:
            permissions = None

        if "u" in checks:
            user = file_info.st_uid 
            group = file_info.st_gid
            user_grupe = f"{user}/{group}"
        else:
            user_grupe = None
        
        if "h" in checks:
            mode = os.lstat(file).st_mode
            if stat.S_ISREG(mode):

                file_data = self.get_file_hase(file)
            elif stat.S_ISLNK(mode):

                file_data = os.path.realpath(file)
            else:

                print(f"File did not mach the a filetile that is comparebelle: {file}")
                file_data = None
        else:
            file_data = None
        

        file_name = file.split("/")[-1]

        path = file.split("/")[:-1]
        path = "/".join(path)
        
        return (file_name, path, file_data, permissions, user_grupe, severity)
    

    
    def build_db_from_folder(self, folder, sructure):
        print(folder)
        default_checks = sructure["default"]["checks"]
        default_severity = sructure["default"]["severity"]

        exceptions = sructure["exceptions"]


        if self.db not in sructure["file_exceptions"]:
            sructure["file_exceptions"][self.db] = {
                "checks": "pu",
                "severity": 5
            }
        file_exceptions = sructure["file_exceptions"]


        for root, dirs, files in os.walk(folder):  
            

            match = next(
                (folder for folder in exceptions if root == folder or root.startswith(folder + "/")),
                None
            )
            
            if match:
                if sructure["exceptions"][match]["checks"] == "":
                    continue
                else:
                    checks = sructure["exceptions"][match]["checks"]
                    severity = sructure["exceptions"][match]["severity"]
            else:
                checks = default_checks
                severity = default_severity


            for file in files:
                try:
                    file_path = os.path.join(root, file)

                    
                    if file_path in file_exceptions:
                        if sructure["file_exceptions"][file_path]["checks"] == "":
                            continue
                        else:
                            file_severity = file_exceptions[file_path]["severity"]
                            file_checks = file_exceptions[file_path]["checks"]
                            
                            file_info = self.get_file_info(file_path, file_severity, file_checks)
                            self.add_file_to_db(file_info)
                    else:
                        file_info = self.get_file_info(file_path, severity, checks)
                        self.add_file_to_db(file_info)
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
                    
    def build_system_db(self):
        
        structure = self.structure
        for folder in structure:
            try:
                self.build_db_from_folder(folder, structure[folder])
            except Exception as e:
                print(f"Error processing folder {folder}: {e}")

       
    def check_folder_for_changes(self, folder, sructure):

        print(folder)
        default_checks = sructure["default"]["checks"]
        default_severity = sructure["default"]["severity"]

        if self.db not in sructure["file_exceptions"]:
            sructure["file_exceptions"][self.db] = {
                "checks": "pu",
                "severity": 5
            }
        file_exceptions = sructure["file_exceptions"]
        exceptions = sructure["exceptions"]
        

        vialations = []
        
        files = os.walk(folder)
        for root, dirs, files in files:

            match = next(
                (folder for folder in exceptions if root == folder or root.startswith(folder + "/")),
                None
            )
            if match:
                if sructure["exceptions"][match]["checks"] == "":
                    continue
                else:
                    checks = sructure["exceptions"][match]["checks"]
                    severity = sructure["exceptions"][match]["severity"]
            else:
                checks = default_checks
                severity = default_severity
                
            
            for file in files:
                try:
                    
                    file_vialations  = []
                    file_path = os.path.join(root, file)

                    
                    if file_path in file_exceptions:
                        if sructure["file_exceptions"][file_path]["checks"] == "":
                            continue
                        else:
                            file_severity = file_exceptions[file_path]["severity"]
                            file_checks = file_exceptions[file_path]["checks"]
                            
                            file_info = self.get_file_info(file_path, file_severity, file_checks)
                    else:
                        file_info = self.get_file_info(file_path, severity, checks)
                    

                    conn = sqlite3.connect(self.db)
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT name, path, hash, permissions, users, severity FROM file_hashes WHERE name=? AND path=?
                    ''', (file_info[0], file_info[1]))
                    result = cursor.fetchone()
                    conn.close()

                    if result is None:
                        print(f"File {file_path} is new.")
                        
                        file_vialations.append({
                                "problem": "new",
                                "file content": f"File {file_path} is new.",
                                "severity" : file_info[5]
                                })
                    else:

                        if result[2] != file_info[2]:
                            print(f"File {file_path} has changed. Hash went from {result[2]} to {file_info[2]}.")
                            file_vialations.append({
                                "problem": "file change",
                                "file content": f"File {file_path} has changed. Hash went from {result[2]} to {file_info[2]}.",
                                "severity" : result[5]
                                })
                        if result[3] != file_info[3]:
                            print(f"File {file_path} has different permissions. used to be {result[3]} now is {file_info[3]}.")

                            file_vialations.append({
                                "problem": "permissions",
                                "file content": f"File {file_path} has different permissions. used to be {result[3]} now is {file_info[3]}.",
                                "severity" : result[5]
                                })
                        if result[4] != file_info[4]:
                            print(f"File {file_path} has different user/group. used to be {result[4]} now is {file_info[4]}.")
                            file_vialations.append({
                                "problem": "user/group",
                                "file content": f"File {file_path} has different user/group. used to be {result[4]} now is {file_info[4]}.",
                                "severity" : result[5]
                                })
                    
                    if len(file_vialations) > 0:
                        vialations.append({
                            "file" : file_path,
                            "vialations" : file_vialations,
                        })
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
        return vialations
        
    
    def check_system_for_changes(self):

        if not os.path.exists(self.db):
            print(f"Database {self.db} does not exist. Creating a new one.")
            self.build_db()
            self.build_system_db()
            return []

        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM file_hashes")
            count = cursor.fetchone()[0]
        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                print(f"Table file_hashes does not exist in {self.db}. Creating table.")
                self.build_db()
                self.build_system_db()
                conn.close()
                return []
        conn.close()

        if count < 1:
            print(f"Database {self.db} exists but contains no data.")
            self.build_system_db()
            return []
        
        count = None
        
        structure = self.structure
        
        vialations = []
        
        for folder in structure:
            try:
                vialations += self.check_folder_for_changes(folder, structure[folder])
            except Exception as e:
                print(f"Error processing folder {folder}: {e}")
                
        return vialations

        
if __name__ == "__main__":
    system_checker = SystemFileChecker("database1.db")
    system_checker.build_db()
    system_checker.build_system_db()
    print(system_checker.check_system_for_changes())
    print("Database created successfully.")