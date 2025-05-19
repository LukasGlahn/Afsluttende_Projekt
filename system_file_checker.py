import sqlite3
import os
import hashlib
import stat
import json
import sys

# fungtion to return the curent folder path to the file curently running, 
# takes one argument to append eanything at the end of the returned string like a filename
def get_folder_path(append=''):
    # Get the script that was initially executed
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
        # Create a new SQLite database with all necessary tables
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
        # file is a tuple with the following structure:
        # (name, path, hash, permissions, users, severity)
        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_hashes (name, path, hash, permissions, users, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', file)
        conn.commit()
        conn.close()
        
    def get_file_hase(self, file):
        # Compute the hash of a file using the specified algorithm.
        hash_func = hashlib.new('md5')
        # Open the file in binary mode
        
        with open(file, 'rb') as file:
            # Read the file in chunks of 8192 bytes
            while chunk := file.read(8192):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()

    
    def get_file_info(self, file, severity, checks = "hpu"):
        # Get info about file like hash, permissions, users, severity from linux system
        file_info = os.lstat(file)
        
        # Get the file permissions if "p" is in checks 
        if "p" in checks:
            # Get the file permissions in octal format
            permissions = oct(file_info.st_mode)[-3:]
        else:
            permissions = None

        if "u" in checks:
            user = file_info.st_uid 
            group = file_info.st_gid
            user_grupe = f"{user}/{group}"
        else:
            user_grupe = None
        
        # Get the file hash if "h" is in checks
        if "h" in checks:
            mode = os.lstat(file).st_mode
            if stat.S_ISREG(mode):
                # Calculate hash of the file
                # If it's a file, get the hash using the get_file_hase method
                file_data = self.get_file_hase(file)
            elif stat.S_ISLNK(mode):
                # If it's a symlink, get the target of the symlink
                file_data = os.path.realpath(file)
            else:
                # If it's not a regular file or symlink, set file_data to None
                print(f"File did not mach the a filetile that is comparebelle: {file}")
                file_data = None
        else:
            file_data = None
        
        # Get the file name by splitting the path and getting the last element
        file_name = file.split("/")[-1]
        # Get the file path by removing the file name from the full path
        path = file.split("/")[:-1]
        path = "/".join(path)
        
        # return the file info as a tuple
        # (name, path, hash, permissions, users, severity) to mach the db structure
        return (file_name, path, file_data, permissions, user_grupe, severity)
    
    ##################################################################################################
    # Filling part
    
    def build_db_from_folder(self, folder, sructure):
        print(folder)
        default_checks = sructure["default"]["checks"]
        default_severity = sructure["default"]["severity"]
        # exseption states
        exceptions = sructure["exceptions"]

        # Ensure self.database is always in file_exceptions
        if self.db not in sructure["file_exceptions"]:
            sructure["file_exceptions"][self.db] = {
                "checks": "pu",
                "severity": 5
            }
        file_exceptions = sructure["file_exceptions"]

        # Iterate over all files and folders in the folder
        for root, dirs, files in os.walk(folder):  # unpacking files for prosessing
            
            # Check if the current folder is in the exceptions
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


            # Iterate over all files in the folder
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    # Get the file info and add it to the database
                    
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
        # Build the database with all posebel files and folders in the system
        
        structure = self.structure
        for folder in structure:
            try:
                self.build_db_from_folder(folder, structure[folder])
            except Exception as e:
                print(f"Error processing folder {folder}: {e}")

    ##################################################################################################
    # Comparesen part
    
    # Check if the folder has changed since the last check         
    def check_folder_for_changes(self, folder, sructure):
        ## unpack all info about the sructure
        print(folder)
        default_checks = sructure["default"]["checks"]
        default_severity = sructure["default"]["severity"]
        # exseption states
        if self.db not in sructure["file_exceptions"]:
            sructure["file_exceptions"][self.db] = {
                "checks": "pu",
                "severity": 5
            }
        file_exceptions = sructure["file_exceptions"]
        exceptions = sructure["exceptions"]
        
        # list to store vialations found doring the test
        vialations = []
        
        files = os.walk(folder)
        for root, dirs, files in files:
            # Check if the current folder is in the exceptions
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
                    # Get the file info and check if it exists in the database
                    
                    if file_path in file_exceptions:
                        if sructure["file_exceptions"][file_path]["checks"] == "":
                            continue
                        else:
                            file_severity = file_exceptions[file_path]["severity"]
                            file_checks = file_exceptions[file_path]["checks"]
                            
                            file_info = self.get_file_info(file_path, file_severity, file_checks)
                    else:
                        file_info = self.get_file_info(file_path, severity, checks)
                    
                    # get file info from the database
                    conn = sqlite3.connect(self.db)
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT name, path, hash, permissions, users, severity FROM file_hashes WHERE name=? AND path=?
                    ''', (file_info[0], file_info[1]))
                    result = cursor.fetchone()
                    conn.close()

                    # Check if the file exists in the database
                    if result is None:
                        print(f"File {file_path} is new.")
                        
                        file_vialations.append({
                                "problem": "new",
                                "file content": f"File {file_path} is new.",
                                "severity" : file_info[5]
                                })
                    else:
                        #check for changes in the file
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
                    
                    # If ther was a change add it to vialations so it can be returnd later
                    if len(file_vialations) > 0:
                        vialations.append({
                            "file" : file_path,
                            "vialations" : file_vialations,
                        })
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
        return vialations
        
    
    def check_system_for_changes(self):
        # Check if the system has changed since the last check
        
        # Check if the database exists and has data
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
        
        # Load the structure from the JSON file
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