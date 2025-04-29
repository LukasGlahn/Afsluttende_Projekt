import sqlite3
import os
import hashlib


class UserChecker:
    def __init__(self):
        self.db = "database1.db"

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

    def get_folder_hase(self, folder):
        # Compute the hash of a folder by hashing all files in it.
        hash_func = hashlib.new('md5')
        # Iterate over all files in the folder
        for root, _, files in os.walk(folder):
            for file in files:
                file_path = os.path.join(root, file)
                # Open the file in binary mode
                with open(file_path, 'rb') as f:
                    # Read the file in chunks of 8192 bytes
                    while chunk := f.read(8192):
                        hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    
    def get_file_info(self, file, severity):
        # Get info about file like hash, permissions, users, severity from linux system
        file_info = os.stat(file)
        permissions = oct(file_info.st_mode)[-3:]
        user = file_info.st_uid 
        group = file_info.st_gid
        # Calculate hash of the file
        hash_md5 = self.get_file_hase(file)
        
        # Get the file name by splitting the path and getting the last element
        file_name = file.split("/")[-1]
        # Get the file path by removing the file name from the full path
        path = file.split("/")[:-1]
        path = "/".join(path)
        
        # return the file info as a tuple
        # (name, path, hash, permissions, users, severity) to mach the db structure
        return (file_name, path, hash_md5, permissions, f"{user}/{group}", severity)
    
    
        
if __name__ == "__main__":
    user_checker = UserChecker()
    user_checker.build_db()
    print("Database created successfully.")