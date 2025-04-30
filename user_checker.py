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

    
    def get_file_info(self, file, severity):
        # Get info about file like hash, permissions, users, severity from linux system
        file_info = os.stat(file)
        permissions = oct(file_info.st_mode)[-3:]
        user = file_info.st_uid 
        group = file_info.st_gid
        # Calculate hash of the file
        # If it's a file, get the hash using the get_file_hase method
        hash_md5 = self.get_file_hase(file)
        
        # Get the file name by splitting the path and getting the last element
        file_name = file.split("/")[-1]
        # Get the file path by removing the file name from the full path
        path = file.split("/")[:-1]
        path = "/".join(path)
        
        # return the file info as a tuple
        # (name, path, hash, permissions, users, severity) to mach the db structure
        return (file_name, path, hash_md5, permissions, f"{user}/{group}", severity)
    
    def build_db_from_folder(self, folder, severity):
        # Iterate over all files and folders in the folder
        for root, dirs, files in os.walk(folder):  # Corrected unpacking
            # Process files
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    # Get the file info and add it to the database
                    file_info = self.get_file_info(file_path, severity)  # Removed "file" argument
                    self.add_file_to_db(file_info)
                except Exception as e:
                    print(f"Error processing file {file}: {e}")
                    
    def check_folder_for_changes(self, folder):
        # Check if the folder has changed since the last check
        files = os.walk(folder)
        for root, dirs, files in files:
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    # Get the file info and check if it exists in the database
                    file_info = self.get_file_info(file_path, 0)  # Removed "file" argument
                    conn = sqlite3.connect(self.db)
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT name, path, hash, permissions, users, severity FROM file_hashes WHERE name=? AND path=?
                    ''', (file_info[0], file_info[1]))
                    result = cursor.fetchone()
                    conn.close()

                    if result is None:
                        print(f"File {file} is new.")
                    else:
                        if result[2] != file_info[2]:
                            print(f"File {file} has changed. Hash went from {result[2]} to {file_info[2]}.")
                        if result[3] != file_info[3]:
                            print(f"File {file} has different permissions. used to be {result[3]} now is {file_info[3]}.")
                        if result[4] != file_info[4]:
                            print(f"File {file} has different user/group. used to be {result[4]} now is {file_info[4]}.")
                    
                except Exception as e:
                    print(f"Error processing file {file}: {e}")
        
        
        

        
if __name__ == "__main__":
    user_checker = UserChecker()
    user_checker.build_db()
    user_checker.build_db_from_folder("/home/lukas", 1)
    user_checker.check_folder_for_changes("/home/lukas")
    print("Database created successfully.")