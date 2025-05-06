import subprocess
from system_file_checker import SystemFileChecker
from firewall import FireWallChecker


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

class system_checker():
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
    
    
    # build all databases for the system to fungtion
    def build_database(self):
        # make the database
        self.system_file_checker.build_db()
        
        # fille te database with all files requerd
        self.system_file_checker.build_system_db()
        
        
    def full_scan(self):
        #check if the database exsists
        if self.file_exsists():
            pass
        else:
            self.build_database()
            return
        
        firewall_vialations = self.fire_wall_checker.check_difrense()
        
        changed_files = self.system_file_checker.check_system_for_changes()
        
        
    
    def small_scan(self):
        pass
    
    



if __name__ == "__main__":

    log("hello Watts",6)