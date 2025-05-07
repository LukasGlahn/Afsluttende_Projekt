import subprocess
from system_file_checker import SystemFileChecker
from firewall import FireWallChecker
import sys


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
        log(info, loging_score)
    
    # build all databases for the system to fungtion
    def build_database(self):
        # make the database
        self.system_file_checker.build_db()
        
        # fille te database with all files requerd
        self.system_file_checker.build_system_db()
        
    
    ## Full scan weary resouse intesiv and takes a while to do
    def full_scan(self):
        ## Check if the database exsists
        if self.file_exsists():
            pass
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
    