import subprocess
import os
import sys

# fungtion to return the curent folder path to the file curently running, 
# takes one argument to append eanything at the end of the returned string like a filename
def get_folder_path(append=''):
    # Get the script that was initially executed
    script_path = os.path.abspath(sys.argv[0])
    folder_path = os.path.dirname(script_path)
    return os.path.join(folder_path, append)


class VirusScaner:
    
    def remove_values_from_list(self, the_list, val):
        return [value for value in the_list if value != val]
    
    def __init__(self):
        #self.virus_scaner = self.run_command(['sudo', 'clamscan', '-r', '-i', '/mnt'])
        list_file = get_folder_path("scan_folders.txt")
        with open(list_file, "r") as file:
            directory_list = file.read()
        directory_list = directory_list.split("\n")
        self.directory_list = self.remove_values_from_list(directory_list,"")
    
    def scan_directory(self, directory):
        # Scan the directory with clamscan
        try:
            result = subprocess.run(
                ['sudo', 'clamscan', '-r', '-i', directory],
                capture_output=True,  # Capture the output
                text=True  # Ensure the output is returned as a string
            )
            result_output = result.stdout
            result_output = result_output.split("\n")
            output_lenth = len(result_output)
            if "Infected files: 0" in result_output:
                return None
            else:
                return result_output[0:output_lenth-13]
        except subprocess.CalledProcessError as e:
            print(f"Error during scan: {e.stderr}")
            
    def scan_all_directories(self):
        # Scan all directories in the list
        vialations = []
        for directory in self.directory_list:
            result = self.scan_directory(directory)
            if result:
                print(f"Infected files found in {directory}:")
                for line in result:
                    print(line)
                    vialations.append({
                    "problem": "virus",
                    "info": f"Infected files found in {directory}",
                    "severity": 5
                    })
            else:
                print(f"No infected files found in {directory}.")
    
    
if __name__ == "__main__":
    virus_scaner = VirusScaner()
    virus_scaner.scan_all_directories()

