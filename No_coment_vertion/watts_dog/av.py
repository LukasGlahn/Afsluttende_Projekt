import subprocess
import os
import sys


def get_folder_path(append=''):
    script_path = os.path.abspath(sys.argv[0])
    folder_path = os.path.dirname(script_path)
    return os.path.join(folder_path, append)


class VirusScaner:
    
    def remove_values_from_list(self, the_list, val):
        return [value for value in the_list if value != val]
    
    def __init__(self):
        list_file = get_folder_path("scan_folders.txt")
        with open(list_file, "r") as file:
            directory_list = file.read()
        directory_list = directory_list.split("\n")
        self.directory_list = self.remove_values_from_list(directory_list,"")
    
    def scan_directory(self, directory):
        
        try:
            result = subprocess.run(
                ['sudo', 'clamscan', '-r', '-i', directory],
                capture_output=True,  
                text=True  
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
        return vialations
    
    
if __name__ == "__main__":
    virus_scaner = VirusScaner()
    virus_scaner.scan_all_directories()

