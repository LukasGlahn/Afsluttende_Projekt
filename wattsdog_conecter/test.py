import os
import sys

# fungtion to return the curent folder path to the file curently running, 
# takes one argument to append eanything at the end of the returned string like a filename
def get_folder_path(append=''):
    # Get the script that was initially executed
    script_path = os.path.abspath(sys.argv[0])
    folder_path = os.path.dirname(script_path)
    return os.path.join(folder_path, append)


print(get_folder_path(""))