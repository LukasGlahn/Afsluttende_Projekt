import os
import stat



file = "/etc/sv/ssh/supervise"

file_info = os.lstat(file)
        
# Get the file permissions if "p" is in checks 

# Get the file permissions in octal format
permissions = oct(file_info.st_mode)[-3:]

print("Permissions:", permissions)

user = file_info.st_uid 
group = file_info.st_gid
user_grupe = f"{user}/{group}"

print("User/Group:", user_grupe)



mode = os.lstat(file).st_mode
if stat.S_ISREG(mode):
    # Calculate hash of the file
    # If it's a file, get the hash using the get_file_hase method
    print("hasinh")
elif stat.S_ISLNK(mode):
    # If it's a symlink, get the target of the symlink
    file_data = os.path.realpath(file)
    print("simling", file_data)
else:
    # If it's not a regular file or symlink, set file_data to None
    print(f"File did not mach the a filetile that is comparebelle: {file}")
    file_data = None