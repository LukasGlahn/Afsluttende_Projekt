structure = {
    "/home": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        "exceptions": {
            "/home/kr/gg" : {
                "checks" : "pu",
                "severity" : 2
                },
            "/home/kr" : {
                "checks" : "pu",
                "severity" : 2
                },
            "/home/fwer" : {
                "checks" : "pu",
                "severity" : 2
                },
            "/home/ligma" : {
                "checks" : "pu",
                "severity" : 2
                },
            
            },
    }}

list_of_folders = structure["/home"]["exceptions"]


path = "/home/kr/gg/something"

match = next(
    (folder for folder in list_of_folders if path == folder or path.startswith(folder + "/")),
    None
)

if match:
    print(f"Match found: {match}")
else:
    print("No match")