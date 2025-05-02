structure = {
    "/home": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        "exceptions": {
            "/home/lukas/watts_dog" : {
                "checks" : "pu",
                "severity" : 3
                },
            
            }
    },
    "/etc": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {
                "/etc/sv/ssh/supervise" : {
                    "checks" : "pu",
                    "severity" : 1
                    },
                "/etc/sv/ssh/supervise" : {
                    "checks" : "pu",
                    "severity" : 1
                    },
            },
        
    },
    "/bin": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/sbin": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/media": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/root": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    }
