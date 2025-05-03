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
            
            },
        "file_exceptions": {

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
    "/lib": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/boot": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/dev": {
        "default": {
            "checks" : "pu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/lost+found": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/mnt": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            "/mnt/storage1/influxdb2/data/engine/data" : {
                "checks" : "",
                "severity" : 0
                },
            "/mnt/storage1/influxdb2/data/engine/wal" : {
                "checks" : "",
                "severity" : 0
                },
            },
            
        
        "file_exceptions": {
            "/mnt/storage1/edgeHub/000295.log" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/mnt/storage1/edgeAgent/000190.log" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/mnt/storage1/edgeAgent/availability/avaliability.checkpoint" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/mnt/storage1/influxdb2/data/influxd.bolt" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            }, 
    },
    "/opt": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/run": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/usr": {
        "default": {
            "checks" : "hpu",
            "severity" : 3
            },
        
        "exceptions": {
            
            },
        
        "file_exceptions": {

            },
        
    },
    "/var": {
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
