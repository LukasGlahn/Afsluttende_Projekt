import json

structure = {
    "/home": {
        "default": {
            "checks" : "hpu",
            "severity" : 4
            },
        "exceptions": {
            "/home/lukas/watts_dog" : {
                "checks" : "pu",
                "severity" : 4
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
                    "severity" : 2
                    },
                "/etc/sv/ssh/supervise" : {
                    "checks" : "pu",
                    "severity" : 2
                    },
                "/etc/mtab" : {
                    "checks" : "",
                    "severity" : 0
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
            "severity" : 4
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
            "severity" : 2
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
                    "severity" : 2
                    },
            "/mnt/storage1/influxdb2/data/influxd.bolt" : {
                    "checks" : "pu",
                    "severity" : 2
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
            "/var/lib/docker/overlay2" : {
                "checks" : "",
                "severity" : 0
                },
            "/var/lib/docker/image/overlay2/layerdb/sha256" : {
                "checks" : "",
                "severity" : 0
                },
            "/var/lib/docker/image/overlay2/imagedb/content/sha256" : {
                "checks" : "",
                "severity" : 0
                },
            "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256" : {
                "checks" : "",
                "severity" : 0
                },
            "/var/lib/docker/containers" : {
                "checks" : "pu",
                "severity" : 3
                },
            "/var/log/journal" : {
                "checks" : "",
                "severity" : 3
                },
            "/var/lib/aziot/edged/mnt" : {
                "checks" : "pu",
                "severity" : 3
                },
            },
        
        "file_exceptions": {
            "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/var/log/wtmp" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/var/lib/docker/network/files/local-kv.db" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/var/log/lastlog" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            "/var/lib/fail2ban/fail2ban.sqlite3" : {
                    "checks" : "pu",
                    "severity" : 3
                    },
            },
        },
    }

with open ('structure.json', 'w') as f:
    json.dump(structure, f, indent=4)