import subprocess

def log(info,priority=7):
    identifier = "Watts Dog"

    subprocess.run(
        ["systemd-cat", "--identifier=" + identifier, f"--priority={priority}"],
        input=info.encode(),
        check=True
    )

log("hello Watts",6)