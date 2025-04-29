import socket
import subprocess
from time import sleep

interface =  "eth0"  # Replace with your network interface name

UDP_IP = ""
UDP_PORT = 7777

while True:
    ip_comand_output = subprocess.check_output(f"ip -f inet6 addr show {interface}", shell=True).decode()
    print(ip_comand_output)

    message = ip_comand_output

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    sock.sendto(bytes(message, "utf-8"), (UDP_IP, UDP_PORT))
    sleep(3600)  # Sleep for 1 hour (3600 seconds)