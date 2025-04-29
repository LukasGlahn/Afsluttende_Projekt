import socket

# Define the UDP IP address and port to listen on
UDP_IP = "0.0.0.0"  # Listen on all interfaces
UDP_PORT = 7777

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))


while True:
    # Receive data from the socket
    data, addr = sock.recvfrom(1024)
    with open("ip.txt", "a") as f:
        f.write(data.decode() + "\n")
    print(f"Received message: {data.decode()} from {addr}")