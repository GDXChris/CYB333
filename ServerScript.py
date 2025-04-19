#Imorting necessary libraries
import socket

# Define the host and port for the server
host = "127.0.0.1"  # Localhost IP address
port = 6000  # Port number to connect to

# Create a socket that will use IPv4 addressing and TCP protocol
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the specified host and port
s.bind((host, port))
# Listen for incoming connection requests
s.listen() 
print(f"Server is listening on {host}:{port}")
# Accept connection from a client
connection, client_addr = s.accept()
print(f"Connection established with {client_addr}")

# Receive data from the client
data = connection.recv(1024)  # Buffer size of 1024 bytes
print(f"Received data: {data.decode()}")
# Send a response back to the client
response = "Hello from the server!"
connection.sendall(response.encode())

# Close the connection
connection.close()
print("Connection closed.")
# Close the server socket
s.close()

