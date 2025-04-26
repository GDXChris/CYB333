#Imorting necessary libraries
import socket

# Define the host and port for the server
host = "127.0.0.1"  # Localhost IP address
port = 6000  # Port number to connect to

# Display current target host and port
print(f"Current host: {host}, Current target port: {port}")

# Ask user if they want to change the port (if yes, prompt for new values).
change_target = input("Do you want to change the port? (yes/no): ").strip().lower()
if change_target == "yes":
	port_input = input("Enter new port (default is 6000): ").strip()
	port = int(port_input) if port_input.isdigit() else 6000

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

