#Import required libraries
import socket

#Define the target host and port (Host and port of the server)
target_host = "127.0.0.1"  # Localhost IP address
target_port = 6000  # Port number to connect to

#Create a socket that will use IPv4 addressing and TCP protocol to match the server socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    #connect to the server
    s.connect((target_host, target_port))
    print(f"Connected with server at {target_host}:{target_port}")

    #Send data to the server
    s.sendall(b"Hello from the client!") #b signifies data will be sent in 8 bit bytes
    #Receive a response from the server
    data = s.recv(1024)  # Buffer size of 1024 bytes
    print(f"Received from server: {data.decode()}")

    #close the connection and the client socket
    s.close()
    print("Connection closed.")

except socket.error as err:
    print(f"Socket error: {err}")
    exit()
except Exception as error:
    print(f"An unexpected error occurred: {error}")
    exit()
finally:
    #Ensure the socket is closed if it is still open
    if s:
        s.close()
