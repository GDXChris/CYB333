#Import required libraries
import socket
import time  # Added to introduce delay between retries


#Define the target host and port (Host and port of the server)
target_host = "127.0.0.1"  # Localhost IP address
target_port = 6000  # Port number to connect to
# Ask user if they want to change the target host and port (if yes, prompt for new values).  Before prompt, display current target host and port
print(f"Current target host: {target_host}, Current target port: {target_port}")
change_target = input("Do you want to change the target host and port? (yes/no): ").strip().lower()
if change_target == "yes":
    target_host = input("Enter the new target host (e.g., 127.0.0.1): ").strip()
    target_port = int(input("Enter the new target port (e.g., 6000): ").strip())


#Create a socket that will use IPv4 addressing and TCP protocol to match the server socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    #make connection with server without establishing socket to determine online presence
    s.settimeout(5)  # 5 second timeout
    while True:
        try:
            #Attempt to connect to the target host and port
            s.connect((target_host, target_port))
            break  # Exit the loop if connection is successful
        except socket.error:
            print(f"Unable to connect to {target_host}:{target_port}. Retrying...")
            time.sleep(1)  # Introduce a 1-second delay before retrying
            continue  # Retry connecting
            time.sleep(1)  # Wait for 1 second before retrying
            continue  # Retry connecting
    print(f"Connected with server at {target_host}:{target_port}")

    #Send data to the server
    s.sendall(b"Hello from the client!") # b signifies a byte string
    #Receive a response from the server
    # Receive data in chunks until the server closes the connection
    data = b""  # Initialize an empty bytes object
    while True:
        chunk = s.recv(1024)  # Buffer size of 1024 bytes
        if not chunk:  # If no more data is received, break the loop
            break
        data += chunk  # Append the received chunk to the data
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
