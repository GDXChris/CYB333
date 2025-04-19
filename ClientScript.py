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
    # Set a timeout for the socket to prevent indefinite hanging
    s.settimeout(5)  # 5-second timeout
    retry_limit = 10  # Maximum number of retries
    retries = 0  # Counter for retries

    # Attempt to connect to the target host and port with retries
    while retries < retry_limit:
        try:
            s.connect((target_host, target_port))
            break  # Exit the loop if connection is successful
        except socket.error:
            retries += 1
            print(f"Unable to connect to {target_host}:{target_port}. Retrying ({retries}/{retry_limit})...")
            time.sleep(1)  # Introduce a 1-second delay before retrying
    else:
        print("Exceeded maximum retry limit. Exiting...")
        exit()  # Exit if retry limit is reached

    print(f"Connected with server at {target_host}:{target_port}")


# Handle problems that may occur during the socket connection
except socket.error as err:
    print(f"Socket error: {err}")
    exit()
except Exception as error:
    print(f"An unexpected error occurred: {error}")
    exit()
finally:
    # Ensure the socket is closed if it is still open
    s.close()
