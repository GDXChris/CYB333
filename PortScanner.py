# Import required libraries/modules
import socket

#target_host = 127.0.0.1  # Localhost IP address
#port_range = 1-1024  # Port range to scan

# Prompt the user for the target host and port range
def beginning():
    while True:
        try:
            target_host = input("Enter the target host (IP address or hostname): ")
            port_range = input("Enter the port range (e.g., 1-65535): ").split('-')
            # Check if the port range contains exactly two elements and valid numeric values before converting to integers
            if len(port_range) != 2 or not port_range[0].isdigit() or not port_range[1].isdigit():
                print("Invalid input. Please enter a valid port range in the format 'start-end' with numeric values.")
                continue
            # Convert the port range to integers
            port_range = [int(port_range[0]), int(port_range[1])]
            # Check if the port range is valid
            if port_range[0] < 1 or port_range[1] > 65535 or port_range[0] > port_range[1]:
                print("Invalid port range. Please enter a valid range (1-65535).")
                continue
            #exit the loop if the input is valid
            break
        # Handle unexpected errors during the input process and display an error message
        except ValueError:
            print("Invalid input. Please enter numeric values for the port range.")
    # Return the validated target host and port range
    return target_host, port_range

# Define the port_scanner function
def port_scanner(target_host, port_range):
    
    try:
        # Loop through the specified port range
        for port in range(port_range[0], port_range[1] + 1):
            # Create a socket object using IPv4 and TCP protocol
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a timeout for the socket connection to keep it from hanging indefinitely
            s.settimeout(5)  # 5 second timeout
            # Attempt to connect to the target host and port
            result = s.connect_ex((target_host, port))
            # Check if the connection was successful (result == 0 means success)
            if result == 0:
                print(f"Port {port} is open")
            else:
                print(f"Port {port} is closed")
            # Close the socket connection
            s.close()
    # Handle problems that may occur during the socket connection, close the socket and exit the program
    except socket.error as err:
        print(f"Socket error: {err}")
        exit()
    # Handle any other exceptions that may occur, close the socket and exit the program
    except Exception as error:
        print(f"An unexpected error occurred: {error}")
        exit()
    finally:
        # Close the socket connection if it is still open
            s.close()

# Run the beginning function to prompt user input
target_host, port_range = beginning()
# Run the port_scanner function with validated the user input
port_scanner(target_host, port_range)