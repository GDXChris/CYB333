# Import required libraries/modules
import socket

#target_host = 127.0.0.1  # Localhost IP address
#port_range = 1-1024  # Port range to scan

# Prompt the user for the target host and port range
def beginning():
    while True:
        try:
            target_host = input("Enter the target host (IP address or hostname): ")
            scan_option = input("Enter '1' to scan a specific port range or '2' to scan common ports: ") #prompt user for option to scan specific port range or common ports
            # Check if the user wants to scan a specific port range or common ports
            # If the user chooses option 1, prompt for the port range
            # If the user chooses option 2, use a predefined list of common ports
            
            if scan_option == '1':
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
            elif scan_option == '2':
                # Define a list of common ports
                port_range = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]
            else:
                print("Invalid option. Please enter '1' or '2'.")
                continue
            # Exit the loop if the input is valid
            break
        # Handle unexpected errors during the input process and display an error message
        except ValueError:
            print("Invalid input. Please try again.")
    # Return the validated target host and port range
    return target_host, port_range

# Define the port_scanner function
def port_scanner(target_host, port_range):
    try:
        # Check if port_range is a list of specific ports or a range
        if len(port_range) == 2 and isinstance(port_range[0], int) and isinstance(port_range[1], int):
            # Create a range for scanning if port_range is a start-end range
            ports_to_scan = range(port_range[0], port_range[1] + 1)
        else:
            # Use the list directly if it is a list of specific ports
            ports_to_scan = port_range

        # Loop through the ports to scan
        for port in ports_to_scan:
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
    # Handle problems that may occur during the socket connection
    except socket.error as err:
        print(f"Socket error: {err}")
        exit()
    # Handle any other exceptions that may occur
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