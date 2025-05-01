# Import necessary Libraries
import datetime
import os
import ctypes
import getpass
import shutil
import hashlib
from cryptography.fernet import Fernet

# Prompt user for username and password (use Windows authentication system)
def authenticate_user(username, password):
    #Authenticate user using Windows authentication.
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0

    # Call Windows API to validate credentials
    handle = ctypes.c_void_p()
    #Try to authenticate the user using the provided username and password
    try:
        success = ctypes.windll.advapi32.LogonUserW(
            username, None, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ctypes.byref(handle)
        )
        # If authentication fails, retrieve the error code, print an error message, and set success to False
        if not success:
            error_code = ctypes.windll.kernel32.GetLastError()
            print(f"Authentication failed. Error code: {error_code}. Ensure the script is run with administrative privileges.")
    except Exception as e:
        print(f"An unexpected error occurred during authentication: {e}")
        success = False
    # If authentication is successful, close the handle and return True, otherwise return False
    if success:
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    else:
        return False

# Loop until the user provides valid input or chooses to exit
while True:
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")  # Hides password input
    if authenticate_user(username, password):
        print("Authentication successful. Proceeding with the backup process.")
        break
    else:
        print("Authentication failed. Please try again.")

# Define the backup process function
def perform_backup():
    """Perform the backup process."""
    # Prompt the user for the backup destination and the user directory to be backed up
    backup_destination = input("Enter the backup destination path: ").strip()
    user_directory = input("Enter the user directory to be backed up: ").strip()

    # Verify the backup destination
    if not os.path.exists(backup_destination):
        try:
            os.makedirs(backup_destination, exist_ok=True)
            print(f"Backup destination did not exist. Created the directory: {backup_destination}")
        except Exception as e:
            print(f"Failed to create backup destination. Error: {e}")
            return

    # Prompt the user for scheduled backup time and frequency
    scheduled_time = input("Enter the scheduled backup time (HH:MM): ").strip()
    frequency = input("Enter the backup frequency (daily/weekly/monthly): ").strip().lower()

    # Validate the scheduled backup time and frequency
    if frequency not in ['daily', 'weekly', 'monthly']:
        print("Invalid backup frequency. Exiting the script.")
        return

    # Define the path to the user directory to be backed up
    if not os.path.exists(user_directory):
        print("Invalid user directory. Exiting the script.")
        return

    # Recognize the folders and contents in the user directory
    files_to_backup = []
    for root, dirs, files in os.walk(user_directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Detected file: {file_path}")
            files_to_backup.append(file_path)

    # Check for modification dates and do not back up files that have not been modified since the last backup
    last_backup_time = datetime.datetime.now() - datetime.timedelta(days=1)  # Example: 1 day ago
    files_to_backup = [f for f in files_to_backup if datetime.datetime.fromtimestamp(os.path.getmtime(f)) > last_backup_time]

    # Calculate the size of the files to be backed up and print it
    total_size = sum(os.path.getsize(f) for f in files_to_backup)
    print(f"Total size of files to be backed up: {total_size / (1024 * 1024):.2f} MB")

    # Prompt the user for confirmation to proceed with the backup
    confirm = input("Do you want to proceed with the backup? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("Backup process aborted.")
        return

    # Create a backup directory with the current date and time
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(backup_destination, f"backup_{timestamp}")
    os.makedirs(backup_dir, exist_ok=True)

    # Encrypt the files to be backed up using a symmetric encryption algorithm
    # Generate a random encryption key and save it to a file
    encryption_key = Fernet.generate_key()
    cipher = Fernet(encryption_key)
    #Define the path to the encryption key file and save it in the backup directory
    key_file = os.path.join(backup_dir, "encryption_key.key")
    with open(key_file, "wb") as kf:
        kf.write(encryption_key)

    # Use a secure hashing algorithm (e.g., SHA-256) to generate a hash of the files to be backed up
    for file in files_to_backup:
        try:
            with open(file, "rb") as f:
                file_data = f.read()
                encrypted_data = cipher.encrypt(file_data)
                file_hash = hashlib.sha256(file_data).hexdigest()

            # Save the encrypted file to the backup directory
            relative_path = os.path.relpath(file, start=user_directory)
            backup_file_path = os.path.join(backup_dir, relative_path)
            os.makedirs(os.path.dirname(backup_file_path), exist_ok=True)
            with open(backup_file_path, "wb") as bf:
                bf.write(encrypted_data)

            # Print the file hash for verification
            print(f"Backed up: {file} (SHA-256: {file_hash})")
        except Exception as e:
            print(f"Error backing up {file}: {e}")

    # Create a log file in the backup directory and write the backup details to it
    log_file = os.path.join(backup_dir, "backup_log.txt")
    with open(log_file, "w") as lf:
        lf.write(f"Backup completed on {datetime.datetime.now()}\n")
        lf.write(f"Total size: {total_size / (1024 * 1024):.2f} MB\n")
        lf.write(f"Backup directory: {backup_dir}\n")
        for file in files_to_backup:
            file_hash = hashlib.sha256(open(file, "rb").read()).hexdigest()
            lf.write(f"{file}: {file_hash}\n")  # Store absolute path        

    # Print the backup summary
    print("Backup process completed successfully.")
    print(f"Backup files are located at: {backup_dir}")

# RESTORE PROCESS --------------------------------------------------------------------------
# Define the restore process function
def restore_backup():
    # Prompt the user for the backup directory
    backup_dir = input("Enter the backup directory path: ").strip()

    # Verify the backup directory
    if not os.path.exists(backup_dir):
        print("Invalid backup directory. Exiting the script.")
        return

    # Prompt the user for the original user directory
    user_directory = input("Enter the original user directory path: ").strip()

    # Verify the user directory
    if not os.path.exists(user_directory):
        print("Invalid user directory. Exiting the script.")
        return

    # Locate the encryption key file
    key_file = os.path.join(backup_dir, "encryption_key.key")
    if not os.path.exists(key_file):
        print("Encryption key file not found in the backup directory. Exiting the script.")
        return

    # Load the encryption key
    try:
        with open(key_file, "rb") as kf:
            encryption_key = kf.read()
        cipher = Fernet(encryption_key)
    except Exception as e:
        print(f"Failed to load encryption key. Error: {e}")
        return

    # Locate the backup log file
    log_file = os.path.join(backup_dir, "backup_log.txt")
    if not os.path.exists(log_file):
        print("Backup log file not found in the backup directory. Exiting the script.")
        return

    # Read the log file to get the list of files and their original paths
    files_to_restore = []
    try:
        with open(log_file, "r") as lf:
            for line in lf:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                if line.lower().startswith("backup completed on") or line.lower().startswith("total size") or line.lower().startswith("backup directory"):
                    continue
                try:
                    # Split only on the last colon to avoid splitting the "C:\..." drive
                    path_part, hash_part = line.rsplit(":", 1)
                    files_to_restore.append(path_part.strip())
                except ValueError:
                    print(f"Could not parse line: {line}")
    except FileNotFoundError:
        print("Log file not found.")

    except Exception as e:
        print(f"Failed to read the backup log file. Error: {e}")
        return

    # Restore each file to its original location
    for original_path in files_to_restore:
        try:
            # Determine the relative path and locate the encrypted file in the backup directory
            relative_path = os.path.relpath(original_path, start=os.path.abspath(user_directory))
            encrypted_file_path = os.path.join(backup_dir, relative_path)

            if not os.path.exists(encrypted_file_path):
                print(f"Encrypted file not found: {encrypted_file_path}. Skipping.")
                continue

            # Decrypt the file
            with open(encrypted_file_path, "rb") as ef:
                encrypted_data = ef.read()
                decrypted_data = cipher.decrypt(encrypted_data)

            # Restore the file to its original location
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            with open(original_path, "wb") as of:
                of.write(decrypted_data)

            # Print file restoration status
            print(f"Restored: {original_path}")
        except Exception as e:
            print(f"Error restoring {original_path}: {e}")

    # Print the restoration summary
    print("Restore process completed successfully.")

# Prompt the user to select an option (backup or restore) or exit the program
while True:
    print("1. Backup")
    print("2. Restore")
    print("3. Exit")
    choice = input("Enter your choice (1/2/3): ").strip()
    # Validate the choice and call the appropriate function
    if choice == '1':
        perform_backup()
    elif choice == '2':
        restore_backup()
    elif choice == '3':
        print("Exiting the program.")
        break
    # If the user enters an invalid choice, prompt them again
    else:
        print("Invalid choice. Please try again.")
