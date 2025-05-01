Python-based Backup and Recovery Script

Core Objectives:< br/>
-Create a script that can securely interact with the Windows filesystem< br/>
-Enforce strong authentication to restrict file access to authorized users (DO NOT RUN AS ADMINISTRATOR)< br/>
-Encrypt backup files at rest to ensure data integrity< br/>
-Decrypt backup files as they are restored to intended destination< br/>

How to Use:
1. Place file in convenient location (for sake of simplicity, it is best saved in root directory)
2. Ensure all required dependencies are installed if using PowerShell with pip (Refer to below dependencies for a list)
3. Run script after dependencies are installed.  The script will prompt for anything further.

## Requirements
- Python 3.x

## Dependencies

### Standard Libraries (No installation required)
- `datetime`
- `os`
- `ctypes`
- `getpass`
- `shutil`
- `hashlib`

### External Library (Must be installed)
- `cryptography` – required for `Fernet` encryption < br/>
Use "pip install cryptography" to install.
