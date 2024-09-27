# Linux Privilege Escalation Script

This Python script automates the enumeration of potential privilege escalation vectors on a Linux system. It gathers essential information about the system and identifies common misconfigurations and vulnerabilities that can be exploited to gain elevated privileges.

## Features
- **System Information**: Retrieves kernel version, hostname, and distribution details.
- **User Information**: Displays the current user, UID/GID, group memberships, and sudo rights.
- **Sensitive File Permissions**: Checks if `/etc/passwd` or `/etc/shadow` are writable.
- **SUID Binaries**: Searches for binaries with the SUID bit set.
- **Capabilities**: Lists files with elevated capabilities.
- **Cron Jobs**: Enumerates cron jobs and scheduled tasks.
- **Writable Directories**: Identifies world-writable directories.
- **Compilers**: Checks for the presence of compilers such as GCC, Perl, and Python.
- **Docker/LXC Privileges**: Detects if the user is part of the Docker or LXC group or has access to the Docker socket.
- **Sudoers Misconfigurations**: Searches for misconfigurations in sudoers files.
- **Kernel Exploit Suggestions**: Provides a link for checking kernel exploits based on the system's kernel version.

## How to Install and Run

### 1. Clone the Repository

```bash
git clone https://github.com/DameAeternus/LinuxPrivEsc.git
cd linux-priv-esc-script
```
2. Make the Script Executable
`chmod +x linprivesc.py`
3. Run the script
`python3 linprivesc.py`

## Disclaimer
This script is for educational and authorized testing purposes only. Do not use it on systems you do not own or have explicit permission to test.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Feel free to submit issues or pull requests if you'd like to contribute to this project!

### Happy hacking!

