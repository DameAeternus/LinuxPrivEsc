#!/usr/bin/env python3

import os
import subprocess
import pwd
import grp

# Function to run a shell command and capture its output
def run_cmd(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, text=True)
        return result.strip()
    except subprocess.CalledProcessError:
        return ""

# System Information
def sys_info():
    print("\n[+] Gathering System Information...\n")
    print(f"Hostname: {run_cmd('hostname')}")
    print(f"Kernel Version: {run_cmd('uname -r')}")
    print(f"Distribution: {run_cmd('cat /etc/os-release')}")

# Current User Information
def current_user_info():
    print("\n[+] Current User Information...\n")
    print(f"User: {run_cmd('whoami')}")
    print(f"UID: {os.getuid()} | GID: {os.getgid()}")
    print(f"Groups: {run_cmd('groups')}")
    print(f"Sudo Rights (without password):\n{run_cmd('sudo -l 2>/dev/null')}")

# Check for Writable /etc/passwd and /etc/shadow
def check_passwd_shadow():
    print("\n[+] Checking /etc/passwd and /etc/shadow Permissions...\n")
    if os.access('/etc/passwd', os.W_OK):
        print("[!] /etc/passwd is writable!")
    if os.access('/etc/shadow', os.W_OK):
        print("[!] /etc/shadow is writable!")

# Check for SUID binaries
def check_suid_bins():
    print("\n[+] Checking for SUID Binaries...\n")
    suid_bins = run_cmd("find / -perm -4000 -type f 2>/dev/null")
    print(suid_bins)

# Check for Capabilities
def check_capabilities():
    print("\n[+] Checking for Files with Capabilities...\n")
    caps = run_cmd("getcap -r / 2>/dev/null")
    print(caps)

# Check for cron jobs
def check_cron_jobs():
    print("\n[+] Checking Cron Jobs...\n")
    cron_jobs = run_cmd("ls -la /etc/cron* /var/spool/cron* 2>/dev/null")
    print(cron_jobs)

# Check for writable directories
def check_writable_dirs():
    print("\n[+] Checking for World Writable Directories...\n")
    writable_dirs = run_cmd("find / -type d -perm -o+w 2>/dev/null")
    print(writable_dirs)

# Check for installed compilers
def check_compilers():
    print("\n[+] Checking for Installed Compilers...\n")
    compilers = run_cmd("which gcc g++ perl python python3 2>/dev/null")
    print(compilers)

# Check for Docker/LXC privileges
def check_docker_lxc():
    print("\n[+] Checking for Docker/LXC Privileges...\n")
    if run_cmd("grep -E '^docker|^lxc' /etc/group") or os.path.exists('/var/run/docker.sock'):
        print("[!] User is in Docker or LXC group or has Docker socket access!")

# Check for misconfigured sudoers
def check_sudoers_misconfig():
    print("\n[+] Checking Sudoers Misconfigurations...\n")
    sudoers_misconfig = run_cmd("grep -vE '^#|^$' /etc/sudoers /etc/sudoers.d/* 2>/dev/null")
    print(sudoers_misconfig)

# Check kernel exploit suggestions
def kernel_exploit_suggestions():
    print("\n[+] Kernel Exploit Suggestions (Based on Kernel Version)...\n")
    kernel_version = run_cmd("uname -r")
    print(f"Check for kernel exploits at https://www.kernel-exploits.com/search?version={kernel_version}")

# Main function to execute all checks
def main():
    sys_info()
    current_user_info()
    check_passwd_shadow()
    check_suid_bins()
    check_capabilities()
    check_cron_jobs()
    check_writable_dirs()
    check_compilers()
    check_docker_lxc()
    check_sudoers_misconfig()
    kernel_exploit_suggestions()

if __name__ == "__main__":
    main()
