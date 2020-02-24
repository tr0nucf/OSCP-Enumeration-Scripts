'''

    Functionality to add:

    - Display pentesting methodology in console (menu type interface)
    - Generate multiple msfvenom payloads based on certain criteria and output to separate directory
    - Process each host file extracting information (using regex).  For each port make a list of ips
      that have specific port/ports open,invoke tools to probe for additional information based on results.
    - Notify when a process has completed with corresponding ip
    - Automate eternal blue exploitation (to avoid metasploit usage)
    - Add menu that displays functionality
    - Make suggestions based on findings
    - Let user choose location of output directories
    - Suggest password lists based on port
    - If tools are timing out add functionality to handle eloquently
    - Display all shells available by service/port

'''

import subprocess
import os
import re
from subprocess import Popen

live_host_list = []

'''
    Function: process_hosts
    Purpose: Process ip addresses obtained from live_hosts scan and output
             each ip to iplist.txt for further processing or reference
'''


def process_hosts():
    pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')  # Match ip addresses

    with open('iplist.txt', 'w') as ip_list:  # Open iplist.txt file for writing
        with open('hosts.txt', 'r') as hosts_list:  # Open hosts.txt file for reading
            next(hosts_list)  # Skip first line
            for line in hosts_list:  # Iterate over every line in hosts_list
                ip = pattern.findall(line)  # Find all ip addresses
                live_host_list.append(ip)  # Append every ip to live_host_list
                ip_address = ' '.join(ip)  # Strip brackets and quotes
                ip_list.writelines(ip_address + "\n")  # Write every ip address on new line

    # Close files
    ip_list.close()
    hosts_list.close()


'''
    Function: live_hosts
    Purpose: Purpose perform a ping scan for host discovery and output results
             to hosts.txt for further processing
'''


def live_hosts():
    # Prompt user for network
    network = input("[+] Enter ip address in subnet notation i.e. 10.11.1.0/24: ")

    # Scan network for live hosts and save output to hosts.txt
    subprocess.run(["nmap", "-sn", network, "-oG", "hosts.txt"])


'''
    Function: host
    Purpose: Take in ip address as parameter and create a directory for
             the given ip and pass nmap scan parameters to mass_scan function
'''


def host(ip):
    # If ip is a string continue scan else ignore
    if ip:
        output_directory = f"/root/pycannon/{ip}/{ip}_initial_tcp"
        # For each ip passed to function use default scripts, version,
        # and operating system enumeration output results in all formats
        return ["nmap", "-vv", "-sC", "-sV", "-O", "-p-", ip, "-oA", output_directory]

    else:
        return


'''
    Function: clean_up
    Purpose: Remove files that are no longer needed
'''


def clean_up():
    # Clean up all files no longer needed
    subprocess.call(['rm', 'hosts.txt'])  # Delete hosts.txt


'''
    Function: mass_scan
    Purpose: Iterate over every host and initialize nmap scan
             for each host in a separate process
'''


def mass_scan():
    # Scan each host using separate processes
    for address in live_host_list:
        if address:  # Make sure address is not an empty string
            Popen(host(' '.join(address)))


'''
    Function: initial_directories
    Purpose: Make a directory that will contain all scans
'''


def initial_directories():
    os.mkdir("/root/pycannon")
    os.chdir("/root/pycannon")


'''
    Function: ip_directories
    Purpose: Iterate over every ip in iplist.txt and
             and make directory for the given ip
'''


def ip_directories():
    with open('iplist.txt', 'r') as ip_list:
        for ip in ip_list:
            ip = ip.strip()  # Strip string
            if ip:  # Make sure ip is not an empty string
                os.mkdir(ip)  # Make directory for ip

    ip_list.close()  # Close file


def main():
    initial_directories()

    live_hosts()  # Call live hosts method

    process_hosts()  # Extract information

    clean_up()  # Files no longer needed

    ip_directories()

    mass_scan()  # Scan every ip contained in live_host_list


if __name__ == '__main__':
    main()