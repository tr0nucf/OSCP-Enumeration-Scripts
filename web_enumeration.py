import subprocess
import os
import socket
import atexit
import argparse
import sys
import json

from colorama import Fore, Style

'''
    Method: word_lists
    Purpose: To extract wordlists (specified by user) for a given service.
'''


def word_lists():
    json_file = "word_lists.json"  # File containing wordlists
    if json_file_exists(json_file):  # Check if json file exists on system
        with open(json_file, 'r') as word_lists:  # Open wordlists_lists.json file for reading
            word_lists = json.load(word_lists)  # Load word_lists from json file in a format python recognizes
            for word_list in word_lists["dirbuster"]:  # Grab content using key value pairs
                # i.e. for 'common' in 'apache,' for 'wordpress' in 'themes'
                for selection, selections in word_list.items():
                    if selection == 'medium':
                        string = str(selections)
                        print(string)


'''
    Function: json_config_file_exists
    Purpose: Return true if json file exists (false otherwise).
'''


def json_file_exists(json_file):
    try:  # Try to open file for reading
        with open(json_file, "r") as file:  # Open json file as file
            json.load(file)  #
    except ValueError:
        return False
    return True


'''
    Method: remove_emtpy_lines
    Purpose: Remove any empty lines that may occur from tool output.
'''


def remove_empty_lines(filename):
    if not os.path.isfile(filename):  # Check if file exists
        print(f"{filename} does not exist")  # Let user know file does not exist
        return  # Exit method
    with open(filename) as file_handle:  # Open file
        lines = file_handle.readlines()  # Read file line by line

    with open(filename, 'w') as file_handle:  # Open file for writing
        lines = filter(lambda x: x.strip(), lines)  # Strip all empty lines in file
        file_handle.writelines(lines)  # Write stripped lines back to file


'''
    Method: exit_handler
    Purpose: Remove file extension .txt then remove all HTTP error codes
             204,302,307,401,403 and output results to file.new
'''


def exit_handler(file_path):
    new_file = file_path.split(".", maxsplit=1)[0]  # Remove .txt extension
    # Remove any line in file with coinating codes 204,302,307,401,403
    command = f"sed '/204\|302\|307\|401\|403/d' {file_path} > {new_file}.new"
    subprocess.run(command, shell=True)  # Run commands in shell


'''
    Method: is_valid_os
    Purpose: Check if OS is valid.
'''


def is_valid_os(os):
    os = os.lower()
    if os is "linux" or "windows" or "neutral":
        return True
    else:
        return False


'''
    Method: get_current_directory
    Purpose: Return current working directory.
'''


def get_current_directory():
    return os.getcwd()  # Return current working directory


'''
    Method: progress
    Purpose: Let user know the current tool progress.
'''


def progress(tool):
    print(Style.BRIGHT + Fore.BLUE + f'[+] {tool} scanning in progress' + Style.RESET_ALL)


'''
    Method: finished
    Purpose: Let user know when tool has finished.
'''


def finished(tool):
    print(Style.BRIGHT + Fore.MAGENTA + f'[✔] {tool} Finished!\n' + Style.RESET_ALL)


'''
    Method: prepare_scan_results_file
    Purpose: Create file with ip and port descriptors for tool output.
'''


def prepare_scan_results_file(ip, port):
    file_path = get_current_directory()  # Save current directory as file path
    file_name = f"{ip}_port_{port}_scan_results"  # Create file name with ip and port
    complete_path = os.path.join(file_path, file_name + ".txt")  # Join file path and file name
    return complete_path  # Return the complete file path


'''
    Method: is_valid_ip
    Purpose: Check if ip is valid.
'''


def is_valid_ip(ip):
    try:
        if socket.gethostbyname(ip) == ip:
            return True
        else:
            return False
    except socket.gaierror:
        print(Fore.RED + Style.BRIGHT + f'[!] Invalid format {ip}' + Style.RESET_ALL)


'''
    Method: is_valid_port
    Purpose: Make port is within a valid range.
'''


def is_valid_port(port):
    if port >= 1 and port <= 65535:
        return True
    else:
        return False


'''
    Method: port_443
    Purpose: Check if port is HTTPS
'''


def port_443(port):
    if port == 443:
        return True
    else:
        return False


'''
    Method: check_range
    Purpose: Check if thread count is within valid range
'''


def check_range(threads):
    if threads >= 1 and threads <= 50:
        return True
    else:
        return False


'''
    Method: whatweb
    Purpose: Invoke whatweb scan on target.
'''


def whatweb(ip, port, file):
    progress('Whatweb')
    if not port_443(port):
        whatweb = f"whatweb -v -a 1 http://{ip}:{port} > {file}"
    else:
        whatweb = f"whatweb -v -a 1 https://{ip}:{port} > {file}"

    subprocess.run(whatweb, shell=True)
    finished('Whatweb')


'''
    Method: dirsearch
'''


def dirsearch(ip, port, threads, file):
    progress('Dirsearch')
    if not port_443(port):
        dirsearch = f"/opt/dirsearch/./dirsearch.py -u http://{ip}:{port} -e php,txt,pl,sh,asp,aspx,html,json,py,cfm,rb,cgi -r -t {threads} >> {file}"
    else:
        dirsearch = f"/opt/dirsearch/./dirsearch.py -u https://{ip}:{port} -e php,txt,pl,sh,asp,aspx,html,json,py,cfm,rb,cgi -r -t {threads} >> {file}"

    subprocess.run(dirsearch, shell=True)
    finished('Dirsearch')


'''
    Method: nikto
'''


def nikto(ip, port, file):
    progress('Nikto')
    nikto = f"nikto -host {ip} -p {port} >> {file}"
    subprocess.run(nikto, shell=True)
    finished('Nikto')


'''
    Method: gobuster
'''


def gobuster(ip, port, threads, file):
    progress('Gobuseter')
    if not port_443(port):
        gobuster = f"gobuster dir -u http://{ip}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t {threads} >> {file}"
    else:
        gobuster = f"gobuster dir -u https://{ip}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t {threads} -k >> {file}"

    subprocess.run(gobuster, shell=True)
    finished('Gobuster')


'''
    Method: dirb
'''


def dirb(ip, port, file):
    progress('Dirb')
    if not port_443(port):
        dirb = f"dirb http://{ip}:{port} >> {file}"
    else:
        dirb = f"dirb https://{ip}:{port} >> {file}"

    subprocess.run(dirb, shell=True)
    finished('Dirb')


def scan(ip, port, threads, file):
    whatweb(ip, port, file)
    dirsearch(ip, port, threads, file)
    nikto(ip, port, file)
    gobuster(ip, port, threads, file)
    dirb(ip, port, file)


def main():
    global file_path
    parser = argparse.ArgumentParser(description="Web application enumeration tool without a lame banner",
                                     usage=''' python3 web_enum.py <target> <port> [options]
                                     
    Example: 
    
        python3 web_enum.py -t 10.15.1.1 -p 80''',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t',
                        '--target',
                        type=str,
                        required=True,
                        help='Scan a single target')
    parser.add_argument('-p',
                        '--port',
                        type=int,
                        required=True,
                        default=80,
                        help="Web port to scan i.e. 80,443,8080,...")
    parser.add_argument('-th',
                        '--threads',
                        type=int,
                        required=False,
                        default=10,
                        help='Number of threads you want each tool run (50 MAX) default 10')
    parser.add_argument('-o',
                        '--output',
                        type=str,
                        required=False,
                        help='Absolute path you want scan results stored')
    parser.add_argument('-s',
                        '--system',
                        type=str,
                        required=False,
                        default="neutral",
                        help='The operating system of target i.e. Linux,Windows,etc...')
    parser.add_argument('-e',
                        '--extensions',
                        type=str,
                        required=False,
                        help='''File extensions you want tools to enumerate separated by comma Example: 
                                asp,aspx,sh,html,txt,etc,...''')
    parser.add_argument('-c',
                        '--codes',
                        type=str,
                        required=False,
                        help='''HTTP status codes to accept i.e. 200,302,307,401,403,... default accepts all status 
                                codes, however two seprate files are made one with successful status codes the other 
                                with all status codes''')
    parser.add_argument('-i',
                        '--include',
                        type=str,
                        required=False,
                        help='''List of tools you want to invoke (in order) on target separated by common Example: 
                                Whatweb,Dirsearch,Nikto. Default scan will invoke all tools''')
    parser.add_argument('-a',
                        '--aggressive',
                        type=str,
                        help='Perform thorough enumeation on target (will increase time of scan significantly)')
    parser.add_argument("-wl",
                        "--wordlist",
                        type=str,
                        required=False,
                        help='''
  Options:
                                
    Apache: apache:common, apache:fuzz, apache:vulns
    Apache Tomcat: apache_tomcat:common
    Wordpress: wordpress:themes, wordpress:plugins, wordpress:fuzz
    Joomla: joomla:themes
    Coldfusion: coldfusion:fuzz, coldfusion:vulns
    Drupal: drupal:fuzz
    Dirb: dirb:big, dirb:common
    Dirbuster: dirbuster:ls, dirbuster:lm, dirbuster:sm, dirbuster:m, dirbuster:s
  
  Examples:
                                
    -wl dirb:medium = Scan target with worlist from dirb
    -wl wordpress:themes plugins = Scan target with for wordpress plugins
    
    ''')

    args = parser.parse_args()

    if args.target is None:
        sys.exit(Fore.RED + Style.BRIGHT + "[!] You must specify a target's IP address" + Style.RESET_ALL)
    elif not is_valid_ip(args.target):
        sys.exit()
    if args.port is None:
        sys.exit(Fore.RED + Style.BRIGHT + "[!] You must specify a web port to scan" + Style.RESET_ALL)
    elif not is_valid_port(args.port):
        sys.exit(Fore.RED + Style.BRIGHT + '[!] Port must between 1 and 65535' + Style.RESET_ALL)
    if args.threads is None:
        pass
    elif not check_range(args.threads):
        sys.exit(Fore.RED + Style.BRIGHT + '[!] Thread count must be between 1 and 50' + Style.RESET_ALL)
    if args.output is None:
        args.output = prepare_scan_results_file(args.target, args.port)  # Add default directory
    if args.system is None:
        pass
    elif not is_valid_os(args.system):
        sys.exit(Fore.RED + Style.BRIGHT + f'[!] Invalid OS {args.system}' + Style.RESET_ALL)
    if args.extensions is not None:
        pass  # Get extensions form user
    if args.codes is not None:
        pass  # Get codes from user
    if args.include is not None:
        pass  # Only scan with specified tools
    if args.aggressive is not None:
        pass  # Update tools to aggressive scan
    if args.wordlist is not None:
        pass  # Parse arguments

    try:
        file_path = prepare_scan_results_file(args.target, args.port)
        # Invoke whatweb, nikto, dirsearch, gobuster, dirb
        scan(args.target, args.port, args.threads, file_path)
    finally:
        remove_empty_lines(file_path)
        atexit.register(exit_handler)


if __name__ == '__main__':
    main()
