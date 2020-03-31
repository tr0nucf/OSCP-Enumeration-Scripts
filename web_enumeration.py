import subprocess
import os
import socket
from colorama import Fore, Style


def get_current_directory():
    return os.getcwd()


def progress(tool):
    print(Style.BRIGHT + Fore.BLUE + f'{tool} scanning in progress' + Style.RESET_ALL)


def finished(tool):
    print(Style.BRIGHT + Fore.MAGENTA + f'{tool} Finished!' + Style.RESET_ALL)


def prepare_scan_results_file(ip, port):
    file_path = get_current_directory()
    file_name = f"{ip}_port_{port}_scan_results"
    complete_path = os.path.join(file_path, file_name + ".txt")
    return complete_path


def is_valid_ip():
    global ip
    while True:
        try:
            ip = input("[*] Enter ip of host:")
            if socket.gethostbyname(ip) == ip:
                break
        except socket.gaierror:
            print(Fore.RED + 'Something is wrong' + Style.RESET_ALL)
    return ip


def is_valid_port():
    global port
    while True:
        try:
            port = int(input("[*] Enter port of host:"))
        except ValueError:
            print(Fore.RED + 'Error: expect an integer. Try again.' + Style.RESET_ALL)
            continue
        if port >= 1 and port <= 65535:
            break
        else:
            print(Fore.CYAN + 'Port must between range 1 >= port <= 65535' + Style.RESET_ALL)
            continue

    return port


def port_443(port):
    if port == 443:
        return True
    else:
        return False


def get_threads():
    global threads
    while True:
        try:
            threads = int(input("[*] Enter number of threads Max of 50:"))
        except ValueError:
            print(Fore.RED + 'Error: expect an integer. Try again.' + Style.RESET_ALL)
            continue
        if threads >= 1 and threads <= 50:
            break
        else:
            print(Fore.CYAN + 'Thread count must be between range 1 >= port <= 50' + Style.RESET_ALL)
            continue

    return threads


def whatweb(ip, port, file):
    progress('Whatweb')
    if not port_443(port):
        whatweb = f"whatweb -v -a 1 http://{ip}:{port} > {file}"
    else:
        whatweb = f"whatweb -v -a 1 https://{ip}:{port} > {file}"

    subprocess.run(whatweb, shell=True)
    finished('Whatweb')


def dirsearch(ip, port, threads, file):
    progress('Dirsearch')
    if not port_443(port):
        dirsearch = f"/opt/dirsearch/./dirsearch.py -u http://{ip}:{port} -e php,txt,pl,sh,asp,aspx,html,json,py,cfm,rb,cgi -r -t {threads} >> {file}"
    else:
        dirsearch = f"/opt/dirsearch/./dirsearch.py -u https://{ip}:{port} -e php,txt,pl,sh,asp,aspx,html,json,py,cfm,rb,cgi -r -t {threads} >> {file}"

    subprocess.run(dirsearch, shell=True)
    finished('Dirsearch')


def nikto(ip, port, file):
    progress('Nikto')
    nikto = f"nikto -host {ip} -p {port} >> {file}"
    subprocess.run(nikto, shell=True)
    finished('Nikto')


def gobuster(ip, port, threads, file):
    if not port_443(port):
        gobuster = f"gobuster dir -u http://{ip}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t {threads} >> {file}"
    else:
        gobuster = f"gobuster dir -u https://{ip}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t {threads} -k >> {file}"

    subprocess.run(gobuster, shell=True)


def dirb(ip, port, file):
    if not port_443(port):
        dirb = f"dirb http://{ip}:{port} >> {file}"
    else:
        dirb = f"dirb https://{ip}:{port} >> {file}"

    subprocess.run(dirb, shell=True)


def scan(ip, port, threads, file):
    whatweb(ip, port, file)
    dirsearch(ip, port, threads, file)
    nikto(ip, port, file)
    gobuster(ip, port, threads, file)
    dirb(ip, port, file)


def main():
    # Prompt for ip input
    ip = is_valid_ip()
    port = is_valid_port()
    threads = get_threads()
    file_path = prepare_scan_results_file(ip, port)
    # Invoke whatweb, nikto, dirsearch, gobuster, dirb
    scan(ip, port, threads, file_path)


if __name__ == '__main__':
    main()
