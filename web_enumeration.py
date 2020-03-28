import subprocess
import socket


def is_valid_ip():
    global ip
    while True:
        try:
            ip = input("[*] Enter ip of host:")
            if socket.gethostbyname(ip) == ip:
                break
        except socket.gaierror:
            print("Something is wrong")

    return ip


def is_valid_port():
    global port
    while True:
        try:
            port = int(input("[*] Enter port of host:"))
        except ValueError:
            print("Error: expect an integer. Try again.")
            continue
        if 1 <= port <= 65535:
            break
        else:
            print("Port must between range 1 <= port <= 65535")
            continue

    return port


def port_443(port):
    if port == 443:
        return True
    else:
        return False


def whatweb(ip, port):
    if not port_443(port):
        whatweb = f"whatweb -v -a 1 http://{ip}:{port}"
    else:
        whatweb = f"whatweb -v -a 1 https://{ip}:{port}"

    subprocess.run(whatweb, shell=True)


def dirsearch(ip, port):
    if not port_443(port):
        dirsearch = f"/opt/dirsearch/./dirsearch.py -u http://{ip}:{port} -e php,asp,aspx,sh,py,rb,pl,jsp -r"
    else:
        dirsearch = f"/opt/dirsearch/./dirsearch.py -u https://{ip}:{port} -e php,asp,aspx,sh,py,rb,pl,jsp -r"

    subprocess.run(dirsearch, shell=True)


def gobuster(ip, port):
    if not port_443(port):
        gobuster = f"gobuster dir -u http://{ip}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t 20"
    else:
        gobuster = f"gobuster dir -u https://{ip}:{port} -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t 20 -k"

    subprocess.run(gobuster, shell=True)


def nikto(ip, port):
    nikto = f"nikto -host {ip} -p {port}"
    subprocess.run(nikto, shell=True)


def dirb(ip, port):
    if not port_443(port):
        dirb = f"dirb http://{ip}:{port}"
    else:
        dirb = f"dirb https://{ip}:{port}"

    subprocess.run(dirb, shell=True)


def scan(ip, port):
    whatweb(ip, port)
    dirsearch(ip, port)
    gobuster(ip, port)
    nikto(ip, port)
    dirb(ip, port)


def main():
    # Prompt for ip input
    ip = is_valid_ip()
    port = is_valid_port()
    # Invoke whatweb, nikto, dirsearch, gobuster, dirb
    scan(ip, port)


if __name__ == '__main__':
    main()
