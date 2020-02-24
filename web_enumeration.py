import subprocess


def whatweb(ip, port):
    whatweb = f"whatweb {ip}:{port}"
    subprocess.run(whatweb, shell=True)


def dirsearch(ip, port):
    dirsearch = f"/opt/dirsearch/./dirsearch.py -u {ip}:{port} -e php,asp,aspx,sh,py,rb,pl,jsp -r"
    subprocess.run(dirsearch, shell=True)


def gobuster(ip, port):
    gobuster = f"gobuster dir -u http://{ip}:{port}/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php -o gobuster-root -t 50"
    subprocess.run(gobuster, shell=True)


def nikto(ip, port):
    nikto = f"nikto -host {ip} -p {port}"
    subprocess.run(nikto, shell=True)


def dirb(ip, port):
    dirb = f"dirb http://{ip}:{port}"
    subprocess.run(dirb, shell=True)


def scan(ip, port):
    whatweb(ip, port)
    dirsearch(ip, port)
    gobuster(ip, port)
    nikto(ip, port)
    dirb(ip, port)


def main():
    # Prompt for ip input
    ip = input("[*] Enter ip of host:")
    port = input("[*] Enter port of host:")
    # Invoke whatweb, nikto, dirsearch, gobuster, dirb
    scan(ip, port)


if __name__ == '__main__':
    main()