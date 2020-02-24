import fnmatch
import json
import os
import subprocess
from shutil import which

'''
    Function: utilities_check
    Purpose: Check if utilities exist on the system.  If they do, do not install the given utilities,
             else install missing utilities in specified directory.
'''


def utilities_check():
    json_config_file = 'installation_config.json'
    if json_config_file_exists(json_config_file):  # If config file exists continue
        with open(json_config_file, 'r') as tools_list:  # Open installation_config.json file for reading
            tools_list = json.load(tools_list)  # Load tools_list from json file
            for json_dict in tools_list['utilities_list']:  # Access dictionary inside installed_tools_list
                # For each "tool" stored as dictionary key "install_tool" value
                for tools, tool in json_dict.items():
                    tools = str(tools)  # Convert tool key to string
                    if is_tool(tools):  # If is_tool returns true package is already installed
                        print(tools + " is installed")
                    else:  # Else update packages then install missing tools
                        print("Installing " + tools)
                        install_tool(tool)

            for json_dict in tools_list['utilities_directories']:  # Access dictionary inside installed_directories
                for tools, tool in json_dict.items():
                    tools = str(tools)  # Convert tool key to string
                    if tools == "dirsearch.py" or "PayloadsAllTheThings":
                        # Search directories for tool, if it doesn't exist on system then install it in /opt/ directory
                        if not search_directories_for_tool(tools):
                            os.chdir("/opt/")
                            install_tool(tool)
                            os.chdir("/root/")
                    else:
                        if not os.path.isdir(tools):
                            install_tool(tool)


'''
    Function: install_tool
    Purpose: Install missing utility using shell
'''


def install_tool(tool):
    subprocess.run(tool, shell=True)  # Install missing tool


'''
    Function: is_tool
    Purpose: Check whether utility is on PATH and marked as executable
'''


def is_tool(tool):
    return which(tool) is not None


'''
    Function: json_config_file_exists
    Purpose: Return true is json is valid or false if unable to load
'''


def json_config_file_exists(json_file):
    try:
        with open(json_file, "r") as file:
            json.load(file)
    except ValueError:
        return False
    return True


'''
    Function: search_directories_for_tool
    Purpose: Recursively search for file or directory on system    
'''


def search_directories_for_tool(utility):
    root_directory = '/'
    pattern = utility
    fileList = []

    # Recursively walk through directories starting from root '/' searching for file
    for root, directories, file_list in os.walk(root_directory):
        for name in file_list:
            if fnmatch.fnmatch(name, pattern):  # If the file is found, append the path to fileList
                fileList.append(os.path.join(root, name))

    if not fileList:  # If list is not empty then the file already exists on the system
        return False  # don't install

    return True  # File does not exist on system install it


'''
    Function: add_kali_rolling
    Purpose: Check if kali-rolling exists in sources.list.  If it does do nothing else append source to file.
'''


def add_kali_rolling():
    with open("/etc/apt/sources.list", "r+") as file:
        kali_rolling_found = any(
            "deb http://http.kali.org/kali kali-rolling main non-free contrib" in line for line in file)
        if not kali_rolling_found:
            file.seek(0, os.SEEK_END)
            file.write("deb http://http.kali.org/kali kali-rolling main non-free contrib\n")


def main():
    add_kali_rolling()
    utilities_check()


if __name__ == '__main__':
    main()
