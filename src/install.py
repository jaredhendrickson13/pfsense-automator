# /usr/bin/python3
# Copyright 2019 - Jared Hendrickson
# Purpose: This script is intended to install a `one folder` build of pfsense-automator on supported operating systems.
#          The `one file` builds do not need to execute this to function but may have reduced performance

# IMPORT MODULES
import sys
import platform
import os
import subprocess
import shutil
import getpass

# CLASSES
class colors:
    OK = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'

# GLOBAL VARIABLES
supported_platforms = ["Darwin","Linux","Windows","FreeBSD"]    # Create a list of our supported platforms
exec_name = "pfsense-automator" if platform.system() != "Windows" else "pfsense-automator.exe"    # Save our executable name
success_msg = colors.OK + "SUCCESS" + colors.RESET if platform.system() != "Windows" else "SUCCESS"   # Format our success msg
error_msg = colors.FAIL + "ERROR  " + colors.RESET if platform.system() != "Windows" else "ERROR  "    # Format our fail msg

# FUNCTIONS
# check_os_platform() checks what platform the target system is running
def check_os_platform():
    # Local variables
    support = ""    # Specify our return value default as blank string
    bits = platform.architecture()[0]    # Save our architecture bit count
    arch = platform.machine()    # Save our machine architecture
    system = platform.system()    # Save our OS type
    pyv = platform.python_version()    # Save our python version
    # Check that platform is supported
    if system in supported_platforms:
        support = system    # Assing our return value to our system variable
    # Return our value
    return support

# copy() copies files and folders to another destination
def copy_install_dir(src, dest):
    # Local variables
    copied = False    # Assign a boolean to track if the file was copied
    # Try to copy directories
    try:
        shutil.copytree(src, dest)
        copied = True    # Assign a true value
    except Exception as copy_err:
        print("- " + error_msg + " : " + copy_err)
        copied = False    # Reinforce False value if failed
    # Return our bool
    return copied

# check_windows_admin() checks if user is running as administrator
def check_windows_admin():
    # Check if user is running windows NT
    if os.name == 'nt':
        # Only windows users with admin privileges can read the C:\windows\temp directory, check if we can read it
        try:
            temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
        # Return false is we can't read it
        except:
            return False
        # Return true if we can
        else:
            return True
    # If system is not windows, return false
    else:
        return False


# install() runs through the processes required to install pfsense-automator
def install(install, platform):
    # Local variables
    installed = 2    # Assign default return code to track whether software installed successfully
    run_cwd = os.path.dirname(sys.argv[0])    # Save the directory our script is running in
    usr_cwd = os.getcwd()   # Save the users current working directory
    install_cwd = run_cwd if exec_name in run_cwd else usr_cwd    # Save our current working directory
    req_depends = ["certifi",exec_name]    # Assign list of required dependencies to look for
    dev_null = open(os.devnull,"w")    # Start dev null write object
    os_path_data = {
        "Darwin": {"data_path":"/usr/local/share/pfsense-automator","link_path":"/usr/local/bin/pfsense-automator"},
        "Linux": {"data_path":"/usr/share/pfsense-automator","link_path":"/usr/bin/pfsense-automator"},
        "FreeBSD": {"data_path":"/usr/share/pfsense-automator","link_path":"/usr/bin/pfsense-automator"},
        "Windows": {"data_path":"/Program Files/pfsense-automator","link_path":"\Program Files\pfsense-automator\pfsense-automator.exe"}
    }
    # Check that we have permissions or if we're on a Mac (which doesn't require root privilege to install)
    if getpass.getuser() == "root" or platform == "Darwin" or check_windows_admin():
        # Check if we are installing or uninstalling
        if install:
            # START INSTALL
            print("- " + success_msg + " : Identified install platform `" + platform + "`...")
            # Check that we are in the install directory
            if install_cwd.rstrip("/").split("/")[-1] == exec_name or install_cwd.rstrip("\\").split("\\")[-1] == exec_name.rstrip(".exe"):
                # Check if dependencies are found
                dep_found = False    # Create a bool tracker to check if we found our required dependencies
                dir_list = os.listdir(install_cwd)    # Save a list of all the files in our directory
                for dep in req_depends:
                    # Check if our dependencies are found
                    if dep in dir_list:
                        dep_found = True
                    else:
                        dep_found = False
                        break
                # Check if our dependencies were found
                if dep_found:
                    print("- " + success_msg + " : Located dependencies...")
                    # Remove current install if present
                    if os.path.exists(os_path_data[platform]["data_path"]):
                        shutil.rmtree(os_path_data[platform]["data_path"])
                    # Copy our files
                    copy_install = copy_install_dir(install_cwd,os_path_data[platform]["data_path"])
                    # Check if files were copies
                    if copy_install:
                        print("- " + success_msg + " : Installed dependencies...")
                        # If platform is not Windows, symlink the executable and test
                        if platform != "Windows":
                            # Check if symlink already exists
                            if os.path.exists(os_path_data[platform]["link_path"]):
                                os.remove(os_path_data[platform]["link_path"])
                            try:
                                os.symlink(os_path_data[platform]["data_path"] + "/" + exec_name, os_path_data[platform]["link_path"])    # Create our symlink
                                print("- " + success_msg + " : Created symlink at " + os_path_data[platform]["link_path"] + "...")    # Print Success message
                            except Exception as sym_err:
                                print("- " + error_msg + " : Could not create symlink `" + sym_err + "`")
                            # Try to run the newly installed program
                            try:
                                exec_init = subprocess.call([exec_name,"-v"],stdout=dev_null,stderr=dev_null)    # Initialize our software and ensure we get a proper exit code
                                installed = 0 if os.path.exists(os_path_data[platform]["link_path"]) and exec_init == 0 else installed    # Return code 0 if symlink exists and exit code is 0
                            except OSError:
                                print("- " + error_msg + " : Could not execute installed software. Ensure you downloaded the correct installer for your platform")
                            # Final success messages
                            if installed == 0:
                                print("- " + success_msg + " : Installed pfsense-automator. Restart your shell and type `pfsense-automator` to get started.")
                            else:
                                print("- " + error_msg + " : Could not execute installed software. Ensure you downloaded the correct installer for your platform")
                        # If Platform is Windows
                        else:
                            # Try to run the newly installed program
                            try:
                                exec_init = subprocess.call([os_path_data[platform]["link_path"],"-v"],stdout=dev_null,stderr=dev_null)    # Initialize our software and ensure we get a proper exit code
                                installed = 0 if exec_init == 0 else installed    # Return code 0 if symlink exists and exit code is 0
                            except OSError:
                                print("- " + error_msg + " : Could not execute installed software. Ensure you downloaded the correct installer for your platform")
                            # Final success messages
                            if installed == 0:
                                print("- " + success_msg + " : Installed pfsense-automator. Executable available at `" + os_path_data[platform]["link_path"] + "`")
                            else:
                                print("- " + error_msg + " : Could not execute installed software. Ensure you downloaded the correct installer for your platform")
                    else:
                        print("- " + error_msg + " : Could not install dependencies")
                else:
                    print("- " + error_msg + " : Could not locate dependencies")
            # If we are not in the install directory
            else:
                print("- " + error_msg + " : install.py is running outside of install folder")
        # If we are wanting to uninstall
        else:
            # Try to get input from user, exit if KeyboardInterrupt
            try:
                user_confirm = input("Are you sure you would like to uninstall pfsense-automator? (y/n)")
            except KeyboardInterrupt:
                sys.exit()
            # Check if user confirms they want to uninstall
            if user_confirm.lower() in ["yes","y"]:
                # Check if expected files exist
                if os.path.exists(os_path_data[platform]["link_path"]):
                    os.remove(os_path_data[platform]["link_path"])
                if os.path.exists(os_path_data[platform]["data_path"]):
                    shutil.rmtree(os_path_data[platform]["data_path"])
                # Check that expected files are now gone
                if not os.path.exists(os_path_data[platform]["link_path"]) and not os.path.exists(os_path_data[platform]["data_path"]):
                    print("- " + success_msg + " : Uninstalled pfsense-automator")
    # If we do not have permission
    else:
        print("- " + error_msg + " : Installer requires root privileges")
    # Return our install return code
    return installed

# main() our main function that controls what the user is trying to do
def main():
    # Local variables
    uninstall_input = sys.argv[1] if len(sys.argv) > 1 else ""    # Capture our user arguments
    install_mode = False if uninstall_input == "uninstall" else True    # Determine if we are installing or uninstalling
    host_platform = check_os_platform()    # Get our host platform
    # Check if our host's platform is found in our supported platforms
    if host_platform in supported_platforms:
        inst = install(install_mode,host_platform)    # Install on detected platforms
    else:
        print("- ERROR detecting platform. Your OS may be unsupported")

# Run main()
main()
