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

# GLOBAL VARIABLES
supported_platforms = ["Darwin","Linux","Windows","FreeBSD"]    # Create a list of our supported platforms
exec_name = "pfsense-automator"    # Save our executable name

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
    # If we received an OS error, run alternate check
    except Exception as copy_err:
        print("- ERROR " + copy_err)
        copied = False    # Reinforce False value if failed
    # Return our bool
    return copied

# install_darwin() runs through the processes required to install pfsense-automator on Mac/Darwin
def install_darwin(install):
    # Local variables
    installed = 2    # Assign default return code to track whether software installed successfully
    dep_dest = "/usr/local/share/pfsense-automator"    # Assign the destination directory for our software (shared objects, libraries, executables)
    exec_link_dest = "/usr/local/bin/pfsense-automator"    # Assign our softlink executable destination
    install_cwd = os.getcwd()    # Save our current working directory
    req_depends = ["Python",exec_name,"base_library.zip"]    # Assign list of required dependencies to look for
    dev_null = open(os.devnull,"w")    # Start dev null write object
    # Check if we are installing or uninstalling
    if install:
        # START INSTALL
        print("- Install platform `Darwin` detected...starting install")    # Print our install platform
        # Check that we are in the install directory
        if install_cwd.rstrip("/").split("/")[-1] == exec_name:
            # Check if dependencies are found
            dep_found = False    # Create a bool tracker to check if we found our required dependencies
            dir_list = os.listdir(install_cwd)    # Save a list of all the files in our directory
            for dep in req_depends:
                # Check if our dependencies are found
                if dep in dir_list:
                    dep_found = True    # Set our value to true
                else:
                    dep_found = False   # Set our value to false
                    break    # Break our loop
            # Check if our dependencies were found
            if dep_found:
                print("- SUCCESS locating dependencies")
                # Remove current install if present
                if os.path.exists(dep_dest):
                    shutil.rmtree(dep_dest)
                # Copy our files
                copy_install = copy_install_dir(install_cwd,dep_dest)    # Copy our install data
                # check if files were copies
                if copy_install:
                    print("- SUCCESS installing dependencies...creating symlink")
                    # Check if symlink already exists
                    if os.path.exists(exec_link_dest) and os.path.islink(exec_link_dest):
                        os.remove(exec_link_dest)
                    try:
                        os.symlink(dep_dest + "/" + exec_name, exec_link_dest)    # Create our symlink
                        print("- SUCCESS creating symlink at " + exec_link_dest)    # Print Success message
                        exec_init = subprocess.call([exec_name,"-v"],stdout=dev_null,stderr=dev_null)    # Initialize our software and ensure we get a proper exit code
                        installed = 0 if os.path.exists(exec_link_dest) and exec_init == 0 else installed    # Return code 0 if symlink exists and exit code is 0
                    except Exception as sym_err:
                        print("- ERROR creating symlink `" + sym_err + "`")
                    # Final success messages
                    if installed == 0:
                        print("- SUCCESS installing pfsense-automator. Restart your shell and type `pfsense-automator` to get started.")
                else:
                    print("- ERROR installing dependencies")
            else:
                print("- ERROR locating dependencies")
        # If we are not in the install directory
        else:
            installed = 3    # Assign return code 3 (not in install directory)
    # If we are wanting to uninstall
    else:
        user_confirm = input("Are you sure you would like to uninstall pfsense-automator? (y/n)")
        # Check if user confirms they want to uninstall
        if user_confirm.lower() in ["yes","y"]:
            # Check if expected files exist
            if os.path.exists(exec_link_dest):
                os.remove(exec_link_dest)
            if os.path.exists(dep_dest):
                shutil.rmtree(dep_dest)
            # Check that expected files are now gone
            if not os.path.exists(exec_link_dest) and not os.path.exists(dep_dest):
                print("- SUCCESS uninstalling pfsense-automator")
    # Return our install return code
    return installed

# main() our main function that controls what the user is trying to do
def main():
    # Local variables
    uninstall_input = sys.argv[1] if len(sys.argv) > 1 else ""    # Capture our user arguments
    install_mode = False if uninstall_input == "uninstall" else True    # Determine if we are installing or uninstalling
    host_platform = check_os_platform()    # Get our host platform
    # If host platform is a Mac/Darwin
    if host_platform == "Darwin":
        inst = install_darwin(install_mode)    # Install on Darwin

# Run main()
main()
