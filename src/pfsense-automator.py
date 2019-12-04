#!/usr/bin/python3
# ----------------------------------------------------------------------------------------------------------------
# Author: Jared Hendrickson
# Copyright 2019 - Jared Hendrickson
# Purpose: This script is intended to add a CLI interface for pfSense devices. This uses cURL libraries to execute
# pfSense's many PHP configuration scripts. All functions in this script mimic changes regularly made in a browser
# and utilizes pfSense's built-in CSRF checks, input validation, and configuration parsing
# ----------------------------------------------------------------------------------------------------------------
# IMPORT MODULES
from pfsensewc import *
from pfsensexml import *

# Variables
firstArg = sys.argv[1] if len(sys.argv) > 1 else ""    # Declare 'firstArg' to populate the first argument passed in to the script
secondArg = sys.argv[2] if len(sys.argv) > 2 else ""    # Declare 'secondArg' to populate the second argument passed in to the script
thirdArg = sys.argv[3] if len(sys.argv) > 3 else None    # Declare 'thirdArg' to populate the third argument passed in to the script
fourthArg = sys.argv[4] if len(sys.argv) > 4 else None    # Declare 'fourthArg' to populate the fourth argument passed in to the script
fifthArg = sys.argv[5] if len(sys.argv) > 5 else None    # Declare 'fifthArg' to populate the fifth argument passed in to the script
sixthArg = sys.argv[6] if len(sys.argv) > 6 else None    # Declare 'sixthArg' to populate the sixth argument passed in to the script
seventhArg = sys.argv[7] if len(sys.argv) > 7 else None    # Declare 'seventhArg' to populate the seventh argument passed in to the script
eighthArg = sys.argv[8] if len(sys.argv) > 8 else None    # Declare 'eighthArg' to populate the eigth argument passed in to the script
ninthArg = sys.argv[9] if len(sys.argv) > 9 else None    # Declare 'ninthArg' to populate the ninth argument passed in to the script
tenthArg = sys.argv[10] if len(sys.argv) > 10 else None    # Declare 'tenthArg' to populate the tenth argument passed in to the script
eleventhArg = sys.argv[11] if len(sys.argv) > 11 else None    # Declare 'eleventhArg' to populate the eleventh argument passed in to the script
twelfthArg = sys.argv[12] if len(sys.argv) > 12 else None    # Declare 'twelfthArg' to populate the twelth argument passed in to the script
thirteenthArg = sys.argv[13] if len(sys.argv) > 13 else None    # Declare 'thirteenthArg' to populate the thirteenth argument passed in to the script
fourteenthArg = sys.argv[14] if len(sys.argv) > 14 else None    # Declare 'fourteenthArg' to populate the fourteenth argument passed in to the script
fifteenthArg = sys.argv[15] if len(sys.argv) > 15 else None    # Declare 'fifteenthArg' to populate the fifteenth argument passed in to the script
sixteenthArg = sys.argv[16] if len(sys.argv) > 16 else None    # Declare 'sixteenthArg' to populate the sixteenth argument passed in to the script
seventeenthArg = sys.argv[17] if len(sys.argv) > 17 else None    # Declare 'seventeenthArg' to populate the seventeenth argument passed in to the script
PfaVar.software_version = "v0.0.4 " + platform.system() + "/" + platform.machine()    # Define our current version of this software
PfaVar.local_hostname = socket.gethostname()    # Gets the hostname of the system running pfsense-automator
PfaVar.current_date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")    # Get the current date in a file supported format
PfaVar.wc_protocol = "https"    # Assigns whether the script will use HTTP or HTTPS connections
PfaVar.wc_protocol_port = 443 if PfaVar.wc_protocol == 'https' else 80    # If PfaVar.wc_protocol is set to https, assign a integer value to coincide
req_session = requests.Session()    # Start our requests session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)    # Disable urllib warnings (suppress invalid cert warning)

### FUNCTIONS ###
# no_escape() Prevents SIGINT from killing the script unsafely
def no_escape(signum, frame):
    try:
        print("")
        os._exit(0)
    except Exception as x:
        print("")
        sys.exit(0)
# Set the signal handler to prevent exiting the script without killing the tunnel
signal.signal(signal.SIGINT, no_escape)

# main() is the primary function that maps arguments to other functions
def main():
    # Local Variables
    pfsenseServer = firstArg.replace("https://", "")    # Assign the server value to the firstArg (filtered)
    pfsenseAction = filter_input(secondArg)    # Assign the action to execute (filtered)
    # Check if user requests HTTPS override
    if pfsenseServer.lower().startswith("http://"):
        pfsenseServer = pfsenseServer.replace("http://", "")    # Replace the http:// protocol from the servername
        PfaVar.wc_protocol = "http"    # Reassign our webconfigurator protocol
        PfaVar.wc_protocol_port = 80    # Assign webconfigurator port to HTTP (80)
    # Check if user requests non-standard UI port
    if ":" in pfsenseServer:
        nonStdPort = pfsenseServer.split(":")[1]    # Assign the value after our colon to a variable
        nonStdPortInt = int(nonStdPort) if nonStdPort.isdigit() else 999999    # Assign a integer value of our port variable, if it is not a number save out of range
        PfaVar.wc_protocol_port = nonStdPortInt if 1 <= nonStdPortInt <= 65535 else PfaVar.wc_protocol_port    # Change our webUI port specification if it is a valid number
        pfsenseServer = pfsenseServer.replace(":" + nonStdPort, "")    # Remove our port specification from our servername string
    pfsenseServer = filter_input(pfsenseServer.replace("http://", ""))    # Filter our hostname/IP input
    # Check if we are simply requesting the software version
    if firstArg.upper() in ("--VERSION", "-V"):
        print(get_exit_message("version", "", "generic", "", ""))
        sys.exit(0)
    # Check that user passed in an IP or hostname
    if pfsenseServer is not "":
        # Check if the pfSense server is available for connections
        if check_remote_port(pfsenseServer, PfaVar.wc_protocol_port):
            # If user is trying to add a DNS entry and the correct number of arguments are present
            if pfsenseAction == "--add-dns":
                # Check if the correct number of arguments were given
                if len(sys.argv) > 6:
                    # Action Variables
                    hostToAdd = filter_input(thirdArg)    # Assign the user passed hostname (filtered)
                    domainToAdd = filter_input(fourthArg)    # Assign the user passed domain (filtered)
                    fqdnToAdd = filter_input(hostToAdd + "." + domainToAdd)    # Join the host and domain together to calculate the FQDN
                    ipToAdd = filter_input(fifthArg)    # Assign the user passed ip address (filtered)
                    descrToAdd = filter_input(sixthArg)    # Assign the user passed description (filtered)
                    user = eighthArg if seventhArg == "-u" and eighthArg is not None else input("Please enter username: ")    # Parse passed in username, if empty, prompt user to enter one
                    key = tenthArg if ninthArg == "-p" and tenthArg is not None else getpass.getpass("Please enter password: ")    # Parse passed in passkey, if empty, prompt user to enter one
                    descrToAdd = "Auto-added by " + user + " on " + PfaVar.local_hostname if descrToAdd == "default" else descrToAdd    # Write default description if default is passed
                    # If the IP passed into the command is valid, try to add the entry to pfSense
                    if validate_ip(ipToAdd):
                        # Execute DNS entry function
                        addDnsExitCode = add_dns_entry(pfsenseServer, user, key, hostToAdd, domainToAdd, ipToAdd, descrToAdd)
                        # Check exit codes and print strings accordingly.
                        print(get_exit_message(addDnsExitCode, pfsenseServer, pfsenseAction, hostToAdd, domainToAdd))
                        sys.exit(addDnsExitCode)
                    # If IP is not valid, return error
                    else:
                        print(get_exit_message("invalid_ip", "", pfsenseAction, "", ""))
                        sys.exit(1)
                # If incorrect number of arguments were given, return error
                else:
                    print(get_exit_message("invalid_syntax", "", pfsenseAction, "", ""))
                    sys.exit(1)
            # If user is trying to pull the DNS resolver configuration
            if pfsenseAction == "--read-dns":
                # Check if the minimum number of arguments was given
                if len(sys.argv) > 3:
                    # Action variables
                    dnsFilter = thirdArg    # Save our sort filter
                    user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")    # Parse passed in username, if empty, prompt user to enter one
                    key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")    # Parse passed in passkey, if empty, prompt user to enter one
                    dnsConfig = get_dns_entries(pfsenseServer, user, key)    # Pull our DNS resolver (unbound) configuration
                    idHead = structure_whitespace("ID", 5, "-", True) + " "    # Format the table header ID column
                    hostHead = structure_whitespace("HOST", 25, "-", True) + " "    # Format the table header host column
                    domainHead = structure_whitespace("DOMAIN", 25, "-", True) + " "    # Format the table header domain column
                    ipHead = structure_whitespace("IP", 15, "-", True) + " "    # Format the table header domain column
                    descrHead = structure_whitespace("DESCRIPTION", 30, "-", True) + " "    # Format the table header description column
                    # If our DNS configuration is empty
                    if dnsConfig["ec"] == 0:
                        # If user wants to export the data as JSON
                        if dnsFilter.startswith("-j=") or dnsFilter.startswith("--json="):
                            jsonPath = dnsFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readdns-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(dnsConfig["domains"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If user wants to print the JSON output
                        elif dnsFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(dnsConfig["domains"]))   # Print our JSON data
                        # If user wants to print all items
                        elif dnsFilter.upper() in ("--ALL","-A") or dnsFilter.upper() in ("DEFAULT", "-D") or dnsFilter.startswith(("--host=","-h=")):
                            # Format and print our header
                            print(idHead + hostHead + domainHead + ipHead + descrHead)
                            # Loop through each domain dictionary and pull out the host data
                            for domainKey, domainValue in dnsConfig["domains"].items():
                                # Loop through each host in the domain
                                for hostKey, hostValue in domainValue.items():
                                    # Loop Variables
                                    host = structure_whitespace(hostValue["hostname"], 25, " ", True) + " "    # Format our host data
                                    domain = structure_whitespace(hostValue["domain"], 25, " ", True) + " "    # Format our domain data
                                    ip = structure_whitespace(hostValue["ip"], 15, " ", True) + " "    # Format our ip data
                                    id = structure_whitespace(hostValue["id"], 5, " ", True) + " "    # Format our id data
                                    descr = structure_whitespace(hostValue["descr"], 30, " ", True) + " "    # Format our description data
                                    alias = ""    # Initialize our alias data as empty string. This will populate below if user requested ALL
                                    # Check that user wants all info first
                                    if dnsFilter.upper() in ("--ALL","-A") or dnsFilter.startswith(("--host=","-h=")):
                                        # Loop through our aliases and try to parse data if it exists
                                        for aliasKey, aliasValue in hostValue["alias"].items():
                                            try:
                                                alias = alias + "      - Alias: " + aliasValue["hostname"] + "." + aliasValue["domain"] + "\n"
                                            except KeyError:
                                                alias = ""    # Assign empty string
                                    # If we are only looking for one value
                                    if dnsFilter.startswith(("--host=","-h=")):
                                        aliasMatch = False    # Predefine aliasMatch. This will change to true if the FQDN matches an alias exactly
                                        fqdnFilter = dnsFilter.replace("--host=", "").replace("-h=", "")    # Remove expected strings from argument to get our hostname filter
                                        # Check if domain is our hostFilter
                                        if fqdnFilter.endswith(hostValue["domain"]):
                                            # Format our filter
                                            domainFilter = hostValue["domain"]    # Save our matched domain
                                            hostnameFilter = fqdnFilter.replace("." + domainFilter, "")    # Format our hostname portion
                                            # Check if the hostname/alias matches our filter
                                            if hostnameFilter in hostValue["alias"]:
                                                # Check if our FQDN matches the alias
                                                aliasValue = hostValue["alias"][hostnameFilter]
                                                aliasMatch = True if aliasValue["hostname"] + "." + aliasValue["domain"] == fqdnFilter else False
                                            if hostnameFilter == hostValue["hostname"] or aliasMatch:
                                                print(id + host + domain + ip + descr)
                                                print(alias.rstrip("\n")) if alias is not "" else None
                                                break   # Break the loop as we found our match
                                    # If we are looking for all values
                                    else:
                                        # Print our formatted data
                                        print(id + host + domain + ip + descr)
                                        print(alias.rstrip("\n")) if alias is not "" else None
                            # If we did not match an expected filter
                        else:
                            print(get_exit_message("invalid_filter", "", pfsenseAction, dnsFilter, ""))
                    # If our DNS config read failed
                    else:
                        print(get_exit_message(dnsConfig["ec"], pfsenseServer, pfsenseAction, "", ""))
                # If we did not pass in the correct number of arguments
                else:
                    print(get_exit_message("invalid_syntax", pfsenseServer, pfsenseAction, "", ""))    # Print our error message
            # Assigns functions for --read-users
            elif pfsenseAction == "--read-users":
                # Action variables
                userFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                userData = get_users(pfsenseServer, user, key)    # Pull our user data
                idHeader = structure_whitespace("ID",5,"-", False) + " "   # Create our ID header
                usHeader = structure_whitespace("USERNAME",25,"-", False) + " "    # Create our username header
                fnHeader = structure_whitespace("FULL NAME",20,"-", True) + " "    # Create our full name header
                enHeader = structure_whitespace("ENABLED",8,"-", True) + " "    # Create our enabled header
                pvHeader = structure_whitespace("PRIVILEGE",10,"-", True) + " "    # Create our privilege header
                gpHeader = structure_whitespace("GROUPS",30,"-", True) + " "    # Create our privilege header
                header = idHeader + usHeader + fnHeader + enHeader + pvHeader + gpHeader    # Piece our header together
                # Check that we were able to pull our user data successfully
                if userData["ec"] == 0:
                    # Check if user only wants to display data for one username
                    if userFilter.startswith(("--username=","-un=")):
                        userExp = userFilter.replace("--username=", "").replace("-un=","")  # Remove our filter identifier to capture our username expression
                        # Check that we have data for the given username
                        if userExp in userData["users"]:
                            print(structure_whitespace("Username:",20," ",True) + userData["users"][userExp]["username"])    # Print username
                            print(structure_whitespace("Full name:",20," ",True) + userData["users"][userExp]["full_name"])   # Print our user full name
                            print(structure_whitespace("ID:",20," ",True) + userData["users"][userExp]["id"])   # Print our user id
                            # noinspection SyntaxError
                            print(structure_whitespace("Enabled:",20," ",True) + "Yes") if userData["users"][userExp]["disabled"] != "yes" else print(structure_whitespace("Enabled:",20," ",True) + "No")  # Print our enabled value
                            print(structure_whitespace("Created-by:",20," ",True) + userData["users"][userExp]["type"])   # Print our user type
                            print(structure_whitespace("Expiration:",20," ",True) + userData["users"][userExp]["expiration"]) if userData["users"][userExp]["expiration"] != "" else None  # Print our expiration date
                            print(structure_whitespace("Custom UI:",20," ",True) + "Yes") if userData["users"][userExp]["custom_ui"] != "yes" else print(structure_whitespace("Custom UI:",20," ",True) + "No")  # Print our enabled value
                            # Loop through each of our groups and print it's values
                            groupStr = ""
                            for g in userData["users"][userExp]["groups"]:
                                groupStr = groupStr + g + ", "   # Concentrate our strings together
                            print(structure_whitespace("Groups:",20," ",True) + groupStr.rstrip(", "))  # Print header indicate start of group print
                            print(structure_whitespace("Privilege:",20," ",True) + userData["users"][userExp]["privileges"]["level"])   # Print our privilege level
                            print(structure_whitespace("Authorized Keys:",20," ",True) + structure_whitespace(userData["users"][userExp]["authorized_keys"],30," ",True))    # Print the start of our authorized keys file
                            print(structure_whitespace("IPsec Keys:",20," ",True) + structure_whitespace(userData["users"][userExp]["ipsec_keys"],30," ",True))    # Print the start of our IPsec keys file
                        # If user does not exist
                        else:
                            print(get_exit_message("invalid_user",pfsenseServer,pfsenseAction,userExp,""))    # Print error message
                            sys.exit(1)    # Exit on non-zero
                    # Check if user wants to print all users
                    elif userFilter.lower() in ("--all","-a","default"):
                        print(header)    # Print our header
                        # Loop through our users and print their data
                        for u,d in userData["users"].items():
                            loopId = structure_whitespace(d["id"],5," ", True) + " "
                            loopUs = structure_whitespace(d["username"],25," ", True) + " "
                            loopFn = structure_whitespace(d["full_name"],20," ", True) + " "
                            loopEn = structure_whitespace("yes",8," ", True) + " " if d["disabled"] != "yes" else structure_whitespace("no",8," ", True) + " "
                            loopPv = structure_whitespace(d["privileges"]["level"],10," ", True) + " "
                            loopGp = structure_whitespace(''.join([str(v) + ", " for v in d["groups"]]).rstrip(", "),30," ", True) + " "
                            print(loopId + loopUs + loopFn + loopEn + loopPv + loopGp)
                    # If user wants to print the JSON output
                    elif userFilter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(userData["users"]))   # Print our JSON data
                    # If we want to export values as JSON
                    elif userFilter.startswith(("--json=", "-j=")):
                        jsonPath = userFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readusers-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(jsonPath):
                            # Open an export file and save our data
                            jsonExported = export_json(userData["users"], jsonPath, jsonName)
                            # Check if the file now exists
                            if jsonExported:
                                print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                            else:
                                print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                    # If we did not pass in a valid filter
                    else:
                        print(get_exit_message("invalid_filter",pfsenseServer,pfsenseAction,userFilter,""))
                        sys.exit(1)
                # If we could not pull our user data, return error
                else:
                    print(get_exit_message(userData["ec"],pfsenseServer,pfsenseAction,"",""))   # Print error
                    sys.exit(userData["ec"])    # Exit on our return code

            # Assign functions for flag --add-user
            elif pfsenseAction == "--add-user":
                # Action variables
                uname = thirdArg if len(sys.argv) > 3 else input("Username: ")    # Save our user input for the new username or prompt for input if none
                enable = filter_input(fourthArg) if len(sys.argv) > 4 else input("Enable user [yes,no]: ")    # Save our enable user input or prompt for input if none
                passwd = fifthArg if len(sys.argv) > 5 else getpass.getpass("Password: ")    # Save our password input or prompt user for input if none
                fname = sixthArg if len(sys.argv) > 6 else input("Full name: ")    # Save our full name input or prompt user for input if none
                fname = "" if fname.lower() == "none" else fname    # Allow user to specify `none` if they do not want to add a full name
                expDate = seventhArg if len(sys.argv) > 7 else input("Expiration date [mm/dd/yyyy, blank for none]: ")    # Save our date input (mm/dd/yyyy) or prompt user for input if none
                expDate = "" if expDate.lower() == "none" else expDate    # Allow user to specify `none` if they don't want the account to expire
                groupsRaw = eighthArg + "," if len(sys.argv) > 8 else None    # Save our groups input, or assign None value if none. Will be prompted for input later if none
                groupsRaw = "," if groupsRaw is not None and groupsRaw.lower() == "none," else groupsRaw    # Allow user to specify `none` if they don't want to add user to any groups
                # Check if groups input via interactive mode
                if groupsRaw is None:
                    groups = []    # Initialize our groups list
                    # Loop until we have all our desired groups
                    while True:
                        gInput = input("Add user to group [blank entry if done]: ")
                        # Check if a non blank input was recieved
                        if gInput != "":
                            groups.append(gInput)    # Add our entry to the group and repeat the loop
                        # Otherwise break the loop
                        else:
                            break
                # Otherwise, format our groups to a list
                else:
                    groups = list(filter(None, groupsRaw.split(",")))
                user = tenthArg if ninthArg == "-u" and tenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = twelfthArg if eleventhArg == "-p" and twelfthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our enable value is valid
                if enable in ["yes","no","enable","disable"]:
                    enable = "" if enable in ["yes","enable"] else "yes"    # Switch our enabled to value to blank string (meaning do not disable) otherwise "yes"
                    # Check if our expiration date is valid, or if the user does not want to specify an expiration
                    if validate_date_format(expDate) or expDate == "":
                        # Pull our group configuration and check if we encountered an error
                        availGroups = get_user_groups(pfsenseServer, user, key)
                        if availGroups["ec"] == 0:
                            # Check if our groups exist
                            for grp in groups:
                                # If our group doesn't exist, print error and exit on non zero status
                                if grp not in availGroups["groups"]:
                                    print(get_exit_message("invalid_group",pfsenseServer,pfsenseAction,grp,""))
                                    sys.exit(1)
                            # Add our user, check if the user was successfully added and print our exit message and exit on return code
                            userAdded = add_user(pfsenseServer, user, key, uname, enable, passwd, fname, expDate, groups)
                            print(get_exit_message(userAdded, pfsenseServer, pfsenseAction, uname, ""))
                            sys.exit(userAdded)
                        # If we encountered an error pulling our groups, print our error message and exit on non-zero status
                        else:
                            print(get_exit_message(availGroups["ec"],pfsenseServer,pfsenseAction,"",""))
                            sys.exit(1)
                    # If our date is invalid, print error message and exit on non zero status
                    else:
                        print(get_exit_message("invalid_date",pfsenseServer,pfsenseAction,expDate,""))
                        sys.exit(1)
                # If our enable value is invalid, print error message and exit on non zero status
                else:
                    print(get_exit_message("invalid_enable",pfsenseServer,pfsenseAction,enable,""))
                    sys.exit(1)

            # Assign functions for flag --del-user
            elif pfsenseAction == "--del-user":
                # Action variables
                uid = thirdArg if len(sys.argv) > 3 else input("Username or UID to remove: ")    # Save our username/id input from the user, or prompt for input if none
                noConfArg = "--force"    # Assign the argument that will bypass confirmation before deletion
                # Check if the user must confirm the deletion before proceeding
                if noConfArg not in sys.argv:
                    uidConf = input("Are you sure you would like to remove user `" + uid + "`? [y/n]: ").lower()    # Have user confirm the deletion
                    # Exit if user did not confirm the deletion
                    if uidConf not in ["y","yes"]:
                        sys.exit(0)
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our username is not "admin" or "0"
                if uid.lower() not in ["admin","0"]:
                    # Check that we are not trying to remove our own username
                    if uid != user:
                        # Run our function, print the return message and exit on the return code
                        userDel = del_user(pfsenseServer, user, key, uid)
                        print(get_exit_message(userDel, pfsenseServer, pfsenseAction, uid, ""))
                        sys.exit(userDel)
                    # If our uid to delete matches our username
                    else:
                        print(get_exit_message("invalid_user", pfsenseServer, pfsenseAction, "", ""))
                        sys.exit(1)
                # If our UID was "admin" or "0", return error
                else:
                    print(get_exit_message("invalid_uid", pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(1)

            # Assign functions for flag --add-user-key
            elif pfsenseAction == "--add-user-key":
                # Action variables
                uname = thirdArg.lower() if len(sys.argv) > 3 else input("Username to add key: ").lower()    # Get user input for username, otherwise prompt user for input
                keyType = filter_input(fourthArg).lower() if len(sys.argv) > 4 else input("Key type [ssh,ipsec]: ").lower()    # Get user input for key type, or prompt user to input
                validInput = False    # Init a bool as false to track whether we are ready to run our configuration function
                # Get variables if key type is SSH
                if keyType.lower() == "ssh":
                    pubKeyPath = fifthArg if len(sys.argv) > 5 else input("Path to key file: ")    # Get our key path, or prompt user for path if none
                    destruct = sixthArg if len(sys.argv) > 6 else input("Override existing keys? [yes,no]: ")    # Get our key override value, or prompt user for input if none
                    user = eighthArg if seventhArg == "-u" and eighthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = tenthArg if ninthArg == "-p" and tenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    # INPUT VALIDATION
                    # Check if our key file exists
                    if os.path.exists(pubKeyPath):
                        # Read our file and save it's contents
                        with open(pubKeyPath,"r") as kf:
                            pubKey = kf.read()
                        # Check that our destruct value is okay
                        if destruct.lower() in ["yes","no"]:
                            destruct = True if destruct.lower() == "yes" else False    # Swap yes to True, and no to False
                            validInput = True    # Assign true value, we're ready to run our command
                        # If our destruct value is invalid
                        else:
                            print(get_exit_message("invalid_override", pfsenseServer, pfsenseAction, destruct, ""))
                            sys.exit(1)
                    # If our key file does not exist, print our error message and exit
                    else:
                        print(get_exit_message("invalid_ssh_path", pfsenseServer, pfsenseAction, pubKeyPath, ""))
                        sys.exit(1)
                # Get variables if key type is IPsec
                elif keyType.lower() == "ipsec":
                    pubKey = fifthArg if len(sys.argv) > 5 else getpass.getpass("IPsec pre-shared key: ")    # Get our key, or prompt user for key if none
                    user = seventhArg if sixthArg == "-u" and seventhArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = ninthArg if eighthArg == "-p" and ninthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    destruct = True    # Always replace this value if run, only one key is allowed
                    validInput = True  # Assign true value, we're ready to run our command
                # If we received an invalid key type input
                else:
                    print(get_exit_message("invalid_key_type", pfsenseServer, pfsenseAction, keyType, ""))
                    sys.exit(1)
                # Check if we are ready to run our configure function
                if validInput:
                    # Execute our add_user_key() function
                    addKeyEc = add_user_key(pfsenseServer, user, key, uname, keyType, pubKey, destruct)
                    print(get_exit_message(addKeyEc, pfsenseServer, pfsenseAction, keyType, uname))
                    sys.exit(addKeyEc)
                # If for any reason our valid input was false, print error and exit on non-zero
                else:
                    print(get_exit_message(2, pfsenseServer, pfsenseAction, keyType, ""))
                    sys.exit(2)

            # Assign functions for flag --change-user-passwd
            elif pfsenseAction == "--change-user-passwd":
                # Action variables
                uname = thirdArg if len(sys.argv) > 3 else input("Change username: ")    # Save our user input for username to change, prompt for input if none
                passwd = fourthArg if len(sys.argv) > 4 else None    # Save our user input, or assing None if interactive mode. Interactive mode will require confirmation
                # If our passwd is being passed using interactive mode
                if passwd is None:
                   # Loop until our passwd is successfully confirmed
                    while True:
                        passwd = getpass.getpass("New password: ")    # Prompt user for new passwd
                        passwdConf = getpass.getpass("Confirm password: ")    # Prompt user to confirm password
                        # Check if our inputs match, otherwise prompt user to reinput passwords
                        if passwd == passwdConf:
                            break
                        else:
                            print("Passwords do not match")
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Run our change passwd function
                passwdChanged = change_user_passwd(pfsenseServer, user, key, uname, passwd)
                print(get_exit_message(passwdChanged,pfsenseServer,pfsenseAction,uname,""))
                sys.exit(passwdChanged)

            # If user is trying to add an auth server, gather required configuration data from user
            elif pfsenseAction == "--add-ldapserver":
                # Local variables
                yesNo = ["yes", "no"]
                ldapConfig = {
                    "selection": {
                        "transport": ["TCP - Standard", "TCP - STARTTLS", "SSL - Encrypted"],
                        "ldapProtocol" : ["2","3"],
                        "searchScope": ["one", "subtree"],
                        "ldapTemplate": ["open", "msad", "edir"],
                    },
                    "input" : {
                        "descrName" : filter_input(sys.argv[3]) if len(sys.argv) > 3 else input("Descriptive name: "),
                        "ldapServer" : filter_input(sys.argv[4] if len(sys.argv) > 4 else input("LDAP Server: ")),
                        "ldapPort" : str(filter_input(sys.argv[5])) if len(sys.argv) > 5 else input("LDAP Port: "),
                        "transport" : filter_input(sys.argv[6]) if len(sys.argv) > 6 else input("Transport Type [standard, starttls, encrypted]: "),
                        "ldapProtocol" : filter_input(sys.argv[7]) if len(sys.argv) > 7 else input("LDAP Version [2, 3]: "),
                        "timeout" : filter_input(sys.argv[8]) if len(sys.argv) > 8 else input("Server Timeout (seconds): "),
                        "searchScope" : filter_input(sys.argv[9]) if len(sys.argv) > 9 else input("Search Scope [one, subtree]: "),
                        "baseDN" : sys.argv[10] if len(sys.argv) > 10 else input("Base DN: "),
                        "authContainers" : sys.argv[11] if len(sys.argv) > 11 else input("Auth Containers: "),
                        "extQuery" : filter_input(sys.argv[12] if len(sys.argv) > 12 else input("Extended Query [yes, no]: ")),
                        "query" : filter_input(sys.argv[13]) if len(sys.argv) > 13 else input("Query Expression: "),
                        "bindAnon" : filter_input(sys.argv[14]) if len(sys.argv) > 14 else input("Bind Anonymously [yes, no]: "),
                        "bindDN" : sys.argv[15] if len(sys.argv) > 15 else input("Bind DN: "),
                        "bindPw" : sys.argv[16] if len(sys.argv) > 16 else getpass.getpass("Bind Password: "),
                        "ldapTemplate" : filter_input(sys.argv[17]) if len(sys.argv) > 17 else input("LDAP Template [open, msad, edir]: "),
                        "userAttr" : sys.argv[18] if len(sys.argv) > 18 else input("User Attribute: "),
                        "groupAttr" : sys.argv[19] if len(sys.argv) > 19 else input("Group Attribute: "),
                        "memberAttr" : sys.argv[20] if len(sys.argv) > 20 else input("Member Attribute: "),
                        "rfc2307" : filter_input(sys.argv[21]) if len(sys.argv) > 21 else input("RFC2307 [yes, no]: "),
                        "groupObject" : sys.argv[22] if len(sys.argv) > 22 else input("Group Object Class: "),
                        "encode" : filter_input(sys.argv[23]) if len(sys.argv) > 23 else input("UTF-8 Encode [yes, no]: "),
                        "userAlt" : filter_input(sys.argv[24]) if len(sys.argv) > 24 else input("Username Alterations [yes, no]: "),
                        "user" : sys.argv[26] if len(sys.argv) > 26 and sys.argv[25] == "-u" else input("Please enter username: "),
                        "passwd" : sys.argv[28] if len(sys.argv) > 28 and sys.argv[27] == "-p" else getpass.getpass("Please enter password: ")
                    }
                }
                # INPUT VERIFICATION: LDAP configurations are large and prone to typos, verify that input before trying to add the server
                if len(ldapConfig["input"]) >= 24:
                    # Try to verify our LDAP port
                    try:
                        intCheck = int(ldapConfig["input"]["ldapPort"])
                        intPortCheck = True
                    except:
                        intPortCheck = False    # If we could not convert the port string to an integer
                    # If our ldap port could is invalid
                    if intPortCheck:
                        # Check that our port is in range
                        if 0 < intCheck <= 65535:
                            # Check that we have a valid transport type entered
                            if ldapConfig["input"]["transport"] in ["standard", "starttls", "encrypted"]:
                                # Swap our shorthand transport options to their valid option values
                                ldapConfig["input"]["transport"] = ldapConfig["selection"]["transport"][0] if ldapConfig["input"]["transport"] == "standard" else ldapConfig["input"]["transport"]
                                ldapConfig["input"]["transport"] = ldapConfig["selection"]["transport"][1] if ldapConfig["input"]["transport"] == "starttls" else ldapConfig["input"]["transport"]
                                ldapConfig["input"]["transport"] = ldapConfig["selection"]["transport"][2] if ldapConfig["input"]["transport"] == "encrypted" else ldapConfig["input"]["transport"]
                                # Check our LDAP version
                                if ldapConfig["input"]["ldapProtocol"] in ldapConfig["selection"]["ldapProtocol"]:
                                    # Try to validate our timeout value as an integer
                                    try:
                                        timeoutInt = int(ldapConfig["input"]["timeout"])
                                        intTimeCheck = True
                                    except:
                                        timeoutInt = 0
                                        intTimeCheck = False
                                    # Check if we now have a n integer
                                    if intTimeCheck:
                                        # Check if our timeout is in range
                                        if 9999999999 > timeoutInt > 0:
                                            # Check if our search scope is valid
                                            if ldapConfig["input"]["searchScope"] in ldapConfig["selection"]["searchScope"]:
                                                # Check if our extended query entry is valid
                                                if ldapConfig["input"]["extQuery"] in yesNo:
                                                    ldapConfig["input"]["extQuery"] = "" if ldapConfig["input"]["extQuery"] == "no" else ldapConfig["input"]["extQuery"]
                                                    # Check if our bind anonymously entry is valid
                                                    if ldapConfig["input"]["bindAnon"] in yesNo:
                                                        ldapConfig["input"]["bindAnon"] = "" if ldapConfig["input"]["bindAnon"] == "no" else ldapConfig["input"]["bindAnon"]
                                                        # Check if our LDAP template value is valid
                                                        if ldapConfig["input"]["ldapTemplate"] in ldapConfig["selection"]["ldapTemplate"]:
                                                            # Check if our rfc2307 value is valid
                                                            if ldapConfig["input"]["rfc2307"] in yesNo:
                                                                ldapConfig["input"]["rfc2307"] = "" if ldapConfig["input"]["rfc2307"] == "no" else ldapConfig["input"]["rfc2307"]
                                                                # Check if our encode value is valid
                                                                if ldapConfig["input"]["encode"] in yesNo:
                                                                    ldapConfig["input"]["encode"] = "" if ldapConfig["input"]["encode"] == "no" else ldapConfig["input"]["encode"]
                                                                    # Check if our userAlt value is valid
                                                                    if ldapConfig["input"]["userAlt"] in yesNo:
                                                                        ldapConfig["input"]["userAlt"] = "" if ldapConfig["input"]["userAlt"] == "no" else ldapConfig["input"]["userAlt"]
                                                                        # Now that we have verified our syntax, run the function
                                                                        addLdapExitCode = add_auth_server_ldap(pfsenseServer, ldapConfig["input"]["user"], ldapConfig["input"]["passwd"], ldapConfig["input"]["descrName"], ldapConfig["input"]["ldapServer"], ldapConfig["input"]["ldapPort"], ldapConfig["input"]["transport"], ldapConfig["input"]["ldapProtocol"], ldapConfig["input"]["timeout"], ldapConfig["input"]["searchScope"], ldapConfig["input"]["baseDN"], ldapConfig["input"]["authContainers"], ldapConfig["input"]["extQuery"], ldapConfig["input"]["query"], ldapConfig["input"]["bindAnon"], ldapConfig["input"]["bindDN"], ldapConfig["input"]["bindPw"], ldapConfig["input"]["ldapTemplate"], ldapConfig["input"]["userAttr"], ldapConfig["input"]["groupAttr"], ldapConfig["input"]["memberAttr"], ldapConfig["input"]["rfc2307"], ldapConfig["input"]["groupObject"], ldapConfig["input"]["encode"], ldapConfig["input"]["userAlt"])
                                                                        print(get_exit_message(addLdapExitCode, pfsenseServer, pfsenseAction, ldapConfig["input"]["descrName"], ''))
                                                                        sys.exit(addLdapExitCode)
                                                                    # If our userAlt value is invalid
                                                                    else:
                                                                        print(get_exit_message("invalid_userAlt", "", pfsenseAction,ldapConfig["input"]["userAlt"], ''))
                                                                        sys.exit(1)
                                                                # If our encode value is invalid
                                                                else:
                                                                    print(get_exit_message("invalid_encode", "", pfsenseAction,ldapConfig["input"]["encode"], ''))
                                                                    sys.exit(1)
                                                            # If our rfc2307 value is invalid
                                                            else:
                                                                print(get_exit_message("invalid_rfc2307", "", pfsenseAction,ldapConfig["input"]["rfc2307"], ''))
                                                                sys.exit(1)
                                                        # If our LDAP template value is invalid
                                                        else:
                                                            print(get_exit_message("invalid_ldapTemplate", "", pfsenseAction,ldapConfig["input"]["ldapTemplate"], ''))
                                                            sys.exit(1)
                                                    # If our bind anonymously entry is invalid
                                                    else:
                                                        print(get_exit_message("invalid_bindAnon", "", pfsenseAction,ldapConfig["input"]["bindAnon"], ''))
                                                        sys.exit(1)
                                                # If our extended query entry is invalid
                                                else:
                                                    print(get_exit_message("invalid_extQuery", "", pfsenseAction,ldapConfig["input"]["extQuery"], ''))
                                                    sys.exit(1)
                                            # If search scope is invalid, print error
                                            else:
                                                print(get_exit_message("invalid_searchScope", "", pfsenseAction,ldapConfig["input"]["searchScope"], ''))
                                                sys.exit(1)
                                        # If timeout is out of range
                                        else:
                                            print(get_exit_message("invalid_timeout_range", "", pfsenseAction,ldapConfig["input"]["timeout"], ''))
                                            sys.exit(1)
                                    # If we could not convert the input to an integer
                                    else:
                                        print(get_exit_message("invalid_timeout", "", pfsenseAction,ldapConfig["input"]["timeout"], ''))
                                        sys.exit(1)
                                # If invalid LDAP protocol was given
                                else:
                                    print(get_exit_message("invalid_protocol", "", pfsenseAction,ldapConfig["input"]["ldapProtocol"], ''))
                                    sys.exit(1)
                            # If unknown transport type was entered
                            else:
                                print(get_exit_message("invalid_transport", "", pfsenseAction,ldapConfig["input"]["transport"], ''))
                                sys.exit(1)
                        # If our LDAP port is out of range
                        else:
                            print(get_exit_message("invalid_portrange", "", pfsenseAction,ldapConfig["input"]["ldapPort"], ''))
                            sys.exit(1)
                    # If our LDAP port contained invalid characters
                    else:
                        print(get_exit_message("invalid_port", "", pfsenseAction,ldapConfig["input"]["ldapPort"], ''))
                        sys.exit(1)
                # If we are missing arguments
                else:
                    print(get_exit_message("missing_args", "", pfsenseAction, '', ''))
                    sys.exit(1)

            # If user is trying to add an SSL cert to the webconfigurator, try to add the cert
            elif pfsenseAction == "--add-sslcert":
                # Check if user passed in the correct number of arguments
                if len(sys.argv) > 5:
                    # Action Variables
                    certData = ""    # Init empty string
                    certKeyData = ""    # Init empty string
                    certPath = thirdArg    # Save the user passed file path to the crt file
                    certKeyPath = fourthArg    # Save the user passwed file path to the key file
                    descrToAdd = filter_input(fifthArg)    # Assign the user passed description (filtered)
                    descrToAdd = PfaVar.current_date if descrToAdd == "default" else descrToAdd    # Write default description if default is passed
                    user = seventhArg if sixthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = ninthArg if eighthArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    # Check if cert file exists
                    if os.path.exists(certPath):
                        # Read the certificate data
                        with open(certPath, "r") as certFile:
                            certData = certFile.read()
                        # Check if cert key file exists
                        if os.path.exists(certKeyPath):
                            # Read the certificate data
                            with open(certKeyPath, "r") as certKeyFile:
                                certKeyData = certKeyFile.read()
                        # If key doesn't exist, return error
                        else:
                            print(get_exit_message("no_key", pfsenseServer, pfsenseAction, certKeyPath, ""))
                            sys.exit(1)
                    # If cert doesn't exist, return error
                    else:
                        print(get_exit_message("no_cert", pfsenseServer, pfsenseAction, certPath, ""))
                        sys.exit(1)
                    # Ensure we have data to post, if so, try to add the cert to pfSense
                    if certData is not "" and certKeyData is not "":
                        addSslCertExitCode = add_ssl_cert(pfsenseServer, user, key, certData, certKeyData, descrToAdd)
                        # Check for authentication failed exit code
                        print(get_exit_message(addSslCertExitCode, pfsenseServer, pfsenseAction, "", ""))
                        sys.exit(addSslCertExitCode)
                    # Return error if files are empty
                    else:
                        print(get_exit_message("empty", pfsenseServer, pfsenseAction, "", ""))
                        sys.exit(1)

            # Assign functions for flag --check-auth
            elif pfsenseAction == "--check-auth":
                # Check if the correct number of arguments are found
                if len(sys.argv) > 2:
                    # Print Warning prompt and gather login creds
                    print("WARNING: Large numbers of authentication failures will enforce a pfSense lockout for your IP address. Proceed with caution.")
                    user = fourthArg if thirdArg == "-u" and fourthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = sixthArg if fifthArg == "-p" and sixthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    # Test authentication
                    if check_auth(pfsenseServer, user, key):
                        print(get_exit_message("success", pfsenseServer, pfsenseAction, '', ''))
                    else:
                        print(get_exit_message("fail", pfsenseServer, pfsenseAction, '', ''))
                        sys.exit(1)

            # Assign functions for flag --check-version
            elif pfsenseAction == "--check-version":
                # Action variables
                user = fourthArg if thirdArg == "-u" and fourthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixthArg if fifthArg == "-p" and sixthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                pfVersion = get_pfsense_version(pfsenseServer, user, key)    # Pull our pfSense version
                # Ensure we were able to pull our version successfully
                if pfVersion["ec"] == 0:
                    print(pfVersion["version"]["installed_version"])
                # If we encountered an error pulling our version
                else:
                    print(get_exit_message(pfVersion["ec"],pfsenseServer,pfsenseAction,"",""))    # Print our error msg
                    sys.exit(pfVersion["ec"])    # Exit on our non-zero function return code

            # Assign functions for flag --read-rules
            elif pfsenseAction == "--read-rules":
                # Action variables
                iface = thirdArg if len(sys.argv) > 3 else input("Interface: ")    # Save our inline argumnet for interface, or prompt if none
                ruleFilter = fourthArg if len(sys.argv) > 4 else input("Filter [blank if none]:")   # Assign our filter argument to the fourth slot
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                getRules = get_firewall_rules(pfsenseServer, user, key, iface)    # Get our alias data dictionary
                idHeader = structure_whitespace("ID",5,"-", False) + " "   # Create our ID header
                typeHeader = structure_whitespace("TYPE",6,"-", False) + " "    # Create our TYPE header
                protocolHeader = structure_whitespace("PROTOCOL", 10,"-", True) + " "    # Create our PROTOCOL header
                srcHeader = structure_whitespace("SOURCE",25,"-", True) + " "    # Create our SOURCE header
                dstHeader = structure_whitespace("DESTINATION",25,"-", True) + " "    # Create our DESTINATION header
                gwHeader = structure_whitespace("GATEWAY",12,"-", True) + " "    # Create our GATEWAY header
                descrHeader = structure_whitespace("DESCRIPTION",30,"-", True) + " "    # Create our DESCRIPTION header
                header = idHeader + typeHeader + protocolHeader + srcHeader + dstHeader + gwHeader + descrHeader   # Piece our header together
                # Check that we pulled our rules without error
                if getRules["ec"] == 0:
                    # FORMAT OUR STATIC SYSTEM RULES
                    defId = structure_whitespace("",5," ",True) + " "    # Format our default ID for system rules
                    defProt = structure_whitespace("ANY",10," ",True) + " "   # Format our default PROTOCOL for system rules
                    # BOGONS
                    bogonType = structure_whitespace("block",6," ", True) + " "
                    bogonSrc = structure_whitespace("Any unassigned by IANA",25," ",True) + " "
                    bogonDst = structure_whitespace("*",25," ",True) + " "
                    bogonGw = structure_whitespace("*",12," ",True) + " "
                    bogonDescr = structure_whitespace("Block bogon networks",30," ",True) + " "
                    bogonData = defId + bogonType + defProt + bogonSrc + bogonDst + bogonGw + bogonDescr
                    # RFC1918
                    prvType = structure_whitespace("block",6," ", True) + " "
                    prvSrc = structure_whitespace("RFC1918 networks",25," ",True) + " "
                    prvDst = structure_whitespace("*",25," ",True) + " "
                    prvGw = structure_whitespace("*",12," ",True) + " "
                    prvDescr = structure_whitespace("Block private networks",30," ",True) + " "
                    prvData = defId + prvType + defProt + prvSrc + prvDst + prvGw + prvDescr
                    # ANTILOCKOUT
                    alType = structure_whitespace("pass", 6, " ", True) + " "
                    alSrc = structure_whitespace("*", 25, " ", True) + " "
                    alDst = structure_whitespace("LAN address:22,80,443", 25, " ", True) + " "
                    alGw = structure_whitespace("*", 12, " ", True) + " "
                    alDescr = structure_whitespace("Anti-lockout rule", 30, " ", True) + " "
                    alData = defId + alType + defProt + alSrc + alDst + alGw + alDescr
                    # CHECK OUR USERS FILTER AND READ INFORMATION ACCORDINGLY
                    headPrinted = False    # Create a counter for our loop
                    for key,value in getRules["rules"]["user_rules"].items():
                        # FORMAT OUR ACL DATA VALUES
                        ipProto = ("v" + (value["ipprotocol"].replace("inet","") + "4")).replace("v464","*").replace("64","6")    # Format our IP protocol into either *, v4, or v6
                        transProto = value["proto"].upper()    # Save our transport protocol in uppercase
                        formatProto = "ANY" if transProto == ipProto else transProto + ipProto    # Determine how to display our IP and transport protocols
                        proto = structure_whitespace(formatProto,10," ", True) + " "   # Create our type data
                        srcNegated = "!" if value["srcnot"] == "yes" else ""    # Add ! char if context is inverted
                        dstNegated = "!" if value["dstnot"] == "yes" else ""    # Add ! char if context is inverted
                        srcFormat = srcNegated + value["src_net"] if value["src_net"] != "" else srcNegated + value["src"]     # Determine which source value to print
                        dstFormat = dstNegated + value["dst_net"] if value["dst_net"] != "" else dstNegated + value["dst"]    # Determine which dest value to print
                        id = structure_whitespace(value["id"],5," ", True) + " "   # Create our ID data
                        type = structure_whitespace(value["type"],6," ", True) + " "   # Create our type data
                        src = structure_whitespace("*" if srcFormat == "any" else srcFormat,25," ", True) + " "     # Create our SOURCE
                        dst = structure_whitespace("*" if dstFormat == "any" else dstFormat,25," ", True) + " "    # Create our DESTINATION
                        gw = structure_whitespace("*" if value["gateway"] == "" else value["gateway"],12," ", True) + " "    # Create our GATEWAY
                        descr = structure_whitespace(value["descr"],30," ", True) + " "    # Create our DESCRIPTION
                        data = id + type + proto + src + dst + gw + descr   # Piece our data together
                        # Check our user filter and print data accordingly
                        if ruleFilter.lower() in ["-a", "--all", ""]:
                            print(header) if not headPrinted else None
                            # Check if our system rules are using
                            if getRules["rules"]["antilockout"] == True and not headPrinted:
                                print(alData)
                            if getRules["rules"]["bogons"] == True and not headPrinted:
                                print(bogonData)
                            if getRules["rules"]["private"] == True and not headPrinted:
                                print(prvData)
                            headPrinted = True
                            print(data)
                        elif ruleFilter.startswith(("--source=","-s=")):
                            srcExp = ruleFilter.replace("--source=","").replace("-s=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if srcFormat.startswith(srcExp):
                                print(header) if not headPrinted else None
                                headPrinted = True
                                print(data)
                        elif ruleFilter.startswith(("--destination=","-d=")):
                            dstExp = ruleFilter.replace("--destination=","").replace("-d=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if dstFormat.startswith(dstExp):
                                print(header) if not headPrinted else None
                                headPrinted = True
                                print(data)
                        elif ruleFilter.startswith(("--protocol=","-p=")):
                            proExp = ruleFilter.replace("--protocol=","").replace("-p=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if formatProto == proExp:
                                print(header) if not headPrinted else None
                                headPrinted = True
                                print(data)
                        elif ruleFilter.startswith(("--ip-version=","-i=")):
                            ipExp = ruleFilter.replace("--ip-version=","").replace("-i=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if ipExp.lower() == ipProto:
                                print(header) if not headPrinted else None
                                headPrinted = True
                                print(data)
                        elif ruleFilter.startswith(("--gateway=","-g=")):
                            gwExp = ruleFilter.replace("--gateway=","").replace("-g=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if gw.startswith(gwExp):
                                print(header) if not headPrinted else None
                                headPrinted = True
                                print(data)
                        # If user wants to print the JSON output
                        elif ruleFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(getRules["rules"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif ruleFilter.startswith(("--json=", "-j=")):
                            jsonPath = ruleFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readrules-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(getRules["rules"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, ruleFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                # If we encountered an error pulling our rules
                else:
                    print(get_exit_message(getRules["ec"], pfsenseServer, pfsenseAction, iface, ""))
                    sys.exit(getRules["ec"])

            # Assign functions for flag --add-rule
            elif pfsenseAction == "--add-rule":
                # Action variables
                availProtos = ["any","tcp","udp","tcp/udp","icmp"]    # Assign list of available protocols
                portProtos = ["tcp","udp","tcp/udp"]    # Assign a list of protocols that allow ports
                invertSrc = False    # Init our invert source match to False
                invertDst = False    # Init our invert dest match to False
                pos = "top" if "--top" in sys.argv else ""  # If user requests option for the rule to be added to top of ACL, assign value "top"
                iface = thirdArg if len(sys.argv) > 3 else input("Interface: ")    # Get our user input for the interface ACL to add to, or prompt for input if none
                type = filter_input(fourthArg).lower() if len(sys.argv) > 4 else input("Rule type [pass,block,reject]: ").lower()    # Get our user input for ACL type, or prompt user if none
                ipver = filter_input(fifthArg).lower() if len(sys.argv) > 5 else input("IP protocol version [ipv4]: ")    # Get our user input for IP protocol type, or prompt user if none
                ipver = "inet6" if ipver == "ipv6" else ipver    # Swap our ipv6 input for inet6 as required by POST data form
                ipver = "inet" if ipver == "ipv4" else ipver    # Swap our ipv4 input for inet as required by POST data form
                proto = sixthArg.lower() if len(sys.argv) > 6 else input("Protocol [" + ",".join(availProtos) + "]: ")    # Get our user input for protocol type, or prompt user if none
                noPort = True if proto not in portProtos else False    # Set a bool indicating the we require a port for this rule
                # Gather remaining input differently if a port is required
                if not noPort:
                    source = seventhArg.lower() if len(sys.argv) > 7 else input("Source address: ")    # Get our user input for source address, or prompt user if none
                    sourcePort = filter_input(eighthArg).lower() if len(sys.argv) > 8 else input("Source port (port range hyphen separated): ")    # Get our user input for source ports, or prompt user if none
                    dest = ninthArg.lower() if len(sys.argv) > 9 else input("Destination address: ")    # Get our user input for dest address, or prompt user if none
                    destPort = filter_input(tenthArg).lower() if len(sys.argv) > 10 else input("Destination port (port range hyphen separated): ")    # Get our user input for dest port, or prompt user if none
                    gw = filter_input(eleventhArg) if len(sys.argv) > 11 else input("Gateway [blank for none]: ")    # Get our user input for gateway, or prompt user for input
                    gw = "" if gw.lower() in ["default","none"] else gw    # Swap out default or none input for empty string as required by POST data form
                    log = filter_input(twelfthArg) if len(sys.argv) > 12 else input("Log rule matches [yes,no]: ")    # Get our user input for logging, or prompt user for input
                    logBool = True if log == "yes" else False    # Swap out our "no" entry for blank string as required by POST data form
                    descr = thirteenthArg if len(sys.argv) > 13 else input("Rule description: ")    # Get our user input for description or prompt user for input if none
                    user = fifteenthArg if fourteenthArg == "-u" and fifteenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = seventeenthArg if sixteenthArg == "-p" and seventeenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # If our protocol does not require a port
                else:
                    sourcePort = ""    # Default our source port blank
                    destPort = ""    # Default our dest port to blank
                    source = seventhArg.lower() if len(sys.argv) > 7 else input("Source address: ")    # Get our user input for source address, or prompt user if none
                    dest = eighthArg.lower() if len(sys.argv) > 8 else input("Destination address: ")    # Get our user input for dest address, or prompt user if none
                    gw = filter_input(ninthArg) if len(sys.argv) > 9 else input("Gateway [blank for none]: ")    # Get our user input for gateway, or prompt user for input
                    gw = "" if gw.lower() in ["default","none"] else gw    # Swap out default or none input for empty string as required by POST data form
                    log = filter_input(tenthArg) if len(sys.argv) > 10 else input("Log rule matches [yes,no]: ")    # Get our user input for logging, or prompt user for input
                    logBool = True if log == "yes" else False    # Swap out our "no" entry for blank string as required by POST data form
                    descr = eleventhArg if len(sys.argv) > 11 else input("Rule description: ")    # Get our user input for description or prompt user for input if none
                    user = thirteenthArg if twelfthArg == "-u" and thirteenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = fifteenthArg if fourteenthArg == "-p" and fifteenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                ### INPUT VALIDATION ###
                # Check our rule type
                if type in ["pass","block","reject"]:
                    # Check if our IP version is valid
                    if ipver in ["inet","inet6","any"]:
                        # Check if our protocol is valid
                        if proto in availProtos:
                            # Check if our source address contains our invert chars (!-?~)
                            if source.startswith(("!","-","?","~")):
                                invertSrc = True    # Assign our invert source bool to True for use in our function
                                source = source.strip("!-?~")    # Remove the ! from our source address
                            # Check if our source includes a CIDR
                            srcBit = "32"  # Assign a default bit count
                            if "/" in source:
                                srcCidrList = source.split("/")    # Split our CIDR into a list containing the address and bitmask
                                if len(srcCidrList) == 2 and srcCidrList[1].isdigit():
                                    # Check if our bitmask is within range
                                    if 1 <= int(srcCidrList[1]) <= 32:
                                        srcBit = srcCidrList[1]    # Save our bitmask
                                        source = srcCidrList[0]    # Save our address
                                    # If our bitmask is invalid
                                    else:
                                        print(get_exit_message("invalid_bitmask", pfsenseServer, pfsenseAction, srcCidrList[1], ""))
                                        sys.exit(1)
                            # Check that our source IP is valid
                            if validate_ip(source):
                                # Check if our dest address contains our invert char (!)
                                if dest.startswith(("!","-","?","~")):
                                    invertDst = True    # Assign our invert dest bool to True for use in our function
                                    dest = dest.strip("!-?~")    # Remove the ! from our dest address
                                # Check if our dest includes a CIDR
                                dstBit = "32"  # Assign a default bit count
                                if "/" in dest:
                                    dstCidrList = dest.split("/")    # Split our CIDR into a list containing the address and bitmask
                                    if len(dstCidrList) == 2 and dstCidrList[1].isdigit():
                                        # Check if our bitmask is within range
                                        if 1 <= int(dstCidrList[1]) <= 32:
                                            dstBit = dstCidrList[1]    # Save our bitmask
                                            dest = dstCidrList[0]    # Save our address
                                        # If our bitmask is invalid
                                        else:
                                            print(get_exit_message("invalid_bitmask", pfsenseServer, pfsenseAction, dstCidrList[1], ""))
                                            sys.exit(1)
                                # Check if our dest IP is valid
                                if validate_ip(dest):
                                    # Check that our log is valid
                                    if log in ["yes",""]:
                                        # Run our function to add the rule
                                        addRuleEc = add_firewall_rule(pfsenseServer, user, key, iface, type, ipver, proto, invertSrc, source, srcBit, sourcePort, invertDst, dest, dstBit, destPort, gw, descr, logBool, pos, noPort)
                                        print(get_exit_message(addRuleEc, pfsenseServer, pfsenseAction, iface, ""))
                                        sys.exit(addRuleEc)
                                    # If our log is invalid
                                    else:
                                        print(get_exit_message("invalid_log", pfsenseServer, pfsenseAction, log, ""))
                                        sys.exit()
                                # If our destination IP is invalid
                                else:
                                    print(get_exit_message("invalid_dest", pfsenseServer, pfsenseAction, dest, ""))
                            # If our source IP is invalid
                            else:
                                print(get_exit_message("invalid_source", pfsenseServer, pfsenseAction, source, ""))
                                sys.exit(1)
                        # If our protocol is invalid
                        else:
                            print(get_exit_message("invalid_protocol", pfsenseServer, pfsenseAction, proto, ",".join(availProtos)))
                            sys.exit(1)
                    # If our IP version is invalid
                    else:
                        print(get_exit_message("invalid_ipver", pfsenseServer, pfsenseAction, ipver, ""))
                        sys.exit(1)
                # If our rule type is invalid
                else:
                    print(get_exit_message("invalid_type", pfsenseServer, pfsenseAction, type, ""))
                    sys.exit(1)

            # Assign functions for flag --del-rule
            elif pfsenseAction == "--del-rule":
                # Action variables
                iface = thirdArg if len(sys.argv) > 3 else input("Interface: ")    # Save our users interface input, or prompt for input if none
                ruleId = filter_input(fourthArg) if len(sys.argv) > 4 else input("Rule ID: ")    # Save our users rule ID input, or prompt for input if none
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                noConfirm = True if "--force" in sys.argv else False    # Track if user wants to remove the rule without user confirmation beforehand (option --force)
                # INPUT VALIDATION
                if ruleId.isdigit():
                    # Ask user to confirm deletion if not requested otherwise
                    if not noConfirm:
                        usrCon = input("WARNING: Firewall rule deletions cannot be undone.\nAre you sure you would like to remove firewall rule ID `" + ruleId + "` from " + iface + "? [y/n]")
                        if usrCon.lower() != "y":
                            sys.exit(0)
                    # Run our deletion command
                    ruleDel = del_firewall_rule(pfsenseServer, user, key, iface, ruleId)
                    print(get_exit_message(ruleDel, pfsenseServer, pfsenseAction, iface, ruleId))
                    sys.exit(ruleDel)
                # If our rule ID is invalid
                else:
                    print(get_exit_message("invalid_id", pfsenseServer, pfsenseAction, ruleId, ""))
                    sys.exit()

            # Assign functions for flag --read-aliases
            elif pfsenseAction == "--read-aliases":
                # Action Variables
                aliasFilter = thirdArg    # Assign our filter argument to the third slot
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                getAliasData = get_firewall_aliases(pfsenseServer, user, key)    # Get our alias data dictionary
                # Check that our exit code was good
                if getAliasData["ec"] == 0:
                    # If user wants to display all info, print in YAML like format
                    if aliasFilter.upper() in ("-A", "--ALL"):
                        # Print our alias values
                        for key,value in getAliasData["aliases"].items():
                            print("- name: " + value["name"])
                            print("  description: \"" + value["descr"] + "\"")
                            print("  type: " + value["type"])
                            print("  entries:")
                            # Loop through entries and print their values
                            for entryKey,entryValue in value["entries"].items():
                                print("    id: " + str(entryValue["id"]))
                                print("      value: " + entryValue["value"])
                                print("      subnet: " + entryValue["subnet"]) if entryValue["subnet"] != "0" else None
                                print("      description: \"" + entryValue["descr"] + "\"")
                            print("")
                    # If user wants to display all info, print in YAML like format
                    elif aliasFilter.startswith(("--name=","-n=")):
                        aliasScope = aliasFilter.replace("--name=", "").replace("-n=", "")    # Remove expected argument values to determine our VLAN scope
                        # Print our alias values
                        if aliasScope in getAliasData["aliases"]:
                            print("- name: " + getAliasData["aliases"][aliasScope]["name"])
                            print("  description: \"" + getAliasData["aliases"][aliasScope]["descr"] + "\"")
                            print("  type: " + getAliasData["aliases"][aliasScope]["type"])
                            print("  entries:")
                            # Loop through entries and print their values
                            for entryKey,entryValue in getAliasData["aliases"][aliasScope]["entries"].items():
                                print("    id: " + str(entryValue["id"]))
                                print("      value: " + entryValue["value"])
                                print("      subnet: " + entryValue["subnet"]) if entryValue["subnet"] != "0" else None
                                print("      description: \"" + entryValue["descr"] + "\"")
                    # If user wants to print the JSON output
                    elif aliasFilter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(getAliasData["aliases"]))   # Print our JSON data
                    # Check if JSON mode was selected
                    elif aliasFilter.startswith("-j=") or aliasFilter.startswith("--json="):
                        jsonPath = aliasFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readaliases-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(jsonPath):
                            # Open an export file and save our data
                            jsonExported = export_json(getAliasData["aliases"], jsonPath, jsonName)
                            # Check if the file now exists
                            if jsonExported:
                                print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                            else:
                                print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                            sys.exit(1)
                    # If unknown filter was given
                    else:
                        print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, aliasFilter, ""))
                # If non-zero exit code was received from get_firewall_aliases()
                else:
                    print(get_exit_message(getAliasData["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(getAliasData["ec"])

            # Assign functions for flag --modify-alias
            elif pfsenseAction == "--modify-alias":
                aliasName = thirdArg    # Assign our thirdArgument to aliasName which will be used to search for existing aliases
                aliasValue = fourthArg    # Assign our fourthArgument to aliasValue which will be our new entry values
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Check that we have our required arguments
                if aliasName is not None and aliasValue is not None:
                    aliasModded = modify_firewall_alias(pfsenseServer, user, key, aliasName, aliasValue)    # Assign aliasModded which will be used to track errors
                    print(get_exit_message(aliasModded, pfsenseServer, pfsenseAction, aliasName, ""))
                    sys.exit(aliasModded)
                # Otherwise, print error containing correct syntax
                else:
                    print("Error: Invalid syntax - `pfsense-automator <pfSense IP or FQDN> --modify-alias <alias name> <alias values>`")
                    sys.exit(1)

            # Assign functions for flag --read-virtual-ip
            elif pfsenseAction == "--read-virtual-ips":
                # Action variables
                vipFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                vipTable = get_virtual_ips(pfsenseServer, user, key)    # Get our virtual IP configuration
                idHead = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                subnetHead = structure_whitespace("SUBNET", 20, "-", True) + " "    # Format our subnet header value
                typeHead = structure_whitespace("TYPE", 10, "-", True) + " "    # Format our type header value
                ifaceHead = structure_whitespace("INTERFACE", 15, "-", True) + " "    # Format our interface header value
                descrHead = structure_whitespace("DESCRIPTION", 45, "-", True) + " "    # Format our description header value
                header = idHead + subnetHead + typeHead + ifaceHead + descrHead    # Format our print header
                # Check that we did not receive an error pulling the data
                if vipTable["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 0    # Assign a loop counter
                    for key,value in vipTable["virtual_ips"].items():
                        id = structure_whitespace(str(key), 5, " ", True) + " "    # Get our entry number
                        subnet = structure_whitespace(value["subnet"] + "/" + value["subnet_bits"], 20, " ", True) + " "    # Get our subnet in CIDR form
                        type = structure_whitespace(value["type"], 10, " ", True) + " "    # Get our type value
                        iface = structure_whitespace(value["interface"], 15, " ", True) + " "    # Get our interface value
                        descr = structure_whitespace(value["descr"], 45, " ", True) + " "    # Get our description value
                        # Check if user passed in the ALL filter
                        if vipFilter.upper() in ["-A", "--ALL"]:
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            print(id + subnet + type + iface + descr)    # Print our data values
                        # Check if user wants to filter by interface
                        elif vipFilter.startswith(("-i=","--iface=")):
                            ifaceExp = vipFilter.replace("-i=","").replace("--iface","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if value["interface"].startswith(ifaceExp):
                                print(id + subnet + type + iface + descr)    # Print our data values
                        # Check if user wants to filter by type
                        elif vipFilter.startswith(("-t=","--type=")):
                            typeExp = vipFilter.replace("-t=","").replace("--type","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if value["type"] == typeExp:
                                print(id + subnet + type + iface + descr)    # Print our data values
                         # Check if user wants to filter by subnet
                        elif vipFilter.startswith(("-s=","--subnet=")):
                            subnetExp = vipFilter.replace("-s=","").replace("--subnet","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if subnet.startswith(subnetExp):
                                print(id + subnet + type + iface + descr)    # Print our data values
                        # If user wants to print the JSON output
                        elif vipFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(vipTable["virtual_ips"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif vipFilter.startswith(("--json=", "-j=")):
                            jsonPath = vipFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readvirtip-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(vipTable["virtual_ips"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perform this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, vipFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we could not pull our virtual IP data
                else:
                    print(get_exit_message(vipTable["ec"],pfsenseServer,pfsenseAction,"",""))    # Print error message
                    sys.exit(vipTable["ec"])    # Exit on non-zero

            # Assign functions for flag --add-virtual-ip
            elif pfsenseAction == "--add-virtual-ip":
                # Action variables
                vipModes = ["ipalias","carp","proxyarp","other"]    # Save a list of our available Virtual IP modes
                vipMode = filter_input(thirdArg) if len(sys.argv) > 3 else input("Virtual IP type " + str(vipModes).replace('\'',"") + ": ")    # Gather user input for virtual IP mode
                vipIface = filter_input(fourthArg) if len(sys.argv) > 4 else input("Interface: ")    # Gather user input for virtual IP interface
                vipSubnet = fifthArg if len(sys.argv) > 5 else input("Virtual IP subnet: ")    # Gather user input for virtual IP subnet
                vipExpand = filter_input(sixthArg) if len(sys.argv) > 6 else input("Disable IP expansion [yes,no]: ")    # Gather user input for IP expansion option
                vipPasswd = seventhArg if len(sys.argv) > 7 else None    # If a seventh argument is passed, save it as the vip password
                vipPasswd = getpass.getpass("Virtual IP Password: ") if vipPasswd is None and vipMode.lower() == "carp" else vipPasswd    # If interactive mode is initiated, prompt user for vip password if mode is carp
                vipVhid = eighthArg if len(sys.argv) > 8 else None    # If a eighth argument is passed, save it as the vip vhid
                vipVhid = input("VHID Group [1-255,auto]: ") if vipVhid is None and vipMode.lower() == "carp" else ""    # If interactive mode is initiated, prompt user for vip vhid if mode is carp
                vipAdvBase = ninthArg if len(sys.argv) > 9 else None    # If a ninth argument is passed, save it as the vip advbase
                vipAdvBase = input("Advertising Base [1-254,default]: ") if vipAdvBase is None and vipMode.lower() == "carp" else ""    # If interactive mode is initiated, prompt user for vip advbase if mode is carp
                vipAdvBase = "1" if vipAdvBase.lower() == "default" else vipAdvBase    # If user requests default value, assign 1, otherwise retain existing value
                vipAdvSkew = tenthArg if len(sys.argv) > 10 else None    # If a ninth argument is passed, save it as the vip advskew
                vipAdvSkew = input("Advertising Skew [0-254,default]: ") if vipAdvSkew is None and vipMode.lower() == "carp" else ""    # If interactive mode is initiated, prompt user for vip advskew if mode is carp
                vipAdvSkew = "0" if vipAdvSkew.lower() == "default" else vipAdvSkew    # If user requests default value, assign 1, otherwise retain existing value
                vipDescr = eleventhArg if len(sys.argv) > 11 else input("Virtual IP Description: ")    # Get user input for description
                user = thirteenthArg if twelfthArg == "-u" and thirteenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = fifteenthArg if fourteenthArg == "-p" and fifteenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                existingVips = get_virtual_ips(pfsenseServer,user,key)    # Pull our existing virtual IPs
                existingIfaces = get_interfaces(pfsenseServer,user,key)    # Pull our existing interfaces
                # INPUT VALIDATION
                # Check if our VIP mode is valid
                if vipMode.lower() in vipModes:
                    # Check if our interface is valid
                    ifFound = False  # Assign a bool to track whether a match was found
                    if vipIface in existingIfaces["ifaces"]:
                        ifFound = True  # Assign true value to indicate we found a match
                    # If the user did not pass in the interfaces pfid, check our descriptive id and physical id
                    else:
                        # Loop through each interface and check alternate IDs
                        for pfId,data in existingIfaces["ifaces"].items():
                            # Check if input matches our physical iface ID
                            if vipIface == data["id"]:
                                vipIface = pfId    # Assign our interface to the PF ID version of this interface
                                ifFound = True    # Assign true value to indicate we found a match
                                break    # Break our loop as our match has been found
                            # Check if our input matches our descriptive interface ID
                            elif vipIface == data["descr"]:
                                vipIface = pfId  # Assign our interface to the PF ID version of this interface
                                ifFound = True  # Assign true value to indicate we found a match
                                break  # Break our loop as our match has been found
                    # Check if we were able to find our interface using alternate IDs
                    if ifFound:
                        # Check if our subnet is valid
                        if "/" in vipSubnet:
                            parseSubnet = vipSubnet.split("/")
                            # Check if our list is an expected size
                            if len(parseSubnet) == 2:
                                vipIpAddr = parseSubnet[0]    # Our first list item will be our IP address
                                vipSubnetBits = parseSubnet[1]    # Our second list item will be our subnet bit count
                                # Check if our IP is valid
                                if validate_ip(vipIpAddr):
                                    # Check if our subnet is valid
                                    if vipSubnetBits.isdigit():
                                        if 1 <= int(vipSubnetBits) <= 32:
                                            # Check our vipExpand input
                                            if vipExpand in ["yes","no"]:
                                                vipExpand.replace("no","")    # Remove no from the string as POST requires empty string later on
                                                # Check our vhid input
                                                vhidValid = False    # Assign a bool to track if our VHID input is valid
                                                # Check if our input is "auto"
                                                if vipVhid == "auto" or vipVhid is "":
                                                    vhidValid = True  # Our value is valid
                                                # Check that our values are valid
                                                elif vipVhid.isdigit():
                                                    # Check if our integer is within range
                                                    if 1 <= int(vipVhid) <= 255:
                                                        # Loop through to ensure our value is not already taken
                                                        for id,data in existingVips["virtual_ips"].items():
                                                            # Return error and exit if our vhid value is a duplicate
                                                            if vipVhid == data["vhid"] and vipIface == data["interface"]:
                                                                print(get_exit_message("vhid_exists",pfsenseServer,pfsenseAction,vipVhid,vipIface))    # Print error msg
                                                                sys.exit(1)    # Exit on non-zero
                                                        vhidValid = True    # Our value is valid if it survived the loop
                                                # If our input is not expected, print error msg and exit on non-zero
                                                else:
                                                    print(get_exit_message("invalid_vhid",pfsenseServer,pfsenseAction,vipVhid,""))
                                                    sys.exit(1)
                                                # Check if our vhidValid is true
                                                if vhidValid:
                                                    vipAdvValid = False    # Assign a bool to track if our advertisements are valid
                                                    # Check if our input is None
                                                    if vipAdvBase is "" and vipAdvSkew is "":
                                                        vipAdvValid = True  # Our input is valid
                                                    # Check if our VHID base and skew advertisements are valid
                                                    elif vipAdvBase.isdigit() and vipAdvSkew.isdigit():
                                                        # Check if our integers are valid
                                                        if 1 <= int(vipAdvBase) <= 254 and 0 <= int(vipAdvSkew) <= 254:
                                                            vipAdvValid = True    # Our input is valid
                                                        # If our input is invalid
                                                        else:
                                                            print(get_exit_message("invalid_adv",pfsenseServer,pfsenseAction,vipAdvBase,vipAdvSkew))    # Print error msg
                                                            sys.exit(1)    # Exit on non-zero

                                                    # Check if our input is valid
                                                    if vipAdvValid:
                                                        # Run our POST function to add the vitrual IP
                                                        postVip = add_virtual_ip(pfsenseServer,user,key,vipMode,vipIface,vipIpAddr,vipSubnetBits,vipExpand,vipPasswd,vipVhid,vipAdvBase,vipAdvSkew,vipDescr)
                                                        # Print our exit message and exit on function return code
                                                        print(get_exit_message(postVip,pfsenseServer,pfsenseAction,vipSubnet,""))
                                                        sys.exit(postVip)
                                            # If our vipExpand option is invalid return error and exit on non-zero
                                            else:
                                                print(get_exit_message("invalid_expand",pfsenseServer,pfsenseAction,vipExpand,""))
                                                sys.exit(1)
                                        # If our subnet bit count is out of range
                                        else:
                                            print(get_exit_message("invalid_subnet",pfsenseServer,pfsenseAction,vipSubnet,""))    # Print error msg
                                            sys.exit(1)    # Exit on non-zero
                                    # If our subnet bit count is invalid
                                    else:
                                        print(get_exit_message("invalid_subnet",pfsenseServer,pfsenseAction,vipSubnet,""))    # Print error msg
                                        sys.exit(1)    # Exit on non-zero
                                # If our IP section of our CIDR is invalid
                                else:
                                    print(get_exit_message("invalid_subnet",pfsenseServer,pfsenseAction,vipSubnet,""))    # Print error msg
                                    sys.exit(1)    # Exit on non-zero
                            # If our CIDR could not be split correctly
                            else:
                                print(get_exit_message("invalid_subnet",pfsenseServer,pfsenseAction,vipSubnet,""))    # Print error msg
                                sys.exit(1)    # Exit on non-zero
                        # If our CIDR is invalid
                        else:
                            print(get_exit_message("invalid_subnet",pfsenseServer,pfsenseAction,vipSubnet,""))    # Print error msg
                            sys.exit(1)    # Exit on non-zero
                    # If we did not find a match, return error and exit on non-zero
                    else:
                        print(get_exit_message("invalid_iface",pfsenseServer,pfsenseAction,vipIface,""))
                        sys.exit(1)
                # If our mode is invalid
                else:
                    print(get_exit_message("invalid_mode",pfsenseServer,pfsenseAction,vipMode,""))
                    sys.exit(1)
            # Assign functions for flag --read-sslcert
            elif pfsenseAction == "--read-sslcerts":
                verbosity = thirdArg    # Assign our verbosity mode to thirdArgs value
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                getCertData = get_ssl_certs(pfsenseServer, user, key)    # Save the function output dict for use later
                # Check that we did not receive an error
                if getCertData["ec"] == 0:
                    # Check if data was returned
                    if len(getCertData["certs"]) > 0:
                        # Check if JSON mode was selected
                        if verbosity.startswith("-j=") or verbosity.startswith("--json="):
                            jsonPath = verbosity.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readsslcerts-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(getCertData["certs"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If user wants to print the JSON output
                        elif verbosity.lower() in ("--read-json", "-rj"):
                            print(json.dumps(getCertData["certs"]))   # Print our JSON data
                        # If JSON mode was not selected
                        else:
                            # Format header values
                            idHead = structure_whitespace("#", 3, "-", False) + " "    # Format our ID header value
                            nameHead = structure_whitespace("NAME", 37, "-", True) + " "    # Format our name header value
                            isrHead = structure_whitespace("ISSUER", 11, "-", True) + " "    # Format our issuer header value
                            cnHead = structure_whitespace("CN", 25, "-", True) + " "    # Format our CN header value
                            startHead = structure_whitespace("VALID FROM", 25, "-", True) + " "    # Format our start date header value
                            expHead = structure_whitespace("VALID UNTIL", 25, "-", True) + " "    # Format our expiration date header value
                            serialHead = structure_whitespace("SERIAL", 30, "-", True) + " "    # Format our serial header value
                            iuHead = "IN USE"    # Format our certificate in use header value
                            # Format header
                            if verbosity == "-v":
                                print(idHead + nameHead + isrHead + cnHead + startHead + expHead + serialHead + iuHead)
                                #print(structure_whitespace("#", 3, "-", False) + " " + structure_whitespace("NAME", 37, "-", True) + " " + structure_whitespace("ISSUER", 11, "-", True) + " " + structure_whitespace("CN", 25, "-", True) + " " + structure_whitespace("VALID FROM", 25, "-", True) + " " + structure_whitespace("VALID UNTIL", 25, "-", True) + " " + structure_whitespace("SERIAL", 30, "-", True) + " " + "IN USE")
                            else:
                                print(idHead + nameHead + isrHead + cnHead + expHead + iuHead)
                                #print(structure_whitespace("#", 3, "-", False) + " " + structure_whitespace("NAME", 37, "-", True) + " " + structure_whitespace("ISSUER", 11, "-", True) + " " + structure_whitespace("CN", 25, "-", True) + " " + structure_whitespace("VALID UNTIL", 25, "-", True) + " " + "IN USE")
                            # For each certificate found in the list, print the information
                            for key,value in getCertData["certs"].items():
                                id = structure_whitespace(str(key), 3, " ", False) + " "   # Set our cert ID to the key value
                                name = structure_whitespace(value["name"], 37, " ", False) + " "    # Set name to the name dict value
                                isr = structure_whitespace(value["issuer"], 11, " ", True) + " "    # Set name to the issuer dict value
                                cn = structure_whitespace(value["cn"], 25, " ", True) + " "    # Set name to the cn dict value
                                start = structure_whitespace(value["start"], 25, " ", True) + " "    # Set name to the start date dict value
                                exp = structure_whitespace(value["expire"], 25, " ", True) + " "    # Set name to the expiration date dict value
                                srl = structure_whitespace(value["serial"], 30, " ", True) + " "    # Set name to the start date dict value
                                iu = structure_whitespace("ACTIVE", 6, " ", False) if value["active"] else ""    # Set the inuse keyword if the cert is in use
                                # Check if verbose mode was selected
                                if verbosity == "-v" or verbosity == "--verbose":
                                    print(id + name + isr + cn + start + exp + srl + iu)
                                # If no specific mode was specified assume the default
                                else:
                                    print(id + name + isr + cn + exp + iu)
                    # Print error if no data was returned and exit with ec 1
                    else:
                        print(get_exit_message("read_err", "", pfsenseAction, "", ""))
                        sys.exit(1)
                # If we did receive an error, print our error message and exit on that exit code
                else:
                    print(get_exit_message(getCertData["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(getCertData["ec"])

            # Assign functions for flag --modify-alias
            elif pfsenseAction == "--set-wc-sslcert":
                certName = thirdArg
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                setWcResponse = set_wc_certificate(pfsenseServer, user, key, certName)    # Save the function output list for use later
                # Check for error codes and print confirmation accordingly
                # If success code is returned, print success message
                print(get_exit_message(setWcResponse, pfsenseServer, pfsenseAction, certName, ""))
                sys.exit(setWcResponse)
            # Assign functions for flag --add-vlan
            elif pfsenseAction == "--add-vlan":
                # Action Varibles
                interface = filter_input(thirdArg) if thirdArg is not None else input("Interface ID: ")    # Get our interface argument or prompt for input if missing
                vlanId = filter_input(fourthArg) if fourthArg is not None else input("VLAN ID [1-4094]: ")    # Get our vlan tag argument or prompt for input if missing
                priority = filter_input(fifthArg) if fifthArg is not None else input("VLAN priority [0-7]: ")    # Get our vlan priority argument or prompt for input if missing
                descr = sixthArg if sixthArg is not None else input("Description [optional]: ")    # Get our vlan description argument or prompt for input if missing
                user = eighthArg if seventhArg == "-u" and eighthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = tenthArg if ninthArg == "-p" and tenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                priority = "" if priority.upper() == "DEFAULT" else priority    # Assign a default priority if requested
                descr = "Auto-added by " + user + " on " + PfaVar.local_hostname if descr.upper() == "DEFAULT" else descr    # Assign a default description if requested
                # Try to convert number strings to integers for conditional checks
                try:
                    vlanIdInt = int(vlanId)
                except ValueError:
                    vlanIdInt = 0    # On error, assign an integer value that is out of range (1-4094)
                try:
                    priorityInt = int(priority)
                except ValueError:
                    priorityInt = 0    # On error, assign an integer value that is out of range (0-7)
                # Check our VLAN tag input
                if 1 <= vlanIdInt <= 4094:
                    # Check our VLAN priority input
                    if 0 <= priorityInt <= 7:
                        # Run our function to add VLAN
                        addVlanEc = add_vlan_id(pfsenseServer, user, key, interface, vlanId, priority, descr)
                        # Print our exit message
                        print(get_exit_message(addVlanEc, pfsenseServer, pfsenseAction, vlanId, interface))
                    # If our VLAN priority is out of range
                    else:
                        print(get_exit_message("invalid_priority", pfsenseServer, pfsenseAction, priority, ""))
                # If our VLAN tag is out range
                else:
                    print(get_exit_message("invalid_vlan", pfsenseServer, pfsenseAction, vlanId, ""))
                    sys.exit(1)    # Exit on non-zero

            # Assign functions for --run-shell-cmd
            elif pfsenseAction == "--run-shell-cmd":
                # Action variables
                shellCmd = thirdArg if len(sys.argv) > 3 else None    # Save our shell input if inline mode, otherwise indicate None for interactive shell
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                vShellTimeout = 180    # Set the amount of time before our virtual shell session times out
                # INTERACTIVE MODE/VIRTUAL SHELL
                if shellCmd is None or shellCmd.lower() == "virtualshell":
                    if check_auth(pfsenseServer, user, key):
                        print("---Virtual shell established---")
                        # Loop input to simulate an interactive shell
                        while True:
                            startTime = time.time()    # Track the time when the loop starts
                            cmd = input(user + "@" + pfsenseServer + ":/usr/local/www $ ")    # Accept shell command inputs
                            endTime = time.time()    # Track the time after input was received
                            elapsedTime = endTime - startTime    # Determine the elapsed time
                            # Check if user typed "close" indicating they wish to end the virtual shell
                            if cmd.lower() in ["close","exit","quit"]:
                                print("---Virtual shell terminated---")
                                sys.exit(0)
                            # Check if our virtual session has timed out
                            elif elapsedTime > vShellTimeout or 0 > elapsedTime:
                                print("---Virtual shell timeout---")
                                sys.exit(0)
                            # If input is valid, submit the command to pfSense
                            else:
                                cmdExec = get_shell_output(pfsenseServer, user, key, cmd)    # Attempt to execute our command
                                # Check if our command executed successfully, if so print our response and decode HTML entities
                                if cmdExec["ec"] == 0:
                                    print(cmdExec["shell_output"])
                                # If our command was not successful, print error
                                else:
                                    print(get_exit_message(2, pfsenseServer, pfsenseAction, cmd, ""))
                    # If authentication failed, print error and exit on non-zero
                    else:
                        print(get_exit_message(3, pfsenseServer, pfsenseAction, "", ""))
                        sys.exit(3)
                # INLINE MODE/SINGLE CMD
                else:
                    cmdExec = get_shell_output(pfsenseServer, user, key, shellCmd)    # Run our command
                    # Check if our command ran successfully, if so print our output
                    if cmdExec["ec"] == 0:
                        print(cmdExec["shell_output"])
                        sys.exit(0)
                    # If our command did not run successfully, print our error and exit on non-zero
                    else:
                        print(get_exit_message(cmdExec["ec"], pfsenseServer, pfsenseAction, shellCmd, ""))
                        sys.exit(cmdExec["ec"])

            # Assign functions for flag --read-carp-status
            elif pfsenseAction == "--read-carp-status":
                # Action variables
                carpFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                carpStatus = get_status_carp(pfsenseServer, user, key)    # Pull our CARP status dictionary
                idHeader = structure_whitespace("ID",5,"-",True) + " "    # Format our ID header
                vipHeader = structure_whitespace("VIRTUAL IP",20,"-",True) + " "    # Format our virtual IP header
                statusHeader = structure_whitespace("STATUS",10,"-",True) + " "    # Format our status header
                ifaceHeader = structure_whitespace("INTERFACE",12,"-",True) + " "    # Format our interface header
                vhidHeader = structure_whitespace("VHID",12,"-",True) + " "    # Format our VHID header
                header = idHeader + vipHeader + ifaceHeader + vhidHeader + statusHeader    # Concentrate our header string
                # Check that we did not recieve an error pulling the CARP status
                if carpStatus["ec"] == 0:
                    # If user passes in nodes filter, print all pfsync node IDs
                    if carpFilter.lower() in ["--nodes","-n"]:
                        print("PFSYNC NODES")    # Print our pfsync nodes
                        print("------------")
                        # Loop through each value in our list
                        for node in carpStatus["carp"]["pfsync_nodes"]:
                            print(node)    # Print our node ID
                    # If user passes in filter general or all
                    elif carpFilter.lower() in ["--general","-g"]:
                        mmStatus = "enabled" if carpStatus["carp"]["maintenance_mode"] else "disabled"    # If maintenance mode is true, set string to "enabled" otherwise "disabled"
                        print(structure_whitespace("CARP STATUS",37,"-",True))    # Print CARP STATUS header
                        print(structure_whitespace("Status:",27," ",False) + carpStatus["carp"]["status"])    # Print our status
                        print(structure_whitespace("Maintenance Mode:",27," ",False) + mmStatus)    # Print our status
                    # If not either of these options, explore further filters
                    else:
                        # Loop through our CARP interfaces and parse their values, print as needed
                        counter = 0   # Create a loop counter
                        for id,data in carpStatus["carp"]["carp_interfaces"].items():
                            carpId = structure_whitespace(str(id),5," ",True) + " "    # Format our CARP ID
                            virtIp = structure_whitespace(data["cidr"],20," ", True) + " "   # Format our virtual IP data
                            status = structure_whitespace(data["status"],10," ",True) + " "    # Format our status data
                            iface = structure_whitespace(data["interface"],12," ",True) + " "    # Format our interface data
                            vhid = structure_whitespace(data["vhid"],12," ",True) + " "    # Format our vhid data
                            carpData = carpId + virtIp + iface + vhid + status   # Combine our strings into our dataset
                            # If user has select all filter
                            if carpFilter.lower() in ["--all","-a"]:
                                mmStatus = "enabled" if carpStatus["carp"]["maintenance_mode"] else "disabled"    # If maintenance mode is true, set string to "enabled" otherwise "disabled"
                                print(structure_whitespace("CARP STATUS",37,"-",True)) if counter == 0 else None    # Print CARP STATUS header
                                print(structure_whitespace("Status:",27," ",False) + carpStatus["carp"]["status"]) if counter == 0 else None    # Print our status
                                print(structure_whitespace("Maintenance Mode:",27," ",False) + mmStatus + "\n") if counter == 0 else None    # Print our status
                                print(header) if counter == 0 else None   # Print our header
                                print(carpData)    # Print our dataset
                            # If user has selected subnet filter
                            elif carpFilter.startswith(("--subnet=","-s=")):
                                subnetExp = carpFilter.replace("-s=","").replace("--subnet=","")    # Remove our filter identifier to capture our subnet expression
                                # Check if our subnet matches our expression
                                if data["cidr"].startswith(subnetExp) or subnetExp == "*":
                                    print(header) if counter == 0 else None  # Print our header
                                    print(carpData)    # Print our dataset
                            # If user has selected interface filter
                            elif carpFilter.startswith(("--iface=","-i=")):
                                ifaceExp = carpFilter.replace("-iface=","").replace("-i=","")    # Remove our filter identifier to capture our iface expression
                                # Check if our iface matches our expression
                                if data["interface"].lower() == ifaceExp.lower():
                                    print(header) if counter == 0 else None  # Print our header
                                    print(carpData)    # Print our dataset
                            # If user has selected vhidExp filter
                            elif carpFilter.startswith(("--vhid=","-v=")):
                                vhidExp = carpFilter.replace("--vhid=","").replace("-v=","")    # Remove our filter identifier to capture our vhidExp expression
                                # Check if our vhidExp matches our expression
                                if data["vhid"] == vhidExp:
                                    print(header) if counter == 0 else None  # Print our header
                                    print(carpData)    # Print our dataset
                            # If user wants to print the JSON output
                            elif carpFilter.lower() in ("--read-json", "-rj"):
                                print(json.dumps(carpStatus["carp"]))   # Print our JSON data
                                break
                            # If we want to export values as JSON
                            elif carpFilter.startswith(("--json=", "-j=")):
                                jsonPath = carpFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                                jsonName = "pf-readcarp-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                                # Check if JSON path exists
                                if os.path.exists(jsonPath):
                                    # Open an export file and save our data
                                    jsonExported = export_json(carpStatus["carp"], jsonPath, jsonName)
                                    # Check if the file now exists
                                    if jsonExported:
                                        print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                        break    # Break the loop as we only need to perfrom this function once
                                    else:
                                        print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                        sys.exit(1)
                                # Print error if path does not exist
                                else:
                                    print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # If none of these filters match, return error
                            else:
                                print(get_exit_message("invalid_filter",pfsenseServer,pfsenseAction,carpFilter,""))
                                sys.exit(1)
                            # Increase our counter
                            counter = counter + 1
                # If we did encounter an error pulling our carp status
                else:
                    print(get_exit_message(carpStatus["ec"],pfsenseServer,pfsenseAction,"",""))    # Print our error message
                    sys.exit(carpStatus["ec"])    # Exit on our non-zero code

            # Assign functions for flag --set-carp-maintenance
            elif pfsenseAction == "--set-carp-maintenance":
                # Action variables
                enableToggle = filter_input(thirdArg) if len(sys.argv) > 3 else input("CARP Maintenance Mode [enable,disable]: ")    # Gather our mode toggle from the user either inline or interactively
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                altToggleTense1 = "enabled" if enableToggle == "enable" else ""    # Create an alternate tense for enabled
                altToggleTense1 = "disabled" if enableToggle == "disable" else altToggleTense1    # Create an alternate tense for disabled
                altToggleTense2 = "enabling" if enableToggle == "enable" else ""    # Create an alternate tense for enabling
                altToggleTense2 = "disabling" if enableToggle == "disable" else altToggleTense2    # Create an alternate tense disabling
                # INPUT VALIDATION
                # Check that our toggle is valid
                if enableToggle.lower() in ["enable","disable"]:
                    enableToggle = True if enableToggle.lower() == 'enable' else False    # Switch our string keywords to booleans
                    # Run our function to POST maintenance mode setting
                    setCarpMode = set_carp_maintenance(pfsenseServer, user, key, enableToggle)    # Save our function exit code
                    print(get_exit_message(setCarpMode, pfsenseServer, pfsenseAction, altToggleTense1, altToggleTense2))    # Print our error message
                    sys.exit(setCarpMode)    # Exit on our function return code
                # If our enable toggle is invalid
                else:
                    print(get_exit_message("invalid_toggle", pfsenseServer, pfsenseAction, enableToggle,""))
                    sys.exit(1)

            # Assign functions for flag --read-available-pkgs
            elif pfsenseAction == "--read-available-pkgs":
                # Action variables
                pkgFilter = thirdArg   # Save our third argument as our read filter
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                availablePkgs = get_available_packages(pfsenseServer, user, key)    # Pull our pkg configuration
                idHead = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                pkgHead = structure_whitespace("PACKAGE", 25, "-", True) + " "    # Format our package header header value
                versionHead = structure_whitespace("VERSION", 15, "-", True) + " "    # Format our version header value
                statusHead = structure_whitespace("STATUS", 15, "-", True) + " "    # Format our version header value
                header = idHead + pkgHead + versionHead + statusHead    # Piece our header together
                # Check that we did not receive an error pulling our data
                if availablePkgs["ec"] == 0:
                    # Loop through each item in our dictionary
                    counter = 1    # Assign a loop counter
                    for key,value in availablePkgs["available_pkgs"].items():
                        # Format our data to line up with headers
                        id = structure_whitespace(str(counter), 5, " ", True) + " "    # Get our entry number
                        pkg = structure_whitespace(value["name"], 25, " ", True)  + " "   # Get our pkg name
                        version = structure_whitespace(value["version"], 15, " ", True) + " "    # Get our pkg version
                        installed = structure_whitespace("Installed" if value["installed"] else "Not installed", 15, " ", True) + " "    # Get our pkg version
                        data = id + pkg + version + installed
                        # Check user's filter input
                        if pkgFilter.lower() in ["-a", "--all"]:
                            print(header) if counter == 1 else None
                            print(data)
                        elif pkgFilter.lower().startswith(("--name=","-n=")):
                            pkgExp = pkgFilter.replace("--name=","").replace("-n=","")    # Remove our filter identifier to capture our interface expression
                            # Check if our expression matches any packages
                            print(header) if counter == 1 else None
                            if pkgExp in value["name"]:
                                print(data)
                        # If user wants to print the JSON output
                        elif pkgFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(availablePkgs["available_pkgs"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif pkgFilter.startswith(("--json=", "-j=")):
                            jsonPath = pkgFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readavailpkgs-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(availablePkgs["available_pkgs"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, pkgFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        # Increase our counter
                        counter = counter + 1
                # If we encountered an error pulling our pkg data
                else:
                    print(get_exit_message(availablePkgs["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(availablePkgs["ec"])

            # Assign functions for flag --read-installed-pkgs
            elif pfsenseAction == "--read-installed-pkgs":
                # Action variables
                pkgFilter = thirdArg    # Save our third argument as our read filter
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                installedPkgs = get_installed_packages(pfsenseServer, user, key)    # Pull our pkg configuration
                idHead = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                pkgHead = structure_whitespace("PACKAGE", 25, "-", True) + " "    # Format our package header header value
                versionHead = structure_whitespace("VERSION", 15, "-", True) + " "    # Format our version header value
                header = idHead + pkgHead + versionHead    # Piece our header together
                # Check that we did not receive an error pulling our data
                if installedPkgs["ec"] == 0:
                    # Loop through each item in our dictionary
                    counter = 1    # Assign a loop counter
                    for key,value in installedPkgs["installed_pkgs"].items():
                        # Format our data to line up with headers
                        id = structure_whitespace(str(counter), 5, " ", True) + " "    # Get our entry number
                        pkg = structure_whitespace(value["name"], 25, " ", True)  + " "   # Get our pkg name
                        version = structure_whitespace(value["version"], 15, " ", True) + " "    # Get our pkg version
                        data = id + pkg + version
                        # Check user's filter input
                        if pkgFilter.lower() in ["-a", "--all"]:
                            print(header) if counter == 1 else None
                            print(data)
                        elif pkgFilter.lower().startswith(("--name=","-n=")):
                            pkgExp = pkgFilter.replace("--name=","").replace("-n=","")    # Remove our filter identifier to capture our interface expression
                            # Check if our expression matches any packages
                            print(header) if counter == 1 else None
                            if pkgExp in value["name"]:
                                print(data)
                        # If user wants to print the JSON output
                        elif pkgFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(installedPkgs["installed_pkgs"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif pkgFilter.startswith(("--json=", "-j=")):
                            jsonPath = pkgFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readpkgs-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(installedPkgs["installed_pkgs"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, pkgFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        # Increase our counter
                        counter = counter + 1
                # If we encountered an error pulling our pkg data
                else:
                    print(get_exit_message(installedPkgs["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(installedPkgs["ec"])

            # Assign functions for flag --add-pkg
            elif pfsenseAction == "--add-pkg":
                # Action variables
                pkgToAdd = thirdArg if len(sys.argv) > 3 else input("Add package: ")    # Get our user input inline, if not prompt user for input
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Run our add pkg function, print our exit message and exit on code
                pkgAdded = add_package(pfsenseServer, user, key, pkgToAdd)
                print(get_exit_message(pkgAdded, pfsenseServer, pfsenseAction, pkgToAdd, ""))
                sys.exit(pkgAdded)

             # Assign functions for flag --del-pkg
            elif pfsenseAction == "--del-pkg":
                # Action variables
                pkgToDel = thirdArg if len(sys.argv) > 3 else input("Delete package: ")    # Get our user input inline, if not prompt user for input
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Run our add pkg function, print our exit message and exit on code
                pkgDeleted = del_package(pfsenseServer, user, key, pkgToDel)
                print(get_exit_message(pkgDeleted, pfsenseServer, pfsenseAction, pkgToDel, ""))
                sys.exit(pkgDeleted)

            # Assign functions for flag --read-arp
            elif pfsenseAction == "--read-arp":
                arpFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                arpTable = get_arp_table(pfsenseServer, user, key)
                idHead = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                interfaceHead = structure_whitespace("INTERFACE", 15, "-", True) + " "    # Format our interface header header value
                ipHead = structure_whitespace("IP", 15, "-", True) + " "    # Format our ip header value
                hostHead = structure_whitespace("HOSTNAME", 20, "-", True) + " "    # Format our host header value
                macAddrHead = structure_whitespace("MAC ADDR", 20, "-", True) + " "    # Format our mac address header value
                vendorHead = structure_whitespace("MAC VENDOR", 12, "-", True) + " "    # Format our mac vendor header value
                expireHead = structure_whitespace("EXPIRES", 12, "-", True) + " "    # Format our expiration header value
                linkHead = structure_whitespace("LINK", 8, "-", True) + " "    # Format our link type header value
                header = idHead + interfaceHead + ipHead + hostHead + macAddrHead + vendorHead + expireHead + linkHead   # Format our print header
                # Check that we did not receive an error pulling the data
                if arpTable["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 0    # Assign a loop counter
                    for key,value in arpTable["arp"].items():
                        id = structure_whitespace(str(key), 5, " ", True) + " "    # Get our entry number
                        interface = structure_whitespace(value["interface"], 15, " ", True)  + " "   # Get our interface ID
                        ip = structure_whitespace(value["ip"], 15, " ", True) + " "    # Get our IP
                        hostname = structure_whitespace(value["hostname"], 20, " ", True) + " "    # Get our hostnames
                        macAddr = structure_whitespace(value["mac_addr"], 20, " ", True) + " "    # Get our MAC address level
                        macVendor = structure_whitespace(value["mac_vendor"], 12, " ", True) + " "   # Get our MAC vendor
                        expires = structure_whitespace(value["expires"], 12, " ", True) + " "   # Get our expiration
                        link = structure_whitespace(value["type"], 8, " ", True) + " "   # Get our link
                        # If we want to return all values
                        if arpFilter.upper() in ["-A", "--ALL"]:
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # Check if user wants to filter by interface
                        elif arpFilter.startswith(("-i=", "--iface=")):
                            ifaceExp = arpFilter.replace("-i=","").replace("--iface=","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if value["interface"].startswith(ifaceExp):
                                print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # Check if user wants to filter by IP
                        elif arpFilter.startswith(("-p=","--ip=")):
                            ipExp = arpFilter.replace("-p=","").replace("--ip=","")    # Remove our filter identifier to capture our IP expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our IP expression
                            if value["ip"].startswith(ipExp):
                                print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # Check if user wants to filter by hostname
                        elif arpFilter.startswith(("-h=","--hostname=")):
                            hostnameExp = arpFilter.replace("-h=","").replace("--hostname=","")    # Remove our filter identifier to capture our hostname expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our hostname expression
                            if value["hostname"].startswith(hostnameExp):
                                print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # Check if user wants to filter by MAC
                        elif arpFilter.startswith(("-m=","--mac=")):
                            macExp = arpFilter.replace("-m=","").replace("--mac=","")    # Remove our filter identifier to capture our MAC expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our MAC expression
                            if value["mac_addr"].startswith(macExp):
                                print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # Check if user wants to filter by MAC vendor
                        elif arpFilter.startswith(("-v=","--vendor=")):
                            vendorExp = arpFilter.replace("-v=","").replace("--vendor=","")    # Remove our filter identifier to capture our MAC vendor expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our MAC vendor expression
                            if value["mac_vendor"].startswith(vendorExp):
                                print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # Check if user wants to filter by link type
                        elif arpFilter.startswith(("-l=","--link=")):
                            vendorExp = arpFilter.replace("-l=","").replace("--link","")    # Remove our filter identifier to capture our link type expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our link type expression
                            if value["type"].startswith(vendorExp):
                                print(id + interface + ip + hostname + macAddr + macVendor + expires + link)    # Print our data values
                        # If user wants to print the JSON output
                        elif arpFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(arpTable["arp"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif arpFilter.startswith(("--json=", "-j=")):
                            jsonPath = arpFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readarp-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(arpTable["arp"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, arpFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we received an error, print the error message and exit on non-zero ec
                else:
                    print(get_exit_message(arpTable["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(arpTable["ec"])

            # Assign functions/processes for --read-hasync
            elif pfsenseAction == "--read-hasync":
                # Action variables
                haFilter = thirdArg if len(sys.argv) > 3 else None   # Save our filter input
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                haSyncData = get_ha_sync(pfsenseServer, user, key)    # Pull our current HA Sync data dictionary
                syncAreas = ["synchronizeusers","synchronizeauthservers","synchronizecerts",
                    "synchronizerules", "synchronizeschedules","synchronizealiases","synchronizenat","synchronizeipsec","synchronizeopenvpn",
                    "synchronizedhcpd","synchronizewol","synchronizestaticroutes","synchronizelb","synchronizevirtualip","synchronizetrafficshaper",
                    "synchronizetrafficshaperlimiter", "synchronizednsforwarder", "synchronizecaptiveportal"]    # Define a list XMLRPC Sync areas
                # Check that we did not encounter an error pulling our HA Sync data
                if haSyncData["ec"] == 0:
                    # FORMAT OUR PRINT DATA
                    pfToggle = "enabled" if haSyncData["ha_sync"]["pfsyncenabled"] == "on" else "disabled"    # Change "yes" to enabled
                    pfsyncHead = structure_whitespace("--STATE SYNC SETTINGS (PFSYNC)",40,"-",True)    # Fromat our header
                    pfsyncEnable = structure_whitespace("Enabled:",30," ",True) + pfToggle    # Format our enable value
                    pfsyncIface = structure_whitespace("PFSYNC Interface:",30," ",True) + haSyncData["ha_sync"]["pfsyncinterface"]    # Format our interface
                    pfsyncPip = structure_whitespace("PFSYNC Peer IP:",30," ",True) + haSyncData["ha_sync"]["pfsyncpeerip"]    # Format our peer IP
                    pfsyncData = pfsyncHead + "\n" + pfsyncEnable + "\n" + pfsyncIface + "\n" + pfsyncPip    # Format our data points together
                    xmlrpcHeader = structure_whitespace("--CONFIGURATION SYNC SETTINGS (XMLRPC)", 40, "-", True)    # Fromat our XMLRPC header
                    xmlrpcIp = structure_whitespace("Sync to IP:",30," ",True) + haSyncData["ha_sync"]["synchronizetoip"]    # Format our XMLRPC sync IP
                    xmlrpcUser = structure_whitespace("Remote System Username:",30," ",True) + haSyncData["ha_sync"]["username"]    # Format our XMLRPC remote username
                    xmlrpcOptStr = ""
                    # For each SYNC option enabled, print
                    for so in syncAreas:
                        # Check if option is enabled
                        if haSyncData["ha_sync"][so] == "on":
                            xmlrpcOptStr = xmlrpcOptStr + "\n  - " + so.replace("synchronize","")
                    xmlrpcSyncOpt = structure_whitespace("Synced options:",30," ",True) + xmlrpcOptStr   # Format our SYNC options
                    xmlrpcData = xmlrpcHeader + "\n" + xmlrpcIp + "\n" + xmlrpcUser + "\n" + xmlrpcSyncOpt    # Format our XMLRPC data set
                    # Check if we need to print our PFSYNC data
                    if haFilter.lower() in ["--all","-a"]:
                        print(pfsyncData)    # Print our PFSYNC data
                        print(xmlrpcData)    # Print our XMLRPC data
                    elif haFilter.lower() in ["--pfsync","-p"]:
                        print(pfsyncData)    # Print our PFSYNC data
                    # Check if we need to print our XMLRPC data
                    elif haFilter.lower() in ["--xmlrpc","-x"]:
                        print(xmlrpcData)    # Print our XMLRPC data
                    # If user wants to print the JSON output
                    elif haFilter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(haSyncData["ha_sync"]))   # Print our JSON data
                    # If we want to export values as JSON
                    elif haFilter.startswith(("--json=", "-j=")):
                        jsonPath = haFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readhasync-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(jsonPath):
                            # Open an export file and save our data
                            jsonExported = export_json(haSyncData["ha_sync"], jsonPath, jsonName)
                            # Check if the file now exists
                            if jsonExported:
                                print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                            else:
                                print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                            sys.exit(1)
                    # If our filter did not match any expected filters, return error
                    else:
                        print(get_exit_message("invalid_filter",pfsenseServer,pfsenseAction,haFilter,""))
                        sys.exit(1)
                # If we encountered an error pulling our HA Sync data
                else:
                    print(get_exit_message(haSyncData["ec"],pfsenseServer,pfsenseAction,"",""))    # Print our error message
                    sys.exit(haSyncData["ec"])     # Exit on our non-zero function return code

            # Assign functions/processes for --setup-hasync
            elif pfsenseAction == "--setup-hasync":
                # Action variables
                availSyncOpts = {"synchronizeusers": "", "synchronizeauthservers": "", "synchronizecerts": "",
                                 "synchronizerules": "", "synchronizeschedules": "", "synchronizealiases": "",
                                 "synchronizenat": "", "synchronizeipsec": "", "synchronizeopenvpn": "",
                                 "synchronizedhcpd": "", "synchronizewol": "", "synchronizestaticroutes": "",
                                 "synchronizelb": "", "synchronizevirtualip": "", "synchronizetrafficshaper": "",
                                 "synchronizetrafficshaperlimiter": "", "synchronizednsforwarder": "",
                                 "synchronizecaptiveportal": ""}
                enablePfsync = filter_input(thirdArg) if len(sys.argv) > 3 else input("Enable PFSYNC [enable,disable,default]: ")    # Enable/disable pfsync input
                pfsyncIf = filter_input(fourthArg) if len(sys.argv) > 4 else input("PFSYNC interface: ")    # Assign our pfsync interface input
                pfsyncIp = filter_input(fifthArg) if len(sys.argv) > 5 else input("PFSYNC Peer IP: ")    # Assign our pfsync peer IP input
                pfsyncIp = "" if pfsyncIp.lower() == "none" else pfsyncIp    # Allow input none as blank string
                xmlsyncIp = filter_input(sixthArg) if len(sys.argv) > 6 else input("XMLRPC Peer IP: ")    # Assign our xmlrpc IP input
                xmlsyncIp = "" if xmlsyncIp.lower() == "none" else xmlsyncIp    # Asslow input none as blank string
                xmlsyncUname = seventhArg if len(sys.argv) > 7 else input("XMLRPC Peer Username: ")    # Assing our xmlrpc username input
                xmlsyncPass = eighthArg if len(sys.argv) > 8 else getpass.getpass("XMLRPC Peer Password: ")     # Asign our xmlrpc password input
                xmlSyncOptions = ninthArg + "," if len(sys.argv) > 9 else None     # Assign our xmlrpc sync options
                # If interactive mode was used before passing in sync options, loop through options and have user confirm sync options
                if xmlSyncOptions is None:
                    for key,value in availSyncOpts.items():
                        # Loop until we get our expected value
                        while True:
                            # Prompt user for input
                            userInput = input("Synchronize " + key.replace("synchronize","") + " [yes,no,default]: ").lower()
                            # Check that our users input was valid
                            if userInput in ["yes","no","default",""]:
                                userInput = "on" if userInput == "yes" else userInput  # Assume default if empty input
                                userInput = "default" if userInput == "" else userInput    # Assume default if empty input
                                userInput = "" if userInput == "no" else userInput    # Change "no" to blank string, this is how the POST request is formatted
                                availSyncOpts[key] = userInput    # Assign the new value to our sync options dictionary
                                break    # Break our while loop to move to the next for loop item
                            # Print error if invalid input
                            else:
                                print("Unknown input `" + userInput + "`. Expected `yes`,`no,`default` or blank entry")
                user = eleventhArg if tenthArg == "-u" and eleventhArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = thirteenthArg if twelfthArg == "-p" and thirteenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check if our enable pfsync argument is valid
                if enablePfsync in ["enable","disable","yes","no","default"]:
                    enablePfsync = "on" if enablePfsync in ["enable","yes"] else enablePfsync
                    enablePfsync = "" if enablePfsync in ["disable","no"] else enablePfsync
                    # Check if our interface value is valid
                    ifPfId = find_interface_pfid(pfsenseServer,user,key,pfsyncIf,None)    # Try to find our pf_id value for this interface
                    # Check if we received an auth error trying to find the pf_id
                    if ifPfId["ec"] == 0:
                        if ifPfId["pf_id"] != "":
                            # Check if our pfsync IP is valid
                            if validate_ip(pfsyncIp) or pfsyncIp == "":
                                # Check if our xmlrpc IP is valid
                                if validate_ip(xmlsyncIp) or xmlsyncIp == "":
                                    # Check if our username is valid
                                    if len(xmlsyncUname) >= 1:
                                        # Check if our xmlrpc passwd is valid
                                        if len(xmlsyncPass) >= 1:
                                            # If inline mode was used to pass in sync options, parse them into our dictionary
                                            if xmlSyncOptions is not None:
                                                userOptions = xmlSyncOptions.split(",")
                                                # Loop through our available options and check for matches
                                                for key,value in availSyncOpts.items():
                                                    if key.replace("synchronize","") in userOptions or "all" in userOptions:
                                                        availSyncOpts[key] = "on"
                                            # Run our setup function, print our return message and exit on return code
                                            setupHaSyncEc = setup_hasync(pfsenseServer, user, key, enablePfsync, ifPfId["pf_id"], pfsyncIp, xmlsyncIp, xmlsyncUname, xmlsyncPass, availSyncOpts)
                                            print(get_exit_message(setupHaSyncEc,pfsenseServer,pfsenseAction,"",""))
                                            sys.exit(setupHaSyncEc)
                                        # If our XMLRPC passwd is invalid
                                        else:
                                            print(get_exit_message("invalid_passwd",pfsenseServer,pfsenseAction,xmlsyncPass,""))
                                            sys.exit(1)
                                    # If our XMLRPC username is invalid
                                    else:
                                        print(get_exit_message("invalid_user",pfsenseServer,pfsenseAction,xmlsyncUname,""))
                                        sys.exit(1)
                                # If our xmlrpc IP is invalid
                                else:
                                    print(get_exit_message("invalid_ip",pfsenseServer,pfsenseAction,"XMLRPC",pfsyncIp))
                                    sys.exit(1)
                            # If our pfsync IP is invalid
                            else:
                                print(get_exit_message("invalid_ip",pfsenseServer,pfsenseAction,"PFSYNC",pfsyncIp))
                                sys.exit(1)
                        # If our interfcae value is invalid
                        else:
                            print(get_exit_message("invalid_interface",pfsenseServer,pfsenseAction,pfsyncIf,""))
                            sys.exit(1)
                    # If we received an error trying to find our pf_id
                    else:
                        print(get_exit_message(ifPfId["ec"],pfsenseServer,pfsenseAction,"",""))
                        sys.exit(ifPfId["ec"])
                # If our enable pfsync argument is invalid
                else:
                    print(get_exit_message("invalid_enable",pfsenseServer,pfsenseAction,enablePfsync,""))    # Print error msg
                    sys.exit(1)

            # Assign functions/processes for --setup-ha-pfsense
            elif pfsenseAction == "--setup-hapfsense":
                # Action variables
                backupNode = filter_input(thirdArg) if len(sys.argv) > 3 else input("Backup node IP: ")    # Save user input for our backup node's IP address
                carpIfsRaw = fourthArg + "," if len(sys.argv) > 4 else None    # Save user input for carp interfaces if passed inline, otherwise indicate None for interactive mode
                carpIpsRaw = fifthArg + "," if len(sys.argv) > 5 else None    # Save user input for carp IPs if passed inline, otherwise indicate None for interactive mode
                # Format our CARP interfaces and IPs into lists
                carpIfs = list(filter(None, carpIfsRaw.split(","))) if carpIfsRaw is not None else []
                carpIps = list(filter(None, carpIpsRaw.split(","))) if carpIpsRaw is not None else []
                # Get our CARP interfaces if interactive mode
                if carpIfsRaw is None:
                    while True:
                        ifInput = input("Enter interface to include in HA [blank entry if done]: ").replace(" ","")
                        # Check if input is empty, break if so
                        if ifInput == "":
                            break
                        # Add our input to our interface list otherwise
                        else:
                            carpIfs.append(ifInput)
                # Get our CARP interfaces if interactive mode
                if carpIpsRaw is None:
                    for i in carpIfs:
                        while True:
                            ipInput = input("Enter available IP address on `" + i + "`: ")    # Prompt user to input IP
                            # Check that the IP is valid
                            if validate_ip(ipInput):
                                carpIps.append(ipInput)    # Append the IP to our list
                                break    # Break our loop to move to the next item
                            else:
                                print("Invalid IP `" + ipInput + "`")
                carpPasswd = sixthArg if len(sys.argv) > 6 else getpass.getpass("CARP password: ")    # Save our user input for CARP password or prompt user for input
                pfsyncIf = seventhArg if len(sys.argv) > 7 else input("PFSYNC interface: ")    # Save our PFSYNC interface input or prompt user for input if missing
                pfsyncIp = eighthArg if len(sys.argv) > 8 else input("PFSYNC Peer IP: ")    # Save our PFSYNC IP input or prompt user for input if missing
                user = tenthArg if ninthArg == "-u" and tenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = twelfthArg if eleventhArg == "-p" and twelfthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check if our backup node is valid and reachable
                if check_remote_port(backupNode, PfaVar.wc_protocol_port):
                    # Check that our HA synced interfaces exist on both MASTER and BACKUP
                    finalCarpIfs = []    # Initialize our final interface list containing the pf ID values
                    for c in carpIfs:
                        pfId = find_interface_pfid(pfsenseServer, user, key, c, None)    # Find our pfID for this interface on MASTER
                        pfIdBackup = find_interface_pfid(backupNode, user, key, c, None)    # Find our pfID for this interface on BACKUP
                        # Check if our interface exists on MASTER
                        if pfId["pf_id"] != "" and pfId["pf_id"] == pfIdBackup["pf_id"]:
                            # Check if our interface exists on BACKUP
                            if pfIdBackup["pf_id"] != "" and pfId["pf_id"] == pfIdBackup["pf_id"]:
                                finalCarpIfs.append(pfId["pf_id"])    # Add our PFID to the list
                            else:
                                print(get_exit_message("invalid_backup_if", pfsenseServer, pfsenseAction, i, backupNode))
                                sys.exit(1)
                        else:
                            print(get_exit_message("invalid_master_if",pfsenseServer,pfsenseAction,i,""))
                            sys.exit(1)
                    # Check that each of our IPs are valid
                    for ip in carpIps:
                        # Print error message and exit on non zero if invalid IP
                        if not validate_ip(ip):
                            print(get_exit_message("invalid_carp_ip",pfsenseServer,pfsenseAction,ip,""))
                            sys.exit(1)
                    # Check that our PFSYNC interface exists
                    checkPfsyncIf = find_interface_pfid(pfsenseServer, user, key, pfsyncIf, None)
                    if checkPfsyncIf["pf_id"] != "":
                        pfsyncIf = checkPfsyncIf["pf_id"]
                        # Check if our PFSYNC IP is valid
                        if validate_ip(pfsyncIp):
                            # Run our setup function, display our return message and exit on return code
                            setupHaPfsense = setup_hapfsense(pfsenseServer, user, key, backupNode, finalCarpIfs, carpIps, carpPasswd, pfsyncIf, pfsyncIp)
                            print(get_exit_message(setupHaPfsense, pfsenseServer, pfsenseAction, "", ""))
                            sys.exit(setupHaPfsense)
                        # If our PFSYNC IP is invalid, print error message and exit on non zero
                        else:
                            print(get_exit_message("invalid_pfsync_ip",pfsenseServer,pfsenseAction,pfsyncIp,""))
                            sys.exit(1)
                    # If our PFSYNC interface does not exist
                    else:
                        print(get_exit_message("invalid_pfsync_if",pfsenseServer,pfsenseAction,pfsyncIf,""))
                        sys.exit(1)
                # If we could not communicate with our backup node, print error and exit on non-zero
                else:
                    print(get_exit_message("invalid_backup_ip",pfsenseServer,pfsenseAction,backupNode,""))
                    sys.exit(1)

            # Assign functions/processes for --read-xml
            elif pfsenseAction == "--read-xml":
                # Action variables
                xmlFilter = thirdArg if len(sys.argv) > 3 else "read"   # Save our filter to a variable (this sets function to read or save)
                xmlArea = filter_input(fourthArg) if len(sys.argv) > 4 else input("XML Backup Area: ")    # Save our XML backup area
                xmlAreaPost = "" if xmlArea.lower() == "all" else xmlArea    # Change our CLI area for all into the POST data value (blank string)
                xmlAreaList = ["","aliases","unbound","filter","interfaces","installedpackages","rrddata","cron","syslog","system","sysctl","snmpd","vlans"]    # Assign a list of supported XML areas
                xmlPkg = filter_input(fifthArg) if len(sys.argv) > 5 else input("Include package data in XML [yes, no]: ")   # Save our nopackage toggle (includes or excludes pkg data from backup)
                xmlRrd = filter_input(sixthArg) if len(sys.argv) > 6 else input("Include RRD data in XML [yes, no]: ")    # Save our norrddata toggle (includes or excludes rrd data from backup)
                xmlEncrypt = filter_input(seventhArg) if len(sys.argv) > 6 else input("Encrypt XML [yes, no]: ")   # Save our encrypt toggle (enables or disables xml encryption)
                # Determine how to handle encryption passwords
                if len(sys.argv) > 8:
                    xmlEncryptPass = eighthArg     # Set an encryption password if encryption is enabled
                elif xmlEncrypt in ["encrypt", "yes"]:
                    xmlEncryptPass = getpass.getpass("Encryption password: ")
                else:
                    xmlEncryptPass = ""
                user = tenthArg if ninthArg == "-u" and tenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = twelfthArg if eleventhArg == "-p" and twelfthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our XML area is valid
                if xmlAreaPost.lower() in xmlAreaList:
                    # Check if user wants to skip package data in the backups
                    if xmlPkg in ["skip","exclude","no"]:
                        xmlPkgPost = True
                    elif xmlPkg in ["include","yes"]:
                        xmlPkgPost = False
                    else:
                        print(get_exit_message("invalid_pkg", pfsenseServer, pfsenseAction, xmlRrd, ""))
                        sys.exit(1)
                    # Check that our RRD value is valid
                    if xmlRrd in ["skip","exclude","no"]:
                        xmlRrdPost = True
                    elif xmlRrd in ["include","yes"]:
                        xmlRrdPost = False
                    else:
                        print(get_exit_message("invalid_rrd", pfsenseServer, pfsenseAction, xmlRrd, ""))
                        sys.exit(1)
                    # Check if user wants to encrypt the XML
                    if xmlEncrypt in ["encrypt", "yes"]:
                        xmlEncryptPost = True
                    elif xmlEncrypt in ["default", "no", "noencrypt"]:
                        xmlEncryptPost = False
                    else:
                        print(get_exit_message("invalid_encrypt", pfsenseServer, pfsenseAction, xmlEncrypt, ""))
                        sys.exit(1)
                    # Run our function
                    getXmlData = get_xml_backup(pfsenseServer, user, key, xmlAreaPost, xmlPkgPost, xmlRrdPost, xmlEncryptPost, xmlEncryptPass)
                    # Check our exit code
                    if getXmlData["ec"] == 0:
                        # Check how the user wants to display the data
                        if xmlFilter.lower() in ["--read", "-r", "read"]:
                            print(getXmlData["xml"])
                            sys.exit(0)
                        # If user wants to export the XML data to a file
                        elif xmlFilter.startswith(("--export=","-e=")):
                            exportPath = xmlFilter.replace("-e=", "").replace("--export=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            exportName = "pf-xml-" + xmlArea + "-" + pfsenseServer + "-" + PfaVar.current_date + ".xml"    # Assign our default XML name
                            # Check if our directory exists
                            if os.path.exists(exportPath):
                                # Open our file for writing
                                with open(exportPath + exportName, "w") as xwr:
                                    xwr.write(getXmlData["xml"])    # Write our XML data to a file
                                # Check if our file exists, if so print success message and exit on zero
                                if os.path.exists(exportPath + exportName):
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, exportPath + exportName, ""))
                                    sys.exit(0)
                                # If our file does not exit, print error and exit on non-zero
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, "", ""))
                                    sys.exit(1)
                        # If our filter is invalid
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, xmlFilter, ""))
                            sys.exit(1)
                    # If non-zero exit code, exit script on non-zero with error msg
                    else:
                        print(get_exit_message(getXmlData["ec"], pfsenseServer, pfsenseAction, "", ""))
                        sys.exit(getXmlData["ec"])
                # If XML area is invalid
                else:
                    print(get_exit_message("invalid_area", pfsenseServer, pfsenseAction, xmlArea, ""))
                    sys.exit(1)

            # Assign functions/processes for --upload-xml
            elif pfsenseAction == "--upload-xml":
                # Action variables
                restoreAreas = ["", "aliases", "captiveportal", "voucher", "dnsmasq", "unbound", "dhcpd", "dhcpdv6",
                                "filter", "interfaces", "ipsec", "nat", "openvpn", "installedpackages", "rrddata",
                                "cron", "syslog", "system", "staticroutes", "sysctl", "snmpd", "shaper", "vlans", "wol"]    # Assign a list of supported restore areas
                restoreAreaRaw = filter_input(thirdArg) if len(sys.argv) > 3 else input("Restore area: ")    # Get our restore area input from user either in line or prompt
                confFilePath = fourthArg if len(sys.argv) > 4 else input("XML file: ")    # Get our XML file path from user either in line or prompt
                decryptPassRaw = fifthArg if len(sys.argv) > 5 else getpass.getpass("Decryption password: ")    # Get our decryption password in line or prompt
                user = seventhArg if sixthArg == "-u" and seventhArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = ninthArg if eighthArg == "-p" and ninthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                restoreArea = "" if restoreAreaRaw.lower() in ["all", "default", "any"] else restoreAreaRaw    # Format our restore area to match expect POST values
                decryptPass = "" if decryptPassRaw.lower() in ["none", "default"] else decryptPassRaw    # Format our decryption password to revert to blank on expected keywords
                # Check that our restore area is valid
                if restoreArea in restoreAreas:
                    # Check that our XML file exists
                    if os.path.exists(confFilePath):
                        xmlFileObj = {"conffile" : open(confFilePath, "rb")}    # Open our file and embed our file object in a dict to POST to pfSense
                        # Validation has passed at this point, run our post command
                        uploadXml = upload_xml_backup(pfsenseServer, user, key, restoreArea, xmlFileObj, decryptPass)    # Run function and save exit code
                        # Print our exit message and exit on exit code
                        print(get_exit_message(uploadXml, pfsenseServer, pfsenseAction, restoreArea, ""))
                        sys.exit(uploadXml)
                    # If our XML file does not exist
                    else:
                        print(get_exit_message("invalid_filepath", pfsenseServer, pfsenseAction, confFilePath, ""))
                        sys.exit(1)
                # If user passed in an unexpected restore area
                else:
                    print(get_exit_message("invalid_area", pfsenseServer, pfsenseAction, restoreAreaRaw, ""))
                    sys.exit(1)

            # Assign functions/processes for --replicate-xml
            elif pfsenseAction == "--replicate-xml":
                # Action variables
                xmlAreaList = ["", "aliases", "captiveportal", "voucher", "dnsmasq", "unbound", "dhcpd", "dhcpdv6",
                                "filter", "interfaces", "ipsec", "nat", "openvpn", "installedpackages", "rrddata",
                                "cron", "syslog", "system", "staticroutes", "sysctl", "snmpd", "shaper", "vlans", "wol"]    # Assign a list of supported restore areas
                maxTargets = 100    # Only allow a specied number of replication targets
                replicationArea = filter_input(thirdArg) if len(sys.argv) > 3 else input("XML area: ")    # Assign user input for XML area to be replicated
                replicationTargets = "," + fourthArg if len(sys.argv) > 4 else ","   # Assign user input for hosts to apply configuration to (comma seperated)
                # If user requested interactive mode
                if replicationTargets == ",":
                    # Create a loop prompting user to add hosts to replicate XML to
                    counter = 1    # Create a counter to track loop iteration
                    while True:
                        inputMsg = "Replication target " + str(counter) + ": " if counter == 1 else "Replication target " + str(counter) + " [leave blank if done]: "    # Conditionally format input prompt
                        hostInput = input(inputMsg)    # Prompt user for host input
                        # Check that user wants to stop inputting
                        if hostInput == "":
                            replicationTargets.rstrip(",")    # Remove last comma to prevent orphan list item later
                            break    # Break loop
                        # Check if we have maxed out the number of replication targets
                        elif counter > maxTargets:
                            replicationTargets = replicationTargets + hostInput    # Add the entry as the final entry
                            break    # Break loop
                        # Assume user wants to continue adding hosts
                        else:
                            replicationTargets = replicationTargets + hostInput + ","    # Populate our replication string
                            counter = counter + 1    # Increase our counter
                # Get our username and password. This must match ALL systems (master and targets)
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                if replicationArea in xmlAreaList:
                    if "," in replicationTargets:
                        targetList = replicationTargets.replace(" ", "").split(",")    # Save our target list
                        # Loop through targets and remove blank values
                        counter = 0    # Create a counter to track loop iteration
                        for tg in targetList:
                            # Remove item if it is blank
                            if tg == "":
                                del targetList[counter]
                            # Increase our counter
                            counter = counter + 1
                        # Run our replication function and print results
                        replicationEc = replicate_xml(pfsenseServer, user, key, replicationArea, targetList)
                        # Check if our function succeeded
                        if replicationEc["ec"] == 0:
                            # Define a dictionary with predefined result values
                            statusDict = {
                                0: {"status": "SUCCESS", "reason": "Replicated `" + replicationArea + "` from " + pfsenseServer},
                                2: {"status": "FAILED", "reason": "Replication unexpectedly failed"},
                                3: {"status": "FAILED", "reason": "Authentication failure"},
                                6: {"status": "FAILED", "reason": "Non-pfSense platform identified"},
                                10: {"status": "FAILED", "reason": "DNS rebind detected"},
                                15: {"status": "FAILED", "reason": "Permission denied"},
                            }
                            hostHeader = structure_whitespace("HOST", 30, "-", True) + " "   # Format our HOST header
                            statusHeader = structure_whitespace("STATUS", 8, "-", True) + " "   # Format our STATUS header
                            infoHeader = structure_whitespace("INFO", 60, "-", True) + " "   # Format our INFO header
                            print(hostHeader + statusHeader + infoHeader)    # Format our header
                            # Loop through our target result and print them
                            for lists,item in replicationEc["targets"].items():
                                hostData = structure_whitespace(item["host"], 30, " ", True) + " "    # Format our HOST data
                                statusData = structure_whitespace(statusDict[item["ec"]]["status"], 8, " ", True) + " "    # Format our STATUS data
                                infoData = structure_whitespace(statusDict[item["ec"]]["reason"], 60, " ", True) + " "    # Format our INFO data
                                print(hostData + statusData + infoData)    # Print our data
                            # Exit on zero (success)
                            sys.exit(replicationEc["ec"])
                        # If we could not pull the master configuration
                        else:
                            print(get_exit_message(replicationEc["ec"], pfsenseServer, pfsenseAction, "", ""))
                            sys.exit(replicationEc["ec"])
                    # If our replication target seperator is not found, print error message and exit on non-zero code
                    else:
                        print(get_exit_message("invalid_targets", pfsenseServer, pfsenseAction, replicationTargets, ""))
                        sys.exit(1)
                # If our requested area does not exist, print error message and exit on non-zero code
                else:
                    print(get_exit_message("invalid_area", pfsenseServer, pfsenseAction, replicationArea, ""))
                    sys.exit(1)

            # Assign functions/processes for --read-interfaces
            elif pfsenseAction == "--read-interfaces":
                # Action variables
                ifaceFilter = thirdArg if len(sys.argv) > 3 else "--all"   # Assign a filter argument that we can use to change the returned output
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                supportedFilters = ("--all", "-a", "-d", "default", "-i=","--iface=","-v=","--vlan=","-n=", "--name=", "-c=", "--cidr=", "-j", "--json", "-rj", "--read-json")    # Tuple of support filter arguments
                # Check if our filter input is all or default
                if ifaceFilter.lower() in supportedFilters or ifaceFilter.startswith(supportedFilters):
                    ifaceData = get_interfaces(pfsenseServer, user, key)  # Get our data dictionary
                    # Check that we did not encounter an error
                    if ifaceData["ec"] == 0:
                        # If we want to export values as JSON
                        if ifaceFilter.startswith(("--json=", "-j=")):
                            jsonPath = ifaceFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readifaces-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(ifaceData["ifaces"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If user wants to print the JSON output
                        elif ifaceFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(ifaceData["ifaces"]))   # Print our JSON data
                        # If user is not requesting JSON, print normally
                        else:
                            # Format our header values
                            headerName = structure_whitespace("NAME", 30, "-", True) + " "    # NAME header
                            headerIface = structure_whitespace("INTERFACE", 18, "-", True) + " "    # INTERFACE header
                            headerId = structure_whitespace("ID", 8, "-", True) + " "    # ID header
                            headerType = structure_whitespace("TYPE", 10, "-", True) + " "    # TYPE header
                            headerCidr = structure_whitespace("CIDR", 20, "-", True) + " "    # CIDR header
                            headerEnabled = structure_whitespace("ENABLED", 8, "-", True)    # ENABLED header
                            header = headerName + headerIface + headerId + headerType + headerCidr + headerEnabled    # Piece our header together
                            # Loop through our dictionary and print our values
                            dataTable = header    # Assign a dataTable our loop will populate with data before printing
                            for pfId,data in ifaceData["ifaces"].items():
                                # Format and print our values
                                name = structure_whitespace(data["descr"], 30, " ", True) + " "    # Format our name value
                                iface = structure_whitespace(data["id"], 18, " ", True) + " "    # Format our iface value
                                id = structure_whitespace(data["pf_id"], 8, " ", True) + " "    # Format our pf_id value
                                type = structure_whitespace(data["type"], 10, " ", True) + " "    # Format our IP type
                                # Check that our type should include a CIDR (static)
                                if data["type"] == "staticv4":
                                    cidr = structure_whitespace(data["ipaddr"] + "/" + data["subnet"], 20, " ", True) + " "    # Format our CIDR
                                # Otherwise keep empty
                                else:
                                    cidr = structure_whitespace("", 20, " ", True) + " "    # Format our CIDR as empty
                                # Check if our interface is enabled
                                if data["enable"]:
                                    enabled = structure_whitespace("yes", 8, " ", True)    # Format our enabled value
                                else:
                                    enabled = structure_whitespace("no", 8, " ", True)    # Format our enabled value
                                # Add only data that matches iface input from user
                                if ifaceFilter.startswith(("-i=","--iface=")):
                                    ifaceInput = ifaceFilter.split("=")[1]    # Save our user input from the filter
                                    # If the current interface matches
                                    if data["id"].startswith(ifaceInput):
                                        dataTable = dataTable + "\n" + name + iface + id + type + cidr + enabled
                                # Add only data that matches vlan input from user
                                elif ifaceFilter.startswith(("-v=","--vlan=")):
                                    vlanInput = ifaceFilter.split("=")[1]    # Save our user input from the filter
                                    # If the current VLAN matches
                                    if data["id"].endswith("." + vlanInput):
                                        dataTable = dataTable + "\n" + name + iface + id + type + cidr + enabled
                                # Add only data that contains name string input from user
                                elif ifaceFilter.startswith(("-n=","--name=")):
                                    nameInput = ifaceFilter.split("=")[1]    # Save our user input from the filter
                                    # If the current NAME matches
                                    if nameInput in data["descr"]:
                                        dataTable = dataTable + "\n" + name + iface + id + type + cidr + enabled
                                # Add only data that starts with a specified IP or CIDR
                                elif ifaceFilter.startswith(("-c=","--cidr=")):
                                    cidrInput = ifaceFilter.split("=")[1]    # Save our user input from the filter
                                    # If the current CIDR matches
                                    checkCidr = data["ipaddr"] + "/" + data["subnet"]
                                    if checkCidr.startswith(cidrInput) and checkCidr != "/":
                                        dataTable = dataTable + "\n" + name + iface + id + type + cidr + enabled
                                # Otherwise, write all data
                                else:
                                    dataTable = dataTable + "\n" + name + iface + id + type + cidr + enabled
                            print(dataTable)    # Print our data table
                    # If we did receive a 0 exit code
                    else:
                        print(get_exit_message(ifaceData["ec"], pfsenseServer, pfsenseAction, ifaceFilter,""))    # Print error msg
                        sys.exit(ifaceData["ec"])    # Exit on our function exit code
                # If user passed in unknown filter
                else:
                    print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, ifaceFilter, ""))
                    sys.exit(1)

            # Assign functions and processes for --read-available-interfaces
            elif pfsenseAction == "--read-available-interfaces":
                # Action variables
                user = fourthArg if thirdArg == "-u" and fourthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixthArg if fifthArg == "-p" and sixthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                availableIf = get_available_interfaces(pfsenseServer, user, key)    # Save our interface data
                # Check that we did not encounter errors pulling interface data
                if availableIf["ec"] == 0:
                    # Check that we have available interfaces
                    if len(availableIf["if_add"]) > 0:
                        print("--AVAILABLE INTERFACES-----")
                        # Loop through our available interfaces and print the data
                        for iface in availableIf["if_add"]:
                            print(iface)    # Print our interface ID
                        sys.exit(0)    # Exit on good terms
                    # If we did not have any available interfaces
                    else:
                        print(get_exit_message("no_if", pfsenseServer, pfsenseAction, "", ""))
                        sys.exit(0)    # Exit on good terms as this is not an error
                # If we encountered an error pulling our interface data
                else:
                    print(get_exit_message(availableIf["ec"], pfsenseServer, pfsenseAction, "", ""))    # Print error msg
                    sys.exit(availableIf["ec"])    # Exit on our function exit code

            # Assign functions for --add-tunable
            elif pfsenseAction == "--add-tunable":
                # Action Variables
                tunableName = thirdArg if thirdArg is not None else input("Tunable name: ")    # Assign our tunable name to the third argument passed in
                tunableDescr = fourthArg if fourthArg is not None else input("Description: ")    # Assign our tunable description to the fourth argument passed in
                tunableValue = fifthArg if fifthArg is not None else input("Value: ")   # Assign our tunable description to the fifth argument passed in
                user = seventhArg if sixthArg == "-u" and seventhArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = ninthArg if eighthArg == "-p" and ninthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                tunableDescr = "Auto-added by" + user + " on " + PfaVar.local_hostname if tunableDescr.upper() == "DEFAULT" else tunableDescr    # Assign default description value
                addTunableEc = add_system_tunable(pfsenseServer, user, key, tunableName, tunableDescr, tunableValue)    # Save the exit code of our POST function
                print(get_exit_message(addTunableEc, pfsenseServer, pfsenseAction, tunableName, ""))    # Print our exit message
                sys.exit(addTunableEc)    # Exit on our exit code

            # Assign functions for flag --read-arp
            elif pfsenseAction == "--read-tunables":
                tunableFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                tunables = get_system_tunables(pfsenseServer, user, key)
                numHead = structure_whitespace("#", 3, "-", True) + " "    # Format our number header value
                nameHead = structure_whitespace("NAME", 40, "-", True) + " "    # Format our name header value
                descrHead = structure_whitespace("DESCRIPTION", 30, "-", True) + " "    # Format our ip description value
                valueHead = structure_whitespace("VALUE", 15, "-", True) + " "    # Format our host value value
                idHead = structure_whitespace("ID", 40, "-", True) + " "    # Format our host value value
                header = numHead + nameHead + descrHead + valueHead + idHead  # Format our print header
                # Check that we did not receive an error pulling the data
                if tunables["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 1    # Assign a loop counter
                    for key,value in tunables["tunables"].items():
                        tunNumber = structure_whitespace(str(counter), 3, " ", True) + " "    # Get our entry number
                        tunName = structure_whitespace(value["name"], 40, " ", True)  + " "   # Get our tunable name
                        tunDescr = structure_whitespace(value["descr"], 30, " ", True) + " "    # Get our tunable description
                        tunValue = structure_whitespace(value["value"], 15, " ", True) + " "    # Get our value
                        tunId = structure_whitespace(value["id"], 40, " ", True) + " "    # Get our ID
                        # If we want to return all values
                        if tunableFilter.upper() in ["-A", "--ALL", "-D", "DEFAULT"]:
                            print(header) if counter == 1 else None  # Print our header if we are just starting loop
                            print(tunNumber + tunName + tunDescr + tunValue + tunId)    # Print our data values
                        # If user wants to print the JSON output
                        elif tunableFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(tunables["tunables"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif tunableFilter.startswith(("--json=", "-j=")):
                            jsonPath = tunableFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readtunables-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(tunables["tunables"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, tunableFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we received an error, print the error message and exit on non-zero ec
                else:
                    print(get_exit_message(tunables["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(tunables["ec"])
            # Functions and processes for flag --read-general-setup
            elif pfsenseAction == "--read-general-setup":
                generalFilter = thirdArg if thirdArg is not None else ""    # Assign our third argument as a filter value
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                generalSetupData = get_general_setup(pfsenseServer, user, key)  # Get our data dictionary
                # Check our data pull exit code
                if generalSetupData["ec"] == 0:
                    # Check which filter/argument was passed in
                    # If user wants to print SYSTEM settings, or everything
                    if generalFilter.upper() in ["-S", "--SYSTEM", "-A", "--ALL", "DEFAULT", "-D"]:
                        print(structure_whitespace("--SYSTEM", 50, "-", False))
                        print(structure_whitespace("Hostname: ", 25, " ", False) + generalSetupData["general"]["system"]["hostname"])
                        print(structure_whitespace("Domain: ", 25, " ", False) + generalSetupData["general"]["system"]["domain"])
                    # If user wants to print DNS settings, or everything
                    if generalFilter.upper() in ["-N", "--DNS", "-A", "--ALL", "DEFAULT", "-D"]:
                        print(structure_whitespace("--DNS CLIENT", 50, "-", False))
                        print(structure_whitespace("DNS Override: ", 25, " ", False) + str(generalSetupData["general"]["dns"]["dnsallowoverride"]))
                        print(structure_whitespace("No DNS Localhost: ", 25, " ", False) + str(generalSetupData["general"]["dns"]["dnslocalhost"]))
                        # Loop through our DNS servers and print configured info
                        for key,value in generalSetupData["general"]["dns"]["servers"].items():
                            ip = structure_whitespace(value["ip"] + " ", 15, " ", True)    # Format our IP
                            hostname = structure_whitespace("Host: " + value["hostname"] + " ", 25, " ", True)    # Format our hostname
                            gw = structure_whitespace("Gateway: " + value["gateway"], 18, " ", True)    # Format our Gateway
                            print(structure_whitespace("DNS" + value["id"] + ": ", 25, " ", False) + ip + hostname + gw)    # Print our DNS line
                    # If user wants to print LOCALIZATION settings, or everything
                    if generalFilter.upper() in ["-L", "--LOCALIZATION", "-A", "--ALL", "DEFAULT", "-D"]:
                        print(structure_whitespace("--LOCALIZATION", 50, "-", False))
                        print(structure_whitespace("Timezone: ", 25, " ", False) + str(generalSetupData["general"]["localization"]["timezone"]))
                        print(structure_whitespace("Language: ", 25, " ", False) + str(generalSetupData["general"]["localization"]["language"]))
                        # Loop through our timeservers and print their values
                        tsCounter = 0    # Assign a loop counter
                        tsList = generalSetupData["general"]["localization"]["timeservers"].split(" ")    # Split our timeservers into a list
                        for ts in tsList:
                            # Check that we have a value
                            if ts != "":
                                print(structure_whitespace("Timeserver" + str(tsCounter) + ": ", 25, " ", False) + ts)    # Print each of our configured timeservers
                                tsCounter = tsCounter + 1    # Increase our counter
                    # If user wants to print WEBCONFIGURED settings, or everything
                    if generalFilter.upper() in ["-WC", "--WEBCONFIGURATOR", "-A", "--ALL"]:
                        print(structure_whitespace("--WEBCONFIGURATOR", 50, "-", False))
                        print(structure_whitespace("Theme: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["webguicss"]))
                        print(structure_whitespace("Top Navigation: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["webguifixedmenu"]))
                        print(structure_whitespace("Host in Menu: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["webguihostnamemenu"]))
                        print(structure_whitespace("Dashboard Columns: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["dashboardcolumns"]))
                        print(structure_whitespace("Sort Interfaces: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["interfacessort"]))
                        print(structure_whitespace("Show Widgets: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["dashboardavailablewidgetspanel"]))
                        print(structure_whitespace("Show Log Filter: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["systemlogsfilterpanel"]))
                        print(structure_whitespace("Show Log Manager: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["systemlogsmanagelogpanel"]))
                        print(structure_whitespace("Show Monitoring: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["statusmonitoringsettingspanel"]))
                        print(structure_whitespace("Require State Filter: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["requirestatefilter"]))
                        print(structure_whitespace("Left Column Labels: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["webguileftcolumnhyper"]))
                        print(structure_whitespace("Disable Alias Popups: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["disablealiaspopupdetail"]))
                        print(structure_whitespace("Disable Dragging: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["roworderdragging"]))
                        print(structure_whitespace("Login Page Color: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["logincss"]))
                        print(structure_whitespace("Login hostname: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["loginshowhost"]))
                        print(structure_whitespace("Dashboard refresh: ", 25, " ", False) + str(generalSetupData["general"]["webconfigurator"]["dashboardperiod"]))
                    # If user wants to print the JSON output
                    if generalFilter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(generalSetupData["general"]))   # Print our JSON data
                    # If we want to export values as JSON
                    if generalFilter.startswith(("--json=", "-j=")):
                        jsonPath = generalFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readgeneral-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(jsonPath):
                            # Open an export file and save our data
                            jsonExported = export_json(generalSetupData["general"], jsonPath, jsonName)
                            # Check if the file now exists
                            if jsonExported:
                                print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                            else:
                                print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                            sys.exit(1)
                # If we received a non-zero exit code, print our exit message
                else:
                    print(get_exit_message(generalSetupData["ec"], pfsenseServer, pfsenseAction, generalFilter, ""))
                    sys.exit(generalSetupData["ec"])
            # Functions and processes for flag --set-system-hostname
            elif pfsenseAction == "--set-system-hostname":
                # Print warning prompt if user is using interactive mode
                if len(sys.argv) < 8:
                    print(get_exit_message("inter_warn", pfsenseServer, pfsenseAction, "", ""))
                # Local variables
                host = filter_input(thirdArg) if len(sys.argv) > 3 else input("Hostname: ")    # Pull our passed in hostname argument or prompt user to input if missing
                domain = filter_input(fourthArg) if len(sys.argv) > 4 else input("Domain: ")    # Pull our passed in domain argument or prompt user to input if missing
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                setSysHostEc = set_system_hostname(pfsenseServer, user, key, host, domain)    # Run our function that adds the hostname and save the exit code
                # Print our exit message and exit on our exit code
                print(get_exit_message(setSysHostEc, pfsenseServer, pfsenseAction, host, domain))
                sys.exit(setSysHostEc)
            # Functions and processes for flag --read-adv-admin
            elif pfsenseAction == "--read-adv-admin":
                advAdmFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                advAdmData = get_system_advanced_admin(pfsenseServer, user, key)    # Get our data dictionary
                # Check our data pull exit code
                if advAdmData["ec"] == 0:
                    # Check which filter/argument was passed in
                    # If user wants to print webconfigurator settings, or everything
                    if advAdmFilter.upper() in ["-WC", "--WEBCONFIGURATOR", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin WEBCONFIGURATOR
                        print(structure_whitespace("--WEBCONFIGURATOR", 50, "-", False))
                        print(structure_whitespace("Protocol: ", 30, " ", False) + advAdmData["adv_admin"]["webconfigurator"]["webguiproto"])
                        print(structure_whitespace("SSL Certificate: ", 30, " ", False) + advAdmData["adv_admin"]["webconfigurator"]["ssl-certref"])
                        print(structure_whitespace("TCP Port: ", 30, " ", False) + advAdmData["adv_admin"]["webconfigurator"]["webguiport"])
                        print(structure_whitespace("Max Processes: ", 30, " ", False) + advAdmData["adv_admin"]["webconfigurator"]["max_procs"])
                        print(structure_whitespace("WebUI Redirect: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["webgui-redirect"]))
                        print(structure_whitespace("HSTS: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["webgui-hsts"]))
                        print(structure_whitespace("OCSP Stapling: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["ocsp-staple"]))
                        print(structure_whitespace("Login Auto-complete: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["loginautocomplete"]))
                        print(structure_whitespace("Login Messages: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["webgui-login-messages"]))
                        print(structure_whitespace("Disable Anti-lockout: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["noantilockout"]))
                        print(structure_whitespace("Disable DNS Rebind Check: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["nodnsrebindcheck"]))
                        print(structure_whitespace("Alternate Hostnames: ", 30, " ", False) + advAdmData["adv_admin"]["webconfigurator"]["althostnames"])
                        print(structure_whitespace("Disable HTTP_REFERRER: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["nohttpreferercheck"]))
                        print(structure_whitespace("Browser Tab Text: ", 30, " ", False) + str(advAdmData["adv_admin"]["webconfigurator"]["pagenamefirst"]))
                    # If user wants to print SECURE SHELL settings, or everything
                    if advAdmFilter.upper() in ["-SSH", "--SECURE-SHELL", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin SECURE SHELL
                        print(structure_whitespace("--SECURE SHELL", 50, "-", False))
                        print(structure_whitespace("Enable SSH: ", 30, " ", False) + str(advAdmData["adv_admin"]["secure_shell"]["enablesshd"]))
                        print(structure_whitespace("Enable SSH-Agent Forwarding: ", 30, " ", False) + str(advAdmData["adv_admin"]["secure_shell"]["sshdagentforwarding"]))
                        print(structure_whitespace("SSH Port: ", 30, " ", False) + str(advAdmData["adv_admin"]["secure_shell"]["sshport"]))
                        print(structure_whitespace("SSH Authentication Type: ", 30, " ", False) + str(advAdmData["adv_admin"]["secure_shell"]["sshdkeyonly"]))
                    # If user wants to print LOGIN PROTECTION settings, or everything
                    if advAdmFilter.upper() in ["-LC", "--LOGIN-PROTECTION", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin LOGIN PROTECTION
                        print(structure_whitespace("--LOGIN PROTECTION", 50, "-", False))
                        print(structure_whitespace("Threat Threshold: ", 30, " ", False) + str(advAdmData["adv_admin"]["login_protection"]["sshguard_threshold"]))
                        print(structure_whitespace("Threat Blocktime: ", 30, " ", False) + str(advAdmData["adv_admin"]["login_protection"]["sshguard_blocktime"]))
                        print(structure_whitespace("Threat Detection Time: ", 30, " ", False) + str(advAdmData["adv_admin"]["login_protection"]["sshguard_detection_time"]))
                        print("Whitelist:")
                        # Loop through our whitelisted addresses
                        for key,value in advAdmData["adv_admin"]["login_protection"]["whitelist"].items():
                            # Check that we have a legitimate value
                            if value["value"] != "":
                                # Check if subnet was specified
                                addrStr = "  - " + value["value"]   # Assign our IP to our address string
                                if value["subnet"] != "":
                                    addrStr = addrStr + "/" + value["subnet"]    # Append our subnet to our address string
                                print(addrStr)    # Print our address string
                    # If user wants to print SERIAL COMMUNICATIONS settings, or everything
                    if advAdmFilter.upper() in ["-SC", "--SERIAL-COMMUNICATIONS", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin SERIAL COMMUNICATIONS
                        print(structure_whitespace("--SERIAL COMMUNICATIONS", 50, "-", False))
                        print(structure_whitespace("Enable Serial Communication: ", 30, " ", False) + str(advAdmData["adv_admin"]["serial_communcations"]["enableserial"]))
                        print(structure_whitespace("Serial Speed: ", 30, " ", False) + str(advAdmData["adv_admin"]["serial_communcations"]["serialspeed"]))
                        print(structure_whitespace("Console Type: ", 30, " ", False) + str(advAdmData["adv_admin"]["serial_communcations"]["primaryconsole"]))
                    # If user wants to print CONSOLE OPTIONS settings, or everything
                    if advAdmFilter.upper() in ["-CO", "--CONSOLE-OPTIONS", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin CONSOLE OPTIONS
                        print(structure_whitespace("--CONSOLE OPTIONS", 50, "-", False))
                        print(structure_whitespace("Password Protect Console: ", 30, " ", False) + str(advAdmData["adv_admin"]["console_options"]["disableconsolemenu"]))
                    # If user wants to print the JSON output
                    if advAdmFilter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(advAdmData["adv_admin"]))   # Print our JSON data
                    # If we want to export values as JSON
                    if advAdmFilter.startswith(("--json=", "-j=")):
                        jsonPath = advAdmFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readadvadm-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(jsonPath):
                            # Open an export file and save our data
                            jsonExported = export_json(advAdmData["adv_admin"], jsonPath, jsonName)
                            # Check if the file now exists
                            if jsonExported:
                                print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                            else:
                                print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                            sys.exit(1)
                # If we received a non-zero exit code, print our exit message
                else:
                    print(get_exit_message(advAdmData["ec"], pfsenseServer, pfsenseAction, advAdmFilter, ""))
                    sys.exit(advAdmData["ec"])
            # Functions and processes for flag --setup-wc
            elif pfsenseAction == "--setup-wc":
                # Action variables
                maxProc = filter_input(thirdArg) if len(sys.argv) > 3 else input("Max processes [1-1024, default]: ")    # Assign our max process option, prompt user for input if empty
                maxProc = "default" if maxProc == "" else maxProc    # Assume default if entry is blank
                maxProcInt = int(maxProc) if maxProc.isdigit() else 99999    # Convert the maxProc value to an integer if possible, otherwise assign an integer that is out of range
                uiRedirect = filter_input(fourthArg) if len(sys.argv) > 4 else input("HTTP redirect [enable, disable, default]: ")    # Assign our redirect option, prompt user for input if empty
                uiRedirect = "default" if uiRedirect == "" else uiRedirect    # Assume default if entry is blank
                hsts = filter_input(fifthArg) if len(sys.argv) > 5 else input("HTTP Strict Transport Security [enable, disable, default]: ")    # Assign our hsts option, prompt user for input if empty
                hsts = "default" if hsts == "" else hsts    # Assume default if entry is blank
                autoComplete = filter_input(sixthArg) if len(sys.argv) > 6 else input("Login auto-complete [enable, disable, default]: ")    # Assign our login autocompletion option, prompt user for input if empty
                autoComplete = "default" if autoComplete == "" else autoComplete    # Assume default if entry is blank
                authLog = filter_input(seventhArg) if len(sys.argv) > 7 else input("Authentication logging [enable, disable, default]: ")    # Assign our login logging option, prompt user for input if empty
                authLog = "default" if authLog == "" else authLog    # Assume default if entry is blank
                uiAntilock = filter_input(eighthArg) if len(sys.argv) > 8 else input("WebUI anti-lockout [enable, disable, default]: ")    # Assign our uiAntilock option, prompt user for input if empty
                uiAntilock = "default" if uiAntilock == "" else uiAntilock    # Assume default if entry is blank
                dnsRebind = filter_input(ninthArg) if len(sys.argv) > 9 else input("DNS Rebind checking [enable, disable, default]: ")    # Assign our dns rebind option, prompt user for input if empty
                dnsRebind = "default" if dnsRebind == "" else dnsRebind    # Assume default if entry is blank
                altHost = filter_input(tenthArg) if len(sys.argv) > 10 else input("Alternate hostnames (separate FQDNs by space): ")    # Assign our alt hostname option, prompt user for input if empty
                altHost = "default" if altHost == "" else altHost    # Assume default if entry is blank
                httpRef = filter_input(eleventhArg) if len(sys.argv) > 11 else input("HTTP_REFERER checking [enable, disable, default]: ")    # Assign our http_referer option, prompt user for input if empty
                httpRef = "default" if httpRef == "" else httpRef    # Assume default if entry is blank
                tabText = filter_input(twelfthArg) if len(sys.argv) > 12 else input("Display hostname in tab [enable, disable, default]: ")    # Assign our http_referer option, prompt user for input if empty
                tabText = "default" if tabText == "" else tabText    # Assume default if entry is blank
                user = fourteenthArg if thirteenthArg == "-u" and fourteenthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixteenthArg if fifteenthArg == "-p" and sixteenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our integer is in range
                if 1 <= maxProcInt <= 1024 or maxProc.lower() == "default":
                    # Check that our uiRedirect is valid
                    if uiRedirect.lower() in ["enable", "disable", "redirect", "no-redirect", "default"]:
                        # Check that our HSTS value is valid
                        if hsts.lower() in ["enable", "disable", "hsts", "no-hsts", "default"]:
                            # Check that our auto complete value is valid
                            if autoComplete.lower() in ["enable", "disable", "autocomplete", "no-autocomplete", "default"]:
                                # Check that our authLog value is valid
                                if authLog.lower() in ["enable", "disable", "loginmsg", "no-loginmsg", "default"]:
                                    # Check that our uiAntilock value is valid
                                    if uiAntilock.lower() in ["enable", "disable", "antilockout", "no-antilockout", "default"]:
                                        # Check that our dnsRebind value is valid
                                        if dnsRebind.lower() in ["enable", "disable", "dnsrebind", "no-dnsrebind", "default"]:
                                            # Check that our httpRef value is valid
                                            if httpRef.lower() in ["enable", "disable", "httpreferer", "no-httpreferer", "default"]:
                                                # Check that our tabText value is valid
                                                if tabText.lower() in ["enable", "disable", "display-tabtext", "hide-tabtext", "default"]:
                                                    # Run our function now that all input is validated
                                                    setupWcEc = setup_wc(pfsenseServer, user, key, maxProc, uiRedirect, hsts, autoComplete, authLog, uiAntilock, dnsRebind, altHost, httpRef, tabText)
                                                    # Print our exit message and exit script on returned exit code
                                                    print(get_exit_message(setupWcEc, pfsenseServer, pfsenseAction, "", ""))
                                                    sys.exit(setupWcEc)
                                                # If our tabText value is invalid
                                                else:
                                                    print(
                                                    "invalid_tabtext", pfsenseServer, pfsenseAction, tabText, "")
                                                    sys.exit(1)
                                            # If our httpRef value is invalid
                                            else:
                                                print("invalid_httpreferer", pfsenseServer, pfsenseAction, httpRef, "")
                                                sys.exit(1)
                                        # If our dnsRebind value is invalid
                                        else:
                                            print("invalid_dnsrebind", pfsenseServer, pfsenseAction, dnsRebind, "")
                                            sys.exit(1)
                                    # If our uiAntilock value is invalid
                                    else:
                                        print("invalid_lockout", pfsenseServer, pfsenseAction, uiAntilock, "")
                                        sys.exit(1)
                                # If our loginmsg value is invalid
                                else:
                                    print("invalid_loginmsg", pfsenseServer, pfsenseAction, authLog, "")
                                    sys.exit(1)
                            # If our autocomplete value is invalid
                            else:
                                print("invalid_autocomplete", pfsenseServer, pfsenseAction, autoComplete, "")
                                sys.exit(1)
                        # If our HSTS value is invalid
                        else:
                            print("invalid_hsts", pfsenseServer, pfsenseAction, hsts, "")
                            sys.exit(1)
                    # If our redirect value is invalid
                    else:
                        print("invalid_redirect", pfsenseServer, pfsenseAction, uiRedirect, "")
                        sys.exit(1)
                # If integer is out of range
                else:
                    print(get_exit_message("invalid_proc", pfsenseServer, pfsenseAction, maxProc, ""))
                    sys.exit(1)
            # Functions and process for flag --set-wc-port
            elif pfsenseAction == "--set-wc-port":
                # Action variables
                protocol = filter_input(thirdArg) if len(sys.argv) > 3 else input("HTTP Protocol [http, https, default]: ")    # Get our protocol from the user, either inline or interactively
                port = filter_input(fourthArg) if len(sys.argv) > 4 else input("TCP port [1-65535, default]: ")    # Get ou webconfigurator port either inline or interactively
                portInt = int(port) if port.isdigit() else 999999    # Convert our port to an integer if possible, otherwise assign a port value that is out of range
                user = sixthArg if fifthArg == "-u" and sixthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighthArg if seventhArg == "-p" and eighthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our protocol is valid
                if protocol.lower() in ["http", "https", "default"]:
                    # Check that our port is valid
                    if 1 <= portInt <= 65535 or port.upper() == "DEFAULT":
                        # Run our function
                        wcPortEc = set_wc_port(pfsenseServer, user ,key, protocol, port)
                        # Print our exit message and exit on code
                        print(get_exit_message(wcPortEc, pfsenseServer,pfsenseAction, protocol, port))
                        sys.exit(wcPortEc)
                    # If our port is out of range
                    else:
                        print(get_exit_message("invalid_port", pfsenseServer, pfsenseAction, port, ""))
                        sys.exit(1)
                # If our protocol is invalid
                else:
                    print(get_exit_message("invalid_protocol", pfsenseServer, pfsenseAction, protocol, ""))
                    sys.exit(1)
            # Functions and processes for flag --setup-ssh
            elif pfsenseAction == "--setup-ssh":
                # Action variables
                enableSsh = filter_input(thirdArg) if len(sys.argv) > 3 else input("Enable SSH [enable, disable, default]: ")    # Assign our enable option, prompt user for input if empty
                enableSsh = "default" if enableSsh == "" else enableSsh    # Assume default if entry is blank
                sshPort = filter_input(fourthArg) if len(sys.argv) > 4 else input("SSH Port [1-65535, default]: ")    # Assign our port option, prompt user for input if empty
                sshPort = "default" if sshPort == "" else sshPort    # Assume default if entry is blank
                sshAuth = filter_input(fifthArg) if len(sys.argv) > 5 else input("SSH Authentication method [passwd, key, both, default]: ")    # Assign our authentication option, prompt user for input if empty
                sshAuth = "default" if sshAuth == "" else sshAuth    # Assume default if entry is blank
                sshForward = filter_input(sixthArg) if len(sys.argv) > 6 else input("SSH-AGENT Forwarding [enable, disable, default]: ")    # Assign our ssh-agent forward option, prompt user for input if empty
                sshForward = "default" if sshForward == "" else sshForward    # Assume default if entry is blank
                user = eighthArg if seventhArg == "-u" and eighthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = tenthArg if ninthArg == "-p" and tenthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Check that we are actually trying to change a variable aka default isn't set for each input
                if all("DEFAULT" in x for x in [enableSsh.upper(),sshPort.upper(),sshAuth.upper(),sshForward.upper()]):
                    # If we requested all default values, print error as nothing will be changed
                    print(get_exit_message("no_change", pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(0)
                # If all values were not DEFAULT
                else:
                    # Check our enable SSH value
                    if enableSsh.lower() in ["enable", "disable", "default"]:
                        # Check if we are trying to change the SSH port
                        if sshPort.upper() != "DEFAULT":
                            # Try to convert our port to an integer and verify it is in range
                            try:
                                sshPortInt = int(sshPort)    # Convert our SSH port to an integer for checks
                            except ValueError:
                                sshPortInt = 99999999     # If we could not convert our port to an integer, assign integer that is out of port range
                            # Check if port is within range
                            if 1 > sshPortInt or 65535 < sshPortInt:
                                # If port is out of range print our exit message and exit on non-zero status
                                print(get_exit_message("invalid_port", pfsenseServer, pfsenseAction, sshPort, ""))
                                sys.exit(1)
                        # Check that we have chosen a valid SSH auth type
                        if sshAuth.lower() in ["keyonly", "key", "pass", "password", "passwd", "mfa", "both", "all", "default"]:
                            # Check if we have a valid sshForward value
                            if sshForward.lower() in ["enable", "disable", "enable-forwarding", "yes", "none", "default"]:
                                ecSetupSsh = setup_ssh(pfsenseServer, user, key, enableSsh, sshPort, sshAuth, sshForward)    # Execute our configuration function
                                # Print our exit message and exit on return code
                                print(get_exit_message(ecSetupSsh, pfsenseServer, pfsenseAction, sshAuth, ""))
                                sys.exit(ecSetupSsh)
                            # If our sshForward value is invalid
                            else:
                                print(get_exit_message("invalid_forward", pfsenseServer, pfsenseAction, sshForward, ""))
                                sys.exit(1)
                        # If our auth type is invalid
                        else:
                            print(get_exit_message("invalid_auth", pfsenseServer, pfsenseAction, sshAuth, ""))
                            sys.exit(1)
                    # If our enableSSH value is invalid, print error
                    else:
                        print(get_exit_message("invalid_enable", pfsenseServer, pfsenseAction, enableSsh, ""))
                        sys.exit(1)

            # Functions and processes for flag --setup-console
            elif pfsenseAction == "--setup-console":
                # Action variables
                consolePass = filter_input(thirdArg) if len(sys.argv) > 3 else input("Console password protection [enable,disable]: ")    # Capture our user input or prompt user for input if missing
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Check our input
                if consolePass.upper() in ["ENABLE","DISABLE"]:
                    ecSetupConsole = setup_console(pfsenseServer, user, key, consolePass)    # run our function and save return code
                    print(get_exit_message(ecSetupConsole, pfsenseServer, pfsenseAction, "", ""))    # Print our exit message
                    sys.exit(ecSetupConsole)    # Exit on our return code
                # If our inupt is invalid
                else:
                    print(get_exit_message("invalid_option", pfsenseServer, pfsenseAction, consolePass, ""))    # Print our error message
                    sys.exit(1)    # Exit on non-zero exit code

            # Functions and process for flag --read-vlans
            elif pfsenseAction == "--read-vlans":
                # Action Variables
                vlanFilter = thirdArg if thirdArg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                vlans = get_vlan_ids(pfsenseServer, user, key)
                idHead = structure_whitespace("#", 4, "-", True) + " "    # Format our ID header value
                interfaceHead = structure_whitespace("INTERFACE", 12, "-", True) + " "    # Format our interface header header value
                vlanHead = structure_whitespace("VLAN ID", 10, "-", True) + " "    # Format our VLAN ID header value
                priorityHead = structure_whitespace("PRIORITY", 10, "-", True) + " "    # Format our priority header value
                descrHead = structure_whitespace("DESCRIPTION", 30, "-", True) + " "    # Format our description header value
                header = idHead + interfaceHead + vlanHead + priorityHead + descrHead    # Format our print header
                # Check that we did not receive an error pulling the data
                if vlans["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 0    # Assign a loop counter
                    for key,value in vlans["vlans"].items():
                        id = structure_whitespace(str(key), 4, " ", True) + " "    # Get our entry number
                        interface = structure_whitespace(value["interface"], 12, " ", True)  + " "   # Get our interface ID
                        vlanId = structure_whitespace(value["vlan_id"], 10, " ", True) + " "    # Get our VLAN ID
                        priority = structure_whitespace(value["priority"], 10, " ", True) + " "    # Get our priority level
                        descr = structure_whitespace(value["descr"], 30, " ", True) + " "   # Get our description
                        # If we want to return all values
                        if vlanFilter.upper() in ["-A", "--ALL"]:
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            print(id + interface + vlanId + priority + descr)    # Print our data values
                        # If we only want to return value of one VLAN ID
                        elif vlanFilter.startswith(("--vlan=","-v=")):
                            vlanScope = vlanFilter.replace("--vlan=", "").replace("-v=", "")    # Remove expected argument values to determine our VLAN scope
                            # Check if we have found our expected VLAN
                            if vlanScope == value["vlan_id"]:
                                print(header)    # Print our header
                                print(id + interface + vlanId + priority + descr)    # Print our data values
                                break    # Break the loop as we only need this matched value
                        # If we only want to return value of one VLAN ID
                        elif vlanFilter.startswith(("--iface=","-i=")):
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            interfaceScope = vlanFilter.replace("--iface=", "").replace("-i=", "")    # Remove expected argument values to determine our VLAN scope
                            # Check if we have found our expected VLAN
                            if interfaceScope == value["interface"]:
                                print(id + interface + vlanId + priority + descr)    # Print our data values
                        # If user wants to print the JSON output
                        elif vlanFilter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(vlans["vlans"]))   # Print our JSON data
                            break    # Break our loop, we only want to print this once
                        # If we want to export values as JSON
                        elif vlanFilter.startswith(("--json=", "-j=")):
                            jsonPath = vlanFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readvlans-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(vlans["vlans"], jsonPath, jsonName)
                                # Check if the file now exists
                                if jsonExported:
                                    print(get_exit_message("export_success", pfsenseServer, pfsenseAction, jsonPath + jsonName, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsenseServer, pfsenseAction, jsonPath, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsenseServer, pfsenseAction, jsonPath, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsenseServer, pfsenseAction, vlanFilter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we received an error, print the error message and exit on non-zero ec
                else:
                    print(get_exit_message(vlans["ec"], pfsenseServer, pfsenseAction, "", ""))
                    sys.exit(vlans["ec"])
            # If an unexpected action was given, return error
            else:
                flagDescrs = ""    # Initialize our flag description help string
                flagDict = get_exit_message("",pfsenseServer,"all","","")    # Pull our descr dictionary
                # Loop through our flag descriptions and save them to a string
                for key,value in flagDict.items():
                    # Only perform this on dict keys with -- flags
                    if key.startswith("--"):
                        flagDescrs = flagDescrs + value["descr"] + "\n"   # Format our return string
                print("COMMANDS:")
                print(flagDescrs.rstrip("/"))
                print(get_exit_message("invalid_arg", pfsenseServer, "generic", pfsenseAction, ""))
                sys.exit(1)
        # If we couldn't connect to pfSense's web configurator, return error
        else:
            print(get_exit_message("connect_err", pfsenseServer, "generic", pfsenseAction, ""))
            sys.exit(1)
    # If user did not pass in a hostname or IP
    else:
        print("pfsense-automator " + PfaVar.software_version)
        print("SYNTAX:")
        print("  " + get_exit_message("syntax","","generic","",""))
        flagDescrs = ""    # Initialize our flag description help string
        flagDict = get_exit_message("",pfsenseServer,"all","","")    # Pull our descr dictionary
        # Loop through our flag descriptions and save them to a string
        for key,value in flagDict.items():
            # Only perform this on dict keys with -- flags
            if key.startswith("--"):
                flagDescrs = flagDescrs + value["descr"] + "\n"   # Format our return string
        print("COMMANDS:")
        print(flagDescrs.rstrip("/"))
        # Print our error and exit
        print(get_exit_message("invalid_host", "", "generic", "", ""))
        sys.exit(1)

# Execute main function
main()
# If nothing forced us to exit the script, return exit code 0
sys.exit(0)