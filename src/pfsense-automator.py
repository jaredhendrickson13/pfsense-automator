#!/usr/bin/python3
# ----------------------------------------------------------------------------------------------------------------
# Author: Jared Hendrickson
# Copyright 2019 - Jared Hendrickson
# Purpose: This script is intended to add a CLI interface for pfSense devices. This uses cURL libraries to execute
# pfSense's many PHP configuration scripts. All functions in this script mimic changes regularly made in a browser
# and utilizes pfSense's built-in CSRF checks, input validation, and configuration parsing
# ----------------------------------------------------------------------------------------------------------------
# IMPORT MODULES #
from pfsensewc import *
import signal


# Variables
first_arg = sys.argv[1] if len(sys.argv) > 1 else ""    # Declare 'first_arg' to populate the first argument passed in to the script
second_arg = sys.argv[2] if len(sys.argv) > 2 else ""    # Declare 'second_arg' to populate the second argument passed in to the script
third_arg = sys.argv[3] if len(sys.argv) > 3 else None    # Declare 'third_arg' to populate the third argument passed in to the script
fourth_arg = sys.argv[4] if len(sys.argv) > 4 else None    # Declare 'fourth_arg' to populate the fourth argument passed in to the script
fifth_arg = sys.argv[5] if len(sys.argv) > 5 else None    # Declare 'fifth_arg' to populate the fifth argument passed in to the script
sixth_arg = sys.argv[6] if len(sys.argv) > 6 else None    # Declare 'sixth_arg' to populate the sixth argument passed in to the script
seventh_arg = sys.argv[7] if len(sys.argv) > 7 else None    # Declare 'seventh_arg' to populate the seventh argument passed in to the script
eighth_arg = sys.argv[8] if len(sys.argv) > 8 else None    # Declare 'eighth_arg' to populate the eigth argument passed in to the script
ninth_arg = sys.argv[9] if len(sys.argv) > 9 else None    # Declare 'ninth_arg' to populate the ninth argument passed in to the script
tenth_arg = sys.argv[10] if len(sys.argv) > 10 else None    # Declare 'tenth_arg' to populate the tenth argument passed in to the script
eleventh_arg = sys.argv[11] if len(sys.argv) > 11 else None    # Declare 'eleventh_arg' to populate the eleventh argument passed in to the script
twelfth_arg = sys.argv[12] if len(sys.argv) > 12 else None    # Declare 'twelfth_arg' to populate the twelth argument passed in to the script
thirteenth_arg = sys.argv[13] if len(sys.argv) > 13 else None    # Declare 'thirteenth_arg' to populate the thirteenth argument passed in to the script
fourteenth_arg = sys.argv[14] if len(sys.argv) > 14 else None    # Declare 'fourteenth_arg' to populate the fourteenth argument passed in to the script
fifteenth_arg = sys.argv[15] if len(sys.argv) > 15 else None    # Declare 'fifteenth_arg' to populate the fifteenth argument passed in to the script
sixteenth_arg = sys.argv[16] if len(sys.argv) > 16 else None    # Declare 'sixteenth_arg' to populate the sixteenth argument passed in to the script
seventeenth_arg = sys.argv[17] if len(sys.argv) > 17 else None    # Declare 'seventeenth_arg' to populate the seventeenth argument passed in to the script
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)    # Disable urllib warnings (suppress invalid cert warning)

# FUNCTIONS #
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
    pfsense_server = first_arg.replace("https://", "")    # Assign the server value to the first_arg (filtered)
    pfsense_action = filter_input(second_arg)    # Assign the action to execute (filtered)
    # Check if user requests HTTPS override
    if pfsense_server.lower().startswith("http://"):
        pfsense_server = pfsense_server.replace("http://", "")    # Replace the http:// protocol from the servername
        PfaVar.wc_protocol = "http"    # Reassign our webconfigurator protocol
        PfaVar.wc_protocol_port = 80    # Assign webconfigurator port to HTTP (80)
    # Check if user requests non-standard UI port
    if ":" in pfsense_server:
        non_std_port = pfsense_server.split(":")[1]    # Assign the value after our colon to a variable
        non_std_port_int = int(non_std_port) if non_std_port.isdigit() else 999999    # Assign a integer value of our port variable, if it is not a number save out of range
        PfaVar.wc_protocol_port = non_std_port_int if 1 <= non_std_port_int <= 65535 else PfaVar.wc_protocol_port    # Change our webUI port specification if it is a valid number
        pfsense_server = pfsense_server.replace(":" + non_std_port, "")    # Remove our port specification from our servername string
    pfsense_server = filter_input(pfsense_server.replace("http://", ""))    # Filter our hostname/IP input
    # Check if we are simply requesting the software version
    if first_arg.upper() in ("--VERSION", "-V"):
        print(get_exit_message("version", "", "generic", "", ""))
        sys.exit(0)
    # Check that user passed in an IP or hostname
    if pfsense_server is not "":
        # Check if the pfSense server is available for connections
        if check_remote_port(pfsense_server, PfaVar.wc_protocol_port):
            # If user is trying to add a DNS entry and the correct number of arguments are present
            if pfsense_action == "--add-dns":
                # Check if the correct number of arguments were given
                if len(sys.argv) > 6:
                    # Action Variables
                    host_to_add = filter_input(third_arg)    # Assign the user passed hostname (filtered)
                    domain_to_add = filter_input(fourth_arg)    # Assign the user passed domain (filtered)
                    fqdn_to_add = filter_input(host_to_add + "." + domain_to_add)    # Join the host and domain together to calculate the FQDN
                    ip_to_add = filter_input(fifth_arg)    # Assign the user passed ip address (filtered)
                    descr_to_add = filter_input(sixth_arg)    # Assign the user passed description (filtered)
                    user = eighth_arg if seventh_arg == "-u" and eighth_arg is not None else input("Please enter username: ")    # Parse passed in username, if empty, prompt user to enter one
                    key = tenth_arg if ninth_arg == "-p" and tenth_arg is not None else getpass.getpass("Please enter password: ")    # Parse passed in passkey, if empty, prompt user to enter one
                    descr_to_add = "Auto-added by " + user + " on " + PfaVar.local_hostname if descr_to_add == "default" else descr_to_add    # Write default description if default is passed
                    # If the IP passed into the command is valid, try to add the entry to pfSense
                    if validate_ip(ip_to_add):
                        # Execute DNS entry function
                        add_dns_exit_code = add_dns_entry(pfsense_server, user, key, host_to_add, domain_to_add, ip_to_add, descr_to_add)
                        # Check exit codes and print strings accordingly.
                        print(get_exit_message(add_dns_exit_code, pfsense_server, pfsense_action, host_to_add, domain_to_add))
                        sys.exit(add_dns_exit_code)
                    # If IP is not valid, return error
                    else:
                        print(get_exit_message("invalid_ip", "", pfsense_action, "", ""))
                        sys.exit(1)
                # If incorrect number of arguments were given, return error
                else:
                    print(get_exit_message("invalid_syntax", "", pfsense_action, "", ""))
                    sys.exit(1)
            # If user is trying to pull the DNS resolver configuration
            if pfsense_action == "--read-dns":
                # Check if the minimum number of arguments was given
                if len(sys.argv) > 3:
                    # Action variables
                    dns_filter = third_arg    # Save our sort filter
                    user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")    # Parse passed in username, if empty, prompt user to enter one
                    key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")    # Parse passed in passkey, if empty, prompt user to enter one
                    dns_config = get_dns_entries(pfsense_server, user, key)    # Pull our DNS resolver (unbound) configuration
                    id_head = structure_whitespace("ID", 5, "-", True) + " "    # Format the table header ID column
                    host_head = structure_whitespace("HOST", 25, "-", True) + " "    # Format the table header host column
                    domain_head = structure_whitespace("DOMAIN", 25, "-", True) + " "    # Format the table header domain column
                    ip_head = structure_whitespace("IP", 15, "-", True) + " "    # Format the table header domain column
                    descr_head = structure_whitespace("DESCRIPTION", 30, "-", True) + " "    # Format the table header description column
                    # If our DNS configuration is empty
                    if dns_config["ec"] == 0:
                        # If user wants to export the data as JSON
                        if dns_filter.startswith("-j=") or dns_filter.startswith("--json="):
                            json_path = dns_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readdns-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(dns_config["domains"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If user wants to print the JSON output
                        elif dns_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(dns_config["domains"]))   # Print our JSON data
                        # If user wants to print all items
                        elif dns_filter.upper() in ("--ALL","-A") or dns_filter.upper() in ("DEFAULT", "-D") or dns_filter.startswith(("--host=","-h=")):
                            # Format and print our header
                            print(id_head + host_head + domain_head + ip_head + descr_head)
                            # Loop through each domain dictionary and pull out the host data
                            for domain_key, domain_value in dns_config["domains"].items():
                                # Loop through each host in the domain
                                for host_key, host_value in domain_value.items():
                                    # Loop Variables
                                    host = structure_whitespace(host_value["hostname"], 25, " ", True) + " "    # Format our host data
                                    domain = structure_whitespace(host_value["domain"], 25, " ", True) + " "    # Format our domain data
                                    ip = structure_whitespace(host_value["ip"], 15, " ", True) + " "    # Format our ip data
                                    id_num = structure_whitespace(host_value["id"], 5, " ", True) + " "    # Format our id data
                                    descr = structure_whitespace(host_value["descr"], 30, " ", True) + " "    # Format our description data
                                    alias = ""    # Initialize our alias data as empty string. This will populate below if user requested ALL
                                    # Check that user wants all info first
                                    if dns_filter.upper() in ("--ALL","-A") or dns_filter.startswith(("--host=","-h=")):
                                        # Loop through our aliases and try to parse data if it exists
                                        for aliasKey, alias_value in host_value["alias"].items():
                                            try:
                                                alias = alias + "      - Alias: " + alias_value["hostname"] + "." + alias_value["domain"] + "\n"
                                            except KeyError:
                                                alias = ""    # Assign empty string
                                    # If we are only looking for one value
                                    if dns_filter.startswith(("--host=","-h=")):
                                        alias_match = False    # Predefine alias_match. This will change to true if the FQDN matches an alias exactly
                                        fqdn_filter = dns_filter.replace("--host=", "").replace("-h=", "")    # Remove expected strings from argument to get our hostname filter
                                        # Check if domain is our hostFilter
                                        if fqdn_filter.endswith(host_value["domain"]):
                                            # Format our filter
                                            domain_filter = host_value["domain"]    # Save our matched domain
                                            hostname_filter = fqdn_filter.replace("." + domain_filter, "")    # Format our hostname portion
                                            # Check if the hostname/alias matches our filter
                                            if hostname_filter in host_value["alias"]:
                                                # Check if our FQDN matches the alias
                                                alias_value = host_value["alias"][hostname_filter]
                                                alias_match = True if alias_value["hostname"] + "." + alias_value["domain"] == fqdn_filter else False
                                            if hostname_filter == host_value["hostname"] or alias_match:
                                                print(id_num + host + domain + ip + descr)
                                                print(alias.rstrip("\n")) if alias is not "" else None
                                                break   # Break the loop as we found our match
                                    # If we are looking for all values
                                    else:
                                        # Print our formatted data
                                        print(id_num + host + domain + ip + descr)
                                        print(alias.rstrip("\n")) if alias is not "" else None
                            # If we did not match an expected filter
                        else:
                            print(get_exit_message("invalid_filter", "", pfsense_action, dns_filter, ""))
                    # If our DNS config read failed
                    else:
                        print(get_exit_message(dns_config["ec"], pfsense_server, pfsense_action, "", ""))
                # If we did not pass in the correct number of arguments
                else:
                    print(get_exit_message("invalid_syntax", pfsense_server, pfsense_action, "", ""))    # Print our error message
            # Assigns functions for --read-users
            elif pfsense_action == "--read-users":
                # Action variables
                user_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                user_data = get_users(pfsense_server, user, key)    # Pull our user data
                id_header = structure_whitespace("ID",5,"-", False) + " "   # Create our ID header
                us_header = structure_whitespace("USERNAME",25,"-", False) + " "    # Create our username header
                fn_header = structure_whitespace("FULL NAME",20,"-", True) + " "    # Create our full name header
                en_header = structure_whitespace("ENABLED",8,"-", True) + " "    # Create our enabled header
                pv_header = structure_whitespace("PRIVILEGE",10,"-", True) + " "    # Create our privilege header
                gp_header = structure_whitespace("GROUPS",30,"-", True) + " "    # Create our privilege header
                header = id_header + us_header + fn_header + en_header + pv_header + gp_header    # Piece our header together
                # Check that we were able to pull our user data successfully
                if user_data["ec"] == 0:
                    # Check if user only wants to display data for one username
                    if user_filter.startswith(("--username=","-un=")):
                        user_exp = user_filter.replace("--username=", "").replace("-un=","")  # Remove our filter identifier to capture our username expression
                        # Check that we have data for the given username
                        if user_exp in user_data["users"]:
                            print(structure_whitespace("Username:",20," ",True) + user_data["users"][user_exp]["username"])    # Print username
                            print(structure_whitespace("Full name:",20," ",True) + user_data["users"][user_exp]["full_name"])   # Print our user full name
                            print(structure_whitespace("ID:",20," ",True) + user_data["users"][user_exp]["id"])   # Print our user id
                            # noinspection SyntaxError
                            print(structure_whitespace("Enabled:",20," ",True) + "Yes") if user_data["users"][user_exp]["disabled"] != "yes" else print(structure_whitespace("Enabled:",20," ",True) + "No")  # Print our enabled value
                            print(structure_whitespace("Created-by:",20," ",True) + user_data["users"][user_exp]["type"])   # Print our user type
                            print(structure_whitespace("Expiration:",20," ",True) + user_data["users"][user_exp]["expiration"]) if user_data["users"][user_exp]["expiration"] != "" else None  # Print our expiration date
                            # noinspection SyntaxError
                            print(structure_whitespace("Custom UI:",20," ",True) + "Yes") if user_data["users"][user_exp]["custom_ui"] != "yes" else print(structure_whitespace("Custom UI:",20," ",True) + "No")  # Print our enabled value
                            # Loop through each of our groups and print it's values
                            group_str = ""
                            for g in user_data["users"][user_exp]["groups"]:
                                group_str = group_str + g + ", "   # Concentrate our strings together
                            print(structure_whitespace("Groups:",20," ",True) + group_str.rstrip(", "))  # Print header indicate start of group print
                            print(structure_whitespace("Privilege:",20," ",True) + user_data["users"][user_exp]["privileges"]["level"])   # Print our privilege level
                            print(structure_whitespace("Authorized Keys:",20," ",True) + structure_whitespace(user_data["users"][user_exp]["authorized_keys"],30," ",True))    # Print the start of our authorized keys file
                            print(structure_whitespace("IPsec Keys:",20," ",True) + structure_whitespace(user_data["users"][user_exp]["ipsec_keys"],30," ",True))    # Print the start of our IPsec keys file
                        # If user does not exist
                        else:
                            print(get_exit_message("invalid_user", pfsense_server, pfsense_action, user_exp, ""))    # Print error message
                            sys.exit(1)    # Exit on non-zero
                    # Check if user wants to print all users
                    elif user_filter.lower() in ("--all","-a","default"):
                        print(header)    # Print our header
                        # Loop through our users and print their data
                        for u,d in user_data["users"].items():
                            loop_id = structure_whitespace(d["id"],5," ", True) + " "
                            loop_us = structure_whitespace(d["username"],25," ", True) + " "
                            loop_fn = structure_whitespace(d["full_name"],20," ", True) + " "
                            loop_en = structure_whitespace("yes",8," ", True) + " " if d["disabled"] != "yes" else structure_whitespace("no",8," ", True) + " "
                            loop_pv = structure_whitespace(d["privileges"]["level"],10," ", True) + " "
                            loop_gp = structure_whitespace(''.join([str(v) + ", " for v in d["groups"]]).rstrip(", "),30," ", True) + " "
                            print(loop_id + loop_us + loop_fn + loop_en + loop_pv + loop_gp)
                    # If user wants to print the JSON output
                    elif user_filter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(user_data["users"]))   # Print our JSON data
                    # If we want to export values as JSON
                    elif user_filter.startswith(("--json=", "-j=")):
                        json_path = user_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        json_name = "pf-readusers-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(json_path):
                            # Open an export file and save our data
                            json_exported = export_json(user_data["users"], json_path, json_name)
                            # Check if the file now exists
                            if json_exported:
                                print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                            else:
                                print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                    # If we did not pass in a valid filter
                    else:
                        print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, user_filter, ""))
                        sys.exit(1)
                # If we could not pull our user data, return error
                else:
                    print(get_exit_message(user_data["ec"], pfsense_server, pfsense_action, "", ""))   # Print error
                    sys.exit(user_data["ec"])    # Exit on our return code

            # Assign functions for flag --add-user
            elif pfsense_action == "--add-user":
                # Action variables
                uname = third_arg if len(sys.argv) > 3 else input("Username: ")    # Save our user input for the new username or prompt for input if none
                enable = filter_input(fourth_arg) if len(sys.argv) > 4 else input("Enable user [yes,no]: ")    # Save our enable user input or prompt for input if none
                passwd = fifth_arg if len(sys.argv) > 5 else getpass.getpass("Password: ")    # Save our password input or prompt user for input if none
                fname = sixth_arg if len(sys.argv) > 6 else input("Full name: ")    # Save our full name input or prompt user for input if none
                fname = "" if fname.lower() == "none" else fname    # Allow user to specify `none` if they do not want to add a full name
                exp_date = seventh_arg if len(sys.argv) > 7 else input("Expiration date [mm/dd/yyyy, blank for none]: ")    # Save our date input (mm/dd/yyyy) or prompt user for input if none
                exp_date = "" if exp_date.lower() == "none" else exp_date    # Allow user to specify `none` if they don't want the account to expire
                groups_raw = eighth_arg + "," if len(sys.argv) > 8 else None    # Save our groups input, or assign None value if none. Will be prompted for input later if none
                groups_raw = "," if groups_raw is not None and groups_raw.lower() == "none," else groups_raw    # Allow user to specify `none` if they don't want to add user to any groups
                # Check if groups input via interactive mode
                if groups_raw is None:
                    groups = []    # Initialize our groups list
                    # Loop until we have all our desired groups
                    while True:
                        g_input = input("Add user to group [blank entry if done]: ")
                        # Check if a non blank input was recieved
                        if g_input != "":
                            groups.append(g_input)    # Add our entry to the group and repeat the loop
                        # Otherwise break the loop
                        else:
                            break
                # Otherwise, format our groups to a list
                else:
                    groups = list(filter(None, groups_raw.split(",")))
                user = tenth_arg if ninth_arg == "-u" and tenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = twelfth_arg if eleventh_arg == "-p" and twelfth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our enable value is valid
                if enable in ["yes","no","enable","disable"]:
                    enable = "" if enable in ["yes","enable"] else "yes"    # Switch our enabled to value to blank string (meaning do not disable) otherwise "yes"
                    # Check if our expiration date is valid, or if the user does not want to specify an expiration
                    if validate_date_format(exp_date) or exp_date == "":
                        # Pull our group configuration and check if we encountered an error
                        avail_groups = get_user_groups(pfsense_server, user, key)
                        if avail_groups["ec"] == 0:
                            # Check if our groups exist
                            for grp in groups:
                                # If our group doesn't exist, print error and exit on non zero status
                                if grp not in avail_groups["groups"]:
                                    print(get_exit_message("invalid_group", pfsense_server, pfsense_action, grp, ""))
                                    sys.exit(1)
                            # Add our user, check if the user was successfully added and print our exit message and exit on return code
                            user_added = add_user(pfsense_server, user, key, uname, enable, passwd, fname, exp_date, groups)
                            print(get_exit_message(user_added, pfsense_server, pfsense_action, uname, ""))
                            sys.exit(user_added)
                        # If we encountered an error pulling our groups, print our error message and exit on non-zero status
                        else:
                            print(get_exit_message(avail_groups["ec"], pfsense_server, pfsense_action, "", ""))
                            sys.exit(1)
                    # If our date is invalid, print error message and exit on non zero status
                    else:
                        print(get_exit_message("invalid_date", pfsense_server, pfsense_action, exp_date, ""))
                        sys.exit(1)
                # If our enable value is invalid, print error message and exit on non zero status
                else:
                    print(get_exit_message("invalid_enable", pfsense_server, pfsense_action, enable, ""))
                    sys.exit(1)

            # Assign functions for flag --del-user
            elif pfsense_action == "--del-user":
                # Action variables
                uid = third_arg if len(sys.argv) > 3 else input("Username or UID to remove: ")    # Save our username/id input from the user, or prompt for input if none
                no_conf_arg = "--force"    # Assign the argument that will bypass confirmation before deletion
                # Check if the user must confirm the deletion before proceeding
                if no_conf_arg not in sys.argv:
                    uid_conf = input("Are you sure you would like to remove user `" + uid + "`? [y/n]: ").lower()    # Have user confirm the deletion
                    # Exit if user did not confirm the deletion
                    if uid_conf not in ["y","yes"]:
                        sys.exit(0)
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our username is not "admin" or "0"
                if uid.lower() not in ["admin","0"]:
                    # Check that we are not trying to remove our own username
                    if uid != user:
                        # Run our function, print the return message and exit on the return code
                        user_del = del_user(pfsense_server, user, key, uid)
                        print(get_exit_message(user_del, pfsense_server, pfsense_action, uid, ""))
                        sys.exit(user_del)
                    # If our uid to delete matches our username
                    else:
                        print(get_exit_message("invalid_user", pfsense_server, pfsense_action, "", ""))
                        sys.exit(1)
                # If our UID was "admin" or "0", return error
                else:
                    print(get_exit_message("invalid_uid", pfsense_server, pfsense_action, "", ""))
                    sys.exit(1)

            # Assign functions for flag --add-user-key
            elif pfsense_action == "--add-user-key":
                # Action variables
                uname = third_arg.lower() if len(sys.argv) > 3 else input("Username to add key: ").lower()    # Get user input for username, otherwise prompt user for input
                key_type = filter_input(fourth_arg).lower() if len(sys.argv) > 4 else input("Key type [ssh,ipsec]: ").lower()    # Get user input for key type, or prompt user to input
                valid_input = False    # Init a bool as false to track whether we are ready to run our configuration function
                # Get variables if key type is SSH
                if key_type.lower() == "ssh":
                    pub_key_path = fifth_arg if len(sys.argv) > 5 else input("Path to key file: ")    # Get our key path, or prompt user for path if none
                    destruct = sixth_arg if len(sys.argv) > 6 else input("Override existing keys? [yes,no]: ")    # Get our key override value, or prompt user for input if none
                    user = eighth_arg if seventh_arg == "-u" and eighth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = tenth_arg if ninth_arg == "-p" and tenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    # INPUT VALIDATION
                    # Check if our key file exists
                    if os.path.exists(pub_key_path):
                        # Read our file and save it's contents
                        with open(pub_key_path,"r") as kf:
                            pub_key = kf.read()
                        # Check that our destruct value is okay
                        if destruct.lower() in ["yes","no"]:
                            destruct = True if destruct.lower() == "yes" else False    # Swap yes to True, and no to False
                            valid_input = True    # Assign true value, we're ready to run our command
                        # If our destruct value is invalid
                        else:
                            print(get_exit_message("invalid_override", pfsense_server, pfsense_action, destruct, ""))
                            sys.exit(1)
                    # If our key file does not exist, print our error message and exit
                    else:
                        print(get_exit_message("invalid_ssh_path", pfsense_server, pfsense_action, pub_key_path, ""))
                        sys.exit(1)
                # Get variables if key type is IPsec
                elif key_type.lower() == "ipsec":
                    pub_key = fifth_arg if len(sys.argv) > 5 else getpass.getpass("IPsec pre-shared key: ")    # Get our key, or prompt user for key if none
                    user = seventh_arg if sixth_arg == "-u" and seventh_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = ninth_arg if eighth_arg == "-p" and ninth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    destruct = True    # Always replace this value if run, only one key is allowed
                    valid_input = True  # Assign true value, we're ready to run our command
                # If we received an invalid key type input
                else:
                    print(get_exit_message("invalid_key_type", pfsense_server, pfsense_action, key_type, ""))
                    sys.exit(1)
                # Check if we are ready to run our configure function
                if valid_input:
                    # Execute our add_user_key() function
                    add_key_ec = add_user_key(pfsense_server, user, key, uname, key_type, pub_key, destruct)
                    print(get_exit_message(add_key_ec, pfsense_server, pfsense_action, key_type, uname))
                    sys.exit(add_key_ec)
                # If for any reason our valid input was false, print error and exit on non-zero
                else:
                    print(get_exit_message(2, pfsense_server, pfsense_action, key_type, ""))
                    sys.exit(2)

            # Assign functions for flag --change-user-passwd
            elif pfsense_action == "--change-user-passwd":
                # Action variables
                uname = third_arg if len(sys.argv) > 3 else input("Change username: ")    # Save our user input for username to change, prompt for input if none
                passwd = fourth_arg if len(sys.argv) > 4 else None    # Save our user input, or assing None if interactive mode. Interactive mode will require confirmation
                # If our passwd is being passed using interactive mode
                if passwd is None:
                   # Loop until our passwd is successfully confirmed
                    while True:
                        passwd = getpass.getpass("New password: ")    # Prompt user for new passwd
                        passwd_conf = getpass.getpass("Confirm password: ")    # Prompt user to confirm password
                        # Check if our inputs match, otherwise prompt user to reinput passwords
                        if passwd == passwd_conf:
                            break
                        else:
                            print("Passwords do not match")
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Run our change passwd function
                passwd_changed = change_user_passwd(pfsense_server, user, key, uname, passwd)
                print(get_exit_message(passwd_changed, pfsense_server, pfsense_action, uname, ""))
                sys.exit(passwd_changed)

            # If user is trying to add an auth server, gather required configuration data from user
            elif pfsense_action == "--add-ldapserver":
                # Local variables
                yes_no = ["yes", "no"]
                ldap_config = {
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
                if len(ldap_config["input"]) >= 24:
                    # Try to verify our LDAP port
                    try:
                        int_check = int(ldap_config["input"]["ldapPort"])
                        int_port_check = True
                    except:
                        int_port_check = False    # If we could not convert the port string to an integer
                    # If our ldap port could is invalid
                    if int_port_check:
                        # Check that our port is in range
                        if 0 < int_check <= 65535:
                            # Check that we have a valid transport type entered
                            if ldap_config["input"]["transport"] in ["standard", "starttls", "encrypted"]:
                                # Swap our shorthand transport options to their valid option values
                                ldap_config["input"]["transport"] = ldap_config["selection"]["transport"][0] if ldap_config["input"]["transport"] == "standard" else ldap_config["input"]["transport"]
                                ldap_config["input"]["transport"] = ldap_config["selection"]["transport"][1] if ldap_config["input"]["transport"] == "starttls" else ldap_config["input"]["transport"]
                                ldap_config["input"]["transport"] = ldap_config["selection"]["transport"][2] if ldap_config["input"]["transport"] == "encrypted" else ldap_config["input"]["transport"]
                                # Check our LDAP version
                                if ldap_config["input"]["ldapProtocol"] in ldap_config["selection"]["ldapProtocol"]:
                                    # Try to validate our timeout value as an integer
                                    try:
                                        timeout_int = int(ldap_config["input"]["timeout"])
                                        int_time_check = True
                                    except:
                                        timeout_int = 0
                                        int_time_check = False
                                    # Check if we now have a n integer
                                    if int_time_check:
                                        # Check if our timeout is in range
                                        if 9999999999 > timeout_int > 0:
                                            # Check if our search scope is valid
                                            if ldap_config["input"]["searchScope"] in ldap_config["selection"]["searchScope"]:
                                                # Check if our extended query entry is valid
                                                if ldap_config["input"]["extQuery"] in yes_no:
                                                    ldap_config["input"]["extQuery"] = "" if ldap_config["input"]["extQuery"] == "no" else ldap_config["input"]["extQuery"]
                                                    # Check if our bind anonymously entry is valid
                                                    if ldap_config["input"]["bindAnon"] in yes_no:
                                                        ldap_config["input"]["bindAnon"] = "" if ldap_config["input"]["bindAnon"] == "no" else ldap_config["input"]["bindAnon"]
                                                        # Check if our LDAP template value is valid
                                                        if ldap_config["input"]["ldapTemplate"] in ldap_config["selection"]["ldapTemplate"]:
                                                            # Check if our rfc2307 value is valid
                                                            if ldap_config["input"]["rfc2307"] in yes_no:
                                                                ldap_config["input"]["rfc2307"] = "" if ldap_config["input"]["rfc2307"] == "no" else ldap_config["input"]["rfc2307"]
                                                                # Check if our encode value is valid
                                                                if ldap_config["input"]["encode"] in yes_no:
                                                                    ldap_config["input"]["encode"] = "" if ldap_config["input"]["encode"] == "no" else ldap_config["input"]["encode"]
                                                                    # Check if our userAlt value is valid
                                                                    if ldap_config["input"]["userAlt"] in yes_no:
                                                                        ldap_config["input"]["userAlt"] = "" if ldap_config["input"]["userAlt"] == "no" else ldap_config["input"]["userAlt"]
                                                                        # Now that we have verified our syntax, run the function
                                                                        add_ldap_exit_code = add_auth_server_ldap(pfsense_server, ldap_config["input"]["user"], ldap_config["input"]["passwd"], ldap_config["input"]["descrName"], ldap_config["input"]["ldapServer"], ldap_config["input"]["ldapPort"], ldap_config["input"]["transport"], ldap_config["input"]["ldapProtocol"], ldap_config["input"]["timeout"], ldap_config["input"]["searchScope"], ldap_config["input"]["baseDN"], ldap_config["input"]["authContainers"], ldap_config["input"]["extQuery"], ldap_config["input"]["query"], ldap_config["input"]["bindAnon"], ldap_config["input"]["bindDN"], ldap_config["input"]["bindPw"], ldap_config["input"]["ldapTemplate"], ldap_config["input"]["userAttr"], ldap_config["input"]["groupAttr"], ldap_config["input"]["memberAttr"], ldap_config["input"]["rfc2307"], ldap_config["input"]["groupObject"], ldap_config["input"]["encode"], ldap_config["input"]["userAlt"])
                                                                        print(get_exit_message(add_ldap_exit_code, pfsense_server, pfsense_action, ldap_config["input"]["descrName"], ''))
                                                                        sys.exit(add_ldap_exit_code)
                                                                    # If our userAlt value is invalid
                                                                    else:
                                                                        print(get_exit_message("invalid_userAlt", "", pfsense_action, ldap_config["input"]["userAlt"], ''))
                                                                        sys.exit(1)
                                                                # If our encode value is invalid
                                                                else:
                                                                    print(get_exit_message("invalid_encode", "", pfsense_action, ldap_config["input"]["encode"], ''))
                                                                    sys.exit(1)
                                                            # If our rfc2307 value is invalid
                                                            else:
                                                                print(get_exit_message("invalid_rfc2307", "", pfsense_action, ldap_config["input"]["rfc2307"], ''))
                                                                sys.exit(1)
                                                        # If our LDAP template value is invalid
                                                        else:
                                                            print(get_exit_message("invalid_ldapTemplate", "", pfsense_action, ldap_config["input"]["ldapTemplate"], ''))
                                                            sys.exit(1)
                                                    # If our bind anonymously entry is invalid
                                                    else:
                                                        print(get_exit_message("invalid_bindAnon", "", pfsense_action, ldap_config["input"]["bindAnon"], ''))
                                                        sys.exit(1)
                                                # If our extended query entry is invalid
                                                else:
                                                    print(get_exit_message("invalid_extQuery", "", pfsense_action, ldap_config["input"]["extQuery"], ''))
                                                    sys.exit(1)
                                            # If search scope is invalid, print error
                                            else:
                                                print(get_exit_message("invalid_searchScope", "", pfsense_action, ldap_config["input"]["searchScope"], ''))
                                                sys.exit(1)
                                        # If timeout is out of range
                                        else:
                                            print(get_exit_message("invalid_timeout_range", "", pfsense_action, ldap_config["input"]["timeout"], ''))
                                            sys.exit(1)
                                    # If we could not convert the input to an integer
                                    else:
                                        print(get_exit_message("invalid_timeout", "", pfsense_action, ldap_config["input"]["timeout"], ''))
                                        sys.exit(1)
                                # If invalid LDAP protocol was given
                                else:
                                    print(get_exit_message("invalid_protocol", "", pfsense_action, ldap_config["input"]["ldapProtocol"], ''))
                                    sys.exit(1)
                            # If unknown transport type was entered
                            else:
                                print(get_exit_message("invalid_transport", "", pfsense_action, ldap_config["input"]["transport"], ''))
                                sys.exit(1)
                        # If our LDAP port is out of range
                        else:
                            print(get_exit_message("invalid_portrange", "", pfsense_action, ldap_config["input"]["ldapPort"], ''))
                            sys.exit(1)
                    # If our LDAP port contained invalid characters
                    else:
                        print(get_exit_message("invalid_port", "", pfsense_action, ldap_config["input"]["ldapPort"], ''))
                        sys.exit(1)
                # If we are missing arguments
                else:
                    print(get_exit_message("missing_args", "", pfsense_action, '', ''))
                    sys.exit(1)

            # If user is trying to add an SSL cert to the webconfigurator, try to add the cert
            elif pfsense_action == "--add-sslcert":
                # Check if user passed in the correct number of arguments
                if len(sys.argv) > 5:
                    # Action Variables
                    cert_data = ""    # Init empty string
                    cert_key_data = ""    # Init empty string
                    cert_path = third_arg    # Save the user passed file path to the crt file
                    cert_key_path = fourth_arg    # Save the user passwed file path to the key file
                    descr_to_add = filter_input(fifth_arg)    # Assign the user passed description (filtered)
                    descr_to_add = PfaVar.current_date if descr_to_add == "default" else descr_to_add    # Write default description if default is passed
                    user = seventh_arg if sixth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = ninth_arg if eighth_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    # Check if cert file exists
                    if os.path.exists(cert_path):
                        # Read the certificate data
                        with open(cert_path, "r") as certFile:
                            cert_data = certFile.read()
                        # Check if cert key file exists
                        if os.path.exists(cert_key_path):
                            # Read the certificate data
                            with open(cert_key_path, "r") as certKeyFile:
                                cert_key_data = certKeyFile.read()
                        # If key doesn't exist, return error
                        else:
                            print(get_exit_message("no_key", pfsense_server, pfsense_action, cert_key_path, ""))
                            sys.exit(1)
                    # If cert doesn't exist, return error
                    else:
                        print(get_exit_message("no_cert", pfsense_server, pfsense_action, cert_path, ""))
                        sys.exit(1)
                    # Ensure we have data to post, if so, try to add the cert to pfSense
                    if cert_data is not "" and cert_key_data is not "":
                        add_ssl_cert_exit_code = add_ssl_cert(pfsense_server, user, key, cert_data, cert_key_data, descr_to_add)
                        # Check for authentication failed exit code
                        print(get_exit_message(add_ssl_cert_exit_code, pfsense_server, pfsense_action, "", ""))
                        sys.exit(add_ssl_cert_exit_code)
                    # Return error if files are empty
                    else:
                        print(get_exit_message("empty", pfsense_server, pfsense_action, "", ""))
                        sys.exit(1)

            # Assign functions for flag --check-auth
            elif pfsense_action == "--check-auth":
                # Check if the correct number of arguments are found
                if len(sys.argv) > 2:
                    # Print Warning prompt and gather login creds
                    print("WARNING: Large numbers of authentication failures will enforce a pfSense lockout for your IP address. Proceed with caution.")
                    user = fourth_arg if third_arg == "-u" and fourth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = sixth_arg if fifth_arg == "-p" and sixth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                    # Test authentication
                    if check_auth(pfsense_server, user, key):
                        print(get_exit_message("success", pfsense_server, pfsense_action, '', ''))
                    else:
                        print(get_exit_message("fail", pfsense_server, pfsense_action, '', ''))
                        sys.exit(1)

            # Assign functions for flag --check-version
            elif pfsense_action == "--check-version":
                # Action variables
                user = fourth_arg if third_arg == "-u" and fourth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixth_arg if fifth_arg == "-p" and sixth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                pf_version = get_pfsense_version(pfsense_server, user, key)    # Pull our pfSense version
                # Ensure we were able to pull our version successfully
                if pf_version["ec"] == 0:
                    print(pf_version["version"]["installed_version"])
                # If we encountered an error pulling our version
                else:
                    print(get_exit_message(pf_version["ec"], pfsense_server, pfsense_action, "", ""))    # Print our error msg
                    sys.exit(pf_version["ec"])    # Exit on our non-zero function return code

            # Assign functions for flag --read-rules
            elif pfsense_action == "--read-rules":
                # Action variables
                iface = third_arg if len(sys.argv) > 3 else input("Interface: ")    # Save our inline argumnet for interface, or prompt if none
                rule_filter = fourth_arg if len(sys.argv) > 4 else input("Filter [blank if none]:")   # Assign our filter argument to the fourth slot
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                get_rules = get_firewall_rules(pfsense_server, user, key, iface)    # Get our alias data dictionary
                id_header = structure_whitespace("ID",5,"-", False) + " "   # Create our ID header
                type_header = structure_whitespace("TYPE",6,"-", False) + " "    # Create our TYPE header
                protocol_header = structure_whitespace("PROTOCOL", 10,"-", True) + " "    # Create our PROTOCOL header
                src_header = structure_whitespace("SOURCE",25,"-", True) + " "    # Create our SOURCE header
                dst_header = structure_whitespace("DESTINATION",25,"-", True) + " "    # Create our DESTINATION header
                gw_header = structure_whitespace("GATEWAY",12,"-", True) + " "    # Create our GATEWAY header
                descr_header = structure_whitespace("DESCRIPTION",30,"-", True) + " "    # Create our DESCRIPTION header
                header = id_header + type_header + protocol_header + src_header + dst_header + gw_header + descr_header   # Piece our header together
                # Check that we pulled our rules without error
                if get_rules["ec"] == 0:
                    # FORMAT OUR STATIC SYSTEM RULES
                    def_id = structure_whitespace("",5," ",True) + " "    # Format our default ID for system rules
                    def_prot = structure_whitespace("ANY",10," ",True) + " "   # Format our default PROTOCOL for system rules
                    # BOGONS
                    bogon_type = structure_whitespace("block",6," ", True) + " "
                    bogon_src = structure_whitespace("Any unassigned by IANA",25," ",True) + " "
                    bogon_dst = structure_whitespace("*",25," ",True) + " "
                    bogon_gw = structure_whitespace("*",12," ",True) + " "
                    bogon_descr = structure_whitespace("Block bogon networks",30," ",True) + " "
                    bogon_data = def_id + bogon_type + def_prot + bogon_src + bogon_dst + bogon_gw + bogon_descr
                    # RFC1918
                    prv_type = structure_whitespace("block",6," ", True) + " "
                    prv_src = structure_whitespace("RFC1918 networks",25," ",True) + " "
                    prv_dst = structure_whitespace("*",25," ",True) + " "
                    prv_gw = structure_whitespace("*",12," ",True) + " "
                    prv_descr = structure_whitespace("Block private networks",30," ",True) + " "
                    prv_data = def_id + prv_type + def_prot + prv_src + prv_dst + prv_gw + prv_descr
                    # ANTILOCKOUT
                    al_type = structure_whitespace("pass", 6, " ", True) + " "
                    al_src = structure_whitespace("*", 25, " ", True) + " "
                    al_dst = structure_whitespace("LAN address:22,80,443", 25, " ", True) + " "
                    al_gw = structure_whitespace("*", 12, " ", True) + " "
                    al_descr = structure_whitespace("Anti-lockout rule", 30, " ", True) + " "
                    al_data = def_id + al_type + def_prot + al_src + al_dst + al_gw + al_descr
                    # CHECK OUR USERS FILTER AND READ INFORMATION ACCORDINGLY
                    head_printed = False    # Create a counter for our loop
                    for key,value in get_rules["rules"]["user_rules"].items():
                        # FORMAT OUR ACL DATA VALUES
                        ip_proto = ("v" + (value["ipprotocol"].replace("inet","") + "4")).replace("v464","*").replace("64","6")    # Format our IP protocol into either *, v4, or v6
                        trans_proto = value["proto"].upper()    # Save our transport protocol in uppercase
                        format_proto = "ANY" if trans_proto == ip_proto else trans_proto + ip_proto    # Determine how to display our IP and transport protocols
                        proto = structure_whitespace(format_proto,10," ", True) + " "   # Create our type data
                        src_negated = "!" if value["srcnot"] == "yes" else ""    # Add ! char if context is inverted
                        dst_negated = "!" if value["dstnot"] == "yes" else ""    # Add ! char if context is inverted
                        src_format = src_negated + value["src_net"] if value["src_net"] != "" else src_negated + value["src"]     # Determine which source value to print
                        dst_format = dst_negated + value["dst_net"] if value["dst_net"] != "" else dst_negated + value["dst"]    # Determine which dest value to print
                        id_num = structure_whitespace(value["id"],5," ", True) + " "   # Create our ID data
                        type_id = structure_whitespace(value["type"],6," ", True) + " "   # Create our type data
                        src = structure_whitespace("*" if src_format == "any" else src_format,25," ", True) + " "     # Create our SOURCE
                        dst = structure_whitespace("*" if dst_format == "any" else dst_format,25," ", True) + " "    # Create our DESTINATION
                        gw = structure_whitespace("*" if value["gateway"] == "" else value["gateway"],12," ", True) + " "    # Create our GATEWAY
                        descr = structure_whitespace(value["descr"],30," ", True) + " "    # Create our DESCRIPTION
                        data = id_num + type_id + proto + src + dst + gw + descr   # Piece our data together
                        # Check our user filter and print data accordingly
                        if rule_filter.lower() in ["-a", "--all", ""]:
                            print(header) if not head_printed else None
                            # Check if our system rules are using
                            if get_rules["rules"]["antilockout"] == True and not head_printed:
                                print(al_data)
                            if get_rules["rules"]["bogons"] == True and not head_printed:
                                print(bogon_data)
                            if get_rules["rules"]["private"] == True and not head_printed:
                                print(prv_data)
                            head_printed = True
                            print(data)
                        elif rule_filter.startswith(("--source=","-s=")):
                            src_exp = rule_filter.replace("--source=","").replace("-s=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if src_format.startswith(src_exp):
                                print(header) if not head_printed else None
                                head_printed = True
                                print(data)
                        elif rule_filter.startswith(("--destination=","-d=")):
                            dst_exp = rule_filter.replace("--destination=","").replace("-d=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if dst_format.startswith(dst_exp):
                                print(header) if not head_printed else None
                                head_printed = True
                                print(data)
                        elif rule_filter.startswith(("--protocol=","-p=")):
                            pro_exp = rule_filter.replace("--protocol=","").replace("-p=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if format_proto == pro_exp:
                                print(header) if not head_printed else None
                                head_printed = True
                                print(data)
                        elif rule_filter.startswith(("--ip-version=","-i=")):
                            ip_exp = rule_filter.replace("--ip-version=","").replace("-i=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if ip_exp.lower() == ip_proto:
                                print(header) if not head_printed else None
                                head_printed = True
                                print(data)
                        elif rule_filter.startswith(("--gateway=","-g=")):
                            gw_exp = rule_filter.replace("--gateway=","").replace("-g=","")    # Remove our filter identifier to capture our source expression
                            # Check that our expression matches before printing
                            if gw.startswith(gw_exp):
                                print(header) if not head_printed else None
                                head_printed = True
                                print(data)
                        # If user wants to print the JSON output
                        elif rule_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(get_rules["rules"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif rule_filter.startswith(("--json=", "-j=")):
                            json_path = rule_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readrules-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(get_rules["rules"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, rule_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                # If we encountered an error pulling our rules
                else:
                    print(get_exit_message(get_rules["ec"], pfsense_server, pfsense_action, iface, ""))
                    sys.exit(get_rules["ec"])

            # Assign functions for flag --add-rule
            elif pfsense_action == "--add-rule":
                # Action variables
                avail_protos = ["any","tcp","udp","tcp/udp","icmp"]    # Assign list of available protocols
                port_protos = ["tcp","udp","tcp/udp"]    # Assign a list of protocols that allow ports
                invert_src = False    # Init our invert source match to False
                invert_dst = False    # Init our invert dest match to False
                pos = "top" if "--top" in sys.argv else ""  # If user requests option for the rule to be added to top of ACL, assign value "top"
                iface = third_arg if len(sys.argv) > 3 else input("Interface: ")    # Get our user input for the interface ACL to add to, or prompt for input if none
                type_id = filter_input(fourth_arg).lower() if len(sys.argv) > 4 else input("Rule type [pass,block,reject]: ").lower()    # Get our user input for ACL type, or prompt user if none
                ipver = filter_input(fifth_arg).lower() if len(sys.argv) > 5 else input("IP protocol version [ipv4]: ")    # Get our user input for IP protocol type, or prompt user if none
                ipver = "inet6" if ipver == "ipv6" else ipver    # Swap our ipv6 input for inet6 as required by POST data form
                ipver = "inet" if ipver == "ipv4" else ipver    # Swap our ipv4 input for inet as required by POST data form
                proto = sixth_arg.lower() if len(sys.argv) > 6 else input("Protocol [" + ",".join(avail_protos) + "]: ")    # Get our user input for protocol type, or prompt user if none
                no_port = True if proto not in port_protos else False    # Set a bool indicating the we require a port for this rule
                # Gather remaining input differently if a port is required
                if not no_port:
                    source = seventh_arg.lower() if len(sys.argv) > 7 else input("Source address: ")    # Get our user input for source address, or prompt user if none
                    source_port = filter_input(eighth_arg).lower() if len(sys.argv) > 8 else input("Source port (port range hyphen separated): ")    # Get our user input for source ports, or prompt user if none
                    dest = ninth_arg.lower() if len(sys.argv) > 9 else input("Destination address: ")    # Get our user input for dest address, or prompt user if none
                    dest_port = filter_input(tenth_arg).lower() if len(sys.argv) > 10 else input("Destination port (port range hyphen separated): ")    # Get our user input for dest port, or prompt user if none
                    gw = filter_input(eleventh_arg) if len(sys.argv) > 11 else input("Gateway [blank for none]: ")    # Get our user input for gateway, or prompt user for input
                    gw = "" if gw.lower() in ["default","none"] else gw    # Swap out default or none input for empty string as required by POST data form
                    log = filter_input(twelfth_arg) if len(sys.argv) > 12 else input("Log rule matches [yes,no]: ")    # Get our user input for logging, or prompt user for input
                    log_bool = True if log == "yes" else False    # Swap out our "no" entry for blank string as required by POST data form
                    descr = thirteenth_arg if len(sys.argv) > 13 else input("Rule description: ")    # Get our user input for description or prompt user for input if none
                    user = fifteenth_arg if fourteenth_arg == "-u" and fifteenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = seventeenth_arg if sixteenth_arg == "-p" and seventeenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # If our protocol does not require a port
                else:
                    source_port = ""    # Default our source port blank
                    dest_port = ""    # Default our dest port to blank
                    source = seventh_arg.lower() if len(sys.argv) > 7 else input("Source address: ")    # Get our user input for source address, or prompt user if none
                    dest = eighth_arg.lower() if len(sys.argv) > 8 else input("Destination address: ")    # Get our user input for dest address, or prompt user if none
                    gw = filter_input(ninth_arg) if len(sys.argv) > 9 else input("Gateway [blank for none]: ")    # Get our user input for gateway, or prompt user for input
                    gw = "" if gw.lower() in ["default","none"] else gw    # Swap out default or none input for empty string as required by POST data form
                    log = filter_input(tenth_arg) if len(sys.argv) > 10 else input("Log rule matches [yes,no]: ")    # Get our user input for logging, or prompt user for input
                    log_bool = True if log == "yes" else False    # Swap out our "no" entry for blank string as required by POST data form
                    descr = eleventh_arg if len(sys.argv) > 11 else input("Rule description: ")    # Get our user input for description or prompt user for input if none
                    user = thirteenth_arg if twelfth_arg == "-u" and thirteenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                    key = fifteenth_arg if fourteenth_arg == "-p" and fifteenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION #
                # Check our rule type
                if type_id in ["pass","block","reject"]:
                    # Check if our IP version is valid
                    if ipver in ["inet","inet6","any"]:
                        # Check if our protocol is valid
                        if proto in avail_protos:
                            # Check if our source address contains our invert chars (!-?~)
                            if source.startswith(("!","-","?","~")):
                                invert_src = True    # Assign our invert source bool to True for use in our function
                                source = source.strip("!-?~")    # Remove the ! from our source address
                            # Check if our source includes a CIDR
                            src_bit = "32"  # Assign a default bit count
                            if "/" in source:
                                src_cidr_list = source.split("/")    # Split our CIDR into a list containing the address and bitmask
                                if len(src_cidr_list) == 2 and src_cidr_list[1].isdigit():
                                    # Check if our bitmask is within range
                                    if 1 <= int(src_cidr_list[1]) <= 32:
                                        src_bit = src_cidr_list[1]    # Save our bitmask
                                        source = src_cidr_list[0]    # Save our address
                                    # If our bitmask is invalid
                                    else:
                                        print(get_exit_message("invalid_bitmask", pfsense_server, pfsense_action, src_cidr_list[1], ""))
                                        sys.exit(1)
                            # Check that our source IP is valid
                            if validate_ip(source):
                                # Check if our dest address contains our invert char (!)
                                if dest.startswith(("!","-","?","~")):
                                    invert_dst = True    # Assign our invert dest bool to True for use in our function
                                    dest = dest.strip("!-?~")    # Remove the ! from our dest address
                                # Check if our dest includes a CIDR
                                dst_bit = "32"  # Assign a default bit count
                                if "/" in dest:
                                    dst_cidr_list = dest.split("/")    # Split our CIDR into a list containing the address and bitmask
                                    if len(dst_cidr_list) == 2 and dst_cidr_list[1].isdigit():
                                        # Check if our bitmask is within range
                                        if 1 <= int(dst_cidr_list[1]) <= 32:
                                            dst_bit = dst_cidr_list[1]    # Save our bitmask
                                            dest = dst_cidr_list[0]    # Save our address
                                        # If our bitmask is invalid
                                        else:
                                            print(get_exit_message("invalid_bitmask", pfsense_server, pfsense_action, dst_cidr_list[1], ""))
                                            sys.exit(1)
                                # Check if our dest IP is valid
                                if validate_ip(dest):
                                    # Check that our log is valid
                                    if log in ["yes",""]:
                                        # Run our function to add the rule
                                        add_rule_ec = add_firewall_rule(pfsense_server, user, key, iface, type_id, ipver, proto, invert_src, source, src_bit, source_port, invert_dst, dest, dst_bit, dest_port, gw, descr, log_bool, pos, no_port)
                                        print(get_exit_message(add_rule_ec, pfsense_server, pfsense_action, iface, ""))
                                        sys.exit(add_rule_ec)
                                    # If our log is invalid
                                    else:
                                        print(get_exit_message("invalid_log", pfsense_server, pfsense_action, log, ""))
                                        sys.exit()
                                # If our destination IP is invalid
                                else:
                                    print(get_exit_message("invalid_dest", pfsense_server, pfsense_action, dest, ""))
                            # If our source IP is invalid
                            else:
                                print(get_exit_message("invalid_source", pfsense_server, pfsense_action, source, ""))
                                sys.exit(1)
                        # If our protocol is invalid
                        else:
                            print(get_exit_message("invalid_protocol", pfsense_server, pfsense_action, proto, ",".join(avail_protos)))
                            sys.exit(1)
                    # If our IP version is invalid
                    else:
                        print(get_exit_message("invalid_ipver", pfsense_server, pfsense_action, ipver, ""))
                        sys.exit(1)
                # If our rule type is invalid
                else:
                    print(get_exit_message("invalid_type", pfsense_server, pfsense_action, type_id, ""))
                    sys.exit(1)

            # Assign functions for flag --del-rule
            elif pfsense_action == "--del-rule":
                # Action variables
                iface = third_arg if len(sys.argv) > 3 else input("Interface: ")    # Save our users interface input, or prompt for input if none
                rule_id = filter_input(fourth_arg) if len(sys.argv) > 4 else input("Rule ID: ")    # Save our users rule ID input, or prompt for input if none
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                no_confirm = True if "--force" in sys.argv else False    # Track if user wants to remove the rule without user confirmation beforehand (option --force)
                # INPUT VALIDATION
                if rule_id.isdigit():
                    # Ask user to confirm deletion if not requested otherwise
                    if not no_confirm:
                        usr_con = input("WARNING: Firewall rule deletions cannot be undone.\nAre you sure you would like to remove firewall rule ID `" + rule_id + "` from " + iface + "? [y/n]")
                        if usr_con.lower() != "y":
                            sys.exit(0)
                    # Run our deletion command
                    rule_del = del_firewall_rule(pfsense_server, user, key, iface, rule_id)
                    print(get_exit_message(rule_del, pfsense_server, pfsense_action, iface, rule_id))
                    sys.exit(rule_del)
                # If our rule ID is invalid
                else:
                    print(get_exit_message("invalid_id", pfsense_server, pfsense_action, rule_id, ""))
                    sys.exit()

            # Assign functions for flag --read-aliases
            elif pfsense_action == "--read-aliases":
                # Action Variables
                alias_filter = third_arg    # Assign our filter argument to the third slot
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                get_alias_data = get_firewall_aliases(pfsense_server, user, key)    # Get our alias data dictionary
                # Check that our exit code was good
                if get_alias_data["ec"] == 0:
                    # If user wants to display all info, print in YAML like format
                    if alias_filter.upper() in ("-A", "--ALL"):
                        # Print our alias values
                        for key,value in get_alias_data["aliases"].items():
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
                    elif alias_filter.startswith(("--name=","-n=")):
                        alias_scope = alias_filter.replace("--name=", "").replace("-n=", "")    # Remove expected argument values to determine our VLAN scope
                        # Print our alias values
                        if alias_scope in get_alias_data["aliases"]:
                            print("- name: " + get_alias_data["aliases"][alias_scope]["name"])
                            print("  description: \"" + get_alias_data["aliases"][alias_scope]["descr"] + "\"")
                            print("  type: " + get_alias_data["aliases"][alias_scope]["type"])
                            print("  entries:")
                            # Loop through entries and print their values
                            for entryKey,entryValue in get_alias_data["aliases"][alias_scope]["entries"].items():
                                print("    id: " + str(entryValue["id"]))
                                print("      value: " + entryValue["value"])
                                print("      subnet: " + entryValue["subnet"]) if entryValue["subnet"] != "0" else None
                                print("      description: \"" + entryValue["descr"] + "\"")
                    # If user wants to print the JSON output
                    elif alias_filter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(get_alias_data["aliases"]))   # Print our JSON data
                    # Check if JSON mode was selected
                    elif alias_filter.startswith("-j=") or alias_filter.startswith("--json="):
                        json_path = alias_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        json_name = "pf-readaliases-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(json_path):
                            # Open an export file and save our data
                            json_exported = export_json(get_alias_data["aliases"], json_path, json_name)
                            # Check if the file now exists
                            if json_exported:
                                print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                            else:
                                print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                            sys.exit(1)
                    # If unknown filter was given
                    else:
                        print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, alias_filter, ""))
                # If non-zero exit code was received from get_firewall_aliases()
                else:
                    print(get_exit_message(get_alias_data["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(get_alias_data["ec"])

            # Assign functions for flag --modify-alias
            elif pfsense_action == "--modify-alias":
                alias_name = third_arg    # Assign our thirdArgument to alias_name which will be used to search for existing aliases
                alias_value = fourth_arg    # Assign our fourthArgument to alias_value which will be our new entry values
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Check that we have our required arguments
                if alias_name is not None and alias_value is not None:
                    alias_modded = modify_firewall_alias(pfsense_server, user, key, alias_name, alias_value)    # Assign alias_modded which will be used to track errors
                    print(get_exit_message(alias_modded, pfsense_server, pfsense_action, alias_name, ""))
                    sys.exit(alias_modded)
                # Otherwise, print error containing correct syntax
                else:
                    print("Error: Invalid syntax - `pfsense-automator <pfSense IP or FQDN> --modify-alias <alias name> <alias values>`")
                    sys.exit(1)

            # Assign functions for flag --read-virtual-ip
            elif pfsense_action == "--read-virtual-ips":
                # Action variables
                vip_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                vip_table = get_virtual_ips(pfsense_server, user, key)    # Get our virtual IP configuration
                id_head = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                subnet_head = structure_whitespace("SUBNET", 20, "-", True) + " "    # Format our subnet header value
                type_head = structure_whitespace("TYPE", 10, "-", True) + " "    # Format our type header value
                iface_head = structure_whitespace("INTERFACE", 15, "-", True) + " "    # Format our interface header value
                descr_head = structure_whitespace("DESCRIPTION", 45, "-", True) + " "    # Format our description header value
                header = id_head + subnet_head + type_head + iface_head + descr_head    # Format our print header
                # Check that we did not receive an error pulling the data
                if vip_table["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 0    # Assign a loop counter
                    for key,value in vip_table["virtual_ips"].items():
                        id_num = structure_whitespace(str(key), 5, " ", True) + " "    # Get our entry number
                        subnet = structure_whitespace(value["subnet"] + "/" + value["subnet_bits"], 20, " ", True) + " "    # Get our subnet in CIDR form
                        type_id = structure_whitespace(value["type"], 10, " ", True) + " "    # Get our type value
                        iface = structure_whitespace(value["interface"], 15, " ", True) + " "    # Get our interface value
                        descr = structure_whitespace(value["descr"], 45, " ", True) + " "    # Get our description value
                        # Check if user passed in the ALL filter
                        if vip_filter.upper() in ["-A", "--ALL"]:
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            print(id_num + subnet + type_id + iface + descr)    # Print our data values
                        # Check if user wants to filter by interface
                        elif vip_filter.startswith(("-i=","--iface=")):
                            iface_exp = vip_filter.replace("-i=","").replace("--iface","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if value["interface"].startswith(iface_exp):
                                print(id_num + subnet + type_id + iface + descr)    # Print our data values
                        # Check if user wants to filter by type
                        elif vip_filter.startswith(("-t=","--type=")):
                            type_exp = vip_filter.replace("-t=","").replace("--type","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if value["type"] == type_exp:
                                print(id_num + subnet + type_id + iface + descr)    # Print our data values
                         # Check if user wants to filter by subnet
                        elif vip_filter.startswith(("-s=","--subnet=")):
                            subnet_exp = vip_filter.replace("-s=","").replace("--subnet","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if subnet.startswith(subnet_exp):
                                print(id_num + subnet + type_id + iface + descr)    # Print our data values
                        # If user wants to print the JSON output
                        elif vip_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(vip_table["virtual_ips"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif vip_filter.startswith(("--json=", "-j=")):
                            json_path = vip_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readvirtip-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(vip_table["virtual_ips"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perform this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, vip_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we could not pull our virtual IP data
                else:
                    print(get_exit_message(vip_table["ec"], pfsense_server, pfsense_action, "", ""))    # Print error message
                    sys.exit(vip_table["ec"])    # Exit on non-zero

            # Assign functions for flag --add-virtual-ip
            elif pfsense_action == "--add-virtual-ip":
                # Action variables
                vip_modes = ["ipalias","carp","proxyarp","other"]    # Save a list of our available Virtual IP modes
                vip_mode = filter_input(third_arg) if len(sys.argv) > 3 else input("Virtual IP type " + str(vip_modes).replace('\'', "") + ": ")    # Gather user input for virtual IP mode
                vip_iface = filter_input(fourth_arg) if len(sys.argv) > 4 else input("Interface: ")    # Gather user input for virtual IP interface
                vip_subnet = fifth_arg if len(sys.argv) > 5 else input("Virtual IP subnet: ")    # Gather user input for virtual IP subnet
                vip_expand = filter_input(sixth_arg) if len(sys.argv) > 6 else input("Disable IP expansion [yes,no]: ")    # Gather user input for IP expansion option
                vip_passwd = seventh_arg if len(sys.argv) > 7 else None    # If a seventh argument is passed, save it as the vip password
                vip_passwd = getpass.getpass("Virtual IP Password: ") if vip_passwd is None and vip_mode.lower() == "carp" else vip_passwd    # If interactive mode is initiated, prompt user for vip password if mode is carp
                vip_vhid = eighth_arg if len(sys.argv) > 8 else None    # If a eighth argument is passed, save it as the vip vhid
                vip_vhid = input("VHID Group [1-255,auto]: ") if vip_vhid is None and vip_mode.lower() == "carp" else ""    # If interactive mode is initiated, prompt user for vip vhid if mode is carp
                vip_adv_base = ninth_arg if len(sys.argv) > 9 else None    # If a ninth argument is passed, save it as the vip advbase
                vip_adv_base = input("Advertising Base [1-254,default]: ") if vip_adv_base is None and vip_mode.lower() == "carp" else ""    # If interactive mode is initiated, prompt user for vip advbase if mode is carp
                vip_adv_base = "1" if vip_adv_base.lower() == "default" else vip_adv_base    # If user requests default value, assign 1, otherwise retain existing value
                vip_adv_skew = tenth_arg if len(sys.argv) > 10 else None    # If a ninth argument is passed, save it as the vip advskew
                vip_adv_skew = input("Advertising Skew [0-254,default]: ") if vip_adv_skew is None and vip_mode.lower() == "carp" else ""    # If interactive mode is initiated, prompt user for vip advskew if mode is carp
                vip_adv_skew = "0" if vip_adv_skew.lower() == "default" else vip_adv_skew    # If user requests default value, assign 1, otherwise retain existing value
                vip_descr = eleventh_arg if len(sys.argv) > 11 else input("Virtual IP Description: ")    # Get user input for description
                user = thirteenth_arg if twelfth_arg == "-u" and thirteenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = fifteenth_arg if fourteenth_arg == "-p" and fifteenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                existing_vips = get_virtual_ips(pfsense_server, user, key)    # Pull our existing virtual IPs
                existing_ifaces = get_interfaces(pfsense_server, user, key)    # Pull our existing interfaces
                # INPUT VALIDATION
                # Check if our VIP mode is valid
                if vip_mode.lower() in vip_modes:
                    # Check if our interface is valid
                    if_found = False  # Assign a bool to track whether a match was found
                    if vip_iface in existing_ifaces["ifaces"]:
                        if_found = True  # Assign true value to indicate we found a match
                    # If the user did not pass in the interfaces pfid, check our descriptive id and physical id
                    else:
                        # Loop through each interface and check alternate IDs
                        for pf_id,data in existing_ifaces["ifaces"].items():
                            # Check if input matches our physical iface ID
                            if vip_iface == data["id"]:
                                vip_iface = pf_id    # Assign our interface to the PF ID version of this interface
                                if_found = True    # Assign true value to indicate we found a match
                                break    # Break our loop as our match has been found
                            # Check if our input matches our descriptive interface ID
                            elif vip_iface == data["descr"]:
                                vip_iface = pf_id  # Assign our interface to the PF ID version of this interface
                                if_found = True  # Assign true value to indicate we found a match
                                break  # Break our loop as our match has been found
                    # Check if we were able to find our interface using alternate IDs
                    if if_found:
                        # Check if our subnet is valid
                        if "/" in vip_subnet:
                            parse_subnet = vip_subnet.split("/")
                            # Check if our list is an expected size
                            if len(parse_subnet) == 2:
                                vip_ip_addr = parse_subnet[0]    # Our first list item will be our IP address
                                vip_subnet_bits = parse_subnet[1]    # Our second list item will be our subnet bit count
                                # Check if our IP is valid
                                if validate_ip(vip_ip_addr):
                                    # Check if our subnet is valid
                                    if vip_subnet_bits.isdigit():
                                        if 1 <= int(vip_subnet_bits) <= 32:
                                            # Check our vip_expand input
                                            if vip_expand in ["yes","no"]:
                                                vip_expand.replace("no","")    # Remove no from the string as POST requires empty string later on
                                                # Check our vhid input
                                                vhid_valid = False    # Assign a bool to track if our VHID input is valid
                                                # Check if our input is "auto"
                                                if vip_vhid == "auto" or vip_vhid is "":
                                                    vhid_valid = True  # Our value is valid
                                                # Check that our values are valid
                                                elif vip_vhid.isdigit():
                                                    # Check if our integer is within range
                                                    if 1 <= int(vip_vhid) <= 255:
                                                        # Loop through to ensure our value is not already taken
                                                        for id_num,data in existing_vips["virtual_ips"].items():
                                                            # Return error and exit if our vhid value is a duplicate
                                                            if vip_vhid == data["vhid"] and vip_iface == data["interface"]:
                                                                print(get_exit_message("vhid_exists", pfsense_server, pfsense_action, vip_vhid, vip_iface))    # Print error msg
                                                                sys.exit(1)    # Exit on non-zero
                                                        vhid_valid = True    # Our value is valid if it survived the loop
                                                # If our input is not expected, print error msg and exit on non-zero
                                                else:
                                                    print(get_exit_message("invalid_vhid", pfsense_server, pfsense_action, vip_vhid, ""))
                                                    sys.exit(1)
                                                # Check if our vhid_valid is true
                                                if vhid_valid:
                                                    vip_adv_valid = False    # Assign a bool to track if our advertisements are valid
                                                    # Check if our input is None
                                                    if vip_adv_base is "" and vip_adv_skew is "":
                                                        vip_adv_valid = True  # Our input is valid
                                                    # Check if our VHID base and skew advertisements are valid
                                                    elif vip_adv_base.isdigit() and vip_adv_skew.isdigit():
                                                        # Check if our integers are valid
                                                        if 1 <= int(vip_adv_base) <= 254 and 0 <= int(vip_adv_skew) <= 254:
                                                            vip_adv_valid = True    # Our input is valid
                                                        # If our input is invalid
                                                        else:
                                                            print(get_exit_message("invalid_adv", pfsense_server, pfsense_action, vip_adv_base, vip_adv_skew))    # Print error msg
                                                            sys.exit(1)    # Exit on non-zero

                                                    # Check if our input is valid
                                                    if vip_adv_valid:
                                                        # Run our POST function to add the vitrual IP
                                                        post_vip = add_virtual_ip(pfsense_server, user, key, vip_mode, vip_iface, vip_ip_addr, vip_subnet_bits, vip_expand, vip_passwd, vip_vhid, vip_adv_base, vip_adv_skew, vip_descr)
                                                        # Print our exit message and exit on function return code
                                                        print(get_exit_message(post_vip, pfsense_server, pfsense_action, vip_subnet, ""))
                                                        sys.exit(post_vip)
                                            # If our vip_expand option is invalid return error and exit on non-zero
                                            else:
                                                print(get_exit_message("invalid_expand", pfsense_server, pfsense_action, vip_expand, ""))
                                                sys.exit(1)
                                        # If our subnet bit count is out of range
                                        else:
                                            print(get_exit_message("invalid_subnet", pfsense_server, pfsense_action, vip_subnet, ""))    # Print error msg
                                            sys.exit(1)    # Exit on non-zero
                                    # If our subnet bit count is invalid
                                    else:
                                        print(get_exit_message("invalid_subnet", pfsense_server, pfsense_action, vip_subnet, ""))    # Print error msg
                                        sys.exit(1)    # Exit on non-zero
                                # If our IP section of our CIDR is invalid
                                else:
                                    print(get_exit_message("invalid_subnet", pfsense_server, pfsense_action, vip_subnet, ""))    # Print error msg
                                    sys.exit(1)    # Exit on non-zero
                            # If our CIDR could not be split correctly
                            else:
                                print(get_exit_message("invalid_subnet", pfsense_server, pfsense_action, vip_subnet, ""))    # Print error msg
                                sys.exit(1)    # Exit on non-zero
                        # If our CIDR is invalid
                        else:
                            print(get_exit_message("invalid_subnet", pfsense_server, pfsense_action, vip_subnet, ""))    # Print error msg
                            sys.exit(1)    # Exit on non-zero
                    # If we did not find a match, return error and exit on non-zero
                    else:
                        print(get_exit_message("invalid_iface", pfsense_server, pfsense_action, vip_iface, ""))
                        sys.exit(1)
                # If our mode is invalid
                else:
                    print(get_exit_message("invalid_mode", pfsense_server, pfsense_action, vip_mode, ""))
                    sys.exit(1)
            # Assign functions for flag --read-sslcert
            elif pfsense_action == "--read-sslcerts":
                verbosity = third_arg    # Assign our verbosity mode to thirdArgs value
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                get_cert_data = get_ssl_certs(pfsense_server, user, key)    # Save the function output dict for use later
                # Check that we did not receive an error
                if get_cert_data["ec"] == 0:
                    # Check if data was returned
                    if len(get_cert_data["certs"]) > 0:
                        # Check if JSON mode was selected
                        if verbosity.startswith("-j=") or verbosity.startswith("--json="):
                            json_path = verbosity.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readsslcerts-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(get_cert_data["certs"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If user wants to print the JSON output
                        elif verbosity.lower() in ("--read-json", "-rj"):
                            print(json.dumps(get_cert_data["certs"]))   # Print our JSON data
                        # If JSON mode was not selected
                        else:
                            # Format header values
                            id_head = structure_whitespace("#", 3, "-", False) + " "    # Format our ID header value
                            name_head = structure_whitespace("NAME", 37, "-", True) + " "    # Format our name header value
                            isr_head = structure_whitespace("ISSUER", 11, "-", True) + " "    # Format our issuer header value
                            cn_head = structure_whitespace("CN", 25, "-", True) + " "    # Format our CN header value
                            start_head = structure_whitespace("VALID FROM", 25, "-", True) + " "    # Format our start date header value
                            exp_head = structure_whitespace("VALID UNTIL", 25, "-", True) + " "    # Format our expiration date header value
                            serial_head = structure_whitespace("SERIAL", 30, "-", True) + " "    # Format our serial header value
                            iu_head = "IN USE"    # Format our certificate in use header value
                            # Format header
                            if verbosity == "-v":
                                print(id_head + name_head + isr_head + cn_head + start_head + exp_head + serial_head + iu_head)
                                #print(structure_whitespace("#", 3, "-", False) + " " + structure_whitespace("NAME", 37, "-", True) + " " + structure_whitespace("ISSUER", 11, "-", True) + " " + structure_whitespace("CN", 25, "-", True) + " " + structure_whitespace("VALID FROM", 25, "-", True) + " " + structure_whitespace("VALID UNTIL", 25, "-", True) + " " + structure_whitespace("SERIAL", 30, "-", True) + " " + "IN USE")
                            else:
                                print(id_head + name_head + isr_head + cn_head + exp_head + iu_head)
                                #print(structure_whitespace("#", 3, "-", False) + " " + structure_whitespace("NAME", 37, "-", True) + " " + structure_whitespace("ISSUER", 11, "-", True) + " " + structure_whitespace("CN", 25, "-", True) + " " + structure_whitespace("VALID UNTIL", 25, "-", True) + " " + "IN USE")
                            # For each certificate found in the list, print the information
                            for key,value in get_cert_data["certs"].items():
                                id_num = structure_whitespace(str(key), 3, " ", False) + " "   # Set our cert ID to the key value
                                name = structure_whitespace(value["name"], 37, " ", False) + " "    # Set name to the name dict value
                                isr = structure_whitespace(value["issuer"], 11, " ", True) + " "    # Set name to the issuer dict value
                                cn = structure_whitespace(value["cn"], 25, " ", True) + " "    # Set name to the cn dict value
                                start = structure_whitespace(value["start"], 25, " ", True) + " "    # Set name to the start date dict value
                                exp = structure_whitespace(value["expire"], 25, " ", True) + " "    # Set name to the expiration date dict value
                                srl = structure_whitespace(value["serial"], 30, " ", True) + " "    # Set name to the start date dict value
                                iu = structure_whitespace("ACTIVE", 6, " ", False) if value["active"] else ""    # Set the inuse keyword if the cert is in use
                                # Check if verbose mode was selected
                                if verbosity == "-v" or verbosity == "--verbose":
                                    print(id_num + name + isr + cn + start + exp + srl + iu)
                                # If no specific mode was specified assume the default
                                else:
                                    print(id_num + name + isr + cn + exp + iu)
                    # Print error if no data was returned and exit with ec 1
                    else:
                        print(get_exit_message("read_err", "", pfsense_action, "", ""))
                        sys.exit(1)
                # If we did receive an error, print our error message and exit on that exit code
                else:
                    print(get_exit_message(get_cert_data["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(get_cert_data["ec"])

            # Assign functions for flag --modify-alias
            elif pfsense_action == "--set-wc-sslcert":
                cert_name = third_arg
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                set_wc_response = set_wc_certificate(pfsense_server, user, key, cert_name)    # Save the function output list for use later
                # Check for error codes and print confirmation accordingly
                # If success code is returned, print success message
                print(get_exit_message(set_wc_response, pfsense_server, pfsense_action, cert_name, ""))
                sys.exit(set_wc_response)
            # Assign functions for flag --add-vlan
            elif pfsense_action == "--add-vlan":
                # Action Varibles
                interface = filter_input(third_arg) if third_arg is not None else input("Interface ID: ")    # Get our interface argument or prompt for input if missing
                vlan_id = filter_input(fourth_arg) if fourth_arg is not None else input("VLAN ID [1-4094]: ")    # Get our vlan tag argument or prompt for input if missing
                priority = filter_input(fifth_arg) if fifth_arg is not None else input("VLAN priority [0-7]: ")    # Get our vlan priority argument or prompt for input if missing
                descr = sixth_arg if sixth_arg is not None else input("Description [optional]: ")    # Get our vlan description argument or prompt for input if missing
                user = eighth_arg if seventh_arg == "-u" and eighth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = tenth_arg if ninth_arg == "-p" and tenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                priority = "" if priority.upper() == "DEFAULT" else priority    # Assign a default priority if requested
                descr = "Auto-added by " + user + " on " + PfaVar.local_hostname if descr.upper() == "DEFAULT" else descr    # Assign a default description if requested
                # Try to convert number strings to integers for conditional checks
                try:
                    vlan_id_int = int(vlan_id)
                except ValueError:
                    vlan_id_int = 0    # On error, assign an integer value that is out of range (1-4094)
                try:
                    priority_int = int(priority)
                except ValueError:
                    priority_int = 0    # On error, assign an integer value that is out of range (0-7)
                # Check our VLAN tag input
                if 1 <= vlan_id_int <= 4094:
                    # Check our VLAN priority input
                    if 0 <= priority_int <= 7:
                        # Run our function to add VLAN
                        add_vlan_ec = add_vlan_id(pfsense_server, user, key, interface, vlan_id, priority, descr)
                        # Print our exit message
                        print(get_exit_message(add_vlan_ec, pfsense_server, pfsense_action, vlan_id, interface))
                    # If our VLAN priority is out of range
                    else:
                        print(get_exit_message("invalid_priority", pfsense_server, pfsense_action, priority, ""))
                # If our VLAN tag is out range
                else:
                    print(get_exit_message("invalid_vlan", pfsense_server, pfsense_action, vlan_id, ""))
                    sys.exit(1)    # Exit on non-zero

            # Assign functions for --run-shell-cmd
            elif pfsense_action == "--run-shell-cmd":
                # Action variables
                shell_cmd = third_arg if len(sys.argv) > 3 else None    # Save our shell input if inline mode, otherwise indicate None for interactive shell
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                v_shell_timeout = 180    # Set the amount of time before our virtual shell session times out
                # INTERACTIVE MODE/VIRTUAL SHELL
                if shell_cmd is None or shell_cmd.lower() == "virtualshell":
                    if check_auth(pfsense_server, user, key):
                        print("---Virtual shell established---")
                        # Loop input to simulate an interactive shell
                        while True:
                            start_time = time.time()    # Track the time when the loop starts
                            cmd = input(user + "@" + pfsense_server + ":/usr/local/www $ ")    # Accept shell command inputs
                            end_time = time.time()    # Track the time after input was received
                            elapsed_time = end_time - start_time    # Determine the elapsed time
                            # Check if user typed "close" indicating they wish to end the virtual shell
                            if cmd.lower() in ["close","exit","quit"]:
                                print("---Virtual shell terminated---")
                                sys.exit(0)
                            # Check if our virtual session has timed out
                            elif elapsed_time > v_shell_timeout or 0 > elapsed_time:
                                print("---Virtual shell timeout---")
                                sys.exit(0)
                            # If input is valid, submit the command to pfSense
                            else:
                                cmd_exec = get_shell_output(pfsense_server, user, key, cmd)    # Attempt to execute our command
                                # Check if our command executed successfully, if so print our response and decode HTML entities
                                if cmd_exec["ec"] == 0:
                                    print(cmd_exec["shell_output"])
                                # If our command was not successful, print error
                                else:
                                    print(get_exit_message(2, pfsense_server, pfsense_action, cmd, ""))
                    # If authentication failed, print error and exit on non-zero
                    else:
                        print(get_exit_message(3, pfsense_server, pfsense_action, "", ""))
                        sys.exit(3)
                # INLINE MODE/SINGLE CMD
                else:
                    cmd_exec = get_shell_output(pfsense_server, user, key, shell_cmd)    # Run our command
                    # Check if our command ran successfully, if so print our output
                    if cmd_exec["ec"] == 0:
                        print(cmd_exec["shell_output"])
                        sys.exit(0)
                    # If our command did not run successfully, print our error and exit on non-zero
                    else:
                        print(get_exit_message(cmd_exec["ec"], pfsense_server, pfsense_action, shell_cmd, ""))
                        sys.exit(cmd_exec["ec"])

            # Assign functions for flag --read-carp-status
            elif pfsense_action == "--read-carp-status":
                # Action variables
                carp_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                carp_status = get_status_carp(pfsense_server, user, key)    # Pull our CARP status dictionary
                id_header = structure_whitespace("ID",5,"-",True) + " "    # Format our ID header
                vip_header = structure_whitespace("VIRTUAL IP",20,"-",True) + " "    # Format our virtual IP header
                status_header = structure_whitespace("STATUS",10,"-",True) + " "    # Format our status header
                iface_header = structure_whitespace("INTERFACE",12,"-",True) + " "    # Format our interface header
                vhid_header = structure_whitespace("VHID",12,"-",True) + " "    # Format our VHID header
                header = id_header + vip_header + iface_header + vhid_header + status_header    # Concentrate our header string
                # Check that we did not recieve an error pulling the CARP status
                if carp_status["ec"] == 0:
                    # If user passes in nodes filter, print all pfsync node IDs
                    if carp_filter.lower() in ["--nodes","-n"]:
                        print("PFSYNC NODES")    # Print our pfsync nodes
                        print("------------")
                        # Loop through each value in our list
                        for node in carp_status["carp"]["pfsync_nodes"]:
                            print(node)    # Print our node ID
                    # If user passes in filter general or all
                    elif carp_filter.lower() in ["--general","-g"]:
                        mm_status = "enabled" if carp_status["carp"]["maintenance_mode"] else "disabled"    # If maintenance mode is true, set string to "enabled" otherwise "disabled"
                        print(structure_whitespace("CARP STATUS",37,"-",True))    # Print CARP STATUS header
                        print(structure_whitespace("Status:",27," ",False) + carp_status["carp"]["status"])    # Print our status
                        print(structure_whitespace("Maintenance Mode:",27," ",False) + mm_status)    # Print our status
                    # If not either of these options, explore further filters
                    else:
                        # Loop through our CARP interfaces and parse their values, print as needed
                        counter = 0   # Create a loop counter
                        for id_num,data in carp_status["carp"]["carp_interfaces"].items():
                            carp_id = structure_whitespace(str(id_num),5," ",True) + " "    # Format our CARP ID
                            virt_ip = structure_whitespace(data["cidr"],20," ", True) + " "   # Format our virtual IP data
                            status = structure_whitespace(data["status"],10," ",True) + " "    # Format our status data
                            iface = structure_whitespace(data["interface"],12," ",True) + " "    # Format our interface data
                            vhid = structure_whitespace(data["vhid"],12," ",True) + " "    # Format our vhid data
                            carp_data = carp_id + virt_ip + iface + vhid + status   # Combine our strings into our dataset
                            # If user has select all filter
                            if carp_filter.lower() in ["--all","-a"]:
                                mm_status = "enabled" if carp_status["carp"]["maintenance_mode"] else "disabled"    # If maintenance mode is true, set string to "enabled" otherwise "disabled"
                                print(structure_whitespace("CARP STATUS",37,"-",True)) if counter == 0 else None    # Print CARP STATUS header
                                print(structure_whitespace("Status:",27," ",False) + carp_status["carp"]["status"]) if counter == 0 else None    # Print our status
                                print(structure_whitespace("Maintenance Mode:",27," ",False) + mm_status + "\n") if counter == 0 else None    # Print our status
                                print(header) if counter == 0 else None   # Print our header
                                print(carp_data)    # Print our dataset
                            # If user has selected subnet filter
                            elif carp_filter.startswith(("--subnet=","-s=")):
                                subnet_exp = carp_filter.replace("-s=","").replace("--subnet=","")    # Remove our filter identifier to capture our subnet expression
                                # Check if our subnet matches our expression
                                if data["cidr"].startswith(subnet_exp) or subnet_exp == "*":
                                    print(header) if counter == 0 else None  # Print our header
                                    print(carp_data)    # Print our dataset
                            # If user has selected interface filter
                            elif carp_filter.startswith(("--iface=","-i=")):
                                iface_exp = carp_filter.replace("-iface=","").replace("-i=","")    # Remove our filter identifier to capture our iface expression
                                # Check if our iface matches our expression
                                if data["interface"].lower() == iface_exp.lower():
                                    print(header) if counter == 0 else None  # Print our header
                                    print(carp_data)    # Print our dataset
                            # If user has selected vhid_exp filter
                            elif carp_filter.startswith(("--vhid=","-v=")):
                                vhid_exp = carp_filter.replace("--vhid=","").replace("-v=","")    # Remove our filter identifier to capture our vhid_exp expression
                                # Check if our vhid_exp matches our expression
                                if data["vhid"] == vhid_exp:
                                    print(header) if counter == 0 else None  # Print our header
                                    print(carp_data)    # Print our dataset
                            # If user wants to print the JSON output
                            elif carp_filter.lower() in ("--read-json", "-rj"):
                                print(json.dumps(carp_status["carp"]))   # Print our JSON data
                                break
                            # If we want to export values as JSON
                            elif carp_filter.startswith(("--json=", "-j=")):
                                json_path = carp_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                                json_name = "pf-readcarp-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                                # Check if JSON path exists
                                if os.path.exists(json_path):
                                    # Open an export file and save our data
                                    json_exported = export_json(carp_status["carp"], json_path, json_name)
                                    # Check if the file now exists
                                    if json_exported:
                                        print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                        break    # Break the loop as we only need to perfrom this function once
                                    else:
                                        print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                        sys.exit(1)
                                # Print error if path does not exist
                                else:
                                    print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # If none of these filters match, return error
                            else:
                                print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, carp_filter, ""))
                                sys.exit(1)
                            # Increase our counter
                            counter = counter + 1
                # If we did encounter an error pulling our carp status
                else:
                    print(get_exit_message(carp_status["ec"], pfsense_server, pfsense_action, "", ""))    # Print our error message
                    sys.exit(carp_status["ec"])    # Exit on our non-zero code

            # Assign functions for flag --set-carp-maintenance
            elif pfsense_action == "--set-carp-maintenance":
                # Action variables
                enable_toggle = filter_input(third_arg) if len(sys.argv) > 3 else input("CARP Maintenance Mode [enable,disable]: ")    # Gather our mode toggle from the user either inline or interactively
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                alt_toggle_tense1 = "enabled" if enable_toggle == "enable" else ""    # Create an alternate tense for enabled
                alt_toggle_tense1 = "disabled" if enable_toggle == "disable" else alt_toggle_tense1    # Create an alternate tense for disabled
                alt_toggle_tense2 = "enabling" if enable_toggle == "enable" else ""    # Create an alternate tense for enabling
                alt_toggle_tense2 = "disabling" if enable_toggle == "disable" else alt_toggle_tense2    # Create an alternate tense disabling
                # INPUT VALIDATION
                # Check that our toggle is valid
                if enable_toggle.lower() in ["enable","disable"]:
                    enable_toggle = True if enable_toggle.lower() == 'enable' else False    # Switch our string keywords to booleans
                    # Run our function to POST maintenance mode setting
                    set_carp_mode = set_carp_maintenance(pfsense_server, user, key, enable_toggle)    # Save our function exit code
                    print(get_exit_message(set_carp_mode, pfsense_server, pfsense_action, alt_toggle_tense1, alt_toggle_tense2))    # Print our error message
                    sys.exit(set_carp_mode)    # Exit on our function return code
                # If our enable toggle is invalid
                else:
                    print(get_exit_message("invalid_toggle", pfsense_server, pfsense_action, enable_toggle, ""))
                    sys.exit(1)

            # Assign functions for flag --read-available-pkgs
            elif pfsense_action == "--read-available-pkgs":
                # Action variables
                pkg_filter = third_arg   # Save our third argument as our read filter
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                available_pkgs = get_available_packages(pfsense_server, user, key)    # Pull our pkg configuration
                id_head = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                pkg_head = structure_whitespace("PACKAGE", 25, "-", True) + " "    # Format our package header header value
                version_head = structure_whitespace("VERSION", 15, "-", True) + " "    # Format our version header value
                status_head = structure_whitespace("STATUS", 15, "-", True) + " "    # Format our version header value
                header = id_head + pkg_head + version_head + status_head    # Piece our header together
                # Check that we did not receive an error pulling our data
                if available_pkgs["ec"] == 0:
                    # Loop through each item in our dictionary
                    counter = 1    # Assign a loop counter
                    for key,value in available_pkgs["available_pkgs"].items():
                        # Format our data to line up with headers
                        id_num = structure_whitespace(str(counter), 5, " ", True) + " "    # Get our entry number
                        pkg = structure_whitespace(value["name"], 25, " ", True)  + " "   # Get our pkg name
                        version = structure_whitespace(value["version"], 15, " ", True) + " "    # Get our pkg version
                        installed = structure_whitespace("Installed" if value["installed"] else "Not installed", 15, " ", True) + " "    # Get our pkg version
                        data = id_num + pkg + version + installed
                        # Check user's filter input
                        if pkg_filter.lower() in ["-a", "--all"]:
                            print(header) if counter == 1 else None
                            print(data)
                        elif pkg_filter.lower().startswith(("--name=","-n=")):
                            pkg_exp = pkg_filter.replace("--name=","").replace("-n=","")    # Remove our filter identifier to capture our interface expression
                            # Check if our expression matches any packages
                            print(header) if counter == 1 else None
                            if pkg_exp in value["name"]:
                                print(data)
                        # If user wants to print the JSON output
                        elif pkg_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(available_pkgs["available_pkgs"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif pkg_filter.startswith(("--json=", "-j=")):
                            json_path = pkg_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readavailpkgs-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(available_pkgs["available_pkgs"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, pkg_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        # Increase our counter
                        counter = counter + 1
                # If we encountered an error pulling our pkg data
                else:
                    print(get_exit_message(available_pkgs["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(available_pkgs["ec"])

            # Assign functions for flag --read-installed-pkgs
            elif pfsense_action == "--read-installed-pkgs":
                # Action variables
                pkg_filter = third_arg    # Save our third argument as our read filter
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                installed_pkgs = get_installed_packages(pfsense_server, user, key)    # Pull our pkg configuration
                id_head = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                pkg_head = structure_whitespace("PACKAGE", 25, "-", True) + " "    # Format our package header header value
                version_head = structure_whitespace("VERSION", 15, "-", True) + " "    # Format our version header value
                header = id_head + pkg_head + version_head    # Piece our header together
                # Check that we did not receive an error pulling our data
                if installed_pkgs["ec"] == 0:
                    # Loop through each item in our dictionary
                    counter = 1    # Assign a loop counter
                    for key,value in installed_pkgs["installed_pkgs"].items():
                        # Format our data to line up with headers
                        id_num = structure_whitespace(str(counter), 5, " ", True) + " "    # Get our entry number
                        pkg = structure_whitespace(value["name"], 25, " ", True)  + " "   # Get our pkg name
                        version = structure_whitespace(value["version"], 15, " ", True) + " "    # Get our pkg version
                        data = id_num + pkg + version
                        # Check user's filter input
                        if pkg_filter.lower() in ["-a", "--all"]:
                            print(header) if counter == 1 else None
                            print(data)
                        elif pkg_filter.lower().startswith(("--name=","-n=")):
                            pkg_exp = pkg_filter.replace("--name=","").replace("-n=","")    # Remove our filter identifier to capture our interface expression
                            # Check if our expression matches any packages
                            print(header) if counter == 1 else None
                            if pkg_exp in value["name"]:
                                print(data)
                        # If user wants to print the JSON output
                        elif pkg_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(installed_pkgs["installed_pkgs"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif pkg_filter.startswith(("--json=", "-j=")):
                            json_path = pkg_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readpkgs-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(installed_pkgs["installed_pkgs"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, pkg_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        # Increase our counter
                        counter = counter + 1
                # If we encountered an error pulling our pkg data
                else:
                    print(get_exit_message(installed_pkgs["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(installed_pkgs["ec"])

            # Assign functions for flag --add-pkg
            elif pfsense_action == "--add-pkg":
                # Action variables
                pkg_to_add = third_arg if len(sys.argv) > 3 else input("Add package: ")    # Get our user input inline, if not prompt user for input
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Run our add pkg function, print our exit message and exit on code
                pkg_added = add_package(pfsense_server, user, key, pkg_to_add)
                print(get_exit_message(pkg_added, pfsense_server, pfsense_action, pkg_to_add, ""))
                sys.exit(pkg_added)

             # Assign functions for flag --del-pkg
            elif pfsense_action == "--del-pkg":
                # Action variables
                pkg_to_del = third_arg if len(sys.argv) > 3 else input("Delete package: ")    # Get our user input inline, if not prompt user for input
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Run our add pkg function, print our exit message and exit on code
                pkg_deleted = del_package(pfsense_server, user, key, pkg_to_del)
                print(get_exit_message(pkg_deleted, pfsense_server, pfsense_action, pkg_to_del, ""))
                sys.exit(pkg_deleted)

            # Assign functions for flag --read-arp
            elif pfsense_action == "--read-arp":
                arp_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                arp_table = get_arp_table(pfsense_server, user, key)
                id_head = structure_whitespace("#", 5, "-", True) + " "    # Format our ID header value
                interface_head = structure_whitespace("INTERFACE", 15, "-", True) + " "    # Format our interface header header value
                ip_head = structure_whitespace("IP", 15, "-", True) + " "    # Format our ip header value
                host_head = structure_whitespace("HOSTNAME", 20, "-", True) + " "    # Format our host header value
                mac_addr_head = structure_whitespace("MAC ADDR", 20, "-", True) + " "    # Format our mac address header value
                vendor_head = structure_whitespace("MAC VENDOR", 12, "-", True) + " "    # Format our mac vendor header value
                expire_head = structure_whitespace("EXPIRES", 12, "-", True) + " "    # Format our expiration header value
                link_head = structure_whitespace("LINK", 8, "-", True) + " "    # Format our link type header value
                header = id_head + interface_head + ip_head + host_head + mac_addr_head + vendor_head + expire_head + link_head   # Format our print header
                # Check that we did not receive an error pulling the data
                if arp_table["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 0    # Assign a loop counter
                    for key,value in arp_table["arp"].items():
                        id_num = structure_whitespace(str(key), 5, " ", True) + " "    # Get our entry number
                        interface = structure_whitespace(value["interface"], 15, " ", True)  + " "   # Get our interface ID
                        ip = structure_whitespace(value["ip"], 15, " ", True) + " "    # Get our IP
                        hostname = structure_whitespace(value["hostname"], 20, " ", True) + " "    # Get our hostnames
                        mac_addr = structure_whitespace(value["mac_addr"], 20, " ", True) + " "    # Get our MAC address level
                        mac_vendor = structure_whitespace(value["mac_vendor"], 12, " ", True) + " "   # Get our MAC vendor
                        expires = structure_whitespace(value["expires"], 12, " ", True) + " "   # Get our expiration
                        link = structure_whitespace(value["type"], 8, " ", True) + " "   # Get our link
                        # If we want to return all values
                        if arp_filter.upper() in ["-A", "--ALL"]:
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # Check if user wants to filter by interface
                        elif arp_filter.startswith(("-i=", "--iface=")):
                            iface_exp = arp_filter.replace("-i=","").replace("--iface=","")    # Remove our filter identifier to capture our interface expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our interface expression
                            if value["interface"].startswith(iface_exp):
                                print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # Check if user wants to filter by IP
                        elif arp_filter.startswith(("-p=","--ip=")):
                            ip_exp = arp_filter.replace("-p=","").replace("--ip=","")    # Remove our filter identifier to capture our IP expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our IP expression
                            if value["ip"].startswith(ip_exp):
                                print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # Check if user wants to filter by hostname
                        elif arp_filter.startswith(("-h=","--hostname=")):
                            hostname_exp = arp_filter.replace("-h=","").replace("--hostname=","")    # Remove our filter identifier to capture our hostname expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our hostname expression
                            if value["hostname"].startswith(hostname_exp):
                                print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # Check if user wants to filter by MAC
                        elif arp_filter.startswith(("-m=","--mac=")):
                            mac_exp = arp_filter.replace("-m=","").replace("--mac=","")    # Remove our filter identifier to capture our MAC expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our MAC expression
                            if value["mac_addr"].startswith(mac_exp):
                                print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # Check if user wants to filter by MAC vendor
                        elif arp_filter.startswith(("-v=","--vendor=")):
                            vendor_exp = arp_filter.replace("-v=","").replace("--vendor=","")    # Remove our filter identifier to capture our MAC vendor expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our MAC vendor expression
                            if value["mac_vendor"].startswith(vendor_exp):
                                print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # Check if user wants to filter by link type
                        elif arp_filter.startswith(("-l=","--link=")):
                            vendor_exp = arp_filter.replace("-l=","").replace("--link","")    # Remove our filter identifier to capture our link type expression
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            # Check that our interface matches our link type expression
                            if value["type"].startswith(vendor_exp):
                                print(id_num + interface + ip + hostname + mac_addr + mac_vendor + expires + link)    # Print our data values
                        # If user wants to print the JSON output
                        elif arp_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(arp_table["arp"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif arp_filter.startswith(("--json=", "-j=")):
                            json_path = arp_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readarp-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(arp_table["arp"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, arp_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we received an error, print the error message and exit on non-zero ec
                else:
                    print(get_exit_message(arp_table["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(arp_table["ec"])

            # Assign functions/prcoesses for --read-states
            elif pfsense_action == "--read-states":
                user = fourth_arg if third_arg == "-u" and fourth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixth_arg if fifth_arg == "-p" and sixth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                state_table = get_state_table(pfsense_server, user, key)    # Pull our state table
                # Check if we pulled our table successfully
                if state_table["ec"] == 0:
                    print(state_table["state_table"])
                else:
                    print(get_exit_message(state_table["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(state_table["ec"])

            # Assign functions/processes for --read-hasync
            elif pfsense_action == "--read-hasync":
                # Action variables
                ha_filter = third_arg if len(sys.argv) > 3 else None   # Save our filter input
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                ha_sync_data = get_ha_sync(pfsense_server, user, key)    # Pull our current HA Sync data dictionary
                sync_areas = ["synchronizeusers","synchronizeauthservers","synchronizecerts",
                    "synchronizerules", "synchronizeschedules","synchronizealiases","synchronizenat","synchronizeipsec","synchronizeopenvpn",
                    "synchronizedhcpd","synchronizewol","synchronizestaticroutes","synchronizelb","synchronizevirtualip","synchronizetrafficshaper",
                    "synchronizetrafficshaperlimiter", "synchronizednsforwarder", "synchronizecaptiveportal"]    # Define a list XMLRPC Sync areas
                # Check that we did not encounter an error pulling our HA Sync data
                if ha_sync_data["ec"] == 0:
                    # FORMAT OUR PRINT DATA
                    pf_toggle = "enabled" if ha_sync_data["ha_sync"]["pfsyncenabled"] == "on" else "disabled"    # Change "yes" to enabled
                    pfsync_head = structure_whitespace("--STATE SYNC SETTINGS (PFSYNC)",40,"-",True)    # Fromat our header
                    pfsync_enable = structure_whitespace("Enabled:",30," ",True) + pf_toggle    # Format our enable value
                    pfsync_iface = structure_whitespace("PFSYNC Interface:",30," ",True) + ha_sync_data["ha_sync"]["pfsyncinterface"]    # Format our interface
                    pfsync_pip = structure_whitespace("PFSYNC Peer IP:",30," ",True) + ha_sync_data["ha_sync"]["pfsyncpeerip"]    # Format our peer IP
                    pfsync_data = pfsync_head + "\n" + pfsync_enable + "\n" + pfsync_iface + "\n" + pfsync_pip    # Format our data points together
                    xmlrpc_header = structure_whitespace("--CONFIGURATION SYNC SETTINGS (XMLRPC)", 40, "-", True)    # Fromat our XMLRPC header
                    xmlrpc_ip = structure_whitespace("Sync to IP:",30," ",True) + ha_sync_data["ha_sync"]["synchronizetoip"]    # Format our XMLRPC sync IP
                    xmlrpc_user = structure_whitespace("Remote System Username:",30," ",True) + ha_sync_data["ha_sync"]["username"]    # Format our XMLRPC remote username
                    xmlrpc_opt_str = ""
                    # For each SYNC option enabled, print
                    for so in sync_areas:
                        # Check if option is enabled
                        if ha_sync_data["ha_sync"][so] == "on":
                            xmlrpc_opt_str = xmlrpc_opt_str + "\n  - " + so.replace("synchronize","")
                    xmlrpc_sync_opt = structure_whitespace("Synced options:",30," ",True) + xmlrpc_opt_str   # Format our SYNC options
                    xmlrpc_data = xmlrpc_header + "\n" + xmlrpc_ip + "\n" + xmlrpc_user + "\n" + xmlrpc_sync_opt    # Format our XMLRPC data set
                    # Check if we need to print our PFSYNC data
                    if ha_filter.lower() in ["--all","-a"]:
                        print(pfsync_data)    # Print our PFSYNC data
                        print(xmlrpc_data)    # Print our XMLRPC data
                    elif ha_filter.lower() in ["--pfsync","-p"]:
                        print(pfsync_data)    # Print our PFSYNC data
                    # Check if we need to print our XMLRPC data
                    elif ha_filter.lower() in ["--xmlrpc","-x"]:
                        print(xmlrpc_data)    # Print our XMLRPC data
                    # If user wants to print the JSON output
                    elif ha_filter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(ha_sync_data["ha_sync"]))   # Print our JSON data
                    # If we want to export values as JSON
                    elif ha_filter.startswith(("--json=", "-j=")):
                        json_path = ha_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        json_name = "pf-readhasync-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(json_path):
                            # Open an export file and save our data
                            json_exported = export_json(ha_sync_data["ha_sync"], json_path, json_name)
                            # Check if the file now exists
                            if json_exported:
                                print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                            else:
                                print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                            sys.exit(1)
                    # If our filter did not match any expected filters, return error
                    else:
                        print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, ha_filter, ""))
                        sys.exit(1)
                # If we encountered an error pulling our HA Sync data
                else:
                    print(get_exit_message(ha_sync_data["ec"], pfsense_server, pfsense_action, "", ""))    # Print our error message
                    sys.exit(ha_sync_data["ec"])     # Exit on our non-zero function return code

            # Assign functions/processes for --setup-hasync
            elif pfsense_action == "--setup-hasync":
                # Action variables
                avail_sync_opts = {"synchronizeusers": "", "synchronizeauthservers": "", "synchronizecerts": "",
                                 "synchronizerules": "", "synchronizeschedules": "", "synchronizealiases": "",
                                 "synchronizenat": "", "synchronizeipsec": "", "synchronizeopenvpn": "",
                                 "synchronizedhcpd": "", "synchronizewol": "", "synchronizestaticroutes": "",
                                 "synchronizelb": "", "synchronizevirtualip": "", "synchronizetrafficshaper": "",
                                 "synchronizetrafficshaperlimiter": "", "synchronizednsforwarder": "",
                                 "synchronizecaptiveportal": ""}
                enable_pfsync = filter_input(third_arg) if len(sys.argv) > 3 else input("Enable PFSYNC [enable,disable,default]: ")    # Enable/disable pfsync input
                pfsync_if = filter_input(fourth_arg) if len(sys.argv) > 4 else input("PFSYNC interface: ")    # Assign our pfsync interface input
                pfsync_ip = filter_input(fifth_arg) if len(sys.argv) > 5 else input("PFSYNC Peer IP: ")    # Assign our pfsync peer IP input
                pfsync_ip = "" if pfsync_ip.lower() == "none" else pfsync_ip    # Allow input none as blank string
                xmlsync_ip = filter_input(sixth_arg) if len(sys.argv) > 6 else input("XMLRPC Peer IP: ")    # Assign our xmlrpc IP input
                xmlsync_ip = "" if xmlsync_ip.lower() == "none" else xmlsync_ip    # Asslow input none as blank string
                xmlsync_uname = seventh_arg if len(sys.argv) > 7 else input("XMLRPC Peer Username: ")    # Assing our xmlrpc username input
                xmlsync_pass = eighth_arg if len(sys.argv) > 8 else getpass.getpass("XMLRPC Peer Password: ")     # Asign our xmlrpc password input
                xml_sync_options = ninth_arg + "," if len(sys.argv) > 9 else None     # Assign our xmlrpc sync options
                # If interactive mode was used before passing in sync options, loop through options and have user confirm sync options
                if xml_sync_options is None:
                    for key,value in avail_sync_opts.items():
                        # Loop until we get our expected value
                        while True:
                            # Prompt user for input
                            user_input = input("Synchronize " + key.replace("synchronize","") + " [yes,no,default]: ").lower()
                            # Check that our users input was valid
                            if user_input in ["yes","no","default",""]:
                                user_input = "on" if user_input == "yes" else user_input  # Assume default if empty input
                                user_input = "default" if user_input == "" else user_input    # Assume default if empty input
                                user_input = "" if user_input == "no" else user_input    # Change "no" to blank string, this is how the POST request is formatted
                                avail_sync_opts[key] = user_input    # Assign the new value to our sync options dictionary
                                break    # Break our while loop to move to the next for loop item
                            # Print error if invalid input
                            else:
                                print("Unknown input `" + user_input + "`. Expected `yes`,`no,`default` or blank entry")
                user = eleventh_arg if tenth_arg == "-u" and eleventh_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = thirteenth_arg if twelfth_arg == "-p" and thirteenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check if our enable pfsync argument is valid
                if enable_pfsync in ["enable","disable","yes","no","default"]:
                    enable_pfsync = "on" if enable_pfsync in ["enable","yes"] else enable_pfsync
                    enable_pfsync = "" if enable_pfsync in ["disable","no"] else enable_pfsync
                    # Check if our interface value is valid
                    if_pf_id = find_interface_pfid(pfsense_server, user, key, pfsync_if, None)    # Try to find our pf_id value for this interface
                    # Check if we received an auth error trying to find the pf_id
                    if if_pf_id["ec"] == 0:
                        if if_pf_id["pf_id"] != "":
                            # Check if our pfsync IP is valid
                            if validate_ip(pfsync_ip) or pfsync_ip == "":
                                # Check if our xmlrpc IP is valid
                                if validate_ip(xmlsync_ip) or xmlsync_ip == "":
                                    # Check if our username is valid
                                    if len(xmlsync_uname) >= 1:
                                        # Check if our xmlrpc passwd is valid
                                        if len(xmlsync_pass) >= 1:
                                            # If inline mode was used to pass in sync options, parse them into our dictionary
                                            if xml_sync_options is not None:
                                                user_options = xml_sync_options.split(",")
                                                # Loop through our available options and check for matches
                                                for key,value in avail_sync_opts.items():
                                                    if key.replace("synchronize","") in user_options or "all" in user_options:
                                                        avail_sync_opts[key] = "on"
                                            # Run our setup function, print our return message and exit on return code
                                            setup_ha_sync_ec = setup_hasync(pfsense_server, user, key, enable_pfsync, if_pf_id["pf_id"], pfsync_ip, xmlsync_ip, xmlsync_uname, xmlsync_pass, avail_sync_opts)
                                            print(get_exit_message(setup_ha_sync_ec, pfsense_server, pfsense_action, "", ""))
                                            sys.exit(setup_ha_sync_ec)
                                        # If our XMLRPC passwd is invalid
                                        else:
                                            print(get_exit_message("invalid_passwd", pfsense_server, pfsense_action, xmlsync_pass, ""))
                                            sys.exit(1)
                                    # If our XMLRPC username is invalid
                                    else:
                                        print(get_exit_message("invalid_user", pfsense_server, pfsense_action, xmlsync_uname, ""))
                                        sys.exit(1)
                                # If our xmlrpc IP is invalid
                                else:
                                    print(get_exit_message("invalid_ip", pfsense_server, pfsense_action, "XMLRPC", pfsync_ip))
                                    sys.exit(1)
                            # If our pfsync IP is invalid
                            else:
                                print(get_exit_message("invalid_ip", pfsense_server, pfsense_action, "PFSYNC", pfsync_ip))
                                sys.exit(1)
                        # If our interfcae value is invalid
                        else:
                            print(get_exit_message("invalid_interface", pfsense_server, pfsense_action, pfsync_if, ""))
                            sys.exit(1)
                    # If we received an error trying to find our pf_id
                    else:
                        print(get_exit_message(if_pf_id["ec"], pfsense_server, pfsense_action, "", ""))
                        sys.exit(if_pf_id["ec"])
                # If our enable pfsync argument is invalid
                else:
                    print(get_exit_message("invalid_enable", pfsense_server, pfsense_action, enable_pfsync, ""))    # Print error msg
                    sys.exit(1)

            # Assign functions/processes for --setup-ha-pfsense
            elif pfsense_action == "--setup-hapfsense":
                # Action variables
                backup_node = filter_input(third_arg) if len(sys.argv) > 3 else input("Backup node IP: ")    # Save user input for our backup node's IP address
                carp_ifs_raw = fourth_arg + "," if len(sys.argv) > 4 else None    # Save user input for carp interfaces if passed inline, otherwise indicate None for interactive mode
                carp_ips_raw = fifth_arg + "," if len(sys.argv) > 5 else None    # Save user input for carp IPs if passed inline, otherwise indicate None for interactive mode
                # Format our CARP interfaces and IPs into lists
                carp_ifs = list(filter(None, carp_ifs_raw.split(","))) if carp_ifs_raw is not None else []
                carp_ips = list(filter(None, carp_ips_raw.split(","))) if carp_ips_raw is not None else []
                # Get our CARP interfaces if interactive mode
                if carp_ifs_raw is None:
                    while True:
                        if_input = input("Enter interface to include in HA [blank entry if done]: ").replace(" ","")
                        # Check if input is empty, break if so
                        if if_input == "":
                            break
                        # Add our input to our interface list otherwise
                        else:
                            carp_ifs.append(if_input)
                # Get our CARP interfaces if interactive mode
                if carp_ips_raw is None:
                    for i in carp_ifs:
                        while True:
                            ip_input = input("Enter available IP address on `" + i + "`: ")    # Prompt user to input IP
                            # Check that the IP is valid
                            if validate_ip(ip_input):
                                carp_ips.append(ip_input)    # Append the IP to our list
                                break    # Break our loop to move to the next item
                            else:
                                print("Invalid IP `" + ip_input + "`")
                carp_passwd = sixth_arg if len(sys.argv) > 6 else getpass.getpass("CARP password: ")    # Save our user input for CARP password or prompt user for input
                pfsync_if = seventh_arg if len(sys.argv) > 7 else input("PFSYNC interface: ")    # Save our PFSYNC interface input or prompt user for input if missing
                pfsync_ip = eighth_arg if len(sys.argv) > 8 else input("PFSYNC Peer IP: ")    # Save our PFSYNC IP input or prompt user for input if missing
                user = tenth_arg if ninth_arg == "-u" and tenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = twelfth_arg if eleventh_arg == "-p" and twelfth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check if our backup node is valid and reachable
                if check_remote_port(backup_node, PfaVar.wc_protocol_port):
                    # Check that our HA synced interfaces exist on both MASTER and BACKUP
                    final_carp_ifs = []    # Initialize our final interface list containing the pf ID values
                    for c in carp_ifs:
                        pf_id = find_interface_pfid(pfsense_server, user, key, c, None)    # Find our pfID for this interface on MASTER
                        pf_id_backup = find_interface_pfid(backup_node, user, key, c, None)    # Find our pfID for this interface on BACKUP
                        # Check if our interface exists on MASTER
                        if pf_id["pf_id"] != "" and pf_id["pf_id"] == pf_id_backup["pf_id"]:
                            # Check if our interface exists on BACKUP
                            if pf_id_backup["pf_id"] != "" and pf_id["pf_id"] == pf_id_backup["pf_id"]:
                                final_carp_ifs.append(pf_id["pf_id"])    # Add our PFID to the list
                            else:
                                print(get_exit_message("invalid_backup_if", pfsense_server, pfsense_action, i, backup_node))
                                sys.exit(1)
                        else:
                            print(get_exit_message("invalid_master_if", pfsense_server, pfsense_action, i, ""))
                            sys.exit(1)
                    # Check that each of our IPs are valid
                    for ip in carp_ips:
                        # Print error message and exit on non zero if invalid IP
                        if not validate_ip(ip):
                            print(get_exit_message("invalid_carp_ip", pfsense_server, pfsense_action, ip, ""))
                            sys.exit(1)
                    # Check that our PFSYNC interface exists
                    check_pfsync_if = find_interface_pfid(pfsense_server, user, key, pfsync_if, None)
                    if check_pfsync_if["pf_id"] != "":
                        pfsync_if = check_pfsync_if["pf_id"]
                        # Check if our PFSYNC IP is valid
                        if validate_ip(pfsync_ip):
                            # Run our setup function, display our return message and exit on return code
                            setup_ha_pfsense = setup_hapfsense(pfsense_server, user, key, backup_node, final_carp_ifs, carp_ips, carp_passwd, pfsync_if, pfsync_ip)
                            print(get_exit_message(setup_ha_pfsense, pfsense_server, pfsense_action, "", ""))
                            sys.exit(setup_ha_pfsense)
                        # If our PFSYNC IP is invalid, print error message and exit on non zero
                        else:
                            print(get_exit_message("invalid_pfsync_ip", pfsense_server, pfsense_action, pfsync_ip, ""))
                            sys.exit(1)
                    # If our PFSYNC interface does not exist
                    else:
                        print(get_exit_message("invalid_pfsync_if", pfsense_server, pfsense_action, pfsync_if, ""))
                        sys.exit(1)
                # If we could not communicate with our backup node, print error and exit on non-zero
                else:
                    print(get_exit_message("invalid_backup_ip", pfsense_server, pfsense_action, backup_node, ""))
                    sys.exit(1)

            # Assign functions/processes for --read-xml
            elif pfsense_action == "--read-xml":
                # Action variables
                xml_filter = third_arg if len(sys.argv) > 3 else "read"   # Save our filter to a variable (this sets function to read or save)
                xml_area = filter_input(fourth_arg) if len(sys.argv) > 4 else input("XML Backup Area: ")    # Save our XML backup area
                xml_area_post = "" if xml_area.lower() == "all" else xml_area    # Change our CLI area for all into the POST data value (blank string)
                xml_area_list = ["","aliases","unbound","filter","interfaces","installedpackages","rrddata","cron","syslog","system","sysctl","snmpd","vlans"]    # Assign a list of supported XML areas
                xml_pkg = filter_input(fifth_arg) if len(sys.argv) > 5 else input("Include package data in XML [yes, no]: ")   # Save our nopackage toggle (includes or excludes pkg data from backup)
                xml_rrd = filter_input(sixth_arg) if len(sys.argv) > 6 else input("Include RRD data in XML [yes, no]: ")    # Save our norrddata toggle (includes or excludes rrd data from backup)
                xml_encrypt = filter_input(seventh_arg) if len(sys.argv) > 6 else input("Encrypt XML [yes, no]: ")   # Save our encrypt toggle (enables or disables xml encryption)
                # Determine how to handle encryption passwords
                if len(sys.argv) > 8:
                    xml_encrypt_pass = eighth_arg     # Set an encryption password if encryption is enabled
                elif xml_encrypt in ["encrypt", "yes"]:
                    xml_encrypt_pass = getpass.getpass("Encryption password: ")
                else:
                    xml_encrypt_pass = ""
                user = tenth_arg if ninth_arg == "-u" and tenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = twelfth_arg if eleventh_arg == "-p" and twelfth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our XML area is valid
                if xml_area_post.lower() in xml_area_list:
                    # Check if user wants to skip package data in the backups
                    if xml_pkg in ["skip","exclude","no"]:
                        xml_pkg_post = True
                    elif xml_pkg in ["include","yes"]:
                        xml_pkg_post = False
                    else:
                        print(get_exit_message("invalid_pkg", pfsense_server, pfsense_action, xml_rrd, ""))
                        sys.exit(1)
                    # Check that our RRD value is valid
                    if xml_rrd in ["skip","exclude","no"]:
                        xml_rrd_post = True
                    elif xml_rrd in ["include","yes"]:
                        xml_rrd_post = False
                    else:
                        print(get_exit_message("invalid_rrd", pfsense_server, pfsense_action, xml_rrd, ""))
                        sys.exit(1)
                    # Check if user wants to encrypt the XML
                    if xml_encrypt in ["encrypt", "yes"]:
                        xml_encrypt_post = True
                    elif xml_encrypt in ["default", "no", "noencrypt"]:
                        xml_encrypt_post = False
                    else:
                        print(get_exit_message("invalid_encrypt", pfsense_server, pfsense_action, xml_encrypt, ""))
                        sys.exit(1)
                    # Run our function
                    get_xml_data = get_xml_backup(pfsense_server, user, key, xml_area_post, xml_pkg_post, xml_rrd_post, xml_encrypt_post, xml_encrypt_pass)
                    # Check our exit code
                    if get_xml_data["ec"] == 0:
                        # Check how the user wants to display the data
                        if xml_filter.lower() in ["--read", "-r", "read"]:
                            print(get_xml_data["xml"])
                            sys.exit(0)
                        # If user wants to export the XML data to a file
                        elif xml_filter.startswith(("--export=","-e=")):
                            export_path = xml_filter.replace("-e=", "").replace("--export=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            export_name = "pf-xml-" + xml_area + "-" + pfsense_server + "-" + PfaVar.current_date + ".xml"    # Assign our default XML name
                            # Check if our directory exists
                            if os.path.exists(export_path):
                                # Open our file for writing
                                with open(export_path + export_name, "w") as xwr:
                                    xwr.write(get_xml_data["xml"])    # Write our XML data to a file
                                # Check if our file exists, if so print success message and exit on zero
                                if os.path.exists(export_path + export_name):
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, export_path + export_name, ""))
                                    sys.exit(0)
                                # If our file does not exit, print error and exit on non-zero
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, "", ""))
                                    sys.exit(1)
                        # If our filter is invalid
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, xml_filter, ""))
                            sys.exit(1)
                    # If non-zero exit code, exit script on non-zero with error msg
                    else:
                        print(get_exit_message(get_xml_data["ec"], pfsense_server, pfsense_action, "", ""))
                        sys.exit(get_xml_data["ec"])
                # If XML area is invalid
                else:
                    print(get_exit_message("invalid_area", pfsense_server, pfsense_action, xml_area, ""))
                    sys.exit(1)

            # Assign functions/processes for --upload-xml
            elif pfsense_action == "--upload-xml":
                # Action variables
                restore_areas = ["", "aliases", "captiveportal", "voucher", "dnsmasq", "unbound", "dhcpd", "dhcpdv6",
                                "filter", "interfaces", "ipsec", "nat", "openvpn", "installedpackages", "rrddata",
                                "cron", "syslog", "system", "staticroutes", "sysctl", "snmpd", "shaper", "vlans", "wol"]    # Assign a list of supported restore areas
                restore_area_raw = filter_input(third_arg) if len(sys.argv) > 3 else input("Restore area: ")    # Get our restore area input from user either in line or prompt
                conf_file_path = fourth_arg if len(sys.argv) > 4 else input("XML file: ")    # Get our XML file path from user either in line or prompt
                decrypt_pass_raw = fifth_arg if len(sys.argv) > 5 else getpass.getpass("Decryption password: ")    # Get our decryption password in line or prompt
                user = seventh_arg if sixth_arg == "-u" and seventh_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = ninth_arg if eighth_arg == "-p" and ninth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                restore_area = "" if restore_area_raw.lower() in ["all", "default", "any"] else restore_area_raw    # Format our restore area to match expect POST values
                decrypt_pass = "" if decrypt_pass_raw.lower() in ["none", "default"] else decrypt_pass_raw    # Format our decryption password to revert to blank on expected keywords
                # Check that our restore area is valid
                if restore_area in restore_areas:
                    # Check that our XML file exists
                    if os.path.exists(conf_file_path):
                        xml_file_obj = {"conffile" : open(conf_file_path, "rb")}    # Open our file and embed our file object in a dict to POST to pfSense
                        # Validation has passed at this point, run our post command
                        upload_xml = upload_xml_backup(pfsense_server, user, key, restore_area, xml_file_obj, decrypt_pass)    # Run function and save exit code
                        # Print our exit message and exit on exit code
                        print(get_exit_message(upload_xml, pfsense_server, pfsense_action, restore_area, ""))
                        sys.exit(upload_xml)
                    # If our XML file does not exist
                    else:
                        print(get_exit_message("invalid_filepath", pfsense_server, pfsense_action, conf_file_path, ""))
                        sys.exit(1)
                # If user passed in an unexpected restore area
                else:
                    print(get_exit_message("invalid_area", pfsense_server, pfsense_action, restore_area_raw, ""))
                    sys.exit(1)

            # Assign functions/processes for --replicate-xml
            elif pfsense_action == "--replicate-xml":
                # Action variables
                xml_area_list = ["", "aliases", "captiveportal", "voucher", "dnsmasq", "unbound", "dhcpd", "dhcpdv6",
                                "filter", "interfaces", "ipsec", "nat", "openvpn", "installedpackages", "rrddata",
                                "cron", "syslog", "system", "staticroutes", "sysctl", "snmpd", "shaper", "vlans", "wol"]    # Assign a list of supported restore areas
                max_targets = 100    # Only allow a specied number of replication targets
                replication_area = filter_input(third_arg) if len(sys.argv) > 3 else input("XML area: ")    # Assign user input for XML area to be replicated
                replication_targets = "," + fourth_arg if len(sys.argv) > 4 else ","   # Assign user input for hosts to apply configuration to (comma seperated)
                # If user requested interactive mode
                if replication_targets == ",":
                    # Create a loop prompting user to add hosts to replicate XML to
                    counter = 1    # Create a counter to track loop iteration
                    while True:
                        input_msg = "Replication target " + str(counter) + ": " if counter == 1 else "Replication target " + str(counter) + " [leave blank if done]: "    # Conditionally format input prompt
                        host_input = input(input_msg)    # Prompt user for host input
                        # Check that user wants to stop inputting
                        if host_input == "":
                            replication_targets.rstrip(",")    # Remove last comma to prevent orphan list item later
                            break    # Break loop
                        # Check if we have maxed out the number of replication targets
                        elif counter > max_targets:
                            replication_targets = replication_targets + host_input    # Add the entry as the final entry
                            break    # Break loop
                        # Assume user wants to continue adding hosts
                        else:
                            replication_targets = replication_targets + host_input + ","    # Populate our replication string
                            counter = counter + 1    # Increase our counter
                # Get our username and password. This must match ALL systems (master and targets)
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                if replication_area in xml_area_list:
                    if "," in replication_targets:
                        target_list = replication_targets.replace(" ", "").split(",")    # Save our target list
                        # Loop through targets and remove blank values
                        counter = 0    # Create a counter to track loop iteration
                        for tg in target_list:
                            # Remove item if it is blank
                            if tg == "":
                                del target_list[counter]
                            # Increase our counter
                            counter = counter + 1
                        # Run our replication function and print results
                        replication_ec = replicate_xml(pfsense_server, user, key, replication_area, target_list)
                        # Check if our function succeeded
                        if replication_ec["ec"] == 0:
                            # Define a dictionary with predefined result values
                            status_dict = {
                                0: {"status": "SUCCESS", "reason": "Replicated `" + replication_area + "` from " + pfsense_server},
                                2: {"status": "FAILED", "reason": "Replication unexpectedly failed"},
                                3: {"status": "FAILED", "reason": "Authentication failure"},
                                6: {"status": "FAILED", "reason": "Non-pfSense platform identified"},
                                10: {"status": "FAILED", "reason": "DNS rebind detected"},
                                15: {"status": "FAILED", "reason": "Permission denied"},
                            }
                            host_header = structure_whitespace("HOST", 30, "-", True) + " "   # Format our HOST header
                            status_header = structure_whitespace("STATUS", 8, "-", True) + " "   # Format our STATUS header
                            info_header = structure_whitespace("INFO", 60, "-", True) + " "   # Format our INFO header
                            print(host_header + status_header + info_header)    # Format our header
                            # Loop through our target result and print them
                            for lists,item in replication_ec["targets"].items():
                                host_data = structure_whitespace(item["host"], 30, " ", True) + " "    # Format our HOST data
                                status_data = structure_whitespace(status_dict[item["ec"]]["status"], 8, " ", True) + " "    # Format our STATUS data
                                info_data = structure_whitespace(status_dict[item["ec"]]["reason"], 60, " ", True) + " "    # Format our INFO data
                                print(host_data + status_data + info_data)    # Print our data
                            # Exit on zero (success)
                            sys.exit(replication_ec["ec"])
                        # If we could not pull the master configuration
                        else:
                            print(get_exit_message(replication_ec["ec"], pfsense_server, pfsense_action, "", ""))
                            sys.exit(replication_ec["ec"])
                    # If our replication target seperator is not found, print error message and exit on non-zero code
                    else:
                        print(get_exit_message("invalid_targets", pfsense_server, pfsense_action, replication_targets, ""))
                        sys.exit(1)
                # If our requested area does not exist, print error message and exit on non-zero code
                else:
                    print(get_exit_message("invalid_area", pfsense_server, pfsense_action, replication_area, ""))
                    sys.exit(1)

            # Assign functions/processes for --read-interfaces
            elif pfsense_action == "--read-interfaces":
                # Action variables
                iface_filter = third_arg if len(sys.argv) > 3 else "--all"   # Assign a filter argument that we can use to change the returned output
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                supported_filters = ("--all", "-a", "-d", "default", "-i=","--iface=","-v=","--vlan=","-n=", "--name=", "-c=", "--cidr=", "-j", "--json", "-rj", "--read-json")    # Tuple of support filter arguments
                # Check if our filter input is all or default
                if iface_filter.lower() in supported_filters or iface_filter.startswith(supported_filters):
                    iface_data = get_interfaces(pfsense_server, user, key)  # Get our data dictionary
                    # Check that we did not encounter an error
                    if iface_data["ec"] == 0:
                        # If we want to export values as JSON
                        if iface_filter.startswith(("--json=", "-j=")):
                            json_path = iface_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readifaces-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(iface_data["ifaces"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If user wants to print the JSON output
                        elif iface_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(iface_data["ifaces"]))   # Print our JSON data
                        # If user is not requesting JSON, print normally
                        else:
                            # Format our header values
                            header_name = structure_whitespace("NAME", 30, "-", True) + " "    # NAME header
                            header_iface = structure_whitespace("INTERFACE", 18, "-", True) + " "    # INTERFACE header
                            header_id = structure_whitespace("ID", 8, "-", True) + " "    # ID header
                            header_type = structure_whitespace("TYPE", 10, "-", True) + " "    # TYPE header
                            header_cidr = structure_whitespace("CIDR", 20, "-", True) + " "    # CIDR header
                            header_enabled = structure_whitespace("ENABLED", 8, "-", True)    # ENABLED header
                            header = header_name + header_iface + header_id + header_type + header_cidr + header_enabled    # Piece our header together
                            # Loop through our dictionary and print our values
                            data_table = header    # Assign a data_table our loop will populate with data before printing
                            for pf_id,data in iface_data["ifaces"].items():
                                # Format and print our values
                                name = structure_whitespace(data["descr"], 30, " ", True) + " "    # Format our name value
                                iface = structure_whitespace(data["id"], 18, " ", True) + " "    # Format our iface value
                                id_num = structure_whitespace(data["pf_id"], 8, " ", True) + " "    # Format our pf_id value
                                type_id = structure_whitespace(data["type"], 10, " ", True) + " "    # Format our IP type
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
                                if iface_filter.startswith(("-i=","--iface=")):
                                    iface_input = iface_filter.split("=")[1]    # Save our user input from the filter
                                    # If the current interface matches
                                    if data["id"].startswith(iface_input):
                                        data_table = data_table + "\n" + name + iface + id_num + type_id + cidr + enabled
                                # Add only data that matches vlan input from user
                                elif iface_filter.startswith(("-v=","--vlan=")):
                                    vlan_input = iface_filter.split("=")[1]    # Save our user input from the filter
                                    # If the current VLAN matches
                                    if data["id"].endswith("." + vlan_input):
                                        data_table = data_table + "\n" + name + iface + id_num + type_id + cidr + enabled
                                # Add only data that contains name string input from user
                                elif iface_filter.startswith(("-n=","--name=")):
                                    name_input = iface_filter.split("=")[1]    # Save our user input from the filter
                                    # If the current NAME matches
                                    if name_input in data["descr"]:
                                        data_table = data_table + "\n" + name + iface + id_num + type_id + cidr + enabled
                                # Add only data that starts with a specified IP or CIDR
                                elif iface_filter.startswith(("-c=","--cidr=")):
                                    cidr_input = iface_filter.split("=")[1]    # Save our user input from the filter
                                    # If the current CIDR matches
                                    check_cidr = data["ipaddr"] + "/" + data["subnet"]
                                    if check_cidr.startswith(cidr_input) and check_cidr != "/":
                                        data_table = data_table + "\n" + name + iface + id_num + type_id + cidr + enabled
                                # Otherwise, write all data
                                else:
                                    data_table = data_table + "\n" + name + iface + id_num + type_id + cidr + enabled
                            print(data_table)    # Print our data table
                    # If we did receive a 0 exit code
                    else:
                        print(get_exit_message(iface_data["ec"], pfsense_server, pfsense_action, iface_filter, ""))    # Print error msg
                        sys.exit(iface_data["ec"])    # Exit on our function exit code
                # If user passed in unknown filter
                else:
                    print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, iface_filter, ""))
                    sys.exit(1)

            # Assign functions and processes for --read-available-interfaces
            elif pfsense_action == "--read-available-interfaces":
                # Action variables
                user = fourth_arg if third_arg == "-u" and fourth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixth_arg if fifth_arg == "-p" and sixth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                available_if = get_available_interfaces(pfsense_server, user, key)    # Save our interface data
                # Check that we did not encounter errors pulling interface data
                if available_if["ec"] == 0:
                    # Check that we have available interfaces
                    if len(available_if["if_add"]) > 0:
                        print("--AVAILABLE INTERFACES-----")
                        # Loop through our available interfaces and print the data
                        for iface in available_if["if_add"]:
                            print(iface)    # Print our interface ID
                        sys.exit(0)    # Exit on good terms
                    # If we did not have any available interfaces
                    else:
                        print(get_exit_message("no_if", pfsense_server, pfsense_action, "", ""))
                        sys.exit(0)    # Exit on good terms as this is not an error
                # If we encountered an error pulling our interface data
                else:
                    print(get_exit_message(available_if["ec"], pfsense_server, pfsense_action, "", ""))    # Print error msg
                    sys.exit(available_if["ec"])    # Exit on our function exit code

            # Assign functions for --add-tunable
            elif pfsense_action == "--add-tunable":
                # Action Variables
                tunable_name = third_arg if third_arg is not None else input("Tunable name: ")    # Assign our tunable name to the third argument passed in
                tunable_descr = fourth_arg if fourth_arg is not None else input("Description: ")    # Assign our tunable description to the fourth argument passed in
                tunable_value = fifth_arg if fifth_arg is not None else input("Value: ")   # Assign our tunable description to the fifth argument passed in
                user = seventh_arg if sixth_arg == "-u" and seventh_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = ninth_arg if eighth_arg == "-p" and ninth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                tunable_descr = "Auto-added by" + user + " on " + PfaVar.local_hostname if tunable_descr.upper() == "DEFAULT" else tunable_descr    # Assign default description value
                add_tunable_ec = add_system_tunable(pfsense_server, user, key, tunable_name, tunable_descr, tunable_value)    # Save the exit code of our POST function
                print(get_exit_message(add_tunable_ec, pfsense_server, pfsense_action, tunable_name, ""))    # Print our exit message
                sys.exit(add_tunable_ec)    # Exit on our exit code

            # Assign functions for flag --read-arp
            elif pfsense_action == "--read-tunables":
                tunable_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                tunables = get_system_tunables(pfsense_server, user, key)
                num_head = structure_whitespace("#", 3, "-", True) + " "    # Format our number header value
                name_head = structure_whitespace("NAME", 40, "-", True) + " "    # Format our name header value
                descr_head = structure_whitespace("DESCRIPTION", 30, "-", True) + " "    # Format our ip description value
                value_head = structure_whitespace("VALUE", 15, "-", True) + " "    # Format our host value value
                id_head = structure_whitespace("ID", 40, "-", True) + " "    # Format our host value value
                header = num_head + name_head + descr_head + value_head + id_head  # Format our print header
                # Check that we did not receive an error pulling the data
                if tunables["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 1    # Assign a loop counter
                    for key,value in tunables["tunables"].items():
                        tun_number = structure_whitespace(str(counter), 3, " ", True) + " "    # Get our entry number
                        tun_name = structure_whitespace(value["name"], 40, " ", True)  + " "   # Get our tunable name
                        tun_descr = structure_whitespace(value["descr"], 30, " ", True) + " "    # Get our tunable description
                        tun_value = structure_whitespace(value["value"], 15, " ", True) + " "    # Get our value
                        tun_id = structure_whitespace(value["id"], 40, " ", True) + " "    # Get our ID
                        # If we want to return all values
                        if tunable_filter.upper() in ["-A", "--ALL", "-D", "DEFAULT"]:
                            print(header) if counter == 1 else None  # Print our header if we are just starting loop
                            print(tun_number + tun_name + tun_descr + tun_value + tun_id)    # Print our data values
                        # If user wants to print the JSON output
                        elif tunable_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(tunables["tunables"]))   # Print our JSON data
                            break
                        # If we want to export values as JSON
                        elif tunable_filter.startswith(("--json=", "-j=")):
                            json_path = tunable_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readtunables-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(tunables["tunables"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, tunable_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we received an error, print the error message and exit on non-zero ec
                else:
                    print(get_exit_message(tunables["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(tunables["ec"])
            # Functions and processes for flag --read-general-setup
            elif pfsense_action == "--read-general-setup":
                general_filter = third_arg if third_arg is not None else ""    # Assign our third argument as a filter value
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                general_setup_data = get_general_setup(pfsense_server, user, key)  # Get our data dictionary
                # Check our data pull exit code
                if general_setup_data["ec"] == 0:
                    # Check which filter/argument was passed in
                    # If user wants to print SYSTEM settings, or everything
                    if general_filter.upper() in ["-S", "--SYSTEM", "-A", "--ALL", "DEFAULT", "-D"]:
                        print(structure_whitespace("--SYSTEM", 50, "-", False))
                        print(structure_whitespace("Hostname: ", 25, " ", False) + general_setup_data["general"]["system"]["hostname"])
                        print(structure_whitespace("Domain: ", 25, " ", False) + general_setup_data["general"]["system"]["domain"])
                    # If user wants to print DNS settings, or everything
                    if general_filter.upper() in ["-N", "--DNS", "-A", "--ALL", "DEFAULT", "-D"]:
                        print(structure_whitespace("--DNS CLIENT", 50, "-", False))
                        print(structure_whitespace("DNS Override: ", 25, " ", False) + str(general_setup_data["general"]["dns"]["dnsallowoverride"]))
                        print(structure_whitespace("No DNS Localhost: ", 25, " ", False) + str(general_setup_data["general"]["dns"]["dnslocalhost"]))
                        # Loop through our DNS servers and print configured info
                        for key,value in general_setup_data["general"]["dns"]["servers"].items():
                            ip = structure_whitespace(value["ip"] + " ", 15, " ", True)    # Format our IP
                            hostname = structure_whitespace("Host: " + value["hostname"] + " ", 25, " ", True)    # Format our hostname
                            gw = structure_whitespace("Gateway: " + value["gateway"], 18, " ", True)    # Format our Gateway
                            print(structure_whitespace("DNS" + value["id"] + ": ", 25, " ", False) + ip + hostname + gw)    # Print our DNS line
                    # If user wants to print LOCALIZATION settings, or everything
                    if general_filter.upper() in ["-L", "--LOCALIZATION", "-A", "--ALL", "DEFAULT", "-D"]:
                        print(structure_whitespace("--LOCALIZATION", 50, "-", False))
                        print(structure_whitespace("Timezone: ", 25, " ", False) + str(general_setup_data["general"]["localization"]["timezone"]))
                        print(structure_whitespace("Language: ", 25, " ", False) + str(general_setup_data["general"]["localization"]["language"]))
                        # Loop through our timeservers and print their values
                        ts_counter = 0    # Assign a loop counter
                        ts_list = general_setup_data["general"]["localization"]["timeservers"].split(" ")    # Split our timeservers into a list
                        for ts in ts_list:
                            # Check that we have a value
                            if ts != "":
                                print(structure_whitespace("Timeserver" + str(ts_counter) + ": ", 25, " ", False) + ts)    # Print each of our configured timeservers
                                ts_counter = ts_counter + 1    # Increase our counter
                    # If user wants to print WEBCONFIGURED settings, or everything
                    if general_filter.upper() in ["-WC", "--WEBCONFIGURATOR", "-A", "--ALL"]:
                        print(structure_whitespace("--WEBCONFIGURATOR", 50, "-", False))
                        print(structure_whitespace("Theme: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["webguicss"]))
                        print(structure_whitespace("Top Navigation: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["webguifixedmenu"]))
                        print(structure_whitespace("Host in Menu: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["webguihostnamemenu"]))
                        print(structure_whitespace("Dashboard Columns: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["dashboardcolumns"]))
                        print(structure_whitespace("Sort Interfaces: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["interfacessort"]))
                        print(structure_whitespace("Show Widgets: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["dashboardavailablewidgetspanel"]))
                        print(structure_whitespace("Show Log Filter: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["systemlogsfilterpanel"]))
                        print(structure_whitespace("Show Log Manager: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["systemlogsmanagelogpanel"]))
                        print(structure_whitespace("Show Monitoring: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["statusmonitoringsettingspanel"]))
                        print(structure_whitespace("Require State Filter: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["requirestatefilter"]))
                        print(structure_whitespace("Left Column Labels: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["webguileftcolumnhyper"]))
                        print(structure_whitespace("Disable Alias Popups: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["disablealiaspopupdetail"]))
                        print(structure_whitespace("Disable Dragging: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["roworderdragging"]))
                        print(structure_whitespace("Login Page Color: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["logincss"]))
                        print(structure_whitespace("Login hostname: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["loginshowhost"]))
                        print(structure_whitespace("Dashboard refresh: ", 25, " ", False) + str(general_setup_data["general"]["webconfigurator"]["dashboardperiod"]))
                    # If user wants to print the JSON output
                    if general_filter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(general_setup_data["general"]))   # Print our JSON data
                    # If we want to export values as JSON
                    if general_filter.startswith(("--json=", "-j=")):
                        json_path = general_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        json_name = "pf-readgeneral-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(json_path):
                            # Open an export file and save our data
                            json_exported = export_json(general_setup_data["general"], json_path, json_name)
                            # Check if the file now exists
                            if json_exported:
                                print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                            else:
                                print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                            sys.exit(1)
                # If we received a non-zero exit code, print our exit message
                else:
                    print(get_exit_message(general_setup_data["ec"], pfsense_server, pfsense_action, general_filter, ""))
                    sys.exit(general_setup_data["ec"])
            # Functions and processes for flag --set-system-hostname
            elif pfsense_action == "--set-system-hostname":
                # Print warning prompt if user is using interactive mode
                if len(sys.argv) < 8:
                    print(get_exit_message("inter_warn", pfsense_server, pfsense_action, "", ""))
                # Local variables
                host = filter_input(third_arg) if len(sys.argv) > 3 else input("Hostname: ")    # Pull our passed in hostname argument or prompt user to input if missing
                domain = filter_input(fourth_arg) if len(sys.argv) > 4 else input("Domain: ")    # Pull our passed in domain argument or prompt user to input if missing
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                set_sys_host_ec = set_system_hostname(pfsense_server, user, key, host, domain)    # Run our function that adds the hostname and save the exit code
                # Print our exit message and exit on our exit code
                print(get_exit_message(set_sys_host_ec, pfsense_server, pfsense_action, host, domain))
                sys.exit(set_sys_host_ec)
            # Functions and processes for flag --read-adv-admin
            elif pfsense_action == "--read-adv-admin":
                adv_adm_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                adv_adm_data = get_system_advanced_admin(pfsense_server, user, key)    # Get our data dictionary
                # Check our data pull exit code
                if adv_adm_data["ec"] == 0:
                    # Check which filter/argument was passed in
                    # If user wants to print webconfigurator settings, or everything
                    if adv_adm_filter.upper() in ["-WC", "--WEBCONFIGURATOR", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin WEBCONFIGURATOR
                        print(structure_whitespace("--WEBCONFIGURATOR", 50, "-", False))
                        print(structure_whitespace("Protocol: ", 30, " ", False) + adv_adm_data["adv_admin"]["webconfigurator"]["webguiproto"])
                        print(structure_whitespace("SSL Certificate: ", 30, " ", False) + adv_adm_data["adv_admin"]["webconfigurator"]["ssl-certref"])
                        print(structure_whitespace("TCP Port: ", 30, " ", False) + adv_adm_data["adv_admin"]["webconfigurator"]["webguiport"])
                        print(structure_whitespace("Max Processes: ", 30, " ", False) + adv_adm_data["adv_admin"]["webconfigurator"]["max_procs"])
                        print(structure_whitespace("WebUI Redirect: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["webgui-redirect"]))
                        print(structure_whitespace("HSTS: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["webgui-hsts"]))
                        print(structure_whitespace("OCSP Stapling: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["ocsp-staple"]))
                        print(structure_whitespace("Login Auto-complete: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["loginautocomplete"]))
                        print(structure_whitespace("Login Messages: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["webgui-login-messages"]))
                        print(structure_whitespace("Disable Anti-lockout: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["noantilockout"]))
                        print(structure_whitespace("Disable DNS Rebind Check: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["nodnsrebindcheck"]))
                        print(structure_whitespace("Alternate Hostnames: ", 30, " ", False) + adv_adm_data["adv_admin"]["webconfigurator"]["althostnames"])
                        print(structure_whitespace("Disable HTTP_REFERRER: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["nohttpreferercheck"]))
                        print(structure_whitespace("Browser Tab Text: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["webconfigurator"]["pagenamefirst"]))
                    # If user wants to print SECURE SHELL settings, or everything
                    if adv_adm_filter.upper() in ["-SSH", "--SECURE-SHELL", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin SECURE SHELL
                        print(structure_whitespace("--SECURE SHELL", 50, "-", False))
                        print(structure_whitespace("Enable SSH: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["secure_shell"]["enablesshd"]))
                        print(structure_whitespace("Enable SSH-Agent Forwarding: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["secure_shell"]["sshdagentforwarding"]))
                        print(structure_whitespace("SSH Port: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["secure_shell"]["sshport"]))
                        print(structure_whitespace("SSH Authentication Type: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["secure_shell"]["sshdkeyonly"]))
                    # If user wants to print LOGIN PROTECTION settings, or everything
                    if adv_adm_filter.upper() in ["-LC", "--LOGIN-PROTECTION", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin LOGIN PROTECTION
                        print(structure_whitespace("--LOGIN PROTECTION", 50, "-", False))
                        print(structure_whitespace("Threat Threshold: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["login_protection"]["sshguard_threshold"]))
                        print(structure_whitespace("Threat Blocktime: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["login_protection"]["sshguard_blocktime"]))
                        print(structure_whitespace("Threat Detection Time: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["login_protection"]["sshguard_detection_time"]))
                        print("Whitelist:")
                        # Loop through our whitelisted addresses
                        for key,value in adv_adm_data["adv_admin"]["login_protection"]["whitelist"].items():
                            # Check that we have a legitimate value
                            if value["value"] != "":
                                # Check if subnet was specified
                                addr_str = "  - " + value["value"]   # Assign our IP to our address string
                                if value["subnet"] != "":
                                    addr_str = addr_str + "/" + value["subnet"]    # Append our subnet to our address string
                                print(addr_str)    # Print our address string
                    # If user wants to print SERIAL COMMUNICATIONS settings, or everything
                    if adv_adm_filter.upper() in ["-SC", "--SERIAL-COMMUNICATIONS", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin SERIAL COMMUNICATIONS
                        print(structure_whitespace("--SERIAL COMMUNICATIONS", 50, "-", False))
                        print(structure_whitespace("Enable Serial Communication: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["serial_communcations"]["enableserial"]))
                        print(structure_whitespace("Serial Speed: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["serial_communcations"]["serialspeed"]))
                        print(structure_whitespace("Console Type: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["serial_communcations"]["primaryconsole"]))
                    # If user wants to print CONSOLE OPTIONS settings, or everything
                    if adv_adm_filter.upper() in ["-CO", "--CONSOLE-OPTIONS", "-A", "--ALL", "DEFAULT", "-D"]:
                        # Print all our advanced admin CONSOLE OPTIONS
                        print(structure_whitespace("--CONSOLE OPTIONS", 50, "-", False))
                        print(structure_whitespace("Password Protect Console: ", 30, " ", False) + str(adv_adm_data["adv_admin"]["console_options"]["disableconsolemenu"]))
                    # If user wants to print the JSON output
                    if adv_adm_filter.lower() in ("--read-json", "-rj"):
                        print(json.dumps(adv_adm_data["adv_admin"]))   # Print our JSON data
                    # If we want to export values as JSON
                    if adv_adm_filter.startswith(("--json=", "-j=")):
                        json_path = adv_adm_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        json_name = "pf-readadvadm-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                        # Check if JSON path exists
                        if os.path.exists(json_path):
                            # Open an export file and save our data
                            json_exported = export_json(adv_adm_data["adv_admin"], json_path, json_name)
                            # Check if the file now exists
                            if json_exported:
                                print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                            else:
                                print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # Print error if path does not exist
                        else:
                            print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                            sys.exit(1)
                # If we received a non-zero exit code, print our exit message
                else:
                    print(get_exit_message(adv_adm_data["ec"], pfsense_server, pfsense_action, adv_adm_filter, ""))
                    sys.exit(adv_adm_data["ec"])
            # Functions and processes for flag --setup-wc
            elif pfsense_action == "--setup-wc":
                # Action variables
                max_proc = filter_input(third_arg) if len(sys.argv) > 3 else input("Max processes [1-1024, default]: ")    # Assign our max process option, prompt user for input if empty
                max_proc = "default" if max_proc == "" else max_proc    # Assume default if entry is blank
                max_proc_int = int(max_proc) if max_proc.isdigit() else 99999    # Convert the max_proc value to an integer if possible, otherwise assign an integer that is out of range
                ui_redirect = filter_input(fourth_arg) if len(sys.argv) > 4 else input("HTTP redirect [enable, disable, default]: ")    # Assign our redirect option, prompt user for input if empty
                ui_redirect = "default" if ui_redirect == "" else ui_redirect    # Assume default if entry is blank
                hsts = filter_input(fifth_arg) if len(sys.argv) > 5 else input("HTTP Strict Transport Security [enable, disable, default]: ")    # Assign our hsts option, prompt user for input if empty
                hsts = "default" if hsts == "" else hsts    # Assume default if entry is blank
                auto_complete = filter_input(sixth_arg) if len(sys.argv) > 6 else input("Login auto-complete [enable, disable, default]: ")    # Assign our login autocompletion option, prompt user for input if empty
                auto_complete = "default" if auto_complete == "" else auto_complete    # Assume default if entry is blank
                auth_log = filter_input(seventh_arg) if len(sys.argv) > 7 else input("Authentication logging [enable, disable, default]: ")    # Assign our login logging option, prompt user for input if empty
                auth_log = "default" if auth_log == "" else auth_log    # Assume default if entry is blank
                ui_antilock = filter_input(eighth_arg) if len(sys.argv) > 8 else input("WebUI anti-lockout [enable, disable, default]: ")    # Assign our ui_antilock option, prompt user for input if empty
                ui_antilock = "default" if ui_antilock == "" else ui_antilock    # Assume default if entry is blank
                dns_rebind = filter_input(ninth_arg) if len(sys.argv) > 9 else input("DNS Rebind checking [enable, disable, default]: ")    # Assign our dns rebind option, prompt user for input if empty
                dns_rebind = "default" if dns_rebind == "" else dns_rebind    # Assume default if entry is blank
                alt_host = filter_input(tenth_arg) if len(sys.argv) > 10 else input("Alternate hostnames (separate FQDNs by space): ")    # Assign our alt hostname option, prompt user for input if empty
                alt_host = "default" if alt_host == "" else alt_host    # Assume default if entry is blank
                http_ref = filter_input(eleventh_arg) if len(sys.argv) > 11 else input("HTTP_REFERER checking [enable, disable, default]: ")    # Assign our http_referer option, prompt user for input if empty
                http_ref = "default" if http_ref == "" else http_ref    # Assume default if entry is blank
                tab_text = filter_input(twelfth_arg) if len(sys.argv) > 12 else input("Display hostname in tab [enable, disable, default]: ")    # Assign our http_referer option, prompt user for input if empty
                tab_text = "default" if tab_text == "" else tab_text    # Assume default if entry is blank
                user = fourteenth_arg if thirteenth_arg == "-u" and fourteenth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = sixteenth_arg if fifteenth_arg == "-p" and sixteenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our integer is in range
                if 1 <= max_proc_int <= 1024 or max_proc.lower() == "default":
                    # Check that our ui_redirect is valid
                    if ui_redirect.lower() in ["enable", "disable", "redirect", "no-redirect", "default"]:
                        # Check that our HSTS value is valid
                        if hsts.lower() in ["enable", "disable", "hsts", "no-hsts", "default"]:
                            # Check that our auto complete value is valid
                            if auto_complete.lower() in ["enable", "disable", "autocomplete", "no-autocomplete", "default"]:
                                # Check that our auth_log value is valid
                                if auth_log.lower() in ["enable", "disable", "loginmsg", "no-loginmsg", "default"]:
                                    # Check that our ui_antilock value is valid
                                    if ui_antilock.lower() in ["enable", "disable", "antilockout", "no-antilockout", "default"]:
                                        # Check that our dns_rebind value is valid
                                        if dns_rebind.lower() in ["enable", "disable", "dnsrebind", "no-dnsrebind", "default"]:
                                            # Check that our http_ref value is valid
                                            if http_ref.lower() in ["enable", "disable", "httpreferer", "no-httpreferer", "default"]:
                                                # Check that our tab_text value is valid
                                                if tab_text.lower() in ["enable", "disable", "display-tabtext", "hide-tabtext", "default"]:
                                                    # Run our function now that all input is validated
                                                    setup_wc_ec = setup_wc(pfsense_server, user, key, max_proc, ui_redirect, hsts, auto_complete, auth_log, ui_antilock, dns_rebind, alt_host, http_ref, tab_text)
                                                    # Print our exit message and exit script on returned exit code
                                                    print(get_exit_message(setup_wc_ec, pfsense_server, pfsense_action, "", ""))
                                                    sys.exit(setup_wc_ec)
                                                # If our tab_text value is invalid
                                                else:
                                                    print(
                                                    "invalid_tabtext", pfsense_server, pfsense_action, tab_text, "")
                                                    sys.exit(1)
                                            # If our http_ref value is invalid
                                            else:
                                                print("invalid_httpreferer", pfsense_server, pfsense_action, http_ref, "")
                                                sys.exit(1)
                                        # If our dns_rebind value is invalid
                                        else:
                                            print("invalid_dnsrebind", pfsense_server, pfsense_action, dns_rebind, "")
                                            sys.exit(1)
                                    # If our ui_antilock value is invalid
                                    else:
                                        print("invalid_lockout", pfsense_server, pfsense_action, ui_antilock, "")
                                        sys.exit(1)
                                # If our loginmsg value is invalid
                                else:
                                    print("invalid_loginmsg", pfsense_server, pfsense_action, auth_log, "")
                                    sys.exit(1)
                            # If our autocomplete value is invalid
                            else:
                                print("invalid_autocomplete", pfsense_server, pfsense_action, auto_complete, "")
                                sys.exit(1)
                        # If our HSTS value is invalid
                        else:
                            print("invalid_hsts", pfsense_server, pfsense_action, hsts, "")
                            sys.exit(1)
                    # If our redirect value is invalid
                    else:
                        print("invalid_redirect", pfsense_server, pfsense_action, ui_redirect, "")
                        sys.exit(1)
                # If integer is out of range
                else:
                    print(get_exit_message("invalid_proc", pfsense_server, pfsense_action, max_proc, ""))
                    sys.exit(1)
            # Functions and process for flag --set-wc-port
            elif pfsense_action == "--set-wc-port":
                # Action variables
                protocol = filter_input(third_arg) if len(sys.argv) > 3 else input("HTTP Protocol [http, https, default]: ")    # Get our protocol from the user, either inline or interactively
                port = filter_input(fourth_arg) if len(sys.argv) > 4 else input("TCP port [1-65535, default]: ")    # Get ou webconfigurator port either inline or interactively
                port_int = int(port) if port.isdigit() else 999999    # Convert our port to an integer if possible, otherwise assign a port value that is out of range
                user = sixth_arg if fifth_arg == "-u" and sixth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = eighth_arg if seventh_arg == "-p" and eighth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # INPUT VALIDATION
                # Check that our protocol is valid
                if protocol.lower() in ["http", "https", "default"]:
                    # Check that our port is valid
                    if 1 <= port_int <= 65535 or port.upper() == "DEFAULT":
                        # Run our function
                        wc_port_ec = set_wc_port(pfsense_server, user, key, protocol, port)
                        # Print our exit message and exit on code
                        print(get_exit_message(wc_port_ec, pfsense_server, pfsense_action, protocol, port))
                        sys.exit(wc_port_ec)
                    # If our port is out of range
                    else:
                        print(get_exit_message("invalid_port", pfsense_server, pfsense_action, port, ""))
                        sys.exit(1)
                # If our protocol is invalid
                else:
                    print(get_exit_message("invalid_protocol", pfsense_server, pfsense_action, protocol, ""))
                    sys.exit(1)
            # Functions and processes for flag --setup-ssh
            elif pfsense_action == "--setup-ssh":
                # Action variables
                enable_ssh = filter_input(third_arg) if len(sys.argv) > 3 else input("Enable SSH [enable, disable, default]: ")    # Assign our enable option, prompt user for input if empty
                enable_ssh = "default" if enable_ssh == "" else enable_ssh    # Assume default if entry is blank
                ssh_port = filter_input(fourth_arg) if len(sys.argv) > 4 else input("SSH Port [1-65535, default]: ")    # Assign our port option, prompt user for input if empty
                ssh_port = "default" if ssh_port == "" else ssh_port    # Assume default if entry is blank
                ssh_auth = filter_input(fifth_arg) if len(sys.argv) > 5 else input("SSH Authentication method [passwd, key, both, default]: ")    # Assign our authentication option, prompt user for input if empty
                ssh_auth = "default" if ssh_auth == "" else ssh_auth    # Assume default if entry is blank
                ssh_forward = filter_input(sixth_arg) if len(sys.argv) > 6 else input("SSH-AGENT Forwarding [enable, disable, default]: ")    # Assign our ssh-agent forward option, prompt user for input if empty
                ssh_forward = "default" if ssh_forward == "" else ssh_forward    # Assume default if entry is blank
                user = eighth_arg if seventh_arg == "-u" and eighth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = tenth_arg if ninth_arg == "-p" and tenth_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Check that we are actually trying to change a variable aka default isn't set for each input
                if all("DEFAULT" in x for x in [enable_ssh.upper(),ssh_port.upper(),ssh_auth.upper(),ssh_forward.upper()]):
                    # If we requested all default values, print error as nothing will be changed
                    print(get_exit_message("no_change", pfsense_server, pfsense_action, "", ""))
                    sys.exit(0)
                # If all values were not DEFAULT
                else:
                    # Check our enable SSH value
                    if enable_ssh.lower() in ["enable", "disable", "default"]:
                        # Check if we are trying to change the SSH port
                        if ssh_port.upper() != "DEFAULT":
                            # Try to convert our port to an integer and verify it is in range
                            try:
                                ssh_port_int = int(ssh_port)    # Convert our SSH port to an integer for checks
                            except ValueError:
                                ssh_port_int = 99999999     # If we could not convert our port to an integer, assign integer that is out of port range
                            # Check if port is within range
                            if 1 > ssh_port_int or 65535 < ssh_port_int:
                                # If port is out of range print our exit message and exit on non-zero status
                                print(get_exit_message("invalid_port", pfsense_server, pfsense_action, ssh_port, ""))
                                sys.exit(1)
                        # Check that we have chosen a valid SSH auth type
                        if ssh_auth.lower() in ["keyonly", "key", "pass", "password", "passwd", "mfa", "both", "all", "default"]:
                            # Check if we have a valid ssh_forward value
                            if ssh_forward.lower() in ["enable", "disable", "enable-forwarding", "yes", "none", "default"]:
                                ec_setup_ssh = setup_ssh(pfsense_server, user, key, enable_ssh, ssh_port, ssh_auth, ssh_forward)    # Execute our configuration function
                                # Print our exit message and exit on return code
                                print(get_exit_message(ec_setup_ssh, pfsense_server, pfsense_action, ssh_auth, ""))
                                sys.exit(ec_setup_ssh)
                            # If our ssh_forward value is invalid
                            else:
                                print(get_exit_message("invalid_forward", pfsense_server, pfsense_action, ssh_forward, ""))
                                sys.exit(1)
                        # If our auth type is invalid
                        else:
                            print(get_exit_message("invalid_auth", pfsense_server, pfsense_action, ssh_auth, ""))
                            sys.exit(1)
                    # If our enableSSH value is invalid, print error
                    else:
                        print(get_exit_message("invalid_enable", pfsense_server, pfsense_action, enable_ssh, ""))
                        sys.exit(1)

            # Functions and processes for flag --setup-console
            elif pfsense_action == "--setup-console":
                # Action variables
                console_pass = filter_input(third_arg) if len(sys.argv) > 3 else input("Console password protection [enable,disable]: ")    # Capture our user input or prompt user for input if missing
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                # Check our input
                if console_pass.upper() in ["ENABLE","DISABLE"]:
                    ec_setup_console = setup_console(pfsense_server, user, key, console_pass)    # run our function and save return code
                    print(get_exit_message(ec_setup_console, pfsense_server, pfsense_action, "", ""))    # Print our exit message
                    sys.exit(ec_setup_console)    # Exit on our return code
                # If our inupt is invalid
                else:
                    print(get_exit_message("invalid_option", pfsense_server, pfsense_action, console_pass, ""))    # Print our error message
                    sys.exit(1)    # Exit on non-zero exit code

            # Functions and process for flag --read-vlans
            elif pfsense_action == "--read-vlans":
                # Action Variables
                vlan_filter = third_arg if third_arg is not None else ""    # Assign our filter value if one was provided, otherwise default to empty string
                user = fifth_arg if fourth_arg == "-u" and fifth_arg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventh_arg if sixth_arg == "-p" and seventh_arg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                vlans = get_vlan_ids(pfsense_server, user, key)
                id_head = structure_whitespace("#", 4, "-", True) + " "    # Format our ID header value
                interface_head = structure_whitespace("INTERFACE", 12, "-", True) + " "    # Format our interface header header value
                vlan_head = structure_whitespace("VLAN ID", 10, "-", True) + " "    # Format our VLAN ID header value
                priority_head = structure_whitespace("PRIORITY", 10, "-", True) + " "    # Format our priority header value
                descr_head = structure_whitespace("DESCRIPTION", 30, "-", True) + " "    # Format our description header value
                header = id_head + interface_head + vlan_head + priority_head + descr_head    # Format our print header
                # Check that we did not receive an error pulling the data
                if vlans["ec"] == 0:
                    # Loop through each value in our dictionary
                    counter = 0    # Assign a loop counter
                    for key,value in vlans["vlans"].items():
                        id_num = structure_whitespace(str(key), 4, " ", True) + " "    # Get our entry number
                        interface = structure_whitespace(value["interface"], 12, " ", True)  + " "   # Get our interface ID
                        vlan_id = structure_whitespace(value["vlan_id"], 10, " ", True) + " "    # Get our VLAN ID
                        priority = structure_whitespace(value["priority"], 10, " ", True) + " "    # Get our priority level
                        descr = structure_whitespace(value["descr"], 30, " ", True) + " "   # Get our description
                        # If we want to return all values
                        if vlan_filter.upper() in ["-A", "--ALL"]:
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            print(id_num + interface + vlan_id + priority + descr)    # Print our data values
                        # If we only want to return value of one VLAN ID
                        elif vlan_filter.startswith(("--vlan=","-v=")):
                            vlan_scope = vlan_filter.replace("--vlan=", "").replace("-v=", "")    # Remove expected argument values to determine our VLAN scope
                            # Check if we have found our expected VLAN
                            if vlan_scope == value["vlan_id"]:
                                print(header)    # Print our header
                                print(id_num + interface + vlan_id + priority + descr)    # Print our data values
                                break    # Break the loop as we only need this matched value
                        # If we only want to return value of one VLAN ID
                        elif vlan_filter.startswith(("--iface=","-i=")):
                            print(header) if counter == 0 else None  # Print our header if we are just starting loop
                            interface_scope = vlan_filter.replace("--iface=", "").replace("-i=", "")    # Remove expected argument values to determine our VLAN scope
                            # Check if we have found our expected VLAN
                            if interface_scope == value["interface"]:
                                print(id_num + interface + vlan_id + priority + descr)    # Print our data values
                        # If user wants to print the JSON output
                        elif vlan_filter.lower() in ("--read-json", "-rj"):
                            print(json.dumps(vlans["vlans"]))   # Print our JSON data
                            break    # Break our loop, we only want to print this once
                        # If we want to export values as JSON
                        elif vlan_filter.startswith(("--json=", "-j=")):
                            json_path = vlan_filter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            json_name = "pf-readvlans-" + PfaVar.current_date + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(json_path):
                                # Open an export file and save our data
                                json_exported = export_json(vlans["vlans"], json_path, json_name)
                                # Check if the file now exists
                                if json_exported:
                                    print(get_exit_message("export_success", pfsense_server, pfsense_action, json_path + json_name, ""))
                                    break    # Break the loop as we only need to perfrom this function once
                                else:
                                    print(get_exit_message("export_fail", pfsense_server, pfsense_action, json_path, ""))
                                    sys.exit(1)
                            # Print error if path does not exist
                            else:
                                print(get_exit_message("export_err", pfsense_server, pfsense_action, json_path, ""))
                                sys.exit(1)
                        # If we did not recognize the requested filter print our error message
                        else:
                            print(get_exit_message("invalid_filter", pfsense_server, pfsense_action, vlan_filter, ""))
                            sys.exit(1)    # Exit on non-zero status
                        counter = counter + 1  # Increase our counter
                # If we received an error, print the error message and exit on non-zero ec
                else:
                    print(get_exit_message(vlans["ec"], pfsense_server, pfsense_action, "", ""))
                    sys.exit(vlans["ec"])
            # If an unexpected action was given, return error
            else:
                flag_descrs = ""    # Initialize our flag description help string
                flag_dict = get_exit_message("", pfsense_server, "all", "", "")    # Pull our descr dictionary
                # Loop through our flag descriptions and save them to a string
                for key,value in flag_dict.items():
                    # Only perform this on dict keys with -- flags
                    if key.startswith("--"):
                        flag_descrs = flag_descrs + value["descr"] + "\n"   # Format our return string
                print("COMMANDS:")
                print(flag_descrs.rstrip("/"))
                print(get_exit_message("invalid_arg", pfsense_server, "generic", pfsense_action, ""))
                sys.exit(1)
        # If we couldn't connect to pfSense's web configurator, return error
        else:
            print(get_exit_message("connect_err", pfsense_server, "generic", pfsense_action, ""))
            sys.exit(1)
    # If user did not pass in a hostname or IP
    else:
        print("pfsense-automator " + PfaVar.software_version)
        print("SYNTAX:")
        print("  " + get_exit_message("syntax","","generic","",""))
        flag_descrs = ""    # Initialize our flag description help string
        flag_dict = get_exit_message("", pfsense_server, "all", "", "")    # Pull our descr dictionary
        # Loop through our flag descriptions and save them to a string
        for key,value in flag_dict.items():
            # Only perform this on dict keys with -- flags
            if key.startswith("--"):
                flag_descrs = flag_descrs + value["descr"] + "\n"   # Format our return string
        print("COMMANDS:")
        print(flag_descrs.rstrip("/"))
        # Print our error and exit
        print(get_exit_message("invalid_host", "", "generic", "", ""))
        sys.exit(1)


# RUN TIME CALLS 
# Execute main function
main()

# If nothing forced us to exit the script, return exit code 0
sys.exit(0)
