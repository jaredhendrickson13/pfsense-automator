#!/usr/bin/python3
# ----------------------------------------------------------------------------------------------------------------
# Author: Jared Hendrickson
# Copyright 2019 - Jared Hendrickson
# Purpose: This script is intended to add a CLI interface for pfSense devices. This uses cURL libraries to execute
# pfSense's many PHP configuration scripts. All functions in this script mimic changes regularly made in a browser
# and utilizes pfSense's built-in CSRF checks, input validation, and configuration parsing
# ----------------------------------------------------------------------------------------------------------------
# IMPORT MODULES
import platform
import datetime
import sys
import os
import getpass
import socket
import signal
import requests
import urllib3
import json

# Variables
softwareVersion = "v0.0.3 " + platform.system() + "/" + platform.machine()    # Define our current version of this software
firstArg = sys.argv[1] if len(sys.argv) > 1 else ""    # Declare 'firstArg' to populate the first argument passed in to the script
secondArg = sys.argv[2] if len(sys.argv) > 2 else ""    # Declare 'secondArg' to populate the second argument passed in to the script
thirdArg = sys.argv[3] if len(sys.argv) > 3 else None    # Declare 'thirdArg' to populate the third argument passed in to the script
fourthArg = sys.argv[4] if len(sys.argv) > 4 else None    # Declare 'fourthArg' to populate the fourth argument passed in to the script
fifthArg = sys.argv[5] if len(sys.argv) > 5 else None    # Declare 'fifthArg' to populate the fifth argument passed in to the script
sixthArg = sys.argv[6] if len(sys.argv) > 6 else None    # Declare 'sixthArg' to populate the first argument passed in to the script
seventhArg = sys.argv[7] if len(sys.argv) > 7 else None    # Declare 'seventhArg' to populate the second argument passed in to the script
eighthArg = sys.argv[8] if len(sys.argv) > 8 else None    # Declare 'eighthArg' to populate the third argument passed in to the script
ninthArg = sys.argv[9] if len(sys.argv) > 9 else None    # Declare 'ninthArg' to populate the fourth argument passed in to the script
tenthArg = sys.argv[10] if len(sys.argv) > 10 else None    # Declare 'tenthArg' to populate the fifth argument passed in to the script
localUser = getpass.getuser()    # Save our current user's username to a string
localHostname = socket.gethostname()    # Gets the hostname of the system running pfsense-controller
currentDate = datetime.datetime.now().strftime("%Y%m%d%H%M%S")    # Get the current date in a file supported format
wcProtocol = "https"    # Assigns whether the script will use HTTP or HTTPS connections
wcProtocolPort = 443 if wcProtocol == 'https' else 80    # If wcProtocol is set to https, assign a integer value to coincide
req_session = requests.Session()    # Start our requests session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)    # Disable urllib warnings (suppress invalid cert warning)

### FUNCTIONS ###
# no_escape() Prevents SIGINT from killing the script unsafely
def no_escape(signum, frame):
    sys.exit(0)
# Set the signal handler to prevent exiting the script without killing the tunnel
signal.signal(signal.SIGINT, no_escape)

# get_exit_message() takes an exit code and other parameters to determine what success or error message to print
def get_exit_message(ec, server, command, data1, data2):
    # Local Variables
    exitMessage = ""    # Define our return value as empty string
    globalDnsRebindMsg = "Error: DNS rebind detected. Ensure `" + server + "` is listed in System > Advanced > Alt. Hostnames"
    globalAuthErrMsg = "Error: Authentication failed"
    globalPlatformErrMsg = "Error: `" + server + "` does not appear to be running pfSense"
    globalPermissionErrMsg = "Error: Unable to execute function. Your user may lack necessary permissions"
    # Define our ERROR/SUCCESS message dictionary
    ecd = {
        # Generic error message that don't occur during commands
        "generic" : {
            "invalid_arg" : "Error: Invalid argument. Unknown action `" + data1 + "`",
            "connect_err" : "Error: Failed connection to " + server + ":" + str(wcProtocolPort),
            "invalid_host" : "Error: Invalid hostname. Expected syntax: `pfsense-automator <HOSTNAME or IP> <COMMAND> <ARGS>`",
            "timeout" : "Error: connection timeout",
            "version" : "pfsense-automator " + softwareVersion
        },
        # Error/success messages for --add-vlan flag
        "--add-vlan" : {
            0 : "Successfully added VLAN `" + data1 + "` on `" + data2 + "`",
            1 : "Error: No usable interfaces were detected",
            2 : "Error: Unexpected error adding VLAN `" + data1 + "` on `" + data2 + "`",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            7 : "Error: Interface `" + data2 + "` does not exist",
            8 : "Error: VLAN `" + data1 + "` already exists on interface `" + data2 + "`",
            10 : globalDnsRebindMsg,
            15 : globalPermissionErrMsg,
            "invalid_vlan" : "Error: VLAN `" + data1 + "` out of range. Expected 1-4094",
            "invalid_priority" : "Error: VLAN priority `" + data1 + "` out of range. Expected 0-7"
        },
        # Error/success messages for --read-adv-admin flag
        "--read-adv-admin": {
            2: "Error: Unexpected error reading Advanced Settings",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported advanced admin options to " + data1,
            "export_fail": "Failed to export advanced admin options as JSON"
        },
        # Error/success messages for --set-ssh
        "--setup-ssh": {
            0: "Successfully setup SSH on `" + server + "`",
            2: "Error: Unexpected error configuring SSH",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            20: "Error: Unknown legacy SSH authentication option `" + data1 + "`",
            21: "Error: Unknown SSH authentication option `" + data1 + "`",
            "invalid_enable" : "Error: Unknown enable value `" + data1 + "`",
            "invalid_port" : "Error: SSH port `" + data1 + "` out of range. Expected 1-65535",
            "invalid_auth" : "Error: Unknown SSH authentication method `" + data1 + "`",
            "invalid_forward" : "Error: Unknown ssh-agent forwarding value `" + data1 + "`",
            "no_change" : "INFO: No differing values were requested"
        },
        # Error/success messages for --read-vlans flag
        "--read-arp": {
            2: "Error: Unexpected error reading ARP table",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported ARP table to " + data1,
            "export_fail": "Failed to export ARP table as JSON"
        },
        # Error/success messages for --add-tunable flag
        "--add-tunable" : {
            0 : "Successfully added tunable `" + data1 + "` to `" + server + "`",
            2 : "Error: Unexpected error adding system tunable",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            8 : "Error: Tunable `" + data1 + "` already exists",
            10 : globalDnsRebindMsg,
            15 : globalPermissionErrMsg
        },
        # Error/success messages for --read-tunables flag
        "--read-tunables": {
            2: "Error: Unexpected error reading system tunables",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported tunable data to " + data1,
            "export_fail": "Failed to export tunable data as JSON"
        },
        # Error/success messages for --read-vlans flag
        "--read-vlans" : {
            2 : "Error: Unexpected error reading VLAN configuration. You may not have any VLANs configured",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter" : "Error: Invalid filter `" + data1 + "`",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported VLAN data to " + data1,
            "export_fail" : "Failed to export VLAN data as JSON"
        },
        # Error/success messages for --add-dns flag
        "--add-dns" : {
            0 : "DNS record was added successfully",
            1 : "Error: DNS entry for `" + data1 + "." + data2  + "` already exists @" + server,
            2: "Error: Unexpected error adding `" + data1 + "." + data2  + "`",
            3 : globalAuthErrMsg,
            4 : "Error: DNS unreachable at " + server,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_ip" : "Error: Invalid IP address",
            "invalid_syntax" : "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --add-dns <HOST> <DOMAIN> <IP> <DESCR>`"
        },
        # Error/success messages for --read-dns
        "--read-dns" : {
            0 : True,
            2 : "Error: Unexpected error reading DNS Resolver configuration",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_syntax" : "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --read-dns <FILTER>`",
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported DNS Resolver data to " + data1,
            "export_fail" : "Failed to export DNS Resolver data as JSON"
        },
        # Error/success messages for --add-sslcert flag
        "--add-sslcert" : {
            0 : "SSL certificate successfully uploaded",
            2 : "Error: Failed to upload SSL certificate",
            3 : globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "no_cert" : "Error: No certificate file found at `" + data1 + "`",
            "no_key" : "Error: No key file found at `" + data1 + "`",
            "empty" : "Error: Certificate or key file is empty"
        },
        # Error/success messages for --read-sslcerts flag
        "--read-sslcerts" : {
            2 : "Error: Unexpected error reading SSL certificates",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "read_err" : "Error: failed to read SSL certificates from pfSense. You may not have any certificates installed",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported SSL certificate data to " + data1,
            "export_fail" : "Failed to export SSL certificate data as JSON"
        },
        # Error/success messages for --check-auth flag
        "--check-auth" : {
            "success" : "Authentication successful",
            "fail" : "Error: Authentication failed"
        },
        # Error/success messages for --read-aliases
        "--read-aliases" : {
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "read_err" : "Error: failed to read Firewall Aliases from pfSense. You may not have any Firewall Aliases configured",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported Firewall Alias data to " + data1,
            "export_fail" : "Failed to export Firewall Alias data as JSON"
        },
        # Error/success messages for --modify-alias
        "--modify-alias" : {
            0 : "Alias `" + data1 +"` successfully updated",
            1 : "Error: Unable to parse alias `" + data1 + "`",
            2 : "Error: Unexpected error processing alias",
            3 : globalAuthErrMsg,
            4 : "Error: Unable to locate alias `" + data1 + "`",
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_syntax" : "Error: Invalid syntax - `pfsense-automator <pfSense IP or FQDN> --modify-alias <alias name> <alias values>`"
        },
        # Error/success messages for --set-wc-sslcert
        "--set-wc-sslcert" : {
            0 : "Successfully changed WebConfigurator SSL certificate to `" + data1 + "`",
            1 : "Error: SSL certificate `" + data1 + "` is already in use",
            2 : "Error: Failed setting SSL certificate `" + data1 + "`",
            3 : globalAuthErrMsg,
            4 : "Error: SSL certificate `" + data1 + "` matches multiple certificates",
            5 : "Error: Certificate `" + data1 + "` not found",
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "unknown_err" : "Error: An unknown error has occurred"
        },
        # Error/success messages for -add-ldapserver
        "--add-ldapserver" : {
            0 : "Successfully added LDAP server `" + data1 + "` on `" + server + "`",
            2 : "Error: Failed to configure LDAP server",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_userAlt" : "Error: Invalid username alteration value `" + data1 + "`. Expected yes or no",
            "invalid_encode" : "Error: Invalid encode value `" + data1 + "`. Expected yes or no",
            "invalid_rfc2307": "Error: Invalid RFC2307 value `" + data1 + "`. Expected yes or no",
            "invalid_ldapTemplate": "Error: Invalid LDAP template value `" + data1 + "`",
            "invalid_bindAnon" : "Error: Invalid bind anonymous value `" + data1 + "`. Expected yes or no",
            "invalid_extQuery": "Error: Invalid extended query value `" + data1 + "`. Expected yes or no",
            "invalid_searchScope": "Error: Invalid search scope value `" + data1 + "`",
            "invalid_timeout_range": "Error: server timeout value `" + data1 + "` out of range. Expected 1-9999999999",
            "invalid_timeout": "Error: Invalid timeout value `" + data1 + "`",
            "invalid_protocol": "Error: Invalid LDAP version value `" + data1 + "`. Expected 2 or 3",
            "invalid_transport": "Error: Unknown transport type `" + data1 + "`",
            "invalid_port" : "Error: Invalid LDAP port value `" + data1 + "`",
            "invalid_portrange" : "Error: LDAP port `" + data1 + "` out of range. Expected 1-65535",
            "missing_args" : "Error: missing arguments"
        }
    }
    # Pull the requested message
    exitMessage = ecd[command][ec]
    # Return our message
    return exitMessage

# http_request() uses the requests module to make HTTP POST/GET requests
def http_request(url, data, headers, method):
    # Local Variables
    resp_dict = {}    # Initialize response dictionary to return our response values
    data = {} if type(data) != dict else data
    headers = {} if type(headers) != dict else headers
    method_list = ['GET', 'POST']    # Set a list of supported HTTP methods
    # Check that our method is valid
    if method.upper() in method_list:
        # Process to run if a GET request was requested
        if method.upper() == "GET":
            try:
                req = req_session.get(url, headers=headers, verify=False, timeout=45)
            except requests.exceptions.ReadTimeout:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
        # Process to run if a POST request was requested
        elif method.upper() == "POST":
            # Try to open the connection and gather data
            try:
                req = req_session.post(url, data=data, headers=headers, verify=False, timeout=45)
            except requests.exceptions.ReadTimeout:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
        # Populate our response dictionary with our response values
        resp_dict["text"] = req.text  # Save our HTML text data
        resp_dict["resp_code"] = req.status_code  # Save our response code
        resp_dict["req_url"] = url    # Save our requested URL
        resp_dict["resp_url"] = req.url    # Save the URL returned in our response
        resp_dict["resp_headers"] = req.headers  # Save our response headers
        resp_dict["method"] = method.upper()    # Save our HTTP method
        resp_dict['encoding'] = req.encoding    # Save our encode type
        resp_dict['cookies'] = req.cookies    # Save our encode type
        # Return our response dict
        return resp_dict
    # Return method error if method is invalid
    else:
        raise ValueError("invalid HTTP method `" + method + "`")

# export_json() exports a Python dictionary as a JSON file
def export_json(dictionary, jsonPath, jsonName):
    # Open an export file and save our data
    with open(jsonPath + jsonName, "w") as jf:
        json.dump(dictionary, jf)
    # Check that file now exists
    jsonExported = True if os.path.exists(jsonPath + jsonName) else False
    # Return our boolean
    return jsonExported

# filter_input() sanitizes a string of special or otherwise malicious characters. Returns the formatted string.
def filter_input(stf):
    # Local Variables
    specialChars = [",","~","!","@","#","$","%","^","&","*","(",")","+","=","{","}","[","]","\\", "\"","\'",":",";","\'","?","/","<",">"]
    # Check if input is string
    if isinstance(stf, str):
        # For each character in the list, replace the character with blank space
        for char in specialChars:
            stf = stf.replace(char,"")
    # Return filtered string
    return stf

# structure_whitespace() takes a string and a length and adds whitespace to ensure that string matches that length
def structure_whitespace(string, length, char, strict_length):
    # Check that variables are correct type
    if type(string) is str and type(length) is int:
        # Check the string length
        if len(string) < length:
            # Loop until the str is the appropriate length
            while len(string) < length:
                string = string + char    # Add single whitespace
        # If strict_length is True, remove extra character length from longer strings
        if len(string) > length and strict_length:
            # Loop through through string length and remove anything after the max length
            remLoop = 0    # Assign a loop index to track which character we are on
            remString = ""    # Assign variable to temporarily assign our characters to
            for c in string:
                # Check if we've reach our max length -3 (make room for ellipses)
                if remLoop == length - 3:
                    remString = remString + "..."     # Add ellipses
                    string = remString    # Save remString to our return string
                    break
                # Add the character to our string and increase our index
                remString = remString + c
                remLoop = remLoop + 1
    # Return our structured string
    return string

# validate_platform()
def validate_platform(url):
    # Local variables
    htmlStr = http_request(url, {}, {}, "GET")["text"]    # Get our HTML data
    platformConfidence = 0    # Assign a integer confidence value
    # List of platform dependent key words to check for
    checkItems = [
        "pfSense", "pfsense.org", "Login to pfSense", "pfsense-logo",
        "netgate.com", "__csrf_magic", "ESF", "Netgate", "Rubicon Communications, LLC"
    ]
    # Loop through our list and add up a confidence score
    for ci in checkItems:
        # Check if our keyword is in the HTML string, if so add 10 to our confidence value
        platformConfidence = platformConfidence + 10 if ci in htmlStr else platformConfidence
    # Determine whether our confidence score is high enough to allow requests
    platformConfirm = True if platformConfidence > 50 else False
    # Return our bool
    return platformConfirm

# validate_ip() attempts to parse the IP into expected data. If the IP is not valid, false is returned.
def validate_ip(ip):
    # Local Variables
    validIP = False    # Assign the function's return value as a boolean
    loopIndex = 0    # Assign the octet validation loop's index as 0
    # Try to split the IP into an array at each octet (dot)
    if isinstance(ip, str):
        ipToValidate = ip.split(".")
        # Check if the expected 4 octets are returned (IPv4 only)
        if len(ipToValidate) == 4:
            # For each octet, ensure IP is in range
            for octet in ipToValidate:
                # Try to convert each octet into an integer, if there is a ValueError we know it is not a valid IP
                try:
                    octetInteger = int(octet)
                # Break if we cannot convert to integer
                except ValueError:
                    break
                # Check if integer is within the acceptable range (0-255)
                if 255 >= octetInteger >= 0:
                    # If all octets were validated
                    if loopIndex == 3:
                        validIP = True    # If all octets survived the check, return True
                # Break if int is out of range
                else:
                    break
                loopIndex = loopIndex + 1    # Increase the index after each loop completion
    # Return boolean
    return validIP

# check_remote_port tests if a remote port is open. This function will return True if the connection was successful.
def check_remote_port(HOST,PORT):
    checkConnect = None    # Initialize checkConnect a variable to track connection statuses
    notResolve = None     # Initialize notResolve for use in DNS resolution errors
    portOpen = False    # Assign boolean variable to return from this function
    portTestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Setup a socket for testing connections to a remote host and port
    portTestSock.settimeout(0.5)    # Set the socket timeout time. This should be as low as possible to improve performance
    # Try to use the socket to connect to the remote port
    try:
        checkConnect = portTestSock.connect_ex((HOST,PORT))    # If the port test was successful, checkConnect will be 0
        portTestSock.close()    # Close the socket
    # If we could not connect, determine if it was a DNS issue and print error
    except socket.gaierror as sockErr:
        notResolve = True
    # If the connection was established, return portOpen as true. Otherwise false
    if checkConnect == 0:
        portOpen = True
    return portOpen

# check_dns() checks the DNS server for existing A records
def check_dns(server, user, key, host, domain):
    # Local Variables
    recordExists = False # Set return value False by default
    recordDict = get_dns_entries(server, user, key)
    # Check if domain is valid
    if domain in recordDict["domains"]:
        # Check if host entry exists
        if host in recordDict["domains"][domain]:
            recordExists = True
    #Return boolean
    return recordExists

# check_permissions() tasks an HTTP response and determines whether a permissions error was thrown
def check_permissions(httpResp):
    # Local Variables
    permit = False    # Default our return value to false
    noUserPage = "<a href=\"index.php?logout\">No page assigned to this user! Click here to logout.</a>"    # HTML error page when user does not have any permissions
    # Check if our user receives responses indicating permissions failed
    if noUserPage not in httpResp["text"] and httpResp["req_url"].split("?")[0] == httpResp["resp_url"].split("?")[0]:
        permit = True    # Return a true value if our response looks normal
    # Return our boolean
    return permit

# check_dns_rebind_error() checks if access to the webconfigurator is denied due to a DNS rebind error
def check_dns_rebind_error(url):
    # Local Variables
    httpResponse = http_request(url, {}, {}, "GET")["text"]    # Get the HTTP response of the URL
    rebindError = "Potential DNS Rebind attack detected"    # Assigns the error string to look for when DNS rebind error occurs
    rebindFound = False    # Assigns a boolean to track whether a rebind error was found. This is our return value
    # Check the HTTP response code for error message
    if rebindError in httpResponse:
        rebindFound = True    # If the the HTTP response contains the error message, return true
    # Return our boolean
    return rebindFound

# check_auth() runs a basic authentication check. If the authentication is successful a true value is returned
def check_auth(server, user, key):
    print(wcProtocol + str(wcProtocolPort))
    # Local Variables
    authSuccess = False    # Set the default return value to false
    url = wcProtocol + "://" + server    # Assign our base URL
    authCheckData = {"__csrf_magic": get_csrf_token(url + "/index.php", "GET"), "usernamefld": user, "passwordfld": key, "login": "Sign In"}    # Define a dictionary for our login POST data
    preAuthCheck = http_request(url + "/index.php", {}, {}, "GET")
    # Check that we're not already signed
    if not "class=\"fa fa-sign-out\"" in preAuthCheck["text"]:
        # Complete authentication
        authCheck = http_request(url + "/index.php", authCheckData, {}, "POST")
        authSuccess = True if not "Username or Password incorrect" in authCheck["text"] and "class=\"fa fa-sign-out\"" in authCheck["text"] else authSuccess    # Return false if login failed
    # Else return true because we are already signed in
    else:
        authSuccess = True
    return authSuccess

# get_csrf_token() makes an initial connection to pfSense to retrieve the CSRF token. This supports both GET and POST requests
def get_csrf_token(url, type):
        # Local Variables
        csrfTokenLength = 55  # Set the expected token length of the csrf token
        csrfResponse = http_request(url, None, {}, type)
        # Parse CSRF token and conditionalize return value
        csrfParsed = "sid:" + csrfResponse['text'].split("sid:")[1].split(";")[0].replace(" ", "").replace("\n", "").replace("\"", "")
        csrfToken = csrfParsed if len(csrfParsed) is csrfTokenLength else ""    # Assign the csrfToken to the parsed value if the expected string length is found
        return csrfToken    # Return our token

# get_system_advanced_admin() pulls our current configuration from System > Advanced > Admin Access and saves it to a dictionary
def get_system_advanced_admin(server, user, key):
    # Pre-define our function dictionary
    advAdm = {"ec" : 2, "adv_admin" : {
        "webconfigurator" : {},
        "secure_shell" : {},
        "login_protection" : {"whitelist" : {}},
        "serial_communcations" : {},
        "console_options" : {}
    }}
    url = wcProtocol + "://" + server    # Assign our base URL
    # Submit our intitial request and check for errors
    advAdm["ec"] = 10 if check_dns_rebind_error(url) else advAdm["ec"]    # Return exit code 10 if dns rebind error found
    advAdm["ec"] = 6 if not validate_platform(url) else advAdm["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if advAdm["ec"] == 2:
        advAdm["ec"] = 3 if not check_auth(server, user, key) else advAdm["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if advAdm["ec"] == 2:
        # Check that we had permissions for this page
        getAdvAdmData = http_request(url + "/system_advanced_admin.php", {}, {}, "GET")    # Pull our admin data using GET HTTP
        if check_permissions(getAdvAdmData):
            # Check that we have a webconfigurator table
            if "<h2 class=\"panel-title\">webConfigurator</h2>" in getAdvAdmData["text"]:
                # Parse the values from the 'WEBCONFIGURATOR' section of /system_advanced_admin.php
                wcAdmTableBody = getAdvAdmData["text"].split("<h2 class=\"panel-title\">webConfigurator</h2>")[1].split("<span class=\"help-block\">When this is unchecked, the browser tab shows")[0]  # Find the data table body
                advAdm["adv_admin"]["webconfigurator"]["webguiproto"] = "http" if "checked=\"checked\"" in wcAdmTableBody.split("id=\"webguiproto_http:")[1].split("</label>")[0] else "https"    # Check what protocol webconfigurator is using
                advAdm["adv_admin"]["webconfigurator"]["webguiport"] = wcAdmTableBody.split("id=\"webguiport\"")[1].split("value=\"")[1].split("\"")[0] if "webguiport" in wcAdmTableBody else ""    # Check the max processes webconfigurator allows
                advAdm["adv_admin"]["webconfigurator"]["max_procs"] = wcAdmTableBody.split("id=\"max_procs\"")[1].split("value=\"")[1].split("\"")[0] if "max_procs" in wcAdmTableBody else ""   # Check the max processes webconfigurator allows
                advAdm["adv_admin"]["webconfigurator"]["webgui-redirect"] = True if "webgui-redirect" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"webgui-redirect\"")[1].split("</label>")[0] else False    # Check if HTTPS redirect is enabled
                advAdm["adv_admin"]["webconfigurator"]["webgui-hsts"] = True if "webgui-hsts" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"webgui-hsts\"")[1].split("</label>")[0] else False    # Check if strict transport security is enabled
                advAdm["adv_admin"]["webconfigurator"]["ocsp-staple"] = True if "ocsp-staple" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"ocsp-staple\"")[1].split("</label>")[0] else False    # Check if OCSP stapling is enabled
                advAdm["adv_admin"]["webconfigurator"]["loginautocomplete"] = True if "loginautocomplete" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"loginautocomplete\"")[1].split("</label>")[0] else False    # Check if login auto completeion is enabled
                advAdm["adv_admin"]["webconfigurator"]["webgui-login-messages"] = True if "webgui-login-messages" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"webgui-login-messages\"")[1].split("</label>")[0] else False    # Check if login logging is enabled
                advAdm["adv_admin"]["webconfigurator"]["noantilockout"] = True if "noantilockout" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"noantilockout\"")[1].split("</label>")[0] else False    # Check if anti-lockout rule is disabled
                advAdm["adv_admin"]["webconfigurator"]["nodnsrebindcheck"] = True if "nodnsrebindcheck" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"noantilockout\"")[1].split("</label>")[0] else False    # Check if DNS rebind checking is enabled
                advAdm["adv_admin"]["webconfigurator"]["nohttpreferercheck"] = True if "nohttpreferercheck" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"nohttpreferercheck\"")[1].split("</label>")[0] else False    # Check if HTTP-REFERRER checks are enabled
                advAdm["adv_admin"]["webconfigurator"]["pagenamefirst"] = True if "pagenamefirst" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"pagenamefirst\"")[1].split("</label>")[0] else False    # Check if page name first is checked (adds hostname to browser tab first)
                advAdm["adv_admin"]["webconfigurator"]["althostnames"] = wcAdmTableBody.split("id=\"althostnames\"")[1].split("value=\"")[1].split("\"")[0] if "althostnames" in wcAdmTableBody else ""    # Save our alternate hostname values to a string
                # Loop through our WC SSL CERTIFICATE to find which is being used
                sslCertOpt = wcAdmTableBody.split("id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=\"")
                for cert in sslCertOpt:
                    # Check our certificate is selected
                    if "selected>" in cert:
                        advAdm["adv_admin"]["webconfigurator"]["ssl-certref"] = cert.split("\"")[0]    # Assign our cert ref ID to our dictionary
                        break
                    # If no certificate was found, assume default
                    else:
                        advAdm["adv_admin"]["webconfigurator"]["ssl-certref"] = ""    # Assign default if not found
            # If we did not have a webconfigurator table
            else:
                # Assign all default webconfigurator values
                advAdm["adv_admin"]["webconfigurator"] = {
                    "webguiproto" : "",
                    "webguiport" : "", "max_procs" : "",
                    "webgui-redirect" : False,
                    "webgui-hsts" : False,
                    "ocsp-staple" : False,
                    "loginautocomplete" : False,
                    "webgui-login-messages" : False,
                    "noantilockout" : False,
                    "nodnsrebindcheck" : False,
                    "nohttpreferercheck" : False,
                    "pagenamefirst" : False,
                    "althostnames" : "",
                    "ssl-certref" : ""
                }
            # Check that we have a configuration table for SECURE SHELL
            if "<h2 class=\"panel-title\">Secure Shell</h2>" in getAdvAdmData["text"]:
                # Parse the values from the 'SECURE SHELL' section of /system_advanced_admin.php
                sshAdmTableBody = getAdvAdmData["text"].split("<h2 class=\"panel-title\">Secure Shell</h2>")[1].split("<span class=\"help-block\">Note: Leave this blank for the default of 22")[0]  # Find the data table body
                advAdm["adv_admin"]["secure_shell"]["enablesshd"] = True if "enablesshd" in sshAdmTableBody and "checked=\"checked\"" in sshAdmTableBody.split("id=\"enablesshd\"")[1].split("</label>")[0] else False    # Check if SSH  is enabled
                advAdm["adv_admin"]["secure_shell"]["sshdagentforwarding"] = True if "sshdagentforwarding" in sshAdmTableBody and "checked=\"checked\"" in sshAdmTableBody.split("id=\"sshdagentforwarding\"")[1].split("</label>")[0] else False    # Check if SSH forwarding  is enabled
                advAdm["adv_admin"]["secure_shell"]["sshport"] = sshAdmTableBody.split("id=\"sshport\"")[1].split("value=\"")[1].split("\"")[0] if "value=\"" in sshAdmTableBody.split("id=\"sshport\"")[1] and "sshport" in sshAdmTableBody else ""   # Save our SSH port value
                # Check if we are running pfsense 2.4.4+
                if "<select class=\"form-control\" name=\"sshdkeyonly\" id=\"sshdkeyonly\">" in sshAdmTableBody:
                    # Loop through our SSL authentication options and find the currently select option
                    advAdm["adv_admin"]["secure_shell"]["legacy"] = False    # Assign a value to indicate this isn't a legacy pfSense version
                    sshAuthOpt = sshAdmTableBody.split("id=\"sshdkeyonly\">")[1].split("</select>")[0].split("<option value=\"") if "sshdkeyonly" in sshAdmTableBody else []    # Find our options if available, otherwise assume default
                    for auth in sshAuthOpt:
                        # Check our certificate is selected
                        if "selected>" in auth:
                            advAdm["adv_admin"]["secure_shell"]["sshdkeyonly"] = auth.split("\"")[0]    # Assign our auth type to our dictionary
                            break
                        # If the default is used
                        else:
                            advAdm["adv_admin"]["secure_shell"]["sshdkeyonly"] = "disabled"    # Assign our default value
                # Check if we are running an older version of pfSense
                elif "<label class=\"chkboxlbl\"><input name=\"sshdkeyonly\"" in sshAdmTableBody:
                    advAdm["adv_admin"]["secure_shell"]["sshdkeyonly"] = True if "checked=\"checked\"" in sshAdmTableBody.split("id=\"sshdkeyonly\"")[1].split("</label>")[0] else False    # Assign our ssh auth type
                    advAdm["adv_admin"]["secure_shell"]["legacy"] = True    # Assign a value to indicate this is a legacy pfSense version
            # If we did not have a secure shell table
            else:
                # Assign all default secure shell values
                advAdm["adv_admin"]["secure_shell"] = {
                    "enablesshd" : False,
                    "sshdagentforwarding" : False,
                    "sshport" : "",
                    "sshdkeyonly" : ""
                }
            # Parse the values from the 'LOGIN PROTECTION' section of /system_advanced_admin.php
            if "<h2 class=\"panel-title\">Login Protection</h2>" in getAdvAdmData["text"]:
                loginAdmTableBody = getAdvAdmData["text"].split("<h2 class=\"panel-title\">Login Protection</h2>")[1].split("class=\"btn btn-success addbtn")[0]  # Find the data table body
                advAdm["adv_admin"]["login_protection"]["sshguard_threshold"] = loginAdmTableBody.split("id=\"sshguard_threshold\"")[1].split("value=\"")[1].split("\"")[0] if "sshguard_threshold" in loginAdmTableBody else ""    # Save our protection threshold value (number of allowed attacks)
                advAdm["adv_admin"]["login_protection"]["sshguard_blocktime"] = loginAdmTableBody.split("id=\"sshguard_blocktime\"")[1].split("value=\"")[1].split("\"")[0] if "sshguard_blocktime" in loginAdmTableBody else ""   # Save our protection block value (duration of block)
                advAdm["adv_admin"]["login_protection"]["sshguard_detection_time"] = loginAdmTableBody.split("id=\"sshguard_detection_time\"")[1].split("value=\"")[1].split("\"")[0] if "sshguard_detection_time" in loginAdmTableBody else ""    # Save our protection detection value (duration until threshold resets)
                # Loop through our whitelisted hosts (hosts that are not included in login protection)
                loginWhitelist = loginAdmTableBody.split("<input class=\"form-control\" name=\"address")
                for host in loginWhitelist:
                    # Check that we have a value and selections
                    if "value=" in host and "<select" in host:
                        addressId = host.split("\"")[0]    # Get our address ID
                        value = host.split("value=\"")[1].split("\"")[0]
                        # Loop through our subnet select options and pull our subnet
                        subnetData = host.split("<select class=\"form-control pfIpMask\"")[1].split("</select>")[0]
                        subnetSelection = subnetData.split("<option value=\"")    # Split our subnet options into a list
                        for net in subnetSelection:
                            # Check if this subnet is selected
                            if "selected>" in net:
                                subnet = net.split("\"")[0]
                                break
                            # If a selected subnet was not found assume the default
                            else:
                                subnet = ""    # Assign our DEFAULT subnet
                        advAdm["adv_admin"]["login_protection"]["whitelist"][addressId] = {"id" : "address" + addressId, "value" : value, "subnet" : subnet}
            # If we did not have a login protection table
            else:
                # Assign all default login protection values
                advAdm["adv_admin"]["login_protection"] = {
                    "sshguard_threshold" : "",
                    "sshguard_blocktime" : "",
                    "sshguard_detection_time" : "",
                    "whitelist" : {}
                }
            # Parse the values from the 'SERIAL COMMUNICATIONS' section of /system_advanced_admin.php
            if "<h2 class=\"panel-title\">Serial Communications</h2>" in getAdvAdmData["text"]:
                serialAdmTableBody = getAdvAdmData["text"].split("<h2 class=\"panel-title\">Serial Communications</h2>")[1].split("<span class=\"help-block\">Select the preferred console")[0]  # Find the data table body
                advAdm["adv_admin"]["serial_communcations"]["enableserial"] = True if "enableserial" in serialAdmTableBody and "checked=\"checked\"" in serialAdmTableBody.split("id=\"enableserial\"")[1].split("</label>")[0] else False    # Check if serial communication is enabled
                # Loop through our SERIALSPEEDS to find our selected speed value
                speedSelect = serialAdmTableBody.split("id=\"serialspeed\">")[1].split("</select>")[0].split("<option value=\"")    # Target our serial speed options
                for spd in speedSelect:
                    # Check that it meets our expected criteria
                    if "selected>" in spd:
                        advAdm["adv_admin"]["serial_communcations"]["serialspeed"] = spd.split("\"")[0]    # Save our serial speed
                        break
                    else:
                        advAdm["adv_admin"]["serial_communcations"]["serialspeed"] = ""    # Assume default if speed not found in current loop cycle
                # Loop through our console types to find our primaryconsole
                consoleSelect = serialAdmTableBody.split("id=\"primaryconsole\">")[1].split("</select>")[0].split("<option value=\"")    # Target our serial console options
                for csl in consoleSelect:
                    # Check that it meets our expected criteria
                    if "selected>" in csl:
                        advAdm["adv_admin"]["serial_communcations"]["primaryconsole"] = csl.split("\"")[0]    # Save our serial console type
                        break
                    else:
                        advAdm["adv_admin"]["serial_communcations"]["primaryconsole"] = ""    # Assume default if console type not found in current loop cycle
            # If we did not have a serial communications table
            else:
                # Assign all default serial communications values
                advAdm["adv_admin"]["serial_communcations"] = {
                    "enableserial" : False,
                    "serialspeed" : "",
                    "primaryconsole" : ""
                }
            # Parse the values from the 'CONSOLE OPTIONS' section of /system_advanced_admin.php
            if "<h2 class=\"panel-title\">Console Options</h2>" in getAdvAdmData["text"]:
                consoleAdmTableBody = getAdvAdmData["text"].split("<h2 class=\"panel-title\">Console Options</h2>")[1].split("<div class=\"col-sm-10 col-sm-offset-2\">")[0]  # Find the data table body
                advAdm["adv_admin"]["console_options"]["disableconsolemenu"] = True if "disableconsolemenu" in consoleAdmTableBody and "checked=\"checked\"" in consoleAdmTableBody.split("id=\"disableconsolemenu\"")[1].split("</label>")[0] else False    # Check if console is password protected
            # If we did not hae a console options table
            else:
                # Assign all default console option values
                advAdm["adv_admin"]["console_options"]["disableconsolemenu"] = False
            # Update to exit code 0 (success) if we populated our dictionary
            advAdm["ec"] = 0
        # If we did not have permissions
        else:
            advAdm["ec"] = 15    # Assign exit code 15 (permission denied)
    # Return our exit code
    return advAdm

# get_system_advanced_admin_post_data() converts our advanced admin dictionary to a POST data dictionary
def get_system_advanced_admin_post_data(dictionary):
    # Local Variables
    postData = {}    # Pre-define our return value as empty dictionary
    # Loop through our existing /system_advanced_admin.php configuration and add the data to the POST request
    for table, data in dictionary.items():
        # Loop through each value in the table dictionaries
        for key, value in data.items():
            value = "yes" if value == True else value  # Swap true values to "yes"
            value = "" if value == False else value  # Swap false values to empty string
            # Check if we are checking our login protection whitelist
            if key == "whitelist":
                # Add each of our whitelisted IPs to our post data
                for id, info in value.items():
                    addrId = info["id"]
                    postData[addrId] = info["value"]
                    postData["address_subnet" + id] = info["subnet"]
            # If we are not adding whitelist values, simply add the key and value
            else:
                postData[key] = value  # Populate our data to our POST data
    # Return our POST data dictionary
    return postData

# setup_ssh() configures sshd settings found in /system_advanced_admin.php
def setup_ssh(server, user, key, enable, port, auth, forwarding):
    # Local Variables
    sshConfigured = 2    # Pre-define our exit code as 2
    url = wcProtocol + "://" + server    # Assign our base URL
    existingAdvAdm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    # Check if we got our advanced admin dictionary successfully
    if existingAdvAdm["ec"] == 0:
        # FORMAT OUR POST DATA
        sshPostData = get_system_advanced_admin_post_data(existingAdvAdm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
        sshPostData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        # Check that we do not want to retain our current value
        if enable.upper() != "DEFAULT":
            sshPostData["enablesshd"] = "yes" if enable == "enable" else ""    # Save our enablesshd POST value to "yes" if we passed in a true value to enable
        # Check that we do not want to retain our current value
        if port.upper() != "DEFAULT":
            sshPostData["sshport"] = port    # Save our ssh port value to our POST data
        # Check that we do not want to retain our current auth value
        if auth.upper() != "DEFAULT":
            # Check if we are POSTing to an older pfSense version
            if existingAdvAdm["adv_admin"]["secure_shell"]["legacy"]:
                # Check that our auth method is expected
                if auth in ["keyonly", "key", "pass", "password", "passwd"]:
                    sshPostData["sshdkeyonly"] = "yes" if auth in ["keyonly", "key"] else ""    # For legacy pfSense versions, assign a "yes" or empty string value given a bool
                else:
                    sshConfigured = 20    # Assign exit code 20 (invalid legacy ssh auth method)
            # If we are not on a legacy pfSense system
            else:
                # Check that our auth method is expected
                if auth in ["keyonly", "key", "pass", "password", "passwd", "mfa", "both", "all"]:
                    sshPostData["sshdkeyonly"] = "disabled" if auth in ["pass", "password", "passwd"] else sshPostData["sshdkeyonly"]    # Save our sshdkeyonly value if user wants password logins
                    sshPostData["sshdkeyonly"] = "enabled" if auth in ["keyonly", "key"] else sshPostData["sshdkeyonly"]    # Save our sshdkeyonly value if user wants keyonly logins
                    sshPostData["sshdkeyonly"] = "both" if auth in ["mfa", "both", "all"] else sshPostData["sshdkeyonly"]    # Save our sshdkeyonly value if user wants MFA SSH logins (key and password)
                else:
                    sshConfigured = 21    # Assign exit code 20 (invalid ssh auth method)
        # Check that we do not want to retain our current auth value
        if forwarding.upper() != "DEFAULT":
            # This value only exists on non-legacy pfSense, check that we are not running legacy
            if not existingAdvAdm["adv_admin"]["secure_shell"]["legacy"]:
                sshPostData["sshdagentforwarding"] = "yes" if forwarding in ["enable", "enable-forwarding", "yes", "ef"] else ""    # Save our sshdagentforwarding value to our POST data
        # Check that we did not encounter an error
        if sshConfigured == 2:
            # Use POST HTTP to save our new values
            postSshConfig = http_request(url + "/system_advanced_admin.php", sshPostData, {}, "POST")    # POST our data
            # Check that our values were updated, assign exit codes accordingly
            newExistingAdvAdm = get_system_advanced_admin_post_data(get_system_advanced_admin(server, user, key)["adv_admin"])    # Get our dictionary of configured advanced options
            # Loop through our POST variables and ensure they match
            for d in ["enablesshd", "sshport", "sshdkeyonly", "sshdagentforwarding"]:
                if newExistingAdvAdm[d] != sshPostData[d]:
                    sshConfigured = 2    # Revert to exit code 2 (unexpected error
                    break
                else:
                    sshConfigured = 0    # Assign our success exit code
    # If we could not successfully pull our advanced admin configuration, return the exit code of that function
    else:
        sshConfigured = existingAdvAdm["ec"]
    # Return our exit code
    return sshConfigured
# get_arp_table() pulls our pfSense's current ARP table
def get_arp_table(server, user, key):
    arpTable = {"ec" : 2, "arp" : {}}    # Pre-define our function dictionary
    url = wcProtocol + "://" + server    # Assign our base URL
    # Submit our intitial request and check for errors
    arpTable["ec"] = 10 if check_dns_rebind_error(url) else arpTable["ec"]    # Return exit code 10 if dns rebind error found
    arpTable["ec"] = 6 if not validate_platform(url) else arpTable["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if arpTable["ec"] == 2:
        arpTable["ec"] = 3 if not check_auth(server, user, key) else arpTable["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if arpTable["ec"] == 2:
        # Check that we had permissions for this page
        getArpData = http_request(url + "/diag_arp.php", {}, {}, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(getArpData):
            arpTableBody = getArpData["text"].split("<tbody>")[1].split("</tbody>")[0]  # Find the data table body
            arpTableRows = arpTableBody.replace("\t", "").replace("\n", "").replace("</tr>", "").split("<tr>")  # Find each of our table rows
            # Loop through our rows to pick out our values
            counter = 0    # Assign a loop counter
            for row in arpTableRows:
                # Check that the row is not empty
                if row != "" and "<td>" in row:
                    arpTableData = row.split("<td>")    # Split our table row into individual data fields
                    arpTable["arp"][counter] = {}    # Assign a dictionary for each arp value
                    arpTable["arp"][counter]["interface"] = arpTableData[1].replace("</td>", "")    # Assign our interface value to the dictionary
                    arpTable["arp"][counter]["ip"] = arpTableData[2].replace("</td>", "")    # Assign our ip value to the dictionary
                    arpTable["arp"][counter]["mac_addr"] = arpTableData[3].split("<small>")[0].replace("</td>", "")    # Assign our mac address value to the dictionary
                    arpTable["arp"][counter]["mac_vendor"] = ""    # Default our mac_vendor value to empty string
                    # Assign a mac vendor value if one exists
                    if "<small>" in arpTableData[3]:
                        arpTable["arp"][counter]["mac_vendor"] = arpTableData[3].split("<small>")[1].replace("</small>", "").replace("(", "").replace(")", "").replace("</td>", "")    # Assign our mac vendor value to the dictionary
                    # Check if extra values exist (pfSense 2.4+)
                    arpTable["arp"][counter]["hostname"] = arpTableData[4].replace("</td>", "") if len(arpTableData) > 4 else ""    # Assign our hostname value to the dictionary
                    arpTable["arp"][counter]["expires"] = arpTableData[5].replace("</td>", "").replace("Expires in ", "") if len(arpTableData) > 6 else ""   # Assign our expiration value to the dictionary
                    arpTable["arp"][counter]["type"] = arpTableData[6].replace("</td>", "") if len(arpTableData) > 6 else ""    # Assign our link type value to the dictionary
                    counter = counter + 1    # Increase our counter
            # Set our exit code to zero if our dictionary is populated
            arpTable["ec"] = 0 if len(arpTable) > 0 else arpTable["ec"]
        # If we did not have permission to the ARP table
        else:
            arpTable["ec"] = 15    # Assign exit code 15 if we did not have permission (permission denied)
    # Return our dictionary
    return arpTable

# get_system_tunables() pulls the System Tunable values from the advanced settings
def get_system_tunables(server, user, key):
    tunables = {"ec" : 2, "tunables" : {}}    # Pre-define our function dictionary
    url = wcProtocol + "://" + server    # Assign our base URL
    # Submit our intitial request and check for errors
    tunables["ec"] = 10 if check_dns_rebind_error(url) else tunables["ec"]    # Return exit code 10 if dns rebind error found
    tunables["ec"] = 6 if not validate_platform(url) else tunables["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if tunables["ec"] == 2:
        tunables["ec"] = 3 if not check_auth(server, user, key) else tunables["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if tunables["ec"] == 2:
        # Check that we had permissions for this page
        getTunableData = http_request(url + "/system_advanced_sysctl.php", {}, {}, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(getTunableData):
            tunableBody = getTunableData["text"].split("<table class")[1].split("</table>")[0]  # Find the data table body
            tunableRows = tunableBody.replace("\t", "").replace("\n", "").replace("</tr>", "").split("<tr>")  # Find each of our table rows
            # Loop through our rows to pick out our values
            counter = 0    # Assign a loop counter
            for row in tunableRows:
                # Check that the row is not empty
                if row != "" and "<td>" in row:
                    tunableData = row.split("<td>")    # Split our data into a list
                    tunableName = tunableData[1].replace("</td>", "")    # Assign our tunable name to a variables
                    tunables["tunables"][tunableName] = {"name" : tunableName} if tunableName not in tunables["tunables"] else tunables["tunables"][tunableName]    # Define our value dict if one doesn't exist
                    tunables["tunables"][tunableName]["descr"] = tunableData[2].replace("</td>", "")    # Assign our tunable description to a variables
                    tunables["tunables"][tunableName]["value"] = tunableData[3].replace("</td>", "")    # Assign our tunable value to a variables
                    tunables["tunables"][tunableName]["id"] = tunableData[4].replace("</td>", "").split("href=\"system_advanced_sysctl.php?act=edit&amp;id=")[1].split("\"")[0]    # Assign our tunable description to a variables
            # Set our exit code to zero if our dictionary is populated
            tunables["ec"] = 0 if len(tunables["tunables"]) > 0 else tunables["ec"]
        # If we did not have permission to the tunables
        else:
            tunables["ec"] = 15    # Assign exit code 15 if we did not have permission (permission denied)
    # Return our dictionary
    return tunables

# add_system_tunable() adds a new system tunable
def add_system_tunable(server, user, key, name, descr, value):
    # Local Variables
    tunableAdded = 2    # Assign our default return code. (2 means generic failure)
    url = wcProtocol + "://" + server    # Assign our base URL
    existingTunables = get_system_tunables(server, user, key)    # Get our dictionary of configured tunables
    tunablePostData = {"__csrf_magic" : "", "tunable" : name, "value" : value, "descr" : descr, "save" : "Save"}    # Assign our POST data
    # Check if we got our VLAN dictionary successfully
    if existingTunables["ec"] == 0:
        # Loop through existing VLAN to check that our requested VLAN ID isn't already configured
        if name in existingTunables["tunables"]:
            tunableAdded = 8  # Return exit code 8 (tunable already exists)
        # Check that we did not encounter an error
        if tunableAdded == 2:
            # Use GET HTTP to see what interfaces are available
            getExistingIfaces = http_request(url + "/system_advanced_sysctl.php?act=edit", {}, {}, "GET")    # Get our HTTP response
            # Check that we had permissions for this page
            if check_permissions(getExistingIfaces):
                tunablePostData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_sysctl.php?act=edit", "GET")    # Update our CSRF token
                postTunable = http_request(url + "/system_advanced_sysctl.php?act=edit", tunablePostData, {}, "POST")    # POST our data
                applyTunableData = {"__csrf_magic" : get_csrf_token(url + "/system_advanced_sysctl.php", "GET"), "apply" : "Apply Changes"}    # Assign our post data to apply changes
                applyTunable = http_request(url + "/system_advanced_sysctl.php", applyTunableData, {}, "POST")    # POST our data
                updatedTunables = get_system_tunables(server, user, key)    # Get our updated dictionary of configured tunables
                tunableAdded = 0 if name in updatedTunables["tunables"] else tunableAdded    # Check that our new value is listed
            # If we didn't have permissions to add the tunable
            else:
                tunableAdded = 15  # Return exit code 15 (permission denied)
    # If we couldn't pull existing tunables
    else:
        tunableAdded = existingTunables["ec"]    # Return the exit code that was returned by our get_existing_tunables()
    # Return our exit code
    return tunableAdded

# get_vlan_ids() pulls existing VLAN configurations from Interfaces > Assignments > VLANs
def get_vlan_ids(server, user, key):
    # Local Variables
    vlans = {"ec" : 2, "vlans" : {}}    # Predefine our dictionary that will track our VLAN data as well as errors
    url = wcProtocol + "://" + server    # Assign our base URL
    # Submit our intitial request and check for errors
    vlans["ec"] = 10 if check_dns_rebind_error(url) else vlans["ec"]    # Return exit code 10 if dns rebind error found
    vlans["ec"] = 6 if not validate_platform(url) else vlans["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if vlans["ec"] == 2:
        vlans["ec"] = 3 if not check_auth(server, user, key) else vlans["ec"]    # Return exit code 3 if we could not sign in
    # Check if we did not encountered any errors thus far, continue if not
    if vlans["ec"] == 2:
        getVlanData = http_request(url + "/interfaces_vlan.php", {}, {}, "GET")    # Pull our VLAN data using GET HTTP
        # Check that we had permissions for this page
        if check_permissions(getVlanData):
            vlanTableBody = getVlanData["text"].split("<tbody>")[1].split("</tbody>")[0]    # Find the data table body
            vlanTableRows = vlanTableBody.replace("\t","").replace("\n","").replace("</tr>", "").split("<tr>")    # Find each of our table rows
            # For each VLAN entry, parse the individual table data field
            counter = 0    # Create a counter to track the current VLAN item's placement ID
            for row in vlanTableRows:
                vlanTableData = row.replace("</td>", "").split("<td>")    # Split our row values into list of data fields
                # If the row has the minimum number of data fields, parse the data
                if len(vlanTableData) >= 6:
                    vlans["vlans"][counter] = {}    # Predefine our current table data entry as a dictionary
                    vlans["vlans"][counter]["interface"] = vlanTableData[1].split(" ")[0]    # Save our interface ID to the dictionary
                    vlans["vlans"][counter]["vlan_id"] = vlanTableData[2]    # Save our VLAN ID to the dictionary
                    vlans["vlans"][counter]["priority"] = vlanTableData[3]    # Save our priority level to the dictionary
                    vlans["vlans"][counter]["descr"] = vlanTableData[4]    # Save our description to the dictionary
                    vlans["vlans"][counter]["id"] = vlanTableData[5].split("href=\"interfaces_vlan_edit.php?id=")[1].split("\" ></a>")[0]    # Save our configuration ID to the dictionary
                    counter = counter + 1    # Increase our counter by 1
            # If our vlans dictionary was populated, return exit code 0
            vlans["ec"] = 0 if len(vlans["vlans"]) > 0 else vlans["ec"]
        # If we did not have the correct permissions return error code 15
        else:
            vlans["ec"] = 15    # Return error code 15 (permission denied)
    # Return our dictionary
    return vlans

# add_vlan_id() creates a VLAN tagged interface provided a valid physical interface in Interfaces > Assignments > VLANs
def add_vlan_id(server, user, key, iface, vlanId, priority, descr):
    # Local Variables
    vlanAdded = 2    # Assign our default return code. (2 means generic failure)
    url = wcProtocol + "://" + server    # Assign our base URL
    existingVlans = get_vlan_ids(server, user, key)    # Get our dictionary of configured VLANs
    vlanPostData = {"__csrf_magic" : "", "if" : iface, "tag" : vlanId, "pcp" : priority, "descr" : descr, "save" : "Save"}    # Assign our POST data
    # Check if we got our VLAN dictionary successfully
    if existingVlans["ec"] == 0:
        # Loop through existing VLAN to check that our requested VLAN ID isn't already configured
        for key, value in existingVlans["vlans"].items():
            if iface == value["interface"] and vlanId == value["vlan_id"]:
                vlanAdded = 8  # Return exit code 8 (VLAN already exists
                break  # Break the loop as we have found a match
        # Check that we did not encounter an error
        if vlanAdded == 2:
            # Use GET HTTP to see what interfaces are available
            getExistingIfaces = http_request(url + "/interfaces_vlan_edit.php", {}, {}, "GET")    # Get our HTTP response
            # Check that we had permissions for this page
            if check_permissions(getExistingIfaces):
                ifaceSel = getExistingIfaces["text"].split("<select class=\"form-control\" name=\"if\" id=\"if\">")[1].split("</select>")[0]    # Pull iface select tag
                ifaceOpt = ifaceSel.split("<option value=\"")    # Pull our raw options to a list
                ifaceValues = []    # Predefine our final iface value list
                # Check that we have at least one value
                if len(ifaceOpt) > 0:
                    # Loop through each value and save it's iface value to our final list
                    for i in ifaceOpt:
                            i = i.replace("\t","").replace("\n","").split("\">")[0]    # Pull the iface value from the value= parameter
                            ifaceValues.append(i)    # Add our values to the list
                    # Check that we have our values
                    if len(ifaceValues) > 0:
                        # Check that our requested iface is available
                        if iface in ifaceValues:
                            # Update our csrf token and submit our POST request
                            vlanPostData["__csrf_magic"] = get_csrf_token(url + "/interfaces_vlan_edit.php", "GET")
                            vlanPostReq = http_request(url + "/interfaces_vlan_edit.php", vlanPostData, {}, "POST")
                            # Check that our new value is now configured
                            vlanCheck = get_vlan_ids(server, user, key)
                            # Loop through existing VLAN and check for our value
                            if vlanCheck["ec"] == 0:
                                for key, value in vlanCheck["vlans"].items():
                                    # Assign exit code 0 (success) if our value is now in the configuration. Otherwise retain error
                                    vlanAdded = 0 if iface == value["interface"] and vlanId == value["vlan_id"] else vlanAdded
                        # If our request iface is not available
                        else:
                            vlanAdded = 7    # Assign exit code 7 (iface not available)
                    # If we did not have any usable interfaces
                    else:
                        vlanAdded = 1    # Assign exit code 1 (no usable interfaces)
            # If we did not have permissions to the page
            else:
                vlanAdded = 15    # Assign exit code 15 (permission denied)
    # If we failed to get our VLAN dictionary successfully, return the exit code of that function
    else:
        vlanAdded = existingVlans["ec"]    # Assign our get_vlan_ids() exit code to our return value
    # Return our exit code
    return vlanAdded

# add_auth_server_ldap() adds an LDAP server configuration to Advanced > User Mgr > Auth Servers
def add_auth_server_ldap(server, user, key, descrName, ldapServer, ldapPort, transport, ldapProtocol, timeout, searchScope, baseDN, authContainers, extQuery, query, bindAnon, bindDN, bindPw, ldapTemplate, userAttr, groupAttr, memberAttr, rfc2307, groupObject, encode, userAlt):
    # Local Variables
    ldapAdded = 2    # Set return value to 2 by default (2 mean general failure)
    url = wcProtocol + "://" + server    # Assign our base URL
    defaultAttrs = {
        "open" : {"user" : "cn", "group" : "cn", "member" : "member"},    # Assign default attributes for OpenLDAP
        "msad" : {"user" : "samAccountName", "group" : "cn", "member" : "memberOf"},     # Assign default attributes for MS Active Directory
        "edir" : {"user" : "cn", "group" : "cn", "member" : "uniqueMember"}}    # Assign default attributes for Novell eDirectory
    # Define a dictionary for our LDAP server configuration POST data
    addAuthServerData = {
        "__csrf_magic": "",
        "name": descrName,
        "type": "ldap",
        "ldap_host": ldapServer,
        "ldap_port": str(ldapPort),
        "ldap_urltype": transport,
        "ldap_protver": ldapProtocol,
        "ldap_timeout": timeout,
        "ldap_scope": searchScope,
        "ldap_basedn": baseDN,
        "ldapauthcontainers": authContainers,
        "ldap_extended_enabled": extQuery,
        "ldap_extended_query": query,
        "ldap_anon": bindAnon,
        "ldap_binddn": bindDN,
        "ldap_bindpw": bindPw,
        "ldap_tmpltype": ldapTemplate,
        "ldap_attr_user": userAttr if userAttr is not "" and userAttr is not "default" else defaultAttrs[ldapTemplate]['user'],
        "ldap_attr_group": groupAttr if userAttr is not "" and userAttr is not "default" else defaultAttrs[ldapTemplate]['group'],
        "ldap_attr_member": memberAttr if userAttr is not "" and userAttr is not "default" else defaultAttrs[ldapTemplate]['member'],
        "ldap_rfc2307": rfc2307,
        "ldap_attr_groupobj": groupObject,
        "ldap_utf8": encode,
        "ldap_nostrip_at": userAlt,
        "save": "Save"
    }
    # Check for errors and assign exit codes accordingly
    ldapAdded = 10 if check_dns_rebind_error(url) else ldapAdded    # Return exit code 10 if dns rebind error found
    ldapAdded = 6 if not validate_platform(url) else ldapAdded    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ldapAdded == 2:
        ldapAdded = 3 if not check_auth(server, user, key) else ldapAdded    # Return exit code 3 if we could not sign in
    # Check that no errors have occurred so far (should be at 2)
    if ldapAdded == 2:
        # Check that we have permission to these pages before proceeding
        addAuthPermissions = http_request(url + "/system_authservers.php?act=new", {}, {}, "GET")
        if check_permissions(addAuthPermissions):
            # Update our CSRF token and submit our POST request
            addAuthServerData["__csrf_magic"] = get_csrf_token(url + "/system_authservers.php?act=new", "GET")
            addAuthServer = http_request(url + "/system_authservers.php?act=new", addAuthServerData, {}, "POST")
            ldapAdded = 0
        # If we did not have permissions to the page
        else:
            ldapAdded = 15    # Return exit code 15 (permission denied)
    # Return our exit code
    return ldapAdded

def get_dns_entries(server, user, key):
    # Local variables
    url = wcProtocol + "://" + server    # Assign our base URL
    dnsDict = {"domains" : {}, "ec" : 2}    # Initialize our DNS entry dictionary as empty
    # Submit our intitial request and check for errors
    dnsDict["ec"] = 10 if check_dns_rebind_error(url) else dnsDict["ec"]    # Return exit code 10 if dns rebind error found
    dnsDict["ec"] = 6 if not validate_platform(url) else dnsDict["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if dnsDict["ec"] == 2:
        dnsDict["ec"] = 3 if not check_auth(server, user, key) else dnsDict["ec"]    # Return exit code 3 if we could not sign in
    # Check that login was successful
    if dnsDict["ec"] == 2:
        # Check that we have access to these pages before proceeding
        getDnsResp = http_request(url + "/services_unbound.php", {}, {}, "GET")
        if check_permissions(getDnsResp):  # Check that we had permissions for this page
            # Pull our DNS entries
            dnsBody = getDnsResp["text"].split("<tbody>")[1].split("</tbody>")[0]
            dnsRows = dnsBody.split("<tr>")
            # Cycle through our DNS rows to pull out individual values
            for r in dnsRows:
                rInvalid = False    # Tracks if a valid record was identified
                # Try to parse our values into a dictionary
                try:
                    host = r.split("<td>")[1].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                    domain = r.split("<td>")[2].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                    ip = r.split("<td>")[3].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                    descr = r.split("<td>")[4].replace("\t", "").replace("</td>", "").replace("\n", "").replace("<i class=\"fa fa-angle-double-right text-info\"></i>", "")
                    id = r.split("<td>")[5].split("?id=")[1].split("\">")[0].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                except IndexError:
                    rInvalid = True
                # Check if entry is an alias
                if not rInvalid:
                    # Check if IP contains the word ALIASFOR
                    if "Aliasfor" in ip:
                        aliasFqdn = ip.split("Aliasfor")[1]    # Assign our alias FQDN
                        aliasHost = None   # Declare a variable for our aliases parent hostname
                        aliasDomain = None # Declare a variable for our aliases parent domain name
                        # Loop through our domains and check if the Fqdn matches a domain
                        for key,value in dnsDict["domains"].items():
                            # Check what domain the alias is tied to
                            if aliasFqdn.endswith(key):
                                aliasDomain = key
                                aliasHost = aliasFqdn.replace("." + aliasDomain, "")
                                break
                        # If we found our aliases parent domain and host
                        if aliasHost is not None and aliasDomain is not None:
                            dnsDict["domains"][aliasDomain][aliasHost]["alias"][host] = {"hostname" : host, "domain" : domain, "descr" : descr}
                    # Otherwise add our item normally
                    else:
                        dnsDict["domains"][domain] = {} if not domain in dnsDict["domains"] else dnsDict["domains"][domain]
                        dnsDict["domains"][domain][host] = {"hostname" : host, "domain" : domain, "ip" : ip, "descr" : descr, "id" : id, "alias" : {}}
                    # Set our exit code to 0
                    dnsDict["ec"] = 0
        # If we did not have permissions to the page
        else:
            dnsDict["ec"] = 15    # Return exit code 15 (permission denied)
    # Return our dictionary
    return dnsDict

# add_dns_entry() performs the necessary requests to add a DNS entry to pfSense's Unbound service
def add_dns_entry(server, user, key, host, domain, ip, descr):
    # Local Variables
    recordAdded = 2    # Set return value to 2 by default (2 means failed)
    url = wcProtocol + "://" + server    # Populate our base URL
    dnsData = {"__csrf_magic": "","host" : host,"domain" : domain, "ip" : ip, "descr" : descr, "save" : "Save"}    # Define our DNS entry POST data
    saveDnsData = {"__csrf_magic": "", "apply": "Apply Changes"}    # Define our apply DNS changes POST data
    # Check if the record we are adding already exists
    if not check_dns(server, user, key, host, domain):
        # Check for errors and assign exit codes accordingly
        recordAdded = 10 if check_dns_rebind_error(url) else recordAdded    # Return exit code 10 if dns rebind error found
        recordAdded = 6 if not validate_platform(url) else recordAdded    # Check that our URL appears to be pfSense
        # Check if we have not encountered an error that would prevent us from authenticating
        if recordAdded == 2:
            recordAdded = 3 if not check_auth(server, user, key) else recordAdded    # Return exit code 3 if we could not sign in
        # Check that no errors have occurred so far (should be at 2)
        if recordAdded == 2:
            # Check we have permissions to the pages
            dnsReadPermissions = http_request(url + "/services_unbound.php", {}, {}, "GET")
            dnsAddPermissions = http_request(url + "/services_unbound_host_edit.php", {}, {}, "GET")
            if check_permissions(dnsAddPermissions) and check_permissions(dnsReadPermissions):
                # Update our CSRF token and add our DNS entry
                dnsData["__csrf_magic"] = get_csrf_token(url + "/services_unbound_host_edit.php", "GET")
                dnsCheck = http_request(url + "/services_unbound_host_edit.php", dnsData, {}, "POST")
                # Update our CSRF token and save changes
                saveDnsData["__csrf_magic"] = get_csrf_token(url + "/services_unbound.php", "GET")
                saveCheck = http_request(url + "/services_unbound.php", saveDnsData, {}, "POST")
                # Check if a record is now present
                if check_dns(server, user, key, host, domain):
                    recordAdded = 0    # Set return variable 0 (0 means successfully added)
            # If we did not have permissions to the page
            else:
                recordAdded = 15    # Return exit code 15 (permission denied)
    # If a DNS record already exists
    else:
        recordAdded = 1    # Set return value to 1 (1 means record already existed when function started)
    # Return exit code
    return recordAdded
# get_ssl_certs() pulls the list of existing certificates on a pfSense host. This function basically returns the data found on /system_certmanager.php
def get_ssl_certs(server, user, key):
    # Local Variables
    certManagerDict = {"ec" : 2, "certs" : {}}     # Initialize certManagerDict to return our certificate values and exit codes
    certIndex = 0    # Initialize certIndex to track the certificate number in the list/loop
    url = wcProtocol + "://" + server    # Populate our base URL
    # Submit our intitial request and check for errors
    certManagerDict["ec"] = 10 if check_dns_rebind_error(url) else certManagerDict["ec"]    # Return exit code 10 if dns rebind error found
    certManagerDict["ec"] = 6 if not validate_platform(url) else certManagerDict["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if certManagerDict["ec"] == 2:
        certManagerDict["ec"] = 3 if not check_auth(server, user, key) else certManagerDict["ec"]    # Return exit code 3 if we could not sign in
    if certManagerDict["ec"] == 2:
        # Check that we had permissions for this page
        getCertData = http_request(url + "/system_certmanager.php", {}, {}, "GET")
        if check_permissions(getCertData):
            # Parse our output
            certRowList = getCertData['text'].split("<tbody>")[1].split("</tbody>")[0].split("<tr>")
            # Cycle through each table row containing certificate info and parse accordingly
            # End format will be a multi-dimensional list. Example: list[[index, name, issuer, cn, start, end, serial]]
            for tr in certRowList:
                # Check if table row is empty
                if tr.replace(" ", "").replace("\t", "").replace("\n", "") != "":
                    # Try to format table data into the certificate name
                    try:
                        certName = tr.replace(" ", "").replace("\n", "").replace("\t", "").split("<td>")[1].split("<br/>")[0]    # Replace whitespace and parse HTML until we receive or name value
                    except Exception as x:
                        certName = "ERROR"
                    # Try to format table data into the issuer type
                    try:
                        isr = tr.replace(" ", "").split("<td><i>")[1].split("</i></td>")[0]
                    except Exception as x:
                        isr = "ERROR"
                    # Try to format table data into the CN
                    try:
                        cn = "CN=" + tr.replace(" ", "").replace("\t", "").split("</i></td>")[1].split("CN=")[1].split("<divclass=\"infoblock\">")[0]
                    except Exception as x:
                        cn = "ERROR"
                    # Try to format table data into the start data
                    try:
                        strDte = tr.replace("\t", "").split("<small>")[1].split("</small>")[0].split("Valid From: <b>")[1].split("</b>")[0].replace(" ", "_")[:-6]
                    except Exception as x:
                        strDte = "ERROR"
                    # Try to format table data into the expiration date
                    try:
                        exp = tr.replace("\t", "").split("<small>")[1].split("</small>")[0].split("Valid Until: <b>")[1].split("</b>")[0].replace(" ", "_")[:-6]
                    except Exception as x:
                        exp = "ERROR"
                    # Try to format table data into the serial number
                    try:
                        srl = tr.replace("\t", "").split("<div class=\"alert alert-info clearfix\" role=\"alert\"><div class=\"pull-left\"><b>Serial: </b>")[1].split("<br/>")[0].replace(" ", "")
                    except Exception as x:
                        srl = ""
                    # Try to format table data to determine if certificate is in use, if the certifciate is in use
                    ciu = True if "<td>webConfigurator</td>" in tr.replace("\n", "").replace("\t", "").replace(" ", "") else False
                    # Format the certificate data into a list, increase the counter after each loop
                    certManagerDict["certs"][certIndex] = {"name" : certName, "issuer" : isr, "cn" : cn, "start" : strDte, "expire" : exp, "serial" : srl, "active" : ciu}
                    certIndex = certIndex + 1
            # Assign exit code 0 if we have our dictionary populated
            certManagerDict["ec"] = 0 if len(certManagerDict["certs"]) > 0 else certManagerDict["ec"]
        # If we did not have permissions
        else:
            certManagerDict["ec"] = 15    # Return exit code 15 (permissions denied)
    # Return our data dict
    return certManagerDict

# add_ssl_cert() performs the necessary requests to add an SSL certificate to pfSense's WebConfigurator
def add_ssl_cert(server, user, key, cert, certkey, descr):
    # Local Variables
    certAdded = 2    # Set return value to 2 by default (2 means failed)
    url = wcProtocol + "://" + server    # Populate our base URL
    preCertDict = get_ssl_certs(server, user, key)    # Get the current dict of certificate installed on pfSense
    preCertDictLen = len(preCertDict["certs"])    # Track the length of existing certificates in the dict
    # Define a dictionary for our SSL certificate POST data values
    addCertData = {
        "__csrf_magic" : "",
        "method" : "import",
        "descr" : descr,
        "csrtosign" : "new",
        "csrpaste" : "",
        "keypaste" : "",
        "csrsign_lifetime" : "3650",
        "csrsign_digest_alg" : "sha256",
        "keylen" : "2048",
        "digest_alg" : "sha256",
        "lifetime" : "3650",
        "dn_country" : "US",
        "dn_state" : "",
        "dn_city" : "",
        "dn_organization" : "",
        "dn_organizationalunit" : "",
        "dn_email" : "",
        "dn_commonnam" : "",
        "csr_keylen" : "2048",
        "csr_digest_alg" : "sha256",
        "csr_dn_country" : "US",
        "csr_dn_state" : "",
        "csr_dn_city" : "",
        "csr_dn_organization" : "",
        "csr_dn_organizationalunit" : "",
        "csr_dn_email" : "",
        "csr_dn_commonname" : "",
        "certref" : "5d05eb4cb4d91",
        "type" : "user",
        "altname_type0" : "DNS",
        "altname_value0" : "",
        "cert" : cert,
        "key" : certkey,
        "save" : "Save"
    }
     # Check for errors and assign exit codes accordingly
    certAdded = 10 if check_dns_rebind_error(url) else certAdded    # Return exit code 10 if dns rebind error found
    certAdded = 6 if not validate_platform(url) else certAdded    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if certAdded == 2:
        certAdded = 3 if not check_auth(server, user, key) else certAdded    # Return exit code 3 if we could not sign in
    # Only proceed if an error has not occurred
    if certAdded == 2:
        # Check our permissions
        permissionCheck = http_request(url + "/system_certmanager.php?act=new", {}, {}, "GET")
        if check_permissions(permissionCheck):
            # Add SSL cert and check for the added cert afterwards
            addCertData["__csrf_magic"] = get_csrf_token(url + "/system_certmanager.php?act=new", "GET")
            postCheck = http_request(url + "/system_certmanager.php?act=new", addCertData, {}, "POST")
            postCertDict = get_ssl_certs(server, user, key)  # Get the current dict of certificate installed on pfSense
            postCertDictLen = len(postCertDict["certs"])  # Track the length of existing certificates in the dict
            # Check if the dict increased in size by one when we added a new certificate
            if postCertDictLen == preCertDictLen + 1:
                # Check if our descr matches the new certificates name
                if descr == postCertDict["certs"][postCertDictLen - 1]["name"]:
                    certAdded = 0    # We now know the certificate that was added was the certificate intended
        # If we did not have permissions
        else:
            certAdded = 15    # Return exit code 15 (permission denied)
    # Return exit code
    return certAdded

# set_wc_certificate() sets which WebConfigurator SSL certificate to use via /system_advanced_admin.php
def set_wc_certificate(server, user, key, certName):
    # Local Variables
    wccCheck = 2    # Initialize wccCheck to track errors, this will be returned by the function
    url = wcProtocol + "://" + server    # Populate our base URL
    selectedWcc = ""    # Initialize variable to track which certificate is currently selected
    newWcc = ""    # Initialize variable to track the certRef of our certificate to add
    wccFound = False    # Initialize boolean to track whether a certificate match has already occurred
    existingWccData = get_system_advanced_admin(server, user, key)["adv_admin"]    # Pull our existing configuration before making changes
    wccData = {"__csrf_magic" : "", "webguiproto" : wcProtocol, "ssl-certref" : ""}
     # Check for errors and assign exit codes accordingly
    wccCheck = 10 if check_dns_rebind_error(url) else wccCheck    # Return exit code 10 if dns rebind error found
    wccCheck = 6 if not validate_platform(url) else wccCheck    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if wccCheck == 2:
        wccCheck = 3 if not check_auth(server, user, key) else wccCheck    # Return exit code 3 if we could not sign in
    # Check that authentication was successful
    if wccCheck == 2:
        # Check that we have permissions to this page first
        getSysAdvAdm = http_request(url + "/system_advanced_admin.php", {}, {}, "GET")
        if check_permissions(getSysAdvAdm):
            # Make GET request to /system_advanced_admin.php to check response, split the response and target the SSL cert selection HTML field
            getSysAdvAdmList = getSysAdvAdm["text"].split("<select class=\"form-control\" name=\"ssl-certref\" id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=")
            # For each option in the selection box, check that the value is expected and parse the data
            for wcc in getSysAdvAdmList:
                # Remove trailing characters from wcc
                wcc = wcc.replace("\n", "").replace("\t", "")
                # Ensure the option is not blank and that option is found in the field
                if wcc != "" and "</option>" in wcc:
                    # Try to split and parse the data to find the expected values
                    try:
                        certRef = wcc.split(">")[0].replace("\"", "")    # Parse the option and save the certificate reference number
                        certId = wcc.split(">")[1].split("</option")[0]    # Parse the option and save the certificate ID
                    except IndexError as x:
                        pass
                    # Check if certRef is currently selected, save this value
                    if "selected" in certRef:
                        certRef = certRef.replace(" selected", "")    # Remove the selected string
                        selectedWcc = certRef    # Assign certRef to selectedWcc
                    # Check if our certID matches our certName passed into the function
                    if certId == certName:
                        # Check if a certificate was already matched, return error 5 if so
                        if wccFound:
                            wccCheck = 4    # Assign exit code 4 to wccCheck (means multiple certs were found)
                            wccFound = False    # Revert back to false, multiple matches means we can't determine which one the user actually wants
                            break    # Break the loop as we have multiple certs matching the same name
                        wccFound = True
                        newWcc = certRef    # Assign our new webconfigurator certificate ID to a permanent variable
            # Check if we found a legitimate match and no error occurred
            if wccFound:
                # Check if our certRef values are different (meaning we are actually changing the certificate)
                if newWcc != selectedWcc:
                    # Loop through our existing /system_advanced_admin.php configuration and add the data to the POST request
                    for table,data in existingWccData.items():
                        # Loop through each value in the table dictionaries
                        for key,value in data.items():
                            value = "yes" if value == True else value    # Swap true values to "yes"
                            value = "" if value == False else value    # Swap false values to empty string
                            # Check if we are checking our login protection whitelist
                            if key == "whitelist":
                                # Add each of our whitelisted IPs to our post data
                                for id,info in value.items():
                                    addrId = info["id"]
                                    wccData[addrId] = info["value"]
                                    wccData["address_subnet" + id] = info["subnet"]
                            # If we are not adding whitelist values, simply add the key and value
                            else:
                                wccData[key] = value    # Populate our data to our POST data
                    # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
                    wccData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
                    wccData["ssl-certref"] = newWcc
                    postSysAdvAdm = http_request(url + "/system_advanced_admin.php", wccData, {}, "POST")
                    checkSysAdvAdm = http_request(url + "/system_advanced_admin.php", {}, {}, "GET")["text"]
                    checkSysAdvAdm = checkSysAdvAdm.split("<select class=\"form-control\" name=\"ssl-certref\" id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=")
                    # Parse the new GET response to a list of HTML selection options
                    for wcc in checkSysAdvAdm:
                        # Try to split and parse the data to find the expected values
                        try:
                            certRef = wcc.split(">")[0].replace("\"", "")    # Parse the option and save the certificate reference number
                        # Add tolerance for IndexErrors, if we could not parse it, it is invalid data
                        except IndexError as x:
                            pass
                        # Check if certRef is currently selected, save this value
                        if "selected" in certRef:
                            certRef = certRef.replace(" selected", "")    # Remove the selected string
                            newSelectedWcc = certRef    # Assign certRef to selectedWcc
                            if newSelectedWcc == newWcc:
                                wccCheck = 0
                else:
                    wccCheck = 1    # Assign exit code 1 (means specified certificate is already being used)
            # If we couldn't find the cert, and we didn't find multiple, return exit code 5
            elif not wccFound and wccCheck != 4:
                wccCheck = 5    # Return exit code 5, certificate not found
        # If we do not have permission
        else:
            wccCheck = 15    # Return exit code 15 (permission denied)
    # Return our exit code
    return wccCheck

# get_firewall_aliases() pulls aliases information from pfSense and saves it to a Python dictionary
def get_firewall_aliases(server, user, key):
    aliases = {"ec" : 2, "aliases" : {}}    # Pre-define our dictionary to track alias values and errors
    url = wcProtocol + "://" + server    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    aliases["ec"] = 10 if check_dns_rebind_error(url) else aliases["ec"]    # Return exit code 10 if dns rebind error found
    aliases["ec"] = 6 if not validate_platform(url) else aliases["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if aliases["ec"] == 2:
        aliases["ec"] = 3 if not check_auth(server, user, key) else aliases["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if aliases["ec"] == 2:
        # Check that we had permissions for this page
        getAliasIds = http_request(url + "/firewall_aliases.php?tab=all", {}, {}, "GET")    # Save our GET HTTP response
        getAliasEdit = http_request(url + "/firewall_aliases_edit.php", {}, {}, "GET")  # Save our GET HTTP response
        if check_permissions(getAliasIds) and check_permissions(getAliasEdit):
            # GET aliases IDs from /firewall_aliases.php
            aliasIdTableBody = getAliasIds["text"].split("<tbody>")[1].split("</tbody>")[0]    # Pull the table body data from HTML response
            aliasIdTableRows = aliasIdTableBody.replace("\n", "").replace("\t", "").replace("</tr>", "").split("<tr>")    # Split our table body into list of rows
            # Loop through our list and grab our data values
            idList = []    # Pre-define our idList. This will be populated by our loop
            for row in aliasIdTableRows:
                # Check that the row contains an ID
                if "id=" in row:
                    id = row.split("id=")[1].split("\';\">")[0]    # Pull the ID from the row
                    idList.append(id)    # Add our current ID to the list
            # Loop through alias IDs and save values to our dictionary
            for i in idList:
                getAliasIdInfo = http_request(url + "/firewall_aliases_edit.php?id=" + i, {}, {}, "GET")    # Save our GET HTTP response
                check_permissions(getAliasIdInfo)  # Check that we had permissions for this page
                name = getAliasIdInfo["text"].split("<input class=\"form-control\" name=\"name\" id=\"name\" type=\"text\" value=\"")[1].split("\"")[0]    # Save our alias name
                descr = getAliasIdInfo["text"].split("<input class=\"form-control\" name=\"descr\" id=\"descr\" type=\"text\" value=\"")[1].split("\"")[0]    # Save our alias description
                type = ""    # Pre-define our type as empty string. This should be populated by our loop below
                # Loop through our type <select> tag to see what type is currently selected
                typeOpt = getAliasIdInfo["text"].split("<select class=\"form-control\" name=\"type\" id=\"type\">")[1].split("</select>")[0].split("<option ")    # Save our typeOptions as a list
                for opt in typeOpt:
                    # Check if option is selected
                    if "selected" in opt:
                        type = opt.split("value=\"")[1].split("\"")[0]    # Save our type value
                # Save our dict values
                aliases["aliases"][name] = {"name" : name, "type" : type, "descr" : descr, "id" : i, "entries" : {}}
                # Loop through our alias entries and pull data
                counter = 0    # Define a counter to keep track of loop cycle
                while True:
                    # Check if there is an address value for our current index
                    if "id=\"address" + str(counter) in getAliasIdInfo["text"]:
                        aliases["aliases"][name]["entries"][counter] = {} if counter not in aliases["aliases"][name]["entries"] else aliases["aliases"][name]["entries"][counter]    # Create our counter dictionary if not existing
                        aliases["aliases"][name]["entries"][counter]["id"] = str(counter)    # Save our counter value
                        aliases["aliases"][name]["entries"][counter]["value"] = getAliasIdInfo["text"].split("id=\"address" + str(counter))[1].split("value=\"")[1].split("\"")[0]    # Save our entry value
                        aliases["aliases"][name]["entries"][counter]["descr"] = getAliasIdInfo["text"].split("id=\"detail" + str(counter))[1].split("value=\"")[1].split("\"")[0]    # Save our entry value
                        subnetOpt = getAliasIdInfo["text"].split("id=\"address_subnet" + str(counter))[1].split("</select>")[0].split("<option")    # Return our list of subnets
                        # Loop through list of subnets to see if one is selected
                        for opt in subnetOpt:
                            if "selected" in opt:
                                aliases["aliases"][name]["entries"][counter]["subnet"] = opt.split("value=\"")[1].split("\"")[0]    # Save our subnet value
                                break    # Break our loop as there should only be one match
                            else:
                                aliases["aliases"][name]["entries"][counter]["subnet"] = "0"
                        counter = counter + 1  # Increase our counter
                    # If there is not an address value for our current index, we know we have made it through all entries
                    else:
                        break
            # Assign our success code
            aliases["ec"] = 0
        # If we did not have permission to access the page
        else:
            aliases["ec"] = 15    # Return exit code 15 (permission denied)
    # Return our dictionary
    return aliases

# modify_firewall_alias() takes and existing firewall alias and changes configured values within
def modify_firewall_alias(server, user, key, aliasName, newValues):
    # Local Variables
    aliasIdData = get_firewall_aliases(server, user, key)    # Get the alias ID to determine which alias to modify
    aliasModded = 2 if aliasIdData["ec"] == 0 else aliasIdData["ec"]    # Default aliasModded to 2 if authentication didn't fail when we pulled the aliasIDData, otherwise return 3 (auth failed)
    url = wcProtocol + "://" + server    # Populate our base URL
    # If we successfully pulled our aliasId
    if aliasModded == 2:
        # Check if our alias name is in our dictionary
        if aliasName in aliasIdData["aliases"]:
            aliasIdValue = aliasIdData["aliases"][aliasName]["id"]   # Assign the actual alias ID value to a variable
            aliasPostData = {"__csrf_magic" : get_csrf_token(wcProtocol + "://" + server + "/firewall_aliases_edit.php?id=" + aliasIdValue, "GET"), "name" : aliasName, "type" : "host", "tab" : "ip", "id" : aliasIdValue, "save" : "Save"}
            valueToAdd = ""    # Initialize our new alias entry values
            detailToAdd = ""   # Initializes our new alias entry description values
            defaultDetail = "Auto-added by " + user + " on " + localHostname    # Initializes our default alias entry description value
            # Check if the newValues needs to be parsed
            if "," in newValues:
                newValueList = newValues.split(",")    # Split our values to a list
                newValIndex = 0    # Assign an index tracker for our for loop. This will be used to track the address value in our post request
                # For each value in our list, print an address to our post request
                for val in newValueList:
                    # Only add the value if the list item is not emtpy
                    if val != '':
                        aliasPostData["address" + str(newValIndex)] = val
                        aliasPostData["detail" + str(newValIndex)] = defaultDetail
                        newValIndex = newValIndex + 1    # Increase our loop index
            # Else if our data did not need to be parsed
            else:
                aliasPostData["address0"] = newValues
                aliasPostData["detail0"] = defaultDetail
            # Make our post request if no errors were encountered
            if aliasModded == 2:
                # Check that we have permissions to run
                postPfAliasData = http_request(url + "/firewall_aliases_edit.php", {}, {}, "GET")
                if check_permissions(postPfAliasData):
                    # Submit our post requests
                    postPfAliasData = http_request(url + "/firewall_aliases_edit.php", aliasPostData, {}, "POST")
                    saveChangesPostData = {"__csrf_magic" : get_csrf_token(wcProtocol + "://" + server + "/firewall_aliases.php", "GET"), "apply" : "Apply Changes"}
                    saveChanges = http_request(url + "/firewall_aliases.php", saveChangesPostData, {}, "POST")
                    aliasModded = 0    # Assign our success exit code
                # If we did not have permissions to the page
                else:
                    aliasModded = 15    # Return exit code 15 (permission denied)
        # If our alias name was not found
        else:
            aliasModded = 4    # Return exit code 4 (alias not found)
    # Return our integer exit code
    return aliasModded

# main() is the primary function that maps arguments to other functions
def main():
    # Local Variables
    global wcProtocol    # Make wcProtocol modifiable globally
    global wcProtocolPort    # Make wcProtocolPort modifiable globally
    pfsenseServer = firstArg    # Assign the server value to the firstArg (filtered)
    pfsenseAction = filter_input(secondArg)    # Assign the action to execute (filtered)
    # Check if user requests HTTPS override
    if pfsenseServer.lower().startswith("http://"):
        pfsenseServer = pfsenseServer.replace("http://", "")    # Replace the http:// protocol from the servername
        wcProtocol = "http"    # Reassign our webconfigurator protocol
        wcProtocolPort = 80    # Assign webconfigurator port to HTTP (80)
    # Check if user requests non-standard UI port
    if ":" in pfsenseServer:
        nonStdPort = pfsenseServer.split(":")[1]    # Assign the value after our colon to a variable
        nonStdPortInt = int(nonStdPort) if nonStdPort.isdigit() else 999999    # Assign a integer value of our port variable, if it is not a number save out of range
        wcProtocolPort = nonStdPortInt if 1 <= nonStdPortInt <= 65535 else wcProtocolPort    # Change our webUI port specification if it is a valid number
        pfsenseServer = pfsenseServer.replace(":" + nonStdPort, "")    # Remove our port specification from our servername string
    pfsenseServer = filter_input(pfsenseServer.replace("http://", "").replace("https://", ""))    # Filter our hostname/IP input
    # Check if we are simply requesting the software version
    if firstArg.upper() in ("--VERSION", "-V"):
        print(get_exit_message("version", "", "generic", "", ""))
        sys.exit(0)
    # Check that user passed in an IP or hostname
    if pfsenseServer is not "":
        # Check if the pfSense server is available for connections
        if check_remote_port(pfsenseServer, wcProtocolPort):
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
                    descrToAdd = "Auto-added by " + user + " on " + localHostname if descrToAdd == "default" else descrToAdd    # Write default description if default is passed
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
                            jsonName = "pf-readdns-" + currentDate + ".json"    # Assign our default JSON name
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
                                    if dnsFilter.upper() == "--ALL" or dnsFilter.startswith(("--host=","-h=")):
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
                    descrToAdd = currentDate if descrToAdd == "default" else descrToAdd    # Write default description if default is passed
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
                    # Check if JSON mode was selected
                    elif aliasFilter.startswith("-j=") or aliasFilter.startswith("--json="):
                        jsonPath = aliasFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readaliases-" + currentDate + ".json"    # Assign our default JSON name
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
            # Assign functions for flag --modify-alias
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
                            jsonName = "pf-readsslcerts-" + currentDate + ".json"    # Assign our default JSON name
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
                descr = "Auto-added by " + user + " on " + localHostname if descr.upper() == "DEFAULT" else descr    # Assign a default description if requested
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
                        # If we want to export values as JSON
                        elif arpFilter.startswith(("--json=", "-j=")):
                            jsonPath = arpFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readarp-" + currentDate + ".json"    # Assign our default JSON name
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
            # Assign functions for --add-tunable
            elif pfsenseAction == "--add-tunable":
                # Action Variables
                tunableName = thirdArg if thirdArg is not None else input("Tunable name: ")    # Assign our tunable name to the third argument passed in
                tunableDescr = fourthArg if fourthArg is not None else input("Description: ")    # Assign our tunable description to the fourth argument passed in
                tunableValue = fifthArg if fifthArg is not None else input("Value: ")   # Assign our tunable description to the fifth argument passed in
                user = seventhArg if sixthArg == "-u" and seventhArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = ninthArg if eighthArg == "-p" and ninthArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                tunableDescr = "Auto-added by" + user + " on " + localHostname if tunableDescr.upper() == "DEFAULT" else tunableDescr    # Assign default description value
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
                descrHead = structure_whitespace("DESCRIPTION", 25, "-", True) + " "    # Format our ip description value
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
                        tunDescr = structure_whitespace(value["descr"], 25, " ", True) + " "    # Get our tunable description
                        tunValue = structure_whitespace(value["value"], 15, " ", True) + " "    # Get our value
                        tunId = structure_whitespace(value["id"], 40, " ", True) + " "    # Get our ID
                        # If we want to return all values
                        if tunableFilter.upper() in ["-A", "--ALL", "-D", "DEFAULT"]:
                            print(header) if counter == 1 else None  # Print our header if we are just starting loop
                            print(tunNumber + tunName + tunDescr + tunValue + tunId)    # Print our data values
                        # If we want to export values as JSON
                        elif tunableFilter.startswith(("--json=", "-j=")):
                            jsonPath = tunableFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readtunables-" + currentDate + ".json"    # Assign our default JSON name
                            # Check if JSON path exists
                            if os.path.exists(jsonPath):
                                # Open an export file and save our data
                                jsonExported = export_json(tunableFilter["arp"], jsonPath, jsonName)
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
                    # If we want to export values as JSON
                    if advAdmFilter.startswith(("--json=", "-j=")):
                        jsonPath = advAdmFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                        jsonName = "pf-readadvadm-" + currentDate + ".json"    # Assign our default JSON name
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
                                print(get_exit_message(ecSetupSsh, pfsenseServer, pfsenseAction, "", ""))
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
                        # If we want to export values as JSON
                        elif vlanFilter.startswith(("--json=", "-j=")):
                            jsonPath = vlanFilter.replace("-j=", "").replace("--json=", "").rstrip("/") + "/"    # Get our file path by removing the expected JSON flags
                            jsonName = "pf-readvlans-" + currentDate + ".json"    # Assign our default JSON name
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
                print(get_exit_message("invalid_arg", pfsenseServer, "generic", pfsenseAction, ""))
                sys.exit(1)
        # If we couldn't connect to pfSense's web configurator, return error
        else:
            print(get_exit_message("connect_err", pfsenseServer, "generic", pfsenseAction, ""))
            sys.exit(1)
    # If user did not pass in a hostname or IP
    else:
        # Print our error and exit
        print(get_exit_message("invalid_host", "", "generic", "", ""))
        sys.exit(1)

# Execute main function
main()
# If nothing forced us to exit the script, return exit code 0
sys.exit(0)