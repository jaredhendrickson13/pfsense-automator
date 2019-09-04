#!/usr/bin/python3
# ----------------------------------------------------------------------------------------------------------------
# Author: Jared Hendrickson
# Copyright 2019 - SecurityMetrics - Jared Hendrickson
# Purpose: This script is intended to add a CLI interface for pfSense devices. This uses cURL libraries to execute
# pfSense's many PHP configuration scripts. All functions in this script mimic changes regularly made in a browser
# and utilizes pfSense's built-in CSRF checks, input validation, and configuration parsing
# ----------------------------------------------------------------------------------------------------------------

# IMPORT MODULES
import datetime
import subprocess
import sys
import os
import getpass
import socket
import signal
import urllib.parse

# Variables
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
localHostname = socket.gethostname()    # Gets the hostname of the system running pfsense-controller
currentDate = datetime.datetime.now().strftime("%Y%m%d%H%M%S")    # Get the current date in a file supported format
cookieLocation = "/tmp/cookie-" + currentDate + ".pf"    # Set the default cookie location
devnull = open("/dev/null", "w")    # Open file object pointing to /dev/null
wcProtocol = "https"    # Assigns whether the script will use HTTP or HTTPS connections
wcProtocolPort = 443 if wcProtocol == 'https' else 80    # If wcProtocol is set to https, assign a integer value to coincide

### FUNCTIONS ###
# no_escape() Prevents SIGINT from killing the script unsafely
def no_escape(signum, frame):
    sys.exit(1)
# Set the signal handler to prevent exiting the script without killing the tunnel
signal.signal(signal.SIGINT, no_escape)

# get_exit_message() takes an exit code and other parameters to determine what success or error message to print
def get_exit_message(ec, server, command, data1, data2):
    # Local Variables
    exitMessage = ""    # Define our return value as empty string
    globalDnsRebindMsg = "Error: DNS rebind detected. Ensure `" + server + "` is listed in System > Advanced > Alt. Hostnames"
    globalAuthErrMsg = "Error: Authentication failed"
    # Define our ERROR/SUCCESS message dictionary
    ecd = {
        # Generic error message that don't occur during commands
        "generic" : {
            "invalid_arg" : "Error: Invalid argument. Unknown action `" + data1 + "`",
            "connect_err" : "Error: Failed connection to " + server + ":" + str(wcProtocolPort),
            "invalid_host" : "Error: Invalid hostname. Expected syntax: `pfsense-automator <HOSTNAME or IP> <COMMAND> <ARGS>`"
        },
        # Error/success messages for --add-dns flag
        "--add-dns" : {
            0 : "DNS record was added successfully",
            1 : "Error: DNS entry for `" + data1 + "." + data2  + "` already exists @" + server,
            2: "Error: Unexpected error adding `" + data1 + "." + data2  + "`",
            3 : globalAuthErrMsg,
            4 : "Error: DNS unreachable at " + server,
            10 : globalDnsRebindMsg,
            "invalid_ip" : "Error: Invalid IP address",
            "invalid_syntax" : "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --add-dns <HOST> <DOMAIN> <IP> <DESCR>`"
        },
        # Error/success messages for --add-sslcert flag
        "--add-sslcert" : {
            0 : "SSL certificate successfully uploaded",
            2 : "Error: Failed to upload SSL certificate",
            3 : globalAuthErrMsg,
            10 : globalDnsRebindMsg,
            "no_cert" : "Error: No certificate file found at `" + data1 + "`",
            "no_key" : "Error: No key file found at `" + data1 + "`",
            "empty" : "Error: Certificate or key file is empty"
        },
        # Error/success messages for --read-sslcerts flag
        "--read-sslcerts" : {
            "read_err" : "Error: failed to read SSL certificates from pfSense"
        },
        # Error/success messages for --check-auth flag
        "--check-auth" : {
            "success" : "Authentication successful",
            "fail" : "Error: Authentication failed"
        },
        # Error/success messages for --modify-alias
        "--modify-alias" : {
            0 : "Alias `" + data1 +"` successfully updated",
            1 : "Error: Unable to parse alias `" + data1 + "`",
            2: "Error: Unexpected error processing alias",
            3 : globalAuthErrMsg,
            4 : "Error: Unable to locate alias `" + data1 + "`",
            10 : globalDnsRebindMsg,
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
            10 : globalDnsRebindMsg,
            "unknown_err" : "Error: An unknown error has occurred"
        },
        # Error/success messages for -add-ldapserver
        "--add-ldapserver" : {
            0 : "Successfully added LDAP server `" + data1 + "` on `" + server + "`",
            2 : "Error: Failed to configure LDAP server",
            3 : globalAuthErrMsg,
            10 : globalDnsRebindMsg,
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
def check_dns(server, host, type):
    # Local Variables
    recordExists = False # Set return value False by default
    digOutput = subprocess.check_output(["dig", "@" + server, host, type], stderr=devnull).decode('utf-8').split("->>HEADER<<-")[1].split("\n")[0].replace(" ", "")
    # Check for data in dig output
    if "status:NOERROR" in digOutput:
        recordExists = True
    #Return boolean
    return recordExists

# check_dns_rebind_error() checks if access to the webconfigurator is denied due to a DNS rebind error
def check_dns_rebind_error(httpResponse):
    # Local Variables
    rebindError = "Potential DNS Rebind attack detected"    # Assigns the error string to look for when DNS rebind error occurs
    rebindFound = False    # Assigns a boolean to track whether a rebind error was found. This is our return value
    # Check the HTTP response code for error message
    if rebindError in httpResponse:
        rebindFound = True    # If the the HTTP response contains the error message, return true
    # Return our boolean
    return rebindFound

# check_auth() runs a basic authentication check. If the authentication is successful a true value is returned
def check_auth(server, user, key):
    # Local Variables
    authSuccess = False    # Set the default return value to false
    # Complete authentication
    authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
    authSuccess = True if not "Username or Password incorrect" in authCheck else authSuccess    # Return false if login failed
    ckStat = delete_cookies()    # Delete unneeded cookies
    return(authSuccess)

# get_csrf_token() makes an initial connection to pfSense to retrieve the CSRF token. This supports both GET and POST requests
def get_csrf_token(url, type):
        # Local Variables
        csrfTokenLength = 55  # Set the expected token length of the csrf token
        csrfResponse = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation, "-X", type, "-k", url], stderr=devnull).decode('utf-8')
        # Parse CSRF token and conditionalize return value
        csrfParsed = "sid:" + csrfResponse.split("sid:")[1].split(";")[0].replace(" ", "").replace("\n", "").replace("\"", "")
        csrfToken = csrfParsed if len(csrfParsed) is csrfTokenLength else ""    # Assign the csrfToken to the parsed value if the expected string length is found
        return csrfToken

# delete_cookies() ensures the cookies generated during this sessions is removed and leaves a clean slate for the next task
def delete_cookies():
    cookieDeleted = False    # Set initial return value to false. This will let us know if the cookie was actually removed
    if os.path.exists(cookieLocation):
        os.remove(cookieLocation)    # Remove the cookies known to this script
        if not os.path.exists(cookieLocation):
            cookieDeleted = True    # Set the return value to true if the cookie no longer exists
    return cookieDeleted

# add_auth_server_ldap() adds an LDAP server configuration to Advanced > User Mgr > Auth Servers
def add_auth_server_ldap(server, user, key, descrName, ldapServer, ldapPort, transport, ldapProtocol, timeout, searchScope, baseDN, authContainers, extQuery, query, bindAnon, bindDN, bindPw, ldapTemplate, userAttr, groupAttr, memberAttr, rfc2307, groupObject, encode, userAlt):
    # Local Variables
    ldapAdded = 2    # Set return value to 2 by default (2 mean general failure)
    # Complete authentication and check for errors, return exit code three if authentication failed
    authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
    ldapAdded = 3 if "Username or Password incorrect" in authCheck else ldapAdded    # Return exit code 3 if login failed
    ldapAdded = 10 if check_dns_rebind_error(authCheck) else ldapAdded    # Return exit code 10 if dns rebind error found
    # Check that no errors have occurred so far (should be at 2)
    if ldapAdded == 2:
        addAuthServer = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/system_authservers.php?act=new", "GET") + "&name=" + descrName + "&type=ldap&ldap_host=" + ldapServer + "&ldap_port=" + str(ldapPort) + "&ldap_protver=" + str(ldapProtocol) + "&ldap_timeout=" + str(timeout) + "&ldap_scope=" + searchScope + "&ldap_basedn=" + baseDN + "&ldapauthcontainers=" + authContainers + "&ldap_extended_enabled=" + extQuery + "&ldap_extended_query=" + query + "&ldap_anon=" + bindAnon + "&ldap_binddn=" + bindDN + "&ldap_bindpw=" + bindPw + "&ldap_tmpltype=" + ldapTemplate + "&ldap_attr_user=" + userAttr + "&ldap_attr_group=" + groupAttr + "&ldap_attr_member=" + memberAttr + "&ldap_rfc2307=" + rfc2307 + "&ldap_attr_groupobj=" + groupObject + "&ldap_utf8=" + encode + "&ldap_nostrip_at=" + userAlt + "&save=Save\"", "--data-urlencode", "ldap_urltype=" + transport, "-X", "POST", "-k", wcProtocol + "://" + server + "/system_authservers.php?act=new"], stderr=devnull).decode('utf-8')
        ldapAdded = 0
    return ldapAdded

# add_dns_entry() performs the necessary requests to add a DNS entry to pfSense's Unbound service
def add_dns_entry(server, user, key, host, domain, ip, descr):
    # Local Variables
    recordAdded = 2    # Set return value to 2 by default (2 means failed)
    # Check that DNS is available on this server
    if check_remote_port(server, 53):
        # Check if the record we are adding already exists
        if not check_dns(server,host + "." + domain, "A"):
            # Complete authentication
            authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
            recordAdded = 3 if "Username or Password incorrect" in authCheck else recordAdded    # Return exit code 3 if login failed
            recordAdded = 10 if check_dns_rebind_error(authCheck) else recordAdded    # Return exit code 10 if DNS rebind error was found
            if recordAdded == 2:
                # Added DNS entry
                subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/services_unbound_host_edit.php", "GET") + "&host=" + host + "&domain=" + domain + "&ip=" + ip + "&descr=" + descr + "&save=Save\"", "-X", "POST", "-k", wcProtocol + "://" + server + "/services_unbound_host_edit.php"], stderr=devnull).decode('utf-8')
                # Save changes
                subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/services_unbound.php", "GET") + "&apply=Apply Changes", "-X", "POST", "-k", wcProtocol + "://" + server + "/services_unbound.php"], stderr=devnull).decode('utf-8')
                # Check if a record is now present
                if check_dns(server, host + "." + domain, "A"):
                    recordAdded = 0    # Set return variable 0 (0 means successfully added)
        else:
            recordAdded = 1    # Set return value to 1 (1 means record already existed when function started)
    # Return exit code 4 if we couldn't reach the DNS server
    else:
        recordAdded = 4    # Assign exit code 4 (DNS unreachable
    # Remove cookies for this session
    ckStat = delete_cookies()
    # Return exit code
    return recordAdded
# get_ssl_certs() pulls the list of existing certificates on a pfSense host. This function basically returns the data found on /system_certmanager.php
def get_ssl_certs(server, user, key):
    # Local Variables
    certManagerList = []    # Initialize certManagerList to return our certificate values
    certIndex = 0    # Initialize certIndex to track the certificate number in the list/loop
    # Complete authentication and check for errors, return exit code three if authentication failed
    authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
    authSuccess = False if "Username or Password incorrect" in authCheck else True    # Return exit code 3 if login failed
    if authSuccess:
        # Save the GET data for /system_certmanager.php
        getCertData = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation, "-X", "GET", "-k", wcProtocol + "://" + server + "/system_certmanager.php"], stderr=devnull).decode('utf-8')
        if not check_dns_rebind_error(getCertData):
            certRowList = getCertData.split("<tbody>")[1].split("</tbody>")[0].split("<tr>")
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
                    ciu = "ACTIVE" if "<td>webConfigurator</td>" in tr.replace("\n", "").replace("\t", "").replace(" ", "") else ""
                    # Format the certificate data into a list, increase the counter after each loop
                    certManagerList.append([str(certIndex), certName, isr, cn, strDte, exp, srl, ciu])
                    certIndex = certIndex + 1
    # Remove cookies for this session
    ckStat = delete_cookies()
    # Return our data list
    return certManagerList

    # For each certificate entry, parse the data
# add_ssl_cert() performs the necessary requests to add an SSL certificate to pfSense's WebConfigurator
def add_ssl_cert(server, user, key, cert, certkey, descr):
    # Local Variables
    certAdded = 2    # Set return value to 2 by default (2 means failed)
    preCertList = get_ssl_certs(server, user, key)    # Get the current list of certificate installed on pfSense
    preCertListLen = len(preCertList)    # Track the length of existing certificates in the list
    # Complete authentication and check for errors, return exit code three if authentication failed
    authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
    certAdded = 3 if "Username or Password incorrect" in authCheck else certAdded    # Return exit code 3 if login failed
    certAdded = 10 if check_dns_rebind_error(authCheck) else certAdded    # Return exit code 10 if dns rebind error found
    # Only proceed if an error has not occurred
    if certAdded == 2:
        # Add SSL cert and check for the added cert afterwards
        postCheck = subprocess.check_output(["curl", "-v", "-b", cookieLocation, "-c", cookieLocation, "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/system_certmanager.php", "GET") + "&method=import&descr=" + descr + "&csrtosign=new&csrpaste=&keypaste=&csrsign_lifetime=3650&csrsign_digest_alg=sha256&keylen=2048&digest_alg=sha256&lifetime=3650&dn_country=US&dn_state=&dn_city=&dn_organization=&dn_organizationalunit=&dn_email=&dn_commonname=&csr_keylen=2048&csr_digest_alg=sha256&csr_dn_country=US&csr_dn_state=&csr_dn_city=&csr_dn_organization=&csr_dn_organizationalunit=&csr_dn_email=&csr_dn_commonname=&certref=5d05eb4cb4d91&type=user&altname_type0=DNS&altname_value0=&save=Save", "--data-urlencode", "cert=" + cert, "--data-urlencode", "key=" + certkey, "-X", "POST", "-k", wcProtocol + "://" + server + "/system_certmanager.php?act=new"], stderr=devnull).decode('utf-8')
        successCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation, "-X", "GET", "-k", wcProtocol + "://" + server + "/system_certmanager.php"], stderr=devnull).decode('utf-8').split("<tbody>")[1].split("</tbody>")[0].split("<tr>")
        postCertList = get_ssl_certs(server, user, key)  # Get the current list of certificate installed on pfSense
        postCertListLen = len(postCertList)  # Track the length of existing certificates in the list
        # Check if the list increased in size by one when we added a new certificate
        if postCertListLen == preCertListLen + 1:
            # Check if our descr matches the new certificates name
            if descr == postCertList[postCertListLen - 1][1]:
                certAdded = 0    # We now know the certificate that was added was the certificate intended
    # Remove cookies for this session
    ckStat = delete_cookies()
    # Return exit code
    return certAdded

# get_firewall_alias_id() parses the HTML data to retrieve the pfAlias ID. Returns list [alias ID , exit code]
def get_firewall_alias_id(server, user, key, aliasName):
    # Local Variables
    aliasId = ['',2]    # Assigns aliasId list. The first item value will populate our alias ID, the second item value will be our exit code integer
    pfAliasPage = "firewall_aliases_edit.php?id="
    targetTrData = []    # Define empty list for targetTrData, this will be populated later if data exists
    # Complete authentication
    authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
    aliasId[1] = 3 if "Username or Password incorrect" in authCheck else aliasId[1]    # Return exit code 3 if login failed
    aliasId[1] = 10 if check_dns_rebind_error(authCheck) else aliasId[1]    # Return exit code 3 if login failed
    # Check that authentication succeeded
    if aliasId[1] == 2:
        # Use GET to pull existing Firewall Aliases from pfSense
        getPfAliasRaw = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/firewall_aliases.php", "GET"), "-X", "POST", "-k", wcProtocol + "://" + server + "/firewall_aliases.php"], stderr=devnull).decode('utf-8')
        try:
            targetDivData = getPfAliasRaw.split("<div class=\"table-responsive\">")[1].split("</div>")[0]    # Targets the "table-responsive" div on our page
            targetTbodyData = targetDivData.split("<tbody>")[1].split("</tbody>")[0]    # Targets tbody data from div and saves it to a string
            targetTrData = targetTbodyData.split("<tr>")    # Targets tr data from our tbody and splits it into a list
        # We are only expecting IndexErrors here, except that error and return it's own exit code (1)
        except IndexError:
            aliasId[1] = 1    # Return exit code 1 meaning we were unable to find the specified alias name
        # Check if we have at least one tr in our list
        if len(targetTrData) > 0:
            # Cycle through alias tables to test for our criteria
            for tr in targetTrData:
                if pfAliasPage in tr:
                    targetTdData = tr.replace("\t", "").split("<td ondblclick")[1].split("</td>")[0]
                    targetAliasName = targetTdData.split(";\">\n")[1]
                    targetAliasId = targetTdData.split(pfAliasPage)[1].split("\';")[0]
                    # Check if our aliasName matches the name in the table data
                    if aliasName == targetAliasName:
                        aliasId[0] = targetAliasId    # Assign our aliasId list value 0 to the matching aliasId
                        aliasId[1] = 0    # Assign our aliasId list value 1 to integer 0 (success exit code)
                        break    # We found our ID so we do not need to continue the loop
                    # If not, return error code 4 (no alias found)
                    else:
                        aliasId[1] = 4    # Assign our aliasId list value 1 to integer 4 (no alias found)
    # Return our aliasId List
    return aliasId

# set_wc_certificate() sets which WebConfigurator SSL certificate to use via /system_advanced_admin.php
def set_wc_certificate(server, user, key, certName):
    # Local Variables
    wccCheck = 2    # Initialize wccCheck to track errors, this will be returned by the function
    selectedWcc = ""    # Initialize variable to track which certificate is currently selected
    newWcc = ""    # Initialize variable to track the certRef of our certificate to add
    wccFound = False    # Initialize boolean to track whether a certificate match has already occured
    # Complete authentication and check for errors, return exit code three if authentication failed
    authCheck = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/index.php", "GET") + "&usernamefld="+ user + "&passwordfld=" + key + "&login=Sign In", "-X", "POST", "-k", wcProtocol + "://" + server + "/index.php"], stderr=devnull).decode('utf-8')
    wccCheck = 3 if "Username or Password incorrect" in authCheck else wccCheck    # Return exit code 3 if login failed
    wccCheck = 10 if check_dns_rebind_error(authCheck) else wccCheck    # Return exit code 10 if DNS rebind
    # Check that authentication was successful
    if wccCheck == 2:
        # Make GET request to /system_advanced_admin.php to check response, split the response and target the SSL cert selection HTML field
        getSysAdvAdm = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation, "-X", "GET", "-k", wcProtocol + "://" + server + "/system_advanced_admin.php"], stderr=devnull).decode('utf-8')
        getSysAdvAdmList = getSysAdvAdm.split("<select class=\"form-control\" name=\"ssl-certref\" id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=")
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
                # Make our POST request and save a new GET request that should show our new configuration
                postSysAdvAdm = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/system_advanced_admin.php", "GET") + "&webguiproto=https&ssl-certref=" + newWcc, "-X", "POST", "-k", wcProtocol + "://" + server + "/system_advanced_admin.php"], stderr=devnull).decode('utf-8')
                checkSysAdvAdm = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation, "-X", "GET", "-k", wcProtocol + "://" + server + "/system_advanced_admin.php"], stderr=devnull).decode('utf-8').split("<select class=\"form-control\" name=\"ssl-certref\" id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=")
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
            wccCheck = 5    # Returne exit code 5, certificate not found
    # Remove cookies for this session
    ckStat = delete_cookies()
    # Return our exit code
    return wccCheck

# modify_firewall_alias() takes and existing firewall alias and changes configured values within
def modify_firewall_alias(server, user, key, aliasName, newValues):
    # Local Variables
    aliasIdData = get_firewall_alias_id(server, user, key, aliasName)    # Get the alias ID to determine which alias to modify
    aliasModded = 2 if aliasIdData[1] == 0 else aliasIdData[1]    # Default aliasModded to 2 if authentication didn't fail when we pulled the aliasIDData, otherwise return 3 (auth failed)
    # If we successfully pulled our aliasId
    if aliasIdData[0] != '' and aliasIdData[1] == 0:
        aliasIdValue = aliasIdData[0]   # Assign the actual alias ID value to a variable
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
                    valueToAdd = valueToAdd + "&address" + str(newValIndex) + "=" + val
                    detailToAdd = detailToAdd + "&detail" + str(newValIndex) + "=" + defaultDetail
                    newValIndex = newValIndex + 1    # Increase our loop index
        # Else if our data did not need to be parsed
        else:
            valueToAdd = "&address0=" + newValues
            detailToAdd = "&detail0=" + defaultDetail
        # Make our post request if no errors were encountered
        if aliasModded == 2:
            postPfAliasData = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/firewall_aliases_edit.php?id=" + aliasIdValue, "GET") + "&name=" + aliasName + valueToAdd + detailToAdd + "&type=host&tab=ip&id=" + aliasIdValue + "&save=Save", "-X", "POST", "-k", wcProtocol + "://" + server + "/firewall_aliases_edit.php"], stderr=devnull).decode('utf-8')
            saveChanges = subprocess.check_output(["curl", "-b", cookieLocation, "-c", cookieLocation,  "-d", "__csrf_magic=" + get_csrf_token(wcProtocol + "://" + server + "/firewall_aliases.php", "GET") + "&apply=Apply Changes", "-X", "POST", "-k", wcProtocol + "://" + server + "/firewall_aliases.php"], stderr=devnull).decode('utf-8')
            aliasModded = 0    # Assign our success exit code
    # Delete cookies
    ckStat = delete_cookies()
    # Return our integer exit code
    return aliasModded

# main() is the primary function that maps arguments to other functions
def main():
    # Local Variables
    pfsenseServer = filter_input(firstArg)    # Assign the server value to the firstArg (filtered)
    pfsenseAction = filter_input(secondArg)    # Assign the action to execute (filtered)
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
                verbosity = filter_input(thirdArg)
                user = fifthArg if fourthArg == "-u" and fifthArg is not None else input("Please enter username: ")  # Parse passed in username, if empty, prompt user to enter one
                key = seventhArg if sixthArg == "-p" and seventhArg is not None else getpass.getpass("Please enter password: ")  # Parse passed in passkey, if empty, prompt user to enter one
                getCertData = get_ssl_certs(pfsenseServer, user, key)    # Save the function output list for use later
                # Check if data was returned
                if len(getCertData) > 0:
                    # Format header
                    if verbosity == "-v":
                        print(structure_whitespace("#", 3, "-", False) + " " + structure_whitespace("NAME", 37, "-", True) + " " + structure_whitespace("ISSUER", 11, "-", True) + " " + structure_whitespace("CN", 25, "-", True) + " " + structure_whitespace("VALID FROM", 25, "-", True) + " " + structure_whitespace("VALID UNTIL", 25, "-", True) + " " + structure_whitespace("SERIAL", 30, "-", True) + " " + "IN USE")
                    else:
                        print(structure_whitespace("#", 3, "-", False) + " " + structure_whitespace("NAME", 37, "-", True) + " " + structure_whitespace("ISSUER", 11, "-", True) + " " + structure_whitespace("CN", 25, "-", True) + " " + structure_whitespace("VALID UNTIL", 25, "-", True) + " " + "IN USE")
                    # For each certificate found in the list, print the information
                    for cert in getCertData:
                        if verbosity == "-v":
                            print(structure_whitespace(cert[0], 3, " ", False) + " " + structure_whitespace(cert[1], 37, " ", True) + " " + structure_whitespace(cert[2], 11, " ", True) + " " + structure_whitespace(cert[3], 25, " ", True) + " " + structure_whitespace(cert[4].replace("_", " "), 25, " ", True) + " " + structure_whitespace(cert[5].replace("_", " "), 25, " ", True) + " " + structure_whitespace(cert[6], 30, " ", True) + " " + cert[7])
                        else:
                            print(structure_whitespace(cert[0], 3, " ", False) + " " + structure_whitespace(cert[1], 37, " ", True) + " " + structure_whitespace(cert[2], 11, " ", True) + " " + structure_whitespace(cert[3], 25, " ", True) + " " + structure_whitespace(cert[5].replace("_", " "), 25, " ", True) + " " + cert[7])
                # Print error if no data was returned and exit with ec 1
                else:
                    print(get_exit_message("read_err", "", pfsenseAction, "", ""))
                    sys.exit(1)
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