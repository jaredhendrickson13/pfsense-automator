#!/usr/bin/python3
# ----------------------------------------------------------------------------------------------------------------
# Author: Jared Hendrickson
# Copyright 2019 - Jared Hendrickson
# Purpose: This script is intended to add a CLI interface for pfSense devices. This uses cURL libraries to execute
# pfSense's many PHP configuration scripts. All functions in this script mimic changes regularly made in a browser
# and utilizes pfSense's built-in CSRF checks, input validation, and configuration parsing
# ----------------------------------------------------------------------------------------------------------------
# IMPORT MODULES
import datetime
import getpass
import io
import json
import html
import os
import platform
import requests
import signal
import socket
import sys
import time
import urllib3

# Variables
softwareVersion = "v0.0.4 " + platform.system() + "/" + platform.machine()    # Define our current version of this software
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
localUser = getpass.getuser()    # Save our current user's username to a string
localHostname = socket.gethostname()    # Gets the hostname of the system running pfsense-automator
currentDate = datetime.datetime.now().strftime("%Y%m%d%H%M%S")    # Get the current date in a file supported format
wcProtocol = "https"    # Assigns whether the script will use HTTP or HTTPS connections
wcProtocolPort = 443 if wcProtocol == 'https' else 80    # If wcProtocol is set to https, assign a integer value to coincide
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

# get_exit_message() takes an exit code and other parameters to determine what success or error message to print
def get_exit_message(ec, server, command, data1, data2):
    # Local Variables
    exitMessage = ""    # Define our return value as empty string
    cmdFlgLen = 30   # Set the maximum length of our command flags to use in formatting table data
    globalDnsRebindMsg = "Error: DNS rebind detected. Ensure `" + server + "` is listed in System > Advanced > Alt. Hostnames"
    globalAuthErrMsg = "Error: Authentication failed"
    globalPlatformErrMsg = "Error: `" + server + "` does not appear to be running pfSense"
    globalPermissionErrMsg = "Error: Unable to execute function. Your user may lack necessary permissions"
    # Define our ERROR/SUCCESS message dictionary
    ecd = {
        # Generic error message that don't occur during commands
        "generic" : {
            "invalid_arg" : "Error: Invalid argument. Unknown command `" + data1 + "`",
            "connect_err" : "Error: Failed connection to " + server + ":" + str(wcProtocolPort) + " via " + wcProtocol,
            "invalid_host" : "Error: Invalid hostname. Expected syntax: `pfsense-automator <HOSTNAME or IP> <COMMAND> <ARGS>`",
            "timeout" : "Error: Connection timeout",
            "connection" : "Error: Connection dropped by remote host",
            "version" : "pfsense-automator " + softwareVersion,
            "syntax" : "pfsense-automator <HOSTNAME or IP> <COMMAND> <ARGS>"
        },
        # Error/success messages for --check-auth flag
        "--check-auth": {
            "success": "Authentication successful",
            "fail": "Error: Authentication failed",
            "descr": structure_whitespace("  --check-auth",cmdFlgLen," ",True) + " : Test authentication credentials"
        },
        # Error/success messages for --check-version
        "--check-version": {
            2: "Error: Could not determine pfSense version",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "descr": structure_whitespace("  --check-version",cmdFlgLen," ",True) + " : Check the pfSense version running on remote host"
        },
        # Error/success messages for --read-general-setup flag
        "--read-general-setup": {
            2: "Error: Unexpected error reading General Setup",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported general setup to " + data1,
            "export_fail": "Failed to export general setup as JSON",
            "descr" : structure_whitespace("  --read-general-setup",cmdFlgLen," ",True) + " : Read configuration data found in System > General Setup"
        },
        # Error/success messages for --set-system-hostname
        "--set-system-hostname": {
            0: "Successfully set system hostname to `" + data1 + "." + data2 + "` on `" + server + "`",
            2: "Error: Unexpected error configuring system hostname",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            9: "Error: Could not update system hostname. A valid DNS entry for `" + data1 + "." + data2 + "` may not exist",
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "inter_warn": "Warning: if DNS Rebind checks are enabled, changing the system hostname may result in an FQDN lockout",
            "descr": structure_whitespace("  --set-system-hostname",cmdFlgLen," ",True) + " : Set the pfSense system hostname"
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
            "export_fail": "Failed to export advanced admin options as JSON",
            "descr": structure_whitespace("  --read-adv-admin",cmdFlgLen," ",True) + " : Read configuration data found in System > Advanced > Admin Access"
        },
        # Error/success messages for --read-sslcerts flag
        "--read-sslcerts": {
            2: "Error: Unexpected error reading SSL certificates",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "read_err": "Error: failed to read SSL certificates from pfSense. You may not have any certificates installed",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported SSL certificate data to " + data1,
            "export_fail": "Failed to export SSL certificate data as JSON",
            "descr": structure_whitespace("  --read-sslcerts",cmdFlgLen," ",True) + " : Read SSL certificates data found in System > Cert. Manager > Certificates"
        },
        # Error/success messages for --add-sslcert flag
        "--add-sslcert": {
            0: "SSL certificate successfully uploaded",
            2: "Error: Failed to upload SSL certificate",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "no_cert": "Error: No certificate file found at `" + data1 + "`",
            "no_key": "Error: No key file found at `" + data1 + "`",
            "empty": "Error: Certificate or key file is empty",
            "descr": structure_whitespace("  --add-sslcert",cmdFlgLen," ",True) + " : Import SSL certificate and key from file"
        },
        # Error/success messages for --set-wc-sslcert
        "--set-wc-sslcert": {
            0: "Successfully changed WebConfigurator SSL certificate to `" + data1 + "`",
            1: "Error: SSL certificate `" + data1 + "` is already in use",
            2: "Error: Failed setting SSL certificate `" + data1 + "`",
            3: globalAuthErrMsg,
            4: "Error: SSL certificate `" + data1 + "` matches multiple certificates",
            5: "Error: Certificate `" + data1 + "` not found",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "unknown_err": "Error: An unknown error has occurred",
            "descr": structure_whitespace("  --set-wc-sslcert",cmdFlgLen," ",True) + " : Set the SSL certificate used by the webConfigurator"

        },
        # Error/success messages for --setup-wc
        "--setup-wc": {
            0: "Successfully setup webConfigurator options on `" + server + "`",
            2: "Error: Unexpected error configuring webConfigurator options",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_proc": "Error: Invalid max processes value `" + data1 + "`. Expected value between 1-1024",
            "invalid_redirect": "Error: Unknown HTTP redirect option `" + data1 + "`",
            "invalid_hsts": "Error: Unknown HSTS option `" + data1 + "`",
            "invalid_autocomplete": "Error: Unknown login auto-complete option `" + data1 + "`",
            "invalid_loginmsg": "Error: Unknown authentication logging option `" + data1 + "`",
            "invalid_lockout": "Error: Unknown webConfigurator anti-lockout option `" + data1 + "`",
            "invalid_dnsrebind": "Error: Unknown DNS rebind checking option `" + data1 + "`",
            "invalid_httpreferer": "Error: Unknown HTTP_REFERER checking option `" + data1 + "`",
            "invalid_tabtext": "Error: Unknown display hostname in tab option `" + data1 + "`",
            "descr": structure_whitespace("  --setup-wc",cmdFlgLen," ",True) + " : Configure webConfigurator options"
        },
        # Error/success messages for --setup-wc
        "--set-wc-port": {
            0: "Successfully setup webConfigurator at " + wcProtocol + "://" + server + ":" + data2,
            2: "Error: Unexpected error configuring webConfigurator port. You may be sending HTTP requests to an HTTPS port",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            8: "Error: Unexpected error binding to TCP/" + data2,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_protocol": "Error: Unknown protocol `" + data1 + "`. Expected http or https",
            "invalid_port": "Error: Invalid port `" + data2 + "`. Expected value between 1-65535",
            "descr": structure_whitespace("  --set-wc-port", cmdFlgLen, " ", True) + " : Set the webConfigurator protocol and port"
        },
        # Error/success messages for --setup-console
        "--setup-console": {
            0: "Successfully setup console options on `" + server + "`",
            2: "Error: Unexpected error configuring console options",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_option": "Error: Unknown console option value `" + data1 + "`",
            "descr": structure_whitespace("  --setup-console", cmdFlgLen, " ", True) + " : Configure console options"
        },
        # Error/success messages for --setup-ssh
        "--setup-ssh": {
            0: "Successfully setup SSH on `" + server + "`",
            2: "Error: Unexpected error configuring SSH",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            20: "Error: Unknown legacy SSH authentication option `" + data1 + "`",
            21: "Error: Unknown SSH authentication option `" + data1 + "`",
            "invalid_enable": "Error: Unknown enable value `" + data1 + "`",
            "descr": structure_whitespace("  --setup-ssh", cmdFlgLen, " ", True) + " : Configure SSH options"
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
            "export_fail": "Failed to export tunable data as JSON",
            "descr": structure_whitespace("  --read-tunables", cmdFlgLen, " ", True) + " : Read tunable configuration from System > Advanced > System Tunables"
        },
        # Error/success messages for --add-tunable flag
        "--add-tunable": {
            0: "Successfully added tunable `" + data1 + "` to `" + server + "`",
            2: "Error: Unexpected error adding system tunable",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            8: "Error: Tunable `" + data1 + "` already exists",
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "descr": structure_whitespace("  --add-tunable", cmdFlgLen, " ", True) + " : Add a new system tunable"
        },
        # Error/success messages for --read-adv-admin flag
        "--read-users": {
            2: "Error: Unexpected error reading user database",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "invalid_user": "Error: User `" + data1 + "` does not exist",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported user data to " + data1,
            "export_fail": "Failed to export user data as JSON",
            "descr": structure_whitespace("  --read-users", cmdFlgLen, " ", True) + " : Read user data from System > User Manager > Users"
        },
        # Error/success messages for --add-user
        "--add-user": {
            0: "Successfully added user `" + data1 + "` to " + server,
            2: "Error: Unexpected error adding user",
            3: globalAuthErrMsg,
            4: "Error: Username `" + data1 + "` already exists",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_enable": "Error: Invalid enable value `" + data1 + "`",
            "invalid_date": "Error: Invalid expiration date `" + data1 + "`. This must be a future date in MM/DD/YYYY format",
            "invalid_group": "Error: Group `" + data1 + "` does not exist",
            "descr": structure_whitespace("  --add-user", cmdFlgLen, " ", True) + " : Add a new local webConfigurator user"
        },
        # Error/success messages for --del-user
        "--del-user": {
            0: "Successful removed user `" + data1 + "` from " + server,
            2: "Error: Unexpected error removing user",
            3: globalAuthErrMsg,
            4: "Error: User `" + data1 + "` does not exist",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_uid": "Error: Username `admin` or UID `0` cannot be removed",
            "invalid_user": "Error: You cannot delete your own user",
            "descr": structure_whitespace("  --del-user", cmdFlgLen, " ", True) + " : Remove an existing webConfigurator user"
        },
        # Error/success messages for --add-user-key
        "--add-user-key": {
            0: "Successfully added " + data1 + " key to user `" + data2 + "`",
            2: "Error: Unexpected error adding " + data1 + " key. Your key may be invalid",
            3: globalAuthErrMsg,
            4: "Error: Username `" + data2 + "` does not exist",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_key_type": "Error: Invalid key type `" + data1 + "`. Expected `ssh` or `ipsec`",
            "invalid_override": "Error: Invalid SSH key override specification `" + data1 + "` Expected `yes` or `no`",
            "invalid_ssh_path": "Error: No SSH keyfile found at `" + data1 + "`",
            "descr": structure_whitespace("  --add-user-key", cmdFlgLen, " ", True) + " : Add and IPsec or SSH key to an existing user"
        },
        # Error/success messages for --change-user-passwd
        "--change-user-passwd": {
            0: "Successfully changed password for user `" + data1 + "`",
            2: "Error: Unexpected error changing user password",
            3: globalAuthErrMsg,
            4: "Error: Username `" + data1 + "` does not exist",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "descr": structure_whitespace("  --change-user-passwd", cmdFlgLen, " ", True) + " : Change an existing user's password"
        },
        # Error/success messages for -add-ldapserver
        "--add-ldapserver": {
            0: "Successfully added LDAP server `" + data1 + "` on `" + server + "`",
            2: "Error: Failed to configure LDAP server",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_userAlt": "Error: Invalid username alteration value `" + data1 + "`. Expected yes or no",
            "invalid_encode": "Error: Invalid encode value `" + data1 + "`. Expected yes or no",
            "invalid_rfc2307": "Error: Invalid RFC2307 value `" + data1 + "`. Expected yes or no",
            "invalid_ldapTemplate": "Error: Invalid LDAP template value `" + data1 + "`",
            "invalid_bindAnon": "Error: Invalid bind anonymous value `" + data1 + "`. Expected yes or no",
            "invalid_extQuery": "Error: Invalid extended query value `" + data1 + "`. Expected yes or no",
            "invalid_searchScope": "Error: Invalid search scope value `" + data1 + "`",
            "invalid_timeout_range": "Error: server timeout value `" + data1 + "` out of range. Expected 1-9999999999",
            "invalid_timeout": "Error: Invalid timeout value `" + data1 + "`",
            "invalid_protocol": "Error: Invalid LDAP version value `" + data1 + "`. Expected 2 or 3",
            "invalid_transport": "Error: Unknown transport type `" + data1 + "`",
            "invalid_port": "Error: Invalid LDAP port value `" + data1 + "`",
            "invalid_portrange": "Error: LDAP port `" + data1 + "` out of range. Expected 1-65535",
            "missing_args": "Error: missing arguments",
            "descr": structure_whitespace("  --add-ldapserver", cmdFlgLen, " ", True) + " : Add a new LDAP authentication server ",
        },
        # Error/success messages for --read-installed-pkgs flag
        "--read-available-pkgs": {
            2: "Error: Unexpected error reading available packages",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported available package data to " + data1,
            "export_fail": "Failed to export available package data as JSON",
            "descr": structure_whitespace("  --read-available-pkgs", cmdFlgLen, " ", True) + " : Read available packages from System > Package Manager",
        },
        # Error/success messages for --read-installed-pkgs flag
        "--read-installed-pkgs": {
            2: "Error: Unexpected error reading package installations",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported package data to " + data1,
            "export_fail": "Failed to export package data as JSON",
            "descr": structure_whitespace("  --read-installed-pkgs", cmdFlgLen, " ", True) + " : Read installed packages from System > Package Manager",
        },
        # Error/success messages for --add-package
        "--add-pkg": {
            0: "Successfully installed package `" + data1 + "`",
            2: "Error: Unexpected error installing package",
            3: globalAuthErrMsg,
            4: "Error: Package `" + data1 + "` does not exist",
            5: "Error: Package `" + data1 + "` is already installed",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "descr": structure_whitespace("  --add-pkg", cmdFlgLen, " ", True) + " : Add a new package to pfSense",
        },
        # Error/success messages for --del-package
        "--del-pkg": {
            0: "Successfully removed package `" + data1 + "`",
            2: "Error: Unexpected error removing package",
            3: globalAuthErrMsg,
            4: "Error: Package `" + data1 + "` is not installed",
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "descr": structure_whitespace("  --del-pkg", cmdFlgLen, " ", True) + " : Remove an existing package from pfSense",
        },
        # Error/success messages for --read-arp flag
        "--read-arp": {
            2: "Error: Unexpected error reading ARP configuration",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported ARP table to " + data1,
            "export_fail": "Failed to export ARP table as JSON",
            "descr": structure_whitespace("  --read-arp", cmdFlgLen, " ", True) + " : Read ARP table from Diagnostics > ARP Table",
        },
        # Error/success messages for --read-xml flag
        "--read-xml": {
            2: "Error: Unexpected error reading XML configuration",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "invalid_area": "Error: invalid XML area `" + data1 + "`",
            "invalid_pkg": "Error: invalid package option `" + data1 + "`",
            "invalid_rrd": "Error: invalid RRD option `" + data1 + "`",
            "invalid_encrypt": "Error: invalid encryption option `" + data1 + "`",
            "export_success": "Successfully exported XML configuration to " + data1,
            "export_fail": "Failed to export XML configuration",
            "descr": structure_whitespace("  --read-xml", cmdFlgLen, " ", True) + " : Read or save XML configuration from Diagnostics > Backup & Restore",
        },
        # Error/success messages for --upload-xml flag
        "--upload-xml": {
            0: "Successfully uploaded XML configuration to restoration area `" + data1 + "`. A reboot may be required.",
            2: "Error: Failed to restore XML configuration. Your XML file may be malformed",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filepath": "Error: No file found at `" + data1 + "`",
            "invalid_area": "Error: Invalid restoration area `" + data1 + "`",
            "descr": structure_whitespace("  --upload-xml", cmdFlgLen, " ", True) + " : Restore an existing XML configuration from file",
        },
        # Error/success messages for --replicate-xml flag
        "--replicate-xml": {
            2: "Error: Unexpected error pulling XML configuration from master `" + server + "`",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_area": "Error: Invalid restoration area `" + data1 + "`",
            "invalid_targets": "Error: Invalid target string `" + data1 + "`",
            "descr": structure_whitespace("  --replicate-xml", cmdFlgLen, " ", True) + " : Copy an XML area from one pfSense server to another",
        },
        # Error/success messages for --run-shell-cmd
        "--run-shell-cmd": {
            2: "Error: Unexpected response from command `" + data1 + "`",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "descr": structure_whitespace("  --run-shell-cmd", cmdFlgLen, " ", True) + " : Run a single shell command or start a virtual shell",
        },
        # Error/success messages for --read-interfaces flag
        "--read-interfaces": {
            2: "Error: Unexpected error reading interface configuration",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported interface data to " + data1,
            "export_fail": "Failed to export interface data as JSON",
            "descr": structure_whitespace("  --read-interfaces", cmdFlgLen, " ", True) + " : Read configured interfaces from Interfaces > Assignments",
        },
        # Error/success messages for --read-available-interfaces flag
        "--read-available-interfaces": {
            2: "Error: Unexpected error reading interface configuration",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "no_if": "No interfaces available on `" + server + "`",
            "descr": structure_whitespace("  --read-available-interfaces", cmdFlgLen, " ", True) + " : Read interfaces that are available but not configured",
        },
        # Error/success messages for --read-vlans flag
        "--read-vlans": {
            2: "Error: Unexpected error reading VLAN configuration. You may not have any VLANs configured",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported VLAN data to " + data1,
            "export_fail": "Failed to export VLAN data as JSON",
            "descr": structure_whitespace("  --read-vlans", cmdFlgLen, " ", True) + " : Read configured VLAN from Interfaces > VLANs",
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
            "invalid_priority" : "Error: VLAN priority `" + data1 + "` out of range. Expected 0-7",
            "descr": structure_whitespace("  --add-vlans", cmdFlgLen, " ", True) + " : Add a new VLAN to an existing interface",
        },
        # Error/success messages for --read-dns
        "--read-dns": {
            0: True,
            2: "Error: Unexpected error reading DNS Resolver configuration",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_syntax": "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --read-dns <FILTER>`",
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported DNS Resolver data to " + data1,
            "export_fail": "Failed to export DNS Resolver data as JSON",
            "descr": structure_whitespace("  --read-dns", cmdFlgLen, " ", True) + " : Read DNS resolver entries from Services > DNS Resolvers",
        },
        # Error/success messages for --add-dns flag
        "--add-dns" : {
            0 : "DNS record was added successfully",
            2: "Error: Unexpected error adding `" + data1 + "." + data2  + "`",
            3 : globalAuthErrMsg,
            4 : "Error: DNS unreachable at " + server,
            6 : globalPlatformErrMsg,
            9 : "Error: DNS entry for `" + data1 + "." + data2  + "` already exists @" + server,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_ip" : "Error: Invalid IP address",
            "invalid_syntax" : "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --add-dns <HOST> <DOMAIN> <IP> <DESCR>`",
            "descr": structure_whitespace("  --add-dns", cmdFlgLen, " ", True) + " : Add a new DNS host override to DNS Resolver",
        },
        # Error/success messages for --read-rules
        "--read-rules" : {
            3 : globalAuthErrMsg,
            4 : "Error: Interface `" + data1 + "` does not exist",
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "read_err" : "Error: Unexpected error reading Firewall Rules from pfSense",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported Firewall Rule data to " + data1,
            "export_fail" : "Failed to export Firewall Rules data as JSON",
            "descr": structure_whitespace("  --read-rules", cmdFlgLen, " ", True) + " : Read configured firewall rules from Firewall > Rules",
        },
        # Error/success messages for --add-rule
        "--add-rule" : {
            0: "Successfully added firewall rule to " + server + " on `" + data1 + "`",
            2: "Error: Unexpected error adding firewall rule",
            3 : globalAuthErrMsg,
            4: "Error: Invalid source port. Port must be between 1 & 65535. If a port range, your start port must be less than your end port",
            5: "Error: Invalid destination port. Port must be between 1 & 65535. If a port range, your start port must be less than your end port",
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_type": "Error: Invalid rule type `" + data1 + "`. Expected `pass`, `block`, or `reject`",
            "invalid_ipver" : "Error: Invalid IP version `" + data1 + "`. Expected `ipv4`, `ipv6` or `any`",
            "invalid_protocol" : "Error: Invalid protocol `" + data1 + "`. Available protocols: [" + data2 + "]",
            "invalid_source" : "Error: Invalid source address `" + data1 + "`",
            "invalid_dest": "Error: Invalid destination address `" + data1 + "`",
            "invalid_bitmask" : "Error: Invalid bitmask `" + data1 + "`. Expected value between 1 & 32",
            "descr": structure_whitespace("  --add-rule", cmdFlgLen, " ", True) + " : Add a new basic firewall rule",
        },
        # Error/success messages for --del-rule
        "--del-rule" : {
            0: "Successfully removed firewall rule ID `" + data2 + "` from ACL `" + data1 + "`",
            2: "Error: Unexpected error remvoing firewall rule",
            3 : globalAuthErrMsg,
            4: "Error: Invalid interface. Interface `" + data1 + "` does not exist",
            5: "Error: Invalid rule ID. Rule ID `" + data2 + "` does not exist",
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_id": "Error: Invalid rule ID. Expected a number greater than 0",
            "descr": structure_whitespace("  --del-rule", cmdFlgLen, " ", True) + " : Delete a firewall rule from an interface ACL",
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
            "export_fail" : "Failed to export Firewall Alias data as JSON",
            "descr": structure_whitespace("  --read-aliases", cmdFlgLen, " ", True) + " : Read configured firewall aliases from Firewall > Aliases",
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
            "invalid_syntax" : "Error: Invalid syntax - `pfsense-automator <pfSense IP or FQDN> --modify-alias <alias name> <alias values>`",
            "descr": structure_whitespace("  --modify-alias", cmdFlgLen, " ", True) + " : Modify an existing firewall alias",
        },
        # Error/success messages for --read-virtual-ip
        "--read-virtual-ips": {
            2: "Error: Unknown error gathering virtual IP data",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported Virtual IP data to " + data1,
            "export_fail": "Failed to export Virtual IP data as JSON",
            "descr": structure_whitespace("  --read-virtual-ips", cmdFlgLen, " ", True) + " : Read configured virtual IPs from Firewall > Virtual IPs",
        },
        # Error/success messages for --add-virtual-ip
        "--add-virtual-ip": {
            0: "Successfully added virtual IP `" + data1 + "`",
            2: "Error: Unexpected error adding virtual IP. It may conflict with an existing IP",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_mode": "Error: Unknown virtual IP type `" + data1 + "`. Expected `ipalias`, `carp`, `proxyarp` or `other`",
            "invalid_iface": "Error: Interface `" + data1 + "` does not exist",
            "invalid_subnet": "Error: Invalid subnet CIDR `" + data1 + "`",
            "invalid_expand": "Error: Unknown IP expansion option `" + data1 + "`. Expected `yes` or `no`",
            "invalid_adv": "Error: Invalid advertisements - BASE: `" + data1 + "` SKEW: `" + data2 + "`. Expected value 0-254",
            "invalid_vhid": "Error: Invalid VHID `" + data1 + "`. Expected value 1-255",
            "vhid_exists": "Error: VHID `" + data1 + "` already exists on interface `" + data2 + "`",
            "descr": structure_whitespace("  --add-virtual-ip", cmdFlgLen, " ", True) + " : Configure a new virtual IP",
        },
        # Error/success messages for --read-hasync
        "--read-hasync" : {
            2 : "Error: Unexpected error gathering HA Sync data",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported HA Sync data to " + data1,
            "export_fail" : "Failed to export HA Sync data as JSON",
            "descr": structure_whitespace("  --read-hasync", cmdFlgLen, " ", True) + " : Read HA sync configuration from System > HA Sync",
        },
        # Error/success messages for --setup-hasync
        "--setup-hasync" : {
            0: "Successfully setup HA sync",
            2: "Error: Unexpected error configuring HA sync",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_enable" : "Error: Invalid PFSYNC enable value `" + data1 + "`. Expected `enable`,`disable`, or `default`",
            "invalid_interface" : "Error: Unknown interface `" + data1 + "`",
            "invalid_ip" : "Error: Invalid " + data1 + " peer IP `" + data2 + "`",
            "invalid_user" : "Error: Invalid XMLRPC username `" + data1 + "`",
            "invalid_passwd" : "Error: Invalid XMLRPC password length",
            "descr": structure_whitespace("  --setup-hasync", cmdFlgLen, " ", True) + " : Configure HA Sync",
        },
        # Error/success messages for --setup-hapfsense
        "--setup-hapfsense" : {
            0 : "Successfully configured HA pfSense",
            2 : "Error: Unexpected error configuring HA pfSense",
            3: globalAuthErrMsg,
            6: globalPlatformErrMsg,
            10: globalDnsRebindMsg,
            12: "Error: pfSense version mismatch. MASTER on pfSense " + data1 + ", BACKUP on pfSense " + data2,
            13: "Error: Unable to add CARP virtual IPs to MASTER node",
            14: "Error: Unable to configure HA Sync on MASTER node",
            15: globalPermissionErrMsg,
            "invalid_backup_ip" : "Error: Invalid BACKUP node IP `" + data1 + "`",
            "invalid_master_if" : "Error: Unknown interface `" + data1 + "` on MASTER node `" + server + "`",
            "invalid_backup_if" : "Error: Unknown interface `" + data1 + "` on BACKUP node `" + data2 + "`",
            "invalid_carp_ip" : "Error: Invalid CARP virtual IP `" + data1 + "`",
            "invalid_pfsync_if" : "Error: Unknown PFSYNC interface `" + data1 + "`",
            "invalid_pfsync_ip" : "Error: Invalid PFSYNC IP address `" + data1 + "`",
            "descr": structure_whitespace("  --setup-hapfsense", cmdFlgLen, " ", True) + " : Configure pfSense to run in full High Availability",
        },
        # Error/success messages for --read-carp-status
        "--read-carp-status" : {
            2 : "Error: Unexpected error checking CARP status. No CARP interfaces found",
            3 : globalAuthErrMsg,
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported CARP data to " + data1,
            "export_fail" : "Failed to export CARP data as JSON",
            "descr": structure_whitespace("  --read-carp-status", cmdFlgLen, " ", True) + " : Read the current CARP failover status from Status > CARP",
        },
        # Error/success messages for --set-carp-maintenance
        "--set-carp-maintenance" : {
            0 : "Successfully " + data1 + " CARP maintenance mode on `" + server + "`",
            2 : "Error: Unexpected error " + data1 + " CARP maintenance mode",
            3 : globalAuthErrMsg,
            4 : "Error: No configured CARP interfaces were found",
            6 : globalPlatformErrMsg,
            10 : globalDnsRebindMsg,
            15: globalPermissionErrMsg,
            "invalid_toggle" : "Error: Invalid toggle `" + data1 + "`. Expected `enable` or `disable`",
            "descr": structure_whitespace("  --set-carp-maintenance", cmdFlgLen, " ", True) + " : Enable CARP maintenance mode",
        }
    }
    # Pull the requested message, return entire dictionary if "all" command is passed, otherwise just return the single values
    exitMessage = ecd[command][ec] if command != "all" else ecd
    # Return our message
    return exitMessage

# http_request() uses the requests module to make HTTP POST/GET requests
def http_request(url, data, headers, files, timeout, method):
    # Local Variables
    resp_dict = {}    # Initialize response dictionary to return our response values
    data = {} if type(data) != dict else data
    headers = {} if type(headers) != dict else headers
    files = {} if type(files) != dict else files
    noRespMode = True if timeout <= 5 else False    # Determine if user expects a response based on timeout value
    method_list = ['GET', 'POST']    # Set a list of supported HTTP methods
    # Check that our method is valid
    if method.upper() in method_list:
        # Process to run if a GET request was requested
        if method.upper() == "GET":
            getTimedOut = False    # Assign bool to track whether we received a timeout
            getConnErr = False    # Assign a bool to track whether we received a connection error
            try:
                req = req_session.get(url, headers=headers, verify=False, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                getTimedOut = True
            except requests.exceptions.ConnectionError:
                getConnErr = True
            # If our connection timed out AND our timeout value was greater than 5 seconds
            if getTimedOut and timeout > 5:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
            # If our connection returned an error
            if getConnErr:
                print(get_exit_message("connection", "", "generic", "", ""))
                sys.exit(1)
        # Process to run if a POST request was requested
        elif method.upper() == "POST":
            postTimedOut = False  # Assign bool to track whether we received a timeout
            postConnErr = False  # Assign a bool to track whether we received a connection error
            # Try to open the connection and gather data
            try:
                req = req_session.post(url, data=data, files=files, headers=headers, verify=False, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                postTimedOut = True
            except requests.exceptions.ConnectionError:
                postConnErr = True
            # If our connection timed out AND our timeout value was greater than 5 seconds
            if postTimedOut and timeout > 5:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
            # If our connection returned an error
            if postConnErr:
                print(get_exit_message("connection", "", "generic", "", ""))
                sys.exit(1)
        # Check if responseless mode is disabled
        if not noRespMode:
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
    htmlStr = http_request(url, {}, {}, {}, 45, "GET")["text"]    # Get our HTML data
    platformConfidence = 0    # Assign a integer confidence value
    # List of platform dependent key words to check for
    checkItems = [
        "pfSense", "pfsense.org", "Login to pfSense", "pfsense-logo", "pfSenseHelpers",
        "netgate.com", "__csrf_magic", "ESF", "Netgate", "Rubicon Communications, LLC",
        "Electric Sheep Fencing LLC", "https://pfsense.org/license"
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

# validate_port_range() takes a port or port range (separated by -) and determine if the port range is valid
def validate_port_range(port):
    # Local variables
    ports = {"valid": False, "start": 0, "end": 0}    # Create a dictionary to track various values
    # Check if port contains `-` range indicator
    if "-" in str(port):
        portRng = str(port).split("-")    # Split our port to capture our start and end port
        # Check that our list only has two values
        if len(portRng) == 2:
            startPort = int(portRng[0]) if portRng[0].isdigit() else 0    # Save our start port
            endPort = int(portRng[1]) if portRng[1].isdigit() else 65536    # Save our start port
            startPortVld = False    # Assign a bool to track if the start port is valid
            endPortVld = False    # Assign a bool to track if the end port is valid
            # Check if our start port is within range and less than the end port
            if 1 <= startPort <= 65535 and 1 <= endPort <= 65535 and startPort <= endPort:
                ports = {"valid": True, "start": startPort, "end": endPort}
    # Check if port is a number
    elif str(port).isdigit():
        # Check that port is in range
        if 1 <= int(port) <= 65535:
            ports = {"valid": True, "start": int(port), "end": int(port)}
    # Return our dictionary
    return ports

# validate_date_format() checks if a date string is in the format mm/dd/yyyy and is a future date
def validate_date_format(dateStr):
    # Local variables
    dateValid = False    # Init our return value as false by default
    dateNow = datetime.datetime.now()    # Create our time object to compare later
    # Check if our date string is actually a string
    if type(dateStr) is str:
        # Check if we have the `/` character in our string
        if "/" in dateStr:
            dateList = dateStr.split("/")    # Split our string into a list so we can verify each date value
            # Check that we have three items in the list
            if len(dateList) == 3:
                # Check that our month value is a digit
                if dateList[0].isdigit() and dateList[1].isdigit() and dateList[2].isdigit():
                    # Try to create a date object with these parameters
                    try:
                        futureDate = datetime.datetime(int(dateList[2]),int(dateList[0]),int(dateList[1]))
                        dObjCreate = True
                    except ValueError as x:
                        dObjCreate = False
                    # If our time object was successfully created, test if our dateStr is greater than the current time
                    if dObjCreate:
                        if futureDate > dateNow:
                            dateValid = True
    # Return our bool
    return dateValid

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
    httpResponse = http_request(url, {}, {}, {}, 45, "GET")["text"]    # Get the HTTP response of the URL
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)   # Assign our base URL
    authCheckData = {"__csrf_magic": get_csrf_token(url + "/index.php", "GET"), "usernamefld": user, "passwordfld": key, "login": "Sign In"}    # Define a dictionary for our login POST data
    preAuthCheck = http_request(url + "/index.php", {}, {}, {}, 45, "GET")
    # Check that we're not already signed
    if not "class=\"fa fa-sign-out\"" in preAuthCheck["text"]:
        # Complete authentication
        authCheck = http_request(url + "/index.php", authCheckData, {}, {}, 45, "POST")
        authSuccess = True if not "Username or Password incorrect" in authCheck["text"] and "class=\"fa fa-sign-out\"" in authCheck["text"] else authSuccess    # Return false if login failed
    # Else return true because we are already signed in
    else:
        authSuccess = True
    return authSuccess

# get_csrf_token() makes an initial connection to pfSense to retrieve the CSRF token. This supports both GET and POST requests
def get_csrf_token(url, type):
        # Local Variables
        csrfTokenLength = 55  # Set the expected token length of the csrf token
        csrfResponse = http_request(url, None, {}, {}, 45, type)
        # Parse CSRF token and conditionalize return value
        if "sid:" in csrfResponse['text']:
            csrfParsed = "sid:" + csrfResponse['text'].split("sid:")[1].split(";")[0].replace(" ", "").replace("\n", "").replace("\"", "")
            csrfToken = csrfParsed if len(csrfParsed) is csrfTokenLength else ""    # Assign the csrfToken to the parsed value if the expected string length is found
        # If we could not find a CSRF token
        else:
            csrfToken = ""    # Assign blank CSRF token as none was found
        return csrfToken    # Return our token

# get_pfsense_version() checks the version of pfSense
def get_pfsense_version(server, user, key):
    # Local variables
    pfVersion = {"ec":2,"version":{"installed_version":""}}    # Initialize a dictionary to save version data
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    pfVersion["ec"] = 10 if check_dns_rebind_error(url) else pfVersion["ec"]    # Return exit code 10 if dns rebind error found
    pfVersion["ec"] = 6 if not validate_platform(url) else pfVersion["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if pfVersion["ec"] == 2:
        pfVersion["ec"] = 3 if not check_auth(server, user, key) else pfVersion["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if pfVersion["ec"] == 2:
        getIndexVersionData = http_request(url + "/widgets/widgets/system_information.widget.php", {}, {}, {}, 45, "GET")    # Pull our version data using GET HTTP
        # Check that we had permissions for this page
        if check_permissions(getIndexVersionData):
            # Check that we are able to find version on the index page
            expectedTag = "<th>Version</th>"
            if expectedTag in getIndexVersionData["text"]:
                versionTableData = getIndexVersionData["text"].split(expectedTag)[1].split("</tr>")[0]
                # Check that we have strong tags
                if "<strong>" in versionTableData:
                    pfVersionFullRelease = versionTableData.split("<strong>")[1].split("</strong>")[0]    # Capture our version data between the strong tags
                    pfVersionPatch = pfVersionFullRelease.replace("RELEASE","").replace("-","").replace("p","_")    # Format our version to shorthand
                    pfVersion["version"]["installed_version"] = pfVersionPatch     # Save our formatted version
            # Update exit code to success
            pfVersion["ec"] = 0 if pfVersion["version"]["installed_version"] != "" else 2  # Set exit code 0 (success)
        # If we did not have permission to the necessary pages
        else:
            pfVersion["ec"] = 15    # Set exit code 15 (permission denied)
    # Return our data dictionary
    return pfVersion

# get_permissions_table() returns a dictionary file containing all user privileges, and their POST data values
def get_permissions_table(server, user, key):
    # Local variables
    prms = {"ec":2,"privileges":{}}    # Initialize a dictionary to populate our user database too
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    prms["ec"] = 10 if check_dns_rebind_error(url) else prms["ec"]    # Return exit code 10 if dns rebind error found
    prms["ec"] = 6 if not validate_platform(url) else prms["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if prms["ec"] == 2:
        prms["ec"] = 3 if not check_auth(server, user, key) else prms["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if prms["ec"] == 2:
        getAllGroupId = get_user_groups(server, user, key)    # Find the 'all' group ID, this group displays all available privileges
        # Check that we could find group containing all available permissions
        if getAllGroupId["ec"] == 0:
            getPrmsData = http_request(url + "/system_groupmanager_addprivs.php?groupid=" + getAllGroupId["groups"]["all"]["id"], {}, {}, {}, 45, "GET")    # Pull our users data using GET HTTP
            # Check that we had permissions for this page
            if check_permissions(getPrmsData):
                # Parse our HTML output to only return the privilege select tag
                permissionSelect = getPrmsData["text"].split("<select class=\"form-control multiselect\" name=\"sysprivs[]\" id=\"sysprivs[]\" multiple=\"multiple\">")[1].split("</select>")[0]
                permissionOpt = permissionSelect.split("<option value=\"")    # Split our select tag into a list of selectable options
                del permissionOpt[0]    # Delete first list item as it contains the data before our options
                # Loop through each option and gather it's info
                for opt in permissionOpt:
                    # Assign default admin privileges in the case that we cannot pull them dynamically
                    defaulAdmPriv = """
                        User - System: Copy files (scp)<br/>User - System: Shell account access<br/>WebCfg - All pages<br/>
                        WebCfg - Diagnostics: Backup & Restore<br/>WebCfg - Diagnostics: Command<br/>WebCfg - Diagnostics: Edit File<br/>WebCfg - Diagnostics: Factory defaults<br/>
                        WebCfg - OpenVPN: Servers Edit Advanced<br/>WebCfg - OpenVPN: Client Specific Override Edit Advanced<br/>
                        WebCfg - OpenVPN: Clients Edit Advanced<br/>WebCfg - System: Authentication Servers<br/>WebCfg - System: Group Manager<br/>
                        WebCfg - System: Group Manager: Add Privileges<br/>WebCfg - System: User Manager<br/>WebCfg - System: User Manager: Add Privileges<br/>
                        WebCfg - System: User Manager: Settings
                    """
                    descrName = opt.split(">")[1].split("</option")[0]    # Find our descriptive UI name for the privilege
                    httpName = opt.split("\"")[0]    # Find our POST name for the value
                    adminPrivData = getPrmsData["text"].split("<span>Privilege information</span>")[1].split("</div>")[0] if "<span>Privilege information</span>" in getPrmsData["text"] else defaulAdmPriv    # Dynamically update privilege data if it's available, otherwise assume defaults
                    privLevel = "admin" if descrName in adminPrivData else "user"    # Check if our privilege is an admin privilege, otherwise assign it as a user privilege
                    privLevel = "readonly" if descrName == "User - Config: Deny Config Write" else privLevel    # If privilege assigns readonly access, assign the privilege level to readonly
                    prms["privileges"][descrName] = {"name":httpName,"level":privLevel}    # Initialize our individual privilege dictionary
                # Assign success exit code
                prms["ec"] = 0
             # If we do not have permissions to access the permissions table
            else:
                prms["ec"] = 15    # Return exit code 15 (permission denied)
        # Return exit code indicating we could not find master privilege list
        else:
            prms["ec"] = 20    # Assign exit code 20, could not locate master privilege list
    # Return our dictionary
    return prms

# get_users() pulls information from /system_usermanager.php to gather information on all local pfSense users
def get_users(server, user, key):
    # Local variables
    users = {"ec":2,"users":{}}    # Initialize a dictionary to populate our user database too
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    users["ec"] = 10 if check_dns_rebind_error(url) else users["ec"]    # Return exit code 10 if dns rebind error found
    users["ec"] = 6 if not validate_platform(url) else users["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if users["ec"] == 2:
        users["ec"] = 3 if not check_auth(server, user, key) else users["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if users["ec"] == 2:
        # Check that we had permissions for this page
        getUserData = http_request(url + "/system_usermanager.php", {}, {}, {}, 45, "GET")    # Pull our users data using GET HTTP
        if check_permissions(getUserData):
            # Save our user permissions dictionary
            masterPrivDict = get_permissions_table(server, user, key)    # Pull the dictionary containing all privileges and their POST data names
            # Parse our HTML response and save user data if expected tags found
            if "<tbody>" in getUserData["text"]:
                userTableBody = getUserData["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save anything between tbody opening and closing tags
                userTableRows = userTableBody.split("<tr>")    # Save our user table rows to a list
                # Check that our list has data
                if len(userTableRows) > 0:
                    # Loop through our users and pull their data
                    for u in userTableRows:
                        # Check that table data exists
                        if "<td>" in u:
                            # Split our row into data fields
                            userTableData = u.split("<td>")
                            uname = userTableData[2].replace("\t","").replace("\n","").replace(" ","").split("</i>")[1].split("</td>")[0]    # Save our username
                            uid = userTableData[6].replace("\t","").replace("\n","").replace(" ","").split("?act=edit&amp;userid=")[1].split("\"></a>")[0]    # Save our user ID
                            # Now that we have our user ID, open the edit page to read more information
                            if uid.isdigit():
                                # Try to parse our values, if an error is thrown break the loop and return failed exit code
                                try:
                                    getUserAdvData = http_request(url + "/system_usermanager.php?act=edit&userid=" + uid, {}, {}, {}, 45, "GET")    # Save our advanced user data
                                    privLevel = "user"    # Default each user to privilege level 'user' until determined otherwise
                                    definedBy = getUserAdvData["text"].split("<span>Defined by</span>")[1].split("</div>")[0].replace("\t","").replace("\n","").split("<div class=\"col-sm-10\">")[1] if "<span>Defined by</span>" in getUserAdvData["text"] else ""    # Save our defined by field
                                    disabled = "yes" if "checked=\"checked\"" in getUserAdvData["text"].split("<span>Disabled</span>")[1].split("</div>")[0] else ""    # Save our disable login value
                                    fullName = getUserAdvData["text"].split("<span>Full name</span>")[1].split("</div>")[0].split("value=\"")[1].split("\"")[0] if "<span>Full name</span>" in getUserAdvData["text"] else ""  # Save our user's full name value
                                    expDate = getUserAdvData["text"].split("<span>Expiration date</span>")[1].split("</div>")[0].split("value=\"")[1].split("\"")[0] if definedBy == "USER" else ""    # Save our exp data if a USER defined user
                                    customUi = "yes" if "checked=\"checked\"" in getUserAdvData["text"].split("<span>Custom Settings</span>")[1].split("</div>")[0] else ""    # Save our custom UI value
                                    authKeys = getUserAdvData["text"].split("=\"authorizedkeys\">")[1].split("</textarea>")[0] if "=\"authorizedkeys\">" in getUserAdvData["text"] else ""   # Save our user's authorized keys
                                    ipsecKeyRaw = getUserAdvData["text"].split("<span>IPsec Pre-Shared Key</span>")[1].split("</div>")[0] if "<span>IPsec Pre-Shared Key</span>" in getUserAdvData["text"] else ""   # Save entire table data value for IPsec keys, we need to be more granular with this value
                                    ipsecKey = ipsecKeyRaw.split("value=\"")[1].split("\"")[0] if "value=" in ipsecKeyRaw else ""    # If our IPsec key contains a value, save that value, otherwise assume default
                                except:
                                    users["ec"] = 2    # Return an error code
                                    break     # Break our loop as we are missing expected data
                                # Check our GROUP memberships
                                groupSelection = getUserAdvData["text"].split("name=\"groups[]\"")[1].split("</select>")[0] if "name=\"groups[]\"" in getUserAdvData["text"] else ""    # Target our select tag for groups we are members of
                                groupListRaw = groupSelection.split("<option value=\"") if "<option value=\"" in groupSelection else [""]    # Create a unformatted list of groups we are members of
                                groupList = []    # Initialize our formatted list to be populated by our loop
                                # Loop through our list of groups and format the final list
                                del groupListRaw[0]    # Remove our first list item as it is before our target value
                                for g in groupListRaw:
                                    groupList.append(g.split("\"")[0])    # Add our formatted items to the list
                                # Check our USER PERMISSIONS
                                privTableBody = getUserAdvData["text"].split("<h2 class=\"panel-title\">Effective Privileges</h2>")[1].split("</i>Add</a></nav>")[0].split("<tbody>")[1].split("</tbody>")[0]
                                privTableRows = privTableBody.split("<tr>") if "<tr>" in privTableBody else ['']   # Split our table rows into a list
                                privDict = {}    # Create a dictionary to save our privilege data to
                                privDict["level"] = "user"  # Default to user privilege until determined otherwise
                                # Loop through our table rows and pull their data
                                del privTableRows[0]    # Remove our first row value as it contains data listed before table rows start
                                counter = 0    # Create a loop counter to track our loop iteration
                                for r in privTableRows:
                                    # Check that we are not on the last index
                                    if "Security notice" not in r:
                                        privDict[counter] = {}    # Create a dictionary for this privilege
                                        privDict[counter]["id"] = r.split("<td>")[4].split("id=\"")[1].split("\"")[0] if "id=\"" in r.split("<td>")[4] else ""
                                        privDict[counter]["inherited"] = r.split("<td>")[1].split("</td>")[0]
                                        privDict[counter]["descr_name"] = r.split("<td>")[2].split("</td>")[0]
                                        privDict[counter]["descr"] = r.split("<td>")[3].split("</td>")[0]
                                        privDict[counter]["name"] = masterPrivDict["privileges"][privDict[counter]["descr_name"]]["name"]
                                        # Check if our privilege level is admin and not readonly
                                        if masterPrivDict["privileges"][privDict[counter]["descr_name"]]["level"] == "admin" and privDict["level"] != "readonly":
                                            privDict["level"] = "admin"    # Set our privilege level to admin
                                        # Check if our privilege level is read only
                                        if masterPrivDict["privileges"][privDict[counter]["descr_name"]]["level"] == "readonly":
                                            privDict["level"] = "readonly"    # Set our privilege level to readonly
                                        counter = counter + 1    # Increase our counter
                                # Check our USER CERTIFICATES
                                certTableBody = getUserAdvData["text"].split("<h2 class=\"panel-title\">User Certificates</h2>")[1].split("</i>Add</a></nav>")[0].split("<tbody>")[1].split("</tbody>")[0]
                                certTableRows = certTableBody.split("<tr>") if "<tr>" in privTableBody else ['']  # Split our table rows into a list
                                certDict = {}  # Create a dictionary to save our cert data to
                                # Loop through our table rows and pull their data
                                del certTableRows[0]  # Remove our first row value as it contains data listed before table rows start
                                counter = 0  # Create a loop counter to track our loop iteration
                                for c in certTableRows:
                                    certDict[counter] = {}    # Create a dictionary for this privilege
                                    certDict[counter]["id"] = c.split("<td>")[3].split("id=\"")[1].split("\"")[0] if "id=\"" in c.split("<td>")[3] else ""
                                    certDict[counter]["name"] = c.split("<td>")[1].split("</td>")[0]
                                    certDict[counter]["ca"] = c.split("<td>")[2].split("</td>")[0]
                                # Check our USER CUSTOM UI values
                                uiDict = {}    # Initialize a UI dictionary to track users UI settings
                                uiSelectTags = ["webguicss","webguifixedmenu","webguihostnamemenu"]
                                uiTextTags = ["dashboardcolumns"]
                                uiCheckTags = ["interfacessort","dashboardavailablewidgetspanel","systemlogsfilterpanel","systemlogsmanagelogpanel",
                                               "statusmonitoringsettingspanel","webguileftcolumnhyper","disablealiaspopupdetail","pagenamefirst"]
                                # Loop through our SELECT input tags
                                for s in uiSelectTags:
                                    if "name=\""+s+"\"" in getUserAdvData["text"]:
                                        userGuiScheme = getUserAdvData["text"].split("name=\""+s+"\"")[1].split("</select>")[0].split("<option value=\"")
                                        # Loop through our UI values and save our configuration
                                        for c in userGuiScheme:
                                            # Check if this value is selected
                                            if "selected>" in c:
                                                uiDict[s] = c.split("\"")[0]    # Save our value
                                                break    # Break the loop as we have found our value
                                            else:
                                                uiDict[s] = ""    # Save default value
                                    else:
                                        uiDict[s] = ""  # Save default value
                                # Loop through our CHECKBOX input tags
                                for x in uiCheckTags:
                                     # Check if we have a systemlogsfilterpanel option
                                    if "<input name=\""+x+"\"" in getUserAdvData["text"]:
                                        uiDict[x] = True if "checked" in getUserAdvData["text"].split("<input name=\""+x+"\"")[1].split("</label>")[0] else False
                                    # If we do not have this option, assign empty string
                                    else:
                                        uiDict[x] = ""
                                # Loop through our TEXT input tags
                                for t in uiTextTags:
                                    if "name=\""+t+"\"" in getUserAdvData["text"]:
                                        uiDict[t] = getUserAdvData["text"].split("name=\""+t+"\"")[1].split("value=\"")[1].split("\"")[0]  # Get our value
                                    # If we do not have this option, assign empty string
                                    else:
                                        uiDict[t] = ""
                                # Save our values to user dictionary
                                users["users"][uname] = {
                                    "username" : uname,
                                    "id" : uid,
                                    "type" : definedBy,
                                    "disabled" : disabled,
                                    "full_name" : fullName,
                                    "expiration" : expDate,
                                    "custom_ui" : customUi,
                                    "custom_ui_config" : uiDict,
                                    "groups" : groupList,
                                    "privileges" : privDict,
                                    "user_certificates" : certDict,
                                    "authorized_keys" : authKeys,
                                    "ipsec_keys" : ipsecKey
                                }
                        # Assign success exit code
                        users["ec"] = 0
        # If we did not have permissions to read user data
        else:
            users["ec"] = 15    # Assign exit code 15 (permission denied)
    return users

# add_user() creates a new webConfigurator user in system_usernamanger.php
def add_user(server, user, key, uname, enable, passwd, fname, expDate, groups):
    # Local variables
    userAdded = 2    # Initialize our return code as 2 (error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)  # Assign our base URL
    existUsers = get_users(server, user, key)    # Pull our existing user database
    # Check that we successfully pulled our existing users
    if existUsers["ec"] == 0:
        # Check that our desired username does not already exist
        if uname not in existUsers["users"]:
            # Format our POST data dictionary
            userPostData = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php", "GET"),
                "usernamefld": uname,
                "disabled": enable,
                "passwordfld1": passwd,
                "passwordfld2": passwd,
                "descr": fname,
                "expires": expDate,
                "groups[]": groups,
                "utype": "user",
                "webguicss": "pfSense.css",
                "webguifixedmenu": "",
                "webguihostnamemenu": "",
                "dashboardcolumns": "2",
                "authorizedkeys": "",
                "ipsecpsk": "",
                "act": "",
                "userid": "",
                "privid": "",
                "certid": "",
                "oldusername": "",
                "save": "Save"
            }
            # Make our POST request
            postNewUser = http_request(url + "/system_usermanager.php?act=new", userPostData, {}, {}, 45, "POST")
            # Check if our user is now in our user database
            updateExistUsers = get_users(server, user, key)
            if uname in updateExistUsers["users"]:
                userAdded = 0    # Return exit code 0 (success
        # If our user already exists
        else:
            userAdded = 4    # Return exit code 4 (user already exists)
    # If we encountered an error pulling our existing users, return the exit code of the get_users() function
    else:
        userAdded = existUsers["ec"]
    # Return our exit code value
    return userAdded

# del_user() deletes a user given a username or user ID
def del_user(server, user, key, uid):
    # Local variables
    userDel = 2    # Assign our return code default as 2 (error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existUsers = get_users(server, user, key)    # Pull our current user configuration
    # Check that we pulled our users successfully
    if existUsers["ec"] == 0:
        usrFound = False    # Assign a bool to track whether or not our user was found
        # Check that our user exists
        if uid in existUsers["users"]:
            uname = uid    # Save our uname as our uid
            id = existUsers["users"][uname]["id"]    # Pull our pfSense user ID from the dictionary for this user
            usrFound = True
        # If our username was not found, check if the user ID passed in is an ID number
        elif uid.isdigit():
            # Loop through our users and check for a user ID match
            for u,data in existUsers["users"].items():
                # Check if the ID matches our input
                if data["id"] == uid:
                    uname = u    # Save our username
                    id = data["id"]    # Save our ID
                    usrFound = True
                    break    # Break our loop, we only need one set of values
        # If we could not find a user, return exit code 4
        else:
            userDel = 4    # Return exit code 4 (user not found)
        # Check if our user was found, if so run our command
        if usrFound:
            # Create a diciontary with our formatted POST values
            delUsrPostData = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php", "GET"),
                "act": "deluser",
                "username": uname,
                "userid": id
            }
            # Run our POST request, then update our current users dictionary to check if the user no longer exists
            delUserPost = http_request(url + "/system_usermanager.php", delUsrPostData, {}, {}, 45, "POST")
            updateUsers = get_users(server, user, key)    # Pull our updated user configuration
            if updateUsers["ec"] == 0 and uname not in updateUsers["users"]:
                userDel = 0    # Return our success return code 0
    # If we could not pull our user configuration, return the error code returned from get_users()
    else:
        userDel = existUsers["ec"]
    # Return our exit value
    return userDel


# add_user_key() adds a new public key for either SSH or IPsec
def add_user_key(server, user, key, uname, keyType, pubKey, destruct):
    # Local variables
    keyAdded = 2    # Init our return code as 2 (error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existUsers = get_users(server, user, key)    # Pull our existing user configuration
    # Check that we pulled our users successfully
    if existUsers["ec"] == 0:
        # Check if our user exists
        if uname in existUsers["users"]:
            uid = existUsers["users"][uname]["id"]    # Pull our user's pf ID
            # Check if our key type is SSH
            if keyType.lower() == "ssh":
                pubKey = existUsers["users"][uname]["authorized_keys"] + "\n" + pubKey if not destruct else pubKey    # Check if user simply wants to append a new key or replace all keys
            # Format our POST request data
            keyPostData = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php?act=edit&userid=" + uid, "GET"),
                "act": "edit",
                "usernamefld": uname,
                "disabled": existUsers["users"][uname]["disabled"],
                "descr": existUsers["users"][uname]["full_name"],
                "expires": existUsers["users"][uname]["expiration"],
                "groups[]":  existUsers["users"][uname]["groups"],
                "utype":  existUsers["users"][uname]["type"],
                "customsettings": existUsers["users"][uname]["custom_ui"],
                "webguicss": existUsers["users"][uname]["custom_ui_config"]["webguicss"],
                "webguifixedmenu": existUsers["users"][uname]["custom_ui_config"]["webguifixedmenu"],
                "interfacessort": "yes" if existUsers["users"][uname]["custom_ui_config"]["interfacessort"] else "",
                "dashboardavailablewidgetspanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["dashboardavailablewidgetspanel"] else "",
                "systemlogsfilterpanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["systemlogsfilterpanel"] else "",
                "systemlogsmanagelogpanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["systemlogsmanagelogpanel"] else "",
                "statusmonitoringsettingspanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["statusmonitoringsettingspanel"] else "",
                "webguileftcolumnhyper": "yes" if existUsers["users"][uname]["custom_ui_config"]["webguileftcolumnhyper"] else "",
                "disablealiaspopupdetail": "yes" if existUsers["users"][uname]["custom_ui_config"]["disablealiaspopupdetail"] else "",
                "pagenamefirst": "yes" if existUsers["users"][uname]["custom_ui_config"]["pagenamefirst"] else "",
                "webguihostnamemenu": existUsers["users"][uname]["custom_ui_config"]["webguihostnamemenu"],
                "dashboardcolumns": existUsers["users"][uname]["custom_ui_config"]["dashboardcolumns"],
                "authorizedkeys":  pubKey if keyType.lower() == "ssh" else existUsers["users"][uname]["authorized_keys"],
                "ipsecpsk":  pubKey if keyType.lower() == "ipsec" else existUsers["users"][uname]["ipsec_keys"],
                "userid": uid,
                "save": "Save"
            }
            # Make our POST request
            keyPost = http_request(url + "/system_usermanager.php?act=edit&userid=" + uid, keyPostData, {}, {}, 45, "POST")
            # Check that our keys are now updated
            updateExistUsers = get_users(server, user, key)    # Update our user configuration
            if updateExistUsers["ec"] == 0:
                if keyType.lower() == "ssh":
                    keyAdded = 0 if updateExistUsers["users"][uname]["authorized_keys"] == pubKey else keyAdded    # If our input matches our configuration, return 0 (success)
                if keyType.lower() == "ipsec":
                    keyAdded = 0 if updateExistUsers["users"][uname]["ipsec_keys"] == pubKey else keyAdded    # If our input matches our configuration, return 0 (success)
        # If our user does not exist
        else:
            keyAdded = 4    # Return code 4 (user not found)
    # If we could not pull our existing users, return the non-zero return code received from get_users()
    else:
        keyAdded = existUsers["ec"]
    # Return our code
    return keyAdded

# change_user_passwd() changes an existing user's password
def change_user_passwd(server, user, key, uname, passwd):
    # Local variables
    passwdChanged = 2    # Init our return code as 2 (error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existUsers = get_users(server, user, key)    # Pull our existing user configuration
    # Check that we pulled our users successfully
    if existUsers["ec"] == 0:
        # Check if our user exists
        if uname in existUsers["users"]:
            uid = existUsers["users"][uname]["id"]    # Pull our user's pf ID
            # Format our POST request data
            chPassData = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php?act=edit&userid=" + uid, "GET"),
                "act": "edit",
                "passwordfld1": passwd,
                "passwordfld2": passwd,
                "usernamefld": uname,
                "disabled": existUsers["users"][uname]["disabled"],
                "descr": existUsers["users"][uname]["full_name"],
                "expires": existUsers["users"][uname]["expiration"],
                "groups[]":  existUsers["users"][uname]["groups"],
                "utype":  existUsers["users"][uname]["type"],
                "customsettings": existUsers["users"][uname]["custom_ui"],
                "webguicss": existUsers["users"][uname]["custom_ui_config"]["webguicss"],
                "webguifixedmenu": existUsers["users"][uname]["custom_ui_config"]["webguifixedmenu"],
                "interfacessort": "yes" if existUsers["users"][uname]["custom_ui_config"]["interfacessort"] else "",
                "dashboardavailablewidgetspanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["dashboardavailablewidgetspanel"] else "",
                "systemlogsfilterpanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["systemlogsfilterpanel"] else "",
                "systemlogsmanagelogpanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["systemlogsmanagelogpanel"] else "",
                "statusmonitoringsettingspanel": "yes" if existUsers["users"][uname]["custom_ui_config"]["statusmonitoringsettingspanel"] else "",
                "webguileftcolumnhyper": "yes" if existUsers["users"][uname]["custom_ui_config"]["webguileftcolumnhyper"] else "",
                "disablealiaspopupdetail": "yes" if existUsers["users"][uname]["custom_ui_config"]["disablealiaspopupdetail"] else "",
                "pagenamefirst": "yes" if existUsers["users"][uname]["custom_ui_config"]["pagenamefirst"] else "",
                "webguihostnamemenu": existUsers["users"][uname]["custom_ui_config"]["webguihostnamemenu"],
                "dashboardcolumns": existUsers["users"][uname]["custom_ui_config"]["dashboardcolumns"],
                "authorizedkeys":  existUsers["users"][uname]["authorized_keys"],
                "ipsecpsk":  existUsers["users"][uname]["ipsec_keys"],
                "userid": uid,
                "save": "Save"
            }
            # Make our POST request
            chPassPost = http_request(url + "/system_usermanager.php?act=edit&userid=" + uid, chPassData, {}, {}, 45, "POST")
            # Check that we did not encounter errors
            if chPassPost["resp_url"] == url + "/system_usermanager.php":
                passwdChanged = 0    # Assign return code 0 (success)
        # If our user does not exist
        else:
            passwdChanged = 4    # Return code 4 (user not found)
    # If we could not pull our existing users, return the non-zero return code received from get_users()
    else:
        passwdChanged = existUsers["ec"]
    # Return our code
    return passwdChanged

# get_user_groups() pulls information from system_groupmanager.php and formats all data about configured user groups
def get_user_groups(server, user, key):
    # Local variables
    groups = {"ec":2,"groups":{}}    # Initialize a dictionary to populate our user database too
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    groups["ec"] = 10 if check_dns_rebind_error(url) else groups["ec"]    # Return exit code 10 if dns rebind error found
    groups["ec"] = 6 if not validate_platform(url) else groups["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if groups["ec"] == 2:
        groups["ec"] = 3 if not check_auth(server, user, key) else groups["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if groups["ec"] == 2:
        # Check that we had permissions for this page
        getGroupData = http_request(url + "/system_groupmanager.php", {}, {}, {}, 45, "GET")    # Pull our groups data using GET HTTP
        if check_permissions(getGroupData):
            # Check that we have table information
            if "<tbody>" in getGroupData["text"]:
                groupTableBody = getGroupData["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save all data between our tbody HTML tags
                groupTableRows = groupTableBody.split("<tr>")    # Split our tbody into list of table rows
                del groupTableRows[0]    # Remove first item as it contains all the data before our table rows
                # Loop through our rows and gather our data
                for g in groupTableRows:
                    g = g.replace("\t","").replace("\n","")    # Remove whitespace
                    groupName = g.split("<td>")[1].split("</td>")[0]    # Save our group name
                    groupDescr = g.split("<td>")[2].split("</td>")[0]    # Save our group description
                    groupCount = g.split("<td>")[3].split("</td>")[0]    # Save our group member count
                    groupId = g.split("<td>")[4].split("</td>")[0].split("groupid=")[1].split("\">")[0]    # Save our group ID
                    groups["groups"][groupName] = {"name":groupName,"descr":groupDescr,"count":groupCount,"id":groupId}    # Define a nested dict for our current group
                # Return success exit code
                groups["ec"] = 0
        # If we could not access the groups page
        else:
            groups["ec"] = 15    # Assign exit code 15 (permission denied)
    # Return our group dictionary
    return groups

# get_general_setup() pulls information from /system.php (this excludes webConfigurator UI preferences)
def get_general_setup(server, user, key):
    # Local variables
    general = {
        "ec" : 2,
        "general" : {
            "system" : {},
            "dns" : {"servers":{}},
            "localization" : {},
            "webconfigurator" : {}
        },
    }
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    general["ec"] = 10 if check_dns_rebind_error(url) else general["ec"]    # Return exit code 10 if dns rebind error found
    general["ec"] = 6 if not validate_platform(url) else general["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if general["ec"] == 2:
        general["ec"] = 3 if not check_auth(server, user, key) else general["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if general["ec"] == 2:
        # Check that we had permissions for this page
        getGeneralData = http_request(url + "/system.php", {}, {}, {}, 45, "GET")    # Pull our admin data using GET HTTP
        if check_permissions(getGeneralData):
            # Check that we have a SYSTEM table
            if "<h2 class=\"panel-title\">System</h2>" in getGeneralData["text"]:
                # Split our response to get our System table configuration
                systemTable = getGeneralData["text"].split("<h2 class=\"panel-title\">System</h2>")[1].split("<span class=\"help-block\">Do not use '.local'")[0]
                general["general"]["system"]["hostname"] = systemTable.split("name=\"hostname\"")[1].split("value=\"")[1].split("\"")[0] if "name=\"hostname\"" in systemTable else ""    # Get our hostname value
                general["general"]["system"]["domain"] = systemTable.split("name=\"domain\"")[1].split("value=\"")[1].split("\"")[0] if "name=\"domain\"" in systemTable else ""    # Get our domain value
            # Check that we have a DNS table
            if "<h2 class=\"panel-title\">DNS Server Settings</h2>" in getGeneralData["text"]:
                dnsTable = getGeneralData["text"].split("<h2 class=\"panel-title\">DNS Server Settings</h2>")[1].split("<span class=\"help-block\">By default localhost (127.0.0.1)")[0]
                # Check if we have a DNS WAN override option
                if "<input name=\"dnsallowoverride\"" in dnsTable:
                    general["general"]["dns"]["dnsallowoverride"] = True if "checked" in dnsTable.split("<input name=\"dnsallowoverride\"")[1].split("</label>")[0] else False
                # If not, assume default
                else:
                    general["general"]["dns"]["dnsallowoverride"] = False
                 # Check if we have a dns localhost option
                if "<input name=\"dnslocalhost\"" in dnsTable:
                    general["general"]["dns"]["dnslocalhost"] = True if "checked" in dnsTable.split("<input name=\"dnslocalhost\"")[1].split("</label>")[0] else False
                # If not, assume default
                else:
                    general["general"]["dns"]["dnslocalhost"] = False
                # Loop through our configured DNS servers and save there values to our dictionary
                counter = 0    # Assign a counter
                while True:
                    # Check that we have a DNS server configured for this counter value
                    if "name=\"dns" + str(counter) in dnsTable:
                        general["general"]["dns"]["servers"][counter] = {}    # Create a nested dict for our current counter
                        general["general"]["dns"]["servers"][counter]["id"] = str(counter)    # Assign our counter value to the dict
                        general["general"]["dns"]["servers"][counter]["ip"] = dnsTable.split("name=\"dns" + str(counter) + "\"")[1].split("value=\"")[1].split("\"")[0]
                        general["general"]["dns"]["servers"][counter]["hostname"] = dnsTable.split("name=\"dnshost" + str(counter) + "\"")[1].split("value=\"")[1].split("\"")[0] if "name=\"dnshost" + str(counter) + "\"" in dnsTable else ""    # Assign our DNS hostname value if present
                        # Check that we have a gateway selection option
                        if "name=\"dnsgw" + str(counter) + "\"" in dnsTable:
                            # Split our output to a list of gateway options, loop through this list and find the selected value
                            dnsGwTable = dnsTable.split("name=\"dnsgw" + str(counter) + "\"")[1].split("</select>")[0].split("<option value=\"")
                            for gw in dnsGwTable:
                                # Check for selected> keyword
                                if "selected>" in gw:
                                    # Assign our gateway value to our dictionary and break the loop
                                    general["general"]["dns"]["servers"][counter]["gateway"] = gw.split("\"")[0]
                                    break
                                # Assign empty string if no gateway was selected
                                else:
                                    general["general"]["dns"]["servers"][counter]["gateway"] = ""
                        # If we do not have a DNS gateway option
                        else:
                            general["general"]["dns"]["servers"][counter]["gateway"] = ""    # Assign default
                    # Check if our next value exists before exitting the script
                    elif "name=\"dns" + str(counter + 1) in dnsTable:
                        pass    # Do nothing, this will allow us to increase the counter even though this iteration did nothing
                    # If we have made it through all our DNS servers and the next value does not exist
                    else:
                        break   # Break the loop
                    # Increase our counter
                    counter = counter + 1
            # Check that we have a LOCALIZATION table
            if "<h2 class=\"panel-title\">Localization</h2>" in getGeneralData["text"]:
                localTable = getGeneralData["text"].split("<h2 class=\"panel-title\">Localization</h2>")[1].split("<span class=\"help-block\">Choose a language")[0]   # Split HTML into specific section
                # Check if we have a timeserver configuration
                if "name=\"timeservers\"" in localTable:
                    general["general"]["localization"]["timeservers"] = localTable.split("name=\"timeservers\"")[1].split("value=\"")[1].split("\"")[0]    # Save our timeservers
                # Check that we have a timezone configuration
                if "name=\"timezone\"" in localTable:
                    # Loop through our timezones and find our currently selected timezone
                    timeTable = localTable.split("name=\"timezone\"")[1].split("</select>")[0].split("<option value=\"")
                    for tz in timeTable:
                        # Check if this value is selected
                        if "selected>" in tz:
                            general["general"]["localization"]["timezone"] = tz.split("\"")[0]    # Save our timezone
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["localization"]["timezone"] = ""    # Save default timezone
                # Check that we have a language configuration
                if "name=\"language\"" in localTable:
                    # Loop through our languages and find our currently selected language
                    langTable = localTable.split("name=\"language\"")[1].split("</select>")[0].split("<option value=\"")
                    for lg in langTable:
                        # Check if this value is selected
                        if "selected>" in lg:
                            print
                            general["general"]["localization"]["language"] = lg.split("\"")[0]    # Assign our language
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["localization"]["language"] = ""    # Assign default language
                # If we do not have a language value
                else:
                    general["general"]["localization"]["language"] = ""    # Assign default language
            # Check that we have a WEBCONFIGURATOR table
            if "<h2 class=\"panel-title\">webConfigurator</h2>" in getGeneralData["text"]:
                wcTable = getGeneralData["text"].split("<h2 class=\"panel-title\">webConfigurator</h2>")[1].split("<script type=\"text/javascript\">")[0]   # Split HTML into specific section
                # Check if we have a pfSense color scheme configuration
                if "name=\"webguicss\"" in wcTable:
                    # Loop through our color schemes and find our currently selected color scheme
                    wcGuiScheme = wcTable.split("name=\"webguicss\"")[1].split("</select>")[0].split("<option value=\"")
                    for c in wcGuiScheme:
                        # Check if this value is selected
                        if "selected>" in c:
                            general["general"]["webconfigurator"]["webguicss"] = c.split("\"")[0]    # Save our color scheme
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["webconfigurator"]["webguicss"] = ""    # Save default color scheme
                # If we do not have a webguicss value
                else:
                    general["general"]["webconfigurator"]["webguicss"] = ""    # Assign default webguicss
                # Check if we have a UI menu fix preferenece
                if "name=\"webguifixedmenu\"" in wcTable:
                     # Loop through our UI menu fix values and find our currently selected UI menu fix
                    wcGuiFixed = wcTable.split("name=\"webguifixedmenu\"")[1].split("</select>")[0].split("<option value=\"")
                    for f in wcGuiFixed:
                        # Check if this value is selected
                        if "selected>" in f:
                            general["general"]["webconfigurator"]["webguifixedmenu"] = f.split("\"")[0]    # Save our webguifixedmenu
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["webconfigurator"]["webguifixedmenu"] = ""    # Save default webguifixedmenu
                # If we do not have a webguifixedmenu value
                else:
                    general["general"]["webconfigurator"]["webguifixedmenu"] = ""    # Assign default webguifixedmenu
                # Check if we have a webguihostnamemenu value
                if "name=\"webguihostnamemenu\"" in wcTable:
                     # Loop through our webguihostnamemenu and find our currently selected webguihostnamemenu
                    wcGuiHost = wcTable.split("name=\"webguihostnamemenu\"")[1].split("</select>")[0].split("<option value=\"")
                    for h in wcGuiHost:
                        # Check if this value is selected
                        if "selected>" in h:
                            general["general"]["webconfigurator"]["webguihostnamemenu"] = h.split("\"")[0]    # Save our webguihostnamemenu
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["webconfigurator"]["webguihostnamemenu"] = ""    # Save default webguihostnamemenu
                # If we do not have a webguihostnamemenu value
                else:
                    general["general"]["webconfigurator"]["webguihostnamemenu"] = ""    # Assign default webguihostnamemenu
                # Check if we have a logincss value
                if "name=\"logincss\"" in wcTable:
                     # Loop through our logincss and find our currently selected logincss
                    wcLoginColor = wcTable.split("name=\"logincss\"")[1].split("</select>")[0].split("<option value=\"")
                    for lc in wcLoginColor:
                        # Check if this value is selected
                        if "selected>" in lc:
                            general["general"]["webconfigurator"]["logincss"] = lc.split("\"")[0]    # Save our logincss
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["webconfigurator"]["logincss"] = ""    # Save default logincss
                 # If we do not have a logincss value
                else:
                    general["general"]["webconfigurator"]["logincss"] = ""    # Assign default logincss
                # Check if we have a dashboardcolumns option
                if "name=\"dashboardcolumns\"" in wcTable:
                    general["general"]["webconfigurator"]["dashboardcolumns"] = wcTable.split("name=\"dashboardcolumns\"")[1].split("value=\"")[1].split("\"")[0]     # Get our value
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["dashboardcolumns"] = ""
                # Check if we have a dnslocalhost option
                if "<input name=\"interfacessort\"" in wcTable:
                    general["general"]["webconfigurator"]["interfacessort"] = True if "checked" in wcTable.split("<input name=\"interfacessort\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["interfacessort"] = ""
                # Check if we have a dashboardavailablewidgetspanel option
                if "<input name=\"dashboardavailablewidgetspanel\"" in wcTable:
                    general["general"]["webconfigurator"]["dashboardavailablewidgetspanel"] = True if "checked" in wcTable.split("<input name=\"dashboardavailablewidgetspanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["dashboardavailablewidgetspanel"] = ""
                # Check if we have a systemlogsfilterpanel option
                if "<input name=\"systemlogsfilterpanel\"" in wcTable:
                    general["general"]["webconfigurator"]["systemlogsfilterpanel"] = True if "checked" in wcTable.split("<input name=\"systemlogsfilterpanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["systemlogsfilterpanel"] = ""
                # Check if we have a systemlogsmanagelogpanel option
                if "<input name=\"systemlogsmanagelogpanel\"" in wcTable:
                    general["general"]["webconfigurator"]["systemlogsmanagelogpanel"] = True if "checked" in wcTable.split("<input name=\"systemlogsmanagelogpanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["systemlogsmanagelogpanel"] = ""
                # Check if we have a systemlogsmanagelogpanel option
                if "<input name=\"statusmonitoringsettingspanel\"" in wcTable:
                    general["general"]["webconfigurator"]["statusmonitoringsettingspanel"] = True if "checked" in wcTable.split("<input name=\"statusmonitoringsettingspanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["statusmonitoringsettingspanel"] = ""
                # Check if we have a requirestatefilter option
                if "<input name=\"requirestatefilter\"" in wcTable:
                    general["general"]["webconfigurator"]["requirestatefilter"] = True if "checked" in wcTable.split("<input name=\"requirestatefilter\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["requirestatefilter"] = ""
                # Check if we have a webguileftcolumnhyper option
                if "<input name=\"webguileftcolumnhyper\"" in wcTable:
                    general["general"]["webconfigurator"]["webguileftcolumnhyper"] = True if "checked" in wcTable.split("<input name=\"webguileftcolumnhyper\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["webguileftcolumnhyper"] = ""
                # Check if we have a disablealiaspopupdetail option
                if "<input name=\"disablealiaspopupdetail\"" in wcTable:
                    general["general"]["webconfigurator"]["disablealiaspopupdetail"] = True if "checked" in wcTable.split("<input name=\"disablealiaspopupdetail\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["disablealiaspopupdetail"] = ""
                # Check if we have a roworderdragging option
                if "<input name=\"roworderdragging\"" in wcTable:
                    general["general"]["webconfigurator"]["roworderdragging"] = True if "checked" in wcTable.split("<input name=\"roworderdragging\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["roworderdragging"] = ""
                # Check if we have a loginshowhost option
                if "<input name=\"loginshowhost\"" in wcTable:
                    general["general"]["webconfigurator"]["loginshowhost"] = True if "checked" in wcTable.split("<input name=\"loginshowhost\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["loginshowhost"] = ""
                # Check if we have a dashboardperiod option
                if "name=\"dashboardperiod\"" in wcTable:
                    general["general"]["webconfigurator"]["dashboardperiod"] = wcTable.split("name=\"dashboardperiod\"")[1].split("value=\"")[1].split("\"")[0]     # Get our value
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["dashboardperiod"] = ""
            general["ec"] = 0    # Return our success exit code
        # If we did not have permissions
        else:
            general["ec"] = 15    # Assign exit code 15 (permission denied)
    # Return our dictionary
    return general

# get_general_setup_post_data() converts our advanced admin dictionary to a POST data dictionary
def get_general_setup_post_data(dictionary):
    # Local Variables
    postData = {}    # Pre-define our return value as empty dictionary
    # Loop through our existing /system_advanced_admin.php configuration and add the data to the POST request
    for table, data in dictionary.items():
        # Loop through each value in the table dictionaries
        for key, value in data.items():
            value = "yes" if value == True else value  # Swap true values to "yes"
            value = "" if value == False else value  # Swap false values to empty string
            # Check if we are checking our login protection whitelist
            if key == "servers":
                # Add each of our whitelisted IPs to our post data
                for id, info in value.items():
                    dnsId = info["id"]
                    postData["dns" + dnsId] = info["ip"]
                    postData["dnshost" + dnsId] = info["hostname"]
                    postData["dnsgw" + dnsId] = info["gateway"]
            # If we are not adding whitelist values, simply add the key and value
            else:
                postData[key] = value  # Populate our data to our POST data
    # Return our POST data dictionary
    return postData

# set_system_hostname() assigns the hostname and domain value in /system.php
def set_system_hostname(server, user, key, host, domain):
    # Local variables
    setSysHostEc = 2    # Assign our default exit code (unexpected error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existingSysHost = get_general_setup(server, user, key)    # Assign dictionary of existing general setup configuration
    # Check if we got our general setup dictionary successfully
    if existingSysHost["ec"] == 0:
        # FORMAT OUR POST DATA
        sysHostPostData = get_general_setup_post_data(existingSysHost["general"])    # Convert our general data into a POST dictionary
        # Update our CSRF, save value, and take our POST request and save a new GET request that should show our new configuration
        sysHostPostData["__csrf_magic"] = get_csrf_token(url + "/system.php", "GET")
        sysHostPostData["save"] = "Save"
        # Check that we do not want to retain our current value
        if host.upper() != "DEFAULT":
            sysHostPostData["hostname"] = host    # Save our host POST value
        # Check that we do not want to retain our current value
        if domain.upper() != "DEFAULT":
            sysHostPostData["domain"] = domain    # Save our domain value to our POST data
        if setSysHostEc == 2:
            # Loop pulling our updated config, if DNS rebind is detected try switching the pfSense server to the new hostname
            updateCount = 0    # Assign a loop counter
            while True:
                postSysHost = http_request(url + "/system.php", sysHostPostData, {}, {}, 45, "POST")    # Run our POST request
                newSysHost = get_general_setup(server, user, key)    # Pull our updated configuration to check against our post data
                if newSysHost["ec"] == 10:
                    server = sysHostPostData["hostname"] + "." + sysHostPostData["domain"]    # Try to use our new hostname if we experience a DNS rebind
                # If we did not experience a DNS rebind error, break the loop
                else:
                    break
                # If we ran through our loop three times assign a separate exit code
                if updateCount > 3:
                    setSysHostEc = 9    # Assign our could not update exit code
                    break
                updateCount = updateCount + 1    # Increase our counter
            # Format our configuration dictionary back into a POST dictionary
            newSysHostPostData = get_general_setup_post_data(newSysHost["general"])
            sysHostPostData.pop("__csrf_magic", None)    # Remove our previous CSRF token so we can compare only configuration values below
            sysHostPostData.pop("save", None)    # Remove our previous save value so we can compare only configuration values below
            # Check that our values were updated
            if newSysHostPostData == sysHostPostData:
                setSysHostEc = 0    # Assign our success exit code
    # If we could not successfully pull our general setup configuration, return the exit code of that function
    else:
        setSysHostEc = existingSysHost["ec"]
    # Return our exit code
    return setSysHostEc

# get_ha_sync() pulls our current HA configuration from system_hasync.php
def get_ha_sync(server, user, key):
    # Local variables
    haSync = {"ec": 2, "ha_sync" : {}}    # Pre-define our data dictionary
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    haSync["ec"] = 10 if check_dns_rebind_error(url) else haSync["ec"]    # Return exit code 10 if dns rebind error found
    haSync["ec"] = 6 if not validate_platform(url) else haSync["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if haSync["ec"] == 2:
        haSync["ec"] = 3 if not check_auth(server, user, key) else haSync["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if haSync["ec"] == 2:
        # Check that we had permissions for this page
        getHaSyncData = http_request(url + "/system_hasync.php", {}, {}, {}, 45, "GET")    # Pull our admin data using GET HTTP
        if check_permissions(getHaSyncData):
            # Create a list of all CHECKBOX INPUTS to gather values from
            checkBoxValues = [
                "pfsyncenabled","synchronizeusers","synchronizeauthservers","synchronizecerts","synchronizerules","synchronizeschedules",
                "synchronizealiases","synchronizenat","synchronizeipsec","synchronizeopenvpn","synchronizedhcpd",
                "synchronizewol","synchronizestaticroutes","synchronizelb","synchronizevirtualip","synchronizetrafficshaper",
                "synchronizetrafficshaperlimiter","synchronizednsforwarder","synchronizecaptiveportal"
            ]
            # Loop through our checkbox inputs and save their values
            for cb in checkBoxValues:
                # Check that we have our expected input tag
                expectedTag = "<input name=\""+cb+"\""
                if expectedTag in getHaSyncData["text"]:
                    haSync["ha_sync"][cb] = "on" if "checked=\"checked\"" in getHaSyncData["text"].split(expectedTag)[1].split("</label>")[0] else ""    # Save "yes" if check box is checked, otherwise empty string
                # If we did not find this input tag in our HTML response
                else:
                    haSync["ha_sync"][cb] = ""    # Assume default
            # Create a list of all TEXT INPUTS to gather values from
            textValues = ["pfsyncpeerip","synchronizetoip","username"]
            # Loop through our checkbox inputs and save their values
            for txt in textValues:
                haSync["ha_sync"][txt] = ""    # Assume default
                # Check that we have our expected input tag
                expectedTag = "id=\""+txt+"\" type=\"text\""
                if expectedTag in getHaSyncData["text"]:
                    # Check that we have a value
                    if "value=\"" in getHaSyncData["text"].split(expectedTag)[1].split(">")[0]:
                        haSync["ha_sync"][txt] = getHaSyncData["text"].split(expectedTag)[1].split(">")[0].split("value=\"")[1].split("\"")[0]   # Save our text input's value
            # Check our SELECT INPUTS to gather selected values
            expectedTag = "<select class=\"form-control\" name=\"pfsyncinterface\" id=\"pfsyncinterface\">"
            if expectedTag in getHaSyncData["text"]:
                selectData = getHaSyncData["text"].split(expectedTag)[1].split("</select>")[0]    # Capture data between our select tags
                selectOptions = selectData.split("<option")    # Split our select data into list of option tags
                # Loop through our options and find our selected value
                for opt in selectOptions:
                    # Check if selected keyword is found
                    if "selected>" in opt:
                        haSync["ha_sync"]["pfsyncinterface"] = opt.split("value=\"")[1].split("\"")[0]    # Save our selected option value
                        break    # Break our loop as we only expect one value
                    # Otherwise assume default
                    else:
                        haSync["ha_sync"]["pfsyncinterface"] = ""    # Assign default
            # If we did not found our expected select tag, assume default
            else:
                haSync["ha_sync"]["pfsyncinterface"] = ""    # Assign default
            # Assign success exit code
            haSync["ec"] = 0    # Assign exit code 0 (success)
        # If we did not have permission to the necessary pages
        else:
            haSync["ec"] = 15    # ASsign exit code 15 (permission denied)
    # Return our HA sync dictionary
    return haSync

# setup_hasync() configures HA availability syncing from System > HA Sync.
def setup_hasync(server, user, key, enablePfsync, pfsyncIf, pfsyncIp, xmlsyncIP, xmlsyncUname, xmlsyncPass, xmlsyncOptions):
    # Local variables
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)  # Assign our base URL
    hasyncSetup = 2    # Initialize our return code as 2 (error)
    hasyncConf = get_ha_sync(server, user, key)    # Pull our existing HA sync config
    # Check that we could pull our existing config
    if hasyncConf["ec"] == 0:
        # Format our POST data dictionary
        hasyncPostData = {
            "__csrf_magic": get_csrf_token(url + "/system_hasync.php","GET"),
            "pfsyncenabled": enablePfsync.lower() if enablePfsync.lower() in ["on",""] else hasyncConf["ha_sync"]["pfsyncenabled"],
            "pfsyncinterface": pfsyncIf if pfsyncIf.lower() != "default" else hasyncConf["ha_sync"]["pfsyncinterface"],
            "pfsyncpeerip": pfsyncIp if pfsyncIp.lower() != "default" else hasyncConf["ha_sync"]["pfsyncpeerip"],
            "synchronizetoip": xmlsyncIP if xmlsyncIP.lower() != "default" else hasyncConf["ha_sync"]["synchronizetoip"],
            "username": xmlsyncUname if xmlsyncUname.lower() != "default" else hasyncConf["ha_sync"]["username"],
            "passwordfld": xmlsyncPass if xmlsyncPass.lower() != "default" else None,
            "passwordfld_confirm": xmlsyncPass if xmlsyncPass.lower() != "default" else None,
            "synchronizeusers": xmlsyncOptions["synchronizeusers"] if xmlsyncOptions["synchronizeusers"].lower() != "default" else hasyncConf["ha_sync"]["synchronizeusers"],
            "synchronizeauthservers": xmlsyncOptions["synchronizeauthservers"] if xmlsyncOptions["synchronizeauthservers"].lower() != "default" else hasyncConf["ha_sync"]["synchronizeauthservers"],
            "synchronizecerts": xmlsyncOptions["synchronizecerts"] if xmlsyncOptions["synchronizecerts"].lower() != "default" else hasyncConf["ha_sync"]["synchronizecerts"],
            "synchronizerules": xmlsyncOptions["synchronizerules"] if xmlsyncOptions["synchronizerules"].lower() != "default" else hasyncConf["ha_sync"]["synchronizerules"],
            "synchronizeschedules": xmlsyncOptions["synchronizeschedules"] if xmlsyncOptions["synchronizeschedules"].lower() != "default" else hasyncConf["ha_sync"]["synchronizeschedules"],
            "synchronizealiases": xmlsyncOptions["synchronizealiases"] if xmlsyncOptions["synchronizealiases"].lower() != "default" else hasyncConf["ha_sync"]["synchronizealiases"],
            "synchronizenat": xmlsyncOptions["synchronizenat"] if xmlsyncOptions["synchronizenat"].lower() != "default" else hasyncConf["ha_sync"]["synchronizenat"],
            "synchronizeopenvpn": xmlsyncOptions["synchronizeopenvpn"] if xmlsyncOptions["synchronizeopenvpn"].lower() != "default" else hasyncConf["ha_sync"]["synchronizeopenvpn"],
            "synchronizedhcpd": xmlsyncOptions["synchronizedhcpd"] if xmlsyncOptions["synchronizedhcpd"].lower() != "default" else hasyncConf["ha_sync"]["synchronizedhcpd"],
            "synchronizewol": xmlsyncOptions["synchronizewol"] if xmlsyncOptions["synchronizewol"].lower() != "default" else hasyncConf["ha_sync"]["synchronizewol"],
            "synchronizeipsec": xmlsyncOptions["synchronizeipsec"] if xmlsyncOptions["synchronizeipsec"].lower() != "default" else hasyncConf["ha_sync"]["synchronizeipsec"],
            "synchronizestaticroutes": xmlsyncOptions["synchronizestaticroutes"] if xmlsyncOptions["synchronizestaticroutes"].lower() != "default" else hasyncConf["ha_sync"]["synchronizestaticroutes"],
            "synchronizelb": xmlsyncOptions["synchronizelb"] if xmlsyncOptions["synchronizelb"].lower() != "default" else hasyncConf["ha_sync"]["synchronizelb"],
            "synchronizevirtualip": xmlsyncOptions["synchronizevirtualip"] if xmlsyncOptions["synchronizevirtualip"].lower() != "default" else hasyncConf["ha_sync"]["synchronizevirtualip"],
            "synchronizetrafficshaper": xmlsyncOptions["synchronizetrafficshaper"] if xmlsyncOptions["synchronizetrafficshaper"].lower() != "default" else hasyncConf["ha_sync"]["synchronizetrafficshaper"],
            "synchronizetrafficshaperlimiter": xmlsyncOptions["synchronizetrafficshaperlimiter"] if xmlsyncOptions["synchronizetrafficshaperlimiter"].lower() != "default" else hasyncConf["ha_sync"]["synchronizetrafficshaperlimiter"],
            "synchronizednsforwarder": xmlsyncOptions["synchronizednsforwarder"] if xmlsyncOptions["synchronizednsforwarder"].lower() != "default" else hasyncConf["ha_sync"]["synchronizednsforwarder"],
            "synchronizecaptiveportal": xmlsyncOptions["synchronizecaptiveportal"] if xmlsyncOptions["synchronizecaptiveportal"].lower() != "default" else hasyncConf["ha_sync"]["synchronizecaptiveportal"],
            "save": "Save"
        }
        # Make our POST request, then check if our changes were applied
        postHasyncConf = http_request(url + "/system_hasync.php", hasyncPostData, {}, {}, 45, "POST")
        del hasyncPostData["__csrf_magic"],hasyncPostData["save"],hasyncPostData["passwordfld"],hasyncPostData["passwordfld_confirm"]    # Delete unneeded dict keys
        updateHasyncConf = get_ha_sync(server, user, key)    # Repull our existing config
        hasyncSetup = 0 if updateHasyncConf["ha_sync"] == hasyncPostData else hasyncSetup    # Return exit code 0 if our configurations match
    # If we could not pull our existing config, return the code returned by get_hasync()
    else:
        hasyncSetup = hasyncConf["ec"]
    # Return our return code
    return hasyncSetup

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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    advAdm["ec"] = 10 if check_dns_rebind_error(url) else advAdm["ec"]    # Return exit code 10 if dns rebind error found
    advAdm["ec"] = 6 if not validate_platform(url) else advAdm["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if advAdm["ec"] == 2:
        advAdm["ec"] = 3 if not check_auth(server, user, key) else advAdm["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if advAdm["ec"] == 2:
        # Check that we had permissions for this page
        getAdvAdmData = http_request(url + "/system_advanced_admin.php", {}, {}, {}, 45, "GET")    # Pull our admin data using GET HTTP
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
                advAdm["adv_admin"]["webconfigurator"]["nodnsrebindcheck"] = True if "nodnsrebindcheck" in wcAdmTableBody and "checked=\"checked\"" in wcAdmTableBody.split("id=\"nodnsrebindcheck\"")[1].split("</label>")[0] else False    # Check if DNS rebind checking is enabled
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

# setup_wc() configures webConfigurator settings found in /system_advanced_admin.php
def setup_wc(server, user, key, maxProc, redirect, hsts, autoComplete, loginMsg, lockout, dnsRebind, altHost, httpRef, tabText):
    # Local Variables
    wcConfigured = 2    # Pre-define our exit code as 2
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existingAdvAdm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    wcPostKeys = ["max_procs", "webgui-redirect", "webgui-hsts",
                  "ocsp-staple", "loginautocomplete", "webgui-login-messages", "noantilockout",
                  "nodnsrebindcheck", "althostnames", "nohttpreferercheck", "pagenamefirst"]
    # Check if we got our advanced admin dictionary successfully
    if existingAdvAdm["ec"] == 0:
        # FORMAT OUR POST DATA
        wcPostData = get_system_advanced_admin_post_data(existingAdvAdm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
        wcPostData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        # Check that we do not want to retain our current current value
        if maxProc.upper() != "DEFAULT":
            wcPostData["max_procs"] = maxProc     # Assign our max processes value
        # Check that we do not want to retain our current current value
        if redirect.upper() != "DEFAULT":
            wcPostData["webgui-redirect"] = "yes" if redirect in ["disable","no-redirect"] else ""     # Assign our redirect value
        # Check that we do not want to retain our current current value
        if hsts.upper() != "DEFAULT":
            wcPostData["webgui-hsts"] = "yes" if hsts in ["disable","no-hsts"] else ""     # Assign our hsts value
        # Check that we do not want to retain our current current value
        if autoComplete.upper() != "DEFAULT":
            wcPostData["loginautocomplete"] = "yes" if autoComplete in ["enable", "autocomplete"] else ""     # Assign our autoComplete value
        # Check that we do not want to retain our current current value
        if loginMsg.upper() != "DEFAULT":
            wcPostData["webgui-login-messages"] = "yes" if loginMsg in ["disable", "no-loginmsg"] else ""     # Assign our webgui-login-messages value
        # Check that we do not want to retain our current current value
        if lockout.upper() != "DEFAULT":
            wcPostData["noantilockout"] = "yes" if lockout in ["disable", "no-antilockout"] else ""     # Assign our noantilockout value
        # Check that we do not want to retain our current current value
        if dnsRebind.upper() != "DEFAULT":
            wcPostData["nodnsrebindcheck"] = "yes" if dnsRebind in ["disable", "no-dnsrebind"] else ""     # Assign our nodnsrebindcheck value
        # Check that we do not want to retain our current current value
        if altHost.upper() != "DEFAULT":
            wcPostData["althostnames"] = altHost     # Assign our althostnames value
        # Check that we do not want to retain our current current value
        if httpRef.upper() != "DEFAULT":
            wcPostData["nohttpreferercheck"] = "yes" if httpRef in ["disable", "no-httpreferer"] else ""     # Assign our nohttpreferercheck value
        # Check that we do not want to retain our current current value
        if tabText.upper() != "DEFAULT":
            wcPostData["pagenamefirst"] = "yes" if tabText in ["enable", "display-tabtext"] else ""     # Assign our pagenamefirst value
        # Check that we did not encounter an error
        if wcConfigured == 2:
            # Use POST HTTP to save our new values
            postWcConfig = http_request(url + "/system_advanced_admin.php", wcPostData, {'Cache-Control': 'no-cache'}, {}, 45, "POST")    # POST our data
            # Give pfSense time to restart webconfigurator and read our updated configuration to ensure changes were applied
            time.sleep(2)
            updateAdvAdmData = get_system_advanced_admin(server, user, key)    # Update our raw configuration dictionary
            newExistingAdvAdm = get_system_advanced_admin_post_data(updateAdvAdmData["adv_admin"])    # Get our dictionary of configured advanced options
            # Check that we successfully updated our dictionary
            if updateAdvAdmData["ec"] == 0:
                # Loop through our POST variables and ensure they match
                for d in wcPostKeys:
                    if newExistingAdvAdm[d] != wcPostData[d]:
                        print(d)
                        wcConfigured = 2    # Revert to exit code 2 (unexpected error
                        break
                    else:
                        wcConfigured = 0    # Assign our success exit code
    # If we could not successfully pull our advanced admin configuration, return the exit code of that function
    else:
        wcConfigured = existingAdvAdm["ec"]
        # Return our exit code
    return wcConfigured

# set_wc_port() configures webConfigurator port and protocol settings found in /system_advanced_admin.php
def set_wc_port(server, user, key, protocol, port):
    # Local Variables
    global wcProtocol    # Allow our wcProtocol variable to be updated globally
    global wcProtocolPort    # Allow our wcProtocolPort variable to be updated globally
    wcPortConfigured = 2    # Pre-define our exit code as 2
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existingAdvAdm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    # Check if we got our advanced admin dictionary successfully
    if existingAdvAdm["ec"] == 0:
        # FORMAT OUR POST DATA
        wcPostData = get_system_advanced_admin_post_data(existingAdvAdm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
        wcPostData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        # Check that we do not want to retain our current current value
        if protocol.upper() != "DEFAULT" and protocol.upper() != "":
            # Assign our new protocol value if the value is valid
            wcPostData["webguiproto"] = protocol if protocol in ["http","https"] else wcPostData["webguiproto"]
            wcProtocol = protocol    # Update our global wcProtocol used by the script
        # Check that we do not want to retain our current current value
        if port.upper() != "DEFAULT" and port.upper() != "":
            # Assign our new port value
            wcPostData["webguiport"] = port
            wcProtocolPort = port    # Update our global wcProtocolPort used by the script
        # POST our request
        wcPortPost = http_request(url + "/system_advanced_admin.php", wcPostData, {}, {}, 45, "POST")
        time.sleep(2)    # Give our webConfigurator a couple seconds to restart
        # Loop for up to 10 second and check that our port opens
        counter = 0    # Define a loop counter
        while True:
            # Break the loop if we have waited over 10 seconds
            if counter > 10:
                break
            # Check if our port is open, break the loop if so
            if check_auth(server, user, key):
                wcPortConfigured = 0    # Return our success exit code
                break
            else:
                wcPortConfigured = 8   # Return exit code 8 (port did not bind)
            time.sleep(1)    # Wait one second before running again
            counter = counter + 1    # Increase our counter
    # Return our value
    return wcPortConfigured

# setup_ssh() configures sshd settings found in /system_advanced_admin.php
def setup_ssh(server, user, key, enable, port, auth, forwarding):
    # Local Variables
    sshConfigured = 2    # Pre-define our exit code as 2
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
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
            postSshConfig = http_request(url + "/system_advanced_admin.php", sshPostData, {}, {}, 45, "POST")    # POST our data
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

# setup_console_options() configures password protection of the console menu
def setup_console(server, user, key, consolePass):
    # Local Variables
    consoleConfigured = 2    # Pre-define our exit code as 2
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    existingAdvAdm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    # Check if we got our advanced admin dictionary successfully
    if existingAdvAdm["ec"] == 0:
        # FORMAT OUR POST DATA
        consolePostData = get_system_advanced_admin_post_data(existingAdvAdm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our POST data
        consolePostData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        consolePostData["disableconsolemenu"] = "yes" if consolePass.upper() in ["ENABLE", "YES"] else ""    # If user wants to password protect console, assign value of yes
        if consoleConfigured == 2:
            # Use POST HTTP to save our new values
            postConsoleConfig = http_request(url + "/system_advanced_admin.php", consolePostData, {}, {}, 45, "POST")    # POST our data
            # Check that our values were updated, assign exit codes accordingly
            updateAdvAdmData = get_system_advanced_admin(server, user, key)    # Update our raw configuration dictionary
            newExistingAdvAdm = get_system_advanced_admin_post_data(updateAdvAdmData["adv_admin"])    # Get our dictionary of configured advanced options
            # Check that we successfully updated our dictionary
            if updateAdvAdmData == 0:
                if newExistingAdvAdm["disableconsolemenu"] != consolePostData["disableconsolemenu"]:
                    consoleConfigured = 2    # Revert to exit code 2 (unexpected error)
                else:
                    consoleConfigured = 0    # Assign our success exit code
            # If we could not update our configuration dictionary
            else:
                consoleConfigured = updateAdvAdmData["ec"]
    # If we could not successfully pull our advanced admin configuration, return the exit code of that function
    else:
        consoleConfigured = existingAdvAdm["ec"]
    # Return our exit code
    return consoleConfigured

# get_packages() reads installed packages from pfSense's UI repos
def get_installed_packages(server, user, key):
    # Local variables
    installedPkgs = {"ec": 2, "installed_pkgs": {}}    # Init our return dictionary that tracks exit codes and packages
    expOutput = "pfSense-pkg"    # Define the string to check for when looking for pfSense packages
    pkgShellOut = get_shell_output(server, user, key, "pkg info | grep " + expOutput)    # Run our shell cmd to return installed pkgs
    # Check that our command ran successfully
    if pkgShellOut["ec"] == 0:
        # Check that we have expected output
        if expOutput + "-" in pkgShellOut["shell_output"]:
            pkgStr = pkgShellOut["shell_output"] + "\n"    # Add a new line so we always have a list when splitting
            pkgList = pkgStr.split("\n")    # Split our string into a list on every new line
            for p in pkgList:
                if expOutput + "-" in p:
                    p = ' '.join(p.split(" "))    # Replace multiple spaces with one space
                    fullPkg = p.split(" ")[0]    # Save our entire pkg name
                    pkgParse = fullPkg.replace("pfSense-pkg-", "").split("-")
                    pkgName = "-".join(pkgParse[:-1])  # Everything but our last entry is the pkg name
                    pkgVer = pkgParse[-1:][0]  # The last entry is our pkg version
                    installedPkgs["installed_pkgs"][pkgName] = {}    # Create our single pkg dict
                    installedPkgs["installed_pkgs"][pkgName]["pkg"] = fullPkg
                    installedPkgs["installed_pkgs"][pkgName]["name"] = pkgName
                    installedPkgs["installed_pkgs"][pkgName]["version"] = pkgVer
            # Return our success exit code
            installedPkgs["ec"] = 0
    # If we encountered an error running our shell cmd, return the code returned by get_shell_output()
    else:
        installedPkgs["ec"] = pkgShellOut["ec"]
    # Return our dictionary
    return installedPkgs

# get_available_packages() pulls a list of packages that are able to be installed on pfSense
def get_available_packages(server, user, key):
    # Local variables
    availPkgs = {"ec": 2, "available_pkgs": {}}    # Initialize our dictionary to track error codes and available packages
    expOutput = "pfSense-pkg"    # Define the string to check for when looking for pfSense packages
    getAvailPackages = get_shell_output(server, user, key, "pkg search -q " + expOutput)    # Get our available packages
    getInstalledPackages = get_installed_packages(server, user, key)    # Get our  installed packages
    # Check that we received our available pkg output
    if getAvailPackages["ec"] == 0:
        # Check that we received our installed pkg output
        if getInstalledPackages["ec"] == 0:
            # Check that we have expected output
            if expOutput + "-" in getAvailPackages["shell_output"]:
                pkgStr = getAvailPackages["shell_output"] + "\n"    # Add a new line so we always have a list when splitting
                pkgList = pkgStr.split("\n")    # Split our string into a list on every new line
                for p in pkgList:
                    if expOutput + "-" in p:
                        fullPkg = p    # Save our entire pkg name
                        pkgParse = fullPkg.replace("pfSense-pkg-","").split("-")
                        pkgName = "-".join(pkgParse[:-1])    # Everything but our last entry is the pkg name
                        pkgVer = pkgParse[-1:][0]   # The last entry is our pkg version
                        availPkgs["available_pkgs"][pkgName] = {}    # Create our single pkg dict
                        availPkgs["available_pkgs"][pkgName]["pkg"] = fullPkg
                        availPkgs["available_pkgs"][pkgName]["name"] = pkgName
                        availPkgs["available_pkgs"][pkgName]["version"] = pkgVer
                        availPkgs["available_pkgs"][pkgName]["installed"] = True if pkgName in getInstalledPackages["installed_pkgs"] else False    # Check if package is installed already
                # Return our success exit code
                availPkgs["ec"] = 0
        # If we received an error pulling our installed packages
        else:
            availPkgs["ec"] = getAvailPackages["ec"]
    # If we received an error pulling our available packages
    else:
        availPkgs["ec"] = getAvailPackages["ec"]
    # Return our exit code
    return availPkgs

# add_package() adds a new pfSense package
def add_package(server, user, key, pkg):
    # Local variables
    pkgAdded = 2    # Assign an integer to track various errors that may be encountered
    availPkgs = get_available_packages(server, user, key)    # Pull our dictionary of available packages
    # Check that we did not encounter an error pulling our available packages
    if availPkgs["ec"] == 0:
        # Check that our package is in our available packages
        if pkg in availPkgs["available_pkgs"]:
            # Check that our package is not already installed
            if not availPkgs["available_pkgs"][pkg]["installed"]:
                # Install our package, check that it was installed successfully
                addPkg = get_shell_output(server, user, key, "pkg install -y pfSense-pkg-" + pkg)
                if addPkg["ec"] == 0:
                    installedPkgs = get_installed_packages(server, user, key)    # Update our installed pkg dictionary
                    if pkg in installedPkgs["installed_pkgs"]:
                        pkgAdded = 0    # Return exit code 0 (success)
            # If our package is already installed, returne exit code 5 (pkg already installed)
            else:
                pkgAdded = 5
        # If our package is not an available package, return exit code 4 (pkg not found)
        else:
            pkgAdded = 4
    # If we could not pull our available packages, return code returned by get_available_packages()
    else:
        pkgAdded = availPkgs["ec"]
    # Return our code
    return pkgAdded

# del_package() deletes an existing pfSense package
def del_package(server, user, key, pkg):
    # Local variables
    pkgDel = 2    # Assign an integer to track various errors that may be encountered
    installedPkgs = get_installed_packages(server, user, key)    # Pull our dictionary of installed packages
    # Check that we did not encounter an error pulling our available packages
    if installedPkgs["ec"] == 0:
        # Check that our package is in our installed packages
        if pkg in installedPkgs["installed_pkgs"]:
            # Install our package, check that it was installed successfully
            deletePkg = get_shell_output(server, user, key, "pkg remove -y pfSense-pkg-" + pkg)
            if deletePkg["ec"] == 0:
                installedPkgs = get_installed_packages(server, user, key)    # Update our installed pkg dictionary
                if pkg not in installedPkgs["installed_pkgs"]:
                    pkgDel = 0    # Return exit code 0 (success)
        # If our package is not an available package, return exit code 4 (pkg not found)
        else:
            pkgDel = 4
    # If we could not pull our available packages, return code returned by get_installed_pkgs()
    else:
        pkgDel = installedPkgs["ec"]
    # Return our code
    return pkgDel

# get_shell_output() executes a shell command in diag_command.php and returns it's output
def get_shell_output(server, user, key, cmd):
    # Local variables
    shellOut = {"ec": 2, "shell_output" : ""}    # Create a dictionary to track our return code and our shell cmd output
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our initial request and check for errors
    shellOut["ec"] = 10 if check_dns_rebind_error(url) else shellOut["ec"]    # Return exit code 10 if dns rebind error found
    shellOut["ec"] = 6 if not validate_platform(url) else shellOut["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if shellOut["ec"] == 2:
        shellOut["ec"] = 3 if not check_auth(server, user, key) else shellOut["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if shellOut["ec"] == 2:
        # Check that we had permissions for this page
        getShellData = http_request(url + "/diag_arp.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(getShellData):
            # Create our POST data dictionary and run our POST request
            shellCmdPostData = {"__csrf_magic": get_csrf_token(url + "/diag_command.php", "GET"), "txtCommand": cmd, "submit": "EXEC"}
            shellCmdPost = http_request(url + "/diag_command.php", shellCmdPostData, {}, {}, 90, "POST")
            # Check that our output <pre> tags exist
            if "<pre>" in shellCmdPost["text"]:
                shellOut["shell_output"] = shellCmdPost["text"].split("<pre>")[1].split("</pre>")[0]    # Update our shell output value
                shellOut["ec"] = 0    # Return exit code 0 (success)
        # If we did not have permission, return exit code 15 (permission denied)
        else:
            shellOut["ec"] = 15
    # Return our data dictionary
    return shellOut

# get_arp_table() pulls our pfSense's current ARP table
def get_arp_table(server, user, key):
    arpTable = {"ec" : 2, "arp" : {}}    # Pre-define our function dictionary
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our initial request and check for errors
    arpTable["ec"] = 10 if check_dns_rebind_error(url) else arpTable["ec"]    # Return exit code 10 if dns rebind error found
    arpTable["ec"] = 6 if not validate_platform(url) else arpTable["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if arpTable["ec"] == 2:
        arpTable["ec"] = 3 if not check_auth(server, user, key) else arpTable["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if arpTable["ec"] == 2:
        # Check that we had permissions for this page
        getArpData = http_request(url + "/diag_arp.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
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

# get_xml_backup() saves pfSense's XML backup given specific parameters
def get_xml_backup(server, user, key, area, noPkg, noRrd, encrypt, encryptPass):
    xmlTable = {"ec" : 2}    # Pre-define our function dictionary
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    xmlTable["ec"] = 10 if check_dns_rebind_error(url) else xmlTable["ec"]    # Return exit code 10 if dns rebind error found
    xmlTable["ec"] = 6 if not validate_platform(url) else xmlTable["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if xmlTable["ec"] == 2:
        xmlTable["ec"] = 3 if not check_auth(server, user, key) else xmlTable["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if xmlTable["ec"] == 2:
        # Check that we had permissions for this page
        getXmlData = http_request(url + "/diag_backup.php", {}, {}, {}, 45, "GET")    # Pull our XML download page using GET HTTP
        if check_permissions(getXmlData):
            # Populate our POST data dictionary
            getXmlPostData = {
                "__csrf_magic": get_csrf_token(url + "/diag_backup.php", "GET"),
                "backuparea" : area,
                "nopackages" : "yes" if noPkg == True else "",
                "donotbackuprrd" : "yes" if noRrd == True else "",
                "encrypt" : "yes" if encrypt == True else "",
                "encrypt_password" : encryptPass if encrypt == True else "",
                "download" : "Download configuration as XML",
                "restorearea" : "",
                "decrypt_password" : ""
            }
            # Make our POST request
            postXmlReq = http_request(url + "/diag_backup.php", getXmlPostData, {}, {}, 45, "POST")
            xmlTable["xml"] = postXmlReq["text"]    # Save our XML backup to our return dict
            # Check our POST requests response code
            if postXmlReq["resp_code"] == 200:
                xmlTable["ec"] = 0    # Return exit code 0 (success)
        # If we did not pass our permissions check
        else:
            xmlTable["ec"] = 15    # Assign exit code 15 (permissions denied)
    # Return our dictionary
    return xmlTable

# upload_xml_backup() uploads and restores an existing XML backup configuration
def upload_xml_backup(server, user, key, area, confFile, decryptPass):
    # Local Variables
    xmlAdded = 2  # Assign our default return code. (2 means generic failure)
    decryptEnable = "yes" if decryptPass != "" else ""    # Determine our decrypt POST value based on user submitting password
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)  # Assign our base URL
    # Submit our intitial request and check for errors
    xmlAdded = 10 if check_dns_rebind_error(url) else xmlAdded    # Return exit code 10 if dns rebind error found
    xmlAdded = 6 if not validate_platform(url) else xmlAdded    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if xmlAdded == 2:
        xmlAdded = 3 if not check_auth(server, user, key) else xmlAdded   # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if xmlAdded == 2:
        # Check that we had permissions for this page
        getXmlData = http_request(url + "/diag_backup.php", {}, {}, {}, 45, "GET")    # Pull our XML download page using GET HTTP
        if check_permissions(getXmlData):
            # Assign our POST data dictionary
            restoreXmlPostData = {"__csrf_magic": get_csrf_token(url + "/diag_backup.php", "GET"), "restorearea": area, "decrypt": decryptEnable, "decrypt_password": decryptPass, "restore": "Restore Configuration"}
            # Make our HTTP POST
            restoreXmlPost = http_request(url + "/diag_backup.php", restoreXmlPostData, {}, confFile, 45, "POST")
            # Check if our backup was successfully restored
            successStr = "The configuration area has been restored. The firewall may need to be rebooted."
            if successStr in restoreXmlPost["text"]:
                xmlAdded = 0    # Return our success exit code
        # If we did not have permission to the backup_restore page
        else:
            xmlAdded = 15    # Assign exit code 15 if we did not have permission (permission denied)
    # Return our return code
    return xmlAdded

# replicate_xml() copies the XML configuration from one pfSense box to another
def replicate_xml(server, user, key, area, targetList):
    # Local variables
    replicateDict = {"ec" : 2, "targets" : {}}     # Initialize certManagerDict to return our certificate values and exit codes
    masterConfig = get_xml_backup(server, user, key, "", False, False, True, currentDate)    # Get our XML configuration and save it to a variable
    # Check that our master config was pulled successfully before continuing
    if masterConfig["ec"] == 0:
        # Loop through our target list and start to replicate configuration
        counter = 0    # Set a counter to track loop iteration
        for tg in targetList:
            xmlObj = io.StringIO(masterConfig["xml"])
            masterConfigBinary = {"conffile": xmlObj}   # Convert our string to a encoded obj and save it to our POST dictionary
            replicateDict["targets"][counter] = {}    # Create a target dictionary entry
            targetUpload = upload_xml_backup(tg, user, key, area, masterConfigBinary, currentDate)    # Run our function and capture the exit code
            xmlObj.close()    # Close our object now that it is no longer needed
            replicateDict["targets"][counter]["host"] = tg    # Save our target hostname/IP to dictionary
            replicateDict["targets"][counter]["ec"] = targetUpload    # Save our function exit code to dictionary
            replicateDict["targets"][counter]["replicated"] = True if targetUpload == 0 else False    # Assign a bool value stating whether replication was successful
            counter = counter + 1   # Increase our counter
        # Return success exit code as we have populated our dictionary
        replicateDict["ec"] = 0
    # If we could not pull the master configuration
    else:
        replicateDict["ec"] = masterConfig["ec"]    # Save exit code from the failed function
    # Return our dictionary
    return replicateDict

# get_system_tunables() pulls the System Tunable values from the advanced settings
def get_system_tunables(server, user, key):
    tunables = {"ec" : 2, "tunables" : {}}    # Pre-define our function dictionary
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    tunables["ec"] = 10 if check_dns_rebind_error(url) else tunables["ec"]    # Return exit code 10 if dns rebind error found
    tunables["ec"] = 6 if not validate_platform(url) else tunables["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if tunables["ec"] == 2:
        tunables["ec"] = 3 if not check_auth(server, user, key) else tunables["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if tunables["ec"] == 2:
        # Check that we had permissions for this page
        getTunableData = http_request(url + "/system_advanced_sysctl.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
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
            getExistingIfaces = http_request(url + "/system_advanced_sysctl.php?act=edit", {}, {}, {}, 45, "GET")    # Get our HTTP response
            # Check that we had permissions for this page
            if check_permissions(getExistingIfaces):
                tunablePostData["__csrf_magic"] = get_csrf_token(url + "/system_advanced_sysctl.php?act=edit", "GET")    # Update our CSRF token
                postTunable = http_request(url + "/system_advanced_sysctl.php?act=edit", tunablePostData, {}, {}, 45, "POST")    # POST our data
                applyTunableData = {"__csrf_magic" : get_csrf_token(url + "/system_advanced_sysctl.php", "GET"), "apply" : "Apply Changes"}    # Assign our post data to apply changes
                applyTunable = http_request(url + "/system_advanced_sysctl.php", applyTunableData, {}, {}, 45, "POST")    # POST our data
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

# get_interfaces() pulls existing interface configurations from interfaces_assign.php and interfaces.php
def get_interfaces(server, user, key):
# Local Variables
    ifaces = {"ec" : 2, "ifaces" : {}, "if_add" : []}    # Predefine our dictionary that will track our VLAN data as well as errors
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    ifaces["ec"] = 10 if check_dns_rebind_error(url) else ifaces["ec"]    # Return exit code 10 if dns rebind error found
    ifaces["ec"] = 6 if not validate_platform(url) else ifaces["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ifaces["ec"] == 2:
        ifaces["ec"] = 3 if not check_auth(server, user, key) else ifaces["ec"]    # Return exit code 3 if we could not sign in
    # Check if we did not encountered any errors thus far, continue if not
    if ifaces["ec"] == 2:
        getIfData = http_request(url + "/interfaces_assign.php", {}, {}, {}, 45, "GET")    # Pull our interface data using GET HTTP
        # Check that we have a table body to pull from
        if "<tbody>" in getIfData["text"]:
            # Target only HTML data between our tbody tags
            ifTableBody = getIfData["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save data between tbody tags
            # Determine interfaces that are available but unused
            if "<select name=\"if_add\"" in ifTableBody:
                ifAddList = ifTableBody.split("<select name=\"if_add\"")[1].split("</select>")[0].split("<option value=\"")    # Split our response into a list of options
                # Loop through our options and add available interfaces
                for ifAddOpt in ifAddList:
                    ifaces["if_add"].append(ifAddOpt.split("\"")[0])    # Add our option to the list
                # Check that we have data
                if len(ifaces["if_add"]) > 0:
                    del ifaces["if_add"][0]    # Delete the first value as it is not needed
            # Check that we have interface data
            if "<td><a href=\"/interfaces.php?if" in ifTableBody:
                tableBodyIfList = ifTableBody.split("<td><a href=\"/interfaces.php?if=")    # Split our tbody into a list of ifaces
                del tableBodyIfList[0]    # Discard the first value in the last as it saves data listed before our target data
                pfIfList = []    # Define an empty list to populate our interface names too
                # Loop through the ifaces and pull the interface name as it's known to pfSense
                for i in tableBodyIfList:
                    i = i.split("\"")[0]
                    pfIfList.append(i)
                # Request each specific interfaces configuration
                for pfId in pfIfList:
                    ifaces["ifaces"][pfId] = {"pf_id" : pfId}    # Initialize a nested dictionary for each interface
                    # Locate our physical interface ID
                    ifIdSelect = ifTableBody.split("<td><a href=\"/interfaces.php?if=" + pfId + "\">")[1].split("</select>")[0]    # Target our interface ID options
                    ifIdOptions = ifIdSelect.split("<option value=\"")    # Split our options into a list
                    # Loop through our interface IDs to find the selected value
                    for idOpt in ifIdOptions:
                        # Check if value is selected
                        if "selected" in idOpt.split(">")[0]:
                            ifaces["ifaces"][pfId]["id"] = idOpt.split("\"")[0]    # Save our interface ID
                            break
                        # If it is not selected, assume default
                        else:
                            ifaces["ifaces"][pfId]["id"] = ""    # Assign default value
                    # SAVE OUR INTERFACE.PHP HTML INPUT NAMES TO LISTS TO LOOP THROUGH
                    # Text inputs
                    valueInputs = [
                        "descr","spoofmac","mtu","mss","ipaddr","dhcphostname","alias-address","dhcprejectfrom",
                        "adv_dhcp_pt_timeout","adv_dhcp_pt_retry","adv_dhcp_pt_select_timeout","adv_dhcp_pt_reboot",
                        "adv_dhcp_pt_backoff_cutoff","adv_dhcp_pt_initial_interval","adv_dhcp_config_file_override_path",
                        "adv_dhcp_send_options","adv_dhcp_request_options","adv_dhcp_required_options","adv_dhcp_option_modifiers",
                        "ipaddrv6","adv_dhcp6_interface_statement_send_options","adv_dhcp6_interface_statement_request_options",
                        "adv_dhcp6_interface_statement_script","adv_dhcp6_id_assoc_statement_address_id","adv_dhcp6_id_assoc_statement_address",
                        "adv_dhcp6_id_assoc_statement_address_pltime","adv_dhcp6_id_assoc_statement_address_vltime",
                        "adv_dhcp6_id_assoc_statement_prefix_id","adv_dhcp6_id_assoc_statement_prefix","adv_dhcp6_id_assoc_statement_prefix_pltime",
                        "adv_dhcp6_id_assoc_statement_prefix_vltime","adv_dhcp6_prefix_interface_statement_sla_id","adv_dhcp6_prefix_interface_statement_sla_len",
                        "adv_dhcp6_authentication_statement_authname","adv_dhcp6_authentication_statement_protocol","adv_dhcp6_authentication_statement_algorithm",
                        "adv_dhcp6_authentication_statement_rdm","adv_dhcp6_key_info_statement_keyname","adv_dhcp6_key_info_statement_realm",
                        "adv_dhcp6_key_info_statement_keyid","adv_dhcp6_key_info_statement_secret","adv_dhcp6_key_info_statement_expire",
                        "adv_dhcp6_config_file_override_path"
                    ]
                    # Checkbox inputs
                    toggleInputs = [
                        "enable","blockpriv","blockbogons","adv_dhcp_config_advanced","adv_dhcp_config_file_override",
                        "ipv6usev4iface","adv_dhcp6_config_advanced","adv_dhcp6_config_file_override","dhcp6usev4iface",
                        "dhcp6prefixonly","dhcp6-ia-pd-send-hint","dhcp6debug","dhcp6withoutra","dhcp6norelease",
                        "adv_dhcp6_interface_statement_information_only_enable","adv_dhcp6_id_assoc_statement_address_enable",
                        "adv_dhcp6_id_assoc_statement_prefix_enable",
                    ]
                    # Select inputs
                    selectInputs = [
                        "type","type6","mediaopt","subnet","gateway","alias-subnet","subnetv6","gatewayv6","dhcp6-ia-pd-len",
                        "adv_dhcp6_prefix_selected_interface"
                    ]
                    getIfConfig = http_request(url + "/interfaces.php?if=" + pfId, {}, {}, {}, 45, "GET")["text"]    # Get our HTML response
                    # LOOP AND SAVE OUR TOGGLE/CHKBOX INPUTS
                    for chk in toggleInputs:
                        # Check if our interface is enabled
                        if "name=\"" + chk + "\"" in getIfConfig:
                            ifaces["ifaces"][pfId][chk] = True if "checked=\"checked\"" in getIfConfig.split("name=\"" + chk + "\"")[1].split("</label>")[0] else False
                        # Assign default to false
                        else:
                            ifaces["ifaces"][pfId][chk] = False
                    # LOOP AND SAVE OUR VALUE INPUTS
                    for ipts in valueInputs:
                        # Check if we have a value for our input
                        inputTag = getIfConfig.split("name=\"" + ipts + "\"")[1].split(">")[0]
                        if "name=\"" + ipts + "\"" in getIfConfig and "value=\"" in inputTag:
                            ifaces["ifaces"][pfId][ipts] = getIfConfig.split("name=\"" + ipts + "\"")[1].split(">")[0].split("value=\"")[1].split("\"")[0]     # Get our value
                        # If we do not have this option, assign empty string
                        else:
                            ifaces["ifaces"][pfId][ipts] = ""    # Assign default as empty string
                    # LOOP AND SAVE OUR SELECTION INPUTS
                    for sct in selectInputs:
                        # If the selection exists
                        if "name=\"" + sct + "\"" in getIfConfig:
                             # Loop through our option list and find our currently selected value
                            optionList = getIfConfig.split("name=\"" + sct + "\"")[1].split("</select>")[0].split("<option value=\"")
                            for opt in optionList:
                                # Check if this value is selected
                                if "selected>" in opt:
                                    ifaces["ifaces"][pfId][sct] = opt.split("\"")[0]    # Save our value
                                    break    # Break the loop as we have found our value
                                else:
                                    ifaces["ifaces"][pfId][sct] = ""    # Save default value
                    # Set success exit code
                    ifaces["ec"] = 0
        # If we could not parse input
        else:
            ifaces["ec"] = 9    # Assign could not parse exit code
    # Return our data dictionary
    return ifaces

# find_interface_pfid() will search the interface dictionary and return the physical if ID, the pf ID or the descriptive ID of a interface given a value
def find_interface_pfid(server, user, key, id, dct):
    # Local variables
    pfId = {"ec": 2, "pf_id": ""}    # Initialize our return dictionary
    dct = get_interfaces(server, user, key) if dct in [None, {}] else dct    # Allow user to pass in dictionary, otherwise pull it
    # Check that our dictionary was populated successfully
    if dct["ec"] == 0:
        # Loop through our interface dict and see if our values match
        for key,value in dct["ifaces"].items():
            # Check if our id matches the entries in this key
            if id in [value["pf_id"],value["id"]] or id.lower() == value["descr"].lower():
                pfId["pf_id"] = value["pf_id"]    # save our key value as the pf_id
                pfId["ec"] = 0    # Update our return code to 0 (success)
                break    # Break our loop as we only need one value
    # If we did not pull our dictionary successfully, pass the return code listed in the dictionary
    else:
        pfId["ec"] = dct["ec"]
    # Return our dictiontary
    return pfId

# get_vlan_ids() pulls existing VLAN configurations from Interfaces > Assignments > VLANs
def get_vlan_ids(server, user, key):
    # Local Variables
    vlans = {"ec" : 2, "vlans" : {}}    # Predefine our dictionary that will track our VLAN data as well as errors
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
    # Submit our intitial request and check for errors
    vlans["ec"] = 10 if check_dns_rebind_error(url) else vlans["ec"]    # Return exit code 10 if dns rebind error found
    vlans["ec"] = 6 if not validate_platform(url) else vlans["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if vlans["ec"] == 2:
        vlans["ec"] = 3 if not check_auth(server, user, key) else vlans["ec"]    # Return exit code 3 if we could not sign in
    # Check if we did not encountered any errors thus far, continue if not
    if vlans["ec"] == 2:
        getVlanData = http_request(url + "/interfaces_vlan.php", {}, {}, {}, 45, "GET")    # Pull our VLAN data using GET HTTP
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
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
            getExistingIfaces = http_request(url + "/interfaces_vlan_edit.php", {}, {}, {}, 45, "GET")    # Get our HTTP response
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
                            vlanPostReq = http_request(url + "/interfaces_vlan_edit.php", vlanPostData, {}, {}, 45, "POST")
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
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
        addAuthPermissions = http_request(url + "/system_authservers.php?act=new", {}, {}, {}, "GET")
        if check_permissions(addAuthPermissions):
            # Update our CSRF token and submit our POST request
            addAuthServerData["__csrf_magic"] = get_csrf_token(url + "/system_authservers.php?act=new", 45, "GET")
            addAuthServer = http_request(url + "/system_authservers.php?act=new", addAuthServerData, {}, {}, 45, "POST")
            ldapAdded = 0
        # If we did not have permissions to the page
        else:
            ldapAdded = 15    # Return exit code 15 (permission denied)
    # Return our exit code
    return ldapAdded

def get_dns_entries(server, user, key):
    # Local variables
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Assign our base URL
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
        getDnsResp = http_request(url + "/services_unbound.php", {}, {}, {}, 45, "GET")
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
                        # Check what domain the alias is tied to
                        if aliasFqdn.endswith(prevDomain):
                            aliasDomain = prevDomain
                            aliasHost = aliasFqdn.replace("." + aliasDomain, "").replace(aliasDomain, "")
                        # If we found our aliases parent domain and host
                        if aliasHost is not None and aliasDomain is not None:
                            dnsDict["domains"][aliasDomain][aliasHost]["alias"][host] = {"hostname" : host, "domain" : domain, "descr" : descr}
                    # Otherwise add our item normally
                    else:
                        dnsDict["domains"][domain] = {} if not domain in dnsDict["domains"] else dnsDict["domains"][domain]
                        dnsDict["domains"][domain][host] = {"hostname" : host, "domain" : domain, "ip" : ip, "descr" : descr, "id" : id, "alias" : {}}
                        prevDomain = domain    # Keep track of our previous domain
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
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
            dnsReadPermissions = http_request(url + "/services_unbound.php", {}, {}, {}, 45, "GET")
            dnsAddPermissions = http_request(url + "/services_unbound_host_edit.php", {}, {}, {}, 45, "GET")
            if check_permissions(dnsAddPermissions) and check_permissions(dnsReadPermissions):
                # Update our CSRF token and add our DNS entry
                dnsData["__csrf_magic"] = get_csrf_token(url + "/services_unbound_host_edit.php", "GET")
                dnsCheck = http_request(url + "/services_unbound_host_edit.php", dnsData, {}, {}, 45, "POST")
                # Update our CSRF token and save changes
                saveDnsData["__csrf_magic"] = get_csrf_token(url + "/services_unbound.php", "GET")
                saveCheck = http_request(url + "/services_unbound.php", saveDnsData, {}, {}, 45, "POST")
                # Check if a record is now present
                if check_dns(server, user, key, host, domain):
                    recordAdded = 0    # Set return variable 0 (0 means successfully added)
            # If we did not have permissions to the page
            else:
                recordAdded = 15    # Return exit code 15 (permission denied)
    # If a DNS record already exists
    else:
        recordAdded = 9    # Set return value to 9 (9 means record already existed when function started)
    # Return exit code
    return recordAdded

# get_ssl_certs() pulls the list of existing certificates on a pfSense host. This function basically returns the data found on /system_certmanager.php
def get_ssl_certs(server, user, key):
    # Local Variables
    certManagerDict = {"ec" : 2, "certs" : {}}     # Initialize certManagerDict to return our certificate values and exit codes
    certIndex = 0    # Initialize certIndex to track the certificate number in the list/loop
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
    # Submit our intitial request and check for errors
    certManagerDict["ec"] = 10 if check_dns_rebind_error(url) else certManagerDict["ec"]    # Return exit code 10 if dns rebind error found
    certManagerDict["ec"] = 6 if not validate_platform(url) else certManagerDict["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if certManagerDict["ec"] == 2:
        certManagerDict["ec"] = 3 if not check_auth(server, user, key) else certManagerDict["ec"]    # Return exit code 3 if we could not sign in
    if certManagerDict["ec"] == 2:
        # Check that we had permissions for this page
        getCertData = http_request(url + "/system_certmanager.php", {}, {}, {}, 45, "GET")
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
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
        permissionCheck = http_request(url + "/system_certmanager.php?act=new", {}, {}, {}, 45, "GET")
        if check_permissions(permissionCheck):
            # Add SSL cert and check for the added cert afterwards
            addCertData["__csrf_magic"] = get_csrf_token(url + "/system_certmanager.php?act=new", "GET")
            postCheck = http_request(url + "/system_certmanager.php?act=new", addCertData, {}, {}, 45, "POST")
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
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
        getSysAdvAdm = http_request(url + "/system_advanced_admin.php", {}, {}, {}, 45, "GET")
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
                    postSysAdvAdm = http_request(url + "/system_advanced_admin.php", wccData, {}, {}, 45, "POST")
                    checkSysAdvAdm = http_request(url + "/system_advanced_admin.php", {}, {}, {}, 45, "GET")["text"]
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

# get_firewall_rules() pulls the ACL for a specified interface and returns the rules
def get_firewall_rules(server, user, key, iface):
    # Local variables
    rules = {"ec" : 2, "rules" : {"antilockout": False, "bogons": False, "private": False, "user_rules": {}}}    # Pre-define our dictionary to track alias values and errors
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    rules["ec"] = 10 if check_dns_rebind_error(url) else rules["ec"]    # Return exit code 10 if dns rebind error found
    rules["ec"] = 6 if not validate_platform(url) else rules["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if rules["ec"] == 2:
        rules["ec"] = 3 if not check_auth(server, user, key) else rules["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if rules["ec"] == 2:
        ifaces = get_interfaces(server, user, key)    # Get a dictionary of our configured interfaces
        iface = find_interface_pfid(server, user, key, iface, ifaces)["pf_id"]    # Save our interfaces pfID
        rules["rules"]["acl_interface"] = iface    # Save what interface this ACL is for
        # Check if our interface is valid (not empty string)
        if iface != "":
            # Check that we had permissions for this page
            getRuleIds = http_request(url + "/firewall_rules.php?if=" + iface, {}, {}, {}, 45, "GET")    # Save our GET HTTP response
            getRuleEdit = http_request(url + "/firewall_rules_edit.php", {}, {}, {}, 45, "GET")  # Save our GET HTTP response
            if check_permissions(getRuleIds) and check_permissions(getRuleEdit):
                # GATHER PFSENSE RULE IDs & FW STATE DATA/STATISTICS
                # Loop through possible system rules and check if our rules list contains the system rules
                systemRules = ["antilockout","private","bogons"]
                for r in systemRules:
                    if "<tr id=\"" + r + "\">" in getRuleIds["text"]:
                        rules["rules"][r] = True    # Change default false value to True
                # Check if we have user defined rules, if so capture only the table between the <tbody> tags
                if "<tbody class=\"user-entries\">" in getRuleIds["text"]:
                    usrRuleBody = getRuleIds["text"].split("<tbody class=\"user-entries\">")[1].split("</tbody>\n\t\t\t</table>")[0]
                    # Check that our user table has table rows, if so split the string into a list of rows
                    if "<tr" in usrRuleBody:
                        userRuleRows = usrRuleBody.split("<tr")
                        # Loop through our rows and pull the rule ID from each row
                        for row in userRuleRows:
                            # Check that our ID field exists
                            if "ondblclick=\"document.location='firewall_rules_edit.php?id=" in row:
                                id = row.split("ondblclick=\"document.location='firewall_rules_edit.php?id=")[1].split("\'")[0]    # The value before our first `"` char is our ID
                                # Check if our ID is a number
                                if id.isdigit():
                                    # Create a nested dictionary for each user rule
                                    rules["rules"]["user_rules"][id] = {
                                        "id": id,
                                        "state_data": {
                                            "state_rule_id": "",
                                            "state_tracking_id": "",
                                            "state_evaluations": "",
                                            "state_bytes": "",
                                            "state_packets": "",
                                            "state_states": "",
                                            "state_creations": ""
                                        }
                                    }
                                    # Check if a custom gateway was used for this rule, otherwise assume default
                                    if "<i class=\"fa fa-cog\" title=\"advanced setting: gateway" in row:
                                        rules["rules"]["user_rules"][id]["gateway"] = row.split("<i class=\"fa fa-cog\" title=\"advanced setting: gateway")[1].split("\">")[0].replace(" ","")
                                    else:
                                        rules["rules"]["user_rules"][id]["gateway"] = ""
                                    # Check for a state table ID for this rule, save it to our dict if exists and is a number
                                    if "<td><a href=\"diag_dump_states.php?ruleid=" in row:
                                        stateId = row.split("<td><a href=\"diag_dump_states.php?ruleid=")[1].split("\"")[0]
                                        rules["rules"]["user_rules"][id]["state_data"]["state_rule_id"] = stateId if stateId.isdigit() else ""
                                        # Loop through our state data to gather state statistics and information
                                        stateData = ["Tracking ID","evaluations", "packets", "bytes", "states", "state creations"]     # Create list of data fields to capture
                                        tableDataContent = "<br>" + row.split("data-content=\"")[1].split("\"")[0] + "<br>" if "data-content=\"" in row else ""    # Capture the entire data content if found
                                        for sd in stateData:
                                            # Check that the field exists for this data
                                            if "<br>" + sd + ":" in tableDataContent:
                                                sdValue = tableDataContent.split("<br>" + sd + ":")[1].split("<br>")[0].replace(" ", "")     # Capture the data for each field between the <br> tags
                                                rules["rules"]["user_rules"][id]["state_data"]["state_" + sd.replace("state ", "").replace(" ", "_").lower()] = sdValue    # Save our captured value into the corresponding dict key
                # GATHER INDIVIDUAL FIREWALL RULE CONFIGURATION
                # Loop through each of our user rule IDs to gather data
                for urId,urDict in rules["rules"]["user_rules"].items():
                    # GET the edit page for this ID and read it's contents
                    urGetData = http_request(url + "/firewall_rules_edit.php?id=" + urId, {}, {}, {}, 45, "GET")
                    ### SINGLE SELECT FORMS: Get the values for each of our single option <select> forms ###
                    sSelectForms = ["type","interface","ipprotocol","proto","icmptype[]","srctype","srcbeginport","srcendport","srcmask","dsttype",
                                   "dstbeginport","dstendport","dstmask","os","dscp","statetype","vlanprio","vlanprioset","sched",
                                   "dnpipe","pdnpipe","ackqueue","defaultqueue"]
                    # Loop through each of our expected single select form names and get there configured values
                    for ssf in sSelectForms:
                        # Default each of these values to blank string if it does not exist already
                        if ssf not in rules["rules"]["user_rules"][urId]:
                            rules["rules"]["user_rules"][urId][ssf] = ""
                        expTag1 = "<select class=\"form-control\" name=\"" + ssf + "\" id=\"" + ssf + "\">"    # Define the tag we expect to find
                        expTag2 = "<select class=\"form-control pfIpMask\" name=\"" + ssf + "\" id=\"" + ssf + "\">"
                        expTag3 = "<select class=\"form-control\" name=\"" + ssf + "\" id=\"" + ssf + "\" multiple=\"multiple\">"
                        # Check that this form exists
                        if expTag1 in urGetData["text"]:
                            selectData = urGetData["text"].split(expTag1)[1].split("</select>")[0]    # Capture all data between our select tags
                            # Check that we have options
                            if "<option" in selectData:
                                optList = selectData.split("<option")    # Split our options into a list
                                # Loop through our options to find the selected value
                                for opt in optList:
                                    if "selected>" in opt:
                                        rules["rules"]["user_rules"][urId][ssf] = opt.split("value=\"")[1].split("\"")[0]
                        # Check that an alternate select form exists with this name
                        elif expTag2 in urGetData["text"]:
                            selectData = urGetData["text"].split(expTag2)[1].split("</select>")[0]    # Capture all data between our select tags
                            # Check that we have options
                            if "<option" in selectData:
                                optList = selectData.split("<option")    # Split our options into a list
                                # Loop through our options to find the selected value
                                for opt in optList:
                                    if "selected>" in opt:
                                        rules["rules"]["user_rules"][urId][ssf] = opt.split("value=\"")[1].split("\"")[0]
                        # Check that an alternate select form exists with this name
                        elif expTag3 in urGetData["text"]:
                            selectData = urGetData["text"].split(expTag3)[1].split("</select>")[0]    # Capture all data between our select tags
                            rules["rules"]["user_rules"][urId][ssf] = []    # Define a list with our multi data listing
                            # Check that we have options
                            if "<option" in selectData:
                                optList = selectData.split("<option")    # Split our options into a list
                                # Loop through our options to find the selected value
                                for opt in optList:
                                    if "selected>" in opt:
                                        rules["rules"]["user_rules"][urId][ssf].append(opt.split("value=\"")[1].split("\"")[0])
                    ### CHECKBOX FORMS: Get the values for each of our yes/no checkbox input forms ###
                    cbxForms = ["disabled","srcnot","dstnot","log","allowopts","disablereplyto","nopfsync","nosync"
                                "tcpflags1_syn","tcpflags1_rst","tcpflags1_psh","tcpflags1_ack","tcpflags1_urg",
                                "tcpflags1_ece","tcpflags1_cwr","tcpflags2_syn","tcpflags2_rst","tcpflags2_psh",
                                "tcpflags2_ack","tcpflags2_urg","tcpflags2_ece","tcpflags2_cwr","tcpflags_any"]
                    # Loop through each checkbox form and check it's value
                    for cb in cbxForms:
                        rules["rules"]["user_rules"][urId][cb] = ""    # Assign a default for each value
                        expTag1 = "name=\"" + cb + "\""    # Define our expected tag
                        expTag2 = "name=\'" + cb + "\'"    # Define our other expected tag
                        # Check if the value exists
                        if expTag1 in urGetData["text"]:
                            cbxData = urGetData["text"].split(expTag1)[1].split(">")[0]     # Capture our input form data
                            if "checked" in cbxData:
                                rules["rules"]["user_rules"][urId][cb] = cbxData.split("value=\"")[1].split("\"")[0]    # Assign value if the box is checked
                        elif expTag2 in urGetData["text"]:
                            cbxData = urGetData["text"].split(expTag2)[1].split(">")[0]     # Capture our input form data
                            if "checked" in cbxData:
                                rules["rules"]["user_rules"][urId][cb] = cbxData.split("value=\'")[1].split("\'")[0]    # Assign value if the box is checked
                    ### TEXT FORMS: Get the values for each of our text input forms ###
                    txtForms = ["descr","tag","tagged","src","srcbeginport_cust","srcendport_cust","dst","dstbeginport_cust", "dstendport_cust"]
                    # Loop through each text form and check it's value
                    for txt in txtForms:
                        rules["rules"]["user_rules"][urId][txt] = ""    # Assign a default for each value
                        expTag = "<input class=\"form-control\" name=\"" + txt + "\""    # Define our expected tag
                        # Check if the value exists
                        if expTag in urGetData["text"]:
                            txtData = urGetData["text"].split(expTag)[1].split(">")[0]     # Capture our input form data
                            if "value=\"" in txtData:
                                rules["rules"]["user_rules"][urId][txt] = txtData.split("value=\"")[1].split("\"")[0]    # Save value of the input field
                    ### NUMBER FORMS: Get the values for each of our number input forms ###
                    numForms = ["max","max-src-nodes","max-src-conn","max-src-states","max-src-conn-rate","max-src-conn-rates","statetimeout"]
                    # Loop through each text form and check it's value
                    for num in numForms:
                        rules["rules"]["user_rules"][urId][num] = ""    # Assign a default for each value
                        expTag = "id=\"" + num + "\" type=\"number\""    # Define our expected tag
                        # Check if the value exists
                        if expTag in urGetData["text"]:
                            numData = urGetData["text"].split(expTag)[1].split(">")[0]     # Capture our input form data
                            if "value=\"" in numData:
                                rules["rules"]["user_rules"][urId][num] = numData.split("value=\"")[1].split("\"")[0]    # Save value of the input field
                    # Add our SOURCE and DEST nets if the interface network is used as src or dst
                    srcValue = rules["rules"]["user_rules"][urId]["src"]    # Save our source value for quick use later
                    dstValue = rules["rules"]["user_rules"][urId]["dst"]    # Save our destination value for quick use later
                    rules["rules"]["user_rules"][urId]["src_net"] = ""    # Default our src net value
                    rules["rules"]["user_rules"][urId]["dst_net"] = ""    # Default our dst net value
                    # SRC NET
                    if srcValue in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["src_net"] = ifaces["ifaces"][srcValue]["ipaddr"] + "/" + ifaces["ifaces"][srcValue]["subnet"]
                    elif srcValue.rstrip("ip") in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["src_net"] = ifaces["ifaces"][srcValue.rstrip("ip")]["ipaddr"]
                    # DST NET
                    if dstValue in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["dst_net"] = ifaces["ifaces"][dstValue]["ipaddr"] + "/" + ifaces["ifaces"][dstValue]["subnet"]
                    elif dstValue.rstrip("ip") in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["dst_net"] = ifaces["ifaces"][dstValue.rstrip("ip")]["ipaddr"]
                    # Assign our success exit code
                    rules["ec"] = 0
            # If permission was denied, return exit code (permission denied)
            else:
                rules["ec"] = 15
        # If our interface was invalid return exit code 4 (iface not found)
        else:
            rules["ec"] = 4
    # Return our dictionary
    return rules

# add_firewall_rule() adds a new basic firewall rule to a specified interface
def add_firewall_rule(server, user, key, iface, type, ipver, proto, ivSrc, src, srcBit, srcPort, ivDst, dst, dstBit, dstPort, gw, descr, log, pos, noPort):
    # Local variables
    ruleAdded = 2    # Init our return value as 2 (error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
    currentRules = get_firewall_rules(server, user, key, iface)    # Pull our existing firewall rules for this interface
    # Check that we were able to pull our rules successfully
    if currentRules["ec"] == 0:
        # Check our port value
        srcPortCheck = validate_port_range(srcPort)    # Check if our src port is valid and capture the start and end port
        dstPortCheck = validate_port_range(dstPort)    # Check if our dst port is valid and capture the start and end port
        if srcPortCheck["valid"] or noPort == True:
            if dstPortCheck["valid"] or noPort == True:
                # Format our POST data dictionary
                rulePostData = {
                    "__csrf_magic": get_csrf_token(url + "/firewall_rules_edit.php","GET"),
                    "interface": currentRules["rules"]["acl_interface"],
                    "after": "-1" if pos.lower() == "top" else None,
                    "type": type,
                    "ipprotocol": ipver,
                    "proto": proto,
                    "srcnot": "yes" if ivSrc == True else "",
                    "srctype": "network",
                    "src": src,
                    "srcmask": srcBit,
                    "srcbeginport_cust": str(srcPortCheck["start"]),
                    "srcendport_cust": str(srcPortCheck["end"]),
                    "dstnot": "yes" if ivDst == True else "",
                    "dsttype": "network",
                    "dst": dst,
                    "dstmask": dstBit,
                    "dstbeginport_cust": str(dstPortCheck["start"]) if not noPort else "",
                    "dstendport_cust": str(dstPortCheck["end"]) if not noPort else "",
                    "gateway": gw,
                    "descr": descr,
                    "log": "yes" if log == True else "",
                    "save": "Save"
                }
                ruleSaveData = {"apply": "Apply Changes", "__csrf_magic": get_csrf_token(url + "/firewall_rules.php", "GET")}
                # Run our POST request to add the new rule and apply our changes
                postRule = http_request(url + "/firewall_rules_edit.php", rulePostData, {}, {}, 45, "POST")
                savePostRule = http_request(url + "/firewall_rules.php", ruleSaveData, {}, {}, 45, "POST")
                updateRules = get_firewall_rules(server, user, key, iface)    # Pull our updated firewall rules for this interface
                # Check that we updated our dictionary
                if updateRules["ec"] == 0:
                    ruleKey = list(updateRules["rules"]["user_rules"].keys())[0] if pos == "top" else list(updateRules["rules"]["user_rules"].keys())[-1]    # Determnine the rule's ACL position
                    valuesList = ["type","src","dst","proto","descr","log"]    # Create a list of values to verify
                    valueMatch = False
                    # Loop through each value to check and ensure it is the same
                    for v in valuesList:
                        valueMatch = False    # Assign a bool to track when our values match
                        if rulePostData[v] == updateRules["rules"]["user_rules"][ruleKey][v]:
                            valueMatch = True
                        else:
                            break
                    if valueMatch:
                        ruleAdded = 0    # Assign exit code 0 (success)
            # If our dest port or port range is invalid
            else:
                ruleAdded = 5    # Return exit code 5 (invalid dest port)
        # If our source port or port range is invalid
        else:
            ruleAdded = 4    # Return exit code 4 (invalid source port)
    # If we were not able to pull our current firewall rules, return the exit code of get_firewall_rules()
    else:
        ruleAdded = currentRules["ec"]
    # Return our exit code
    return ruleAdded

# del_firewall_rule() removes a firewall rule entry from a specified interface's ACL
def del_firewall_rule(server, user, key, iface, ruleId):
    # Local variables
    ruleDel = 2    # Init our return value as 2 (error)
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
    currentRules = get_firewall_rules(server, user, key, iface)    # Get our current firewall ACL
    # Check that we pulled our ACL without error
    if currentRules["ec"] == 0:
        # Check if our rule ID is in the current ACL
        if ruleId in currentRules["rules"]["user_rules"]:
            # Format our POST dictionaries
            delRulePostData = {
                "__csrf_magic": get_csrf_token(url + "/firewall_rules.php?if=" + currentRules["rules"]["acl_interface"], "GET"),
                "act": "del",
                "if": currentRules["rules"]["acl_interface"],
                "id": ruleId
            }
            ruleSaveData = {"apply": "Apply Changes", "__csrf_magic": get_csrf_token(url + "/firewall_rules.php", "GET")}
            # Make our POST requests
            delRulePost = http_request(url + "/firewall_rules.php", delRulePostData, {}, {}, 45, "POST")
            savePost = http_request(url + "/firewall_rules.php", ruleSaveData, {}, {}, 45, "POST")
            updateRules = get_firewall_rules(server, user, key, iface)  # Update our ACL dict
            # Check that our rule was deleted
            if ruleId in updateRules["rules"]["user_rules"]:
                if currentRules["rules"]["user_rules"][ruleId] != updateRules["rules"]["user_rules"][ruleId]:
                    ruleDel = 0    # Return our success exit code
            else:
                ruleDel = 0    # Return our success exit code
        # If our rule ID was not found
        else:
            ruleDel = 5    # Return exit code 4 (rule not found)
    # If we encountered an error pulling our current rules, return error returned by get_firewall_rules()
    else:
        ruleDel = currentRules["ec"]
    # Return our exit code
    return ruleDel

# get_firewall_aliases() pulls aliases information from pfSense and saves it to a Python dictionary
def get_firewall_aliases(server, user, key):
    # Local variables
    aliases = {"ec" : 2, "aliases" : {}}    # Pre-define our dictionary to track alias values and errors
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    aliases["ec"] = 10 if check_dns_rebind_error(url) else aliases["ec"]    # Return exit code 10 if dns rebind error found
    aliases["ec"] = 6 if not validate_platform(url) else aliases["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if aliases["ec"] == 2:
        aliases["ec"] = 3 if not check_auth(server, user, key) else aliases["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if aliases["ec"] == 2:
        # Check that we had permissions for this page
        getAliasIds = http_request(url + "/firewall_aliases.php?tab=all", {}, {}, {}, 45, "GET")    # Save our GET HTTP response
        getAliasEdit = http_request(url + "/firewall_aliases_edit.php", {}, {}, {}, 45, "GET")  # Save our GET HTTP response
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
                getAliasIdInfo = http_request(url + "/firewall_aliases_edit.php?id=" + i, {}, {}, {}, 45, "GET")    # Save our GET HTTP response
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
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
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
                postPfAliasData = http_request(url + "/firewall_aliases_edit.php", {}, {}, {}, 45, "GET")
                if check_permissions(postPfAliasData):
                    # Submit our post requests
                    postPfAliasData = http_request(url + "/firewall_aliases_edit.php", aliasPostData, {}, {}, 45, "POST")
                    saveChangesPostData = {"__csrf_magic" : get_csrf_token(wcProtocol + "://" + server + "/firewall_aliases.php", "GET"), "apply" : "Apply Changes"}
                    saveChanges = http_request(url + "/firewall_aliases.php", saveChangesPostData, {}, {}, 45, "POST")
                    aliasModded = 0    # Assign our success exit code
                # If we did not have permissions to the page
                else:
                    aliasModded = 15    # Return exit code 15 (permission denied)
        # If our alias name was not found
        else:
            aliasModded = 4    # Return exit code 4 (alias not found)
    # Return our integer exit code
    return aliasModded

# get_virtual_ips() reads the configured virtual IPs from firwall_virtual_ip.php
def get_virtual_ips(server, user, key):
    # Local variables
    virtIps = {"ec" : 2, "virtual_ips" : {}}    # Pre-define our dictionary to track alias values and errors
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    virtIps["ec"] = 10 if check_dns_rebind_error(url) else virtIps["ec"]    # Return exit code 10 if dns rebind error found
    virtIps["ec"] = 6 if not validate_platform(url) else virtIps["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if virtIps["ec"] == 2:
        virtIps["ec"] = 3 if not check_auth(server, user, key) else virtIps["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if virtIps["ec"] == 2:
        # Check that we had permissions for this page
        getVirtIpIds = http_request(url + "/firewall_virtual_ip.php", {}, {}, {}, 45, "GET")    # Save our GET HTTP response
        getVirtIpEdit = http_request(url + "/firewall_virtual_ip_edit.php", {}, {}, {}, 45, "GET")  # Save our GET HTTP response
        if check_permissions(getVirtIpIds) and check_permissions(getVirtIpEdit):
            # Parse our HTML output to capture the ID of each virtual IP
            if "<tbody>" in getVirtIpIds["text"]:
                # Return our success exit code
                virtIps["ec"] = 0
                virtIpIdTableBody = getVirtIpIds["text"].split("<tbody>")[1].split("</tbody>")[0]    # Capture all data between our tbody tags
                virtualIpIdTableRows = virtIpIdTableBody.split("<tr>")[1:]    # Split our table body into list of rows indicated by the tr tag (remove first entry)
                # Loop through each of our rows and pull the virtual IPs ID
                for r in virtualIpIdTableRows:
                    rowData = r.split("<td>")    # Split our row into the individual table data values
                    virtIpId = rowData[5].split("firewall_virtual_ip_edit.php?id=")[1].split("\">")[0]    # Split our data value to capture the virtual IP ID
                    virtIpDescrName = rowData[1].replace("\n","").replace("\t","").replace("</td>","")    # Capture our virtual IPs descriptive name and remove unneeded chars
                    virtIps["virtual_ips"][virtIpId] = {"id":virtIpId,"descr_name":virtIpDescrName}    # Save each virtual IP to it's own nested dictionary
                    # Pull further configuration from the firewall_virtual_ip_edit.php page if our ID is valid
                    if virtIpId.isdigit():
                        getAdvVirtIpData = http_request(url + "/firewall_virtual_ip_edit.php?id=" + virtIpId, {}, {}, {}, 45, "GET")
                        # Check that we have a TYPE configuration table
                        requiredTags = ["<span class=\"element-required\">Type</span>","<span class=\"element-required\">Interface</span>"]    # Set list of tags required for this section
                        if all(tag in getAdvVirtIpData["text"] for tag in requiredTags):
                            virtIpTypeData = getAdvVirtIpData["text"].split(requiredTags[0])[1].split(requiredTags[1])[0]    # Capture the data in our virt IP type table
                            virtIpTypes = virtIpTypeData.split("<label class=\"chkboxlbl\"><input name=\"mode\"")[1:]    # Split our types into a list to check values in
                            # Loop through our Virtual IP types and determine the current configured type
                            for type in virtIpTypes:
                                # Check if this type is currently checked
                                if "checked=\"checked\"" in type:
                                    virtIps["virtual_ips"][virtIpId]["type"] = type.split("value=\"")[1].split("\"")[0]    # Split our type value and add it to the dictionary
                                    break    # Break our loop to save processing
                                # Assume default if no type is selected
                                else:
                                    virtIps["virtual_ips"][virtIpId]["type"] = ""  # Assign empty string as default
                        # If we do not have the necessary tags, return default
                        else:
                            virtIps["virtual_ips"][virtIpId]["type"] = ""    # Assign empty string as default
                        # Check that we have an INTERFACE configuration table
                        requiredTags = ["<select class=\"form-control\" name=\"interface\" id=\"interface\">","</select>"]    # Set list of tags required for this section
                        if all(tag in getAdvVirtIpData["text"] for tag in requiredTags):
                            virtIpIfData = getAdvVirtIpData["text"].split(requiredTags[0])[1].split(requiredTags[1])[0]    # Capture the data in our virt IP iface table
                            virtIpIfOpt = virtIpIfData.split("<option")[1:]    # Split our select tag into list of options
                            # Loop through our options and check for selected indicator
                            for opt in virtIpIfOpt:
                                if "selected>" in opt:
                                    virtIps["virtual_ips"][virtIpId]["interface"] = opt.split("value=\"")[1].split("\"")[0]    # Parse our interface POST value to our dictionary
                                    virtIps["virtual_ips"][virtIpId]["interface_descr"] = opt.split("selected>")[1].split("</option>")[0]    # Parse our descriptive interface name to our dictionary
                                    break    # Break our loop to save processing
                        # If we did not have the required tags, return defaults
                        else:
                            virtIps["virtual_ips"][virtIpId]["interface"] = ""    # Assign default value as empty string
                            virtIps["virtual_ips"][virtIpId]["interface_descr"] = ""    # Assign default value as empty string
                        # Check that we have an IP ADDRESSES configuration table
                        requiredTags = ["<input class=\"form-control\" name=\"subnet\"","</select>"]    # Set list of tags required for this section
                        if all(tag in getAdvVirtIpData["text"] for tag in requiredTags):
                            virtIpAddrData = getAdvVirtIpData["text"].split(requiredTags[0])[1].split(requiredTags[1])[0]    # Capture the data in our virt IP address table
                            virtIps["virtual_ips"][virtIpId]["subnet"] = virtIpAddrData.split("value=\"")[1].split("\"")[0]    # Capture our configured IP address value and save it to our dictionary
                        # If we did not found our expected tags assume default
                        else:
                            virtIps["virtual_ips"][virtIpId]["subnet"] = ""    # Assign empty string as default
                        # Loop through our SELECT option values to reduce redundant code
                        selectTags = ["subnet_bits","vhid","advbase","advskew"]    # Assign a list of select tags to loop through and pull values from
                        for tg in selectTags:
                            requiredTags = ["<select class=\"form-control\" name=\""+tg+"\" id=\""+tg+"\">","</select>"]    # Set list of tags required for this section
                            if all(tag in getAdvVirtIpData["text"].replace(" pfIpMask","") for tag in requiredTags):
                                virtIpTagData = getAdvVirtIpData["text"].replace(" pfIpMask","").split(requiredTags[0])[1].split(requiredTags[1])[0]    # Capture the data in our virt IP tag table
                                virtIpTagOpt = virtIpTagData.split("<option")[1:]    # Split our select tag into list of options
                                # Loop through our tag data and determine which is selected
                                for opt in virtIpTagOpt:
                                    # Check if the option is current selected
                                    if "selected" in opt:
                                        virtIps["virtual_ips"][virtIpId][tg] = opt.split("value=\"")[1].split("\"")[0]    # Capture our virt IP tag data and save it to our dictionary
                                        break    # Break our loop to save processing
                                    # If none or selected
                                    else:
                                        virtIps["virtual_ips"][virtIpId][tg] = ""    # Assign empty string as default
                            # If we did not found our expected tags assume default
                            else:
                                virtIps["virtual_ips"][virtIpId][tg] = ""    # Assign empty string as default
                        # Check if our NOEXPAND option is enabled
                        if "<input name=\"noexpand\"" in getAdvVirtIpData["text"]:
                            virtIps["virtual_ips"][virtIpId]["noexpand"] = "yes" if "checked=\"checked\"" in getAdvVirtIpData["text"].split("<input name=\"noexpand\"")[1].split("</label>")[0] else ""    # Assign our NOEXPAND option to our dictionary
                        # If expected tag does not exist, assume default
                        else:
                            virtIps["virtual_ips"][virtIpId]["noexpand"] = ""
                        # Check for our DESCRIPTION value
                        if "name=\"descr\"" in getAdvVirtIpData["text"]:
                            virtIps["virtual_ips"][virtIpId]["descr"] = getAdvVirtIpData["text"].split("name=\"descr\"")[1].split("value=\"")[1].split("\"")[0]    # Save our description to the dictionary
                        # If no tag was found return default
                        else:
                            virtIps["virtual_ips"][virtIpId]["descr"] = ""
                    # Break the loop and return error if ID is not valid. This indiciates that we incorrectly parse the output (or their version of pfSense is unsupported)
                    else:
                        virtIps["ec"] = 2    # Return error exit code
                        break    # Break our loop to exit the function
    # Return our dictionary
    return virtIps

# add_virtual_ip() adds a new virtual IP to pfSense
def add_virtual_ip(server, user, key, mode, iface, subnet, subnetBit, expansion, vipPasswd, vhid, advbase, advSkew, descr):
    # Local variables
    vipAdded = 2    # Initialize our function return code (default 2 as error encountered)
    currentVips = get_virtual_ips(server,user,key)    # Pull our current Virtual IP configuration
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
    # Check that we successfully pulled our existing virtual IP configuration
    if currentVips["ec"] == 0:
        # VHID AUTO-DETECTION: Determine our next available VHID for auto specification
        usedVhids = []    # Initialize our list of occupied VHIDs
        autoVhid = ""    # Initialize our auto detected VHID
        for id,data in currentVips["virtual_ips"].items():
            # Ensure that this VHID is configured for our requested interface
            if iface == data["interface"]:
                # Save our VHID value to our list
                usedVhids.append(data["vhid"])
        # Loop through our taken VHIDs and return one that is not taken
        for i in range(256):
            # Check that our iteration is valid
            if 1 <= i <= 255:
                # Check if this VHID is already taken
                if str(i) not in usedVhids:
                    autoVhid = str(i)    # Assign our auto-detected VHID
                    break    # Break the loop as we only need one value
        # Convert our Python variables to our POST data paramemters to create a vIP POST dictionary
        vipPostDict = {
            "__csrf_magic" : get_csrf_token(url + "/firewall_virtual_ip_edit.php","GET"),
            "mode" : mode,
            "interface" : iface,
            "type" : "network",
            "subnet" : subnet,
            "subnet_bits" : subnetBit,
            "noexpand" : expansion if expansion != "" else None,
            "password" : vipPasswd,
            "password_confirm": vipPasswd,
            "vhid" : vhid if vhid != "auto" else autoVhid,
            "advbase" : advbase,
            "advskew" : advSkew,
            "descr" : descr,
            "save" : "Save"
        }
        # Create a dictionary of POST values to apply our virtual IP change
        vipSavePostDict = {
            "__csrf_magic" : get_csrf_token(url + "/firewall_virtual_ip.php","GET"),
            "apply" : "Apply Changes"
        }
        # Make our POST requests
        postVip = http_request(url + "/firewall_virtual_ip_edit.php", vipPostDict, {}, {}, 45, "POST")
        saveVip = http_request(url + "/firewall_virtual_ip.php", vipSavePostDict, {}, {}, 45, "POST")
        # Check that our new virtual IP is now in our configuration
        newVips = get_virtual_ips(server,user,key)    # Pull our current Virtual IP configuration
        for id,data in newVips["virtual_ips"].items():
            # Check if our added values exist in this dictionary
            if data["subnet"] == subnet and data["subnet_bits"] == subnetBit and data["type"] == mode:
                vipAdded = 0    # Return our success exit code
                break    # Break the loop as we found our new entry
    # If we encountered an error pulling the existing virtual IPs
    else:
        vipAdded = currentVips["ec"]    # Save the exit code from our get_virtual_ips() function to this functions exit code
    # Return our exit code
    return vipAdded

# get_status_carp() reads the current CARP status from status_carp.php
def get_status_carp(server, user, key):
    # Local variables
    carp = {"ec" : 2, "carp" : {"status" : "inactive", "maintenance_mode" : False, "carp_interfaces" : {}, "pfsync_nodes" : []}}    # Pre-define our dictionary to track CARP values and errors
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
    carpUnconfiguredMsg = "No CARP interfaces have been defined."    # Define the message pfSense displays when no CARP interfaces are configured
    carpEnabledMsg = "name=\"disablecarp\" value=\"Temporarily Disable CARP\""    # Define the message pfSense displays when CARP is enabled
    carpDisabledMsg = "name=\"disablecarp\" value=\"Enable CARP\""    # Define the message pfSense displays when CARP is disabled
    carpMaintenanceEnabled = "id=\"carp_maintenancemode\" value=\"Leave Persistent CARP Maintenance Mode\""    # Define the message pfSense displays when CARP maintenance mode is enabled
    carpMaintenanceDisabled = "id=\"carp_maintenancemode\" value=\"Enter Persistent CARP Maintenance Mode\""    # Define the message pfSense displays when CARP maintenance mode is disabled
     # Check for errors and assign exit codes accordingly
    carp["ec"] = 10 if check_dns_rebind_error(url) else carp["ec"]    # Return exit code 10 if dns rebind error found
    carp["ec"] = 6 if not validate_platform(url) else carp["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if carp["ec"] == 2:
        carp["ec"] = 3 if not check_auth(server, user, key) else carp["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if carp["ec"] == 2:
        # Check that we had permissions for this page
        getCarpStatusData = http_request(url + "/status_carp.php", {}, {}, {}, 45, "GET")    # Save our GET HTTP response
        if check_permissions(getCarpStatusData):
            # Check that we have a CARP configuration to parse
            if carpUnconfiguredMsg not in getCarpStatusData["text"]:
                # Check if CARP is enabled or disabled
                carp["carp"]["status"] = "enabled" if carpEnabledMsg in getCarpStatusData["text"] else carp["carp"]["status"]    # Determine whether CARP is enabled and save the value if it is
                carp["carp"]["status"] = "disabled" if carpDisabledMsg in getCarpStatusData["text"] else carp["carp"]["status"]    # Determine whether CARP is disabled and save the value
                # Check if CARP is in maintenance mode
                carp["carp"]["maintenance_mode"] = True if carpMaintenanceEnabled in getCarpStatusData["text"] else carp["carp"]["maintenance_mode"]    # Determine whether CARP maintenance mode is enabled and save the value if it is
                carp["carp"]["maintenance_mode"] = False if carpMaintenanceDisabled in getCarpStatusData["text"] else carp["carp"]["maintenance_mode"]    # Determine whether CARP maintenance mode is disabled and save the value
                # Ensure we have a CARP table
                if "<tbody>" in getCarpStatusData["text"]:
                    carpTableData = getCarpStatusData["text"].split("<tbody>")[1].split("</tbody>")[0]    # Capture all data between our tbody tags
                    carpTableRows = carpTableData.split("<tr>")[1:]    # Split table into a list of data rows
                    # Loop through our data rows and parse our data
                    counter = 0    # Create a loop counter to track loop iteration
                    for r in carpTableRows:
                        rowData = r.split("<td>")  # Save our row data into a list of data points
                        carp["carp"]["carp_interfaces"][counter] = {}    # Create a nested dictionary for each CARP interface in our table
                        carp["carp"]["carp_interfaces"][counter]["interface"] = rowData[1].split("@")[0]    # Split our first table data field to capture our interface ID
                        carp["carp"]["carp_interfaces"][counter]["vhid"] = rowData[1].split("@")[1].replace("</td>","").replace("\t","").replace("\n","")    # Split our first table data field to capture our VHID group
                        carp["carp"]["carp_interfaces"][counter]["cidr"] = rowData[2].split("</td>")[0].replace("\t","").replace("\n","")    # Split our second table data field to capture our CARP CIDR
                        carp["carp"]["carp_interfaces"][counter]["ip"] = carp["carp"]["carp_interfaces"][counter]["cidr"].split("/")[0]    # Split our second table data field to capture our CARP IP address
                        carp["carp"]["carp_interfaces"][counter]["subnet_bits"] = carp["carp"]["carp_interfaces"][counter]["cidr"].split("/")[1]    # Split our second table data field to capture our CARP subnet
                        carp["carp"]["carp_interfaces"][counter]["status"] = rowData[3].split("</i>&nbsp;")[1].split("</td>")[0].lower()    # Split our third table data field to capture our CARP status
                        counter = counter + 1    # Increase our counter
                # Check pfSync node IDs
                if "<br />pfSync nodes:<br /><pre>" in getCarpStatusData["text"]:
                    carp["carp"]["pfsync_nodes"] = getCarpStatusData["text"].split("<br />pfSync nodes:<br /><pre>")[1].split("</pre>")[0].split("\n")[:-1]    # Split each of our nodes into a list
                # Update our exit code to success
                carp["ec"] = 0
        # If we did not have permissions
        else:
            carp["ec"] = 15    # Return exit code 15 (permissions denied)
    # Return our dictionary
    return carp

# set_carp_maintenance() enables or disables CARP maintenance mode
def set_carp_maintenance(server, user, key, enable):
    # Local variables
    mmAdded = 2    # Initialize our function return code (default 2 as error encountered)
    currentCarp = get_status_carp(server,user,key)    # Pull our current CARP status
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)    # Populate our base URL
    # Check that we successfully pulled our existing CARP configuration
    if currentCarp["ec"] == 0:
        # Check that CARP is enabled
        if len(currentCarp["carp"]["carp_interfaces"]) > 0:
            # Check that we are actually changing the value before bothering with a POST request
            if currentCarp["carp"]["maintenance_mode"] != enable:
                # Format our POST data dictionary
                mmPostData = {"__csrf_magic":get_csrf_token(url + "/status_carp.php", "GET"), "carp_maintenancemode":""}
                # Check whether user want to enable or disable maintenance mode
                if enable:
                    mmPostData["carp_maintenancemode"] = "Enter Persistent CARP Maintenance Mode"    # Enter maintenance mode POST value
                elif not enable:
                    mmPostData["carp_maintenancemode"] = "Leave Persistent CARP Maintenance Mode"    # Exit maintenance mode POST value
                # Make our POST request but don't wait for a response
                setMmPost = http_request(url + "/status_carp.php", mmPostData, {}, {}, 45, "POST")    # POST our change to pfSense
                # Check that our value was set correctly
                updatedCarp = get_status_carp(server, user, key)  # Pull our updated CARP status
                if updatedCarp["ec"] == 0:
                    if updatedCarp["carp"]["maintenance_mode"] == enable:
                        mmAdded = 0   # Assign success exit code
                # If we could not pull our exist CARP status, exit on function exit code
                else:
                    mmAdded = currentCarp["ec"]    # Return the exit code returned by our get_status_carp() function
            # If we are already set to the requested mode, return success
            else:
                mmAdded = 0  # Assign success exit code
        # If pfSense does not have any configured CARP interfaces
        else:
            mmAdded = 4    # Assign exit code 4 (CARP not configured)
    # If we could not pull our exist CARP status, exit on function exit code
    else:
        mmAdded = currentCarp["ec"]    # Return the exit code returned by our get_status_carp() function
    # Return our exit code
    return mmAdded

# setup_hapfsense() automates the process needed to run pfSense in full high availability
def setup_hapfsense(server, user, key, backupNode, carpIfs, carpIps, carpPasswd, pfsyncIf, pfsyncIp):
    # Local variables
    haActive = 2  # Initialize our function return code (default 2 as error encountered)
    getMasterVer = get_pfsense_version(server, user, key)    # Get the pfSense version of our master node
    getBackupVer = get_pfsense_version(backupNode, user, key)    # Get the pfSense version of our backup node
    url = wcProtocol + "://" + server + ":" + str(wcProtocolPort)  # Populate our base URL
    allSyncOpts = {"synchronizeusers": "on", "synchronizeauthservers": "on", "synchronizecerts": "on",
                     "synchronizerules": "on", "synchronizeschedules": "on", "synchronizealiases": "on",
                     "synchronizenat": "on", "synchronizeipsec": "on", "synchronizeopenvpn": "on",
                     "synchronizedhcpd": "on", "synchronizewol": "on", "synchronizestaticroutes": "on",
                     "synchronizelb": "on", "synchronizevirtualip": "on", "synchronizetrafficshaper": "on",
                     "synchronizetrafficshaperlimiter": "on", "synchronizednsforwarder": "on",
                     "synchronizecaptiveportal": "on"}
    # Check that we were able to check our pfSense version on our master and backup nodes
    if getMasterVer["ec"] == 0:
        if getBackupVer["ec"] == 0:
            # Check if our pfSense versions match
            if getMasterVer["version"]["installed_version"] == getBackupVer["version"]["installed_version"]:
                # Add our CARP interfaces to MASTER
                counter = 0    # Start a loop counter to track our loop iteration
                vipFailed = False    # Track whether we encountered an error during our CARP additions
                for i in carpIps:
                    cVip = add_virtual_ip(server, user, key, "carp", carpIfs[counter], i, "32", "", carpPasswd, "auto", "0", "1", "HA PFSENSE IP: Auto-added by pfsense-automator")
                    # Check if we failed to add the CARP address
                    if cVip != 0:
                        haActive = 13
                        vipFailed = True
                        break
                    counter = counter + 1    # Increase our counter
                # Check if we added all CARP addresses successfully
                if not vipFailed:
                    # Add our HA SYNC configuration to sync the CARP interfaces to the backup node
                    masterSync = setup_hasync(server, user, key, "on", pfsyncIf, pfsyncIp, backupNode, user, key, allSyncOpts)
                    # Check that HA SYNC was successfully configured
                    if masterSync == 0:
                        haActive = 0   # Assign return code 0 (success)
                    # If HA SYNC failed
                    else:
                        haActive = 14
            # If our version do not match exactly, return error
            else:
                haActive = 12    # Return code 13 (versions do not match)
        # If we could not pull our pfSense version on our backup node, return the get_pfsense_version()'s return code
        else:
            haActive = getBackupVer["ec"]
    # If we could not pull our pfSense version on our master node, return the get_pfsense_version()'s return code
    else:
        haActive = getMasterVer["ec"]
    # Return our exit code
    return haActive

# main() is the primary function that maps arguments to other functions
def main():
    # Local Variables
    global wcProtocol    # Make wcProtocol modifiable globally
    global wcProtocolPort    # Make wcProtocolPort modifiable globally
    pfsenseServer = firstArg.replace("https://", "")    # Assign the server value to the firstArg (filtered)
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
    pfsenseServer = filter_input(pfsenseServer.replace("http://", ""))    # Filter our hostname/IP input
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
                        jsonName = "pf-readusers-" + currentDate + ".json"    # Assign our default JSON name
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
                            jsonName = "pf-readrules-" + currentDate + ".json"    # Assign our default JSON name
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
                            jsonName = "pf-readvirtip-" + currentDate + ".json"    # Assign our default JSON name
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
                                    print(html.unescape(cmdExec["shell_output"]))
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
                                jsonName = "pf-readcarp-" + currentDate + ".json"    # Assign our default JSON name
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
                            jsonName = "pf-readavailpkgs-" + currentDate + ".json"    # Assign our default JSON name
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
                            jsonName = "pf-readpkgs-" + currentDate + ".json"    # Assign our default JSON name
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
                        jsonName = "pf-readhasync-" + currentDate + ".json"    # Assign our default JSON name
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
                if check_remote_port(backupNode, wcProtocolPort):
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
                            exportName = "pf-xml-" + xmlArea + "-" + pfsenseServer + "-" + currentDate + ".xml"    # Assign our default XML name
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
                            jsonName = "pf-readifaces-" + currentDate + ".json"    # Assign our default JSON name
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
                availableIf = get_interfaces(pfsenseServer, user, key)    # Save our interface data
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
                            jsonName = "pf-readtunables-" + currentDate + ".json"    # Assign our default JSON name
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
                        jsonName = "pf-readgeneral-" + currentDate + ".json"    # Assign our default JSON name
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
        print("pfsense-automator " + softwareVersion)
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