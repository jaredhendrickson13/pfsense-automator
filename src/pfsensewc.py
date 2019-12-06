#!/usr/bin/python3
# IMPORTS #
import base64
import datetime
import getpass
import html
import io
import json
import os
import pfsensexml
import platform
import requests
import signal
import socket
import subprocess
import sys
import time
import urllib3
import xmltodict

# GLOBAL VARIABLES #
req_session = requests.Session()  # Start our requests session
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Disable urllib warnings (suppress invalid cert warning)
debug = False    # Assign a bool to change values when debug is enabled
local_config_xml_path = "/tmp/config.xml" if debug else "/conf/config.xml"   # Save the file path of our local config.xml file
local_systems = ["FreeBSD","Darwin","Windows","Linux"] if debug else ["FreeBSD"]    # Create a list of Operating Systems that pfSense runs on (currently only FreeBSD)
xml_target_local = os.path.exists(local_config_xml_path) if platform.system() in local_systems else False    # Determine whether the local system is pfSense
xml_indicator = "<pfsense>"    # Save a string that contains the XML indicator that we're working with a pfSense configuration

# CLASSES #
# PfaVar is a class of variables shared between different Python scripts
class PfaVar:
    software_version = "v0.0.4 " + platform.system() + "/" + platform.machine()    # Define our current version of this software
    local_user = getpass.getuser()  # Save our current user's username to a string
    local_hostname = socket.gethostname()  # Gets the hostname of the system running pfsense-automator
    current_date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")  # Get the current date in a file supported format
    wc_protocol = "https"  # Assigns whether the script will use HTTP or HTTPS connections
    wc_protocol_port = 443 if wc_protocol == 'https' else 80  # If PfaVar.wc_protocol is set to https, assign a integer value to coincide
# XmlConfigs saves our current config and our previous config if changed
class XmlConfigs:
    init = False    # Save a bool to track whether our config values are populated
    master = ""    # Our master XML config
    backup = ""    # Our previous XML config

# FUNCTIONS #
# get_exit_message() takes an exit code and other parameters to determine what success or error message to print
def get_exit_message(ec, server, command, data1, data2):
    # Local Variables
    exit_message = ""    # Define our return value as empty string
    cmd_flg_len = 30   # Set the maximum length of our command flags to use in formatting table data
    global_dns_rebind_msg = "Error: DNS rebind detected. Ensure `" + server + "` is listed in System > Advanced > Alt. Hostnames"
    global_auth_err_msg = "Error: Authentication failed"
    global_platform_err_msg = "Error: `" + server + "` does not appear to be running pfSense"
    global_permission_err_msg = "Error: Unable to execute function. Your user may lack necessary permissions"
    # Define our ERROR/SUCCESS message dictionary
    ecd = {
        # Generic error message that don't occur during commands
        "generic" : {
            "invalid_arg" : "Error: Invalid argument. Unknown command `" + data1 + "`",
            "connect_err" : "Error: Failed connection to " + server + ":" + str(PfaVar.wc_protocol_port) + " via " + PfaVar.wc_protocol,
            "invalid_host" : "Error: Invalid hostname. Expected syntax: `pfsense-automator <HOSTNAME or IP> <COMMAND> <ARGS>`",
            "timeout" : "Error: Connection timeout",
            "connection" : "Error: Connection dropped by remote host",
            "version" : "pfsense-automator " + PfaVar.software_version,
            "syntax" : "pfsense-automator <HOSTNAME or IP> <COMMAND> <ARGS>"
        },
        # Error/success messages for --check-auth flag
        "--check-auth": {
            "success": "Authentication successful",
            "fail": "Error: Authentication failed",
            "descr": structure_whitespace("  --check-auth",cmd_flg_len," ",True) + " : Test authentication credentials"
        },
        # Error/success messages for --check-version
        "--check-version": {
            2: "Error: Could not determine pfSense version",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --check-version",cmd_flg_len," ",True) + " : Check the pfSense version running on remote host"
        },
        # Error/success messages for --read-general-setup flag
        "--read-general-setup": {
            2: "Error: Unexpected error reading General Setup",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported general setup to " + data1,
            "export_fail": "Failed to export general setup as JSON",
            "descr" : structure_whitespace("  --read-general-setup",cmd_flg_len," ",True) + " : Read configuration data found in System > General Setup"
        },
        # Error/success messages for --set-system-hostname
        "--set-system-hostname": {
            0: "Successfully set system hostname to `" + data1 + "." + data2 + "` on `" + server + "`",
            2: "Error: Unexpected error configuring system hostname",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            9: "Error: Could not update system hostname. A valid DNS entry for `" + data1 + "." + data2 + "` may not exist",
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "inter_warn": "Warning: if DNS Rebind checks are enabled, changing the system hostname may result in an FQDN lockout",
            "descr": structure_whitespace("  --set-system-hostname",cmd_flg_len," ",True) + " : Set the pfSense system hostname"
        },
        # Error/success messages for --read-adv-admin flag
        "--read-adv-admin": {
            2: "Error: Unexpected error reading Advanced Settings",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported advanced admin options to " + data1,
            "export_fail": "Failed to export advanced admin options as JSON",
            "descr": structure_whitespace("  --read-adv-admin",cmd_flg_len," ",True) + " : Read configuration data found in System > Advanced > Admin Access"
        },
        # Error/success messages for --read-sslcerts flag
        "--read-sslcerts": {
            2: "Error: Unexpected error reading SSL certificates",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "read_err": "Error: failed to read SSL certificates from pfSense. You may not have any certificates installed",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported SSL certificate data to " + data1,
            "export_fail": "Failed to export SSL certificate data as JSON",
            "descr": structure_whitespace("  --read-sslcerts",cmd_flg_len," ",True) + " : Read SSL certificates data found in System > Cert. Manager > Certificates"
        },
        # Error/success messages for --add-sslcert flag
        "--add-sslcert": {
            0: "SSL certificate successfully uploaded",
            2: "Error: Failed to upload SSL certificate",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "no_cert": "Error: No certificate file found at `" + data1 + "`",
            "no_key": "Error: No key file found at `" + data1 + "`",
            "empty": "Error: Certificate or key file is empty",
            "descr": structure_whitespace("  --add-sslcert",cmd_flg_len," ",True) + " : Import SSL certificate and key from file"
        },
        # Error/success messages for --set-wc-sslcert
        "--set-wc-sslcert": {
            0: "Successfully changed WebConfigurator SSL certificate to `" + data1 + "`",
            1: "Error: SSL certificate `" + data1 + "` is already in use",
            2: "Error: Failed setting SSL certificate `" + data1 + "`",
            3: global_auth_err_msg,
            4: "Error: SSL certificate `" + data1 + "` matches multiple certificates",
            5: "Error: Certificate `" + data1 + "` not found",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "unknown_err": "Error: An unknown error has occurred",
            "descr": structure_whitespace("  --set-wc-sslcert",cmd_flg_len," ",True) + " : Set the SSL certificate used by the webConfigurator"

        },
        # Error/success messages for --setup-wc
        "--setup-wc": {
            0: "Successfully setup webConfigurator options on `" + server + "`",
            2: "Error: Unexpected error configuring webConfigurator options",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_proc": "Error: Invalid max processes value `" + data1 + "`. Expected value between 1-1024",
            "invalid_redirect": "Error: Unknown HTTP redirect option `" + data1 + "`",
            "invalid_hsts": "Error: Unknown HSTS option `" + data1 + "`",
            "invalid_autocomplete": "Error: Unknown login auto-complete option `" + data1 + "`",
            "invalid_loginmsg": "Error: Unknown authentication logging option `" + data1 + "`",
            "invalid_lockout": "Error: Unknown webConfigurator anti-lockout option `" + data1 + "`",
            "invalid_dnsrebind": "Error: Unknown DNS rebind checking option `" + data1 + "`",
            "invalid_httpreferer": "Error: Unknown HTTP_REFERER checking option `" + data1 + "`",
            "invalid_tabtext": "Error: Unknown display hostname in tab option `" + data1 + "`",
            "descr": structure_whitespace("  --setup-wc",cmd_flg_len," ",True) + " : Configure webConfigurator options"
        },
        # Error/success messages for --setup-wc
        "--set-wc-port": {
            0: "Successfully setup webConfigurator at " + PfaVar.wc_protocol + "://" + server + ":" + data2,
            2: "Error: Unexpected error configuring webConfigurator port. You may be sending HTTP requests to an HTTPS port",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            8: "Error: Unexpected error binding to TCP/" + data2,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_protocol": "Error: Unknown protocol `" + data1 + "`. Expected http or https",
            "invalid_port": "Error: Invalid port `" + data2 + "`. Expected value between 1-65535",
            "descr": structure_whitespace("  --set-wc-port", cmd_flg_len, " ", True) + " : Set the webConfigurator protocol and port"
        },
        # Error/success messages for --setup-console
        "--setup-console": {
            0: "Successfully setup console options on `" + server + "`",
            2: "Error: Unexpected error configuring console options",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_option": "Error: Unknown console option value `" + data1 + "`",
            "descr": structure_whitespace("  --setup-console", cmd_flg_len, " ", True) + " : Configure console options"
        },
        # Error/success messages for --setup-ssh
        "--setup-ssh": {
            0: "Successfully setup SSH on `" + server + "`",
            2: "Error: Unexpected error configuring SSH",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            20: "Error: Unknown legacy SSH authentication option `" + data1 + "`",
            21: "Error: Unknown SSH authentication option `" + data1 + "`",
            "invalid_enable": "Error: Unknown enable value `" + data1 + "`",
            "descr": structure_whitespace("  --setup-ssh", cmd_flg_len, " ", True) + " : Configure SSH options"
        },
        # Error/success messages for --read-tunables flag
        "--read-tunables": {
            2: "Error: Unexpected error reading system tunables",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported tunable data to " + data1,
            "export_fail": "Failed to export tunable data as JSON",
            "descr": structure_whitespace("  --read-tunables", cmd_flg_len, " ", True) + " : Read tunable configuration from System > Advanced > System Tunables"
        },
        # Error/success messages for --add-tunable flag
        "--add-tunable": {
            0: "Successfully added tunable `" + data1 + "` to `" + server + "`",
            2: "Error: Unexpected error adding system tunable",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            8: "Error: Tunable `" + data1 + "` already exists",
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --add-tunable", cmd_flg_len, " ", True) + " : Add a new system tunable"
        },
        # Error/success messages for --read-adv-admin flag
        "--read-users": {
            2: "Error: Unexpected error reading user database",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "invalid_user": "Error: User `" + data1 + "` does not exist",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported user data to " + data1,
            "export_fail": "Failed to export user data as JSON",
            "descr": structure_whitespace("  --read-users", cmd_flg_len, " ", True) + " : Read user data from System > User Manager > Users"
        },
        # Error/success messages for --add-user
        "--add-user": {
            0: "Successfully added user `" + data1 + "` to " + server,
            2: "Error: Unexpected error adding user",
            3: global_auth_err_msg,
            4: "Error: Username `" + data1 + "` already exists",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_enable": "Error: Invalid enable value `" + data1 + "`",
            "invalid_date": "Error: Invalid expiration date `" + data1 + "`. This must be a future date in MM/DD/YYYY format",
            "invalid_group": "Error: Group `" + data1 + "` does not exist",
            "descr": structure_whitespace("  --add-user", cmd_flg_len, " ", True) + " : Add a new local webConfigurator user"
        },
        # Error/success messages for --del-user
        "--del-user": {
            0: "Successful removed user `" + data1 + "` from " + server,
            2: "Error: Unexpected error removing user",
            3: global_auth_err_msg,
            4: "Error: User `" + data1 + "` does not exist",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_uid": "Error: Username `admin` or UID `0` cannot be removed",
            "invalid_user": "Error: You cannot delete your own user",
            "descr": structure_whitespace("  --del-user", cmd_flg_len, " ", True) + " : Remove an existing webConfigurator user"
        },
        # Error/success messages for --add-user-key
        "--add-user-key": {
            0: "Successfully added " + data1 + " key to user `" + data2 + "`",
            2: "Error: Unexpected error adding " + data1 + " key. Your key may be invalid",
            3: global_auth_err_msg,
            4: "Error: Username `" + data2 + "` does not exist",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_key_type": "Error: Invalid key type `" + data1 + "`. Expected `ssh` or `ipsec`",
            "invalid_override": "Error: Invalid SSH key override specification `" + data1 + "` Expected `yes` or `no`",
            "invalid_ssh_path": "Error: No SSH keyfile found at `" + data1 + "`",
            "descr": structure_whitespace("  --add-user-key", cmd_flg_len, " ", True) + " : Add and IPsec or SSH key to an existing user"
        },
        # Error/success messages for --change-user-passwd
        "--change-user-passwd": {
            0: "Successfully changed password for user `" + data1 + "`",
            2: "Error: Unexpected error changing user password",
            3: global_auth_err_msg,
            4: "Error: Username `" + data1 + "` does not exist",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --change-user-passwd", cmd_flg_len, " ", True) + " : Change an existing user's password"
        },
        # Error/success messages for -add-ldapserver
        "--add-ldapserver": {
            0: "Successfully added LDAP server `" + data1 + "` on `" + server + "`",
            2: "Error: Failed to configure LDAP server",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
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
            "descr": structure_whitespace("  --add-ldapserver", cmd_flg_len, " ", True) + " : Add a new LDAP authentication server ",
        },
        # Error/success messages for --read-installed-pkgs flag
        "--read-available-pkgs": {
            2: "Error: Unexpected error reading available packages",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported available package data to " + data1,
            "export_fail": "Failed to export available package data as JSON",
            "descr": structure_whitespace("  --read-available-pkgs", cmd_flg_len, " ", True) + " : Read available packages from System > Package Manager",
        },
        # Error/success messages for --read-installed-pkgs flag
        "--read-installed-pkgs": {
            2: "Error: Unexpected error reading package installations",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported package data to " + data1,
            "export_fail": "Failed to export package data as JSON",
            "descr": structure_whitespace("  --read-installed-pkgs", cmd_flg_len, " ", True) + " : Read installed packages from System > Package Manager",
        },
        # Error/success messages for --add-package
        "--add-pkg": {
            0: "Successfully installed package `" + data1 + "`",
            2: "Error: Unexpected error installing package",
            3: global_auth_err_msg,
            4: "Error: Package `" + data1 + "` does not exist",
            5: "Error: Package `" + data1 + "` is already installed",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --add-pkg", cmd_flg_len, " ", True) + " : Add a new package to pfSense",
        },
        # Error/success messages for --del-package
        "--del-pkg": {
            0: "Successfully removed package `" + data1 + "`",
            2: "Error: Unexpected error removing package",
            3: global_auth_err_msg,
            4: "Error: Package `" + data1 + "` is not installed",
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --del-pkg", cmd_flg_len, " ", True) + " : Remove an existing package from pfSense",
        },
        # Error/success messages for --read-arp flag
        "--read-arp": {
            2: "Error: Unexpected error reading ARP configuration",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported ARP table to " + data1,
            "export_fail": "Failed to export ARP table as JSON",
            "descr": structure_whitespace("  --read-arp", cmd_flg_len, " ", True) + " : Read ARP table from Diagnostics > ARP Table",
        },
        # Error/success messages for --read-states flag
        "--read-states": {
            2: "Error: Unexpected error reading state table",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --read-states", cmd_flg_len, " ", True) + " : Read a dump of the firewall states table",
        },
        # Error/success messages for --read-xml flag
        "--read-xml": {
            2: "Error: Unexpected error reading XML configuration",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "invalid_area": "Error: invalid XML area `" + data1 + "`",
            "invalid_pkg": "Error: invalid package option `" + data1 + "`",
            "invalid_rrd": "Error: invalid RRD option `" + data1 + "`",
            "invalid_encrypt": "Error: invalid encryption option `" + data1 + "`",
            "export_success": "Successfully exported XML configuration to " + data1,
            "export_fail": "Failed to export XML configuration",
            "descr": structure_whitespace("  --read-xml", cmd_flg_len, " ", True) + " : Read or save XML configuration from Diagnostics > Backup & Restore",
        },
        # Error/success messages for --upload-xml flag
        "--upload-xml": {
            0: "Successfully uploaded XML configuration to restoration area `" + data1 + "`. A reboot may be required.",
            2: "Error: Failed to restore XML configuration. Your XML file may be malformed",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filepath": "Error: No file found at `" + data1 + "`",
            "invalid_area": "Error: Invalid restoration area `" + data1 + "`",
            "descr": structure_whitespace("  --upload-xml", cmd_flg_len, " ", True) + " : Restore an existing XML configuration from file",
        },
        # Error/success messages for --replicate-xml flag
        "--replicate-xml": {
            2: "Error: Unexpected error pulling XML configuration from master `" + server + "`",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_area": "Error: Invalid restoration area `" + data1 + "`",
            "invalid_targets": "Error: Invalid target string `" + data1 + "`",
            "descr": structure_whitespace("  --replicate-xml", cmd_flg_len, " ", True) + " : Copy an XML area from one pfSense server to another",
        },
        # Error/success messages for --run-shell-cmd
        "--run-shell-cmd": {
            2: "Error: Unexpected response from command `" + data1 + "`",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "descr": structure_whitespace("  --run-shell-cmd", cmd_flg_len, " ", True) + " : Run a single shell command or start a virtual shell",
        },
        # Error/success messages for --read-interfaces flag
        "--read-interfaces": {
            2: "Error: Unexpected error reading interface configuration",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported interface data to " + data1,
            "export_fail": "Failed to export interface data as JSON",
            "descr": structure_whitespace("  --read-interfaces", cmd_flg_len, " ", True) + " : Read configured interfaces from Interfaces > Assignments",
        },
        # Error/success messages for --read-available-interfaces flag
        "--read-available-interfaces": {
            2: "Error: Unexpected error reading interface configuration",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "no_if": "No interfaces available on `" + server + "`",
            "descr": structure_whitespace("  --read-available-interfaces", cmd_flg_len, " ", True) + " : Read interfaces that are available but not configured",
        },
        # Error/success messages for --read-vlans flag
        "--read-vlans": {
            2: "Error: Unexpected error reading VLAN configuration. You may not have any VLANs configured",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported VLAN data to " + data1,
            "export_fail": "Failed to export VLAN data as JSON",
            "descr": structure_whitespace("  --read-vlans", cmd_flg_len, " ", True) + " : Read configured VLAN from Interfaces > VLANs",
        },
        # Error/success messages for --add-vlan flag
        "--add-vlan" : {
            0 : "Successfully added VLAN `" + data1 + "` on `" + data2 + "`",
            1 : "Error: No usable interfaces were detected",
            2 : "Error: Unexpected error adding VLAN `" + data1 + "` on `" + data2 + "`",
            3 : global_auth_err_msg,
            6 : global_platform_err_msg,
            7 : "Error: Interface `" + data2 + "` does not exist",
            8 : "Error: VLAN `" + data1 + "` already exists on interface `" + data2 + "`",
            10 : global_dns_rebind_msg,
            15 : global_permission_err_msg,
            "invalid_vlan" : "Error: VLAN `" + data1 + "` out of range. Expected 1-4094",
            "invalid_priority" : "Error: VLAN priority `" + data1 + "` out of range. Expected 0-7",
            "descr": structure_whitespace("  --add-vlans", cmd_flg_len, " ", True) + " : Add a new VLAN to an existing interface",
        },
        # Error/success messages for --read-dns
        "--read-dns": {
            0: True,
            2: "Error: Unexpected error reading DNS Resolver configuration",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_syntax": "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --read-dns <FILTER>`",
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported DNS Resolver data to " + data1,
            "export_fail": "Failed to export DNS Resolver data as JSON",
            "descr": structure_whitespace("  --read-dns", cmd_flg_len, " ", True) + " : Read DNS resolver entries from Services > DNS Resolvers",
        },
        # Error/success messages for --add-dns flag
        "--add-dns" : {
            0 : "DNS record was added successfully",
            2: "Error: Unexpected error adding `" + data1 + "." + data2  + "`",
            3 : global_auth_err_msg,
            4 : "Error: DNS unreachable at " + server,
            6 : global_platform_err_msg,
            9 : "Error: DNS entry for `" + data1 + "." + data2  + "` already exists @" + server,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_ip" : "Error: Invalid IP address",
            "invalid_syntax" : "Error: Invalid arguments. Expected syntax: `pfsense-controller <SERVER> --add-dns <HOST> <DOMAIN> <IP> <DESCR>`",
            "descr": structure_whitespace("  --add-dns", cmd_flg_len, " ", True) + " : Add a new DNS host override to DNS Resolver",
        },
        # Error/success messages for --read-rules
        "--read-rules" : {
            2 : "Error: Unexpected error reading firewall rules",
            3 : global_auth_err_msg,
            4 : "Error: Interface `" + data1 + "` does not exist",
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "read_err" : "Error: Unexpected error reading Firewall Rules from pfSense",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported Firewall Rule data to " + data1,
            "export_fail" : "Failed to export Firewall Rules data as JSON",
            "descr": structure_whitespace("  --read-rules", cmd_flg_len, " ", True) + " : Read configured firewall rules from Firewall > Rules",
        },
        # Error/success messages for --add-rule
        "--add-rule" : {
            0: "Successfully added firewall rule to " + server + " on `" + data1 + "`",
            2: "Error: Unexpected error adding firewall rule",
            3 : global_auth_err_msg,
            4: "Error: Invalid source port. Port must be between 1 & 65535. If a port range, your start port must be less than your end port",
            5: "Error: Invalid destination port. Port must be between 1 & 65535. If a port range, your start port must be less than your end port",
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_type": "Error: Invalid rule type `" + data1 + "`. Expected `pass`, `block`, or `reject`",
            "invalid_ipver" : "Error: Invalid IP version `" + data1 + "`. Expected `ipv4`, `ipv6` or `any`",
            "invalid_protocol" : "Error: Invalid protocol `" + data1 + "`. Available protocols: [" + data2 + "]",
            "invalid_source" : "Error: Invalid source address `" + data1 + "`",
            "invalid_dest": "Error: Invalid destination address `" + data1 + "`",
            "invalid_bitmask" : "Error: Invalid bitmask `" + data1 + "`. Expected value between 1 & 32",
            "descr": structure_whitespace("  --add-rule", cmd_flg_len, " ", True) + " : Add a new basic firewall rule",
        },
        # Error/success messages for --del-rule
        "--del-rule" : {
            0: "Successfully removed firewall rule ID `" + data2 + "` from ACL `" + data1 + "`",
            2: "Error: Unexpected error remvoing firewall rule",
            3 : global_auth_err_msg,
            4: "Error: Invalid interface. Interface `" + data1 + "` does not exist",
            5: "Error: Invalid rule ID. Rule ID `" + data2 + "` does not exist",
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_id": "Error: Invalid rule ID. Expected a number greater than 0",
            "descr": structure_whitespace("  --del-rule", cmd_flg_len, " ", True) + " : Delete a firewall rule from an interface ACL",
        },
        # Error/success messages for --read-aliases
        "--read-aliases" : {
            3 : global_auth_err_msg,
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "read_err" : "Error: failed to read Firewall Aliases from pfSense. You may not have any Firewall Aliases configured",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported Firewall Alias data to " + data1,
            "export_fail" : "Failed to export Firewall Alias data as JSON",
            "descr": structure_whitespace("  --read-aliases", cmd_flg_len, " ", True) + " : Read configured firewall aliases from Firewall > Aliases",
        },
        # Error/success messages for --modify-alias
        "--modify-alias" : {
            0 : "Alias `" + data1 +"` successfully updated",
            1 : "Error: Unable to parse alias `" + data1 + "`",
            2 : "Error: Unexpected error processing alias",
            3 : global_auth_err_msg,
            4 : "Error: Unable to locate alias `" + data1 + "`",
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_syntax" : "Error: Invalid syntax - `pfsense-automator <pfSense IP or FQDN> --modify-alias <alias name> <alias values>`",
            "descr": structure_whitespace("  --modify-alias", cmd_flg_len, " ", True) + " : Modify an existing firewall alias",
        },
        # Error/success messages for --read-virtual-ip
        "--read-virtual-ips": {
            2: "Error: Unknown error gathering virtual IP data",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err": "Error: export directory `" + data1 + "` does not exist",
            "export_success": "Successfully exported Virtual IP data to " + data1,
            "export_fail": "Failed to export Virtual IP data as JSON",
            "descr": structure_whitespace("  --read-virtual-ips", cmd_flg_len, " ", True) + " : Read configured virtual IPs from Firewall > Virtual IPs",
        },
        # Error/success messages for --add-virtual-ip
        "--add-virtual-ip": {
            0: "Successfully added virtual IP `" + data1 + "`",
            2: "Error: Unexpected error adding virtual IP. It may conflict with an existing IP",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_mode": "Error: Unknown virtual IP type `" + data1 + "`. Expected `ipalias`, `carp`, `proxyarp` or `other`",
            "invalid_iface": "Error: Interface `" + data1 + "` does not exist",
            "invalid_subnet": "Error: Invalid subnet CIDR `" + data1 + "`",
            "invalid_expand": "Error: Unknown IP expansion option `" + data1 + "`. Expected `yes` or `no`",
            "invalid_adv": "Error: Invalid advertisements - BASE: `" + data1 + "` SKEW: `" + data2 + "`. Expected value 0-254",
            "invalid_vhid": "Error: Invalid VHID `" + data1 + "`. Expected value 1-255",
            "vhid_exists": "Error: VHID `" + data1 + "` already exists on interface `" + data2 + "`",
            "descr": structure_whitespace("  --add-virtual-ip", cmd_flg_len, " ", True) + " : Configure a new virtual IP",
        },
        # Error/success messages for --read-hasync
        "--read-hasync" : {
            2 : "Error: Unexpected error gathering HA Sync data",
            3 : global_auth_err_msg,
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported HA Sync data to " + data1,
            "export_fail" : "Failed to export HA Sync data as JSON",
            "descr": structure_whitespace("  --read-hasync", cmd_flg_len, " ", True) + " : Read HA sync configuration from System > HA Sync",
        },
        # Error/success messages for --setup-hasync
        "--setup-hasync" : {
            0: "Successfully setup HA sync",
            2: "Error: Unexpected error configuring HA sync",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_enable" : "Error: Invalid PFSYNC enable value `" + data1 + "`. Expected `enable`,`disable`, or `default`",
            "invalid_interface" : "Error: Unknown interface `" + data1 + "`",
            "invalid_ip" : "Error: Invalid " + data1 + " peer IP `" + data2 + "`",
            "invalid_user" : "Error: Invalid XMLRPC username `" + data1 + "`",
            "invalid_passwd" : "Error: Invalid XMLRPC password length",
            "descr": structure_whitespace("  --setup-hasync", cmd_flg_len, " ", True) + " : Configure HA Sync",
        },
        # Error/success messages for --setup-hapfsense
        "--setup-hapfsense" : {
            0 : "Successfully configured HA pfSense",
            2 : "Error: Unexpected error configuring HA pfSense",
            3: global_auth_err_msg,
            6: global_platform_err_msg,
            10: global_dns_rebind_msg,
            12: "Error: pfSense version mismatch. MASTER on pfSense " + data1 + ", BACKUP on pfSense " + data2,
            13: "Error: Unable to add CARP virtual IPs to MASTER node",
            14: "Error: Unable to configure HA Sync on MASTER node",
            15: global_permission_err_msg,
            "invalid_backup_ip" : "Error: Invalid BACKUP node IP `" + data1 + "`",
            "invalid_master_if" : "Error: Unknown interface `" + data1 + "` on MASTER node `" + server + "`",
            "invalid_backup_if" : "Error: Unknown interface `" + data1 + "` on BACKUP node `" + data2 + "`",
            "invalid_carp_ip" : "Error: Invalid CARP virtual IP `" + data1 + "`",
            "invalid_pfsync_if" : "Error: Unknown PFSYNC interface `" + data1 + "`",
            "invalid_pfsync_ip" : "Error: Invalid PFSYNC IP address `" + data1 + "`",
            "descr": structure_whitespace("  --setup-hapfsense", cmd_flg_len, " ", True) + " : Configure pfSense to run in full High Availability",
        },
        # Error/success messages for --read-carp-status
        "--read-carp-status" : {
            2 : "Error: Unexpected error checking CARP status. No CARP interfaces found",
            3 : global_auth_err_msg,
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_filter": "Error: Invalid filter `" + data1 + "`",
            "export_err" : "Error: export directory `" + data1 + "` does not exist",
            "export_success" : "Successfully exported CARP data to " + data1,
            "export_fail" : "Failed to export CARP data as JSON",
            "descr": structure_whitespace("  --read-carp-status", cmd_flg_len, " ", True) + " : Read the current CARP failover status from Status > CARP",
        },
        # Error/success messages for --set-carp-maintenance
        "--set-carp-maintenance" : {
            0 : "Successfully " + data1 + " CARP maintenance mode on `" + server + "`",
            2 : "Error: Unexpected error " + data1 + " CARP maintenance mode",
            3 : global_auth_err_msg,
            4 : "Error: No configured CARP interfaces were found",
            6 : global_platform_err_msg,
            10 : global_dns_rebind_msg,
            15: global_permission_err_msg,
            "invalid_toggle" : "Error: Invalid toggle `" + data1 + "`. Expected `enable` or `disable`",
            "descr": structure_whitespace("  --set-carp-maintenance", cmd_flg_len, " ", True) + " : Enable CARP maintenance mode",
        }
    }
    # Pull the requested message, return entire dictionary if "all" command is passed, otherwise just return the single values
    exit_message = ecd[command][ec] if command != "all" else ecd
    # Return our message
    return exit_message

# http_request() uses the requests module to make HTTP POST/GET requests
def http_request(url, data, headers, files, timeout, method):
    # Local Variables
    resp_dict = {}    # Initialize response dictionary to return our response values
    data = {} if type(data) != dict else data
    headers = {} if type(headers) != dict else headers
    files = {} if type(files) != dict else files
    no_resp_mode = True if timeout <= 5 else False    # Determine if user expects a response based on timeout value
    method_list = ['GET', 'POST']    # Set a list of supported HTTP methods
    # Check that our method is valid
    if method.upper() in method_list:
        # Process to run if a GET request was requested
        if method.upper() == "GET":
            get_timed_out = False    # Assign bool to track whether we received a timeout
            get_conn_err = False    # Assign a bool to track whether we received a connection error
            try:
                req = req_session.get(url, headers=headers, verify=False, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                get_timed_out = True
            except requests.exceptions.ConnectionError:
                get_conn_err = True
            # If our connection timed out AND our timeout value was greater than 5 seconds
            if get_timed_out and timeout > 5:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
            # If our connection returned an error
            if get_conn_err:
                print(get_exit_message("connection", "", "generic", "", ""))
                sys.exit(1)
        # Process to run if a POST request was requested
        elif method.upper() == "POST":
            post_timed_out = False  # Assign bool to track whether we received a timeout
            post_conn_err = False  # Assign a bool to track whether we received a connection error
            # Try to open the connection and gather data
            try:
                req = req_session.post(url, data=data, files=files, headers=headers, verify=False, timeout=timeout)
            except requests.exceptions.ReadTimeout:
                post_timed_out = True
            except requests.exceptions.ConnectionError:
                post_conn_err = True
            # If our connection timed out AND our timeout value was greater than 5 seconds
            if post_timed_out and timeout > 5:
                print(get_exit_message("timeout", "", "generic", "", ""))
                sys.exit(1)
            # If our connection returned an error
            if post_conn_err:
                print(get_exit_message("connection", "", "generic", "", ""))
                sys.exit(1)
        # Check if responseless mode is disabled
        if not no_resp_mode:
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

# update_configs() updates the XmlConfigs class
def update_config(server, user, key):
    XmlConfigs.backup = XmlConfigs.master    # Save our current master as our backup before updating master
    XmlConfigs.master = get_pfsense_config(server, user, key, xml_target_local)["config"]    # Update master config

# get_pfsense_config() parse the config.xml file from pfSense into a Python dictionary
def get_pfsense_config(server, user, key, local_xml):
    # Local variables
    pf_config = {"ec": 2, "config": {}}    # Init our return dict
    xml = ""    # Init our XML string as blank
    ssh_cmd = "ssh -o StrictHostKeyChecking=no -o BatchMode=yes " + server + " \"cat " + local_config_xml_path + "\""
    # Check if we are parsing a local file or a remote file
    if local_xml == True:
        with open(local_config_xml_path,"r") as xf:
            xml = xf.read()
    else:
        # Try to pull our config via SSH
        ssh_resp = run_ssh_cmd(server, "cat " + local_config_xml_path)
        ssh_xml = ssh_resp["ssh_output"]
        if ssh_resp["ec"] == 0:
            # Check if we pulled the config via SSH, if not, pull via webConfigurator
            if xml_indicator not in ssh_xml:
                # Try to pull our XML config via the fastest method first (backup tool)
                xml_backup = get_xml_backup(server, user, key, "", False, True, False, "")    # Pull our XML config through webConfigurator's backup tool
                # Check if our XML was pulled successfully through the backup tool
                if xml_backup["ec"] == 0:
                    xml = xml_backup["xml"]    # Save our config
                # Otherwise pull the XML using the shell tool
                else:
                    xml_shell = get_shell_output(server, user, key, "cat " + local_config_xml_path)    # Pull our XML config through webConfigurator's shell tool
                    # Check if our XML was pulled successfully through the shell tool
                    if xml_shell["ec"] == 0:
                        xml = xml_shell["shell_output"]    # Save our config
                    # Otherwise return the exit code returned by get_shell_output()
                    else:
                        pf_config["ec"] = xml_shell["ec"]
            # Otherwise save our config pulled via SSH
            else:
                xml = ssh_xml
    # Convert our XML to dict type and return success exit code if we have XML
    if xml_indicator in xml:
        pf_config["config"] = xml
        pf_config["ec"] = 0
    # Return our dictionary
    return pf_config

# convert_xml() converts our pfSense XML configuration to a Python3/JSON dictionary
def convert_xml(xml):
    # Local variables
    xml_dict = {}    # Init our return dictionary
    # Check if xml variable is string
    if type(xml) is str:
        # Check if xml variable is a file path
        if len(xml) < 100 and os.path.exists(xml):
            with open(xml, "r") as xr:
                xml = xr.read()    # Save our file's content as XML
        # Try to convert our dictionary
        try:
            xml_dict = xmltodict.parse(xml)
        except Exception as x:
            print(x)    # Pass this exception for now, replace with more specific exception selector
    # Return our dictionary
    return xml_dict

# export_json() exports a Python dictionary as a JSON file
def export_json(dictionary, json_path, json_name):
    # Open an export file and save our data
    with open(json_path + json_name, "w") as jf:
        json.dump(dictionary, jf)
    # Check that file now exists
    json_exported = True if os.path.exists(json_path + json_name) else False
    # Return our boolean
    return json_exported

# filter_input() sanitizes a string of special or otherwise malicious characters. Returns the formatted string.
def filter_input(stf):
    # Local Variables
    special_chars = [",","~","!","@","#","$","%","^","&","*","(",")","+","=","{","}","[","]","\\", "\"","\'",":",";","\'","?","/","<",">"]
    # Check if input is string
    if isinstance(stf, str):
        # For each character in the list, replace the character with blank space
        for char in special_chars:
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
            rem_loop = 0    # Assign a loop index to track which character we are on
            rem_string = ""    # Assign variable to temporarily assign our characters to
            for c in string:
                # Check if we've reach our max length -3 (make room for ellipses)
                if rem_loop == length - 3:
                    rem_string = rem_string + "..."     # Add ellipses
                    string = rem_string    # Save rem_string to our return string
                    break
                # Add the character to our string and increase our index
                rem_string = rem_string + c
                rem_loop = rem_loop + 1
    # Return our structured string
    return string

# validate_platform()
def validate_platform(url,req_obj):
    # Local variables
    html_str = req_obj["text"] if req_obj is not None else http_request(url, {}, {}, {}, 45, "GET")["text"]    # Get our HTML data
    platform_confidence = 0    # Assign a integer confidence value
    # List of platform dependent key words to check for
    check_items = [
        "pfSense", "pfsense.org", "Login to pfSense", "pfsense-logo", "pfSenseHelpers",
        "netgate.com", "__csrf_magic", "ESF", "Netgate", "Rubicon Communications, LLC",
        "Electric Sheep Fencing LLC", "https://pfsense.org/license"
    ]
    # Loop through our list and add up a confidence score
    for ci in check_items:
        # Check if our keyword is in the HTML string, if so add 10 to our confidence value
        platform_confidence = platform_confidence + 10 if ci in html_str else platform_confidence
    # Determine whether our confidence score is high enough to allow requests
    platform_confirm = True if platform_confidence > 50 else False
    # Return our bool
    return platform_confirm

# validate_ip() attempts to parse the IP into expected data. If the IP is not valid, false is returned.
def validate_ip(ip):
    # Local Variables
    valid_ip = False    # Assign the function's return value as a boolean
    loop_index = 0    # Assign the octet validation loop's index as 0
    # Try to split the IP into an array at each octet (dot)
    if isinstance(ip, str):
        ip_to_validate = ip.split(".")
        # Check if the expected 4 octets are returned (IPv4 only)
        if len(ip_to_validate) == 4:
            # For each octet, ensure IP is in range
            for octet in ip_to_validate:
                # Try to convert each octet into an integer, if there is a ValueError we know it is not a valid IP
                try:
                    octet_integer = int(octet)
                # Break if we cannot convert to integer
                except ValueError:
                    break
                # Check if integer is within the acceptable range (0-255)
                if 255 >= octet_integer >= 0:
                    # If all octets were validated
                    if loop_index == 3:
                        valid_ip = True    # If all octets survived the check, return True
                # Break if int is out of range
                else:
                    break
                loop_index = loop_index + 1    # Increase the index after each loop completion
    # Return boolean
    return valid_ip

# validate_port_range() takes a port or port range (separated by -) and determine if the port range is valid
def validate_port_range(port):
    # Local variables
    ports = {"valid": False, "start": 0, "end": 0}    # Create a dictionary to track various values
    # Check if port contains `-` range indicator
    if "-" in str(port):
        port_rng = str(port).split("-")    # Split our port to capture our start and end port
        # Check that our list only has two values
        if len(port_rng) == 2:
            start_port = int(port_rng[0]) if port_rng[0].isdigit() else 0    # Save our start port
            end_port = int(port_rng[1]) if port_rng[1].isdigit() else 65536    # Save our start port
            start_port_vld = False    # Assign a bool to track if the start port is valid
            end_port_vld = False    # Assign a bool to track if the end port is valid
            # Check if our start port is within range and less than the end port
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                ports = {"valid": True, "start": start_port, "end": end_port}
    # Check if port is a number
    elif str(port).isdigit():
        # Check that port is in range
        if 1 <= int(port) <= 65535:
            ports = {"valid": True, "start": int(port), "end": int(port)}
    # Return our dictionary
    return ports

# validate_date_format() checks if a date string is in the format mm/dd/yyyy and is a future date
def validate_date_format(date_str):
    # Local variables
    date_valid = False    # Init our return value as false by default
    date_now = datetime.datetime.now()    # Create our time object to compare later
    # Check if our date string is actually a string
    if type(date_str) is str:
        # Check if we have the `/` character in our string
        if "/" in date_str:
            date_list = date_str.split("/")    # Split our string into a list so we can verify each date value
            # Check that we have three items in the list
            if len(date_list) == 3:
                # Check that our month value is a digit
                if date_list[0].isdigit() and date_list[1].isdigit() and date_list[2].isdigit():
                    # Try to create a date object with these parameters
                    try:
                        future_date = datetime.datetime(int(date_list[2]),int(date_list[0]),int(date_list[1]))
                        d_obj_create = True
                    except ValueError as x:
                        d_obj_create = False
                    # If our time object was successfully created, test if our date_str is greater than the current time
                    if d_obj_create:
                        if future_date > date_now:
                            date_valid = True
    # Return our bool
    return date_valid

# check_remote_port tests if a remote port is open. This function will return True if the connection was successful.
def check_remote_port(HOST,PORT):
    check_connect = None    # Initialize check_connect a variable to track connection statuses
    not_resolve = None     # Initialize not_resolve for use in DNS resolution errors
    port_open = False    # Assign boolean variable to return from this function
    port_test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # Setup a socket for testing connections to a remote host and port
    port_test_sock.settimeout(0.5)    # Set the socket timeout time. This should be as low as possible to improve performance
    # Try to use the socket to connect to the remote port
    try:
        check_connect = port_test_sock.connect_ex((HOST,PORT))    # If the port test was successful, check_connect will be 0
        port_test_sock.close()    # Close the socket
    # If we could not connect, determine if it was a DNS issue and print error
    except socket.gaierror as sockErr:
        not_resolve = True
    # If the connection was established, return port_open as true. Otherwise false
    if check_connect == 0:
        port_open = True
    return port_open

# check_ssh_access() checks if pfSense is accessible via SSH w/ pubkey auth
def check_ssh_access(server):
    ssh_accessible = False    # Define our return bool
    ssh_keyword = "pfa"
    ssh_cmd = "ssh -o StrictHostKeyChecking=no -o BatchMode=yes " + server + " \"echo " + ssh_keyword + "\""    # Our SSH command
    # Check if port 22 is open
    if check_remote_port(server, 22):
        # Try to SSH to the server
        try:
            ssh_run = subprocess.check_output(ssh_cmd, shell=True, stderr=open(os.devnull, "w")).decode('utf-8').strip("\n\r ")
        except subprocess.CalledProcessError:
            ssh_run = ""
         # Check if our SSH command worked
        if ssh_run == ssh_keyword:
            ssh_accessible = True
    # Return our bool
    return ssh_accessible

# check_dns() checks the DNS server for existing A records
def check_dns(server, user, key, host, domain):
    # Local Variables
    record_exists = False # Set return value False by default
    record_dict = get_dns_entries(server, user, key)
    # Check if domain is valid
    if domain in record_dict["domains"]:
        # Check if host entry exists
        if host in record_dict["domains"][domain]:
            record_exists = True
    #Return boolean
    return record_exists

# check_permissions() tasks an HTTP response and determines whether a permissions error was thrown
def check_permissions(http_resp):
    # Local Variables
    permit = False    # Default our return value to false
    no_user_page = "<a href=\"index.php?logout\">No page assigned to this user! Click here to logout.</a>"    # HTML error page when user does not have any permissions
    # Check if our user receives responses indicating permissions failed
    if no_user_page not in http_resp["text"] and http_resp["req_url"].split("?")[0] == http_resp["resp_url"].split("?")[0]:
        permit = True    # Return a true value if our response looks normal
    # Return our boolean
    return permit

# check_dns_rebind_error() checks if access to the webconfigurator is denied due to a DNS rebind error
def check_dns_rebind_error(url, req_obj):
    # Local Variables
    http_response = req_obj["text"] if req_obj is not None else http_request(url, {}, {}, {}, 45, "GET")["text"]    # Get the HTTP response of the URL
    rebind_error = "Potential DNS Rebind attack detected"    # Assigns the error string to look for when DNS rebind error occurs
    rebind_found = False    # Assigns a boolean to track whether a rebind error was found. This is our return value
    # Check the HTTP response code for error message
    if rebind_error in http_response:
        rebind_found = True    # If the the HTTP response contains the error message, return true
    # Return our boolean
    return rebind_found

# check_auth() runs a basic authentication check. If the authentication is successful a true value is returned
def check_auth(server, user, key):
    # Local Variables
    auth_success = False    # Set the default return value to false
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)   # Assign our base URL
    auth_check_data = {"__csrf_magic": get_csrf_token(url + "/index.php", "GET"), "usernamefld": user, "passwordfld": key, "login": "Sign In"}    # Define a dictionary for our login POST data
    pre_auth_check = http_request(url + "/index.php", {}, {}, {}, 45, "GET")
    # Check that we're not already signed
    if not "class=\"fa fa-sign-out\"" in pre_auth_check["text"]:
        # Complete authentication
        auth_check = http_request(url + "/index.php", auth_check_data, {}, {}, 45, "POST")
        auth_success = True if not "Username or Password incorrect" in auth_check["text"] and "class=\"fa fa-sign-out\"" in auth_check["text"] else auth_success    # Return false if login failed
    # Else return true because we are already signed in
    else:
        auth_success = True
    return auth_success

# check_errors() consolidates all error check functions into one
def check_errors(server, user, key, priv_list):
    # Local variables
    ec = 2    # Init our error code to 2
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    get_base = http_request(url, None, None, None, 45, "GET")    # Get our base URL to check for errors
    # Submit our intitial request and check for errors
    ec = 10 if check_dns_rebind_error(url, get_base) else ec    # Return exit code 10 if dns rebind error found
    ec = 6 if not validate_platform(url, get_base) else ec    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ec == 2:
        ec = 3 if not check_auth(server, user, key) else ec    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if ec == 2:
        # Check that we had permissions for each page in priv_list, if we do not, break and return error 15
        for p in priv_list:
            priv_check = http_request(url + "/" + p, None, None, None, 45, "GET")
            if not check_permissions(priv_check):
                ec = 15
                break
    # Return our exit code
    return ec

# get_csrf_token() makes an initial connection to pfSense to retrieve the CSRF token. This supports both GET and POST requests
def get_csrf_token(url, type_var):
        # Local Variables
        csrf_token_length = 55  # Set the expected token length of the csrf token
        csrf_response = http_request(url, None, {}, {}, 45, type_var)
        # Parse CSRF token and conditionalize return value
        if "sid:" in csrf_response['text']:
            csrf_parsed = "sid:" + csrf_response['text'].split("sid:")[1].split(";")[0].replace(" ", "").replace("\n", "").replace("\"", "")
            csrf_token = csrf_parsed if len(csrf_parsed) is csrf_token_length else ""    # Assign the csrf_token to the parsed value if the expected string length is found
        # If we could not find a CSRF token
        else:
            csrf_token = ""    # Assign blank CSRF token as none was found
        return csrf_token    # Return our token

# run_ssh_cmd() runs a shell command via SSH
def run_ssh_cmd(server, cmd):
    ssh_output = {"ec": 2, "ssh_output": ""}    # Init our SSH cmd dictionary
    ssh_cmd = "ssh -o StrictHostKeyChecking=no -o BatchMode=yes " + server + " \"" + cmd + "\""    # Our SSH command
    # Check if SSH is accessible
    if check_ssh_access(server):
        # Try to run our command using SSH, if we catch an error return empty string
        try:
            ssh_resp = subprocess.check_output(ssh_cmd, shell=True, stderr=open(os.devnull, "w")).decode('utf-8')
        except subprocess.CalledProcessError as x:
            ssh_resp = ""
        # Format our dictionary values
        ssh_output["ec"] = 0
        ssh_output["ssh_output"] = ssh_resp
    return ssh_output

# get_pfsense_version() checks the version of pfSense
def get_pfsense_version(server, user, key):
    # Local variables
    pf_version = {"ec":2,"version":{"installed_version":""}}    # Initialize a dictionary to save version data
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    pf_version["ec"] = 10 if check_dns_rebind_error(url, None) else pf_version["ec"]    # Return exit code 10 if dns rebind error found
    pf_version["ec"] = 6 if not validate_platform(url, None) else pf_version["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if pf_version["ec"] == 2:
        pf_version["ec"] = 3 if not check_auth(server, user, key) else pf_version["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if pf_version["ec"] == 2:
        get_index_version_data = http_request(url + "/widgets/widgets/system_information.widget.php", {}, {}, {}, 45, "GET")    # Pull our version data using GET HTTP
        # Check that we had permissions for this page
        if check_permissions(get_index_version_data):
            # Check that we are able to find version on the index page
            expected_tag = "<th>Version</th>"
            if expected_tag in get_index_version_data["text"]:
                version_table_data = get_index_version_data["text"].split(expected_tag)[1].split("</tr>")[0]
                # Check that we have strong tags
                if "<strong>" in version_table_data:
                    pf_version_full_release = version_table_data.split("<strong>")[1].split("</strong>")[0]    # Capture our version data between the strong tags
                    pf_version_patch = pf_version_full_release.replace("RELEASE","").replace("-","").replace("p","_")    # Format our version to shorthand
                    pf_version["version"]["installed_version"] = pf_version_patch     # Save our formatted version
            # Update exit code to success
            pf_version["ec"] = 0 if pf_version["version"]["installed_version"] != "" else 2  # Set exit code 0 (success)
        # If we did not have permission to the necessary pages
        else:
            pf_version["ec"] = 15    # Set exit code 15 (permission denied)
    # Return our data dictionary
    return pf_version

# get_permissions_table() returns a dictionary file containing all user privileges, and their POST data values
def get_permissions_table(server, user, key):
    # Local variables
    prms = {"ec":2,"privileges":{}}    # Initialize a dictionary to populate our user database too
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    prms["ec"] = 10 if check_dns_rebind_error(url, None) else prms["ec"]    # Return exit code 10 if dns rebind error found
    prms["ec"] = 6 if not validate_platform(url, None) else prms["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if prms["ec"] == 2:
        prms["ec"] = 3 if not check_auth(server, user, key) else prms["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if prms["ec"] == 2:
        get_all_group_id = get_user_groups(server, user, key)    # Find the 'all' group ID, this group displays all available privileges
        # Check that we could find group containing all available permissions
        if get_all_group_id["ec"] == 0:
            get_prms_data = http_request(url + "/system_groupmanager_addprivs.php?groupid=" + get_all_group_id["groups"]["all"]["id"], {}, {}, {}, 45, "GET")    # Pull our users data using GET HTTP
            # Check that we had permissions for this page
            if check_permissions(get_prms_data):
                # Parse our HTML output to only return the privilege select tag
                permission_select = get_prms_data["text"].split("<select class=\"form-control multiselect\" name=\"sysprivs[]\" id=\"sysprivs[]\" multiple=\"multiple\">")[1].split("</select>")[0]
                permission_opt = permission_select.split("<option value=\"")    # Split our select tag into a list of selectable options
                del permission_opt[0]    # Delete first list item as it contains the data before our options
                # Loop through each option and gather it's info
                for opt in permission_opt:
                    # Assign default admin privileges in the case that we cannot pull them dynamically
                    defaul_adm_priv = """
                        User - System: Copy files (scp)<br/>User - System: Shell account access<br/>WebCfg - All pages<br/>
                        WebCfg - Diagnostics: Backup & Restore<br/>WebCfg - Diagnostics: Command<br/>WebCfg - Diagnostics: Edit File<br/>WebCfg - Diagnostics: Factory defaults<br/>
                        WebCfg - OpenVPN: Servers Edit Advanced<br/>WebCfg - OpenVPN: Client Specific Override Edit Advanced<br/>
                        WebCfg - OpenVPN: Clients Edit Advanced<br/>WebCfg - System: Authentication Servers<br/>WebCfg - System: Group Manager<br/>
                        WebCfg - System: Group Manager: Add Privileges<br/>WebCfg - System: User Manager<br/>WebCfg - System: User Manager: Add Privileges<br/>
                        WebCfg - System: User Manager: Settings
                    """
                    descr_name = opt.split(">")[1].split("</option")[0]    # Find our descriptive UI name for the privilege
                    http_name = opt.split("\"")[0]    # Find our POST name for the value
                    admin_priv_data = get_prms_data["text"].split("<span>Privilege information</span>")[1].split("</div>")[0] if "<span>Privilege information</span>" in get_prms_data["text"] else defaul_adm_priv    # Dynamically update privilege data if it's available, otherwise assume defaults
                    priv_level = "admin" if descr_name in admin_priv_data else "user"    # Check if our privilege is an admin privilege, otherwise assign it as a user privilege
                    priv_level = "readonly" if descr_name == "User - Config: Deny Config Write" else priv_level    # If privilege assigns readonly access, assign the privilege level to readonly
                    prms["privileges"][descr_name] = {"name":http_name,"level":priv_level}    # Initialize our individual privilege dictionary
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
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    users["ec"] = 10 if check_dns_rebind_error(url, None) else users["ec"]    # Return exit code 10 if dns rebind error found
    users["ec"] = 6 if not validate_platform(url, None) else users["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if users["ec"] == 2:
        users["ec"] = 3 if not check_auth(server, user, key) else users["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if users["ec"] == 2:
        # Check that we had permissions for this page
        get_user_data = http_request(url + "/system_usermanager.php", {}, {}, {}, 45, "GET")    # Pull our users data using GET HTTP
        if check_permissions(get_user_data):
            # Save our user permissions dictionary
            master_priv_dict = get_permissions_table(server, user, key)    # Pull the dictionary containing all privileges and their POST data names
            # Parse our HTML response and save user data if expected tags found
            if "<tbody>" in get_user_data["text"]:
                user_table_body = get_user_data["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save anything between tbody opening and closing tags
                user_table_rows = user_table_body.split("<tr>")    # Save our user table rows to a list
                # Check that our list has data
                if len(user_table_rows) > 0:
                    # Loop through our users and pull their data
                    for u in user_table_rows:
                        # Check that table data exists
                        if "<td>" in u:
                            # Split our row into data fields
                            user_table_data = u.split("<td>")
                            uname = user_table_data[2].replace("\t","").replace("\n","").replace(" ","").split("</i>")[1].split("</td>")[0]    # Save our username
                            uid = user_table_data[6].replace("\t","").replace("\n","").replace(" ","").split("?act=edit&amp;userid=")[1].split("\"></a>")[0]    # Save our user ID
                            # Now that we have our user ID, open the edit page to read more information
                            if uid.isdigit():
                                # Try to parse our values, if an error is thrown break the loop and return failed exit code
                                try:
                                    get_user_adv_data = http_request(url + "/system_usermanager.php?act=edit&userid=" + uid, {}, {}, {}, 45, "GET")    # Save our advanced user data
                                    priv_level = "user"    # Default each user to privilege level 'user' until determined otherwise
                                    defined_by = get_user_adv_data["text"].split("<span>Defined by</span>")[1].split("</div>")[0].replace("\t","").replace("\n","").split("<div class=\"col-sm-10\">")[1] if "<span>Defined by</span>" in get_user_adv_data["text"] else ""    # Save our defined by field
                                    disabled = "yes" if "checked=\"checked\"" in get_user_adv_data["text"].split("<span>Disabled</span>")[1].split("</div>")[0] else ""    # Save our disable login value
                                    full_name = get_user_adv_data["text"].split("<span>Full name</span>")[1].split("</div>")[0].split("value=\"")[1].split("\"")[0] if "<span>Full name</span>" in get_user_adv_data["text"] else ""  # Save our user's full name value
                                    exp_date = get_user_adv_data["text"].split("<span>Expiration date</span>")[1].split("</div>")[0].split("value=\"")[1].split("\"")[0] if defined_by == "USER" else ""    # Save our exp data if a USER defined user
                                    custom_ui = "yes" if "checked=\"checked\"" in get_user_adv_data["text"].split("<span>Custom Settings</span>")[1].split("</div>")[0] else ""    # Save our custom UI value
                                    auth_keys = get_user_adv_data["text"].split("=\"authorizedkeys\">")[1].split("</textarea>")[0] if "=\"authorizedkeys\">" in get_user_adv_data["text"] else ""   # Save our user's authorized keys
                                    ipsec_key_raw = get_user_adv_data["text"].split("<span>IPsec Pre-Shared Key</span>")[1].split("</div>")[0] if "<span>IPsec Pre-Shared Key</span>" in get_user_adv_data["text"] else ""   # Save entire table data value for IPsec keys, we need to be more granular with this value
                                    ipsec_key = ipsec_key_raw.split("value=\"")[1].split("\"")[0] if "value=" in ipsec_key_raw else ""    # If our IPsec key contains a value, save that value, otherwise assume default
                                except:
                                    users["ec"] = 2    # Return an error code
                                    break     # Break our loop as we are missing expected data
                                # Check our GROUP memberships
                                group_selection = get_user_adv_data["text"].split("name=\"groups[]\"")[1].split("</select>")[0] if "name=\"groups[]\"" in get_user_adv_data["text"] else ""    # Target our select tag for groups we are members of
                                group_list_raw = group_selection.split("<option value=\"") if "<option value=\"" in group_selection else [""]    # Create a unformatted list of groups we are members of
                                group_list = []    # Initialize our formatted list to be populated by our loop
                                # Loop through our list of groups and format the final list
                                del group_list_raw[0]    # Remove our first list item as it is before our target value
                                for g in group_list_raw:
                                    group_list.append(g.split("\"")[0])    # Add our formatted items to the list
                                # Check our USER PERMISSIONS
                                priv_table_body = get_user_adv_data["text"].split("<h2 class=\"panel-title\">Effective Privileges</h2>")[1].split("</i>Add</a></nav>")[0].split("<tbody>")[1].split("</tbody>")[0]
                                priv_table_rows = priv_table_body.split("<tr>") if "<tr>" in priv_table_body else ['']   # Split our table rows into a list
                                priv_dict = {}    # Create a dictionary to save our privilege data to
                                priv_dict["level"] = "user"  # Default to user privilege until determined otherwise
                                # Loop through our table rows and pull their data
                                del priv_table_rows[0]    # Remove our first row value as it contains data listed before table rows start
                                counter = 0    # Create a loop counter to track our loop iteration
                                for r in priv_table_rows:
                                    # Check that we are not on the last index
                                    if "Security notice" not in r:
                                        priv_dict[counter] = {}    # Create a dictionary for this privilege
                                        priv_dict[counter]["id"] = r.split("<td>")[4].split("id=\"")[1].split("\"")[0] if "id=\"" in r.split("<td>")[4] else ""
                                        priv_dict[counter]["inherited"] = r.split("<td>")[1].split("</td>")[0]
                                        priv_dict[counter]["descr_name"] = r.split("<td>")[2].split("</td>")[0]
                                        priv_dict[counter]["descr"] = r.split("<td>")[3].split("</td>")[0]
                                        priv_dict[counter]["name"] = master_priv_dict["privileges"][priv_dict[counter]["descr_name"]]["name"]
                                        # Check if our privilege level is admin and not readonly
                                        if master_priv_dict["privileges"][priv_dict[counter]["descr_name"]]["level"] == "admin" and priv_dict["level"] != "readonly":
                                            priv_dict["level"] = "admin"    # Set our privilege level to admin
                                        # Check if our privilege level is read only
                                        if master_priv_dict["privileges"][priv_dict[counter]["descr_name"]]["level"] == "readonly":
                                            priv_dict["level"] = "readonly"    # Set our privilege level to readonly
                                        counter = counter + 1    # Increase our counter
                                # Check our USER CERTIFICATES
                                cert_table_body = get_user_adv_data["text"].split("<h2 class=\"panel-title\">User Certificates</h2>")[1].split("</i>Add</a></nav>")[0].split("<tbody>")[1].split("</tbody>")[0]
                                cert_table_rows = cert_table_body.split("<tr>") if "<tr>" in priv_table_body else ['']  # Split our table rows into a list
                                cert_dict = {}  # Create a dictionary to save our cert data to
                                # Loop through our table rows and pull their data
                                del cert_table_rows[0]  # Remove our first row value as it contains data listed before table rows start
                                counter = 0  # Create a loop counter to track our loop iteration
                                for c in cert_table_rows:
                                    cert_dict[counter] = {}    # Create a dictionary for this privilege
                                    cert_dict[counter]["id"] = c.split("<td>")[3].split("id=\"")[1].split("\"")[0] if "id=\"" in c.split("<td>")[3] else ""
                                    cert_dict[counter]["name"] = c.split("<td>")[1].split("</td>")[0]
                                    cert_dict[counter]["ca"] = c.split("<td>")[2].split("</td>")[0]
                                # Check our USER CUSTOM UI values
                                ui_dict = {}    # Initialize a UI dictionary to track users UI settings
                                ui_select_tags = ["webguicss","webguifixedmenu","webguihostnamemenu"]
                                ui_text_tags = ["dashboardcolumns"]
                                ui_check_tags = ["interfacessort","dashboardavailablewidgetspanel","systemlogsfilterpanel","systemlogsmanagelogpanel",
                                               "statusmonitoringsettingspanel","webguileftcolumnhyper","disablealiaspopupdetail","pagenamefirst"]
                                # Loop through our SELECT input tags
                                for s in ui_select_tags:
                                    if "name=\""+s+"\"" in get_user_adv_data["text"]:
                                        user_gui_scheme = get_user_adv_data["text"].split("name=\""+s+"\"")[1].split("</select>")[0].split("<option value=\"")
                                        # Loop through our UI values and save our configuration
                                        for c in user_gui_scheme:
                                            # Check if this value is selected
                                            if "selected>" in c:
                                                ui_dict[s] = c.split("\"")[0]    # Save our value
                                                break    # Break the loop as we have found our value
                                            else:
                                                ui_dict[s] = ""    # Save default value
                                    else:
                                        ui_dict[s] = ""  # Save default value
                                # Loop through our CHECKBOX input tags
                                for x in ui_check_tags:
                                     # Check if we have a systemlogsfilterpanel option
                                    if "<input name=\""+x+"\"" in get_user_adv_data["text"]:
                                        ui_dict[x] = True if "checked" in get_user_adv_data["text"].split("<input name=\""+x+"\"")[1].split("</label>")[0] else False
                                    # If we do not have this option, assign empty string
                                    else:
                                        ui_dict[x] = ""
                                # Loop through our TEXT input tags
                                for t in ui_text_tags:
                                    if "name=\""+t+"\"" in get_user_adv_data["text"]:
                                        ui_dict[t] = get_user_adv_data["text"].split("name=\""+t+"\"")[1].split("value=\"")[1].split("\"")[0]  # Get our value
                                    # If we do not have this option, assign empty string
                                    else:
                                        ui_dict[t] = ""
                                # Save our values to user dictionary
                                users["users"][uname] = {
                                    "username" : uname,
                                    "id" : uid,
                                    "type" : defined_by,
                                    "disabled" : disabled,
                                    "full_name" : full_name,
                                    "expiration" : exp_date,
                                    "custom_ui" : custom_ui,
                                    "custom_ui_config" : ui_dict,
                                    "groups" : group_list,
                                    "privileges" : priv_dict,
                                    "user_certificates" : cert_dict,
                                    "authorized_keys" : auth_keys,
                                    "ipsec_keys" : ipsec_key
                                }
                        # Assign success exit code
                        users["ec"] = 0
        # If we did not have permissions to read user data
        else:
            users["ec"] = 15    # Assign exit code 15 (permission denied)
    return users

# add_user() creates a new webConfigurator user in system_usernamanger.php
def add_user(server, user, key, uname, enable, passwd, fname, exp_date, groups):
    # Local variables
    user_added = 2    # Initialize our return code as 2 (error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)  # Assign our base URL
    exist_users = get_users(server, user, key)    # Pull our existing user database
    # Check that we successfully pulled our existing users
    if exist_users["ec"] == 0:
        # Check that our desired username does not already exist
        if uname not in exist_users["users"]:
            # Format our POST data dictionary
            user_post_data = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php", "GET"),
                "usernamefld": uname,
                "disabled": enable,
                "passwordfld1": passwd,
                "passwordfld2": passwd,
                "descr": fname,
                "expires": exp_date,
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
            post_new_user = http_request(url + "/system_usermanager.php?act=new", user_post_data, {}, {}, 45, "POST")
            # Check if our user is now in our user database
            update_exist_users = get_users(server, user, key)
            if uname in update_exist_users["users"]:
                user_added = 0    # Return exit code 0 (success
        # If our user already exists
        else:
            user_added = 4    # Return exit code 4 (user already exists)
    # If we encountered an error pulling our existing users, return the exit code of the get_users() function
    else:
        user_added = exist_users["ec"]
    # Return our exit code value
    return user_added

# del_user() deletes a user given a username or user ID
def del_user(server, user, key, uid):
    # Local variables
    user_del = 2    # Assign our return code default as 2 (error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    exist_users = get_users(server, user, key)    # Pull our current user configuration
    # Check that we pulled our users successfully
    if exist_users["ec"] == 0:
        usr_found = False    # Assign a bool to track whether or not our user was found
        # Check that our user exists
        if uid in exist_users["users"]:
            uname = uid    # Save our uname as our uid
            id_var = exist_users["users"][uname]["id"]    # Pull our pfSense user ID from the dictionary for this user
            usr_found = True
        # If our username was not found, check if the user ID passed in is an ID number
        elif uid.isdigit():
            # Loop through our users and check for a user ID match
            for u,data in exist_users["users"].items():
                # Check if the ID matches our input
                if data["id"] == uid:
                    uname = u    # Save our username
                    id_var = data["id"]    # Save our ID
                    usr_found = True
                    break    # Break our loop, we only need one set of values
        # If we could not find a user, return exit code 4
        else:
            user_del = 4    # Return exit code 4 (user not found)
        # Check if our user was found, if so run our command
        if usr_found:
            # Create a diciontary with our formatted POST values
            del_usr_post_data = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php", "GET"),
                "act": "deluser",
                "username": uname,
                "userid": id_var
            }
            # Run our POST request, then update our current users dictionary to check if the user no longer exists
            del_user_post = http_request(url + "/system_usermanager.php", del_usr_post_data, {}, {}, 45, "POST")
            update_users = get_users(server, user, key)    # Pull our updated user configuration
            if update_users["ec"] == 0 and uname not in update_users["users"]:
                user_del = 0    # Return our success return code 0
    # If we could not pull our user configuration, return the error code returned from get_users()
    else:
        user_del = exist_users["ec"]
    # Return our exit value
    return user_del


# add_user_key() adds a new public key for either SSH or IPsec
def add_user_key(server, user, key, uname, key_type, pub_key, destruct):
    # Local variables
    key_added = 2    # Init our return code as 2 (error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    exist_users = get_users(server, user, key)    # Pull our existing user configuration
    # Check that we pulled our users successfully
    if exist_users["ec"] == 0:
        # Check if our user exists
        if uname in exist_users["users"]:
            uid = exist_users["users"][uname]["id"]    # Pull our user's pf ID
            # Check if our key type is SSH
            if key_type.lower() == "ssh":
                pub_key = exist_users["users"][uname]["authorized_keys"] + "\n" + pub_key if not destruct else pub_key    # Check if user simply wants to append a new key or replace all keys
            # Format our POST request data
            key_post_data = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php?act=edit&userid=" + uid, "GET"),
                "act": "edit",
                "usernamefld": uname,
                "disabled": exist_users["users"][uname]["disabled"],
                "descr": exist_users["users"][uname]["full_name"],
                "expires": exist_users["users"][uname]["expiration"],
                "groups[]":  exist_users["users"][uname]["groups"],
                "utype":  exist_users["users"][uname]["type"],
                "customsettings": exist_users["users"][uname]["custom_ui"],
                "webguicss": exist_users["users"][uname]["custom_ui_config"]["webguicss"],
                "webguifixedmenu": exist_users["users"][uname]["custom_ui_config"]["webguifixedmenu"],
                "interfacessort": "yes" if exist_users["users"][uname]["custom_ui_config"]["interfacessort"] else "",
                "dashboardavailablewidgetspanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["dashboardavailablewidgetspanel"] else "",
                "systemlogsfilterpanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["systemlogsfilterpanel"] else "",
                "systemlogsmanagelogpanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["systemlogsmanagelogpanel"] else "",
                "statusmonitoringsettingspanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["statusmonitoringsettingspanel"] else "",
                "webguileftcolumnhyper": "yes" if exist_users["users"][uname]["custom_ui_config"]["webguileftcolumnhyper"] else "",
                "disablealiaspopupdetail": "yes" if exist_users["users"][uname]["custom_ui_config"]["disablealiaspopupdetail"] else "",
                "pagenamefirst": "yes" if exist_users["users"][uname]["custom_ui_config"]["pagenamefirst"] else "",
                "webguihostnamemenu": exist_users["users"][uname]["custom_ui_config"]["webguihostnamemenu"],
                "dashboardcolumns": exist_users["users"][uname]["custom_ui_config"]["dashboardcolumns"],
                "authorizedkeys":  pub_key if key_type.lower() == "ssh" else exist_users["users"][uname]["authorized_keys"],
                "ipsecpsk":  pub_key if key_type.lower() == "ipsec" else exist_users["users"][uname]["ipsec_keys"],
                "userid": uid,
                "save": "Save"
            }
            # Make our POST request
            key_post = http_request(url + "/system_usermanager.php?act=edit&userid=" + uid, key_post_data, {}, {}, 45, "POST")
            # Check that our keys are now updated
            update_exist_users = get_users(server, user, key)    # Update our user configuration
            if update_exist_users["ec"] == 0:
                if key_type.lower() == "ssh":
                    key_added = 0 if update_exist_users["users"][uname]["authorized_keys"] == pub_key else key_added    # If our input matches our configuration, return 0 (success)
                if key_type.lower() == "ipsec":
                    key_added = 0 if update_exist_users["users"][uname]["ipsec_keys"] == pub_key else key_added    # If our input matches our configuration, return 0 (success)
        # If our user does not exist
        else:
            key_added = 4    # Return code 4 (user not found)
    # If we could not pull our existing users, return the non-zero return code received from get_users()
    else:
        key_added = exist_users["ec"]
    # Return our code
    return key_added

# change_user_passwd() changes an existing user's password
def change_user_passwd(server, user, key, uname, passwd):
    # Local variables
    passwd_changed = 2    # Init our return code as 2 (error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    exist_users = get_users(server, user, key)    # Pull our existing user configuration
    # Check that we pulled our users successfully
    if exist_users["ec"] == 0:
        # Check if our user exists
        if uname in exist_users["users"]:
            uid = exist_users["users"][uname]["id"]    # Pull our user's pf ID
            # Format our POST request data
            ch_pass_data = {
                "__csrf_magic": get_csrf_token(url + "/system_usermanager.php?act=edit&userid=" + uid, "GET"),
                "act": "edit",
                "passwordfld1": passwd,
                "passwordfld2": passwd,
                "usernamefld": uname,
                "disabled": exist_users["users"][uname]["disabled"],
                "descr": exist_users["users"][uname]["full_name"],
                "expires": exist_users["users"][uname]["expiration"],
                "groups[]":  exist_users["users"][uname]["groups"],
                "utype":  exist_users["users"][uname]["type"],
                "customsettings": exist_users["users"][uname]["custom_ui"],
                "webguicss": exist_users["users"][uname]["custom_ui_config"]["webguicss"],
                "webguifixedmenu": exist_users["users"][uname]["custom_ui_config"]["webguifixedmenu"],
                "interfacessort": "yes" if exist_users["users"][uname]["custom_ui_config"]["interfacessort"] else "",
                "dashboardavailablewidgetspanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["dashboardavailablewidgetspanel"] else "",
                "systemlogsfilterpanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["systemlogsfilterpanel"] else "",
                "systemlogsmanagelogpanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["systemlogsmanagelogpanel"] else "",
                "statusmonitoringsettingspanel": "yes" if exist_users["users"][uname]["custom_ui_config"]["statusmonitoringsettingspanel"] else "",
                "webguileftcolumnhyper": "yes" if exist_users["users"][uname]["custom_ui_config"]["webguileftcolumnhyper"] else "",
                "disablealiaspopupdetail": "yes" if exist_users["users"][uname]["custom_ui_config"]["disablealiaspopupdetail"] else "",
                "pagenamefirst": "yes" if exist_users["users"][uname]["custom_ui_config"]["pagenamefirst"] else "",
                "webguihostnamemenu": exist_users["users"][uname]["custom_ui_config"]["webguihostnamemenu"],
                "dashboardcolumns": exist_users["users"][uname]["custom_ui_config"]["dashboardcolumns"],
                "authorizedkeys":  exist_users["users"][uname]["authorized_keys"],
                "ipsecpsk":  exist_users["users"][uname]["ipsec_keys"],
                "userid": uid,
                "save": "Save"
            }
            # Make our POST request
            ch_pass_post = http_request(url + "/system_usermanager.php?act=edit&userid=" + uid, ch_pass_data, {}, {}, 45, "POST")
            # Check that we did not encounter errors
            if ch_pass_post["resp_url"] == url + "/system_usermanager.php":
                passwd_changed = 0    # Assign return code 0 (success)
        # If our user does not exist
        else:
            passwd_changed = 4    # Return code 4 (user not found)
    # If we could not pull our existing users, return the non-zero return code received from get_users()
    else:
        passwd_changed = exist_users["ec"]
    # Return our code
    return passwd_changed

# get_user_groups() pulls information from system_groupmanager.php and formats all data about configured user groups
def get_user_groups(server, user, key):
    # Local variables
    groups = {"ec":2,"groups":{}}    # Initialize a dictionary to populate our user database too
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    groups["ec"] = 10 if check_dns_rebind_error(url, None) else groups["ec"]    # Return exit code 10 if dns rebind error found
    groups["ec"] = 6 if not validate_platform(url, None) else groups["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if groups["ec"] == 2:
        groups["ec"] = 3 if not check_auth(server, user, key) else groups["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if groups["ec"] == 2:
        # Check that we had permissions for this page
        get_group_data = http_request(url + "/system_groupmanager.php", {}, {}, {}, 45, "GET")    # Pull our groups data using GET HTTP
        if check_permissions(get_group_data):
            # Check that we have table information
            if "<tbody>" in get_group_data["text"]:
                group_table_body = get_group_data["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save all data between our tbody HTML tags
                group_table_rows = group_table_body.split("<tr>")    # Split our tbody into list of table rows
                del group_table_rows[0]    # Remove first item as it contains all the data before our table rows
                # Loop through our rows and gather our data
                for g in group_table_rows:
                    g = g.replace("\t","").replace("\n","")    # Remove whitespace
                    group_name = g.split("<td>")[1].split("</td>")[0]    # Save our group name
                    group_descr = g.split("<td>")[2].split("</td>")[0]    # Save our group description
                    group_count = g.split("<td>")[3].split("</td>")[0]    # Save our group member count
                    group_id = g.split("<td>")[4].split("</td>")[0].split("groupid=")[1].split("\">")[0]    # Save our group ID
                    groups["groups"][group_name] = {"name":group_name,"descr":group_descr,"count":group_count,"id":group_id}    # Define a nested dict for our current group
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
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    general["ec"] = 10 if check_dns_rebind_error(url, None) else general["ec"]    # Return exit code 10 if dns rebind error found
    general["ec"] = 6 if not validate_platform(url, None) else general["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if general["ec"] == 2:
        general["ec"] = 3 if not check_auth(server, user, key) else general["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if general["ec"] == 2:
        # Check that we had permissions for this page
        get_general_data = http_request(url + "/system.php", {}, {}, {}, 45, "GET")    # Pull our admin data using GET HTTP
        if check_permissions(get_general_data):
            # Check that we have a SYSTEM table
            if "<h2 class=\"panel-title\">System</h2>" in get_general_data["text"]:
                # Split our response to get our System table configuration
                system_table = get_general_data["text"].split("<h2 class=\"panel-title\">System</h2>")[1].split("<span class=\"help-block\">Do not use '.local'")[0]
                general["general"]["system"]["hostname"] = system_table.split("name=\"hostname\"")[1].split("value=\"")[1].split("\"")[0] if "name=\"hostname\"" in system_table else ""    # Get our hostname value
                general["general"]["system"]["domain"] = system_table.split("name=\"domain\"")[1].split("value=\"")[1].split("\"")[0] if "name=\"domain\"" in system_table else ""    # Get our domain value
            # Check that we have a DNS table
            if "<h2 class=\"panel-title\">DNS Server Settings</h2>" in get_general_data["text"]:
                dns_table = get_general_data["text"].split("<h2 class=\"panel-title\">DNS Server Settings</h2>")[1].split("<span class=\"help-block\">By default localhost (127.0.0.1)")[0]
                # Check if we have a DNS WAN override option
                if "<input name=\"dnsallowoverride\"" in dns_table:
                    general["general"]["dns"]["dnsallowoverride"] = True if "checked" in dns_table.split("<input name=\"dnsallowoverride\"")[1].split("</label>")[0] else False
                # If not, assume default
                else:
                    general["general"]["dns"]["dnsallowoverride"] = False
                 # Check if we have a dns localhost option
                if "<input name=\"dnslocalhost\"" in dns_table:
                    general["general"]["dns"]["dnslocalhost"] = True if "checked" in dns_table.split("<input name=\"dnslocalhost\"")[1].split("</label>")[0] else False
                # If not, assume default
                else:
                    general["general"]["dns"]["dnslocalhost"] = False
                # Loop through our configured DNS servers and save there values to our dictionary
                counter = 0    # Assign a counter
                while True:
                    # Check that we have a DNS server configured for this counter value
                    if "name=\"dns" + str(counter) in dns_table:
                        general["general"]["dns"]["servers"][counter] = {}    # Create a nested dict for our current counter
                        general["general"]["dns"]["servers"][counter]["id"] = str(counter)    # Assign our counter value to the dict
                        general["general"]["dns"]["servers"][counter]["ip"] = dns_table.split("name=\"dns" + str(counter) + "\"")[1].split("value=\"")[1].split("\"")[0]
                        general["general"]["dns"]["servers"][counter]["hostname"] = dns_table.split("name=\"dnshost" + str(counter) + "\"")[1].split("value=\"")[1].split("\"")[0] if "name=\"dnshost" + str(counter) + "\"" in dns_table else ""    # Assign our DNS hostname value if present
                        # Check that we have a gateway selection option
                        if "name=\"dnsgw" + str(counter) + "\"" in dns_table:
                            # Split our output to a list of gateway options, loop through this list and find the selected value
                            dns_gw_table = dns_table.split("name=\"dnsgw" + str(counter) + "\"")[1].split("</select>")[0].split("<option value=\"")
                            for gw in dns_gw_table:
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
                    elif "name=\"dns" + str(counter + 1) in dns_table:
                        pass    # Do nothing, this will allow us to increase the counter even though this iteration did nothing
                    # If we have made it through all our DNS servers and the next value does not exist
                    else:
                        break   # Break the loop
                    # Increase our counter
                    counter = counter + 1
            # Check that we have a LOCALIZATION table
            if "<h2 class=\"panel-title\">Localization</h2>" in get_general_data["text"]:
                local_table = get_general_data["text"].split("<h2 class=\"panel-title\">Localization</h2>")[1].split("<span class=\"help-block\">Choose a language")[0]   # Split HTML into specific section
                # Check if we have a timeserver configuration
                if "name=\"timeservers\"" in local_table:
                    general["general"]["localization"]["timeservers"] = local_table.split("name=\"timeservers\"")[1].split("value=\"")[1].split("\"")[0]    # Save our timeservers
                # Check that we have a timezone configuration
                if "name=\"timezone\"" in local_table:
                    # Loop through our timezones and find our currently selected timezone
                    time_table = local_table.split("name=\"timezone\"")[1].split("</select>")[0].split("<option value=\"")
                    for tz in time_table:
                        # Check if this value is selected
                        if "selected>" in tz:
                            general["general"]["localization"]["timezone"] = tz.split("\"")[0]    # Save our timezone
                            break    # Break the loop as we have found our value
                        else:
                            general["general"]["localization"]["timezone"] = ""    # Save default timezone
                # Check that we have a language configuration
                if "name=\"language\"" in local_table:
                    # Loop through our languages and find our currently selected language
                    lang_table = local_table.split("name=\"language\"")[1].split("</select>")[0].split("<option value=\"")
                    for lg in lang_table:
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
            if "<h2 class=\"panel-title\">webConfigurator</h2>" in get_general_data["text"]:
                wc_table = get_general_data["text"].split("<h2 class=\"panel-title\">webConfigurator</h2>")[1].split("<script type=\"text/javascript\">")[0]   # Split HTML into specific section
                # Check if we have a pfSense color scheme configuration
                if "name=\"webguicss\"" in wc_table:
                    # Loop through our color schemes and find our currently selected color scheme
                    wc_gui_scheme = wc_table.split("name=\"webguicss\"")[1].split("</select>")[0].split("<option value=\"")
                    for c in wc_gui_scheme:
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
                if "name=\"webguifixedmenu\"" in wc_table:
                     # Loop through our UI menu fix values and find our currently selected UI menu fix
                    wc_gui_fixed = wc_table.split("name=\"webguifixedmenu\"")[1].split("</select>")[0].split("<option value=\"")
                    for f in wc_gui_fixed:
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
                if "name=\"webguihostnamemenu\"" in wc_table:
                     # Loop through our webguihostnamemenu and find our currently selected webguihostnamemenu
                    wc_gui_host = wc_table.split("name=\"webguihostnamemenu\"")[1].split("</select>")[0].split("<option value=\"")
                    for h in wc_gui_host:
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
                if "name=\"logincss\"" in wc_table:
                     # Loop through our logincss and find our currently selected logincss
                    wc_login_color = wc_table.split("name=\"logincss\"")[1].split("</select>")[0].split("<option value=\"")
                    for lc in wc_login_color:
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
                if "name=\"dashboardcolumns\"" in wc_table:
                    general["general"]["webconfigurator"]["dashboardcolumns"] = wc_table.split("name=\"dashboardcolumns\"")[1].split("value=\"")[1].split("\"")[0]     # Get our value
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["dashboardcolumns"] = ""
                # Check if we have a dnslocalhost option
                if "<input name=\"interfacessort\"" in wc_table:
                    general["general"]["webconfigurator"]["interfacessort"] = True if "checked" in wc_table.split("<input name=\"interfacessort\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["interfacessort"] = ""
                # Check if we have a dashboardavailablewidgetspanel option
                if "<input name=\"dashboardavailablewidgetspanel\"" in wc_table:
                    general["general"]["webconfigurator"]["dashboardavailablewidgetspanel"] = True if "checked" in wc_table.split("<input name=\"dashboardavailablewidgetspanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["dashboardavailablewidgetspanel"] = ""
                # Check if we have a systemlogsfilterpanel option
                if "<input name=\"systemlogsfilterpanel\"" in wc_table:
                    general["general"]["webconfigurator"]["systemlogsfilterpanel"] = True if "checked" in wc_table.split("<input name=\"systemlogsfilterpanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["systemlogsfilterpanel"] = ""
                # Check if we have a systemlogsmanagelogpanel option
                if "<input name=\"systemlogsmanagelogpanel\"" in wc_table:
                    general["general"]["webconfigurator"]["systemlogsmanagelogpanel"] = True if "checked" in wc_table.split("<input name=\"systemlogsmanagelogpanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["systemlogsmanagelogpanel"] = ""
                # Check if we have a systemlogsmanagelogpanel option
                if "<input name=\"statusmonitoringsettingspanel\"" in wc_table:
                    general["general"]["webconfigurator"]["statusmonitoringsettingspanel"] = True if "checked" in wc_table.split("<input name=\"statusmonitoringsettingspanel\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["statusmonitoringsettingspanel"] = ""
                # Check if we have a requirestatefilter option
                if "<input name=\"requirestatefilter\"" in wc_table:
                    general["general"]["webconfigurator"]["requirestatefilter"] = True if "checked" in wc_table.split("<input name=\"requirestatefilter\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["requirestatefilter"] = ""
                # Check if we have a webguileftcolumnhyper option
                if "<input name=\"webguileftcolumnhyper\"" in wc_table:
                    general["general"]["webconfigurator"]["webguileftcolumnhyper"] = True if "checked" in wc_table.split("<input name=\"webguileftcolumnhyper\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["webguileftcolumnhyper"] = ""
                # Check if we have a disablealiaspopupdetail option
                if "<input name=\"disablealiaspopupdetail\"" in wc_table:
                    general["general"]["webconfigurator"]["disablealiaspopupdetail"] = True if "checked" in wc_table.split("<input name=\"disablealiaspopupdetail\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["disablealiaspopupdetail"] = ""
                # Check if we have a roworderdragging option
                if "<input name=\"roworderdragging\"" in wc_table:
                    general["general"]["webconfigurator"]["roworderdragging"] = True if "checked" in wc_table.split("<input name=\"roworderdragging\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["roworderdragging"] = ""
                # Check if we have a loginshowhost option
                if "<input name=\"loginshowhost\"" in wc_table:
                    general["general"]["webconfigurator"]["loginshowhost"] = True if "checked" in wc_table.split("<input name=\"loginshowhost\"")[1].split("</label>")[0] else False
                # If we do not have this option, assign empty string
                else:
                    general["general"]["webconfigurator"]["loginshowhost"] = ""
                # Check if we have a dashboardperiod option
                if "name=\"dashboardperiod\"" in wc_table:
                    general["general"]["webconfigurator"]["dashboardperiod"] = wc_table.split("name=\"dashboardperiod\"")[1].split("value=\"")[1].split("\"")[0]     # Get our value
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
    post_data = {}    # Pre-define our return value as empty dictionary
    # Loop through our existing /system_advanced_admin.php configuration and add the data to the POST request
    for table, data in dictionary.items():
        # Loop through each value in the table dictionaries
        for key, value in data.items():
            value = "yes" if value == True else value  # Swap true values to "yes"
            value = "" if value == False else value  # Swap false values to empty string
            # Check if we are checking our login protection whitelist
            if key == "servers":
                # Add each of our whitelisted IPs to our post data
                for id_var, info in value.items():
                    dns_id = info["id"]
                    post_data["dns" + dns_id] = info["ip"]
                    post_data["dnshost" + dns_id] = info["hostname"]
                    post_data["dnsgw" + dns_id] = info["gateway"]
            # If we are not adding whitelist values, simply add the key and value
            else:
                post_data[key] = value  # Populate our data to our POST data
    # Return our POST data dictionary
    return post_data

# set_system_hostname() assigns the hostname and domain value in /system.php
def set_system_hostname(server, user, key, host, domain):
    # Local variables
    set_sys_host_ec = 2    # Assign our default exit code (unexpected error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_sys_host = get_general_setup(server, user, key)    # Assign dictionary of existing general setup configuration
    # Check if we got our general setup dictionary successfully
    if existing_sys_host["ec"] == 0:
        # FORMAT OUR POST DATA
        sys_host_post_data = get_general_setup_post_data(existing_sys_host["general"])    # Convert our general data into a POST dictionary
        # Update our CSRF, save value, and take our POST request and save a new GET request that should show our new configuration
        sys_host_post_data["__csrf_magic"] = get_csrf_token(url + "/system.php", "GET")
        sys_host_post_data["save"] = "Save"
        # Check that we do not want to retain our current value
        if host.upper() != "DEFAULT":
            sys_host_post_data["hostname"] = host    # Save our host POST value
        # Check that we do not want to retain our current value
        if domain.upper() != "DEFAULT":
            sys_host_post_data["domain"] = domain    # Save our domain value to our POST data
        if set_sys_host_ec == 2:
            # Loop pulling our updated config, if DNS rebind is detected try switching the pfSense server to the new hostname
            update_count = 0    # Assign a loop counter
            while True:
                post_sys_host = http_request(url + "/system.php", sys_host_post_data, {}, {}, 45, "POST")    # Run our POST request
                new_sys_host = get_general_setup(server, user, key)    # Pull our updated configuration to check against our post data
                if new_sys_host["ec"] == 10:
                    server = sys_host_post_data["hostname"] + "." + sys_host_post_data["domain"]    # Try to use our new hostname if we experience a DNS rebind
                # If we did not experience a DNS rebind error, break the loop
                else:
                    break
                # If we ran through our loop three times assign a separate exit code
                if update_count > 3:
                    set_sys_host_ec = 9    # Assign our could not update exit code
                    break
                update_count = update_count + 1    # Increase our counter
            # Format our configuration dictionary back into a POST dictionary
            new_sys_host_post_data = get_general_setup_post_data(new_sys_host["general"])
            sys_host_post_data.pop("__csrf_magic", None)    # Remove our previous CSRF token so we can compare only configuration values below
            sys_host_post_data.pop("save", None)    # Remove our previous save value so we can compare only configuration values below
            # Check that our values were updated
            if new_sys_host_post_data == sys_host_post_data:
                set_sys_host_ec = 0    # Assign our success exit code
    # If we could not successfully pull our general setup configuration, return the exit code of that function
    else:
        set_sys_host_ec = existing_sys_host["ec"]
    # Return our exit code
    return set_sys_host_ec

# get_ha_sync() pulls our current HA configuration from system_hasync.php
def get_ha_sync(server, user, key):
    # Local variables
    ha_sync = {"ec": 2, "ha_sync" : {}}    # Pre-define our data dictionary
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    ha_sync["ec"] = 10 if check_dns_rebind_error(url, None) else ha_sync["ec"]    # Return exit code 10 if dns rebind error found
    ha_sync["ec"] = 6 if not validate_platform(url, None) else ha_sync["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ha_sync["ec"] == 2:
        ha_sync["ec"] = 3 if not check_auth(server, user, key) else ha_sync["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if ha_sync["ec"] == 2:
        # Check that we had permissions for this page
        get_ha_sync_data = http_request(url + "/system_hasync.php", {}, {}, {}, 45, "GET")    # Pull our admin data using GET HTTP
        if check_permissions(get_ha_sync_data):
            # Create a list of all CHECKBOX INPUTS to gather values from
            check_box_values = [
                "pfsyncenabled","synchronizeusers","synchronizeauthservers","synchronizecerts","synchronizerules","synchronizeschedules",
                "synchronizealiases","synchronizenat","synchronizeipsec","synchronizeopenvpn","synchronizedhcpd",
                "synchronizewol","synchronizestaticroutes","synchronizelb","synchronizevirtualip","synchronizetrafficshaper",
                "synchronizetrafficshaperlimiter","synchronizednsforwarder","synchronizecaptiveportal"
            ]
            # Loop through our checkbox inputs and save their values
            for cb in check_box_values:
                # Check that we have our expected input tag
                expected_tag = "<input name=\""+cb+"\""
                if expected_tag in get_ha_sync_data["text"]:
                    ha_sync["ha_sync"][cb] = "on" if "checked=\"checked\"" in get_ha_sync_data["text"].split(expected_tag)[1].split("</label>")[0] else ""    # Save "yes" if check box is checked, otherwise empty string
                # If we did not find this input tag in our HTML response
                else:
                    ha_sync["ha_sync"][cb] = ""    # Assume default
            # Create a list of all TEXT INPUTS to gather values from
            text_values = ["pfsyncpeerip","synchronizetoip","username"]
            # Loop through our checkbox inputs and save their values
            for txt in text_values:
                ha_sync["ha_sync"][txt] = ""    # Assume default
                # Check that we have our expected input tag
                expected_tag = "id=\""+txt+"\" type=\"text\""
                if expected_tag in get_ha_sync_data["text"]:
                    # Check that we have a value
                    if "value=\"" in get_ha_sync_data["text"].split(expected_tag)[1].split(">")[0]:
                        ha_sync["ha_sync"][txt] = get_ha_sync_data["text"].split(expected_tag)[1].split(">")[0].split("value=\"")[1].split("\"")[0]   # Save our text input's value
            # Check our SELECT INPUTS to gather selected values
            expected_tag = "<select class=\"form-control\" name=\"pfsyncinterface\" id=\"pfsyncinterface\">"
            if expected_tag in get_ha_sync_data["text"]:
                select_data = get_ha_sync_data["text"].split(expected_tag)[1].split("</select>")[0]    # Capture data between our select tags
                select_options = select_data.split("<option")    # Split our select data into list of option tags
                # Loop through our options and find our selected value
                for opt in select_options:
                    # Check if selected keyword is found
                    if "selected>" in opt:
                        ha_sync["ha_sync"]["pfsyncinterface"] = opt.split("value=\"")[1].split("\"")[0]    # Save our selected option value
                        break    # Break our loop as we only expect one value
                    # Otherwise assume default
                    else:
                        ha_sync["ha_sync"]["pfsyncinterface"] = ""    # Assign default
            # If we did not found our expected select tag, assume default
            else:
                ha_sync["ha_sync"]["pfsyncinterface"] = ""    # Assign default
            # Assign success exit code
            ha_sync["ec"] = 0    # Assign exit code 0 (success)
        # If we did not have permission to the necessary pages
        else:
            ha_sync["ec"] = 15    # ASsign exit code 15 (permission denied)
    # Return our HA sync dictionary
    return ha_sync

# setup_hasync() configures HA availability syncing from System > HA Sync.
def setup_hasync(server, user, key, enable_pfsync, pfsync_if, pfsync_ip, xmlsync_ip, xmlsync_uname, xmlsync_pass, xmlsync_options):
    # Local variables
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)  # Assign our base URL
    hasync_setup = 2    # Initialize our return code as 2 (error)
    hasync_conf = get_ha_sync(server, user, key)    # Pull our existing HA sync config
    # Check that we could pull our existing config
    if hasync_conf["ec"] == 0:
        # Format our POST data dictionary
        hasync_post_data = {
            "__csrf_magic": get_csrf_token(url + "/system_hasync.php","GET"),
            "pfsyncenabled": enable_pfsync.lower() if enable_pfsync.lower() in ["on", ""] else hasync_conf["ha_sync"]["pfsyncenabled"],
            "pfsyncinterface": pfsync_if if pfsync_if.lower() != "default" else hasync_conf["ha_sync"]["pfsyncinterface"],
            "pfsyncpeerip": pfsync_ip if pfsync_ip.lower() != "default" else hasync_conf["ha_sync"]["pfsyncpeerip"],
            "synchronizetoip": xmlsync_ip if xmlsync_ip.lower() != "default" else hasync_conf["ha_sync"]["synchronizetoip"],
            "username": xmlsync_uname if xmlsync_uname.lower() != "default" else hasync_conf["ha_sync"]["username"],
            "passwordfld": xmlsync_pass if xmlsync_pass.lower() != "default" else None,
            "passwordfld_confirm": xmlsync_pass if xmlsync_pass.lower() != "default" else None,
            "synchronizeusers": xmlsync_options["synchronizeusers"] if xmlsync_options["synchronizeusers"].lower() != "default" else hasync_conf["ha_sync"]["synchronizeusers"],
            "synchronizeauthservers": xmlsync_options["synchronizeauthservers"] if xmlsync_options["synchronizeauthservers"].lower() != "default" else hasync_conf["ha_sync"]["synchronizeauthservers"],
            "synchronizecerts": xmlsync_options["synchronizecerts"] if xmlsync_options["synchronizecerts"].lower() != "default" else hasync_conf["ha_sync"]["synchronizecerts"],
            "synchronizerules": xmlsync_options["synchronizerules"] if xmlsync_options["synchronizerules"].lower() != "default" else hasync_conf["ha_sync"]["synchronizerules"],
            "synchronizeschedules": xmlsync_options["synchronizeschedules"] if xmlsync_options["synchronizeschedules"].lower() != "default" else hasync_conf["ha_sync"]["synchronizeschedules"],
            "synchronizealiases": xmlsync_options["synchronizealiases"] if xmlsync_options["synchronizealiases"].lower() != "default" else hasync_conf["ha_sync"]["synchronizealiases"],
            "synchronizenat": xmlsync_options["synchronizenat"] if xmlsync_options["synchronizenat"].lower() != "default" else hasync_conf["ha_sync"]["synchronizenat"],
            "synchronizeopenvpn": xmlsync_options["synchronizeopenvpn"] if xmlsync_options["synchronizeopenvpn"].lower() != "default" else hasync_conf["ha_sync"]["synchronizeopenvpn"],
            "synchronizedhcpd": xmlsync_options["synchronizedhcpd"] if xmlsync_options["synchronizedhcpd"].lower() != "default" else hasync_conf["ha_sync"]["synchronizedhcpd"],
            "synchronizewol": xmlsync_options["synchronizewol"] if xmlsync_options["synchronizewol"].lower() != "default" else hasync_conf["ha_sync"]["synchronizewol"],
            "synchronizeipsec": xmlsync_options["synchronizeipsec"] if xmlsync_options["synchronizeipsec"].lower() != "default" else hasync_conf["ha_sync"]["synchronizeipsec"],
            "synchronizestaticroutes": xmlsync_options["synchronizestaticroutes"] if xmlsync_options["synchronizestaticroutes"].lower() != "default" else hasync_conf["ha_sync"]["synchronizestaticroutes"],
            "synchronizelb": xmlsync_options["synchronizelb"] if xmlsync_options["synchronizelb"].lower() != "default" else hasync_conf["ha_sync"]["synchronizelb"],
            "synchronizevirtualip": xmlsync_options["synchronizevirtualip"] if xmlsync_options["synchronizevirtualip"].lower() != "default" else hasync_conf["ha_sync"]["synchronizevirtualip"],
            "synchronizetrafficshaper": xmlsync_options["synchronizetrafficshaper"] if xmlsync_options["synchronizetrafficshaper"].lower() != "default" else hasync_conf["ha_sync"]["synchronizetrafficshaper"],
            "synchronizetrafficshaperlimiter": xmlsync_options["synchronizetrafficshaperlimiter"] if xmlsync_options["synchronizetrafficshaperlimiter"].lower() != "default" else hasync_conf["ha_sync"]["synchronizetrafficshaperlimiter"],
            "synchronizednsforwarder": xmlsync_options["synchronizednsforwarder"] if xmlsync_options["synchronizednsforwarder"].lower() != "default" else hasync_conf["ha_sync"]["synchronizednsforwarder"],
            "synchronizecaptiveportal": xmlsync_options["synchronizecaptiveportal"] if xmlsync_options["synchronizecaptiveportal"].lower() != "default" else hasync_conf["ha_sync"]["synchronizecaptiveportal"],
            "save": "Save"
        }
        # Make our POST request, then check if our changes were applied
        post_hasync_conf = http_request(url + "/system_hasync.php", hasync_post_data, {}, {}, 45, "POST")
        del hasync_post_data["__csrf_magic"],hasync_post_data["save"],hasync_post_data["passwordfld"],hasync_post_data["passwordfld_confirm"]    # Delete unneeded dict keys
        update_hasync_conf = get_ha_sync(server, user, key)    # Repull our existing config
        hasync_setup = 0 if update_hasync_conf["ha_sync"] == hasync_post_data else hasync_setup    # Return exit code 0 if our configurations match
    # If we could not pull our existing config, return the code returned by get_hasync()
    else:
        hasync_setup = hasync_conf["ec"]
    # Return our return code
    return hasync_setup

# get_system_advanced_admin() pulls our current configuration from System > Advanced > Admin Access and saves it to a dictionary
def get_system_advanced_admin(server, user, key):
    # Pre-define our function dictionary
    adv_adm = {"ec" : 2, "adv_admin" : {
        "webconfigurator" : {},
        "secure_shell" : {},
        "login_protection" : {"whitelist" : {}},
        "serial_communcations" : {},
        "console_options" : {}
    }}
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    adv_adm["ec"] = 10 if check_dns_rebind_error(url, None) else adv_adm["ec"]    # Return exit code 10 if dns rebind error found
    adv_adm["ec"] = 6 if not validate_platform(url, None) else adv_adm["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if adv_adm["ec"] == 2:
        adv_adm["ec"] = 3 if not check_auth(server, user, key) else adv_adm["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if adv_adm["ec"] == 2:
        # Check that we had permissions for this page
        get_adv_adm_data = http_request(url + "/system_advanced_admin.php", {}, {}, {}, 45, "GET")    # Pull our admin data using GET HTTP
        if check_permissions(get_adv_adm_data):
            # Check that we have a webconfigurator table
            if "<h2 class=\"panel-title\">webConfigurator</h2>" in get_adv_adm_data["text"]:
                # Parse the values from the 'WEBCONFIGURATOR' section of /system_advanced_admin.php
                wc_adm_table_body = get_adv_adm_data["text"].split("<h2 class=\"panel-title\">webConfigurator</h2>")[1].split("<span class=\"help-block\">When this is unchecked, the browser tab shows")[0]  # Find the data table body
                adv_adm["adv_admin"]["webconfigurator"]["webguiproto"] = "http" if "checked=\"checked\"" in wc_adm_table_body.split("id=\"webguiproto_http:")[1].split("</label>")[0] else "https"    # Check what protocol webconfigurator is using
                adv_adm["adv_admin"]["webconfigurator"]["webguiport"] = wc_adm_table_body.split("id=\"webguiport\"")[1].split("value=\"")[1].split("\"")[0] if "webguiport" in wc_adm_table_body else ""    # Check the max processes webconfigurator allows
                adv_adm["adv_admin"]["webconfigurator"]["max_procs"] = wc_adm_table_body.split("id=\"max_procs\"")[1].split("value=\"")[1].split("\"")[0] if "max_procs" in wc_adm_table_body else ""   # Check the max processes webconfigurator allows
                adv_adm["adv_admin"]["webconfigurator"]["webgui-redirect"] = True if "webgui-redirect" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"webgui-redirect\"")[1].split("</label>")[0] else False    # Check if HTTPS redirect is enabled
                adv_adm["adv_admin"]["webconfigurator"]["webgui-hsts"] = True if "webgui-hsts" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"webgui-hsts\"")[1].split("</label>")[0] else False    # Check if strict transport security is enabled
                adv_adm["adv_admin"]["webconfigurator"]["ocsp-staple"] = True if "ocsp-staple" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"ocsp-staple\"")[1].split("</label>")[0] else False    # Check if OCSP stapling is enabled
                adv_adm["adv_admin"]["webconfigurator"]["loginautocomplete"] = True if "loginautocomplete" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"loginautocomplete\"")[1].split("</label>")[0] else False    # Check if login auto completeion is enabled
                adv_adm["adv_admin"]["webconfigurator"]["webgui-login-messages"] = True if "webgui-login-messages" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"webgui-login-messages\"")[1].split("</label>")[0] else False    # Check if login logging is enabled
                adv_adm["adv_admin"]["webconfigurator"]["noantilockout"] = True if "noantilockout" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"noantilockout\"")[1].split("</label>")[0] else False    # Check if anti-lockout rule is disabled
                adv_adm["adv_admin"]["webconfigurator"]["nodnsrebindcheck"] = True if "nodnsrebindcheck" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"nodnsrebindcheck\"")[1].split("</label>")[0] else False    # Check if DNS rebind checking is enabled
                adv_adm["adv_admin"]["webconfigurator"]["nohttpreferercheck"] = True if "nohttpreferercheck" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"nohttpreferercheck\"")[1].split("</label>")[0] else False    # Check if HTTP-REFERRER checks are enabled
                adv_adm["adv_admin"]["webconfigurator"]["pagenamefirst"] = True if "pagenamefirst" in wc_adm_table_body and "checked=\"checked\"" in wc_adm_table_body.split("id=\"pagenamefirst\"")[1].split("</label>")[0] else False    # Check if page name first is checked (adds hostname to browser tab first)
                adv_adm["adv_admin"]["webconfigurator"]["althostnames"] = wc_adm_table_body.split("id=\"althostnames\"")[1].split("value=\"")[1].split("\"")[0] if "althostnames" in wc_adm_table_body else ""    # Save our alternate hostname values to a string
                # Loop through our WC SSL CERTIFICATE to find which is being used
                ssl_cert_opt = wc_adm_table_body.split("id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=\"")
                for cert in ssl_cert_opt:
                    # Check our certificate is selected
                    if "selected>" in cert:
                        adv_adm["adv_admin"]["webconfigurator"]["ssl-certref"] = cert.split("\"")[0]    # Assign our cert ref ID to our dictionary
                        break
                    # If no certificate was found, assume default
                    else:
                        adv_adm["adv_admin"]["webconfigurator"]["ssl-certref"] = ""    # Assign default if not found
            # If we did not have a webconfigurator table
            else:
                # Assign all default webconfigurator values
                adv_adm["adv_admin"]["webconfigurator"] = {
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
            if "<h2 class=\"panel-title\">Secure Shell</h2>" in get_adv_adm_data["text"]:
                # Parse the values from the 'SECURE SHELL' section of /system_advanced_admin.php
                ssh_adm_table_body = get_adv_adm_data["text"].split("<h2 class=\"panel-title\">Secure Shell</h2>")[1].split("<span class=\"help-block\">Note: Leave this blank for the default of 22")[0]  # Find the data table body
                adv_adm["adv_admin"]["secure_shell"]["enablesshd"] = True if "enablesshd" in ssh_adm_table_body and "checked=\"checked\"" in ssh_adm_table_body.split("id=\"enablesshd\"")[1].split("</label>")[0] else False    # Check if SSH  is enabled
                adv_adm["adv_admin"]["secure_shell"]["sshdagentforwarding"] = True if "sshdagentforwarding" in ssh_adm_table_body and "checked=\"checked\"" in ssh_adm_table_body.split("id=\"sshdagentforwarding\"")[1].split("</label>")[0] else False    # Check if SSH forwarding  is enabled
                adv_adm["adv_admin"]["secure_shell"]["sshport"] = ssh_adm_table_body.split("id=\"sshport\"")[1].split("value=\"")[1].split("\"")[0] if "value=\"" in ssh_adm_table_body.split("id=\"sshport\"")[1] and "sshport" in ssh_adm_table_body else ""   # Save our SSH port value
                # Check if we are running pfsense 2.4.4+
                if "<select class=\"form-control\" name=\"sshdkeyonly\" id=\"sshdkeyonly\">" in ssh_adm_table_body:
                    # Loop through our SSL authentication options and find the currently select option
                    adv_adm["adv_admin"]["secure_shell"]["legacy"] = False    # Assign a value to indicate this isn't a legacy pfSense version
                    ssh_auth_opt = ssh_adm_table_body.split("id=\"sshdkeyonly\">")[1].split("</select>")[0].split("<option value=\"") if "sshdkeyonly" in ssh_adm_table_body else []    # Find our options if available, otherwise assume default
                    for auth in ssh_auth_opt:
                        # Check our certificate is selected
                        if "selected>" in auth:
                            adv_adm["adv_admin"]["secure_shell"]["sshdkeyonly"] = auth.split("\"")[0]    # Assign our auth type to our dictionary
                            break
                        # If the default is used
                        else:
                            adv_adm["adv_admin"]["secure_shell"]["sshdkeyonly"] = "disabled"    # Assign our default value
                # Check if we are running an older version of pfSense
                elif "<label class=\"chkboxlbl\"><input name=\"sshdkeyonly\"" in ssh_adm_table_body:
                    adv_adm["adv_admin"]["secure_shell"]["sshdkeyonly"] = True if "checked=\"checked\"" in ssh_adm_table_body.split("id=\"sshdkeyonly\"")[1].split("</label>")[0] else False    # Assign our ssh auth type
                    adv_adm["adv_admin"]["secure_shell"]["legacy"] = True    # Assign a value to indicate this is a legacy pfSense version
            # If we did not have a secure shell table
            else:
                # Assign all default secure shell values
                adv_adm["adv_admin"]["secure_shell"] = {
                    "enablesshd" : False,
                    "sshdagentforwarding" : False,
                    "sshport" : "",
                    "sshdkeyonly" : ""
                }
            # Parse the values from the 'LOGIN PROTECTION' section of /system_advanced_admin.php
            if "<h2 class=\"panel-title\">Login Protection</h2>" in get_adv_adm_data["text"]:
                login_adm_table_body = get_adv_adm_data["text"].split("<h2 class=\"panel-title\">Login Protection</h2>")[1].split("class=\"btn btn-success addbtn")[0]  # Find the data table body
                adv_adm["adv_admin"]["login_protection"]["sshguard_threshold"] = login_adm_table_body.split("id=\"sshguard_threshold\"")[1].split("value=\"")[1].split("\"")[0] if "sshguard_threshold" in login_adm_table_body else ""    # Save our protection threshold value (number of allowed attacks)
                adv_adm["adv_admin"]["login_protection"]["sshguard_blocktime"] = login_adm_table_body.split("id=\"sshguard_blocktime\"")[1].split("value=\"")[1].split("\"")[0] if "sshguard_blocktime" in login_adm_table_body else ""   # Save our protection block value (duration of block)
                adv_adm["adv_admin"]["login_protection"]["sshguard_detection_time"] = login_adm_table_body.split("id=\"sshguard_detection_time\"")[1].split("value=\"")[1].split("\"")[0] if "sshguard_detection_time" in login_adm_table_body else ""    # Save our protection detection value (duration until threshold resets)
                # Loop through our whitelisted hosts (hosts that are not included in login protection)
                login_whitelist = login_adm_table_body.split("<input class=\"form-control\" name=\"address")
                for host in login_whitelist:
                    # Check that we have a value and selections
                    if "value=" in host and "<select" in host:
                        address_id = host.split("\"")[0]    # Get our address ID
                        value = host.split("value=\"")[1].split("\"")[0]
                        # Loop through our subnet select options and pull our subnet
                        subnet_data = host.split("<select class=\"form-control pfIpMask\"")[1].split("</select>")[0]
                        subnet_selection = subnet_data.split("<option value=\"")    # Split our subnet options into a list
                        for net in subnet_selection:
                            # Check if this subnet is selected
                            if "selected>" in net:
                                subnet = net.split("\"")[0]
                                break
                            # If a selected subnet was not found assume the default
                            else:
                                subnet = ""    # Assign our DEFAULT subnet
                        adv_adm["adv_admin"]["login_protection"]["whitelist"][address_id] = {"id" : "address" + address_id, "value" : value, "subnet" : subnet}
            # If we did not have a login protection table
            else:
                # Assign all default login protection values
                adv_adm["adv_admin"]["login_protection"] = {
                    "sshguard_threshold" : "",
                    "sshguard_blocktime" : "",
                    "sshguard_detection_time" : "",
                    "whitelist" : {}
                }
            # Parse the values from the 'SERIAL COMMUNICATIONS' section of /system_advanced_admin.php
            if "<h2 class=\"panel-title\">Serial Communications</h2>" in get_adv_adm_data["text"]:
                serial_adm_table_body = get_adv_adm_data["text"].split("<h2 class=\"panel-title\">Serial Communications</h2>")[1].split("<span class=\"help-block\">Select the preferred console")[0]  # Find the data table body
                adv_adm["adv_admin"]["serial_communcations"]["enableserial"] = True if "enableserial" in serial_adm_table_body and "checked=\"checked\"" in serial_adm_table_body.split("id=\"enableserial\"")[1].split("</label>")[0] else False    # Check if serial communication is enabled
                # Loop through our SERIALSPEEDS to find our selected speed value
                speed_select = serial_adm_table_body.split("id=\"serialspeed\">")[1].split("</select>")[0].split("<option value=\"")    # Target our serial speed options
                for spd in speed_select:
                    # Check that it meets our expected criteria
                    if "selected>" in spd:
                        adv_adm["adv_admin"]["serial_communcations"]["serialspeed"] = spd.split("\"")[0]    # Save our serial speed
                        break
                    else:
                        adv_adm["adv_admin"]["serial_communcations"]["serialspeed"] = ""    # Assume default if speed not found in current loop cycle
                # Loop through our console types to find our primaryconsole
                console_select = serial_adm_table_body.split("id=\"primaryconsole\">")[1].split("</select>")[0].split("<option value=\"")    # Target our serial console options
                for csl in console_select:
                    # Check that it meets our expected criteria
                    if "selected>" in csl:
                        adv_adm["adv_admin"]["serial_communcations"]["primaryconsole"] = csl.split("\"")[0]    # Save our serial console type
                        break
                    else:
                        adv_adm["adv_admin"]["serial_communcations"]["primaryconsole"] = ""    # Assume default if console type not found in current loop cycle
            # If we did not have a serial communications table
            else:
                # Assign all default serial communications values
                adv_adm["adv_admin"]["serial_communcations"] = {
                    "enableserial" : False,
                    "serialspeed" : "",
                    "primaryconsole" : ""
                }
            # Parse the values from the 'CONSOLE OPTIONS' section of /system_advanced_admin.php
            if "<h2 class=\"panel-title\">Console Options</h2>" in get_adv_adm_data["text"]:
                console_adm_table_body = get_adv_adm_data["text"].split("<h2 class=\"panel-title\">Console Options</h2>")[1].split("<div class=\"col-sm-10 col-sm-offset-2\">")[0]  # Find the data table body
                adv_adm["adv_admin"]["console_options"]["disableconsolemenu"] = True if "disableconsolemenu" in console_adm_table_body and "checked=\"checked\"" in console_adm_table_body.split("id=\"disableconsolemenu\"")[1].split("</label>")[0] else False    # Check if console is password protected
            # If we did not hae a console options table
            else:
                # Assign all default console option values
                adv_adm["adv_admin"]["console_options"]["disableconsolemenu"] = False
            # Update to exit code 0 (success) if we populated our dictionary
            adv_adm["ec"] = 0
        # If we did not have permissions
        else:
            adv_adm["ec"] = 15    # Assign exit code 15 (permission denied)
    # Return our exit code
    return adv_adm

# get_system_advanced_admin_post_data() converts our advanced admin dictionary to a POST data dictionary
def get_system_advanced_admin_post_data(dictionary):
    # Local Variables
    post_data = {}    # Pre-define our return value as empty dictionary
    # Loop through our existing /system_advanced_admin.php configuration and add the data to the POST request
    for table, data in dictionary.items():
        # Loop through each value in the table dictionaries
        for key, value in data.items():
            value = "yes" if value == True else value  # Swap true values to "yes"
            value = "" if value == False else value  # Swap false values to empty string
            # Check if we are checking our login protection whitelist
            if key == "whitelist":
                # Add each of our whitelisted IPs to our post data
                for id_var, info in value.items():
                    addr_id = info["id"]
                    post_data[addr_id] = info["value"]
                    post_data["address_subnet" + id_var] = info["subnet"]
            # If we are not adding whitelist values, simply add the key and value
            else:
                post_data[key] = value  # Populate our data to our POST data
    # Return our POST data dictionary
    return post_data

# setup_wc() configures webConfigurator settings found in /system_advanced_admin.php
def setup_wc(server, user, key, max_proc, redirect, hsts, auto_complete, login_msg, lockout, dns_rebind, alt_host, http_ref, tab_text):
    # Local Variables
    wc_configured = 2    # Pre-define our exit code as 2
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_adv_adm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    wc_post_keys = ["max_procs", "webgui-redirect", "webgui-hsts",
                  "ocsp-staple", "loginautocomplete", "webgui-login-messages", "noantilockout",
                  "nodnsrebindcheck", "althostnames", "nohttpreferercheck", "pagenamefirst"]
    # Check if we got our advanced admin dictionary successfully
    if existing_adv_adm["ec"] == 0:
        # FORMAT OUR POST DATA
        wc_post_data = get_system_advanced_admin_post_data(existing_adv_adm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
        wc_post_data["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        # Check that we do not want to retain our current current value
        if max_proc.upper() != "DEFAULT":
            wc_post_data["max_procs"] = max_proc     # Assign our max processes value
        # Check that we do not want to retain our current current value
        if redirect.upper() != "DEFAULT":
            wc_post_data["webgui-redirect"] = "yes" if redirect in ["disable","no-redirect"] else ""     # Assign our redirect value
        # Check that we do not want to retain our current current value
        if hsts.upper() != "DEFAULT":
            wc_post_data["webgui-hsts"] = "yes" if hsts in ["disable","no-hsts"] else ""     # Assign our hsts value
        # Check that we do not want to retain our current current value
        if auto_complete.upper() != "DEFAULT":
            wc_post_data["loginautocomplete"] = "yes" if auto_complete in ["enable", "autocomplete"] else ""     # Assign our auto_complete value
        # Check that we do not want to retain our current current value
        if login_msg.upper() != "DEFAULT":
            wc_post_data["webgui-login-messages"] = "yes" if login_msg in ["disable", "no-loginmsg"] else ""     # Assign our webgui-login-messages value
        # Check that we do not want to retain our current current value
        if lockout.upper() != "DEFAULT":
            wc_post_data["noantilockout"] = "yes" if lockout in ["disable", "no-antilockout"] else ""     # Assign our noantilockout value
        # Check that we do not want to retain our current current value
        if dns_rebind.upper() != "DEFAULT":
            wc_post_data["nodnsrebindcheck"] = "yes" if dns_rebind in ["disable", "no-dnsrebind"] else ""     # Assign our nodnsrebindcheck value
        # Check that we do not want to retain our current current value
        if alt_host.upper() != "DEFAULT":
            wc_post_data["althostnames"] = alt_host     # Assign our althostnames value
        # Check that we do not want to retain our current current value
        if http_ref.upper() != "DEFAULT":
            wc_post_data["nohttpreferercheck"] = "yes" if http_ref in ["disable", "no-httpreferer"] else ""     # Assign our nohttpreferercheck value
        # Check that we do not want to retain our current current value
        if tab_text.upper() != "DEFAULT":
            wc_post_data["pagenamefirst"] = "yes" if tab_text in ["enable", "display-tabtext"] else ""     # Assign our pagenamefirst value
        # Check that we did not encounter an error
        if wc_configured == 2:
            # Use POST HTTP to save our new values
            post_wc_config = http_request(url + "/system_advanced_admin.php", wc_post_data, {'Cache-Control': 'no-cache'}, {}, 45, "POST")    # POST our data
            # Give pfSense time to restart webconfigurator and read our updated configuration to ensure changes were applied
            time.sleep(2)
            update_adv_adm_data = get_system_advanced_admin(server, user, key)    # Update our raw configuration dictionary
            new_existing_adv_adm = get_system_advanced_admin_post_data(update_adv_adm_data["adv_admin"])    # Get our dictionary of configured advanced options
            # Check that we successfully updated our dictionary
            if update_adv_adm_data["ec"] == 0:
                # Loop through our POST variables and ensure they match
                for d in wc_post_keys:
                    if new_existing_adv_adm[d] != wc_post_data[d]:
                        print(d)
                        wc_configured = 2    # Revert to exit code 2 (unexpected error
                        break
                    else:
                        wc_configured = 0    # Assign our success exit code
    # If we could not successfully pull our advanced admin configuration, return the exit code of that function
    else:
        wc_configured = existing_adv_adm["ec"]
        # Return our exit code
    return wc_configured

# set_wc_port() configures webConfigurator port and protocol settings found in /system_advanced_admin.php
def set_wc_port(server, user, key, protocol, port):
    # Local Variables
    # global PfaVar.wc_protocol    # Allow our PfaVar.wc_protocol variable to be updated globally
    # global PfaVar.wc_protocol_port    # Allow our PfaVar.wc_protocol_port variable to be updated globally
    wc_port_configured = 2    # Pre-define our exit code as 2
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_adv_adm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    # Check if we got our advanced admin dictionary successfully
    if existing_adv_adm["ec"] == 0:
        # FORMAT OUR POST DATA
        wc_post_data = get_system_advanced_admin_post_data(existing_adv_adm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
        wc_post_data["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        # Check that we do not want to retain our current current value
        if protocol.upper() != "DEFAULT" and protocol.upper() != "":
            # Assign our new protocol value if the value is valid
            wc_post_data["webguiproto"] = protocol if protocol in ["http","https"] else wc_post_data["webguiproto"]
            PfaVar.wc_protocol = protocol    # Update our global PfaVar.wc_protocol used by the script
        # Check that we do not want to retain our current current value
        if port.upper() != "DEFAULT" and port.upper() != "":
            # Assign our new port value
            wc_post_data["webguiport"] = port
            PfaVar.wc_protocol_port = port    # Update our global PfaVar.wc_protocol_port used by the script
        # POST our request
        wc_port_post = http_request(url + "/system_advanced_admin.php", wc_post_data, {}, {}, 45, "POST")
        time.sleep(2)    # Give our webConfigurator a couple seconds to restart
        # Loop for up to 10 second and check that our port opens
        counter = 0    # Define a loop counter
        while True:
            # Break the loop if we have waited over 10 seconds
            if counter > 10:
                break
            # Check if our port is open, break the loop if so
            if check_auth(server, user, key):
                wc_port_configured = 0    # Return our success exit code
                break
            else:
                wc_port_configured = 8   # Return exit code 8 (port did not bind)
            time.sleep(1)    # Wait one second before running again
            counter = counter + 1    # Increase our counter
    # Return our value
    return wc_port_configured

# setup_ssh() configures sshd settings found in /system_advanced_admin.php
def setup_ssh(server, user, key, enable, port, auth, forwarding):
    # Local Variables
    ssh_configured = 2    # Pre-define our exit code as 2
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_adv_adm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    # Check if we got our advanced admin dictionary successfully
    if existing_adv_adm["ec"] == 0:
        # FORMAT OUR POST DATA
        ssh_post_data = get_system_advanced_admin_post_data(existing_adv_adm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
        ssh_post_data["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        # Check that we do not want to retain our current value
        if enable.upper() != "DEFAULT":
            ssh_post_data["enablesshd"] = "yes" if enable == "enable" else ""    # Save our enablesshd POST value to "yes" if we passed in a true value to enable
        # Check that we do not want to retain our current value
        if port.upper() != "DEFAULT":
            ssh_post_data["sshport"] = port    # Save our ssh port value to our POST data
        # Check that we do not want to retain our current auth value
        if auth.upper() != "DEFAULT":
            # Check if we are POSTing to an older pfSense version
            if existing_adv_adm["adv_admin"]["secure_shell"]["legacy"]:
                # Check that our auth method is expected
                if auth in ["keyonly", "key", "pass", "password", "passwd"]:
                    ssh_post_data["sshdkeyonly"] = "yes" if auth in ["keyonly", "key"] else ""    # For legacy pfSense versions, assign a "yes" or empty string value given a bool
                else:
                    ssh_configured = 20    # Assign exit code 20 (invalid legacy ssh auth method)
            # If we are not on a legacy pfSense system
            else:
                # Check that our auth method is expected
                if auth in ["keyonly", "key", "pass", "password", "passwd", "mfa", "both", "all"]:
                    ssh_post_data["sshdkeyonly"] = "disabled" if auth in ["pass", "password", "passwd"] else ssh_post_data["sshdkeyonly"]    # Save our sshdkeyonly value if user wants password logins
                    ssh_post_data["sshdkeyonly"] = "enabled" if auth in ["keyonly", "key"] else ssh_post_data["sshdkeyonly"]    # Save our sshdkeyonly value if user wants keyonly logins
                    ssh_post_data["sshdkeyonly"] = "both" if auth in ["mfa", "both", "all"] else ssh_post_data["sshdkeyonly"]    # Save our sshdkeyonly value if user wants MFA SSH logins (key and password)
                else:
                    ssh_configured = 21    # Assign exit code 20 (invalid ssh auth method)
        # Check that we do not want to retain our current auth value
        if forwarding.upper() != "DEFAULT":
            # This value only exists on non-legacy pfSense, check that we are not running legacy
            if not existing_adv_adm["adv_admin"]["secure_shell"]["legacy"]:
                ssh_post_data["sshdagentforwarding"] = "yes" if forwarding in ["enable", "enable-forwarding", "yes", "ef"] else ""    # Save our sshdagentforwarding value to our POST data
        # Check that we did not encounter an error
        if ssh_configured == 2:
            # Use POST HTTP to save our new values
            post_ssh_config = http_request(url + "/system_advanced_admin.php", ssh_post_data, {}, {}, 45, "POST")    # POST our data
            # Check that our values were updated, assign exit codes accordingly
            new_existing_adv_adm = get_system_advanced_admin_post_data(get_system_advanced_admin(server, user, key)["adv_admin"])    # Get our dictionary of configured advanced options
            # Loop through our POST variables and ensure they match
            for d in ["enablesshd", "sshport", "sshdkeyonly", "sshdagentforwarding"]:
                if new_existing_adv_adm[d] != ssh_post_data[d]:
                    ssh_configured = 2    # Revert to exit code 2 (unexpected error
                    break
                else:
                    ssh_configured = 0    # Assign our success exit code
    # If we could not successfully pull our advanced admin configuration, return the exit code of that function
    else:
        ssh_configured = existing_adv_adm["ec"]
    # Return our exit code
    return ssh_configured

# setup_console_options() configures password protection of the console menu
def setup_console(server, user, key, console_pass):
    # Local Variables
    console_configured = 2    # Pre-define our exit code as 2
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_adv_adm = get_system_advanced_admin(server, user, key)    # Get our dictionary of configured advanced options
    # Check if we got our advanced admin dictionary successfully
    if existing_adv_adm["ec"] == 0:
        # FORMAT OUR POST DATA
        console_post_data = get_system_advanced_admin_post_data(existing_adv_adm["adv_admin"])    # Convert our advanced admin data into a POST dictionary
        # Update our POST data
        console_post_data["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
        console_post_data["disableconsolemenu"] = "yes" if console_pass.upper() in ["ENABLE", "YES"] else ""    # If user wants to password protect console, assign value of yes
        if console_configured == 2:
            # Use POST HTTP to save our new values
            post_console_config = http_request(url + "/system_advanced_admin.php", console_post_data, {}, {}, 45, "POST")    # POST our data
            # Check that our values were updated, assign exit codes accordingly
            update_adv_adm_data = get_system_advanced_admin(server, user, key)    # Update our raw configuration dictionary
            new_existing_adv_adm = get_system_advanced_admin_post_data(update_adv_adm_data["adv_admin"])    # Get our dictionary of configured advanced options
            # Check that we successfully updated our dictionary
            if update_adv_adm_data == 0:
                if new_existing_adv_adm["disableconsolemenu"] != console_post_data["disableconsolemenu"]:
                    console_configured = 2    # Revert to exit code 2 (unexpected error)
                else:
                    console_configured = 0    # Assign our success exit code
            # If we could not update our configuration dictionary
            else:
                console_configured = update_adv_adm_data["ec"]
    # If we could not successfully pull our advanced admin configuration, return the exit code of that function
    else:
        console_configured = existing_adv_adm["ec"]
    # Return our exit code
    return console_configured

# get_packages() reads installed packages from pfSense's UI repos
def get_installed_packages(server, user, key):
    # Local variables
    installed_pkgs = {"ec": 2, "installed_pkgs": {}}    # Init our return dictionary that tracks exit codes and packages
    exp_output = "pfSense-pkg"    # Define the string to check for when looking for pfSense packages
    pkg_shell_out = get_shell_output(server, user, key, "pkg info | grep " + exp_output)    # Run our shell cmd to return installed pkgs
    # Check that our command ran successfully
    if pkg_shell_out["ec"] == 0:
        # Check that we have expected output
        if exp_output + "-" in pkg_shell_out["shell_output"]:
            pkg_str = pkg_shell_out["shell_output"] + "\n"    # Add a new line so we always have a list when splitting
            pkg_list = pkg_str.split("\n")    # Split our string into a list on every new line
            for p in pkg_list:
                if exp_output + "-" in p:
                    p = ' '.join(p.split(" "))    # Replace multiple spaces with one space
                    full_pkg = p.split(" ")[0]    # Save our entire pkg name
                    pkg_parse = full_pkg.replace("pfSense-pkg-", "").split("-")
                    pkg_name = "-".join(pkg_parse[:-1])  # Everything but our last entry is the pkg name
                    pkg_ver = pkg_parse[-1:][0]  # The last entry is our pkg version
                    installed_pkgs["installed_pkgs"][pkg_name] = {}    # Create our single pkg dict
                    installed_pkgs["installed_pkgs"][pkg_name]["pkg"] = full_pkg
                    installed_pkgs["installed_pkgs"][pkg_name]["name"] = pkg_name
                    installed_pkgs["installed_pkgs"][pkg_name]["version"] = pkg_ver
            # Return our success exit code
            installed_pkgs["ec"] = 0
    # If we encountered an error running our shell cmd, return the code returned by get_shell_output()
    else:
        installed_pkgs["ec"] = pkg_shell_out["ec"]
    # Return our dictionary
    return installed_pkgs

# get_available_packages() pulls a list of packages that are able to be installed on pfSense
def get_available_packages(server, user, key):
    # Local variables
    avail_pkgs = {"ec": 2, "available_pkgs": {}}    # Initialize our dictionary to track error codes and available packages
    exp_output = "pfSense-pkg"    # Define the string to check for when looking for pfSense packages
    get_avail_packages = get_shell_output(server, user, key, "pkg search -q " + exp_output)    # Get our available packages
    get_installed_packages = get_installed_packages(server, user, key)    # Get our  installed packages
    # Check that we received our available pkg output
    if get_avail_packages["ec"] == 0:
        # Check that we received our installed pkg output
        if get_installed_packages["ec"] == 0:
            # Check that we have expected output
            if exp_output + "-" in get_avail_packages["shell_output"]:
                pkg_str = get_avail_packages["shell_output"] + "\n"    # Add a new line so we always have a list when splitting
                pkg_list = pkg_str.split("\n")    # Split our string into a list on every new line
                for p in pkg_list:
                    if exp_output + "-" in p:
                        full_pkg = p    # Save our entire pkg name
                        pkg_parse = full_pkg.replace("pfSense-pkg-","").split("-")
                        pkg_name = "-".join(pkg_parse[:-1])    # Everything but our last entry is the pkg name
                        pkg_ver = pkg_parse[-1:][0]   # The last entry is our pkg version
                        avail_pkgs["available_pkgs"][pkg_name] = {}    # Create our single pkg dict
                        avail_pkgs["available_pkgs"][pkg_name]["pkg"] = full_pkg
                        avail_pkgs["available_pkgs"][pkg_name]["name"] = pkg_name
                        avail_pkgs["available_pkgs"][pkg_name]["version"] = pkg_ver
                        avail_pkgs["available_pkgs"][pkg_name]["installed"] = True if pkg_name in get_installed_packages["installed_pkgs"] else False    # Check if package is installed already
                # Return our success exit code
                avail_pkgs["ec"] = 0
        # If we received an error pulling our installed packages
        else:
            avail_pkgs["ec"] = get_avail_packages["ec"]
    # If we received an error pulling our available packages
    else:
        avail_pkgs["ec"] = get_avail_packages["ec"]
    # Return our exit code
    return avail_pkgs

# add_package() adds a new pfSense package
def add_package(server, user, key, pkg):
    # Local variables
    pkg_added = 2    # Assign an integer to track various errors that may be encountered
    avail_pkgs = get_available_packages(server, user, key)    # Pull our dictionary of available packages
    # Check that we did not encounter an error pulling our available packages
    if avail_pkgs["ec"] == 0:
        # Check that our package is in our available packages
        if pkg in avail_pkgs["available_pkgs"]:
            # Check that our package is not already installed
            if not avail_pkgs["available_pkgs"][pkg]["installed"]:
                # Install our package, check that it was installed successfully
                add_pkg = get_shell_output(server, user, key, "pkg install -y pfSense-pkg-" + pkg)
                if add_pkg["ec"] == 0:
                    installed_pkgs = get_installed_packages(server, user, key)    # Update our installed pkg dictionary
                    if pkg in installed_pkgs["installed_pkgs"]:
                        pkg_added = 0    # Return exit code 0 (success)
            # If our package is already installed, returne exit code 5 (pkg already installed)
            else:
                pkg_added = 5
        # If our package is not an available package, return exit code 4 (pkg not found)
        else:
            pkg_added = 4
    # If we could not pull our available packages, return code returned by get_available_packages()
    else:
        pkg_added = avail_pkgs["ec"]
    # Return our code
    return pkg_added

# del_package() deletes an existing pfSense package
def del_package(server, user, key, pkg):
    # Local variables
    pkg_del = 2    # Assign an integer to track various errors that may be encountered
    installed_pkgs = get_installed_packages(server, user, key)    # Pull our dictionary of installed packages
    # Check that we did not encounter an error pulling our available packages
    if installed_pkgs["ec"] == 0:
        # Check that our package is in our installed packages
        if pkg in installed_pkgs["installed_pkgs"]:
            # Install our package, check that it was installed successfully
            delete_pkg = get_shell_output(server, user, key, "pkg remove -y pfSense-pkg-" + pkg)
            if delete_pkg["ec"] == 0:
                installed_pkgs = get_installed_packages(server, user, key)    # Update our installed pkg dictionary
                if pkg not in installed_pkgs["installed_pkgs"]:
                    pkg_del = 0    # Return exit code 0 (success)
        # If our package is not an available package, return exit code 4 (pkg not found)
        else:
            pkg_del = 4
    # If we could not pull our available packages, return code returned by get_installed_pkgs()
    else:
        pkg_del = installed_pkgs["ec"]
    # Return our code
    return pkg_del

# get_shell_output() executes a shell command in diag_command.php and returns it's output
def get_shell_output(server, user, key, cmd):
    # Local variables
    shell_out = {"ec": 2, "shell_output" : ""}    # Create a dictionary to track our return code and our shell cmd output
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our initial request and check for errors
    shell_out["ec"] = 10 if check_dns_rebind_error(url, None) else shell_out["ec"]    # Return exit code 10 if dns rebind error found
    shell_out["ec"] = 6 if not validate_platform(url, None) else shell_out["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if shell_out["ec"] == 2:
        shell_out["ec"] = 3 if not check_auth(server, user, key) else shell_out["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if shell_out["ec"] == 2:
        # Check that we had permissions for this page
        get_shell_data = http_request(url + "/diag_arp.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(get_shell_data):
            # Create our POST data dictionary and run our POST request
            shell_cmd_post_data = {"__csrf_magic": get_csrf_token(url + "/diag_command.php", "GET"), "txtCommand": cmd, "submit": "EXEC"}
            shell_cmd_post = http_request(url + "/diag_command.php", shell_cmd_post_data, {}, {}, 90, "POST")
            # Check that our output <pre> tags exist
            if "<pre>" in shell_cmd_post["text"]:
                shell_out["shell_output"] = html.unescape(shell_cmd_post["text"].split("<pre>")[1].split("</pre>")[0])    # Update our shell output value
                shell_out["ec"] = 0    # Return exit code 0 (success)
        # If we did not have permission, return exit code 15 (permission denied)
        else:
            shell_out["ec"] = 15
    # Return our data dictionary
    return shell_out

# get_arp_table() pulls our pfSense's current ARP table
def get_arp_table(server, user, key):
    arp_table = {"ec" : 2, "arp" : {}}    # Pre-define our function dictionary
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our initial request and check for errors
    arp_table["ec"] = 10 if check_dns_rebind_error(url, None) else arp_table["ec"]    # Return exit code 10 if dns rebind error found
    arp_table["ec"] = 6 if not validate_platform(url, None) else arp_table["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if arp_table["ec"] == 2:
        arp_table["ec"] = 3 if not check_auth(server, user, key) else arp_table["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if arp_table["ec"] == 2:
        # Check that we had permissions for this page
        get_arp_data = http_request(url + "/diag_arp.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(get_arp_data):
            arp_table_body = get_arp_data["text"].split("<tbody>")[1].split("</tbody>")[0]  # Find the data table body
            arp_table_rows = arp_table_body.replace("\t", "").replace("\n", "").replace("</tr>", "").split("<tr>")  # Find each of our table rows
            # Loop through our rows to pick out our values
            counter = 0    # Assign a loop counter
            for row in arp_table_rows:
                # Check that the row is not empty
                if row != "" and "<td>" in row:
                    arp_table_data = row.split("<td>")    # Split our table row into individual data fields
                    arp_table["arp"][counter] = {}    # Assign a dictionary for each arp value
                    arp_table["arp"][counter]["interface"] = arp_table_data[1].replace("</td>", "")    # Assign our interface value to the dictionary
                    arp_table["arp"][counter]["ip"] = arp_table_data[2].replace("</td>", "")    # Assign our ip value to the dictionary
                    arp_table["arp"][counter]["mac_addr"] = arp_table_data[3].split("<small>")[0].replace("</td>", "")    # Assign our mac address value to the dictionary
                    arp_table["arp"][counter]["mac_vendor"] = ""    # Default our mac_vendor value to empty string
                    # Assign a mac vendor value if one exists
                    if "<small>" in arp_table_data[3]:
                        arp_table["arp"][counter]["mac_vendor"] = arp_table_data[3].split("<small>")[1].replace("</small>", "").replace("(", "").replace(")", "").replace("</td>", "")    # Assign our mac vendor value to the dictionary
                    # Check if extra values exist (pfSense 2.4+)
                    arp_table["arp"][counter]["hostname"] = arp_table_data[4].replace("</td>", "") if len(arp_table_data) > 4 else ""    # Assign our hostname value to the dictionary
                    arp_table["arp"][counter]["expires"] = arp_table_data[5].replace("</td>", "").replace("Expires in ", "") if len(arp_table_data) > 6 else ""   # Assign our expiration value to the dictionary
                    arp_table["arp"][counter]["type"] = arp_table_data[6].replace("</td>", "") if len(arp_table_data) > 6 else ""    # Assign our link type value to the dictionary
                    counter = counter + 1    # Increase our counter
            # Set our exit code to zero if our dictionary is populated
            arp_table["ec"] = 0 if len(arp_table) > 0 else arp_table["ec"]
        # If we did not have permission to the ARP table
        else:
            arp_table["ec"] = 15    # Assign exit code 15 if we did not have permission (permission denied)
    # Return our dictionary
    return arp_table

# get_state_table() pulls the firewall state table via SSH or webConfigurator shell
def get_state_table(server, user, key):
    # Local variables
    state_table = {"ec": 2, "state_table": ""}
    state_table_cmd = "pfctl -s state"
    #Pull our state table using the webConfigurator's shell tool
    state_table_resp = get_shell_output(server, user, key, state_table_cmd)
    state_table["state_table"] = state_table_resp["shell_output"]
    state_table["ec"] = state_table_resp["ec"]
    # Return our state table
    return state_table

# get_xml_backup() saves pfSense's XML backup given specific parameters
def get_xml_backup(server, user, key, area, no_pkg, no_rrd, encrypt, encrypt_pass):
    xml_table = {"ec" : 2}    # Pre-define our function dictionary
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    xml_table["ec"] = 10 if check_dns_rebind_error(url, None) else xml_table["ec"]    # Return exit code 10 if dns rebind error found
    xml_table["ec"] = 6 if not validate_platform(url, None) else xml_table["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if xml_table["ec"] == 2:
        xml_table["ec"] = 3 if not check_auth(server, user, key) else xml_table["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if xml_table["ec"] == 2:
        # Check that we had permissions for this page
        get_xml_data = http_request(url + "/diag_backup.php", {}, {}, {}, 45, "GET")    # Pull our XML download page using GET HTTP
        if check_permissions(get_xml_data):
            # Populate our POST data dictionary
            get_xml_post_data = {
                "__csrf_magic": get_csrf_token(url + "/diag_backup.php", "GET"),
                "backuparea" : area,
                "nopackages" : "yes" if no_pkg == True else "",
                "donotbackuprrd" : "yes" if no_rrd == True else "",
                "encrypt" : "yes" if encrypt == True else "",
                "encrypt_password" : encrypt_pass if encrypt == True else "",
                "download" : "Download configuration as XML",
                "restorearea" : "",
                "decrypt_password" : ""
            }
            # Make our POST request
            post_xml_req = http_request(url + "/diag_backup.php", get_xml_post_data, {}, {}, 45, "POST")
            xml_table["xml"] = post_xml_req["text"]    # Save our XML backup to our return dict
            # Check our POST requests response code
            if post_xml_req["resp_code"] == 200:
                xml_table["ec"] = 0    # Return exit code 0 (success)
        # If we did not pass our permissions check
        else:
            xml_table["ec"] = 15    # Assign exit code 15 (permissions denied)
    # Return our dictionary
    return xml_table

# upload_xml_backup() uploads and restores an existing XML backup configuration
def upload_xml_backup(server, user, key, area, conf_file, decrypt_pass):
    # Local Variables
    xml_added = 2  # Assign our default return code. (2 means generic failure)
    decrypt_enable = "yes" if decrypt_pass != "" else ""    # Determine our decrypt POST value based on user submitting password
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)  # Assign our base URL
    # Submit our intitial request and check for errors
    xml_added = 10 if check_dns_rebind_error(url, None) else xml_added    # Return exit code 10 if dns rebind error found
    xml_added = 6 if not validate_platform(url, None) else xml_added    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if xml_added == 2:
        xml_added = 3 if not check_auth(server, user, key) else xml_added   # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if xml_added == 2:
        # Check that we had permissions for this page
        get_xml_data = http_request(url + "/diag_backup.php", {}, {}, {}, 45, "GET")    # Pull our XML download page using GET HTTP
        if check_permissions(get_xml_data):
            # Assign our POST data dictionary
            restore_xml_post_data = {"__csrf_magic": get_csrf_token(url + "/diag_backup.php", "GET"), "restorearea": area, "decrypt": decrypt_enable, "decrypt_password": decrypt_pass, "restore": "Restore Configuration"}
            # Make our HTTP POST
            restore_xml_post = http_request(url + "/diag_backup.php", restore_xml_post_data, {}, conf_file, 45, "POST")
            # Check if our backup was successfully restored
            success_str = "The configuration area has been restored. The firewall may need to be rebooted."
            if success_str in restore_xml_post["text"]:
                xml_added = 0    # Return our success exit code
        # If we did not have permission to the backup_restore page
        else:
            xml_added = 15    # Assign exit code 15 if we did not have permission (permission denied)
    # Return our return code
    return xml_added

# replicate_xml() copies the XML configuration from one pfSense box to another
def replicate_xml(server, user, key, area, target_list):
    # Local variables
    replicate_dict = {"ec" : 2, "targets" : {}}     # Initialize certManagerDict to return our certificate values and exit codes
    master_config = get_xml_backup(server, user, key, "", False, False, True, PfaVar.current_date)    # Get our XML configuration and save it to a variable
    # Check that our master config was pulled successfully before continuing
    if master_config["ec"] == 0:
        # Loop through our target list and start to replicate configuration
        counter = 0    # Set a counter to track loop iteration
        for tg in target_list:
            xml_obj = io.StringIO(master_config["xml"])
            master_config_binary = {"conffile": xml_obj}   # Convert our string to a encoded obj and save it to our POST dictionary
            replicate_dict["targets"][counter] = {}    # Create a target dictionary entry
            target_upload = upload_xml_backup(tg, user, key, area, master_config_binary, PfaVar.current_date)    # Run our function and capture the exit code
            xml_obj.close()    # Close our object now that it is no longer needed
            replicate_dict["targets"][counter]["host"] = tg    # Save our target hostname/IP to dictionary
            replicate_dict["targets"][counter]["ec"] = target_upload    # Save our function exit code to dictionary
            replicate_dict["targets"][counter]["replicated"] = True if target_upload == 0 else False    # Assign a bool value stating whether replication was successful
            counter = counter + 1   # Increase our counter
        # Return success exit code as we have populated our dictionary
        replicate_dict["ec"] = 0
    # If we could not pull the master configuration
    else:
        replicate_dict["ec"] = master_config["ec"]    # Save exit code from the failed function
    # Return our dictionary
    return replicate_dict

# get_system_tunables() pulls the System Tunable values from the advanced settings
def get_system_tunables(server, user, key):
    tunables = {"ec" : 2, "tunables" : {}}    # Pre-define our function dictionary
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    tunables["ec"] = 10 if check_dns_rebind_error(url, None) else tunables["ec"]    # Return exit code 10 if dns rebind error found
    tunables["ec"] = 6 if not validate_platform(url, None) else tunables["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if tunables["ec"] == 2:
        tunables["ec"] = 3 if not check_auth(server, user, key) else tunables["ec"]    # Return exit code 3 if we could not sign in
    # Check if we encountered any errors before staring
    if tunables["ec"] == 2:
        # Check that we had permissions for this page
        get_tunable_data = http_request(url + "/system_advanced_sysctl.php", {}, {}, {}, 45, "GET")    # Pull our Interface data using GET HTTP
        if check_permissions(get_tunable_data):
            tunable_body = get_tunable_data["text"].split("<table class")[1].split("</table>")[0]  # Find the data table body
            tunable_rows = tunable_body.replace("\t", "").replace("\n", "").replace("</tr>", "").split("<tr>")  # Find each of our table rows
            # Loop through our rows to pick out our values
            counter = 0    # Assign a loop counter
            for row in tunable_rows:
                # Check that the row is not empty
                if row != "" and "<td>" in row:
                    tunable_data = row.split("<td>")    # Split our data into a list
                    tunable_name = tunable_data[1].replace("</td>", "")    # Assign our tunable name to a variables
                    tunables["tunables"][tunable_name] = {"name" : tunable_name} if tunable_name not in tunables["tunables"] else tunables["tunables"][tunable_name]    # Define our value dict if one doesn't exist
                    tunables["tunables"][tunable_name]["descr"] = tunable_data[2].replace("</td>", "")    # Assign our tunable description to a variables
                    tunables["tunables"][tunable_name]["value"] = tunable_data[3].replace("</td>", "")    # Assign our tunable value to a variables
                    tunables["tunables"][tunable_name]["id"] = tunable_data[4].replace("</td>", "").split("href=\"system_advanced_sysctl.php?act=edit&amp;id=")[1].split("\"")[0]    # Assign our tunable description to a variables
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
    tunable_added = 2    # Assign our default return code. (2 means generic failure)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_tunables = get_system_tunables(server, user, key)    # Get our dictionary of configured tunables
    tunable_post_data = {"__csrf_magic" : "", "tunable" : name, "value" : value, "descr" : descr, "save" : "Save"}    # Assign our POST data
    # Check if we got our VLAN dictionary successfully
    if existing_tunables["ec"] == 0:
        # Loop through existing VLAN to check that our requested VLAN ID isn't already configured
        if name in existing_tunables["tunables"]:
            tunable_added = 8  # Return exit code 8 (tunable already exists)
        # Check that we did not encounter an error
        if tunable_added == 2:
            # Use GET HTTP to see what interfaces are available
            get_existing_ifaces = http_request(url + "/system_advanced_sysctl.php?act=edit", {}, {}, {}, 45, "GET")    # Get our HTTP response
            # Check that we had permissions for this page
            if check_permissions(get_existing_ifaces):
                tunable_post_data["__csrf_magic"] = get_csrf_token(url + "/system_advanced_sysctl.php?act=edit", "GET")    # Update our CSRF token
                post_tunable = http_request(url + "/system_advanced_sysctl.php?act=edit", tunable_post_data, {}, {}, 45, "POST")    # POST our data
                apply_tunable_data = {"__csrf_magic" : get_csrf_token(url + "/system_advanced_sysctl.php", "GET"), "apply" : "Apply Changes"}    # Assign our post data to apply changes
                apply_tunable = http_request(url + "/system_advanced_sysctl.php", apply_tunable_data, {}, {}, 45, "POST")    # POST our data
                updated_tunables = get_system_tunables(server, user, key)    # Get our updated dictionary of configured tunables
                tunable_added = 0 if name in updated_tunables["tunables"] else tunable_added    # Check that our new value is listed
            # If we didn't have permissions to add the tunable
            else:
                tunable_added = 15  # Return exit code 15 (permission denied)
    # If we couldn't pull existing tunables
    else:
        tunable_added = existing_tunables["ec"]    # Return the exit code that was returned by our get_existing_tunables()
    # Return our exit code
    return tunable_added

# get_interfaces() reads config.xml for our interface configuration
def get_interfaces_xml(server, user, key):
    # Local Variables
    interfaces = {"ec": 2, "ifaces": {}}    # Init our interface dictionary
    # Check if we have not initialized our XML config and we are running in remote target mode
    if not XmlConfigs.init:
        update_config(server, user, key)    # Initialize our XML configuration
    # Check that our configuration was pulled
    if xml_indicator in XmlConfigs.master:
        # Check if we did not encountered any errors thus far, continue if not
        if interfaces["ec"] == 2:
            xml_iface_dict = convert_xml(XmlConfigs.master)["pfsense"]["interfaces"]    # Save our interface dictionary from XML
            # Check that our dictionary is not empty
            if xml_iface_dict is not None and len(xml_iface_dict) > 0:
                # Define lists of our expected values
                txt_value_list = ["if","dhcp6-ia-pd-send-hint","adv_dhcp6_id_assoc_statement_prefix_enable","descr","spoofmac",
                                  "mtu","mss","ipaddr","ipaddrv6","dhcphostname","alias-address","dhcprejectfrom","adv_dhcp_pt_timeout",
                                  "adv_dhcp_pt_retry","adv_dhcp_pt_select_timeout","adv_dhcp_pt_reboot","adv_dhcp_pt_backoff_cutoff",
                                  "adv_dhcp_pt_initial_interval","adv_dhcp_config_file_override_path","adv_dhcp_send_options",
                                  "adv_dhcp_request_options","adv_dhcp_required_options","adv_dhcp_option_modifiers","ipaddrv6",
                                  "adv_dhcp6_interface_statement_send_options","adv_dhcp6_interface_statement_request_options",
                                  "adv_dhcp6_interface_statement_script","adv_dhcp6_id_assoc_statement_address_id",
                                  "adv_dhcp6_id_assoc_statement_address","adv_dhcp6_id_assoc_statement_address_pltime",
                                  "adv_dhcp6_id_assoc_statement_address_vltime","adv_dhcp6_id_assoc_statement_prefix_id",
                                  "adv_dhcp6_id_assoc_statement_prefix","adv_dhcp6_id_assoc_statement_prefix_pltime",
                                  "adv_dhcp6_id_assoc_statement_prefix_vltime","adv_dhcp6_prefix_interface_statement_sla_id",
                                  "adv_dhcp6_prefix_interface_statement_sla_len","adv_dhcp6_authentication_statement_authname",
                                  "adv_dhcp6_authentication_statement_protocol","adv_dhcp6_authentication_statement_algorithm",
                                  "adv_dhcp6_authentication_statement_rdm","adv_dhcp6_key_info_statement_keyname","adv_dhcp6_key_info_statement_realm",
                                  "adv_dhcp6_key_info_statement_keyid","adv_dhcp6_key_info_statement_secret","adv_dhcp6_key_info_statement_expire",
                                  "adv_dhcp6_config_file_override_path","mediaopt","subnet","gateway","alias-subnet","subnetv6","gatewayv6",
                                  "dhcp6-ia-pd-len","adv_dhcp6_prefix_selected_interface","prefix-6rd","gateway-6rd","prefix-6rd-v4plen",
                                  "track6-interface","track6-prefix-id--hex"]
                cbx_value_list = ["enable","blockpriv","blockbogons","adv_dhcp_config_advanced","adv_dhcp_config_file_override",
                                  "ipv6usev4iface","adv_dhcp6_config_advanced","adv_dhcp6_config_file_override","dhcp6usev4iface",
                                  "dhcp6prefixonly","dhcp6prefixonly","dhcp6debug","dhcp6withoutra","dhcp6norelease",
                                  "adv_dhcp6_interface_statement_information_only_enable","adv_dhcp6_id_assoc_statement_address_enable"]
                ip_types = ["dhcp","ppp","pppoe","pptp","l2tp"]
                ipv6_types = ["dhcp6","slaac","6to4","track6"]
                # Loop through each interface and pull it's configuration
                for key,val in xml_iface_dict.items():
                    interfaces["ifaces"][key] = {"pf_id": key}    # Save our PFSENSE interface ID
                    # For our TEXT VALUES, pull the values from each expected key
                    for tv in txt_value_list:
                        interfaces["ifaces"][key][tv] = ""    # Create our default value
                        # Check if our XML dictionary has these values
                        if tv in val and val[tv] is not None:
                            xml_val = val[tv][0] if len(val[tv]) == 1 else val[tv]
                            interfaces["ifaces"][key][tv] = xml_val
                    # For our CHECKBOX VALUES, pull the values from each expected key
                    for cb in cbx_value_list:
                        interfaces["ifaces"][key][cb] = "yes" if cb in val else ""    # If our XML contains this value, add it to our dict as "yes" otherwise empty string
                    # FINAL CONDITIONALS/MANUAL CORRECTIONS
                    # Save our source net and dest net
                    # Save our ID as our interface
                    interfaces["ifaces"][key]["id"] = interfaces["ifaces"][key]["if"]
                    # Format our `type` value
                    interfaces["ifaces"][key]["type"] = interfaces["ifaces"][key]["ipaddr"] if interfaces["ifaces"][key]["ipaddr"] in ip_types else "none"
                    interfaces["ifaces"][key]["type"] = "staticv4" if interfaces["ifaces"][key]["type"] is "none" and interfaces["ifaces"][key]["ipaddr"] != "" else interfaces["ifaces"][key]["type"]
                    # Format our `type6` value
                    interfaces["ifaces"][key]["type6"] = interfaces["ifaces"][key]["ipaddrv6"] if interfaces["ifaces"][key]["ipaddrv6"] in ipv6_types else "none"
                    interfaces["ifaces"][key]["type6"] = "staticv6" if interfaces["ifaces"][key]["type6"] is "none" and interfaces["ifaces"][key]["ipaddrv6"] != "" else interfaces["ifaces"][key]["type6"]
                # Return success exit code
                interfaces["ec"] = 0    # Return exit code 0
    # Return our dictionary
    return interfaces

# get_interfaces() pulls existing interface configurations from interfaces_assign.php and interfaces.php
def get_interfaces(server, user, key):
    # Local Variables
    ifaces = {"ec": 2, "ifaces": {}, "if_add": []}    # Predefine our dictionary that will track our VLAN data as well as errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    ifaces_xml = pfsensexml.get_interfaces_xml(server, user, key)    # Try to pull our interfaces through XML (for speed)
    # Check if we can read our interfaces via XML, if not, try via webconfigurator
    if ifaces_xml["ec"] != 0:
        err_check = check_errors(server, user, key, ["interfaces_assign.php", "interfaces.php"])    # Check for webconfigurator errors
        # Check if we did not encountered any errors thus far, continue if not
        if err_check == 2:
            get_if_data = http_request(url + "/interfaces_assign.php", {}, {}, {}, 45, "GET")    # Pull our interface data using GET HTTP
            # Check that we have a table body to pull from
            if "<tbody>" in get_if_data["text"]:
                # Target only HTML data between our tbody tags
                if_table_body = get_if_data["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save data between tbody tags
                # Check that we have interface data
                if "<td><a href=\"/interfaces.php?if" in if_table_body:
                    table_body_if_list = if_table_body.split("<td><a href=\"/interfaces.php?if=")    # Split our tbody into a list of ifaces
                    del table_body_if_list[0]    # Discard the first value in the last as it saves data listed before our target data
                    pf_if_list = []    # Define an empty list to populate our interface names too
                    # Loop through the ifaces and pull the interface name as it's known to pfSense
                    for i in table_body_if_list:
                        i = i.split("\"")[0]
                        pf_if_list.append(i)
                    # Request each specific interfaces configuration
                    for pfId in pf_if_list:
                        ifaces["ifaces"][pfId] = {"pf_id" : pfId}    # Initialize a nested dictionary for each interface
                        # Locate our physical interface ID
                        if_id_select = if_table_body.split("<td><a href=\"/interfaces.php?if=" + pfId + "\">")[1].split("</select>")[0]    # Target our interface ID options
                        if_id_options = if_id_select.split("<option value=\"")    # Split our options into a list
                        # Loop through our interface IDs to find the selected value
                        for id_opt in if_id_options:
                            # Check if value is selected
                            if "selected" in id_opt.split(">")[0]:
                                ifaces["ifaces"][pfId]["id"] = id_opt.split("\"")[0]    # Save our interface ID
                                break
                            # If it is not selected, assume default
                            else:
                                ifaces["ifaces"][pfId]["id"] = ""    # Assign default value
                        # SAVE OUR INTERFACE.PHP HTML INPUT NAMES TO LISTS TO LOOP THROUGH
                        # Text inputs
                        value_inputs = [
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
                        toggle_inputs = [
                            "enable","blockpriv","blockbogons","adv_dhcp_config_advanced","adv_dhcp_config_file_override",
                            "ipv6usev4iface","adv_dhcp6_config_advanced","adv_dhcp6_config_file_override","dhcp6usev4iface",
                            "dhcp6prefixonly","dhcp6-ia-pd-send-hint","dhcp6debug","dhcp6withoutra","dhcp6norelease",
                            "adv_dhcp6_interface_statement_information_only_enable","adv_dhcp6_id_assoc_statement_address_enable",
                            "adv_dhcp6_id_assoc_statement_prefix_enable",
                        ]
                        # Select inputs
                        select_inputs = [
                            "type","type6","mediaopt","subnet","gateway","alias-subnet","subnetv6","gatewayv6","dhcp6-ia-pd-len",
                            "adv_dhcp6_prefix_selected_interface"
                        ]
                        get_if_config = http_request(url + "/interfaces.php?if=" + pfId, {}, {}, {}, 45, "GET")["text"]    # Get our HTML response
                        # LOOP AND SAVE OUR TOGGLE/CHKBOX INPUTS
                        for chk in toggle_inputs:
                            # Check if our interface is enabled
                            if "name=\"" + chk + "\"" in get_if_config:
                                ifaces["ifaces"][pfId][chk] = "yes" if "checked=\"checked\"" in get_if_config.split("name=\"" + chk + "\"")[1].split("</label>")[0] else ""
                            # Assign default to false
                            else:
                                ifaces["ifaces"][pfId][chk] = False
                        # LOOP AND SAVE OUR VALUE INPUTS
                        for ipts in value_inputs:
                            # Check if we have a value for our input
                            input_tag = get_if_config.split("name=\"" + ipts + "\"")[1].split(">")[0]
                            if "name=\"" + ipts + "\"" in get_if_config and "value=\"" in input_tag:
                                ifaces["ifaces"][pfId][ipts] = get_if_config.split("name=\"" + ipts + "\"")[1].split(">")[0].split("value=\"")[1].split("\"")[0]     # Get our value
                            # If we do not have this option, assign empty string
                            else:
                                ifaces["ifaces"][pfId][ipts] = ""    # Assign default as empty string
                        # LOOP AND SAVE OUR SELECTION INPUTS
                        for sct in select_inputs:
                            # If the selection exists
                            if "name=\"" + sct + "\"" in get_if_config:
                                 # Loop through our option list and find our currently selected value
                                option_list = get_if_config.split("name=\"" + sct + "\"")[1].split("</select>")[0].split("<option value=\"")
                                for opt in option_list:
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
        # If we encountered an error, return the error
        else:
            ifaces["ec"] = err_check
    # If we could pull our data through XML return that dictionary
    else:
        ifaces = ifaces_xml
    # Return our data dictionary
    return ifaces

# get_interfaces() pulls existing interface configurations from interfaces_assign.php and interfaces.php
def get_available_interfaces(server, user, key):
    # Local Variables
    ifaces = {"ec": 2, "if_add": []}    # Predefine our dictionary that will track our VLAN data as well as errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    ifaces["ec"] = 10 if check_dns_rebind_error(url, None) else ifaces["ec"]    # Return exit code 10 if dns rebind error found
    ifaces["ec"] = 6 if not validate_platform(url, None) else ifaces["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ifaces["ec"] == 2:
        ifaces["ec"] = 3 if not check_auth(server, user, key) else ifaces["ec"]    # Return exit code 3 if we could not sign in
    # Check if we did not encountered any errors thus far, continue if not
    if ifaces["ec"] == 2:
        get_if_data = http_request(url + "/interfaces_assign.php", {}, {}, {}, 45, "GET")    # Pull our interface data using GET HTTP
        # Check that we have a table body to pull from
        if "<tbody>" in get_if_data["text"]:
            # Target only HTML data between our tbody tags
            if_table_body = get_if_data["text"].split("<tbody>")[1].split("</tbody>")[0]    # Save data between tbody tags
            # Determine interfaces that are available but unused
            if "<select name=\"if_add\"" in if_table_body:
                if_add_list = if_table_body.split("<select name=\"if_add\"")[1].split("</select>")[0].split("<option value=\"")    # Split our response into a list of options
                # Loop through our options and add available interfaces
                for ifAddOpt in if_add_list:
                    ifaces["if_add"].append(ifAddOpt.split("\"")[0])    # Add our option to the list
                # Check that we have data
                if len(ifaces["if_add"]) > 0:
                    del ifaces["if_add"][0]    # Delete the first value as it is not needed
            ifaces["ec"] = 0
        # If we could not parse input
        else:
            ifaces["ec"] = 9    # Assign could not parse exit code
    # Return our ifaces dictionary
    return ifaces

# find_interface_pfid() will search the interface dictionary and return the physical if ID, the pf ID or the descriptive ID of a interface given a value
def find_interface_pfid(server, user, key, id_var, dct):
    # Local variables
    pf_id = {"ec": 2, "pf_id": ""}    # Initialize our return dictionary
    dct = get_interfaces(server, user, key) if dct in [None, {}] else dct    # Allow user to pass in dictionary, otherwise pull it
    # Check that our dictionary was populated successfully
    if dct["ec"] == 0:
        # Loop through our interface dict and see if our values match
        for key,value in dct["ifaces"].items():
            # Check if our id matches the entries in this key
            if id_var in [value["pf_id"],value["id"]] or id_var.lower() == value["descr"].lower():
                pf_id["pf_id"] = value["pf_id"]    # save our key value as the pf_id
                pf_id["ec"] = 0    # Update our return code to 0 (success)
                break    # Break our loop as we only need one value
    # If we did not pull our dictionary successfully, pass the return code listed in the dictionary
    else:
        pf_id["ec"] = dct["ec"]
    # Return our dictiontary
    return pf_id

# get_vlan_ids() pulls existing VLAN configurations from Interfaces > Assignments > VLANs
def get_vlan_ids(server, user, key):
    # Local Variables
    vlans = {"ec" : 2, "vlans" : {}}    # Predefine our dictionary that will track our VLAN data as well as errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    # Submit our intitial request and check for errors
    vlans["ec"] = 10 if check_dns_rebind_error(url, None) else vlans["ec"]    # Return exit code 10 if dns rebind error found
    vlans["ec"] = 6 if not validate_platform(url, None) else vlans["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if vlans["ec"] == 2:
        vlans["ec"] = 3 if not check_auth(server, user, key) else vlans["ec"]    # Return exit code 3 if we could not sign in
    # Check if we did not encountered any errors thus far, continue if not
    if vlans["ec"] == 2:
        get_vlan_data = http_request(url + "/interfaces_vlan.php", {}, {}, {}, 45, "GET")    # Pull our VLAN data using GET HTTP
        # Check that we had permissions for this page
        if check_permissions(get_vlan_data):
            vlan_table_body = get_vlan_data["text"].split("<tbody>")[1].split("</tbody>")[0]    # Find the data table body
            vlan_table_rows = vlan_table_body.replace("\t","").replace("\n","").replace("</tr>", "").split("<tr>")    # Find each of our table rows
            # For each VLAN entry, parse the individual table data field
            counter = 0    # Create a counter to track the current VLAN item's placement ID
            for row in vlan_table_rows:
                vlan_table_data = row.replace("</td>", "").split("<td>")    # Split our row values into list of data fields
                # If the row has the minimum number of data fields, parse the data
                if len(vlan_table_data) >= 6:
                    vlans["vlans"][counter] = {}    # Predefine our current table data entry as a dictionary
                    vlans["vlans"][counter]["interface"] = vlan_table_data[1].split(" ")[0]    # Save our interface ID to the dictionary
                    vlans["vlans"][counter]["vlan_id"] = vlan_table_data[2]    # Save our VLAN ID to the dictionary
                    vlans["vlans"][counter]["priority"] = vlan_table_data[3]    # Save our priority level to the dictionary
                    vlans["vlans"][counter]["descr"] = vlan_table_data[4]    # Save our description to the dictionary
                    vlans["vlans"][counter]["id"] = vlan_table_data[5].split("href=\"interfaces_vlan_edit.php?id=")[1].split("\" ></a>")[0]    # Save our configuration ID to the dictionary
                    counter = counter + 1    # Increase our counter by 1
            # If our vlans dictionary was populated, return exit code 0
            vlans["ec"] = 0 if len(vlans["vlans"]) > 0 else vlans["ec"]
        # If we did not have the correct permissions return error code 15
        else:
            vlans["ec"] = 15    # Return error code 15 (permission denied)
    # Return our dictionary
    return vlans

# add_vlan_id() creates a VLAN tagged interface provided a valid physical interface in Interfaces > Assignments > VLANs
def add_vlan_id(server, user, key, iface, vlan_id, priority, descr):
    # Local Variables
    vlan_added = 2    # Assign our default return code. (2 means generic failure)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    existing_vlans = get_vlan_ids(server, user, key)    # Get our dictionary of configured VLANs
    vlan_post_data = {"__csrf_magic" : "", "if" : iface, "tag" : vlan_id, "pcp" : priority, "descr" : descr, "save" : "Save"}    # Assign our POST data
    # Check if we got our VLAN dictionary successfully
    if existing_vlans["ec"] == 0:
        # Loop through existing VLAN to check that our requested VLAN ID isn't already configured
        for key, value in existing_vlans["vlans"].items():
            if iface == value["interface"] and vlan_id == value["vlan_id"]:
                vlan_added = 8  # Return exit code 8 (VLAN already exists
                break  # Break the loop as we have found a match
        # Check that we did not encounter an error
        if vlan_added == 2:
            # Use GET HTTP to see what interfaces are available
            get_existing_ifaces = http_request(url + "/interfaces_vlan_edit.php", {}, {}, {}, 45, "GET")    # Get our HTTP response
            # Check that we had permissions for this page
            if check_permissions(get_existing_ifaces):
                iface_sel = get_existing_ifaces["text"].split("<select class=\"form-control\" name=\"if\" id=\"if\">")[1].split("</select>")[0]    # Pull iface select tag
                iface_opt = iface_sel.split("<option value=\"")    # Pull our raw options to a list
                iface_values = []    # Predefine our final iface value list
                # Check that we have at least one value
                if len(iface_opt) > 0:
                    # Loop through each value and save it's iface value to our final list
                    for i in iface_opt:
                            i = i.replace("\t","").replace("\n","").split("\">")[0]    # Pull the iface value from the value= parameter
                            iface_values.append(i)    # Add our values to the list
                    # Check that we have our values
                    if len(iface_values) > 0:
                        # Check that our requested iface is available
                        if iface in iface_values:
                            # Update our csrf token and submit our POST request
                            vlan_post_data["__csrf_magic"] = get_csrf_token(url + "/interfaces_vlan_edit.php", "GET")
                            vlan_post_req = http_request(url + "/interfaces_vlan_edit.php", vlan_post_data, {}, {}, 45, "POST")
                            # Check that our new value is now configured
                            vlan_check = get_vlan_ids(server, user, key)
                            # Loop through existing VLAN and check for our value
                            if vlan_check["ec"] == 0:
                                for key, value in vlan_check["vlans"].items():
                                    # Assign exit code 0 (success) if our value is now in the configuration. Otherwise retain error
                                    vlan_added = 0 if iface == value["interface"] and vlan_id == value["vlan_id"] else vlan_added
                        # If our request iface is not available
                        else:
                            vlan_added = 7    # Assign exit code 7 (iface not available)
                    # If we did not have any usable interfaces
                    else:
                        vlan_added = 1    # Assign exit code 1 (no usable interfaces)
            # If we did not have permissions to the page
            else:
                vlan_added = 15    # Assign exit code 15 (permission denied)
    # If we failed to get our VLAN dictionary successfully, return the exit code of that function
    else:
        vlan_added = existing_vlans["ec"]    # Assign our get_vlan_ids() exit code to our return value
    # Return our exit code
    return vlan_added

# add_auth_server_ldap() adds an LDAP server configuration to Advanced > User Mgr > Auth Servers
def add_auth_server_ldap(server, user, key, descr_name, ldap_server, ldap_port, transport, ldap_protocol, timeout, search_scope, base_dn, auth_containers, ext_query, query, bind_anon, bind_dn, bind_pw, ldap_template, user_attr, group_attr, member_attr, rfc_2307, group_obj, encode, user_alt):
    # Local Variables
    ldap_added = 2    # Set return value to 2 by default (2 mean general failure)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    default_attrs = {
        "open" : {"user" : "cn", "group" : "cn", "member" : "member"},    # Assign default attributes for OpenLDAP
        "msad" : {"user" : "samAccountName", "group" : "cn", "member" : "memberOf"},     # Assign default attributes for MS Active Directory
        "edir" : {"user" : "cn", "group" : "cn", "member" : "uniqueMember"}}    # Assign default attributes for Novell eDirectory
    # Define a dictionary for our LDAP server configuration POST data
    add_auth_server_data = {
        "__csrf_magic": "",
        "name": descr_name,
        "type": "ldap",
        "ldap_host": ldap_server,
        "ldap_port": str(ldap_port),
        "ldap_urltype": transport,
        "ldap_protver": ldap_protocol,
        "ldap_timeout": timeout,
        "ldap_scope": search_scope,
        "ldap_basedn": base_dn,
        "ldapauthcontainers": auth_containers,
        "ldap_extended_enabled": ext_query,
        "ldap_extended_query": query,
        "ldap_anon": bind_anon,
        "ldap_binddn": bind_dn,
        "ldap_bindpw": bind_pw,
        "ldap_tmpltype": ldap_template,
        "ldap_attr_user": user_attr if user_attr is not "" and user_attr is not "default" else default_attrs[ldap_template]['user'],
        "ldap_attr_group": group_attr if user_attr is not "" and user_attr is not "default" else default_attrs[ldap_template]['group'],
        "ldap_attr_member": member_attr if user_attr is not "" and user_attr is not "default" else default_attrs[ldap_template]['member'],
        "ldap_rfc2307": rfc_2307,
        "ldap_attr_groupobj": group_obj,
        "ldap_utf8": encode,
        "ldap_nostrip_at": user_alt,
        "save": "Save"
    }
    # Check for errors and assign exit codes accordingly
    ldap_added = 10 if check_dns_rebind_error(url, None) else ldap_added    # Return exit code 10 if dns rebind error found
    ldap_added = 6 if not validate_platform(url, None) else ldap_added    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if ldap_added == 2:
        ldap_added = 3 if not check_auth(server, user, key) else ldap_added    # Return exit code 3 if we could not sign in
    # Check that no errors have occurred so far (should be at 2)
    if ldap_added == 2:
        # Check that we have permission to these pages before proceeding
        add_auth_permissions = http_request(url + "/system_authservers.php?act=new", {}, {}, {}, "GET")
        if check_permissions(add_auth_permissions):
            # Update our CSRF token and submit our POST request
            add_auth_server_data["__csrf_magic"] = get_csrf_token(url + "/system_authservers.php?act=new", 45, "GET")
            add_auth_server = http_request(url + "/system_authservers.php?act=new", add_auth_server_data, {}, {}, 45, "POST")
            ldap_added = 0
        # If we did not have permissions to the page
        else:
            ldap_added = 15    # Return exit code 15 (permission denied)
    # Return our exit code
    return ldap_added

def get_dns_entries(server, user, key):
    # Local variables
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Assign our base URL
    dns_dict = {"domains" : {}, "ec" : 2}    # Initialize our DNS entry dictionary as empty
    # Submit our intitial request and check for errors
    dns_dict["ec"] = 10 if check_dns_rebind_error(url, None) else dns_dict["ec"]    # Return exit code 10 if dns rebind error found
    dns_dict["ec"] = 6 if not validate_platform(url, None) else dns_dict["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if dns_dict["ec"] == 2:
        dns_dict["ec"] = 3 if not check_auth(server, user, key) else dns_dict["ec"]    # Return exit code 3 if we could not sign in
    # Check that login was successful
    if dns_dict["ec"] == 2:
        # Check that we have access to these pages before proceeding
        get_dns_resp = http_request(url + "/services_unbound.php", {}, {}, {}, 45, "GET")
        if check_permissions(get_dns_resp):  # Check that we had permissions for this page
            # Pull our DNS entries
            dns_body = get_dns_resp["text"].split("<tbody>")[1].split("</tbody>")[0]
            dns_rows = dns_body.split("<tr>")
            # Cycle through our DNS rows to pull out individual values
            for r in dns_rows:
                r_invalid = False    # Tracks if a valid record was identified
                # Try to parse our values into a dictionary
                try:
                    host = r.split("<td>")[1].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                    domain = r.split("<td>")[2].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                    ip = r.split("<td>")[3].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                    descr = r.split("<td>")[4].replace("\t", "").replace("</td>", "").replace("\n", "").replace("<i class=\"fa fa-angle-double-right text-info\"></i>", "")
                    id_var = r.split("<td>")[5].split("?id=")[1].split("\">")[0].replace("\t", "").replace("</td>", "").replace("\n", "").replace(" ", "")
                except IndexError:
                    r_invalid = True
                # Check if entry is an alias
                if not r_invalid:
                    # Check if IP contains the word ALIASFOR
                    if "Aliasfor" in ip:
                        alias_fqdn = ip.split("Aliasfor")[1]    # Assign our alias FQDN
                        alias_host = None   # Declare a variable for our aliases parent hostname
                        alias_domain = None # Declare a variable for our aliases parent domain name
                        # Check what domain the alias is tied to
                        if alias_fqdn.endswith(prev_domain):
                            alias_domain = prev_domain
                            alias_host = alias_fqdn.replace("." + alias_domain, "").replace(alias_domain, "")
                        # If we found our aliases parent domain and host
                        if alias_host is not None and alias_domain is not None:
                            dns_dict["domains"][alias_domain][alias_host]["alias"][host] = {"hostname" : host, "domain" : domain, "descr" : descr}
                    # Otherwise add our item normally
                    else:
                        dns_dict["domains"][domain] = {} if not domain in dns_dict["domains"] else dns_dict["domains"][domain]
                        dns_dict["domains"][domain][host] = {"hostname" : host, "domain" : domain, "ip" : ip, "descr" : descr, "id" : id_var, "alias" : {}}
                        prev_domain = domain    # Keep track of our previous domain
                    # Set our exit code to 0
                    dns_dict["ec"] = 0
        # If we did not have permissions to the page
        else:
            dns_dict["ec"] = 15    # Return exit code 15 (permission denied)
    # Return our dictionary
    return dns_dict

# add_dns_entry() performs the necessary requests to add a DNS entry to pfSense's Unbound service
def add_dns_entry(server, user, key, host, domain, ip, descr):
    # Local Variables
    record_added = 2    # Set return value to 2 by default (2 means failed)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    dns_data = {"__csrf_magic": "","host" : host,"domain" : domain, "ip" : ip, "descr" : descr, "save" : "Save"}    # Define our DNS entry POST data
    save_dns_data = {"__csrf_magic": "", "apply": "Apply Changes"}    # Define our apply DNS changes POST data
    # Check if the record we are adding already exists
    if not check_dns(server, user, key, host, domain):
        # Check for errors and assign exit codes accordingly
        record_added = 10 if check_dns_rebind_error(url, None) else record_added    # Return exit code 10 if dns rebind error found
        record_added = 6 if not validate_platform(url, None) else record_added    # Check that our URL appears to be pfSense
        # Check if we have not encountered an error that would prevent us from authenticating
        if record_added == 2:
            record_added = 3 if not check_auth(server, user, key) else record_added    # Return exit code 3 if we could not sign in
        # Check that no errors have occurred so far (should be at 2)
        if record_added == 2:
            # Check we have permissions to the pages
            dns_read_permissions = http_request(url + "/services_unbound.php", {}, {}, {}, 45, "GET")
            dns_add_permissions = http_request(url + "/services_unbound_host_edit.php", {}, {}, {}, 45, "GET")
            if check_permissions(dns_add_permissions) and check_permissions(dns_read_permissions):
                # Update our CSRF token and add our DNS entry
                dns_data["__csrf_magic"] = get_csrf_token(url + "/services_unbound_host_edit.php", "GET")
                dns_check = http_request(url + "/services_unbound_host_edit.php", dns_data, {}, {}, 45, "POST")
                # Update our CSRF token and save changes
                save_dns_data["__csrf_magic"] = get_csrf_token(url + "/services_unbound.php", "GET")
                save_check = http_request(url + "/services_unbound.php", save_dns_data, {}, {}, 45, "POST")
                # Check if a record is now present
                if check_dns(server, user, key, host, domain):
                    record_added = 0    # Set return variable 0 (0 means successfully added)
            # If we did not have permissions to the page
            else:
                record_added = 15    # Return exit code 15 (permission denied)
    # If a DNS record already exists
    else:
        record_added = 9    # Set return value to 9 (9 means record already existed when function started)
    # Return exit code
    return record_added

# get_ssl_certs() pulls the list of existing certificates on a pfSense host. This function basically returns the data found on /system_certmanager.php
def get_ssl_certs(server, user, key):
    # Local Variables
    cert_manager_dict = {"ec" : 2, "certs" : {}}     # Initialize cert_manager_dict to return our certificate values and exit codes
    cert_index = 0    # Initialize cert_index to track the certificate number in the list/loop
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    # Submit our intitial request and check for errors
    cert_manager_dict["ec"] = 10 if check_dns_rebind_error(url, None) else cert_manager_dict["ec"]    # Return exit code 10 if dns rebind error found
    cert_manager_dict["ec"] = 6 if not validate_platform(url, None) else cert_manager_dict["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if cert_manager_dict["ec"] == 2:
        cert_manager_dict["ec"] = 3 if not check_auth(server, user, key) else cert_manager_dict["ec"]    # Return exit code 3 if we could not sign in
    if cert_manager_dict["ec"] == 2:
        # Check that we had permissions for this page
        get_cert_data = http_request(url + "/system_certmanager.php", {}, {}, {}, 45, "GET")
        if check_permissions(get_cert_data):
            # Parse our output
            cert_row_list = get_cert_data['text'].split("<tbody>")[1].split("</tbody>")[0].split("<tr>")
            # Cycle through each table row containing certificate info and parse accordingly
            # End format will be a multi-dimensional list. Example: list[[index, name, issuer, cn, start, end, serial]]
            for tr in cert_row_list:
                # Check if table row is empty
                if tr.replace(" ", "").replace("\t", "").replace("\n", "") != "":
                    # Try to format table data into the certificate name
                    try:
                        cert_name = tr.replace(" ", "").replace("\n", "").replace("\t", "").split("<td>")[1].split("<br/>")[0]    # Replace whitespace and parse HTML until we receive or name value
                    except Exception as x:
                        cert_name = "ERROR"
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
                        str_dte = tr.replace("\t", "").split("<small>")[1].split("</small>")[0].split("Valid From: <b>")[1].split("</b>")[0].replace(" ", "_")[:-6]
                    except Exception as x:
                        str_dte = "ERROR"
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
                    cert_manager_dict["certs"][cert_index] = {"name" : cert_name, "issuer" : isr, "cn" : cn, "start" : str_dte, "expire" : exp, "serial" : srl, "active" : ciu}
                    cert_index = cert_index + 1
            # Assign exit code 0 if we have our dictionary populated
            cert_manager_dict["ec"] = 0 if len(cert_manager_dict["certs"]) > 0 else cert_manager_dict["ec"]
        # If we did not have permissions
        else:
            cert_manager_dict["ec"] = 15    # Return exit code 15 (permissions denied)
    # Return our data dict
    return cert_manager_dict

# add_ssl_cert() performs the necessary requests to add an SSL certificate to pfSense's WebConfigurator
def add_ssl_cert(server, user, key, cert, certkey, descr):
    # Local Variables
    cert_added = 2    # Set return value to 2 by default (2 means failed)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    pre_cert_dict = get_ssl_certs(server, user, key)    # Get the current dict of certificate installed on pfSense
    pre_cert_dict_len = len(pre_cert_dict["certs"])    # Track the length of existing certificates in the dict
    # Define a dictionary for our SSL certificate POST data values
    add_cert_data = {
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
    cert_added = 10 if check_dns_rebind_error(url, None) else cert_added    # Return exit code 10 if dns rebind error found
    cert_added = 6 if not validate_platform(url, None) else cert_added    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if cert_added == 2:
        cert_added = 3 if not check_auth(server, user, key) else cert_added    # Return exit code 3 if we could not sign in
    # Only proceed if an error has not occurred
    if cert_added == 2:
        # Check our permissions
        permission_check = http_request(url + "/system_certmanager.php?act=new", {}, {}, {}, 45, "GET")
        if check_permissions(permission_check):
            # Add SSL cert and check for the added cert afterwards
            add_cert_data["__csrf_magic"] = get_csrf_token(url + "/system_certmanager.php?act=new", "GET")
            post_check = http_request(url + "/system_certmanager.php?act=new", add_cert_data, {}, {}, 45, "POST")
            post_cert_dict = get_ssl_certs(server, user, key)  # Get the current dict of certificate installed on pfSense
            post_cert_dict_len = len(post_cert_dict["certs"])  # Track the length of existing certificates in the dict
            # Check if the dict increased in size by one when we added a new certificate
            if post_cert_dict_len == pre_cert_dict_len + 1:
                # Check if our descr matches the new certificates name
                if descr == post_cert_dict["certs"][post_cert_dict_len - 1]["name"]:
                    cert_added = 0    # We now know the certificate that was added was the certificate intended
        # If we did not have permissions
        else:
            cert_added = 15    # Return exit code 15 (permission denied)
    # Return exit code
    return cert_added

# set_wc_certificate() sets which WebConfigurator SSL certificate to use via /system_advanced_admin.php
def set_wc_certificate(server, user, key, cert_name):
    # Local Variables
    wcc_check = 2    # Initialize wcc_check to track errors, this will be returned by the function
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    selected_wcc = ""    # Initialize variable to track which certificate is currently selected
    new_wcc = ""    # Initialize variable to track the cert_ref of our certificate to add
    wcc_found = False    # Initialize boolean to track whether a certificate match has already occurred
    existing_wcc_data = get_system_advanced_admin(server, user, key)["adv_admin"]    # Pull our existing configuration before making changes
    wcc_data = {"__csrf_magic" : "", "webguiproto" : PfaVar.wc_protocol, "ssl-certref" : ""}
     # Check for errors and assign exit codes accordingly
    wcc_check = 10 if check_dns_rebind_error(url, None) else wcc_check    # Return exit code 10 if dns rebind error found
    wcc_check = 6 if not validate_platform(url, None) else wcc_check    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if wcc_check == 2:
        wcc_check = 3 if not check_auth(server, user, key) else wcc_check    # Return exit code 3 if we could not sign in
    # Check that authentication was successful
    if wcc_check == 2:
        # Check that we have permissions to this page first
        get_sys_adv_adm = http_request(url + "/system_advanced_admin.php", {}, {}, {}, 45, "GET")
        if check_permissions(get_sys_adv_adm):
            # Make GET request to /system_advanced_admin.php to check response, split the response and target the SSL cert selection HTML field
            get_sys_adv_adm_list = get_sys_adv_adm["text"].split("<select class=\"form-control\" name=\"ssl-certref\" id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=")
            # For each option in the selection box, check that the value is expected and parse the data
            for wcc in get_sys_adv_adm_list:
                # Remove trailing characters from wcc
                wcc = wcc.replace("\n", "").replace("\t", "")
                # Ensure the option is not blank and that option is found in the field
                if wcc != "" and "</option>" in wcc:
                    # Try to split and parse the data to find the expected values
                    try:
                        cert_ref = wcc.split(">")[0].replace("\"", "")    # Parse the option and save the certificate reference number
                        cert_id = wcc.split(">")[1].split("</option")[0]    # Parse the option and save the certificate ID
                    except IndexError as x:
                        pass
                    # Check if cert_ref is currently selected, save this value
                    if "selected" in cert_ref:
                        cert_ref = cert_ref.replace(" selected", "")    # Remove the selected string
                        selected_wcc = cert_ref    # Assign cert_ref to selected_wcc
                    # Check if our certID matches our cert_name passed into the function
                    if cert_id == cert_name:
                        # Check if a certificate was already matched, return error 5 if so
                        if wcc_found:
                            wcc_check = 4    # Assign exit code 4 to wcc_check (means multiple certs were found)
                            wcc_found = False    # Revert back to false, multiple matches means we can't determine which one the user actually wants
                            break    # Break the loop as we have multiple certs matching the same name
                        wcc_found = True
                        new_wcc = cert_ref    # Assign our new webconfigurator certificate ID to a permanent variable
            # Check if we found a legitimate match and no error occurred
            if wcc_found:
                # Check if our cert_ref values are different (meaning we are actually changing the certificate)
                if new_wcc != selected_wcc:
                    # Loop through our existing /system_advanced_admin.php configuration and add the data to the POST request
                    for table,data in existing_wcc_data.items():
                        # Loop through each value in the table dictionaries
                        for key,value in data.items():
                            value = "yes" if value == True else value    # Swap true values to "yes"
                            value = "" if value == False else value    # Swap false values to empty string
                            # Check if we are checking our login protection whitelist
                            if key == "whitelist":
                                # Add each of our whitelisted IPs to our post data
                                for id_var,info in value.items():
                                    addr_id = info["id"]
                                    wcc_data[addr_id] = info["value"]
                                    wcc_data["address_subnet" + id_var] = info["subnet"]
                            # If we are not adding whitelist values, simply add the key and value
                            else:
                                wcc_data[key] = value    # Populate our data to our POST data
                    # Update our CSRF, certref, and take our POST request and save a new GET request that should show our new configuration
                    wcc_data["__csrf_magic"] = get_csrf_token(url + "/system_advanced_admin.php", "GET")
                    wcc_data["ssl-certref"] = new_wcc
                    post_sys_adv_adm = http_request(url + "/system_advanced_admin.php", wcc_data, {}, {}, 45, "POST")
                    check_sys_adv_adm = http_request(url + "/system_advanced_admin.php", {}, {}, {}, 45, "GET")["text"]
                    check_sys_adv_adm = check_sys_adv_adm.split("<select class=\"form-control\" name=\"ssl-certref\" id=\"ssl-certref\">")[1].split("</select>")[0].split("<option value=")
                    # Parse the new GET response to a list of HTML selection options
                    for wcc in check_sys_adv_adm:
                        # Try to split and parse the data to find the expected values
                        try:
                            cert_ref = wcc.split(">")[0].replace("\"", "")    # Parse the option and save the certificate reference number
                        # Add tolerance for IndexErrors, if we could not parse it, it is invalid data
                        except IndexError as x:
                            pass
                        # Check if cert_ref is currently selected, save this value
                        if "selected" in cert_ref:
                            cert_ref = cert_ref.replace(" selected", "")    # Remove the selected string
                            new_selected_wcc = cert_ref    # Assign cert_ref to selected_wcc
                            if new_selected_wcc == new_wcc:
                                wcc_check = 0
                else:
                    wcc_check = 1    # Assign exit code 1 (means specified certificate is already being used)
            # If we couldn't find the cert, and we didn't find multiple, return exit code 5
            elif not wcc_found and wcc_check != 4:
                wcc_check = 5    # Return exit code 5, certificate not found
        # If we do not have permission
        else:
            wcc_check = 15    # Return exit code 15 (permission denied)
    # Return our exit code
    return wcc_check

# get_firewall_rules_xml() reads ACLs via the XML config
def get_firewall_rules_xml(server, user, key, iface):
    # Local Variables
    rules = {"ec" : 2, "rules" : {"antilockout": False, "bogons": False, "private": False, "user_rules": {}}}    # Pre-define our dictionary to track alias values and errors
    # Check if we have not initialized our XML config and we are running in remote target mode
    if not XmlConfigs.init:
        update_config(server, user, key)    # Initialize our XML configuration
    # Check that our configuration was pulled
    if xml_indicator in XmlConfigs.master:
        # Check if we did not encountered any errors thus far, continue if not
        if rules["ec"] == 2:
            xml_rule_dict = convert_xml(XmlConfigs.master)["pfsense"]["filter"]    # Save our interface dictionary from XML
            export_json(xml_rule_dict,"/tmp/","rulesxml.json")
            # Check that our dictionary is not empty
            if xml_rule_dict is not None and len(xml_rule_dict) > 0:
                # Define lists of our expected values
                txt_value_list = ["type","interface","ipprotocol","protocol","statetype","descr","tag","tagged","max","max-src-nodes"
                                  "max-src-conn","max-src-states","statetimeout","os",]
                cbx_value_list = ["allowopts","tcpflags_any","tcpflags1_rst",""]
                ip_types = []
                ipv6_types = []
                # Loop through each item in our dictionary and create nested dictionaries
                for key, val in xml_rule_dict.items():
                    rules["rules"]["user_rules"][key] = {}
                # Return success exit code
                rules["ec"] = 0    # Return exit code 0
    # Return our dictionary
    return rules

# get_firewall_rules_xml("10.7.200.2", "admin", "pfsense", "lan")
# sys.exit()

# get_firewall_rules() pulls the ACL for a specified interface and returns the rules
def get_firewall_rules(server, user, key, iface):
    # Local variables
    rules = {"ec" : 2, "rules" : {"antilockout": False, "bogons": False, "private": False, "user_rules": {}}}    # Pre-define our dictionary to track alias values and errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    rules["ec"] = 10 if check_dns_rebind_error(url, None) else rules["ec"]    # Return exit code 10 if dns rebind error found
    rules["ec"] = 6 if not validate_platform(url, None) else rules["ec"]    # Check that our URL appears to be pfSense
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
            get_rule_ids = http_request(url + "/firewall_rules.php?if=" + iface, {}, {}, {}, 45, "GET")    # Save our GET HTTP response
            get_rule_edit = http_request(url + "/firewall_rules_edit.php", {}, {}, {}, 45, "GET")  # Save our GET HTTP response
            if check_permissions(get_rule_ids) and check_permissions(get_rule_edit):
                # GATHER PFSENSE RULE IDs & FW STATE DATA/STATISTICS
                # Loop through possible system rules and check if our rules list contains the system rules
                system_rules = ["antilockout","private","bogons"]
                for r in system_rules:
                    if "<tr id=\"" + r + "\">" in get_rule_ids["text"]:
                        rules["rules"][r] = True    # Change default false value to True
                # Check if we have user defined rules, if so capture only the table between the <tbody> tags
                if "<tbody class=\"user-entries\">" in get_rule_ids["text"]:
                    rules["ec"] = 0
                    usr_rule_body = get_rule_ids["text"].split("<tbody class=\"user-entries\">")[1].split("</tbody>\n\t\t\t</table>")[0]
                    # Check that our user table has table rows, if so split the string into a list of rows
                    if "<tr" in usr_rule_body:
                        user_rule_rows = usr_rule_body.split("<tr")
                        # Loop through our rows and pull the rule ID from each row
                        for row in user_rule_rows:
                            # Check that our ID field exists
                            if "ondblclick=\"document.location='firewall_rules_edit.php?id=" in row:
                                id_var = row.split("ondblclick=\"document.location='firewall_rules_edit.php?id=")[1].split("\'")[0]    # The value before our first `"` char is our ID
                                # Check if our ID is a number
                                if id_var.isdigit():
                                    # Create a nested dictionary for each user rule
                                    rules["rules"]["user_rules"][id_var] = {"id": id_var}
                                    # Check if a custom gateway was used for this rule, otherwise assume default
                                    if "<i class=\"fa fa-cog\" title=\"advanced setting: gateway" in row:
                                        rules["rules"]["user_rules"][id_var]["gateway"] = row.split("<i class=\"fa fa-cog\" title=\"advanced setting: gateway")[1].split("\">")[0].replace(" ","")
                                    else:
                                        rules["rules"]["user_rules"][id_var]["gateway"] = ""
                # GATHER INDIVIDUAL FIREWALL RULE CONFIGURATION
                # Loop through each of our user rule IDs to gather data
                for urId,urDict in rules["rules"]["user_rules"].items():
                    # GET the edit page for this ID and read it's contents
                    ur_get_data = http_request(url + "/firewall_rules_edit.php?id=" + urId, {}, {}, {}, 45, "GET")
                    # SINGLE SELECT FORMS: Get the values for each of our single option <select> forms #
                    s_select_forms = ["type","interface","ipprotocol","proto","icmptype[]","srctype","srcbeginport","srcendport","srcmask","dsttype",
                                   "dstbeginport","dstendport","dstmask","os","dscp","statetype","vlanprio","vlanprioset","sched",
                                   "dnpipe","pdnpipe","ackqueue","defaultqueue"]
                    # Loop through each of our expected single select form names and get there configured values
                    for ssf in s_select_forms:
                        # Default each of these values to blank string if it does not exist already
                        if ssf not in rules["rules"]["user_rules"][urId]:
                            rules["rules"]["user_rules"][urId][ssf] = ""
                        exp_tag1 = "<select class=\"form-control\" name=\"" + ssf + "\" id=\"" + ssf + "\">"    # Define the tag we expect to find
                        exp_tag2 = "<select class=\"form-control pfIpMask\" name=\"" + ssf + "\" id=\"" + ssf + "\">"
                        exp_tag3 = "<select class=\"form-control\" name=\"" + ssf + "\" id=\"" + ssf + "\" multiple=\"multiple\">"
                        # Check that this form exists
                        if exp_tag1 in ur_get_data["text"]:
                            select_data = ur_get_data["text"].split(exp_tag1)[1].split("</select>")[0]    # Capture all data between our select tags
                            # Check that we have options
                            if "<option" in select_data:
                                opt_list = select_data.split("<option")    # Split our options into a list
                                # Loop through our options to find the selected value
                                for opt in opt_list:
                                    if "selected>" in opt:
                                        rules["rules"]["user_rules"][urId][ssf] = opt.split("value=\"")[1].split("\"")[0]
                        # Check that an alternate select form exists with this name
                        elif exp_tag2 in ur_get_data["text"]:
                            select_data = ur_get_data["text"].split(exp_tag2)[1].split("</select>")[0]    # Capture all data between our select tags
                            # Check that we have options
                            if "<option" in select_data:
                                opt_list = select_data.split("<option")    # Split our options into a list
                                # Loop through our options to find the selected value
                                for opt in opt_list:
                                    if "selected>" in opt:
                                        rules["rules"]["user_rules"][urId][ssf] = opt.split("value=\"")[1].split("\"")[0]
                        # Check that an alternate select form exists with this name
                        elif exp_tag3 in ur_get_data["text"]:
                            select_data = ur_get_data["text"].split(exp_tag3)[1].split("</select>")[0]    # Capture all data between our select tags
                            rules["rules"]["user_rules"][urId][ssf] = []    # Define a list with our multi data listing
                            # Check that we have options
                            if "<option" in select_data:
                                opt_list = select_data.split("<option")    # Split our options into a list
                                # Loop through our options to find the selected value
                                for opt in opt_list:
                                    if "selected>" in opt:
                                        rules["rules"]["user_rules"][urId][ssf].append(opt.split("value=\"")[1].split("\"")[0])
                    # CHECKBOX FORMS: Get the values for each of our yes/no checkbox input forms #
                    cbx_forms = ["disabled","srcnot","dstnot","log","allowopts","disablereplyto","nopfsync","nosync"
                                "tcpflags1_syn","tcpflags1_rst","tcpflags1_psh","tcpflags1_ack","tcpflags1_urg",
                                "tcpflags1_ece","tcpflags1_cwr","tcpflags2_syn","tcpflags2_rst","tcpflags2_psh",
                                "tcpflags2_ack","tcpflags2_urg","tcpflags2_ece","tcpflags2_cwr","tcpflags_any"]
                    # Loop through each checkbox form and check it's value
                    for cb in cbx_forms:
                        rules["rules"]["user_rules"][urId][cb] = ""    # Assign a default for each value
                        exp_tag1 = "name=\"" + cb + "\""    # Define our expected tag
                        exp_tag2 = "name=\'" + cb + "\'"    # Define our other expected tag
                        # Check if the value exists
                        if exp_tag1 in ur_get_data["text"]:
                            cbx_data = ur_get_data["text"].split(exp_tag1)[1].split(">")[0]     # Capture our input form data
                            if "checked" in cbx_data:
                                rules["rules"]["user_rules"][urId][cb] = cbx_data.split("value=\"")[1].split("\"")[0]    # Assign value if the box is checked
                        elif exp_tag2 in ur_get_data["text"]:
                            cbx_data = ur_get_data["text"].split(exp_tag2)[1].split(">")[0]     # Capture our input form data
                            if "checked" in cbx_data:
                                rules["rules"]["user_rules"][urId][cb] = cbx_data.split("value=\'")[1].split("\'")[0]    # Assign value if the box is checked
                    # TEXT FORMS: Get the values for each of our text input forms #
                    txt_forms = ["descr","tag","tagged","src","srcbeginport_cust","srcendport_cust","dst","dstbeginport_cust", "dstendport_cust"]
                    # Loop through each text form and check it's value
                    for txt in txt_forms:
                        rules["rules"]["user_rules"][urId][txt] = ""    # Assign a default for each value
                        exp_tag = "<input class=\"form-control\" name=\"" + txt + "\""    # Define our expected tag
                        # Check if the value exists
                        if exp_tag in ur_get_data["text"]:
                            txt_data = ur_get_data["text"].split(exp_tag)[1].split(">")[0]     # Capture our input form data
                            if "value=\"" in txt_data:
                                rules["rules"]["user_rules"][urId][txt] = txt_data.split("value=\"")[1].split("\"")[0]    # Save value of the input field
                    # NUMBER FORMS: Get the values for each of our number input forms #
                    num_forms = ["max","max-src-nodes","max-src-conn","max-src-states","max-src-conn-rate","max-src-conn-rates","statetimeout"]
                    # Loop through each text form and check it's value
                    for num in num_forms:
                        rules["rules"]["user_rules"][urId][num] = ""    # Assign a default for each value
                        exp_tag = "id=\"" + num + "\" type=\"number\""    # Define our expected tag
                        # Check if the value exists
                        if exp_tag in ur_get_data["text"]:
                            num_data = ur_get_data["text"].split(exp_tag)[1].split(">")[0]     # Capture our input form data
                            if "value=\"" in num_data:
                                rules["rules"]["user_rules"][urId][num] = num_data.split("value=\"")[1].split("\"")[0]    # Save value of the input field
                    # Add our SOURCE and DEST nets if the interface network is used as src or dst
                    src_type = rules["rules"]["user_rules"][urId]["srctype"]    # Save our source type for quick use later
                    dst_type = rules["rules"]["user_rules"][urId]["dsttype"]    # Save our destination type for quick use later
                    src_value = rules["rules"]["user_rules"][urId]["src"]    # Save our source value for quick use later
                    dst_value = rules["rules"]["user_rules"][urId]["dst"]    # Save our destination value for quick use later
                    src_mask = rules["rules"]["user_rules"][urId]["srcmask"]    # Save our source mask for quick use later
                    dst_mask = rules["rules"]["user_rules"][urId]["srcmask"]    # Save our destination mask for quick use later
                    rules["rules"]["user_rules"][urId]["src_net"] = ""    # Default our src net value
                    rules["rules"]["user_rules"][urId]["dst_net"] = ""    # Default our dst net value
                    # SRC NET
                    if src_value in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["src_net"] = ifaces["ifaces"][src_value]["ipaddr"] + "/" + ifaces["ifaces"][src_value]["subnet"]
                    elif src_value.rstrip("ip") in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["src_net"] = ifaces["ifaces"][src_value.rstrip("ip")]["ipaddr"]
                    elif src_value != "" and src_mask != "" and src_type == "network":
                        rules["rules"]["user_rules"][urId]["src_net"] = src_value + "/" + src_mask
                    # DST NET
                    if dst_value in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["dst_net"] = ifaces["ifaces"][dst_value]["ipaddr"] + "/" + ifaces["ifaces"][dst_value]["subnet"]
                    elif dst_value.rstrip("ip") in ifaces["ifaces"]:
                        rules["rules"]["user_rules"][urId]["dst_net"] = ifaces["ifaces"][dst_value.rstrip("ip")]["ipaddr"]
                    elif dst_value != "" and dst_mask != "" and dst_type == "network":
                        rules["rules"]["user_rules"][urId]["dst_net"] = dst_value + "/" + dst_mask
            # If permission was denied, return exit code (permission denied)
            else:
                rules["ec"] = 15
        # If our interface was invalid return exit code 4 (iface not found)
        else:
            rules["ec"] = 4
    # Return our dictionary
    return rules

# get_firewall_rule_state_data() reads the state data of firewall rules given an interface ACL
def get_firewall_rule_state_data(server, user, key, iface):
    # Local variables
    rules = {"ec" : 2, "rules" : {}}    # Pre-define our dictionary to track alias values and errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    err_check = check_errors(server, user, key, ["firewall_rules.php"])
    # Check that no errors were found
    if err_check == 2:
        ifaces = get_interfaces(server, user, key)    # Get a dictionary of our configured interfaces
        iface = find_interface_pfid(server, user, key, iface, ifaces)["pf_id"]    # Save our interfaces pfID
        rules["rules"]["acl_interface"] = iface    # Save what interface this ACL is for
        # Check if our interface is valid (not empty string)
        if iface != "":
            get_rule_ids = http_request(url + "/firewall_rules.php?if=" + iface, {}, {}, {}, 45, "GET")    # Save our GET HTTP response
            # GATHER PFSENSE RULE IDs & FW STATE DATA/STATISTICS
            # Check if we have user defined rules, if so capture only the table between the <tbody> tags
            if "<tbody class=\"user-entries\">" in get_rule_ids["text"]:
                rules["ec"] = 0
                usr_rule_body = get_rule_ids["text"].split("<tbody class=\"user-entries\">")[1].split("</tbody>\n\t\t\t</table>")[0]
                # Check that our user table has table rows, if so split the string into a list of rows
                if "<tr" in usr_rule_body:
                    user_rule_rows = usr_rule_body.split("<tr")
                    # Loop through our rows and pull the rule ID from each row
                    for row in user_rule_rows:
                        # Check that our ID field exists
                        if "ondblclick=\"document.location='firewall_rules_edit.php?id=" in row:
                            id_var = row.split("ondblclick=\"document.location='firewall_rules_edit.php?id=")[1].split("\'")[0]    # The value before our first `"` char is our ID
                            # Check if our ID is a number
                            if id_var.isdigit():
                                # Create a nested dictionary for each user rule
                                rules["rules"][id_var] = {
                                    "id": id_var,
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
                                # Check for a state table ID for this rule, save it to our dict if exists and is a number
                                if "<td><a href=\"diag_dump_states.php?ruleid=" in row:
                                    state_id = row.split("<td><a href=\"diag_dump_states.php?ruleid=")[1].split("\"")[0]
                                    rules["rules"][id_var]["state_rule_id"] = state_id if state_id.isdigit() else ""
                                    # Loop through our state data to gather state statistics and information
                                    state_data = ["Tracking ID","evaluations", "packets", "bytes", "states", "state creations"]     # Create list of data fields to capture
                                    table_data_content = "<br>" + row.split("data-content=\"")[1].split("\"")[0] + "<br>" if "data-content=\"" in row else ""    # Capture the entire data content if found
                                    for sd in state_data:
                                        # Check that the field exists for this data
                                        if "<br>" + sd + ":" in table_data_content:
                                            sd_value = table_data_content.split("<br>" + sd + ":")[1].split("<br>")[0].replace(" ", "")     # Capture the data for each field between the <br> tags
                                            rules["rules"][id_var]["state_" + sd.replace("state ", "").replace(" ", "_").lower()] = sd_value    # Save our captured value into the corresponding dict key
        # If our interface does not exist
        else:
            rules["ec"] = 4
    # If we encountered an error
    else:
        rules["ec"] = err_check
    # Return our data
    return rules

# add_firewall_rule() adds a new basic firewall rule to a specified interface
def add_firewall_rule(server, user, key, iface, type_var, ipver, proto, iv_src, src, src_bit, src_port, iv_dst, dst, dst_bit, dst_port, gw, descr, log, pos, no_port):
    # Local variables
    rule_added = 2    # Init our return value as 2 (error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    current_rules = get_firewall_rules(server, user, key, iface)    # Pull our existing firewall rules for this interface
    # Check that we were able to pull our rules successfully
    if current_rules["ec"] == 0:
        # Check our port value
        src_port_check = validate_port_range(src_port)    # Check if our src port is valid and capture the start and end port
        dst_port_check = validate_port_range(dst_port)    # Check if our dst port is valid and capture the start and end port
        if src_port_check["valid"] or no_port == True:
            if dst_port_check["valid"] or no_port == True:
                # Format our POST data dictionary
                rule_post_data = {
                    "__csrf_magic": get_csrf_token(url + "/firewall_rules_edit.php","GET"),
                    "interface": current_rules["rules"]["acl_interface"],
                    "after": "-1" if pos.lower() == "top" else None,
                    "type": type_var,
                    "ipprotocol": ipver,
                    "proto": proto,
                    "srcnot": "yes" if iv_src == True else "",
                    "srctype": "network",
                    "src": src,
                    "srcmask": src_bit,
                    "srcbeginport_cust": str(src_port_check["start"]),
                    "srcendport_cust": str(src_port_check["end"]),
                    "dstnot": "yes" if iv_dst == True else "",
                    "dsttype": "network",
                    "dst": dst,
                    "dstmask": dst_bit,
                    "dstbeginport_cust": str(dst_port_check["start"]) if not no_port else "",
                    "dstendport_cust": str(dst_port_check["end"]) if not no_port else "",
                    "gateway": gw,
                    "descr": descr,
                    "log": "yes" if log == True else "",
                    "save": "Save"
                }
                rule_save_data = {"apply": "Apply Changes", "__csrf_magic": get_csrf_token(url + "/firewall_rules.php", "GET")}
                # Run our POST request to add the new rule and apply our changes
                post_rule = http_request(url + "/firewall_rules_edit.php", rule_post_data, {}, {}, 45, "POST")
                save_post_rule = http_request(url + "/firewall_rules.php", rule_save_data, {}, {}, 45, "POST")
                update_rules = get_firewall_rules(server, user, key, iface)    # Pull our updated firewall rules for this interface
                # Check that we updated our dictionary
                if update_rules["ec"] == 0:
                    rule_key = list(update_rules["rules"]["user_rules"].keys())[0] if pos == "top" else list(update_rules["rules"]["user_rules"].keys())[-1]    # Determnine the rule's ACL position
                    values_list = ["type","src","dst","proto","descr","log"]    # Create a list of values to verify
                    value_match = False
                    # Loop through each value to check and ensure it is the same
                    for v in values_list:
                        value_match = False    # Assign a bool to track when our values match
                        if rule_post_data[v] == update_rules["rules"]["user_rules"][rule_key][v]:
                            value_match = True
                        else:
                            break
                    if value_match:
                        rule_added = 0    # Assign exit code 0 (success)
            # If our dest port or port range is invalid
            else:
                rule_added = 5    # Return exit code 5 (invalid dest port)
        # If our source port or port range is invalid
        else:
            rule_added = 4    # Return exit code 4 (invalid source port)
    # If we were not able to pull our current firewall rules, return the exit code of get_firewall_rules()
    else:
        rule_added = current_rules["ec"]
    # Return our exit code
    return rule_added

# del_firewall_rule() removes a firewall rule entry from a specified interface's ACL
def del_firewall_rule(server, user, key, iface, rule_id):
    # Local variables
    rule_del = 2    # Init our return value as 2 (error)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    current_rules = get_firewall_rules(server, user, key, iface)    # Get our current firewall ACL
    # Check that we pulled our ACL without error
    if current_rules["ec"] == 0:
        # Check if our rule ID is in the current ACL
        if rule_id in current_rules["rules"]["user_rules"]:
            # Format our POST dictionaries
            del_rule_post_data = {
                "__csrf_magic": get_csrf_token(url + "/firewall_rules.php?if=" + current_rules["rules"]["acl_interface"], "GET"),
                "act": "del",
                "if": current_rules["rules"]["acl_interface"],
                "id": rule_id
            }
            rule_save_data = {"apply": "Apply Changes", "__csrf_magic": get_csrf_token(url + "/firewall_rules.php", "GET")}
            # Make our POST requests
            del_rule_post = http_request(url + "/firewall_rules.php", del_rule_post_data, {}, {}, 45, "POST")
            save_post = http_request(url + "/firewall_rules.php", rule_save_data, {}, {}, 45, "POST")
            update_rules = get_firewall_rules(server, user, key, iface)  # Update our ACL dict
            # Check that our rule was deleted
            if rule_id in update_rules["rules"]["user_rules"]:
                if current_rules["rules"]["user_rules"][rule_id] != update_rules["rules"]["user_rules"][rule_id]:
                    rule_del = 0    # Return our success exit code
            else:
                rule_del = 0    # Return our success exit code
        # If our rule ID was not found
        else:
            rule_del = 5    # Return exit code 4 (rule not found)
    # If we encountered an error pulling our current rules, return error returned by get_firewall_rules()
    else:
        rule_del = current_rules["ec"]
    # Return our exit code
    return rule_del

# get_firewall_aliases() pulls aliases information from pfSense and saves it to a Python dictionary
def get_firewall_aliases(server, user, key):
    # Local variables
    aliases = {"ec" : 2, "aliases" : {}}    # Pre-define our dictionary to track alias values and errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    aliases["ec"] = 10 if check_dns_rebind_error(url, None) else aliases["ec"]    # Return exit code 10 if dns rebind error found
    aliases["ec"] = 6 if not validate_platform(url, None) else aliases["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if aliases["ec"] == 2:
        aliases["ec"] = 3 if not check_auth(server, user, key) else aliases["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if aliases["ec"] == 2:
        # Check that we had permissions for this page
        get_alias_ids = http_request(url + "/firewall_aliases.php?tab=all", {}, {}, {}, 45, "GET")    # Save our GET HTTP response
        get_alias_edit = http_request(url + "/firewall_aliases_edit.php", {}, {}, {}, 45, "GET")  # Save our GET HTTP response
        if check_permissions(get_alias_ids) and check_permissions(get_alias_edit):
            # GET aliases IDs from /firewall_aliases.php
            alias_id_table_body = get_alias_ids["text"].split("<tbody>")[1].split("</tbody>")[0]    # Pull the table body data from HTML response
            alias_id_table_rows = alias_id_table_body.replace("\n", "").replace("\t", "").replace("</tr>", "").split("<tr>")    # Split our table body into list of rows
            # Loop through our list and grab our data values
            id_list = []    # Pre-define our id_list. This will be populated by our loop
            for row in alias_id_table_rows:
                # Check that the row contains an ID
                if "id=" in row:
                    id_var = row.split("id=")[1].split("\';\">")[0]    # Pull the ID from the row
                    id_list.append(id_var)    # Add our current ID to the list
            # Loop through alias IDs and save values to our dictionary
            for i in id_list:
                get_alias_id_info = http_request(url + "/firewall_aliases_edit.php?id=" + i, {}, {}, {}, 45, "GET")    # Save our GET HTTP response
                check_permissions(get_alias_id_info)  # Check that we had permissions for this page
                name = get_alias_id_info["text"].split("<input class=\"form-control\" name=\"name\" id=\"name\" type=\"text\" value=\"")[1].split("\"")[0]    # Save our alias name
                descr = get_alias_id_info["text"].split("<input class=\"form-control\" name=\"descr\" id=\"descr\" type=\"text\" value=\"")[1].split("\"")[0]    # Save our alias description
                type_var = ""    # Pre-define our type as empty string. This should be populated by our loop below
                # Loop through our type <select> tag to see what type is currently selected
                type_opt = get_alias_id_info["text"].split("<select class=\"form-control\" name=\"type\" id=\"type\">")[1].split("</select>")[0].split("<option ")    # Save our typeOptions as a list
                for opt in type_opt:
                    # Check if option is selected
                    if "selected" in opt:
                        type_var = opt.split("value=\"")[1].split("\"")[0]    # Save our type value
                # Save our dict values
                aliases["aliases"][name] = {"name" : name, "type" : type_var, "descr" : descr, "id" : i, "entries" : {}}
                # Loop through our alias entries and pull data
                counter = 0    # Define a counter to keep track of loop cycle
                while True:
                    # Check if there is an address value for our current index
                    if "id=\"address" + str(counter) in get_alias_id_info["text"]:
                        aliases["aliases"][name]["entries"][counter] = {} if counter not in aliases["aliases"][name]["entries"] else aliases["aliases"][name]["entries"][counter]    # Create our counter dictionary if not existing
                        aliases["aliases"][name]["entries"][counter]["id"] = str(counter)    # Save our counter value
                        aliases["aliases"][name]["entries"][counter]["value"] = get_alias_id_info["text"].split("id=\"address" + str(counter))[1].split("value=\"")[1].split("\"")[0]    # Save our entry value
                        aliases["aliases"][name]["entries"][counter]["descr"] = get_alias_id_info["text"].split("id=\"detail" + str(counter))[1].split("value=\"")[1].split("\"")[0]    # Save our entry value
                        subnet_opt = get_alias_id_info["text"].split("id=\"address_subnet" + str(counter))[1].split("</select>")[0].split("<option")    # Return our list of subnets
                        # Loop through list of subnets to see if one is selected
                        for opt in subnet_opt:
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
def modify_firewall_alias(server, user, key, alias_name, new_values):
    # Local Variables
    alias_id_data = get_firewall_aliases(server, user, key)    # Get the alias ID to determine which alias to modify
    alias_modded = 2 if alias_id_data["ec"] == 0 else alias_id_data["ec"]    # Default alias_modded to 2 if authentication didn't fail when we pulled the aliasIDData, otherwise return 3 (auth failed)
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    # If we successfully pulled our aliasId
    if alias_modded == 2:
        # Check if our alias name is in our dictionary
        if alias_name in alias_id_data["aliases"]:
            alias_id_value = alias_id_data["aliases"][alias_name]["id"]   # Assign the actual alias ID value to a variable
            alias_post_data = {"__csrf_magic" : get_csrf_token(PfaVar.wc_protocol + "://" + server + "/firewall_aliases_edit.php?id=" + alias_id_value, "GET"), "name" : alias_name, "type" : "host", "tab" : "ip", "id" : alias_id_value, "save" : "Save"}
            value_to_add = ""    # Initialize our new alias entry values
            detail_to_add = ""   # Initializes our new alias entry description values
            default_detail = "Auto-added by " + user + " on " + PfaVar.local_hostname    # Initializes our default alias entry description value
            # Check if the new_values needs to be parsed
            if "," in new_values:
                new_value_list = new_values.split(",")    # Split our values to a list
                new_val_index = 0    # Assign an index tracker for our for loop. This will be used to track the address value in our post request
                # For each value in our list, print an address to our post request
                for val in new_value_list:
                    # Only add the value if the list item is not emtpy
                    if val != '':
                        alias_post_data["address" + str(new_val_index)] = val
                        alias_post_data["detail" + str(new_val_index)] = default_detail
                        new_val_index = new_val_index + 1    # Increase our loop index
            # Else if our data did not need to be parsed
            else:
                alias_post_data["address0"] = new_values
                alias_post_data["detail0"] = default_detail
            # Make our post request if no errors were encountered
            if alias_modded == 2:
                # Check that we have permissions to run
                post_pf_alias_data = http_request(url + "/firewall_aliases_edit.php", {}, {}, {}, 45, "GET")
                if check_permissions(post_pf_alias_data):
                    # Submit our post requests
                    post_pf_alias_data = http_request(url + "/firewall_aliases_edit.php", alias_post_data, {}, {}, 45, "POST")
                    save_changes_post_data = {"__csrf_magic" : get_csrf_token(PfaVar.wc_protocol + "://" + server + "/firewall_aliases.php", "GET"), "apply" : "Apply Changes"}
                    save_changes = http_request(url + "/firewall_aliases.php", save_changes_post_data, {}, {}, 45, "POST")
                    alias_modded = 0    # Assign our success exit code
                # If we did not have permissions to the page
                else:
                    alias_modded = 15    # Return exit code 15 (permission denied)
        # If our alias name was not found
        else:
            alias_modded = 4    # Return exit code 4 (alias not found)
    # Return our integer exit code
    return alias_modded

# get_virtual_ips() reads the configured virtual IPs from firwall_virtual_ip.php
def get_virtual_ips(server, user, key):
    # Local variables
    virt_ips = {"ec" : 2, "virtual_ips" : {}}    # Pre-define our dictionary to track alias values and errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
     # Check for errors and assign exit codes accordingly
    virt_ips["ec"] = 10 if check_dns_rebind_error(url, None) else virt_ips["ec"]    # Return exit code 10 if dns rebind error found
    virt_ips["ec"] = 6 if not validate_platform(url, None) else virt_ips["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if virt_ips["ec"] == 2:
        virt_ips["ec"] = 3 if not check_auth(server, user, key) else virt_ips["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if virt_ips["ec"] == 2:
        # Check that we had permissions for this page
        get_virt_ip_ids = http_request(url + "/firewall_virtual_ip.php", {}, {}, {}, 45, "GET")    # Save our GET HTTP response
        get_virt_ip_edit = http_request(url + "/firewall_virtual_ip_edit.php", {}, {}, {}, 45, "GET")  # Save our GET HTTP response
        if check_permissions(get_virt_ip_ids) and check_permissions(get_virt_ip_edit):
            # Parse our HTML output to capture the ID of each virtual IP
            if "<tbody>" in get_virt_ip_ids["text"]:
                # Return our success exit code
                virt_ips["ec"] = 0
                virt_ip_id_table_body = get_virt_ip_ids["text"].split("<tbody>")[1].split("</tbody>")[0]    # Capture all data between our tbody tags
                virtual_ip_id_table_rows = virt_ip_id_table_body.split("<tr>")[1:]    # Split our table body into list of rows indicated by the tr tag (remove first entry)
                # Loop through each of our rows and pull the virtual IPs ID
                for r in virtual_ip_id_table_rows:
                    row_data = r.split("<td>")    # Split our row into the individual table data values
                    virt_ip_id = row_data[5].split("firewall_virtual_ip_edit.php?id=")[1].split("\">")[0]    # Split our data value to capture the virtual IP ID
                    virt_ip_descr_name = row_data[1].replace("\n","").replace("\t","").replace("</td>","")    # Capture our virtual IPs descriptive name and remove unneeded chars
                    virt_ips["virtual_ips"][virt_ip_id] = {"id":virt_ip_id,"descr_name":virt_ip_descr_name}    # Save each virtual IP to it's own nested dictionary
                    # Pull further configuration from the firewall_virtual_ip_edit.php page if our ID is valid
                    if virt_ip_id.isdigit():
                        get_adv_virt_ip_data = http_request(url + "/firewall_virtual_ip_edit.php?id=" + virt_ip_id, {}, {}, {}, 45, "GET")
                        # Check that we have a TYPE configuration table
                        required_tags = ["<span class=\"element-required\">Type</span>","<span class=\"element-required\">Interface</span>"]    # Set list of tags required for this section
                        if all(tag in get_adv_virt_ip_data["text"] for tag in required_tags):
                            virt_ip_type_data = get_adv_virt_ip_data["text"].split(required_tags[0])[1].split(required_tags[1])[0]    # Capture the data in our virt IP type table
                            virt_ip_types = virt_ip_type_data.split("<label class=\"chkboxlbl\"><input name=\"mode\"")[1:]    # Split our types into a list to check values in
                            # Loop through our Virtual IP types and determine the current configured type
                            for type_var in virt_ip_types:
                                # Check if this type is currently checked
                                if "checked=\"checked\"" in type_var:
                                    virt_ips["virtual_ips"][virt_ip_id]["type"] = type_var.split("value=\"")[1].split("\"")[0]    # Split our type value and add it to the dictionary
                                    break    # Break our loop to save processing
                                # Assume default if no type is selected
                                else:
                                    virt_ips["virtual_ips"][virt_ip_id]["type"] = ""  # Assign empty string as default
                        # If we do not have the necessary tags, return default
                        else:
                            virt_ips["virtual_ips"][virt_ip_id]["type"] = ""    # Assign empty string as default
                        # Check that we have an INTERFACE configuration table
                        required_tags = ["<select class=\"form-control\" name=\"interface\" id=\"interface\">","</select>"]    # Set list of tags required for this section
                        if all(tag in get_adv_virt_ip_data["text"] for tag in required_tags):
                            virt_ip_if_data = get_adv_virt_ip_data["text"].split(required_tags[0])[1].split(required_tags[1])[0]    # Capture the data in our virt IP iface table
                            virt_ip_if_opt = virt_ip_if_data.split("<option")[1:]    # Split our select tag into list of options
                            # Loop through our options and check for selected indicator
                            for opt in virt_ip_if_opt:
                                if "selected>" in opt:
                                    virt_ips["virtual_ips"][virt_ip_id]["interface"] = opt.split("value=\"")[1].split("\"")[0]    # Parse our interface POST value to our dictionary
                                    virt_ips["virtual_ips"][virt_ip_id]["interface_descr"] = opt.split("selected>")[1].split("</option>")[0]    # Parse our descriptive interface name to our dictionary
                                    break    # Break our loop to save processing
                        # If we did not have the required tags, return defaults
                        else:
                            virt_ips["virtual_ips"][virt_ip_id]["interface"] = ""    # Assign default value as empty string
                            virt_ips["virtual_ips"][virt_ip_id]["interface_descr"] = ""    # Assign default value as empty string
                        # Check that we have an IP ADDRESSES configuration table
                        required_tags = ["<input class=\"form-control\" name=\"subnet\"","</select>"]    # Set list of tags required for this section
                        if all(tag in get_adv_virt_ip_data["text"] for tag in required_tags):
                            virt_ip_addr_data = get_adv_virt_ip_data["text"].split(required_tags[0])[1].split(required_tags[1])[0]    # Capture the data in our virt IP address table
                            virt_ips["virtual_ips"][virt_ip_id]["subnet"] = virt_ip_addr_data.split("value=\"")[1].split("\"")[0]    # Capture our configured IP address value and save it to our dictionary
                        # If we did not found our expected tags assume default
                        else:
                            virt_ips["virtual_ips"][virt_ip_id]["subnet"] = ""    # Assign empty string as default
                        # Loop through our SELECT option values to reduce redundant code
                        select_tags = ["subnet_bits","vhid","advbase","advskew"]    # Assign a list of select tags to loop through and pull values from
                        for tg in select_tags:
                            required_tags = ["<select class=\"form-control\" name=\""+tg+"\" id=\""+tg+"\">","</select>"]    # Set list of tags required for this section
                            if all(tag in get_adv_virt_ip_data["text"].replace(" pfIpMask","") for tag in required_tags):
                                virt_ip_tag_data = get_adv_virt_ip_data["text"].replace(" pfIpMask","").split(required_tags[0])[1].split(required_tags[1])[0]    # Capture the data in our virt IP tag table
                                virt_ip_tag_opt = virt_ip_tag_data.split("<option")[1:]    # Split our select tag into list of options
                                # Loop through our tag data and determine which is selected
                                for opt in virt_ip_tag_opt:
                                    # Check if the option is current selected
                                    if "selected" in opt:
                                        virt_ips["virtual_ips"][virt_ip_id][tg] = opt.split("value=\"")[1].split("\"")[0]    # Capture our virt IP tag data and save it to our dictionary
                                        break    # Break our loop to save processing
                                    # If none or selected
                                    else:
                                        virt_ips["virtual_ips"][virt_ip_id][tg] = ""    # Assign empty string as default
                            # If we did not found our expected tags assume default
                            else:
                                virt_ips["virtual_ips"][virt_ip_id][tg] = ""    # Assign empty string as default
                        # Check if our NOEXPAND option is enabled
                        if "<input name=\"noexpand\"" in get_adv_virt_ip_data["text"]:
                            virt_ips["virtual_ips"][virt_ip_id]["noexpand"] = "yes" if "checked=\"checked\"" in get_adv_virt_ip_data["text"].split("<input name=\"noexpand\"")[1].split("</label>")[0] else ""    # Assign our NOEXPAND option to our dictionary
                        # If expected tag does not exist, assume default
                        else:
                            virt_ips["virtual_ips"][virt_ip_id]["noexpand"] = ""
                        # Check for our DESCRIPTION value
                        if "name=\"descr\"" in get_adv_virt_ip_data["text"]:
                            virt_ips["virtual_ips"][virt_ip_id]["descr"] = get_adv_virt_ip_data["text"].split("name=\"descr\"")[1].split("value=\"")[1].split("\"")[0]    # Save our description to the dictionary
                        # If no tag was found return default
                        else:
                            virt_ips["virtual_ips"][virt_ip_id]["descr"] = ""
                    # Break the loop and return error if ID is not valid. This indiciates that we incorrectly parse the output (or their version of pfSense is unsupported)
                    else:
                        virt_ips["ec"] = 2    # Return error exit code
                        break    # Break our loop to exit the function
    # Return our dictionary
    return virt_ips

# add_virtual_ip() adds a new virtual IP to pfSense
def add_virtual_ip(server, user, key, mode, iface, subnet, subnet_bit, expansion, vip_passwd, vhid, advbase, advskew, descr):
    # Local variables
    vip_added = 2    # Initialize our function return code (default 2 as error encountered)
    current_vips = get_virtual_ips(server,user,key)    # Pull our current Virtual IP configuration
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    # Check that we successfully pulled our existing virtual IP configuration
    if current_vips["ec"] == 0:
        # VHID AUTO-DETECTION: Determine our next available VHID for auto specification
        used_vhids = []    # Initialize our list of occupied VHIDs
        auto_vhid = ""    # Initialize our auto detected VHID
        for id_var,data in current_vips["virtual_ips"].items():
            # Ensure that this VHID is configured for our requested interface
            if iface == data["interface"]:
                # Save our VHID value to our list
                used_vhids.append(data["vhid"])
        # Loop through our taken VHIDs and return one that is not taken
        for i in range(256):
            # Check that our iteration is valid
            if 1 <= i <= 255:
                # Check if this VHID is already taken
                if str(i) not in used_vhids:
                    auto_vhid = str(i)    # Assign our auto-detected VHID
                    break    # Break the loop as we only need one value
        # Convert our Python variables to our POST data paramemters to create a vIP POST dictionary
        vip_post_dict = {
            "__csrf_magic" : get_csrf_token(url + "/firewall_virtual_ip_edit.php","GET"),
            "mode" : mode,
            "interface" : iface,
            "type" : "network",
            "subnet" : subnet,
            "subnet_bits" : subnet_bit,
            "noexpand" : expansion if expansion != "" else None,
            "password" : vip_passwd,
            "password_confirm": vip_passwd,
            "vhid" : vhid if vhid != "auto" else auto_vhid,
            "advbase" : advbase,
            "advskew" : advskew,
            "descr" : descr,
            "save" : "Save"
        }
        # Create a dictionary of POST values to apply our virtual IP change
        vip_save_post_dict = {
            "__csrf_magic" : get_csrf_token(url + "/firewall_virtual_ip.php","GET"),
            "apply" : "Apply Changes"
        }
        # Make our POST requests
        post_vip = http_request(url + "/firewall_virtual_ip_edit.php", vip_post_dict, {}, {}, 45, "POST")
        save_vip = http_request(url + "/firewall_virtual_ip.php", vip_save_post_dict, {}, {}, 45, "POST")
        # Check that our new virtual IP is now in our configuration
        new_vips = get_virtual_ips(server,user,key)    # Pull our current Virtual IP configuration
        for id_var,data in new_vips["virtual_ips"].items():
            # Check if our added values exist in this dictionary
            if data["subnet"] == subnet and data["subnet_bits"] == subnet_bit and data["type"] == mode:
                vip_added = 0    # Return our success exit code
                break    # Break the loop as we found our new entry
    # If we encountered an error pulling the existing virtual IPs
    else:
        vip_added = current_vips["ec"]    # Save the exit code from our get_virtual_ips() function to this functions exit code
    # Return our exit code
    return vip_added

# get_status_carp() reads the current CARP status from status_carp.php
def get_status_carp(server, user, key):
    # Local variables
    carp = {"ec" : 2, "carp" : {"status" : "inactive", "maintenance_mode" : False, "carp_interfaces" : {}, "pfsync_nodes" : []}}    # Pre-define our dictionary to track CARP values and errors
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    carp_unconfigured_msg = "No CARP interfaces have been defined."    # Define the message pfSense displays when no CARP interfaces are configured
    carp_enabled_msg = "name=\"disablecarp\" value=\"Temporarily Disable CARP\""    # Define the message pfSense displays when CARP is enabled
    carp_disabled_msg = "name=\"disablecarp\" value=\"Enable CARP\""    # Define the message pfSense displays when CARP is disabled
    carp_maintenance_enabled = "id=\"carp_maintenancemode\" value=\"Leave Persistent CARP Maintenance Mode\""    # Define the message pfSense displays when CARP maintenance mode is enabled
    carp_maintenance_disabled = "id=\"carp_maintenancemode\" value=\"Enter Persistent CARP Maintenance Mode\""    # Define the message pfSense displays when CARP maintenance mode is disabled
     # Check for errors and assign exit codes accordingly
    carp["ec"] = 10 if check_dns_rebind_error(url, None) else carp["ec"]    # Return exit code 10 if dns rebind error found
    carp["ec"] = 6 if not validate_platform(url, None) else carp["ec"]    # Check that our URL appears to be pfSense
    # Check if we have not encountered an error that would prevent us from authenticating
    if carp["ec"] == 2:
        carp["ec"] = 3 if not check_auth(server, user, key) else carp["ec"]    # Return exit code 3 if we could not sign in
    # Check that authentication succeeded
    if carp["ec"] == 2:
        # Check that we had permissions for this page
        get_carp_status_data = http_request(url + "/status_carp.php", {}, {}, {}, 45, "GET")    # Save our GET HTTP response
        if check_permissions(get_carp_status_data):
            # Check that we have a CARP configuration to parse
            if carp_unconfigured_msg not in get_carp_status_data["text"]:
                # Check if CARP is enabled or disabled
                carp["carp"]["status"] = "enabled" if carp_enabled_msg in get_carp_status_data["text"] else carp["carp"]["status"]    # Determine whether CARP is enabled and save the value if it is
                carp["carp"]["status"] = "disabled" if carp_disabled_msg in get_carp_status_data["text"] else carp["carp"]["status"]    # Determine whether CARP is disabled and save the value
                # Check if CARP is in maintenance mode
                carp["carp"]["maintenance_mode"] = True if carp_maintenance_enabled in get_carp_status_data["text"] else carp["carp"]["maintenance_mode"]    # Determine whether CARP maintenance mode is enabled and save the value if it is
                carp["carp"]["maintenance_mode"] = False if carp_maintenance_disabled in get_carp_status_data["text"] else carp["carp"]["maintenance_mode"]    # Determine whether CARP maintenance mode is disabled and save the value
                # Ensure we have a CARP table
                if "<tbody>" in get_carp_status_data["text"]:
                    carp_table_data = get_carp_status_data["text"].split("<tbody>")[1].split("</tbody>")[0]    # Capture all data between our tbody tags
                    carp_table_rows = carp_table_data.split("<tr>")[1:]    # Split table into a list of data rows
                    # Loop through our data rows and parse our data
                    counter = 0    # Create a loop counter to track loop iteration
                    for r in carp_table_rows:
                        row_data = r.split("<td>")  # Save our row data into a list of data points
                        carp["carp"]["carp_interfaces"][counter] = {}    # Create a nested dictionary for each CARP interface in our table
                        carp["carp"]["carp_interfaces"][counter]["interface"] = row_data[1].split("@")[0]    # Split our first table data field to capture our interface ID
                        carp["carp"]["carp_interfaces"][counter]["vhid"] = row_data[1].split("@")[1].replace("</td>","").replace("\t","").replace("\n","")    # Split our first table data field to capture our VHID group
                        carp["carp"]["carp_interfaces"][counter]["cidr"] = row_data[2].split("</td>")[0].replace("\t","").replace("\n","")    # Split our second table data field to capture our CARP CIDR
                        carp["carp"]["carp_interfaces"][counter]["ip"] = carp["carp"]["carp_interfaces"][counter]["cidr"].split("/")[0]    # Split our second table data field to capture our CARP IP address
                        carp["carp"]["carp_interfaces"][counter]["subnet_bits"] = carp["carp"]["carp_interfaces"][counter]["cidr"].split("/")[1]    # Split our second table data field to capture our CARP subnet
                        carp["carp"]["carp_interfaces"][counter]["status"] = row_data[3].split("</i>&nbsp;")[1].split("</td>")[0].lower()    # Split our third table data field to capture our CARP status
                        counter = counter + 1    # Increase our counter
                # Check pfSync node IDs
                if "<br />pfSync nodes:<br /><pre>" in get_carp_status_data["text"]:
                    carp["carp"]["pfsync_nodes"] = get_carp_status_data["text"].split("<br />pfSync nodes:<br /><pre>")[1].split("</pre>")[0].split("\n")[:-1]    # Split each of our nodes into a list
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
    mm_added = 2    # Initialize our function return code (default 2 as error encountered)
    current_carp = get_status_carp(server,user,key)    # Pull our current CARP status
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)    # Populate our base URL
    # Check that we successfully pulled our existing CARP configuration
    if current_carp["ec"] == 0:
        # Check that CARP is enabled
        if len(current_carp["carp"]["carp_interfaces"]) > 0:
            # Check that we are actually changing the value before bothering with a POST request
            if current_carp["carp"]["maintenance_mode"] != enable:
                # Format our POST data dictionary
                mm_post_data = {"__csrf_magic":get_csrf_token(url + "/status_carp.php", "GET"), "carp_maintenancemode":""}
                # Check whether user want to enable or disable maintenance mode
                if enable:
                    mm_post_data["carp_maintenancemode"] = "Enter Persistent CARP Maintenance Mode"    # Enter maintenance mode POST value
                elif not enable:
                    mm_post_data["carp_maintenancemode"] = "Leave Persistent CARP Maintenance Mode"    # Exit maintenance mode POST value
                # Make our POST request but don't wait for a response
                set_mm_post = http_request(url + "/status_carp.php", mm_post_data, {}, {}, 45, "POST")    # POST our change to pfSense
                # Check that our value was set correctly
                updated_carp = get_status_carp(server, user, key)  # Pull our updated CARP status
                if updated_carp["ec"] == 0:
                    if updated_carp["carp"]["maintenance_mode"] == enable:
                        mm_added = 0   # Assign success exit code
                # If we could not pull our exist CARP status, exit on function exit code
                else:
                    mm_added = current_carp["ec"]    # Return the exit code returned by our get_status_carp() function
            # If we are already set to the requested mode, return success
            else:
                mm_added = 0  # Assign success exit code
        # If pfSense does not have any configured CARP interfaces
        else:
            mm_added = 4    # Assign exit code 4 (CARP not configured)
    # If we could not pull our exist CARP status, exit on function exit code
    else:
        mm_added = current_carp["ec"]    # Return the exit code returned by our get_status_carp() function
    # Return our exit code
    return mm_added

# setup_hapfsense() automates the process needed to run pfSense in full high availability
def setup_hapfsense(server, user, key, backup_node, carp_ifs, carp_ips, carp_passwd, pfsync_if, pfsync_ip):
    # Local variables
    ha_active = 2  # Initialize our function return code (default 2 as error encountered)
    get_master_ver = get_pfsense_version(server, user, key)    # Get the pfSense version of our master node
    get_backup_ver = get_pfsense_version(backup_node, user, key)    # Get the pfSense version of our backup node
    url = PfaVar.wc_protocol + "://" + server + ":" + str(PfaVar.wc_protocol_port)  # Populate our base URL
    all_sync_opts = {"synchronizeusers": "on", "synchronizeauthservers": "on", "synchronizecerts": "on",
                     "synchronizerules": "on", "synchronizeschedules": "on", "synchronizealiases": "on",
                     "synchronizenat": "on", "synchronizeipsec": "on", "synchronizeopenvpn": "on",
                     "synchronizedhcpd": "on", "synchronizewol": "on", "synchronizestaticroutes": "on",
                     "synchronizelb": "on", "synchronizevirtualip": "on", "synchronizetrafficshaper": "on",
                     "synchronizetrafficshaperlimiter": "on", "synchronizednsforwarder": "on",
                     "synchronizecaptiveportal": "on"}
    # Check that we were able to check our pfSense version on our master and backup nodes
    if get_master_ver["ec"] == 0:
        if get_backup_ver["ec"] == 0:
            # Check if our pfSense versions match
            if get_master_ver["version"]["installed_version"] == get_backup_ver["version"]["installed_version"]:
                # Add our CARP interfaces to MASTER
                counter = 0    # Start a loop counter to track our loop iteration
                vip_failed = False    # Track whether we encountered an error during our CARP additions
                for i in carp_ips:
                    c_vip = add_virtual_ip(server, user, key, "carp", carp_ifs[counter], i, "32", "", carp_passwd, "auto", "0", "1", "HA PFSENSE IP: Auto-added by pfsense-automator")
                    # Check if we failed to add the CARP address
                    if c_vip != 0:
                        ha_active = 13
                        vip_failed = True
                        break
                    counter = counter + 1    # Increase our counter
                # Check if we added all CARP addresses successfully
                if not vip_failed:
                    # Add our HA SYNC configuration to sync the CARP interfaces to the backup node
                    master_sync = setup_hasync(server, user, key, "on", pfsync_if, pfsync_ip, backup_node, user, key, all_sync_opts)
                    # Check that HA SYNC was successfully configured
                    if master_sync == 0:
                        ha_active = 0   # Assign return code 0 (success)
                    # If HA SYNC failed
                    else:
                        ha_active = 14
            # If our version do not match exactly, return error
            else:
                ha_active = 12    # Return code 13 (versions do not match)
        # If we could not pull our pfSense version on our backup node, return the get_pfsense_version()'s return code
        else:
            ha_active = get_backup_ver["ec"]
    # If we could not pull our pfSense version on our master node, return the get_pfsense_version()'s return code
    else:
        ha_active = get_master_ver["ec"]
    # Return our exit code
    return ha_active
