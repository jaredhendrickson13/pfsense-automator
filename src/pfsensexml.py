#!/usr/bin/python3
# PURPOSE: pfsense-xml.py contains the functions necessary to read configuration straight from the core XML file
# AUTHOR: Jared Hendrickson - Copyright 2020

### IMPORTS ###
import pfsensewc
import platform
import os
import subprocess
import xmltodict

### GLOBAL VARIABLES ###
debug = False    # Assign a bool to change values when debug is enabled
local_config_xml_path = "/tmp/config.xml" if debug else "/conf/config.xml"   # Save the file path of our local config.xml file
local_systems = ["FreeBSD","Darwin","Windows","Linux"] if debug else ["FreeBSD"]    # Create a list of Operating Systems that pfSense runs on (currently only FreeBSD)
xml_target_local = os.path.exists(local_config_xml_path) if platform.system() in local_systems else False    # Determine whether the local system is pfSense
xml_indicator = "<pfsense>"    # Save a string that contains the XML indicator that we're working with a pfSense configuration

### CLASSES ###
class XmlConfigs:
    init = False    # Save a bool to track whether our config values are populated
    master = ""    # Our master XML config
    backup = ""    # Our previous XML config

### FUNCTIONS ###
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
        # Try to pull our config using SSH, if we catch an error return empty string
        try:
            ssh_xml = subprocess.check_output(ssh_cmd, shell=True, stderr=open(os.devnull, "w")).decode('utf-8')
        except subprocess.CalledProcessError:
            ssh_xml = ""
        # Check if we pulled the config via SSH, if not, pull via webConfigurator
        if xml_indicator not in ssh_xml:
            # Try to pull our XML config via the fastest method first (backup tool)
            xml_backup = pfsensewc.get_xml_backup(server, user, key, "", False, True, False, "")    # Pull our XML config through webConfigurator's backup tool
            # Check if our XML was pulled successfully through the backup tool
            if xml_backup["ec"] == 0:
                xml = xml_backup["xml"]    # Save our config
            # Otherwise pull the XML using the shell tool
            else:
                xml_shell = pfsensewc.get_shell_output(server, user, key, "cat " + local_config_xml_path)    # Pull our XML config through webConfigurator's shell tool
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
                    interfaces["ifaces"][key]["id"] = interfaces["ifaces"][key]["if"]    # Save our ID as our interface
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
