
pfSense Automator
=========
PFSENSE-AUTOMATOR - pfSense Automation command line tool
Copyright 2019 - Jared Hendrickson

Description
------------  
pfSense Automator translates pfSense's WebConfigurator into a command line tool. This allows 
you to easily run or automate pfSense configuration changes via your command line. This is
made possible by initiating HTTP POST/GET requests to gather and submit configuration changes.
All security features such as CSRF and syntax checks are left intact and changes appear exactly
as they would via the WebConfigurator UI

Supported pfSense builds: 2.3.x, 2.4.x, 2.5.x

Syntax
------------
- `pfsense-automator <pfSense IP or hostname> <COMMAND> <ARGUMENTS> -u <USERNAME> -p <PASSWORD>`

Commands
------------
- `--add-vlan` : Attempts to add a new VLAN tag to a specified interface
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-vlan <iface> <vlan_id> <priority> <descr>`
    - **Arguments**:
        - `<iface>` : Specify an existing physical interface to add the VLAN tag to (e.g. igb1, re0)
        - `<vlan_id>` : Specify what VLAN ID to tag the interface as (1-4094)
        - `<priority>` : Specify the VLAN priority value for QoS purposes (0-7)
        - `<descr>` : Specify a description for the VLAN. Use `default` to add the username and local hostname of individual running the command

- `--read-vlans` : Attempts to read current configured VLANs
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-vlans <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all available VLAN values 
        - `--vlan=<vlan_id>` : Return only one entry given a valid VLAN ID
        - `--iface=<iface_id>` (`-i`) : Return only VLANs configured on a specific interface 
        - `--json=<directory_path>` : Exports VLAN data to a JSON file given an existing directory

- `--add-dns` : Attempts to add a DNS entry to Unbound (DNS Resolver). This will not overwrite existing DNS entries
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-dns <subdomain> <primary_domain> <IP> <description>`
    - **Arguments**: 
        - `<subdomain>` : Specify the subdomain of the DNS entry (SUBDOMAIN.primarydomain.com)
        - `<primary_domain>` : Specify the primary domain of the DNS entry (subdomain.PRIMARYDOMAIN.COM)
        - `<IP>` : Specify the IPv4 address that the record will resolve to 
        - `<description>` : Add a custom description to the DNS entry
        - `default` : Adds a default description that includes the users username and hostname 

- `--read-dns` : Attempts to read current DNS Resolver (Unbound) entries
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-dns <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all available DNS values including aliases
        - `--default` (`-d`) : Return only base entries, no aliases are included
        - `--host=<FQDN>` (beta) : Return only one entry given exact FQDN. If an alias matches the FQDN, the parent entry is printed             
        - `--json=<directory_path>` : Exports SSL certificate data to a JSON file given an existing directory

- `--add-sslcert` : Attempts to add a new external certificate to pfSense's Certificate Manager
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-sslcert <cert_file_path> <key_file_path> <cert_name>`
    - **Arguments**:
        - `<cert_file_path>` : Specify a file path to the certificate file
        - `<key_file_path>` : Specify a file path to the key file
        - `<cert_name>` : Specify the descriptive name of the certificate to display in the Certificate Manager

- `--read-sslcerts` : Attempts to read existing certificates in pfSense's certifiate manager
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-sslcerts <verbosity>`
    - **Arguments**:
        - `<verbosity>`
            - `--verbose` : Includes all details about the certificates
            - `default` : Includes base info
            - `--json=<directory_path>` : Exports SSL certificate data to a JSON file given an existing directory

- `--set-wc-sslcert` : Sets the SSL certificate that the WebConfigurator will use
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --set-wc-sslcert <cert_name>`
    - **Arguments**:
        - `<cert_name>` : Specify which certificate to use by it's certificate name. This much match exactly as it shows in the Certificate Manager. If multiple certificates match the same name, an error is thrown.

- `--read-aliases` : Attempts to read current firewall aliases (only supports host, network and port aliases)
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-aliases <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all available alias values in a YAML like format
        - `--name=<alias_name>` (`-n`) : Return only one alias given a valid alias name
        - `--json=<directory_path>` : Exports alias data to a JSON file given an existing directory

- `--modify-alias` : Modifies an existing Firewall Alias. Existing entries will be overwritten. 
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --modify-alias <alias name> <IPs or hostnames>`
    - **Arguments**:
        - `<alias name>` : Specify which alias you would like to modify, this much match the name exactly
        - `<IPs or hostnames>` : Specify what IPs or hostnames to include in the alias. Multiple entries must be separated by a comma

- `--check-auth` : Attempts to sign in using specified credentials. WARNING: abuse of this function will result in a WebConfigurator lockout
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --check-auth -u <username> -p <password>` 
    - **Arguments**:
        - `-u <username>` : Allows you to pass in the username in the command, leave blank for interactive entry
        - `-p <password>` : Allows you to pass in a password in the command, leave blank for interactive entry

- `--add-ldapserver` : Adds a new LDAP authentication server - this may be configured inline or interactively (will prompt for configuration if missing arguments)
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-ldapserver <descr_name> <IP or hostname> <port> <transport> <protocol> <timeout> <search_scope> <base_dn> <auth_container> <ext_query> <query> <bind_anon> <bind_dn> <bind_pw> <template> <user_attr> <group_attr> <member_attr> <rfc2307> <group_obj> <encode> <user_alt> -u <username> -p <password>`
    - **Arguments**:
        - `<descr_name>` : Specify a descriptive name for the authentication server
        - `<ip_hostname>` : Specify the IP or hostname of the remote LDAP server
        - `<port>` : Specify the TCP port number of the remote LDAP server
        - `<transport>` : Specify the LDAP transport type
        - `standard` : Use standard LDAP (unencrypted)
        - `starttls` : Use TLS encryption if available
        - encrypted : Required encryption on all LDAP queries
        - `<protocol>` : Specify the LDAP protocol version (2 or 3)
        - `<timeout>` : Specify the timeout when connecting to the LDAP server
        - `<search_scope>` : Specify the search scope of LDAP queries
        - `one` : Only search one level of the LDAP subtree 
        - `subtree` : Search the entire subtree
        - `<base_dn>` : Specify your base distinguished name
        - `<auth_container>` : Specify a container queries will check during authentication
        - `<ext_query>` : Enabled extended queries (yes or no)
        - `<query>` : Specify your extended query string (leave blank if `<ext_query>` is `no`)
        - `<bind_anon>` : Enable annonymous binding (yes or no)
        - `<bind_dn>` : Specify your LDAP binder DN (leave blank if `<bind_anon>` is `yes`)
        - `<bind_pw>` : Specify your LDAP binder password (leave blank if `<bind_anon>` is `yes`)
        - `<template>` : Choose an LDAP template. This sets the defaults for attritbutes
        - `open` : Uses OpenLDAP template (`cn`, `cn`, `member`)
        - `msad` : Uses Microsoft Active Directory template (`samAccountName`, `cn`, `memberOf`)
        - `edir` : Uses Novell eDirectory (`cn`, `cn`, `uniqueMember`)
        - `<user_attr>` : Specify the user attribute (leave blank for template default)
        - `<group_attr>` : Specify the group attribute (leave blank for template default)
        - `<member_attr>` : Specify the member attribute (leave blank for template default)
        - `<rfc2307>` : Enable RFC2307 style membership (yes or no)
        - `<group_object>` : Specify object class used for groups in RFC2307 mode. Typically "posixGroup" or "group" (leave blank if `<rfc2307>` is `no`)
        - `<encode>` : Enable UTF-8 encoded queries (yes or no)
        - `<user_alt>` : Prevent LDAP from stripping anything after @ char in username (yes or no)   

Disclaimer
------------  
pfSense®  is a trademark or service mark of ESF. This software (pfsense-automator) is not a monetized project in any way, and should only be used as a tool to aide licensed builds of pfSense. This software is not a product of ESF or Netgate and therefor contains no support from either entity. 
