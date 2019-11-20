pfSense Automator
=========
PFSENSE-AUTOMATOR - pfSense Automation command line tool<br>
Copyright &copy; 2019 - Jared Hendrickson

Description
------------  
pfSense Automator translates pfSense's WebConfigurator into a command line tool. This allows 
you to easily run or automate pfSense configuration changes via your command line. This is
made possible by initiating HTTP POST/GET requests to gather and submit configuration changes.
All security features such as CSRF and syntax checks are left intact and changes appear exactly
as they would via the WebConfigurator UI

Supported pfSense builds: 2.3.x*, 2.4.x, 2.5.x<br>
<sub><sup>*- pfSense 2.3.x is officially EOL. While many of these commands will function on pfSense 2.3.x, there will be no further development to ensure it's functionality</sup></sub>

Installation
------------
pfsense-automator is distributed with all dependencies included. It is recommended that you use the included `pfa_installer` executable to ensure all dependencies are moved to the correct location and symlinks are properly created. To install `pfsense-automator` run the following commands<br>

**Extract**<br>
Extract the program folder from the .tar.gz file _Note: Windows systems may need additional software to extract .tar.gz files_
- `tar xvzf <downloaded tar.gz file path>`

**Run the Installer**<br>
Locate the extracted folder, this should be titled `pfsense-automator`. Execute the installer `pfa_installer` in this folder 
- macOS: `./pfa_installer`
- Ubuntu: `sudo ./pfa_installer`
- FreeBSD: `sudo ./pfa_installer`
- Windows `pfa_install.exe` _Note: you must start command prompt as administrator_

**Uninstall**<br>
If you need to uninstall `pfsense-automator` for any reason, you can do so easily using the same `pfa_installer` executable
- macOS: `/usr/local/share/pfsense-automator/pfa_installer uninstall`
- Ubuntu: `/usr/share/pfsense-automator/pfa_installer uninstall`
- FreeBSD: `/usr/share/pfsense-automator/pfa_installer uninstall`
- Windows: `"\Program Files\pfsense-automator\pfsense-automator.exe" uninstall` _Note: you may need to `cd` into the directory containing `pfa_installer.exe`_


Syntax
------------
**Syntax Types**<br>
pfsense-automator can be run either inline (for automation and scriptability) or interactively via command line (for added security or assistance). If the command's syntax is fulfilled completely, then inline mode is assumed and no input prompts will display. However, if you leave out an argument (you may specify some arguments inline and specify the rest interctively), you will be prompted to input a value for that argument. This is also useful if you cannot remember the exact syntax for a command
- INLINE SYNTAX
    - `pfsense-automator <pfSense IP or hostname> <COMMAND> <ARGUMENTS> -u <USERNAME> -p <PASSWORD>`
- INTERACTIVE SYNTAX
    - `pfsense-automator <pfSense IP or hostname> <COMMAND>` 
***
**Alternate Protocol & Port**<br>
By default, pfsense-automator uses the HTTPS protocol over port 443. Some users may have pfSense's webConfigurator configured to work off of an alternate protocol and or port. You may format the desired protocol and port to the `<pfSense IP or hostname>` field as a URL. _Note: using HTTP protocol is not recommended as this will allow login credentials to pass in cleartext over your network(s)_
    - Examples
        - `pfsense-automator http://127.0.0.1:80 --check-version -u admin -p pfsense`    (Makes an HTTP connection to pfSense over port 80)
        - `pfsense-automator 127.0.0.1:8443 --check-version -u admin -p pfsense` (Makes an HTTPS connection to pfSense over port 8443)
***
**Version**<br>
To check the current version of pfsense-automator, you can run the following command:<br>
`pfsense-automator -v`

Commands
------------
- `--check-auth` : Attempts to sign in using specified credentials. _WARNING: abuse of this function may result in a WebConfigurator lockout_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --check-auth -u <username> -p <password>` 
    - **Arguments**:
        - `-u <username>` : Allows you to pass in the username in the command, leave blank for interactive entry
        - `-p <password>` : Allows you to pass in a password in the command, leave blank for interactive entry

- `--check-version` : Checks the current installed version of pfSense on the target server. _Note: you must have the version data enabled in /widgets/widgets/system_information.widget.php_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --check-version -u <username> -p <password>` 
    - **Arguments**:
        - `-u <username>` : Allows you to pass in the username in the command, leave blank for interactive entry
        - `-p <password>` : Allows you to pass in a password in the command, leave blank for interactive entry

- `--read-interfaces` : Reads the current interface configuration _Note: at this time, only IPv4 configurations are available for command line display. If you require IPv6 configurations, please use the `--json` argument. This will contain the IPv6 data_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-interfaces <argument>`
    - **Arguments**:
        - `--all` (`-a`,`--all`,`default`,`-d`) : Return all available interface values 
        - `--iface=<iface_expr>` : Return only interface data for interfaces that starts with a specified expression (e.g. `--iface=igb1`)
        - `--vlan=<vlan_id>` (`-v`) : Return only interfaces that are associated with a specific VLAN tag (e.g. `--vlan=50`) 
        - `--name=<name_expr>` (`-n`) : Return only interfaces whose description contains a specified expression (e.g. `--name=FWUPLINK`) 
        - `--cidr=<cidr_expr>` (`-c`) : Return only interfaces whose CIDR starts with a specified expression (e.g. `--cidr=127.0.0.1`) 
        - `--read-json` (`-rf`) : Prints interface data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports interface data to a JSON file given an existing directory
        
-  `--read-available-interfaces` : Prints interfaces that are available but unused by pfSense
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-available-interfaces`

- `--add-vlan` : Attempts to add a new VLAN tag to a specified interface
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-vlan <iface> <vlan_id> <priority> <descr>`
    - **Arguments**:
        - `<iface>` : Specify an existing physical interface to add the VLAN tag to (e.g. igb1, re0)
        - `<vlan_id>` : Specify what VLAN ID to tag the interface as (1-4094)
        - `<priority>` : Specify the VLAN priority value for QoS purposes (0-7). Use `default` for no value.
        - `<descr>` : Specify a description for the VLAN. Use `default` to add the username and local hostname of individual running the command

- `--read-vlans` : Attempts to read current configured VLANs
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-vlans <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all available VLAN values 
        - `--vlan=<vlan_id>` : Return only one entry given a valid VLAN ID
        - `--iface=<iface_id>` (`-i`) : Return only VLANs configured on a specific interface 
        - `--read-json` (`-rf`) : Prints VLAN data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports VLAN data to a JSON file given an existing directory

- `--read-general-setup` : Reads current General Setup settings from /system.php
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-general-setup <argument>`
    - **Arguments**:
        - `--all` (`-a`,`-d`,`default`) : Return all configured Advanced Admin options
        - `--system` (`-s`) : Return only configuration from the System section of /system.php
        - `--dns` (`-n`) : Return only configuration from the DNS section of /system.php
        - `--localization` (`-l`) : Return only configuration from the Localization section of /system.php
        - `--webconfigurator` (`-wc`) : Return only configuration from the webConfigurator section of /system.php
        - `--read-json` (`-rf`) : Prints General Setup data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports General Setup data to a JSON file given an existing directory

- `--set-system-hostname` : Sets pfSense's system hostname values. _Note: proceed with caution if you have __DNS rebind checks enabled__! Either use the IP address to connect, or ensure that pfSense is able to resolve the new system hostname back to it's own IP address before changing the hostname_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --set-system-hostname <hostname> <domain>`
    - **Arguments**:
        - `<hostname>` : Specify a host portion for the system (e.g __hostname__.domain.com)
        - `<domain>` : Specify a domain the domain portion for the system (e.g hostname.__domain.com__)

- `--read-adv-admin` : Reads current Advanced Admin settings from /system_advanced_admin.php
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-adv-admin <argument>`
    - **Arguments**:
        - `--all` (`-a`,`-d`,`default`) : Return all configured Advanced Admin options
        - `--webconfigurator` (`-wc`) : Return only configuration from the webConfigurator section of /system_advanced_admin.php
        - `--secure-shell` (`-ssh`) : Return only configuration from the Secure Shell section of /system_advanced_admin.php
        - `--login-protection` (`-lp`) : Return only configuration from the Login Protection section of /system_advanced_admin.php
        - `--serial-communications` (`-sc`) : Return only configuration from the Serial Communications section of /system_advanced_admin.php
        - `--console-options` (`-co`) : Return only configuration from the Console options section of /system_advanced_admin.php
        - `--read-json` (`-rf`) : Prints Advanced Admin data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports Advanced Admin data to a JSON file given an existing directory

- `--read-hasync` : Gathers the current High Availability configuration from system_hasync.php and prints it to your command line or exports as JSON
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-hasync <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Returns all available HA Sync configurations
        - `--pfsync` (`-p`) : Returns only PFSYNC configuration
        - `--xmlrpc` (`-x`) : Returns only XMLRPC configuration
        - `--read-json` (`-rf`) : Prints HA Sync data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports HA Sync data to a JSON file given an existing directory    
        
- `--setup-hasync` : Configures HA Sync settings _Note: Ensure both pfSense systems are running the same pfSense version. It is recommended to have a dedicated interface for PFSYNC if enabled_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --setup-hasync <pfsync_enable> <pfsync_if> <pfsync_ip <xmlrpc_ip> <xmlrpc_user> <xmlrpc_passwd> <xmlrpc_opts>`
    - **Arguments**:
        - `<pfsync_enable>` - Enables or disables PFSYNC. Use `default` to retain existing configuration (`enable`,`disable`,`default`)
        - `<pfsync_if>` - Specify the interface PFSYNC will use. This may be the physical interface name (e.g. `igb1`), the pfSense interface ID (e.g. `opt1`) or the interface descriptive name (e.g. `WAN2`)
        - `<pfsync_ip>` - Specify the IP of the remote pfSense system PFSYNC will sync to
        - `<xmlrpc_ip>` -  Specify the IP of the remote pfSense system XMLRPC will sync to
        - `<xmlrpc_user>` -  Specify the username of the remote pfSense system XMLRPC will use to authenticate
        - `<xmlrpc_passwd>` -  Specify the password of the remote pfSense system XMLRPC will use to authenticate
        - `<xmlrpc_opts>` -  Specify the configuration areas XMLRPC will sync between systems
            - `all` - Sync all available configuration areas
            - `users` - Sync user configurations between systems
            - `authservers` - Sync authentication server configurations between systems
            - `certs` - Sync certificate configurations between systems
            - `rules` - Sync firewall rule configurations between systems
            - `schedules` - Sync firewall schedule configurations between systems
            - `alises` - Sync firewall alias configurations between systems
            - `nat` - Sync NAT configurations between systems
            - `ipsec` - Sync IPsec configurations between systems
            - `openvpn` - Sync OpenVPN configurations between systems
            - `dhcpd` - Sync DHCP configurations between systems
            - `wol` - Sync Wake-on-LAN configurations between systems
            - `staticroutes` - Sync static route configurations between systems
            - `lb` - Sync load balancer configurations between systems
            - `virtualip` - Sync virtual IP configurations between systems
            - `trafficshaper` - Sync traffic shaper configurations between systems
            - `trafficshaperlimiter` - Sync traffic shaper limiter configurations between systems
            - `dnsforwarder` - Sync DNS Resolver and DNS Forwarder configurations between systems
            - `captiveportal` - Sync captive portal configurations between systems

- `--read-users`: Reads current local user database
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-users <argument>`
    - **Arguments**:
        - `--all` (`-a`,`-d`,`default`) : Return all users
        - `--username` (`-un`) : Return only configuration for a single user (e.g. `--username=admin`)
        - `--read-json` (`-rf`) : Prints user data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports user data to a JSON file given an existing directory

- `--setup-wc` : Configures pfSense webConfigurator's advanced options. This excludes the webConfigurator protocol and port number as they cannot be changed statefully. See `--set-wc-port` below. 
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --setup-wc <max_procs> <http_redirect> <hsts> <login_autocomplete> <login_msg> <anti_lockout> <dns_rebind> <alt_hostnames> <http_referer> <tab_text>`
    - **Arguments**:
        - `<max_procs>` - Sets the maxinum number of processes allowed by the webConfigurator
            - `1-1024` - Assign the number of maximum processes 
            - `default` - Retains the current configured value
        - `<http_redirect>` - Enables or disables HTTP to HTTPS redirects 
            - `redirect` (`enable`) ( - Enables HTTP to HTTPS redirects within the webConfigurator
            - `no-redirect` (`disable`) - Disables HTTP to HTTPS redirects within the webConfigurator
            - `default` - Retains the current configured value
        - `<hsts>` - Enables or disables HTTP Strict Transport Security enforcement
            - `hsts` (`enable`) - Enables HTTP Strict Transport Security enforcement
            - `no-hsts` (`disable`) - Disables HTTP Strict Transport Security enforcement
            - `default` - Retains the current configured value
        - `<login_autocomplete>` - Enables or disables login auto-completion
            - `autocomplete` (`enable`) - Enables login auto-completion
            - `no-autocomplete` (`disable`) - Disables login auto-completion
            - `default` - Retains the current configured value
        - `<login_msg>` - Enables or disables webConfigurator authentication logging 
           - `loginmsg` (`enable`) - Enables webConfigurator authentication logging
           - `no-loginmsg` (`disable`) - Disables webConfigurator authentication logging
           - `default` - Retains the current configured value
        - `<anti_lockout>` - Enables or disables webConfigurator anti-lockout rule
            - `antilockout` (`enable`) - Enables webConfigurator anti-lockout rule
            - `no-antilockout` (`disable`) - Disables webConfigurator anti-lockout rule
            - `default` - Retains the current configured value
        - `<dns_rebind>` - Enables or disables DNS rebind checks
            - `dnsrebind` (`enable`) - Enables DNS rebind checks
            - `no-dnsrebind` (`disable`) - Disables DNS rebind checks
            - `default` - Retains the current configured value
        - `<alt_hostnames>` - Add additional hostnames to whitelist in HTTP_REFERER and DNS Rebind checks
            - `<FQDNs>` - List FQDNs. Separate multiple entries with spaces
            - `default` - Retains the current configured value
        - `<http_referer>` - Enables or disables HTTP_REFERER check
            - `httpreferer` (`enable`) - Enables HTTP_REFERER check
            - `no-httpreferer` (`disable`) - Disables HTTP_REFERER check
            - `default` - Retains the current configured value
        - `<tab_text>` - Configure webConfigurator to display pfSense hostname in tab text
            - `display-tabtext` (`enable`) - Enables displaying of hostname in tab text
            - `hide-tabtext` (`disable`) - Disables displaying of hostname in tab text
            - `default` - Retains the current configured value

- `--set-wc-port` - Configures the webConfigurator's HTTP protocol and TCP port specification
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --set-wc-port <http_protocol> <tcp_port>`
    - **Arguments**:
        - `<http_protocol>` - Assigns the HTTP protocol to use
            - `http` - Use basic HTTP for webConfigurator connections. _Caution: this will allow credentials to pass in cleartext_
            - `https` - Use encrypted HTTPS for webConfigurator connections (recommended)
            - `default` - Retain the existing configured value
        - `<tcp_port>` - Specify which TCP port the webConfigurator will bind to
            - `1-65535` - Assigns a specified TCP port value between 1-65535
            - `default` - Retains the current configured value

- `--setup-ssh` : Configures `sshd` on pfSense
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --setup-ssh <enable_ssh> <ssh_port> <ssh_auth> <sshagent_forwarding>`
    - **Arguments**:
        - `<enable_ssh>` - Either enables or disables `sshd` on pfSense
            - `enable` - Enables `sshd`
            - `disable` - Disables `sshd`
            - `default` - Retains existing value (empty input in interactive mode assumes `default`)
        - `<ssh_port>` - Either enables or disables `sshd` on pfSense
            - `1-65535` - Specifies a valid port number between 1 and 65535
            - `default` - Retains existing value (empty input in interactive mode assumes `default`)
         - `<ssh_auth>` - Choose the SSH authentication method
            - `passwd` - Allow either password or public key authentication
            - `key` - Enforce public key authentication only
            - `both` - Require both a password and public for authentication (only available on pfSense 2.4.4 or later)
            - `<sshagent_forwarding>` - Enable or disable ssh-agent forwarding (only available on pfSense 2.4.4-p1)
                - `enable` - Enables ssh-agent forwarding
                - `disable` - Disables ssh-agent forwarding
                - `default` - Retains existing value (empty input in interactive mode assumes `default`)

- `--setup-console` - Configures console options found in system_advanced_admin.php
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --setup-console <console_pass_protect>`
    - **Arguments**:
      - `<console_pass_protect>` - Enable or disables console password protection
        - `enable` - Enables console password protection
        - `disable` - Disables console password protection

- `--read-arp` : Reads the ARP table
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-arp <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all available ARP table values 
        - `--iface` (`-i`) : Return only ARP entries on a specific interface name (e.g.`--iface=WAN`)
        - `--ip` (`-p`) : Return only ARP entries with a specific IP (e.g. `--ip=127.0.0.1`)
        - `--hostname` (`-h`) : Return only ARP entries with a specific hostname (e.g. `--hostname=foo-system.local`)
        - `--mac` (`-m`) : Return only ARP entries with a specific MAC (e.g. `--mac=00:00:00:00:00:00`)
        - `--vendor` (`-v`) : Return only ARP entries with a specific MAC vendor (e.g. `--vendor=Apple`)
        - `--link` (`-l`) : Return only ARP entries with a specific link type(e.g. `--link=ethernet`)
        - `--read-json` (`-rf`) : Prints ARP data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports ARP data to a JSON file given an existing directory

- `--read-xml` : Reads or exports XML configuration
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-xml <filter> <xml_area> <pkg> <rrd> <encrypt> <encrypt_pass>`
    - **Arguments**:
      - `<filter>` : Specify either read or export options
            - `--read` (`read`,`-r`) : Prints XML configuration to the command line
            - `--export=<directory_path` (`-e`) : Exports the XML configuration to a specified directory path
      - `<xml_area>` : Define the XML area to include (aliases, unbound, filter, interfaces, installedpackages, rrddata, cron, syslog, system, sysctl, snmpd, vlans)
      - `<pkg>` : Include or exclude package data in the XML configuration (`include`, `exclude`)
      - `<rrd>` : Include or exclude RRD data in the XML configuration (`include`, `exclude`)
      - `<encrypt>` : Enable or disable encrypting the XML data (`encrypt`, `noencrypt`)
      - `<encrypt_pass>` : Assign an encryption password if encryption is enabled, otherwise specify `none`

- `--upload-xml` : Restore configuration using an existing XML configuration file
  - **Syntax**: `pfsense-automator <pfSense IP or hostname> --upload-xml <xml_area> <xml_filepath> <decrypt_pass>`
  - **Arguments**:
      -  `<xml_area>`: Specify the configuration area to restore
            - `all`: Restore entire XML configuration
            - `aliases`: Restore only firewall aliases
            - `captiveportal`: Restore captive portal configurations
            - `voucher`: Restore captive portal vouchers
            - `dnmasq`: Restore DNS Forwarder configuration only
            - `unbound`: Restore DNS Resolver configuration only
            - `dhcpd`: Restore DHCP configuration only
            - `dhcpdv6`: Restore DHCP (IPv6) configuration only
            - `filter`: Restore Firewall configuration only
            - `interfaces`: Restore Interface configuration only
            - `ipsec`: Restore IPsec configuration only
            - `nat`: Restore NAT configuration only
            - `OpenVPN`: Restore OpenVPN configuration only
            - `installedpackages`: Restore installed packages only
            - `rrddata`: Restore RRD graph data only
            - `cron`: Restore Cron configuration only
            - `syslog`: Restore Syslog configuration only
            - `system`: Restore System settings only
            - `staticroutes`: Restore Static Route configuration only
            - `sysctl`: Restore sysctl configuration only
            - `snmpd`: Restore SNMP configuration only
            - `shaper`: Restore Traffic Shaper configuration only
            - `vlans`: Restore VLAN configurations only
            - `wol`: Restore Wake-On-LAN configuration only
      - `<xml_filepath>`: Specify a valid file path to the existing XML configuration file
      - `<decrypt_pass>`: Specify the decryption password for encrypted XML configurations, if not encrypted use `none`

- `--replicate-xml` : Replicate XML configurations to one or more pfSense systems. This replicates the XML configuration from the `<pfSense IP or hostname>` to the `<replication_targets>` shown in the syntax secion below. _Note: credentials, protocol, and port on all pfSense servers must match to replicate configuration_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --replicate-xml <xml_area> <replication_targets>`
    - **Arguments**:
        - `<xml_area>` : Specify the XML area to replicate (aliases, unbound, filter, interfaces, installedpackages, rrddata, cron, syslog, system, sysctl, snmpd, vlans)
            - `all`: Replicate entire XML configuration
            - `aliases`: Replicate only firewall aliases
            - `captiveportal`: Replicate captive portal configurations
            - `voucher`: Replicate captive portal vouchers
            - `dnmasq`: Replicate DNS Forwarder configuration only
            - `unbound`: Replicate DNS Resolver configuration only
            - `dhcpd`: Replicate DHCP configuration only
            - `dhcpdv6`: Replicate DHCP (IPv6) configuration only
            - `filter`: Replicate Firewall configuration only
            - `interfaces`: Replicate Interface configuration only
            - `ipsec`: Replicate IPsec configuration only
            - `nat`: Replicate NAT configuration only
            - `OpenVPN`: Replicate OpenVPN configuration only
            - `installedpackages`: Replicate installed packages only
            - `rrddata`: Replicate RRD graph data only
            - `cron`: Replicate Cron configuration only
            - `syslog`: Replicate Syslog configuration only
            - `system`: Replicate System settings only
            - `staticroutes`: Replicate Static Route configuration only
            - `sysctl`: Replicate sysctl configuration only
            - `snmpd`: Replicate SNMP configuration only
            - `shaper`: Replicate Traffic Shaper configuration only
            - `vlans`: Replicate VLAN configurations only
            - `wol`: Replicate Wake-On-LAN configuration only
        - `<replication_targets>` : Specify hostname/IPs of pfSense systems to replicate the configuration to (multiple entries must be comma separated or added interactively)

- `--add-tunable` : Adds a new system tunable to System > Advanced > System Tunables
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-tunable <tunable_name> <descr> <value>`
    - **Arguments**:
        - `<tunable_name>` : Specify the tunable name, this should correspond with a valid system tunable
        - `<descr>` : Add a description for the system tunable
        - `<value>` : Specify the tunable's value. This is typically a integer value
   
- `--read-tunables` : Reads the system tunables from System > Advanced > System Tunables
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-tunables <argument>`
    - **Arguments**:
        - `--all` (`-a`, `-d`, `default`) : Return all available ARP table values 
        - `--read-json` (`-rf`) : Prints tunable data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports system tunables data to a JSON file given an existing directory
        
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
        - `--read-json` (`-rf`) : Prints DNS Resolver data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports Resolver data to a JSON file given an existing directory

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
            - `--read-json` (`-rf`) : Prints SSL certificate data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
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
        - `--read-json` (`-rf`) : Prints alias data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports alias data to a JSON file given an existing directory

- `--read-virtual-ips` : Reads our configured virtual IPs from firewall_virtual_ip.php
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-virtual-ips <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all configured virtual IPs and print them 
        - `--type` (`-t`) : Return only a specified type of virtual IPs (e.g. `--type=proxyarp`)
        - `--iface` (`-i`) : Return only virtual IPs configured on a specific interface (e.g. `--iface=wan`) _Note: this uses the pf interface ID not the user configured ID_
        - `--subnet` (`-s`) : Return virtual IPs matching a subnet expression (e.g. `--subnet=127.0.0.1/32`) _Note: this filter matches entries that start with your expression, the more specific your expression the more specific your results will be_
        - `--read-json` (`-rf`) : Prints virtual IP data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports virtual IP data to a JSON file given an existing directory

- `--add-virtual-ip` : Adds a new virtual IP to firewall_virtual_ip.php
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-virtual-ip <type> <interface> <cidr> <disable_expand> <vhid_group> <adv_base> <adv_skew> <descr>`
    - **Arguments**:
        - `<type>` : Specify the virtual IP type (`ipalias`, `carp`, `proxyarp`, `other`) _Note: using interactive mode will only request input for values your requested virtual IP type needs_
        - `<interface>` : Specify the interface to advertise the virtual IP from 
        - `<cidr>` : Specify the subnet CIDR of the virutal IP address you are creating (e.g. `192.168.0.1/32`)
        - `<disable_expand>` : Disable expansion of this entry into IPs on NAT lists (`yes`, `no`)
        - `<vhid_group>` : Specify the VHID group that the machines will share (`1-255`) _Note: this is only necessary on `carp` virtual IPs, leave as `1` on other virtual IP types_
        - `<adv_base>` : Specify the advertising frequency base (`1-254`) _Note: this is only necessary on `carp` virtual IPs, leave as `1` on other virtual IP types_
        - `<adv_skew>` : Specify the advertising frequency skew (`0-254`) _Note: this is only necessary on `carp` virtual IPs, leave as `0` on other virtual IP types_
        - `<descr>` : Specify a description for your virtual IP

- `--read-carp-status` : Checks our CARP status
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --read-virtual-ips <argument>`
    - **Arguments**:
        - `--all` (`-a`) : Return all CARP configuration information 
        - `--nodes` (`-n`) : Return only pfSync node IDs
        - `--iface` (`-i`) : Return only virtual IPs configured on a specific interface (e.g. `--iface=wan`) _Note: this uses the pf interface ID not the user configured ID_
        - `--subnet` (`-s`) : Return virtual IPs matching a subnet expression (e.g. `--subnet=127.0.0.1/32`) _Note: this filter matches entries that start with your expression, the more specific your expression the more specific your results will be_
        - `--read-json` (`-rf`) : Prints CARP status data as JSON. _Note: This is useful for developers wanting to integrate pfsense-automator into their own scripts_
        - `--json=<directory_path>` : Exports virtual IP data to a JSON file given an existing directory

- `--set-carp-maintenance`: Enables or disables CARP persistent maintenance mode. _Note: Enabling maintenance mode on the MASTER node is not recommended, command timeouts are likely to occur if you are enabling maintenance on the MASTER node_
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --set-carp-maintenance <toggle>`
    - **Arguments**:
    - `<toggle>` : Specify whether to enable or disable CARP maintenance mode (`enable`,`disable`)

- `--modify-alias` : Modifies an existing Firewall Alias. Existing entries will be overwritten. 
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --modify-alias <alias name> <IPs or hostnames>`
    - **Arguments**:
        - `<alias name>` : Specify which alias you would like to modify, this much match the name exactly
        - `<IPs or hostnames>` : Specify what IPs or hostnames to include in the alias. Multiple entries must be separated by a comma

- `--add-ldapserver` : Adds a new LDAP authentication server - this may be configured inline or interactively (will prompt for configuration if missing arguments)
    - **Syntax**: `pfsense-automator <pfSense IP or hostname> --add-ldapserver <descr_name> <IP or hostname> <port> <transport> <protocol> <timeout> <search_scope> <base_dn> <auth_container> <ext_query> <query> <bind_anon> <bind_dn> <bind_pw> <template> <user_attr> <group_attr> <member_attr> <rfc2307> <group_obj> <encode> <user_alt> -u <username> -p <password>`
    - **Arguments**:
        - `<descr_name>` : Specify a descriptive name for the authentication server
        - `<ip_hostname>` : Specify the IP or hostname of the remote LDAP server
        - `<port>` : Specify the TCP port number of the remote LDAP server
        - `<transport>` : Specify the LDAP transport type
            - `standard` : Use standard LDAP (unencrypted)
            - `starttls` : Use TLS encryption if available
            - `encrypted` : Required encryption on all LDAP queries
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
