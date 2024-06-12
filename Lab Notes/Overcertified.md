hint: take a look for some open services you might think you have to authenticate to, but don't actually

# User
* Tried normal nmap scan: `nmap -sV -sC 10.129.229.25`
	* got host seems down as a result, so added `-Pn`
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-12 15:28 EDT
Nmap scan report for 10.129.229.25
Host is up (0.022s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-13 02:28:58Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CERTIFIED.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CERTIFIED.certified.htb
| Not valid before: 2024-06-13T02:17:06
|_Not valid after:  2025-06-13T02:17:06
|_ssl-date: 2024-06-13T02:30:18+00:00; +6h59m59s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
|_ssl-date: 2024-06-13T02:30:18+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=CERTIFIED.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CERTIFIED.certified.htb
| Not valid before: 2024-06-13T02:17:06
|_Not valid after:  2025-06-13T02:17:06
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CERTIFIED.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CERTIFIED.certified.htb
| Not valid before: 2024-06-13T02:17:06
|_Not valid after:  2025-06-13T02:17:06
|_ssl-date: 2024-06-13T02:30:18+00:00; +6h59m59s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb, Site: Default-First-Site-Name)
|_ssl-date: 2024-06-13T02:30:18+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=CERTIFIED.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CERTIFIED.certified.htb
| Not valid before: 2024-06-13T02:17:06
|_Not valid after:  2025-06-13T02:17:06
Service Info: Host: CERTIFIED; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-13T02:29:38
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.16 seconds
```
* Investigating SMB first because I have no clue what else to do
	* installed smbclient: `sudo apt install cifs-utils smbclient`
	* 

# Root 