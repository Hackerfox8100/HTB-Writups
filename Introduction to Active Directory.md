# Why Active Directory?
* designed to be backward-compatible, and many features are arguably not "secure by default," and it can be easily misconfigured
	* can be leveraged to move laterally and vertically within a network and gain unauthorized access
* A basic AD user account with no added privileges can enumerate most objects within AD
	* can be used to enumerate the domain and hunt for misconfigurations and flaws thoroughly
* multiple attacks can be performed with only a standard domain user account
![](Introduction%20to%20Active%20Directory-paste.png)
* estimated that around 95% of Fortune 500 companies run Active Directory

# AD Attacks & Tools
2021
 * Print Nightmare
	*  remote code execution flaw in the Windows Print Spooler that could be used to take over hosts in an AD environment
* Shadow Credentials
	* allows for low privileged users to impersonate other user and computer accounts if conditions are right, and can be used to escalate privileges in a domain
* noPac
	* allows an attacker to gain full control over a domain from a standard domain user account if the right conditions exist
2020
* ZeroLogon
	* critical flaw that allowed an attacker to impersonate any unpatched domain controller in a network
2019
* ["Kerberoasting Revisited"](https://www.slideshare.net/harmj0y/derbycon-2019-kerberoasting-revisited)
2018
* "Printer Bug" bug was discovered and the SpoolSample PoC tool was released which leverages this bug to coerce Windows hosts to authenticate to other machines via the MS-RPRN RPC interface
*  Rubeus toolkit for attacking Kerberos
* DCShadow Attack Technique
* Ping Castle tool 
	* for performing security audits of Active Directory by looking for misconfigurations and other flaws that can raise the risk level of a domain and producing a report that can be used to identify ways to further harden the environment
2017
*  ASREPRoast technique was introduced for attacking user accounts that don't require Kerberos preauthentication
2016
* Bloodhound was released

# AD Structure
* Active Directory Domain Services (AD DS) stores information such as usernames and passwords and manages the rights needed for authorized users to access this information
* A basic AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to:
	* Domain Computers
	* Domain Users
	* Domain Group Information
	* Organizational Units (OUs)
	* Default Domain Policy
	* Functional Domain Levels
	* Password Policy
	* Group Policy Objects (GPOs)
	* Domain Trusts
	* Access Control Lists (ACLs)
* At a very (simplistic) high level, an AD structure may look as follows:
```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```
* *What Active Directory structure can contain one or more domains?*
	* forest
* *True or False; It can be common to see multiple domains linked together by trust relationships?*
	* true
* *Active Directory provides authentication and <> within a Windows domain environment.*
	* authorization

# AD Terminology
* **Object:** ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc
	* Every object in Active Directory has an associated set of attributes
* **Attributes:** used to define characteristics of the given object
	* All attributes in AD have an associated LDAP name that can be used when performing LDAP queries, such as `displayName` for `Full Name` and `given name` for `First Name`
* **Schema:** the blueprint of any enterprise environment. 
	* defines what types of objects can exist in the AD database and their associated attributes
	* lists definitions corresponding to AD objects and holds information about each object
* **Domain:** logical group of objects such as computers, users, OUs, groups, etc
	* can operate entirely independently of one another or be connected via trust relationships
* **Forest:** a collection of Active Directory domains. the topmost container and contains all of the AD objects introduced below, including but not limited to domains, users, groups, computers, and Group Policy objects
	* collection of AD trees
* **Tree:** collection of Active Directory domains that begins at a single root domain
* **Container:** Container objects hold other objects and have a defined place in the directory subtree hierarchy
* **Leaf:** Leaf objects do not contain other objects and are found at the end of the subtree hierarchy
* **Global Unique Identifier (GUID):** a unique 128-bit value assigned when a domain user or group is created. This GUID value is unique across the enterprise, similar to a MAC address.
	* stored in the `ObjectGUID` attribute
	* When querying for an AD object (such as a user, group, computer, domain, domain controller, etc.), we can query for its `objectGUID` value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name
	* used by AD to identify objects internally
	* Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for
* **Security principles:** anything that the operating system can authenticate, including users, computer accounts, or even threads/processes that run in the context of a user or computer account (i.e., an application such as Tomcat running in the context of a service account within the domain)
	* domain objects that can manage access to other resources within the domain
	* We can also have local user accounts and security groups used to control access to resources on only that specific computer 
		* These are not managed by AD but rather by the Security Accounts Manager (SAM)
* **Security Identifier (SID):** used as a unique identifier for a security principal or security group
	* Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database
	* can only be used once
	* Even if the security principle is deleted, it can never be used again in that environment to identify another user or group
	* When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of
		* This token is used to check rights whenever the user performs an action on the computer
* **Distinguished Name (DN):** describes the full path to an object in AD (such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`)
* **Relative Distinguished Name (RDN):** a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy
* **sAMAccountName:** the user's logon name. Here it would just be `bjones`. It must be a unique value and 20 or fewer characters
* **userPrincipalName:** another way to identify users in AD. This attribute consists of a prefix (the user account name) and a suffix (the domain name) in the format of `bjones@inlanefreight.local` 
	* This attribute is not mandatory
* **FSMO Roles:** Flexible Single Master Operation roles. give Domain Controllers (DC) the ability to continue authenticating users and granting permissions without interruption (authorization and authentication)
	* There are five FSMO roles: `Schema Master` and `Domain Naming Master` (one of each per forest), `Relative ID (RID) Master` (one per domain), `Primary Domain Controller (PDC) Emulator` (one per domain), and `Infrastructure Master` (one per domain)
	* FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed
* **Global Catalog (GC):** a domain controller that stores copies of ALL objects in an Active Directory forest
	* stores a full copy of all objects in the current domain and a partial copy of objects that belong to other domains in the forest
	*  a feature that is enabled on a domain controller and performs the following functions:
		* Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
		* Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)
* **Read-Only Domain Controller (RODC):** has a read-only Active Directory database 
	* No AD account passwords are cached on an RODC (other than the RODC computer account & RODC KRBTGT passwords) 
	* No changes are pushed out via an RODC's AD database, SYSVOL, or DNS 
	* RODCs also include a read-only DNS server, allow for administrator role separation, reduce replication traffic in the environment, and prevent SYSVOL modifications from being replicated to other DCs
* **Replication:** happens in AD when AD objects are updated and transferred from one Domain Controller to another
* **Service Principal Name (SPN):** uniquely identifies a service instance 
	* They are used by Kerberos authentication to associate an instance of a service with a logon account, allowing a client application to request the service to authenticate an account without needing to know the account name
* **Group Policy Objects (GPO):** virtual collections of policy settings 
	* Each GPO has a unique GUID
	* A GPO can contain local file system settings or Active Directory settings
	* GPO settings can be applied to both user and computer objects
	* They can be applied to all users and computers within the domain or defined more granularly at the OU level
* **Access Control List (ACL):** the ordered collection of Access Control Entries (ACEs) that apply to an object
* **Access Control Entries (ACEs):** identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee
* **Discretionary Access Control List (DACL):** define which security principles are granted or denied access to an object; it contains a list of ACEs
* **System Access Control Lists (SACL):** Allows for administrators to log access attempts that are made to secured objects
	* specify the types of access attempts that cause the system to generate a record in the security event log
* **Fully Qualified Domain Name (FQDN):** the complete name for a specific computer or host. It is written with the hostname and domain name in the format `[host name].[domain name].[tld]`
	* used to specify an object's location in the tree hierarchy of DNS
* **Tombstone:** a container object in AD that holds deleted AD objects
	* When an object is deleted from AD, the object remains for a set period of time known as the `Tombstone Lifetime,` and the `isDeleted` attribute is set to `TRUE`. Once an object exceeds the `Tombstone Lifetime`, it will be entirely removed
* **SYSVOL:** stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment
* **AdminSDHolder:** object used to manage ACLs for members of built-in groups in AD marked as privileged
* **dsHeuristics:** a string value set on the Directory Service object used to define multiple forest-wide configuration settings
	* Groups in this list are protected from modification via the `AdminSDHolder` object
	* If a group is excluded via the `dsHeuristics` attribute, then any changes that affect it will not be reverted when the SDProp process runs
* **adminCount:** attribute determines whether or not the SDProp process protects a user. If the value is set to `0` or not specified, the user is not protected. If the attribute value is set to `value`, the user is protected
* **Active Directory Users and Computers (ADUC):** a GUI console commonly used for managing users, groups, computers, and contacts in AD
* **ADSI Edit:** a GUI tool used to manage objects in AD. It provides access to far more than is available in ADUC and can be used to set or delete any attribute available on an object, add, remove, and move objects as well
* **sIDHistory:** attribute holds any SIDs that an object was assigned previously
* **NTDS.DIT:** file can be considered the heart of Active Directory. It is stored on a Domain Controller at `C:\Windows\NTDS\` and is a database that stores AD data such as information about user and group objects, group membership, and, most important to attackers and penetration testers, the password hashes for all users in the domain
	* Once full domain compromise is reached, an attacker can retrieve this file, extract the hashes, and either use them to perform a pass-the-hash attack or crack them offline using a tool such as Hashcat to access additional resources in the domain
	* If the setting Store password with reversible encryption is enabled, then the NTDS.DIT will also store the cleartext passwords for all users created or who changed their password after this policy was set
* **MSBROWSE:** is a Microsoft networking protocol that was used in early versions of Windows-based local area networks (LANs) to provide browsing services

# Active Directory Objects
* ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers
* Users: 
	* considered `leaf objects`, which means that they cannot contain any other objects within them
	* considered a security principal and has a security identifier (SID) and a global unique identifier (GUID)
	* have many possible attributes, such as their display name, last login time, date of last password change, email address, account description, manager, address, and more
* Contacts
	* usually used to represent an external user and contains informational attributes such as first name, last name, email address, telephone number, etc
	* leaf objects, NOT security principles
		* no SID only GUID
* Printers
	* points to a printer accessible within the AD network
	* leaf objects, NOT security principles
	* Printers have attributes such as the printer's name, driver information, port number, etc.
* Computers
	* any computer joined to the AD network (workstation or server)
	* leaf object AND security principles
	* prime targets for attackers since full administrative access to a computer (as the all-powerful `NT AUTHORITY\SYSTEM` account) grants similar rights to a standard domain user and can be used to perform the majority of the enumeration tasks that a user account can (save for a few exceptions across domain trusts)
* Shared Folders
	* points to a shared folder on the specific computer where the folder resides
	* NOT security principals and only have a GUID
	* attributes can include the name, location on the system, security access rights
* Groups
	* considered a `container object` because it can contain other objects, including users, computers, and even other groups
	* regarded as a security principle and has both a SUID and GUID
	* can have nested groups which are often used to obtain unintended rights
		* bloodhound helps find these
	*  most common attributes are the name, description, membership, and other groups that the group belongs to
* Organizational Units (OUs)
	* a container that systems administrators can use to store similar objects for ease of administration
	* A few OU attributes include its name, members, security settings, and more
* Domain
	* the structure of an AD network
	*  Every domain has its own separate database and sets of policies that can be applied to any and all objects within the domain
* Domain Controllers
	* essentially the brains of an AD network
	* They handle authentication requests, verify users on the network, and control who can access the various resources in the domain
	* It also enforces security policies and stores information about every other object in the domain
* Sites
	* a set of computers across one or more subnets connected using high-speed links
	* They are used to make replication across domain controllers run efficiently
* Built-in
	*  a container that holds default groups in an AD domain
	* They are predefined when an AD domain is created
* Foreign Security Principals
	*  an object created in AD to represent a security principal that belongs to a trusted external forest

# Active Directory Functionality
*  five Flexible Single Master Operation (FSMO) roles

| Roles                    | Description                                                                                                                                                                                                                                                                                                       |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Schema Master            | This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD                                                                                                                                                                                            |
| Domain Naming Master     | Manages domain names and ensures that two domains of the same name are not created in the same forest                                                                                                                                                                                                             |
| Relative ID (RID) Master | The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID          |
| PDC Emulator             | The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain                                                                                      |
| Infrastructure Master    | This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names |
### Trusts
* Creates a link between the authentication systems of two domains

| Trust Type   | Description                                                                                                                                                            |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Parent-child | Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.                                                                |
| Cross-link   | a trust between child domains to speed up authentication.                                                                                                              |
| External     | A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering.     |
| Tree-root    | a two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest. |
| Forest       | a transitive trust between two forest root domains.                                                                                                                    |
* Trusts can be transitive or non-transitive
	* A transitive trust means that trust is extended to objects that the child domain trusts
	* In a non-transitive trust, only the child domain itself is trusted
* Trusts can be set up to be one-way or two-way (bidirectional)
* Often, domain trusts are set up improperly and provide unintended attack paths

# Kerberos, DNS, LDAP, MSRPC
* Active Directory specifically requires:
	* Lightweight Directory Access Protocol (LDAP)
	* Kerberos
	* DNS
		* for authentication and communication
	* MSRPC
		* Microsoft implementation of remote procedure call
### Kerberos
* Kerberos is a stateless authentication protocol based on tickets instead of transmitting user passwords over the network
* Domain Controllers have a Kerberos Key Distribution Center (KDC) that issues tickets
* When a user initiates a login request to a system, the client they are using to authenticate requests a ticket from the KDC, encrypting the request with the user's password
* If the KDC can decrypt the request (AS-REQ) using their password, it will create a Ticket Granting Ticket (TGT) and transmit it to the user
* The user then presents its TGT to a Domain Controller to request a Ticket Granting Service (TGS) ticket, encrypted with the associated service's NTLM password hash
* Finally, the client requests access to the required service by presenting the TGS to the application or service, which decrypts it with its password hash
* *Kerberos Ticket Granting Service ticket (TGS) relies on a valid Ticket Granting Ticket (TGT). It assumes that if the user has a valid TGT, they must have proven their identity*
![](Introduction%20to%20Active%20Directory-paste-1.png)
* Uses port 88 (TCP and UDP)
	* can be used to identify DCs
### DNS
* AD DS) uses DNS to allow clients (workstations, servers, and other systems that communicate with the domain) to locate Domain Controllers and for Domain Controllers that host the directory service to communicate amongst themselves
* AD maintains a database of services running on the network in the form of service records (SRV)
* When a client joins the network, it locates the Domain Controller by sending a query to the DNS service, retrieving an SRV record from the DNS database, and transmitting the Domain Controller's hostname to the client
* Uses port 53 (TCP and UDP)
* Forward DNS Lookup
```powershell-session
PS C:\htb> nslookup INLANEFREIGHT.LOCAL

Server:  172.16.6.5
Address:  172.16.6.5

Name:    INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```
* Reverse DNS Lookup
```powershell-session
PS C:\htb> nslookup 172.16.6.5

Server:  172.16.6.5
Address:  172.16.6.5

Name:    ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```
* Finding IP Address of a Host
```powershell-session
PS C:\htb> nslookup ACADEMY-EA-DC01

Server:   172.16.6.5
Address:  172.16.6.5

Name:    ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
Address:  172.16.6.5
```

### LDAP
* For directory lookups in AD
* Open-source and cross-platform protocol used for authentication against various directory services (such as AD)
* uses port 389, and LDAP over SSL (LDAPS) communicates over port 636
* LDAP is how systems in the network environment can "speak" to AD
* An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent
* The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests
![](Introduction%20to%20Active%20Directory-paste-2.png)
* While uncommon, you may come across organization while performing an assessment that do not have AD but are using LDAP, meaning that they most likely use another type of LDAP server such as OpenLDAP
* AD LDAP authentication:
	* LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session
	* **Simple Authentication**: This includes anonymous authentication, unauthenticated authentication, and username/password authentication
		* Simple authentication means that a `username` and `password` create a BIND request to authenticate to the LDAP server
	* **SASL Authentication**: The Simple Authentication and Security Layer framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP
		* SASL can provide additional security due to the separation of authentication methods from application protocols
	* LDAP authentication messages are sent in cleartext by default so anyone can sniff out LDAP messages on the internal network
### MSRPC
* an interprocess communication technique used for client-server model-based applications
* Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces

| Interface Name | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| lsarpc         | A set of RPC calls to the Local Security Authority (LSA) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| netlogon       | Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| samr           | Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as Bloodhoundto visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved. Organizations can protect against this type of reconnaissance by changing a Windows registry key to only allow administrators to perform remote SAM queries since, by default, all authenticated domain users can make these queries to gather a considerable amount of information about the AD domain. |
| drsuapi        | drsuapi is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. Attackers can utilize drsuapi to [create a copy of the Active Directory domain database](https://attack.mitre.org/techniques/T1003/003/) (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM.                                                                                                                                                                                                                    |
# NTLM Authentication
* LM and NTLM here are the hash names
* NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash
* Kerberos is often the authentication protocol of choice wherever possible
* Hash protocol comparison

| Hash/Protocol | Cryptographic Technique                              | Mutual Authenication | Message Type                    | Trusted Third Party                             |
| ------------- | ---------------------------------------------------- | -------------------- | ------------------------------- | ----------------------------------------------- |
| NTLM          | Symmetric key cryptography                           | No                   | Random number                   | Domain Controller                               |
| NTLMv1        | Symmetric key cryptography                           | No                   | MD4 hash, random number         | Domain Controller                               |
| NTLMv2        | Symmetric key cryptography                           | No                   | MD4 hash, random number         | Domain Controller                               |
| Kerberos      | Symmetric key cryptography & asymmetric cryptography | Yes                  | Encrypted ticket using DES, MD5 | Domain Controller/Key Distribution Center (KDC) |
### LM
* `LAN Manager` (LM or LANMAN) hashes are the oldest password storage mechanism used by the Windows operating system
* If in use, they are stored in the SAM database on a Windows host and the NTDS.DIT database on a Domain Controller
* Passwords using LM are limited to a maximum of `14` characters
	* Passwords are not case sensitive and are converted to uppercase before generating the hashed value, limiting the keyspace to a total of 69 characters making it relatively easy to crack these hashes using a tool such as Hashcat
	* Before hashing, a 14 character password is first split into two seven-character chunks
		* If the password is less than fourteen characters, it will be padded with NULL characters to reach the correct value
		* Two DES keys are created from each chunk
			* These chunks are then encrypted using the string `KGS!@#$%`, creating two 8-byte ciphertext values
* This hashing algorithm means that an attacker only needs to brute force seven characters twice instead of the entire fourteen characters
* An LM hash takes the form of `299bd128c1101fd6`
* Windows operating systems prior to Windows Vista and Windows Server 2008 (Windows NT4, Windows 2000, Windows 2003, Windows XP) stored both the LM hash and the NTLM hash of a user's password by default
### NTHash (NTLM)
* `NT LAN Manager` (NTLM) hashes are used on modern Windows systems
* challenge-response authentication protocol and uses three messages to authenticate
	*  a client first sends a `NEGOTIATE_MESSAGE` to the server
	* response is a `CHALLENGE_MESSAGE` to verify the client's identity
	* the client responds with an `AUTHENTICATE_MESSAGE`
* These hashes are stored locally in the SAM database or the NTDS.DIT database file on a Domain Controller
* The protocol has two hashed password values to choose from to perform authentication: the LM hash (as discussed above) and the NT hash, which is the MD4 hash of the little-endian UTF-16 value of the password
* The algorithm can be visualized as: `MD4(UTF-16-LE(password))`
![](Introduction%20to%20Active%20Directory-paste-3.png)
* GPU attacks have shown that the entire NTLM 8 character keyspace can be brute-forced in under `3 hours`
* NTLM is also vulnerable to the pass-the-hash attack, which means an attacker can use just the NTLM hash (after obtaining via another successful attack) to authenticate to target systems where the user is a local admin without needing to know the cleartext value of the password
* An NT hash takes the form of `b4b9b02e6f09a9bd760f388b67351e2b`, which is the second half of the full NTLM hash. An NTLM hash looks like this:
```shell-session
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```
* Rachel is the username
* 500 is the RID
	* 500 is the known RID for the `administrator` account
* `aad3c435b514a4eeaad3b935b51304fe` is the LM hash and, if LM hashes are disabled on the system, can not be used for anything
* `e46b9e548fa0d122de7f59fb6d48eaa2` is the NT hash. This hash can either be cracked offline to reveal the cleartext value (depending on the length/strength of the password) or used for a pass-the-hash attack
* Below is an example of a successful pass-the-hash attack using the [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) tool:

```shell-session
$ crackmapexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2

SMB         10.129.43.9     445    DC01      [*] Windows 10.0 Build 17763 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    DC01      [+] INLANEFREIGHT.LOCAL\rachel:e46b9e548fa0d122de7f59fb6d48eaa2 (Pwn3d!)
```

### NTLMv1 (Net-NTLMv1)
* NTLMv1 uses both the NT and the LM hash, which can make it easier to "crack" offline after capturing a hash using a tool such as Responder or via an NTLM relay attack
* used for network authentication
* . The server sends the client an 8-byte random number (challenge), and the client returns a 24-byte response
	* These hashes can NOT be used for pass-the-hash attacks
* NTLMv1 Hash ex:
```shell-session
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```
### NTLMv2 (Net-NTLMv2)
*  default in Windows since Server 2000
* It is hardened against certain spoofing attacks that NTLMv1 is susceptible to
* sends two responses to the 8-byte challenge received by the server
	* responses contain a 16-byte HMAC-MD5 hash of the challenge, a randomly generated challenge from the client, and an HMAC-MD5 hash of the user's credentials
	* A second response is sent, using a variable-length client challenge including the current time, an 8-byte random value, and the domain name
* NTLMv2 Hash ex:
```shell-session
admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
```
### Domain Cached Credentials (MSCache2)
* does not require a persistent network connection to work
* developed to solve the potential issue of a domain-joined host being unable to communicate with a domain controller (i.e., due to a network outage or other technical issue) and, hence, NTLM/Kerberos authentication not working to access the host in question
* Hosts save the last `ten` hashes for any domain users that successfully log into the machine in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry key
* hashes cannot be used in pass-the-hash attacks
* the hash is very slow to crack with a tool such as Hashcat, even when using an extremely powerful GPU cracking rig
* Hashes have the following format: `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`

# User and Machine Accounts
* When a user logs in, the system verifies their password and creates an access token
	* token describes the security content of a process or thread and includes the user's security identity and group membership
* Typically, every company we encounter will have at least one AD user account provisioned per user
* Aside from standard user and admin accounts tied back to a specific user, we will often see many service accounts used to run a particular application or service in the background or perform other vital functions
* We may also see organizations with hundreds of disabled accounts from former employees, temporary/seasonal employees, interns, etc
### Local Accounts
*  stored locally on a particular server or workstation
* Any rights assigned can only be granted to that specific host and will not work across the domain
* several default local user accounts that are created on a Windows system:
	* Administrator
		* SID `S-1-5-domain-500` and is the first account created with a new Windows installation
	* Guest
		* account is disabled by default
		* By default, it has a blank password and is generally recommended to be left disabled
	* SYSTEM
		* SYSTEM (or `NT AUTHORITY\SYSTEM`) account on a Windows host is the default account installed and used by the operating system to perform many of its internal functions
		* a profile for it does not exist, but it will have permissions over almost everything on the host
		* does not appear in User Manager and cannot be added to any groups
		* A `SYSTEM` account is the highest permission level one can achieve on a Windows host
	* Network Service
		* a predefined local account used by the Service Control Manager (SCM) for running Windows services
		* When a service runs in the context of this particular account, it will present credentials to remote services
	* Local Service
		* another predefined local account used by the Service Control Manager (SCM) for running Windows services
		* It is configured with minimal privileges on the computer and presents anonymous credentials to the network
### Domain Users
* granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on the permissions granted to their user account or the group that account is a member of
* One account to keep in mind is the `KRBTGT` account
	* a type of local account built into the AD infrastructure
	* This account acts as a service account for the Key Distribution service providing authentication and access for domain resources
	* common target of many attackers since gaining control or access will enable an attacker to have unconstrained access to the domain
		* can be leveraged for privilege escalation and persistence in a domain through attacks such as the golden ticket attack
### User Naming Attributes

| Naming Attribute        | Description                                                                                                                                                                                                                                                                      |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| UserPrincipalName (UPN) | This is the primary logon name for the user. By convention, the UPN uses the email address of the user.                                                                                                                                                                          |
| ObjectGUID              | This is a unique identifier of the user. In AD, the ObjectGUID attribute name never changes and remains unique even if the user is removed.                                                                                                                                      |
| SAMAccountName          | This is a logon name that supports the previous version of Windows clients and servers.                                                                                                                                                                                          |
| objectSID               | The user's Security Identifier (SID). This attribute identifies a user and its group memberships during security interactions with the server.                                                                                                                                   |
| sIDHistory              | This contains previous SIDs for the user object if moved from another domain and is typically seen in migration scenarios from domain to domain. After a migration occurs, the last SID will be added to the `sIDHistory` property, and the new SID will become its `objectSID`. |

### Domain-joined vs Non-domain-joined Machines
* Domain joined
	* Hosts joined to a domain have greater ease of information sharing within the enterprise and a central management point (the DC) to gather resources, policies, and updates from
* Non-domain joined
	* Non-domain joined computers or computers in a `workgroup` are not managed by domain policy
	* It is important to note that a machine account (`NT AUTHORITY\SYSTEM` level access) in an AD environment will have most of the same rights as a standard domain user account
	* access in the context of the `SYSTEM` account will allow us read access to much of the data within the domain and is a great launching point for gathering as much information about the domain as possible before proceeding with applicable AD-related attacks

# Active Directory Groups
### Types of Groups & Group Scopes
* Groups in Active Directory have two fundamental characteristics: `type` and `scope`
	* `group type` defines the group's purpose
		* There are two main types: `security` and `distribution` groups
			* `Security groups` type is primarily for ease of assigning permissions and rights to a collection of users instead of one at a time
				* All users added to a security group will inherit any permissions assigned to the group, making it easier to move users in and out of groups while leaving the group's permissions unchanged
			* `Distribution groups` type is used by email applications such as Microsoft Exchange to distribute messages to group members
				* This type of group cannot be used to assign permissions to resources in a domain environment
	* `group scope` shows how the group can be used within the domain or forest
		* There are three different `group scopes` that can be assigned when creating a new group
			* `Domain Local Group`: can only be used to manage permissions to domain resources in the domain where it was created
			* `Global Group`: can be used to grant access to resources in `another domain`
				* can only contain accounts from the domain where it was created
			* `Universal Group`: can be used to manage resources distributed across multiple domains and can be given permissions to any object within the same `forest`
				* available to all domains within an organization and can contain users from any domain
				* stored in the Global Catalog (GC), and adding or removing objects from a universal group triggers forest-wide replication
		* Group scopes can be changed, but there are a few caveats:
			* A Global Group can only be converted to a Universal Group if it is NOT part of another Global Group.
			* A Domain Local Group can only be converted to a Universal Group if the Domain Local Group does NOT contain any other Domain Local Groups as members.
			* A Universal Group can be converted to a Domain Local Group without any restrictions.
			* A Universal Group can only be converted to a Global Group if it does NOT contain any other Universal Groups as members.
### Nested Group Membership
* Tools such as BloodHound are particularly useful in uncovering privileges that a user may inherit through one or more nestings of groups
### Important Group Attributes
* Some of the most important group attributes include:
	- `cn`: The `cn` or Common-Name is the name of the group in Active Directory Domain Services.
	- `member`: Which user, group, and contact objects are members of the group.
	- `groupType`: An integer that specifies the group type and scope.
	- `memberOf`: A listing of any groups that contain the group as a member (nested group membership).
	- `objectSid`: This is the security identifier or SID of the group, which is the unique value used to identify the group as a security principal.

# Active Directory Rights and Privileges
* `Rights` are typically assigned to users or groups and deal with permissions to `access` an object such as a file
* `privileges` grant a user permission to `perform an action` such as run a program, shut down a system, reset passwords, etc
	* can be assigned individually to users or conferred upon them via built-in or custom group membership
* Windows computers have a concept called `User Rights Assignment`, which, while referred to as rights, are actually types of privileges granted to a user
### Built-in AD Groups

| Group Name                         | Description                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account Operators                  | Members can create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers. They cannot manage the Administrator account, administrative user accounts, or members of the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups.            |
| Administrators                     | Members have full and unrestricted access to a computer or an entire domain if they are in this group on a Domain Controller.                                                                                                                                                                                                                                                     |
| Backup Operators                   | Members can back up and restore all files on a computer, regardless of the permissions set on the files. Backup Operators can also log on to and shut down the computer. Members can log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, which, if taken, can be used to extract credentials and other juicy info. |
| DnsAdmins                          | Members have access to network DNS information. The group will only be created if the DNS server role is or was at one time installed on a domain controller in the domain.                                                                                                                                                                                                       |
| Domain Admins                      | Members have full access to administer the domain and are members of the local administrator's group on all domain-joined machines.                                                                                                                                                                                                                                               |
| Domain Computers                   | Any computers created in the domain (aside from domain controllers) are added to this group.                                                                                                                                                                                                                                                                                      |
| Domain Controllers                 | Contains all DCs within a domain. New DCs are added to this group automatically.                                                                                                                                                                                                                                                                                                  |
| Domain Guests                      | This group includes the domain's built-in Guest account. Members of this group have a domain profile created when signing onto a domain-joined computer as a local guest.                                                                                                                                                                                                         |
| Domain Users                       | This group contains all user accounts in a domain. A new user account created in the domain is automatically added to this group.                                                                                                                                                                                                                                                 |
| Enterprise Admins                  | Membership in this group provides complete configuration access within the domain. The group only exists in the root domain of an AD forest. Members in this group are granted the ability to make forest-wide changes such as adding a child domain or creating a trust. The Administrator account for the forest root domain is the only member of this group by default.       |
| Event Log Readers                  | Members can read event logs on local computers. The group is only created when a host is promoted to a domain controller.                                                                                                                                                                                                                                                         |
| Group Policy Creator Owners        | Members create, edit, or delete Group Policy Objects in the domain.                                                                                                                                                                                                                                                                                                               |
| Hyper-V Administrators             | Members have complete and unrestricted access to all the features in Hyper-V. If there are virtual DCs in the domain, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.                                                                                                                                                   |
| IIS_IUSRS                          | This is a built-in group used by Internet Information Services (IIS), beginning with IIS 7.0.                                                                                                                                                                                                                                                                                     |
| Pre–Windows 2000 Compatible Access | This group exists for backward compatibility for computers running Windows NT 4.0 and earlier. Membership in this group is often a leftover legacy configuration. It can lead to flaws where anyone on the network can read information from AD without requiring a valid AD username and password.                                                                               |
| Print Operators                    | Members can manage, create, share, and delete printers that are connected to domain controllers in the domain along with any printer objects in AD. Members are allowed to log on to DCs locally and may be used to load a malicious printer driver and escalate privileges within the domain.                                                                                    |
| Protected Users                    | Members of this group are provided additional protections against credential theft and tactics such as Kerberos abuse.                                                                                                                                                                                                                                                            |
| Read-only Domain Controllers       | Contains all Read-only domain controllers in the domain.                                                                                                                                                                                                                                                                                                                          |
| Remote Desktop Users               | This group is used to grant users and groups permission to connect to a host via Remote Desktop (RDP). This group cannot be renamed, deleted, or moved.                                                                                                                                                                                                                           |
| Remote Management Users            | This group can be used to grant users remote access to computers via WinRM                                                                                                                                                                                                                                                                                                        |
| Schema Admins                      | Members can modify the Active Directory schema, which is the way all objects with AD are defined. This group only exists in the root domain of an AD forest. The Administrator account for the forest root domain is the only member of this group by default.                                                                                                                    |
| Server Operators                   | This group only exists on domain controllers. Members can modify services, access SMB shares, and backup files on domain controllers. By default, this group has no members.                                                                                                                                                                                                      |
* Domain Admins Group Membership
```powershell-session
Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members
```
### User Rights Assignment

| Privilege                     | Description                                                                                                                                                                                                                                                                                       |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SeRemoteInteractiveLogonRight | This privilege could give our target user the right to log onto a host via Remote Desktop (RDP), which could potentially be used to obtain sensitive data or escalate privileges.                                                                                                                 |
| SeBackupPrivilege             | This grants a user the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file.                                            |
| SeDebugPrivilege              | This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as [Mimikatz](https://github.com/ParrotSec/mimikatz) to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory. |
| SeImpersonatePrivilege        | This privilege allows us to impersonate a token of a privileged account such as `NT AUTHORITY\SYSTEM`. This could be leveraged with a tool such as JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system.                                                        |
| SeLoadDriverPrivilege         | A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system.                                                                                                                                                       |
| SeTakeOwnershipPrivilege      | This allows a process to take ownership of an object. At its most basic level, we could use this privilege to gain access to a file share or a file on a share that was otherwise not accessible to us.                                                                                           |
* After logging into a host, typing the command `whoami /priv` will give us a listing of all user rights assigned to the current user

# Security in Active Directory
* General Active Directory Hardening Measures
	* LAPS (Microsoft Local Administrator Solution): used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement
		* Accounts can be set up to have their password rotated on a fixed interval (i.e., 12 hours, 24 hours, etc.)
	* Audit policy settings (logging and monitoring)
	* Group policy security settings: GPOs are virtual collections of policy settings that can be applied to specific users, groups, and computers at the OU level
		* Account policies
		* Local policies
		* software restriction policies
		* application control policies
		* Advanced audit policy configuration
	* Update management (SCCM/WSUS)
		* Windows server update service: can be installed as a role on a Windows Server and can be used to minimize the manual task of patching Windows systems
		* System Center Configuration Manager: paid solution that relies on the WSUS Windows Server role being installed and offers more features than WSUS on its own
	* group managed service accounts (gMSA)
		* An account managed by the domain that offers a higher level of security than other types of service accounts for use with non-interactive applications, services, processes, and tasks that are run automatically but require credentials to run
	* security groups
		* Active Directory automatically creates some default security groups during installation
			* Some examples are Account Operators, Administrators, Backup Operators, Domain Admins, and Domain Users
	* Account separation
	* password complexity policies + passphrase + 2fa
	* limiting domain admin account usage
	* Periodically Auditing and Removing Stale Users and Objects
	* Auditing Permissions and Access
	* Audit Policies & Logging
	* Using Restricted Groups
	* Limiting Server Roles
	* Limiting Local Admin and RDP Rights

# Examining Group Policy
* A Group Policy Object (GPO) is a virtual collection of policy settings that can be applied to `user(s)` or `computer(s)`
* GPO settings are processed using the hierarchical structure of AD and are applied using the `Order of Precedence` rule
	* Local Group Policy
	* Site Policy
	* Domain-wide Policy
	* Organizational Unit (OU)
	* Any OU Policies nested within other OUs
![](Introduction%20to%20Active%20Directory-paste-4.png)
* When a new GPO is created, the settings are not automatically applied right away
	* periodic Group Policy updates by default is done every 90 minutes with a randomized offset of +/- 30 minutes for users and computers
	* it could take up to 2 hours (120 minutes) until the settings take effect
	* we can issue the command `gpupdate /force` to kick off the update process
		* command will compare the GPOs currently applied on the machine against the domain controller and either modify or skip them depending on if they have changed since the last automatic update
	* can modify the refresh interval via Group Policy by clicking on `Computer Configuration --> Policies --> Administrative Templates --> System --> Group Policy` and selecting `Set Group Policy refresh interval for computers`

# AD Administration: Guided Lab Part 1
1. Managing Users
* Need to add new-hires to AD
* In Active Directory Users and computers create new users in `Inlanefreight.local > Corp > Employees > HQ-NYC > IT`
	* add name, email, and have user change password at next logon
* Right click the `Employees` and select find
	* enter the names of the user you want to remove and then delete the user
	* find name of user you need to unlock, right click and select reset password
		* change password and select unlock user's account
2. Manage Groups and Other Organizational Units
* Right click the `IT` folder and select new, then OU
	* Enter the name and hit ok
* Right click the new OU and select new, group
	* enter the name, domain local,  and security
* Back in the `IT` folder right click the new users and add to the new group
3. Manage Group Policy Objects
* Now in Group Policy Management right click logon banner and paste it into group policy objects
	* rename it to `Security Analysts Control`
* Right click the new gpo and under `User Configuration > Policies > Administrative Templates > System > Removable Storage Access` right click `All removeable storage classes: deny all access` 
	* select enable and then apply, then ok
* Under `User Configuration > Policies > Administrative Templates > System` right click `prevent access to the command prompt`
	* select disable and then apply, then ok
* Under `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options` and right click `interactive logon: message text for users attempting to logon`
	* make sure that the radial to define the policy setting is enabled and there is a Banner in the text box
	* right click `Interactive logon: message title for users attempting to logon` and make sure the title is defined and the radical is selected
* Now under account policies select password policy
	* configure a password policy
		* pass history: 5
		* min pass age: 7 days
		* max pass age: 30 days
		* min pass length: 10 chars
		* pass must meet complexity reqs

# AD Administration: Guided Lab Part 2
4. Add and Remove Computers to the Domain
* 