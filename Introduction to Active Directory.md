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
* 