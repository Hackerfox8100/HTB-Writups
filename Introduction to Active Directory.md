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
* **userPrincipalName:** 