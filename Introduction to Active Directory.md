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
* 