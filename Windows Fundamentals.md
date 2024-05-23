# Introduction to Windows
### Get-WmiObject
* `Get-WmiObject` cmdlet can be used to find information about the OS like version number and build number
	* This can be done by specifying the `win32_OperatingSystem` class: `Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber`
* Other useful classes:
	* `Win32_Process`: Process listing
	* `Win32_Service`: Service listing
	* `Win32_Service`: BIOS information
	* `ComputerName`: Information about remote computers
* `Get-WmiObject` can also be used to start and stop services on local and remote computers

### Xfreedp
* Used to remotely access Windows targets from Linux-based attack hosts
* `xfreerdp /v:<targetIp> /u:<Username> /p:<Password>`
	* connection via RDP

# Operating System Structure

| Directory                  | Function                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Perflogs                   | Can hold Windows performance logs but is empty by default                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Program Files              | On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Program Files (x86)        | 32-bit and 16-bit programs are installed here on 64-bit editions of Windows.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ProgramData                | This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.                                                                                                                                                                                                                                                                                                                                                                                  |
| Users                      | This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Default                    | This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.                                                                                                                                                                                                                                                                                                                                                                                                    |
| Public                     | This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.                                                                                                                                                                                                                                                                                                                                                         |
| AppData                    | Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode. |
| Windows                    | The majority of the files required for the Windows operating system are contained here.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| System, System32, SysWOW64 | Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.                                                                                                                                                                                                                                                                                                                                                        |
| WinSxS                     | The Windows Component Store contains a copy of all Windows components, updates, and service packs.                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

* Explore the file system with the `dir` command
	* Windows equivalent of `ls`
* `tree` graphically displays the directory structure

# File System
* 5 types of Windows file systems, but main focus is NTFS
* NTFS has basic and advanced permissions

| Permission Type      | Description                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Full Control         | Allows reading, writing, changing, deleting of files/folders.                                                                                                                                                                                                                                                                                                                              |
| Modify               | Allows reading, writing, and deleting of files/folders.                                                                                                                                                                                                                                                                                                                                    |
| List Folder Contents | Allows for viewing and listing folders and subfolders as well as executing files. Folders only inherit this permission.                                                                                                                                                                                                                                                                    |
| Read and Execute     | Allows for viewing and listing files and subfolders as well as executing files. Files and folders inherit this permission.                                                                                                                                                                                                                                                                 |
| Write                | Allows for adding files to folders and subfolders and writing to a file.                                                                                                                                                                                                                                                                                                                   |
| Read                 | Allows for viewing and listing of folders and subfolders and viewing a file's contents.                                                                                                                                                                                                                                                                                                    |
| Traverse Folder      | This allows or denies the ability to move through folders to reach other files or folders. For example, a user may not have permission to list the directory contents or view files in the documents or web apps directory in this example c:\users\bsmith\documents\webapps\backups\backup_02042020.zip but with Traverse Folder permissions applied, they can access the backup archive. |

* NTFS perms on files and folders can be managed through the File Explorer GUI in the security tab
* List NTFS perms on a specific dir by running `icacls`
* Inheritance settings
	* (CI): container inherit
	* (OI): object inherit
	* (IO): inherit only
	* (NP): do not propagate inherit
	* (I): permission inherited from parent container
* Access permissions
	* F: full access
	* D: delete access
	* N: no access
	* M: modify access
	* RX: read and execute access
	* R: read-only access
	* W: write-only access

# NTFS vs. Share Permissions
* SMB is used to connect shared resources like files and printers
* Visualization
![](Windows%20Fundamentals-paste.png)
* NTFS and share permissions are not the same, but often apply to the same shared resources
### Share permissions

| Permission   | Description                                                                                                                                 |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Full Control | Users are permitted to perform all actions given by Change and Read permissions as well as change permissions for NTFS files and subfolders |
| Change       | Users are permitted to read, edit, delete and add files and subfolders                                                                      |
| Read         | Users are allowed to view file & subfolder contents                                                                                         |

### NTFS basic permissions

| Permission           | Description                                                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Full Control         | Users are permitted to add, edit, move, delete files & folders as well as change NTFS permissions that apply to all allowed folders |
| Modify               | Users are permitted or denied permissions to view and modify files and folders. This includes adding or deleting files              |
| Read & Execute       | Users are permitted or denied permissions to read the contents of files and execute programs                                        |
| List folder contents | Users are permitted or denied permissions to view a listing of files and subfolders                                                 |
| Read                 | Users are permitted or denied permissions to read the contents of files                                                             |
| Write                | Users are permitted or denied permissions to write changes to a file and add new files to a folder                                  |
| Special Permissions  | A variety of advanced permissions options                                                                                           |
* Similar to NTFS permissions, there is an access control list (ACL) for shared resources
	* Basically the SMB permissions list
* Contains access control entries (ACEs)
	* made up of users and groups (also called security principles)
* Windows Defender Firewall Considerations
	* could potentially be blocking access to the SMB share
* **It is also important to note that when a Windows system is part of a workgroup, all `netlogon` requests are authenticated against that particular Windows system's `SAM` database**
* **When a Windows system is joined to a Windows Domain environment, all netlogon requests are authenticated against `Active Directory`**
	* The primary difference between a workgroup and a Windows Domain in terms of authentication, is with a workgroup the local SAM database is used and in a Windows Domain a centralized network-based database (Active Directory) is used
* Mounting to a share:
	* `sudo mount -t cifs -o username=USER,password=PASS //TARGETIP/"Company Data" /home/user/Desktop/`
	* If the syntax is correct and the command is not working try running: `sudo apt-get install cifs-utils` 
* Display shares with the command `net share`
* Computer management can also be used to monitor shared resources
	* good places to check for information are in Shares, Sessions, and Open Files
* Share access logs can be accessed in Event Viewer

# Windows Services & Processes
### Services
* Services are managed via the Service Control Manager (SCM) system
	* Accessible via the `services.msc` MMC add-in
* Can also query and manage services through CLI using sc.exe using powershell cmdlets like `Get-Service`. Ex:
```powershell
Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl
```
* Service statuses can appear as Running, Stopped, or Paused, and they can be set to start manually, automatically, or on a delay at system boot
* Three categories of services:
	* Local services
	* network services
	* system services
* **Critical system services:**

| Service                   | Description                                                                                                                                                                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| smss.exe                  | Session Manager SubSystem. Responsible for handling sessions on the system.                                                                                                                                                                             |
| csrss.exe                 | Client Server Runtime Process. The user-mode portion of the Windows subsystem.                                                                                                                                                                          |
| wininit.exe               | Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program.                                                                                                        |
| logonui.exe               | Used for facilitating user login into a PC                                                                                                                                                                                                              |
| lsass.exe                 | The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service.                                                                |
| services.exe              | Manages the operation of starting and stopping services.                                                                                                                                                                                                |
| winlogon.exe              | Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running.                                                                                                        |
| System                    | A background system process that runs the Windows kernel.                                                                                                                                                                                               |
| svchost.exe with RPCSS    | Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS).                                |
| svchost.exe with Dcom/PnP | Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services. |
### Processes
* **Local security authority subsystem service (LSASS)**
	* `lsass.exe` is the process that is responsible for enforcing the security policy on Windows systems
	* When a user attempts to log on to the system, this process verifies their log on attempt and creates access tokens based on the user's permission levels
	* also responsible for user account password changes
	* events associated with this process (logon/logoff attempts, etc.) are logged within the Windows Security Log
	* HIGH VALUE TARGET
		* can be used to extract cleartext and hashed creds that are stored in memory
* Sysinternals
	* Can be downloaded from the Microsoft website or can be loaded directly from an internet-accessible file share by typing `\\live.sysinternals.com\tools` into a Windows Explorer window
	* Includes tools like Process Explorer, Task Manager, and Process Monitor
		* also includes TCPView, which is used to monitor internet activity, and PSExec, which can be used to manage/connect to systems via the SMB protocol remotely
* Task Manager
	* provides information about running processes, system performance, running services, startup programs, logged-in users/logged in user processes, and services
* Process Explorer
	* part of sysinternals tool suite
	* can show which handles and DLL processes are loaded when a program runs

# Service permissions 
* be mindful of service permissions and the permissions of the directories they execute from because it is possible to replace the path to an executable with a malicious DLL or executable file
* Can use `services.msc` to view and manage almost all details regarding services
* Most services run with LocalSystem privileges by default which is the highest level of access allowed on an individual Windows OS
* Notable built-in service accounts in Windows:
	* LocalService
	* NetworkService
	* LocalSystem
* The `sc qc` command is used to query the service
* If we wanted to query a service on a device over the network, we could specify the hostname or IP address immediately after `sc`
```cmd-session
sc //hostname or ip of box query ServiceName
```
* can also use sc to start and stop services
```cmd-session
sc stop wuauserv
```
* Another helpful way we can examine service permissions using `sc` is through the `sdshow` command
	* amalgamation of characters crunched together and delimited by opened and closed parentheses is in a format known as the `Security Descriptor Definition Language` (`SDDL`)
* Every named object in Windows is a securable object, and even some unnamed objects are securable
	* If it's securable in a Windows OS, it will have a security descriptor. Security descriptors identify the object’s owner and a primary group containing a `Discretionary Access Control List` (`DACL`) and a `System Access Control List` (`SACL`) 
		* DACL is used for controlling access to an object
		* SACL is used to account for and log access attempts
* Using the `Get-Acl` PowerShell cmdlet, we can examine service permissions by targeting the path of a specific service in the registry
	* easier to read output

# Windows Sessions
* Interactive 
	* local logon session
	* initiated by a user authenticating to a local or domain system by entering their credentials
	* can be initiated by logging directly into the system, by requesting a secondary logon session using the `runas` command via the command line, or through a Remote Desktop connection
* Non-interactive
	* differ from standard user accounts as they do not require login credentials
	* 3 types of non-interactive accounts: 
		* Local System Account: `NT AUTHORITY\SYSTEM`
			* most powerful account in Windows systems. It is used for a variety of OS-related tasks, such as starting Windows services. This account is more powerful than accounts in the local administrators group
		* Local Service Account: `NT AUTHORITY\LocalService`
			* less privileged version of the SYSTEM account and has similar privileges to a local user account. It is granted limited functionality and can start some services
		* Network Service Account: `NT AUTHORITY\NetworkService`
			* similar to a standard domain user account. It has similar privileges to the Local Service Account on the local machine. It can establish authenticated sessions for certain network services.
	* used by the Windows operating system to automatically start services and applications without requiring user interaction
	* These accounts have no password associated with them and are usually used to start services when the system boots or to run scheduled tasks

# Interacting with the Windows Operating System
* GUI
* RDP (port 3389)
* Windows Command Line
	* main two ways to interact with the system from the command line are via the Command Prompt (CMD) and PowerShell
	* CMD
		* certain commands have their own help menus, which can be accessed by typing `<command> /?` 
	* PowerShell
		* utilizes cmdlets
			*  in the form of `Verb-Noun`
			* Ex: `Get-ChildItem` can be used to list our current directory
			* can add flags
			* Ex: `Get-ChildItem -Recurse` will show us the contents of our current working directory and all subdirectories
		* aliases
			* Ex: `Get-ChildItem -Recurse` will show us the contents of our current working directory and all subdirectories
### Scripts
* One common way to work with a script in PowerShell is to import it so that all functions are then available within our current PowerShell console session: `Import-Module .\PowerView.ps1`
*  can then either start a command and cycle through the options or type `Get-Module` to list all loaded modules and their associated commands
* `execution policy` attempts to prevent the execution of malicious scripts, and can sometimes stop you from running scripts

# Windows Management Instrumentation (WMI)
* subsystem of PowerShell that provides system administrators with powerful tools for system monitoring
* Some of the uses for WMI are:
	- Status information for local/remote systems
	- Configuring security settings on remote machines/applications
	- Setting and changing user and group permissions
	- Setting/modifying system properties
	- Code execution
	- Scheduling processes
	- Setting up logging
- WMI can be run via the Windows command prompt by typing `WMIC` to open an interactive shell or by running a command directly such as `wmic computersystem get name` to get the hostname
- view a listing of WMIC commands and aliases by typing `WMIC /?`
- WMI can be leveraged offensively for both enumeration and lateral movement.

# Microsoft Management Console (MMC)
* can be used to group snap-ins, or administrative tools, to manage hardware, software, and network components within a Windows host
* can also use MMC to create custom tools and distribute them to users
* works with the concept of snap-ins, allowing administrators to create a customized console with only the administrative tools needed to manage several services
	* These snap-ins can be added to manage both local and remote systems
* Can add or remove snap-ins to begin customizing admin console

# Windows Subsystem for Linux (WSL)
* allows Linux binaries to be run natively on Windows 10 and Windows Server 2019
* WSL can be installed by running the PowerShell command `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux` as an Administrator
	* Once this feature is enabled, we can either download a Linux distro from the Microsoft Store and install it or manually download the Linux distro of our choice and unpack and install it from the command line
*  can access the C$ volume and other volumes on the host operating system via the `mnt` directory

# Windows Security
* Windows follows certain security principles
	* units in the system that can be authorized or authenticated for a particular action
	* units include users, computers on the network, threads, or processes
* Each of the security principals on the system has a unique security identifier (SID)
* `wmic useraccount get name,sid`
	* SIDs are string values with different lengths, which are stored in the security database
	* SIDs are added to the user's access token to identify all actions that the user is authorized to take
	* consists of the Identifier Authority and the Relative ID (RID)
	* In an Active Directory (AD) domain environment, the SID also includes the domain SID.
	* The SID is broken down into this pattern
		* (SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)
		* SID: Identifies the string as a SID.
		* Revision level: To date, this has never changed and has always been `1`.
		* Identifier-authority: A 48-bit string that identifies the authority (the computer or network) that created the SID.
		* Subauthority1: This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account.
		* Subauthority2: Tells us which computer (or domain) created the number
		* Subauthority3: The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group
### Security Accounts Manager (SAM) & Access Control Entries (ACE)
* SAM grants rights to a network to execute specific processes
* The access rights themselves are managed by Access Control Entries (ACE) in Access Control Lists (ACL)
* two types of ACLs: the `Discretionary Access Control List (DACL)` or `System Access Control List (SACL)`
* Every thread and process started or initiated by a user goes through an authorization process
	* An integral part of this process is access tokens, validated by the Local Security Authority (LSA). In addition to the SID, these access tokens contain other security-relevant information
### User Account Control (UAC)
* security feature in Windows to prevent malware from running or manipulating processes that could damage the computer or its contents
* visualization:
![](Windows%20Fundamentals-paste-1.png)
### Registry
* hierarchical database in Windows critical for the operating system
* stores low-level settings for the Windows operating system and applications that choose to use it
* divided into computer-specific and user-specific data
* The entire system registry is stored in several files on the operating system. You can find these under `C:\Windows\System32\Config\`
* The user-specific registry hive (HKCU) is stored in the user folder (i.e., `C:\Users\<USERNAME>\Ntuser.dat`)
### Local Group Policy
* allows administrators to set, configure, and adjust a variety of settings
* group policies are pushed down from a Domain Controller onto all domain-joined machines that Group Policy objects (GPOs) are linked to
* can be configured locally, in both domain environments and non-domain environments
* can open the Local Group Policy Editor by opening the Start menu and typing `gpedit.msc`
*  split into two categories under Local Computer Policy - `Computer Configuration` and `User Configuration`
* ex:  split into two categories under Local Computer Policy - `Computer Configuration` and `User Configuration`
*  can also enable fine-tuned account auditing and configure AppLocker from the Local Group Policy Editor

### Windows Defender AV
* built-in antivirus that ships for free with Windows operating systems
* comes with several features such as real-time protection, which protects the device from known threats in real-time and cloud-delivered protection, which works in conjunction with automatic sample submission to upload suspicious files for analysis
* managed from the Security Center
* can use the PowerShell cmdlet `Get-MpComputerStatus` to check which protection settings are enabled

# Skills Assessment
1. Creating a shared folder called Company Data
2. Creating a subfolder called HR inside of the Company Data folder
3. Creating a user called Jim
	1. Uncheck: `User must change password at logon`
4. Creating a security group called HR
5. Adding Jim to the HR security group
6. Adding the HR security group to the shared Company Data folder and NTFS permissions list
	1. Remove the default group that is present
	2. Share permissions: `Allow Change & Read`
	3. Disable Inheritance before issuing specific NTFS perms
	4. NTFS perms: `Modify, Read & `