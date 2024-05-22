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

# Windows Services & 
# Service permissions 