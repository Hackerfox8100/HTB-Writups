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


# Service permissions 
