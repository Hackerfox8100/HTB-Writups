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
	* `wp-login` will attempt to 