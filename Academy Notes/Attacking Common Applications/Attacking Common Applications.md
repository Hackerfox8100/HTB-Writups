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
* 