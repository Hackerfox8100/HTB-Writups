* A lot of the apps will need to be manually added to the `/etc/hosts` file. Modify this oneliner to do it quick:
```bash
$ IP=10.129.42.195
$ printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```
