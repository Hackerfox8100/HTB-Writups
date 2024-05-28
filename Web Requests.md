# HyperText Transfer Protocol
![](Web%20Requests-paste.png)
* **Note:** Our browsers usually first look up records in the local '`/etc/hosts`' file, and if the requested domain does not exist within it, then they would contact other DNS servers. We can use the '`/etc/hosts`' to manually add records to for DNS resolution, by adding the IP followed by the domain name.
* cURL (client URL) is a command-line tool and library that primarily supports HTTP along with many other protocols
	* can send a basic HTTP request to any URL by using it as an argument for cURL
	* cURL does not render the HTML/JavaScript/CSS code, unlike a web browser, but prints it in its raw format
	* may also use cURL to download a page or a file and output the content into a file using the `-O` flag
		* If we want to specify the output file name, we can use the `-o` flag and specify the name
	*  can silent the status with the `-s` flag, as follows

# HyperText Transfer Protocol Secure (HTTPS)
![](Web%20Requests-paste-1.png)
* cURL should automatically handle all HTTPS communication standards and perform a secure handshake and then encrypt and decrypt data automatically
	*  However, if we ever contact a website with an invalid SSL certificate or an outdated one, then cURL by default would not proceed with the communication to protect against the earlier mentioned MITM attacks
	* To skip the certificate check with cURL, we can use the `-k` flag

# HTTP Requests and Responses
![](Web%20Requests-paste-2.png)
![](Web%20Requests-paste-3.png)
* To view the full HTTP request and response with curl, we can simply add the `-v` verbose flag to our earlier commands, and it should print both the request and response
	* The `-vvv` flag shows an even more verbose output
* Most modern web browsers come with built-in developer tools (`DevTools`), which are mainly intended for developers to test their web applications
	* To open the browser devtools in either Chrome or Firefox, we can click `CTRL+SHIFT+I` or simply click `F12`
	* mostly be focusing on the `Network` tab as it is responsible for web requests
		*  we can use `Filter URLs` to search for a specific request, in case the website loads too many to go through