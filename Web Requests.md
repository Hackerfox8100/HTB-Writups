# HyperText Transfer Protocol
![](Web%20Requests-paste.png)
* **Note:** Our browsers usually first look up records in the local '`/etc/hosts`' file, and if the requested domain does not exist within it, then they would contact other DNS servers. We can use the '`/etc/hosts`' to manually add records to for DNS resolution, by adding the IP followed by the domain name.
* cURL (client URL) is a command-line tool and library that primarily supports HTTP along with many other protocols
	* can send a basic HTTP request to any URL by using it as an argument for cURL
	* cURL does not render the HTML/JavaScript/CSS code, unlike a web browser, but prints it in its raw format
	* may also use cURL to download a page or a file and output the content into a file using the `-O` flag
		* If we want to specify the output file name, we can use the `-o` flag and specify the name
	*  can silent the status with the `-s` flag, as follows