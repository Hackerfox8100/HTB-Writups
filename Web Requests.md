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

# HTTP Headers
* Headers can be divided into the following categories
	* General Headers
		* used in both HTTP requests and responses
		* contextual and are used to `describe the message rather than its contents`
			* Date
			* Connection
	* Entity Headers
		* can be `common to both the request and response`
		* used to `describe the content` (entity) transferred by a message
		* usually found in responses and POST or PUT requests
			* Content-Type
			* Media-Type
			* Boundary
			* Content-Length
			* Content-Encoding
	* Request Headers
		* `used in an HTTP request and do not relate to the content` of the message
			* Host
			* User-Agent
			* Referer
			* Accept
			* Cookie
			* Authorization
	* Response Headers
		* can be `used in an HTTP response and do not relate to the content`
			* Server
			* Set-Cookie
			* WWW-Authenticate
	* Security Headers
		* `a class of response headers used to specify certain rules and policies` to be followed by the browser while accessing the website
			* Content-Security-Policy
			* Strict-Transport-Security
			* Referrer-Policy
* If we were only interested in seeing the response headers, then we can use the `-I` flag to send a `HEAD` request and only display the response headers
	* we can use the `-i` flag to display both the headers and the response body (e.g. HTML code)
* cURL also allows us to set request headers with the `-H` flag
	* cURL also allows us to set request headers with the `-H` flag
*  can go to the `Network` tab to view the different requests made by the page
	* In the first `Headers` tab, we see both the HTTP request and HTTP response headers
	* devtools automatically arrange the headers into sections, but we can click on the `Raw` button to view their details in their raw format
	* we can check the `Cookies` tab to see any cookies used by the request, as discussed in an upcoming section

# HTTP Methods and Codes
* **Note:** Most modern web applications mainly rely on the `GET` and `POST` methods. However, any web application that utilizes REST APIs also rely on `PUT` and `DELETE`, which are used to update and delete data on the API endpoint

# GET
* To provide the credentials through cURL, we can use the `-u` flag
* There is another method we can provide the `basic HTTP auth` credentials, which is directly through the URL as (`username:password@URL`)
* As we are using `basic HTTP auth`, we see that our HTTP request sets the `Authorization` header to `Basic YWRtaW46YWRtaW4=`, which is the base64 encoded value of `admin:admin`
	* If we were using a modern method of authentication (e.g. `JWT`), the `Authorization` would be of type `Bearer` and would contain a longer encrypted token
* As the page returns our results, it may be contacting a remote resource to obtain the information, and then display them on the page
	* we can open the browser devtools and go to the Network tab
		* Before we enter our search term and view the requests, we may need to click on the `trash` icon on the top left, to ensure we clear any previous requests and only monitor newer requests
		* Ex: When we click on the request, it gets sent to `search.php` with the GET parameter `search=le` used in the URL. This helps us understand that the search function requests another page for the results
	* Can right-click on the request and select `Copy>Copy as cURL`. Then, we can paste the copied command in our terminal and execute it, and we should get the exact same response
		* **Note:** The copied command will contain all headers used in the HTTP request. However, we can remove most of them and only keep necessary authentication headers, like the `Authorization` header.
* can also repeat the exact request right within the browser devtools, by selecting `Copy>Copy as Fetch`
	* will copy the same HTTP request using the JavaScript Fetch library

# POST
* 