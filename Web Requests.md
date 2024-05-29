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
* whenever web applications need to transfer files or move the user parameters from the URL, they utilize `POST` requests
* HTTP `POST` places user parameters within the HTTP Request body
	* lack of logging
	* less encoding requirements
	* more data can be sent

### Login Forms
* We can click on the request, click on the `Request` tab (which shows the request body), and then click on the `Raw` button to show the raw request data. We see the following data is being sent as the POST request data
```bash
username=admin&password=admin
```
* With the request data at hand, we can try to send a similar request with cURL, to see whether this would allow us to login as well
	* use the `-X POST` flag to send a `POST` request
	*  to add our POST data, we can use the `-d` flag and add the above data after it
```shell-session
curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```
* **Tip:** Many login forms would redirect us to a different page once authenticated (e.g. /dashboard.php). If we want to follow the redirection with cURL, we can use the `-L` flag

### Authenticated Cookies
* can use the `-v` or `-i` flags to view the response, which should contain the `Set-Cookie` header with our authenticated cookie
* we can set the above cookie with the `-b` flag in cURL, as follows
```shell-session
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```
* It is also possible to specify the cookie as a header
```bash
curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```
* Can use an earlier authenticated cookie to see if you can get in without needing to provide creds
	* in devtools > storage > cookies replace the cookie value with your previous one
		* or right-click on the cookie and select `Delete All`, and the click on the `+` icon to add a new cookie
		* After that, we need to enter the cookie name, which is the part before the `=` (`PHPSESSID`), and then the cookie value, which is the part after the `=` (`c1nsa6op7vtk7kdis7bcnbadf1`)
* *having a valid cookie may be enough to get authenticated into many web applications. This can be an essential part of some web attacks, like Cross-Site Scripting*

### JSON Data
* we can make any search query to see what requests get sent
* the search form sends a POST request to `search.php`, with the following data:
```json
{"search":"london"}
```
*  POST data appear to be in JSON format, so our request must have specified the `Content-Type` header to be `application/json`
*  try to replicate this request as we did earlier, but include both the cookie and content-type headers, and send our request to `search.php`
```shell-session
curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php
["London (UK)"]
```
* can right-click on the request and select `Copy>Copy as Fetch`, and then go to the `Console` tab and execute our code there

# CRUD API
* This section will look at how such a web application may utilize APIs to perform the same thing, and we will directly interact with the API endpoint
* several types of APIs
* Many APIs are used to interact with a database, such that we would be able to specify the requested table and the requested row within our API query, and then use an HTTP method to perform the operation needed
* we can easily specify the table and the row we want to perform an operation on through such APIs
	* we may utilize different HTTP methods to perform different operations on that row

| Operation | HTTP Method | Description                                        |
| --------- | ----------- | -------------------------------------------------- |
| `Create`  | `POST`      | Adds the specified data to the database table      |
| `Read`    | `GET`       | Reads the specified entity from the database table |
| `Update`  | `PUT`       | Updates the data of the specified database table   |
| `Delete`  | `DELETE`    | Removes the specified row from the database table  |
* These four operations are mainly linked to the commonly known CRUD APIs, but the same principle is also used in REST APIs and several other types of APIs
* we can simply specify the table name after the API (e.g. `/city`) and then specify our search term (e.g. `/london`), as follows:
```shell-session
curl http://<SERVER_IP>:<PORT>/api.php/city/london
```
* To have it properly formatted in JSON format, we can pipe the output to the `jq` utility, which will format it properly. We will also silent any unneeded cURL output with `-s`, as follows:
```shell-session
curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq
```
* we can pass an empty string to retrieve all entries in the table
```shell-session
curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq
```

### Create
* To add a new entry, we can use an HTTP POST request
* can simply POST our JSON data, and it will be added to the table
	* As this API is using JSON data, we will also set the `Content-Type` header to JSON, as follows:
```shell-session
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

### Update
* `PUT` is used to update API entries and modify their details
* **Note:** The HTTP `PATCH` method may also be used to update API entries instead of `PUT`. To be precise, `PATCH` is used to partially update an entry (only modify some of its data "e.g. only city_name"), while `PUT` is used to update the entire entry
* Using `PUT` is quite similar to `POST` in this case, with the only difference being that we have to specify the name of the entity we want to edit in the URL, otherwise the API will not know which entity to edit
* all we have to do is specify the `city` name in the URL, change the request method to `PUT`, and provide the JSON data like we did with POST, as follows:
```shell-session
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```
*  replaced the old city name with the new city

### DELETE
*  try to delete a city, which is as easy as reading a city
* simply specify the city name for the API and use the HTTP `DELETE` method, and it would delete the entry, as follows:
```shell-session
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```
