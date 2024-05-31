# Intro to Web Proxies
* Web proxies are specialized tools that can be set up between a browser/mobile application and a back-end server to capture and view all the web requests being sent between both ends, essentially acting as man-in-the-middle (MITM) tools
* some of the other tasks we may use web proxies for besides capturing and replaying HTTP requests:
	*  Web application vulnerability scanning
	- Web fuzzing
	- Web crawling
	* Web application mapping
	- Web request analysis
	- Web configuration testing
	- Code reviews

# Setting Up
* Select `temporary project`
* Select `use burp defaults`
* `start burp`
* can launch ZAP from the terminal with the `zaproxy` command

# Proxy Setup
* In Burp's (`Proxy>Intercept`), we can click on `Open Browser`, which will open Burp's pre-configured browser, and automatically route all web traffic through Burp
* In ZAP, we can click on the Firefox browser icon at the end of the top bar, and it will open the pre-configured browser
* We can manually go to Firefox preferences and set up the proxy to use the web proxy listening port
	* Both Burp and ZAP use port `8080` by default, but we can use any available port
		* **Note:** In case we wanted to serve the web proxy on a different port, we can do that in Burp under (`Proxy>Options`), or in ZAP under (`Tools>Options>Local Proxies`)
* Instead of manually switching the proxy, we can utilize the Firefox extension Foxy Proxy to easily and quickly change the Firefox proxy

### Installing CA Certificate
* We can install Burp's certificate once we select Burp as our proxy in `Foxy Proxy`, by browsing to `http://burp`, and download the certificate from there by clicking on `CA Certificate`
* To get ZAP's certificate, we can go to (`Tools>Options>Dynamic SSL Certificate`), then click on `Save`
	* We can also change our certificate by generating a new one with the `Generate` button
* Once we have our certificates, we can install them within Firefox by browsing to about:preferences#privacy, scrolling to the bottom, and clicking `View Certificates`
* After that, we can select the `Authorities` tab, and then click on `import`, and select the downloaded CA certificate
* Finally, we must select `Trust this CA to identify websites` and `Trust this CA to identify email users`, and then click OK

# Intercepting Web Requests
* In Burp, we can navigate to the `Proxy` tab, and request interception should be on by default
	* If we want to turn request interception on or off, we may go to the `Intercept` sub-tab and click on `Intercept is on/off` button to do so
* In ZAP, interception is off by default, as shown by the green button on the top bar (green indicates that requests can pass and not be intercepted)
	* `CTRL+B` toggles on/off

### Manipulating Intercepted Requests
* Typically, we can only specify numbers in the `IP` field using the browser, as the web page prevents us from sending any non-numeric characters using front-end JavaScript
* with the power of intercepting and manipulating HTTP requests, we can try using other characters to "break" the application
* Ex: let us change the `ip` parameter's value from `1` to `;ls;` and see how the web application handles our input

# Intercepting Responses
* This can be useful when we want to change how a specific web page looks, like enabling certain disabled fields or showing certain hidden fields, which may help us in our penetration testing activities
* In Burp, we can enable response interception by going to (`Proxy>Options`) and enabling `Intercept Response` under `Intercept Server Responses`
* Ex: try changing the `type="number"` on line 27 to `type="text"`, which should enable us to write any value we want
	* also change the `maxlength="3"` to `maxlength="100"` so we can enter longer input
* we could change the way the page is rendered by the browser and can now input any value we want
	* We may use the same technique to persistently enable any disabled HTML buttons by modifying their HTML code
* `Burp` also has a similar feature, which we can enable under `Proxy>Options>Response Modification`, then select one of the options, like `Unhide hidden form fields`

# Automatic Modification
* we can utilize automatic modifications based on rules we set, so the web proxy tools will automatically apply them
* Burp `Match and Replace`
	* go to (`Proxy>Options>Match and Replace`) and click on `Add`

| Option                                        | Description                                                                                                                                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Type`: `Request header`                      | Since the change we want to make will be in the request header and not in its body.                                                              |
| `Match`: `^User-Agent.*$`                     | The regex pattern that matches the entire line with `User-Agent` in it.                                                                          |
| `Replace`: `User-Agent: HackTheBox Agent 1.0` | This is the value that will replace the line we matched above.                                                                                   |
| `Regex match`: True                           | We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above. |

# Repeating Requests
* If we want to repeat the same process with a different command, we would have to intercept the request again, provide a different payload, forward it again, and finally check our browser to get the final result
	* Request repeating allows us to resend any web request that has previously gone through the web proxy
* we can view the HTTP requests history in `Burp` at (`Proxy>HTTP History`)
* Burp provides the ability to examine both the original request and the modified request
* Once we locate the request we want to repeat, we can click `CTRL+R` in Burp to send it to the `Repeater` tab, and then we can either navigate to the `Repeater` tab or click `CTRL+SHIFT+R` to go to it directly
	* Once in `Repeater`, we can click on `Send` to send the request
* Tip: We can also right-click on the request and select `Change Request Method` to change the HTTP method between POST/GET without having to rewrite the entire request.
* *Try using request repeating to be able to quickly test commands. With that, try looking for the other flag*
	* Need to replace spaces with `+`
	* can't actually change the directory, but you can print out the contents of different directories with `ls /path/to/search -la`
	* to print from another directory, need to specify full path: not `ls /path | cat file` but `cat /path/file`

# Encoding/Decoding
* It is essential to ensure that our request data is URL-encoded and our request headers are correctly set. Otherwise, we may get a server error in the response
* Key characteristics we need to encode:
	* `spaces`: may indicate the end of request data if not encoded
	* `&`: otherwise interpreted as a parameter delimiter
	* `#`: otherwise interpreted as a fragment identifier
* To URL-encode text in Burp Repeater, we can select that text and right-click on it, then select (`Convert Selection>URL>URL encode key characters`)
* There are other types of URL-encoding, like `Full URL-Encoding` or `Unicode URL` encoding, which may also be helpful for requests with many special characters
* To access the full encoder in Burp, we can go to the `Decoder` tab
	* we can also use the `Burp Inspector` tool to perform encoding and decoding (among other things), which can be found in various places like `Burp Proxy` or `Burp Repeater`

# Proxying Tools
* An important aspect of using web proxies is enabling the interception of web requests made by command-line tools and thick client applications
* To route all web requests made by a specific tool through our web proxy tools, we have to set them up as the tool's proxy (i.e. `http://127.0.0.1:8080`)
* One very useful tool in Linux is **proxychains**, which routes all traffic coming from any command-line tool to any proxy we specify
	* To use `proxychains`, we first have to edit `/etc/proxychains.conf`, comment out the final line and add the following line at the end of it:
```shell-session
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```
* should also enable `Quiet Mode` to reduce noise by un-commenting `quiet_mode`
* Once that's done, we can prepend `proxychains` to any command, and the traffic of that command should be routed through `proxychains` (i.e., our web proxy)
```shell-session
proxychains curl http://SERVER_IP:PORT
```
Nmap:
```shell-session
nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC
```
Metasploit:
```shell-session
msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080

PROXIES => HTTP:127.0.0.1:8080


msf6 auxiliary(scanner/http/robots_txt) > set RHOST SERVER_IP

RHOST => SERVER_IP


msf6 auxiliary(scanner/http/robots_txt) > set RPORT PORT

RPORT => PORT


msf6 auxiliary(scanner/http/robots_txt) > run

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

# Burp Intruder
* Burp's web fuzzer is called `Burp Intruder`, and can be used to fuzz pages, directories, sub-domains, parameters, parameters values, and many other things
	* need the pro version to not be slow af
* can go to the Proxy History, locate our request, then right-click on the request and select `Send to Intruder`
	* On the first tab, `Target`, we see the details of the target we will be fuzzing, which is fed from the request we sent to `Intruder`
* The second tab, `Positions`, is where we place the payload position pointer, which is the point where words from our wordlist will be placed and iterated over
	* To check whether a web directory exists, our fuzzing should be in '`GET /DIRECTORY/`', such that existing pages would return `200 OK`, otherwise we'd get `404 NOT FOUND`
		* we will need to select `DIRECTORY` as the payload position, by either wrapping it with `§` or by selecting the word `DIRECTORY` and clicking on the the `Add §` button
	* The `Attack Type` defines how many payload pointers are used and determines which payload is assigned to which position
		* simplest is `sniper`
* 