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