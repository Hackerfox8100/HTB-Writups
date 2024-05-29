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
* *