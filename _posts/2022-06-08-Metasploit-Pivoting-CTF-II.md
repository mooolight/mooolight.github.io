---
title: Metasploit Pivoting II
date: 2022-06-08 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Steps Taken:
1. NMAP-ing the nearby network to figure out what services the first target machine is using:

```bash
nmap -sV --script=banner 192.39.205.3
```

![](/assets/img/1765.png)

2. Scan users using 'finger' service:

		- Using the default wordlist:

![](/assets/img/1766.png)

	- Using the hinted wordlist:

![](/assets/img/1767.png)

3. Using 'finger' service to acquire information about this user:
```bash
finger access@{ip}
```

![](/assets/img/1768.png)

4. Trying to do a GET request from this server:

![](/assets/img/1769.png)

	- How can I make a request with SSL enabled then?
	- Add 's' to make it 'https':

![](/assets/img/1770.png)

	- Still doesn't work due to the EE certificate key being too weak.

5. Using the **exploit/unix/webapp/webmin_show_cgi_exec** :

![](/assets/img/1771.png)

	- Notice that the variable we really have to get in here is the "PASSWORD" one.
	- Since we don't have it we have to crack it with the username access.

6. Trying to get /etc/passwd using exploit : "auxiliary/admin/webmin/file_disclosure"

![](/assets/img/1773.png)

		- Notice that it is accessible but you would need to be authenticated which is ironic since we're trying to find information about the passwords of the users of this service.
		- This is on the directory /unauthenticated as the starting point.
		- This output shows us that there is an HTTPS form and you have to log in first!
		- An important URI in here is:/session_login.cgi that uses POST method to log into the form.
		- The variable used for the username box above is 'user'.
		- The variable used for the password box above is 'pass'.

7. Cracking the password for user 'access' with Hydra:

```bash
hydra {target} -l access -P {wordlist} https-form-post "/session_login.cgi:user=^USER^&pass=^PASS^:{error_message}" -s 10000 -f -V
```
		-> Note that the error message will show to you anyway if you try to use Hydra without it the first time.
		-> You can show the login as failed on the third parameter of https-form-post using ":F= or :S=" but which one to use in this?
		-> "-s" flag specifies the port used on the web server.
		-> in this case, wordlist used is: /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

![](/assets/img/1774.png)

8. Executing the exploit:

![](/assets/img/1775.png)

	- the exploit works but it doesn't create a session for some reason.
	- After trying different payloads, it seems to work with cmd/unix/reverse_python:

![](/assets/img/1776.png)

9. Upgrade the shell into Meterpreter shell:
```
		msf > sessions -u 1
```

![](/assets/img/1777.png)

	- Now, you can get information about the internal subnet of the first target machine.

![](/assets/img/1778.png)

	- Internal subnet = 192.121.3.0/24


10. Creating pivot on this compromised machine:

![](/assets/img/1779.png)

	- Add socks4a proxy as well to be able to nmap the internal machine from the attacker's machine.

![](/assets/img/1780.png)

**Note: Notice that when 'portfwd' is used, you don't have to use proxychains.!** Look at the walkthrough for the alternative using 'portfwd' without the use of proxychains. This shows that when you can't use Metasploit at all, you can use proxychains to do the pivoting.

11. Scanning the target machine-internal from the attacker's machine using NMAP+Proxychains:

![](/assets/img/1781.png)

	- Since the service and its version is showing to us, we can assume this isn't behind a firewall and there would be no need to use portfwd from Meterpreter shell.

12. Find whether there are exploits in this service and version to which this is vulnerable to:
```bash
searchsploit proftpd 1.3.3c
```

![](/assets/img/1782.png)

	- Use this!

![](/assets/img/1783.png)

![](/assets/img/1784.png)

![](/assets/img/1785.png)