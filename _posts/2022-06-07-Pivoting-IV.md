---
title: Pivoting IV
date: 2022-06-06 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Pivoting IV

# Steps Taken
#### 1. Get the banner of the target machine.

![](/assets/img/1586.png)

	- Notice that the open ports are 21(vsftpd) and 22(SSH).

#### 2. Set up your database on the Metasploit.

		# service postgresql start
		# msfdb init
		# msfconsole -q
		msf > db_status

#### 3. Search for the exploit for 'vsftpd' and execute it.

![](/assets/img/1587.png)

	- Remember to upgrade the shell from generic to meterpreter one!

#### 4. Get the flag at the first compromised machine:

- Create a pivot on this compromised machine.

#### 5. Using proxychains from the attackers machine to the internal network:

**Note: DONT CLOSE THE METASPLOIT! Use another terminal for the proxychains command!**

**Note: The -sT flag is used because proxychains uses TCP to bounce through different servers so the attacker's original IP address will be hidden to the victim's machine/network.**

		# proxychains nmap -sT -Pn {machine inside the internal network}
		- Note that the machine is only available from the attacker if you have a pivot machine(compromised machine) in the first place otherwise the nmap won't work since the internal network is not available publicly.

![](/assets/img/1588.png)

	- Notice that there are 2 available ports: 80(http) and 3306(mysql).

#### 6. Now, since we can't use the "-sV" flag in this, is there any other way to know the software that is being used with the mysql and this server inside the internal network?

		- Yes! Through the use of curl. Even though we can't probe it with NMAP, we can just make a normal GET request through curl to figure out what the website will give us in html since we don't have an access to a web browser either.

#### 7. Using curl WITH proxychains on the internal server:

		# curl {internal_ip_address}
		- Note that by ONLY using 'curl' WITHOUT proxychains will never make you able to do a get request in the internal network!

![](/assets/img/1589.png)

	- Is there a 'key' name that you think may helpful in the received response from the server? What about 'url=/clipper/manager'? Search it up!

![](/assets/img/1590.png)

	- It seems like there is something about 'web clipper'. Since its a software, we can figure out whether there's an exploit for this or not.

- We can also search up 'clipper' in exploit-db to know what kind of exploits can we use on this software!

![](/assets/img/1591.png)

- Since there seems to be exploits on the software, we have to figure out the current version of the ClipperCMS on the machine!

		msf > search ClipperCMS

![](/assets/img/1592.png)

	- There are no results for ClipperCMS exploits here in Metasploit!
	- All you can do is do the exploit manually by using the exploit found from exploit-db.com and then execute to the target machine through proxychains!

#### 8. You can do trial and error from the exploits you found online but since we need time, just use the:

		ClipperCMS 1.3.0 - Code Execution
		- Also, since we're using proxychains with it, this type of exploit is "Remote" which makes more sense.
		- Read the first few lines of the exploit to figure out what the argument needed for it to work!

		# proxychains python {exploit}.py http://192.9.242.3/clipper/ {user} {pass}
		- In this case, the target machine uses admin:password as a default credential.

Here's the outcome:
![](/assets/img/1593.png)

	- Notice that in the 'url/clipper' you have to add a last '/' at the end so the exploit will work! (I think? Or you have to do it twice like last time?)

#### 9. You can now search up for the flag. Since I'm only a 'www-data' user , I can't traverse to other directories outside 'clipper'.

		www-data$ find / -name *flag*
		-> You'll get /tmp/flag.txt

![](/assets/img/1594.png)

# Key thing
- Use of proxychain is important in here since that is a way to hide your original attacker machine but also so you could connect to the internal network through the pivot setup via Metasploit from your attacker machine.