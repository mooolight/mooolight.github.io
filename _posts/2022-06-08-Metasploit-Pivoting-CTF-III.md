---
title: Metasploit Pivoting III
date: 2022-06-08 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Steps Taken:
1. Scan with NMAP the first target machine:

![](/assets/img/1786.png)

	- Port 21 = ftp is open!

2. Preparing Metasploit:

![](/assets/img/1787.png)

3. Searching for exploit and executing it:

![](/assets/img/1788.png)

	- This isn't vulnerable to this exploit!

4. Check out if anonymous users are allowed using Metasploit module:

		msf > search anonymous

![](/assets/img/1789.png)

![](/assets/img/1790.png)

		- Shows that anon login works but you can only read files on the FTP server!

5. Now, log into the FTP server:

		# ftp {ip}

![](/assets/img/1791.png)

6. Explore the File system of the FTP server + download any hint you could find:

![](/assets/img/1792.png)


	- It tells us to login using 'administrator' account.

7. Logging into 'administrator' account WITHOUT password:

![](/assets/img/1793.png)

		- The log in failed. Try to brute force the password for this user then!
		- Note that from previous experience, we can't use Hydra to brute force the password of an unknown user whether a user actually exists in the FTP server but in this case, we can actually bruteforce a password of a known user. This means that knowing usernames that exist in the servers helps us acquire their password indirectly.

8. Bruteforcing the password of the user 'administrator':

![](/assets/img/1794.png)

	- Trying PASS_FILE = /root/wordlists/100-common-passwords.txt : doesn't work!
	- Trying PASS_FILE = /usr/share/wordlists/metasploit/password.lst : doesn't work!
	- Trying PASS_FILE = /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt : 

9. Logging into the FTP webserver using the 'administrator' account:

![](/assets/img/1795.png)

	- Found the password!

![](/assets/img/1796.png)

	- Now, download the 'files' directory!

	# wget -r ftp://administrator:babygirl@192.27.155.3/
	-> This is wrong since we won't need to download this directory.

10. Putting a file named 'startsuper' at /files directory in the administrator account.

		# touch startsuper
		...(after logging in../in another terminal)
		
		ftp > put startsuper
		-> Note that this file is relative to the directory where you are when you log into the FTP server which in this case is /root.

		-> Recap: We did this because of a note:

![](/assets/img/1797.png)

11. Now, you have to wait for the "Supervisor" to run in the FTP server! Then, scan the target FTP machine with NMAP:

		# nmap -sS -sV {target}

![](/assets/img/1798.png)

	- Now, new port opened serving a new service which in this case is Supervisor process manager.

12. Using 'curl' to do GET request on the new service:

		# curl -v http://{target-ip}:9001

![](/assets/img/1799.png)

	- Notice that at the moment, there are no programs this service is managing.

13. Finding exploits this service is vulnerable in:

![](/assets/img/1800.png)

	- This exploit affects Supervisor(Medusa) with versions 3.0a1 to 3.3.2.


14. Using exploit/linux/http/supervisor_xmlrpc_exec:

![](/assets/img/1801.png)

	- The exploit works!

15. Checking the internal subnet this compromised machine might be connected to as well:

![](/assets/img/1802.png)

16. Creating a pivot using this compromised machine:

		msf > search autoroute
		-> Setup autoroute
		...

![](/assets/img/1803.png)

17. Portscan the internal subnet using portscan/tcp Metasploit module:

		msf > search portscan/tcp
		...
		- Set it up!

![](/assets/img/1804.png)

18. Do an NMAP scan on this internal network machine(2nd target).

		- Use 'portfwd' in Meterpreter to do port forwarding to be able to use nmap locally so you won't have to use proxychains.

		meterpreter > portfwd add -l 1234 -p 21 -r 192.36.1.3

![](/assets/img/1805.png)

![](/assets/img/1806.png)

	# nmap -sS -sV -p1234 localhost
		- Note this is done on ANOTHER TERMINAL!
		
![](/assets/img/1807.png)


19. Check an exploit for this ProFTPD version.

		msf > search proftpd
		...

![](/assets/img/1808.png)

![](/assets/img/1809.png)

20. Executing the exploit:
![](/assets/img/1810.png)

21. Find the flag and print it!

		# find / -iname *flag*

![](/assets/img/1811.png)

![](/assets/img/1812.png)