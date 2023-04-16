---
title: Pivoting III
date: 2022-06-06 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Pivoting III

# Steps taken:
#### 1. Take the banner of the first target machine:

![](/assets/img/1575.png)

#### 2. Use "curl" to figure out the software being used on this server.

![](/assets/img/1576.png)

	- Notice that the program that sticks out is named "XODA". When I look it up it says that it is a "free web-based self hosted file manager". You can use this to find exploit about this specific software.

#### 3. Setup the database to be used for metasploit and then start it.

```bash
		# service postgresql start
		# msfdb init
		# msfconsole -q
		msf > db_status
```

#### 4. Now, check whether there is an exploit for this "XODA" software.

```bash
		msf > search XODA
```

![](/assets/img/1577.png)

	- There is one!

#### 5. Setting up the exploit and then executing it:

![](/assets/img/1578.png)

	- Backtrack and remove this meterpreter shell! Use a generic shell first and then upgrade it!

![](/assets/img/1579.png)

#### 6. Get the flag!

![](/assets/img/1580.png)

#### 7. Now, set the pivot!
- Here's the internal network:

![](/assets/img/1581.png)

![](/assets/img/1582.png)

#### 8. Portscan the hidden machine in the internal network now that the pivot has been set up!

![](/assets/img/1583.png)

	- Since 139 and 445 ports are open, we can assume that its using SAMBA share.


#### 9. Try if you can NMAP the machine inside the internal network to find more information.
- Since there are a lot of exploits for samba, try to find ones for unix and linux!
- I found that exploit/linux/samba/is_known_pipename seems to work!

![](/assets/img/1584.png)

#### 10. Get the flag!

![](/assets/img/1585.png)
