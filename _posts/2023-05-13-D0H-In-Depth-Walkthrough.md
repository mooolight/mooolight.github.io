---
title: D0H! Walkthrough
date: 2023-05-13 12:00:00 -500
categories: [Pentesting, Walkthroughs]
tags: [ReTrain]
---

### Pentest MindMap


![](/assets/img/Pasted image 20230513165648.png)![](/assets/img/Pasted image 20230513165653.png)


-------------

## **Port and Service Enumeration**

![](/assets/img/Pasted image 20230513161344.png)

• Ports Opened:

	◇ 22/ssh
	◇ 80/http
	◇ 111/rpc
	◇ 139/smb
	◇ 445/smb
	◇ 49455/RPC

----------

## **Services Enumeration**

### **Port 80: Visiting the Website**

![](/assets/img/Pasted image 20230513164739.png)

- Scraping all the words found in the website...

◇ Using **cewl**:
	▪ cewl `[http://10.201.10.240](http://10.201.10.240)`

# **Website Directory Enumeration**

-   Using **dirb** :
		▪ With normal wordlist:

![](/assets/img/Pasted image 20230513164818.png)

◇ Using dirbuster:

![](/assets/img/Pasted image 20230513164836.png)

	◇ I highlighted directories that seems to be interesting.

◇ Using BurpSuite's Sitemap:

![](/assets/img/Pasted image 20230513164851.png)



• 10.201.10.240/admin page:

![](/assets/img/Pasted image 20230513164913.png)
 
◇ 10.201.10.240/images:

![](/assets/img/Pasted image 20230513164933.png)

◇ What's inside?

![](/assets/img/Pasted image 20230513164949.png)

- Found two users:
	    → root
	    → T0ny
- Found two emails: 
	→ `root@localhost`
    → `Tony@localhost`

- These emails could be used by attackers to phish these users. Removing these kinds of information that is publicly disclosed reduces attack surface.
- No password found at the moment. You can always use hydra to bruteforce some passwords though.


--------------------

### **Bruteforcing a password for either user 'root' or 'T0ny'**

• Checking what the output would be when passed a wrong credential: 

![](/assets/img/Pasted image 20230513164655.png)

	◇ It outputs the string "Login Failed".

• Bruteforcing it using Burpsuite

	◇ Position setup:

![](/assets/img/Pasted image 20230513164152.png)

- Chose two parameters : '`username`' and '`pass`'
- Attack Type: **Cluster Bomb**. I chose this so each entry in the username parameter will try each password in the password list.

◇ How do we know if we find a right password?
▪ If there is atleast one output that didn't give us the "**`Login Failed`**" string.

◇ Result:

![](/assets/img/Pasted image 20230513164207.png)

	◇ Didn't find atleast one password with the given password list from the website keywords.

• Trying again but using the '`john.lst`' wordlist:

![](/assets/img/Pasted image 20230513164222.png)

- Found one credential for the login page: **`T0ny:test`**

◇ Trying it on the login page:

![](/assets/img/Pasted image 20230513164255.png)

-   ◇ Seems to be a base64 encoding! Let's decode it!

![](/assets/img/Pasted image 20230513164311.png)

◇ Equivalent to some number: `1882B91B7F49D479CF1EC2F1ECEE30D0E5392E963A2109015B7149BF712AD1B6`

### **Logging into the smbclient for user T0ny using the decoded string: (maybe a password?)

• **Nope.** **Not for smbclient nor ssh.**
• **Atleast not at face value!**

![](/assets/img/Pasted image 20230513164324.png)

◇ **Password cracked:**

![](/assets/img/Pasted image 20230513164333.png)

• Bruteforcing it using `Hydra`:

<u>Command</u>:

```bash
hydra -L ~/Exam/users -P /usr/share/wordlists/rockyou.txt 10.201.10.240 http-post-form "/admin/index.php:username=^USER^&password=^PASS^:Login Failed" -vV -f
```

![](/assets/img/Pasted image 20230513164050.png)

Credential Found: `T0ny:babygirl`

	◇ This is wrong!

![](/assets/img/Pasted image 20230513164413.png)

	◇ For some reason, it shows multiple password for these same users as correct but when you try to login with these in the webpage, it won't work.
	◇ This is most likely a defense mechanism against bruteforce attacks but specifically for Hydra?

### **Findings:**
- What worked in this phase is the base64 encoded +sha256 encrypted password for SMB user `T0ny`.

----------

# RPC Enumeration

### **Port 111: Enumerating RPCBind**

![](/assets/img/Pasted image 20230513165007.png)

**Breakdown of the output for the rpcinfo tool:**

`1.`  ‘**program**’ : This column displays the RPC program number. Each RPC service has a unique program number assigned to it. In this output, we can see two program numbers: 100000 for the portmapper service and 100024 for the status service. The "program" column shows the RPC program number, which is a unique identifier assigned to each RPC service. RPC services are designed to allow remote clients to execute procedures on a server. Each service that offers these remote procedures is identified by a program number. This number is used to differentiate between the various RPC services running on a server. Program numbers are typically assigned by the developers of the RPC services and should be unique to avoid conflicts with other services.

`2.`  ‘**vers**’: This column shows the version number of the RPC service. An RPC service can have multiple versions running concurrently to support different clients. Here, the portmapper service has versions 2, 3, and 4, while the status service has version 1. . Different versions may have different features, bug fixes, or performance improvements, and maintaining backward compatibility can be important for clients that have not yet updated to the latest version. The version number helps differentiate between these variations and allows clients to choose the appropriate version when making RPC calls.

`3.`  ‘**proto**’: This column indicates the protocol used by the RPC service, either TCP or UDP. In the example, the portmapper service is running on both TCP and UDP, while the status service is also running on both TCP and UDP.

`4.`  ‘**port**’: This column displays the port number on which the RPC service is running. The portmapper service is running on port 111 for both TCP and UDP protocols. The status service is running on port 32768 for UDP and port 32769 for TCP.

`5.`  ‘**service**’: This column shows the human-readable name of the RPC service. In this output, we see the portmapper service and the status service. This name provides a more user-friendly way to identify the service, as opposed to the program number. The service name typically describes the purpose or functionality of the RPC service. For example, "portmapper" is an RPC service that manages the port numbers used by other RPC services, while "status" might be a service that provides information about the status of various components on the server.

The output provides an overview of the RPC services running on the target server, including their program numbers, version numbers, protocols, and port numbers. This information can be useful for understanding the available services on a server and potentially identifying vulnerabilities or misconfigurations.

### **Understanding how RPC works:**

### Q: What exactly does ‘status’ service do?

Ans: it is a simple RPC service that provides information about the server's status and the availability of other RPC services. It is typically used for monitoring and diagnostic purposes. By querying the status service, you can obtain information about the server's status, such as the current state of various components or services, and potentially identify any issues or misconfigurations.

<u>Step by Step process of the protocol</u>: (Presents to how the rpcclient tool works below)
    
    1. When an RPC client wants to communicate with an RPC service, it first contacts the portmapper on the server to request the port number associated with the desired service.
    
	2.  The portmapper looks up the program number provided by the client, determines the correct port number for the requested service, and returns that information to the client.

	3.  The client can then establish a direct connection with the RPC service using the provided port number.


### Q: What exactly does ‘portmapper’ do?

Ans: The main function of the portmapper is to map RPC program numbers to the corresponding network port numbers on which these services are running. Basically, this is the reason why we can enumerate the target server using rpcclient (below).

<u>Example</u>: When I use rpcclient to query for shares information, what role does portmapper play?
- Here's an outline of the role portmapper plays in the process:

`1.` The rpcclient starts by contacting the portmapper service on the target server. It does so by sending a request to the well-known port for portmapper (usually port 111) and providing the program number for the RPC service it wants to communicate with (in this case, the SMB service).
`2.`  The portmapper checks its registry to find the corresponding port number and protocol (TCP or UDP) for the requested SMB service, and then returns that information to the rpcclient.
`3.`  With the port number and protocol information in hand, the rpcclient establishes a direct connection to the SMB service on the target server using the provided details.
`4.`  Once connected to the SMB service, the rpcclient can send queries to retrieve shares information, such as the list of shared folders, printers, or other resources available on the server.


### Findings:

-   Portmapper service (port 111) is essentially our “guy who knows a guy
-   in this situation. The main reason we are able to enumerate the webserver FROM THE OUTSIDE is because this port is open and available for anyone to use.
- Had it been closed, there would be no way for attackers to figure out that the user ‘T0ny’ can login into the ‘V’ share using rpcclient. (but of course, it was available from the output of NMAP scan)

**Reference for RCP Enumeration:** **[rpcclient enumeration - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration)**

• What exactly is RPC?

	◇ First off, RPC means Remote Procedure Call which allows a computer to execute a command on another computer remotely.

• What tools can we use to further enumerate the rpc   service the target server provides?

    ◇ Well, we can use:
	▪ rpcclient - not available at the moment as we would need both username AND password for this. We got the usernames "root" and "T0ny" but I don't have password at this moment.

- After cracking the string of ‘T0ny’ from the encrypted and encoded password:

• Logging in with rpcclient given the credentials `T0ny:test!`

◇ **Checking server info**:

![](/assets/img/Pasted image 20230513165029.png)

• **Information about user** **'T0ny'**:

![](/assets/img/Pasted image 20230513165038.png)

◇ **Checking for username '****root****'**:

![](/assets/img/Pasted image 20230513165049.png)

◇ **Checking the group user '****T0ny****' is a member of**:

![](/assets/img/Pasted image 20230513165130.png)

◇ **Enumerate the domains**:

![](/assets/img/Pasted image 20230513165138.png)

◇ **Enumerating Domain Info**:

![](/assets/img/Pasted image 20230513165150.png)

◇ **Get all the shares in the system**:

![](/assets/img/Pasted image 20230513165206.png)

- Go next to if you need: `[SSH Access from RPC Enum](Initial_Access--SSH_Access_from_RPC_Enum_9.html)`

• Enumerating information about each shares in the system:

◇ V:

![](/assets/img/Pasted image 20230513165243.png)

◇ D0H:

![](/assets/img/Pasted image 20230513165251.png)

◇ Anon:

![](/assets/img/Pasted image 20230513165301.png)

◇ **print$:**

![](/assets/img/Pasted image 20230513165317.png)

◇ **IPC$:**

![](/assets/img/Pasted image 20230513165334.png)

◇ **T0ny:**

![](/assets/img/Pasted image 20230513165346.png)

• Enumerating SIDs:

![](/assets/img/Pasted image 20230513165400.png)

	▪ S-1-5-32-550
	▪ S-1-5-32-548
	▪ S-1-5-32-551
	▪ S-1-5-32-549
	▪ S-1-5-32-544
	▪ S-1-1-0

![](/assets/img/Pasted image 20230513165407.png)

▪ **These are the groups mapped to these SIDs.**


----------

# SMB Share Enumeration

## **Enumerating the SMB share:**

### Using NMAP:

<u>Command</u>:

```bash
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse   -p445 10.201.10.240
```

### Using smbclient:

<u>Command</u>:

```bash
smbclient -L //10.201.10.240/
```

Output:

![](/assets/img/Pasted image 20230513165429.png)

• **SMB Shares Information:**

![](/assets/img/Pasted image 20230513165439.png)

- **As user '`anonymous`', we only have read access to \\DOH and \\IPC share.

◇ **SMB Domains**:

![](/assets/img/Pasted image 20230513165459.png)

◇ **SMB User, Security and OS:**

![](/assets/img/Pasted image 20230513165508.png)

◇ **Machine Enumeration:**

![](/assets/img/Pasted image 20230513165519.png)

## Accessing \\D0H and \\IPC as anonymous:

• **Accessing D0H:**

![](/assets/img/Pasted image 20230513165536.png)

▪ **It is empty!**

◇ **Accessing IPC:**

![](/assets/img/Pasted image 20230513165551.png)

- **There is nothing in this share.**
- **Also note that C:\tmp is where this share is mapped to.**
- **Let's try to write something!**
→ **Can't for some reason even though it is both** **readable** **and** **writable** **to anonymous user.**


### **Logging into the smbclient for user** T0ny using the decoded string: (maybe a password?)

• **Nope. Not for smbclient nor ssh.**
• **Atleast not at face value!**

![](/assets/img/Pasted image 20230513165603.png)

◇ **Password cracked:**

![](/assets/img/Pasted image 20230513165615.png)

◇ **Trying it on the smbclient:**

<u>Command</u>:

```bash
smbclient  //10.201.10.240/D0H -U T0ny
```

![](/assets/img/Pasted image 20230513165624.png)


---------

## SSH Access from info gathered from RPC Enumeration

**Get all the shares in the system**:

![](/assets/img/Pasted image 20230513165807.png)

• Let's try to log into '**V**' share:

![](/assets/img/Pasted image 20230513165826.png)

◇ Let's download and checkout what's in the notes. It seems that we found 'V's private key?

	▪ Content of 'notes.txt':

![](/assets/img/Pasted image 20230513165841.png)

→ `T35t@123` -> is probably the SSH username?

→ Nope, it was T0ny's SSH key and not V's.

→ Also, in case the private key doesn't work because it is deprecated `([ssh - Sign_and_send_pubkey: no mutual signature supported - Stack Overflow](https://stackoverflow.com/questions/73795935/sign-and-send-pubkey-no-mutual-signature-supported)),`

- user '**V**' provided T0ny's SSH password=> `T35t@123`


▪ Logging into user T0ny's SSH session:

![](/assets/img/Pasted image 20230513165920.png)



-------------


## **Exploring user T0ny's directory using the SSH access:**

![](/assets/img/Pasted image 20230513170018.png)

Found a password: `vagrant@123`

◇ **Checking the users in the system:**

![](/assets/img/Pasted image 20230513170037.png)

◇ **Users with shell we can utilize:**

	▪ **root**
	▪ **vagrant**
	▪ **T0ny**


◇ **Using** **linpeas.sh** **to get PrivEsc surfaces:**
◇ **Use a download server from the Kali machine to allow file transfer:**

![](/assets/img/Pasted image 20230513170134.png)

-----------

## **Interesting PrivEsc Surfaces:**

• **Useful Files inside others home dir:**

![](/assets/img/Pasted image 20230513170153.png)


◇ **Unexpected file in root:**

![](/assets/img/Pasted image 20230513170203.png)


◇ **Directories/files writable to me OR everyone:**

![](/assets/img/Pasted image 20230513170212.png)


◇ **Capabilities:**

![](/assets/img/Pasted image 20230513170222.png)


• **SU/GID bit enabled binaries:**

![](/assets/img/Pasted image 20230513170242.png)


◇ **Samba files configuration:**

![](/assets/img/Pasted image 20230513170254.png)


◇ **Cached hashes:**

![](/assets/img/Pasted image 20230513170308.png)


◇ **SSH keys found (spoiler alert: it is deprecated)**

![](/assets/img/Pasted image 20230513170316.png)


◇ **Compilers in the system:**

![](/assets/img/Pasted image 20230513170328.png)


◇ **Useful software:**

![](/assets/img/Pasted image 20230513170339.png)


◇ **Protection Information:**

![](/assets/img/Pasted image 20230513170352.png)


◇ **Sudo version:**

![](/assets/img/Pasted image 20230513170405.png)


◇ **OS Version:**

![](/assets/img/Pasted image 20230513170417.png)

◇ **Tried `PwnKit` exploit from user `T0ny` but did** **not** **work due to** **`pkexec`** **having the right version and is patched.**

-------------

### **Finding Privilege Escalation Attack Surfaces for user "Vagrant":**

• **Utilizing credential found for user `Vagrant:vagrant@123`**

![](/assets/img/Pasted image 20230513170528.png)

◇ Checking binaries available for this user as a sudoer.

◇ Finding PrivEsc surfaces for user '`Vagrant`' using **linpeas.sh**:

◇ Doesn't load and always freeze!

◇ Manually finding PrivEsc surfaces with user '`Vagrant`':


<u>Command:</u>

```bash
/usr/bin/getcap -r /usr/bin
```

◇ **Getcap** **is** **not** **available for this user.**
◇ **Finding sensitive files that might contain a password:**


<u>Command:</u>

```bash
locate password | more
```


◇ **Applying privesc vector using** **GTFObins with 'mount' binary****:**

Command:

```bash
sudo mount -o bind <source> <target>
sudo mount -o bind /bin/sh /bin/mount
sudo mount
```

-   Breakdown:

		- “-o bind" : this flag overrides mount option. In this case,it “bind mounts” the file /bin/sh to /bin/mount.
    
-   Everytime we call /bin/mount in the system, /bin/sh will be called instead.

-   Essentially, we will call “**sudo mount**”.

-   In this case, the user ‘`vagrant`’ is a sudoer for the binary **/bin/mount** WITHOUT password prompt under the ‘root’ user which is why we are able to escalate privilege.

-   This essentially makes the source file available at the target location as if it were a separate copy, even though they share the same underlying inode and data.

![](/assets/img/Pasted image 20230513170854.png)

![](/assets/img/Pasted image 20230513170900.png)


--------------

# DirtyCOW Exploit PrivEsc Vector

### Applying dirtyCOW exploit as well for PrivEsc:

Reference: `https://www.exploit-db.com/exploits/40616`

◇ **Compilation:**

![](/assets/img/Pasted image 20230513171022.png)


◇ **Execution:**

![](/assets/img/Pasted image 20230513171033.png)

◇ **I waited a bit and then pressed CTRL+C as it seems to be waiting for something.**

◇ **This exploit makes** **/etc/passwd** **writable and modifies it.**

◇ **The password I entered to replace user '****root****'s password is "****password****".**

◇ **The credential is** **firefart:password****.


◇ **Checking the `****/etc/passwd****` after:**

![](/assets/img/Pasted image 20230513171059.png)



◇ **User '`root`' got replaced with the user '`firefart`'.

◇ **Logging in with user '`firefart`':

![](/assets/img/Pasted image 20230513171149.png)

![](/assets/img/Pasted image 20230513171154.png)


-   **The only things that are** **NOT** **different are:**

		▪ uid
		▪ gid
		▪ groups

◇ **This exploit basically just replaces the username and password of the user '`root`' to something else.**


◇ **Reverting `/etc/passwd` back to original to try other LPE exploits:**

![](/assets/img/Pasted image 20230513171225.png)


### Why does Dirty COW(`C`opy-`O`n-`W`rite) exploit works?

<u>What is it</u>:

-   Vulnerability in the Linux Kernel

-   Allows processes to write to "read-only" files. (e.g., `/etc/passwd` like the one from the exploit used in the Pentest.)

-   Uses **race condition**. The DirtyCOW vulnerability is a **race condition** that occurs when two threads are concurrently operating on a COW memory page.


- Which objects in the system specifically achieves the Race Condition?

- There are "Kernel functions" that handles "Copy-On-Write" features of memory mappings.


- What is "**Copy-On-Write**"?

- This is a kernel feature that does not allocate several times the memory for data shared by two or more processes, until a process touches it (writes into it); in this case, memory is allocated for its private copy.

- Okay, so assuming two processes are sharing memory(as a resource). If one process wants to modify that shared memory, this process can't just modify it because when it gets used by the other process, it had changed. What the kernel does instead is it create a private copy for that process of the shared memory(resource) AND THEN modify that to fit it into that process' operations.



### **Steps for Dirty COW exploit:**

-   Reference for the Introduction: `[Dirty Cow (toronto.edu)]([https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/index.html#:~:text=Dirty%20COW%20was%20a%20vulnerability,COW](https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/index.html#:~:text=Dirty%20COW%20was%20a%20vulnerability,COW))%20feature%20of%20memory%20mappings.)`

`1.` Create a private copy (mapping) of a read-only file.

`2.` Modify - specifically, we use `write()` to the private copy of that resource. This is where the COW feature takes place.

<u>Breakdown of the write() using two non-atomic functions</u>:

- Locate physical address (in memory)

- Write to physical address

`3.` Get right in the middle(`what???`) via another thread and tell the kernel to ***throw*** away our private copy using `madvise()`.


- What happens when the kernel threw away our private copy of the supposedly "read-only" shared resource?

- The kernel "accidentally" writes to the original read-only file.


- How is this possible? How does the "accident" happens?

- Note that "Getting right in the middle using another thread" is an important step in here since Race Condition happens when two threads are using the same shared resource.


Small Table of what happens:

![](/assets/img/Pasted image 20230513171439.png)


## **Visual Explanation:**

-   Reference for the diagrams: `[Dirty Cow Demo (toronto.edu)]([https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/demo.html](https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/demo.html))`


### **`a.` System Environment Setup**

![](/assets/img/Pasted image 20230513171457.png)

	a.1) A process for a program named "dirty_cow.c" is our current process.

	a.2) We don't have direct access to physical memory since our current process has normal user privileges.

	a.3) We can only write to the physical memory by going through the kernel and reference the virtual address space mapped onto its assigned physical address space.

	a.4) "/etc/passwd" is in the physical memory which is a file we can read but CANNOT write to.

	a.5) "Physical Memory" means ALL physical bits stored on your computer (not just RAM).


### **`b.` Creating a private copy of the shared resource found in the physical memory that isn't writable to us:**

![](/assets/img/Pasted image 20230513171524.png)


	b.1) Ask the kernel using "mmap()" to create a private mapping of the "/etc/passwd" on our virtual memory. With this private copy, we can modify it using our current process since it resides on our virtual address space.
    
	b.2) Any changes that happens on this file will not trickle down to the original file it was copied from.


### **`c.` Kernel acting on the `dirty_cow` process' request: (creating a private copy of the shared resource)**

	c.1) Before the kernel can assign a private copy for our current process, it will assign a designated memory for this copy of "/etc/passwd" in the physical memory to store our private mapping.

<u>What should happen if there is NO Copy-On-Write</u>:

![](/assets/img/Pasted image 20230513171552.png)


	c.2) HOWEVER, (c.1) won't happen UNTIL we try to write on this supposed private copy. Basically, the allocated memory is NOT yet in the physical memory NOR it is mapped yet in the process' virtual address space.

<u>Result because there is Copy-On-Write</u>:

![](/assets/img/Pasted image 20230513171628.png)



	c.3) The kernel allocates memory in our virtual address space for this private copy of the "/etc/passwd" so we have a way to reference this "copy".

**At this point, `**_**mmap**_**` has done its job**.

![](/assets/img/Pasted image 20230513171642.png)



### **`d.` Write to the private mapping of the resource**

![](/assets/img/Pasted image 20230513171653.png)


	d.1) Use the `write()` to write whatever to the private copy of "/etc/passwd". (Say, concatenate at the end the string "moo"). Basically, We ask the kernel to use `write()` the string `moo` to our private mapping..


![](/assets/img/Pasted image 20230513171710.png)


	d.2) We do write directly to the virtual address space that `**mmap()**`(or specifically, kernel) gave us.
	
	d.3) We write to a unique Linux file called: "**/proc/self/mem**".

- What is "**/proc/self/mem**"?

- Ans: A representation of our current process' virtual memory.

- It is a part of filesystem in Linux called "procfs". Basically, "procfs" is a filesystem information about processes in the Linux system.

- "**/proc/self/mem**" is a REQUIREMENT for the DirtyCOW vulnerability since it lives inside the Linux kernel's implementation of "process-to-process" virtual memory access. (so Inter-process communication? Which other process does our "dirty_cow-process" communicate to then?)

**Note: You could, alternatively, use other methods that allow `process-to-process` virtual memory access (e.g., `ptrace`) for Dirty COW.**


### **`e.` Kernel figuring out where to write**

**Note: At this point, we have the private mapping(copy) of the "`/etc/passwd`" BUT it doesn't have any kind of MAPPING to the physical address. This begs the question, where does the kernel map this allocated virtual memory to?**

![](/assets/img/Pasted image 20230513171742.png)


	e.1) The kernel "tries to remember" which physical address is this virtual address space is mapped to but then it remembered, it is using the "Copy-On-Write" feature which is why this virtual address space doesn't have a physical address mapped to it yet since the current process hasn't TRIED to modify the private copy that references to the virtual address space.


![](/assets/img/Pasted image 20230513171757.png)


	e.2) The kernel remembers now that this private copy of the shared resource ("/etc/passwd" in this case) is a COPY so it allocates ANOTHER physical memory that allows the allocated virtual memory of dirty_cow process for the copy of "/etc/passwd" to be mapped into this newly allocated physical memory:


![](/assets/img/Pasted image 20230513171814.png)


**What do you notice at this point?**

- Note that the string "`moo`" isn't written yet into this newly allocated physical memory in which the virtual space from the dirty_cow's process is mapped onto but **ONLY FOUND** the physical memory. 

- This is the part attackers can exploit and swoop in.


- Attackers can get right in the middle of the steps which is:

`1.` Kernel finding the correct physical address to write the string "moo" onto

`2.` Kernel actually writing (using "_**write()**_") the string "moo" onto the said physical address

**Note: `Atomic operations` are program operations that run `completely independent` of any other processes.**

- Since these TWO operations are **NON-ATOMIC**, this makes it possible for OTHER processes/threads in the system to `swoop in` and modify the environment and/or its objects the current thread is working on.

- In this context, another thread could swoop in and trick the kernel into writing onto the physical address space of the ACTUAL shared resource(in our case is , "`/etc/passwd`")

- Question: How is it possible for another thread to trick the kernel into writing to the wrong physical address?

- How is the "locating" of the physical address by the kernel actually happens?

- If the kernel found the physical address, can a thread inject a malicious address into where the kernel stored that physical address which is for the actual shared resource? (`/etc/passwd`)


# This is the point where another PROCESS/THREAD swoops in the operation...

    - Technically, it is the thread of ANOTHER PROCESS that swoops in to tell the kernel to keep using `madvise()`.


### **`f.` Telling the kernel we don't need the physical memory space allocated to reference the copy of `/etc/passwd` in the physical address ***USING ANOTHER THREAD***:

![](/assets/img/Pasted image 20230513172301.png)


- Note that it is NOT dirty_cow's process' main thread that tells the kernel that it doesn't need the physical memory allocated for the private mapping of "/etc/passwd" but ANOTHER thread created within that process.

- In total, there are TWO threads in "dirty_cow's process":

- 1st Thread(original process): For following the protocol in which the kernel use when it is asked by normal users to copy "read-only" file so users can have their own copy.

- 2nd Thread(new process): Another thread used to trick the kernel into thinking that it doesn't need the physical memory allocated for the private mapping which in turn forces the kernel to map the virtual address space for the private mapping to the physical memory of the actual shared resource("/etc/passwd").


		f.1) We use "mdavise()" to advise the kernel that we don't need (MAVD_DONTNEED) our private mapping anymore. The Kernel then forget the private mapping.


![](/assets/img/Pasted image 20230513172324.png)


- What happens when the kernel forgets the **private mapping** in the physical address?

**Ans**: It will find another physical address it could map the virtual address space for the supposed "private mapping" of shared resource("`/etc/passwd`") which in this case is the ACTUAL physical address for the shared resource (`actual /etc/passwd`) and not a private mapping.


![](/assets/img/Pasted image 20230513172355.png)


**Note: the execution of `madvise()` is REPEATED until the other thread is able to modify(`win the race`) the original shared resource(`/etc/passwd`)**

- **Question**: Why does the kernel does this? Why doesn't it just stop after the fact that physical memory referenced by the virtual address space for the copy has been forgotten?

<u>Breakdown of DirtyCOW exploit with ChatGPT:</u>
```
    - Q: What I don't understand is that, why does the kernel just stop AFTER another thread tells it to execute madvise() to forget the physical memory allocate for the private mapping instead of using the memory address of the physical memory address of the original shared file?
    

-   Ans:
    
    The kernel doesn't stop after the madvise() system call because the madvise() call is intended to provide advice or suggestions to the kernel about how to optimize memory usage. The kernel is not obligated to follow the advice, and the operation is designed to be asynchronous. This means that the kernel can continue executing other operations while processing madvise() requests.
    
    - Q: You said that "the kernel can continue executing other operations while processing madvise() requests.". Why does it specifically choose the physical address of the original shared file (in this case say, /etc/passwd) instead of another physical address to write on? I don't understand.
    
-   Ans:
    The key to understanding why the write operation ends up modifying the original shared file lies in the behavior of the Copy-On-Write (COW) mechanism and the race condition created by the exploit.
    
    When the attacker attempts to write to the read-only memory mapping (which is mapped to the original shared file, e.g., /etc/passwd), the kernel's COW mechanism is triggered. Under normal circumstances, the kernel would create a private copy of the memory page, and the write operation would be performed on that private copy.
    
    However, the exploit creates a race condition by repeatedly calling madvise() with the MADV_DONTNEED flag on the read-only memory mapping. This tells the kernel to discard the physical memory pages associated with the private mapping, forcing it to reload the pages from the original shared file the next time the memory is accessed.
```

- Main Condition that makes writing to the "`read-only`" file possible: ***If the timing of the `madvise()` call and the write operation coincide in such a way that the `madvise()` system call is processed just after the COW mechanism starts(meaning, the kernel tries to find the physical address to write the string onto) but before the kernel can copy the data to the new private page, the write operation ends up modifying the original shared file's memory page instead of the private copy.***

- Recap for the COW Mechanism**:

    `1.` Kernel finding the correct physical address to write the string "moo" onto
    `2.` If the kernel doesn't find the correct physical address, it will allocate one (Kernel copies the string to a new private page). Otherwise, move along.
    `3.` Kernel actually writing (using "write()") the string "moo" onto the said physical address

- The exploit is not specifically choosing the physical address of the original shared file. Rather, it is taking advantage of the race condition and the kernel's handling of the COW mechanism to bypass the expected behavior and achieve unauthorized write access to the original shared file.
    
- In summary, the exploit abuses the lack of proper synchronization between the Copy-On-Write mechanism and the madvise() system call to cause the kernel to write to the memory page of the original shared file instead of the intended private copy.

```
    - Q: Why does the kernel "forced to reload the pages from the original shared file the next time the memory is accessed." when madvise() is repeatedly called? I thought what happens for madvise(MADV_DONTNEED) is just it forgets the physical address of the private mapping but not re-map it to the physical address of the actual physical memory space allocated for the /etc/passwd?
    
-   Ans:
    
    You're correct that when madvise() is called with the MADV_DONTNEED flag, the kernel is advised to discard the contents of the specified memory range. However, it doesn't necessarily forget the physical address of the private mapping or remap it to a different physical address.
    
    Instead, when the memory pages are discarded due to MADV_DONTNEED, the kernel marks these pages as "not present" in the page table entry for the specified memory range. This means that when the memory is accessed again, a page fault will be triggered, and the kernel will need to load the contents of the memory page again.
    
    In the case of a read-only memory mapping that is backed by a file (such as /etc/passwd), the kernel will reload the contents of the memory page from the original file when a page fault is triggered due to a subsequent access. This is the intended behavior because the madvise() system call with MADV_DONTNEED is supposed to be a hint for the kernel to optimize memory usage by discarding unused or unimportant pages, and then reloading them from their original sources when necessary.
    
    The DirtyCOW exploit takes advantage of this behavior by creating a race condition between the madvise() system call and the write operation on the read-only memory mapping. If the timing is just right, the write operation can end up modifying the original file's memory page before the kernel has a chance to create a private copy for the Copy-On-Write (COW) operation.
    
    So, to clarify, the kernel doesn't remap the private mapping to the physical address of the actual physical memory space allocated for the /etc/passwd file. Instead, the exploit abuses the race condition between the madvise() call and the write operation to modify the original file's memory page directly, bypassing the intended COW mechanism.


    - Q: When you said " If the timing is just right, the write operation can end up modifying the original file's memory page before the kernel has a chance to create a private copy for the Copy-On-Write (COW) operation.", what are the SPECIFIC conditions for this?
    
	- Ans: The specific conditions for the DirtyCOW exploit to work revolve around creating a race condition between the madvise() call and the write operation on the read-only memory mapping. Here's a more detailed breakdown of the required conditions for the exploit to succeed:
    
1. The attacker maps a read-only file (e.g., /etc/passwd) into memory using mmap() with the MAP_PRIVATE flag. This creates a private, read-only memory mapping of the file.

2.  Two separate threads are created by the attacker. One thread continuously tries to write to the read-only memory mapping, while the other repeatedly calls madvise() with the MADV_DONTNEED flag on the same memory region.

3.  When the write operation is attempted, the kernel starts the Copy-On-Write (COW) process. It involves creating a private copy of the memory page and updating the page table entry to point to the new private copy. After this, the write operation will be performed on the private copy.

4.  The race condition occurs when the following events happen in quick succession:

		a. The madvise() call is processed, marking the physical memory pages associated with the private mapping as "not present" in the page table entry.
		
		b. A page fault is triggered when the write operation tries to access the memory page. The kernel starts loading the contents of the memory page from the original file (/etc/passwd) as it is a read-only, file-backed mapping.
		
		c. Before the kernel can complete the COW process (i.e., creating a private copy of the memory page and updating the page table entry to point to the new private copy), the write operation manages to modify the memory page that was just loaded from the original file.

The timing of these events is crucial for the exploit to succeed. The window of opportunity for the write operation to modify the original file's memory page is extremely small, as it must occur after the madvise() call has been processed and the page fault has been triggered, but before the kernel can complete the COW process.

It's important to note that this race condition is not deterministic, as it relies on precise timing between multiple threads and the kernel's internal handling of memory management. However, with continuous attempts, the exploit can eventually succeed in modifying the original file's memory page, bypassing the intended COW mechanism and leading to unauthorized write access.
```


	f.2) Now, the ORIGINAL PROCESS' THREAD writes to the actual physical memory of the “read-only” shared resource:


![](/assets/img/Pasted image 20230513172921.png)


**Note that the only thing the OTHER THREAD from the fork()-ed process does is repeatedly execute `madvise()` and that is it. The `write()` is done by the original process' thread.**

# Key Takeaways

- There are TWO operations that are **NON-atomic** that which another process' thread can swoop into the kernel's operation that changes the object(s) in the system environment which is to “forget” the actual physical memory allocated for the private mapping. This will in turn remove the mapping of the current process' virtual memory space to this physical address space it was supposedly mapped onto.

- The "`Copy-On-Write`" feature handling is completely bypassed because of the asynchrony of the two threads executing two different things on the same page and the repetition of execution of `madvise()` by the injecting thread in the operation. Which is why the kernel wasn't able to allocate a physical memory space to map the virtual address memory for the private mapping that is part of the `Copy-On-Write` mechanism.

- The original process' thread was able to `write()` on the shared resource (say `/etc/passwd` in our case) because the Kernel was too busy responding to the `madvise()` function calls the OTHER thread is demanding that when the `madvise()` happens coinciding with the `write()` of the first thread which is the start of the COW mechanism, the kernel just loaded the physical address to the actual shared resource (`/etc/passwd`) and hasn't finished updating the page table entry to point to the new private copy's physical address. The kernel loads this physical address of the original file because in the COW mechanism, this is cloned which results to the creation of the private mapping. Note that we can't create a copy of the file say `/etc/passwd` without knowing the original file's details first.

- Basically, at the time of the `write()` of the first thread, the kernel starts the Copy-On-Write mechanism BUT hasn't updated the page table entry to point to the new private copy yet. It still points to the original physical address space of the original file(`/etc/passwd` in our case). It points there because the kernel has to get the physical address of the original file before the file can be cloned. When this happens, the COW mechanism has been bypassed that leads to unauthorized write access to "read-only" files which in this case is the first line of **/etc/passwd**.



