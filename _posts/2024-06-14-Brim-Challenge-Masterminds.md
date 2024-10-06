---
title: Brim Challenge Masterminds
date: 2024-06-14 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---


# Scenario

Three machines in the Finance department at Pfeffer PLC were compromised. We suspect the initial source of the compromise happened through a phishing attempt and by an infected USB drive. The Incident Response team managed to pull the network traffic logs from the endpoints. Use Brim to investigate the network traffic for any indicators of an attack and determine who stands behind the attacks. 

**NOTE: DO NOT** directly interact with any domains and IP addresses in this challenge.

---
# Infection 1:

Start by loading the Infection1 packet capture in Brim to investigate the compromise event for the first machine. All the PCAPs can be found here: `/home/ubuntu/Desktop/PCAPs`  
**Note**: For questions that require multiple answers, please separate the answers with a comma.

<u>Checking the amount of logs we currently have</u>:
```c
count() by _path | sort -r
```

Output:

![](/assets/img/Pasted image 20240306201210.png)

	- There are 7 log files generated from the capture

- The client machine on the network that was provided with IP:

![](/assets/img/Pasted image 20240306201329.png)


- Provide the victim's IP address.
<u>Checking the network IP addresses</u>:
```c
_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r
```

Output:

![](/assets/img/Pasted image 20240306200708.png)

<u>Checking the connections on the network</u>:
```c
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq
```

![](/assets/img/Pasted image 20240306201009.png)

	- 192.168.75.249 seems to be the most common IP so its probably the victim's IP address

![](/assets/img/Pasted image 20240306201049.png)

	- It is!


- The victim attempted to make `HTTP` connections to two suspicious domains with the status '`404 Not Found`'. Provide the hosts/domains requested.

<u>Command</u>:
```c
_path=="http" | 192.168.75.249 | cut _path,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,host,uri,status_code,status_msg
```

<u>Output</u>:

![](/assets/img/Pasted image 20240306201907.png)

<u>Answer</u>: 
![](/assets/img/Pasted image 20240306201830.png)


- The victim made a successful HTTP connection to one of the domains and received the `response_body_len` of `1,309` (uncompressed content size of the data transferred from the server). Provide the `domain` and the `destination IP` address.
```c
_path=="http" | 192.168.75.249 | cut response_body_len,id.resp_h,id.resp_p,host,uri | sort
```

Output:

![](/assets/img/Pasted image 20240306202210.png)

Answer:

![](/assets/img/Pasted image 20240306202310.png)


- How many unique ***DNS requests*** were made to `cab[.]myfkn[.]com` domain (including the capitalized domain)?

```c
_path=="dns" | count () by query
```

![](/assets/img/Pasted image 20240306202658.png)

	- The domain has 6 DNS requests


- Provide the URI of the domain `bhaktivrind[.]com` that the victim reached out over HTTP.
<u>Command:</u>
```c
_path=="http" | cut id.orig_h,id.orig_p,id.resp_h,id.resp_p,host,uri | bhaktivrind.com
```

![](/assets/img/Pasted image 20240306202920.png)

	- /cgi-bin/JBbb8

![](/assets/img/Pasted image 20240306203052.png)

- Provide the IP address of the malicious server and the executable that the victim downloaded from the server.

Parsing the right columns for the file:
```c
_path=="files" | cut fuid,tx_hosts,rx_hosts,source,md5,sha1
```

![](/assets/img/Pasted image 20240306203249.png)

	- There are 4 files that the victim has downloaded from the attacker's server.


<u>Checking them on VirusTotal</u>:
```c
1. Filetype -  MD5: 68fa9a5dc9b89daa69d8418bf8d05869 SHA1: b897e40829c23b20d52ba23dbf7f606e2af8a83c
2. Filetype -  MD5: 017089b4144bf2fb9e4af12373c50175 SHA1: b6595572d542d6fcd17037539c0b4ac7e5278e82
3. Filetype -  MD5: 7fe07db5541e97de0248e5fbbe18259d SHA1: ddda073882033f6f32fd485dad238c1c880107bf
4. Filetype -  MD5: 3c06f8b36b6db15e6eb5996c3d1a0a76 SHA1: 19293815a07107a28d2364afb832cec5cd81d3d4
```

`1.` First file: An `.mp4` file!

![](/assets/img/Pasted image 20240306203618.png)


`2.` A text file?

![](/assets/img/Pasted image 20240306203717.png)

`3.` Another text file:

![](/assets/img/Pasted image 20240306203754.png)

`4.` Still a text file (html)

![](/assets/img/Pasted image 20240306204050.png)

`5.` (Found from `http.log`)

![](/assets/img/Pasted image 20240306204128.png)

	- hdmilg[.]xyz => 185.239.243.112
	- File: catzx[.]exe

![](/assets/img/Pasted image 20240306204316.png)


- Based on the information gathered from the second question, provide the name of the malware using [VirusTotal](https://www.virustotal.com/gui/home/upload).

![](/assets/img/Pasted image 20240306205147.png)


------------
# Infection 2:

Please, navigate to the `Infection2` packet capture in Brim to investigate the compromise event for the second machine.

Note: For questions that require multiple answers, please separate the answers with a comma.

<u>Checking the amount of logs we currently have</u>:
```c
count() by _path | sort -r
```

Output:

![](/assets/img/Pasted image 20240306211846.png)


- Provide the IP address of the victim machine.

![](/assets/img/Pasted image 20240306211955.png)

	- 192.168.75.146

![](/assets/img/Pasted image 20240306212230.png)

- Provide the IP address the victim made the `POST` connections to.

```c
_path=="http" | cut uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p, method,host,uri | POST
```

![](/assets/img/Pasted image 20240306212200.png)

	- 5.181.156.252

- How many `POST` connections were made to the IP address in the previous question? `3`

- Provide the domain where the binary was downloaded from.

![](/assets/img/Pasted image 20240306212305.png)

- Provide the name of the binary including the full URI.

		- /jollion/apines.exe

- Provide the IP address of the domain that hosts the binary.

		- 45.95.203.28

- There were 2 Suricata "`A Network Trojan was detected`" alerts. What were the source and destination IP addresses?

![](/assets/img/Pasted image 20240306213035.png)

![](/assets/img/Pasted image 20240306213050.png)

- Taking a look at `.top` domain in HTTP requests, provide the name of the stealer (Trojan that gathers information from a system) involved in this packet capture using [URLhaus Database](https://urlhaus.abuse.ch/).

![](/assets/img/Pasted image 20240306213225.png)


-----------
# Infection 3:

Please, load the Infection3 packet capture in Brim to investigate the compromise event for the third machine.  

Note: For questions that require multiple answers, please separate the answers with a comma.

<u>Checking the amount of logs we currently have</u>:
```c
count() by _path | sort -r
```

![](/assets/img/Pasted image 20240306213516.png)

- Provide the IP address of the victim machine.

![](/assets/img/Pasted image 20240306213602.png)

	- Here are the provided IP addresses under the "client_addr"

![](/assets/img/Pasted image 20240306213744.png)

	- that's a lot of connections to different IP and .exe downloads.
	- The victim's machine is 192.168.75.232


- Provide `three C2 domains` from which the binaries were downloaded (starting from the earliest to the latest in the timestamp)
```c
_path=="http" | cut uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p, method,host,uri | .exe
```

Instances of binaries downloaded:

![](/assets/img/Pasted image 20240306213947.png)


All domain names:

![](/assets/img/Pasted image 20240306214155.png)

![](/assets/img/Pasted image 20240306214258.png)


- Provide the IP addresses for all three domains in the previous question.
<u>First one</u>:

![](/assets/img/Pasted image 20240306214337.png)

![](/assets/img/Pasted image 20240306214402.png)

<u>Second one</u>:

![](/assets/img/Pasted image 20240306214437.png)


<u>Third one</u>:

![](/assets/img/Pasted image 20240306214519.png)

<u>Answers</u>:
```c
- 199.21.76.77
- 162.217.98.146
- 63.251.106.25
```


- How many ***unique DNS queries*** were made to the domain associated from the first IP address from the previous answer?
```c
_path=="dns" | cut query | sort | uniq | count()
```

	- Answer is `2`

![](/assets/img/Pasted image 20240306215041.png)

- How many binaries were downloaded from the above domain in total? `5`

![](/assets/img/Pasted image 20240306215112.png)


- Provided the user-agent listed to download the binaries.

![](/assets/img/Pasted image 20240306215209.png)


- Provide the amount of DNS connections made in total for this packet capture. `986`

- With some OSINT skills, provide the name of the worm using the first domain you have managed to collect from Question 2. (Please use quotation marks for Google searches, don't use `.ru` in your search, and DO NOT interact with the domain directly).

![](/assets/img/Pasted image 20240306215518.png)

