---
title: Warzone II
date: 2024-06-17 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---

# Scenario

You work as a Tier 1 Security Analyst L1 for a Managed Security Service Provider (MSSP). Again, you're tasked with monitoring network alerts.

An alert triggered: 

```c
- **Misc activity**, 
- **A Network Trojan Was Detected**, and 
- **Potential Corporate Privacy Violation** 
```

The case was assigned to you. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive. 

##### Your tools:

- [Brim](https://tryhackme.com/room/brim)
- [Network Miner](https://tryhackme.com/room/networkminer)
- [Wireshark](https://tryhackme.com/room/wireshark)


### Question and Answers section

##### With `Brim` (Log Analysis)

Checking the traffic type from the pcap:
```c
count() by _path | sort -r
```

![](/assets/img/Pasted image 20240320053341.png)


- What was the `alert signature` for **A Network Trojan was Detected**?

Using the Suricata filter:

```c
event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip
```

![](/assets/img/Pasted image 20240320053504.png)

Going to logs:

![](/assets/img/Pasted image 20240320053530.png)

![](/assets/img/Pasted image 20240320053606.png)

	- Answer: ET Malware Likely Evil EXE download from MSXMLHTTP non-exe extension M2


- What was the alert signature for **Potential Corporate Privacy Violation**?

Got from previous question:

![](/assets/img/Pasted image 20240320053606.png)

	- Answer: ET POLICY PE EXE or DLL Windows file download HTTP


- What was the ***IP*** to trigger either alert? Enter your answer in a **defanged** format. `185[.]118[.]164[.]8`


##### With NetworkMiner (Network Forensics)

- Provide the full URI for the malicious downloaded file. In your answer, **defang** the URI.

File correlation with Brim:

![](/assets/img/Pasted image 20240320053919.png)


Getting the full URI with Wireshark and going to the files downloaded:

![](/assets/img/Pasted image 20240320055653.png)

![](/assets/img/Pasted image 20240320055726.png)

Looking at the response packet:

![](/assets/img/Pasted image 20240320055802.png)

Answer:

![](/assets/img/Pasted image 20240320055548.png)


- What is the name of the payload within the cab file?

Go to Wireshark and save the `gap1.cab` file locally:

![](/assets/img/Pasted image 20240320061639.png)


Get the `sha256` hash of the file:

![](/assets/img/Pasted image 20240320061701.png)


Hop on VT for more info:

![](/assets/img/Pasted image 20240320061746.png)

	- Answer: draw.dll


- What is the ***user-agent*** associated with this network traffic?

It is available in `notice`, `files`, and `http`:

![](/assets/img/Pasted image 20240320062145.png)


From the `notice` path:

![](/assets/img/Pasted image 20240320062233.png)


From the `files` path:

![](/assets/img/Pasted image 20240320062306.png)


From the `http` path:

![](/assets/img/Pasted image 20240320062334.png)




- What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains **defanged** and in alphabetical order. (**`format: domain[.]zzz,domain[.]zzz`**)

![](/assets/img/Pasted image 20240320062449.png)

### False Negatives:

- There are IP addresses flagged as **Not Suspicious Traffic**. What are the IP addresses? Enter your answer in numerical order and **defanged**. (format: IPADDR,IPADDR)

```c
- 64[.]225[.]65[.]166
- 142[.]93[.]211[.]176
```

![](/assets/img/Pasted image 20240320062623.png)


- For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a **defanged** format. Enter your answer in alphabetical order, in a defanged format. (**format: `domain[.]zzz,domain[.]zzz`,etc**)

![](/assets/img/Pasted image 20240320062738.png)

```c
- [ulcertification[.]xyz](https://www.virustotal.com/gui/domain/ulcertification[.]xyz)
- [safebanktest[.]top](https://www.virustotal.com/gui/domain/safebanktest[.]top)
- [tocsicambar[.]xyz](https://www.virustotal.com/gui/domain/tocsicambar[.]xyz)
```


- Now for the second IP marked as Not Suspicious Traffic. What was the `domain` ***you spotted in the network traffic*** associated with this IP address? Enter your answer in a **defanged** format. (format: `domain[.]zzz`)

Hint: Use NetworkMiner

![](/assets/img/Pasted image 20240320063529.png)

```c
2partscow[.]top
```






