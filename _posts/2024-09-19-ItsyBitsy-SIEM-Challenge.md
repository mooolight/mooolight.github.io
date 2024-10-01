---
title: ItsyBitsy - SIEM Challenge
date: 2024-09-19 00:00:00 -500
categories: [TryHackMe, SIEM, Threat Hunting]
tags: [TryHackMe]
---


# Intro

**Username:** `Admin`

**Password:** `elastic123`

In this challenge room, we will take a simple challenge to investigate an alert by IDS regarding a potential C2 communication.

--------
# Scenario : Investigate a potential C2 comms alert

During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern `THM:{ ________ }`. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.  

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.


- How many events were returned for the month of March 2022?

```c
1482
```
![](/assets/img/Pasted image 20240406231824.png)
![](/assets/img/Pasted image 20240406232047.png)


- What is the source IP associated with the suspected user in the logs?

```c
192.166.65.54
```

![](/assets/img/Pasted image 20240406232621.png)

	- Suspicious URI from pastebin which is also a popular site you can download files from including malware.


- The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

```c
bitsadmin.exe
```

![](/assets/img/Pasted image 20240406233245.png)


- The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

```c
pastebin.com
```


- What is the full URL of the C2 to which the infected host is connected?

```c
pastebin[.]com/yTg0Ah6a
```


- A file was accessed on the filesharing site. What is the name of the file accessed?

```c
secret.txt
```

![](/assets/img/Pasted image 20240406234727.png)


- The file contains a secret code with the format `THM{_____}`.

```c
THM{SECRET__CODE}
```




