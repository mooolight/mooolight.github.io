---
title: Benign - Splunk Challenge
date: 2024-09-19 00:00:00 -500
categories: [TryHackMe, SIEM, Splunk]
tags: [TryHackMe]
---


# Identify and Investigate an Infected Host

One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with `Event ID: 4688` and ingested them into Splunk with the index **`win_eventlogs`** for further investigation.  

### About the Network Information

The network is divided into three logical segments. It will help in the investigation.  

**IT Department**
- James
- Moin
- Katrina

**HR department**
- Haroon
- Chris
- Diana

**Marketing department**
- Bell
- Amelia
- Deepak


- How many logs are ingested from the month of March, 2022?

```c
13959
```

![](/assets/img/Pasted image 20240408030049.png)


- Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

```c
Amel1a
```
![](/assets/img/Pasted image 20240408033651.png)

- Which user from the HR department was observed to be running scheduled tasks?
```c
Chris.fort
```
![](/assets/img/Pasted image 20240408031203.png)


- Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

```c
haroon
```
![](/assets/img/Pasted image 20240408031830.png)


- To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

```c
certutil.exe
```


- What was the date that this binary was `executed` by the infected host? format (YYYY-MM-DD)

![](/assets/img/Pasted image 20240408032235.png)

- Which third-party site was accessed to download the malicious payload?

```c
controlc.com
```


- What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

```c
benign.exe
```


- The suspicious file downloaded from the C2 server contained malicious content with the pattern `THM{..........}`; what is that pattern?

```c
THM{KJ&*H^B0}
```
![](/assets/img/Pasted image 20240408032651.png)

- What is the URL that the infected host connected to?


