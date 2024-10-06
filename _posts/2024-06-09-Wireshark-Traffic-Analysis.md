---
title: Wireshark Traffic Analysis
date: 2024-06-09 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---


---
Date: 03/06/2024
---
# NMAP Scans

Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.

```c
- TCP connect scans
- SYN scans
- UDP scans
```


It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. 

- Below are the base filters to probe Nmap scan behaviour on the network:

![](/assets/img/Pasted image 20240307003638.png)


### TCP Connect Scans

**TCP Connect Scan in a nutshell:**

- Relies on the three-way handshake (needs to finish the handshake process).
- Usually conducted with `nmap -sT` command.
- Used by non-privileged users (only option for a non-root user).
- Usually has a windows size larger than ***1024 bytes*** as the request expects some data due to the nature of the protocol.

![](/assets/img/Pasted image 20240307003715.png)

The images below show the three-way handshake process of the open and close TCP ports. Images and pcap samples are split to make the investigation easier and understand each case's details:

***Open TCP Port (Connect):***

![](/assets/img/Pasted image 20240307004102.png)

***Closed TCP port (Connect)**:

![](/assets/img/Pasted image 20240307004220.png)

The above images provide the patterns in isolated traffic. ***However, it is not always easy to spot the given patterns in big capture files***. Therefore analysts need to use a generic filter to view the initial anomaly patterns, and then it will be easier to focus on a specific traffic point.

- The given filter shows the ***TCP Connect scan*** patterns in a capture file:
```c
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

![](/assets/img/Pasted image 20240307004348.png)


### **SYN Scans**  

TCP SYN Scan in a nutshell:

- Doesn't rely on the three-way handshake (no need to finish the handshake process).
- Usually conducted with:
```c
$ nmap -sS
```

- ***Used by privileged users***.
- Usually have a size less than or equal to `1024 bytes` as the request is not finished and it doesn't expect to receive data.

![](/assets/img/Pasted image 20240307004518.png)

**Open TCP port (SYN):**

![](/assets/img/Pasted image 20240307004643.png)

**Closed TCP port (SYN):**

![](/assets/img/Pasted image 20240307004700.png)


The given filter shows the TCP SYN scan patterns in a capture file:
```c
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
```

![](/assets/img/Pasted image 20240307004753.png)

	- I dont get it. Why does it only show the SYN parts? Its just the beginning of the interaction.


### UDP Scans  

UDP Scan in a nutshell:

- Doesn't require a handshake process
- No prompt for open ports
- ICMP error message for close ports
- Usually conducted with:

```c
$ nmap -sU
```


![](/assets/img/Pasted image 20240307004901.png)


**Closed (port no. 69) and open (port no. 68) UDP ports:**

![](/assets/img/Pasted image 20240307004917.png)

	- The above image shows that the closed port returns an ICMP error packet. 


- No further information is provided about the error at first glance, so ***how can an analyst decide WHERE(source of error) this error message belongs?*** 
- The ICMP error message uses the original request as ***encapsulated data*** to show the source/reason of the packet. Once you expand the ICMP section in the packet details pane, you will see the encapsulated data and the original request, as shown in the below image.

![](/assets/img/Pasted image 20240307005044.png)


The given filter shows the `UDP scan patterns` in a capture file:
```c
icmp.type==3 and icmp.code==3
```

![](/assets/img/Pasted image 20240307005317.png)

	- Shows all the failed UDP packet sent and if you deep dive enough, you'll see to which UDP packet this ICMP packet is partnered with.

##### Questions and Answer sections:

- What is the total number of the "TCP Connect" scans?
<u>Filter</u>:
```c
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

Output:

![](/assets/img/Pasted image 20240307010249.png)

Navigation: `Wireshark > Statistics > Capture File Properties > Packets Captured`

![](/assets/img/Pasted image 20240307010646.png)

- Which scan type is used to scan the TCP port 80? `TCP Connect`

- How many "`UDP close port`" messages are there?

The given filter shows the `UDP scan patterns` in a capture file:
```c
icmp.type==3 and icmp.code==3
```

![](/assets/img/Pasted image 20240307010843.png)


- Which UDP port in the `55-70 port` range is open? (I assume this is inclusive on both sides?)

![](/assets/img/Pasted image 20240307011358.png)

	- Notice that there are TWO Closed ports that received UDP packets.
	- What we want are the Open ports that received it:

![](/assets/img/Pasted image 20240307011522.png)

	- All destination port is 68!

---
# ARP Poisoning and MiTM

### ARP Poisoning/Spoofing (A.K.A. Man In The Middle Attack)  

**ARP** protocol, or **A**ddress **R**esolution **P**rotocol (**ARP**), is the technology responsible for allowing devices to identify themselves on a network. Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the **"IP to MAC address table"** and sniff the traffic of the target host.

There are a variety of tools available to conduct ARP attacks. However, the mindset of the attack is static, so it is easy to detect such an attack by knowing the ARP protocol workflow and Wireshark skills.    

**ARP analysis in a nutshell:**
```c
- Works on the local network
- Enables the communication between MAC addresses
- Not a secure protocol
- Not a routable protocol
- It doesn''t have an authentication function
- Common patterns are request & response, announcement and gratuitous packets.
```


- Before investigating the traffic, let's review some legitimate and suspicious ARP packets. 
- The legitimate requests are similar to the shown picture: 

		- A broadcast request that asks if any of the available hosts use an IP address
		- A reply from the host that uses the particular IP address


![](/assets/img/Pasted image 20240307011800.png)

###### ARP in Wireshark:
![](/assets/img/Pasted image 20240307011814.png)

- ***A suspicious situation means having two different ARP responses (conflict) for a particular IP address.*** 
- In that case, Wireshark's expert info tab warns the analyst. However, it only shows the second occurrence of the duplicate value to highlight the conflict. 
- ***Therefore, identifying the malicious packet from the legitimate one is the analyst's challenge.*** A possible IP spoofing case is shown in the picture below.

![](/assets/img/Pasted image 20240307015059.png)


- Here, knowing the network architecture and inspecting the traffic for a specific time frame can help detect the anomaly. 
- As an analyst, you should take notes of your findings before going further. 
- This will help you be organised and make it easier to correlate the further findings. 
- Look at the given picture; there is a conflict; the MAC address that ends with "`b4`" crafted an ARP request with the "`192.168.1.25`" IP address, then claimed to have the "`192.168.1.1`" IP address.

![](/assets/img/Pasted image 20240307015701.png)

