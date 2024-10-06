---
title: Wireshark Cheatsheet
date: 2024-06-09 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---



# Wireshark Basics

### Packet Lookups:

![](/assets/img/Pasted image 20240306220141.png)

![](/assets/img/Pasted image 20240306232041.png)


-----

### Viewing File Details

```c
Statistics --> Capture File Properties
```

![](/assets/img/Pasted image 20240306220522.png)

-----

### Marking a Packet

```c
Edit > Mark
```

![](/assets/img/Pasted image 20240306232153.png)


-----

### Packet Commenting

- Helps with marking a packet:
```c
Edit > Packet Comment...
```

![](/assets/img/Pasted image 20240306232343.png)

-----

### Exporting Object Files

```c
Edit > Export Objects
```

![](/assets/img/Pasted image 20240306232549.png)

-----

### Time Display Format

```c
View > Time Display Format
```

![](/assets/img/Pasted image 20240306232627.png)


Expected Output:

![](/assets/img/Pasted image 20240306232801.png)

-----

### Conversation Filter

```c
Right click menu -> Analyze -> Conversation Filter
```

![](/assets/img/Pasted image 20240306235421.png)


-----

### Applying a parameter as Column

```c
Right-click -> Apply as Column
```

![](/assets/img/Pasted image 20240307000047.png)


----
# Wireshark Traffic Analysis

### TCP Connect Scan

```c
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

-----

### TCP SYN Scan

```c
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
```

-----

### UDP Scan

```c
icmp.type==3 and icmp.code==3
```

-----

### ARP Poisoning:

Opcode 1 (ARP Request): 
```c
arp.opcode == 1
```

Opcode 2 (ARP Response): 
```c
arp.opcode == 2
```

ARP Scanning:
```c
arp.dst.hw_mac==00:00:00:00:00:00
```

Possible ARP Poisoning detection: 

```c
arp.duplicate-address-detected or arp.duplicate-address-frame
```

Possible ARP Flooding from detection:

```c
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac==<target-mac-address>)
```

###### ARP in Wireshark:

![](/assets/img/Pasted image 20240307011814.png)


Spoofing:

![](/assets/img/Pasted image 20240307015059.png)


-----
# DNS


### Checking the query name of a specific DNS query and having the DNS server IP:

```c
dns.qry.name.len > 15 and !mdns and ip.dst == 10.9.23.102
```

![](/assets/img/Pasted image 20240315152646.png)


---
# Credentials


### Getting the credentials used inside the network

```c
Tools > Credentials
```

![](/assets/img/Pasted image 20240318152504.png)

![](/assets/img/Pasted image 20240318152518.png)







