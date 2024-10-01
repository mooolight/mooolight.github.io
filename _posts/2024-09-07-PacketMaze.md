---
title: PacketMaze
date: 2024-09-07 00:00:00 -500
categories: [DFIR, Network Forensics]
tags: [CyberDefenders]
---


---
Date: July 22,2024
---

# Instructions:

- Uncompress the lab (pass: **cyberdefenders.org**)
- Load suricatarunner.exe and suricataupdater.exe in BrimSecurity.
- Uncompress `suricata.zip` and move `suricata.rules` to "`.\var\lib\suricata\rules`" inside `suricatarunner` directory.

---
# Scenario

As a soc analyst working for a security service provider, you have been tasked with analyzing a packet capture for a customer's employee whose network activity has been monitored for a while -possible insider.

# Tools:
```c
- [BrimSecurity](https://www.brimsecurity.com/)
- [suricatarunner](https://github.com/brimsec/build-suricata/releases/tag/v5.0.3-brim1)
- [suricata.rules](https://download.cyberdefenders.org/BlueYard/misc/suricata.zip)
- [NetworkMiner](https://www.netresec.com/?page=networkminer)
- [WireShark](https://www.wireshark.org/)
- [MAC lookup](https://macaddress.io/)
```

# Tags
```c
[SMB](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=smb)
[Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=wireshark)
[PCAP](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=pcap)
[MAC](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=mac)
[NetworkMiner](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=networkminer)
[Suricata](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=suricata)
[BRIM](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=brim)
```


# Questions:

<u>Preview</u>:
![](/assets/img/Pasted image 20240727233705.png)

	- Seems like this IP talks a lot of hosts outside of its network.


<u>Checking major protocols used</u>:
![](/assets/img/Pasted image 20240727233918.png)



## `Q1` What is the FTP password?

Checking out the FTP protocol:
![](/assets/img/Pasted image 20240727234122.png)

	- The attacker seems to be connecting to the FTP server encapsulated with TLS and checking all the documents under the /home/kali/Documents and found the file 'accountNum.zip'.

-> Answer: `AfricaCTF2021`


## `Q2` What is the IPv6 address of the DNS server used by 192.168.1.26? (####::####:####:####:####)

Checking the DNS protocol with this query:
```c
dns && ip.addr == 192.168.1.26
```

MAC address of the victim's machine:
```c
c8:09:a8:57:47:93
```

![](/assets/img/Pasted image 20240727234448.png)

The IP address of the organization's DNS server is:
```c
192.168.1.10 
```

MAC address of this:
```c
ca:0b:ad:ad:20:ba
```

![](/assets/img/Pasted image 20240728000218.png)

Wireshark query:
```c
eth.addr == ca:0b:ad:ad:20:ba && ipv6 && dns
```

![](/assets/img/Pasted image 20240728000511.png)


![](/assets/img/Pasted image 20240728000826.png)


-> Answer: `fe80::c80b:adff:feaa:1db7`


## `Q3` What domain is the user looking up in packet 15174?

Wireshark query:
```c
eth.addr == ca:0b:ad:ad:20:ba && ipv6 && dns
```

![](/assets/img/Pasted image 20240728001008.png)

-> Answer: `www.7-zip.org`


## `Q4`: How many UDP packets were sent from `192.168.1.26` to `24.39.217.246`?

Wireshark Query:
```c
ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp
```

![](/assets/img/Pasted image 20240728001206.png)

-> Answer: `10`

## `Q5`:What is the MAC address of the system being investigated in the `PCAP`?

-> Answer: `c8:09:a8:57:47:93`

## `Q6`:What was the camera model name used to take picture `20210429_152157.jpg` ?

Checking the ftp sessions: There's a second authentication on the FTP server after the listing of `accountNum.zip`:
![](/assets/img/Pasted image 20240728002737.png)

Two `.jpeg` files got stored on the FTP server:
![](/assets/img/Pasted image 20240728002837.png)

- This question seems to be related to DFIR. Let's go check `dfir.science` requests in the pcap:
```
There's nothing...
```

Going back to the FTP transaction but this time, we filter using `ftp-data` since the file was uploaded:
![](/assets/img/Pasted image 20240728003710.png)

Following the stream:
![](/assets/img/Pasted image 20240728004030.png)


-> Answer: `LM-Q725K`


## `Q7`:What is the server certificate public key that was used in TLS session: `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?

- Note that this is a 16 hex byte format.
```c
da:4a:00:00:34:2e:4b:73:45:9d:73:60:b4:be:a9:71:cc:30:3a:c1:8d:29:b9:90:67:e4:6d:16:cc:07:f4:ff
```

Wireshark query:
```c
tls.handshake.certificate && tls.handshake.type==2 && tls.handshake.session_id == da:4a:00:00:34:2e:4b:73:45:9d:73:60:b4:be:a9:71:cc:30:3a:c1:8d:29:b9:90:67:e4:6d:16:cc:07:f4:ff
```

	- tls.handshake.type==2 focuses on SERVER HELLO packet which contains the public key certificate of the session.


<u>Server Hellos packet</u>:
![](/assets/img/Pasted image 20240728010742.png)

Output:
![](/assets/img/Pasted image 20240728011425.png)

-> Answer: `04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d`


## `Q8`:What is the first `TLS 1.3` client random that was used to establish a connection with protonmail.com?

First, let's find an instance of a packet to know the hex byte equivalent of the `tls.record.version` for `TLS v1.3`:
![](/assets/img/Pasted image 20240728012444.png)


	- Seems to be that the URL related with the TLSv1.3 in mind is connected to "Client Hello" after I double-clicked it and this packet got highlighted.


New query:
```c
tls.handshake.type == 1 && tls.handshake.extensions_server_name contains protonmail
```

![](/assets/img/Pasted image 20240728013355.png)

	- This is mail.protonmail.com


Refining the query:
```c
tls.handshake.type == 1 && tls.handshake.extensions_server_name == protonmail.com
```

![](/assets/img/Pasted image 20240728013900.png)


-> Answer: `ddfb32c96ba450dee42f208944d96bebad751298ce3471cb8e06ee112e37493c`


## `Q9`: What country is the MAC address of the FTP server registered in? (two words, one space in between)

- Use `macaddress.io`

-> Answer: `United States`

## `Q10`: What time was a non-standard folder created on the FTP server on the 20th of April? (hh:mm)

![](/assets/img/Pasted image 20240728014916.png)

-> Answer: `17:53`


## `Q11`: What domain was the user connected to in packet 27300?

![](/assets/img/Pasted image 20240728015245.png)


-> Answer: `dfir.science`


