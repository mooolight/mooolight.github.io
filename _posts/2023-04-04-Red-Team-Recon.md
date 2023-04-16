---
title: Red Team Recon
date: 2022-12-30 12:00:00 -500
categories: [Red Team Operator, Initial Access]
tags: [TryHackMe]
---

# Intro

#### Topics:

	- Types of recon activities
	- WHOIS and DNS-based recon
	- Advanced searching
	- Searching by image
	- Google Hacking
	- Specialized search engines
	- Recon-ng
	- Maltego

#### Objectives:

	- Discovering subdomains related to our target company
	- Gathering publicly available info about a host and IP addresses
	- Finding email adresses related to the target
	- Discovering login creds and leaked passwords
	- Locating leaked docs and spreadsheets

<u>Two parts</u>:

##### 1. Passive -> focus in this room.
##### 2. Active

----------
# Taxonomy of Recon
##### 1. Passive : carried out passively without interacting with the thing you're observing.
##### 2. Active: requires interaction


Active Recon types:

	- External : conducted OUTSIDE the target's network by gathering info on the target's public info.
	- Internal : conducted WITHIN the target's network like doing vulnerability assessments.

-------
# Built-in Tools

	- whois
	- dig
	- nslookup
	- host
	- traceroute/tracert

##### WHOIS:
- Request and response tool and listens on TCP port 43 for incoming requests.
- What we can see with WHOIS:

		- Registrar WHOIS server
		- Registrar URL
		- Record creation date
		- Record update date
		- Registrant contact info and address (unless withhelp for privacy)
		- Admin contact info and address (unless withheld for privacy)
		- Tech contact info and address (unless withheld for privacy)

<u>Example</u>: Provides information about the domain regarding its metadata.
```bash
pentester@TryHackMe$ whois thmredteam.com 
[Querying whois.verisign-grs.com] 
[Redirected to whois.namecheap.com] 
[Querying whois.namecheap.com] 
[whois.namecheap.com] 
Domain name: thmredteam.com 
Registry Domain ID: 2643258257_DOMAIN_COM-VRSN 
Registrar WHOIS Server: whois.namecheap.com 
Registrar URL: http://www.namecheap.com 
Updated Date: 0001-01-01T00:00:00.00Z 
Creation Date: 2021-09-24T14:04:16.00Z 
Registrar Registration Expiration Date: 2022-09-24T14:04:16.00Z 
Registrar: NAMECHEAP INC Registrar IANA ID: 1068 
Registrar Abuse Contact Email: abuse@namecheap.com 
Registrar Abuse Contact Phone: +1.6613102107 
Reseller: NAMECHEAP INC 
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited 
Registry Registrant ID:  
Registrant Name: Withheld for Privacy Purposes 
Registrant Organisation: Privacy service provided by Withheld for Privacy ehf 
Registrant Street: Kalkofnsvegur 2  
Registrant City: Reykjavik 
Registrant State/Province: Capital Region 
Registrant Postal Code: 101 
Registrant Country: IS 
Registrant Phone: +354.4212434 
Registrant Phone Ext:  
Registrant Fax:  
Registrant Fax Ext:  
Registrant Email: 4c9d5617f14e4088a4396b2f25430925.protect@withheldforprivacy.com 
Registry Admin ID:  
Admin Name: Withheld for Privacy Purposes [...] 
Tech Name: Withheld for Privacy Purposes [...] 
Name Server: kip.ns.cloudflare.comName 
Server: uma.ns.cloudflare.com 
DNSSEC: unsigned 
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/ 
>>> Last update of WHOIS database: 2021-10-13T10:42:40.11Z <<< 
>>> For more information on Whois status codes, please visit https://icann.org/epp
```

		Things you can get:
		- email
		- phone number
		- Authoritative NS
		- etc.

**DNS Queries** : provides the jumps to get to the domain name

		- nslookup

```bash
pentester@TryHackMe$ nslookup cafe.thmredteam.com 
Server:		127.0.0.53 
Address:	127.0.0.53#53  
Non-authoritative answer: 
Name:	cafe.thmredteam.com 
Address: 104.21.93.169 
Name:	cafe.thmredteam.com 
Address: 172.67.212.249 
Name:	cafe.thmredteam.com 
Address: 2606:4700:3034::ac43:d4f9 
Name:	cafe.thmredteam.com 
Address: 2606:4700:3034::6815:5da9
```

**Domain Information Groper(`dig`)**: provides information about the DNS stuff of a domain including its subdomains,etc.

```bash
pentester@TryHackMe$ dig cafe.thmredteam.com @1.1.1.1  
; <<>> DiG 9.16.21-RH <<>> cafe.thmredteam.com @1.1.1.1 
;; global options: +cmd 
;; Got answer: 
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16698 
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1  

;; OPT PSEUDOSECTION: 
; EDNS: version: 0, flags:; udp: 4096 
;; QUESTION SECTION: 
;cafe.thmredteam.com.		IN	A  


;; ANSWER SECTION: 
cafe.thmredteam.com.	3114	IN	A	104.21.93.169 
cafe.thmredteam.com.	3114	IN	A	172.67.212.249  
;; Query time: 4 msec ;; SERVER: 1.1.1.1#53(1.1.1.1) 
;; WHEN: Thu Oct 14 10:44:11 EEST 2021 
;; MSG SIZE  rcvd: 80
```

**`host`** : alternative for querying DNS servers for DNS records.

![](/assets/img/Pasted image 20221201104325.png)


**`traceroute/tracert`**: traces route taken by the packets from our system to the target host. (hops)
-> If we see a `*` , this means that the routers doesn't respond to the packet sent.

![](/assets/img/Pasted image 20221201104443.png)

##### NOTE: WHOIS databases and DNS servers hold publicly available information, and querying either DOES NOT generate any suspicious traffic.

<u>Questions</u>:
![](/assets/img/Pasted image 20221201104242.png)

	- '2' because these are the "subdomain" and for the actual domain name.

-----------
# Advanced Searching

![](/assets/img/Pasted image 20221201104712.png)

- Confidential information that might get indexed:

		- Documents for internal company use
		- Confidential spreadsheets with usernames, email addresses and even passwords
		- Files containing usernames
		- Sensitive directories
		- Service version number
		- Error messages

**GHDB(Google Hacking Database) queries**: 

- Footholds : 
- Files Containing Usernames : 
- Sensitiv Directories : 
- Web Server Detection : 
- Vulnerable Files : 
- Vulnerable Servers : 
- Error Messages : 