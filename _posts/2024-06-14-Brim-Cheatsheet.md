---
title: Brim Cheatsheet
date: 2024-06-14 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---



### Queries and History

```c
count() by _path | sort -r
```

![](/assets/img/Pasted image 20240306164546.png)


### Checking `smb` or `dce_rpc` path:

```c
_path matches smb* OR _path=="dce_rpc" | sort -r _path
```

Output:

![](/assets/img/Pasted image 20240306171857.png)


##### Unique Network Connections and Transferred Data

```c
Command 1: _path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq

Command 2: _path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

![](/assets/img/Pasted image 20240306172136.png)


##### DNS and HTTP Methods

```c
Command 1: _path=="dns" | count() by query | sort -r

Command 2: _path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c 
```

![](/assets/img/Pasted image 20240306172223.png)


##### File Activity

```c
filename!=null | cut_path, tx_hosts, rx_hosts, conn_uids, mime_type,filename, md5, sha1
```

![](/assets/img/Pasted image 20240306173008.png)


##### IP Subnet Statistics

```c
_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r
```

![](/assets/img/Pasted image 20240306172924.png)


##### Suricata Alerts

```c
Command 1: event_type=="alert" | count() by alert.severity,alert.category | sort count

Command 2: event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip

Command 3: event_type=="alert" | alerts := union(alert.category) by network_of(dest_ip)
```

![](/assets/img/Pasted image 20240306173254.png)

![](/assets/img/Pasted image 20240319164728.png)

![](/assets/img/Pasted image 20240319164743.png)



##### Checking identified city names

```c
_path=="conn" | cut geo.resp.city | sort -r | uniq
```

![](/assets/img/Pasted image 20240306174637.png)


###### Brim Query Reference

Basic Search:
```c
Find logs containing this IP: 10.0.0.1
```

Logical Operators:
```c
192 and NTP
```

Filter values:
```c
id.orig_h==192.168.121.40
```

List specific log file contents:
```c
_path=="conn"
```

Count field values:
```c
count () by _path
```

Sort findings:
```c
count () by _path | sort -r
```

Cut specific field from a log file:
```c
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h
```

List unique values:
```c
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq
```

Communicated hosts:
```c
_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq
```

Frequently communicated hosts:
```c
_path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r
```

Most Active Ports:
```c
-> _path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count
-> _path=="conn" | cut id.orig_h, id.resp_h, id.resp_p, service | sort id.resp_p | uniq -c | sort -r
```

Long connections:
```c
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration
```

Transferred Data:
```c
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

DNS and HTTP queries:
```c
-> _path=="dns" | count () by query | sort -r
-> _path=="http" | count () by uri | sort -r
```

Suspicious Hostnames:
```c
_path=="dhcp" | cut host_name, domain
```

Suspicious IP Addresses:
```c
_path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r
```

Detect Files:
```c
filename!=null
```

SMB Activity:
```c
_path=="dce_rpc" OR _path=="smb_mapping" OR _path=="smb_files"
```

Known Patterns:
```c
event_type=="alert" or _path=="notice" or _path=="signatures"
```

---

### Threat Hunting with Brim - Malware C2 Detection

Query 1:
```c
count() by _path | sort -r
```

Output:

![](/assets/img/Pasted image 20240306181210.png)

Query 2: Extract unique ports and communicating IPs
```c
$ cut id.orig_h, id.resp_p, id.resp_h | sort  | uniq -c | sort -r count
```

Output:

![](/assets/img/Pasted image 20240306181214.png)


Query 3: Look at the port numbers and available services
```c
_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count
```

![](/assets/img/Pasted image 20240306181517.png)


Query 4: Checking all DNS queries
```c
_path=="dns" | count() by query | sort -r
```

![](/assets/img/Pasted image 20240306181555.png)

	- Use VirusTotal on these.


Query 5:  look at the HTTP requests before narrowing down our investigation with the found malicious IP addresses.
```c
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri
```

![](/assets/img/Pasted image 20240306181822.png)

	- Important IP -> 104.168.44.45 becauses of download file request


Query 6: Checking Suricata logs
```c
event_type=="alert" | count() by alert.severity,alert.category | sort count
```

![](/assets/img/Pasted image 20240306182146.png)

### ***Please note, Adversaries using CobaltStrike are usually skilled threats and don't rely on a single C2 channel***


Query 7: Checking downloaded Cobalt Strike C2:

```c
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri
```

![](/assets/img/Pasted image 20240306182646.png)

Query 8: Checking the CobaltStrike connections using port 443

```c
event_type=="alert" | cut dest_port | sort | count() by dest_port
```

![](/assets/img/Pasted image 20240306183434.png)


Query 9: Checking the secondary C2 channel:
```c
event_type=="alert" | cut alert.signature |sort | uniq -c | sort -r count
```

![](/assets/img/Pasted image 20240306184130.png)

----
### Threat Hunting with Brim : CryptoMining

Query 1:
```c
count() by _path | sort -r
```

![](/assets/img/Pasted image 20240306184711.png)


**Query 2:** Review the frequently communicated hosts to see if there is an anomaly indicator
```c
cut id.orig_h, id.resp_p, id.resp_h | sort  | uniq -c | sort -r
```

Output:

![](/assets/img/Pasted image 20240306185320.png)

![](/assets/img/Pasted image 20240306190516.png)


Query 3: Port numbers and available services before focusing on the suspicious IP address
```c
_path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count
```

Output:

![](/assets/img/Pasted image 20240306185457.png)

![](/assets/img/Pasted image 20240306190606.png)


Query 4: Transferred data bytes to support our findings and find more indicators
```c
_path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

Output:

![](/assets/img/Pasted image 20240306190650.png)


Query 5: Hunt the low hanging fruits with the help of Suricata rules. Let's investigate the Suricata logs

```c
event_type=="alert" | count() by alert.severity,alert.category | sort count
```


![](/assets/img/Pasted image 20240306185706.png)


Query 6: Let's dig deeper and discover which data pool is used for the mining activity. First, we will list the associated connection logs with the suspicious IP, and then we will run a VirusTotal search against the destination IP.

```c
_path=="conn" | 192.168.1.100
```

![](/assets/img/Pasted image 20240306185800.png)

![](/assets/img/Pasted image 20240306185810.png)


Query 7: use Suricata logs to discover mapped out MITRE ATT&CK techniques

```c
event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c
```

Output:

![](/assets/img/Pasted image 20240306185854.png)

<u>Now we can identify the mapped out MITRE ATT&CK details as shown in the table below</u>:

![](/assets/img/Pasted image 20240306185916.png)


Query 8: Checking the number of connections on a specific port. In this case, port `19999`:

```c
_path=="conn" | 19999 | count()
```

![](/assets/img/Pasted image 20240306191559.png)

![](/assets/img/Pasted image 20240306191616.png)


Query 9: Checking the name of service used for a specific port. In this case, its port `6666`:

![](/assets/img/Pasted image 20240306191810.png)


Query 10: Checking the amount of total bytes transferred on a specific `<ip>:<port>` combination. In this case, `101.201.172.235:8888`:

```c
_path=="conn" | 101.201.172.235 | 8888 | put total_bytes := orig_bytes + resp_bytes | cut uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, orig_bytes,resp_bytes,total_bytes
```

![](/assets/img/Pasted image 20240306192253.png)


Query 11: Checking Suricata log alerts and their MITRE attack Technique name and ID:

```c
event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c
```

Output:

![](/assets/img/Pasted image 20240306192428.png)

![](/assets/img/Pasted image 20240306192522.png)

![](/assets/img/Pasted image 20240306192535.png)








