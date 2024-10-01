---
title: Slingshot
date: 2024-09-13 00:00:00 -500
categories: [TryHackMe, SIEM, Advanced ELK Queries]
tags: [TryHackMe]
---


# Scenario

Slingway Inc., a leading toy company, has recently noticed suspicious activity on its e-commerce web server and potential modifications to its database. To investigate the suspicious activity, they've hired you as a SOC Analyst to look into the web server logs and uncover any instances of malicious activity.

To aid in your investigation, you've received an `Elastic Stack instance containing logs` from the suspected attack. Below, you'll find credentials to access the Kibana dashboard. ***`Slingway's IT`*** staff mentioned that the suspicious activity started on **`July 26, 2023`**.

By investigating and answering the questions below, we can create a timeline of events to lead the incident response activity. This will also allow us to present concise and confident findings that answer questions such as:
```c
1. What vulnerabilities did the attacker exploit on the web server?
2. What user accounts were compromised?
3. What data was exfiltrated from the server?
```

# Question and Answers section:

- Set the time range first:
![](/assets/img/Pasted image 20240422011824.png)


- What was the attacker's IP?
![](/assets/img/Pasted image 20240422012232.png)

<u>Answer</u>:
```c
10.0.2.15
```


- What was the first scanner that the attacker ran against the web server?
![](/assets/img/Pasted image 20240422012832.png)

<u>Answer</u>:
```c
NMAP Scripting Engine
```



- What was the `User Agent` of the directory enumeration tool that the attacker used on the web server?
![](/assets/img/Pasted image 20240422012947.png)

<u>Answer</u>:
```c
Gobuster is the only directory enumeration tool that seems to be used extensively.
```



- In total, how many `requested resources` on the web server did the attacker fail to find?
![](/assets/img/Pasted image 20240422013206.png)

	- Since we want to know the failed requests, we want the `404` HTTP status code.

![](/assets/img/Pasted image 20240422013257.png)

<u>Here's an example of an event entry</u>:
```c
{
  "_index": ".ds-filebeat-8.8.2-2023.07.26-000001",
  "_id": "fh6YkokBFYsRLQlCtprK",
  "_version": 1,
  "_score": 0,
  "_source": {
    "@timestamp": "2023-07-26T14:27:08.138Z",
    "input": {
      "type": "log"
    },
    "agent": {
      "name": "slingwayweb",
      "type": "filebeat",
      "version": "8.8.2",
      "ephemeral_id": "ceecb9b4-2c4b-472b-96ca-e27ca9358fcb",
      "id": "2e8f766e-fd18-4a7e-b709-f730de06b7b4"
    },
    "transaction": {
      "remote_address": "10.0.2.15",
      "remote_port": 43442,
      "local_address": "10.0.2.4",
      "local_port": 80,
      "time": "26/Jul/2023:14:27:07 +0000",
      "transaction_id": "ZMEtOztcHeWClKRTMN1f3AAAAAA"
    },
    "request": {
      "request_line": "GET /.git/HEAD HTTP/1.1",
      "headers": {
        "User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        "Connection": "close",
        "Host": "slingway.thm"
      }
    },
    "response": {
      "protocol": "HTTP/1.1",
      "status": 404, <-- Important Part
      "headers": {
        "Content-Length": "274",
        "Connection": "close",
        "Content-Type": "text/html; charset=iso-8859-1"
      }
    },
    "audit_data": {},
    "http": {
      "version": "HTTP/1.1",
      "method": "GET",
      "url": "/.git/HEAD"
    },
    "message": "{\"transaction\":{\"time\":\"26/Jul/2023:14:27:07 +0000\",\"transaction_id\":\"ZMEtOztcHeWClKRTMN1f3AAAAAA\",\"remote_address\":\"10.0.2.15\",\"remote_port\":43442,\"local_address\":\"10.0.2.4\",\"local_port\":80},\"request\":{\"request_line\":\"GET /.git/HEAD HTTP/1.1\",\"headers\":{\"User-Agent\":\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\",\"Connection\":\"close\",\"Host\":\"slingway.thm\"}},\"response\":{\"protocol\":\"HTTP/1.1\",\"status\":404,\"headers\":{\"Content-Length\":\"274\",\"Connection\":\"close\",\"Content-Type\":\"text/html; charset=iso-8859-1\"}},\"audit_data\":{}}",
    "ecs": {
      "version": "8.0.0"
    },
    "host": {
      "name": "slingwayweb"
    },
    "log": {
      "offset": 16947,
      "file": {
        "path": "/var/log/apache2/modsec_audit.log"
      }
    }
  },
  "fields": {
    "request.request_line": [
      "GET /.git/HEAD HTTP/1.1"
    ],
    "request.headers.User-Agent": [
      "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
    ],
    "transaction.local_port": [
      80
    ],
    "response.headers.Content-Type": [
      "text/html; charset=iso-8859-1"
    ],
    "response.headers.Connection": [
      "close"
    ],
    "http.url": [
      "/.git/HEAD"
    ],
    "request.headers.Connection": [
      "close"
    ],
    "transaction.local_address": [
      "10.0.2.4"
    ],
    "agent.type": [
      "filebeat"
    ],
    "response.headers.Content-Length": [
      "274"
    ],
    "agent.name": [
      "slingwayweb"
    ],
    "host.name": [
      "slingwayweb"
    ],
    "request.headers.Host": [
      "slingway.thm"
    ],
    "http.version": [
      "HTTP/1.1"
    ],
    "http.method": [
      "GET"
    ],
    "response.protocol": [
      "HTTP/1.1"
    ],
    "transaction.transaction_id": [
      "ZMEtOztcHeWClKRTMN1f3AAAAAA"
    ],
    "input.type": [
      "log"
    ],
    "log.offset": [
      16947
    ],
    "message": [
      "{\"transaction\":{\"time\":\"26/Jul/2023:14:27:07 +0000\",\"transaction_id\":\"ZMEtOztcHeWClKRTMN1f3AAAAAA\",\"remote_address\":\"10.0.2.15\",\"remote_port\":43442,\"local_address\":\"10.0.2.4\",\"local_port\":80},\"request\":{\"request_line\":\"GET /.git/HEAD HTTP/1.1\",\"headers\":{\"User-Agent\":\"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\",\"Connection\":\"close\",\"Host\":\"slingway.thm\"}},\"response\":{\"protocol\":\"HTTP/1.1\",\"status\":404,\"headers\":{\"Content-Length\":\"274\",\"Connection\":\"close\",\"Content-Type\":\"text/html; charset=iso-8859-1\"}},\"audit_data\":{}}"
    ],
    "agent.hostname": [
      "slingwayweb"
    ],
    "@timestamp": [
      "2023-07-26T14:27:08.138Z"
    ],
    "agent.id": [
      "2e8f766e-fd18-4a7e-b709-f730de06b7b4"
    ],
    "ecs.version": [
      "8.0.0"
    ],
    "transaction.remote_address": [
      "10.0.2.15"
    ],
    "log.file.path": [
      "/var/log/apache2/modsec_audit.log"
    ],
    "agent.ephemeral_id": [
      "ceecb9b4-2c4b-472b-96ca-e27ca9358fcb"
    ],
    "transaction.time": [
      "26/Jul/2023:14:27:07 +0000"
    ],
    "transaction.remote_port": [
      43442
    ],
    "agent.version": [
      "8.8.2"
    ],
    "response.status": [
      404 <-- Important Part!
    ]
  }
}
```

<u>Answer</u>:
```c
1867
```


- What is the `flag` under the interesting directory the attacker found?

<u>Filter</u>:
```c
transaction.remote_address: 10.0.2.15
response.status: 200
request.headers.User-Agent: Mozilla/5.0 (Gobuster)
```

![](/assets/img/Pasted image 20240422013656.png)

<u>Entries</u>:
```c
- /cart.php
- /about.php
- /
- /careers.php
- /contact.php
- /checkout.php
- /index.php
- /register.php
- /backups/?flag=a76637b62ea99acda12f5859313f539a
```

<u>Answer</u>;
```c
a76637b62ea99acda12f5859313f539a
```


- What login page did the attacker ***discover*** using the `directory enumeration tool`?
`Discover -> doesnt always mean attackers have access`?

Directory attackers didn't have access because it has been relocated:
![](/assets/img/Pasted image 20240422014637.png)

Webpage attacker didn't have access completely but was discovered:
![](/assets/img/Pasted image 20240422014736.png)

<u>Answer</u>:
```c
/admin-login.php
```

- What was the user agent of the brute-force tool that the attacker used on the admin panel?
![](/assets/img/Pasted image 20240422014954.png)

	- Attacker used hydra to bruteforce the php site


<u>Answer</u>:
```c
Mozilla/4.0 (Hydra)
```


- What `username:password` combination did the attacker use to gain access to the admin page?
![](/assets/img/Pasted image 20240422015109.png)

There are TWO event hits one for Hydra to check if the `username:password` combination is possible and one from Mozilla on Linux for actually logging in:
![](/assets/img/Pasted image 20240422015623.png)

**Note**: It says `admin page`:
![](/assets/img/Pasted image 20240422023018.png)

Full filter:
![](/assets/img/Pasted image 20240422023031.png)

<u>Answer</u>:
```c
admin:thx1138
```


- What flag was included in the file that the attacker `uploaded` from the `admin` directory?
![](/assets/img/Pasted image 20240422024124.png)

	- This is the file uploaded


`->` How can I see the contents of the file uploaded by the attacker?
- From the `POST` request that the attacker made, you can see the contents but NOT the actual file uploaded.
- Made a mistake of targeting the GET request shooting for the name of the file uploaded instead of the attacker's action of uploading it to the web server with the POST request.
![](/assets/img/Pasted image 20240422035205.png)

As you can see, there are THREE filters:
```c
1) transaction.remote_address: 10.0.2.15
2) http.method : POST
3) message : "*THM{*"
```

<u>Answer</u>:
```c
THM{ecb012e53a58818cbd17a924769ec447}
```




- What was the `first command` the attacker ran on the web shell?
```c
whoami
```


- What file location on the web server did the attacker extract database credentials from using **Local File Inclusion**?
![](/assets/img/Pasted image 20240422040656.png)

<u>Answer</u>:
```c
/etc/phpmyadmin/config-db.php
```


- What **`directory`** did the attacker use to access the `database manager`?
![](/assets/img/Pasted image 20240422040840.png)


<u>Answer</u>:
```c
/phpmyadmin
```


- What was the name of the database that the attacker **exported**?
![](/assets/img/Pasted image 20240422040921.png)

<u>Answer</u>:
```c
customer_credit_cards
```


- What flag does the attacker **insert** into the database?

Get the URIs for all possible mysql `insert` command:
![](/assets/img/Pasted image 20240422044345.png)

Use a URL Decoder:
![](/assets/img/Pasted image 20240422044259.png)

Find something that sticks out that doesn't seem to be related to credit cards:
```c
c6aa3215a7d519eeb40a660f3b76e64c
```


# Further Actions

After completing the log investigation, you can present confident findings that an attacker compromised the web server and database. You managed to follow the timeline of events, allowing for a clearer understanding of the incident and actions performed.

In response to this incident, Slingway Inc. should address the identified vulnerabilities promptly to enhance the security of its web server. Furthermore, the company should take appropriate steps to notify affected customers about the data breach and implement proactive security measures to mitigate future attacks.

Your investigation's comprehensive findings and actionable insights will enable Slingway Inc. to mitigate the damage caused by the compromised server, bolster its cyber security posture, and safeguard its customers' trust. Well done!

