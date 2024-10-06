---
title: Snort Live Attacks
date: 2024-06-06 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---


First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

<u>Commands to capture the attack</u>:

```c
sudo snort -X
```

<u>Output</u>:

![](/assets/img/Pasted image 20240304122701.png)

<u>Attacker IP, port</u>:

```c
- 10.10.245.36:46478
```

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:
- Create the rule and test it with "`-A console`" mode. 
- Use **"`-A full`"** mode and the **`default log path`** to stop the attack.
- Write the correct rule and run the Snort in IPS "`-A full`" mode.
- Block the traffic at least for a minute and then the flag file will appear on your desktop.


<u>Rule Created</u>: (add this to `/etc/snort/rules/local.rules`)

```c
drop tcp any any <> 10.10.140.29 22 (msg:"Brute Force attack detected_request"; sid:10000000001; rev:1)
drop tcp 10.10.140.29 22 <> 10.10.245.36 46482 (msg:"Brute Force attack detected_response"; content:"ssh"; sid:10000000002; rev:1)
```

![](/assets/img/Pasted image 20240304133517.png)

<u>Testing</u>:

```c
sudo snort -c /etc/snort/rules/local.rules -A console -l .
```

<u>Commands to read the captured packets</u>:
```c
sudo snort -c /etc/snort/rules/local.rules -A full -l .
```

```c
sudo snort -r snort.log.<num> -X -d -n 20
```


Stop the attack and get the flag (which will appear on your Desktop)

```c
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console
```

![](/assets/img/Pasted image 20240304135326.png)

	- Different ports and IP from the attacker are being used on the brute force attack
	- Note, you have to use the /etc/snort/rules/local.rules since it works with /etc/snort/snort.conf to DROP the packets.


What is the name of the service under attack? 
- `SSH`

What is the used protocol/port in the attack?
- `tcp/22`

----------------
# Scenario 2 : Reverse-Shell

First of all, start Snort in sniffer mode and try to figure out the attack source, service and port. 

```c
sudo snort -X
```

##### Log Analysis
- Important IP address and Port numbers:

```c
- 10.10.196.55:54242 (victim''s)
- 10.10.144.156:4444 (attackers)
```

##### Pattern Analysis

![](/assets/img/Pasted image 20240304141008.png)

	- Notice that there are different ports used to connect to the attacker's machine. Most likely for persistence.


##### Packet Analysis

<u>Outputs and clues</u>:

![](/assets/img/Pasted image 20240304140536.png)

	- This is the shell on the victim's machine from the attacker's perspective.

- This one shows the directories inside the VM:

![](/assets/img/Pasted image 20240304140615.png)

	- Notice the direction of the connection. It sends data to the 10.10.144.156

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

<u>Rule Created</u>:

```c
drop tcp 10.10.144.156 4444 <> any any (msg:"RevShell detected outbound dropped";sid:1000000001;rev:1;)
drop tcp any any <> 10.10.144.156 (msg:"RevShell detected inbound dropped";sid:10000000002;rev:1;)
```

Here are a few points to remember:

- Create the rule and test it with "`-A console`" mode. 
- Use "`-A full`" mode and the default log path to stop the attack.
- Write the correct rule and run the Snort in IPS "`-A full`" mode.
- Block the traffic at least for a minute and then the flag file will appear on your desktop.

Stop the attack and get the flag (which will appear on your Desktop)

<u>Testing</u>:
```c
sudo snort -c /etc/snort/rules/local.rules -A console -l .
```

<u>Commands to read the captured packets</u>:
```c
sudo snort -c /etc/snort/rules/local.rules -A full -l .
```

```c
sudo snort -r snort.log.<num> -X -d -n 20
```


Stop the attack and get the flag (which will appear on your Desktop)
```c
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console
```

![](/assets/img/Pasted image 20240304141940.png)

	- Use '-A full' to get the flag

What is the used protocol/port in the attack? `tcp/4444`


Which tool is highly associated with this specific port number? `metasploit`







