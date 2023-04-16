---
title: Pivoting VI
date: 2022-06-06 12:00:00 -500
categories: [Pentesting,Pivoting]
tags: [Pentester Academy,Metasploit]
---

# Pivoting VI


- Used NMAP to scan which ports are open on the target machine.
- Used Hydra to bruteforce the credential for SSH using the given password wordlist.

**Skipping to the part where I create a pivot on the compromised machine**:

# Creating a Pivot using the compromised machine:
```bash
ssh -D 9050 root@{target-ip}
```

	- This port forwards all traffic to in this SSH session.
	- "-D" flag is claled dynamic port forwarding.
	- Note that the SSH session created with this command should be maintained otherwise, the tunnel will be broken and you won't be able to connect inside the internal network anymore where this compromised machine is connected as well.

**Without pivot using port forwarding in SSH**:

![](/assets/img/1618.png)

**With the pivot created using port forwarding in SSH**:

![](/assets/img/1619.png)

	- A new 'tunnel' via port 9050 is created. Note that you can use this with proxychains!
	- Now, any connection you make with port 9050 will be tunneled through the SSH session that you have maintained.

# How does Dynamic Port Forwarding works? Conceptual Approach:
- In this case, since we want to access a machine INSIDE an internal network which we normally wouldn't have any access to and creates a SOCKS proxy server in the client that allows us to tunnel our connection to the machine inside the internal network, this is called **Local Port Forwarding and Dynamic Port Forwarding**, respectively.

		- WAIT, in this box, the applied forwarding method is "Dynamic Port Forwarding". This is because although we know the ports that are open in the machine inside the internal network, creating a connection to the ports in this machine was not specified at all on the destination machine.
		- Also, on the client machine, a socket is created that acts as a SOCKS proxy server which when pass data to it, will then forward to the SSH session to the compromised web server which then gets forwarded again on the internal network to a "dynamic" port in the destination machine.

**Here's a good diagram**:

![](/assets/img/1620.png)

	- However in this digram, it uses Local port forwarding, the scenario is pretty much the same. THe only thing that is different is that we don't know any other port we can connect to in the "faraway host" but from this diagram, it seems that the author knows one which is why Dynamic Port Forwarding is used.

**Reference to this diagram + in depth guide on Local and Remote Port forwarding with diagrams**:
- https://pswalia2u.medium.com/ssh-tunneling-port-forwarding-pivoting-socks-proxy-85fb7129912d

3. Doing a GET request using curl:

```bash
proxychains curl http://{target-ip}
```

![](/assets/img/1621.png)

	- Seems like Clipper is the software that is used again. We can use the same exploit as the one from "Pivoting IV" lab.

4. Applying the ClipperCMS exploit from "Pivoting IV" lab:

![](/assets/img/1622.png)

	- Notice that I also used the same credentials for this software again as the one from "Pivoting IV" lab but in real pentest with the same software exploit, you may want to bruteforce it.

5. Getting the flag:

```bash
find / -name *flag*
```

![](/assets/img/1623.png)


