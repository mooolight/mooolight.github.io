---
title: Red Team OPSEC
date: 2022-12-30 12:00:00 -500
categories: [Red Team Operator, Red Team Fundamentals Theory]
tags: [TryHackMe]
---

# Intro

- Operations Security (OPSEC) is a term coined by the US military.
- In the field of cybersec, let's start with the definition provided by NIST:

		Systematic and proven process by which potential adversaries can be denied information about capabilities and intentions by identifying, controlling and protecting generally unclassified evidence of the planning and execution of sensitive activities.
		The process involves five steps: identification of critical information, analysis of threats, analysis of vulnerabilities, assessment of risks, and application of appropriate countermeasures.


- Let's dive into the definition from a red team perspective.
- As a red team member, your potential adversaries are the blue team and third parties.
- The blue team is considered an adversary as we are attacking the systems they hired to monitor and defend.
- Red vs. blue team exercises are common to help an organization understand what threats exist in a given environment and better prepare their blue team if a real malicious attack occurs.
- As red teamers, even though we are abiding by the law and authorized to attack systems within a defined scope, it does not change the fact that we are acting against the blue team's objectives and trying to circumvent their security controls.
- The blue team wants to protect their systems, while we want to penetrate them.


- Denying any potential adversary the ability to gather information about our capabilities and intentions is critical to maintaining OPSEC.
### - OPSEC is a process to identify, control and protect any information related to the planning and execution of our activities.
- Frameworks such as Lockheed Martin's Cyber Kill Chain and MITRE ATT&CK help defenders identify the objectives an adversary is trying to accomplish.
- MITRE ATT&CK is arguably at the forefront of reporting and classifying adversary tactics, techniques and procedures (TTPs) and offers a publicly accessible knowledge base as publicly available threat intelligence and incident reporting as its primary data source.

![](/assets/img/Pasted image 20221129221141.png)

- The OPSEC process has five steps:

		1. Identify critical information
		2. Analyze threats
		3. Analyze vulnerabilities
		4. Assess risks
		5. Apply appropriate countermeasures

![](/assets/img/Pasted image 20221129221316.png)

- If the adversary discovers that you are scanning their network with NMAP (the blue team in our case), they should easily be able to discover the IP address used.
- For instance, if you use the same IP to host a phishing site, it won't be very difficult for the blue team to connect the two events and attribute them to the same actor.
- OPSEC is NOT a solution or a set of rules.
- OPSEC is a five-step process to **deny adversaries** from gaining access to any critical information (defined in Task 2). We will dive into each step and see how we can improve OPSEC as part of our red team operations.

----------
# Critical Information Identification

- What a red teamer considers critical infromation worth protecting depends on the operation and the assets or tooling used.
- In this setting, critical information includes, but is not limited to, the red team's intentions, capabilities, activities and limitations.
- Critical information includes any information that, once obtained by the blue team, would hinder or degrade the red team's mission.

![](/assets/img/Pasted image 20221130091107.png)

- To identify critical information, the red team needs to use an adversarial approach and ask themselves what information an adversary, the blue team in this case, would want to know about the mission.
- If obtained, the adversary will be in a solid position to thwart the red team's attacks.
- Therefore, critical information is NOT necessarily sensitive information; however, it is any information that might jeopardize your plans if leaked to an adversary.

<u>Examples</u>:

- Client information that your team has learned

		- It's unacceptable to share client specific information such as employee names, roles and infrastructure that your team has discovered.
		- Sharing this type of information should kept on need-to-know basis as it could compromise the integrity of the operation.
		- The Principle of Least privilege dictates that any entity (user or process) must be able to access only the information necessary to carry out its task.
		- PoLP should be applied in every step taken by the Red Team.

- Red team information such as identities, activities, plans, capabilities and limitations. The adversary can use such information to be better prepared to face your attacks.

- Tactics, Techniques and Procedures (TTPs) that your team uses in order to emulate an attack.

- OS, cloud hosting provider, or C2 framework utilized by your team. Let's say that your team uses **Pentoo** for pentesting and the defender knows this. Consequently, they can keep an eye for logs exposing the OS as Pentoo. Depending on the target, there is a possibility that other attackers are also using Pentoo to launch their attacks; however, there is no reason to expose your OS if you don't have to.

- Public IP address that your red team will use. If the blue team gains access to this kind of information, they could quickly mitigate the attack by blocking all inbound and outbound traffic to your IP addresses, leaving you to figure out what has happened.

- Domain names that your team has registered. Domain names play a significant role in attacks such as phishing. Likewise, if the blue team figures out the domain names you will be using to launch your attacks, they could simply block or sinkhole your malicious domains to neutralize your attack.

- Hosted websites, such as phishing websites for adversary emulation.

<u>Questions</u>:
![](/assets/img/Pasted image 20221130092302.png)

	- 1st: its not since its a commonly used browser.
	- 2nd: it is since not many people use this type of browser.
	- 3rd: its not since its a commonly used OS.
	- 4th: it is since its obvious that this OS is used for this kind of purpose.
	- 5th: Yes. Once this is blocked, any phishing attack related to this domain name won't work.

------
# Threat Analysis

- After we identify critical information, we need to analyze threats.
- ***Threat Analysis*** : identifying potential adversaries and their intentions and capabilities.
- Adapted from US DoD OPSEC program manual: Threat analysis aims to answer the following questions:

		1. Who is the adversary?
		2. What are the adversary's goals?
		3. What tactics, techniques, and procedures does the adversary use?
		4. What critical information has the adversary obtained, if any?

![](/assets/img/Pasted image 20221130092618.png)

- The task of the red team is to `emulate` an actual attack so that the `blue team discovers its shortcomings`, if any, and becomes better prepared to face incoming threats.
- The blue team's main objective is to ensure the security of the organization's network and systems.
- The intentions of the blue team are clear; they want to keep the red team out of their network. Consequently, considering the task of the red team, the blue team is considered our adversary as each team has conflicting objectives.

**Note: Blue team's capabilities might NOT always be known at the beginning.**

- Malicious third-party players might have different intentions and capabilities and might pose a threat as a result.
- This party can be someone with humble capabilities scanning the systems randomly looking for low-hanging fruit (`bug bounty hunters or not`), such as unpatched exploitable server. or it can be a capable adversary targeting your company or client systems.
- Consequently, the intentions and the capabilities of this third party can make them an adversary as well.

![](/assets/img/Pasted image 20221130095634.png)
-> We consider any adversary with the intent and capability to take actions that would prevent us from completing our operation as a threat:

`threat = adversary * intent + capability`

- In other words, an adversary without an intent or capability does NOT pose a threat for our purposes.

-----------
# Vulnerability Analysis
- After identifying critical information and analyzing threats, we can start with the third step: analyzing vulnerabilities.
- This is not to be confused with vulnerabilities related to cybersecurity.
- An **OPSEC vulnerability** exists when an adversary can obtain critical information, analyze the findings, and act in a way that would affect your plans.

![](/assets/img/Pasted image 20221130100013.png)

- To better understand an OPSEC vulnerability as related to red teaming, we'll consider the following scenario.

		- You use NMAP to discover live hosts on a target subnet and find open ports on live hosts.
		- Moreover, you send various phishing emails leading the victim to a phishing webpage you're hosting.
		- Furthermore, you're using Metasploit framework to attempt to exploit certain software vulnerabilities.

#### - These are three separate activities: however, if you use the same IP address(es) to carry out these different activities, this would lead to an OPSEC vulnerability.
-> This is because after the first action, you might not be able to do the 2nd and 3rd because they will get blocked after the first one.

	- Once any hostile/malicious activity is detected, the blue team is expected to take action, such as blocking the source IP address(es) temporarily or permanently.
	- Consequently, it would take one source IP address to be blocked for all the other activities use this IP address to fail.
	- In other words, this would block access to the destination IP address used for the phishing server, and the source IP address using NMAP and Metasploit framework.

<u>Analogy</u>:
- A sniper shoots once and switches position every shot so as to not reveal its position to its enemies for future attacks.

- Another example of an OPSEC vulnerability would be:

		- Unsecured database that's used to store data received from phishing victims.
		- If the database is not properly secured, it may lead to a malicious third party compromising the operation and could result in data being exfiltrated and used in an attack against your client's network.
		- As a result, instead of helping your client secure their network, you would end up helping expose login names and passwords.

- Lax OPSEC could also result in less sophisticated vulnerabilities.
- For instance, consider a case where one of your red team member posts on social media revealing your client's name.
- If the blue team monitors such information, it will trigger(**google alert?**) them to learn more about your team and your approaches to better prepare against expected penetration attempts.

<u>Questions</u>:
![](/assets/img/Pasted image 20221130101233.png)

![](/assets/img/Pasted image 20221130101245.png)

![](/assets/img/Pasted image 20221130101253.png)

![](/assets/img/Pasted image 20221130101312.png)

-----------
# Risk Assessment

- We finished analyzing the vulnerabilities, and now we can proceed to the fourth step: **conducting risk assessment**.
- NIST defines a risk assessment as:

		- "The process of identifying risks to organizational operations (including mission,functions, image,reputation), organizational assets, individuals, other organizations, and the Nation, resulting from the operation of an information system."

- In OPSEC, risk assessment requires learning the possibility of an event taking place along with the expected cost of that event.
- Consequently, this involves `assessing the adversary's ability to exploit the vulnerabilities`.

- Once the level of risk is determined, countermeasures can be considered to mitigate that risk. We need to consider the followign three factors:

		1. The efficiency of the countermeasure in reducing the risk.
		2. The cost of the countermeasure compared to the impact of the vulnerability being exploited.
		3. The possibility that the countermeasure can reveal information to the adversary.

- Let's revisit the two examples from the previous task.
- In the first example, we considered the vulnerability scanning of network with NMAP, using the Metasploit framework, and hosting the phishing pages using the same public IP address.
- We analyze that this is a vulnerability as it makes it easier for the adversary to block our three activities by simply detecting one activity.
- Now let's assess this risk.
- To evaluate the risk related to this vulnerability, we need to ***learn the possibility of one or more of these activities being detected***.
- We cannot answer this without obtaining some information about the adversary's capabilities.
- Let's consider the case where the client has a `Security Information and Event Management System (SIEM)` in place.
- SIEM: system that allows real-time monitoring and analysis of events related to security from different sources across the network.
- We can expect that a SIEM would make it reasonably uncomplicated to detect suspicious activity and connect the three events.
- As a result, we would assess the related risk as high.
- On the other hand, if we know that the adversary has minimal resources for detecting security events, we can assess the risk related to this vulnerability is low.


- Let's consider the `second example` of an **unsecured database** used to store data received from a phishing page.
- Based on data collected from several research groups using honeypots, we can expect various malicious bots to actively target random IP addresses on the internet.
- Therefore, it is only a matter of time before a system with weak security is discovered and exploited.

![](/assets/img/Pasted image 20221130104255.png)

	-> You are more vulnerable to the IDS since it can connect the two incidents.

----------
# Countermeasures

- Definition by the US DoD: 

		- designed to prevent an adversary from detecting critical information, provide an alternative interpretation of critical information or indicators (deception), or deny  the adversary's collection system.

- Let's revisit the two examples we presented in the Vulnerability Analysis task.
- First example countermeasure: use different IP addresses on different operations
- 2nd example counter: secure the databased adequately so no 3rd parties would be able to access it.

------
# More Practical Examples

- In this task, we apply the five elements of the OPSEC process as we focus on different examples of critical information related to red team tasks. Steps:

		- Identify critical information
		- Analyze threats
		- Analyze vulnerabilities
		- Assess risk
		- Apply appropriate countermeasures

### Programs/OS/VM used by the red team
- **Critical information** : We are talking about the programs, the OS and the VM together.
- **Threat Analysis**: the blue team is looking for any malicious or abnormal activity on the network. Depending on the service we're connecting to, it's possible that the name and the version of the program we're using, and the OS version and VM hostname could be logged.
- **Vulnerability Analysis** : if the OS chosen for the given activity is too unique, it could make it easier to link activities back to your operation. The same applies to VMs with hostnames that stand out. For instance, on a network of physical laptops and desktops, if a new host joins with the hostname `kali2021vm`, it should be easy to spot by the blue team. Likewise, if you use various security scanners or for instance you don't use a common user agent for web-based activities.
- **Risk Assessment** : The risk mainly depends on which services we're connecting to. For instance, if we sstart a VPN connection, the VPN server will log plenty of information about us. The same applies to other services to which we might connect.
- **Countermeasures** : If the OS we are using is uncommon, it would be worth the effort to make the necessary changes to camouflage our OS as a different one. For VMs and physical hosts, it's worth changing the hostnames to something inconspicuous or consistent with the client's naming convention, as you don't want a hostname such as **AttackBox** to appear in the DHCP server logs. As for programs and tools, it is worth learning the signatures that each tool leaves on the server logs.

<u>Example</u>:  The figure below shows the `User-Agent` that will be logged by the remote web server when running NMAP scans with the `-sC` option when NMAP probes the web server. If an HTTP user agent isn't set at the time of running the given NMAP script, the logs on the target system could log a user agent containing `NMAP Scripting Engine`. This can be mitigated using the option `--script-args http.useragent="CUSTOM_AGENT"`:

![](/assets/img/Pasted image 20221130144646.png)

![](/assets/img/Pasted image 20221130150105.png)

![](/assets/img/Pasted image 20221130150738.png)

![](/assets/img/Pasted image 20221130150755.png)

![](/assets/img/Pasted image 20221130150809.png)

![](/assets/img/Pasted image 20221130150821.png)

![](/assets/img/Pasted image 20221130150112.png)









