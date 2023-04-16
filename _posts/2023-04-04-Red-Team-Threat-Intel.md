---
title: Red Team Threat Intel
date: 2022-12-30 12:00:00 -500
categories: [Red Team Operator, Red Team Fundamentals Theory]
tags: [TryHackMe]
---

# Intro

- ***Threat Intelligence*** or ***Cyber Threat Intelligence(CTI)*** is the information, or TTPs attributed to an adversary, commonly used by defenders to aid in detection measures.
- The `red cell` can leverage CTI from an offensive perspective to assist in adversary emulation.

### Learning Objectives
- Understand the basics of threat intelligence and how it can be applied to red team engagements.
- Learn how to create a threat-intel-driven campaign.
- Use frameworks to understand concepts and leverage threat intelligence.

--------
# What is Threat Intelligence
- Expanding upon task 1, CTI can be consumed (to take action upon data) by collecting IOCs and TTPs commonly distributed and maintained by ***Information and Sharing Analysis Centers***(ISAC).
- Intelligence platforms and frameworks also aid in the consumption of CTI, primarily focusing on an overarching timeline of all activities.

**Note:** the term ISAC means threat intelligence platform.

- Traditionally, defenders use threat intel to provide context to the ever-changing threat landscape and quantify findings.
- IOCs are quantified by traces left by adversaries such as domains, IPs, files, strings,etc.
- The blue team can utilize various IOCs to build detections and analyze behaviour.
- From a red team perspective, you can think of threat intel as the red team's analysis of the blue team's ability to properly leverage CTI for detections.

- In this room, we **focus on APTs activity** and how to leverage their documented TTPs.

---------
# Applying Threat Intel to the Red Team

- As previously mentioned, the red team will leverage CTI to aid in adversary emulation and support evidence of an adversary's behaviours.
- To aid in consuming CTI and collecting TTPs, red teams will often use threat intelligence platforms and frameworks such as MITRE ATTACK, TIBER-EU, and OST-map.


- These cyber frameworks will collect known TTPs and categorize them based on varying characteristics such as:

		- Threat Group
		- Kill Chain Phase
		- Tactic
		- Objective Goal

- Once a targeted adversary is selected, the goal is to identify ALL TTPs categorized with that chosen adversary and map them to a known ***cyber kill chain***.
- Leveraging TTPs is used as a *planning technique* rather than something a team will focus on during engagement execution.
- Depending on the size of the team, a CTI team or `threat intelligence operator` may be employed to gather TTPs for the red team.
- During the execution of an engagement, the red team will use threat intelligence` craft tooling`, `modify traffic and behaviour`, and `emulate the targeted adversary`.
- Overeall, the `red team consumes threat intel` to analyze and `emulate` the behaviours of adversaries through collected TTPs and IOCs.

---------
# The TIBER-EU Framework
- TIBER-EU (Threat Intel based Ethical Red Teaming) is a common framework developed by the European Central Bank that centers around the use of threat intel.
- From the **ECB TIBER-EU white paper**, "The Framework for Threat Intel-based Ethical Red Teaming(TIBER-EU)" enables european and national authorities to work with financial infrastructures and institutions (hereafter referred to collectively as 'entities') to put in place a program to **test and improve their resilience against sophisticated cyber attacks**.

![](/assets/img/Pasted image 20221129103550.png)

- The main difference between this framework and others is the **"Testing" phase** that requires threat intel to feed the red team's testing.
- This framework encompasses a best practice rather than anything actionable from a red team perspective.
- There are several public white papers and documents if you are interested in reading about this framework further:

		-   [https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf)
		-   [https://www.crest-approved.org/membership/tiber-eu/](https://www.crest-approved.org/membership/tiber-eu/)  
		-   [](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/pf/ms/sb-tiber-eu.pdf)[https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/pf/ms/sb-tiber-eu.pdf](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/pf/ms/sb-tiber-eu.pdf)

---------
# TTP Mapping

- TTP Mapping is employed by the red cell to map adversaries' collected TTPs to a standard cyber kill chain.
- Mapping TTPs to a kill chain aids the red team in planning an engagement to emulate an adversary.


- To begin the process of mapping TTPs, an adversary mut be selected as the target.
- An adversary can be chosen based on:

		- Target Industry
		- Employed Attack Vectors
		- Country of Origin
		- Other factors

- As an example for this task, we have decided to use **APT39**, a cyber-espionage group run by the Iranian ministry, known for targeting a wide variety of industries.
- We will be using the **Lockheed Martin Cyber Killchain** as our standard cyber kill chain to map TTPs:
![](/assets/img/Pasted image 20221129104700.png)

- The first cyber framework, we will be collecting TTPs from is **MITRE ATT&CK**.
- If you're not familiar with MITRE ATT&CK, it `provides IDs` and `descriptions of categorized TTPs`.
- For more information about MITRE and how to use ATT&CK , check out the MITRE room.


- ATT&CK provides a basic summary of a group's collected TTPs.
- We can use **ATT&CK Navigator** to help us `visualize` each TTP and categorize its place in the kill chain.
- Navigator visualizes the ATT&CK chain with the adversaries' designated TTPs highlighted under the corresponding sub-section.


- To use the ***ATT&CK Navigator*** : 

		- navigate to the groups summary page, next to "`Techniques used`"
		- Go to "ATT&CK Navigator Layers"
		- From the dropdown, navigate to "view"
		-> An ATT&CK Navigator Layer should have opened with the selected group's TTPs highlighted in a new tab.

<u>Link to the attack navigator</u>: `https://mitre-attack.github.io/attack-navigator/`

- Going through the Navigator layer, we can assign various TTPs we want to employ during the engagement.
- Below is a **compiled kill chain** with mapped TTPs for ***APT39***.

##### 1. **Reconnaissance**:
			- No identified TTPs , use internal team methodology
##### 2. **Weaponization**: 
			- Command and Scripting Interpreter
					- PowerShell
					- Python
					- VBA
			- User executed malicious attachments
##### 3. **Delivery**:
			- Exploit Public-Facing Applications
			- Spearphishing
##### 4. **Exploitation**:
			- Registry Modification
			- Scheduled Tasks
			- Keylogging
			- Credential Dumping
##### 5. **Installation**:
			- Ingress Tool Transfer : adversaries transferring tools from an external system to the victim's system like malware. (opposite of Living Off the Land)
			- Proxy usage
##### 6. **Command & Control**:
			- Web protocols (HTTP/HTTPS)
			- DNS
##### 7. **Actions on Objectives**:
			- Exfiltration over C2.

<u>Example Diagram</u>:
![](/assets/img/Pasted image 20221129205053.png)

- MITRE ATT&CK will do most of the work needed, but we can also supplement threat intel information with other platforms and frameworks.
- Another example of a TTP framework is **OST Map**:
![](/assets/img/Pasted image 20221129205218.png)

- OST Map provides a visual map to link multiple threat actors and their TTPs.
- Other open-source and enterprise threat intelligence platforms can aid red teamers in adversary emulation and TTP mapping such as:

		- Mandiant Advantage
		- Ontic
		- CrowdStrike Falcon

<u>Questions and Instructions</u>:

![](/assets/img/Pasted image 20221129210145.png)

![](/assets/img/Pasted image 20221129210221.png)

		- With this, you can easily emulate a threat actor!

![](/assets/img/Pasted image 20221129210413.png)

![](/assets/img/Pasted image 20221129210436.png)
...
![](/assets/img/Pasted image 20221129210446.png)
-> Remote Access Software and Bidirectional Communication

![](/assets/img/Pasted image 20221129210514.png)

![](/assets/img/Pasted image 20221129210526.png)
...
![](/assets/img/Pasted image 20221129210536.png)
...
![](/assets/img/Pasted image 20221129210547.png)
-> Rundll32!

![](/assets/img/Pasted image 20221129210640.png)

![](/assets/img/Pasted image 20221129210625.png)

--------
# Other Red Team Applications of CTI
- CTI can also be used during engagement execution, emulating the adversary's behavioural characteristic such as:

		- C2 Traffic:
				- User Agents
				- Ports, Protocols
				- Listener Profiles
		- Malware and Tooling
				- IOCs
				- Behaviours

- The **first behavioural** use of CTI we will showcase is ***C2 traffic manipulation***.
- A red team can use CTI to identify adversaries' traffic and modify their C2 traffic to emulate it.


- An example of a red team modifying C2 traffic based on gathered CTI is ***malleable profiles***.
- ***Malleable Profiles*** allows a red team operator to control multiple aspects of a C2's listener traffic.
- Information to be implemented in the profile can be gathered from ISACs and collected IOCs or packet captures including:

		- Host Headers
		- POST URIs
		- Server Responses and Headers

- The gathered traffic can aid a red team to make their traffic look similar to the targeted adversary ***`to get closer to the goal of adversary emulation`***.

- The **second behavioural** use of CTI is analyzing behaviour and actions of an adveraries' malware and tools to develop your offensive tooling that emulates similar behaviours or has similar vital indicators.

- An example of this could be an adversary using a ***custom dropper***. The red team can emulate the dropper by,

		- Identifying traffic
		- Observing syscalls and API calls
		- Identifying overall dropper behaviour and objective
		- Tampering with file signatures and IOCs.

#### Note: Not only you can re-create a malware from scratch based on high-level concepts but you can also emulate how it is being perceived.

-> Intelligence and tools gathered from ***behavioural threat intelligence*** can `aid` a red team in preparing the specific tools they will use to action planned TTPs.

---------
# Creating a Threat Intel Driven Campaign
- A threat-intel-driven campaign will take all knowledge and topics previously covered and combine them to create a `well-planned and researched campaign`.

- The task flow in this room logically follows the same path you would take as a red team to begin planning a campaign:

		1. Identify framework and general kill chain
		2. Determine targeted adversary (to emulate)
		3. Identify adversary's TTPs and IOCs
		4. Map gathered threat intelligence to a kill chain or framework
		5. Draft and maintain needed engagement documentation
		6. Determine and use needed engagement resources (tools, C2 modification, domains, etc.)

- In this task, we will be walking through a `red team's thought process` from beginning to end of planning a threat-intel-driven campaign.
- The hardest part of planning a `threat-intel-driven` campaign can be **mapping two different cyber frameworks**.
- To make this process simpler, we have provided a basic table comparing the **Lockheed Martin Cyber Kill Chain** and the **MITRE ATT&CK** framework.

![](/assets/img/Pasted image 20221129212617.png)

	- We use these two frameworks because the first one lets us see the engagement in a bird's eye view while the latter can help us see the trees in the forest.

- To begin working through this task, download the required resources and launch the static site attached to this task.
- Your team has already decided to use the Lockheed Martin cyber kill chain to emulate **APT41** as the adversary that best fits the client's objectives and scope.

<u>APT41's Mitre ATT&CK Framework</u>:
![](/assets/img/Pasted image 20221129215025.png)

<u>Questions</u>:
![](/assets/img/Pasted image 20221129215051.png)

![](/assets/img/Pasted image 20221129215101.png)

![](/assets/img/Pasted image 20221129215228.png)

![](/assets/img/Pasted image 20221129215236.png)

![](/assets/img/Pasted image 20221129220203.png)