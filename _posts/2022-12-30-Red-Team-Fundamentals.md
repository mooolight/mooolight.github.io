---
title: Red Team Fundamentals
date: 2022-12-30 12:00:00 -500
categories: [Red Team Operator, Red Team Fundamentals Theory]
tags: [TryHackMe]
---

----------
# Intro

- Cybersecurity is a `constant` race between `white hat hackers` and `black hat.`

		- Arms race.

- As threats in the cyber-world evolve, so does the need for more specialized services that allow companies to prepare for real attacks the best they can.

- While conventional security engagements like vulnerability assessments and pentests could provide an excellent overview of the technical security posture of a company, they might overlook some other aspects that a real attacker can exploit.

		- Basically, they want the red team to act like real adversaries and do what actual adversaries will do based on the engagement.
		- This is the main difference between pentesters and red teamers is that the latter will go through lengths that the former won't.

- In that sense, we could say that conventional pentests are good at `showing vulnerabilities` so that you can take `proactive measures` but might not teach you how to respond to an actual ongoing attack by a motivated adversary.

		- Pentesters are the people that proves the vulnerability found during the vulnerability assessments are actually there or if its a false positive.

### Objectives
- Learn about the basics of red team engagements
- Identify the main components and stakeholders involved in a red team engagement.
- Understand the main differences between red teaming and other types of cybersecurity engagements.


### Room Prerequisites
- Before beginning this room, familiarity with general hacking techniques is required.

----------
# Vulnerability Assessments and Pentests Limitations

## Vulnerability Assessments
- This is the simplest form of security assessment, and its main objective is to identify as many vulnerabilities in as many systems in the network as possible.

		- Note that this can be either automated or manually done by pentesters.

- To this end, `concessions` may be made to meet this goal effectively. 
- For example, the attacker's machine(not an actual threat actor) may be `allowlisted` on the available security solutions to avoid interfering with the vulnerability discovery process.
- This makes sense since the objective is to look at `every host` on the network and evaluate its security posture `individually` while providing the most information to the company about where to focus its `remediation` efforts.

		- So whichever host contains the crucial information there is in an organization, the urgent the remediation on that host it is.

- To summarize, a vulnerability assessment focuses on `scanning hosts for vulnerabilities` as individual entities so that security deficiencies can be `identified` and effective security measures can be deployed to protect the network in a `prioritized manner`.

		- Note that this phase is mostly done with automated softwares like Nessus.

- Most of the work can be done with automated tools and performed by operations without requiring much technical knowledge. (`Nessus` exactly.)

<u>Example</u>: We scan the network for vulnerabilities but we `don't` exploit it if we found them.
![](/assets/img/Pasted image 20221128173811.png)

# Penetration Tests

- On top of scanning every single host for vulnerabilities, we often need to understand how they impact our network `as a whole`.

		- Note that an attacker could just find one vulnerable machine in the network and pivot to other machine which could be prevented had the vulnerable machine been patched.

- Pentests `add` to vulnerability assessments by allowing pensters to explore the impact of an attacker on the overall network by doing additional steps that include:

		- Attempt to exploit the vulnerabilities on each system.
		- This is important as sometimes a vulnerability might exist in a system, but compensatory controls in place effectively prevent its exploitation.
		- It also allows us to test if we can use the detected vulnerabilities to compromise a given host.

		-> So at this point, we are considering the action actors might take upon stumbling a vulnerability on a host found in the network.

		- Conduct a 'post-exploitation' tasks on ANY compromised host, allowing us to find if we can extract any helpful information from them or if we might use them to 'pivot' to other hosts that were not previously accessible from where we stand.

- Penetration tests might start by scanning vulnerabilities just as a regular vulnerability assessment but provide further information on `how an attacker can "chain" vulnerabilities to achieve specific goals`.

		- Note that to have initial access on the vulnerable host, an attacker is exploiting a vulnerability from the outside.
			-> However, if an attacker got in but has low privilege (which is by default), it might want to escalate its privilege by exploiting another vulnerability AGAIN that exists on the host's environment. Note that the latter vulnerability DOES NOT exists on the host's environment but from its 'exterior surface'.
			-> You can imagine the former vulnerability as a gap on the force field created so you won't be able to access the building. Because of this gap, you are able to scooch in to the force field and getting into the building's perimeter. The latter vulnerability is kind of like the broken window in the building that was just covered with tape. If this is the case, you only need a scissor at the least to get into the building which provides the attacker more access to resources.

- While its focus remains on `identifying vulnerabilities` and establishing measures to protect the network, it also considers the network as a `whole ecosystem` and how an attacker could profit from interactions between its components.

		- The attacker would want to know how each entity in the system is interconnected. Are there hosts that are not connected with one another? Are there hosts that is connected to some other hosts but is not visible? Are there implications of a hidden host? etc.

- If we were to perform a pentest using the same example as before, on top of scanning all of the hosts on the network for vulnerabilities, we would try to confirm if they can be exploited in order to show the impact an attacker could have on the network:

![](/assets/img/Pasted image 20221128175449.png)

	- In this example, there are 3 vulnerabilities present:
	1. Server's vulnerability from SQLi
	2. User Alice's bad password complexity.
	3. The organization's vulnerable FTP server.

- By analyzing how an attacker could move around our network, we also gain a basic insight on possible security measure bypasses and our ability to detect a real threat actor to a certain extent, limited because the scope of pentest is usually extensive and `pentesters don't care much about being loud` or generating lots of alerts on security devices since `time constraints` on such projects often requires us to check the network in a `short time`.

------------
# Advanced Persistent Threats and why regular Pentesting is NOT enough

- While the conventional security engagements we have mentioned cover the finding of most technical vulnerabilities, there are limitations on such processes and the extent to which they can effectively prepare a company against a real attacker. Such limitations include:

![](/assets/img/Pasted image 20221128180105.png)

- As a consequence, some aspects of penetration tests might significantly differ from a real attack, like:

- Pentests are loud because they are asked to find as many vulnerabilities as they can for a limited amount of time. Also, they ignore security mechanisms in place and won't make an effort to hide themselves.
- Non-technical attack vectors might be overlooked: physical intrusions and social engineering is mostly out of scope for pentesters.
- **Relaxation of Security Mechanisms** : for the pentesters to have an efficient work, the defense of the network is sometimes lifted because the focus is on reviewing `critical technological infrastructure` for vulnerabilities.


- However, there are real attackers who won't follow any ethical code and most of their actions are unrestricted. They are called **Advanced Persistent Threats**.
- These kind of hackers are highly skilled which are mostly nation-state sponsored or organized crime groups.

What do they target:

		- Critical Infrastructure like water supply, food,etc.
		- Financial Organizations (banks)
		- Gov't Institutions


- They are called **Persistent** because they can stay on compromised network for a long period of time.
- If a company is affected by an `APT`, would it be prepared to respond effectively?
- Could they detect the methods used to gain and maintain access on their networks if the attacker has been there for several months?
- What if the initial access was obtained because John at accounting opened a suspicious email attachment?
- What if a `0-day` exploit was involved?
- Do previous pentests prepare us for this?
- To provide a more realistic approach to security, red team engagements were born.

---------------
# Red Team Engagements
- To keep up with the emerging threats, red team engagements were designed to shift the focus from regular pentests into a process that allows us to clearly see our defensive team's capabilities at `detecting` and `responding` to a real threat actor.
- They don't replace traditional pentests but `complement them by focusing on detection and response` rather than prevention (which is the focus for pentesters).


- **Red Teaming** is a term borrowed from the military. In military exercises, a group would take the role of a red team to simulate attack techniques to test the reaction capabilities of a defending team, generally known as `blue team`, against `known` adversary strategies.

		- Can't emulate threat actors if you don't know how they operate.

- Translated into the world of cybersecurity, red team engagements consist of emulating a real threat actor's **Tactics, Techniques and Procedures (TTPs)** so that we can measure how well our blue team responds to them and ultimately improve any security controls in place.

		- So Red teams can emulate certain threat groups so check whether there are threat groups that the blue team can't defend on.

- Every red team engagement will start by defining clear goals, often referenced as `crown jewels or flags`, ranging from compromising a given critical host to stealing some sensitive information from the target.

- Usually, the blue team won't be informed of such exercises to avoid introducing any biases in their analysis.

		- Blue team would have to defend black-boxed as if they are really expecting threat actors.

- The red team will do everything they can to achieve the goals `while remaining undetected and evading any existing security mechanisms` like:

		- Firewall (pfsense,palo alto firewall,etc.)
		- AVs (McAffee, Microsoft Defender,etc.)
		- EDRs
		- IPS (Snort,Suricata,etc.)
		- etc.

- Notice how on a red team engagement, **not all** of the hosts on a network will be checked for vulnerabilities.
- A real attacker would `only need to find a single path to its goal` and is not interested in performing noisy scans that the blue team could detect.

		- How else can they find that 'path' if they aren't scanning?

- Taking the same network as before, on a red team engagement where the `goal is to compromise the intranet server`, we would plan for a way to reach our objective `while interacting as little as possible with other hosts`.

		- Less pivoting is being done?
		- No scanning as well.

- Meanwhile, the blue team's capacity to detect and respond accordingly to the attack can be evaluated:

![](/assets/img/Pasted image 20221128182958.png)

- It is important to note that the final objective of such exercises should never be for the red team to `beat` the blue team.
- But rather, `simulate enough TTPs` for the blue team to learn to react to a real ongoing threat adequately.
- If needed, they could tweak or add security controls that help to improve their detection capabilities.

		- The goal of the red team(proactive) is to constantly challenge the blue team(reactive).

- Red Team Engagements also improve on regular penetration tests by considering several attack surfaces:

		- Technical Infrastructure : red team uncovers techincal vulnerabilities that has emphasis on evasion and stealth.
		- Social Engineering : targets people with phishing campaigns, phone calls or social media
		- Physical Intrusion : using techniques like Lockpicking, RFID cloning, exploiting weaknesses in electronic access control devices to access restricted areas of facilities.

- How are red team exercises executed?

		- "Full Engagement" : simulate a threat actor's full workflow from initial compromise until the end.
		- "Assumed Breach" : there is a starting point inside the target network
		- "Table-top Exercise" : an over the table simulation where scenarios are discussed between the red and blue team to evaluate how they would theoretically respond to certain threats. Ideal for situations where doing live simulations might be complicated. Its like a high-level 'debate' between red and blue teams. So pretty much like chess.

-------------
# Teams and Functions of an Engagement
- There are several factors and people involved within a red team engagement.
- Everyone will have their mindset and methodology to approach the engagement personnel; 
- However, each engagement can be broken into three teams or cells.
- Below is a brief illustration of each teams and brief explanation of their responsibilities:

![](/assets/img/Pasted image 20221128184750.png)

		- ROE : Rules of Engagement

Links for red team definitions: https://redteam.guide/docs/definitions/

- These teams or cells can be broken down further into an engagement hierarchy:
![](/assets/img/Pasted image 20221128185115.png)

**Roles and responsibilities of each member of the red team**:
![](/assets/img/Pasted image 20221128185157.png)

------------
# Engagement Structure

- A core function of the red team is `adversary emulation`.
- While `not mandatory`, it is commonly used to assess what a real adversary would do in an environment using their tools and methodologies.
- The red team can use various `cyber kill chains` to summarize and assess the steps and procedures of an engagement.


- Many regulation and standardization bodies have released their cyber kill chain but we mainly use the `Lockheed Martin` one:

		-   [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
		-   [Unified Kill Chain](https://unifiedkillchain.com/)
		-   [Varonis Cyber Kill Chain](https://www.varonis.com/blog/cyber-kill-chain/)
		-   [Active Directory Attack Cycle](https://github.com/infosecn1nja/AD-Attack-Defense)
		-   [MITRE ATT&CK Framework](https://attack.mitre.org/)

- The `LockHeed Martin kill chain` focuses on a `perimeter` or `external breach`.
- Unlike other kill chains, it does NOT provide an in-depth breakdown of internal movement.
- This is basically the summary:

![](/assets/img/Pasted image 20221128190320.png)

---------
# Overview of Red Team Engagement
- See the website.

-------
# Quizlet

##### 1. What is the main difference between a red teamer and a pentester? Submit a paragraph answer. To do this, google it and find different answers from different sources and extract the common denominator from these sources.
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
```
    Red teamers focus more on objectives called "`Crown Jewels`" rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
```
</p>
</details>

##### 2. What kind of vulnerability assessments exists in a security audit?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 3. What exactly is being done during this assessment? Who does this kind of scanning?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 4. Are there difference in how red team attack the organization's network in comparison with how APTs does it?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 5. Why is it called **Persistent** in the first place?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 6. What signs do we have to look for to figure out if we are being targeted by APTs?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 7. How different red teamers are exactly in comparison with pentesters?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 8. What things can red-teamers cover the gap of pentesters?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 9. How does red and blue teams interact during engagements?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 10. What weakness(es) do red teams have that will have a huge impact to blue team’s defense as a whole?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 11. Explain the engagement hierarchy.
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 12. What are the cells in a red team engagement?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 13. For red team roles, enumerate each of them and describe what their roles are.
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 14. Enumerate each phase in the Lockheed martin kill chain.
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 15. What is the main difference between this kill chain and all others?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>

##### 16. How do red teamers use this?
<details>
<summary><mark><font color=darkred>One Possible Answer:</font></mark>
</summary>
<p>
- Red teamers focuses more on objectives rather than exploiting vulnerabilities found in the system. Pentester on the other hand focuses on a given scope and tries to find vulnerability on the given scope.
</p>
</details>
 
-----