---
title: Analyzing Volatile Memory
date: 2024-08-01 00:00:00 -500
categories: [SOC L1, Digital Forensics and Incident Response]
tags: [TryHackMe]
---



# Introduction

  
In the Windows OS, volatile memory stores data currently accessed or manipulated by the operating system or the user. It is termed volatile due to its transient nature. This memory type is characterized by the temporary retention of data, which is removed upon system shutdown or restart.

In this Room, we will discuss various ways Microsoft OS manages its volatile memory apart from the RAM.

### Learning Objectives

In this Room, we will cover the following learning objectives:

```c
- How Windows Manages Volatile Memory
- Overview of PageFile and how to examine the pagefile
- How a volatile memory is stored once the system is hybernated.
- How to explore the Crash dump.
```


### Data Collection

There are three ways or options to collect data using Redline:

![](/assets/img/Pasted image 20240807192155.png)

Standard Collector: gathers the minimum amount of data for analysis and is the preferred method for this room. It takes only a few minutes to complete.

```c
- 'Comprehensive Collector': gathers the most data for further analysis and takes up to an hour or more.
- 'IOC Search Collector (Windows only)': collects data that matches with the IOCs created in IOC Editor. It is used to run the data collection against known
```

IOCs gathered through threat intelligence, incident response, or malware analysis.
In this task, we will be using the Standard Collector method.

```c
- From Redline, click on 'Create a Standard Collector'.
- You will have an option to choose the target platform. In our case, we will select Windows.
```

![](/assets/img/Pasted image 20240807221758.png)


- Under the Review Script Configuration, click on `Edit your script`:


![](/assets/img/Pasted image 20240807221849.png)


<u>Redline Script Configuration</u>:


![](/assets/img/Pasted image 20240807221908.png)

![](/assets/img/Pasted image 20240807221926.png)

![](/assets/img/Pasted image 20240807221936.png)

- Click OK. And then click on “`Browse`” under “`Save Your Collector To`”.

- You will need to create a folder where your analysis file will be saved and the script for collecting the data you need.

- In the folder, run the “`RunRedlineAudit`” script as Administrator to collect the data we need. This will automatically open a command prompt window; It will close automatically (15–20 mins) when the data collection process finishes.


###### Questions:
- What data collection method takes the least amount of time?
-> Standard Collector

- You are reading a research paper on a new strain of ransomware. You want to run the data collection on your computer based on the patterns provided, such as domains, hashes, IP addresses, filenames, etc. What method would you choose to run a granular data collection against the known indicators?
-> IOC Search Collector

- What script would you run to initiate the data collection process? Please include the file extension. 
-> RunRedlineAudit.bat

- If you want to collect the data on Disks and Volumes, under which option can you find it? 
-> Disk Enumeration

- What cache does Windows use to maintain a preference for recently executed code? 
-> Prefetch

------------------------------------------------------------------------------------------------------------------------
# The Redline Interface

Let's look at the Redline Interface.

You should have your first analysis file. Double-click on the `AnalysisSession1.mans` file and the data will be imported automatically into Redline. Please give it up to 10 minutes to get the data imported.

![](/assets/img/Pasted image 20240807222126.png)

Created files inside the folder: (you have to create the directory to store these files on)

![](/assets/img/Pasted image 20240807222145.png)


When the data is imported, you will be presented with this view:

![](/assets/img/Pasted image 20240807222157.png)


On the left panel, you will see different types of Analysis Data; this is where you will perform information gathering and investigation process.

```c
- System Information: this is where you will see the information about the machine, BIOS (Windows only), operating system, and user information.
- Processes: processes will contain different attributes such as Process Name, PID, Path, Arguments, Parent process, Username, etc. When you expand the Processes tab, there will be four sections: Handles, Memory Sections, Strings, and Ports.
```

- A handle is a connection from a process to an object or resource in a Windows operating system. Operating systems use handles for referencing internal objects like files, registry keys, resources, etc.

- Memory Sections will let you investigate unsigned memory sections used by some processes. Many processes usually use legitimate dynamic link libraries (DLLs), which will be signed. This is particularly interesting because if you see any unsigned DLLs then it will be worth taking a closer look.

- `Strings` - you will see the information on the captured strings.
- `Ports` - this is one of the critical sections to pay attention to. Most malware often initiates the outbound or inbound connections to communicate to their command and control server (C2) to do some malicious activities like exfiltrating the data or grabbing a payload to the machine. This situation is where you can review the suspicious connections from ports and IP addresses. Pay attention to the system processes as well. The threat actors like to avoid detection by hiding under the system processes. For example, `explorer.exe` or `notepad.exe` shouldn't be on the list of processes with outbound connections. (unless their connecting outside)

Some of the other important sections you need to pay attention to are:

```c
- File System (not included in this analysis session)
- Registry
- Windows Services
- Tasks (Threat actors like to create scheduled tasks for persistence)
- Event Logs (this another great place to look for the suspicious Windows PowerShell events as well as the Logon/Logoff, user creation events, and others)
- ARP and Route Entries (not included in this analysis session)
- Browser URL History (not included in this analysis session)
- File Download History
```

The ***`Timeline`*** will help you to better understand when the compromise happened and what steps the malicious actor took to escalate the attack. The ***`Timeline`*** will also record every action on the file if it got create, changed, modified, accessed.

![](/assets/img/Pasted image 20240807222405.png)


If you know when the host compromise or suspicious activity occurred, you can use TimeWrinkles™ to filter out the timeline to only the events that took place around that time:

![](/assets/img/Pasted image 20240807222427.png)


TimeCrunches™ helps to reduce the excessive amount of data that is not relevant in the table view. A TimeCrunch will hide the same types of events that occurred within the same minute you specified:

![](/assets/img/Pasted image 20240807222445.png)


You can find out more about each type of data analysis using the ***Redline User Guide***: `https://fireeye.market/assets/apps/211364/documents/877936_en.pdf`.
Now you have learned some basics of different data types to help you during the investigation process. Let's go hunting and see if you can answer some of the questions in the next task.

<u>Opening the extracted data</u>:

![](/assets/img/Pasted image 20240807222537.png)


<u>Program collected should be here</u>:

![](/assets/img/Pasted image 20240807222558.png)


<u>System Information</u>:

![](/assets/img/Pasted image 20240807222623.png)


<u>Inside processes</u>: (there are couple sub-categories underneath it)

![](/assets/img/Pasted image 20240807222707.png)


<u>Checking the handles</u>:

![](/assets/img/Pasted image 20240807222746.png)


<u>Registry Information</u>:

![](/assets/img/Pasted image 20240807222817.png)


<u>Timeline (for timeline analysis)</u>:

![](/assets/img/Pasted image 20240807222850.png)


- Provide the Operating System detected for the workstation.
-> `Windows Server 2019 Standard 17763`


- What is the suspicious scheduled task that got created on the victim's computer? 

![](/assets/img/Pasted image 20240807222934.png)

	-> Answer: MSOfficeUpdateFa.ke


- Find the message that the intruder left for you in the task.
-> Answer: `THM-p3R5IStENCe-m3Chani$m`


- There is a new System Event ID created by an intruder with the source name "`THM-Redline-User`" and the Type "`ERROR`". Find the Event ID #.

![](/assets/img/Pasted image 20240807223038.png)

-> Answer: `546`


- Provide the message for the Event ID.
->  Answer: "`Someone cracked my password. Now I need to rename my puppy-++-`"

- It looks like the intruder downloaded a file containing the flag for Question 8. Provide the full URL of the website.

![](/assets/img/Pasted image 20240807223128.png)

-> Answer: `hxxps[://]wormhole[.]app/download-stream/gI9vQtChjyYAmZ8Ody0AuA`


- Provide the full path to where the file was downloaded to including the filename.
-> Answer: `C:\Program Files (x86)\Windows Mail\SomeMailFolder\flag.txt`


- Provide the message the intruder left for you in the file.

![](/assets/img/Pasted image 20240807223222.png)

-> Answer: `THM{600D-C@7cH-My-FR1EnD}`


------------------------------------------------------------------------------------------------------------------------
# IOC Search Collector

We briefly discussed the usage of the IOC Search Collector in the Data Collection task. 

Let's take a closer look at the capabilities of this collector type. But first, let's recap what an IOC is. 

IOC stands for `Indicators of Compromise`; they are artifacts of the potential compromise and host intrusion on the system or network that you need to look for when conducting threat hunting or performing incident response. IOCs can be:

```c
- MD5,
- SHA1,
- SHA256 hashes,
- IP address,
- C2 domain,
- file size,
- filename,
- file path,
- a registry key, etc.
```

One of the great tools you can use is IOC Editor, created by FireEye, to create IOC files. You can refer to this link to learn how to use the IOC 

Editor: `https://fireeye.market/assets/apps/S7cWpi9W//9cb9857f/ug-ioc-editor.pdf`

***Note***: According to the IOC Editor download page Windows 7 is the latest operating system officially supported. It is the same version installed in the attached VM. There is another tool called OpenIOC Editor by FireEye, which supports Windows 10 that is worth taking a look at. 

***Tip***: Before proceeding you can close Redline to free up some system resources while using IOC Editor.

You can create a text file containing IOCs, modify them, and share it with other people in the InfoSec industry.

In this example, we will look at an IOC of a keylogger created with IOC Editor. 

***Note***: Below, you may follow along with the screenshots and don't have to create the IOC file in this task. You will create an IOC file using IOC Editor and perform an IOC Search in the next task. 

Open IOC Editor which was conveniently placed for you in the taskbar next to `Redline`. 

`Note`: It may take ***~60 seconds*** for the application to launch.

Before proceeding, create the directory which will store the IOC file (IOC Directory). 

Next, create the IOC file. (`File > New > Indicator`)

![](/assets/img/Pasted image 20240807223507.png)



![](/assets/img/Pasted image 20240807223527.png)


***Output***:

![](/assets/img/Pasted image 20240807223552.png)



***Keylogger indicators in IOC Editor***:

![](/assets/img/Pasted image 20240807223624.png)

![](/assets/img/Pasted image 20240807223644.png)

	- Copy all the file strings from the IOC source (possibly, Threat Intel) → Then click “Save”.


Output:

![](/assets/img/Pasted image 20240807223718.png)



Now, add  the 2nd string: "`<?<L<T<g=” plus 834936 bytes`":

![](/assets/img/Pasted image 20240807223802.png)


A brief explanation of the above image:

```c
- The Name of the IOC file is Keylogger, Keylogger.ioc. (this field you can edit)
- The Author is RussianPanda. (this field you can edit)
- GUID, Created, and Modified are fields you can NOT edit, and IOC Editor populates the information.
- Under Description, you can add a summary explaining the purpose of the IOC file.
```


The actual IOCs will be added under, you guessed it, Add. 
Here are the values from the image above:

```c
- File Strings : psylog.exe
- File Strings : RIDEV_INPUTSINK
- File MD5 : 791ca706b285b9ae3192a33128e4ecbb
- File Size : 35400
```

Adding specific IOCs to the IOC file:

![](/assets/img/Pasted image 20240807223909.png)

```c
- After executing the '.bat' file, you need to wait for the analysis to finish.
- When the report generation completes, you can see the 'Hits' and expand the list by clicking on the entries in each row.
```


IOC Search Collector ignores data that doesn’t match an IOC you have gathered, but you can collect additional data if needed.
- To create an IOC Search Collector, you need to browse and choose the location of the `.ioc` file.

![](/assets/img/Pasted image 20240807224012.png)


```c
- After reviewing the configured IOCs, you can edit the script to configure what data will be collected for the analysis.
- After executing the '.bat' file, you need to wait for the analysis to finish and then open the '.mans' file in Redline.
- If Redline fails to generate the IOC Report automatically, you can manually generate it by clicking 'Create a New IOC Report' and importing your '.ioc' file.
```

![](/assets/img/Pasted image 20240807224103.png)


- What is the actual filename of the Keylogger? 
-> Answer: `psylog.exe`

- What filename is the file masquerading as? 
-> Answer: `THM1768.exe`

- Who is the owner of the file? 
-> Answer: `WIN-2DET5DP0NPT\charles`

- What is the file size in bytes? 
-> Answer: 35400

- Provide the full path of where the .ioc file was placed after the Redline analysis, include the .ioc filename as well
-> Answer: `C:\Users\charles\Desktop\Keylogger-IOCSearch\IOCs\keylogger.ioc`

------------------------------------------------------------------------------------------------------------------------
# IOC Search Collector Analysis

Scenario: You are assigned to do a threat hunting task at Osinski Inc. They believe there has been an intrusion, and the malicious actor was using the tool to perform the lateral movement attack, possibly a "`pass-the-hash`" attack. 

***Task***: Can you find the file planted on the victim's computer using IOC Editor and Redline IOC Search Collector?
So far, you only know the following artifacts for the file:

```c
File Strings:
- 20210513173819Z0w0=
- <?<L<T<g=

File Size (Bytes):
- 834936
```

***Note***: Open Previous Analysis, and use the existing Redline Session found in `C:\Users\Administrator\Documents\Analysis\Sessions\AnalysisSession1`.

![](/assets/img/Pasted image 20240807224323.png)

	- After running the .bat file, you should see this file generated. It takes a while.


<u>Loading it to Redline</u>:

![](/assets/img/Pasted image 20240807224349.png)


Make sure to add these on the scripts:
```c
- File Info
- PE Info
```


###### Questions:

- Provide the path of the file that matched all the artifacts along with the filename.
-> Answer: `C:\Users\Administrator\AppData\Local\Temp\8eJv8w2id6IqN85dfC.exe`

- Provide the path where the file is located without including the filename.
-> Answer: `C:\Users\Administrator\AppData\Local\Temp\`

- Who is the owner of the file?
-> Answer: `BUILTIN\Administrators`

- Provide the subsystem for the file.
-> Answer: `Windows_CUI`

- Provide the Device Path where the file is located.
-> Answer: `\Device\HarddiskVolume2`

- Provide the hash (SHA-256) for the file.
-> Answer: `57492d33b7c0755bb411b22d2dfdfdf088cbbfcd010e30dd8d425d5fe66adff4`

- The attacker managed to masquerade the real filename. Can you find it having the hash in your arsenal? 
-> Answer: `PsExec.exe`

------------------------------------------------------------------------------------------------------------------------
# Endpoint Investigation

<u>Scenario</u>: 

A Senior Accountant, Charles, is complaining that he cannot access the spreadsheets and other files he has been working on. He also mentioned that his wallpaper got changed with the saying that his files got encrypted. This is not good news!
Are you ready to perform the memory analysis of the compromised host? You have all the data you need to do some investigation on the victim's machine. Let's go hunting!
Task:
```c
- Navigate to the folder on your desktop titled Endpoint Investigation. 
- Double-click on the AnalysisSession1.mans file. The data will be imported automatically into Redline. 
- Analyze the file to answer the questions below.
```

***Note***: Give it up to 10 minutes for all the data import. 

###### Questions:
- Can you identify the product name of the machine?
-> Answer: `Windows 7 Home Basic`

- Can you find the name of the note left on the Desktop for the "`Charles`"?

![](/assets/img/Pasted image 20240807225007.png)

-> Answer: `_R_E_A_D___T_H_I_S___AJYG1O_.txt`


- Find the Windows Defender service; what is the name of its service DLL? 

![](/assets/img/Pasted image 20240807225032.png)

![](/assets/img/Pasted image 20240807225043.png)

	-> Answer: MpSvc.dll


- The user manually downloaded a zip file from the web. Can you find the filename?
 
![](/assets/img/Pasted image 20240807225131.png)

![](/assets/img/Pasted image 20240807225202.png)

-> Answer: `eb5489216d4361f9e3650e6a6332f7ee21b0bc9f3f3a4018c69733949be1d481.zip`


- Provide the filename of the malicious executable that got dropped on the user's Desktop.

![](/assets/img/Pasted image 20240807225246.png)

-> Answer: `Endermanch@Cerber5.exe`


- Provide the MD5 hash for the dropped malicious executable. (Just double-click the line above)

![](/assets/img/Pasted image 20240807225322.png)


- What is the name of the ransomware? 

![](/assets/img/Pasted image 20240807225358.png)

	-> Answer: Cerber
























