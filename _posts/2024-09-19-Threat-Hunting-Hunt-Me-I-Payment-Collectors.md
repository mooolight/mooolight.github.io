---
title: Threat Hunting; Hunt Me I - Payment Collectors 
date: 2024-09-19 00:00:00 -500
categories: [TryHackMe, Threat Hunting]
tags: [TryHackMe]
---


On **Friday, September 15, 2023**, Michael Ascot, a Senior Finance Director from SwiftSpend, was checking his emails in **Outlook** and came across an email appearing to be from Abotech Waste Management regarding a monthly invoice for their services. Michael actioned this email and downloaded the attachment to his workstation without thinking.

![[Pasted image 20240524004548.png]]


The following week, Michael received another email from his contact at Abotech claiming they were recently hacked and to carefully review any attachments sent by their employees. However, the damage has already been done. Use the attached Elastic instance to hunt for malicious activity on Michael's workstation and within the SwiftSpend domain!


##### Question and Answer:

- What was the name of the ZIP attachment that Michael downloaded?

<u>Filter</u>:
```c
related.user.keyword: michael.ascot
event.type.keyword: creation
```

<u>Query</u>:
```c
*.zip
```

![[Pasted image 20240525012317.png]]

<u>Answer</u>:
```c
Invoice_AT_2023-227.zip
```


- What was the contained file that Michael extracted from the attachment?

Checking the surrounding documents from the previous question:
![[Pasted image 20240525012608.png]]

<u>Answer</u>:
```c
Payment_Invoice.pdf.lnk.lnk
```


- What was the name of the command-line process that spawned from the extracted file attachment?

<u>Filters and Queries</u>:
```c
Process that executes the '.pdf.lnk.lnk' file
process.name: explorer.exe
process.pid: 3180
message: (contains) Payment_Invoice.pdf.lnk.lnk

Process that spawned from it and the query used:
process.parent.pid: 3180

Selected fields:
- process.command_line
- process.parent.command_line
- process.name
- process.parent_name
```

![[Pasted image 20240525014007.png]]

<u>Answer</u>:
```c
outlook.exe
```

	- As you can see, the 'OUTLOOK.EXE' that spawned from the '.pdf.lnk.lnk' file downloaded powercat.ps1 and established a reverse shell connection in powershell.

Flow:
```c
explorer.exe(1st stage) -> OUTLOOK.EXE(2nd stage) -> powershell.exe (revshell)
```

![[Pasted image 20240525015438.png]]

	- See that powercat disabled the powershell restriction
	- Query: process.name : powershell.exe


- What URL did the attacker use to download a tool to establish a reverse shell connection?
```c
https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1
```



- What port did the workstation connect to the attacker on?
```c
19282
```


- What was the first native Windows binary the attacker ran for system enumeration after obtaining remote access?

Get the process spawned by the `powershell.exe` first I guess:
```c
process.pid (powershell.exe) : 3880 -> use this as a parent process query

OR

destination.port : 19282 -> use the port : 19282 as a lead
```

![[Pasted image 20240525014816.png]]

	- it shows the egress network connection but doesn't necessarily show the other commands the attacker executed.


Create a Table Visualization from `process.command_line.keyword` then find the native windows binaries for enumeration:
![[Pasted image 20240525020138.png]]

	- Notice that the enumeration queries are executed few times.
	- You can sort them with the least amount of binary execution (sort in ascending mode), collect all the binaries executed and pick out the native to windows.


<u>Answer</u>:
```c
systeminfo.exe
```

<u>Other Windows native binaries used</u>:
```c
- C:\Windows\System32\whoami.exe
- C:\Windows\System32\net1.exe
- C:\Windows\System32\svchost.exe
- C:\Windows\System32\nslookup.exe
- C:\Windows\System32\mmc.exe
- C:\Windows\System32\Robocopy.exe
- C:\Program Files (x86)\Internet Explorer\IEXPLORE.EXE
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```


- What is the URL of the script that the attacker downloads to enumerate the domain?

Since `powercat.ps1` was used for reverse shell connection, another powershell script must be used for enumeration...
![[Pasted image 20240525023223.png]]

![[Pasted image 20240525025026.png]]

<u>Answer</u>:
```c
https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1
```


- What was the name of the file share that the attacker mapped to Michael's workstation?
![[Pasted image 20240525030031.png]]

![[Pasted image 20240525030102.png]]

<u>Answer</u>:
```c
SSF-FinancialRecords
```


- What directory did the attacker copy the contents of the file share to?
```c
C:\Users\michael.ascot\downloads\exfiltration
```


- What was the name of the Excel file the attacker extracted from the file share?
<u>Filter</u>:
```c
event.type.keyword: creation
```

The adversary took two files:
![[Pasted image 20240525022247.png]]

![[Pasted image 20240525022317.png]]

<u>Answer</u>:
```c
ClientPortfolioSummary.xlsx
```


- What was the name of the archive file that the attacker created to prepare for exfiltration?
![[Pasted image 20240525022348.png]]

<u>Answer</u>:
```c
exfilt8me.zip
```


- What is the **MITRE ID** of the technique that the attacker used to exfiltrate the data? `->` (How was the `exfiltr8.zip` was taken by the adversary?)

There are two main network protocols shown from the logs: `dns` and `https`
![[Pasted image 20240525030324.png]]

	- We know that `dns` was used to resolve the attacker's domain and the open source tools it used.

There are two hits coming from github cdn:
![[Pasted image 20240525030527.png]]

	- The github cdn was used to download the powershell scripts for powershell restriction bypass(powercat.ps1) and system enumeration with PowerView.ps1


Here are the DNS queries found:
```c
- QueryName: DC-01.swiftspendfinancial.thm -> Domain controller enumeration
- QueryName: autodiscover.swiftspend.finance
- QueryName: mailsrv-01.swiftspendfinancial.thm -> MX server
- QueryName: raw.githubusercontent.com -> for the open source enumeration tools/scripts
- QueryName: 2.tcp.ngrok.io -> for downloading the reverse shell
```

	- With these queries, its more likely that the attacker used HTTPS as a C2 channel than DNS!


`->` From the command line statistics table, we can see that there is a domain with different subdomains with irregular subdomain string size which points to a C2 channel. This confirms that it beacons via HTTPS.

<u>Answer</u>:
```c
T1048
```


- What was the domain of the attacker's server that retrieved the exfiltrated data?

First, check all the resolved domain from the compromised workstation:
![[Pasted image 20240525033317.png]]

```c
haz4rdw4re.io
```


- The attacker exfiltrated an additional file from the victim's workstation. What is the flag you receive after reconstructing the file?

`->` Use `*nslookup*` as a query and look at the most recent beacon.

Search up anything related to this `.txt` file that is a base64 encoded command in the C2:
![[Pasted image 20240525035528.png]]

Got the first half:
![[Pasted image 20240525035629.png]]

Second half:

![[Pasted image 20240525035831.png]]

![[Pasted image 20240525035741.png]]


<u>Answer</u>:
```c
THM{1497321f4f6f059a52dfb124fb16566e}
```
























