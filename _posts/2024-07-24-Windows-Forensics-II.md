---
title: Windows Forensics II
date: 2024-07-24 00:00:00 -500
categories: [SOC L1, Digital Forensics and Incident Response]
tags: [TryHackMe]
---




# Introduction

We learned about Windows Forensics in the previous room and practiced extracting forensic artifacts from the Windows Registry. We learned about gathering:
```c
	- System information
	- User information
	- Files and folders accessed
	- Programs run, and
	- External devices connected to the system,
```
all from the Windows registry.

However, the registry is not the only place where forensic artifacts are present. In this room, we will learn about forensic artifacts in other places. We will learn about the different file systems commonly used by Windows and where to look in these file systems when looking for artifacts.

We will identify locations and artifacts to prove:
```c
	- Evidence of execution,
	- File/folder usage or knowledge, and
	- External device usage.
	- We will also cover the basics of recovering deleted files.
```

We will use Eric Zimmerman's tools to parse information present in the artifacts for most of this room. We already used Registry Explorer and ShellBags Explorer in the previous room. For some of the tasks, we will use Autopsy.

------------------------------------------------------------------------------------------------------------------------
# The FAT Filesystems

A storage device in a computer system, for example, a hard disk drive or a USB device, is just a collection of bits. To convert these bits into meaningful information, they need to be organized. For this purpose, computer scientists and engineers have created different file systems that organize the bits in a hard drive as per a standard, so that information stored in these bits can be interpreted easily.

### The File Allocation Table (FAT):
The File Allocation Table (FAT) is one of these file systems. It has been the default file system for Microsoft Operating Systems since at least the late 1970s and is still in use, though not the default anymore. As the name suggests, the File Allocation Table creates a table that indexes the location of bits that are allocated to different files. If you are interested in the history of the FAT file system, you can head to the Wikipedia page for it.

### Data structures of the FAT file system:
The FAT file system supports the following Data structures:
- (a) Clusters: A cluster is a basic storage unit of the FAT file system. Each file stored on a storage device can be considered a group of clusters containing bits of information.

- (b) Directory: A directory contains information about file identification, like file name, starting cluster, and filename length. (so metadata of a file?)

- (c) File Allocation Table: The File Allocation Table is a linked list of all the clusters. It contains the status of the cluster and the pointer to the next cluster in the chain. 
In summary, the bits that make up a file are stored in clusters. All the filenames on a file system, their starting clusters, and their lengths are stored in directories. And the location of each cluster on the disk is stored in the File Allocation Table. We can see that we started with a raw disk composed of bits and organized it to define what group of bits refers to what file stored on the disk. 


### FAT12, FAT16, and FAT32:
The FAT file format divides the available disk space into clusters for more straightforward addressing. The number of these clusters depends on the number of bits used to address the cluster. Hence the different variations of the FAT file system. FAT was initially developed with 8-bit cluster addressing, and it was called the FAT Structure. Later, as the storage needed to be increased, FAT12, FAT16, and FAT32 were introduced. The last one of them was introduced in 1996. 
Theoretically, FAT12 used 12-bit cluster addressing for a maximum of 4096 clusters(2^12). FAT16 used 16-bit cluster addressing for a maximum of 65,536 clusters (2^16). In the case of FAT32, the actual bits used to address clusters are 28, so the maximum number of clusters is actually 268,435,456 or 2^28. 

However, not all of these clusters are used for file storage. Some are used for administrative purposes, e.g., 
```c
	- To store the end of a chain of clusters,
	- The unusable parts of the disk, or
	- Other such purposes
```

The following table summarizes the information as mentioned earlier and how it impacts the maximum volume and file sizes:
```c
Attribute	                      FAT12	FAT16	FAT32
Addressable bits	                12	 16	     28
Max number of clusters	          4,096	65,536	268,435,456
Supported size of clusters	   512B-8KB	2KB-32KB  4KB - 32KB
Maximum Volume size	               32MB	 2GB	 2TB
```

Even though the maximum volume size for FAT32 is 2TB, Windows limits formatting to only 32GB. However, volume sizes formatted on other OS with larger volume sizes are supported by Windows.
The chances of coming across a FAT12 filesystem are very rare nowadays. FAT16 and FAT32 are still used in some places, like USB drives, SD cards, or Digital cameras. However, the maximum volume size and the maximum file size (4GB - 1 file size for both FAT16 and FAT32) are limiting factors that have reduced their usage.


### The exFAT file system:
As the file sizes have grown, especially with higher resolution images and videos being supported by the newer digital cameras, the maximum file size limit of FAT32 became a substantial limiting factor for camera manufacturers. Though Microsoft had moved on to the NTFS file system, it was not suitable for digital media devices as they did not need the added security features and the overhead that came with it. Therefore, these manufacturers lobbied Microsoft to create the exFAT file system.
The exFAT file system is now the default for SD cards larger than 32GB. It has also been adopted widely by most manufacturers of digital devices. The exFAT file system supports a cluster size of 4KB to 32MB. It has a maximum file size and a maximum volume size of 128PB (Petabytes). It also reduces some of the overheads of the FAT file system to make it lighter and more efficient. It can have a maximum of 2,796,202 files per directory.


### Questions:
- How many addressable bits are there in the FAT32 file system?
-> 28 bits

- What is the maximum file size supported by the FAT32 file system?
-> 4GB → windows only support double of what FAT16 was capable of.

- Which file system is used by digital cameras and SD cards?
-> exFAT

------------------------------------------------------------------------------------------------------------------------
# The NTFS Filesystem

As observed in the previous task, the FAT file system is a very basic file system. It does the job when it comes to organizing our data, but it offers little more in terms of security, reliability, and recovery capabilities. It also has certain limitations when it comes to file and volume sizes. Hence, Microsoft developed a newer file system called the New Technology File System (NTFS) to add these features. This file system was introduced in 1993 with the Windows NT 3.1. However, it became mainstream since Windows XP. The NTFS file system resolves many issues present in the FAT file system and introduces a lot of new features. We will discuss some of the features below.

##### (a) Journaling
The NTFS file system keeps a log of changes to the metadata in the volume. This feature helps the system recover from a crash or data movement due to defragmentation. This log is stored in $LOGFILE in the volume's root directory. Hence the NTFS file system is called a journaling file system.

##### (b) Access Controls
The FAT file system did NOT have access controls based on the user. The NTFS file system has access controls that define the owner of a file/directory and permissions for each user.

##### (c) Volume Shadow Copy
The NTFS file system keeps track of changes made to a file using a feature called Volume Shadow Copies. Using this feature, a user can restore previous file versions for recovery or system restore. 
	- Example application in cybersecurity: In recent ransomware attacks, ransomware actors have been noted to delete the shadow copies on a victim's file systems to prevent them from recovering their data.

##### (d) Alternate Data Streams (ADS)
A file is a stream of data organized in a file system. Alternate data streams (ADS) is a feature in NTFS that allows files to have multiple streams of data stored in a single file. Internet Explorer and other browsers use Alternate Data Streams to identify files downloaded from the internet (using the ADS Zone Identifier). Malware has also been observed to hide their code in ADS.

# Master File Table
Like the File Allocation Table, there is a Master File Table in NTFS. However, the Master File Table, or MFT, is much more extensive than the File Allocation Table. It is a structured database that tracks the objects stored in a volume. Therefore, we can say that the NTFS file system data is organized in the Master File Table. From a forensics point of view, the following are some of the critical files in the MFT:

##### (a) $MFT
The $MFT is the first record in the volume. The Volume Boot Record (VBR) points to the cluster where it is located. $MFT stores information about the clusters where all other objects present on the volume are located. This file contains a directory of all the files present on the volume.

##### (b) $LOGFILE
The $LOGFILE stores the transactional logging of the file system. It helps maintain the integrity of the file system in the event of a crash.

##### (c) $UsnJrnl
It stands for the Update Sequence Number (USN) Journal. It is present in the $Extend record. It contains information about all the files that were changed in the file system and the reason for the change. It is also called the change journal.

##### (d) MFT Explorer
MFT Explorer is one of Eric Zimmerman's tools used to explore MFT files. It is available in both command line and GUI versions. We will be using the CLI version for this task.
Start the machine attached with the task. It will open in the split view. If preferred, login to the machine through RDP using the following credentials:
```c
Username: thm-4n6
Password: 123
```
Open an elevated command prompt (right-click command prompt, and click Run as Administrator). Navigate to the directory C:\Users\THM-4n6\Desktop\Eztools and run the command MFTECmd.exe. 
You will see the following options:

![](/assets/img/Pasted image 20240723204300.png)


##### Commands to execute:

- MFTECmd parses data from the different files created by the NTFS file system like $MFT, $Boot, etc. The above screenshot shows the available options for parsing MFT files. For parsing the $MFT file, we can use the following command:

Command:	
```c
MFTECmd.exe -f <path-to-$MFT-file>--csv <path-to-save-results-in-csv>
```


<u>Viewing output files from the command above</u>:
- You can then use the EZviewer tool inside the EZtools folder to view the output of `MFTECmd`, or to view CSV files in the next tasks as well.


You will see that it lists information about all the files present on the volume. You can similarly parse the $Boot file, which will provide information about the boot sector of the volume. MFTECmd doesn't support $LOGFILE as of now.

Let's parse the MFT files present on the location `C:\users\THM-4n6\Desktop\triage\C\` in the attached VM and answer the questions below. Currently, `MFTECmd.exe` doesn't support $Logfile:

Command:	
```c
MFTECmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\$MFT--csv C:\Users\THM-4n6\Desktop\
```

![](/assets/img/Pasted image 20240723204453.png)


Here are the files:

![](/assets/img/Pasted image 20240723204506.png)





Viewing the output with Ezviewer:

![](/assets/img/Pasted image 20240723204545.png)

![](/assets/img/Pasted image 20240723204554.png)


<u>Questions</u>:

⦁	Parse the $MFT file placed in `C:\users\THM-4n6\Desktop\triage\C\` and analyze it. What is the Size of the file located at `.\Windows\Security\logs\SceSetupLog.etl` 

Since `EZViewer` doesn’t seem to have a search functionality, just use notepad then match the column:

![](/assets/img/Pasted image 20240723204644.png)
 

⦁	What is the size of the cluster for the volume from which this triage was taken?
Hint: Parse the $Boot file. If you are having trouble viewing the CSV file, you can use EZviewer from the EZtools folder

![](/assets/img/Pasted image 20240723204728.png)

![](/assets/img/Pasted image 20240723204737.png)

------------------------------------------------------------------------------------------------------------------------
# Recovering Deleted Files

### Deleted files and Data recovery:
Understanding the file systems makes it easier to know how files are deleted, recovered, and wiped. As we learned in the previous two tasks, a file system stores the location of a file on the disk in a table(FAT/exFAT) or a database(`NTFS[MFT]`). When we delete a file from the file system, the file system deletes the entries that store the file's location on the disk. For the file system, the location where the file existed is now available for writing or unallocated. However, the file contents on disk are still there, as long as they are not overwritten by the file system while copying another file or by the disk firmware while performing maintenance on the disk.
Similarly, there is data on the disk in different unallocated clusters, which can possibly be recovered. To recover this data, we have to understand the file structure of different file types to identify the specific file through the data we see in a hex editor. However, we will not cover that in this room. What we will do, is to use a tool that does this work for us and identifies deleted files in a disk image file. But what is a disk image file?

### Disk Image:
A disk image file is a file that contains a bit-by-bit copy of a disk drive. A bit-by-bit copy saves all the data in a disk image file, including the metadata, in a single file. Thus, while performing forensics, one can make several copies of the physical evidence, i.e., the disk, and use them for investigation. This helps in two ways. 1) The original evidence is not contaminated while performing forensics, and 2) The disk image file can be copied to another disk and analyzed without using specialized hardware.

### Recovering files using Autopsy
With that out of the way, let's see how we can recover deleted files from a disk. We will use Autopsy for recovering deleted files. For a room dedicated to Autopsy, you can go here.
On the attached VM, you will find an icon for Autopsy on the Desktop. Double-click it to run Autopsy. You will be greeted with the following screen:

![](/assets/img/Pasted image 20240723204810.png)


Click on the '`New Case`' Option. You will find a window similar to the following:

![](/assets/img/Pasted image 20240723204919.png)


Enter a name to save your case by, and click Next.

![](/assets/img/Pasted image 20240723204933.png)




You can add the required details here. For now, we can click Finish to move forward. Autopsy will perform some processing and then show the following screen. Click `Next` to move forward.

![](/assets/img/Pasted image 20240723204949.png)


You will see this screen. Since we will be performing analysis on a disk image, select the topmost option, Disk Image or VM File.

![](/assets/img/Pasted image 20240723205014.png)


It will ask you for the location of the data source.
![](/assets/img/Pasted image 20240723205028.png)


Provide the location of the data source. You will find a disk image named 'usb.001' on the Desktop. Provide the path to that file in the above window and click next. You will see the following window:
![](/assets/img/Pasted image 20240723205048.png)

![](/assets/img/Pasted image 20240723205100.png)


Here, click Deselect All. These are different modules that Autopsy runs on the data for processing. For this task, we don't need any of these. If enabled, they take a lot of time to run. Click Next after clicking Deselect All. Autopsy will load the disk image. You will see the following in the left panel.

![](/assets/img/Pasted image 20240723205141.png)

![](/assets/img/Pasted image 20240723205212.png)


The Data Sources show the data sources that we have added to Autopsy. We can add more sources as well. The File Views and Tags menus show what Autopsy has found after processing the data. Expand the Data Sources, and click on the usb.001 device. Autopsy will show the contents of the disk image in the following way:

![](/assets/img/Pasted image 20240723205235.png)


The contents of the disk are shown on the right side. All the files and folders present in the disk are listed in the upper tab. In the lower tab, details about the selected files are shown. There are different options to see the details here. You can check them out to find interesting information.
Notice the X mark on the last file in the screenshot above, named New `Microsoft Excel Worksheet.xlsx~RFcd07702.TMP`. This indicates that this is a deleted file. Deleted files will have this X mark on them. To recover a deleted file, right-click on it, and select the Extract File(s) option. 

![](/assets/img/Pasted image 20240723205307.png)

 
Provide the path to save the extracted file, and you will have your deleted file recovered. Now let's see what other deleted files you can find on this disk image and answer the following questions.

![](/assets/img/Pasted image 20240723205320.png)


### Questions:

⦁	There is another xlsx file that was deleted. What is the full name of that file?
→ Tryhackme.xlsx

⦁	What is the name of the TXT file that was deleted from the disk?
→ TryHackMe2.txt

⦁	Recover the TXT file from Question #2. What was written in this txt file?

![](/assets/img/Pasted image 20240723205338.png)

→ Answer: thm-4n6-2-4


------------------------------------------------------------------------------------------------------------------------
# Evidence of Execution

Now that we have learned about the Filesystem, let's learn where to find artifacts present in the file system to perform forensic analysis. In this task, we will look into the artifacts that provide us evidence of execution:

### (a) Windows Prefetch files (its a cache)
When a program is run in Windows, it stores its information for future use. This stored information is used to load the program quickly in case of frequent use. This information is stored in prefetch files which are located in the `C:\Windows\Prefetch` directory.
Prefetch files have an extension of `.pf`:

```c
'Prefetch files' : contain the last run times of the application, the number of times the application was run, and any files and device handles used by the file. 
```

Thus it forms an excellent source of information about the last executed contain the last run times of the application, the number of times the application was run, and any files and device handles used by the file. programs and files.
We can use Prefetch Parser (PECmd.exe) from Eric Zimmerman's tools for parsing Prefetch files and extracting data. When we run PECmd.exe in an elevated command prompt, we get this output:

![](/assets/img/Pasted image 20240723205613.png)

To run `Prefetch Parser` on a file and save the results in a CSV, we can use the following command:
Command:
```c
PECmd.exe -f <path-to-Prefetch-files>--csv <path-to-save-csv>
```

Similarly, for parsing a whole directory, we can use the following command:
Command:	
```c
PECmd.exe -d <path-to-Prefetch-directory>--csv <path-to-save-csv>
```

We can use this information to answer the questions at the end.
These are all the prefetch files from the programs executed in the environment:

![](/assets/img/Pasted image 20240723205637.png)
 
![](/assets/img/Pasted image 20240723205704.png)

![](/assets/img/Pasted image 20240723205734.png)

![](/assets/img/Pasted image 20240723205758.png)

 → Ans: 2



⦁	What is the last execution time of gkape.exe

![](/assets/img/Pasted image 20240723205817.png)


### (b) Windows 10 Timeline
Windows 10 stores recently used applications and files in an SQLite database called the Windows 10 Timeline. This data can be a source of information about the last executed programs. It contains the application that was executed and the focus time of the application. The Windows 10 timeline can be found at the following location: 
Command:
```c
C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db
```

We can use Eric Zimmerman's `WxTCmd.exe` for parsing Windows 10 Timeline. We get the following options when we run it:

![](/assets/img/Pasted image 20240723205845.png)


We can use the following command to run `WxTCmd`:
Command:	
```c
WxTCmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Local\ConnectedDevicesPlatform\L.THM-4n6\ActivitiesCache.db--csv C:\Users\THM-4n6\Desktop\
```
 
Executing the command: (example using `ActivitiesCache.db`)

![](/assets/img/Pasted image 20240723205925.png)


Output in EZViewer:

![](/assets/img/Pasted image 20240723205945.png)

![](/assets/img/Pasted image 20240723210001.png)


# Windows Jump Lists

Windows introduced jump lists to help users go directly to their recently used files from the taskbar. We can view jumplists by right-clicking an application's icon in the taskbar, and it will show us the recently opened files in that application. This data is stored in the following directory: 
Command:	
```c
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
```

Jumplists include information about the:
```c
	- Applications executed,
	- First time of execution, and
	- Last time of execution of the application against an AppID.
```

We can use Eric Zimmerman's JLECmd.exe to parse Jump Lists. We get the following options when we run it:

![](/assets/img/Pasted image 20240723210047.png)


We can use the following command to parse Jumplists using JLECmd.exe:
Commands:	
```c
JLECmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms--csv C:\Users\THM-4n6\Desktop\
```

In the folder named triage, present on the Desktop of the attached machine, we have extracted the Windows directory of a system we want to investigate. It retains the directory structure of the original Windows directory, that is, `C:\Windows` directory from the system is mapped on to `C:\users\thm-4n6\Desktop\triage\C\Windows`. Now let's use the information we have learned to perform analysis on the data saved in the folder named triage on the Desktop in the attached VM and answer the following questions.
If you are having trouble viewing the CSV file, you can use `EZviewer` from the `EZtools` folder.

Jump Lists files: 

![](/assets/img/Pasted image 20240723210138.png)



##### Example usage for JLECmd.exe command:
Command:	
```c
JLECmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms --csv C:\Users\THM-4n6\Desktop\
```

![](/assets/img/Pasted image 20240723210218.png)


Questions:
- When Notepad.exe was opened on 11/30/2021 at 10:56, how long did it remain in focus?
- 
![](/assets/img/Pasted image 20240723210253.png)


- What program was used to open `C:\Users\THM-4n6\Desktop\KAPE\KAPE\ChangeLog.txt`?

		 - In terms of opened application, I guess you can use either Jump Lists or Timeline? Not sure why ChangeLog.txt wouldn’t be visible on Windows Jump Lists.


Jump Lists files: (used the 3rd one)

![](/assets/img/Pasted image 20240723210342.png)

![](/assets/img/Pasted image 20240723210353.png)


------------------------------------------------------------------------------------------------------------------------
# File/Folder Knowledge

### (a) Shortcut Files
Windows creates a shortcut file for each file opened either locally or remotely. The shortcut files contain information about the first and last opened times of the file and the path of the opened file, along with some other data. Shortcut files can be found in the following locations: 

```c
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\
```

We can use Eric Zimmerman's LECmd.exe (Lnk Explorer) to parse Shortcut files. When we run the LECmd.exe, we see the following options:

![](/assets/img/Pasted image 20240723210900.png)

```c
C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\
```


We can use the following command to parse shortcut files using LECmd.exe:
```c
Command:	LECmd.exe -f C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\ --csv C:\Users\<username>\Desktop
Command:	LECmd.exe -f C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\ --csv C:\Users\<username>\Desktop
```

The creation date of the shortcut file points to the date/time when the file was first opened. The date/time of modification of the shortcut file points to the last time the file was accessed.

Shortcuts for user `THM-4n6`:

![](/assets/img/Pasted image 20240723210930.png)


No office directory for this user:

![](/assets/img/Pasted image 20240723210950.png)

Output:

![](/assets/img/Pasted image 20240723211003.png)


Example Eztools shortcut:

![](/assets/img/Pasted image 20240723211024.png)


# IE/Edge history

An interesting thing about the IE/Edge browsing history is that it includes files opened in the system as well, whether those files were opened using the browser or not. Hence, a valuable source of information on opened files in a system is the IE/Edge history. We can access the history in the following location: 
```c
C:\Users\<username>\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat
```

The files/folders accessed appear with a `file:///*` prefix in the IE/Edge history. Though several tools can be used to analyze Web cache data, you can use Autopsy to do so in the attached VM. For doing that, select Logical Files as a data source. 

![](/assets/img/Pasted image 20240723211104.png)

It will then ask you to select the path from which you want files to be analyzed. You can provide the path to the triage folder.
 
![](/assets/img/Pasted image 20240723211128.png)

In the Window where Autopsy asks about ingest modules to process data, check the box in front of 'Recent Activity' and uncheck everything else.

![](/assets/img/Pasted image 20240723211257.png)

You will be able to view local files accessed in the Web history option in the left panel.
 
![](/assets/img/Pasted image 20240723211311.png)


- It takes a while for this to show.

![](/assets/img/Pasted image 20240723211330.png)


This is what it will look like in the right panel.

![](/assets/img/Pasted image 20240723211345.png)

As shown above, the 'Data Artifacts' tab displays information about the file accessed.

### Jump Lists

As we already learned in the last task, Jump Lists create a list of the last opened files. This information can be used to identify both the last executed programs and the last opened files in a system. Remembering from the last task, Jump Lists are present at the following location:


```c
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
```

We have already learned about parsing Jump lists in the previous task so we won't go over that again. Let's analyze the triage data available on the following location in the attached VM to answer the questions:
```c
C:\Users\THM-4n6\Desktop\triage\C\
```

Question:
- When was the folder `C:\Users\THM-4n6\Desktop\regripper` last opened?
→ 3rd to 5th one doesn’t output anything.
→ If it contains a directory, you have to specify it with “`—WithDir`” flag

Command:	
```c
JLECmd.exe -f C:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms --csv C:\Users\THM-4n6\Desktop\
```


Output from Ezviewer:

![](/assets/img/Pasted image 20240723211503.png)

![](/assets/img/Pasted image 20240723211520.png)

	- Answer is adjacent column to where the arrow is point at.


- When was the above-mentioned folder first opened?

![](/assets/img/Pasted image 20240723211537.png)


------------------------------------------------------------------------------------------------------------------------
# External Devices / USB Device forensics
- `Setupapi` dev logs for USB devices
When any new device is attached to a system, information related to the setup of that device is stored in the setupapi.dev.log. This log is present at the following location:

```c
C:\Windows\inf\setupapi.dev.log
```

This log contains the device serial number and the first/last times when the device was connected. 

![](/assets/img/Pasted image 20240723211634.png)


Here is what it looks like when opened in `Notepad.exe`. Notice the first line where we can see the device ID and Serial Number.


# Shortcut files
As we learned in the previous task, shortcut files are created automatically by Windows for files opened locally or remotely. These shortcut files can sometimes provide us with information about connected USB devices. It can provide us with information about the volume name, type, and serial number. Recalling from the previous task, this information can be found at:

```c
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\
```

As we have already learned about parsing Shortcut files using Eric Zimmerman's LECmd.exe in a previous task, we will not go over it again. 

Command: use the ‘`-d`’ flag
```c
JLECmd.exe -dC:\Users\THM-4n6\Desktop\triage\C\Users\THM-4n6\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\  --csv C:\Users\THM-4n6\Desktop\
```


Shortcuts for user `THM-4n6`:

![](/assets/img/Pasted image 20240723211816.png)

- Not sure which ones in here works for checking last connected USB…
- Its at `C:\Windows\inf\setupapi.dev.log` though, its not visible from the triage directory.

![](/assets/img/Pasted image 20240723211843.png)




