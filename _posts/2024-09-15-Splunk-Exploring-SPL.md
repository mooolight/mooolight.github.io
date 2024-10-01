---
title: Splunk - Exploring SPL
date: 2024-09-15 00:00:00 -500
categories: [TryHackMe, SIEM, Advanced Splunk]
tags: [TryHackMe]
---


# Intro

Splunk is a powerful SIEM solution that provides the ability to search and explore machine data. **`Search Processing Language (SPL)`** is used to make the search more effective. It comprises various functions and commands used together to form complex yet effective search queries to get optimized results.

This room will dive deep into some key fundamentals of searching capability, like ***`chaining SPL queries`*** to construct simple to complex queries.  


### Learning Objectives

This room will teach the following topics:
```c
- What are Search processing Language?  
- How to apply filters to narrow down results.
- Using transformational commands.
- Changing the order of the results.
```

##### Room Prerequisites

- This room is based on the SIEM concepts covered in [Intro to SIEM](https://tryhackme.com/room/introtosiem) and [Splunk: Basics](https://tryhackme.com/jr/splunk101) rooms. Complete these rooms and continue to the next task.


-----
# Search and Reporting App Overview

**Search & Reporting App** is the default interface used to search and analyze the data on the Splunk Home page. It has various functionalities that assist analysts in improving the search experience.

![](/assets/img/Pasted image 20240414180837.png)

	- Some important functionalities present in the search App are explained below:


##### **1) Search Head:**  

Search Head is where we use search processing language queries to look for the data.

![](/assets/img/Pasted image 20240414180932.png)


##### **2) Time Duration:**

This tab option provides multiple options to select the time duration for the search. **`All-time`** will display the events in real-time. Similarly, the **`last 60 minutes`** will display all the events captured in the last hour.

![](/assets/img/Pasted image 20240414181101.png)



**3) Search History:**

This tab saves the search queries that the user has run in the past along with the time when it was run. It lets the user click on the past searches and look at the result. The filter option is used to search for the particular query based on the term.

![](/assets/img/Pasted image 20240414181211.png)




**4) Data Summary:**

This tab provides a summary of the data type, the data source, and the hosts that generated the events as shown below. This tab is very important feature used ***`to get a brief idea`*** about the network visibility.

![[81459123900e070704fe4fdac9f9b33e.gif]]



**5) Field Sidebar:**

The Field Sidebar can be found on the left panel of Splunk search. This sidebar has two sections showing selected fields and interesting fields. It also provides quick results, such as top values and raw values against each field.

![](/assets/img/Pasted image 20240414181427.png)


<u>Some important points to understand about the sidebar are explained below</u>:
![](/assets/img/Pasted image 20240414181509.png)


##### Question and Answers section:

- In the search History, what is the 7th search query in the list? (excluding your searches from today)

![](/assets/img/Pasted image 20240414181855.png)

<u>Answer</u>:
```c
index=windowslogs | chart count(EventCode) by Image
```


- In the left field panel, which `Source IP` has recorded max events?
![](/assets/img/Pasted image 20240414182041.png)

<u>Answer</u>:
```c
172[.]90[.]12[.]11
```



- How many events are returned when we apply the time filter to display events on `04/15/2022` and Time from `08:05 AM to 08:06 AM`?

![](/assets/img/Pasted image 20240414182618.png)


<u>Answer</u>:
```c
134
```


------
# Splunk Processing Language Overview


Splunk Search Processing Language comprises of multiple functions, operators and commands that are used together to form a simple to complex search and get the desired results from the ingested logs. Main components of SPL are explained below:

### `(a)` ﻿**Search Field Operators**

Splunk field operators are the building blocks used to construct any search query. These field operators are used to `filter`, `remove`, and `narrow down` the search result based on the given criteria. Common field operators are `Comparison` `operators`, `wildcards`, and `boolean` operators.

### `(b)` Comparison Operators

﻿These operators are used to compare the values against the fields. Some common comparisons operators are mentioned below:
![](/assets/img/Pasted image 20240414182721.png)


`1.` ﻿﻿Lets use the comparison operator to display all the event logs from the index "`windowslogs`", where `AccountName` is not Equal to "`System`"

**Search Query:** 
```c
index=windowslogs AccountName !=SYSTEM
```

![](/assets/img/Pasted image 20240414182949.png)


### `(c)` Boolean Operators

Splunk supports the following Boolean operators, which can be very handy in searching/filtering and narrowing down results.

![](/assets/img/Pasted image 20240414183020.png)

﻿To understand how boolean operator works in SPL, lets add the condition to show the events from the James account.

**Search Query:** 
```c
index=windowslogs AccountName !=SYSTEM **AND** AccountName=James
```

![](/assets/img/Pasted image 20240414183109.png)



### `(d)` Wild Card

Splunk supports wildcards to match the characters in the strings.

![](/assets/img/Pasted image 20240414183150.png)

In the events, there are multiple DestinationIPs reported. Let's use the wildcard only to show the **DestinationIP** starting from `172.*`


**Search Query:** 
```c
index=windowslogs DestinationIp=172.*
```


![](/assets/img/Pasted image 20240414183253.png)



### Question and Answers section:

- How many Events are returned when searching for `Event ID 1` **AND** `User` as *`James`*?

Query:
```c
index="windowslogs" User="Cybertees\\James" EventID=1
```

![](/assets/img/Pasted image 20240414183848.png)

<u>Answer</u>:
```c
4
```



- How many events are observed with Destination IP `172.18.39.6` AND destination `Port 135`?

![](/assets/img/Pasted image 20240414184137.png)

<u>Answer</u>:
```c
4
```



- What is the ***`Source IP`*** with highest count returned with this Search query?
<u>Search Query</u>:
```c
index=windowslogs  Hostname="Salena.Adam" DestinationIp="172.18.38.5"
```

![](/assets/img/Pasted image 20240414184427.png)

Event log example:
![](/assets/img/Pasted image 20240414184608.png)

	- Weird to have an 'svchost.exe' connecting the machine to somewhere else


<u>Answer</u>:
```c
172.90.12.11
```



- In the index `windowslogs`, search for all the events that contain the term **cyber** how many events returned?
```c
0
```


- Now search for the term`cyber*`, how many events are returned?
![](/assets/img/Pasted image 20240414184724.png)

<u>Answer</u>:
```c
12256
```


-------
# Filtering the results in SPL

Our network generates thousands of logs each minute, all ingesting into our SIEM solution. It becomes a daunting task to search for any anomaly without using filters. SPL allows us to use **Filters** to narrow down the result and only show the important events that we are interested in. We can add or remove certain data from the result using filters. The following commands are useful in applying filters to the search results.

<u>Fields</u>:
![](/assets/img/Pasted image 20240414184838.png)

Let's use the fields command to only display host, User, and SourceIP fields using the following syntax.  

**Search Query:** 
```c
index=windowslogs | fields + host + User + SourceIp
```

![](/assets/img/Pasted image 20240414185007.png)

	- Automatically select three fields along in the search query


**Note:** Click on the **More field** to display the fields if some fields are not visible.

![](/assets/img/Pasted image 20240414185020.png)



##### **Search**
![](/assets/img/Pasted image 20240414185210.png)

Use the search command to show all the events containing the term `Powershell`. This will return all the events that contain the term "**`Powershell`**".  


**Search Query:** 
```c
index=windowslogs | search Powershell
```

![](/assets/img/Pasted image 20240414185251.png)


##### Dedup

![](/assets/img/Pasted image 20240414185347.png)

We can use the `dedup` command to show the list of unique **`EventIDs`** from a particular hostname.


**Search Query:** 
```c
index=windowslogs | table EventID User Image Hostname | dedup EventID
```

![](/assets/img/Pasted image 20240414185409.png)


### **Rename**

![](/assets/img/Pasted image 20240414202242.png)

Let's rename the User field to Employees using the following search query.

**Search Query**: 
```c
index=windowslogs | fields + host + User + SourceIp | rename User as Employees
```

![](/assets/img/Pasted image 20240414202304.png)


- What is the third EventID returned against this search query?

<u>Search Query</u>: 
```c
index=windowslogs | table _time EventID Hostname SourceName | reverse
```


![](/assets/img/Pasted image 20240414202730.png)


- Use the `dedup` command against the `Hostname` field before the `reverse` command in the query mentioned in Question 1. What is the first `username` returned in the `Hostname` field?
<u>Search Query</u>: 
```c
index=windowslogs | table _time EventID Hostname SourceName | reverse | dedup EventID
```


![](/assets/img/Pasted image 20240414203056.png)


-------
# SPL - Structuring the Search results


SPL provides various commands to bring structure or order to the search results. 

These sorting commands like `head`, `tail`, and `sort` can be very useful during logs investigation. These ordering commands are explained below:

##### Table

![](/assets/img/Pasted image 20240414203154.png)

This search query will create a table with three columns selected and ignore all the remaining columns from the display.  

**Search Query:** 
```c
index=windowslogs | table EventID Hostname SourceName
```

![](/assets/img/Pasted image 20240414203245.png)


##### Head

![](/assets/img/Pasted image 20240414203308.png)


The following search query will show the table containing the mentioned fields and display only the top 5 entries.  

**Search Query:** 
```c
index=windowslogs |  table _time EventID Hostname SourceName | head 5
```
![](/assets/img/Pasted image 20240414203355.png)


##### Tail

![](/assets/img/Pasted image 20240414203433.png)

The following search query will show the table containing the mentioned fields and display only 5 entries from the bottom of the list.

**Search Query:** 
```c
index=windowslogs |  table _time EventID Hostname SourceName | tail 5
```

![](/assets/img/Pasted image 20240414203452.png)


##### sort

![](/assets/img/Pasted image 20240414203525.png)

The following search query will sort the results based on the Hostname field.

**Search Query:** 
```c
index=windowslogs |  table _time EventID Hostname SourceName | sort Hostname
```

![](/assets/img/Pasted image 20240414203545.png)


##### Reverse

![](/assets/img/Pasted image 20240414203617.png)

**Search Query:** 
```c
index=windowslogs | table _time EventID Hostname SourceName | reverse
```

![](/assets/img/Pasted image 20240414203633.png)


- Using the Reverse command with the search query ***index=windowslogs | table _time `EventID` `Hostname` `SourceName`*** - what is the `HostName` that comes on top?
```c
James.Browne
```


- What is the `last` `EventID` returned when the query in question 1 is updated with the **`tail`** command?
Query:
```c
index=windowslogs | table _time EventID Hostname SourceName | tail 5
```

<u>Output</u>:
![](/assets/img/Pasted image 20240414204011.png)


- Sort the above query against the `SourceName`. What is the `top` `SourceName` returned?
Query:
```c
index=windowslogs | table _time EventID Hostname SourceName | reverse
| sort SourceName
```

![](/assets/img/Pasted image 20240414204409.png)

```c
Microsoft-Windows-Directory-Services-SAM
```


--------
# Transformational Commands in SPL


Transformational commands are those commands that change the result into a data structure from the field-value pairs. 

These commands simply transform specific values for each event into numerical values which can easily be utilized for statistical purposes or turn the results into `visualizations`. 

Searches that use these transforming commands are called `transforming searches`. 

Some of the most used transforming commands are explained below.

## General Transformational Commands

##### Top

![](/assets/img/Pasted image 20240414204537.png)

The following command will display the top 7 Image (representing Processes) captured.

	- Basically uses two parameters to query: "Image" and "Count"


**Search Query:**
```c
index=windowslogs | top limit=7 Image
```

![](/assets/img/Pasted image 20240414204613.png)


##### **Rare**

![](/assets/img/Pasted image 20240414204732.png)

The following command will display the `rare 7 Image (Processes)` captured.

**Search Query:**
```c
index=windowslogs | rare limit=7 Image
```

![](/assets/img/Pasted image 20240414204839.png)


##### **Highlight**

![](/assets/img/Pasted image 20240414204900.png)

The following command will highlight the three mentioned fields in the raw logs  

**Search Query:** 
```c
index=windowslogs | highlight User, host, EventID, Image
```

![[61ad47b204639fa0f75b278bec21abac.gif]]



### STATS Commands

SPL supports various stats commands that help in calculating statistics on the values. Some common `stat` commands are:

| **Command**             | **Explanation**                                                   | **Syntax**                        | **Example**              |
| ----------------------- | ----------------------------------------------------------------- | --------------------------------- | ------------------------ |
| **`Average`  <br>**     | This command is used to calculate the average of the given field. | stats avg(field_name)             | stats avg(product_price) |
| **`Max`  <br>**         | It will return the maximum value from the specific field.         | stats max(field_name)             | stats max(user_age)      |
| **`Min`**               | It will return the minimum value from the specific field.         | stats min(field_name)             | stats min(product_price) |
| **`Sum`**               | It will return the sum of the fields in a specific value.         | stats sum(field_name)             | stats sum(product_cost)  |
|  **`Count`**            command returns the number of data occurrences.         | stats count(function) AS new_NAME | stats count(source_IP)   |


### **Splunk Chart Commands**  

These are very important types of transforming commands that are used to present the data in table or visualization form. Most of the chart commands utilize various `stat` commands.

##### Chart

![](/assets/img/Pasted image 20240414205345.png)

**Search Query:**
```c
index=windowslogs | chart count by User
```

![[a954b0a1d37542650df294461d756c61.gif]]


### Timechart

![](/assets/img/Pasted image 20240414205524.png)

The following query will display the Image chart based on the time.  

**Search Query:** 
```c
index=windowslogs | timechart count by Image
```


#### Question and Answers section:

- List the top 8 Image processes using the top command -  what is the total count of the 6th Image?
![](/assets/img/Pasted image 20240414205825.png)

<u>Answer</u>:
```c
196
```


- Using the rare command, identify the `user` with the least number of activities captured?
Query:
```c
index=windowslogs | rare User
```

![](/assets/img/Pasted image 20240414210732.png)
<u>Answer</u>:
```c
James
```


- Create a `pie-chart` using the chart command - what is the count for the `conhost.exe` process?
<u>Query</u>:
```c
index=windowslogs | chart count by Image | sort Image
```

<u>Statistics</u>:
![](/assets/img/Pasted image 20240414211140.png)

<u>Pie chart</u>:
![](/assets/img/Pasted image 20240414211204.png)










