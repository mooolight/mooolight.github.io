---
title: Targeted Password Attacks
date: 2022-12-30 12:00:00 -500
categories: [Red Team Operator, Initial Access]
tags: [TryHackMe]
---

# Password Profiling #1 - Default, Weak, Leaked, Combined and Username Wordlists

- Having a good wordlist is critical to carrying out a successfull password attack.
- It is important to know how you can generate username lists and password lists.
- In this section, we will discuss **creating targeted username and password lists**.

### Default Passwords

- Before performing password attacks, it is worth trying a couple of default passwords against the targeted service.
- Manufacturers set default passwords with prodcts and equipment such as switches , firewalls and routers.
- There are scenarios where customers don't change the default password, which makes them vulnerable.
- Thus, it is a good practice to try out `admin:admin` , `admin:123456`,etc.
- If we know the target device, we can look up the default passwords and try default passwords we can try: `admin:admin` or `tomcat:admin`.

<u>Here are some website lists that provide default passwords for various products</u>:

- `https[:][/][/]cirt[.]net[/]passwords`
- `https[:][/][/]default-password[.]info[/`]
- `https[:][/][/]datarecovery[.]com[/]rd[/]default-passwords[/`]

### Weak Passwords
- Pros collect and generate weak password lists over time and often combine them into one large wordlist.
- Lists are generated based on their experience and what they see in pentesting engagements.
- These lists may also contain leaked passwords that have been published.
- Here are common weak password lists:

		- https[:][/][/]wiki[.]skullsecurity[.]org/index[.]php?title=Passwords
		- SecLists in GitHub.


### Leaked Passwords
- Sensitive data such as passwords or hashes may be publicly disclosed or sold as a result of a breach.
- These public or privately available leaks are often referred to as `'dumps'`.
- Depending on the contents of the dump, an attacker may need to extract the passwords out of the data.
- In some cases, the dump may only contain hashes of the passwords and require cracking in order to gain the plain-text passwords.
- Examples:

		- webhost
		- elitehacker
		- hak5
		- Hotmail
		- PhpBB

<u>Source</u>: SecLists == `https[:][/][/]github[.]com[/]danielmiessler[/]SecLists[/]tree[/]master[/]Passwords[/]Leaked-Databases`

### Combined Wordlists
- Let's say that we have more than one wordlist. Then, we can combine these wordlists into one large file. This can be done as follows using `cat`:

```shell-session
$ cat file1.txt file2.txt file3.txt > combined_list.txt
```

<u>Cleaning up generated combined list to remove duplicated words</u>:

```shell-session
$ sort combined_list.txt | uniq -u > cleaned_combined_list.txt
```

### Customized Wordlists
- Customizing password lists is one of the best ways to increase the chances of finding valid credentials.
- We can create custom password lists from the target website.
- Often, a company's website contains valuable information about the company and its employees, including emails and employee names.
- In addition, the website may contain keywords specific to what the company offers, including product and service names, which may be used in an employee's password!

- Tools such as `Cewl` can be used to effectively crawl a website and extract strings or keywords.
- `Cewl` is a powerful tool to generate a wordlist specific to a given company or target.

<u>Example</u>:

```
$ cewl -w list.txt -d 5 -m 5 http://thm.labs
```

	Breakdown:
	- "-w" : write the contents to a file. In this case, "list.txt".
	- "-m 5" : gathers strings that has length of 5 chars.
	- "-d 5" : is the depth level of web crawling/spidering(default 2)
	- "http://thm.labs" : the URL to crawl on.

<u>Task</u>: 

`Apply what we discuss using cewl against https://clinic.thmredteam.com/ to parse all words and generate a wordlist with a minimum length of 8. Note that we will be using this wordlist later on with another task!`

```
$ cewl -w list.txt -m 8 -d 5 https://clinic.thmredteam.com/
```

### Username Wordlists:
- Gathering employee's names in the enumeration stage is essential.
- We can generate username lists from the target's website.
- For the following example, we'll assume we have a `{first name} {last name}` and a method of generating usernames.

```
-   **{first name}:** john
-   **{last name}:** smith
-   **{first name}{last name}:  johnsmith** 
-   **{last name}{first name}:  smithjohn**  
-   first letter of the **{first name}{last name}: jsmith** 
-   first letter of the **{last name}{first name}: sjohn**  
-   first letter of the **{first name}.{last name}: j.smith** 
-   first letter of the **{first name}-{last name}: j-smith** 
-   and so on
```

- You can use `username_generator` a python tool to generate these kinds of combinations:

![[Pasted image 20221229155048.png]]
![](/assets/img/Pasted image 20221129215051.png)

<u>How to use this tool</u>:
![[Pasted image 20221229155106.png]]
![](/assets/img/Pasted image 20221129215051.png)

![[Pasted image 20221229155124.png]]
![](/assets/img/Pasted image 20221129215051.png)

---------
# Password Profiling #2 - Keyspace Technique and CUPP

### Keyspace Technique
- Another way of preparing a wordlist is by usign the `key-space` technique.
- In this technique, we specify a range of characters, numbers and symbols in our wordlist.
- `Crunch` is one of many powerful tools for creating an `offline wordlist`.
- Specifies:

		- Min
		- Max
		- etc.

![[Pasted image 20221229155530.png]]
![](/assets/img/Pasted image 20221129215051.png)

- The following example creates a wordlist containing all possible combinations of `2 characters`, `0-4` and `a-d`.
- We can use the "`-o`" argument and specify a file to save the output to:
![[Pasted image 20221229155626.png]]
![](/assets/img/Pasted image 20221129215051.png)

<u>Output</u>;

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229155640.png]]

- Generating a big file with `crunch`:
```
$ crunch 8 8 0123456789abcdefABCDEF -o crunch.txt
```

	- The file generated is 459GB and contains '54875873536' words.

- Specifying character set in crunch with the `'-t'` flag:

		- '@' : lowercase alpha characters
		- ',' : uppercase alpha characters
		- '%' : numeric characters
		- '^' : special characters including space

- Case Scenario: Password is known to us and we know it starts with the substring `pass` and follows two numbers:

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229160014.png]]

	- We can use '%' as a number placeholder since the string length is specified anyways.

### CUPP - Common User Passwords Profiler
- Basically, this is a type of tool to create a custom wordlists that has a feature for `1337/leet mode `that checks whether there is a semantic meaning for numbers used in a string say, `1337` means `leet` and so on.
- How to run: you need `python3` and clone it from Github.

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229160509.png]]

- Checking the help options:

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229160530.png]]

- **CUPP Interactive Mode**:

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229160635.png]]

- **Downloading pre-created wordlists**:

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229160714.png]]

- Creating custom wordlists based on default usernames and passwords from the `Alecto Database` with the flag `'-a'`:

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229160805.png]]

<u>Questions</u>:

![](/assets/img/Pasted image 20221129215051.png)
![[Pasted image 20221229161750.png]]

---------
# Offline Attacks - Dictionary and Brute-Force

See tryhackme: https://tryhackme.com/room/passwordattacks