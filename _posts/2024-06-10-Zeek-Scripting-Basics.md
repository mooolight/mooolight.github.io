---
title: Zeek Scripting Basics
date: 2024-06-10 00:00:00 -500
categories: [TryHackMe, Network Security]
tags: [TryHackMe]
---


- Reference: `[The Basics — Book of Zeek (git/master)](https://docs.zeek.org/en/master/scripting/basics.html)`

<u>detect-MHR.zeek</u>:
```c
##! Detect file downloads that have hash values matching files in Team
##! Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).

@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

module TeamCymruMalwareHashRegistry;

export {
    redef enum Notice::Type += {
        ## The hash value of a file transferred over HTTP matched in the
        ## malware hash registry.
        Match
    };

    ## File types to attempt matching against the Malware Hash Registry.
    option match_file_types = /application\/x-dosexec/ |
                             /application\/vnd.ms-cab-compressed/ |
                             /application\/pdf/ |
                             /application\/x-shockwave-flash/ |
                             /application\/x-java-applet/ |
                             /application\/jar/ |
                             /video\/mp4/;

    ## The Match notice has a sub message with a URL where you can get more
    ## information about the file. The %s will be replaced with the SHA-1
    ## hash of the file.
    option match_sub_url = "https://www.virustotal.com/en/search/?query=%s";

    ## The malware hash registry runs each malware sample through several
    ## A/V engines.  Team Cymru returns a percentage to indicate how
    ## many A/V engines flagged the sample as malicious. This threshold
    ## allows you to require a minimum detection rate.
    option notice_threshold = 10;
}

function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
    {
    local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

    when ( local MHR_result = lookup_hostname_txt(hash_domain) )
        {
        # Data is returned as "<dateFirstDetected> <detectionRate>"
        local MHR_answer = split_string1(MHR_result, / /);

        if ( |MHR_answer| == 2 )
            {
            local mhr_detect_rate = to_count(MHR_answer[1]);

            if ( mhr_detect_rate >= notice_threshold )
                {
                local mhr_first_detected = double_to_time(to_double(MHR_answer[0]));
                local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
                local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
                local virustotal_url = fmt(match_sub_url, hash);
                # We don't have the full fa_file record here in order to
                # avoid the "when" statement cloning it (expensive!).
                local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
                Notice::populate_file_info2(fi, n);
                NOTICE(n);
                }
            }
        }
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( kind == "sha1" && f?$info && f$info?$mime_type &&
         match_file_types in f$info$mime_type )
        do_mhr_lookup(hash, Notice::create_file_info(f));
    }
```


##### Breakdown:
- First, there is a base level with no indentation where libraries are included in the script through `@load` and a namespace is defined with `module`:

![](/assets/img/Pasted image 20240305223735.png)

	- Consists of `@load` directives which process the `__load__.zeek` script in the respective directories being loaded.
	- The `@load` directives are ensuring the Files framework, the Notice framework and the script to hash all files has been loaded by Zeek.


- This is followed by an indented and formatted section explaining the ***custom variables*** being provided (`export`) as part of the script’s namespace:

![](/assets/img/Pasted image 20240305223837.png)

	- The 'export' section redefines an enumerable constant that describes the type of notice we will generate with the Notice framework
	- Variables that can only be altered before Zeek starts running
	- By extending the `Notice::Type` as shown, this allows for the [`NOTICE`] function to generate notices with a `$note` field set as `TeamCymruMalwareHashRegistry::Match` 
		- Remember this is from the 'module'


- Finally there is a second indented and formatted section describing the instructions to take for a specific event (`event file_hash`):

![](/assets/img/Pasted image 20240305223948.png)

	- With the next section, the script starts to define instructions to take in a given event.
	- The `file_hash` event allows scripts to access the information associated with a file for which Zeek’s file analysis framework has generated a hash
	- Arguments:
			- 'f' : the file itself to which the event handler was passed
			- 'kind' : type of digest algorithm
			- 'hash' : hash generated
	- The 'do_mhr_lookup()' is a helper function!

```c
// 1st cond: it checks whether the hashed used was sha1
// 2nd cond: Checks whether the "f?info" structure exists
	// Checks whether the variable inside "f?$info" named "mime_type" exists
// 3rd cond: Matches the file types on the lists of mime types.
if( kind == "sha1" && f?$info && f?$info?$mime_type && match_file_types in f$info$mime_type )
	do_mhr_lookup(hash, Notice::create_file_info(f));
//
// "f?info" is a structure.
// "f?info$mime_type" is a pointer to a variable inside the structure named "mime_type"
```


<u>What are 'mime_types' again</u>?

![](/assets/img/Pasted image 20240305230258.png)

	- Based on previous rooms, you can see that these are the file types passes on your network when browsing or trying to download a file


```c
function do_mhr_lookup(hash: string, fi: Notice::FileInfo)
{
	// Concatenates the hash received from the event handler to the string '.malware.hash.cymru.com'
	// Probably dependent on some of the frameworks?
    local hash_domain = fmt("%s.malware.hash.cymru.com", hash);

	// Looks up the hostname I guess to some reputable sources? and then save it on this var
	//The `when` block performs a DNS TXT lookup and stores the result in the local variable `MHR_result`
    when ( local MHR_result = lookup_hostname_txt(hash_domain) )
    {
        # Data is returned as "<dateFirstDetected> <detectionRate>"
        local MHR_answer = split_string1(MHR_result, / /);

        if ( |MHR_answer| == 2 ) // Tne amount of answer split into
		{
			local mhr_detect_rate = to_count(MHR_answer[1]);
	
			if ( mhr_detect_rate >= notice_threshold ) // this was defined earlier at the 'export' sect
			{
			local mhr_first_detected = double_to_time(to_double(MHR_answer[0]));
			local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
			local message = fmt("Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected);
			local virustotal_url = fmt(match_sub_url, hash);
			# We don't have the full fa_file record here in order to
			# avoid the "when" statement cloning it (expensive!).
			local n: Notice::Info = Notice::Info($note=Match, $msg=message, $sub=virustotal_url);
			Notice::populate_file_info2(fi, n);
			NOTICE(n);
			}
		}
    }
}
```


- A `when` block is used when Zeek needs to perform ***asynchronous actions***, such as a `DNS lookup`, to ensure that performance isn’t effected.













