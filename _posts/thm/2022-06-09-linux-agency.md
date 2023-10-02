---
title: TryHackMe - Linux Agency                   # Add title of the machine here
date: 2022-07-24 08:00:00 -0600                           # Change the date to match completion date
categories: TryHackMe                    # Change Templates to Writeup
tags: [thm, writeup, linux, privesc]     # TAG names should always be lowercase; replace template with writeup, and add relevant tags
toc: true
image:
  path: /assets/images/thm/Linux-Agency/LinuxAgency.jpg
---



## Info

| Name         | Linux Agency                                                                      |
| ------------ | --------------------------------------------------------------------------------- |
| Room link    | [https://tryhackme.com/room/linuxagency](https://tryhackme.com/room/linuxagency)  |
| Difficulty   | Medium                                                                            |
| Created by   | [Xyan1d3](https://tryhackme.com/p/Xyan1d3) [0z09e](https://tryhackme.com/p/0z09e) |
| solving date | June 9th 2022                                                                     |


## Task 3-Linux Fundamentals

### Mission 1 

```bash
ssh agent47@10.10.12.15
agent47@10.10.12.15's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

**mission1{174d****************************}**
```

* we can see the first flag inside the banner, we can find it in `~/.ssh/rc`

```bash
agent47@linuxagency:~$ cat .ssh/rc
**echo "mission1{174d****************************}"**
```

***

### Mission 2 

* the password for mission1 user is the previous flag

```bash
agent47@linuxagency:~$ su mission1
Password: 
mission1@linuxagency:/home/agent47$ cd 
mission1@linuxagency:~$ ls
mission2{8a1b****************************}
mission1@linuxagency:~$
```

***

### Mission 3 

```bash
mission2@linuxagency:/home/mission1$ cd
mission2@linuxagency:~$ ls
flag.txt
mission2@linuxagency:~$ cat flag.txt
mission3{ab1e****************************}
```

***

### Mission 4 

```bash
mission2@linuxagency:~$ su mission3
Password: 
mission3@linuxagency:/home/mission2$ cd
mission3@linuxagency:~$ ls
flag.txt
mission3@linuxagency:~$ cat flag.txt 
I am really sorry man the flag is stolen by some thief's.
```

* I transferred the flag to my machine to use `hexeditor`, but we can use `xxd`, instead

![Untitled](/assets/images/thm/Linux-Agency/Untitled.png)

```bash
mission3@linuxagency:~$ xxd flag.txt 
00000000: 6d69 7373 696f 6e34 7b32 3634 6137 6565  mission4{264a***
00000010: 6239 3230 6638 3062 3365 6539 3636 3566  ****************
00000020: 6166 6237 6666 3932 647d 0d49 2061 6d20  **********}.I am 
00000030: 7265 616c 6c79 2073 6f72 7279 206d 616e  really sorry man
00000040: 2074 6865 2066 6c61 6720 6973 2073 746f   the flag is sto
00000050: 6c65 6e20 6279 2073 6f6d 6520 7468 6965  len by some thie
00000060: 6627 732e 0a                             f's..
mission3@linuxagency:~$
```

***

### Mission 5 

```bash
mission3@linuxagency:~$ su mission4 
Password: 
mission4@linuxagency:/home/mission3$ cd 
mission4@linuxagency:~$ ls
flag
mission4@linuxagency:~$ cd flag
mission4@linuxagency:~/flag$ ls
flag.txt
mission4@linuxagency:~/flag$ cat flag.txt
mission5{bc67****************************}
mission4@linuxagency:~/flag$
```

***

### Mission 6 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 1.png)

***

### Mission 7 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 2.png)

***

### Mission 8 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 3.png)

***

### Mission 9 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 4.png)

***

### Mission 10 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 5.png)

*   it’s rockyou.txt wordlist, don’t `cat` it , it will explode into your terminal 😅, use grep to cut down the output

    <img src="/assets/images/thm/Linux-Agency/Untitled 6.png" alt="Untitled" data-size="original">

***

### Mission 11 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 7.png)

***

### Mission 12 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 8.png)

*   first, we didn’t find anything inside mission11’s home so I searched for flag.txt but we didn’t find mission12s’ flag so we checked my Environment Variables (`env`), you also can echo the flag

    <img src="/assets/images/thm/Linux-Agency/Untitled 9.png" alt="Untitled" data-size="original">

***

### Mission 13 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 10.png)

* It’s simple: the flag.txt has no read permission so we changed the permissions to allow reading it

***

### Mission 14 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 11.png)

* decode flag.txt content to get the flag

***

### Mission 15 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 12.png)

* it’s binary, we need to convert it into ASCII text

![Untitled](/assets/images/thm/Linux-Agency/Untitled 13.png)

* Just hit the magic stick

![Untitled](/assets/images/thm/Linux-Agency/Untitled 14.png)

***

### Mission 16 

Just like the previous mission, we found hexadecimal encoded and tried to decode it

![Untitled](/assets/images/thm/Linux-Agency/Untitled 15.png)

***

### Mission 17 

* flag file is ELF binary, I thought that the flag inside it so I used `strings` to print any printable characters but I didn’t find any interesting thing, so I changed the permissions to allow running it and run it to get the flag

![Untitled](/assets/images/thm/Linux-Agency/Untitled 16.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 17.png)

***

### Mission 18 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 18.png)

***

### Mission 19 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 19.png)

***

### Mission 20 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 20.png)

***

### Mission 21 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 21.png)

***

### Mission 22 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 22.png)

* We navigated to the home directory but we didn’t find any flags, I have checked the current shell because of the prompt (`$`) using `echo $0` I found it `shell` so I switch it to bash I found the flag, so the flag is in `.bashrc`

![Untitled](/assets/images/thm/Linux-Agency/Untitled 23.png)

***

### Mission 23 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 24.png)

* it’s python interactive shell, I think mission22 `.bashrc` file starts python whenever mission22 log in

![Untitled](/assets/images/thm/Linux-Agency/Untitled 25.png)

* to execute system commands in python we imported `system` function from `os` module
* it’s very easy to use `system` function just: `system('command')`
* then we navigated to our home directory to get the flag

***

### Mission 24 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 26.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 27.png)

* I didn’t find the flag inside the home directory, so I guessed it was the md5 hash of the message but it’s not, so I started to enumerate the host I found mission24.com inside `/etc/hosts`. use `curl` or `wget` to get the flag

***

### Mission 25 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 28.png)

* We can see bribe binary file Guide us to give him money, I searched for ‘mission’ in `.bashrc`, `.profile`, `.viminfo` but nothing found

![Untitled](/assets/images/thm/Linux-Agency/Untitled 29.png)

*   we found the following in `.viminfo` file

    <img src="/assets/images/thm/Linux-Agency/Untitled 30.png" alt="Untitled" data-size="original">

    *   `.viminfo` content

        ```
        # This viminfo file was generated by Vim 8.0.
        # You may edit it if you're careful!

        # Viminfo version
        |1,4

        # Value of 'encoding' when this file was written
        *encoding=utf-8

        # hlsearch on (H) or off (h):
        ~h
        # Command Line History (newest to oldest):
        :wq
        |2,0,1610305351,,"wq"

        # Search String History (newest to oldest):

        # Expression History (newest to oldest):

        # Input Line History (newest to oldest):

        # Debug Line History (newest to oldest):

        # Registers:
        "0      LINE    0
                const char* p = getenv("pocket");
        |3,0,0,1,1,0,1610305036,"const char* p = getenv(\"pocket\");"
        ""1     LINE    0
                }
                return 0;
        |3,1,1,1,2,0,1610305126,"}","return 0;"
        "2      LINE    0
                }
        |3,0,2,1,1,0,1610305125,"}"
        "3      LINE    0
                        printf("Don't tell police about the deal man ;)");
        |3,0,3,1,1,0,1610305123,"       printf(\"Don't tell police about the deal man ;)\");"
        "4      LINE    0
        printf("Here ya go!!!\n");
        |3,0,5,1,1,0,1610305122,"       printf(\"Here ya go!!!\\n\");"
        "6      LINE    0
                {
        |3,0,6,1,1,0,1610305122,"{      "
        "7      LINE    0
                if(strncmp(p,"money",5) == 0 )
        |3,0,7,1,1,0,1610305121,"if(strncmp(p,\"money\",5) == 0 )"
        "8      LINE    0
                return 0;}
        |3,0,8,1,1,0,1610305120,"return 0;}"
        "9      LINE    0
                {
        |3,0,9,1,1,0,1610305119,"{"

        # File marks:
        '0  14  51  ~/bribe.c
        |4,48,14,51,1610305351,"~/bribe.c"
        '1  7  4  ~/bribe.c
        |4,49,7,4,1610305330,"~/bribe.c"
        '2  7  4  ~/bribe.c
        |4,50,7,4,1610305330,"~/bribe.c"
        '3  6  16  ~/bribe.c
        |4,51,6,16,1610305272,"~/bribe.c"
        '4  6  16  ~/bribe.c
        |4,52,6,16,1610305272,"~/bribe.c"
        '5  6  16  ~/bribe.c
        |4,53,6,16,1610305272,"~/bribe.c"
        '6  6  16  ~/bribe.c
        |4,54,6,16,1610305272,"~/bribe.c"
        '7  17  13  ~/bribe.c
        |4,55,17,13,1610305230,"~/bribe.c"
        '8  16  13  ~/bribe.c
        |4,56,16,13,1610305230,"~/bribe.c"
        '9  17  13  ~/bribe.c
        |4,57,17,13,1610305230,"~/bribe.c"

        # Jumplist (newest first):
        -'  14  51  ~/bribe.c
        |4,39,14,51,1610305351,"~/bribe.c"
        -'  7  4  ~/bribe.c
        |4,39,7,4,1610305342,"~/bribe.c"
        -'  7  4  ~/bribe.c
        |4,39,7,4,1610305330,"~/bribe.c"
        -'  6  16  ~/bribe.c
        |4,39,6,16,1610305316,"~/bribe.c"
        -'  6  16  ~/bribe.c
        |4,39,6,16,1610305316,"~/bribe.c"
        -'  6  16  ~/bribe.c
        |4,39,6,16,1610305272,"~/bribe.c"
        -'  17  13  ~/bribe.c
        |4,39,17,13,1610305244,"~/bribe.c"
        -'  17  13  ~/bribe.c
        |4,39,17,13,1610305244,"~/bribe.c"
        -'  17  13  ~/bribe.c
        |4,39,17,13,1610305244,"~/bribe.c"
        -'  16  13  ~/bribe.c
        |4,39,16,13,1610305230,"~/bribe.c"
        -'  16  13  ~/bribe.c
        |4,39,16,13,1610305230,"~/bribe.c"
        -'  16  13  ~/bribe.c
        |4,39,16,13,1610305230,"~/bribe.c"
        -'  30  0  ~/bribe.c
        |4,39,30,0,1610305107,"~/bribe.c"
        -'  29  0  ~/bribe.c
        |4,39,29,0,1610305107,"~/bribe.c"
        -'  30  0  ~/bribe.c
        |4,39,30,0,1610305107,"~/bribe.c"
        -'  29  0  ~/bribe.c
        |4,39,29,0,1610305107,"~/bribe.c"
        -'  30  0  ~/bribe.c
        |4,39,30,0,1610305107,"~/bribe.c"
        -'  29  0  ~/bribe.c
        |4,39,29,0,1610305107,"~/bribe.c"
        -'  28  0  ~/bribe.c
        |4,39,28,0,1610305070,"~/bribe.c"
        -'  28  0  ~/bribe.c
        |4,39,28,0,1610305070,"~/bribe.c"
        -'  29  0  ~/bribe.c
        |4,39,29,0,1610305070,"~/bribe.c"
        -'  28  0  ~/bribe.c
        |4,39,28,0,1610305070,"~/bribe.c"
        -'  5  0  ~/bribe.c
        |4,39,5,0,1610305063,"~/bribe.c"
        -'  5  0  ~/bribe.c
        |4,39,5,0,1610305063,"~/bribe.c"
        -'  5  0  ~/bribe.c
        |4,39,5,0,1610305063,"~/bribe.c"
        -'  5  0  ~/bribe.c
        |4,39,5,0,1610305063,"~/bribe.c"
        -'  5  0  ~/bribe.c
        |4,39,5,0,1610305063,"~/bribe.c"
        -'  5  0  ~/bribe.c
        |4,39,5,0,1610305046,"~/bribe.c"
        -'  21  0  ~/bribe.c
        |4,39,21,0,1610304952,"~/bribe.c"
        -'  20  0  ~/bribe.c
        |4,39,20,0,1610304952,"~/bribe.c"
        -'  19  0  ~/bribe.c
        |4,39,19,0,1610304952,"~/bribe.c"
        -'  21  0  ~/bribe.c
        |4,39,21,0,1610304952,"~/bribe.c"
        -'  20  0  ~/bribe.c
        |4,39,20,0,1610304952,"~/bribe.c"
        -'  19  0  ~/bribe.c
        |4,39,19,0,1610304952,"~/bribe.c"
        -'  21  0  ~/bribe.c
        |4,39,21,0,1610304952,"~/bribe.c"
        -'  20  0  ~/bribe.c
        |4,39,20,0,1610304952,"~/bribe.c"
        -'  20  0  ~/bribe.c
        |4,39,20,0,1610304952,"~/bribe.c"
        -'  19  0  ~/bribe.c
        |4,39,19,0,1610304952,"~/bribe.c"
        -'  19  0  ~/bribe.c
        |4,39,19,0,1610304952,"~/bribe.c"
        -'  9  0  ~/bribe.c
        |4,39,9,0,1610304944,"~/bribe.c"
        -'  8  0  ~/bribe.c
        |4,39,8,0,1610304944,"~/bribe.c"
        -'  9  0  ~/bribe.c
        |4,39,9,0,1610304944,"~/bribe.c"
        -'  8  0  ~/bribe.c
        |4,39,8,0,1610304944,"~/bribe.c"
        -'  9  0  ~/bribe.c
        |4,39,9,0,1610304944,"~/bribe.c"
        -'  8  0  ~/bribe.c
        |4,39,8,0,1610304944,"~/bribe.c"
        -'  8  0  ~/bribe.c
        |4,39,8,0,1610304944,"~/bribe.c"
        -'  8  0  ~/bribe.c
        |4,39,8,0,1610304944,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"
        -'  1  0  ~/bribe.c
        |4,39,1,0,1610304929,"~/bribe.c"

        # History of marks within files (newest to oldest):

        > ~/bribe.c
                *       1610305350      0
                "       14      51
                ^       14      52
                .       14      51
                +       17      0
                +       20      0
                +       18      14
                +       6       0
                +       5       0
                +       30      0
                +       34      0
                +       35      0
                +       36      0
                +       15      9
                +       9       32
                +       10      7
                +       9       0
                +       6       20
                +       6       17
                +       7       4
                +       14      51
        ```
* bribe binary checks Environment variable called pocket to check the money, let’s assign this variable

![Untitled](/assets/images/thm/Linux-Agency/Untitled 31.png)

***

### Mission 26 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 32.png)

* PATH env was not assigned, so we assigned it using `export PATH=Value`

***

### Mission 27 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 33.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 34.png)

***

### Mission 28 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 35.png)

* It’s gzip compressed data, we decompressed it using `gunzip <file>`, the output is image we used strings to print any printable characters in it.

***

### Mission 29 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 36.png)

* very simple: the flag was reversed we used `rev` to reverse it back

***

### Mission 30 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 37.png)

* `.htpasswd` is **used to create and update the flat-files used to store usernames and password for basic authentication of HTTP users**.

***

### viktor's Flag 
![Untitled](/assets/images/thm/Linux-Agency/Untitled 38.png)

* It’s git repository we used `git log` to Show commit logs

***

## Task4 - Privilege Escalation

![Untitled](/assets/images/thm/Linux-Agency/Untitled 39.png)

> su into viktor user using viktor's flag as password

***

### Dalia's flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 40.png)

*   first We checked our privileges using `sudo -l` but we have no permission to run `sudo` after enumerating `/etc/shadow` (check if it’s readable), `/etc/crontab` we found a corn job for Dalia `sleep30;/opt/scripts/[47.sh](http://47.sh)` and a cron job for root (overwrite 47.sh file and make viktor (the current user we use) the owner, let’s inject bash script to start a listener

    <img src="/assets/images/thm/Linux-Agency/Untitled 41.png" alt="Untitled" data-size="original">
*   We created a pipe then we started `netcat` listener redirecting the input from `f` and the output to `bash` which output redirected to `f`

    <img src="/assets/images/thm/Linux-Agency/Untitled 42.png" alt="Untitled" data-size="original">
*   Stabilizing the shell

    <img src="/assets/images/thm/Linux-Agency/Untitled 43.png" alt="Untitled" data-size="original">
*   Gotcha

    <img src="/assets/images/thm/Linux-Agency/Untitled 44.png" alt="Untitled" data-size="original">

    ***

    *   Another Easy way

        <img src="/assets/images/thm/Linux-Agency/Untitled 45.png" alt="Untitled" data-size="original">

***

### Silvio’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 46.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 47.png)

* [Check GTFOBins](https://gtfobins.github.io/gtfobins/zip/#sudo)
* in our case we can run `zip` as Silvio with No Password, so we will add `-u silvio` option to `sudo` command

![Untitled](/assets/images/thm/Linux-Agency/Untitled 48.png)

***

### Reza’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 49.png)

* `SETENV` allows the user to **set an environment variable** while executing something
*   [GTFOBins](https://gtfobins.github.io/gtfobins/git/#sudo)

    <img src="/assets/images/thm/Linux-Agency/Untitled 50.png" alt="Untitled" data-size="original">

***

### Jordan’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 51.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 52.png)

* Gun-Shop.py imports module called shop
*   We are going to use `PYTHONPATH` Hijacking

    * What is `PYTHONPATH`
      * `PYTHONPATH` is **an environment variable which you can set to add additional directories where python will look for modules and packages**. For most installations, you should not set these variables since they are not needed for Python to run. Python knows where to find its standard library.

    <img src="/assets/images/thm/Linux-Agency/Untitled 53.png" alt="Untitled" data-size="original">

    <img src="/assets/images/thm/Linux-Agency/Untitled 54.png" alt="Untitled" data-size="original">

***

### Ken’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 55.png)

* [GTFOBins](https://gtfobins.github.io/gtfobins/less/#sudo)
*   `sudo -u ken less /etc/passwd`

    <img src="/assets/images/thm/Linux-Agency/Untitled 56.png" alt="Untitled" data-size="original">

    <img src="/assets/images/thm/Linux-Agency/Untitled 57.png" alt="Untitled" data-size="original">

    <img src="/assets/images/thm/Linux-Agency/Untitled 58.png" alt="Untitled" data-size="original">

***

### Sean’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 59.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 60.png)

```bash
sean@linuxagency:~$ grep 'sean{' -R /* 2>/dev/null
/var/log/syslog.bak:Jan 12 02:58:58 ubuntu kernel: [    0.000000] ACPI: LAPIC_NMI (acpi_id[0x6d] high edge lint[0x1]) : sean{4c56****************************} **VGhlIHBhc3N3b3JkIG9mIHBlbmVsb3BlIGlzIHAzbmVsb3BlCg==**
```

***

### penelope’s flag

![Untitled](/assets/images/thm/Linux-Agency/Untitled 61.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 62.png)

***

### Maya’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 63.png)

SUID: It is **special file permission for executable files**. This enables other users to run the file with the effective permissions of the file owner. But Instead of normal x which represents executable permissions.

![Untitled](/assets/images/thm/Linux-Agency/Untitled 64.png)

* We can’t read `/home/maya/flag.txt`, but may can so we can run `base64` SUID file to encode `flag.txt` with Maya's privilege and then decode the result with `base64`

***

### robert’s flag 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 65.png)

* Let’s crack the ssh key passphrase, but we need to convert the key to an understandable format for john, we can do it using `ssh2john`

![Untitled](/assets/images/thm/Linux-Agency/Untitled 66.png)

***

### user.txt 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 67.png)

* Let’s use the ssh key with the Passphrase we cracked

![Untitled](/assets/images/thm/Linux-Agency/Untitled 68.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 69.png)

*   Oh😀 It’s `CVE-2019-14287`, It’s very easy to exploit

    <img src="/assets/images/thm/Linux-Agency/Untitled 70.png" alt="Untitled" data-size="original">

    * Just it😊
* There is a great TryHackMe room explains this vulnerability [here](https://tryhackme.com/room/sudovulnsbypass)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 71.png)

***

### root.txt 

![Untitled](/assets/images/thm/Linux-Agency/Untitled 72.png)

![Untitled](/assets/images/thm/Linux-Agency/Untitled 73.png)

***

