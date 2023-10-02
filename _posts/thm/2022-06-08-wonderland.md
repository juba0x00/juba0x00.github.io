---
title: TryHackMe - Wonderland                    # Add title of the machine here
date: 2022-06-09 08:00:00 -0600                           # Change the date to match completion date
categories: TryHackMe                    # Change Templates to Writeup
tags: [thm, writeup, privesc]     # TAG names should always be lowercase; replace template with writeup, and add relevant tags
toc: true
image:
  path: /assets/images/thm/Wonderland/wonderland.png
---

# Info

| Name         | Wonderland                                     |
| ------------ | ---------------------------------------------- |
| Room link    | [https://tryhackme.com/room/wonderland](https://tryhackme.com/room/wonderland)          |
| Difficulty   | Medium                                         |
| Created by   | [NinjaJc01](https://tryhackme.com/p/NinjaJc01) |
| solving date | June 8th 2022                                  |

***

* Table Of Contents
  * Information Gathering
  * Gaining Access
  * Privilege Escalation
    * from Alice to rabbit
    * from rabbit to hatter
    * from hatter to root
  * Getting the flag
    * root flag
    * user flag

***

# Information Gathering

```bash
export target=10.10.43.237
```

*   namp inital port scan

    ```
    Nmap scan report for 10.10.43.237
    Host is up, received user-set (0.12s latency).
    Scanned at 2022-06-09 12:54:20 EET for 34s
    Not shown: 998 closed ports
    Reason: 998 conn-refused
    PORT   STATE SERVICE REASON  VERSION
    **22**/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    **80**/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 34.24 seconds
    ```

    * we found ports 22 and 80 open let’s navigate to the website while scanning all the ports with `nmap -Pn -vv -p- $target`
*   the website:

    <img src="/assets/images/thm/Wonderland/Untitled 2.png" alt="Untitled" data-size="original">
*   look for any interesting information on the site Source

    <img src="/assets/images/thm/Wonderland/Untitled 3.png" alt="Untitled" data-size="original">

    * nothing interesting here
* I close it because the internet speed with really bad and Nmap full scan took too much time, but it seems that there is no more open ports
*   Let’s do some fuzzing using `feroxbuster`

    <img src="/assets/images/thm/Wonderland/Untitled 4.png" alt="Untitled" data-size="original">
* it seems that the directory is rabbit, like: /r/a/b/b/i/t

![Untitled](</assets/images/thm/Wonderland/Untitled 5.png>)

![Untitled](</assets/images/thm/Wonderland/Untitled 6.png>)

![Untitled](</assets/images/thm/Wonderland/Untitled 7.png>)

![Untitled](</assets/images/thm/Wonderland/Untitled 8.png>)

![Untitled](</assets/images/thm/Wonderland/Untitled 9.png>)

![Untitled](</assets/images/thm/Wonderland/Untitled 10.png>)

*   After checking the sources of these pages, we found this interesting information in `/r/a/b/b/i/t` path

    <img src="/assets/images/thm/Wonderland/Untitled 11.png" alt="Untitled" data-size="original">

***

# Gaining Access

*   let’s check if this is a valid credential using ssh (we know that ssh is running from our nmap scan

    <img src="/assets/images/thm/Wonderland/Untitled 12.png" alt="Untitled" data-size="original">

    * Great 🙂

***

# Privilege Escalation

## PrivEsc: From Alice to rabbit

*   we can’t view root.txt content

    <img src="/assets/images/thm/Wonderland/Untitled 13.png" alt="Untitled" data-size="original">
*   Let’s search for user.txt file first

    ```bash
    alice@wonderland:~$ find / -name user.txt 2>/dev/null
    alice@wonderland:~$ # Nothing found
    ```
* checking our privileges

![Untitled](</assets/images/thm/Wonderland/Untitled 14.png>)

* we can run `/usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py` as rabbit user
* as we can see, we can’t edit the python script, but we can read it

```bash
alice@wonderland:~$ ls -l walrus_and_the_carpenter.py 
-rw-r--r-- 1 root root 3577 May 25  2020 walrus_and_the_carpenter.py
```

<details>

<summary>walrus_and_the_carpenter.py (click me)</summary>


**import random**
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.

The moon was shining sulkily,
Because she thought the sun
Had got no business to be there
After the day was done —
"It’s very rude of him," she said,
"To come and spoil the fun!"

The sea was wet as wet could be,
The sands were dry as dry.
You could not see a cloud, because
No cloud was in the sky:
No birds were flying over head —
There were no birds to fly.

The Walrus and the Carpenter
Were walking close at hand;
They wept like anything to see
Such quantities of sand:
"If this were only cleared away,"
They said, "it would be grand!"

"If seven maids with seven mops
Swept it for half a year,
Do you suppose," the Walrus said,
"That they could get it clear?"
"I doubt it," said the Carpenter,
And shed a bitter tear.

"O Oysters, come and walk with us!"
The Walrus did beseech.
"A pleasant walk, a pleasant talk,
Along the briny beach:
We cannot do with more than four,
To give a hand to each."

The eldest Oyster looked at him.
But never a word he said:
The eldest Oyster winked his eye,
And shook his heavy head —
Meaning to say he did not choose
To leave the oyster-bed.

But four young oysters hurried up,
All eager for the treat:
Their coats were brushed, their faces washed,
Their shoes were clean and neat —
And this was odd, because, you know,
They hadn’t any feet.

Four other Oysters followed them,
And yet another four;
And thick and fast they came at last,
And more, and more, and more —
All hopping through the frothy waves,
And scrambling to the shore.

The Walrus and the Carpenter
Walked on a mile or so,
And then they rested on a rock
Conveniently low:
And all the little Oysters stood
And waited in a row.

"The time has come," the Walrus said,
"To talk of many things:
Of shoes — and ships — and sealing-wax —
Of cabbages — and kings —
And why the sea is boiling hot —
And whether pigs have wings."

"But wait a bit," the Oysters cried,
"Before we have our chat;
For some of us are out of breath,
And all of us are fat!"
"No hurry!" said the Carpenter.
They thanked him much for that.

"A loaf of bread," the Walrus said,
"Is what we chiefly need:
Pepper and vinegar besides
Are very good indeed —
Now if you’re ready Oysters dear,
We can begin to feed."

"But not on us!" the Oysters cried,
Turning a little blue,
"After such kindness, that would be
A dismal thing to do!"
"The night is fine," the Walrus said
"Do you admire the view?

"It was so kind of you to come!
And you are very nice!"
The Carpenter said nothing but
"Cut us another slice:
I wish you were not quite so deaf —
I’ve had to ask you twice!"

"It seems a shame," the Walrus said,
"To play them such a trick,
After we’ve brought them out so far,
And made them trot so quick!"
The Carpenter said nothing but
"The butter’s spread too thick!"

"I weep for you," the Walrus said.
"I deeply sympathize."
With sobs and tears he sorted out
Those of the largest size.
Holding his pocket handkerchief
Before his streaming eyes.

"O Oysters," said the Carpenter.
"You’ve had a pleasant run!
Shall we be trotting home again?"
But answer came there none —
And that was scarcely odd, because
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)



</details>

*   in the first line, we can see it imports `random` module, so we can do python module Hijacking by creating `random.py` file in the same directory using `touch random.py` command

    <img src="/assets/images/thm/Wonderland/Untitled 15.png" alt="Untitled" data-size="original">
*   run the script to make sure it runs as rabbit

    <img src="/assets/images/thm/Wonderland/Untitled 16.png" alt="Untitled" data-size="original">

    * as we can notice the user running the script is rabbit
*   let’s inject our malicious script

    <img src="/assets/images/thm/Wonderland/Untitled 17.png" alt="Untitled" data-size="original">

    <img src="/assets/images/thm/Wonderland/Untitled 18.png" alt="Untitled" data-size="original">

***

## PrivEsc: From rabbit to hatter

*   discovering rabbit home directory

    <img src="/assets/images/thm/Wonderland/Untitled 19.png" alt="Untitled" data-size="original">
* it’s SUID binary file running with root privileges
*   strings command is not installed, so we will copy teaParty to our system (strings: print the sequences of printable characters in files)

    <img src="/assets/images/thm/Wonderland/Untitled 20.png" alt="Untitled" data-size="original">
*   transferring teaParty using netcat

    <img src="/assets/images/thm/Wonderland/Untitled 21.png" alt="Untitled" data-size="original">
*   teaParty content:

    ```
    ╭─juba@Kubuntu ~ 
    ╰─$ strings teaParty 
    /lib64/ld-linux-x86-64.so.2
    2U~4
    libc.so.6
    setuid
    puts
    getchar
    system
    __cxa_finalize
    setgid
    __libc_start_main
    GLIBC_2.2.5
    _ITM_deregisterTMCloneTable
    __gmon_start__
    _ITM_registerTMCloneTable
    u/UH
    []A\A]A^A_
    Welcome to the tea party!
    The Mad Hatter will be here soon.
    /bin/echo -n 'Probably by ' && **date** --date='next hour' -R
    Ask very nicely, and I will give you some tea while you wait for him
    Segmentation fault (core dumped)
    ;*3$"
    GCC: (Debian 8.3.0-6) 8.3.0
    crtstuff.c
    deregister_tm_clones
    __do_global_dtors_aux
    completed.7325
    __do_global_dtors_aux_fini_array_entry
    frame_dummy
    __frame_dummy_init_array_entry
    teaParty.c
    __FRAME_END__
    __init_array_end
    _DYNAMIC
    __init_array_start
    __GNU_EH_FRAME_HDR
    _GLOBAL_OFFSET_TABLE_
    __libc_csu_fini
    _ITM_deregisterTMCloneTable
    puts@@GLIBC_2.2.5
    _edata
    system@@GLIBC_2.2.5
    __libc_start_main@@GLIBC_2.2.5
    __data_start
    getchar@@GLIBC_2.2.5
    __gmon_start__
    __dso_handle
    _IO_stdin_used
    __libc_csu_init
    __bss_start
    main
    setgid@@GLIBC_2.2.5
    __TMC_END__
    _ITM_registerTMCloneTable
    setuid@@GLIBC_2.2.5
    __cxa_finalize@@GLIBC_2.2.5
    .symtab
    .strtab
    .shstrtab
    .interp
    .note.ABI-tag
    .note.gnu.build-id
    .gnu.hash
    .dynsym
    .dynstr
    .gnu.version
    .gnu.version_r
    .rela.dyn
    .rela.plt
    .init
    .plt.got
    .text
    .fini
    .rodata
    .eh_frame_hdr
    .eh_frame
    .init_array
    .fini_array
    .dynamic
    .got.plt
    .data
    .bss
    .comment
    ```
* we noticed this line `/bin/echo -n 'Probably by ' && **date** --date='next hour' -R` he is calling `date` without specifying the full path, so let’s create an executable date file and add it’s directory to the $PATH env
*   write a script to check our plan

    <img src="/assets/images/thm/Wonderland/Untitled 22.png" alt="Untitled" data-size="original">
*   give execution permission for all users

    <img src="/assets/images/thm/Wonderland/Untitled 23.png" alt="Untitled" data-size="original">
*   run teaParty

    <img src="/assets/images/thm/Wonderland/Untitled 24.png" alt="Untitled" data-size="original">
*   as we can see we are hatter, so let’s inject our malicious script it’s just adding (`/bin/bash`) 😊 to get the shell

    <img src="/assets/images/thm/Wonderland/Untitled 25.png" alt="Untitled" data-size="original">

***

## PrivEsc: From hatter to root

*   discovering hatter home directory

    <img src="/assets/images/thm/Wonderland/Untitled 26.png" alt="Untitled" data-size="original">
*   we found a password but I don’t know if it’s the root password or hatter’s password, so let’s try it

    <img src="/assets/images/thm/Wonderland/Untitled 27.png" alt="Untitled" data-size="original">

    <img src="/assets/images/thm/Wonderland/Untitled 28.png" alt="Untitled" data-size="original">

    * it’s hatter’s password
* After some manual enumeration, I prefer to speed the process by using an automation tool like [Linenum](https://github.com/rebootuser/LinEnum)

<details>

<summary>LinEnum Result (click me)</summary>


[REDACTED]

Files with POSIX capabilities set:[00m
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep

[REDACTED]






</details>



* we noticed this line ‘`/usr/bin/perl = **cap_setuid+ep`’\*\* it means that `/usr/bin/perl` can set the user ID, so we can use perl to set it to zero (root)
* if you are not familiar with perl, you can see this exploit in [GTFoBins](https://gtfobins.github.io/gtfobins/perl/#capabilities)

![Untitled](</assets/images/thm/Wonderland/Untitled 29.png>)

* great, we are root (Notice the prompt is #)

***


# Getting the flags

## root flag

![Untitled](</assets/images/thm/Wonderland/Untitled 30.png>)

***

## user flag

![Untitled](</assets/images/thm/Wonderland/Untitled 31.png>)

***
