# LinkVortex Write-Up - HTB

## Recon

Starting off with nmap:

{% code overflow="wrap" %}
```
PORTS=$(grep "open" all_syn.txt | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//'); sudo nmap -sVC -p $PORTS -Pn -n 10.10.11.47
```
{% endcode %}

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

Navigated to the webapp, didn't find anything special.&#x20;

Running directory and vhost scanning:

### VHOST:

{% code overflow="wrap" %}
```
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://linkvortex.htb -t 100 --exclude-length 226 
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

### Directory:

{% code overflow="wrap" %}
```
gobuster dir -u http://linkvortex.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt --exclude-length 0 -t 100
```
{% endcode %}

Nothing special neither...

So I quickly check the source of the page:

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

```
Ghost 5.58
```

<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

### BruteForcing:

Found admin portal:

<figure><img src="../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Great finding:

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

### SQLi:

And trying SQLi:

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

I tried brute-forcing with custom CeWL list and SQLmap, but I get blacklisted.&#x20;

I started inspecting the source files and the API endpoints of Ghost CMS better...&#x20;

{% code overflow="wrap" %}
```
<script defer src="https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/sodo-search.min.js" data-key="054f7096476b0e8c7ec591c72c" data-styles="https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/main.css" data-sodo-search="http://linkvortex.htb/" crossorigin="anonymous"></script>
```
{% endcode %}

That's the key for the content api, though we can't access the admin api with it..

### Going back...:

I must do something wrong. I went back and realized I fkd the vhost command, I added --append-domain now and found:

```
dev.linkvortex.htb
```

Ran some sub-directory brute-forcing, and found:

```
http://dev.linkvortex.htb/.git/
```

Used git-dumper to dump it.

There are quite some files inside:

<figure><img src="../.gitbook/assets/image (196).png" alt=""><figcaption></figcaption></figure>

Let's do some credential hunting:

```
find . -type f -exec grep -l "password" {} \;
```

Many files! Let's use AI, so I will:

```
grep -r -i "password" /home/czr/HTB/LinkVortex/git-dumper/
```

And feed the enormous output to AI.

{% code overflow="wrap" %}
```
File: /extracted-repo/ghost/core/test/utils/fixtures/data-generator.js
// Password = Sl1m3rson99
password: 'Sl1m3rson99',
This appears frequently as a test user password throughout the codebase.

2. Hashed Passwords for Test Users
File: /extracted-repo/ghost/core/test/regression/api/content/authors.test.js & /posts.test.js
const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';

3. Database Connection Password in CI Workflow
File: /extracted-repo/.github/workflows/ci.yml
mysql root password: 'root'

4. MySQL Authentication in CI
File: /extracted-repo/.github/workflows/ci.yml
authentication plugin: 'caching_sha2_password'

5. Test User "Bad Password" in Regression Tests
File: /extracted-repo/ghost/core/test/regression/api/admin/authentication.test.js
const password = 'OctopiFociPilfer45';

6. Client Certificate Password in Git Dumper Script
File: /home/czr/HTB/LinkVortex/git-dumper/git_dumper.py
client_cert_p12_password=None
This appears to be a parameter in the git_dumper.py script you're using, rather than an actual credential.

7. Various Generated Passwords in Tests
File: /extracted-repo/ghost/core/test/e2e-api/admin/users.test.js
newPassword: '1234abcde!!',
```
{% endcode %}

## Foothold

Found a match - admin@linkvortex.htb:OctopiFociPilfer45

Honestly, this is the worst box ever! It's super random, feels like there is no intended path. Even this password is in a "test" folder.

Using: [https://github.com/godylockz/CVE-2023-40028/tree/main](https://github.com/godylockz/CVE-2023-40028/tree/main)

<figure><img src="../.gitbook/assets/image (197).png" alt=""><figcaption></figcaption></figure>

It seems that we are running in a docker container...

```
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}

```

We got the creds:

```
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
```

<figure><img src="../.gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

## PrivEsc

```
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

```
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh 
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi

```

Super basic. We will nest 2 symlinks...

<figure><img src="../.gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

Not so cool box, but nice enumeration.
