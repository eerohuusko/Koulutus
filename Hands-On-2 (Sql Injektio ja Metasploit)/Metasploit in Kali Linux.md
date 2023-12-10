Kyberturva - Metasploit in Kali Linux
===

Metasploit-land - https://docs.metasploit.com/

Kali Linux comes pre-equipped with all the tools necessary for penetration testing. 

One such tool is the **Metasploit framework** that allows red teamers to perform reconnaissance, scan, enumerate, and exploit vulnerabilities for all types of applications, networks, servers, operating systems, and platforms.

# Metasploit Interface and Its Modules

Metasploit is the most commonly used pentesting tool that comes in Kali Linux. The main components of Metasploit are **msfconsole** and the modules it offers.

## What Is msfconsole?

**msfconsole** is the most commonly used shell-like all-in-one interface that allows you to access all features of Metasploit. 

It has Linux-like command-line (CLI) support as it offers command auto-completion, tabbing, and other bash shortcuts.

It's the main interface that'll allow to work with Metasploit modules for scanning and launching an attack on the target machine.

## Metasploit Modules

Metasploit has small code snippets that enable its main functionality. However, before explaining the modules, you must be clear about the following recurring concepts:

* **Vulnerability:** It is a flaw in the design or code of the target that makes it vulnerable to exploitation leading to the disclosure of confidential information.
* **Exploit:** A code that exploits the found vulnerability. Exploit is a code that leverages the target vulnerabilities to ensure system access via payloads.
* **Payload:** It's a code that helps you achieve the goal of exploiting a vulnerability. It runs inside the target system to access the target data, like maintaining access via Meterpreter or a reverse shell. Payloads helps achieve the desired goal of attacking the target system. That means they will either help get an interactive shell or help maintain a backdoor, run a command or load malware, etc. Metasploit offers two types of payloads: stageless payloads and staged payloads.
* **Auxiliary:** The auxiliary module contains a set of programs such as fuzzers, scanners, and SQL injection tools to gather information and get a deeper understanding of the target system.
* **Encoders:** Encoders encrypt the payloads/exploits to protect them against signature-based antivirus solutions. As payloads or exploits contain null or bad characters, there are high chances for them to be detected by an antivirus solution.
* **Post:** The post-exploitation module will help you gather further information about the system. For instance, it can help you dump the password hashes and look for user credentials for lateral movement or privilege escalation.

````
cd /usr/share/metasploit-framework/modules
ls
tree -L 1 module-name/
````
![](https://gitlab.dclabra.fi/wiki/uploads/upload_f664d02cff625a79202e2e9a497b0edf.png)

# Metasploit’s Interface: msfconsole

To begin using the Metasploit interface, open the Kali Linux terminal and type **msfconsole**.

By default, msfconsole opens up with a banner; to remove that and start the interface in quiet mode, use the msfconsole command with the **-q** flag.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_c701610eac1559f2fb1a50037a43e950.png)

The interface looks like a Linux command-line shell. Some Linux Bash commands it supports are ls, clear, grep, history, jobs, kill, cd, exit, etc.

Type help or a question mark "?" to see the list of all available commands you can use inside msfconsole.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_4b105d4797a2d1bcdec2797090111080.png)

Before beginning, set up the Metasploit database by starting the PostgreSQL server and initialize msfconsole database as follows:

![](https://gitlab.dclabra.fi/wiki/uploads/upload_74c65e34af5825a852d7c5166df85a1e.png)

Now check the database status by initializing msfconsole and running the **./db_status** command.

### msfdb commands
The commands for msfdb are as follows:

**msfdb init** - Creates and begins execution of a database & web service. Additional prompts displayed after this command is executed allows optional configuration of both the username and the password used to connect to the database via the web service. Web service usernames and passwords can be set to a default value, or a value of the users choice.
**msfdb delete** - Deletes the web service and database configuration files. You will also be prompted to delete the database’s contents, but this is not mandatory.
**msfdb reinit** - same as running ./msfdb delete followed immediately by ./msfdb init.
**msfdb status** - Displays if the database & web service are currently active. If the database is active it displays the path to its location. If the web service is active, the Process ID it has been assigned will be displayed.
**msfdb start** - Start the database & web service.
**msfdb stop** - Stop the database & web service.
**msfdb restart** - same as running ./msfdb stop followed immediately by ./msfdb start.

**Example msfdb_status commad**
![](https://gitlab.dclabra.fi/wiki/uploads/upload_7096f3e484d20430d1fd2a7d6695f85b.png)

# MySQL Reconnaissance With msfconsole

Find the IP address of the Metasploitable machine first. Then, use the msfdb_nmap command in msfconsole with Nmap flags to scan the MySQL database at 3306 port.
![](https://gitlab.dclabra.fi/wiki/uploads/upload_479b994f434df194e98f35bb62dfd34b.png)

![](https://gitlab.dclabra.fi/wiki/uploads/upload_f49d280e1c6af6c414740e1bf1b3b5dc.png)

Use the **search option** to look for an **auxiliary module** to scan and enumerate the MySQL database.
![](https://gitlab.dclabra.fi/wiki/uploads/upload_990a3d9ae59ad6a0316e8872be82841b.png)

From the above list, we can use the auxiliary/scanner/mysql/mysql_version module by typing the module name or associated number to scan MySQL version details.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_049f4b2af8802415fd801715d0af6d69.png)

Or use CLI commad

```
use auxiliary/scanner/mysql/mysql_version
```

![](https://gitlab.dclabra.fi/wiki/uploads/upload_482dca31938bc18cdb7c1108c3041e52.png)

The output displays that the only required and unset option is RHOSTS which is the IP address of the target machine. Use the set rhosts command to set the parameter and run the module, as follows:

![](https://gitlab.dclabra.fi/wiki/uploads/upload_38afed39f0ffd50528ad0f6f09d0e43d.png)

The output should be displays the similar MySQL version details as the db_nmap function.

# Bruteforce MySQL Root Account With msfconsole

After scanning, you can also brute force MySQL root account via Metasploit's auxiliary(scanner/mysql/mysql_login) module.

![](https://gitlab.dclabra.fi/wiki/uploads/upload_4fc4f4477e3aee6b803c1578ad48255d.png)

We have to need to set the PASS_FILE parameter to the wordlist path available inside /usr/share/wordlists:

```
set PASS_FILE /usr/share/wordlistss/rockyou.txt
````
Then, specify the IP address of the target machine with the RHOSTS command.
```
set RHOSTS <metasploitable-ip-address>
````
Set BLANK_PASSWORDS to true in case there is no password set for the root account like Case Vastaamo.

``` 
set BLANK_PASSWORDS true
 ````
Finally, **run** the module by typing **run** in the terminal.
![](https://gitlab.dclabra.fi/wiki/uploads/upload_a4c8e0eccac3193edb76f4062d8f152b.png)

# MySQL Enumeration With msfconsole

**msfconsole** also allows you to enumerate the database with the help of the auxiliary(admin/mysql/mysql_enum) module. 
![](https://gitlab.dclabra.fi/wiki/uploads/upload_9910c32ecd8dcd7f8cbd4e0ffebd4ab8.png)


It returns all the accounts with details such as associated privileges and password hashes.

To do that, you'll have to specify the password, username, and rhosts variable.

````
set password ""
set username root
set rhosts <metasploitable-ip-address>
````
![](https://gitlab.dclabra.fi/wiki/uploads/upload_d9b61c03c06dd30cbb08b12749f7ba91.png)

Finally, **run** the module by typing **run** in terminal:

![](https://gitlab.dclabra.fi/wiki/uploads/upload_e9b66f1e66b891cd47ebd6b0eaeb26ec.png)

# MySQL Exploitation With msfconsole

From the enumeration phase, it's clear that the root account has file privileges that enable an attacker to execute the load_file() function. The function allows you to exploit the MySQL database by loading all data from the /etc/password file via the **auxiliary/admin/mysql/mysql_sql** module:

Again, **set the username, password, and rhosts variable.** 
Then, execute a query that invokes the load_file() function and loads the /etc/passwd file.
```
set sql select load_file(\"/etc/password\")
````
![](https://gitlab.dclabra.fi/wiki/uploads/upload_9acd0848e8307a1eecc47fdb540c630e.png)


