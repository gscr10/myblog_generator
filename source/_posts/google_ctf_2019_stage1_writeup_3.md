---
title: goolge ctf 2019 stage1 writeup_part_3
date: 2019-10-02 12:54:01
tags:
- ctf
categories:
- [ctf]
---
## 09 Drive to the target(coding)

- <https://drivetothetarget.web.ctfcompetition.com/>

```txt
Driving to the target
Hurry up, don't be late for you rendez-vous!

Pick your direction
51.6498  0.0982  go
```

- when we change the number, the web will tips :
You went 44m at a speed of 21km/h. You are getting away…
Woa, were about to move at 126318km/h, this is too fast!
...
- the url has 3 parameters:`lat` `lon` `token`,<https://drivetothetarget.web.ctfcompetition.com/?lat=51.6508&lon=3.1001&token=gAAAAABdjLCgmVVSZCgN5-oaDZn9wJnMyNh-EuBXjx1vuSEaMEt4rmB4okyhbOWTOFVo8W4ttBuFX6-7z8A1dqNbzm1XMpVJVDdwj7vQCxPqYYA_Wlrhz_7cbEL61hfMst4nAlYhlNtR>
- in the 2-d maps we should calculate the right directoin lat-lon, and get the flag
- calculate.py

```py
#!/usr/bin/env python3

import bs4
import requests
import sys

def get_coordinates(url):

    page = requests.get(url).content
    soup = bs4.BeautifulSoup(page, "html.parser")

    cLat = float(soup.find("input", attrs={"name": "lat"})["value"])
    cLon = float(soup.find("input", attrs={"name": "lon"})["value"])
    tken = soup.find("input", attrs={"name": "token"})["value"]
    stat = -1 if "away" in soup.text else 0

    return [cLat, cLon], tken, stat

def main(args):

    url = "https://drivetothetarget.web.ctfcompetition.com/"

    if len(args) == 0:
        pair, token, stat = get_coordinates(url)
    else:
        pair, token, stat = get_coordinates(args[0])

    done   = False
    switch = False
    before = None

    step = 0.0001

    while True:

        if not switch:
            params = "?lat=%.4f&lon=%.4f&token=%s" % (pair[0], pair[1] + step, token)
        else:
            params = "?lat=%.4f&lon=%.4f&token=%s" % (pair[0] + step, pair[1], token)

        try:
            pair, token, stat = get_coordinates(url + params)
        except:
            print(url + params)
            quit()

        if ( stat == -1 and before == -1 ):
            step *= -1

        if not switch and ( stat == -1 and before == 0 ):
            switch   = True
            pair[1] -= step
        elif switch and ( stat == -1 and before == 0 ):
            print(url + params)
            quit()

        before = stat

        print("%.4f, %.4f" % (pair[0], pair[1]), ": Closer" if not stat else ": Further")

if __name__ == "__main__":
    main(sys.argv[1::])
```

```sh
⚡ root@r10  ~/google_ctf  python3 calculate.py
51.6498, 0.0983 : Further
51.6498, 0.0984 : Further
51.6498, 0.0983 : Closer
51.6498, 0.0982 : Closer
51.6498, 0.0981 : Closer
...
```

- finily get 

```txt
lat=51 .4921 , lon= -01929
Congratulations, you made it, here is the flag: CTF{Who_isardis_Ormandy}
```

- ==**flag:CTF{Who_is_Tardis_Ormandy}**==

## 10 Crypto Caulingo(crypto)

- check files information

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/10_crypto_caulingo
╰─➤  file *
crypto.zip:     Zip archive data, at least v2.0 to extract
msg.txt:        ASCII text, with very long lines
project_dc.pdf: PDF document, version 1.5
```

- msg.txt

```txt
n:
17450892350509567071590987572582143158927907441748820483575144211411640241849663641180283816984167447652133133054833591585389505754635416604577584488321462013117163124742030681698693455489404696371546386866372290759608301392572928615767980244699473803730080008332364994345680261823712464595329369719516212105135055607592676087287980208987076052877442747436020751549591608244950255761481664468992126299001817410516694015560044888704699389291971764957871922598761298482950811618390145762835363357354812871474680543182075024126064364949000115542650091904557502192704672930197172086048687333172564520657739528469975770627

e:
65537

msg:
50fb0b3f17315f7dfa25378fa0b06c8d955fad0493365669bbaa524688128ee9099ab713a3369a5844bdd99a5db98f333ef55159d3025630c869216889be03120e3a4bd6553d7111c089220086092bcffc5e42f1004f9888f25892a7ca007e8ac6de9463da46f71af4c8a8f806bee92bf79a8121a7a34c3d564ac7f11b224dc090d97fdb427c10867ad177ec35525b513e40bef3b2ba3e6c97cb31d4fe3a6231fdb15643b84a1ce704838d8b99e5b0737e1fd30a9cc51786dcac07dcb9c0161fc754cda5380fdf3147eb4fbe49bc9821a0bcad98d6df9fbdf63cf7d7a5e4f6cbea4b683dfa965d0bd51f792047e393ddd7b7d99931c3ed1d033cebc91968d43f
```

- check project_dc.pdf, we find `RSA`
- use RSA encryption to get the clear msg. n is very big ,but primes p, q composing the modulus are subject to the following constraint:

```txt
|a*p-b*q| < 10000, with 1 <= a,b <= 1000.
=>
a * p ≈ b * q
-> a / b * p ≈ q
-> a / b * p * q ≈ q * q
-> a / b * N ≈ q^2
-> q^2 ≈ N / b * a
-> q ≈ sqrt(N / b * a)
```

- use bruteforce find a and b, then find q and q (p*q=n)
- solution.py

```py
#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, isqrt, invert, powmod

n = mpz(17450892350509567071590987572582143158927907441748820483575144211411640241849663641180283816984167447652133133054833591585389505754635416604577584488321462013117163124742030681698693455489404696371546386866372290759608301392572928615767980244699473803730080008332364994345680261823712464595329369719516212105135055607592676087287980208987076052877442747436020751549591608244950255761481664468992126299001817410516694015560044888704699389291971764957871922598761298482950811618390145762835363357354812871474680543182075024126064364949000115542650091904557502192704672930197172086048687333172564520657739528469975770627)
e = 65537

c = bytes_to_long(bytes.fromhex('50fb0b3f17315f7dfa25378fa0b06c8d955fad0493365669bbaa524688128ee9099ab713a3369a5844bdd99a5db98f333ef55159d3025630c869216889be03120e3a4bd6553d7111c089220086092bcffc5e42f1004f9888f25892a7ca007e8ac6de9463da46f71af4c8a8f806bee92bf79a8121a7a34c3d564ac7f11b224dc090d97fdb427c10867ad177ec35525b513e40bef3b2ba3e6c97cb31d4fe3a6231fdb15643b84a1ce704838d8b99e5b0737e1fd30a9cc51786dcac07dcb9c0161fc754cda5380fdf3147eb4fbe49bc9821a0bcad98d6df9fbdf63cf7d7a5e4f6cbea4b683dfa965d0bd51f792047e393ddd7b7d99931c3ed1d033cebc91968d43f'))

def solve_pq(n):
    for a in range(1, 1001):
        for b in range(a, 1001):
            est_q = isqrt(n // b * a)
            for q in range(est_q - 100, est_q + 100):
                if n % q == 0:
                    return n // q, q

p, q = solve_pq(n)
phi = (p - 1) * (q - 1)
d = invert(e, phi)

msg = long_to_bytes(powmod(c, d, n))
print(msg.decode('utf-8'))
```

```sh
⚡ ⚙ root@r10  ~/google_ctf  python3 solution.py
Hey there!

If you are able to decrypt this message, you must a life form with high intelligence!

Therefore, we would like to invite you to our dancing party! 

Here’s your invitation code: CTF{017d72f0b513e89830bccf5a36306ad944085a47}
```

- ==**flag:CTF{017d72f0b513e89830bccf5a36306ad944085a47}**==

## 11 Gate lock(hardware)

- unzip the file, and check the information

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/11_gate_lock
╰─➤  ll
total 1.4M
drwxrwxrwx 1 r10 r10 4.0K May 21 06:06 beginner
-rwxrwxrwx 1 r10 r10 686K Dec 31  1979 challenge.tgz
-rwxrwxrwx 1 r10 r10 686K Jun 23 03:31 gate_lock.zip

╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/11_gate_lock
╰─➤  cd beginner

╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/11_gate_lock/beginner
╰─➤  ll
total 5.6M
-rwxrwxrwx 1 r10 r10  24K May 21 06:06 auth.sqlite
-rwxrwxrwx 1 r10 r10  588 May 21 06:06 env_meta.txt
-rwxrwxrwx 1 r10 r10    9 May 21 06:06 force_loaded.txt
-rwxrwxrwx 1 r10 r10    0 May 21 06:06 ipban.txt
-rwxrwxrwx 1 r10 r10 5.6M May 21 06:06 map.sqlite
-rwxrwxrwx 1 r10 r10  783 May 21 06:06 map_meta.txt
-rwxrwxrwx 1 r10 r10    9 May 21 06:06 mesecon_actionqueue
-rwxrwxrwx 1 r10 r10  36K May 21 06:06 players.sqlite
drwxrwxrwx 1 r10 r10 4.0K May 20 22:49 schems
-rwxrwxrwx 1 r10 r10  611 May 21 06:19 world.mt

╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/11_gate_lock/beginner
╰─➤  file *
auth.sqlite:         SQLite 3.x database, last written using SQLite version 3028000
env_meta.txt:        ASCII text, with very long lines
force_loaded.txt:    ASCII text, with no line terminators
ipban.txt:           empty
map.sqlite:          SQLite 3.x database, last written using SQLite version 3028000
map_meta.txt:        ASCII text
mesecon_actionqueue: ASCII text, with no line terminators
players.sqlite:      SQLite 3.x database, last written using SQLite version 3028000
schems:              directory
world.mt:            ASCII text
```

- this is a world in game minetest, load the world, show a map of logic gates.
- analyze the map and caiculate 
- world.py

```py
from itertools import product

def first_stage(x):
    return [
        x[2] and not x[3],
        x[4] or x[5],
        x[14] or x[6],
        x[9] and not x[1],
        x[20] and not x[18],
        x[17] or x[19],
        x[7] and not x[6],
        x[16] or x[8],
        x[10] or not x[2],
        x[12] or not x[4],
        x[2] or not x[10],
        x[5] or not x[13],
        x[11] and x[3],
        x[13] or not x[5],
        x[4] or not x[12],
        x[14] and x[6],
        x[15] and x[7],
        x[15] or x[7],
        x[11] or x[3]
    ]

def second_stage(x):
    return [
        x[1] and not x[2],
        x[3] and x[4],
        x[5] and not x[6],
        x[7] and not x[8],
        x[10] and x[11],
        x[12] and not x[13],
        x[14] and x[15],
        x[16] or x[17],
        x[18] and x[19]
    ]

def third_stage(x,f):
    return [
        x[1] and x[2],
        x[3] and x[4],
        x[5] and f[9],
        x[6] and x[7],
        x[8] or not x[9]
    ]

def fourth_stage(x):
    return [
        x[1] and x[2],
        x[4] and not x[5]
    ]

def circuit(arr):
    f = first_stage(arr)
    f = [None] + f
    s = second_stage(f)
    s = [None] + s
    t = third_stage(s,f)
    t= [None] + t
    f4 = fourth_stage(t)
    last = f4[0] and (f4[1] and t[3])
    return last

def solution():
    for arr in product([True,False],repeat=20):
        l = list(arr)
        l = [None] + l
        if circuit(l):
            return arr

sol = solution()
print('CTF{{{}}}'.format(
    ''.join(['1' if sol[i] else '0' for i in range(20)])
    ))
```

```sh
╭─r10@GSCR10 /mnt/c/Users/R10/Desktop/google ctf/ctf/11_gate_lock
╰─➤  python3 world.py
CTF{01000010111001000001}
```

- ==**flag:CTF{01000010111001000001}**==

## 12 Ad(ad)

- https://www.youtube.com/watch?v=QzFuwljOj8Y
- watch the video, find the flag in the video

- ==**flag:CTF{9e796ca74932912c216a1cd00c25c84fae00e139}**==
