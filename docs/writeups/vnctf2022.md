---
comment: True
---

# VNCTF 2022 Writeup

!!! abstract
    寒假里的一场个人赛，随便打着玩了玩，做了几个 misc，和像 misc 的 web/rev/crypto，排了 35
    
    有几道题差点就能做出来，这里也都写下来了

    [VNCTF 2022 Official WriteUp](/assets/images/writeups/vnctf2022/VNCTF\ 2022\ Official\ WriteUp.pdf)

---

## GameV4.0
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

web 类型的签到题

开始还去认真地玩了这个游戏，然后打完 flag 关也没有看到 flag，就去翻了源码<br/>
发现了 data.js 这个文件保存了所有关卡的数据，然后在文件的最末尾有一行
```json
"ZmxhZw==": "Vk5DVEYlN0JXZWxjb21lX3RvX1ZOQ1RGMjAyMiU3RA=="
```
base64 解码，然后 URL 解码，得到：flag: `VNCTF{Welcome_to_VNCTF2022}`

---

## gocalc0
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

看样子是非预期了

点进 flag 在这里，里面说 flag is in your session，打开 cookies 发现：
```text
session: MTY0NDk4ODEyMnxEdi1CQkFFQ180SUFBUkFCRUFBQVNQLUNBQUVHYzNSeWFXNW5EQVlBQkVaTVFVY0djM1J5YVc1bkRDd0FLbVpzWVdkN01EWXlZamcyWlRNdE1tSTFNaTAwTURFMUxUZzJNall0TjJFNVkyVTVORFV4TldZMGZRPT18sud3sUmK5woUfaXQnzZ_R_eu8wGDMVPjfgXvyKo99os=
```
base64 解码后发现里面还有一段 base64，继续解码，就有 flag 了：`flag{062b86e3-2b52-4015-8626-7a9ce94515f4}`

---

## ezmath
![](https://img.shields.io/badge/-CRYPTO-orange?style=flat-square)

一道没什么含金量的 crypto

题目问第 x 个满足 $(2^n-1)\equiv 0\pmod{15}$ 的 n，并且在一分钟之内回答 777 次<br/>
可以发现这里的 n 一定是 4 的倍数，而且是充要的，所以直接读入然后乘 4 再回答就好了

---

## BabyMaze
![](https://img.shields.io/badge/-REVERSE-inactive?style=flat-square)

一道 python 的 rev

直接 uncompyle6 发现卡死，然后 marshal+dis 读取字节码反编译
```python
import dis
import marshal

with open("BabyMaze.pyc", "rb") as f:
    code = marshal.loads(f.read()[16:])

dis.dis(code)
```
得到开头：
```python
  1           0 JUMP_ABSOLUTE            4
        >>    2 JUMP_ABSOLUTE            6
        >>    4 JUMP_ABSOLUTE            2
        >>    6 LOAD_CONST               0 (1)
...
             66 LOAD_CONST               0 (1)
             68 BUILD_LIST              31
             70 LOAD_CONST               0 (1)
             72 LOAD_CONST               1 (5)
             74 LOAD_CONST               0 (1)
...
            130 LOAD_CONST               0 (1)
            132 BUILD_LIST              31
...
...
           1862 LOAD_CONST               0 (1)
           1864 LOAD_CONST               2 (0)
...
           1920 LOAD_CONST               3 (7)
           1922 LOAD_CONST               0 (1)
           1924 BUILD_LIST              31
           1926 LOAD_CONST               0 (1)
...
           1986 LOAD_CONST               0 (1)

  3        1988 BUILD_LIST              31
           1990 BUILD_LIST              31
           1992 STORE_NAME               0 (_map)
```
结尾：
```python
Disassembly of <code object main at 0x00000222A2AC4660, file ".\BabyMaze.py", line 23>:
0 LOAD_GLOBAL        0 (print)
2 LOAD_CONST         1 ('Welcome To VNCTF2022!!!')
4 CALL_FUNCTION      1
6 POP_TOP

8 LOAD_GLOBAL        0 (print)
0 LOAD_CONST         2 ('Hello Mr. X, this time your mission is to get out of this maze this time.(FIND THAT 7!)')
2 CALL_FUNCTION      1
4 POP_TOP

6 LOAD_GLOBAL        0 (print)
8 LOAD_CONST         3 ('you are still doing the mission alone, this tape will self-destruct in five seconds.')
0 CALL_FUNCTION      1
2 POP_TOP

4 LOAD_GLOBAL        1 (maze)
6 CALL_FUNCTION      0
8 POP_JUMP_IF_FALSE 40

0 LOAD_GLOBAL        0 (print)
2 LOAD_CONST         4 ('Congratulation! flag: VNCTF{md5(your input)}')
4 CALL_FUNCTION      1
6 POP_TOP
8 JUMP_FORWARD       8 (to 48)
```
所以大概意思就是有一个 31*31 列表构成的 _map 地图，1 是墙，0 可以走，5 是自己，要到达 7<br/>
并且通过 wasd 操纵方向，到达 7 的所有输入再 md5 就是 flag

所以直接正则提取列表，然后打印出来手动做一下就好
```python
import re

with open("maze.pyc", "r") as f:
    content = f.read()

res = re.findall("(?:LOAD_CONST.*?\((\d)\))", content, re.S)
print(res)
ptr = 0
for i in range(31):
    for j in range(31):
        if res[ptr] == "1":
            print("█", end="")
        else:
            print(" ", end="")
        ptr += 1
    print()
```

??? done "结果"
    ```text
    ███████████████████████████████
    █ █                 █         █
    █ █ █████████ █████ █ ███████ █
    █ █   █       █   █   █ █   █ █
    █ █████ █████████ █████ █ █ █ █
    █   █   █             █   █   █
    ███ █ ███ █████████████ ███████
    █   █ █   █         █   █   █ █
    █ ███ █ ███ ███████ █ ███ █ █ █
    █     █ █   █   █ █ █   █ █   █
    ███████ █ ███ █ █ █ ███ █ ███ █
    █       █     █   █ █   █ █   █
    █ ███████████████ █ █ ███ █ ███
    █       █       █ █   █   █   █
    █ █████ █ █ █ ███ █████ ███████
    █ █   █ █ █ █ █   █           █
    █ █ █ █ █ █ ███ ███ █████ ███ █
    █ █ █ █ █ █   █   █ █   █ █   █
    █ █ ███ █ ███ ███ █ █ █ ███ ███
    █   █   █ █     █ █ █ █   █   █
    █ ███ █ █ █ █████ █ █ ███ █ █ █
    █ █   █ █ █       █ █ █ █ █ █ █
    █ █ ███ █ ███████████ █ █ █ █ █
    █ █   █ █ █         █ █ █ █ █ █
    █ ███ █ █ █████ █ █ █ █ █ █ █ █
    █   █ █ █     █ █ █   █   █ █ █
    █████ ███████ ███ ███████ ███ █
    █     █     █   █       █     █
    █ █████ ███ ███ ███████ █████ █
    █         █             █     █
    ███████████████████████████████
    ssssddssaassddddwwwwddwwddddddwwddddddssddwwddddddddssssaawwaassaassaassddssaassaawwwwwwaaaaaaaassaassddddwwddssddssssaassddssssaaaaaawwddwwaawwwwaassssssssssssddddssddssddddddddwwaaaaaawwwwddssddwwwwwwwwddssddssssssssddddss
    VNCTF{801f190737434100e7d2790bd5b0732e}
    ```

---

## 仔细找找
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

??? question "题目"
    ![](/assets/images/writeups/vnctf2022/zxzz.png)

很明显能发现有像素格点，并且有一些颜色不一样，可能是 flag<br/>
于是打算提取出所有格点，但是好像是分块的，不能一次性完整提取

于是就肉眼硬看，得到 flag：`vnctf{34aE@w}`

看了 wp，是缩放大小重新采样：
```python
from PIL import Image
img = Image.open("flag.png")
img = img.resize((79, 71), Image.NEAREST)
img.show()
```
就能清晰看到 flag 了

---

## Strange flag
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

一个流量包，wireshark 打开，追踪最后一个 TCP 流<br/>
读一下请求，发现是进入到了 flag 目录下执行了 tree 命令

得到的 response 是 gzip 压缩后的，取出内容，然后解压得到 tree 的结果：
```text
flag
`-- New\ folder
    |-- New\ folder
    |   |-- New\ folder
    |   |-- New\ folder\ (2)
    |   |-- New\ folder\ (3)
    |   `-- New\ folder\ (4)
    `-- New\ folder\ (2)
        |-- New\ Folder\ (3)
        |   |-- New\ folder
        |   |   |-- New\ folder
        |   |   |   |-- New\ folder
        |   |   |   |-- New\ folder(2)
        |   |   |   |   `-- New\ folder
        |   |   |   |-- New\ folder(3)
        |   |   |   |   `-- New\ folder
        |   |   |   `-- New\ folder(4)
        |   |   |       `-- New\ folder
        |   |   `-- New\ folder(2)
        |   |       |-- New\ folder
        |   |       |-- New\ folder(2)
        |   |       |   `-- New\ folder
        |   |       |-- New\ folder(3)
        |   |       |   `-- New\ folder
        |   |       `-- New\ folder(4)
        |   |-- New\ folder(10)
...
```
不难发现，是一堆空文件夹形成的结构<br/>
然后就回想起了之前看到的一种 esolang 叫 Folders，是通过一堆嵌套的空文件夹编写的，这个可能就是

先重建起这个目录结构，没找到逆 tree 的现成工具，只好手写一个了：
```python
import os
from pathlib import Path

with open("test", "r") as f:
    tree = f.readlines()

path = Path("flag")
last_level = -1

for each in tree:
    level = each.find("N")//4
    if level < last_level:
        path = path.parent
    if level == last_level:
        path = path.parent
    diff = last_level - level
    for _ in range(diff):
        path = path.parent
    path = path / each.strip().replace("\\", "")
    last_level = level
    os.makedirs(path)
```
查了下，Folders 有工具，pip install Folders，然后 Folders flag/，得到 flag：`vnctf{d23903879df57503879bcdf1efc141fe}`

---

## prize wheel
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 差一点，最后的图片逆过去的思路完全错了

首先给了一个 exe，开始也没意识到这个是抽奖，规则也没看，随便跑了跑就拿到了压缩包密码 `f6a623a2c577de3b46c079267d4bdd6e`<br/>
再细看发现是 0.5% 的概率能抽到密码，预期是自动化抽奖或者逆向，结果我三次就抽出来了？？（欧在了不需要的地方.jpg）
??? tip "充满希望的影像（"
    ![](/assets/images/writeups/vnctf2022/prize.jpg)

压缩包解开之后得到另一个图片
??? question "题目"
    ![](/assets/images/writeups/vnctf2022/prize.png)

很明显应该是一张图片提取出了所有像素点，然后蛇形重新排列形成这张图片

题目 hint 也说了存在可以定位的东西，肯定是那些白点<br/>
但是我的写法怎么样都不会让这些对在一起<br/>
我的想法是蛇形提取出所有像素点，然后按照顺序从上到下从左到右填入
??? fail "我的写法"
    ```python
    from PIL import Image
    from tqdm import tqdm
    import sys

    img = Image.open("flag.png")
    width, height = img.size
    res = Image.new("RGBA", (1220, 1220))

    lst = []

    for i in range(width // 2 + 1):
        for j in range(i, width - i):
            lst.append(img.getpixel((i, j)))
        for j in range(i + 1, width - i):
            lst.append(img.getpixel((j, width-i-1)))
        for j in range(width - i - 2, i, -1):
            lst.append(img.getpixel((width-i-1, j)))
        for j in range(width - i - 1, i, -1):
            lst.append(img.getpixel((j, i)))

    lst = lst[::-1]

    with tqdm(total=600) as pbar:
        for times in range(600):
            ptr = 0
            res = Image.new("RGBA", (610, 1221))
            for j in range(1220):
                for i in range(width-times):
                    try:
                        res.putpixel((i, j), lst[ptr])
                        ptr += 1
                    except:
                        pass
            pbar.update(1)
            res.save(f"res/-{times}.png")
    ```
    换了好多种顺序，导出了一千多张图片也没有长得好看的

看了 wp，知道了每一个正方形的圈上都有一个白色的点，要旋转每一圈，让白色的点对成一条线

所以需要写脚本来旋转每一个正方形的圈直到对齐：
??? done "正解"
    ```python
    from PIL import Image
    img = Image.open('flag.png')
    width, height = img.size
    c_x = width // 2
    c_y = height // 2
    for count in range(3, width+1, 2):
        print(count)
        d = count // 2
        for i in range((count-1)*4):
            p_x = c_x - d
            p_y = c_y - d
            tmp0 = img.getpixel((width//2, c_y-count//2))
            if tmp0[0] == 255 and tmp0[1] == 255 and tmp0[2] == 255:
                break
            tmp = img.getpixel((p_x, p_y))
            for j in range(count-1):
                img.putpixel((p_x, p_y), (img.getpixel((p_x+1, p_y))))
                p_x += 1
            for j in range(count-1):
                img.putpixel((p_x, p_y), (img.getpixel((p_x, p_y+1))))
                p_y += 1
            for j in range(count-1):
                img.putpixel((p_x, p_y), (img.getpixel((p_x-1, p_y))))
                p_x -= 1
            for j in range(count-2):
                img.putpixel((p_x, p_y), (img.getpixel((p_x, p_y-1))))
                p_y -= 1
            img.putpixel((p_x, p_y), tmp)
    img.save("trueflag.png")
    ```
    ![](/assets/images/writeups/vnctf2022/prize_wheel.png)

---

## simple macos
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 也是差一点，看错隐写的图片文件了，做了半天做不出来

macOS 取证，给的压缩包是 System 和 Users 文件夹的一部分<br/>
全局搜索 flag，发现 /Users/scr1pt/Librarys/Mail/V9/.../[Gmail].mbox/已删除邮件.mbox/ 中有一个 603.emlx 文件，是一封删除掉的邮件

用 mac 邮件客户端就能直接打开：
![](/assets/images/writeups/vnctf2022/mail.png)

然后去找说的 profile picture，发现有三个文件里有类似图片的 base64:
```text
/System/Volumes/Preboot/79FABCCE-3636-4266-A6CF-8E3BB40332B4/var/db/CryptoUserInfo.plist
/System/Volumes/Preboot/79FABCCE-3636-4266-A6CF-8E3BB40332B4/System/Library/Caches/com.apple.corestorage/EncryptedRoot.plist.wipekey
/System/Volumes/Preboot/79FABCCE-3636-4266-A6CF-8E3BB40332B4/var/db/AllUsersInfo.plist
```
第一个是花园宝宝的一个角色 jpeg 图片，第二个是一朵荷花的 tiff 图片，第三个是一个压缩包，解压之后有一堆荷花图片的不同样式（大小边框文字之类）

然后我就去看那个 tiff 了，什么都看不出来

看了 wp，是在第一个图片中隐藏的信息<br/>
文件末尾有一串 flag 的结尾 `nsllc_1s_s1MMple}`（不太确定）

然后再去掉这一串，放到 Our Secret 中读取，弱密码 123456，得到前半部分 flag: `VNCTF{Macos_Fore`

