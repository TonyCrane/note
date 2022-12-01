---
comment: True
---

# SUSCTF 2022 Writeup

!!! abstract
    这次的 misc 题质量不高，难度分划严重，AK 了，写一下

---

## ra2
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

红警自制关卡，通过这个游戏自带的 Extras → map editor，即可进入看到地图中的 lunar flag 和 billboard

![](/assets/images/writeups/susctf2022/Untitled.png)

其中 billboard 上播放的就是三帧 flag

或者可以找到游戏文件夹 mods/rv/maps/ctf-01，修改其中控制游戏逻辑的 lua 文件，将难度降低，可以进入游戏找到 flag

flag: **SUSCTF{RED_ALERT_WINNER!!!}**

---

## Tanner
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

Tanner 图，LDPC 码，发现文件尾有所求内容：

```text
THE FLAG IS the sha256 of the sum ofthe proper codewords(binary plus)which satisfy the condition.(note: with no zeros front)
```

即求所有满足这个 LDPC 校验码的所有比特序列加起来之后的值的 sha256

从网上随便找了个 decoder 来用：[http://leohope.com/解问题/2019/01/11/ldpc-with-python/](http://leohope.com/%E8%A7%A3%E9%97%AE%E9%A2%98/2019/01/11/ldpc-with-python/)

随意传入一个比特序列，如果它解出来的序列没有变化，则说明当前序列满足需要

一共 10 个比特，1024 种情况，枚举即可：

```python
import hashlib
import numpy as np

def decode(H, y, m, n, p):
    fr = np.zeros((m, 2 * p))
    fs = np.zeros((m, 2 * p))
    sum = np.zeros(m)
    c = np.zeros((n, p+2))
    y1 = np.zeros(n)

    for i in range(m):
        count = 0
        for j in range(n):
            if H[i][j] == 1:
                fr[i, count] = y[j]
                sum[i] = sum[i]+y[j]
                count = count+1

    for i in range(m):
        for j in range(2*p):
            fs[i, j] = (sum[i]-fr[i, j]) % 2

    for i in range(m):
        count = 0
        for j in range(n):
            if H[i][j] == 1:
                index = int(c[j, p+1])
                c[j, index] = fs[i, count]
                count = count+1
                c[j, p+1] += 1

    for i in range(n):
        c[i, p] = y[i]

    for i in range(n):
        count = 0
        for j in range(p+1):
            if c[i, j] == 1:
                count += 1
        if count > (p+1)/2:
            y1[i] = 1
    return y1

m = 5
n = 10
p = 2

H = np.zeros((5, 10))
H = [[1, 1, 1, 1, 0, 0, 0, 0, 0, 0],
     [1, 0, 0, 0, 1, 1, 1, 0, 0, 0],
     [0, 1, 0, 0, 1, 0, 0, 1, 1, 0],
     [0, 0, 1, 0, 0, 1, 0, 1, 0, 1],
     [0, 0, 0, 1, 0, 0, 1, 0, 1, 1]]

ans = 0
for i in range(1024):
    bi = f"{bin(i)[2:]:>010}"
    lst = list(map(int, bi))
    res = decode(H, lst, m, n, p)
    if all(lst == res):
        ans += i
print(hashlib.sha256(bin(ans)[2:].encode("utf-8")).hexdigest())
# c17019990bf57492cddf24f3cc3be588507b2d567934a101d4de2fa6d606b5c1
```

flag: **SUSCTF{c17019990bf57492cddf24f3cc3be588507b2d567934a101d4de2fa6d606b5c1}**

## AUDIO
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

音频隐写，已经给了修改后的文件和原文件，肯定要比较异同，直接在 Au 里进行操作

先匹配响度，然后给一段音频反相，之后两段音频进行多轨混音，这样相同部分会抵消掉

可以很清楚地听到中间有一段滴滴声，是摩尔斯电码，抄写翻译：
```text
... ..- ... -.-. - ..-. -- .- ... - . .-. --- ..-. .- ..- -.. .. ---
```

`SUSCTFMASTEROFAUDIO`

flag: **SUSCTF{MASTEROFAUDIO}**

## misound
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

音频，明显是 SSTV，但是中间穿插了杂乱的音频，裁剪出来：

![](/assets/images/writeups/susctf2022/Untitled%202.png)

```python
AnEWmuLTiPLyis_etimes_wiLLbEcomE_B
```

再根据 hint，可以得到一个新乘法运算 _e * _ = _B 意义不明

再把 wav 传入 SilentEye，得到：

```python
MjA3IDM1OSAyMjAgMjI0IDM1MiAzMTUgMzU5IDM3NCAyOTAgMzEwIDI3NyA1MDcgMzkxIDUxMyA0MjMgMzkyIDUwOCAzODMgNDQwIDMyMiA0MjAgNDI3IDUwMyA0NjAgMjk1IDMxOCAyNDUgMzAyIDQwNyA0MTQgNDEwIDEzMCAzNjkgMzE3
```

base64 解码：

```python
207 359 220 224 352 315 359 374 290 310 277 507 391 513 423 392 508 383 440 322 420 427 503 460 295 318 245 302 407 414 410 130 369 317
```

三十四个数字，对应前面的字符串是三十四个字符，可能是进行了某些操作

然后能确定的是 flag 开头结尾是 `SUSCTF{` 和 `}`

进行漫长的运算和猜测，最后发现 AnEWmuLTiPLyis_etimes_wiLLbEcomE_B 这个字符串逐字符乘 flag 后值的变化趋势和前面 SilentEye 结果的趋势相同，把已知的写下来，进行线性回归拟合

```python
207, 5395
359, 9350
220, 5727
224, 5829
352, 9156
315, 8190
359, 9348
317, 8250
```

![](/assets/images/writeups/susctf2022/Untitled%203.png)

<div style="text-align: center">F(x) = 26.011670619246555*x+4.942379114107098</div>

```python
>>> def f(x):
...     return 26.011670619246555*x+4.942379114107098
...
>>> for x, y in zip([207, 359, 220, 224, 352, 315, 359, 374, 290, 310, 277, 507, 391, 513, 423, 392, 508, 383, 440, 322, 420, 427, 503, 460, 295, 318, 245, 302, 407, 414, 410, 130, 369, 317], [65, 110, 69, 87, 109, 117, 76, 84, 105, 80, 76, 121, 105, 115, 95, 101, 116, 105, 109, 101, 115, 95, 119, 105, 76, 76, 98, 69, 99, 111, 109, 69, 95, 66]):
...     print(chr(round(f(x) / y)), end="")
...
SUSCTF{tHe_matter_iS_unremArkab1e}
```

flag: **SUSCTF{tHe_matter_iS_unremArkab1e}**

