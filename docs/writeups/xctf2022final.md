---
comment: True
---

# XCTF 2022 Final Writeup

!!! abstract
    只做了一道 misc，蛮谜语的，还非预期了

---

## Shop
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

只有 nc，大概率纯猜谜，连接上要求输入用户名，之后：

```text
What would you like to buy? TonyCrane

    These are what you can buy.
    no.0 1da price: 10
    no.1 apple price: 2
    no.2 f1ag price: 1999
    no.3 banana price: 1
    no.4 xctf price: 5
    no.5 b3rpsu1t price: 3
    no.6 0l0_3ider price: 108
    
How about some ('no.1 apple', 2) ?
Please input your good number:
```

直接选 2 flag 会 Please earn more!，一直选 3 或者其他方法都可以得到初始的总金额是 120。

在一直买 0 的时候第六天会得到 You eat too much 1da! What about trying something other? 然后继续选 0 ，第十次可以得到 You eat too much 1da and You triggered the hidden task: Get membership!

所以这时就触发了下一个任务也就是拿到会员。（其实这里有暗示但当时没注意，最开头要求输入用户名的时候告诉了不能是 admin，也不能过长，实际上这两种情况下都会改为 Bob，并且输出一句“Do not eat too much 1da!!!”作为提示）

经过多种尝试可以知道从输入得到选项的做法是取输入中的第一个数字字符，而且如果超过 6 或者根本没有数字，会输出 What? Sorry, you can not buy anything today. This may affect your membership(A \*\*month\*\* of continuous shopping)

所以大概猜测会员要一个月才能得到，这样的话选 10 次 0 触发任务，然后剩下的钱正好够选 20 次 3，这样 30 天之后就拿到会员了：

```text
Thanks!
Dear Membership TonyCrane
I will show you my Recommendation system. It contains A super AI and I test it myself!
But before I show that, what about a easy game?
Your answer is(Y/N):
```

这里回答是 Y/N 都是一样的，会让你去解一道题目：

```text
Here is the game, please find my score(integer) to those goods which have 0 score:

beginmatrix
[[27, 0, 20, 0, 11, 0, 31, 23, 10, 0, 0, 15, 0, 13], [26, 32, 21, 7, 15, 18, 32, 26, 13, 25, 22, 13, 13, 14], [40, 46, 39, 11, 27, 24, 46, 28, 23, 41, 32, 29, 35, 28], [23, 27, 17, 6, 10, 15, 27, 21, 9, 20, 21, 12, 15, 11], [35, 40, 25, 9, 13, 22, 40, 30, 12, 29, 33, 19, 26, 16], [42, 49, 32, 11, 19, 27, 49, 37, 17, 37, 38, 23, 29, 21], [43, 52, 42, 12, 32, 28, 52, 36, 27, 46, 33, 28, 29, 30], [30, 35, 25, 8, 16, 19, 35, 25, 14, 28, 26, 18, 22, 17]]
endmatirx
where row stand for user and col stand for goods
The good and user embedding dim are both 3!
The flag is md5(first row)
Example: if the first row is [14 13  9 22 20 25 14 27 20 15 19 10 32 21] md5(141392220251427201519103221)==59d25d2c3cc2bb1d27f550329d35f5a5
So, the answer is 59d25d2c3cc2bb1d27f550329d35f5a5
Now, what is your answer?
```

看起来和 AI 以及推荐算法有关，搜了好多也没找到，写不出来。

然后在一次次尝试中发现了一个非预期（大概也是很多队做出来的原因），在这个输出的矩阵中，有一定概率会出现两行一样的情况，也就是有可能会出现和原本第一行一样的行，这种情况下答案就直接打出来了，md5 一下交上去就可以了，得到 flag: **flag{a2b035c8_congratulations+7618=on=528f1b1_solving_this>814464a4c6812<problem:D}**

预期就是 AI 相关的推荐系统矩阵分解算法，教程：https://blog.csdn.net/weixin_43164078/article/details/124278175。