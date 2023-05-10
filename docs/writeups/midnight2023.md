---
comment: True
---

# Midnight Sun CTF 2023 Quals Writeup

!!! abstract
    比赛区分度很小，只差一道题 AK 但拍了第十没进决赛。

    做了几个 misc 还可以。

---

## whistle
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

一个蛮大的文件，内容开头：

```text
G00 S1;
G00 E0;
G01 S1;
G01 E0;
G21;
G91 G0 F300.0 Z20.000;
G90;
G28 X;
G28 Y;
G28 Z;
G00 F300.0 Z35.000;
G00 F2400.0 Y0.000;
G00 F2400.0 X0.000;
G00 F2400.0 X170.045 Y109.968;
G00 F300.0 Z15.000;
G01 F2100.0 X169.464 Y109.947;
G01 F2100.0 X169.158 Y109.883;
G01 F2100.0 X168.900 Y109.777;
G01 F2100.0 X168.692 Y109.628;
G01 F2100.0 X168.530 Y109.444;
```

还挺有特征，搜一下是数控编程的 G-code，手写不太现实，可以搜到 simulator: <https://ncviewer.com/>，跑一下：

![](/assets/images/writeups/midnight2023/whistle1.jpeg)

有很多 redacted，应该是无用信息，除此之外还有些 _? 等字符应该是 flag，动态绘制一下，除掉 redacted 相关的部分，可以得到干干净净的：

![](/assets/images/writeups/midnight2023/whistle.jpeg)

flag: **midnight{router_hacking?}**

---

还有两道我都只参与了一部分，还是不写了（