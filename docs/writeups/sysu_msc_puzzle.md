---
comment: True
---

# SYSU MSC Puzzle 2021 Writeup

> MSC Puzzle 是由中山大学 MSClub 与中山大学 W4terDr0p 战队联合举办的趣味性解谜游戏

!!! abstract
    基本上都是 GZTime 出的题，算到 CTF 里就都是 misc 类，一共 24 道题，下面是简要的 writeup：

---

## 你好！勇士
宣传海报和首页都有，flag：`msc{He1lo_Wor1d}`

---

## 老古董
`-.-. --- -.. . --- ..-. - .... . .---- ----. - .... -.-. . -. - ..- .-. -.--`

摩尔斯电码，根据首页的说明在单词间加上下划线得到 flag：`msc{CODE_OF_THE_19TH_CENTURY}`

---

## 躲在墙后
打开 DevTools 看 Console，flag：`msc{Wow_Y0u_f1nd_me}`

---

## 隐身药水
打开 DevTools 看代码，有一个 display: none 的 flag：`msc{Inv1sibility_P0tiOn}`

---

## 完形填空
> We, the rustling leaves, <br/>
have a voice that answers the storms,<br/>
but who are you so silent?<br/>
<br/>
I am ___________.

搜索这段诗歌得到空缺内容，格式化一下得到 flag：`msc{a_mere_flower}`

---

## 去问导航
> 去找那个地方吧！👻.👾.sysums.club

并且可以发现有一个 display: none 的 TXT 字样

链接直接转到的地址是 `http://xn--9q8h.xn--dr8h.sysums.club/`

所以用 dig 命令查询一下这个域名的 TXT 记录就可以了
```shell 
dig xn--9q8h.xn--dr8h.sysums.club txt
```
flag：`msc{Domain_w1th_IDNs}`

---

## 世间万物的答案
>The answer to the ultimate question of life, the universe, and everything<br/>
equals to<br/>
A^3 + B^3 + C^3<br/>
勇士，这道题的答案是 msc{A+B+C}

世间万物的答案即指 42，然后搜索得到 

$$
-80538738812075974^3 + 80435758145817515^3+ 12602123297335631^3 = 42
$$

所以 flag：`msc{12499142631077172}`

---

## 我的咖啡
> 我们的酒馆采用最新的 HTCPCP/1.0 协议为您提供服务！<br/>
“嘿，酒保！我的咖啡呢？”<br/>
“在做了！”<br/>
该死，我忘了让他少加点牛奶，我得立刻让他停下！

搜索 HTCPCP/1.0 （超文本咖啡壶）协议，停止加入牛奶的请求是 WHEN，所以 flag：`msc{WHEN}`

---

## 设计师
>「我想要这个字小一点的同时大一点」
>
>ww91igfYzsb0AguGyMvZDcbKzxnPz25LCIekBxnJE1qWxZrUB3rOzxjFqMfZzty0Fq==

大写转小写，小写转大写，然后 base64 解码，得到 flag：`msc{T0_4nother_Base64}`

---

## 监听电话
> https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/phone.mp3

是一串电话的拨号音，放到 Au 里面看频谱，把对应按键抄下来就行了，具体是什么记不得了

---

## 一张图片
> https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/msc.png

stegsolve 打开，在 red 0 可以清晰看到 flag：`msc{Text_Hidd3n_Und6r_The_1mage}`
![](/assets/images/writeups/sysu_msc_puzzle/a_picture.png){width=50%}

---

## 数字序列
> ..., 22, 30, 42, 56, ? , 101, 135, 176, 231, 297, ...<br/>
..., 72, 81, 90, 100, 110, ?, 132, 144, 156, 169, ...<br/>
..., 43, 47, 55, 67, 79, ?, 123, 155, 171, 175, ...<br/>
..., 891, 9805, 25, 527, 23, ?, 17, 37, 131, 43, ...<br/>
..., 58, 51, 89, 28, 97, ?, 30, 103, 107, 62, ...<br/>
..., 20, 26, 36, 50, 60, ?, 135, 138, 248, 315, ...<br/>
..., 2, 1, 9, 35, 77, ?, 91, 49, 15, 2, ...<br/>
..., 49, 62, 70, 77, 91, ?, 103, 107, 115, 122, ...<br/>
..., 8, 26, 60, ?, 196, 308, 456, 645, 880, 1166, ...

直接分别粘贴到 [OEIS](http://oeis.org/) 中，得到需要填的数字：

`77 121 95 83 101 114 105 101 115`

看数字范围挺规整，ASCII 转换一下得到 flag：`msc{My_Series}`

---

## 未知信号
> https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/signal.mp3<br/>
> 我觉得，这里面有蹊跷！你知道二十世纪五六十年代的电视是使用摄像管和电子监视器制成的吗？

所以应该是 SSTV（慢扫描电视）传输图片，用手机软件 Robot36 就可以转换，得到：
![](/assets/images/writeups/sysu_msc_puzzle/SSTV.jpg)

扫描得到 flag：`msc{SSTV_transfer_image}`

---

## 又一张图片
> https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/msc2.png

还是扔到 stegsolve 里，在 red0 green0 blue0 分别能看到文字，合起来是
`密码是 p455w0rd`
![](/assets/images/writeups/sysu_msc_puzzle/picture2.png){width=50%}

binwalk 可以发现这个 png 里偏移 `0xC23A` 后面藏了一个 zip，提取出来用密码解压得到一个 svg 文件

浏览器打开之后发现有一个白色矩形，删掉它就能看到 flag：`msc{svg_The_vectors}`

![](/assets/images/writeups/sysu_msc_puzzle/picture2_2.png)

---

## 盲人数学家
> ⠸⠩⠮⠰⠤⠆⠘⠆⠐⠷⠭⠘⠒⠐⠉⠕⠎⠹⠭⠌⠆⠼⠬⠹⠂⠌⠆⠼⠾⠜⠲⠤⠭⠘⠆⠐⠻⠙⠭⠸⠱
>
> Tip: 将结果四舍五入保留 7 位小数，并用_替换小数点后提交

对照教程 https://nemeth.aphtech.org/ 学习，转换公式：

![](/assets/images/writeups/sysu_msc_puzzle/meth_dark.jpg#only-dark)
![](/assets/images/writeups/sysu_msc_puzzle/meth_light.jpg#only-light)

$$
\int_{-2}^2(x^3\cos\frac{x}{2}+\frac{1}{2})\sqrt{4-x^2}\mathrm dx = \pi \approx 3.1415927
$$

所以 flag：`msc{3_1415927}`

---

## 最小的语言
> 勇士，据说这个世界在很久远的时候有一位凯撒大帝，在他离世的时候，为这个世界创造了一种最小的语言，我们都不敢读出它的名称……<br/>
```brainfuck
+++++++[->+++++++<]>++++++++++++.<+++++[->+++++<]>+.++.<+++++[->+++++<]>++++++.+.<+++++[->-----<]>--.-------.+.<++++[->----<]>-------.<+++++++[->+++++++<]>.----.<++++++++[->--------<]>------.<++++++++[->++++++++<]>+++++++++.++.+++++++++.<+++[->---<]>---.<++++++++[->--------<]>---------------.<+++[->+++<]>+++.<+++++++[->+++++++<]>+++++++++++++.<++++++[->------<]>-----------.<++++++++[->++++++++<]>++.<++++++++[->--------<]>--.<+++++[->+++++<]>+++.<++++++[->------<]>.<+++++++[->+++++++<]>++++.<++++++[->------<]>----------.++++++.<+++++[->+++++<]>+.<+++++++[->-------<]>---------.<++++++++[->++++++++<]>+++++++++++++.<+++++++[->-------<]>----.--.<++++++++[->++++++++<]>+++.-----.<++++++++[->--------<]>-.<++++++[->++++++<]>+.<+++++[->+++++<]>.+++.++++++.<+++++++[->-------<]>----------.---..<+++++++[->+++++++<]>+++++++++++++.<+++[->---<]>-.------.<+++[->+++<]>+++.<++++++++[->--------<]>------------.<+++[->+++<]>+++.+.<+++++++[->+++++++<]>+++++++++++.++++.++++++.<+++++[->-----<]>----------.<+++++[->-----<]>---------.-----.++++++.<++++[->----<]>.<++++[->++++<]>++++++++.<+++++++[->+++++++<]>++++++.<++++++++[->--------<]>---..<++++[->----<]>.<+++++[->+++++<]>+.<++++[->++++<]>+++++.<+++++[->-----<]>.-------.-------.--------.<++++[->++++<]>+++++.-----..<++++[->----<]>.<++++[->++++<]>++++.<+++[->---<]>-.++++.+++.<+++++[->+++++<]>++++++.<++++[->----<]>------.++++.<++++[->++++<]>+++++++.<++++++[->------<]>-----------.<++++++++[->++++++++<]>++++++.<+++++++[->-------<]>-------.----.------.<++++++++[->++++++++<]>+++++++++++++.<++++++++[->--------<]>--------..<++++++[->++++++<]>+++++.<+++++[->+++++<]>++++.--.<+++++[->-----<]>--------.<+++++[->-----<]>---.---------.<+++[->+++<]>++++.<+++++++[->+++++++<]>++++.+++++++++.<++++++++[->--------<]>----------------.<++++++++[->++++++++<]>+++++.+++.<++++++++[->--------<]>-------.<+++++++[->+++++++<]>+++++++++++++.<+++++++[->-------<]>--------.<+++[->---<]>---.<+++++++[->+++++++<]>++++.<+++[->+++<]>+++.<++++++++[->--------<]>.++++++++.<+++++++[->+++++++<]>++++++++++++++.<+++++[->-----<]>-.<+++++++[->-------<]>----.<++++++++[->++++++++<]>++++++++++++++.+.<++++[->----<]>-----.<+++++++[->-------<]>--.<+++++++[->+++++++<]>+.<+++++[->-----<]>-------.-----.-.<+++++++[->+++++++<]>+.<+++++++[->-------<]>------.<++++++++[->++++++++<]>++++..<+++[->---<]>---.<+++[->+++<]>++++.<++++++++[->--------<]>------------.-------.<+++++++[->+++++++<]>++++++.++.<+++++[->+++++<]>+++++++++.----.-------.<+++[->+++<]>++.<+++[->---<]>----.++++++..+.<++++++++[->--------<]>-----------.<++++[->++++<]>+++++.<+++++++[->+++++++<]>+++++++++++.<+++++++++[->---------<]>----------.<+++++[->+++++<]>+++.<+++++++[->+++++++<]>+++++++.<
```

brainfuck 输出得到：`=WYxy^WXArn(qs|p!-k<~<X4i;A[!n97zu4Yru{@=={qkw+78tx~[94:*By66&@U<5.&;66&:047V@D[,r:60}55^{yX<3@u~.sv/m4(]i)1pV!op[(Z:54f/ssgt(!XZ|xq|ouuv+@|!=u`

根据题面的凯撒，可以推测是 ASCII 偏移，然后把输出限制在 [33, 126] 中（ASCII可见字符），第 54 次偏移的结果：`v24ST923zMIaLNWKZfFuYu3mDtz6ZIrpUPm4MPVyvvVLFRdpqOSY6rmsc{Too_y0ung_too_simp1y}6eMsoiXnn9VT3ulyPYgNQhHma8DbjK1ZJK6a5snmAhNNBOaZ35WSLWJPPQdyWZvP`

中间就是 flag：`msc{Too_y0ung_too_simp1y}`

---

## 一个传说
> “勇士，我听过一个古老的传说……”<br/>
“请讲！”<br/>
「1024×768 大小的图片，可以轻松藏下 786432 个地址。」<br/>
https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/justcolor.png

一个纯色文件，根据题面可以推测是读取 rgba 值作为 ip 地址

所以写个脚本读一下 `#!python from PIL import Image;print(Image.open("justcolor.png").getpixel((0, 0)))`，得到 ip 地址：116.63.166.50

访问得到 flag：`msc{Hide_IP_in_RGBA}`

---

## 时间商人
> 你发现了一块布满苔藓的石板，上面刻着下面的几个字：<br/>
&emsp;⊧ã⊷¬§×ãˆ𝔎<br/>
你看不懂，但大受震撼。<br/>
路边有个神秘的黑衣商人，他自称能为你提供帮助，但是有一个苛刻的条件：你必须在每天凌晨四点的第一个八分钟内过来找他，他才能给你提供线索。

调整时间到凌晨四点的第一个八分钟内，得到 hint：`商人看着你，什么话也没说，给你递了一张纸条，上面写着：charref。`

搜索得到字符对照表：https://dev.w3.org/html5/html-author/charref

然后依次搜索这些字符，首字母拼起来就是 flag：`msc{mainstacK}`

---

## 追踪目标
> 一张通缉令贴在村口的公告牌上，据说捕获到了盗贼下一次要作案的地方，但没人看得懂。<br/>
7PMM399R+FQ2<br/>
“哦，你只需要用\*\*\*\*\*\*\*\*\*\*就能得到答案”<br/>
“哦！收到！”<br/>
“你知道 The simplest way to talk about location 吗？”<br/>
“知道……原来你就是想要那三个单词啊”

直接使用[三词地址](https://map.what3words.com/flux.tank.pitch)调成英文搜索 `7PMM399R+FQ2` 得到位置的三个单词 `///flux.tank.pitch`

所以 flag：`msc{flux_tank_pitch}`

---

## 紧急唤醒
??? question "问题"
    ```python
    from Crypto.Util.number import*

    p = 0xbb1a21ab46e16672a6dfe537c5d03121252685a1a72fab827ed14d61caa80f68b9bda9fb0d9651719ab099d05fd0da03443a50106533f1034a81e280cd3e85fd
    q = 0x85eed89c104292b715a45ec8a1c3328506b429c2b7477c9ab094313fcf0020ba7352b102608cab79bde92978aedb052a546fb289c453feac87ee791ba1019579

    n = p * q
    e = 0x10001

    answer = b'something you dont know'
    m = bytes_to_long(answer)

    c = pow(m,e,n)
    # c = 0x17c7af1ec9c020eb9d8f26049f002b58f93591a817ebff4c00e9e46254261db54a2c2d086dd0f532994329faf2133b1c7002913b187f898d87c8093b2290440e927 78956c60b92f27e3dc4d15b4c79f97b79bca253b0b4542375c37f8e37e1f8e38d728634133376eacd2c448aa523b2eda0b4c5f2af47250147f4193d58596c
    ```

基础的 RSA，计算出 d 然后解密就可以得到 flag：
```python
d = pow(e, -1, (p-1) * (q-1))
print(long_to_bytes(pow(c, d, n)))
# b'msc{W0w_You_know_H0w_to_d3crypt_the_RSA}'
```

---

## Emojis
> “这是一串 `EMOJI`，里面会藏着什么样的信息呢？”<br/>
🙃💵🌿🎤🚪🌏🐎🥋🚫😆✅😊👉👣📂⏩😆🌿🌪😎🍵☃📂🚹👌🏹🐎🌿😀👣🏎😍😆🍴✅👁✅✅😆🕹🔬🐍🎅✖🌪👣🚹💧🍴💵🍍🌪✉👁🚪🔪⏩💧🎃🥋🕹🍎😊ℹ
>
> 哦对了，我要的是忽略误差后的数字哦~

DevTools 里可以看到 display: none 的 aes？所以应该是使用 [emoji-aes](https://aghorler.github.io/emoji-aes/)

根据题面中的全大写、代码块包裹的 `EMOJI`，可以推测出 key 就是 EMOJI，解密得到：
```text 
ORANGE
RED
YELLOW
GREEN
GOLD
```

根据颜色以及题面中的“忽略误差”猜测是五色环电阻，转换得到忽略误差后是 32400000 欧姆，所以 flag：`msc{32400000}`

---

## 简易加密
> 据说这是一种极其普遍的加密方法……<br/>
而且任何人都可以解密……<br/>
或许……你可以听到来自答案的声音……<br/>
https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/msc.enc

任何人都可以解密的简易加密，可以猜测是异或，然后打开看十六进制发现很多 `0x66`，所以考虑全部异或 `0x66`：
```python 
import struct
res = []
with open("msc.enc", "rb") as f:
    while True:
        c = f.read(1)
        if not c:
            break
        res.append(ord(c) ^ 0x66)

with open("res.bin", "wb") as f:
    for each in res:
        f.write(struct.pack("B", each))
```
得到的 res.bin 中可以很容易发现 `FL Keys` 和一些键名，用 fl 或者库乐队等软件打开就可以看到 flag：`msc{The_xor_midi_GIFT}`

---

## 图像处理大师
> 你就是图像处理大师！<br/>
所以帮我找到藏在图片里的秘密吧！哦对了，这里还有一张小纸条，应该能帮到你（<br/>
`0.8560967955058971 17.682512473330895`<br/>
https://mscpuzzle.oss-cn-guangzhou.aliyuncs.com/2021/cv.zip

??? question "题目代码"
    ```python 
    import cv2
    import numpy as np

    def mapping(data, down=0, up=255, tp=np.uint8):
        data_max = data.max()
        data_min = data.min()
        interval = data_max - data_min
        new_interval = up - down
        new_data = (data - data_min) * new_interval / interval + down
        new_data = new_data.astype(tp)
        return new_data

    def fft(img):
        fft = np.fft.fft2(img)
        fft = np.fft.fftshift(fft)
        m = np.log(np.abs(fft))
        p = np.angle(fft)
        return m, p

    if __name__ == '__main__':
        img = cv2.imread(f'answer.png', cv2.IMREAD_GRAYSCALE)

        m, p = fft(img)
        print(m.min(), m.max())

        new_img1 = mapping(m)
        new_img2 = mapping(p)

        cv2.imwrite(f'cv1.png', new_img1)
        cv2.imwrite(f'cv2.png', new_img2)
    ```

一个 FFT，直接把代码逆回去就好了：
```python 
import cv2
import numpy as np

def mapping(data, down=0, up=255, tp=np.uint8):
    data_max = data.max()
    data_min = data.min()
    interval = data_max - data_min
    new_interval = up - down
    new_data = (data - data_min) * new_interval / interval + down
    new_data = new_data.astype(tp)
    return new_data

if __name__ == '__main__':
    img1 = cv2.imread("cv1.png", cv2.IMREAD_GRAYSCALE)
    img2 = cv2.imread("cv2.png", cv2.IMREAD_GRAYSCALE)

    m = mapping(img1, 0.8560967955058971, 17.682512473330895)
    p = mapping(img2, 0, 2*np.pi)
    res = m * (np.cos(p) + np.sin(p) * 1j)

    ishift = np.fft.ifftshift(res)
    iimg = np.fft.ifft2(ishift)
    iimg = np.abs(iimg)
    iimg = mapping(iimg)
    cv2.imwrite(f'answer.png', iimg)
```
??? success "flag: msc{The_master_of_cv}"
    ![](/assets/images/writeups/sysu_msc_puzzle/answer.png)

---

## 混乱的二维码
> 你好！勇士，你走到这里已经证明了你的实力！<br/>
我本该给你的是一张记录着答案的二维码，但由于在传输过程中我们忘记标注每一行的顺序了，导致我们收到了这样的数据……勇士，你能还原出它的原始模样吗？

??? question "题目"
    ```python
    [
      "10111010111000011000001011101", "00111010110010101000000000010",
      "11100001101100100001011010110", "10000010000111101111111111101",
      "10111010000010001000001011101", "01110011010111001001011100001",
      "10101101110101001110000110010", "10111010111010111110001011101",
      "10010100110101101111100111110", "10111110011101011000011010111",
      "11001010001011011000000001000", "10111010100101100111111110100",
      "10000010110010110100100011001", "11111110101010101010101111111",
      "10111010001100010100110110111", "11111110101101010101110110000",
      "00000000100100100101100011100", "00000000111001101011011111001",
      "11111100100110010010001011110", "00010001110001001101110001010",
      "10000010111110001101101000001", "11001110110110010101100100001",
      "11011110111101111101111110100", "11111110100010100101101011100",
      "00000000011111011001100000000", "10111010111001000110010100010",
      "11111110101110011001001111111", "10000010001100011010101000001",
      "10011111111101000101110010111"
    ]
    ```

把这些值输入到 csv 中，然后 Excel 打开，调一调格式，开始按照二维码的规则（三个定位点，对齐图样、时序图样等）来确定可以确定的行，结果：
![](/assets/images/writeups/sysu_msc_puzzle/qrcode1.png#only-light)
![](/assets/images/writeups/sysu_msc_puzzle/qrcode2.png#only-dark)

上面有 2 行顺序不确定，中间有 11 行顺序不确定（其中由于时序图样的原因，所以相当于有 5 行顺序不确定和 6 行顺序不确定），所以总共有 `2*5!*6! = 172800` 种可能，所以可以枚举了。可以使用 pyzbar 这个包来自动解二维码

改一改 GZTime 2021 祥云杯的 [writeup](https://blog.gztime.cc/posts/2021/eee18328/#shuffle-code-Misc) 里的代码：

??? note "代码"
    ```python 
    data = [
        "11111110101110011001001111111",
        "10000010111110001101101000001",
        "10111010111010111110001011101", # <- 这两行需要手动调换各跑一次
        "10111010000010001000001011101",
        "10111010111000011000001011101", # <- 这两行需要手动调换各跑一次
        "10000010001100011010101000001",
        "11111110101010101010101111111",
        "00000000011111011001100000000",
        "10011111111101000101110010111",
        "11100001101100100001011010110",
        "00111010110010101000000000010",
        "10101101110101001110000110010",
        "01110011010111001001011100001",
        "10010100110101101111100111110", 
        "10111110011101011000011010111",
        "00000000111001101011011111001",
        "11001010001011011000000001000",
        "11111100100110010010001011110",
        "11001110110110010101100100001",
        "00010001110001001101110001010",
        "11011110111101111101111110100",
        "00000000100100100101100011100",
        "11111110100010100101101011100",
        "10000010110010110100100011001",
        "10111010100101100111111110100",
        "10111010111001000110010100010",
        "10111010001100010100110110111",
        "10000010000111101111111111101",
        "11111110101101010101110110000"
    ]
    
    import pyzbar.pyzbar as pyzbar
    from itertools import permutations
    from PIL import Image, ImageDraw as draw
    import matplotlib.pyplot as plt
    from tqdm import tqdm
    
    shuffle_1 = [9, 11, 13, 15, 17, 19]
    shuffle_2 = [10, 12, 14, 16, 18]
    
    head = data[:9]
    tail = data[20:]
    
    def body(body_1, body_2): # 获取中间部分的一种排列
        body = []
        for i in range(5):
            body.append(body_1[i])
            body.append(body_2[i])
        body.append(body_1[5])
        return [data[i] for i in body]
    
    def draw_img(data): # 生成二维码图片
        assert len(data) == 29 and len(data[0]) == 29
        img = Image.new('RGB', (31, 31), (255,255,255))
        for i, row in enumerate(data):
            for j, pixel in enumerate(row):
                img.putpixel((j + 1, i + 1), (0,0,0) if pixel == "1" else (255,255,255))
        return img
    
    with tqdm(total=86400) as pbar:
        for body_1 in permutations(shuffle_1):
            for body_2 in permutations(shuffle_2):
                im = draw_img(head + body(body_1, body_2) + tail)
                barcodes = pyzbar.decode(im)
                pbar.update(1)
                if(len(barcodes) == 0):
                    continue
                
                for barcode in barcodes:
                    barcodeData = barcode.data.decode("utf-8")
                    print(barcodeData)
                    plt.imshow(im)
                    plt.show()
    ```

可以跑出可解的二维码和 flag：

??? success "flag：msc{You_ar3_g0od_4t_QR_Code}"
    ![](/assets/images/writeups/sysu_msc_puzzle/qrcode.png)