---
counter: True
comment: True
---

# 伪造 AP 与 WPA2 密码爆破

!!! abstract
    无线与物联网安全 lab3 实验报告（实验中使用指纹非本人指纹）

    !!! warning "仅供学习参考，请勿抄袭，请勿用于非法用途，一切后果与本人无关"

## 实验目标

1. 利用无线网卡伪造手机热点，并引导被害者连接伪造 AP 
2. 暴力破解 WPA2-Personal 加密 WiFi

## 实验过程

### Fake AP 实验

一台手机开启无密码热点“iQOO Neo9”，另一台手机搜索可以正常连接。通过 airodump-ng 查找热点（这里无线网卡的网络接口是 wlx0013eff1140e 而不是 wlan0）：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img1.png" width="70%" style="margin: 0 auto;">
</div>

可以看到该热点的 BSSID 与 Channel。接下来通过 airbase-ng 伪造 AP：

```bash
airbase-ng -e "iQOO Neo9" -c 6 wlx0013eff1140e
```

然后设置 IP、网关，运行 dnsmasq：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img2.png" width="70%" style="margin: 0 auto;">
</div>

dnsmasq 无法启动，因为 systemd-resolved 占用了 53 端口，需要临时暂停 systemd-resolved 服务：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img3.png" width="70%" style="margin: 0 auto;">
</div>

接下来通过 aireplay-ng 来进行 deauth 攻击：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img4.png" width="70%" style="margin: 0 auto;">
</div>

-a 的 AP 就是前面得到的 BSSID，-c 的 STA 是要攻击的设备的 MAC 地址，可以通过两部手机的热点或者无线连接信息查看。上图中可以看到 ACK 左侧是受害者的 ACK，有非 0 值说明受害手机收到了 deauth 包被踢掉热点了，右侧是真实 AP 的 ACK。可以看到伪造的 AP 获得了手机的连接：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img7.png" width="70%" style="margin: 0 auto;">
</div>

可以看到被攻击的设备断开了之前的连接，试图连接到伪造的 AP：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img5.png" width="60%" style="margin: 0 auto;">
</div>

但伪造的 AP 无法连接，可能是网络设置哪里有问题，问了助教，助教说可以踢掉就可以，不一定要连得上新的。同时可以让 airbase-ng 伪造的 AP 改个名，可以看到有两个热点：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img6.png" width="50%" style="margin: 0 auto;">
</div>

#### 思考题

> **1. 第 6 步，攻击者强制受害者手机断连原理是什么？**

第六步的命令中，aireplay-ng 会利用伪造的 AP 根据真实热点的 MAC 地址和 channel 伪造真实 AP 来向目标设备发送 deauth 包，使其与真实热点断连。之后手机会自动连接信号更好的 AP，如果伪造的 AP 更近，则会连接到伪造的 AP。

> **2. 设立伪造 AP 后，攻击者可以在此基础上实施哪些攻击？**

攻击者可以进行流量监听，获取受害者通信的流量，进行解码，获取用户隐私信息。也可以进行中间人攻击，伪造受害者与真实服务器的通信，获取用户的账号密码等信息。还可以注入恶意流量、转发恶意数据，进行 DoS 攻击等。

> **3. 攻击者实施 Fake AP 攻击后，受害者能否分辨 Fake AP 和真实 AP？为什么？**

本实验中伪造的 AP 可以分辨，因为 aireplay-ng + dnsmasq 够早的伪造 AP 无法连接，受害者无法正常上网。但如果伪造的 AP 能够正常连接，而且伪造的 MAC 地址、channel 信息与真实 AP 一致，受害者可能无法分辨。

> **4. 如何防御 Fake AP 攻击？**

真实的 AP 和主机之间应当先进行密钥交换，然后进行加密信息传输，这样伪造的 AP 不知道密钥，无法解密信息也就不会造成有效攻击。所以应当避免连接无密码的热点和 WiFi，在每次连接前都进行密码确认，这样伪造的 AP 不知道密码就无法进行验证，可以避免 Fake AP 攻击。

### WPA2 密码破解

手机热点设为 WPA2-Personal，设置弱密码 12345678，接下来通过 airodump-ng 进行流量捕获：

```bash
airodump-ng wlx0013eff1140e -w dump -c 1 # channel 会更换
```

然后同时进行 deauth 使得连接设备重连，捕获相关数据包：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/img9.png" width="70%" style="margin: 0 auto;">
<img src="/assets/images/sec/iotsec/lab3/img8.png" width="70%" style="margin: 0 auto;">
</div>

捕获到的流量在 dump-01.cap 中。接下来使用 aircrack-ng 和网上下载的 wpa-dictionary.cap 字典进行破解：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/imga.png" width="70%" style="margin: 0 auto;">
</div>

可见很快就破解掉了弱密码 12345678。另外如果是强密码则要消耗一定时间从字典中爆破：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab3/imgb.png" width="70%" style="margin: 0 auto;">
</div>

#### 思考题

> **1. 为什么单利用握手包就足以暴破密码？**

WPA2 建立连接需要四次握手，其中第一次握手时 STA 会根据 ANonce（AP 生成的随机数）、SNonce（Station 生成的随机数）、MAC(STA)、MAC(AP) 及 PMK（根据 WiFi 密码 PSK 和SSID 计算获得）计算出 MIC。而 ANonce、SNonce、MAC(STA) 和 MAC(AP) 都是可以直接通过握手包获得的明文信息且 SSID 已知，故只需要通过枚举 PSK 然后计算 MIC 并与握手包中的 MIC 进行比较即可知道 PSK 是否正确。根据这样的算法，就可以做到离线爆破 WiFi 密码。

> **2. 你的暴破密码的速度如何？用这种方法 1 分钟能暴力尝试多少个密码？**

从上面强密码的截图可以看到，7 秒内尝试了 69568 个密码，按照这个速度一分钟能尝试 69568 / 7 * 60 = 596297 即大约 600000 个密码。

> **3. 如果是全数字的密码，想要抵抗为期 1 天的持续暴力破解，它的位数需要多长？**

根据前面估计的速度，我们一天内可以尝试 600000 * 60 * 24 = 864000000 = 8.64e8 个密码。而如果是数字密码则每位只有 10 种情况，n 位数字密码有 10^n 种情况，所以至少需要 9 位数字的密码（10^9 = 1e9 > 8.64e8）才能抵抗为期 1 天的持续暴力破解。
