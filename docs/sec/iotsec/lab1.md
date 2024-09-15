---
counter: True
comment: True
---

# 蓝牙传输与嗅探

!!! abstract
    无线与物联网安全 lab1 实验报告

    !!! warning "仅供学习参考，请勿抄袭，请勿用于非法用途，一切后果与本人无关"

## 实验目标

1. 蓝牙数据包的发送。
    - 用 esp32 发送蓝牙 beacon 帧
2. 对蓝牙数据包进行嗅探
    - 用 nrf52840+wireshark 进行嗅探，捕捉 esp32 发送的 beacon 数据包
3. 发送指定蓝牙包并抓取
    - 手机端通过 nRF Connect 与 esp32 建立连接，向 esp32 发送指定数据，并通过 wireshark 对其进行捕获

## 实验过程

### 环境配置

（macOS 环境）

- Arduino IDE 从官网下载，在 boards manager 界面安装 esp32
- 安装 wireshark
- 配置 nRF sniffer 插件
    - 将插件包中 extcap 文件夹下的内容移动至 wireshark 的 personal extcap 文件夹下
    - 修改 nrf_sniffer_ble.sh 中 python 路径
    - 对对应路径的 python 安装 requirements.txt 中的依赖
    - 执行 ./nrf_sniffer_ble.sh --extcap-interfaces 验证
- 安装 nRF Connect for Desktop
    - 在其中安装 programmer app
- 手机 iOS App Store 安装 nRF Connect

### 开发板连接与烧录

连接 esp32 板子到电脑后，Arduino IDE 中选择 Board 并指定 ESP32 Dev Module，接下来可以在 File > Examples 中找到 ESP32 BLE Arduino 系列示例代码，选择其中的 BLE_iBeacon 运行。可以修改其中的 DEVICE_NAME 使其更容易识别：

```c 
#define DEVICE_NAME            "ESP32_tonycrane"
```

烧录时遇到了问题 Unable to verify flash chip connection (Invalid head of packet (0xE0): Possible serial noise or corruption.). 在调整 Tools > Upload Speed 为 115200 后解决。

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image1.png" width="85%" style="margin: 0 auto;">
</div>

此时板子就开始发送 beacon 信号等待连接了。

### nRF Sniffer 烧录

将 sniffer 模块连接至电脑，按板子上大按钮旁边的侧按钮 reset。打开 nRF Connect 中的 Programmer，选择 Open DFU Bootloader，再载入插件文件夹中的 sniffer_nrf52840dongle_nrf52840_4.1.1.hex，进行 write 即可：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image2.png" width="85%" style="margin: 0 auto;">
</div>

此时选择设备处变为 nRF Sniffer for Bluetooth LE，即可以使用。

### Wireshark 抓包

打开 Wireshark 后可以看到在 USB 接口上的 nRF Sniffer:

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image3.png" width="85%" style="margin: 0 auto;">
</div>

选择这个接口进行流量捕获，在启动了 esp32 板子并烧录了 BLE_iBeacon 程序后，可以在 device 处发现这个设备并过滤只保留这个设备上的数据包：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image4.png" width="85%" style="margin: 0 auto;">
</div>

可以看见从板子发出来的 beacon 帧，此时正在等待连接。在手机上连接后，可以看到一直在收发 Empty PDU：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image5.png" width="85%" style="margin: 0 auto;">
</div>

App Store 上下载的 nRF Sniffer 在这里会卡在 connecting 状态，所以我换成了“蓝牙调试助手”这个 APP 来连接，接收板子的 notify 并发送学号后四位 5811:

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image6.png" width="35%" style="margin: 0 auto;">
</div>

此时 Arduino 的串口也监测到了输出：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image7.png" width="85%" style="margin: 0 auto;">
</div>

在 Wireshark 中也可以捕获到包含 5811 明文的 Send Write Request 数据包：

<div style="text-align: center;">
<img src="/assets/images/sec/iotsec/lab1/image8.png" width="85%" style="margin: 0 auto;">
</div>

至此完成了实验目标，进行了蓝牙数据的收发，以及通过 wireshark 进行数据的捕获。
