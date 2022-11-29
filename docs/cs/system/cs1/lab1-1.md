---
counter: True
comment: True
---

# 四位全加器和七段管译码器

!!! abstract
    计算机系统 Ⅰ lab1-1 实验报告（2022.03.11 ~ 2022.03.25）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 使用 Logisim 实现四位全加器 
    1. 打开 Logisim 软件，打开输入模板文件 full_adder.circ
    2. 文件中表明了该模块的输入输出端口，其中 A_0 至 A_3 是 A 信号为从低至高位的 4 个位。同理 B_0 至 B_3 是 B 信号从低至高位的 4 个位，Cin 是进位输入；S_out0 至 S_out3 是 S 输出信号从低到高的 4 个位，Cout 是进位输出
    3. 实现正确的四位全加器的电路绘画（其中的端口可以复制使用，并且可以使用 poke tool 更改输入信号）
- 使用 Logisim 实现七段管译码器
    1. 打开 Logisim 软件，打开输入模板文件 encoder.circ
    2. 文件中表明了该模块的输入输出端口，其中 A_0 至 A_3 是 A 信号为从低至高位的 4 个位
    3. 同理 B_0 至 B_6 是 B 输出信号从低至高位的 7 个位
    4. 正确连接输出信号至七段管相对应的引脚
    5. 实现正确的七段管译码器

## 四位全加器

四位全加器可以通过将四个一位全加器连接直接得到（每一位的 Cout 对接到高一位的 Cin，最低位 Cin 为输入信号的 Cin，最高位的 Cout 为输出信号的 Cout）

### 一位全加器

一位全加器有三个输入 A、B、Cin，两个输出 S、Cout。其真值表：

<style>
.md-typeset table:not([class]) th {
    min-width: 0;
}
</style>

<div style="text-align: center" markdown="1">

|A|B|Cin|S|Cout|
|:--:|:--:|:--:|:--:|:--:|
|0|0|0|0|0|
|1|0|0|0|1|
|0|1|0|0|1|
|1|1|0|1|0|
|0|0|1|0|1|
|1|0|1|1|0|
|0|1|1|1|0|
|1|1|1|1|1|

</div>

可以发现 S 是 A、B、Cin 的异或和，Cout 也可以推导得出：

$$
S = (A\oplus B)\oplus Cin\\
Cout = (A\&B) |((A\oplus B)\&Cin)
$$

按照这个逻辑构造出逻辑电路即可：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab1-1/add1.jpg" width="50%" style="margin: 0 auto;">
</div>

### 四位全加器
直接将一位全加器复制成四分，每个负责对应位数相加并带上低一位的进位，然后输出结果的一位，并且将输出的进位传给高一位

逻辑电路图：

![](/assets/images/cs/system/cs1/lab1-1/add4.jpg)

### 测试
令 A = 0 ~ 15、B = 0 ~ 15、Cin = 0/1，均进行了测试，结果和正常加法结果相同，并且已经交给 TA 验收过。

## 七段管译码器

### 实验思路
连接输出信号到七段管引脚可以直接对应七段管引脚与 LED 条的对应关系直接连接

将输入信号转为输出信号可以先写出对应的真值表，然后使用 Logisim 内置的 "Combinational Analysis" 功能构建逻辑电路，避免重复劳动

### 输出信号与七段管引脚连接
根据引脚与 LED 条的对应图：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab1-1/seven.png" width="10%" style="margin: 0 auto;">
<img src="/assets/images/cs/system/cs1/lab1-1/seven2.png" width="12%" style="margin: 0 auto;">
</div>

并将 B0 ~ B6 依次视为 A ~ G 七个 LED 条，可以连接出：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab1-1/seven_con.png" width="40%" style="margin: 0 auto;">
</div>

### 译码器
现有输入 A（从高位到低位 A3 ~ A0）以二进制形式表示一个数，要将其转换为七位输出 B0 ~ B6，真值表：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab1-1/table.jpg" width="80%" style="margin: 0 auto;">
</div>

生成逻辑电路图：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab1-1/circ.png" width="80%" style="margin: 0 auto;">
</div>

### 测试
已经组合了 0000 ~ 1111（0 ~ F）所有情况，显示均正常。