---
counter: True
comment: True
---

# 多路选择器的设计和测试

!!! abstract
    计算机系统 Ⅰ lab1-2 实验报告（2022.03.18 ~ 2022.04.01）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 使用 Logisim 完成电路级别的多路选择器
    1. 打开 Logisim 软件，打开输入模板文件 multi.circ
    2. 文件的 Standard sample 使用了 1 位的四路选择器，实现了通过改变 SW 对输入的选择
    3. 在本次实验中，为了理解多路选择器的电路级别具体实现，放弃使用 Logisim 封装的多路选择器，只采用门级电路，完成 Standard sample 的功能实现
- 使用 Vivado 实现多路选择器
    1. 打开 Vivado 软件，按照实验 1 的加入文件方式，加入设计文件样例文件 Multi_2CH32.v
    2. 同样加入测试文件 Mul_test.v
    3. 这个测试文件是 32 位 2 路选择器的样例文件，使用 Run Simulation 可以仿真。通过更改 SW 的值，多路选择器可以选择 data1 或者 data0 进行输出
    4. 本次实验要求，参考设计文件样例文件 Multi_2CH32.v 的 32 位 2 路选择器，使用 verilog 代码完成 32 位 8 路选择器。命名为 Multi_8CH32.v
    5. 同理需要参考测试文件 Mul_test.v，自主编写测试的 testbench 文件

## 电路级别多路选择器搭建

一位四路选择器可以使用三个一位二路选择器拼接形成，所以先来实现一位二路选择器

### 一位二路选择器搭建

假设两路输入分别为 A、B，开关为 S，则最终的输出为 A<span style="text-decoration: overline">S</span>+BS，转为逻辑电路：

![](/assets/images/cs/system/cs1/lab1-2/2CH1.png)

### 一位四路选择器
使用三个一位二路选择器连接即可：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab1-2/4CH1.png" width="50%" style="margin: 0 auto;">
</div>

### 测试
已经使用全部的输入和开关组合进行测试，结果均正确。

## Verilog 实现多路选择器
仿照所给的 Multi_2CH32.v 使用 case 语句即可实现

### 代码
```verilog
`timescale 1ns / 1ps

module Multi_8CH32(
    input [2:0]SW,      // 三位二进制数表示开关选择状态
    input [31:0]Data0,  // 八个三十二位数待选择
    input [31:0]Data1,
    input [31:0]Data2,
    input [31:0]Data3,
    input [31:0]Data4,
    input [31:0]Data5,
    input [31:0]Data6,
    input [31:0]Data7,
    output reg [31:0]Disp_num // 输出的 32 位数
);
    always @ (*)
    begin
    case (SW)  // 判断 SW 的八个值，分别为输出赋值
        3'b000: begin Disp_num = Data0; end
        3'b001: begin Disp_num = Data1; end
        3'b010: begin Disp_num = Data2; end
        3'b011: begin Disp_num = Data3; end
        3'b100: begin Disp_num = Data4; end
        3'b101: begin Disp_num = Data5; end
        3'b110: begin Disp_num = Data6; end
        3'b111: begin Disp_num = Data7; end
    endcase
    end
endmodule
```

### 测试
编写了仿真文件用来测试：
```verilog
`timescale 1ns / 1ps

module Mul_test();
reg [31:0]data0 = 32'hAA1111AA; // 任意的八个待选择值
reg [31:0]data1 = 32'hBB2222BB;
reg [31:0]data2 = 32'hCC3333CC;
reg [31:0]data3 = 32'hDD4444DD;
reg [31:0]data4 = 32'hEE5555EE;
reg [31:0]data5 = 32'hFF6666FF;
reg [31:0]data6 = 32'h00777700;
reg [31:0]data7 = 32'h11888811;
reg [2:0]SW;  // 开关状态
wire [31:0]out;
Multi_8CH32 ut(
    .SW(SW),
    .Data0(data0),
    .Data1(data1),
    .Data2(data2),
    .Data3(data3),
    .Data4(data4),
    .Data5(data5),
    .Data6(data6),
    .Data7(data7),
    .Disp_num(out)
);
initial
begin
SW = 3'b000;       // 测试 SW 所有值下的结果
#125 SW = 3'b001;
#125 SW = 3'b010;
#125 SW = 3'b011;
#125 SW = 3'b100;
#125 SW = 3'b101;
#125 SW = 3'b110;
#125 SW = 3'b111;
end
endmodule
```
仿真结果：
![](/assets/images/cs/system/cs1/lab1-2/sim.png)

从时序图和上面标注的数值可以看出确实按照正常预期运行了。