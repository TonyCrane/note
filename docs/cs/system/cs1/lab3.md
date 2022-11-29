---
counter: True
comment: True
---

# 七段管显示器

!!! abstract
    计算机系统 Ⅰ lab3 实验报告（2022.04.16 ~ 2022.04.29）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 理解约束文件，添加开关控制
    1. 打开 Vivado 软件，按照实验 1 的加入文件方式，加入所有的 .v 文件和 .xdc 文件
    2. 样例中已经将七段管和时钟及 rst 设计好
    3. 刷入板子后，发现板子间接性闪烁 FFFFFFFF，由于没有开关输入，所以样例中将所有的输入都设置为了 F
    4. 理解现有的 xdc 文件，然后请添加 R15,M13,L16,J15 开关到约束文件。
- 理解时钟分频，降低闪烁速度
    1. 本次实验已经实现了一个较为简单的时钟分频使得闪烁速度接近 1s 一次
    2. 理解原有的代码，让闪烁消失
- 七段管的译码器
    1. 目前尚未完成 hex2shape 的译码器，只能实现显示 F
    2. 重新修改代码，使得七段管可以显示 0-9
    3. 将 R15,M13,L16,J15 开关和输入信号相关联，使得更改开关可以改变闪烁的七段管显示
    4. 需要实现的部分已用注释标出
- Bonus：七段管扩展
    1. 完成 AbCdEF 的额外显示

## 约束文件中添加开关控制
### 思路及代码
可以发现约束文件中对应引脚和变量的语句都是如下形式：
```haskell
set_property PACKAGE_PIN 引脚 [get_ports {变量}]
set_property IOSTANDARD LVCMOS33 [get_ports {变量}]
```
所以添加开关控制需要先在 Top.v 顶层模块中增加 SW 输入：
```verilog
module Top(
    input sys_clk,
    input rstn,
    input [3:0] SW,  // 四个开关
    output [7:0]  num_csn,
    output [7:0]  num_an
);
```
然后在 xdc 约束文件中加入：
```haskell
set_property PACKAGE_PIN R15 [get_ports {SW[3]}]
set_property IOSTANDARD LVCMOS33 [get_ports {SW[3]}]
set_property PACKAGE_PIN M13 [get_ports {SW[2]}]
set_property IOSTANDARD LVCMOS33 [get_ports {SW[2]}]
set_property PACKAGE_PIN L16 [get_ports {SW[1]}]
set_property IOSTANDARD LVCMOS33 [get_ports {SW[1]}]
set_property PACKAGE_PIN J15 [get_ports {SW[0]}]
set_property IOSTANDARD LVCMOS33 [get_ports {SW[0]}]
```
即从左到右 R15,M13,L16,J15 依次对应 SW 的从高到低位

## 取消闪烁
### 思路及代码
counter.v 中是时钟控制逻辑：
```verilog
module counter(
    input  wire clk,        // clock
    input  wire rstn,       // RESET Low Enable
    output reg [31:0] clkn  // clock number [32 bits]
);

always @ (posedge clk) begin
    if (rstn)
        clkn <= clkn + 1;   // clkn ++
    else
        clkn <= 0;          // clkn reset
end

endmodule
```
即每一个 clk 时钟上升沿增加一次 clkn。然后在 Top.v 中有控制刷新的部分逻辑：
```verilog
assign flash_clk = clkn[25];

always @(posedge flash_clk) begin
    // data_src <= ...
end
```
也就是当 clkn 的第 25 位从 0 变为 1 时（即 flash_clk 上升沿）执行对于 data_src 的赋值操作，也就是刷新。所以取消闪烁只要使刷新速度加快到人眼难以分辨。也就是让 flash_clk 记录 clkn 更低位的比特：
```verilog
assign flash_clk = clkn[15];
```

## 七段管的译码器
从提供的文件中可以看出需要实现的是 hex2shape.v 中的 hex_to_shape 模块，以及 Top.v 中将开关输入与 data_src 相连接
### hex_to_shape
#### 思路
```verilog
module hex_to_shape(
    input   [3:0] hex,
    output  [7:0] shape
);
```
只需要实现根据 hex 来对 shape 进行赋值。需要注意的是 shape 的顺序从低位到高位依次表示七段管的 A~G 以及小数点 DP：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs1/lab3/img1.png" width="20%" style="margin: 0 auto;">
</div>

并且由于七段管是低电平驱动，所以各个位置上 0 表示点亮，1 表示熄灭

#### 代码
根据各个显示的数字字母的形状来写出 shape，这里直接顺势完成了对于 A~F 的支持
```verilog
module hex_to_shape(
    input   [3:0] hex,
    output  [7:0] shape
);

reg [7:0] shape_reg;       // 需要一个 register 来在 case 语句中赋值
assign shape = shape_reg; 

always @(*) begin 
    case (hex)    // case 各种 hex 情况
        4'h0: begin shape_reg <= 8'b11000000; end
        4'h1: begin shape_reg <= 8'b11111001; end
        4'h2: begin shape_reg <= 8'b10100100; end
        4'h3: begin shape_reg <= 8'b10110000; end
        4'h4: begin shape_reg <= 8'b10011001; end
        4'h5: begin shape_reg <= 8'b10010010; end
        4'h6: begin shape_reg <= 8'b10000010; end
        4'h7: begin shape_reg <= 8'b11111000; end
        4'h8: begin shape_reg <= 8'b10000000; end
        4'h9: begin shape_reg <= 8'b10010000; end
        4'hA: begin shape_reg <= 8'b10001000; end
        4'hB: begin shape_reg <= 8'b10000011; end
        4'hC: begin shape_reg <= 8'b11000110; end
        4'hD: begin shape_reg <= 8'b10100001; end
        4'hE: begin shape_reg <= 8'b10000110; end
        4'hF: begin shape_reg <= 8'b10001110; end
        default: begin shape_reg <= 8'b11111111; end 
        // 虽然不会触发，但还是写了一个不显示的 default
    endcase
end

endmodule
```

### 关联开关输入与 data_src
#### 思路
给出的示例部分是：
```verilog
always @(posedge flash_clk) begin
    // 32'h00000000 <-> 32'hffffffff
    if (rstn) data_src <= ~data_src;
    else data_src <= 0;
end
```
也就是当 rstn 为 1 的时候，data_src 被赋值为 32'hffffffff，所以这个里面是要进行赋值操作的位置，而下面的 else 则是复位时进行的赋值操作

#### 代码
我这里将八个七段管显示为同样的字符，都由 SW 控制：
```verilog
always @(posedge flash_clk) begin
    if (rstn) begin
        data_src[31:28] <= SW[3:0];
        data_src[27:24] <= SW[3:0];
        data_src[23:20] <= SW[3:0];
        data_src[19:16] <= SW[3:0];
        data_src[15:12] <= SW[3:0];
        data_src[11: 8] <= SW[3:0];
        data_src[ 7: 4] <= SW[3:0];
        data_src[ 3: 0] <= SW[3:0];
    end
    else data_src <= 0;
end
```

## 上板测试
进行所有修改后进行了上板验证，均按照预期显示，一切正常。
