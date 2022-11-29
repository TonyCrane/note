---
counter: True
comment: True
---

# 复杂操作：乘法器

!!! abstract
    计算机系统 Ⅰ lab2-2 实验报告（2022.03.25 ~ 2022.04.15）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 32 位移位相加有符号乘法器
    1. 按照移位相加的原理，使用 verilog 编写 32 位乘法器
    2. 编写仿真测试代码，对所写乘法器做不少于 5 组样例的仿真测试
    3. 使用提供的测试环境进行上板测试
- 32 位 Booth 乘法器
    1. 按照 Booth Algorithm，使用 verilog 编写 32 位乘法器
    2. 编写仿真测试代码，对所写乘法器做不少于 5 组样例的仿真测试
    3. 使用提供的测试环境进行上板测试

## 32 位移位相加有符号乘法器
### 思路及代码
移位相加乘法器的原理就是进行位数次循环，每次循环检查 multiplier 的最低位，如果是 1，将乘法结果加上 multiplicand，是 0 就不进行这个操作，之后将 multiplicand 左移一位，multiplier 右移一位然后继续循环。

在 verilog 中可以使用 always @(*) 来创建一个串行运行的块，直接在其中按照移位相加的逻辑进行运算即可。并且要先判断一下正负，如果是负的（最高位为 1）则要先取反加一（即取绝对值），并且也要判断结果的正负。代码：
```verilog
module ShiftAddMultiplier(
    input [31:0] A,
    input [31:0] B,
    output [63:0] P
);
    integer i;
    reg [31:0] multiplicand;
    reg [31:0] multiplier;
    reg [63:0] prod;
    wire A_sign, B_sign, P_sign;
    assign A_sign = A[31];
    assign B_sign = B[31];
    assign P_sign = A_sign ^ B_sign;
    
    always @(*) begin
        multiplicand = A_sign? ~A+1 : A;
        multiplier = B_sign? ~B+1 : B;
        prod = 0;
        for (i = 0; i < 32; i = i + 1) begin
            if (multiplier[0] == 1'b1) begin
                prod = prod + multiplicand;
            end
            multiplicand = multiplicand << 1;
            multiplier = multiplier >> 1;
        end
    end
    assign P = P_sign? ~prod+1 : prod;
endmodule
```

### 仿真测试
包含五组测试样例的 test bench：
```verilog
module TestMultiplier();
    reg [31:0] A;
    reg [31:0] B;
    wire [63:0] P;

    ShiftAddMultiplier multiplier(
        .A(A),
        .B(B),
        .P(P)
    );
    
    initial begin
        A = 32'h00000001;
        B = 32'h00000002;
    #200
        A = 32'h00000002;
        B = 32'h00000005;
    #200
        A = 32'h00000009;
        B = 32'h00000009;
    #200
        A = -14;
        B = 12;
    #200
        A = -123;
        B = -456;
    end
endmodule
```
仿真结果：
![](/assets/images/cs/system/cs1/lab2-2/multi_sim.png)

可以看出工作正常。

### 上板验证
和 lab 2-1 类似，在顶层模块中连入乘法器：
```verilog
module Top(
    input RSTN, clk_100mhz,
    input BTNL, BTNR, BTNU, BTND, BTNC,
    input [15:0]SW,
    output [15:0]LED,
    output [7:0]SEGMENT, AN
);
    wire rst = ~RSTN;
    assign LED = SW;
    wire [31:0] Ai, Bi;
    wire [31:0] sum;
    wire [63:0] prod;
    
    ENV env(
        .clk(clk_100mhz), .rst(rst),
        .SW(SW),
        .BTNL(BTNL),
        .BTNR(BTNR),
        .BTNU(BTNU),
        .BTND(BTND),
        .BTNC(BTNC),
        .SEGMENT(SEGMENT),
        .AN(AN),
        .Ai(Ai),
        .Bi(Bi),
        .SUM(sum),
        .MUL(prod)
    );
    
    CarryLookaheadAdder adder(
        .A(Ai),
        .B(Bi),
        .S(sum)
    );
    
    ShiftAddMultiplier multiplier(
        .A(Ai),
        .B(Bi),
        .P(prod)
    );
endmodule
```
上板测试后也都按照正常工作。

## 32 位 Booth 乘法器
### 思路及代码
按照给出的 Booth Algorithm 流程，即：
- A = {multiplicand[31], multiplicand, 33'b0}
- S = {-{multiplicand[31], multiplicand}, 33'b0}
- P = {33'b0, multiplier, 0}
- 循环 32 次：
    - 如果 P[1:0] 为 2'b10：P = P + S
    - 如果 P[1:0] 为 2'b01：P = P + A
    - 如果 P[1:0] 为 2'b00、2'b11：不变
    - P 算术右移一位
- P[64:1] 即为乘法结果

按照这个思路，在 always @(*) 块中进行运算就可以得到乘法结果，代码：
```verilog
module BoothMultiplier(
    input [31:0] A,
    input [31:0] B,
    output [63:0] P
);
    reg [65:0] a, s, p;
    integer i;
    
    always @(*) begin
        a[31:0] = A;
        a[32] = a[31];
        a = a << 33;
        s = 0;
        s[31:0] = A;
        s[32] = s[31];
        s = ~s + 1;
        s = s << 33;
        p = 0;
        p[32:1] = B;
        for (i = 0; i < 32; i = i + 1) begin
            if (p[1:0] == 2'b10) begin
                p = p + s;
            end
            else if (p[1:0] == 2'b01) begin
                p = p + a;
            end
            p = ($signed(p)) >>> 1;
        end
    end
    assign P = p[64:1];
endmodule
```

### 仿真测试及上板测试
和 lab 2-1 以及前面移位相加乘法器同理，将其中乘法器实例化部分换为：
```verilog
    BoothMultiplier multiplier(
        .A(A),
        .B(B),
        .P(P)
    );
```
即可完成对 Booth 乘法器的仿真以及上板验证，仿真结果：
![](/assets/images/cs/system/cs1/lab2-2/multi_sim.png)

运行正确，并且上板验证后也按照预期工作。