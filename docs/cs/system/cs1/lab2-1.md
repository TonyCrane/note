---
counter: True
comment: True
---

# 复杂操作：加法器

!!! abstract
    计算机系统 Ⅰ lab2-1 实验报告（2022.03.25 ~ 2022.04.08）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 32 位行波进位加法器（32-bit ripple-carry adder）
    1. 按照 ripple-carry adder 原理，使用 verilog 实现 32-bit 的 ripple-carry adder
    2. 编写仿真测试代码，对所写加法器做不少于 5 组样例的仿真测试
    3. 使用提供的测试环境进行上板测试
- 32 位超前进位加法器（32-bit carry-lookahead adder）
    1. 按照 carry-lookahead adder 原理，使用 verilog 实现 32-bit 的 carry-lookahead adder
    2. 编写仿真测试代码，对所写加法器做不少于 5 组样例的仿真测试
    3. 使用提供的测试环境进行上板测试

## 32 位行波进位加法器
主体思路就是使用两个 16 位加法器串联成 32 位加法器。16 位加法器使用 4 个 4 位加法器串联，4 位加法器使用 4 个全加器串联

### 一位全加器
lab 1-1 中已经做过对应的逻辑电路，只需要将其写成 verilog 语言：
```verilog
module FullAdder(
    input A,
    input B,
    input Cin,
    output S,
    output Cout
);
    assign S = A ^ B ^ Cin;
    assign Cout = (A & B) | ((A ^ B) & Cin);
endmodule
```

### 4~32 位行波进位加法器
```verilog
module RippleCarryAdder4(
    input [3:0] A,
    input [3:0] B,
    input Cin,
    output [3:0] S,
    output Cout
);
    wire cout_1, cout_2, cout_3; // 进位，用于串联加法器
    
    FullAdder adder0(
        .A(A[0]),
        .B(B[0]),
        .Cin(Cin),
        .S(S[0]),
        .Cout(cout_1)
    );
    
    FullAdder adder1(
        .A(A[1]),
        .B(B[1]),
        .Cin(cout_1),  // 连接 adder0 的进位
        .S(S[1]),
        .Cout(cout_2)
    );
    
    FullAdder adder2(
        .A(A[2]),
        .B(B[2]),
        .Cin(cout_2),  // 连接 adder1 的进位
        .S(S[2]),
        .Cout(cout_3)
    );
    
    FullAdder adder3(
        .A(A[3]),
        .B(B[3]),
        .Cin(cout_3),  // 连接 adder2 的进位
        .S(S[3]),
        .Cout(Cout)
    );

endmodule


module RippleCarryAdder16(
    input [15:0] A,
    input [15:0] B,
    input Cin,
    output [15:0] S,
    output Cout
);
    wire cout_1, cout_2, cout_3; // 与四位加法器同理
    
    RippleCarryAdder4 adder0(
        .A(A[3:0]),
        .B(B[3:0]),
        .Cin(Cin),
        .S(S[3:0]),
        .Cout(cout_1)
    );
    
    RippleCarryAdder4 adder1(
        .A(A[7:4]),
        .B(B[7:4]),
        .Cin(cout_1),
        .S(S[7:4]),
        .Cout(cout_2)
    );
    
    RippleCarryAdder4 adder2(
        .A(A[11:8]),
        .B(B[11:8]),
        .Cin(cout_2),
        .S(S[11:8]),
        .Cout(cout_3)
    );
    
    RippleCarryAdder4 adder3(
        .A(A[15:12]),
        .B(B[15:12]),
        .Cin(cout_3),
        .S(S[15:12]),
        .Cout(Cout)
    );

endmodule


module RippleCarryAdder(
    input [31:0] A,
    input [31:0] B,
    output [31:0] S
);
    wire cout, Cout;
    
    RippleCarryAdder16 adder0(
        .A(A[15:0]),
        .B(B[15:0]),
        .Cin(1'b0),
        .S(S[15:0]),
        .Cout(cout)
    );
    
    RippleCarryAdder16 adder1(
        .A(A[31:16]),
        .B(B[31:16]),
        .Cin(cout),
        .S(S[31:16]),
        .Cout(Cout)
    );
    
endmodule
```

### 仿真测试 TestBench
编写了包含五组测试样例的 test bench：
```verilog
module TestAdder();
    reg [31:0] A;
    reg [31:0] B;
    wire [31:0] S;
    
    RippleCarryAdder adder(
        .A(A),
        .B(B),
        .S(S)
    );
    
    initial begin
        A = 32'h00000001;
        B = 32'h00000001;
    #200
        A = 32'h00000AAA;
        B = 32'h00000BBB;
    #200
        A = 32'h12345678;
        B = 32'h23456789;
    #200
        A = 32'h87654321;
        B = 32'h12345678;
    #200
        A = 32'h10101010;
        B = 32'h4DEF67BC;
    end

endmodule
```
仿真结果：
![](/assets/images/cs/system/cs1/lab2-1/adder_sim.png)

可见加法运算正常

### 连接测试环境
按照提供的测试环境以及使用方法创建一个顶层模块来调用加法器，并且实现板子上的交互。载入 ENV.edf ENV_stub.v 文件，以及 Nexys4.xdc constraints，编写顶层模块：
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
    wire [31:0] sum; // 加法结果
    
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
        .SUM(sum),  // 连接结果
        .MUL(prod)
    );
    
    RippleCarryAdder adder(
        .A(Ai),
        .B(Bi),
        .S(sum)
    );
endmodule
```

上板测试也一切正常。

## 32 位超前进位加法器
按照给定的思路，使用 4 个 4 位超前进位加法器按照超前进位逻辑拼成 16 位超前进位加法器，然后使用行波进位逻辑串联成 32 位加法器。
### 4 位超前进位加法器
根据给出的一系列公式即可写出代码，并且为了连接出 16 位超前进位加法器，还要 output 整体的 P 和 G 信号，代码：
```verilog
module CarryLookaheadAdder4(
    input [3:0] A,
    input [3:0] B,
    input Cin,
    output [3:0] S,
    output P,
    output G,
    output Cout
);
    wire [3:0] p;
    wire [3:0] g;
    assign p = A ^ B;
    assign g = A & B;
    
    wire [4:0] c;
    assign c[0] = Cin;
    assign c[1] = g[0] | (p[0] & c[0]);
    assign c[2] = g[1] | (p[1] & g[0]) | (p[1] & p[0] & c[0]);
    assign c[3] = g[2] | (p[2] & g[1]) | (p[2] & p[1] & g[0]) | (p[2] & p[1] & p[0] & c[0]);
    assign c[4] = g[3] | (p[3] & g[2]) | (p[3] & p[2] & g[1]) | (p[3] & p[2] & p[1] & g[0]) | (p[3] & p[2] & p[1] & p[0] & c[0]);

    assign S = p ^ c[3:0];
    assign Cout = c[4];
    
    assign P = p[0] & p[1] & p[2] & p[3];
    assign G = g[3] | (p[3] & g[2]) | (p[3] & p[2] & g[1]) | (p[3] & p[2] & p[1] & g[0]);
endmodule
```

### 16 位超前进位加法器
使用四个 4 位超前进位加法器，根据超前进位逻辑拼接在一起。即四个 4 位加法器同时计算，进位不依次传入而是在当前模块中根据 P 和 G 超前计算得出，代码：
```verilog
module CarryLookaheadAdder16(
    input [15:0] A,
    input [15:0] B,
    input Cin,
    output [15:0] S,
    output P,
    output G,
    output Cout
);
    wire [4:0] c;
    wire [3:0] p;
    wire [3:0] g;
    assign c[0] = Cin;
    assign Cout = c[4];
    
    CarryLookaheadAdder4 adder0(
        .A(A[3:0]),
        .B(B[3:0]),
        .Cin(c[0]),
        .S(S[3:0]),
        .P(p[0]),
        .G(g[0])
    );
    
    CarryLookaheadAdder4 adder1(
        .A(A[7:4]),
        .B(B[7:4]),
        .Cin(c[1]),
        .S(S[7:4]),
        .P(p[1]),
        .G(g[1])
    );
    
    CarryLookaheadAdder4 adder2(
        .A(A[11:8]),
        .B(B[11:8]),
        .Cin(c[2]),
        .S(S[11:8]),
        .P(p[2]),
        .G(g[2])
    );
    
    CarryLookaheadAdder4 adder3(
        .A(A[15:12]),
        .B(B[15:12]),
        .Cin(c[3]),
        .S(S[15:12]),
        .P(p[3]),
        .G(g[3])
    );
    
    assign c[1] = g[0] | (p[0] & c[0]);
    assign c[2] = g[1] | (p[1] & g[0]) | (p[1] & p[0] & c[0]);
    assign c[3] = g[2] | (p[2] & g[1]) | (p[2] & p[1] & g[0]) | (p[2] & p[1] & p[0] & c[0]);
    assign c[4] = g[3] | (p[3] & g[2]) | (p[3] & p[2] & g[1]) | (p[3] & p[2] & p[1] & g[0]) | (p[3] & p[2] & p[1] & p[0] & c[0]);
    
    assign P = p[0] & p[1] & p[2] & p[3];
    assign G = g[3] | (p[3] & g[2]) | (p[3] & p[2] & g[1]) | (p[3] & p[2] & p[1] & g[0]);
endmodule
```

### 32 位超前进位加法器
使用两个 16 位超前进位加法器用行波进位逻辑串联在一起：
```verilog
module CarryLookaheadAdder(
    input [31:0] A,
    input [31:0] B,
    output [31:0] S
);
    wire cout, Cout;
    
    CarryLookaheadAdder16 adder0(
        .A(A[15:0]),
        .B(B[15:0]),
        .Cin(1'b0),
        .S(S[15:0]),
        .Cout(cout)
    );
    
    CarryLookaheadAdder16 adder1(
        .A(A[31:16]),
        .B(B[31:16]),
        .Cin(cout),
        .S(S[31:16]),
        .Cout(Cout)
    );
endmodule
```

### 仿真测试与上板测试
与前面行波进位加法器类似，将其 test bench 与 top 模块中实例化加法器模块部分改为：
```verilog
    CarryLookaheadAdder adder(
        .A(A),
        .B(B),
        .S(S)
    );
```
即可测试超前进位加法器与上板测试。仿真结果：
![](/assets/images/cs/system/cs1/lab2-1/adder_sim.png)

上板测试也一切正常。
