---
counter: True
comment: True
---

# 流水线冒险处理

!!! abstract
    计算机系统 Ⅱ lab2 实验报告（2022.10.08 ~ 2022.10.27）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- lab 2-1：暂停与冒险
    - 在 lab 1 的基础上加入 stall 机制处理数据冒险和控制冒险
    - 进行仿真测试，检验 CPU 基本功能
    - 进行上板测试，检验 CPU 设计规范
    - 思考题
        1. 请你对数据冲突情况进行分析归纳，试着将他们分类列出。
        2. 如果 EX, MEM, WB 段中不止一个段的写寄存器与 ID 段的读寄存器发生了冲突，该如何处理？
- lab 2-2：旁路优化 Forwarding
    - 在 lab 2-1 基础上实现 Forwarding 机制
    - 进行仿真测试和上板测试
    - 思考题
        1. 在引入 Forwarding 机制后，是否意味着 stall 机制就不再需要了？为什么？
        2. 你认为 Forwarding 机制在实际的电路设计中是否存在一定的弊端？如果存在，请给出你的理由。

本报告没有按照两个 lab 的顺序进行，而是以具体进行修改的顺序进行的（先处理数据冒险，然后处理控制冒险，最后处理在实际运行时遇到的其它冒险问题）。

<h2 style="margin-top: 0.5em">数据冒险</h2>

### Forwarding 机制
和上课/书上讲的一样，通过一个 ForwardingUnit 来计算是否需要前递，然后通过多路选择器选择出传入 ALU 的结果。
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab2/img1.png" width="75%" style="margin: 0 auto;">
</div>

在此基础上需要一些改进的是，在我的 CPU 中，ALU 的两个输入都已经需要先选择（一个通过 auipc 选择 PC 还是寄存器值，一个通过 alu_src 选择寄存器值还是立即数），所以 ForwardingUnit 还需要接收 auipc、alu_src 两个信号，如果 auipc 为 1 则该侧不会使用寄存器值，也就不涉及到数据冒险，alu_src 也同理。这样输出的值有四种情况，具体见下面代码注释：
```verilog
module ForwardingUnit(
    input       [4:0]   EX_MEM_rd,
    input       [4:0]   MEM_WB_rd,
    input       [4:0]   ID_EX_rs1,
    input       [4:0]   ID_EX_rs2,
    input               EX_MEM_reg_write,
    input               MEM_WB_reg_write,
    input               auipc,
    input               alu_src_b,
    output reg  [1:0]   ForwardA,   // 00 来自寄存器，01 来自 EX/MEM，10 来自 MEM/WB，11 来自 PC
    output reg  [1:0]   ForwardB    // 00 来自寄存器，01 来自 EX/MEM，10 来自 MEM/WB，11 来自 imm
);
    always @(*) begin
        if (auipc) assign ForwardA = 2'b11;
        else begin
            if (EX_MEM_reg_write == 1 && EX_MEM_rd != 0 && EX_MEM_rd == ID_EX_rs1) assign ForwardA = 2'b01;
            else if (MEM_WB_reg_write == 1 && MEM_WB_rd != 0 && MEM_WB_rd == ID_EX_rs1) assign ForwardA = 2'b10;
            else assign ForwardA = 2'b00; 
        end
        if (alu_src_b) assign ForwardB = 2'b11;
        else begin
            if (EX_MEM_reg_write == 1 && EX_MEM_rd != 0 && EX_MEM_rd == ID_EX_rs2) assign ForwardB = 2'b01;
            else if (MEM_WB_reg_write == 1 && MEM_WB_rd != 0 && MEM_WB_rd == ID_EX_rs2) assign ForwardB = 2'b10;
            else assign ForwardB = 2'b00;
        end
    end
endmodule
```
此外需要一些 wire 和 reg：
```verilog
    wire    [2:0]   forwardA, forwardB;
    reg     [4:0]   ID_EX_rs1, ID_EX_rs2;

// 时序更新：
    ID_EX_rs1 <= IF_ID_inst[19:15];
    ID_EX_rs2 <= IF_ID_inst[24:20];
```
以及最后连线选择 ALU 输入：
```verilog
ForwardingUnit forwarding (
    .EX_MEM_rd(EX_MEM_write_addr),
    .MEM_WB_rd(MEM_WB_write_addr),
    .ID_EX_rs1(ID_EX_rs1),
    .ID_EX_rs2(ID_EX_rs2),
    .EX_MEM_reg_write(EX_MEM_reg_write),
    .MEM_WB_reg_write(MEM_WB_reg_write),
    .auipc(ID_EX_auipc),
    .alu_src_b(ID_EX_alu_src),
    .ForwardA(forwardA),
    .ForwardB(forwardB),
);

Mux4x32 mux_alu_a (
    .I0(ID_EX_data1),
    .I1(EX_MEM_alu_result),
    .I2(write_data),   // WB 段选择出来的写回寄存器的数据
    .I3(ID_EX_pc),
    .s(forwardA),
    .o(alu_data1)
);

Mux4x32 mux_alu_b (
    .I0(ID_EX_data2),
    .I1(EX_MEM_alu_result),
    .I2(write_data),
    .I3(ID_EX_imm),
    .s(forwardB),
    .o(alu_data2)
);
```

### Double bump 机制 
根据指导，为了解决同一个周期内写入 reg 后读的冒险情况，需要使用 double bump 机制。在寄存器组的定义中，读取的结果是直接 assign 的，而写入才是时序逻辑，所以只要让寄存器组在 CPU 的一个周期中完成写入即可（而不是在下一个周期开始的上升沿写入）。这样来说只要将寄存器组的写入触发改为下降沿（negedge）即可：
```verilog
always @(negedge clk or posedge rst) begin
    if (rst == 1) for (i = 1; i < 32; i = i + 1) register[i] <= 0; // reset
    else if (we == 1 && write_addr != 0) register[write_addr] <= write_data;
end
```

### Stall 机制
对于 load-use 类数据冒险，仅 forwarding 是不够的，需要再 stall 一个周期才可以 forwarding。
![](/assets/images/cs/system/cs2/lab2/img2.png)

如上图，需要在每条指令进入 ID 阶段后进行验证，验证这时处于 EX 阶段的指令是不是 load 指令（是否发生了 D-Mem 的数据读取）然后检测是否与当前指令有数据冲突。如果有冲突则需要 stall 一个周期，具体为：

- EX/MEM 与 MEM/WB 阶段仍正常执行流转
- 将当前的 ID/EX 阶段寄存器中控制信号置 0，即相当于插入 bubble
- 阻止 IF/ID 阶段寄存器和 PC 的时序更新，实现暂停

首先需要添加一个 mem_read 控制信号来判断是否发生了数据读取（不可以通过 mem_write 判断，因为 mem_write 为 0 可能也不会使用读取的数据）：
```verilog
module Control (
    ...
    output reg          mem_read
);
    `include "AluOp.vh"
    always @(*) begin
        ...
        mem_read    = 0;
        case (op_code)
            7'b0000011: begin   // lw
                ...
                mem_read = 1;
            end
            ...   
        endcase
    end
endmodule
```
然后同理在 CPU 中创建 wire mem_read 用于接收当前 Control 的输出，然后通过时序赋值给 reg ID_EX_mem_read 寄存器。之后需要一个 StallUnit 来判断是否需要暂停：
```verilog
module StallUnit(
    input           ID_EX_mem_read,
    input   [4:0]   ID_EX_rd,
    input   [4:0]   IF_ID_rs1,
    input   [4:0]   IF_ID_rs2,
    output          bubble_stop
);
    assign bubble_stop = ID_EX_mem_read && (ID_EX_rd == IF_ID_rs1 || ID_EX_rd == IF_ID_rs2);
endmodule
```
连接：
```verilog
wire bubble_stop;
StallUnit stallunit (
    .ID_EX_mem_read(ID_EX_mem_read),
    .ID_EX_rd(ID_EX_write_addr),
    .IF_ID_rs1(IF_ID_inst[19:15]),
    .IF_ID_rs2(IF_ID_inst[24:20]),
    .bubble_stop(bubble_stop)
);
```
然后在时序更新部分判断 bubble_stop 是否为 1，如果为 1 则进行特殊处理（不更新 pc 和 IF/ID，为 ID/EX 控制信号赋 0）：
```verilog
always @(posedge clk or posedge rst) begin 
    if (rst) begin ... end
    else begin
        if (bubble_stop) begin
            ID_EX_alu_op <= 4'b0;          ID_EX_pc_src <= 2'b0;
            ID_EX_mem_to_reg <= 2'b0;      ID_EX_reg_write <= 1'b0;
            ID_EX_alu_src <= 1'b0;         ID_EX_branch <= 1'b0;
            ID_EX_b_type <= 1'b0;          ID_EX_auipc <= 1'b0;
            ID_EX_mem_write <= 1'b0;       ID_EX_mem_read <= 1'b0;
        end else begin
            pc <= pc_next;

            IF_ID_pc <= pc;                IF_ID_inst <= inst;

            ID_EX_pc_src <= pc_src;        ID_EX_mem_to_reg <= mem_to_reg;
            ID_EX_reg_write <= reg_write;  ID_EX_alu_src <= alu_src;
            ID_EX_branch <= branch;        ID_EX_b_type <= b_type;
            ID_EX_auipc <= auipc;          ID_EX_alu_op <= alu_op;
            ID_EX_mem_write <= mem_write_; ID_EX_mem_read <= mem_read;
        end
        // update of EX/MEM and MEM/WB
    end
end
```

### 测试
从给出的汇编中挑取了一小部分用来测试前面处理过的数据冒险：
```asm
addi x1, x0, 1  
addi x2, x0, 1
addi x4, x0, 5
add x3, x1, x2
add x1, x2, x3
add x2, x1, x3
ld x4, 0(x2)
addi x4, x4, -1
```
载入给出的初始 RAM，仿真波形及其分析如下，可见计算结果均正确，暂停也符合预期
![](/assets/images/cs/system/cs2/lab2/img3.png)

## 控制冒险
### 分支判断前移
按照之前的设计，关于分支跳转语句的 pc_next 计算是在 MEM 段完成的（利用从 EX 段传出来的 alu_result），但这种情况下对于每一条分支跳转语句后面都需要等待三个周期才能得到正确 pc。而实际上在 ID 段就可以根据从寄存器中读出来的结果判断是否需要分支。所以可以将 MEM 阶段的 pc mux 移到 ID 段，这样就只需要等待一个周期。

这样等待一个周期和前面的 stall 就很相似了，但是还有一些不同，前面数据冒险的 stall 是将当前指令暂停，即变成一个 bubble 传下去而当前指令等待。而此处的当前指令是 branch 指令，需要继续传下去，而在其后插入一条 bubble，所以实际的操作为：

- pc 可以继续更新（但是如果检测到了是跳转指令，则在选择当前 pc_next 时不传入 pc+4 而是 pc，即暂停一条）
- IF/ID 段的 pc 可以随意，inst 设置为 32'h00000013，即 nop（相当于在后面插入了一条 bubble）
- 剩下的部分都正常更新流转

因此首先需要为控制模块加一个 jump 控制信号判断是否是分支跳转语句：
```verilog
module Control (
    ...
    output reg          jump
);
    `include "AluOp.vh"
    always @(*) begin
        ...
        jump        = 0;
        case (op_code)
            ...
            7'b1100011: begin   // bne beq
                ...     jump = 1;
            end
            7'b1101111: begin   // jal
                ...     jump = 1;
            end
            7'b1100111: begin   // jalr
                ...     jump = 1;
            end
            ...   
        endcase
    end
endmodule
```

然后是新增 wire jump 用来传输，以及针对于 jump 情况 stall 的时序更新：
```verilog
always @(posedge clk or posedge rst) begin 
    if (rst) begin ... end
    else begin
        if (bubble_stop) begin ... end 
        else if (jump) begin
            pc <= pc_next;

            IF_ID_pc <= pc;
            IF_ID_inst <= 32'h00000013;
            
            ID_EX_pc_src <= pc_src;
            ID_EX_mem_to_reg <= mem_to_reg;
            ID_EX_reg_write <= reg_write;
            ID_EX_alu_src <= alu_src;
            ID_EX_branch <= branch;
            ID_EX_b_type <= b_type;
            ID_EX_auipc <= auipc;
            ID_EX_alu_op <= alu_op;
            ID_EX_mem_write <= mem_write_;
            ID_EX_mem_read <= mem_read;
        end else begin 
            ...
```

最后是在 ID 阶段的 pc 选择器：

```verilog
assign jal_addr = IF_ID_pc + imm;
assign jalr_addr = read_data1 + read_data2;
MuxPC mux_pc (
    .I0(jump ? pc : pc + 4),
    .I1(jalr_addr),
    .I2(jal_addr),
    .I3(jal_addr),
    .s(pc_src),
    .branch(branch),
    .b_type(b_type),
    .alu_res(read_data1 ^ read_data2),
    .o(pc_next)
);
```

### 处理控制冒险中的数据冒险
前面将 pc 选择器提前到 ID 阶段并 stall 是不够的，因为一般对于循环，在 branch 语句检查的前一条会涉及到循环变量寄存器的修改，例如：
```asm
addi x1, x1, -1
bne x1, x0, loop
```
此时 bne 需要在 ID 阶段读取 x1，但是在 ID 阶段时上一条指令仍在 EX 阶段，x1 还没有更新。所以需要 stall 一个周期等待上一条指令 EX 阶段结束，然后将 ALU 结果通过 forwarding 传给 bne 的 ID 阶段然后进行判断。即下图：
![](/assets/images/cs/system/cs2/lab2/img5.png)

可以看出，此处的数据冒险的 stall 方式和前面数据冒险一样，因此只需要在 StallUnit 中对 bubble_stop 加一个条件即可（上一条指令有寄存器写入，且与读取的寄存器产生了冲突）。然后 ID 阶段的 forwarding 需要单独写一下。在 branch 指令后面的 bubble 即为前面写过的 stall。

因此代码上的修改：对于 StallUnit 的修改：
```verilog
module StallUnit(
    ...
    input           jump,
    input           ID_EX_reg_write,
    ...
);
    assign bubble_stop = (...) || (jump && ID_EX_reg_write && ID_EX_rd != 0 && (ID_EX_rd == IF_ID_rs1 || ID_EX_rd == IF_ID_rs2));
```
在 ID 阶段的 forwarding：
```verilog
wire    [31:0]  reg1, reg2;
assign reg1 = (jump && EX_MEM_reg_write && (EX_MEM_write_addr != 0) && (EX_MEM_write_addr == IF_ID_inst[19:15])) ? EX_MEM_alu_result : read_data1;
assign reg2 = (jump && EX_MEM_reg_write && (EX_MEM_write_addr != 0) && (EX_MEM_write_addr == IF_ID_inst[24:20])) ? EX_MEM_alu_result : read_data2;
assign jalr_addr = reg1 + reg2;
MuxPC mux_pc (
    ...
    .alu_res(reg1 ^ reg2),
    ...
);
```

## 其它情况引起的冒险
在前面简单处理了数据冒险和控制冒险之后，给出的程序仍然不能完全正确运行，还存在一些疏漏的数据冒险：

### R 型指令后 store

如果 R 型指令修改了一个寄存器的值，然后通过 store 存储它，这种情况下并不会 store 正确的值，因为 EX 阶段的结构如下图（黑、红色为原来的）：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab2/img6.png" width="70%" style="margin: 0 auto;">
</div>

其中对于 store 指令，ALU 和前面两个 mux 都会用到（用来计算写入地址），而写入的值实际上是直接从寄存器读取的 data2 接入的（即红色线），这里并没有处理数据冒险。而且写入值也无法借用前面写过的 forwarding（因为此时都在使用），所以可以直接从 ForwardingUnit 再判断、引出一个 ForwardC 信号，来选择写入数据，同理，可能来自 EX/MEM 或 MEM/WB。

因此修改 ForwardingUnit：
```verilog
module ForwardingUnit(
    ...
    output reg  [1:0]   ForwardC // 00 来自 data2、01 来自 EX/MEM、10 来自 MEM/WB
);
        if (EX_MEM_reg_write && EX_MEM_rd != 0 && EX_MEM_rd == ID_EX_rs2) assign ForwardC = 2'b01
        else if (MEM_WB_reg_write && MEM_WB_rd != 0 && MEM_WB_rd == ID_EX_rs2) assign ForwardC = 2'b01
        else assign ForwardC = 2'b00;
```
以及在 EX 阶段增加一个四路选择器（有一路不用）来选择最终要赋值给 EX_MEM_data2 的值（即在 MEM 阶段要进行写入的值）：
```verilog
wire    [1:0]   forwardC;
wire    [31:0]  ex_mem_data2;
Mux4x32 mux_data2 (
    .I0(ID_EX_data2),
    .I1(EX_MEM_alu_result),
    .I2(write_data),
    .I3(32'h00000000),
    .s(forwardC),
    .o(ex_mem_data2)
);
```
以及将时序更新里的更新 EX_MEM_data2 为 ID_EX_data2 改为 ex_mem_data2：
```verilog
...
    EX_MEM_data2 <= ex_mem_data2;
...
```

### lui 后 R 型指令
前面的 Forwarding 仍然存在一些问题，比如在 lui 指令和其后面的 R 型指令发生冲突：
```asm
lui x1, 0x0001
add x2, x1, x3
```
此时的 add 语句并不会正确处理与前面 lui 产生的数据冒险，因为 add 语句读取 x1 发生冲突，而上一条语句正在使用，所以按照前面写的会去读取 EX_MEM 寄存器中的 alu_result 作为 x1 的值。但实际上 lui 写回寄存器的值并不是 ALU 的计算结果，而是 lui 指令的立即数（由 mem_to_reg 信号决定）。

另一种情况是 jal/jalr 指令跳转到的位置处有一条指令需要读取返回地址（也就是 pc+4），这时写回寄存器的也不是 ALU 的结果，而是当前跳转指令的 pc+4。这两种情况都可以通过判断 mem_to_reg 来解决。所以需要修改 ForwardingUnit，将 ForwardA、ForwardB 信号扩展一位：
```verilog
module ForwardingUnit(
    ...
    output reg  [2:0]   ForwardA,   
        // 000 来自寄存器，001 来自 EX/MEM，010 来自 MEM/WB，011 来自 PC
        // 100 来自 EX/MEM 的 PC + 4，101 来自 MEM/WB 的 PC + 4
        // 110 来自 EX/MEM 的 imm，111 来自 MEM/WB 的 imm
    output reg  [2:0]   ForwardB,   // ...
    output reg  [1:0]   ForwardC
);
    always @(*) begin
        if (auipc) begin
            assign ForwardA = 3'b011;
        end else begin
            if          (EX_MEM_reg_write == 1 && EX_MEM_rd != 0 && EX_MEM_rd == ID_EX_rs1) begin
                if      (EX_MEM_mem_to_reg == 2'b01) assign ForwardA = 3'b110;
                else if (EX_MEM_mem_to_reg == 2'b10) assign ForwardA = 3'b100;
                else                                 assign ForwardA = 3'b001;
            end else if (MEM_WB_reg_write == 1 && MEM_WB_rd != 0 && MEM_WB_rd == ID_EX_rs1) begin
                if      (MEM_WB_mem_to_reg == 2'b01) assign ForwardA = 3'b111;
                else if (MEM_WB_mem_to_reg == 2'b10) assign ForwardA = 3'b101;
                else                                 assign ForwardA = 3'b010;
            end else begin
                assign ForwardA = 3'b000;
            end
        end
        if (alu_src_b) begin
            assign ForwardB = 3'b011;
        end else begin
            if          (EX_MEM_reg_write == 1 && EX_MEM_rd != 0 && EX_MEM_rd == ID_EX_rs2) begin
                if      (EX_MEM_mem_to_reg == 2'b01) assign ForwardB = 3'b110;
                else if (EX_MEM_mem_to_reg == 2'b10) assign ForwardB = 3'b100;
                else                                 assign ForwardB = 3'b001;
            end else if (MEM_WB_reg_write == 1 && MEM_WB_rd != 0 && MEM_WB_rd == ID_EX_rs2) begin
                if      (MEM_WB_mem_to_reg == 2'b01) assign ForwardB = 3'b111;
                else if (MEM_WB_mem_to_reg == 2'b10) assign ForwardB = 3'b101;
                else                                 assign ForwardB = 3'b010;
            end else begin
                assign ForwardB = 3'b000;
            end
        end
        ... // for ForwardC
    end
endmodule
```
以及需要修改 ALU 前选择输入的两个寄存器，改为八路选择器：
```verilog
wire    [2:0]   forwardA, forwardB;

Mux8x32 mux_alu_a (
    .I0(ID_EX_data1),
    .I1(EX_MEM_alu_result),
    .I2(write_data),
    .I3(ID_EX_pc),
    .I4(EX_MEM_pc + 4),
    .I5(MEM_WB_pc + 4),
    .I6(EX_MEM_imm),
    .I7(MEM_WB_imm),
    .s(forwardA),
    .o(alu_data1)
);

Mux8x32 mux_alu_b (
    .I0(ID_EX_data2),
    .I1(EX_MEM_alu_result),
    .I2(write_data),
    .I3(ID_EX_imm),
    .I4(EX_MEM_pc + 4),
    .I5(MEM_WB_pc + 4),
    .I6(EX_MEM_imm),
    .I7(MEM_WB_imm),
    .s(forwardB),
    .o(alu_data2)
);
```

## 仿真测试及分析
运行所给的 lab2.s 程序，载入 lab2-ram.coe 和 lab2-rom.coe，以 Core_tb.sv 为顶层模块进行仿真。
### 仿真结果
仿真波形如下（有部分循环省略了）：
![](/assets/images/cs/system/cs2/lab2/sim1.png)
![](/assets/images/cs/system/cs2/lab2/sim2.png)
![](/assets/images/cs/system/cs2/lab2/sim3.png)
![](/assets/images/cs/system/cs2/lab2/sim4.png)

整个寄存器组值的变化（上十进制，下十六进制）：
![](/assets/images/cs/system/cs2/lab2/reg1.png)
![](/assets/images/cs/system/cs2/lab2/reg2.png)

### 结果分析
根据汇编代码分析波形：
![](/assets/images/cs/system/cs2/lab2/sim_ana1.png)
![](/assets/images/cs/system/cs2/lab2/sim_ana2.png)
![](/assets/images/cs/system/cs2/lab2/sim_ana3.png)
![](/assets/images/cs/system/cs2/lab2/sim_ana4.png)

可以看出，结果均正确，且按照预期进行 stall、跳转。

## 思考题
### lab 2-1
1. **请你对数据冲突情况进行分析归纳，试着将他们分类列出。**

<div style="margin-left: 2em">

RISC-V 流水线数据冲突归纳后本质其实就是一种，即在尚未写入寄存器时读取其值（RAW），其包含很多种细分的情况：

- use-use 冲突
- load-use 冲突
- use-store 冲突

</div>


2. **如果 EX, MEM, WB 段中不止一个段的写寄存器与 ID 段的读寄存器发生了冲突，该如何处理？**

<div style="margin-left: 2em">

不止一个段与 ID 的读寄存器发生了冲突，应该先考虑最近的一个写寄存器（先 EX 然后 MEM 最后 WB），将其值前递到 ID 段作为当前读寄存器的实际值。

</div>

### lab 2-2
1. **在引入 Forwarding 机制后，是否意味着 stall 机制就不再需要了？为什么？**

<div style="margin-left: 2em">

不是，因为 Forwarding 机制只能解决部分数据冲突，例如 load-use 冲突就无法通过 Forwarding 完全解决，需要先 stall 一个周期后再使用 Forwarding。其次，控制冲突也需要通过 stall 才能解决。

</div>

2. **你认为 Forwarding 机制在实际的电路设计中是否存在一定的弊端？如果存在，请给出你的理由。**

<div style="margin-left: 2em">

Forwarding 机制需要在 ID 段中增加一些选择器，增加了电路的复杂度，同时也增加了电路的延迟，存在一些弊端。不过 Forwarding 机制可以解决部分数据冲突，可以减少 stall 的次数，从而提高电路的效率。总之 Forwarding 机制确实有弊端，但综合来看不一定有没有弊端。

</div>
