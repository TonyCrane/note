---
counter: True
comment: True
---

# 综合实验（特权级 CPU）

!!! abstract
    计算机系统 Ⅱ lab7 实验报告（2022.12.08 ~ 2022.12.29）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 完善 CPU Core，实现部分特权级内容
    - 增加 CSR 寄存器及相关指令
    - 增加特权态指令
    - 增加异常处理逻辑
- 运行 Naive Kernel
    - normal：ecall 指令处理
    - advance(bonus)：ecall 指令处理 + 非法指令异常处理

## 实验相关逻辑

本次实验设计到的 RISC-V 特权级 ISA 都在我的笔记 https://note.tonycrane.cc/cs/pl/riscv/privileged/ 中整理过了，这里是一部分梳理。

### CSR
RISC-V 分配了 4096 个 CSR 寄存器，每个寄存器有一个 12 位的编号，本实验中用到的几个：

- 0x300 mstatus：存储 M 态的状态值，本实验中只进行写入，而不需要处理其具体内容
- 0x305 mtvec：存储 M 态的中断向量地址，在遇到 trap 时需要跳转此处
- 0x341 mepc：存储 trap 发生时的 pc 值，异常处理结束后跳转回此处
- 0x342 mcause：存储 trap 发生的原因，本实验中用到的两个值：
    - &nbsp;2 - Illegal Instruction：非法指令
    - 11 - Environment Call from M-mode：从 M 态发出的 ecall

几个 CSR 操作指令，都在一个指令中同时进行 GPR、CSR 两个寄存器的读写：

- csrrw：csr -> rd, rs1 -> csr
- csrrs：csr -> rd, csr | rs1 -> csr
- csrrc：csr -> rd, csr & ~rs1 -> csr

本次实验中我并没有完全实现这些目标，而只考虑了 csrr 和 csrw 两种伪指令的情况：

- csrr rd, csr（原型为 csrrs rd, csr, x0）：csr -> rd
- csrw csr, rs1（原型为 csrrw x0, csr, rs1）：rs1 -> csr

### 特权指令及异常处理逻辑
本次实验中需要处理的几种特殊情况：

- ecall：
    - 读取 mtvec 寄存器的值，跳转到此处
    - 将此时的 pc 写入 mepc 寄存器中
    - 将 11 写入 mcause 寄存器中
- mret：
    - 读取 mepc 寄存器的值，跳转到此处
- 非法指令：
    - （unimp 指令实际上是 csr 指令操纵了未定义的 CSR 寄存器，所以要仔细判断非法指令）
    - 读取 mtvec 寄存器的值，跳转到此处
    - 将此时的 pc 写入 mepc 寄存器中
    - 将 2 写入 mcause 寄存器中

## 具体实现
### RAM 与 ROM 替换
使用提供的自定义的 myRam 和 myRom 来替代原来的 ip 核方便调试。

这里我附加了一个更改是初始化所有 RAM 值为 0，避免后续在仿真时出现不定态干扰运行。

```verilog
module myRam(
    ...
    initial begin
        for (i = 0; i < 2048; i = i + 1) ram[i] <= 32'h00000000;
    end
    ...
endmodule
```

### Forwarding bug 修复
在实际运行的时候发现 lab2 中写的 forwarding 有一个 bug，我的设计针对所有跳转指令都会强制 stall 一个周期，然后在实际的 ID 阶段就进行跳转。这里做了 forwarding 处理，为了解决在 R 型指令后进行跳转的数据冒险：

```verilog
assign reg1 = (jump && EX_MEM_reg_write && (EX_MEM_write_addr != 0) && (EX_MEM_write_addr == IF_ID_inst[19:15])) ? EX_MEM_alu_result : read_data1;
assign reg2 = (jump && EX_MEM_reg_write && (EX_MEM_write_addr != 0) && (EX_MEM_write_addr == IF_ID_inst[24:20])) ? EX_MEM_alu_result : read_data2;
```

但是这里有一个问题，如果跳转的前一句指令是 load 指令，那么这个语句也会认为需要 forwarding，也确实需要 forwarding，不过它拉过来的值是 alu_result，在 load 指令中 alu 计算的结果是要 load 的地址，而这里需要的是 load 出来的值。根据时序，在这里 RAM 已经完成读取，此时正好可以使用 RAM 传来的值进行 forwarding，所以判断一下 mem_to_reg 是否代表 load 指令，如果是则使用 data_in 即可：

```verilog
assign reg1 = (jump && EX_MEM_reg_write && (EX_MEM_write_addr != 0) && (EX_MEM_write_addr == IF_ID_inst[19:15])) ? (EX_MEM_mem_to_reg == 2'b11 ? data_in : EX_MEM_alu_result) : read_data1;
assign reg2 = (jump && EX_MEM_reg_write && (EX_MEM_write_addr != 0) && (EX_MEM_write_addr == IF_ID_inst[24:20])) ? (EX_MEM_mem_to_reg == 2'b11 ? data_in : EX_MEM_alu_result) : read_data2;
```

### 分支语句扩充
之前的分支语句只实现了 beq 和 bne，将所有分支语句都按照 funct3[0] 强制分为 beq 或 bne，会导致结果并不正确。这里将所有分支语句都进行了实现，只需要修改控制模块：

```verilog
case (op_code)
    ...
    7'b1100011: begin
        branch = 1; jump = 1;
        case (funct3)
            3'b000: begin alu_op = XOR; b_type = 1; end     // beq
            3'b001: begin alu_op = XOR; b_type = 0; end     // bne
            3'b100: begin alu_op = SLT; b_type = 0; end     // blt
            3'b101: begin alu_op = SLT; b_type = 1; end     // bge
            3'b110: begin alu_op = SLTU; b_type = 0; end    // bltu
            3'b111: begin alu_op = SLTU; b_type = 1; end    // bgeu
        endcase
    end
    ...
endcase
```

### CSR 寄存器组
根据前面的分析，本次实验只需要实现四个 CSR 寄存器，所以这个模块中只需要定义四个寄存器即可，而不需要全部实现 4096 个。

而且由于异常处理逻辑的存在，例如 ecall 指令，一句就可能进行多个 CSR 寄存器的读写，所以针对 trap 我进行了特殊的处理：

- 传入一个 trap，00 表示没有 trap，01 表示是 ecall，10 表示是非法指令
- 还需要传入此时的 pc 值
- 后两者需要将 pc 写入 mepc，将对应异常值写入 mcause

其余情况类似 GPR 一样处理即可（即时读取、写入 double bump）：

```verilog
`timescale 1ns / 1ps

module CSRs (
    input           clk,
    input           rst,
    input           we,
    input   [1:0]   trap, // 00 no trap, 01 ecall, 10 unimp, 11 mret
    input   [31:0]  pc,
    input   [11:0]  csr_read_addr,
    input   [11:0]  csr_write_addr,
    input   [31:0]  csr_write_data,
    output  [31:0]  csr_read_data
);
    reg [31:0] mstatus, mepc, mtvec, mcause;
    
    assign csr_read_data = (csr_read_addr == 12'h300) ? mstatus :
                           (csr_read_addr == 12'h341) ? mepc :
                           (csr_read_addr == 12'h305) ? mtvec :
                           (csr_read_addr == 12'h342) ? mcause : 0;
    
    always @(negedge clk or posedge rst) begin
        if (rst == 1) begin
            mstatus <= 0;
            mepc <= 0;
            mtvec <= 0;
            mcause <= 0;
        end
        else if (trap != 0) begin
            if (trap == 2'b01) begin
                mepc <= pc;
                mcause <= 11;
            end
            else if (trap == 2'b10) begin
                mepc <= pc;
                mcause <= 2;
            end
        end
        else if (we == 1) begin
            if (csr_write_addr == 12'h300) mstatus <= csr_write_data;
            else if (csr_write_addr == 12'h341) mepc <= csr_write_data;
            else if (csr_write_addr == 12'h305) mtvec <= csr_write_data;
            else if (csr_write_addr == 12'h342) mcause <= csr_write_data;
        end
    end
endmodule
```

### 控制模块与数据通路扩充
我的设计是将 CSR 和 GPR 同样放在 ID 阶段进行读取，同样在 WB 阶段再进行写回。

```verilog
CSRs csrs (
    .clk(clk),
    .rst(rst),
    .we(MEM_WB_csr_write),
    .trap(trap),
    .pc(IF_ID_pc),
    .csr_read_addr(csr_read_addr),
    .csr_write_addr(MEM_WB_csr_write_addr),
    .csr_write_data(MEM_WB_csr_write_data),
    .csr_read_data(csr_read_data)
);
```

具体的 CSR 读取地址由控制模块来进行处理，多将 inst[31:20] 部分传入控制模块，如果是 CSR 指令则保留原样，如果是 ecall、非法指令则还要强制读取 mtvec 值，如果是 mret 指令还要读取 mepc 值。然后读出来的值传入 PC 的选择器，这几种情况直接选择 csr 读取的值作为 pc。另外根据我的设计，这些涉及到跳转的指令都需要强制 stall 一个周期，可以和原来的 jump 信号一起处理。

```verilog
module Control (
    ...
    input       [11:0]  csr,
    output reg  [1:0]   pc_src,     // 00 pc+4 01 JALR 10 JAL 11 csr
    ...
    output reg  [2:0]   mem_to_reg, // 00 写回数据来自 ALU 01 来自立即数 10 来自 pc+4 11 来自 data memory 100 来自 csr
    ...
    output reg  [1:0]   trap,       // 00 no trap, 01 ecall, 10 unimp, 11 mret(标识跳转)
    output reg  [11:0]  csr_read_addr,
    output reg  [11:0]  csr_write_addr,
    output reg          csr_write
);
    `include "AluOp.vh"
    always @(*) begin
    ...
    case (op_code)
        ...
        7'b1110011: begin   // system
            case (funct3)
                3'b000: begin
                    case (csr)
                        12'b000000000000: begin // ecall
                            trap = 2'b01;   csr_read_addr = 12'h305;
                            pc_src = 2'b11;
                        end
                        12'b001100000010: begin // mret
                            trap = 2'b11;
                            csr_read_addr = 12'h341;  pc_src = 2'b11;
                        end
                        default: begin
                            trap = 2'b10;   csr_read_addr = 12'h305;
                            pc_src = 2'b11;
                        end
                    endcase
                end
                3'b001: begin // csrrw
                    if (csr != 12'h300 && csr != 12'h341 && csr != 12'h305 && csr != 12'h342) begin
                        trap = 2'b10;   csr_read_addr = 12'h305;
                        pc_src = 2'b11;
                    end else begin
                        csr_write = 1;  csr_read_addr = csr;
                        csr_write_addr = csr; csr_write_src = 0;
                        reg_write = 1;  mem_to_reg = 3'b100;
                    end
                end
                3'b010: begin // csrrs
                    if (csr != 12'h300 && csr != 12'h341 && csr != 12'h305 && csr != 12'h342) begin
                        trap = 2'b10;   csr_read_addr = 12'h305;
                        pc_src = 2'b11;
                    end else begin
                        csr_write = 0;  csr_read_addr = csr; // csrr
                        alu_op = OR;    alu_src_b = 2'b01;
                        reg_write = 1;  mem_to_reg = 3'b100;
                    end
                end
                default: begin
                    trap = 2'b10;   csr_read_addr = 12'h305;
                    pc_src = 2'b11;
                end
            endcase
        end
        default: begin
            trap = 2'b10;   csr_read_addr = 12'h305;
            pc_src = 2'b11;
        end
    endcase
    end
```

对于 CSR 和 GPR 的写回。GPR 只需要扩充一下 mem_to_reg，加一个从 csr_read_data 的来源即可。而 CSR 考虑到数据冒险，这里直接使用 EX 阶段已经 forwarding 处理后的 alu_data1 来向后传递作为 csr_write_data（正常来讲这里要通过 ALU 运算的，但是目前还没有处理）。

```verilog
always @(posedge clk or posedge rst) begin
    ...
    EX_MEM_csr_write_data <= alu_data1
    ...
end

...

Mux8x32 mux8x32 (
    .I0(MEM_WB_alu_result),
    .I1(MEM_WB_imm),
    .I2(MEM_WB_pc + 4),
    .I3(MEM_WB_data_in),
    .I4(MEM_WB_csr_read_data),
    .I5(0),
    .I6(0),
    .I7(0),
    .s(MEM_WB_mem_to_reg),
    .o(write_data)
);
```

同时还要考虑几个新增的数据冒险，首先是设置 mepc 后下一条指令 mret，由于 mret 的 csr 读出值最后要传入 PC 选择器作为 pc，所以可以在中间插入一个针对这个的 forwarding 单元，探测一下上一条指令是否写入了 mepc，这里直接选择出正确的 mepc 值作为输出，然后传给 PC 选择器。MretForwarding 单元：

```verilog
module MretForwarding (
    input           ID_EX_csr_write,
    input   [11:0]  ID_EX_csr_write_addr,
    input   [31:0]  EX_MEM_alu_result,
    input   [31:0]  csr_read_data,
    input   [1:0]   trap, // 00 no trap, 01 ecall, 10 unimp
    output  [31:0]  csr_ret_pc
);
    reg     [31:0]  _csr_ret_pc;
    assign csr_ret_pc = _csr_ret_pc;
    always @(*) begin
        if (trap == 2'b11) begin
            if (ID_EX_csr_write == 1 && ID_EX_csr_write_addr == 12'h341) begin
                _csr_ret_pc <= EX_MEM_alu_result;
            end
            else begin
                _csr_ret_pc <= csr_read_data;
            end
        end else begin
            _csr_ret_pc <= csr_read_data;
        end
    end
endmodule
```

数据通路中的连接：

```verilog
MuxPC mux_pc (
    .I0(jump ? pc : pc + 4),
    .I1(jalr_addr),
    .I2(jal_addr),
    .I3(csr_ret_pc),
    .s(pc_src),
    .branch(branch),
    .b_type(b_type),
    .alu_res(reg1 ^ reg2),
    .o(pc_next)
);

MretForwarding mretforwarding (
    .ID_EX_csr_write(ID_EX_csr_write),
    .ID_EX_csr_write_addr(ID_EX_csr_write_addr),
    .EX_MEM_alu_result(EX_MEM_alu_result),
    .csr_read_data(csr_read_data),
    .trap(trap),
    .csr_ret_pc(csr_ret_pc)
);
```

另外一个需要考虑的是 csrr 指令后对其写入的 gpr 进行修改，由于目前的设计我并没有将 csr 指令经过 ALU 单元，所以其 ALU 结果是未知的，而这里显然回出现数据冒险，处理单元会读取这一阶段的 ALU 输出值进行前递，导致下一个语句的结果不正确。

这里的一个曲线救国的方法是，在 forwarding 单元中，如果当前指令的 b 操作数是立即数，则不会进行任何前递，所以可以在此时判断，将立即数替换为 csr 的读出值，这样再配合控制模块的信号，则可以正常通过一次 ALU 运算，得到用于前递的结果（但目前这个结果会被舍弃，有时间可以直接用这个完整实现所有 csr 指令）：
```verilog
wire    [31:0]  alu_b_imm;
assign alu_b_imm = (ID_EX_mem_to_reg == 3'b100 ? ID_EX_csr_read_data : ID_EX_imm);

Mux8x32 mux_alu_b (
    ...
    .I3(alu_b_imm),
    ...
);
```

## 实验结果
### 仿真波形解析
这里只解析 advance 版本的波形，按顺序分成几个部分进行解析：
![](/assets/images/cs/system/cs2/lab7/wave1.png)
![](/assets/images/cs/system/cs2/lab7/wave2.png)
![](/assets/images/cs/system/cs2/lab7/wave3.png)
![](/assets/images/cs/system/cs2/lab7/wave4.png)

最终整体的波形：
![](/assets/images/cs/system/cs2/lab7/wave5.png)

可见后面 gp 在 0x101 和 0x102 之间反复变换。

### 上板验证
上板验证结果一致，且已经验收通过。