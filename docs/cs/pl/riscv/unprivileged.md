---
counter: True
comment: True
---

# RISC-V 非特权级 ISA

!!! abstract
    RISC-V 指令集的非特权级（用户级）部分。

    参考：

    - [The RISC-V Instruction Set Manual Volume I: Unprivileged ISA v.20191213](https://github.com/riscv/riscv-isa-manual/releases/download/Ratified-IMAFDQC/riscv-spec-20191213.pdf)
    - 浙江大学 “计算机系统 Ⅰ “（大一春夏）“计算机系统 Ⅱ “（大二秋冬）课程

## RV32I 基础
### 寄存器
- 一个 PC 寄存器（program counter）
- 32 个 32 位寄存器（x0~x31）
    - 其中 x0 永远是 0

寄存器的常用用途如下：

|寄存器|ABI 名称|用途描述|saver|
|:--:|:--:|:--|:--:|
|x0|zero|硬件 0||
|x1|ra|返回地址（return address）|caller|
|x2|sp|栈指针（stack pointer）|callee|
|x3|gp|全局指针（global pointer）||
|x4|tp|线程指针（thread pointer）||
|x5|t0|临时变量/备用链接寄存器（alternate link reg）|caller|
|x6-7|t1-2|临时变量|caller|
|x8|s0/fp|需要保存的寄存器/帧指针（frame pointer）|callee|
|x9|s1|需要保存的寄存器|callee|
|x10-11|a0-1|函数参数/返回值|caller|
|x12-17|a2-7|函数参数|caller|
|x18-27|s2-11|需要保存的寄存器|callee|
|x28-31|t3-6|临时变量|caller|

其中 sp s0-11 需要在函数调用前后保证一致，其它不用保证

### 指令格式
RV32I 有 4 种基础的指令格式（R/I/S/U），再根据立即数解码的不同又分出两种（B/J），总共六种指令格式

#### R 型指令

<table class="riscv-table">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node">funct7</td>
    <td colspan="5" class="riscv-table-node">rs2</td>
    <td colspan="5" class="riscv-table-node">rs1</td>
    <td colspan="3" class="riscv-table-node">funct3</td>
    <td colspan="5" class="riscv-table-node">rd</td>
    <td colspan="7" class="riscv-table-node">opcode</td>
</tr>
</table>

使用寄存器进行数字逻辑运算的指令格式，运算由 opcode funct3 funct7 决定，rd = rs1 op rs2（shift 类例外，它们用 rs2 位置表示移位数的立即数）

#### I 型指令

<table class="riscv-table">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node">rs1</td>
    <td colspan="3" class="riscv-table-node">funct3</td>
    <td colspan="5" class="riscv-table-node">rd</td>
    <td colspan="7" class="riscv-table-node">opcode</td>
</tr>
</table>

使用寄存器和立即数进行数字逻辑运算，以及 load 类指令等的指令格式，运算类型等由 opcode funct3 决定，如果是 ALU 运算，则 rd = rs1 op imm

立即数是 {{20{inst[31]}}, inst[31:20]}，也就是对 imm[11:0] 进行符号位扩展到 32 位

#### S 型指令

<table class="riscv-table">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node">imm[11:5]</td>
    <td colspan="5" class="riscv-table-node">rs2</td>
    <td colspan="5" class="riscv-table-node">rs1</td>
    <td colspan="3" class="riscv-table-node">funct3</td>
    <td colspan="5" class="riscv-table-node">imm[4:0]</td>
    <td colspan="7" class="riscv-table-node">opcode</td>
</tr>
</table>

store 类指令，store 的大小由 funct3 决定，以变址模式进行寻址，即 rs1 = [rs2+imm]

立即数是 {{20{inst[31]}}, inst[31:25], inst[11:7]}

#### B 型指令

<table class="riscv-table">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node">rs2</td>
    <td colspan="5" class="riscv-table-node">rs1</td>
    <td colspan="3" class="riscv-table-node">funct3</td>
    <td colspan="5" class="riscv-table-node">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node">opcode</td>
</tr>
</table>

由 S 型指令分来，与之区别是立即数读取顺序不同，是所有分支类指令。是否分支由 funct3 rs1 rs2 决定

立即数是 {{19{inst[31]}}, inst[31], inst[7], inst[30:25], inst[11:8], 1'b0}

#### U 型指令

<table class="riscv-table">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="18"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="20" class="riscv-table-node">imm[31:12]</td>
    <td colspan="5" class="riscv-table-node">rd</td>
    <td colspan="7" class="riscv-table-node">opcode</td>
</tr>
</table>

LUI 和 AUIPC，立即数都是在高 20 位，而且没有源操作数

立即数是 {inst[31:12], 12'b0}

#### J 型指令

<table class="riscv-table">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="18"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="20" class="riscv-table-node">imm[20,10:1,11,19:12]</td>
    <td colspan="5" class="riscv-table-node">rd</td>
    <td colspan="7" class="riscv-table-node">opcode</td>
</tr>
</table>

由 U 型指令分来，区别也是立即数读取不同，仅有 JAL 一个指令

立即数是 {{11{inst[31]}}, inst[31], inst[19:12], inst[20], inst[30:21], 1'b0}

## RV32I 指令
### 整型计算指令
#### 加减法指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>add</span>
    <span>R 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：add rd, rs1, rs2
- **指令作用**：rd = rs1 + rs2
- **注意**：溢出会被忽略

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sub</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0100000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：sub rd, rs1, rs2
- **指令作用**：rd = rs1 - rs2
- **注意**：溢出会被忽略

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>addi</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：addi rd, rs1, imm
- **指令作用**：rd = rs1 + imm
- **注意**：溢出会被忽略，imm 在 [-2048, 2047] 范围内

</div>
</div>

#### 比较运算指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>slt</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">010</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：slt rd, rs1, rs2
- **指令作用**：（set less than）如果 rs1 < rs2 则 rd = 1，否则 rd = 0
- **注意**：rs1 rs2 会被视为有符号数进行比较

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sltu</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">011</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：sltu rd, rs1, rs2
- **指令作用**：（set less than unsigned）如果 rs1 < rs2 则 rd = 1，否则 rd = 0
- **注意**：rs1 rs2 会被视为无符号数进行比较

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>slti</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">010</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：slti rd, rs1, imm
- **指令作用**：（set less than immediate）如果 rs1 < imm 则 rd = 1，否则 rd = 0
- **注意**：imm 在 [-2048, 2047] 范围内，被视为有符号数进行比较

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sltiu</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">011</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：sltiu rd, rs1, imm
- **指令作用**：（set less than immediate unsigned）如果 rs1 < imm 则 rd = 1，否则 rd = 0
- **注意**：imm 在 [-2048, 2047] 范围内，rs1 imm 被视为无符号数进行比较

</div>
</div>

#### 二进制位运算指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>and</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">111</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：and rd, rs1, rs2
- **指令作用**：rd = rs1 & rs2 按位与

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>or</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">110</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：or rd, rs1, rs2
- **指令作用**：rd = rs1 | rs2 按位或

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>xor</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">100</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：xor rd, rs1, rs2
- **指令作用**：rd = rs1 ^ rs2 按位异或

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>andi</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">111</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：andi rd, rs1, imm
- **指令作用**：rd = rs1 & imm 按位与
- **注意**：imm 在 [-2048, 2047] 范围内，会扩展符号位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>ori</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">110</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：ori rd, rs1, imm
- **指令作用**：rd = rs1 | imm 按位或
- **注意**：imm 在 [-2048, 2047] 范围内，会扩展符号位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>xori</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">100</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：xori rd, rs1, imm
- **指令作用**：rd = rs1 ^ imm 按位异或
- **注意**：imm 在 [-2048, 2047] 范围内，会扩展符号位（xori rd, rs1, -1 相当于 rd = ~rs1）

</div>
</div>

#### 移位运算指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sll</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">001</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：sll rd, rs1, rs2
- **指令作用**：rd = rs1 << rs2[4:0] 左移（左侧丢掉，右侧补 0）
- **注意**：会取 rs2 内数值的低 5 位进行运算

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>srl</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：srl rd, rs1, rs2
- **指令作用**：rd = rs1 >> rs2[4:0] 逻辑右移（左侧补 0，右侧丢掉）
- **注意**：会取 rs2 内容的低 5 位 

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sra</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0100000</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110011</td>
</tr>
</table>

- **指令格式**：sra rd, rs1, rs2
- **指令作用**：rd = rs1 >>> rs2[4:0] 算数右移（左侧补符号位，右侧丢掉）
- **注意**：会取 rs2 内容的低 5 位进行运算

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>slli</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">shamt</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">001</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：slli rd, rs1, shamt
- **指令作用**：rd = rs1 << shamt 左移（左侧丢掉，右侧补 0）
- **注意**：shamt（shift amount）会编码到原来 rs2 的位置，它是一个立即数，正好有 5 位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>srli</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0000000</td>
    <td colspan="5" class="riscv-table-node-little">shamt</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：srli rd, rs1, shamt
- **指令作用**：rd = rs1 >> shamt 逻辑右移（左侧补 0，右侧丢掉）
- **注意**：shamt（shift amount）会编码到原来 rs2 的位置，它是一个立即数，正好有 5 位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>srai</span>
    <span>r 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0100000</td>
    <td colspan="5" class="riscv-table-node-little">shamt</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010011</td>
</tr>
</table>

- **指令格式**：srai rd, rs1, shamt
- **指令作用**：rd = rs1 >>> shamt 算数右移（左侧补符号位，右侧丢掉）
- **注意**：shamt（shift amount）会编码到原来 rs2 的位置，它是一个立即数，正好有 5 位

</div>
</div>

#### 数据加载指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lui</span>
    <span>U 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="18"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="20" class="riscv-table-node-little">imm[31:12]</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0110111</td>
</tr>
</table>

- **指令格式**：lui imm
- **指令作用**：（load upper immediate）rd = imm << 12 将 imm 加载到 rd 的高 20 位
- **注意**：imm 不能超过 20 位，rd 以十六进制表示就是 imm 后接三个 0

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>auipc</span>
    <span>U 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="18"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="20" class="riscv-table-node-little">imm[31:12]</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0010111</td>
</tr>
</table>

- **指令格式**：auipc rd
- **指令作用**：（add upper immediate with pc）rd = pc + imm << 12 将 imm 加载到高 20 位，然后加上 pc 值
- **注意**：常用来构建 pc 相对寻址的地址，imm 不能超过 20 位

</div>
</div>

### 控制流变化指令
#### jump 类无条件跳转指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>jal</span>
    <span>J 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="18"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="20" class="riscv-table-node-little">imm[20,10:1,11,19:12]</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1101111</td>
</tr>
</table>

- **指令格式**：jal rd, imm
- **指令作用**：（jump and link）rd = pc+4, pc = pc+imm 即将当前指令下一条指令的地址存入 rd，然后相对跳转到 imm 处
- **注意**：imm 在汇编程序中一般用标号来指定，jal 可以跳到 ±1MiB 范围内的代码

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>jalr</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1100111</td>
</tr>
</table>

- **指令格式**：jalr rd, imm(rs1)
- **指令作用**：rd = pc+4, pc = (imm+rs1) & 0xFFFFFFFE 即最低位会被设为 0
- **注意**：可以实现任意位置跳转

</div>
</div>

#### branch 类条件跳转指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>beq</span>
    <span>B 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node-little">1100011</td>
</tr>
</table>

- **指令格式**：beq rs1, rs2, imm
- **指令作用**：（branch if equal）如果 rs1 == rs2，则 pc = pc+imm
- **注意**：可以跳转到 ±4KiB 范围内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bne</span>
    <span>B 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">001</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node-little">1100011</td>
</tr>
</table>

- **指令格式**：bne rs1, rs2, imm
- **指令作用**：（branch if not equal）如果 rs1 != rs2，则 pc = pc+imm
- **注意**：可以跳转到 ±4KiB 范围内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>blt</span>
    <span>B 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">100</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node-little">1100011</td>
</tr>
</table>

- **指令格式**：blt rs1, rs2, imm
- **指令作用**：（branch if less than）如果 rs1 < rs2 则 pc = pc+imm
- **注意**：rs1 rs2 视为有符号数进行比较，可以跳转到 ±4KiB 范围内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bge</span>
    <span>B 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node-little">1100011</td>
</tr>
</table>

- **指令格式**：bge rs1, rs2, imm
- **指令作用**：（branch if greater than or equal）如果 rs1 >= rs2 则 pc = pc+imm
- **注意**：rs1 rs2 视为有符号数进行比较，可以跳转到 ±4KiB 范围内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bltu</span>
    <span>B 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">110</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node-little">1100011</td>
</tr>
</table>

- **指令格式**：bltu rs1, rs2, imm
- **指令作用**：（blt unsigned）如果 rs1 < rs2 则 pc = pc+imm
- **注意**：rs1 rs2 视为无符号数进行比较，可以跳转到 ±4KiB 范围内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bgeu</span>
    <span>B 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[12,10:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">111</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:1,11]</td>
    <td colspan="7" class="riscv-table-node-little">1100011</td>
</tr>
</table>

- **指令格式**：bgeu rs1, rs2, imm
- **指令作用**：（bge unsigned）如果 rs1 >= rs2 则 pc = pc+imm
- **注意**：rs1 rs2 视为无符号数进行比较，可以跳转到 ±4KiB 范围内

</div>
</div>

### 装载存储指令
#### load 类装载指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lb</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0000011</td>
</tr>
</table>

- **指令格式**：lb rd, imm(rs1)
- **指令作用**：从 rs1 + imm 处内存读取一个字节到 rd 低八位，再进行符号扩展

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lh</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">001</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0000011</td>
</tr>
</table>

- **指令格式**：lh rd, imm(rs1)
- **指令作用**：从 rs1+imm 处内存读取一个 16 位数到 rd 低 16 位，然后进行符号扩展

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lw</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">010</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0000011</td>
</tr>
</table>

- **指令格式**：lw rd, imm(rs1)
- **指令作用**：从 rs1 + imm 处内存读取一个 32 位数到 rd 中

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lbu</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">100</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0000011</td>
</tr>
</table>

- **指令格式**：lbu rd, imm(rs1)
- **指令作用**：从 rs1 + imm 处内存读取一个字节放到 rd 低 8 位，然后进行零扩展（高位全补 0）

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lhu</span>
    <span>I 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">imm[11:0]</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">0000011</td>
</tr>
</table>

- **指令格式**：lhu rd, imm(rs1)
- **指令作用**：从 rs1 + imm 处内存读取 16 位数存入 rd，并进行零扩展（高 16 位全为 0）

</div>
</div>

#### store 类存储指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sb</span>
    <span>S 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[11:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:0]</td>
    <td colspan="7" class="riscv-table-node-little">0100011</td>
</tr>
</table>

- **指令格式**：sb rs2, imm(rs1)
- **指令作用**：将 rs2 的低 8 位拷贝到 rs1 + imm 处内存中

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sh</span>
    <span>S 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[11:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">001</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:0]</td>
    <td colspan="7" class="riscv-table-node-little">0100011</td>
</tr>
</table>

- **指令格式**：sh rs2, imm(rs1)
- **指令作用**：将 rs2 的低 16 位拷贝到 rs1 + imm 处内存中

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sw</span>
    <span>S 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">imm[11:5]</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">010</td>
    <td colspan="5" class="riscv-table-node-little">imm[4:0]</td>
    <td colspan="7" class="riscv-table-node-little">0100011</td>
</tr>
</table>

- **指令格式**：sw rs2, imm(rs1)
- **指令作用**：将 rs2（32 位）拷贝到 rs1 + imm 处内存中

</div>
</div>

### 汇编伪指令
前面的是 RV32I 的所有被编码的指令，下面是可以在 RV32I 汇编程序中写的伪指令，它们将被编译器编译为第二列中的实际指令

<style>
    .small-table table {
        font-size: 0.55rem !important;
    }
</style>

<div class="small-table" markdown="1">

|伪指令|实际指令|意义|
|:--|:--|:--|
|la/lla rd, symbol|auipc rd, delta[31 : 12] + delta[11]<br/>addi rd, rd, delta[11:0]|加载绝对地址<br/>delta = symbol - pc|
|l\{b\|h\|w\} rd, symbol|auipc rd, delta[31 : 12] + delta[11]<br/>l\{b\|h\|w\} rd, delta\[11:0](rd)|加载全局变量|
|s\{b\|h\|w\} rd, symbol, rt|auipc rt, delta[31 : 12] + delta[11]<br/>s\{b\|h\|w\} rd, delta\[11:0](rt)|保存全局变量|
|nop|addi x0, x0, 0||
|li rd, imm|...|将立即数加载到 rd 中|
|mov rd, rs|addi rd, rs, 0|从 rs 拷贝到 rd|
|not rd, rs|xori rd, rs, -1|rd = ~rs 按位取反|
|neg rd, rs|sub rd, x0, rs|rd = -rs|
|seqz rd, rs|sltiu rd, rs, 1|set rd if rs == 0|
|snez rd, rs|sltu rd, x0, rs|set rd if rs != 0|
|sltz rd, rs|slt rd, rs, x0|set rd if rs < 0|
|sgtz rd, rs|slt rd, x0, rs|set rd if rs > 0|
|beqz rs, offset|beq rs, x0, offset|branch if rs == 0|
|bnez rs, offset|bne rs, x0, offset|branch if rs != 0|
|blez rs, offset|bge x0, rs, offset|branch if rs <= 0|
|bgez rs, offset|bge rs, x0, offset|branch if rs >= 0|
|bltz rs, offset|blt rs, x0, offset|branch if rs < 0|
|bgtz rs, offset|blt x0, rs, offset|branch if rs > 0|
|bgt rs, rt, offset|blt rt, rs, offset|branch if rs > rt|
|ble rs, rt, offset|bge rt, rs, offset|branch if rs <= rt|
|bgtu rs, rt, offset|bltu rt, rs, offset|branch if > unsigned|
|bleu rs, rt, offset|bgeu rt, rs, offset|branch if <= unsigned|
|j offset|jal x0, offset|无条件跳转，不存返回地址|
|jal offset|jal x1, offset|无条件跳转，返回地址存到 x1|
|jr rs|jalr x0, 0(rs)|无条件跳转到 rs 位置，忽略返回地址|
|jalr rs|jalr x1, 0(rs)|无条件跳转到 rs 位置，存返回地址|
|ret|jalr x0, 0(x1)|通过返回地址 x1 返回|
|call offset|auipc x1, offset[31 : 12] + offset[11]<br/>jalr x1, offset\[11:0](x1)|远调用|
|tail offset|auipc x6, offset[31 : 12] + offset[11]<br/>jalr x0, offset\[11:0](x6)|忽略返回地址远调用|

</div>

## 汇编代码
```asm
    .text
    .align 2
    .globl main
main:
    addi sp, sp, -16
    sw ra, 12(sp)
    lui a0, %hi(string1)
    addi a0, a0, %lo(string1)
    lui a1, %hi(string2)
    addi a1, a1, %lo(string2)
    call printf
    lw ra, 12(sp)
    addi sp, sp, 16
    li a0, 0
    ret

    .section .rodata
    .balign 4
string1:
    .string "Hello, %s!\n"
string2:
    .string "world"
```

- .text：进入代码段
- .align 2：代码段对齐到 2^2 字节
- .globl main：声明全局标号 main
- .section .rodata：进入 rodata 段
- .balign 4：对齐数据段到 4 字节
- .string ... 定义字符串

其它指令：

- .data：进入数据段
- .bss：进入 bss 段
- .byte b1, b2, ..., bn：存放一些字节
- .half w1, w2, ..., wn：存放一些半字（16 位）
- .word w1, w2, ..., wn：存放一些字（32 位）
