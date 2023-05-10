---
counter: True
comment: True
---

# RISC-V 特权级 ISA（基础&中断）

!!! abstract
    RISC-V 指令集的特权级部分。这里只包含部分特权级的基础介绍，以及中断相关的理解。

    特权级还有一部分比较重要的页表相关的内容，就不继续插到这页里面了，单独放在了 [RISC-V 特权级 ISA（页表相关）](paging/)一页。

    参考：

    - [The RISC-V Instruction Set Manual Volume II: Privileged Architecture v.20211203](https://github.com/riscv/riscv-isa-manual/releases/download/Priv-v1.12/riscv-privileged-20211203.pdf)
    - 浙江大学 “计算机系统 Ⅱ “（大二秋冬）课程

## 特权模式
RISC-V 指令集有三种特权模式，分别是 Machine（M）、Supervisor（S）和 User（U），除此之外还有 Hypervisor（H）模式，不过貌似不常用。

| 等级 | 编码 | 名称 | 缩写 |
|:--:|:-:|:-:|:-:|
| 0 | 00 | User/Application | U |
| 1 | 01 | Supervisor | S |
| 2 | 10 | Hypervisor | H |
| 3 | 11 | Machine | M |

- M 模式是对硬件操作的抽象，有最高级别的权限。
- S 模式介于M模式和U模式之间，在操作系统中对应于内核态（Kernel）。当用户需要内核资源时，向内核申请，并切换到内核态进行处理。
- U 模式用于执行用户程序，在操作系统中对应于用户态，有最低级别的权限。

简单嵌入式系统应该至少有 M 模式，安全的嵌入式系统至少要有 M、U 两个模式，Unix-like 操作系统至少要有 M、S、U 三个模式。

特权模式用来分离、保护不同的运行环境。试图在低特权模式下执行高特权模式的指令会导致异常。

一个 hart（RISC-V hardware thread，指 RISC-V 处理器的一个执行单元）一般在 U 模式下运行应用程序，直到遇到 trap（比如系统调用、时间中断等），这时 hart 会切换到更高特权级的 trap handler，执行完后再切换回低权限模式继续执行。

除此之外，RISC-V 还规定了 Debug mode（D-mode），用于调试，它比 M 模式有更高的权限，有一些只有 D 模式才可以访问的 CSR 寄存器，也会保留一些物理地址空间。

## 控制和状态寄存器（CSRs）
CSR 是 RISC-V CPU 中的一系列特殊寄存器，能够反映和控制 CPU 当前的状态和执行机制。

RISC-V 给 CSR 分配了 12 位的地址空间（csr[11:0])，可以容纳最多 4096 个 CSR，其中 csr[11:10] 表示寄存器的读写权限（00/01/10 均表示可读可写，11 表示只读），csr[9:8] 表示可以访问该寄存器的最低特权级。相关权限一般表示为三位字母，第一个字母表示最低特权级，后两个字母表示读写权限（RW/RO）。

访问不存在的 CSR 会导致 illegal instruction exception，访问更高级的 CSR、或者写入只读 CSR 也会导致该异常。一个可读可写的寄存器也可能会有只读的位，但这时写入只读位会被忽略（而不会导致异常）。

CSR 还分有标准和非标准两类（Standard/Custom），其中 Custom CSR 在未来标准中也不会被占用。它们是：

- 0x800~0x8FF (1000 xxxx) URW、0xCC0~0xCFF (1100 11xx) URO
- 0x5C0~0x5FF (0101 11xx) SRW、0x9C0~0x9FF (1001 11xx) SRW、0xDC0~0xDFF (1101 11xx) SRO
- 0x6C0-0x6FF (0110 11xx) HRW、0xAC0-0xAFF (1010 11xx) HRW、0xEC0-0xEFF (1110 11xx) HRO
- 0x7C0-0x7FF (0111 11xx) MRW、0xBC0-0xBFF (1011 11xx) MRW、0xFC0-0xFFF (1111 11xx) MRO

针对 D 模式有一些保留的 CSR，0x7A0~0x7AF 是 M 模式可以访问的读写 CSR，0x7B0~0x7BF 是只有 D 模式可以访问的读写 CSR。

### CSR 指令（Zicsr 扩展）
Zicsr 扩展中规定了一系列关于访问 CSR 的指令，使用特权级的话一定要实现该扩展。

CSR 指令都使用 I 型指令，其中 12 位的立即数部分表示 CSR 的地址，funct3 低 2 位用来编码读/改/写（read-modify-write）操作、高 1 位表示是否来自立即数（如果来自立即数则 rs1 部分表示一个 5 位无符号立即数），opcode 都是 SYSTEM（1110011）。

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>csrrw</span>
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
    <td colspan="12" class="riscv-table-node-little">csr</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">001</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：csrrw rd, csr, rs1
- **指令作用**：将指定 csr 值存入 rd，将 rs1 值存入 csr
- **注意**：如果 rd 为 x0，则不会读取原 csr（也不会造成任何读的副作用）

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>csrrs</span>
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
    <td colspan="12" class="riscv-table-node-little">csr</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">010</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：csrrs rd, csr, rs1
- **指令作用**：读取 csr 原值到 rd，将 rs1 值与 csr 进行按位或运算后存入 csr
- **注意**：如果 rs1 为 x0，则不会写入 csr（但一定会读），如果某位不可写则忽略该位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>csrrc</span>
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
    <td colspan="12" class="riscv-table-node-little">csr</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">011</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：csrrc rd, csr, rs1
- **指令作用**：将 csr 原值存入 rd，将 rs1 中为 1 的位在 csr 中对应位置 0
- **注意**：如果 rs1 为 x0，则不会写入 csr（但一定会读），如果某位不可写则忽略该位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>csrrwi</span>
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
    <td colspan="12" class="riscv-table-node-little">csr</td>
    <td colspan="5" class="riscv-table-node-little">uimm</td>
    <td colspan="3" class="riscv-table-node-little">101</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：csrrwi rd, csr, uimm
- **指令作用**：将指定 csr 值存入 rd，将 uimm 的值零扩展到 32/64 位后存入 csr
- **注意**：如果 rd 为 x0，则不会读取原 csr

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>csrrsi</span>
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
    <td colspan="12" class="riscv-table-node-little">csr</td>
    <td colspan="5" class="riscv-table-node-little">uimm</td>
    <td colspan="3" class="riscv-table-node-little">110</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：csrrs rd, csr, uimm
- **指令作用**：读取 csr 原值到 rd，将 uimm 的值零扩展到 32/64 位后存入 csr
- **注意**：如果 uimm 为 0，则不会写入 csr（但一定会读），如果某位不可写则忽略该位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>csrrci</span>
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
    <td colspan="12" class="riscv-table-node-little">csr</td>
    <td colspan="5" class="riscv-table-node-little">uimm</td>
    <td colspan="3" class="riscv-table-node-little">111</td>
    <td colspan="5" class="riscv-table-node-little">rd</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：csrrc rd, csr, uimm
- **指令作用**：将 csr 原值存入 rd，将 uimm 的值零扩展到 32/64 位后为 1 的位在 csr 中对应位置 0
- **注意**：如果 uimm 为 0，则不会写入 csr（但一定会读），如果某位不可写则忽略该位

</div>
</div>

#### 汇编伪代码

一些只读/只写的汇编简化写法：

| 伪代码 | 原指令 |
| :--- | :--- |
| csrr rd, csr | csrrs rd, csr, x0 |
| csrw csr, rs1 | csrrw x0, csr, rs1 |
| csrwi csr, uimm | csrrwi x0, csr, uimm |
| csrs csr, rs1 | csrrs x0, csr, rs1 |
| csrsi csr, uimm | csrrsi x0, csr, uimm |
| csrc csr, rs1 | csrrc x0, csr, rs1 |
| csrci csr, uimm | csrrci x0, csr, uimm |

### 已分配的 CSR
Hypervisor/Debug 模式略过了。

#### 非特权级 / User 模式
|  编号  | 权限 | 名称 | 说明 |
| :---  | :--- | :--- | :--- |
| 0x001 | URW | fflags | 浮点异常标志 |
| 0x002 | URW | frm | 浮点舍入模式 |
| 0x003 | URW | fcsr | 浮点控制寄存器 |
| 0xC00 | URO | cycle | 时钟周期计数器（rdcycle 指令读取） |
| 0xC01 | URO | time | 计时器（rdtime 指令读取） |
| 0xC02 | URO | instret | 指令计数器（rdinstret 指令读取） |
| 0xC03-0xC1F | URO | hpmcounter3-31 | 性能计数器 |
| 0xC80 | URO | cycleh | 时钟周期计数器高 32 位（只有 RV32 有） |
| 0xC81 | URO | timeh | 计时器高 32 位（只有 RV32 有） |
| 0xC82 | URO | instreth | 指令计数器高 32 位（只有 RV32 有） |
| 0xC83-0xC9F | URO | hpmcounter3h-31h | 性能计数器高 32 位（只有 RV32 有） |

#### Supervisor 模式
|  编号  | 权限 | 名称 | 说明 |
| :---  | :--- | :--- | :--- |
| 0x100 | SRW | sstatus | Supervisor 状态寄存器 |
| 0x104 | SRW | sie | Supervisor 中断使能寄存器 |
| 0x105 | SRW | stvec | Supervisor 中断向量寄存器 |
| 0x106 | SRW | scounteren | Supervisor 性能计数器使能寄存器 |
| 0x10A | SRW | senvcfg | Supervisor 环境配置寄存器 |
| 0x140 | SRW | sscratch | Supervisor trap handler 临时寄存器 |
| 0x141 | SRW | sepc | Supervisor exception pc 寄存器 |
| 0x142 | SRW | scause | Supervisor trap 原因寄存器 |
| 0x143 | SRW | stval | Supervisor trap 值寄存器 |
| 0x144 | SRW | sip | Supervisor 中断挂起寄存器 |
| 0x180 | SRW | satp | Supervisor 地址翻译寄存器 |
| 0x5A8 | SRW | scontext | Supervisor 模式上下文寄存器 |

#### Machine 模式
??? note "Machine 信息寄存器"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0xF11 | MRO | mvendorid | Machine 厂商 ID |
    | 0xF12 | MRO | marchid | Machine 架构 ID |
    | 0xF13 | MRO | mimpid | Machine 实现 ID |
    | 0xF14 | MRO | mhartid | Machine hart ID |
    | 0xF15 | MRO | mconfigptr | Machine 配置数据结构体指针 |

??? note "Machine trap 设置相关"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0x300 | MRW | mstatus | Machine 状态寄存器 |
    | 0x301 | MRW | misa | Machine ISA 与扩展寄存器 |
    | 0x302 | MRW | medeleg | Machine 异常委托寄存器 |
    | 0x303 | MRW | mideleg | Machine 中断委托寄存器 |
    | 0x304 | MRW | mie | Machine 中断使能寄存器 |
    | 0x305 | MRW | mtvec | Machine 中断向量寄存器 |
    | 0x306 | MRW | mcounteren | Machine 性能计数器使能寄存器 |
    | 0x310 | MRW | mstatush | Machine 状态寄存器附加部分（只有 RV32 有） |

??? note "Machine trap 处理相关"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0x340 | MRW | mscratch | Machine trap handler 临时寄存器 |
    | 0x341 | MRW | mepc | Machine exception pc 寄存器 |
    | 0x342 | MRW | mcause | Machine trap 原因寄存器 |
    | 0x343 | MRW | mtval | Machine trap 值寄存器 |
    | 0x344 | MRW | mip | Machine 中断挂起寄存器 |
    | 0x34A | MRW | mtinst | Machine trap 指令寄存器 |
    | 0x34B | MRW | mtval2 | Machine trap 值寄存器 |

??? note "Machine 配置相关"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0x30A | MRW | menvcfg | Machine 环境配置寄存器 |
    | 0x31A | MRW | menvcfgh | Machine 环境配置寄存器高 32 位（只有 RV32 有） |
    | 0x747 | MRW | mseccfg | Machine 安全配置寄存器 |
    | 0x757 | MRW | mseccfgh | Machine 安全配置寄存器高 32 位（只有 RV32 有） |

??? note "Machine 内存保护相关"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0x3A0-0x3AF | MRW | pmpcfg0-15 | Machine 物理内存保护配置寄存器（奇数只有 RV32 有） |
    | 0x3B0-0x3BF | MRW | pmpaddr0-15 | Machine 物理内存保护地址寄存器 |

??? note "Machine 计数/计时器"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0xB00 | MRW | mcycle | Machine 时钟周期计数器 |
    | 0xB02 | MRW | minstret | Machine 指令计数器 |
    | 0xB03-0xB1F | MRW | mhpmcounter3-31 | Machine 性能计数器 |
    | 0xB80 | MRW | mcycleh | Machine 时钟周期计数器高 32 位（只有 RV32 有） |
    | 0xB82 | MRW | minstreth | Machine 指令计数器高 32 位（只有 RV32 有） |
    | 0xB83-0xB9F | MRW | mhpmcounter3h-31h | Machine 性能计数器高 32 位（只有 RV32 有） |

??? note "Machine 计数器设置"

    |  编号  | 权限 | 名称 | 说明 |
    | :---  | :--- | :--- | :--- |
    | 0x320 | MRW | mcounterinhibit | Machine 性能计数器禁止寄存器 |
    | 0x323-0x33F | MRW | mhpmevent3-31 | Machine 性能计数器事件选择寄存器 |

### CSR 字段缩写规范

后面在定义各个 CSR 字段的时候会出现一些缩写：

- **WPRI**（reserved Writes Preserve values, Reads Ignore values）：写保留，读忽略
- **WLRL**（Write/Read Only Legal values）：只能写/读合法值（不合法的时候推荐但不必须抛出异常）
- **WARL**（Write Any values, Read Legal values）：写任意值，读合法值

## Machine 模式
### M 模式 CSRs
只写一些重要、有用的。

<style>
.csr-bit {
    background-color: #3f6ec6b0;
    border-radius: 3px;
    font-size: .4rem;
    padding: 4px;
}
.csr-behav {
    background-color: #e6695bb0;
    border-radius: 3px;
    font-size: .4rem;
    padding: 4px;
}
</style>

#### misa
- <span class="csr-bit">[31:30] / [63:62]</span> <span class="csr-behav">WARL</span> MXL：编码 XLEN，1 表示 RV32，2 表示 RV64，3 表示 RV128
- <span class="csr-bit">[25:0]</span> <span class="csr-behav">WARL</span> Extensions：扩展，从 0 位到 25 位依次表示 A-Z 扩展，0 表示不存在，1 表示存在


#### mstatus

仅仅是一部分中断处理时会用到的字段：

- <span class="csr-bit">1</span> SIE：S 模式全局中断使能
- <span class="csr-bit">3</span> MIE：M 模式全局中断使能
- <span class="csr-bit">5</span> SPIE：保存的前一个 S 模式全局中断使能
- <span class="csr-bit">7</span> MPIE：保存的前一个 M 模式全局中断使能
- <span class="csr-bit">8</span> <span class="csr-behav">WARL</span> SPP：S 模式中断处理前的特权级别
- <span class="csr-bit">[12:11]</span> <span class="csr-behav">WARL</span> MPP：M 模式中断处理前的特权级别
- <span class="csr-bit">22</span> <span class="csr-behav">WARL</span> TSR：为 1 时禁止 S 模式下执行 sret，为 0 时允许，没有 S 模式时为只读 0

#### mtvec
用于保存 Machine 模式中断处理程序入口地址

- <span class="csr-bit">[31:2] / [63:2]</span> <span class="csr-behav">WARL</span> Base：中断处理程序入口地址（4 字节对齐）
- <span class="csr-bit">[1:0]</span> <span class="csr-behav">WARL</span> Mode：模式，分为以下两种：
    - 0 - Direct：直接模式，中断处理程序入口地址为 Base
    - 1 - Vectored：向量模式，中断处理程序入口地址为 Base + 4 * cause（cause 在下面有定义）

#### medeleg & mideleg
统称 machine trap delegation registers，mideleg（machind interrupt delegation register）用于保存哪些中断要委托给 S 模式进行处理。medeleg（machine exception delegation register）用于保存哪些异常要委托给 S 模式进行处理。

中断码：

- 1: Supervisor Software Interrupt
- 3: Machine Software Interrupt
- 5: Supervisor Timer Interrupt
- 7: Machine Timer Interrupt
- 9: Supervisor External Interrupt
- 11: Machine External Interrupt

异常码：

- 0: Instruction Address Misaligned
- 1: Instruction Access Fault
- 2: Illegal Instruction
- 3: Breakpoint
- 4: Load Address Misaligned
- 5: Load Access Fault
- 6: Store/AMO Address Misaligned
- 7: Store/AMO Access Fault
- 8: Environment Call from U-mode
- 9: Environment Call from S-mode
- 11: Environment Call from M-mode
- 12: Instruction Page Fault
- 13: Load Page Fault
- 15: Store/AMO Page Fault

需要委托哪些中断/异常，就将对应寄存器的对应位设置为 1，不需要委托就设置为 0。

#### mip & mie
分别是 machine interrupt pending 和 machine interrupt enable，用于保存中断是否发生以及是否允许中断。

中断 i（上面定义的中断码）陷入 M 模式当以下条件同时满足时：

- 当前特权模式为 M 模式，且 mstatus[MIE] 为 1，或当前特权模式低于 M
- mip[i] 为 1，且 mie[i] 为 1
- 如果存在 mideleg 寄存器，则需要 mideleg[i] 为 0（不委托）

#### mepc & mcause
mepc 用于保存 trap 发生时的指令地址。

mcause 用于保存 trap 发生的原因（上面规定）：

- <span class="csr-bit">31 / 63</span> Interrupt：为 1 时表示是中断，为 0 时表示是异常
- <span class="csr-bit">[30:0] / [62:0]</span> <span class="csr-behav">WLRL</span> Code：中断/异常码（以值的方式存储，而不是对应位）

#### mtval
用于保存 trap 发生时的附加信息：

- 如果是由存储器访问引起的异常，则 mtval 保存的是要访问的地址
- 如果是非法指令造成的异常，则将该指令的编码保存在 mtval 中

### M 模式内存映射寄存器
RISC-V 特权级规范规定了两个 M 模式内存映射寄存器，分别是 mtime 和 mtimecmp。

mtime 和 mtimecmp 在 RV32 和 RV64 中都是 64 位的。mtime 应该由机器实现，以固定频率递增。当 mtime 的值大于等于 mtimecmp 时，要触发 machine timer interrupt（当 mie 寄存器中的 MTIE 位为 1 时）。

!!! note 
    在 qemu 的默认设置中，mtime 的地址位于 0x200bff8，mtimecmp 的地址位于 0x2004000。

### M 模式特权指令
<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>ecall</span>
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
    <td colspan="12" class="riscv-table-node-little">000000000000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：ecall
- **指令作用**：M 模式调用 ecall 会产生 environment-call-from-M-mode 异常
- **注意**：接收特权级的 epc 寄存器要设置为 ecall 指令的地址，而不是 ecall 指令的下一条指令的地址，且 ecall 指令不会增加 minstret 寄存器的值

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>ebreak</span>
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
    <td colspan="12" class="riscv-table-node-little">000000000001</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：ebreak
- **指令作用**：任何模式调用 ebreak 都会产生 breakpoint 异常，将控制流交给调试器
- **注意**：接收特权级的 epc 寄存器要设置为 ebreak 指令的地址，而不是 ebreak 指令的下一条指令的地址，且 ebreak 指令不会增加 minstret 寄存器的值

</div>
</div>


<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>mret</span>
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
    <td colspan="12" class="riscv-table-node-little">001100000010</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：mret
- **指令作用**：在 M 模式处理 trap 之后返回前一特权模式，并将 pc 设置为 mepc 寄存器的值
    - 将当前特权模式设置为 mstatus[MPP]
    - 将 mstatus[MIE] 设置为 mstatus[MPIE]
    - 将 mstatus[MPIE] 设置为 1
    - 将 mstatus[MPP] 设置为 U
    - 将 pc 设置为 mepc 寄存器的值

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>wfi</span>
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
    <td colspan="12" class="riscv-table-node-little">000100000101</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：wfi
- **指令作用**：任何特权模式均可用，执行时当前 hart 会进入休眠，等待中断来唤醒，相当于 nop

</div>
</div>

## Supervisor 模式
### S 模式 CSRs
#### sstatus
sstatus 是 mstatus 的一个子集，用于保存 S 模式的状态，其部分中断相关的结构如下：

- <span class="csr-bit">1</span> SIE：S 模式全局中断使能
- <span class="csr-bit">5</span> SPIE：保存的前一个 S 模式全局中断使能
- <span class="csr-bit">8</span> <span class="csr-behav">WARL</span> SPP：S 模式中断处理前的特权级别

#### 其它
stvec、sip、sie、sepc、scause、stval 意义均与 M 模式类似。

### S 模式特权指令
<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>ecall</span>
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
    <td colspan="12" class="riscv-table-node-little">000000000000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：ecall
- **指令作用**：S 模式调用 ecall 会产生 environment-call-from-S-mode 异常
- **注意**：接收特权级的 epc 寄存器要设置为 ecall 指令的地址，而不是 ecall 指令的下一条指令的地址

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>ebreak</span>
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
    <td colspan="12" class="riscv-table-node-little">000000000001</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：ebreak
- **指令作用**：任何模式调用 ebreak 都会产生 breakpoint 异常，将控制流交给调试器
- **注意**：接收特权级的 epc 寄存器要设置为 ebreak 指令的地址，而不是 ebreak 指令的下一条指令的地址

</div>
</div>


<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sret</span>
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
    <td colspan="12" class="riscv-table-node-little">000100000010</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：sret
- **指令作用**：在 S 模式处理 trap 之后返回前一特权模式，并将 pc 设置为 sepc 寄存器的值
    - 将当前特权模式设置为 sstatus[SPP]
    - 将 sstatus[SIE] 设置为 sstatus[SPIE]
    - 将 sstatus[SPIE] 设置为 1
    - 将 sstatus[SPP] 设置为 U
    - 将 pc 设置为 sepc 寄存器的值

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>wfi</span>
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
    <td colspan="12" class="riscv-table-node-little">000100000101</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：wfi
- **指令作用**：任何特权模式均可用，执行时当前 hart 会进入休眠，等待中断来唤醒，相当于 nop

</div>
</div>

## RISC-V 中断和异常处理
RISC-V 将能引起当前程序中断，使 CPU 转到特定代码的事件称为**陷阱（Trap）**，其分为两类，**中断（Interrupt）**和**异常（Exception）**：

- 中断是硬件产生的，异步处理，是正常事件。包括软件中断、时钟中断、外部中断等。
- 异常是软件产生的，同步处理，是非正常事件，可能会导致程序终止。例如指令异常等。

### 中断处理
RISC-V 中外部中断必须通过 CSR 来开启，开启中断由两个步骤：

- mstatus[MIE] 是全局中断使能位，设置为 1 才会全局开启中断
- mie 寄存器中是针对各种中断类型的使能位，要将需要的位设置为 1

中断响应程序的入口地址由 mtvec 寄存器指定，如前面写到的，它分为两种模式：

- 直接模式（Direct），所有 trap 都跳转到 mtvec 寄存器指定的地址进行处理
- 向量化模式（Vectored），中断将根据中断类型跳转到不同偏移位置的中断响应程序，异常仍使用同一个响应程序

当中断发生时，CPU 会：

- 将发生异常的指令（或下一条指令）的地址保存到 mepc 寄存器
- 将中断类型码保存到 mcause 寄存器
- 如果中断带有附加信息，将其保存到 mtval 寄存器
- 如果是外部引发的中断，令 mstatus[MPIE] = mstatus[MIE]（保存），然后令 mstatus[MIE] = 0（关闭中断）
- 将当前特权模式保存到 mstatus[MPP] 中
- 将当前特权模式设置为 Machine 模式
- 根据 mtvec 寄存器的设置，跳转到对应中断响应程序

中断处理结束后要使用 mret 指令进行返回，它会：

- 令 mstatus[MIE] = mstatus[MPIE]（恢复），然后令 mstatus[MPIE] = 1
- 将当前特权模式设置为 mstatus[MPP] 中保存的值
- 将 mstatus[MPP] 设置为 U 模式
- 将 pc 值设置为 mepc 值，即跳转回中断前的程序

### 委托处理
RISC-V 中，所有中断都会在 Machine 模式下进行处理。在操作系统中，中断通常是要交给内核来处理的，内核态对应的也就是 Supervisor 模式。RISC-V 中提供了委托机制，可以将中断直接委托给 Supervisor 模式处理，而不经过 Machine 模式。

相关的委托设置在 medeleg 和 mideleg 两个寄存器中，相关意义在前面 Machine-Level CSR 部分写过了。

在委托情况下，和上面不同的是将会使用 Supervisor-Level 的 CSR，如 sepc、scause、stval 等，而且也会使用 sret 进行中断返回。