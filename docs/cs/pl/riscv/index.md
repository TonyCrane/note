---
counter: True
comment: True
---

# RISC-V ISA

!!! abstract
    计算机系统课上学到的指令集体系结构 RISC-V，官网 https://riscv.org/

子页面

- [RISC-V 非特权级 ISA](unprivileged)
- [RISC-V 特权级 ISA（基础&中断）](privileged)
- [RISC-V 特权级 ISA（页表相关）](paging/)

## 基础知识

- RISC-V 是一个 ISA 标准
- RISC-V 是完全开放的，允许任何人使用
- 简单、可扩展
- 分为用户级指令集规范（User-level ISA spec）和特权级指令集规范（Privilege ISA spec）等
- 命名为 RV + 数据宽度 + 扩展

### 指令集
- 基础指令集：RV32I、RV64I（32/64 位带有整型操作的指令集）、RV32E（只有 16 个寄存器的 32 位整型指令集）
    - I：带有 ALU 运算、分支跳转、装载存储
- 扩展：
    - M：增加整型乘法、除法
    - A：原子指令
    - F：增加单精度浮点数
    - D：增加双精度浮点数
    - Q：增加 128 位四精度浮点数
    - Zicsr：增加 CSR（控制和状态寄存器）
    - Zifencei：增加 FENCE.I 指令
    - ...
    - G：= IMAFDZicsr_Zifencei
- 扩展了的指令集则命名为 RV32IM、RV32IMA、RV32G 等等

## 编译运行调试
### 编译
编译使用 [:material-github: riscv-collab/riscv-gnu-toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain)。

- 需要手动克隆源码（极大），再编译，时间很长
- 编译时注意 prefix 和选择指令集 --with-arch
- make linux 编译出来的是 riscv*xx*-linux-gnu-*xxx*，使用 glibc 标准库，支持动态链接
- make 或 make newlib 编译出来的是 riscv*xx*-unknown-elf-*xxx*，使用 riscv-newlib，只能静态链接

Ubuntu 20.04+ 可以直接通过 apt 安装：
```shell
$ sudo apt install qemu-system-misc gcc-riscv64-linux-gnu gdb-multiarch
```

编译 c 代码使用 riscv*xx*-unknown-*xxx*-gcc 就可以了，注意指定 -march 和 -mabi，比如加上 `-march=rv32i -mabi=ilp32` 后编译出来的就是使用 RV32I 指令集的机器码。

比如编译一个纯 riscv 的汇编代码就可以这样：

```shell
$ cat code.s
.section .text
.globl _start
_start:
    ...
    ...
$ riscv64-unknown-elf-gcc -nostdlib -nostdinc -static -g -Ttext 0x80000000 -o code.elf code.s
$ riscv64-unknown-elf-gcc -nostdlib -nostdinc -static -g -Ttext 0x80000000 -o code.elf code.s -march=rv32i -mabi=ilp32
$ riscv64-linux-gnu-gcc -nostdlib -nostdinc -static -g -Ttext 0x80000000 -o code.elf code.s
$ riscv64-linux-gnu-gcc -nostdlib -nostdinc -static -g -Ttext 0x80000000 -o code.elf code.s -march=rv32i -mabi=ilp32
```

### 运行
因为 RISC-V 是另一种架构，不能在 x86 机器上直接运行，所以要使用 qemu 来运行。qemu 直接下载就可以，一般都会自带 RISC-V 的模拟器，如果是手动编译需要注意指定编译出 RISC-V。

qemu 有用户态和系统态两种模拟器，分别是 qemu-riscv64 和 qemu-system-riscv64，前者用于模拟用户态的单个程序，后者用于模拟整个 RISC-V 特权级系统。比如：

```shell
$ qemu-riscv64 code.elf
$ qemu-riscv64 -singlestep -g 1234 code.elf # 供 gdb 单步调试（也可以直接用系统态 qemu）
$ qemu-system-riscv64 -nographic -machine virt -bios default -kernel code.elf # 运行内核
$ qemu-system-riscv64 -nographic -machine virt -bios default -kernel code.elf -S -s # 调试内核，开启 localhost:1234 端口供 gdb 连接
```

### 调试
工具链会包含支持 RISC-V 的 gdb，也可以自行编译出支持 RISC-V 的 gdb。或者也可以使用 gdb-multiarch 来进行调试。

对于 RISC-V 架构来说，pwn 常用的 gdb 插件比如 pwndbg 和 peda 都不支持，这里推荐一个 [gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard) 插件，即使是 RISC-V 也可以正常显示寄存器、反汇编等信息，安装：

```shell
$ pip install pygments
$ wget -P ~ https://git.io/.gdbinit
```

### 简化的逐指令翻译
按照前面的方法对 asm 进行编译得到指令机器码有时候还是太麻烦，而且只有机器码的情况下想要 objdump 也有些麻烦。所以我干脆给 CyberChef 加了 RISC-V 的编解码器，调用了 [rvcodec.js](https://gitlab.com/luplab/rvcodecjs/)，位置在 [lab.tonycrane.cc/CyberChef](https://lab.tonycrane.cc/CyberChef)，可以直接使用。

关于 CyberChef 的用法不在这里赘述，大概就是从左侧拖拽模块到中间菜谱（recipe）部分即可，多个模块的话从上到下依次执行。

要注意的是我实现的 Decoder 接收的类型为 raw 的二进制数据，所以如果是 hex 值格式的字节码的话要在前面加一个 From Hex 模块。

## 其他杂项问题
### 链接期重定位问题

在做系统三虚拟内存 lab 的时候发现的问题，简单来说就是不同版本的 RISC-V 工具链对于 relocation 的处理可能不一致，导致不同环境下需要不同代码才能运行。

问题的背景是内核启动时先在物理地址内运行，然后设置好页表后写入 satp 寄存器中，这时也就启用了虚拟内存。所以情况就是一份编译好的代码的寻址相关（比如内核启动时设置 sp，读取本地变量地址等）在运行时可能需要是物理地址，也可能需要是虚拟地址。

- 对于较老的工具链，寻址基本都是以 pc 为基准进行偏移，不会出现问题，因为对应的 pc 就是正确的地址
- 较新的工具链编译出来的会使用 GOT 表来进行寻址，而根据链接脚本，GOT 表内的项肯定都是虚拟地址，这样在启用虚拟地址之前直接寻址就会出现问题

因为其实设置 satp 前的过程大部分都是 head.S 中汇编手写的，所以针对第二种情况，发现有寻址到虚拟地址的话直接手动减一下 offset 就可以了。