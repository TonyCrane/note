---
counter: True
comment: True
---

# RISC-V ISA

!!! abstract
    计算机系统课上学到的指令集体系结构 RISC-V，官网 https://riscv.org/

子页面

- [RISC-V 非特权级 ISA](unprivileged)
- [RISC-V 特权级 ISA](privileged)

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

### 编译运行
#### 编译
编译使用 [:material-github: riscv-collab/riscv-gnu-toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain)

- 需要手动克隆源码（极大），再编译，时间很长
- 编译时注意 prefix 和选择指令集 --with-arch
- make linux 编译出来的是 riscv*xx*-unknown-linux-gnu-*xxx*，使用 glibc 标准库，支持动态链接
- make 或 make newlib 编译出来的是 riscv*xx*-unknown-elf-*xxx*，使用 riscv-newlib，只能静态链接

编译 c 代码使用 riscv*xx*-unknown-*xxx*-gcc 就可以了，注意指定 -march 和 -mabi，比如加上 `-march=rv32i -mabi=ilp32` 后编译出来的就是使用 RV32I 指令集的机器码

Ubuntu 20.04+ 可以直接通过 apt 安装：
```shell
$ sudo apt install qemu-system-misc gcc-riscv64-linux-gnu gdb-multiarch
```

#### 运行
因为 RISC-V 是另一种架构，不能在 x86 机器上直接运行，所以要使用 qemu 来运行。qemu 直接下载就可以，一般都会自带 RISC-V 的模拟器，如果是手动编译需要注意指定编译出 RISC-V