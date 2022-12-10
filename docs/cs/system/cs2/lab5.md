---
counter: True
comment: True
---

# RV64 时钟中断处理

!!! abstract
    计算机系统 Ⅱ lab5 实验报告（2022.11.17 ~ 2022.12.01）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 完成对异常处理的初始化、实现上下文切换功能、编写异常处理函数、完成对时间中断事件的处理
- 完成代码并编译运行：
    1. arch/riscv/kernel/head.S
    1. arch/riscv/kernel/entry.S
    1. arch/riscv/kernel/trap.c
    1. arch/riscv/kernel/clock.c 
    1. 其它必要的修改
- 思考题
    1. 解释 OpenSBI 输出的 MIDELEG、MEDELEG 的含义
    2. 机器启动后 time、cycle 寄存器分别是从 0 开始计时的吗，从 0 计时是否是必要的呢？
    3. 谈谈如何在一台不支持乘除法指令扩展的处理器上执行乘除法指令


## 代码编写
### lab5 提供修改
按照实验手册和 repo 中提供的代码进行修改。即将 puti、puts 换为 printk，需要额外修改 init/main.c：
```c
#include "printk.h"

extern void test();

int start_kernel(int x) {
    printk("%d", x);
    printk(" ZJU Computer System II\n");
    test(); // DO NOT DELETE !!!
	return 0;
}
```

以及根据指导修改 init/test.c、vmlinux.lds、head.S，这里不再赘述。

### head.S 开启异常处理
根据实验指导中的步骤进行编写：

1. 设置 stvec 为 _traps 地址，且使用 direct 模式：
    ```text
    la a0, _traps
    csrw stvec, a0
    ```
    - 因为对齐的原因，后两位一定为 0，即 direct 模式，不需要处理
2. 将 sie[STIE] 置 1
    - sie 的右数第 5 位为 STIE，所以通过 csrs 将其设置为 1 即可：
    ```text
    li a0, 1 << 5
    csrs sie, a0
    ```
3. 设置第一次时钟中断
    - 按照要求，根据 clock_set_next_event 的逻辑用汇编实现
    - （在此前一定要先设置好 sp，因为有 call 了）
    ```text
    rdtime a0
    li t0, 10000000
    add a0, a0, t0
    call sbi_set_timer
    ```
4. 开启 S 态下中断响应，将 sstatus[SIE] 置 1
    - sstatus 的右 1 位为 SIE，通过 csrs 设置
    ```text
    csrs sstatus, 1 << 1
    ```

### entry.S 中实现针对 trap 的上下文切换
根据实验指导：

1. 保存 CPU 寄存器到栈上
    - 后面 sp 需要最后恢复，所以需要最先压入 sp，其它任意
    ```text
    sd sp, -8(sp)
    sd ra, -16(sp)
    sd gp, -24(sp)  
    ...
    sd t5, -240(sp)  
    sd t6, -248(sp)
    addi sp, sp, -248
    ```
2. 调用 trap_handler
    - 需要传入参数，第一个参数 scause 放入 a0、第二个参数 sepc 放入 a1
    ```text
    csrr a0, scause
    csrr a1, sepc
    call trap_handler
    ```
3. 从栈上恢复寄存器
    - 和第一步的顺序相反
    ```text
    ld t6, 0(sp)  
    ld t5, 8(sp)  
    ...
    ld gp, 224(sp)  
    ld ra, 232(sp)  
    ld sp, 240(sp)
    ```
4. 从 trap 中返回
    - 由于是从 S 态异常返回，所以要使用 sret
    ```text
    sret
    ```

### trap.c 实现异常处理函数
需要通过 scause 判断 trap 类型，如果是时钟中断，则打印信息并调用 clock_set_next_event() 函数。

根据手册，时钟中断时 scause 的最高位为 1（Interrupt），剩余位表示的值（Exception Code）为 5（Supervisor timer interrupt），所以在函数里这样判断即可：
```c 
#include "clock.h"
#include "printk.h"

void trap_handler(unsigned long scause, unsigned long sepc) {
    if ((scause >> 63) && (scause & 0x7FFFFFFFFFFFFFFF) == 5) {
        printk("[S] Supervisor Mode Timer Interrupt\n");
        clock_set_next_event();
        return;
    }
}
```

以及为了使用 clock.c 中的 clock_set_next_event 函数，还需要编写一个 clock.h 头文件：
```c 
#ifndef _CLOCK_H
#define _CLOCK_H
void clock_set_next_event();
#endif
```

### clock.c 实现中断相关函数
get_cycles 函数通过内联汇编调用 rdtime 即可：
```c 
unsigned long get_cycles() {
    unsigned long time;
    asm volatile (
        "rdtime %[time]"
        : [time] "=r" (time)
        : : "memory"
    );
    return time;
}
```

clock_set_next_event 函数里计算出 next_time 直接调用 sbi_set_timer 即可：
```c 
void clock_set_next_event() {
    unsigned long next_time = get_cycles() + TIMECLOCK;
    sbi_set_timer(next_time);
}
```

### 运行结果
make run 结果输出正确：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab5/img1.png" width="100%" style="margin: 0 auto;">
</div>

## 思考题
### 解释 OpenSBI 输出 MIDELEG、MEDELEG 含义

MIDELEG（machind interrupt delegation register）、MEDELEG（machine exception delegation register）并称 machine trap delegation registers。它们表示是否将对应位上的 trap 交给 S 模式来处理，如果对应位为 1 则代理给 S、否则由机器模式处理。每个 trap 对应的位和 scause 中定义相同。

MIDELEG 输出值为 0x222（0b1000100010），第 5 位为 1，对应中断 Supervisor timer interrupt。如果其为 0，则不会进入我们编写的处理程序，也就不会输出对应消息。

### 机器启动后 time、cycle 寄存器分别是从 0 开始计时的吗？

make debug 启动，gdb 连接后直接输出 time 寄存器和 cycle 寄存器的值，可见 time 值为 0，cycle 不为 0：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab5/img2.png" width="70%" style="margin: 0 auto;">
</div>

time 在开始时需要为 0，来记录启动时间。cycle 不需要为 0，因为其用处不大。

### 谈谈如何在一台不支持乘除法指令扩展的处理器上执行乘除法指令

在一台不支持乘法指令扩展的处理器上遇到乘法指令会触发 Illegal Instruction 异常（对应值为 2），同样会进入 trap handler 中，此时非法指令的编码会被存储到 mtval（委托情况下是 stval）中，所以在 handler 中读取非法指令进行判断，然后处理得到正确结果即可。
