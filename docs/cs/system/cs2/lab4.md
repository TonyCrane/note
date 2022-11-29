---
counter: True
comment: True
---

# RV64 内核引导

!!! abstract
    计算机系统 Ⅱ lab4 实验报告（2022.11.03 ~ 2022.11.17）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 编写、完成所给实验代码框架，并成功运行
    - arch/riscv/kernel/head.S
    - lib/Makefile
    - arch/riscv/kernel/sbi.c
    - lib/print.c
    - arch/riscv/include/defs.h
- 思考题
    1. 编译之后，通过 System.map 查看 vmlinux.lds 中自定义符号的值，比较他们的地址是否符合你的预期
    1. 在你的第一条指令处添加断点，观察你的程序开始执行时的特权态是多少，中断的开启情况是怎么样的
    1. 在你的第一条指令处添加断点，观察内存中 text、data、bss 段的内容是怎样的
    1. 尝试从汇编代码中给 C 函数 start_kernel 传递参数


## 代码编写
### head.S & vmlinux.lds
head.S 的作用是作为整个内核启动的引导。其要完成的是 1. 为 start_kernel 设置一个栈空间（即创建栈空间并将 sp 指到栈顶）2. 跳转到 start_kernel 内。

vmlinux.lds 的作用是定义内核的内存布局。我们的目的是将栈空间放到 _end 后面，所以可以在 vmlinux.lds 中 _end 后面再加一个段 .stack，方便后续 head.S 在此处插入栈空间：
```text
    _end = .;

    .stack : ALIGN(0x1000){
        _sstack = .;

        *(.stack.entry)

        _estack = .;
    }
}
```
然后在 head.S 中利用 .space 设置空间大小为 4KB、la 来设置 sp 寄存器、j 指令跳转到 start_kernel 中：
```text
.extern start_kernel

.section .text.entry
.globl _start
_start:
    la sp, boot_stack_top
    j start_kernel

.section .stack.entry
.globl boot_stack_bottom
boot_stack_bottom:
    .space 4096
.globl boot_stack_top
boot_stack_top:
```

### sbi.c
sbi.c 的作用是实现 SBI 调用。最主要的目的是实现 sbi_ecall 来执行环境调用，用其可以实现 sbi_console_putchar 等函数。

sbi_ecall 的实现参考了 Linux 6.0.7 的代码实现。其主要过程就是将函数参数布局到寄存器中（ext 放到 a7、fid 放到 a6、arg0-5 放到 a0-5），然后执行 ecall 指令，最后返回的结果有 a0 表示 error code，a1 表示返回值（所以这两个寄存器要是读写的，其它是可读即可），并且可能会修改内存。利用内联汇编可以进行如下实现：
```c
struct sbiret sbi_ecall(int ext, int fid, uint64 arg0,
                        uint64 arg1, uint64 arg2,
                        uint64 arg3, uint64 arg4,
                        uint64 arg5)
{
    struct sbiret ret;
    register uint64 a0 asm("a0") = (uint64)(arg0);
    register uint64 a1 asm("a1") = (uint64)(arg1);
    register uint64 a2 asm("a2") = (uint64)(arg2);
    register uint64 a3 asm("a3") = (uint64)(arg3);
    register uint64 a4 asm("a4") = (uint64)(arg4);
    register uint64 a5 asm("a5") = (uint64)(arg5);
    register uint64 a6 asm("a6") = (uint64)(fid);
    register uint64 a7 asm("a7") = (uint64)(ext);
    asm volatile (
        "ecall"
        : "+r" (a0), "+r" (a1)
        : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (a7)
        : "memory"
    );
    ret.error = a0;
    ret.value = a1;
    return ret;
}
```

对于它的使用可以先实现三个（sbi.h 中还需要添加一下函数声明）：
- sbi_set_timer：ext 为 0x00，有一个输入 stime_value
- sbi_console_putchar：ext 为 0x01，有一个输入 ch 表示要输出的字符 ASCII 码
- sbi_console_getchar：ext 为 0x02，无输入，a0（即 ret.error）为输入字符的 ASCII 码

```c 
void sbi_set_timer(uint64 stime_value) {
    sbi_ecall(0x00, 0, stime_value, 0, 0, 0, 0, 0);
}

void sbi_console_putchar(int ch) {
    sbi_ecall(0x01, 0, ch, 0, 0, 0, 0, 0);
}

int sbi_console_getchar() {
    struct sbiret ret;
    ret = sbi_ecall(0x02, 0, 0, 0, 0, 0, 0, 0);
    return ret.error;
}
```

### print.c & Makefile
print.c 中需要定义两个使用 sbi_ecall (sbi_console_putchar) 来实现输出的两个函数 puts 和 puti。其中 puts 直接逐字符调用 sbi_console_putchar 输出直到遇到 '\0'：
```c 
void puts(char *s) {
    while (*s) {
        sbi_console_putchar(*s++);
    }
}
```
puti 先枚举 0、负数等特殊情况，然后利用取模运算来将数字逐位转为字符，再逐字符输出：
```c 
void puti(int x) {
    char buf[16];
    int i = 0;
    if (x == 0) {
        sbi_console_putchar('0');
        return;
    }
    if (x < 0) {
        sbi_console_putchar('-');
        x = -x;
    }
    while (x) {
        buf[i++] = '0' + x % 10;
        x /= 10;
    }
    while (i) {
        sbi_console_putchar(buf[--i]);
    }
}
```

Makefile 和其它 Makefile 一样就可以，即将目录下所有 .c 文件编译出 .o 文件：
```makefile
C_SRC       = $(sort $(wildcard *.c))
OBJ         = $(patsubst %.c,%.o,$(C_SRC))

file = main.o
all:$(OBJ)
	
%.o:%.c
	${GCC} ${CFLAG} -c $<
clean:
	$(shell rm *.o 2>/dev/null)
```

### defs.h
defs.h 中需要补全 csr_read 宏。直接使用内联汇编调用 csrr 指令将 csr 寄存器的值读入 __v 变量即可：
```c 
#define csr_read(csr)                       \
({                                          \
    register uint64 __v;                    \
    asm volatile ("csrr %0, " #csr          \
                    : "=r" (__v) :          \
                    : "memory");            \
    __v;                                    \
})
```

### 运行结果
运行 make 可以正常编译并产生编译产物：
![](/assets/images/cs/system/cs2/lab4/img1.png)

运行 make run 可以正常启动内核并输出信息 “2022 ZJU Computer System II”：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab4/img2.png" width="70%" style="margin: 0 auto;">
</div>

## 思考题
### 观察 System.map 中的地址是否符合预期

查看 System.map 并将其有效部分按照地址排序输出：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab4/img3.png" width="80%" style="margin: 0 auto;">
</div>

经观察、_start 的地址为 0x80200000、同样 _stext 即 .text 段的起始地址也为 0x80200000。接着是一些 sbi.c 中实现的函数，然后是 start_kernel 函数与其后的一些函数，然后 .text 段结束（_etext）。后面是 .rodata 段，其保存了字符串 " ZJU Computer System II"。然后是空的 .data 段和 .bss 段（这里没有用到），接着 _end 即内核结束地址。然后是栈空间（起始 sp 位于 boot_stack_top，栈空间向小地址增长）。可见均符合预期。

### 调试观察程序开始时的特权态和中断信息

gdb 在开头下断点、运行到程序开头处，检查特权态（priv 寄存器，值为 1 即 Supervisor）和存有中断信息的寄存器：
![](/assets/images/cs/system/cs2/lab4/img5.png)

### 调试观察程序开始时各段内容

连接 gdb、下断点、开始运行、检查各段内容：
![](/assets/images/cs/system/cs2/lab4/img4.png)

可以看见 .text 段存了指令。.rodata 段存了字符串 " ZJU Computer System II\n"。.data 段看起来不为空，但实际上 .data 段在这个程序中并不存在，这部分数据为 \_GLOBAL_OFFSET_TABLE_ 内容。.bss 段为空（实际也不存在）、栈空间内容为空。

### 尝试从汇编代码中给 C 函数 start_kernel 传递参数

RISC-V 调用函数会使用 a0-a7 寄存器传递参数，所以在 head.S 中设置寄存器的值就可以完成怼 start_kernel 函数的传参。首先修改 init/main.c 来为 start_kernel 添加参数：
```c 
int start_kernel(int x) {
    puti(x);
    puts(" ZJU Computer System II\n");
    ...
}
```
然后在 head.S 中直接为 a0 寄存器赋值完成传参：
```text
_start:
    la sp, boot_stack_top
    li a0, 2022
    j start_kernel
```
运行 make run 可以正常启动内核并输出信息 “2022 ZJU Computer System II”：
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab4/img2.png" width="70%" style="margin: 0 auto;">
</div>
