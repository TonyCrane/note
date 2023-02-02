---
counter: True
comment: True
---

# 南京大学 ICS PA 实验纪实

!!! abstract 
    南京大学计算机系统基础课程实验。

    实验指导文档：https://nju-projectn.github.io/ics-pa-gitbook/ics2022/

    一个一直听朋友、学长称赞的实验，寒假做了一下，很爽，也学到了一些，这里会记录一下学到的零散东西以及一些痛苦 debug 经历（

    对于这套实验还是引发了我的一些思考的，相关感悟和思考在 blog 上：[「杂谈」由 PA 实验引发的一些思考](https://blog.tonycrane.cc/p/dc8d460.html)

## 实验概述
整个实验逐步引导完成一个计算机系统的构建，包括底层的 NEMU 模拟器，运行时环境 AbstractMachine（AM），在其上的简易操作系统 NanOS-lite，以及操作系统上的应用程序库 Navy-apps。

一共分为 5 个部分，PA0 配置环境，PA1 完善 NEMU 的调试器功能，PA2 模拟 NEMU 指令运行以及补充 AM，PA3 完善 NEMU 的中断/异常处理、实现操作系统的系统调用以及简易文件系统功能，PA4 在操作系统中实现多道程序的运行、虚拟内存管理以及外部中断处理。

细分每个实验的内容以及涉及到的源码部分，我整理了如下一个表格供参考：

![](/assets/images/cs/system/pa/roadmap_light.png#only-light)
![](/assets/images/cs/system/pa/roadmap_dark.png#only-dark)

PS：其中 AM 由五个部分组成，TRM（图灵机模拟）简单而且已经实现好了，IOE 为输入输出扩展，CTE 为上下文管理扩展，VME 为虚拟内存管理扩展，还有一个 MPE（多处理器扩展）在 PA 中不使用。klib 为简单的运行时库，提供给 AM 和操作系统使用。

总而言之有了计算机系统课以及 RISCV 手册阅读的基础，大部分实验还是比较轻松的，没有什么难以理解的地方。较为痛苦的就是 debug 时一些奇怪的问题以及最后 PA4 中之前没有接触过的虚存管理的内容了。后面记录一些还能回忆起来的问题（其实是做的过程中懒得记录）。

## PA0
这部分就是配置 Linux 环境以及获取源码。Ubuntu 安装就还是正常，UltraISO 准备启动盘，然后进 BIOS 从 U 盘启动，根据指导安装。这次遇到的几个联想的坑（我的 win 电脑是联想小新 Air 14+）：

- 联想会自动开启 BitLocker 保护磁盘，这种情况下 Ubuntu 无法安装，需要回到 Win 中关掉 BitLocker（时间较长）
- 我这台联想开机会立即启动 Windows，没有联想 Logo 页面（Windows 开机界面的 Windows 被替换成了联想小新，这不算开机 logo 的部分），所以要在按下电源键后马上按 F2 才能进入 BIOS
    - 而且那个 FnLock 在这个时候有没有用不清楚，Fn+F2 不行就单独 F2
- 我这台的 BIOS 界面是“优化”过的，不是老式那种蓝灰界面，甚至启动项里找不到 USB，不能通过这种方式启动
    - 正确操作是在关机情况下直接按 F12 右侧的“五角星S”特殊功能键，便会出现页面直接选择进入 BIOS 还是选择启动方式，这里就有 USB 了

关于 Ubuntu 的配置，我的流程大概就是：

- 安装一系列字体，改壁纸
- 装 gnome tweaks 调系统字体和窗口三个按钮（关闭隐藏最大化）调到左上角
- 换 zsh，装 oh-my-zsh、powerlevel10k 主题以及插件，添加 vim 配置
- 装一些命令行常用的工具
- 装中文输入法
- 装 V2rayN，<del>在 FireFox 上用 Bing 搜索</del>安装 Chrome，安装 vscode，并同步设置

几个 Ubuntu 上还没搞好的问题：

- 想要禁用 Logi MX Master 2S 鼠标的无限滚动，但没有 Options，网传的 Solaar 工具里也找不到这一设置
- 想要修改 CapsLk 的行为到与 mac 一致，win 上有 AutoHotkey 可以用，Linux 上没找到好用的替代
    - 其实 tweaks 里有设置可以更改 CapsLk 的行为，但是貌似没有效果，大概是个 bug，可以搜到类似 bug 但没看到解决办法

反正鼓捣了半天就能用就行了。

### 实验代码 git 跟踪
整套实验代码有一个很有趣很神奇的功能，就是在每次编译、运行的时候都会自动提交修改，并生成一条 commit。PA 中称之为“开发跟踪”，通过这个手段来记录实验流程，并检查是否存在作弊行为。

这一功能的实现得益于整个框架都使用提供好的 Makefile，且编译运行都通过 make 来进行。其原理为：

- 根目录下 Makefile：
    ```Makefile
    STUID = ...
    STUNAME = ...
    
    GITFLAGS = -q --author='tracer-ics2022 <tracer@njuics.org>' --no-verify --allow-empty

    define git_commit
        -@git add $(NEMU_HOME)/.. -A --ignore-errors
        -@while (test -e .git/index.lock); do sleep 0.1; done
        -@(echo "> $(1)" && echo $(STUID) $(STUNAME) && uname -a && uptime) | git commit -F - $(GITFLAGS)
        -@sync
    endef
    ```
    - 定义了一个函数 git_commit
        - add 所有内容（NEMU_HOME/.. 即为实验根目录）并确保完成
        - 将参数、学号姓名、系统信息作为 commit message 进行 commit，author 在 GITFLAGS 中指定
- NEMU 的相关 Makefile：
    ```Makefile
    -include $(NEMU_HOME)/../Makefile
    
    compile_git: 
        $(call git_commit, "compile NEMU")
    $(BINARY): compile_git

    run-env: $(BINARY) $(DIFF_REF_SO)
    run: run-env
        $(call git_commit, "run NEMU")
        $(NEMU_EXEC)
    gdb: run-env
        $(call git_commit, "gdb NEMU")
        gdb -s $(BINARY) --args $(NEMU_EXEC)
    ```
    - 导入了前面的 Makefile
    - 编译时添加了依赖 compile_git，其中会调用 git_commit 函数进行 commit，msg 开头为参数 compile NEMU
    - 对于 run 和 gdb，在编译后、运行前还会多加一条 run NEMU 或 gdb NEMU 的空 commit msg 作为记录

由于实验从头到尾都跑在 NEMU 上（native 测试不算），所以每次修改、运行都会经过这些部分，进行 commit 记录，达到自动跟踪的目的。

## PA1
### PA1.1
PA1.1 实际需要写的部分很简单，只要读读源码就能写出来。在读源码的时候发现了一个很有意思的库函数 getopt_long。之前一直以为 C 语言命令行参数都是靠手动提取解析的，原来还有一个专门的库函数用来干这个，大概使用方式就是：
```c 
#include <getopt.h>
static int parse_args(int argc, char *argv[]) {
    const struct option table[] = {
        {"batch", no_argument      , NULL, 'b'},
        {"log"  , required_argument, NULL, 'l'},
        {"help" , no_argument      , NULL, 'h'},
        {0      , 0                , NULL,  0 }.
    };
    int o;
    while ((o = getopt_long(argc, argv, "-bhl:", table, NULL)) != -1) { // l 后冒号表示后面需要参数
        switch (o) {
            case 'b': ...; break;
            case 'l': log_file = optarg; break; // optarg 为等号后的字符串
            case 1: ...; break; // 直接传入的参数，不是选项
            default:
                // print help message
                exit(0);
        }
    }
    return 0;
}
```

剩下的 PA1 好像也没什么好记的了。表达式求值和监视点都还算好写。

## PA2
### PA2.1
这部分是完善 NEMU 的译码、执行过程。这个部分在 ics2022 版的 PA 中写的很神奇，让 riscv 的译码写起来更清晰简洁。具体来说都是通过宏来实现的。

具体来讲就是定义了这么几个宏/函数：
```c 
__attribute__((always_inline))
static inline void pattern_decode(const char *str, int len,
    uint64_t *key, uint64_t *mask, uint64_t *shift) {
  ... // 从 str 中解析出 key, mask, shift
      // 对应位如果是 1 则 key 该位为 1，如果是 ? 则 mask 该位为 0
      // 最终效果为匹配上的指令 (inst >> shift) & mask == key
}
#define INSTPAT_START(name) { const void ** __instpat_end = &&concat(__instpat_end_, name); 
#define INSTPAT_END(name) concat(__instpat_end_, name): ; }
#define INSTPAT_INST(s) ((s)->isa.instr.val)
#define INSTPAT_MATCH(s, name, type, ... /* execute body */) { \
    decode_operand(s, &dest, &src1, &src2, &imm, concat(TYPE_, type)); \
    __VA_ARGS__; \
}
#define INSTPAT(pattern, ...) do { \
    uint64_t key, mask, shift; \
    pattern_decode(pattern, STRLEN(pattern), &key, &mask, &shift); \
    if ((((uint64_t)INSTPAT_INST(s) >> shift) & mask) == key) { \
        INSTPAT_MATCH(s, ##__VA_ARGS__); \
        goto *(__instpat_end); \
    } \
} while (0)
```

然后是两个函数，一个用来根据类型解码操作数，一个用来解码指令（包括译码和执行）：

```c 
static void decode_operand(Decode *s, int *dest, word_t *src1, word_t *src2, word_t *imm, int type) {
    uint32_t i = s->isa.instr.val;
    int rd  = BITS(i, 11, 7);
    int rs1 = BITS(i, 19, 15);
    int rs2 = BITS(i, 24, 20);
    *dest = rd;
    switch (type) {
        case TYPE_I: src1R();          immI(); break;
        case TYPE_U:                   immU(); break;
        case TYPE_S: src1R(); src2R(); immS(); break;
        case TYPE_R: src1R(); src2R();         break;
        case TYPE_B: src1R(); src2R(); immB(); break;
        case TYPE_J:                   immJ(); break;
    }
}

static int decode_exec(Decode *s) {
    int dest = 0;
    word_t src1 = 0, src2 = 0, imm = 0;
    s->dnpc = s->snpc;
    INSTPAT_START();
    INSTPAT("0000000 ????? ????? 000 ????? 01100 11", add, R, Reg(dest) = src1 + src2);
    ...
    INSTPAT_END();
    Reg(0) = 0;
    return 0;
}
```

- INSTPAT_START 和 INSTPAT_END 两个宏构成了一组大括号，在末尾创建了一个标号，并在开头获取了其地址
- INSTPAT 宏展开后首先通过 pattern_decode 获取 key mask shift，然后通过 INSTPAT_INST 获取指令值并检测是否匹配
- 如果匹配则进入 INSTPAT_MATCH 宏中，然后 goto 到结尾标号结束当前指令
    - INSTPAT_MATCH 宏中首先调用 decode_operand 函数，根据传入的指令类型提取对应的操作数到 decode_exec 的局部变量中
    - 然后 \_\_VA\_ARGS\_\_ 将最后一个参数展开并执行，也就是指令的执行部分
    - 通过 Reg 宏即可访问读写寄存器

整体看来这个设计是非常巧妙的，虽然宏看起来比较复杂难懂，但最终实际上要加的就是针对每一种指令增加 INSTPAT 一行的内容，而且指令名、类型、作用都清晰的体现在一行语句中了。缺点大概是一条指令有多种效果的时候（例如 ecall mret csr 指令等）挤在一起看起来不太优美（

有了之前系统实验时读 RISC-V 的基础，对着 [RISC-V 非特权级 ISA](/cs/pl/riscv/unprivileged/) 页面一条条指令抄在里面就可以了。实际运行起来才发现还有 RV32M 的扩展，几个指令也需要实现一下，后续再补充到那个页面。

这部分需要注意的地方就是关于几个 M 扩展指令的操作数类型强转、溢出、除零处理等了。

### PA2.2
PA2.2 前半部分在实现一些库函数内容，包括 string.h 的一些函数（实现 memcpy 的时候出现了一个潜在 bug，后面 PA3.3 再说），以及 stdio.h 的 sprintf 函数，后面 PA2.3 结合串口设备实现 printf 函数，这里是 PA 以来第一次痛苦调试，放在后面写。

除了这些，后半部分实现各种 trace 也没什么难度，这里我把它们都理解为了通过 sdb 命令输出 trace，实际上直接 Log 就是一个很好的方式，不需要搞那么复杂。然后就是 difftest。

原先听到 difftest 我还以为是什么高深的技术，仔细一看原来就是“对拍”，用自己实现的 NEMU 和更准确的 Spike 在每条指令运行后对寄存器的值进行对比，确保指令的执行没有错误。看一看源码其实也是很清晰的。在调试的时候也一直开着 difftest，没出现过什么问题，直到后面加上异常处理之后帮我捕捉到了几个额外的异常，后面再说。

### PA2.3
RISC-V 通过 MMIO 来实现设备通信。原理大概就是 NEMU 中各个设备分别创建一些空间，然后将这些空间映射到指定的地址上，并且注册一个 callback 函数。在访存的时候如果地址不落在物理地址范围内，则尝试搜索地址是否在某一个设备映射的空间中，如果是的话，对于读取先调用 callback，这时可以在实际读取数据之前更新值，对于写入则写入后调用 callback 函数处理新的值。

#### 串口
对于串口，相应代码已经提供好了，callback 函数会要求一定是写入，且写入的长度一定是一个字节。接收到一个字节后则通过 putch 来输出。在 AM 中，TRM 部分就提供了 putch 函数，函数体就只有 `#!c outb(SERIAL_PORT, ch);` 来向串口地址写入字节进行输出。

根据这个功能就可以实现 printf 了。由于 printf、sprintf 工作原理都类似，区别在于输出的位置，所以可以将共用的部分提取出单个函数 vprintf，并且接收一个函数用来输出单个字符。由于 printf 参数不固定，所以就需要使用 va_ 相关的功能了。printf 和 sprintf 本身就是接收一下参数然后传给 vprintf（在系统实验里学来的），所以它们两个写起来就是：
```c 
int printf(const char *fmt, ...) {
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    res = vprintf(putch, fmt, ap);
    va_end(ap);
    return res;
}

static char *__out;
void sputch(char ch) { *__out++ = ch; }

int sprintf(char *out, const char *fmt, ...) {
    int res = 0;
    va_list ap;
    va_start(ap, fmt);
    __out = out;
    res = vprintf(sputch, fmt, ap);
    *__out = '\0';
    va_end(ap);
    return res;
}
```

主要的处理都在 vprintf 中。当时我就直接抄系统二给的 printf 代码了，没想到被坑的超惨，全是 bug。不过主体没什么问题：
```c 
int vprintf(void (*putch)(char), const char *fmt, va_list ap) {
    int in_format = 0, longarg = 0; size_t pos = 0;
    for ( ; *fmt; ++fmt) {
        if (in_format) {
            switch (*fmt) {
                case 'x': ...
                ...
            }
        } else if (*fmt == '%') {
            in_format = 1;
        } else {
            putch(*fmt); pos++;
        }
    }
    return pos;
}
```
当时写完之后跑起来没啥问题，但是后来写时钟的时候发现了两个问题：

1. 对于 64 位数，输出的结果并不正确，很乱，差别很大
2. 对于无符号数，输出乱七八糟，甚至会输出 .)/( 这种一堆乱糟的字符

重新审视了一遍系统二的代码，发现即使是无符号输出，虽然 va_arg 获取参数的时候都写了 unsigned，但最后循环计算输出位的时候中间变量仍然都是 signed 的，改过来后输出不乱套了，但是 64 位输出仍然有问题。

我甚至还看了汇编代码，发现了一些诡异的事情，就是正常来讲函数的参数会依次放入 a0 a1 a2 ... 寄存器中，但是对于 64 位数据，会跳过 a1 放入 a2 和 a3 中，例如：

```text
printf("%d %d", 123, 456);
    a0 -> address of "%d %d"
    a1 -> 123
    a2 -> 456

printf("%lld", 0x1234567890);
    a0 -> address of "%lld"
    a2 -> 0x34567890
    a3 -> 0x12
```

我一度以为这是编译器错了，但即使是 riscv 的 gcc 又怎么会出这种错误呢。在纠结甚至打算放弃的时候我又到 Compiler Explorer 上试了一下，发现确实就是这样编译的，很神奇。所以问题肯定还是出现在 vprintf 内部了。

万恶之源是 vsc 将 uint64_t 提示成了由 unsigned long typedef 而来的，所以我就理所应当的认为用 va_arg 获取一个 64 位数的时候使用 va_arg(ap, long) 是正确的，系统二也是这样写的。而问题就在于 vsc 提示的来源是 x86 的 gcc 内部的，而不是 riscv 的。printf 输出一下 long 的大小的话可以发现也是四个字节……所以在用到 64 位数的时候明确的写出 int64_t 或 uint64_t 就好了。

#### 时钟
时钟其实写起来问题不大的，不过做时钟的时候正是需要 printf 64 位无符号数的时候，这时发现了上面说到的 printf 的 bug，调起来就相当痛苦了。

通过阅读源码发现，NEMU 里 timer 的 callback 函数只有在 offset == 4 也就是读取高 32 位的时候会刷新时间，所以不更改这里的话就需要先读取高 32 位再读取低 32 位，然后合并得到 64 位时间戳。

大概 PA2 需要注意的就这些了，后面键盘、VGA 都还好实现，也没出啥问题。

## PA3
### PA3.1
PA3.1 需要完成异常处理，实现特权指令和一堆 csr 指令。以及后面异常事件的分发，上下文的保存和恢复，这倒是都蛮简单，没啥可记的。

CSR 指令都还好办，虽然 verilog 编写硬件的时候痛苦面具，但是这里就很清晰了，直接写一个读一个写就好，而且可以将所有 csr 指令都当作 I 型，这样解析出的立即数就是 csr 寄存器编号了。

ecall 和 mret 的话就有一点头疼了，虽然表面上做的就是跳转到 mtvec 或者 mepc 位置，但是为了使 difftest 通过还需要按照要求修改 mstatus 的值。在 [RISC-V 特权级 ISA](/cs/pl/riscv/privilege/) 的最后我梳理了异常处理的流程，包括了 ecall 和 mret 期间的全部效果：

!!! note "ecall 和 mret 效果"
    ecall 时：
    
    - 将发生异常的指令地址保存到 mepc 寄存器
    - 将中断类型码保存到 mcause 寄存器（11 表示从 M 模式发出的 ecall）
    - 如果中断带有附加信息，将其保存到 mtval 寄存器（这里忽略）
    - 如果是外部引发的中断，令 mstatus[MPIE] = mstatus[MIE]（保存），然后令 mstatus[MIE] = 0（关闭中断）
    - 将当前特权模式保存到 mstatus[MPP] 中
    - 将当前特权模式设置为 Machine 模式
    - 根据 mtvec 寄存器的设置，跳转到对应中断响应程序

    mret 时：

    - 令 mstatus[MIE] = mstatus[MPIE]（恢复），然后令 mstatus[MPIE] = 1
    - 将当前特权模式设置为 mstatus[MPP] 中保存的值
    - 将 mstatus[MPP] 设置为 U 模式
    - 将 pc 值设置为 mepc 值，即跳转回中断前的程序

由于 mstatus 寄存器每一位有自己的作用，所以使用 union 是一个方便的选择（其实到 PA4 我才转到 union，之前都是位操作）：
```c 
union {
    struct {
        uint32_t UIE: 1, SIE: 1, WPRI_0: 1, MIE: 1;
        uint32_t UPIE: 1, SPIE: 1, WPRI: 1, MPIE: 1;
        uint32_t SPP: 1, WPRI_1_2: 2, MPP: 2, FS: 2;
        uint32_t XS: 2, MPRV: 1, SUM: 1, MXR: 1;
        uint32_t TVM: 1, TW: 1, TSR: 1, WPRI_3_10: 8, SD: 1;
    } part;
    word_t val;
} mstatus;
```

所以在 ecall 时做的操作就是：
```c 
if (cpu.priv == 3) s->dnpc = isa_raise_intr(11, s->pc);
else if (cpu.priv == 0) s->dnpc = isa_raise_intr(8, s->pc);
else assert(0);
// 其中
word_t isa_raise_intr(word_t NO, vaddr_t epc) {
    cpu.mepc = epc;
    cpu.mcause = NO;
    cpu.mstatus.part.MPP = cpu.priv;
    cpu.priv = 3;
    cpu.mstatus.part.MPIE = cpu.mstatus.part.MIE;
    cpu.mstatus.part.MIE = 0;
    return cpu.mtvec;
}
```
在 mret 时做的操作：
```c 
s->dnpc = cpu.mepc;
cpu.mstatus.part.MIE = cpu.mstatus.part.MPIE;
cpu.mstatus.part.MPIE = 1;
cpu.priv = cpu.mstatus.part.MPP;
cpu.mstatus.part.MPP = 0;
```

### PA3.2
这部分也算是实现起来比较复杂的了，因为要实现 ELF 文件的加载。

#### ELF 加载
可以通过 elf.h 导入一些结构体来进行解析。首先最开头的是 ELF 头（Ehdr），先读取然后判断魔数以及机器类型：
```c 
Elf32_Ehdr ehdr;
fread(&ehdr, sizeof(ehdr), 1, fp);
assert(*(uint32_t*)ehdr.e_ident == *(uint32_t*)ELFMAG);
assert(ehdr.e_machine == EM_RISCV);
```
接着根据 ehdr.e_phoff 找到程序表头，然后读取 ehdr.e_phnum 个 Phdr：
```c 
Elf32_Phdr *phdr = (Elf32_Phdr*)malloc(sizeof(Elf32_Phdr) * ehdr.e_phnum);
fseek(fp, ehdr.e_phoff, SEEK_SET);
fread(phdr, sizeof(Elf32_Phdr), ehdr.e_phnum, fp);
```
然后遍历程序表，判断 p_type，如果是 PT_LOAD 则说明是需要加载的部分，然后复制 p_filesz 个字节到 p_vaddr 位置，后再附加 p_memsz - p_filesz 个字节的 0（bss 段）即可。最后 loader 需要返回程序入口地址，即 ehdr.e_entry。

#### 系统调用
系统调用的实现也很简单，前面在 CTE 中将 a7 为 -1 的 ecall 识别为了 yield（底层的 yield 而非系统调用的 yield），剩余的都可以识别为系统调用，指定为 EVENT_SYSCALL，然后处理就在 NanOS-lite 中了，irq.c 中 do_event 接收 event，识别为 EVENT_SYSCALL 后调用 do_syscall，然后再根据 a7 的值进行相应的系统调用即可。这里要记得将 mepc 加 4 否则会死循环。其实可以针对 EVENT_YIELD 和 EVENT_SYSCALL 都进行 mepc += 4，而后面的硬件中断例如时钟中断则不需要。

在软件层面的系统调用是在 navy-apps 的 libos 中的，每个系统调用函数（\_exit、\_open 等）都会调用 \_syscall\_ 函数，其中是内联汇编布局寄存器后执行 ecall 指令，然后返回 a0 的值。系统调用函数只需要 return \_syscall\_(SYS_..., ...) 即可。所以整个系统调用过程是从 Navy-apps 申请开始，NEMU 执行 ecall 指令转到 AM 提供的异常处理程序，然后分发给 NanOS-lite 处理，再一层层返回。可见这是一个非常典型的软硬件协同的例子。

而这一部分需要实现 yield exit write brk 系统调用，前两个没什么问题，brk 这里也比较好写，因为进行的并不是真正的堆管理，而是模拟达到了类似能跑的效果。

而 write 在写的时候就出了一点问题，运行起来一直都是 printf 只会输出一个字符，很奇怪，我当时又怀疑是 printf 出了问题。最后逐一排查发现是 write 系统调用的返回值没有传出去，导致输出一个字符就结束了。

### PA3.3
这一部分要完善一个简易的文件系统（内容固定、大小固定、没有目录……），然后将设备抽象为虚拟文件，再完善 Navy-apps 的一系列库来运行起各种各样的程序。

#### 文件系统
这里的文件系统整体存储在 ramdisk.img 中，通过 resource.S 中的 .incbin 加载进来。然后每一个文件都可以通过一个结构体来记录：
```c 
typedef size_t (*ReadFn) (void *buf, size_t offset, size_t len);
typedef size_t (*WriteFn) (const void *buf, size_t offset, size_t len);
typedef struct {
    char *name;
    size_t size;
    size_t disk_offset;
    ReadFn read;
    WriteFn write;
    size_t open_offset;
} Finfo;
```
然后通过一个 Finfo 的数组来在文件描述符和 Finfo 之间进行映射。这里还有一个我觉得很巧妙的地方，就是在编译 Navy-apps 的过程中，所有可执行文件和素材都会存在 fsimg 文件夹下，然后 Makefile 中的脚本会将其打包成一个 ramdisk.img，然后同时提取出 name、size、disk_offset 的信息格式化到一个 files.h 中。在定义 Finfo 数组的时候直接 include 进来，就在编译时完成了文件系统全部内容的初始化。

对于虚拟文件，直接定义的时候加上对应的名字，然后指定特有的 read 和 write，在执行 fs_read fs_write 的时候如果 read write 不为 NULL 则调用，否则调用 ramdisk_read ramdisk_write，这样就实现了这个文件系统的基本功能。
```c 
enum { FD_STDIN, FD_STDOUT, FD_STDERR, FD_FB, FD_EVENTS };
static Finfo file_table[] = {
    [FD_STDIN]  = { "stdin", 0, 0, invalid_read, invalid_write },
    [FD_STDOUT] = { "stdout", 0, 0, invalid_read, serial_write },
    [FD_STDERR] = { "stderr", 0, 0, invalid_read, serial_write },
    [FD_FB]     = { "/dev/fb", 0, 0, invalid_read, fb_write },
    [FD_EVENTS] = { "/dev/events", 0, 0, events_read, invalid_write },
    {"/proc/dispinfo", 0, 0, dispinfo_read, invalid_write },
#include "files.h"
};
```
除此之外 Finfo 还需要维护 open_offset，这里我当时理解错了，实际上应该是距离 disk_offset 的偏移，而我理解为了在 ramdisk 中整体的偏移，不过实现后的最终效果还是一样的。

#### load 对齐异常
这个问题也 debug 了好久，说起来也很神奇，这个 bug 来自 PA2.2 但一直没发现，直到 PA4.1 才通过 difftest 发现，而实际出问题的地方又是在 PA3.3 这里写过的 ramdisk_read。

PA4.1 发现问题的时候很奇怪，difftest 的 ref 莫名其妙地跳到了 mtvec 异常处理函数位置，而 dut 继续往下运行，导致 pc 出现了不同。返回去看出错的 pc 位置的指令，竟然是一条 load 指令。当时我还以为是什么奇怪的时钟中断啥的，毕竟关掉了 difftest 是完全可以跑起来的。

因为 difftest 发现异常后就退出了，不能让 ref 继续运行，所以当时我就困在这里了，以为不好再调试了。但突然反应过来再发生异常的时候，这时 trap 原因就已经存到 mcause 里了，而这时我是可以输出 ref 中 mcause 的值的。一输出来看，竟然是 4，也就是 Load Address Misaligned。除此之外按照 RISC-V 的规定这时试图访问的地址会被存到 mtval 寄存器中，所以我又加了这个，然后同时输出，发现是 ramdisk 中的地址，而这个地址不是 4 的倍数。

我回忆起来之前文档中有一个地方说到了 Spike 不允许不对齐的访问，然后翻了一遍发现是在 PA2.2，同时里面也说了这大概是由于 klib 实现错误引起的。再深入调了一下发现确实，问题来自于 memcpy。我当时直接选用了 copilot 提供的写法，也就是先尝试一个 int 一个 int 拷贝，最后不到一个 int 了再逐 byte 拷贝。这里就忽略了一个问题，就是如果最开始的地址不是 4 的倍数，那么读取一个 int 就是不对齐的访问，虽然 NEMU 中没问题，但 Spike 认为出了问题，进入了异常处理。

所以解决方案是修改 memcpy，先拷贝字节到对齐的位置，然后再以 int 为单位拷贝。不过还是懒得写了，就全部逐字节拷贝了。

#### Navy 库补充
这里要完善定点算数 fixedpt 库，NDL 库，miniSDL 库。前两个都没什么大问题。

在实现 NDL_DrawRect 的时候最开始还是绕了一下的。它的目标是在显示器中画一个矩形，也就是将矩形的数据填写到 frame buffer 中，也就是写入 /dev/fb 这个虚拟文件。而我当时就被这个操作困住了，因为写的时候参数就只有 offset 和 len，而需要表示的呢，是一个矩形的范围，所以我就想了一个非常沙雕的办法，将左上角 (x, y) 分高 16 位和低 16 位写入 offset，然后长和宽同样写入 len 中，最后在 fb_write 中特殊处理的到 x y w h。这样跑是能跑，但是一旦将 Navy-apps 放在 native 上运行就不行了（因为这时会使用 NDL 库，但底层的 fb 写入处理不是 NanOS-lite 做的，而是 native 做的）。

然后我讲这个问题交给了 copilot，它一下就写出来了，解决办法是通过 for 循环一行一行写入 fb…… 我真的是脑子锈住了（

然后比较痛苦的就是 miniSDL 库了，这时的运行就是软件调用 SDL，SDL 调用 NDL，NDL 写入 fb，fb_write 写入 VGA 设备这样的关系。这个 SDL 的 surface，NDL 的 canvas，fb 的大小之间的关系是一个值得好好考虑的问题。

- 只看 NDL 和 fb
    - canvas 是记录在 NDL 中的全局数据
    - 从 fb 中获取屏幕大小数据存在 screen 中
    - 绘图（DrawRect）的时候根据 canvas screen x y 计算出在屏幕上实际的位置坐标（canvas 相对 screen 居中）然后写入 fb
- 看 SDL，这时候只需要考虑它下一层的 NDL，而无需考虑 fb 的问题
    - `#!c SDL_UpdateRect(SDL_Surface *s, int x, int y, int w, int h);` 实际上是提取 s 上从 (x, y) 开始的 w*h 大小的矩形，然后通过 NDL_DrawRect 画出来，此时的参数也是从 (x, y) 开始，宽高为 w h
    - `#!c SDL_FillRect` 没什么好说的，直接填入 surface 的 pixels 就好
    - `#!c SDL_BlitSurface(SDL_Surface *src, SDL_Rect *srcrect, SDL_Surface *dst, SDL_Rect *dstrect);` 实际上在做的是将 src 上的一部分矩形内容拷贝到 dst 上指定的位置，具体位置和大小参考 SDL 文档。而且这里甚至不需要考虑 NDL，只要复制过去了就好

都调好之后就可以成功运行 NSlider、MENU、NTerm、Flappy Bird、仙剑奇侠传等提供好的程序了。最后的 execve 系统调用这里也只需要直接 load 一个新程序进来就可以了。

## PA4
### PA4.1
这一部分要实现线程上下文的创建，包括内核进程和用户进程，此外用户进程加载时还需要为其布局好 argc argv envp 的参数栈。

对于内核进程，要实现的有为 mstatus 赋初值、设置 mepc 为入口点、设置 a0 为参数，设置 sp 为栈空间开头等。用户进程类似。

而这里用户进程的加载则需要一个新的函数 context_uload 来完成，其中要进行参数的布局。具体来讲就是从栈顶（高地址）开始依次存放 envp 各个字符串，argv 各个字符串，空一个（envp 数组最后的 NULL），然后倒序存放 envp 数组（内容是指向前面各个字符串的指针），空一个（argv 数组最后的 NULL），然后倒序存放 argv 数组，最后存放 argc。然后用户栈从后面开始向低地址延伸。具体就很好实现了。

### PA4.2
这一部分要实现分页机制，做这里的时候学校的系统课程还没有降到虚拟内存管理的部分，RISC-V 手册阅读当时也跳过了这里，可能理解的还是不够透彻，只是能跑而已，所以就不再这里详细写了。具体会在系统讲到的时候写到那里，以及 RISC-V 手册之后再详细读了之后再补充进去。

这里当时调试的一个困难是实现了分页机制之后 difftest 时 mstatus 总是对不上，然后仔细修改了 ecall、mret 的实现，结果异常号又对不上了（8/11，大概是特权级记录的问题）。而且 ref 也会抛出 7 号异常，也就是 Store/AMO Access Fault，大概是分页机制导致的权限问题，根据实验手册的提示，给页表项加了些 flag 算是解决了这个问题。但是特权级绕来绕去不太清楚怎么改，有点复杂。而且后面到了时钟中断就要抛弃 difftest 了，所以这里直接开摆了。

### PA4.3
最后这部分时钟中断和抢占式调度其实都还好写。但是后面内核栈和用户栈切换看的有点迷迷糊糊了，可能是分页机制就不太熟的缘故，也是写得能跑就行了，这里就不记了，之后理解清楚了再补充。

总之这就是能回忆起来的全部值得一记的内容了。

## 遗留问题
第一遍刷 PA，也想着既然有了点基础，那就尽快完成（~~留出的时间还能干点别的~~），虽然说必做任务都完成了，但是还是有一些选做任务还没做，留了一点遗憾。以后有机会二刷的时候再完整完成（我估计可能会咕）。

- PA2.2 trace 有点误解了，我以为都是在 sdb 中通过命令手动输出的，但其实在触发的时候直接 Log 出来是一个很好的选择
- PA2.2 klib 没有进行测试，写完了直接开跑
- PA2.3 声卡实现了，但是听起来有杂音，可能是写的有点问题，没再细调，后面声卡相关的选做也没再做
- PA2.3 最后选做的优化 LiteNES、在 NEMU 上跑 NEMU 的两个实验看起来挺有趣，但没做
- PA3.2 选做的”支持多个 ELF 的 ftrace“没做，还要读取、还要解析、还要计算，懒得写了（x
- PA3.3 在 Navy 上运行 am-kernels、fceux、oslab 以及带声音的程序，这些选做都没做
- PA3.3 自由开关 difftest，快照功能都没做，因为我好像也没怎么用过 sdb 来调试，而且 difftest 不用的时候我就直接关掉了
- PA4.2 添加分页机制后暴露出了 NEMU 的特权级管理没做好，导致 difftest 出现了问题（mstatus 对不上，或者访存权限异常），调了半天没调好，暂时放弃了（~~反正快到时钟中断也要抛弃 difftest 了~~）
- PA4.3 内核栈用户栈切换，还有前面的分页机制配合起来，可能还需要再深入理解理解
- PA4.3 最后选做的运行 ONScripter 部分都没有做（有声音和磁盘的内容）
- 最后关于 ISA，x86 的看起来也有点意思（虽然取指译码看起来有些繁琐），而且以后应该也会较多接触，或许可以看看。mips 的后期看起来就有点痛苦面具，包括 difftest 分支延迟的处理，还有奇怪分页机制什么的，可能不会尝试