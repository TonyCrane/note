---
counter: True
comment: True
---

# RV64 用户模式

!!! abstract
    计算机系统 Ⅲ lab4 实验报告（2023.05.11 ~ 2023.05.25）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- 创建用户态进程，实现内核态和用户态的切换
- 分开设置用户栈和内核栈，并正确切换
- 补充异常处理程序，实现系统调用（write、getpid）功能
- 思考题
    1. 拷贝内核页表为什么可以直接在虚拟地址空间上赋值
    2. 系统调用返回为什么不能直接修改寄存器，要修改 regs 结构体中内容
    3. 针对系统调用，为什么要手动将 sepc + 4
    4. head.S 中为什么要将 sstatus[SIE] 置 0

## 实验过程

### 实验准备
按照实验指导中说的准备就可以。其中没有明确说明的一处是在根目录 Makefile 中添加 user 文件夹的子 make 规则的位置，由于 arch/riscv 中需要依赖 user 中生成的 .o 来链接，所以在这之前即可：

```makefile
all:
	${MAKE} -C lib all
	${MAKE} -C init all
	${MAKE} -C user all
	${MAKE} -C arch/riscv all
	@echo -e '\n'Build Finished OK
```

### 创建用户态进程
#### 修改 proc.h
proc.h 中的一些宏定义和结构体定义需要修改。首先是进程数要设为 1+3。然后要修改 thread_struct 结构体，多保存 sepc sstatus sscratch：

```c
struct thread_struct {
    uint64 ra;
    uint64 sp;
    uint64 s[12];
    uint64 sepc, sstatus, sscratch;
};
```

接下来要修改 task_struct，增加页表的记录。这里我没有按照实验指导中的来，而是直接记录了需要的 satp，省去了在汇编中根据页表地址计算 satp 的麻烦。同时还要记录内核栈和用户栈的 sp，虽然开头就有了 thread_info，但是是一个指针变量，不方便存储和使用，删掉还会影响已经写好了的 thread 的偏移，所以就直接在后面添加了 kernel_sp 和 user_sp：

```c 
struct task_struct {
    struct thread_info* thread_info;
    uint64 state;    
    uint64 counter;  
    uint64 priority; 
    uint64 pid;      

    struct thread_struct thread;
    uint64 satp;
    uint64 kernel_sp;
    uint64 user_sp;
};
```

#### 修改 task_init
在 task_init 初始化进程时，需要为用户态进程设置更多的信息。

- 设置用户栈和内核栈：
    - 内核栈：和之前的 thread.sp 等价
        ```c 
        _task->thread.sp = (uint64)_task + PGSIZE;
        _task->kernel_sp = (uint64)_task + PGSIZE;
        ```
    - 用户栈：通过 kalloc() 分配一个新的页
        ```c 
        _task->user_sp = kalloc();
        ```
- 创建自己的页表并设置新映射
    - 申请页表空间，并将内核页表拷贝进去
        ```c 
        uint64* pgtbl = (uint64*)kalloc();
        memcpy(pgtbl, swapper_pg_dir, PGSIZE);
        ```
        - memcpy 需要在 string.c/h 中实现，类似已有的 memset
            ```c
            void *memcpy(void *dst, void *src, uint64 n) {
                char *cdst = (char *)dst;
                char *csrc = (char *)src;
                for (uint64 i = 0; i < n; ++i)
                    cdst[i] = csrc[i];
                return dst;
            }
            ```
    - 将 uapp 映射到 USER_START 开头的虚拟地址空间
        ```c 
        uint64 va = USER_START;
        uint64 pa = (uint64)(uapp_start) - PA2VA_OFFSET;
        create_mapping(pgtbl, va, pa, uapp_end - uapp_start, PTE_R | PTE_W | PTE_X | PTE_U | PTE_V);
        ```
    - 将用户栈映射到 USER_END-PGSIZE 开头的虚拟地址空间
        ```c 
        va = USER_END - PGSIZE;
        pa = (uint64)(_task->user_sp) - PA2VA_OFFSET;
        create_mapping(pgtbl, va, pa, PGSIZE, PTE_R | PTE_W | PTE_U | PTE_V);
        ```
    - 计算 satp 并设置
        ```c 
        uint64 satp = csr_read(satp);
        satp = (satp >> 44) << 44; // 清空 PPN
        satp |= ((uint64)(pgtbl) - PA2VA_OFFSET) >> 12;
        _task->satp = satp;
        ```
- 设置其他的 csr 寄存器初始值
    - 设置 sepc 为 USER_START
        ```c 
        _task->thread.sepc = USER_START;
        ```
    - 修改 sstatus
        - SPP 设为 0（使 sret 返回到用户态）
            ```c 
            sstatus &= ~(1 << 8)
            ```
        - SPIE 设为 1（sret 后开启中断）
            ```c
            sstatus |= (1 << 5)
            ```
        - SUM 设为 1（允许 S 访问 U）
            ```c
            sstatus |= (1 << 18)
            ```
        - 写入 thread
            ```c 
            _task->thread.sstatus = sstatus
            ```
    - 设置 sscratch 为 USER_END
        ```c 
        _task->thread.sscratch = USER_END;
        ```

#### 修改 \_\_switch_to

\_\_switch_to 用于在两个进程之间进行切换，其保存的上下文就是 thread_struct 结构体，而我们增加了三个 csr 寄存器，所以要修改一下这部分，添加对这三个寄存器的保存和恢复：

```text
    sd ra,40(a0)
    ...
    sd s11,144(a0)
    csrr t1, sepc
    sd t1,152(a0)
    csrr t1, sstatus
    sd t1,160(a0)
    csrr t1, sscratch
    sd t1,168(a0)
    csrr t1, satp
    sd t1,176(a0)

    ld ra,40(a1)
    ...
    ld t1,152(a1)
    csrw sepc, t1
    ld t1,160(a1)
    csrw sstatus, t1
    ld t1,168(a1)
    csrw sscratch, t1
    ld t1,176(a1)
    csrw satp, t1
```

由于我直接在 init 的时候就计算好了 satp，并正好存储在了 thread_struct 后面的位置，所以可以在这里同时进行 satp 的保存和恢复。在设置 satp 后还要再加一句 sfence.vma 刷新 TLB 再返回。

### 修改 trap 逻辑等
#### 修改 _traps 实现栈切换
由于如果内核态触发异常则不进行栈切换，所以我们要判断一下 sscratch 是否为 0，不为 0 则交换 sp 和 sscratch 进行栈切换。

```text
_traps:
    csrr t0, sscratch
    beq t0, x0, _ignore_switch
    csrw sscratch, sp
    mv sp, t0

_ignore_switch:
    sd ra, -256(sp)
    ...
```

同理在 _traps 结尾还要同样判断并切换回来

```text
    ...
    csrr t0, sscratch
    beq t0, x0, _traps_sret
    csrw sscratch, sp
    mv sp, t0

_traps_sret:
    sret
```

#### 修改 \_\_dummy 进入用户态进程
首先要切换栈空间到用户栈，也就是 USER_END，即 sscratch 记录的值。然后设置 sepc 为 0，使得 sret 返回时返回到用户态进程代码段开头的虚拟地址：

```text 
__dummy:
    csrr t0, sscratch
    csrw sscratch, sp
    mv sp, t0
    csrwi sepc, 0
    sret
```

### 添加系统调用
#### 扩充 trap_handler 参数
根据实验指导，trap_handler 需要多加一个参数 regs 来引用栈上保存的寄存器值，_traps 中手动调用 trap_handler，参数通过 a0 a1 a2 传递，所以要将正确的栈地址赋值给 a2，然后在 trap_handler 中通过指向一个结构体的指针来解读。

之前在栈上保存寄存器的顺序有些混乱，肯定需要改变，所以为了方便先设计结构体的布局：

```c 
struct pt_regs {
    uint64 x[32];
    uint64 sepc;
};
```

因此 x0-x31 和 sepc 需要从低地址到高地址依次排布，根据这个简单修改保存和恢复寄存器的顺序即可：

```text
    sd ra, -256(sp)
    ...
    sd t6, -16(sp)
    csrr t0, sepc
    sd t0, -8(sp)
    addi sp, sp, -264
    csrr a0, scause
    csrr a1, sepc
    mv a2, sp
    call trap_handler
    ...
    ld t0, 256(sp)
    csrw sepc, t0
    addi sp, sp, 8
    ld t6, 240(sp)
    ...
    ld sp, 8(sp)
```

#### 实现系统调用
系统调用是通过 U 模式下执行 ecall 指令触发的，所以 trap_handler 要捕获的就是 scause == 8 的异常（Environment Call from U-mode），然后当作 syscall 来处理。

接下来 a7 即 x17 的值作为系统调用号，a0-a6 即 x10-x16 的值作为参数，a0 作为返回值。

同时针对系统调用，还需要手动将 sepc + 4，上次 lab 里是在 entry.S 中手动判断并通过汇编加四的，这里直接通过 regs->sepc 修改栈上存储的值，等接下来恢复即可。

```c
struct pt_regs {
    uint64 x[32];
    uint64 sepc;
};

extern struct task_struct* current;

void syscall(struct pt_regs* regs) {
    if (regs->x[17] == SYS_write) {
        if (regs->x[10] == 1) {
            char* buf = (char*)regs->x[11];
            for (int i = 0; i < regs->x[12]; i++) {
                printk("%c", buf[i]);
            }
            regs->x[10] = regs->x[12];
        } else {
            printk("not support fd = %d\n", regs->x[10]);
            regs->x[10] = -1;
        }
    } else if (regs->x[17] == SYS_getpid) {
        regs->x[10] = current->pid;
    } else {
        printk("not support syscall id = %d\n", regs->x[17]);
    }
    regs->sepc += 4;
}

void trap_handler(uint64 scause, uint64 sepc, struct pt_regs* regs) {
    if ((scause >> 63) && (scause & 0x7FFFFFFFFFFFFFFF) == 5) {
        // printk("[S] Supervisor Mode Timer Interrupt\n");
        clock_set_next_event();
        do_timer();
        return;
    } else if (scause == 8) {
        syscall(regs);
        return;
    }
    Log("Unhandled trap: scause = %lx, sepc = %llx", scause, sepc);
}
```

### 修改启动部分
因为想要在内核启动后就立即进行调度，转到用户进程运行，所以要在 start_kernel 中手动调用 schedule() 函数。同时为了避免此时发生时钟中断，要先将 status[SIE] 设置为 0。

```c 
extern void test();
extern void schedule();

int start_kernel(int x) {
    printk("%d", x);
    printk(" ZJU Computer System III\n");

    schedule();

    test(); // DO NOT DELETE !!!

	return 0;
}
```

```r
    ...
    call sbi_set_timer
    # csrr a0, sstatus
    # ori a0, a0, 1 << 1
    # csrw sstatus, a0

    li a0, 2023
    j start_kernel
```

## 实验测试结果
运行结果如下：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab4/run.png" width="100%" style="margin: 0 auto;">
</div>

可见开头出正确为三个用户进程映射建立了页表，然后内核态输出 2023 ZJU Computer System III 后进行调度切换到了用户进程，三个进程依次输出了正确的 pid（第二次调度到 pid 1 的时候由于进程内是在 busy wait，1s 的时间还没到它下一次输出的时候，所以还没有输出）。

## 思考题
### 拷贝内核页表为什么可以直接在虚拟地址空间上赋值
因为之前建立的内核页表包含了内核的所有虚拟地址，拷贝到用户页表中之后用户态就也可以访问那些分配过的虚拟地址了，所以可以直接在虚拟地址空间上赋值。

### 系统调用返回为什么不能直接修改寄存器
因为系统调用是在 trap 中的，trap_handler 执行前后会进行寄存器的保存和恢复，来使得被中断的程序可以“无意识”地回到原来的状态。但系统调用期望在返回时寄存器有所改变，所以要通过 regs 结构体来修改栈上保存的内容，使得恢复的时候寄存器值更新，否则直接修改寄存器后续就又被覆盖了。

### 针对系统调用，为什么要手动将 sepc + 4
因为针对其他中断/异常，比如时钟中断，当前指令被打断了没有执行完毕，后续再回来的时候还要执行这条被打断的指令，所以 sepc = pc。而系统调用的中断是由 ecall 引起的，再回到同一位置则仍会触发 ecall 如此死循环。所以 ecall 这样实际上是想要在处理后跳到下一条指令，所以要手动将 sepc + 4。

### head.S 中为什么要将 sstatus[SIE] 置 0
因为修改了之后在 start_kernel 中直接调用了 schedule 函数，这次调用不同于之前的 schedule，它不在中断处理过程中（之前都是时钟中断引起），所以此时仍会接收中断（之前由中断引起的话，在中断处理过程中就已经拒绝接收其他中断了）。为了保证 schedule 不被其他中断打断，所以要在这之前关闭所有 S 模式下的中断，也就是将 sstatus[SIE] 置 0。这一效果的恢复发生在返回到用户态时，由于 task_init 中 sstatus[SPIE] 设为了 1，所以返回后 SIE 也就变回了 1。