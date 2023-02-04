---
counter: True
comment: True
---

# RV64 内核线程调度

!!! abstract
    计算机系统 Ⅱ lab6 实验报告（2022.12.01 ~ 2022.12.22）

    !!! warning
        仅供学习参考，请勿抄袭

## 实验内容
- 实现线程的切换、调度，并实现两种调度算法
    - 线程初始化
    - 实现线程切换
    - 实现调度入口函数
    - 实现线程调度
        - 短作业优先调度算法
        - 优先级调度算法
- 完成 proc.c、entry.S 等代码编写，并编译运行
- 思考题
    1. 在 RV64 中一共用 32 个通用寄存器，为什么 context_switch 中只保存了 14 个？
    2. 当线程第一次调用时， 其 ra 所代表的返回点是 __dummy。 那么在之后的线程调用中 context_switch 中，ra 保存/恢复的函数返回点是什么呢？请同学用gdb尝试追踪一次完整的线程切换流程，并关注每一次 ra 的变换。


## 代码编写
### 线程初始化
在 proc.c 中实现 task_init 函数，初始化线程：

1. 设置 idle
    - 调用 kalloc 分配物理内存页
        ```c 
        idle = (struct task_struct*)kalloc()
        ```
    - 设置 state 为 TASK_RUNNING
        ```c 
        idle->state = TASK_RUNNING;
        ```
    - idle 不参与调度，将 counter、priority 设置为 0
        ```c 
        idle->counter = 0;
        idle->priority = 0;
        ```
    - 设置 idle 的 pid 为 0
        ```c 
        idle->pid = 0;
        ```
    - 将 current 和 task[0] 指向 idle
        ```c 
        current = idle;
        task[0] = idle;
        ```
2. 初始化 task[1] ~ task[NR_TASKS-1] 线程
    - counter 为 0，priority 为 rand()，pid 为下标
    - ra 为 __dummy 地址，sp 为内存高地址
    ```c 
    for (int i = 1; i < NR_TASKS; ++i) {
        struct task_struct* _task = (struct task_struct*)kalloc();
        _task->state = TASK_RUNNING;
        _task->counter = 0;
        _task->priority = (uint64)rand() % (PRIORITY_MAX - PRIORITY_MIN + 1) + PRIORITY_MIN;
        _task->pid = i;
        _task->thread.ra = (uint64)__dummy;
        _task->thread.sp = (uint64)_task + PGSIZE;
        task[i] = _task;
    }
    ```

### entry.S 中添加 dummy
__dummy 即设置 sepc 为 dummy 函数地址，然后直接 sret 返回，所以代码：
```text
    .extern dummy
    .globl __dummy
__dummy:
    la a0, dummy
    csrw sepc, a0
    sret
```

### 实现线程切换
proc.c 中实现 switch_to 切换函数，如果当前线程 current 和 next 一致则什么都不做，不同则输出信息并调用 __switch_to 切换线程。
```c 
extern void __switch_to(struct task_struct* prev, struct task_struct* next);

void switch_to(struct task_struct* next) {
    if (next != current) {
        printk("\nswitch to [PID = %d PRIORITY = %d COUNTER = %d]\n", next->pid, next->priority, next->counter);
        struct task_struct* prev = current;
        current = next;
        __switch_to(prev, next);
    }
}
```

在 entry.S 中实现上下文切换 __switch_to，接收两个 task_struct 指针作为参数，需要保存当前线程的 ra、sp、s0~s11 寄存器到当前线程的 thread_struct 中，并将下一个线程的寄存器恢复。其中 task_struct 的结构为一个 uint64 大小指针，四个 uint64 大小的值，然后是 thread_struct 结构体，其中是 ra、sp、s[12] 的位置。所以相对于参数的偏移为 5*8=40，所以代码：
```text
    .globl __switch_to
__switch_to:
    sd ra,40(a0)
    sd sp,48(a0)
    sd s0,56(a0)
    ...
    sd s11,144(a0)
    
    ld ra,40(a1)
    ld sp,48(a1)
    ld s0,56(a1)
    ...
    ld s11,144(a1)

    ret
```

### 实现调度入口函数
即实现 proc.c 中的函数 do_timer，其任务：

1. 如果当前线程是 idle 线程或者当前线程运行剩余时间为 0 进行调度
    ```c 
    if (current == idle || current->counter == 0) {
        schedule();
    }
    ```
2. 如果当前线程不是 idle 且运行剩余时间不为 0 则对当前线程的运行剩余时间减 1，减后为 0 也要调度
    ```c 
    else {
        current->counter--;
        if (current->counter == 0) schedule();
    }
    ```

然后在 trap_handler 函数中调用 do_timer：
```c 
void trap_handler(unsigned long scause, unsigned long long sepc) {
    if ((scause >> 63) && (scause & 0x7FFFFFFFFFFFFFFF) == 5) {
        // printk("[S] Supervisor Mode Timer Interrupt\n");
        clock_set_next_event();
        do_timer();
        return;
    }
}
```

### 实现线程调度
根据目标，循环遍历所有线程，选出 counter 最小的一个进行切换，如果所有 counter 都为 0，则使用 priority 为 counter 赋值：
```c 
void schedule(void) {
    uint64 minCounter = UINT64_MAX;
    struct task_struct* next = idle;
    while (1) {
        for (int i = 1; i < NR_TASKS; ++i) {
            if (task[i]->state == TASK_RUNNING && task[i]->counter != 0 && task[i]->counter < minCounter) {
                minCounter = task[i]->counter;
                next = task[i];
            }
        }
        if (next != idle) break;
        for (int i = 1; i < NR_TASKS; ++i) {
            task[i]->counter = task[i]->priority;
            if (i == 1) printk("\n");
            printk("SET [PID = %d PRIORITY = %d COUNTER = %d]\n", task[i]->pid, task[i]->priority, task[i]->counter);
        }
    }
    switch_to(next);
}
```

### 运行结果

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img1.png" width="100%" style="margin: 0 auto;">
</div>

运行结果正确。


## 思考题
### 为什么 context_switch 只保存 14 个寄存器

因为 __switch_to 函数是在 C 语言的 switch_to 函数中调用的。而 C 语言会将 RISC-V 标准中的 Caller 部分存在栈上，所以 __switch_to 中只需要保存 C 语言没有保存的 Callee 部分（sp 以及 s0~s11）以及 ra 即可，一共 14 个寄存器。

### 调试，关注 ra 变化

查看 __switch_to 函数中指令地址：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img2.jpg" width="100%" style="margin: 0 auto;">
</div>

在 0x80200180 出存储 ra，在 0x802001bc 处恢复 ra，所以在这两个位置下断点：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img3.jpg" width="100%" style="margin: 0 auto;">
</div>

运行到第一个断点处观察 ra 值为 switch_to+128，也就是调用 __switch_to 的下一条指令地址：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img4.jpg" width="100%" style="margin: 0 auto;">
</div>
<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img6.jpg" width="100%" style="margin: 0 auto;">
</div>

继续运行到下一个断点，ra 值为 __dummy 地址：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img5.jpg" width="100%" style="margin: 0 auto;">
</div>

（上图中 Stack 部分不正确，因为 gdb 回溯跟丢了 pc，用 bt 指令能看到报错，可以 si 跟到这里来，实际的调用栈是没有变化的）

持续调试，可以发现前三次时保存的 ra 是 switch_to+128，恢复的 ra 是 __dummy；后面保存和恢复的 ra 都是 switch_to+128：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs2/lab6/img8.png" width="59%" style="margin: 0 auto;">
</div>

原因是前三次线程切换时，该线程都是第一次被调度，没有上下文需要恢复，所以 ra 的值为初始化的 __dummy，保存的 ra 值为上一次调用的 ra，也就是 switch_to 中调用 __switch_to 的时候存入的下一条指令地址。而后面的线程切换中，所有线程都已经有了保存的上下文，恢复的 ra 也就都是 switch_to+128 了。