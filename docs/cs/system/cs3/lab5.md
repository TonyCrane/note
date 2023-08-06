---
counter: True
comment: True
---

# RV64 缺页异常处理以及 fork 机制

!!! abstract
    计算机系统 Ⅲ lab5 实验报告（2023.05.18 ~ 2023.06.01）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- 通过 vm_area_struct 数据结构实现对进程多区域虚拟内存的管理
- 在 lab4 实现用户态程序的基础上，添加缺页异常处理 page fault handler
- 为进程加入 fork 机制，能够支持通过 fork 创建新的用户态进程
- 思考题
    1. 根据实现分析父进程在用户态执行 fork 至子进程被调度并在用户态执行的过程，最好能够将寄存器状态的变化过程清晰说明。

## 实验过程

### 实现虚拟内存管理

按照实验指导修改 proc.h 添加 vm_area_struct 等结构。接下来要实现的就是对于 vma 链表的三个操作函数。

- find_vma
    - 遍历 vma 链表，找到包含 addr 的 vma
    ```c 
    struct vm_area_struct *find_vma(struct mm_struct *mm, uint64 addr) {
        struct vm_area_struct *vma = mm->mmap;
        while (vma != NULL) {
            if (addr >= vma->vm_start && addr < vma->vm_end) {
                return vma;
            }
            vma = vma->vm_next;
        }
        return NULL;
    }
    ```
- do_mmap
    - 为进程添加新的 vma
    - 给出的 addr 只是期望的地址，如果有重叠则调用 get_unmapped_area 寻找实际映射的虚拟地址
    - 第一部分：寻找实际映射的虚拟地址范围
        ```c 
        uint64 start_va = PGROUNDDOWN(addr);
        uint64 end_va = PGROUNDUP(addr + length);
        uint64 page_num = (end_va - start_va) / PGSIZE;
        for (uint64 i = 0; i < page_num; ++i) {
            if (find_vma(mm, start_va + i * PGSIZE) != NULL) {
                start_va = get_unmapped_area(mm, length);
                end_va = PGROUNDUP(start_va + length);
                break;
            }
        }
        ```
    - 第二部分：创建 vma 链表项，填充信息并插入链表
        ```c 
        struct vm_area_struct *vma = (struct vm_area_struct *)kalloc();
        vma->vm_start = start_va;
        vma->vm_end = end_va;
        vma->vm_next = mm->mmap;
        vma->vm_mm = mm;
        vma->vm_flags = prot;
        if (mm->mmap != NULL)
            mm->mmap->vm_prev = vma;
        mm->mmap = vma;
        return start_va;
        ```
- get_unmapped_area
    - 从 USER_START 开始，以 PGSIZE 为单位寻找连续 length 长度未分配的虚拟地址
    ```c 
    uint64 get_unmapped_area(struct mm_struct *mm, uint64 length) {
        uint64 addr = USER_START;
        uint64 page_num = length / PGSIZE + (length % PGSIZE != 0);
        for (addr = USER_START; addr < USER_END; addr += PGSIZE) {
            uint64 i;
            for (i = 0; i < page_num; ++i) {
                if (find_vma(mm, addr + i * PGSIZE) != NULL) {
                    addr = addr + i * PGSIZE;
                    break;
                }
            }
            if (i == page_num) {
                return addr;
            }
        }
    }
    ```

### 处理 Page Fault
这一部分要进行两件事情，一个是修改 task_init，使用 demand paging，不直接创建映射，而是使用前面写过的 do_mmap 记录 vma；一个是处理后续会发生的缺页异常，检查后创建映射。

#### task_init
要进行的修改是首先为每个进程创建好 vma 链表，之后再将两次 create_mapping 改为 do_mmap 即可。

这里为了方便将 VM_READ VM_WRITE VM_EXEC 设为了 PTE_R PTE_W PTE_X。

- 创建链表
    ```c 
    _task->mm = (struct mm_struct*)kalloc();
    _task->mm->mmap = NULL;
    ```
- 创建 vma 记录
    ```c 
    do_mmap(_task->mm, USER_START, uapp_end - uapp_start, VM_READ | VM_WRITE | VM_EXEC);
    do_mmap(_task->mm, USER_END - PGSIZE, PGSIZE, VM_READ | VM_WRITE);
    ```

#### page fault handler
在 trap_handler 中补充对于 scause 为 12、13、15 时的处理，均使用同一个 do_page_fault 函数来处理。

do_page_fault 要先进行 bad address 的检查，如果在分配的范围内再创建映射。不能分配的话（不在范围内或者权限不对）结束进程，这里创建一个新的 TASK_EXITED 并设置给 state 再 schedule 就可以了，这个进程之后就不会再调度到了。

- 检查 bad address
    - 范围检查
        ```c 
        uint64 scause = csr_read(scause);
        uint64 stval = csr_read(stval);
        uint64 sepc = csr_read(sepc);
        struct vm_area_struct* vma = find_vma(current->mm, stval);
        if (vma == NULL) {
            ...
        }
        ```
    - 权限检查（12 检查 EXEC，13 检查 WRITE，15 检查 READ）
        ```c 
        if (vma == NULL || (
            scause == 12 && !(vma->vm_flags & VM_EXEC)) ||
            scause == 13 && !(vma->vm_flags & VM_WRITE) ||
            scause == 15 && !(vma->vm_flags & VM_READ
        )) {
            printk("[pid = %d] page fault at [0x%lx] with cause = %d\n", current->pid, stval, scause);
            current->state = TASK_EXITED;
            schedule();
            return;
        }
        ```
- 创建映射
    - 如果是 12 则映射 uapp_start 之后的物理地址，否则 kalloc 创建新页作为物理地址
    - 因为这里要修改页表，而我在上一个 lab 中将 task_struct 中的页表地址改为了 satp，为了避免计算麻烦，所以又新加了一个 pgtbl 表示页表地址，并在创建进程的时候同时记录 pgtbl 和 satp
    ```c 
    if (scause == 12) {
        uint64 va = PGROUNDDOWN(stval);
        uint64 pa = (uint64)(uapp_start) + (va - USER_START) - PA2VA_OFFSET;
        uint64 perm = vma->vm_flags | PTE_U | PTE_V;
        create_mapping(current->pgtbl, va, pa, PGSIZE, perm);
    } else {
        uint64 va = PGROUNDDOWN(stval);
        uint64 pa = (uint64)kalloc() - PA2VA_OFFSET;
        uint64 perm = vma->vm_flags | PTE_U | PTE_V;
        create_mapping(current->pgtbl, va, pa, PGSIZE, perm);
    }
    ```

trap_handler 里的修改就直接添加一个 else if 就好了

```c 
    ...
    } else if (scause == 12 || scause == 13 || scause == 15) {
        do_page_fault(regs);
        return;
    } ...
```

### 实现 fork
这部分要实现的就是，proc.c 中初始化进程的逻辑，更新 syscall 函数，实现 do_fork 功能，更新 page fault 处理。

我的实现中将 NR_TASKS 设置为允许的最大进程数，根据最后的测试，应该是 1+4，然后 proc.c 中创建一个新的变量 nr_tasks 记录当前实际存在的用户进程数，用于更新 pid。

#### 更新 syscall
trap_handler 不需要修改，只需要在 syscall 函数中判断 a7 是否为 SYS_clone 即可：

```c 
    ...
    } else if (regs->x[17] == SYS_clone) {
        regs->x[10] = do_fork(regs);
    } ...
```

#### 实现 do_fork
do_fork 即创建一个新的进程，所以主体的逻辑和 task_init 中初始化用户进程差不多。

- 创建 task 并设置 state counter priority pid
    ```c 
    struct task_struct *_task = (struct task_struct *)kalloc();
    _task->state = TASK_RUNNING;
    _task->counter = 0;
    _task->priority = (uint64)rand() % (PRIORITY_MAX - PRIORITY_MIN + 1) + PRIORITY_MIN;
    _task->pid = ++nr_tasks;
    ```
- 设置用户栈 sp、内核栈 sp，并拷贝当前进程的用户栈内容到子进程用户栈
    ```c 
    _task->user_sp = kalloc();
    memcpy((void *)_task->user_sp, (void *)current->user_sp, PGSIZE);
    _task->kernel_sp = (uint64)_task + PGSIZE;
    ```
- 设置 thread 结构体信息
    - thread.ra 为 forkret 函数地址
    - thread.sp 为内核栈 sp
    - thread.sscratch 为内核栈 sp
    - thread.sepc 和当前 sepc 一样，sstatus 同理设置
    ```c 
    _task->thread.ra = (uint64)forkret;
    _task->thread.sp = (uint64)_task + PGSIZE;
    _task->thread.sscratch = (uint64)_task + PGSIZE;
    _task->thread.sepc = regs->sepc;
    uint64 sstatus = current->thread.sstatus;
    sstatus &= ~(1 << 8);
    sstatus |= (1 << 5);
    sstatus |= (1 << 18);
    _task->thread.sstatus = sstatus;
    ```
- 创建新的页表，拷贝内核页表，并设置 satp
    ```c 
    uint64 *pgtbl = (uint64 *)kalloc();
    memcpy(pgtbl, swapper_pg_dir, PGSIZE);
    uint64 satp = csr_read(satp);
    satp = (satp >> 44) << 44;
    satp |= ((uint64)(pgtbl) - PA2VA_OFFSET) >> 12;
    _task->satp = satp;
    _task->pgtbl = pgtbl;
    ```
- 创建 vma 链表并拷贝当前进程已创建的记录
    ```c 
    _task->mm = (struct mm_struct *)kalloc();
    _task->mm->mmap = NULL;
    struct vm_area_struct *vma = current->mm->mmap;
    while (vma != NULL) {
        do_mmap(_task->mm, vma->vm_start, vma->vm_end - vma->vm_start, vma->vm_flags);
        vma = vma->vm_next;
    }
    ```
- 创建一个新的 trapframe，拷贝当前进程寄存器到其中
    ```c 
    _task->trapframe = (struct pt_regs *)kalloc();
    for (int i = 0; i < 32; ++i) {
        _task->trapframe->x[i] = regs->x[i];
    }
    _task->trapframe->sepc = regs->sepc;
    ```
    - 特别设置 sp，因为进入 trap_handler 后切换了用户栈和内核栈，所以此时 regs->x[2] 实际为内核栈 sp，而这之前的用户栈 sp 交换到了 sscratch 中，所以要将 sscratch 赋给 x[2]
        ```c
        uint64 sscratch = csr_read(sscratch);
        _task->trapframe->x[2] = sscratch;
        ```
    - 特别设置 a0，子进程的 fork 返回值，为 0
        ```c 
        _task->trapframe->x[10] = 0;
        ```
- 将新建的 _task 添加到 task 列表中，并返回子进程 pid 作为父进程 fork 的返回值
    ```c 
    task[nr_tasks] = _task;
    return _task->pid;
    ```

这之后需要实现的是 forkret 函数，即子进程初始的跳转位置，子进程到这里之后要继续跳转到 ret_from_fork，并提供进程的 trapframe 作为参数：

```c 
extern void ret_from_fork(struct pt_regs *regs);
void forkret() {
    ret_from_fork(current->trapframe);
}
```

而 ret_from_fork 则在 trap.S 中直接 ld 回所有的寄存器以及 sepc，再 sret 即可：
```r
.globl ret_from_fork
ret_from_fork:
    ld t1, 256(a0)
    addi t1, t1, 4 # manually sepc+=4
    csrw sepc, t1
    ld ra, 8(a0)
    ...
    ld s1, 72(a0)
    # restore a0 last
    ld a1, 88(a0)
    ...
    ld t6, 248(a0)
    ld a0, 80(a0)
    sret
```

#### 更新 page fault
因为 do_fork 的时候已经拷贝了用户栈，但没有更新页表，所以子进程开始运行的时候仍会触发 page fault，这时会创建新的用户栈，为了避免这个，我们可以通过 user_sp 来区分，我们在初始化进程的时候设置 user_sp 为 0，然后 do_page_fault 中映射栈空间时检查 user_sp 是否为 0，如果为 0 则调用 kalloc 分配，否则（即表示是 fork 来的）直接使用 user_sp 作为物理地址。

```c 
     } else {
        if (current->user_sp == 0) {
            current->user_sp = kalloc();
        }
        uint64 va = USER_END - PGSIZE;
        uint64 pa = current->user_sp - PA2VA_OFFSET;
        uint64 perm = vma->vm_flags | PTE_U | PTE_V;
        create_mapping(current->pgtbl, va, pa, PGSIZE, perm);
    }
```

## 实验测试结果
### 第一个 main
<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab5/main1.png" width="100%" style="margin: 0 auto;">
</div>

可以根据 log 看到 proc_init 时进行的 do_mmap，以及在每个进程运行时触发两次预期中的 page fault，每次之后触发了 create_mapping，然后进程正常运行。

### 第二个 main
<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab5/main2.png" width="100%" style="margin: 0 auto;">
</div>

可以看到 proc_init 只创建了一个进程，然后进入 main 后调用了 fork，fork 中进行了 do_mmap 有 log 输出。然后直接返回到父进程中，fork 返回值结果为 2 即子进程 pid，然后输出了父进程的信息。

之后进程调度切换到了子进程中，同样触发了两次 page fault 进行了映射创建，然后正常执行，得到 fork 返回值为 0，输出了子进程信息。后续没在截图中，但都在一直正常运行。

### 第三个 main
这部分 do_mmap create_mapping 和 page fault 的 log 输出过多影响观察，所以将那些 log 禁用了：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab5/main3.png" width="100%" style="margin: 0 auto;">
</div>

可以看到 pid 1 先 fork 出了 2，然后 fork 出了 3，之后调度到子进程 2 时又通过代码中第二个 fork 创建了 4 号进程，然后四个进程一直在正常运行，符合预期。

## 思考题

**根据实现，分析父进程在用户态执行 fork 至子进程被调度并在用户态执行的过程，最好能够将寄存器状态的变化过程清晰说明。**

父进程在用户态执行 fork，即调用了 ecall，触发了 Environment Call from U-mode 异常，被捕获，进入到 _traps 中，修改 sp 到内核栈（原 sp 保存到 sscratch 中），然后将寄存器（pt_regs）保存到内核栈上。处理参数，进入到 trap_handler 中，判断 scause 为 8，进入到 syscall 函数中，判断 x7 为 SYS_clone，调用 do_fork(regs)。

do_fork 中创建了子进程，相关寄存器设置为了内核栈上保存的寄存器值，但需要修改 sp，因为栈上保存的是内核栈 sp，需要改为 sscratch 中存放的之前的用户栈当前 sp。以及修改 a0 为 0，即 fork 返回值为 0。除此之外需要注意的是 thread.ra 设置为了 forkret，稍后要用到。

do_fork 结束后返回了子进程 pid，写入了 a0 中，trap_handler 结束，恢复栈上寄存器值，切换内核栈和用户栈，从内核态返回，fork 系统调用结束，父进程正常继续运行。

子进程被调度到后，进行 __switch_to，保存父进程上下文信息，恢复子进程上下文，子进程上下文除了 ra 以外都不重要，ra 导致返回跳转到了 forkret 位置，其中调用了 ret_from_fork，参数为当前进程的 trapframe 地址。ret_from_fork 中将 trapframe 中的寄存器值全部恢复，设置好 sepc 为系统调用 ecall 的下一条地址，通过 sret 返回到用户态 ecall 下一条地址的位置，继续执行。此时的寄存器状态就是 do_fork 中设置的子进程寄存器值，所以正确设置好了 sp 值以及 a0，得到了 fork 返回值为 0，剩下的就是子进程在用户态正常执行了。