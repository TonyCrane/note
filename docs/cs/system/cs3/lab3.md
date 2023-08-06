---
counter: True
comment: True
---

# RV64 虚拟内存管理

!!! abstract
    计算机系统 Ⅲ lab3 实验报告（2023.04.27 ~ 2023.05.11）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- 基于系统二 lab6 代码实现 Sv39 虚拟内存管理
- 具体要实现 vm.c 中要求的功能，更新完善 head.S mm.c 等
- 思考题
    1. 验证 .text, .rodata 段的属性是否成功设置，给出截图。
    2. 思考线性映射时能否不对 opensbi 所在的区域进行映射，给出你的理由。
    3. 为什么需要在修改页表后执行 sfence.vma 指令？

## 虚拟内存映射的实现

### 建立临时页表
这一步内要实现 setup_vm 函数，在其中建立临时页表，将 0x80000000 开始的 1GB 空间映射到虚拟内存高地址处。然后修改 head.S，在最开头就调用 setup_vm 创建页表，然后更新 ra sp 寄存器的值到虚拟内存空间，再设置 satp 寄存器使页表生效并用 sfence.vma 刷新。

#### 实现 setup_vm
首先在 defs.h 里面添加一些宏定义方便后续使用：

```c
// 来自实验手册
#define OPENSBI_SIZE (0x200000)

#define VM_START (0xffffffe000000000)
#define VM_END   (0xffffffff00000000)
#define VM_SIZE  (VM_END - VM_START)

#define PA2VA_OFFSET (VM_START - PHY_START)

// 取出虚拟地址中的三个虚拟页号
#define VPN0(va) (((uint64)(va) >> 12) & 0x1ff)
#define VPN1(va) (((uint64)(va) >> 21) & 0x1ff)
#define VPN2(va) (((uint64)(va) >> 30) & 0x1ff)
// 页表项中末尾的权限位
#define PTE_V 0x001
#define PTE_R 0x002
#define PTE_W 0x004
#define PTE_X 0x008
#define PTE_U 0x010
#define PTE_G 0x020
#define PTE_A 0x040
#define PTE_D 0x080

// 来自 NJU PA 实验，输出更醒目的调试信息
#define Log(format, ...) \
    printk("\33[1;35m[%s,%d,%s] " format "\33[0m\n", \
        __FILE__, __LINE__, __func__, ## __VA_ARGS__)
```

setup_vm 函数需要先清空 early_pgtbl，然后建立一个页表项即可。

由于这里只进行 1GB 的线性映射，所以取中间 9 bit 作为 index 即可，后 30 bit 都是页内偏移。这样中间的 9 bit 正好对应了三级页表中的 VPN2 位置，可以使用前面的宏来提取。页表项的内容也是只设置 PPN2 对应的位置就可以（也就是 28 位及以上），最后的权限位设置为 V | R | W | X：

```c 
void setup_vm(void) {
    memset(early_pgtbl, 0x0, PGSIZE);
    uint64 pa = PHY_START, va = VM_START;
    int index = VPN2(va);
    early_pgtbl[index] = (((pa >> 30) & 0x3ffffff) << 28) | PTE_V | PTE_R | PTE_W | PTE_X;
}
```

#### 启用临时页表
根据指导，修改 head.S 中 _start 开头为：

```text
_start:
    la sp, boot_stack_top

    call setup_vm
    call relocate

    call mm_init
    ...
```

然后在 relocate 中实现对于 ra sp 的更新、satp 的设置以及 TLB 的刷新：

```r
relocate:
    li t0, 0xffffffdf80000000 # PA2VA_OFFSET
    add ra, ra, t0
    add sp, sp, t0

    # set satp with early_pgtbl‘s physical address
  
    la t0, early_pgtbl
    li t1, 8
    slli t1, t1, 60     # mode 部分设置为 8
    srli t0, t0, 12     # PPN 部分设置为页表物理地址右移 12 位
    or t0, t0, t1
    csrw satp, t0
  
    # flush tlb
    sfence.vma zero, zero

    ret
```

这之后 make run 也可以正常运行。

### 建立正式页表
这一部分要建立正式的三级页表，以 page 为单位创建映射并设置权限。并且创建页表的时候会申请内存，在 mm_init 函数中要进行一下修改，将可用地址修改为虚拟内存地址：

```c
void mm_init(void) {
    kfreerange(_ekernel, (char *)(PHY_END+PA2VA_OFFSET));
    Log("...mm_init done!");
}
```

setup_vm_final 函数中针对 .text 段、.rodate 段和剩余部分分别进行映射，设置不同的权限。每次映射调用了 create_mapping 函数，第一个参数就是根页表地址，然后是映射开始的虚拟地址、物理地址以及大小，最后一个参数是权限。所以可以先来实现 setup_vm_final 再来实现内部的 create_mapping。

#### 实现 setup_vm_final
同样清空这部分页空间，然后逐个段设置映射。这里修改了一下指导中的代码：

```c
extern char _stext[];
extern char _srodata[];
extern char _sdata[];
extern char _sbss[];
```

然后直接使用这些符号就可以表示段起始地址了。

- 设置 text 段（可读可执行）
    ```c
    uint64 va = VM_START + OPENSBI_SIZE;
    uint64 pa = PHY_START + OPENSBI_SIZE;
    create_mapping(swapper_pg_dir, va, pa, _srodata - _stext, PTE_X | PTE_R | PTE_V);
    ```
- 设置 rodata 段（可读）
    ```c
    va += _srodata - _stext;
    pa += _srodata - _stext;
    create_mapping(swapper_pg_dir, va, pa, _sdata - _srodata, PTE_R | PTE_V);
    ```
- 设置剩余部分（可读可写）
    ```c
    va += _sdata - _srodata;
    pa += _sdata - _srodata;
    create_mapping(swapper_pg_dir, va, pa, PHY_SIZE - (_sdata - _stext), PTE_W | PTE_R | PTE_V);
    ```
- 计算 satp 寄存器的值并写入
    ```c 
    // 这里要计算对应的物理地址，然后右移
    uint64 _satp = (((uint64)(swapper_pg_dir) - PA2VA_OFFSET) >> 12) | (8L << 60);
    csr_write(satp, _satp);
    Log("set satp to %lx", _satp);
    ```
- 刷新 TLB 并返回
    ```c 
    asm volatile("sfence.vma zero, zero");
    return;
    ```

#### 实现 create_mapping
要逐页添加映射，所以基本框架为：

```c
void create_mapping(uint64 *pgtbl, uint64 va, uint64 pa, uint64 sz, int perm) {
    Log("root: %lx, [%lx, %lx) -> [%lx, %lx), perm: %x", pgtbl, pa, pa+sz, va, va+sz, perm);
    uint64 va_end = va + sz;
    uint64 *now_tbl, now_vpn, now_pte;
    while (va < va_end) {
        ...
        va += PGSIZE;
        pa += PGSIZE;
    }
}
```

其中省略号的部分要实现三级页表的查询，如果不存在（PTE_V 位不为 1）则分配新的一页来存放。

- 第一级
    - 从根页表取出第一级 PTE，以及虚拟地址对应的 VPN2
        ```c 
        now_tbl = pgtbl;
        now_vpn = VPN2(va);
        now_pte = *(now_tbl + now_vpn);
        ```
    - 检查 PTE_V 位是否为 1，如果不是则分配新的页
        - 新页对应页表项为 (物理地址>>12)<<10 再加上 PTE_V
        - 计算后写入根页表对应位置的 PTE
        ```c 
        if ((now_pte & PTE_V) == 0) {
            uint64 new_page_phy = (uint64)kalloc() - PA2VA_OFFSET;
            now_pte = ((uint64)new_page_phy >> 12) << 10 | PTE_V;
            *(now_tbl + now_vpn) = now_pte;
        }
        ```
- 第二级
    - 类似第一级，页表地址要从第一级得到的 PTE 中提取，VPN 使用 VPN1
    ```c 
    now_tbl = (uint64*)(((now_pte >> 10) << 12) + PA2VA_OFFSET);
    now_vpn = VPN1(va);
    now_pte = *(now_tbl + now_vpn);
    if ((now_pte & PTE_V) == 0) {
        uint64 new_page_phy = (uint64)kalloc() - PA2VA_OFFSET;
        now_pte = ((uint64)new_page_phy >> 12) << 10 | PTE_V;
        *(now_tbl + now_vpn) = now_pte;
    }
    ```
- 第三级
    - 最后一级，页表地址从第二级得到的 PTE 中提取，VPN 使用 VPN0
    - 不再需要检查 PTE
    - 需要设置权限
    ```c 
    now_tbl = (uint64*)(((now_pte >> 10) << 12) + PA2VA_OFFSET);
    now_vpn = VPN0(va);
    now_pte = ((pa >> 12) << 10) | perm | PTE_V;
    *(now_tbl + now_vpn) = now_pte;
    ```

#### 调用 setup_vm_final
在 mm_init 后调用 setup_vm_final 即可：

```text 
_start:
    la sp, boot_stack_top

    call setup_vm
    call relocate

    call mm_init
    call setup_vm_final
    call task_init
```

## 实验测试结果
修改一下 proc.c 中输出部分的代码，输出 current 地址就可以了。运行结果（1+3 线程）

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab3/image1.png" width="80%" style="margin: 0 auto;">
</div>

1+31 线程：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab3/image2.png" width="80%" style="margin: 0 auto;">
</div>

可见已经正常启用虚拟内存。

## 思考题
### 验证 .text, .rodata 段的属性是否成功设置
程序可以执行说明 .text 段有执行权限，接下来验证 .rodata 段是否有执行权限。方法是在 head.S 中跳转到 start_kernel 的地方跳转到 _srodata 符号的位置进行尝试。如果没有执行权限则会触发异常转到 trap_handler 中。

trap_handler 中只特殊处理了时钟中断，对于其他情况我们输出 scause 和 sepc：

```c 
void trap_handler(unsigned long scause, unsigned long long sepc) {
    if ((scause >> 63) && (scause & 0x7FFFFFFFFFFFFFFF) == 5) {
        // printk("[S] Supervisor Mode Timer Interrupt\n");
        clock_set_next_event();
        do_timer();
        return;
    }
    Log("scause = %lx, sepc = %llx", scause, sepc);
}
```

但是这样会导致 sret 时一直跳转到同一位置，所以要手动给 sepc 加 4。目前框架的写法最简单的就是在 entry.S 中特判，如果不是时钟中断则给 sepc 加四再写回：

```python 
    call trap_handler

    # -----------

        # 3. restore sepc and 32 registers (x2(sp) should be restore last) from stack

    ld t0, 0(sp)

    # temporarily add 4 to sepc manually
    li t1, 0x8000000000000005
    csrr a0, scause
    beq a0, t1, _csrwrite
    addi t0, t0, 4
_csrwrite:

    csrw sepc, t0
    addi sp, sp, 8
    
    ld t6, 0(sp)  
    ld t5, 8(sp)  
```

运行（即直接 j _srodata）：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab3/image3.png" width="100%" style="margin: 0 auto;">
</div>

可以发现触发了异常，输出的 scause 为 0xc 即 Instruction Page Fault，说明 .rodata 段不可执行（也就是不能从那里读取指令）。

接下来验证 .text 段和 .rodata 段是否可读可写，做法就是在 start_kernel 函数中直接访问 _stext 和 _srodata 起始的字节：

```c 
printk("_stext = %x\n", *_stext);       // 读
printk("_srodata = %x\n", *_srodata);
*_stext = 0;                            // 写
*_srodata = 0;
printk("_stext = %x\n", *_stext);
printk("_srodata = %x\n", *_srodata);
```

运行结果：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/cs/system/cs3/lab3/image4.png" width="100%" style="margin: 0 auto;">
</div>

可以发现读取全部正常，写入的两条触发了异常，scause 为 0xf 即 Store/AMO Page Fault，说明 .text 和 .rodata 段都不可写。完全符合预期，权限均正常设置。

### 线性映射时能否不对 OpenSBI 所在的区域进行映射

可以，因为 OpenSBI 部分的代码都是在 M 态下执行的，可以直接访问物理地址，不需要进行映射。

验证的话可以在 setup_vm 中将 va 和 pa 都加上 OpenSBI 的长度偏移：

```c 
void setup_vm(void) {
    memset(early_pgtbl, 0x0, PGSIZE);
    uint64 pa = PHY_START + OPENSBI_SIZE, va = VM_START + OPENSBI_SIZE;
    int index = VPN2(va);
    early_pgtbl[index] = (((pa >> 30) & 0x3ffffff) << 28) | PTE_V | PTE_R | PTE_W | PTE_X;
}
```

可以无差别地正常运行，说明可以不对 OpenSBI 所在区域进行映射。

### 为什么需要在修改页表后执行 sfence.vma 指令
因为为了提高虚拟地址与物理地址转换的效率，RISC-V 采用了 TLB（Translation Lookaside Buffer）缓存页表项。但是在修改了 satp 更换了页表之后，TLB 中缓存的部分就不再有效了，需要执行 sfence.vma 指令来清空 TLB，保证后续地址转换正常执行。
