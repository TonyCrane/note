---
counter: True
comment: True
---

# 软件安全机制

!!! abstract
    软件安全 lab4 实验报告（2023.06.10 ~ 2023.07.02）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- Task 1: No eXecute bit
    - 使用 NX bit enable/disable 分别编译 sbof2
    - 使用 checksec 对两个程序进行分析
    - 使用 lab-01 答案的本地攻击脚本对两个程序进行攻击
    - 截图、说明二者的差异，解读报错信息
- Task 2: Canary
    - 使用 canary enable/disable 分别编译 sbof1
    - 使用 checksec 对两个程序进行分析
    - 使用 lab-01 答案的本地攻击脚本对两个程序进行攻击
    - 截图、说明二者的差异，解读报错信息
    - 对 sbof1-harden 进行逆向，对其中任意一个函数首尾部分进行反汇编分析
    - 画出开启 canary 与不开启的栈结构
    - 在报告中回答 canary 低位为 0 的原因
- Task 3: PIE
    - 使用 PIE enable/disable 分别编译 sbof1
    - 使用 checksec 对两个程序进行分析
    - 使用 lab-01 答案的本地攻击脚本对两个程序进行攻击
    - 截图、说明二者的差异，解读报错信息
    - 编写一个打印 main 地址的程序，比较开启 PIE 与不开启的 main 地址
        - 注意地址随机化的粒度
- Task 4: SECCOMP
    - 安装 seccomp 相关库和工具，编译 ban.c 和 no-ban.c
    - 使用 checksec 对两个程序进行分析
    - 使用 seccomp-tools 对两个程序进行分析
- Task Bonus: CFI
    - 使用 CFI enable/disable 分别编译 password
    - 使用 checksec 对两个程序进行分析
    - 分别对两个程序进行攻击，说明差异，对报错信息进行解读
    - 对两个程序的 main 函数进行反汇编，对比分析哪些控制流边被加固，哪些没有

## No eXecute bit

关闭 NX 编译 sbof2，checksec，攻击：

![](/assets/images/sec/software/lab4/nx_dis.png)

开启 NX 编译 sbof2，checksec，攻击：

![](/assets/images/sec/software/lab4/nx_en.png)

NX disabled 情况下攻击正常，enabled 时程序提前抛出 SIGSEGV，即段错误，反映了栈上数据段没有执行权限，被禁止所以抛出段错误。

## Canary

关闭 Canary 编译 sbof1，checksec，攻击：

![](/assets/images/sec/software/lab4/canary_dis.png)

开启 Canary 编译 sbof1，checksec，攻击：

![](/assets/images/sec/software/lab4/canary_en.png)

Canary disabled 情况下攻击正常，enabled 时程序打印出 `*** stack smashing detected ***: terminated`，检测到了栈溢出破坏了 canary，抛出了 SIGABRT 终止程序，攻击失败。

使用 objdump 看一下 func 函数首尾部分的反汇编：

```text
000000000040123f <func>:
  40123f:       f3 0f 1e fa             endbr64 
  401243:       55                      push   rbp
  401244:       48 89 e5                mov    rbp,rsp
  401247:       48 83 ec 60             sub    rsp,0x60
  40124b:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
  401252:       00 00 
  401254:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
  ...
  4012c3:       48 8b 45 f8             mov    rax,QWORD PTR [rbp-0x8]
  4012c7:       64 48 2b 04 25 28 00    sub    rax,QWORD PTR fs:0x28
  4012ce:       00 00 
  4012d0:       74 05                   je     4012d7 <func+0x98>
  4012d2:       e8 e9 fd ff ff          call   4010c0 <__stack_chk_fail@plt>
  4012d7:       c9                      leave  
  4012d8:       c3                      ret
```

函数开头先将 fs:0x28 的值保存到栈上 [rbp-0x8]，即取出进程对应的 canary 放在栈上。函数结尾取出栈上 [rbp-0x8] 的值，与 fs:0x28 的值比较，如果相等则跳转 leave ret，否则调用 __stack_chk_fail 打印 detected 信息并抛出 ABORT 信号。

所以开不开启 canary 栈上的结构如下：

![](/assets/images/sec/software/lab4/canary_stack.png)

Canary 的低位一定为 0，这是为了保证在将局部变量当作字符串输出的时候，即使末尾没有 \0 也一定会在输出 canary 内容前截断，避免无意泄露 canary 的值。

## PIE

PIE disabled 的情况和前面 Canary disabled 的一样，这里就不再放截图了。

PIE enabled 的编译、checksec、攻击：

![](/assets/images/sec/software/lab4/pie_en.png)

可以发现程序跑出了 SIGSEGV 段错误，说明我们修改 return address 的地址不再是后门的地址，而是不可执行的段，所以程序抛出了段错误，可以看出 main 函数的地址被随机化了。

再写一个程序打印 main 地址：

```c
#include <stdio.h>

int main() {
    printf("main: %p\n", main);
    return 0;
}
```

在两种情况下进行编译运行：

<div style="text-align: center; margin-top: 5px;">
<img src="/assets/images/sec/software/lab4/pie.png" width="35%" style="margin: 0 auto;">
</div>

可以发现没开启 PIE 的情况下输出的 main 函数地址都是 0x401136，而开启 PIE 后的地址每次都不同。同时也可以发现，开启 PIE 后地址都是 0x5????????149，说明低 12 位是不变的。

## SECCOMP

按照实验指导安装好库和工具，编译 no-ban.c、checksec、seccomp-tools dump：

![](/assets/images/sec/software/lab4/seccomp-noban.png)

编译 ban.c、checksec、seccomp-tools dump：

![](/assets/images/sec/software/lab4/seccomp-ban.png)

可以发现二者 checksec 没有区别，都是满保护（gcc 编译默认开启）。ban 程序不可以正常执行，因为有 invalid system call。在 seccomp-tools dump 的时候 no-ban 程序因为可以正常执行，所以没有输出任何 seccomp 相关信息。而 ban 程序设置了 seccomp，在 dump 的时候输出了 seccomp 相关逻辑的反汇编，即架构不是 x86_64 就终止，系统调用号为 execve 的情况下 kill，其他情况下 allow。

## CFI

对两个编译好的程序 checksec：

![](/assets/images/sec/software/lab4/cfi_checksec.png)

发现保护都一样。然后进行攻击（八个 A 占满 pass，然后写入地址覆盖 func）：

![](/assets/images/sec/software/lab4/cfi_attack.png)

发现没开启 CFI 的程序可以正常覆盖 func 到 success，而开启了 CFI 的程序会抛出 illegal hardware instruction 终止程序继续运行。

在 IDA 中打开反汇编，观察两个程序的 main 函数（左开启右关闭）：

<div style="text-align: center; margin-top: 5px;">  
<img src="/assets/images/sec/software/lab4/cfi_ida.png" width="100%" style="margin: 0 auto;">
</div>

可以发现在 scanf 之前的部分除了栈结构有略微差别之外都完全相同。在 scanf 后要调用 a.func，这时没开启 CFI 的程序直接调用跳转到了栈上存的地址。而开启了 CFI 的程序先将目的地址与 auth 函数地址进行比较，如果相同则 call，否则执行一条 ud2 指令，抛出 illegal hardware instruction 终止程序。

所以调用 a.func 的控制流边被加固了，因为编译器知道这里可能会被修改，而且只应该跳转到 auth 函数的地址，所以加了一层检查。而调用 printf scanf 等函数的控制流边都没有被加固，因为这里不会被修改。
