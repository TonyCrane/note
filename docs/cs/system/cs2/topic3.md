---
counter: True
comment: True
---

# 操作系统结构与系统调用

!!! abstract
    计算机系统 Ⅱ 第 9 至 10 周课程内容

## 操作系统服务
- 用户角度
    - 用户接口（UI，User interface）
        - CLI（Command Line Interface / Command Interpreter）或 GUI
        - CLI 通过 shell 程序
        - 命令就是要执行的程序的名字
            - 寻找程序：通过 PATH 环境变量
        - fork 出一个子进程进行执行
    - 程序执行
    - I/O 操作
    - 文件系统操作
    - 错误处理
- 系统角度
    - 分配资源
        - 当多用户/多程序运行时，需要分配资源
        - 包括 CPU、内存、文件、I/O 设备等
    - 记录用户、日志
    - 保护安全
        - 访问控制
        - 进程隔离
        - ……
- 程序角度
    - 通过 system call 系统调用来接触操作系统服务
    - system call 是程序访问操作系统服务的接口
    - 经常通过 API（Application Programming Interface）来使用、发起系统调用
        - Win32 API、POSIX API、……

## 系统调用
### 系统调用实现
- 一个系统调用对应了一个编号
    - Linux 有 340 左右个系统调用（x86 349 个、arm 345 个）
- 进行系统调用的时候通过 int/swi/ecall（不同架构）指令触发中断
    - CPU 将用户态变到内核态，并将 pc 改为处理程序位置
    - 处理程序通过系统调用号来调用相应的系统调用处理程序
- 用户态向内核态传递参数的方式
    - 通过寄存器传递
        - 在切换到内核态之后，读取之前设定好的规定的寄存器值作为参数
        - 简单，但可能不够放
    - 通过 Block 传递
        - 将参数放在内存中作为一个 Block / Table
        - 通过寄存器传递 Block 的地址
        - Linux 使用的方式
    - 通过栈传递
        - 将参数放在/压入栈（内存）中
        - 操作系统将参数从栈中 pop 出来

        ???+ note "有关栈"
            所说的栈其实不是硬件中真正存在的栈结构，而是内存，通过一种栈的形式来使用。

            push、pop 也是伪指令，实际上做的是操作内存，修改指针。

            硬件中也确实有栈结构，称为硬件栈（Hardware Stack）或者影子栈（Shadow Stack），对于用户、系统都是隐藏的，是用于保护安全的：

            - 调用函数的时候，会将当前调用的返回地址写到当前运行的“栈”里面，用来返回
            - 同时也会将返回地址拷贝一份放入影子栈里面
            - 在函数返回的时候，会比较当前“栈”里的返回地址和影子栈里的返回地址：
                - 如果不一致，说明返回地址可能被恶意覆写
                    - 抛出异常并终止程序
                    - 也有可能以影子栈中的返回地址为准进行返回
                - 如果一致，则正常返回继续执行

一些例子：

- Linux/x86 的 execve 系统调用
    - `#!c execve("/bin/sh", 0, 0)`
    - eax 中存储系统调用号 0x0b
    - ebx 中存储第一个参数（"/bin/sh" 的地址）
    - ecx 存储第二个参数 0，edx 存储第三个参数 0
    - 通过 int 0x80 执行系统调用
    - 执行后返回结果在 eax 中
- Linux/ARM 的 execve 系统调用
    - 通过 C 语言 ABI 来将参数放在对应寄存器中
    - 将 execve 对应的系统调用地址（基地址+调用号 11）放在 r7 寄存器中
    - 调用 swi 指令执行系统调用
    - 返回值在 r0 寄存器中

RISC-V 中系统调用的硬件实现：

- 通过 ecall 指令来抛出异常（Environment Call from U-mode、……）
- 检查 sedeleg 寄存器（是否将该异常代理给 Supervisor 模式）
    - 如果代理给了 S 模式
        - 将 pc 值保存到 sepc 寄存器中
        - 将特权级提升到 Supervisor
        - 跳转到 stvec 存储的地址，执行内核定义的 handler 程序
        - 降级到 User 模式，返回到 sepc
    - 如果没有代理
        - 将 pc 值保存到 mepc 中
        - 将特权级提升到 Machine
        - 跳转到 mtvec 存储的地址，执行 SBI 定义的 handler 程序
        - 降级到 User 模式，返回到 mepc

### 系统调用类别
- 进程控制
    - 创建进程 fork，结束子进程 exit，等待 wait、……
- 文件管理
    - 创建文件、删除文件、打开文件、关闭文件、读写、……
- 设备管理
- 信息维护
    - 获取当前日期、时间、进程属性、……
- 通信
- 保护

## 操作系统结构
- 简单结构（没有结构）：MS-DOS
    - 不区分用户态、内核态
    - 用户程序、操作系统程序、驱动程序都运行在同一个地址空间，可以互相操作
- 整体内核（Monolithic Kernel）结构：UNIX
    - 用户态程序、内核态程序隔离
    - 内核态程序给用户态程序接口来提供服务
    - 内核服务都集成在一起
- 微内核（Microkernel）结构：Minix、Mach、QNX、L4、……
    - 防止内核态程序过于复杂，漏洞概率更大
    - 尽可能多地将内核代码移动到用户态中
    - 内核只提供最基本的服务，其他服务都由用户态程序提供
    - 通过 message passing 来实现内核与用户态程序的通信
    - 优点：易于扩展、易于维护、更安全
    - 缺点：性能开销过大（很多 message passing）
- 模块化内核（Modular Kernel）结构
    - 将内核分为多个可加载内核模块（loadable kernel module），每个模块都有自己的功能
    - 可以加载 .ko 模块文件进行扩展
        - 对于系统版本要求苛刻
    - 易于扩展，但没微内核容易扩展（因为模块和版本紧密绑定）
    - Linux：Monolithic + Modular
- 外内核（Exokernel）结构
    - 上面都是通用系统内核，通过内核来提供各种服务
    - 外内核则进行更少的抽象，来让用户程序可以有更多控制物理资源的可能
    - 内核只进行物理资源的分配和保护，而资源的使用、管理都由用户程序自己决定

![](/assets/images/cs/system/cs2/topic3/img1_light.png#only-light)
![](/assets/images/cs/system/cs2/topic3/img1_dark.png#only-dark)


## Tracing
- 在运行的时候搜集数据
- 工具：
    - strace：跟踪一个进程在运行的时候进行了哪些系统调用
    - gdb：源码级调试器
    - perf：Linux 性能分析工具包
    - tcpdump：收集网络数据包