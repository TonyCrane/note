---
counter: True
comment: True
---

# Lambda 演算

!!! abstract
    编程语言原理第一至第？周课程内容

## 基本定义

- Lambda 演算是是由特定形式语法所组成的⼀种语⾔，⼀组转换规则可运算（operate）其中的 λ 项（term）
- λ 项
    - 变量：变量 $x$ 本身是一个有效的 λ 项
    - 抽象：如果 $t$ 是一个 λ 项，而 $x$ 是一个变量，则 $\lambda x.\ t$ 是一个 λ 项
        - $\lambda x.\ t$ 表示一个形参为 $x$ 返回 $t$ 的函数（$t$ 中**可能**用到 $x$）
        - 不可以为 $\lambda x.\ t$ 命名，比如命名其为 $M$ 然后后续使用 $M$
            - 例外：可以用 $I$ 代替恒等函数 $\lambda x.\ x$ 
    - 应用：如果 $t$ 和 $s$ 是 λ 项，则 $t\ s$ 是一个 λ 项
        - 相当于函数调用，有的作者用 $ap(t\ s)$ 表达
- 消歧约定
    - 函数抽象的函数体尽最大可能向右扩展
        - $\lambda x.\ M\ N$ 表达一整个函数抽象，而非 $(\lambda x.\ M)\ N$
    - 函数应用左结合
        - $M\ N\ P$ 意为 $(M\ N)\ P$ 而非 $M\ (N\ P)$
- 自由变量和绑定变量
    - 形参绑定于函数体，返回内容内出现形参即为绑定变量
        - 绑定变量可以自由改名，比如 $\lambda x.\ x$ 等同于 $\lambda y.\ y$
        - $BV(x) = \empty$、$BV(\lambda x.\ t) = \{x\}\cup BV(t)$、$BV(t_1\ t_2) = BV(t_1)\cup BV(t_2)$
            - 常用 $t$ 一类的符号表示一个任意 λ 项
    - 不是绑定变量就是自由变量
        - 自由变量不可以自由改名
        - $FV(x) = \{x\}$、$FV(\lambda x.\ t) = FV(t) - \{x\}$、$FV(t_1\ t_2) = FV(t_1)\cup FV(t_2)$
    
    ??? example
        $(\lambda y.\ y)\ (\lambda x.\ x\ y)$
        :   一个应用，左侧函数中 $y$ 是绑定变量，右侧函数中 $x$ 是绑定变量、$y$ 是自由变量且与左侧函数中的 $y$ 无关。
        
        $\lambda x.\ (\lambda y.\ x\ y\ z)$
        :   内层函数中 $x$ 绑定于外层函数，$y$ 绑定于内层函数，二者都是绑定变量；$z$ 是自由变量。
