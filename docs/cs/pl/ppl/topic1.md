---
counter: True
comment: True
---

# Lambda 演算

!!! abstract
    编程语言原理第一至第二周课程内容

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

- 封闭（closed）
    - 项 $t$ 是封闭的（闭项），当且仅当 $FV(t) = \empty$
        - 即没有自由变量
        - 类比程序中就是没有使用全局变量的函数（OS 中称为可重入函数）
    - 项 $t$ 相对于 $t'$ 封闭，当且仅当 $FV(t) \cap BV(t') = \empty$
        - 即 $t$ 的自由变量不会与 $t'$ 的绑定变量冲突
        - 闭项 $t$ 相对于任意项 $t'$ 封闭
- 代换：记号 $[N/x]M$ 表示将 $M$ 中的所有 $x$ 替换为 $N$
    - $M$ 中不能有与 $N$ 中自由变量名称冲突的绑定变量
- 函数组合：$(f\circ g)(x) = f(g(x))$
    - $f\circ g = \lambda x.\ f\ (g\ x)$
    - $\circ = \lambda f.\ \lambda g.\ \lambda x.\ f\ (g\ x)$

## λ 形式系统

λ 演算⽤于对 λ 表达式进⾏推理，包含公理语义、操作语义和指称语义三个部分。

- 公理语义：表达式之间等式的形式系统
- 操作语义：对表达式进行规约（reduce）的等式推理的有向形式
- 指称语义：类似其他逻辑系统的模型论（？）

### 等式语义

- 等式语义分为定义等价和语义等价
    - 定义等价：定义时就有相同形式，如 $\lambda x.\ x$ 与 $\lambda x.\ x$ 等价
    - 语义等价：语义相同，即相当于程序有相同效果，如 $\lambda x.\ x$ 与 $\lambda y.\ y$ 等价
- 三种语义等价：
    - $\alpha$ 等价（renaming，相当于给变量改名）
        - 任意参数 $x$ 任意词项 $t$，$\lambda x.\ t\equiv_\alpha \lambda y.\ [y/x]t$
    - $\beta$ 等价（reduction，相当于应用函数得到结果）
        - 任意参数 $x$ 任意词项 $t_1, t_2$，如果 $t_2$ 相对于 $t_1$ 封闭，则 $(\lambda x.\ t_1)\ t_2\equiv_\beta [t_2/x]t_1$
    - $\eta$ 等价
        - 任意参数 $x$ 任意词项 $t$，$\lambda y.\ (\lambda x.\ t)\ y\equiv_\eta \lambda x.\ t$
    - 对于三种等价，都有以下两条额外规则
        - 如果 $t\equiv_? t'$，则对于任意参数 $x$，$\lambda x.\ t\equiv_? \lambda x.\ t'$
        - 如果 $t_1\equiv_? t_1'$ 且 $t_2\equiv_? t_2'$，则 $t_1\ t_2\equiv_? t_1'\ t_2'$
- 语义等价：
    - $t$ 通过 $\alpha/\beta/\eta$ 等价规则可变为 $t'$，则 $t$ 和 $t'$ 语义等价，记为 $t\equiv t'$
    - 语义等价是一个自反对称传递闭包

### 操作语义

- 规约规则提供了等式推理的一种有向形式
- 简单来说就是通过 $\beta$ 规约对表达式进行规约/化简
    - $\rightarrow$ 表示一步规约
    - $\twoheadrightarrow$ 表示零步或多步规约
- 规约过程要注意相对封闭，不封闭的话要先进行 $\alpha$ 重命名

## 通过 λ 项定义值
### 布尔值

- 可以定义两个表达式分别表示 True 和 False
    - $T := \lambda x.\ \lambda y.\ x$
    - $F := \lambda x.\ \lambda y.\ y$
    - 理解：类比 if 语句 `#!c if (cond) { A } else { B }`，如果 cond 为真返回 A，否则返回 B
- 算子：
    - 非：满足 $not\ T\equiv_\beta F$、$not\ F\equiv_\beta T$
        - $not := \lambda b.\ b\ F\ T\equiv \lambda b.\ b\ (\lambda x.\ \lambda y.\ y)\ (\lambda y.\ \lambda y.\ x)$
        - 验证：$not\ T = (\lambda b.\ b\ F\ T)\ T\equiv_\beta T\ F\ T = (\lambda x.\ \lambda y.\ x)\ F\ T\equiv_\beta F$

### 自然数

- 使用参数 $z$ 表示 0，使用 $s$ 表示求后继的函数，则在 $z$ 上应用 $s$ 的次数就可以用来表示自然数：
    - $\overline{0} := \lambda s.\ \lambda z.\ z$
    - $\overline{1} := \lambda s.\ \lambda z.\ s\ z$
    - $\overline{2} := \lambda s.\ \lambda z.\ s\ (s\ z)$
    - $\overline{n} := \lambda s.\ \lambda z.\ \underbrace{s\ (s\ (\cdots\ (s}_{n\ times}\ z)\cdots)) = \lambda s.\ \lambda z.\ s^n\ z$
- 根据如上定义有：
    - $\overline{n}\ f\ x\equiv_\beta f^n\ x$
    - 定义 $zero := \overline{0} = \lambda s.\ \lambda z.\ z$
    - 定义后继函数 $succ := \lambda n.\ \overline{n+1} = \lambda n.\ \lambda s.\ \lambda z.\ s\ (n\ s\ z)$
        - 满足 $succ\ \overline{n}\equiv \overline{n+1}$
        - 验证：$succ\ \overline{n} = \lambda s.\ \lambda z.\ s\ (\overline{n}\ s\ z) \equiv_\beta \lambda s.\ \lambda z.\ s\ (s^n\ z) = \lambda s.\ \lambda z.\ s^{n+1}\ z = \overline{n+1}$
- 定义运算：
    - 加：$plus := \lambda n.\ \lambda k.\ n\ succ\ k$

    ??? example "验证"
        $$
        \begin{align*}
        &plus\ \overline{a}\ \overline{b}\\
        =\ &plus\ (\lambda s.\ \lambda z.\ s^a\ z)\ \overline{b}\\
        =\ &(\lambda n.\ \lambda k.\ n\ succ\ k)\ (\lambda s.\ \lambda z.\ s^a\ z)\ \overline{b}\\
        \equiv_\beta\ &(\lambda k.\ (\lambda s.\ \lambda z.\ s^a\ z)\ succ\ k)\ \overline{b}\\
        \equiv_\beta\ &(\lambda s.\ \lambda z.\ s^a\ z)\ succ\ \overline{b}\\
        \equiv_\beta\ &(\lambda z.\ succ^a\ z)\ \overline{b}\\
        \equiv_\beta\ &succ^a\ \overline{b}\\
        \twoheadrightarrow\ &\overline{a+b}
        \end{align*}
        $$