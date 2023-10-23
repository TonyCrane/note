---
counter: True
comment: True
---

# Lambda 演算

!!! abstract
    编程语言原理第一至第二周课程内容，以及第二次作业中关于 λ 演算的补充内容

## 基本定义

- Lambda 演算是是由特定形式语法所组成的⼀种语⾔，⼀组转换规则可运算（operate）其中的 λ 项（term）
- λ 项
    - 变量：变量 $x$ 本身是一个有效的 λ 项
    - 抽象：如果 $\mathsf{t}$ 是一个 λ 项，而 $x$ 是一个变量，则 $\lambda x.\ \mathsf{t}$ 是一个 λ 项
        - $\lambda x.\ \mathsf{t}$ 表示一个形参为 $x$ 返回 $\mathsf{t}$ 的函数（$\mathsf{t}$ 中**可能**用到 $x$）
        - 不可以为 $\lambda x.\ \mathsf{t}$ 命名，比如命名其为 $M$ 然后后续使用 $M$
            - 例外：可以用 $\mathsf{I}$ 代替恒等函数 $\lambda x.\ x$ 
    - 应用：如果 $t$ 和 $s$ 是 λ 项，则 $t\ s$ 是一个 λ 项
        - 相当于函数调用，有的作者用 $\mathrm{ap}(t\ s)$ 表达
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
    - $\mathsf{T} := \lambda x.\ \lambda y.\ x$
    - $\mathsf{F} := \lambda x.\ \lambda y.\ y$
    - 理解：类比 if 语句 `#!c if (cond) { A } else { B }`，如果 cond 为真返回 A，否则返回 B
- 算子：
    - 非：满足 $\mathsf{not}\ \mathsf{T}\equiv_\beta \mathsf{F}$、$\mathsf{not}\ \mathsf{F}\equiv_\beta \mathsf{T}$
        - $\mathsf{not} := \lambda b.\ b\ \mathsf{F}\ \mathsf{T}\equiv \lambda b.\ b\ (\lambda x.\ \lambda y.\ y)\ (\lambda y.\ \lambda y.\ x)$
        - 验证：$\mathsf{not}\ \mathsf{T} = (\lambda b.\ b\ \mathsf{F}\ \mathsf{T})\ \mathsf{T}\equiv_\beta \mathsf{T}\ \mathsf{F}\ \mathsf{T} = (\lambda x.\ \lambda y.\ x)\ \mathsf{F}\ \mathsf{T}\equiv_\beta \mathsf{F}$
    - 与：$\mathsf{and} := \lambda x.\ \lambda y.\ (x\ y\ \mathsf{F})$
    - 或: $\mathsf{or} := \lambda x.\ \lambda y.\ (x\ \mathsf{T}\ y)$

### 自然数

这里采用的是一种用 λ 表达式表示自然数的方法，称为 Church 数。

- 使用参数 $z$ 表示 0，使用 $s$ 表示求后继的函数，则在 $z$ 上应用 $s$ 的次数就可以用来表示自然数：
    - $\overline{0} := \lambda s.\ \lambda z.\ z$
    - $\overline{1} := \lambda s.\ \lambda z.\ s\ z$
    - $\overline{2} := \lambda s.\ \lambda z.\ s\ (s\ z)$
    - $\overline{n} := \lambda s.\ \lambda z.\ \underbrace{s\ (s\ (\cdots\ (s}_{n\ times}\ z)\cdots)) = \lambda s.\ \lambda z.\ s^n\ z$
- 根据如上定义有：
    - $\overline{n}\ f\ x\equiv_\beta f^n\ x$
    - 定义 $\mathsf{zero} := \overline{0} = \lambda s.\ \lambda z.\ z$
    - 定义后继函数 $\mathsf{succ} := \lambda n.\ \overline{n+1} = \lambda n.\ \lambda s.\ \lambda z.\ s\ (n\ s\ z)$
        - 满足 $\mathsf{succ}\ \overline{n}\equiv \overline{n+1}$
        - 验证：$\mathsf{succ}\ \overline{n} = \lambda s.\ \lambda z.\ s\ (\overline{n}\ s\ z) \equiv_\beta \lambda s.\ \lambda z.\ s\ (s^n\ z) = \lambda s.\ \lambda z.\ s^{n+1}\ z = \overline{n+1}$
- 定义运算：
    - 加：$\mathsf{plus} := \lambda m.\ \lambda n.\ \lambda f.\ \lambda x.\ m\ f\ (n\ f\ x) = \lambda m.\ \lambda n.\ m\ \mathsf{succ}\ n$
    - 乘：$\mathsf{mult} := \lambda m.\ \lambda n.\ \lambda f.\ \lambda x.\ m\ (n\ f)\ x = \lambda m.\ \lambda n.\ \lambda f.\ m\ (n\ f)$

    ??? example "关于 $\mathsf{plus} 的验证"
        $$
        \begin{align*}
        &\mathsf{plus}\ \overline{a}\ \overline{b}\\
        =\ &\mathsf{plus}\ (\lambda s.\ \lambda z.\ s^a\ z)\ \overline{b}\\
        =\ &(\lambda n.\ \lambda k.\ n\ \mathsf{succ}\ k)\ (\lambda s.\ \lambda z.\ s^a\ z)\ \overline{b}\\
        \equiv_\beta\ &(\lambda k.\ (\lambda s.\ \lambda z.\ s^a\ z)\ \mathsf{succ}\ k)\ \overline{b}\\
        \equiv_\beta\ &(\lambda s.\ \lambda z.\ s^a\ z)\ \mathsf{succ}\ \overline{b}\\
        \equiv_\beta\ &(\lambda z.\ \mathsf{succ}^a\ z)\ \overline{b}\\
        \equiv_\beta\ &\mathsf{succ}^a\ \overline{b}\\
        \twoheadrightarrow\ &\overline{a+b}
        \end{align*}
        $$

!!! note "以下是第二次作业中的额外内容"

## Y-Combinator

假设要实现一个递归函数来计算阶乘，在各编程语言中可以使用递归：

```python
def fact(n):
    if n == 0:
        return 1
    else:
        return n * fact(n - 1)
```

写成 λ 表达式的形式就是 $\mathsf{fact} = \lambda n.\ \mathsf{iszero}\ n\ 1\ (\mathsf{mult}\ n\ (\mathsf{fact}\ (\mathsf{pred}\ n)))$（其中 $\mathsf{iszero}\ a\ b\ c$ 判断 $a$ 是否为 0，如果是则结果为 $b$ 否则为 $c$，$\mathsf{pred}$ 计算前驱）。不过 λ 表达式并不允许我们这样引用自己的名字。

解决方法是使用一个这样的函数：

```python
def proto(f, n):
    if n == 0:
        return 1
    else:
        return n * f(f, n - 1)
```

这样 proto 函数内部就没有使用过 proto 自身，那现在假设传入的第一个参数是 proto，就出现了 proto(proto, n) = n * proto(proto, n-1) = n * (n-1) * proto(proto, n-2) = ... 这样成功递归了，所以 $\mathsf{fact} = \mathsf{proto}\ \mathsf{proto}$。

可以看到这里实际就是把一层函数 f 包裹了一层，变成了调用 f f，所以我们可以先将 f f 合并，写出这样一个函数：

$$
\mathsf{u} = \lambda f.\ \lambda n.\ \mathsf{iszero}\ n\ 1\ (\mathsf{mult}\ n\ (f\ (\mathsf{pred}\ n)))
$$

然后我们依此来定义 $\mathsf{proto}$：

$$
\begin{align*}
\mathsf{proto} &= \lambda f.\ \mathsf{u}\ (f\ f)\\
&= \lambda f.\ \lambda n.\ \mathsf{iszero}\ n\ 1\ (\mathsf{mult}\ n\ ((f\ f)\ (\mathsf{pred}\ n)))
\end{align*}
$$

接下来推导 $\mathsf{proto}\ \mathsf{proto}$：

$$
\mathsf{proto}\ \mathsf{proto} = \lambda n.\ \mathsf{iszero}\ n\ 1\ (\mathsf{mult}\ n\ ((\mathsf{proto}\ \mathsf{proto})\ (\mathsf{pred}\ n)))
$$

如果将 $\mathsf{proto}\ \mathsf{proto}$ 都代换为 $\mathsf{fact}$ 就是我们之前想要写的 λ 表达式了。而将这个过程打包起来，把这个 $\mathsf{u}$ 提取出来：

$$
\begin{align*}
\mathsf{fact} &= \mathsf{proto}\ \mathsf{proto}\\
&= (\lambda f.\ \mathsf{u}\ (f\ f))\ (\lambda f.\ \mathsf{u}\ (f\ f))\\
&= (\lambda v.\ (\lambda f.\ v\ (f\ f))\ (\lambda f.\ v\ (f\ f)))\ \mathsf{u}\\
&= \mathsf{Y}\ \mathsf{u}
\end{align*}
$$

这里我们得到了一个 $\mathsf{Y} := \lambda v.\ (\lambda f.\ v\ (f\ f))\ (\lambda f.\ v\ (f\ f))$，这个函数就称为 Y-Combinator，由它和其他函数组合就可以实现递归。

也称其为一个**不动点算子**，因为其有一个性质：

$$
\begin{align*}
\mathsf{Y}\ u &= (\lambda v.\ (\lambda f.\ v\ (f\ f))\ (\lambda f.\ v\ (f\ f)))\ u\\
&= (\lambda f.\ u\ (f\ f))\ (\lambda f.\ u\ (f\ f))\\
&= u\ ((\lambda f.\ u\ (f\ f))\ (\lambda f.\ u\ (f\ f)))\\
&= u\ (\mathsf{Y}\ u)
\end{align*}
$$

所以清晰可见 $\mathsf{Y}$ 实现了 $u$ 的递归。

## SK 组合子演算

有一套新的系统可以实现和不含自由变量的 λ 表达式等价的能力，且只有两个操作符，分别定义如下：

- S 组合子：$\mathsf{S} := \lambda x.\ \lambda y.\ \lambda z.\ x\ z\ (y\ z)$
- K 组合子：$\mathsf{K} := \lambda x.\ \lambda y.\ x$

仅仅用这两个操作符和它们之间的 application 就可以构造与 λ 演算等价的计算系统。比如有些说法中称为 SKI 组合子，多出来的一个 $\mathsf{I} = \lambda x.\ x$ 也可以由 SK 构造而来：$\mathsf{I} = \mathsf{S}\ \mathsf{K}\ \mathsf{K}$。

上面的定义使用了 λ 表达式，实际上 SK 也可以通过自己的一套独立的规则来进行定义：

- $\mathsf{S}\ x\ y\ z \equiv x\ z\ (y\ z)$
- $\mathsf{K}\ x\ y \equiv x$

接下来是将任意闭项转换为 SK 组合子表示的方法：

1. $\lambda x.\ \mathsf{M} \equiv \mathsf{K}\ \mathsf{M}$（如果 $\mathsf{M}$ 中不包含变量 $x$）
2. $\lambda x.\ x \equiv \mathsf{S}\ \mathsf{K}\ \mathsf{K}$
3. $\lambda x.\ \mathsf{U}\ x \equiv \mathsf{U}$（如果 $\mathsf{U}$ 中不包含变量 $x$）
4. $\lambda x.\ \mathsf{U}\ \mathsf{V} \equiv \mathsf{S}\ (\lambda x.\ \mathsf{U})\ (\lambda x.\ \mathsf{V})$（其他情况进行拆分）