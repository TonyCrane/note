---
counter: True
comment: True
---

# 数据类型

!!! abstract
    编程语言原理第十周至第十三周课程内容
    
## 有限数据类型
### 积类型

- 二元积（binary product）：值的有序对（ordered pairs）$\langle\tau_1, \tau_2\rangle$
    - 消去形式：投影，析取分量 $\langle\tau_1, \tau_2\rangle\cdot l = \tau_1$
    - 惰性（lazy）动态语义：无论分量是否有值，有序对都是值
    - 急性（eager）动态语义：分量都是值的时候，有序对才是值
- 空积（nullary product）：不包含任何值的空元组，没有消去形式
- 有限积（infinite product）：$\langle\tau_i\rangle_{i\in I}$（$I$ 是索引的有限集）
- 空积与二元积的语法和语义
    - 定义语法
        - $\mathsf{Typ}\ \tau ::= \mathrm{unit}$ 空积 / $\mathrm{prod}(\tau_1; \tau_2)$ 二元积 $\tau_1\times\tau_2$
        - $\mathsf{Exp}\ e ::= \mathrm{triv}$ 空元组 / $\mathrm{pair}(e_1; e_2)$ 有序对 $\langle e_1, e_2\rangle$
        - $\mathsf{Exp}\ e ::= \mathrm{pr[l]}(e)$ 左投影 / $\mathrm{pr[r]}(e)$ 右投影
    - 静态语义很直接，忽略
    - 动态语义：
        - $\dfrac{}{\langle\rangle\text{ val}},\ \dfrac{[e_1\text{ val}]\quad [e_2\text{ val}]}{\langle e_1, e_2\rangle\text{ val}}$
        - $\left[\dfrac{e_1\mapsto e_1'}{\langle e_1, e_2\rangle\mapsto\langle e_1', e_2\rangle}\right],\ \left[\dfrac{e_1\text{ val}\quad e_2\mapsto e_2'}{\langle e_1, e_2\rangle\mapsto\langle e_1, e_2'\rangle}\right]$
        - $\dfrac{e\mapsto e'}{e\cdot l\mapsto e'\cdot l},\ \dfrac{e\mapsto e'}{e\cdot r\mapsto e'\cdot r}$
        - $\dfrac{[e_1\text{ val}]\quad [e_2\text{ val}]}{\langle e_1, e_2\rangle\cdot l\mapsto e_1},\ \dfrac{[e_1\text{ val}]\quad [e_2\text{ val}]}{\langle e_1, e_2\rangle\cdot r\mapsto e_2}$
    - 安全性
- 积类型的 PL 意义：结构体 struct 组合类型
- 原始互递归
    - 简化 $\mathrm{rec}\{e_0; x.y.e_1\}(e)$，可以定义为 $e'\cdot r$，其中 $e'$ 为：
    - $\mathrm{iter}\{\langle \mathrm{z}, e_0\rangle; x'.\langle s(x'\cdot l), [x'\cdot r/x]e_1\rangle\}(e)$
    
    ???+ example "原始互递归的例子"
        定义两个函数的递归方程 $e(0)=1, o(0)=0, e(n+1)=o(n), o(n+1)=e(n)$
        
        定义辅助函数 $e_{eo}$，类型为 $\mathrm{nat}\rightarrow\mathrm{nat}\times\mathrm{nat}$：
        
        $$
        \lambda(n:\mathrm{nat})\ \mathrm{iter}\ n\{\mathrm{z}\hookrightarrow\langle 1, 0\rangle\ |\ \mathrm{s}(b)\hookrightarrow\langle b\cdot r, b\cdot l\rangle\}
        $$
        
        有其 $l$ 为 $e$ 函数的取值，$r$ 为 $o$ 函数的取值

### 和类型

- 语法：
    - $\mathsf{Typ}\ \tau ::= \mathrm{void}$ 空和 / $\mathrm{sum}(\tau_1; \tau_2)$ 二元和 $\tau_1+\tau_2$
    - $\mathsf{Exp}\ e ::= \mathrm{abort}\{\tau\}(e)$ 终止
    - $\mathsf{Exp}\ e ::= \mathrm{in[l]}\{\tau_1; \tau_2\}(e)$ 左注入（$l\cdot e$）/ $\mathrm{in[r]}\{\tau_1; \tau_2\}(e)$ 右注入
        - 构造形式（积类型的左投影右投影是消去形式）
    - $\mathsf{Exp}\ e ::= \mathrm{case}(e; x_1.e_1; x_2.e_2)$ 消去形式，$\mathrm{case}\ e\{l\cdot x_1\hookrightarrow e_1\ |\ r\cdot x_2\hookrightarrow e_2\}$
- 部分静态语义：
    - $\dfrac{\Gamma\vdash e:\tau_1}{\Gamma\vdash l\cdot e:\tau_1+\tau_2}, \dfrac{\Gamma\vdash e:\tau_2}{\Gamma\vdash r\cdot e:\tau_1+\tau_2}$
- $\mathrm{case}$ 的动态语义：
    - $\dfrac{[e\text{ val}]}{\mathrm{case}\ l\cdot e\{l\cdot x_1\hookrightarrow e_1\ |\ r\cdot x_2\hookrightarrow e_2\}\mapsto [e/x_1]e_1}$
- 和类型的 PL 意义：enum 枚举
- 与积类型的区别：$e:\mathrm{unit}$ 可以求值得到 $\langle\rangle$ 但没意义，$e:\mathrm{void}$ 不会产生任何一个值
- 布尔类型：
    - $\mathsf{Typ}\ \tau ::= \mathrm{bool}$
    - $\mathsf{Exp}\ e ::= \mathrm{true}$ / $\mathrm{false}$ / $\mathrm{if}(e; e_1; e_2)$
    - 也可以用二元和和空积来定义：
        - $\mathrm{bool} = \mathrm{unit} + \mathrm{unit}$
        - $\mathrm{true} = l\cdot \langle\rangle,\ \mathrm{false} = r\cdot\langle\rangle$
        - $\text{if }e\text{ then }e_1\text{ else }e_2 = \mathrm{case}\ e\{l\cdot x_1\hookrightarrow e_1\ |\ r\cdot x_2\hookrightarrow e_2\}$
- Option 类型：
    - $\mathsf{Typ}\ \tau ::= \mathrm{opt}(\tau)$
    - $\mathsf{Exp}\ e ::= \mathrm{null}$ 空 / $\mathrm{just}(e)$ 有值
    - $\mathsf{Exp}\ e ::= \mathrm{ifnull}\{\tau\}\{e_1; x.e_2\}(e)$ 如果 $e$ 是 $\mathrm{null}$ 则值为 $e_1$，否则如果为 $\mathrm{just}(x)$ 则值为 $e_2$
    - 用和和空积定义：
        - $\tau\text{ opt} = \mathrm{unit} + \tau$
        - $\mathrm{null} = l\cdot\langle\rangle,\ \mathrm{just}(e) = r\cdot e$
        - $\mathrm{ifnull}\ e\{\mathrm{null}\hookrightarrow e_1\ |\ \mathrm{just}(x)\hookrightarrow e_2\} = \mathrm{case}\ e\{l\cdot \underline{\ \ }\hookrightarrow e_1\ |\ r\cdot x_2\hookrightarrow e_2\}$

## 无限数据类型
### 泛型编程

- 类型算子：$t.\tau$，表示 $\tau$ 类型中存在一个没有确定的类型 $t$，是其他类型要作用的位置
    - 比如存在 $f\colon \rho\to\rho'$，以及 $\tau=\mathrm{bool}\times t$
    - 则 $f$ 可以扩展为 $\mathrm{bool}\times\rho\to\mathrm{bool}\times\rho'$
- 多项式类型算子：由类型变量 $t$，类型 $\mathrm{void}, \mathrm{unit}$ 以及类型构造器 $+, \times$ 构成的类型算子
    - 断言：$t.\tau\text{ poly}$
    - 泛型扩展：$\mathsf{Exp}\ e := \mathrm{map}\{t.\tau\}(x.e')(e)$
    - 静态语义：$\dfrac{t.\tau\text{ poly}\quad\Gamma,x:\rho\vdash e':\rho'\quad\Gamma\vdash e:[\rho/t]\tau}{\Gamma\vdash\mathrm{map}\{t.\tau\}(x.e')(e):[\rho'/t]\tau}$
    - 例如 $t.\tau$ 为 $t.(\mathrm{unit}+\mathrm{bool}\times t)$，$x.e$ 为 $x.\mathrm{s}(x)$
        - 则 $\mathrm{map}\{t.\tau\}(x.e)(r\cdot\langle\mathrm{true}, n\rangle)\mapsto^* r\cdot\langle\mathrm{true}, n + 1\rangle$
- 正类型算子
    - 正出现：类型变量出现在值域中，负出现：类型变量出现在定义域中
    - $t.\tau_1\to\tau_2$ 是正类型算子，当且仅当 $t$ 不出现在 $\tau_1$ 中且  $t.\tau_2$ 是正类型算子

### 归纳类型与余归纳类型

- 都是递归类型，归纳类型（inductive）对应类型的最小解，余归纳类型（coinductive）对应类型的最大解
    - 如果指定了函数在归纳类型的每种引⼊形式上的⾏为，就为这个类型的所有值定义了函数的⾏为。这样的函数称为迭代式（iterator）
    - 余归纳类型的元素对消去形式的有限次复合做出正确的响应⾏为，这样的元素称为⽣成器（generator）
- 归纳类型的元素是对其引入形式进行有限次复合得到的
- 归纳类型的例子：数据集 $A$ 上的有限表集：
    - 基础情况：$\mathrm{nil}$ 是有限表
    - 迭代规则：如果 $a\in A$ 且 $\sigma$ 是有限表，则 $\mathrm{cons}(a, \sigma)$ 是有限表
    - 最小化条件：除此之外，有限表集中不含其它元素
- 余归纳类型的例子：数据集 $A$ 上的无限表集（流）：
    - 迭代规则：如果 $a\in A$ 且 $\sigma$ 是无限表，则 $\mathrm{cons}(a, \sigma)$ 是无限表
    - 最大化条件：数据集 $A$ 上的无限表集是满足迭代规则的最大集合
- 观察算子：
    - $\mathrm{head}(\mathrm{cons}(a, \sigma)) = a$
    - $\mathrm{tail}(\mathrm{cons}(a, \sigma)) = \sigma$
- 归纳类型上的函数：
    - $\mathrm{length}(\mathrm{nil}) = 0$
    - $\mathrm{length}(\mathrm{cons}(a, \sigma)) = 1 + \mathrm{length}(\sigma)$
- 余归纳类型上的函数
    - 有函数 $f\colon A\to A$，定义 $\mathrm{ext}(f)$ 把 $f$ 作用在无限表的每一个元素得到新的无限表 $\mathrm{ext}(f)(\sigma)$
        - $\mathrm{head}(\mathrm{ext}(f)(\sigma)) = f(\mathrm{head}(\sigma))$
        - $\mathrm{tail}(\mathrm{ext}(f)(\sigma)) = \mathrm{ext}(f)(\mathrm{tail}(\sigma))$
    - $\mathrm{odd}$ 应用在无限表上，忽略所有偶数位置上的元素，将剩余元素按原来次序形成新表
- 互模拟（bisimulation）：即两个表等价，即 head 相等，tail 互模拟
    - $\mathrm{merge}$ 表示依次从两个表轮流取元素生成表
        - 则 $\mathrm{merge}(\mathrm{odd}(\sigma), \mathrm{even}(\sigma))$ 和 $\sigma$ 互模拟
- 自然数类型作为归纳类型：
    - $\dfrac{\Gamma\vdash e:\mathrm{unit}+\mathrm{nat}}{\Gamma\vdash\mathrm{fold}_\mathrm{nat}(e):\mathrm{nat}}$, $\dfrac{\Gamma, x:\mathrm{unit}+\tau\vdash e_1:\tau\quad\Gamma\vdash e_2:\mathrm{nat}}{\Gamma\vdash\mathrm{rec}_\mathrm{nat}(x.e_1;e_2):\tau}$
    - $\mathrm{z} = \mathrm{fold}_\mathrm{nat}(l\cdot\langle\rangle)$, $\mathrm{s}(e) = \mathrm{fold}_\mathrm{nat}(r\cdot e)$
- 余归纳类型：自然数的流类型
    - 每个元素要在所有之前的元素被计算出来之后才能被计算出来
    - 流的引入形式和自然数的消去形式是对偶的
    - $\mathrm{hd}(\mathrm{gen}_\mathrm{stream}\ x\text{ is }e\text{ in }\langle\mathrm{hd}\hookrightarrow e_1, \mathrm{tl}\hookrightarrow e_2\rangle) \mapsto [e/x]e_1$
    - $\mathrm{tl}(\mathrm{gen}_\mathrm{stream}\ x\text{ is } e\text{ in }\langle\mathrm{hd}\hookrightarrow e_1, \mathrm{tl}\hookrightarrow e_2\rangle)$
        - $\mapsto \mathrm{gen}_\mathrm{stream}\ x\text{ is }[e/x]e_2\text{ in }\langle\mathrm{hd}\hookrightarrow e_1, \mathrm{tl}\hookrightarrow e_2\rangle$

## 多态类型

- 即函数的类型不唯一
    - 比如 id: 'a -> 'a 恒等函数，不必指定一个特定类型
- 带类型的 λ 演算
    - $\Lambda(\alpha)\lambda(x:\alpha)\ x$
    - 类型应用：$\Lambda(\alpha)\lambda(x:\alpha)\ x[\mathrm{int}]\vdash [\mathrm{int}/\alpha](\lambda(x:\alpha)\ x)=\lambda(x:\text{int})\ x$
- 多态类型的 F 系统
    - $\mathsf{Typ}\ \tau ::= t$ 类型变量
    - $\mathsf{Typ}\ \tau ::= \mathrm{arr}(\tau_1;\tau_2)$ 函数类型 $\tau_1\to\tau_2$
    - $\mathsf{Typ}\ \tau ::= \mathrm{all}(t.\tau)$ 多态类型（全称类型）$\forall(t.\tau)$
    - $\mathsf{Exp}\ e ::= x$ 变量
    - $\mathsf{Exp}\ e ::= \mathrm{lam}\{\tau\}(x.e)$ 函数抽象 $\lambda(x:\tau)\ e$
    - $\mathsf{Exp}\ e ::= \mathrm{ap}(e_1; e_2)$ 函数应用 $e_1(e_2)$
    - $\mathsf{Exp}\ e ::= \mathrm{Lam}(t.e)$ 类型抽象 $\Lambda(t)\ e$
    - $\mathsf{Exp}\ e ::= \mathrm{App}\{\tau\}(e)$ 类型应用 $e[\tau]$
- 静态语义
    - 谓言：类型形成 $\Delta\vdash\tau\text{ type}$，定型 $\Delta\Gamma\vdash e:\tau$
    - 类型形成：$\dfrac{}{\Delta, t\text{ type}\vdash t\text{ type}},\ \dfrac{\Delta, t\text{ type}\vdash\tau\text{ type}}{\Delta\vdash\forall(t.\tau)\text{ type}}$
    - 算子的类型：$\dfrac{\Delta, t\text{ type}\quad\Gamma\vdash e:\tau}{\Delta\Gamma\vdash\Lambda(t)\ e:\forall(t.\tau)},\ \dfrac{\Delta\Gamma\vdash e:\forall(t.\tau')\quad\Delta\vdash\tau\text{ type}}{\Delta\Gamma\vdash e[\tau]:[\tau/t]\tau'}$