---
counter: True
comment: True
---

# 数据类型

!!! abstract
    编程语言原理第十周至第？周课程内容
    
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