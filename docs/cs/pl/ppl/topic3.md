---
counter: True
comment: True
---

# 静态语义与动态语义

!!! abstract
    编程语言原理第六至第？周课程内容

## 静态语义

- 类型系统的作用是对短语（phrase）的形成加以约束，短语是上下文敏感的

定义 E 语言的语法如下：

```ebnf
Typ τ  ::=  num             num
            str             str
Exp e  ::=  x               x
            num[n]          n
            str[s]          "s"
            plus(e1; e2)    e1 + e2
            times(e1; e2)   e1 * e2
            cat(e1; e2)     e1_e2
            len(e)          |e|
            let(e1; x.e2)   let x be e1 in e2
```

- E 的静态语义（statics）由如下形式的泛型假言判断的归纳定义组成：$\overrightarrow{x}\ |\ \Gamma\vdash e:r$
    - $\overrightarrow{x}=\mathrm{dom}(\Gamma)$：变量的有限集合
    - $\Gamma$：定型上下文（类型指派），针对每个 $x\in\overrightarrow{x}$ 有形如 $x:\tau$ 的假设
        - $\Gamma = \{x_1:\tau_1, \cdots, x_k:\tau_k\}$
        - 如果 $x\notin\mathrm{dom}(\Gamma)$，则称 $x$ 对于 $\Gamma$ 是新的，可以添加得到 $\Gamma,x:\tau$
    - 定型公理：$c:\tau$，符号 $c$ 有类型 $\tau$

???+ example "E 的静态语义定义"
    $$
    \dfrac{}{\Gamma,x:\tau\vdash x:\tau}
    $$

    $$
    \dfrac{}{\Gamma\vdash\mathrm{str}[s]:\mathrm{str}}
    $$

    $$
    \dfrac{}{\Gamma\vdash\mathrm{num}[n]:\mathrm{num}}
    $$

    $$
    \dfrac{\Gamma\vdash e_1:\mathrm{num}\quad \Gamma\vdash e_2:\mathrm{num}}{\Gamma\vdash \mathrm{plus}(e_1;e_2):\mathrm{num}}
    $$

    $$
    \dfrac{\Gamma\vdash e_1:\mathrm{num}\quad \Gamma\vdash e_2:\mathrm{num}}{\Gamma\vdash \mathrm{times}(e_1;e_2):\mathrm{num}}
    $$

    $$
    \dfrac{\Gamma\vdash e_1:\mathrm{str}\quad \Gamma\vdash e_2:\mathrm{str}}{\Gamma\vdash \mathrm{cat}(e_1;e_2):\mathrm{str}}
    $$

    $$
    \dfrac{\Gamma\vdash e:\mathrm{str}}{\Gamma\vdash \mathrm{len}(e):\mathrm{num}}
    $$
    
    $$
    \dfrac{\Gamma\vdash e_1:\tau_1\quad \Gamma, x:\tau_1\vdash e_2:\tau_2}{\Gamma\vdash \mathrm{let}(e_1; x.e_2):\tau_2}
    $$