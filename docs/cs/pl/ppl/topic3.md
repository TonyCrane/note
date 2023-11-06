---
counter: True
comment: True
---

# 静态语义与动态语义

!!! abstract
    编程语言原理第六至第八周课程内容

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

    引入形式（introduction form），确定类型的值或范式（canoncial form）：

    $$
    \dfrac{}{\Gamma\vdash\mathrm{str}[s]:\mathrm{str}}
    $$

    $$
    \dfrac{}{\Gamma\vdash\mathrm{num}[n]:\mathrm{num}}
    $$


    消去形式（elimination form），确定如何操作该类型的值形成另一种类型的计算：

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

- 引理 4.1（类型唯一性，unicity of typing）：$\forall\Gamma, e$，最多存在一个 $\tau$ s.t. $\Gamma\vdash e:\tau$
- 引理 4.2（定型反转，inversion for typing）：假设 $\Gamma\vdash e:\tau$，若 $e=\mathrm{plus}(e_1; e_2)$，则 $\tau=\mathrm{num}$，$\Gamma\vdash e_1:\mathrm{num}$，$\Gamma\vdash e_2:\mathrm{num}$
- 引理 4.3（弱化，weakening）：若 $\Gamma\vdash e':\tau'$，则对任意 $x\notin \mathrm{dom}(\Gamma)$ 和类型 $\tau$ 都有 $\Gamma,x:\tau\vdash e':\tau'$
- 引理 4.4（代换，substitution）：若 $\Gamma, x:\tau\vdash e':\tau'$ 且 $\Gamma\vdash e:\tau$，则 $\Gamma\vdash [e/x]e':\tau'$
- 引理 4.5（分解，decomposition）：若 $\Gamma\vdash [e/x]e':\tau'$ 则对满足 $\Gamma\vdash e:\tau$ 的每个类型 $\tau$，有 $\Gamma,x:\tau\vdash e':\tau'$

## 动态语义

### 转换系统

- 用四种形式的判断来描述：
    - $s\text{ state}$：$s$ 是转换系统的一个状态
    - $s\text{ final}$：在 $s\text{ state}$ 的前提下，$s$ 是一个终结状态
    - $s\text{ initial}$：在 $s\text{ state}$ 的前提下，$s$ 是一个初始状态
    - $s\mapsto s'$：在 $s\text{ state}$ 和 $s'\text{ state}$ 的前提下，$s$ 可以转换到 $s'$
- 无法继续转换的状态是卡住的（stuck）
    - 所有终结状态都是卡住的，但也可能存在卡住的非终结状态
- 一个转换系统是确定性的（deterministic）<=> 对每个状态 $s$，最多只有一个状态 $s'$ 满足 $s\mapsto s'$
    - 否则是非确定性的（non-deterministic）
- 转换序列：一系列状态 $s_0, \cdots, s_m$ 满足 $s_0\text{ initial}$ 且 $s_i\mapsto s_{i+1}, 0\leq i<n$
    - 称之为最大的（maximal）<=> 没有 $s$ 满足 $s_n\mapsto s$（即 $s_n$ 是卡住的）
    - 称之为完备的（complete）<=> 是最大的，而且 $s_n\text{ final}$
    - 判断 $s\downarrow$ 表示有一个从 $s$ 开始的完备转换序列，即存在 $s'\text{ final}$ 满足 $s\mapsto^*s'$

### 结构化动态语义

- 结构化动态语义由一个转换系统给出
    - 所有状态都是初始状态
    - 所有终结状态都是一个值，表示已完成的计算
- 定义判断 $e\text{ val}$ 表示 $e$ 是一个值：$\dfrac{}{\mathrm{num}[n]\text{ val}}, \dfrac{}{\mathrm{str}[s]\text{ val}}$
- 接下来给出 E 语义状态之间的转换判断 $e\mapsto e'$ 的规则

???+ example "E 语言的状态转换判断规则"

    $$
    \dfrac{n_1+n_2=n}{\mathrm{plus}(\mathrm{num}[n_1]; \mathrm{num}[n_2])\mapsto \mathrm{num}[n]}
    $$

    $$
    \dfrac{e_1\mapsto e_1'}{\mathrm{plus}(e_1; e_2)\mapsto \mathrm{plus}(e_1'; e_2)}
    $$

    $$
    \dfrac{e_1\text{ val}\quad e_2\mapsto e_2'}{\mathrm{plus}(e_1; e_2)\mapsto \mathrm{plus}(e_1; e_2')}
    $$

    $$
    \dfrac{s_1s_2=s}{\mathrm{cat}(\mathrm{str}[s_1]; \mathrm{str}[s_2])\mapsto \mathrm{str}[s]}
    $$

    $$
    \dfrac{e_1\mapsto e_1'}{\mathrm{cat}(e_1; e_2)\mapsto \mathrm{cat}(e_1'; e_2)}
    $$

    $$
    \dfrac{e_1\text{ val}\quad e_2\mapsto e_2'}{\mathrm{cat}(e_1; e_2)\mapsto \mathrm{cat}(e_1; e_2')}
    $$

    $$
    \left[\dfrac{e_1\mapsto e_1'}{\mathrm{let}(e_1; x.e_2)\mapsto \mathrm{let}(e_1'; x.e_2)}\right]
    $$

    $$
    \dfrac{[e_1\text{ val}]}{\mathrm{let}(e_1; x.e_2)\mapsto [e_1/x]e_2}
    $$

    省略了类似的 $\mathrm{times}$ 和 $\mathrm{len}$ 规则

对于后两个规则，有方括号括起来的部分，是针对 let 的两种不同解释：

- 按值解释（by-value interpretation）：先求值（保留方括号中内容）
- 按名解释（by-name interpretation）：不求值直接绑定（方括号中内容均删掉）

针对结构化动态语义的两个引理：

- 引理 5.2（值的终结性，finality of values）：不存在 $e$，使得对于某个 $e'$，有 $e\text{ val}$ 和 $e\mapsto e'$ 同时成立
- 引理 5.3（确定性，determinacy）：如果 $e\mapsto e'$ 且 $e\mapsto e''$，则 $e'$ 和 $e''$ 是 $\alpha$ 等价的

### 上下文动态语义

- 上下文动态语义是结构化动态语义的一个变体，没有本质区别
- 主要思想：将指令步骤分离成特殊的判断形式，称为指令转换（instruction transition），并用称为求值上下文（evaluation context）的方法对定位下一条指令的过程加以形式化
- 判断 $\mathcal{E}\text{ ectxt}$ 确定在一个更大的表达式中下一条要执行的指令的位置
    - $\dfrac{}{\circ\text{ ectxt}},\ \dfrac{\mathcal{E}_1\text{ ectxt}}{\mathrm{plus}(\mathcal{E}_1; e_2)\text{ ectxt}},\ \dfrac{e_1\text{ val}\quad\mathcal{E}_2\text{ ectxt}}{\mathrm{plus}(e_1; \mathcal{E}_2)\text{ ectxt}}$
    - 比如第二条规则表示，如果 $\mathrm{plus}$ 的第二个参数是值，则下一条指令执行的位置就存在于第一个参数的位置处或其内部
- 判断 $e'=\mathcal{E}\{e\}$ 表明 $e'$ 是在求值上下文 $\mathcal{E}$ 中用表达式 $e$ 填入 $\circ$ 中的结果：
    - $\dfrac{}{e=\circ\{e\}},\ \dfrac{e_1=\mathcal{E}_1\{e\}}{\mathrm{plus}(e_1; e_2)=\mathrm{plus}(\mathcal{E}_1; e_2)\{e\}},\ \dfrac{e_1\text{ val}\quad e_2=\mathcal{E}_2\{e\}}{\mathrm{plus}(e_1; e_2)=\mathrm{plus}(e_1; \mathcal{E}_2)\{e\}}$
- E 语言的上下文动态语义只有单条规则定义：$\dfrac{e=\mathcal{E}\{e_0\}\quad e_0\rightarrow e_0'\quad e'=\mathcal{E}\{e_0'\}}{e\mapsto e'}$

### 类型安全

- 满足以下两个性质的语言是类型安全（type safe）的：
    - 保持性（preservation）：如果 $e:\tau$ 且 $e\mapsto e'$ 那么 $e':\tau$
    - 进展性（progress）：如果 $e:\tau$，则要么 $e\text{ val}$ 要么存在 $e'$ s.t. $e\mapsto e'$
- 运行时错误，以除以 0 为例
    - 给 E 语言加上除法运算 $\dfrac{e_1:\mathrm{num}\quad e_2:\mathrm{num}}{\mathrm{div}(e_1; e_2):\mathrm{num}}$
    - 如果除以零了则会 stuck，两种解决思路：
        1. 增强类型系统，使得除以 0 的情况不会出现（比较困难，难以静态实现）
        2. 增加动态检查，使得除以 0 时报错并将错误作为求值输出
    - 采用第二种，引入 $e\text{ err}$ 判断表示 $e$ 会导致运行时错误
        - $\dfrac{e_1\text{ val}}{\mathrm{div}(e_1; \mathrm{num}[0])\text{ err}},\ \dfrac{e_1\text{ err}}{\mathrm{div}(e_1; e_2)\text{ err}},\ \dfrac{e_1\text{ val}\quad e_2\text{ err}}{\mathrm{div}(e_1; e_2)\text{ err}}$