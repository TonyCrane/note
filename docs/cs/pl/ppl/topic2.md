---
counter: True
comment: True
---

# 抽象语法树与归纳法

!!! abstract
    编程语言原理第三至第六周课程内容

    由于大翁老师这部分上课吹水非常严重，所以就基本只看了 slide，但是 slide 质量又非常捉急，~~全是字全是话~~，很多都是一个定义写一两页，看半天发现其实屁都没说，我反正就直接抄下来了。我甚至怀疑里面有很多的错误，但也就这样了，姑且认为这些定义都不重要（

## 抽象语法树

- 类别（sort）：ast 按语法的不同分成不同类别 $s$，类别的集合记作 $S$
    - 语法书根据语义的不同有不同的类别
- 运算符 $o$，其集合 $O_s$ 是某个 $s$ 上的集合
    - 元数（arity）规定了运算符的类别、参数的个数 $n$、参数的类别 $s_i$，记作 $(s_1, \cdots, s_n)s$
        - 理解为记录一个函数的参数类型和返回值类型
- 变量 $x$，集合 $X_s$，为某个 $s$ 上的集合，变量族 $X=\{X_s\}_{s\in S}$
    - 变量是某个领域内的位置对象，可以用特定对象代换（substitution）某个表达式中的全部同个变量来变成已知
- 结构归纳法（structural induction）
    - 对于某个类别的所有 ast $a$，都具有性质 $P(a)$，则考虑所有可以生成 $a$ 的方式，并证明每种情况下其子 ast 都有该性质，则生成的 $a$ 也有该性质
    - 用满足性质的 ast 代换变量，得到的代换结果也满足该性质

??? abstract "PPT 里叭叭的绕来绕去还感觉屁用没有的“定义”"
    - 记 $S$ 为类别 sort 的有限集合，给定一个类别集合 $S$，一个具有形式 $(s_1, \cdots, s_n)s$ 的元数表示一个类别为 $s\in S$ 的运算符，它接受 $n\geq 0$ 个参数，第 $i$ 个参数的类别为 $s_i\in S$，令 $O=\{O_a\}$ 为一个按元数索引的、由具有元数 $a$ 的运算符集合 $O_a$ 构成的不相交的集族（family），如果 $o$ 是一个元数为 $(s_1, \cdots, s_n)s$ 的运算符，则称 $o$ 的类别为 $s$ 且有 $n$ 个类别分别为 $s_1, \cdots, s_n$ 的参数
    - 固定一个类别集合 $S$ 和一个按元数索引的、不同元数的运算符集族 $O$，令 $X=\{X_s\}_{s\in S}$，其中 $X_s$ 为类别 $s$ 的变量 $x$ 所形成的集合，$X$ 为各不相交有限集 $X_s$ 组成的，按类别索引的变量集族
        - 当 $X$ 上下文无关时，如果变量 $x\in X$，则称 $x$ 的类别为 $s$
        - 如果对任何类型 $s$ 都有 $x\notin X_s$，则称 $x$ 对于 $X$ 来说是新（fresh）的，或者在理解 $X$ 时是新的
        - 如果 $x$ 对 $X$ 是新的，并且 $s$ 是类别，则 $X,x$ 是通过增加 $x$ 到 $X_s$ 所得到的变量集族
            - 还算稍微有点用的，定义了一个新写法 $X,x$

- 抽象语法树的族
    - $A[X] = \{A[X]_s\}_{s\in S}$ 是满足以下条件的最小族：
        - 一个类别为 $s$ 的变量是一棵类别为 $s$ 的 ast：如果 $x\in X_s$，则 $x\in A[X]_s$
        - 用运算符可以组合 ast：如果 $o$ 是一个元数为 $(s_1, \cdots, s_n)s$ 的运算符，且 $a_1\in A[X]_{s_1}, \cdots, a_n\in A[X]_{s_n}$，则 $o(a_1, \cdots, a_n)\in A[X]_s$
- 代换
    - 变量通过代换赋予含义：如果 $a\in A[X, x]_s$，且 $b\in A[X]_s$，则用 $b$ 代换 $a$ 中出现的所有 $x$ 得到的结果是 $[b/x]a\in A[X]$
    - 定义 ast $a$ 为代换目标 target，而 $x$ 为代换主题 subject，代换由以下等式定义：
        - $[b/x]x = b$，且当 $x\neq y$ 时， $[b/x]y = y$
        - $[b/x]o(a_1, \cdots, a_n) = o([b/x]a_1, \cdots, [b/x]a_n)$
    - 定理：如果 $a\in A[X, x]$，则对于任意 $b\in A[X]$ 都存在唯一的 $c\in A[x]$ 满足 $[b/x]a = c$

### 抽象绑定树

- abt 是对 ast 的扩展，引入具有指定作用域的新变量和符号
- $\text{let }x\text{ be }a_1\text{ in }a_2$，令 $a_2$ 中的 $x$ 为 $a_1$
    - 变量 $x$ 受 $\text{let}$ 表达式约束用于 $a_2$ 中
    - 约束变量可以换名
- 约束绑定
    - abt 通过允许运算符把任意有限个变量绑定到每个参数中来泛化 ast
    - 运算符 $a$ 的参数称作抽象子（abstractor），具有 $x_1, \cdots, x_k.a$ 的形式（当 $k=0$ 时可写作 $a$）
    - 变量序列 $x_1, \cdots, x_k$ 在 abt a 中是约束的
    - $\text{let }x\text{ be }a_1\text{ in }a_2$ 就是 $\mathrm{let}(a_1; x.a_2)$ 这个形式表明 $x$ 在 $a_2$ 是约束的
        - $\mathrm{let}()$ 的结果是一个 ast
    - 将 $x_1, \cdots, x_n$ 表示为 $\overrightarrow{x}$，则 $x_1, \cdots, x_n.a$ 表示为 $\overrightarrow{x}.a$
    - 运算符被赋予形如 $(v_1, \cdots, v_n)s$ 的泛化元数（generalized arity），这个形式规定了类别为 $s、带 $n$ 个价（valence）为 $v_1, \cdots, v_n$ 的参数的运算符
        - 价 $v$ 的形式为 $s_1, \cdots, s_k.s$，指定了参数的类别以及所绑定的变量的数量和类别
        - 变量序列 $\overrightarrow{x}$ 属于类别 $\overrightarrow{s}$，是因为这两个向量有相同的长度 $k$，并且对每一个 $1\leq i\leq k$ 都有变量 $x_i$ 属于类别 $s_i$
- 抽象绑定树的族
    - 固定一个类别集合 $S$ 和一个按其泛化元数索引的运算符的不相交集族 $O$，对给定的一族不相交的变量集合 $X$，抽象绑定树的族（abt 的 $B[X]$） 的定义与 $A[X]$ 类似，但是其中的 $X$ 在定义中是不固定的，而是当进入抽象子的作用域时会发生变化
    - 定义满足如下条件的闭合的最小集族：
        - 如果 $x\in X_s$，则 $x\in B[X]$
        - 对任意元数为 $(\overrightarrow{s_1}, \cdots, \overrightarrow{s_n}.s_n)$ 的运算符 $o$，如果 $a_1\in B[X, \overrightarrow{x_1}]_{s_1}, \cdots$，且 $a_n\in B[X, \overrightarrow{x_n}]_{s_n}$，则 $o(\overrightarrow{x_1}.a_1; \cdots; \overrightarrow{x_n}a_n)\in B[X]_s$
- $\alpha$ 等价关系
    - $a =_\alpha b$ 表示 $a$ 和 $b$ 在不考虑约束变量名的选择下是相同的
    - 称 $a$ 和 $b$ 互为 $\alpha$ 变体（$\alpha$-variant）
- 代换：用类别为 $s$ 的 abt $b$ 代换 abt $a$ 中自由出现的类别为 $s$ 的 $x$，写作 $[b/x]a$
- 标识约定：abt 总是根据 $\alpha$ 等价决定是否相同

## 归纳推理

- 判断（judgment）：关于某种类别的一棵或多棵 abt 的陈述
    - 一些判断的例子：
        - $n\ \mathrm{nat}$：$n$ 是一个自然数
        - $n_1 + n_2 = n$：$n$ 是 $n_1$ 和 $n_2$ 的和
        - $\tau\ \mathrm{type}$：$\tau$ 是一个类型
        - $e:\tau$：表达式 $e$ 具有类型 $\tau$
        - $e\Downarrow v$：表达式 $e$ 的值为 $v$
    - 判断的作用：
        - 表明一棵或多棵 abt 具有某种性质
        - 表明一棵或多棵 abt 彼此之间存在某种关系
    - 一些名词：
        - 判断形式（judgment form）：abt 所具有的性质或关系
        - 判断形式的实例（instance）：对性质或关系的一个判断
        - 谓词（predicate）：判断形式
        - 主语（subject）：构成实例的对象
        - 记法 $a\ J$ 表示 abt $a$ 具有 $J$ 性质，$-J$：不标记参数的 $J$
- 规则（rule）：规定了一个判断有效的充要条件，因此也就决定了这个判断的含义

### 推理规则

- 判断形式的归纳定义（inductive definition）表达为 $\dfrac{J_1\cdots J_k}{J}$
    - 当 $J_1, \cdots, J_k$ 都成立时，$J$ 也成立（反之不一定）
    - 前提（premise）：分子；结论（conclusion）：分母
    - 公理（axiom）：没有前提；正常规则（proper rule）：有前提
- 归纳定义例子：
    - $-\mathrm{nat}$：$\dfrac{}{\mathsf{zero}\ \mathrm{nat}}, \dfrac{a\ \mathrm{nat}}{\mathrm{succ}(a)\ \mathrm{nat}}$
    - $-\mathrm{tree}$：$\dfrac{}{\mathsf{empty}\ \mathrm{tree}}, \dfrac{a_1\ \mathrm{tree}\ \ a_2\ \mathrm{tree}}{\mathrm{node}(a_1; a_2)\ \mathrm{tree}}$
    - $a\ \mathrm{is}\ b$（两棵 abt 相等）：$\dfrac{}{\mathsf{zero}\ \mathrm{is}\ \mathsf{zero}}, \dfrac{a\ \mathrm{is}\ b}{\mathrm{succ}(a)\ \mathrm{is}\ \mathrm{succ}(b)}$
- 规则模式（rule scheme）：以上的定义都是有限的判断，但可以推出无限的规则，这样的有限的模式称为规则模式
- 规则模块的实例：为规则中对象的每一个选择确定的一条规则
- 两种归纳定义：
    - 迭代（iteration）归纳定义：一个归纳定义建立在另一个归纳定义之上
        - e.g. $\dfrac{}{\mathsf{nil}\ \mathrm{list}}, \dfrac{a\ \mathrm{nat}\ \ b\ \mathrm{list}}{\mathrm{cons}(a; b)\ \mathrm{list}}$
    - 联立（simultaneous）归纳定义（相互归纳定义）：所有的判断形式的规则是由整个规则集合同时定义的
        - e.g. $\dfrac{}{\mathsf{zero}\ \mathrm{even}}, \dfrac{b\ \mathrm{odd}}{\mathrm{succ}(b)\ \mathrm{even}}, \dfrac{a\ \mathrm{even}}{\mathrm{succ}(a)\ \mathrm{odd}}$
- 用规则定义函数
    - 通过对输入输出的关系的图做归纳定义来定义函数，然后证明这个关系在给定关系时唯一确定输出

??? example "加法函数的规则定义"
    $\mathrm{sum}(a; b; c)$ 表示 $c$ 是 $a$ 与 $b$ 的和，给出如下定义：

    $$
    \dfrac{b\ \mathrm{nat}}{\mathrm{sum}(\mathsf{zero}; b; b)}, \dfrac{\mathrm{sum}(a; b; c)}{\mathrm{sum}(\mathrm{succ}(a); b; \mathrm{succ}(c))}
    $$

    需要证明对于任意 $a\ \mathrm{nat}$ 和 $b\ \mathrm{nat}$ 都存在唯一的 $c$ 符合 $\mathrm{sum}(a; b; c)$：

    - 存在性：如果 $a\ \mathrm{nat}$ 且 $b\ \mathrm{nat}$ 则存在 $c$ 使得 $\mathrm{sum}(a; b; c)$
        - 设 $P(a\ \mathrm{nat})$ 的含义为“对于任意 $b\ \mathrm{nat}$ 存在 $c$ 使得 $\mathrm{sum}(a; b; c)$
        - 当 $a=\mathsf{zero}$ 时，根据第一个规则显然成立，此时 $c=b$
        - 假设 $P(a\ \mathrm{nat})$ 成立，需要证明 $P(\mathrm{succ}(a)\ \mathrm{nat})$ 成立
            - 因为 $P(a\ \mathrm{nat})$，因此对于这个 $b$ 存在 $c'$ 使得 $\mathrm{sum}(a; b; c')$，根据第二个规则有 $\mathrm{sum}(\mathrm{succ}(a); b; \mathrm{succ}(c'))$，因此可令 $c=\mathrm{succ}(c')$
    - 唯一性：如果 $\mathrm{sum}(a; b; c_1)$ 与 $\mathrm{sum}(a; b; c_2)$，则 $c_1=c_2\ \mathrm{nat}$
        - 当 $a=\mathsf{zero}$ 时，根据第一个规则有 $c_1 = b = c_2$
        - 设 $\mathrm{sum}(a; b; c_1), a=\mathrm{succ}(a'), c_1=\mathrm{succ}(c_1')$，如果 $\mathrm{sum}(a; b; c_2)$，根据第二个规则有 $\mathrm{sum}(\mathrm{succ}(a'); b; \mathrm{succ}(c_1'))$，即 $\mathrm{sum}(a; b; c_1)，因为它们来源于同一条规则，所以 $c_1 = c_2$

- 模式
    - 一条判断中，有一些参数是由另外参数决定的，称为判断的模式声明
    - e.g. 加法函数 $\mathrm{sum}(a; b; c)$
        - $c$ 由 $a, b$ 决定，所以它具有模式 $(\forall, \forall, \exists)$
        - 如果 $c$ 是唯一的，就写作 $(\forall, \forall, \exists !)$
        - 如果 $c$ 不一定存在（最多一个），写作 $(\forall, \forall, \exists\leq 1)$

### 推导

- 规则归纳（rule induction）
    - 要证明“性质 $a\ P$ 在 $a\ J$ 可推导时成立”，则只需证明“$P$ 封闭于定义判断形式 $J$ 的规则或 $P$ 遵从这些规则”
    - 即如果当 $P(a_1), \cdots, P(a_k)$ 成立时 $P(a)$ 成立，则性质 $P$ 遵从规则 $\dfrac{a_1\ J\cdots a_k\ J}{a\ J}$
        - 分子称为这个推理的归纳假设（inductive hypotheses）
        - 分母称为归纳结论（inductive conclusion）
- 根据已知的公理、定理、定律、定义等，借助于逻辑推理、数值演算等，得出新的结论
- 一个判断的推导过程是规则的有限组合，由公理开始，以判断结束
- 推导是一棵树，结点是规则，其子结点是以该规则为前提的推导过程
- 找到一个推导过程就可以说明一个归纳定义判断是可推导的
- 推导方向：
    - 前向链接（forwarding chaining）、自底向上构造（bottom-up construction）：从公理开始，没有方向的
    - 反向链接（backwarding chaining）、自顶向下构造（top-down construction）：从结论开始，是目标导向的

## 假言判断与一般性判断

!!! warning "大翁老师好像没讲，但后面会用到一些记法，看的 [xyx 的笔记](https://xuan-insr.github.io/pl/ppl_notes/3_Hypothetical_and_General_Judgments/)"

- 前面如 $a\ \mathrm{nat}$ 的判断称为基本判断（basic judgement）
- 假言判断（hypothetical judgement）：假设（hypothesis）和结论（conclusion）之间的蕴含关系（entailment）
    - 设 $\Gamma = \{J_1, \cdots, J_k\}$ 为若干基本判断的集合，$R$ 为一个规则集合，$J$ 为基本判断
    - 可导性判断（derivability judgement）：$\Gamma\vdash_R J$，表示根据 $R$ 如果 $\Gamma$ 成立，则 $J$ 成立
        - $\Gamma_1\vdash_R \Gamma_2$ 表示 $\Gamma_1\vdash_R J, \forall J\in\Gamma_2$
        - $\vdash_R J$ 表示 $J$ 可直接从 $R$ 中推导
        - 有自反性、弱化、传递性
    - 可纳性判断（admissible judgement）：$\Gamma\vDash_R J$，表示如果 $\Gamma$ 可由 $R$ 推导，则 $J$ 也可以
        - 也有自反性、弱化、传递性
- 一般性判断（general judgement）：
    - 对于 $\Gamma\vdash_R J$，将 $\Gamma$ 中用到的变量记为 $X$，则可记为 $\Gamma\vdash_R^X J$
    - 将 $X$ 拆分，$\Gamma$ 中自由变量记为 $Y$，其他记为 $X$，则可记 $Y\ |\ \Gamma\vdash_R^X J$