---
comment: True
counter: True
---

# 判定问题

!!! abstract
    理论计算机科学导引第九至第十周课程内容

## Church-Turing Thesis

Intuition of algorithms equals (deterministic) Turing machine that halts on every input. 即算法本质上就是图灵机。算法用来解决（判定）问题，而图灵机可以判定语言，二者是等价的。

## 编码与判定问题

- Any finite set can be encoded
- A finite collection of finite sets can be encoded
    - FA, PDA, CFG, REX, TM 都可以被编码
- 对于 $O$，我们用 $\texttt{"}O\texttt{"}$ 表示其编码
- decide problem <=> recursive languages（可判定）

???+ example "判定问题 $R_1$"
    $A_{\text{DFA}}=\{\texttt{"}D\texttt{"}\texttt{"}w\texttt{"}: D\text{ is a DFA that accpets }w\}$

    设计一个图灵机 $M_{R_1}$ 判定这个问题，输入为 $\texttt{"}D\texttt{"}\texttt{"}w\texttt{"}$

    0. 默认的判断（以后不再重复写）
        1. 如果输入是非法的，则 reject
        2. 如果输入是合法的，则进行解码，得到 $D$ 和 $w$
    1. run $D$ on $w$
    2. if $D$ ends with final ($D$ accept $w$)
    3. &emsp;&emsp;accept $\texttt{"}D\texttt{"}\texttt{"}w\texttt{"}$
    4. else
    5. &emsp;&emsp;reject

???+ example "判定问题 $R_2$"
    $A_{\text{NFA}}$，即 NFA $N$ 是否接受字符串 $w$

    $M_{R_2}$ = on input $\texttt{"}N\texttt{"}\texttt{"}w\texttt{"}$

    1. $N$ -> an equivalent DFA $D$
    2. run $M_{R_1}$ on $\texttt{"}D\texttt{"}\texttt{"}w\texttt{"}$
    3. return the result of $M_{R_1}$

    $\texttt{"}N\texttt{"}\texttt{"}w\texttt{"}\in A_{\text{NFA}}$ <=> $\texttt{"}D\texttt{"}\texttt{"}w\texttt{"}\in A_{\text{DFA}}$ 称为 a reduction from $A_{\text{NFA}}$ to $A_{\text{DFA}}$，即规约

??? example "判定问题 $R_3$ ($A_{\text{REX}}$)"
    $A_{\text{REX}}=\{\texttt{"}R\texttt{"}\texttt{"}w\texttt{"}: R\text{ is a regular expression that generates }w\}$

    $M_{R_3}$ = on input $\texttt{"}R\texttt{"}\texttt{"}w\texttt{"}$

    1. $R$ -> an equivalent NFA $N$
    2. run $M_{R_2}$ on $\texttt{"}N\texttt{"}\texttt{"}w\texttt{"}$
    3. return the result of $M_{R_2}$

??? example "判定问题 $R_4$ ($E_{\text{DFA}}$)"
    $E_{\text{DFA}}=\{\texttt{"}D\texttt{"}: D\text{ is a DFA with }L(D)=\emptyset\}$

    $M_{R_4}$ = on input $\texttt{"}D\texttt{"}$

    1. if $D$ has no final state
    2. &emsp;&emsp;accept
    3. else
    4. &emsp;&emsp;"conceptually" do BFS in the diagram
    5. &emsp;&emsp;if there is a path from $s$ to a final state
    6. &emsp;&emsp;&emsp;&emsp;reject
    7. &emsp;&emsp;else
    8. &emsp;&emsp;&emsp;&emsp;accept

??? example "判定问题 $R_5$ ($EQ_{\text{DFA}}$)"
    $EQ_{\text{DFA}} = \{\texttt{"}D_1\texttt{"}\texttt{"}D_2\texttt{"}: D_1\text{ and }D_2\text{ are two DFAs with }L(D_1)=L(D_2)\}$

    Hint:

    - 对称差 $A\oplus B=\{x\in A\cup B\text{ and }x\notin A\cap B\}=A\cup B - A\cap B$
        - $A\oplus B = (A\cup B)\cap(\overline{A\cap B}) = (A\cup B)\cap(\overline{A}\cup\overline{B})$
    - $A=B$ iff $A\oplus B = \emptyset$（可以借此规约至 $R_4$）

    $M_{R_5}$ = on input $\texttt{"}D_1\texttt{"}\texttt{"}D_2\texttt{"}$

    1. construct $D_3$ with $L(D_3) = L(D_1)\oplus L(D_2)$
    2. run $M_{R_4}$ on $\texttt{"}D_3\texttt{"}$
    3. return the result of $M_{R_4}$

### 规约

- 规约定义：
    - $A,B$ are languages over some alphabet $\Sigma$
    - A reduction from $A$ to $B$ is a recursive function $f\colon \Sigma^*\rightarrow\Sigma^*$
    - s.t. for $x\in\Sigma^*$, $x\in A$ iff $f(x)\in B$
- Theorem. If $B$ is recursive, and exists a reduction $f$ from $A$ to $B$, then $A$ is recursive.
    - Proof. $\exist M_B$ decides $B$, $M_A$ = on input $x$:
        1. compute $f(x)$
        2. run $M_B$ on $\texttt{"}f(x)\texttt{"}$
        3. return the result of $M_B$
- $A$ 的判定难度小于等于 $B$，所以 $A$ 可以规约到 $B$ 也可以记为 $A\leq B$

??? example "判定问题 $C_1$ ($A_{\text{CFG}}$)"
    $A_{\text{CFG}} = \{\texttt{"}G\texttt{"}\texttt{"}w\texttt{"}: G\text{ is a CFG that generates }w\}$

    $M_{C_1}$ = on input $\texttt{"}G\texttt{"}\texttt{"}w\texttt{"}$

    1. $G$ -> $G'$ in CNF
    2. enumerate all the derivations of length $2|w|-1$
    3. if any of them generates $w$
    4. &emsp;&emsp;accept $\texttt{"}G\texttt{"}\texttt{"}w\texttt{"}$
    5. else
    6. &emsp;&emsp;reject

??? example "判定问题 $C_2$ ($A_{\text{PDA}}$)"
    $A_{\text{PDA}} = \{\texttt{"}P\texttt{"}\texttt{"}w\texttt{"}: P\text{ is a PDA that accepts }w\}$

    可以规约到问题 $C_1$。

??? example "判定问题 $C_3$ ($E_\text{CFG}$)"
    $E_\text{CFG} = \{\texttt{"}G\texttt{"}: G\text{ is a CFG with }L(G)=\emptyset\}$

    提供一个算法来进行判断：

    - 标记所有的 terminal symbol
    - 如果一个规则的右侧均被标记，则同样标记左侧符号出现的所有位置
    - 最终无法进一步标记时，如果 S 被标记了，则 $L(G)$ 不为空

    S 被标记了相当于存在一种方案可以推导至均为 terminal。

    e.g. S->Aa A->CB C->e C->a B->b，先标记 abe，再标记 CB，再标记 A（因为 A->CB），再标记 S，所以这个 CFG 的 language 不为空。

??? example "判定问题 $C_4$ ($E_\text{PDA}$)"
    可以规约到 $C_3$。

## 语言的存在性问题

目前我们知道的语言分类如下：

![](/assets/images/cs/tcs/toc/topic4/img1.light.png#only-light)
![](/assets/images/cs/tcs/toc/topic4/img1.dark.png#only-dark)

接下来想要找到两种语言：

- recursively enumerable 但不 recursive
- 不 recursively enumerable

### 集合的可列性

集合 $S$ 是可列的（countable）当且仅当它是有限的或存在双射 $f\colon S\to\mathbb{N}$，否则就是不可列的（uncountable）。

???+ success "Lemma 1. 集合 $S$ 是可列的当且仅当存在一个单射 $g\colon S\to\mathbb{N}$"
    Proof. 如果 $S$ 是有限的，则自然成立，否则：

    - 左推右，双射也满足单射，自然成立
    - 右推左，则构造一个双射
        - 存在单射，则可以将 $S$ 的元素进行排序并编号 $S_1, S_2, \cdots$
            - 同时使其满足 $g(S_1) < g(S_2) < \cdots$
        - 令 $f(S_i) = i$，则 $f$ 是一个双射

???+ tip "Corollary 1. 任意可列集的子集也是可列的"
    Proof. 根据 Lemma 1. $A$ 是可列的，则存在单射 $f\colon A\to\mathbb{N}$，则任意 $A'\subseteq A$，也存在单射 $f\colon A'\to\mathbb{N}$ 成立，所以 $A'$ 是可列的。

### 非递归可枚举语言的存在性

???+ success "Lemma 2. 对于符号集 $\Sigma$，$\Sigma^*$ 是可列的"
    假设 $\Sigma=\{0, 1\}$，则 $\Sigma^*=\{e, 0, 1, 00, 01, 10, 11, \cdots\}$，可以将其映射到 $\{0, 1, 2, \cdots\}$，而且是双射，所以是可列的。

    证明的话则说明 $\forall s\in\Sigma^*, \exist f(s)$ 即可，而 $f(s)$ 不会超过 $2^{|s|}$，所以总可以找到。

???+ tip "Corollary 2. 所有图灵机组成的集合 $\{M: M\text{ is a TM}\}$ 是可列的"
    图灵机都可以用有限的符号集表示，所以等价于字符串，根据 Lemma 2. 所有图灵机组成的集合是可列的。

???+ success "Lemma 3. 令 $\mathcal{L}$ 是 $\Sigma$ 上所有语言的集合，则 $\mathcal{L}$ 不可列"
    Proof. 反证法，假设 $\mathcal{L}$ 是可列的，则可以将其元素编号为 $L_1, L_2, \cdots$。而 $\Sigma^*$ 是可列的，也可以将其编号为 $s_1, s_2, \cdots$。

    接下来构造一个语言 $D=\{s_i:s_i\notin L_i\}$，因为它也是一个 $\Sigma$ 上的语言，所以应该也属于 $\mathcal{L}$。但其包含的字符串都有不属于某一个现有语言中的，即 $\forall i, s_i\in D\text{ iff }s_i\notin L_i$，所以 $D\neq L_i$，所以 $D$ 不属于 $\mathcal{L}$，矛盾。

根据 Corollary 2. 和 Lemma 3. 我们知道图灵机的集合是可列的，但语言的集合是不可列的，所以一定存在一些语言是不能被图灵机判定的，也就是非 recursively enumerable 的。

### 停机问题

现定义语言 $H=\{\texttt{"}M\texttt{"}\texttt{"}w\texttt{"}: M\text{ is a TM that halts on }w\}$，即判定图灵机 $M$ 是否在输入 $w$ 上停机。

???+ success "Theorem 1. 语言 $H$ 是 recursively enumerable 的"
    很简单，直接让 $M$ 在 $w$ 上运行即可，停机就是 accept，不停机就是 reject，所以是 recursively enumerable 的。

    形式化描述则构造图灵机 $U$ = on input $\texttt{"}M\texttt{"}\texttt{"}w\texttt{"}$：

    1. run $M$ on $w$

    $U$ halts on $\texttt{"}M\texttt{"}\texttt{"}w\texttt{"}$ iff $M$ halts on $w$.

    （这个图灵机 $U$ 后续还会用到）

???+ success "Theorem 2. 语言 $H$ 不是 recursive 的"
    再定义一个语言 $H_d=\{\texttt{"}M\texttt{"}: M\text{ is a TM that does NOT halt on }\texttt{"}M\texttt{"}\}$，即判定图灵机 $M$ 是否在输入 $\texttt{"}M\texttt{"}$（自己的编码）上停机。

    接下来我们尝试分别证明两个结论：

    ??? tip "如果 $H$ 是 recursive 的，则 $H_d$ 也是"
        如果 $H$ 是 recursive 的，则存在图灵机 $M_H$ 判定 $H$，那么构造图灵机 $M_d$ = on input $\texttt{"}M\texttt{"}$：

        1. run $M_H$ on $\texttt{"}M\texttt{"}\texttt{"}M\texttt{"}$
        2. if $M_H$ accepts $\texttt{"}M\texttt{"}\texttt{"}M\texttt{"}$
        3. &emsp;&emsp;reject
        4. else
        5. &emsp;&emsp;accept

        那么这个图灵机可以判定 $H_d$，所以 $H_d$ 是 recursive 的。
    
    ??? tip "语言 $H_d$ 不是 recursively enumerable 的"
        假设它是，则存在图灵机 $D$ 半判定它，则 $D$ 在输入 $\texttt{"}M\texttt{"}$ 时：

        - 如果 $\texttt{"}M\texttt{"}\in H_d$ 则停机
        - 如果 $\texttt{"}M\texttt{"}\notin H_d$ 则不停机

        那么当 $M=D$ 时，则出现情况：

        - 如果 $\texttt{"}D\texttt{"}\in H_d$ 则停机
            - 而  $\texttt{"}D\texttt{"}\in H_d$ 意味着 $D$ 不会在自身编码上停机，矛盾
        - 如果 $\texttt{"}D\texttt{"}\notin H_d$ 则不停机
            - 而  $\texttt{"}D\texttt{"}\notin H_d$ 意味着 $D$ 会在自身编码上停机，矛盾
        
        所以假设不成立，$H_d$ 不是 recursively enumerable 的。
    
    根据这两个结论，如果 $H$ 是 recursive 的，则 $H_d$ 也是，而 recursive 一定是 recursively enumerable 的，但我们又证明了 $H_d$ 不是 recursively enumerable 的，所以产生了矛盾。那么就说明 $H$ 不是 recursive 的。

这样就找到了之前说到的两个语言：

- $H$：recursively enumerable 但不 recursive
- $H_d$：不 recursively enumerable

### 停机问题相关判定问题

!!! success "如果 $A\leq B$，且 $A$ 是非 recursive 的，则 $B$ 也非 recursive"

???+ example "判定问题 $A_1 = \{\texttt{"}M\texttt{"}: M\text{ is a TM that halts on }e\}$"
    试图进行规约 $H\leq A_1$，根据规约的定义需要满足将任意输入给 $H$ 的字符串 $\texttt{"}M\texttt{"}\texttt{"}w\texttt{"}$ 转换为输入给 $A_1$ 的字符串 $\texttt{"}M^*\texttt{"}$，满足 $M$ 在 $w$ 上停机当且仅当 $M^*$ 在 $e$ 上停机。

    则定义图灵机 $M^*$ = on input $u$

    1. run $M$ on $w$

    这样就可以达到效果。即 $M^*$ 在 $e$ 上停机 <=> $M^*$ 在某些字符串上停机 <=> $M^*$ 在任意输入上停机 <=> $M$ 在 $w$ 上停机。

??? example "判定问题 $A_2 = \{\texttt{"}M\texttt{"}: M\text{ is a TM that halts on some input}\}$"
    根据上面 $A_1$ 的结论，使用 $M^*$ 即可，是完全等价的。

??? example "判定问题 $A_3 = \{\texttt{"}M\texttt{"}: M\text{ is a TM that halts on every input}\}$"
    同理等价

???+ example "判定问题 $A_4 = \{\texttt{"}M_1\texttt{"}\texttt{"}M_2\texttt{"}: M_1\text{ and }M_2\text{ are two TM with }L(M_1)=L(M_2)\}$"
    尝试规约 $A_3\leq A_4$，$A_3$ 的输入为 $\texttt{"}M\texttt{"}$，$A_4$ 的输入为 $\texttt{"}M_1\texttt{"}\texttt{"}M_2\texttt{"}$，需要满足 $M$ 在任意输入上停机当且仅当 $M_1$ 和 $M_2$ 半判定的语言相同。

    令 $M_1$ = $M$, $M_2$ = on input $x$:
    
    1. halts

    这样我们知道 $M_2$ 会在任意输入上停机，所以 $M$ 在任意输入上停机 <=> $M$ 即 $M_1$ 和 $M_2$ 半判定的语言相同。

???+ example "判定问题 $R_\text{TM}=\{\texttt{"}M\texttt{"}: M\text{ is a TM with }L(M)\text{ is regular}\}$"
    问题 $\overline{R_\text{TM}} = \{\texttt{"}M\texttt{"}: M\text{ is a TM with }L(M)\text{ is not regular}\}$ 是可判定的则 $R_\text{TM}$ 也是可判定的。

    接下来尝试规约 $H\leq\overline{R_\text{TM}}$，$H$ 的输入 $\texttt{"}M\texttt{"}\texttt{"}w\texttt{"}$ 转换为 $\overline{R_\text{TM}}$ 的输入 $\texttt{"}M^*\texttt{"}$，需要满足 $M$ 在 $w$ 上停机当且仅当 $L(M^*)$ 不是 regular 的。

    构造图灵机 $M^*$ = on input $x$

    1. run $M$ on $w$
    2. run $U$ on $x$

    则 $L(M^*)$ 有两种情况：

    - 在第一行停机时 $L(M^*) = L(U) = H$
    - 在第一行不停机时 $L(M^*) = \emptyset$

    因为 $\emptyset$ 是 regular 的，所以 $L(M^*)$ 不是 regular 的 <=> $M$ 在 $w$ 上停机。

??? example "判定问题 $CF_\text{TM}=\{\texttt{"}M\texttt{"}: M\text{ is a TM with }L(M)\text{ is context-free}\}$"
    同上，$\emptyset$ 也是 context-free 的，所以同样可以规约 $H\leq CF_\text{TM}$。

??? example "判定问题 $REC_\text{TM}=\{\texttt{"}M\texttt{"}: M\text{ is a TM with }L(M)\text{ is recursive}\}"
    同上，$\emptyset$ 也是 recursive 的，所以同样可以规约 $H\leq REC_\text{TM}$。