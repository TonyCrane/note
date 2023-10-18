---
comment: True
counter: True
---

# 语言、自动机与正则表达式

!!! abstract
    理论计算机科学导引第一至第四周课程内容

## 前言

- 问题分类
    - 优化问题（Optimization Problem）如最小生成树
    - 搜索问题（Search Problem）如找一棵权重最大为 k 的生成树
    - 决策问题（Decision Problem）如判断是否存在一棵权重最大为 k 的生成树
    - 计数问题（Counting Problem）
- 决策问题最简单
    - 对于一个问题有 yes-instance 和 no-instance
    - 问题可以转化为 Given a string $w$, whether $w\in \{\text{encoding of yes-instance}\}$
    - $\{\text{encoding of yes-instance}\}$ 就是一个语言（Language）

## 语言定义

- 字母表 Alphabet: **finite** set of symbols
    - $\Sigma = \{a, b, c\}$、$\Sigma = \{0, 1\}$、$\Sigma = \{\ \}$
- 字符串 String over $\Sigma$: **finite** sequence of symbols from $\Sigma$
    - $w = 010101$，$w = e$（或 $\epsilon$）是空串
    - $|w|$ 表示字符串长度，$|e| = 0$
    - $\Sigma^i$: set of all strings of length $i$ over $\Sigma$
    - $\Sigma^* = \bigcup_{i\geq 0} \Sigma^i$（$\Sigma$ 上所有字符串），$\Sigma^+ = \bigcup_{i\geq 1} \Sigma^i$
    - 字符串操作
        - 拼接（concatenation）：$w_1w_2$，$|w_1w_2| = |w_1| + |w_2|$
        - 反转（reversal）：$w^R$，$|w^R| = |w|$
        - 重复（exponentiation）：$w^i = \underbrace{ww\cdots w}_{i\ times}$，$|w^i| = i|w|$
- 语言 Language over $\Sigma$: any subset of $\Sigma^*$

## 自动机

自动机（finite automata）有两种：

- Deterministic Finite Automata (DFA)：确定性有限自动机，每一步的转移都是确定的
- Non-deterministic Finite Automata (NFA)：非确定性有限自动机，每一步的转移可以有多种选择

### DFA

\automata
    \node[initial,state]    (q_0)                   {$q_0$};
    \node[state]            (q_1) [right=of q_0]    {$q_1$};
    \node[state,accepting]  (q_2) [right=of q_1]    {$q_2$};
    
    \path
        (q_0) edge [loop above]         node {0} (q_0)
              edge                      node {1} (q_1)
        (q_1) edge [loop above]         node {1} (q_1)
              edge                      node {0} (q_2)
        (q_2) edge [in=30,out=60,loop]  node {0} (q_2)
              edge [bend left]          node {1} (q_1);

- 如上图就是一个 DFA，$q_0$ 是初始状态，双圈 $q_1$ 是接受状态，箭头上的字母是转移条件
- 一个 NFA 定义为一个五元组 $M = (K, \Sigma, \delta, s, F)$
    - $K$：状态集合
    - $\Sigma$：字母表
    - $\delta$：转移函数，$\delta\colon K\times \Sigma \to K$
    - $s$：初始状态
    - $F$：接受状态集合
- 执行逻辑：输入一个字符串，从初始状态，每次取出第一个字符，根据当前状态和字符查找转移函数，得到下一个状态，直到字符串为空
- configuation：$C = (q, w)$，表示当前状态 $q$ 和剩余字符串 $w$
- yields
    - yields in one step：可一步转移到
        - 记为 $(q, w)\vdash_M (q', w')$，if $w=aw'$ for some $a\in\Sigma$ and $\delta(q, a) = q'$
    - yields：可转移到
        - 记为 $(q, w)\vdash_M^* (q', w')$，if $(q, w)\vdash_M (q_1, w_1)\vdash_M \cdots \vdash_M (q', w')$
- 自动机接受字符串
    - $M$ accepts $w\in\Sigma^*$, if $(s, w)\vdash_M^* (q, e)$ for some $q\in F$
    - 即可以从初始状态 $s$ 通过一系列转移得到接受状态 $q$，且剩余字符串为空
- 自动机对应的语言（Language of $M$）
    - $L(M) = \{w\in\Sigma^*: M\text{ accepts }w\}$
    - 即所有能被自动机接受的字符串
- 自动机接受的语言
    - $M$ accepts $L$ if $M$ accepts every string in $L$ and rejects every string not in $L$
    - $M$ accepts $L(M)$

### NFA

\automata
    \node[initial,state]    (q_0)                   {$q_0$};
    \node[state]            (q_1) [right=of q_0]    {$q_1$};
    \node[state,accepting]  (q_2) [right=of q_1]    {$q_2$};
    
    \path 
        (q_0) edge [loop above]         node {a}   (q_0)
              edge                      node {a,b} (q_1)
        (q_1) edge [bend left]          node {b}   (q_0)
              edge                      node {a,e} (q_2);

- 如上图是一个 NFA，和 DFA 有以下两个区别：
    - 一个状态同一条件可以有多个转移方案
    - 可以有 $e$-transition，即不消耗字符的转移
- 同样定义为五元组 $M = (K, \Sigma, \Delta, s, F)$
    - 和 DFA 区别只在 $\Delta$，是一个比函数更一般的关系（relation）
    - $\Delta$：转移关系，$\Delta\subseteq K\times (\Sigma\cup\{e\})\times K$
- 对于一个输入，NFA 可以有多种路线，但只要有一种路线能够接受，就认为 NFA 接受该输入
    - 一种**理解**方式：NFA 可以猜测该往哪里转移，且总能猜对

??? example "Ex. 构造 NFA 接受 $L=\{w\in\{a, b\}^*: \text{the second symbol from the end is }b\}$"
    \automata
        \node[initial,state]    (q_0)                   {$q_0$};
        \node[state]            (q_1) [right=of q_0]    {$q_1$};
        \node[state,accepting]  (q_2) [right=of q_1]    {$q_2$};
        
        \path
            (q_0) edge [loop above]         node {a,b} (q_0)
                  edge                      node {b}   (q_1)
            (q_1) edge                      node {a,b} (q_2);

### NFA 与 DFA

- NFA 虽然看起来比 DFA 强大，但其二者实际上是等价的
    - $\forall$ NFA $M$，$\exists$ DFA $M'$，s.t. $L(M) = L(M')$
    - $\forall$ DFA $M$，$\exists$ NFA $M'$，s.t. $L(M) = L(M')$
- NFA 转 DFA 主要思路
    - NFA 接收一个字符，会有多个转移方案，所有可达的下一状态合在一起的集合构成 DFA 的一个状态
    - 即 DFA 的状态是 NFA 的状态的幂集，结束状态是包含 NFA 的结束状态的 DFA 状态
    - $e$-transition 也要考虑，且不算在字符数里
- NFA $M=(K, \Sigma, \Delta, s, F)$ 转为 DFA $M'=(K', \Sigma, \delta, s', F')$
    - $K' = 2^K = \{Q: Q\subseteq K\}$
    - $F' = \{Q\in K': Q\cap F\neq \emptyset\}$
    - $s' = E(s)$
        - 定义 $\forall q\in K, E(q) = \{p\in K: (q, e)\vdash_M^* (p, e)\}$
        - 即 $E(q)$ 是 $q$ 可以通过 $e$-transition 到达的状态集合
    - $\delta$: $\forall Q\in K', \forall a\in\Sigma$
    
$$
\delta(Q, a) = \bigcup_{q\in Q}\ \bigcup_{p: (q, a, p)\in\Delta}E(p)
$$

???+ example "一个 NFA 转 DFA 的具体例子"
    \automata
        \node[initial,state]    (q_0)                   {$q_0$};
        \node[state,accepting]  (q_1) [right=of q_0]    {$q_1$};
        \node[initial,state]    (p_0) [right=of q_1]    {$\{q_0\}$};
        \node[state,accepting]  (p_1) [right=of p_0]    {$\{q_0,q_1\}$};
        \node[state,accepting]  (p_2) [below=of p_0]    {$\{q_1\}$};
        \node[state]            (p_3) [right=of p_2]    {$\emptyset$};
        
        \path
            (q_0) edge [loop above]         node {a,b} (q_0)
                  edge                      node {b}   (q_1)
            (q_1) edge [bend left]          node {e}   (q_0)
            (p_0) edge [loop above]         node {a}   (p_0)
                  edge                      node {b}   (p_1)
            (p_1) edge [bend left]          node {a}   (p_0)
                  edge [in=30,out=60,loop]  node {b}   (p_1)
            (p_2) edge                      node {a,b} (p_3)
            (p_3) edge [in=30,out=60,loop]  node {a,b} (p_3);

    右侧 DFA 的下边部分是冗余的，可以删掉。

## 正则语言

- A language is regular if it is accepted by some FA
    - 有自动机可以接受的语言是正则的
- Regular Operations
    - Union: $A\cup B = \{w: w\in A\text{ or }w\in B\}$
    - Concatenation: $A\circ B = \{ab: a\in A\text{ and }b\in B\}$
    - Star: $A^* = \{w_1w_2\cdots w_k: k\geq 0\text{ and each }w_i\in A\}$
- 定理：
    - 如果 $A$ 和 $B$ 是正则语言，则 $A\cup B$、$A\circ B$、$A^*$ 也是正则语言
- claim：如果 NFA $M$ accepts $w$，则转为的 DFA $M'$ accepts $w$，反之也成立
    - Corollary：a language is regular $\iff$ it is accepted by some DFA

??? success "Proof. if $A$ and $B$ are regular, so is $A\cup B$"
    思路：合并两个接收 $A$ 和 $B$ 的 DFA

    $\exists M_A=(K_A, \Sigma, \delta_A, s_A, F_A)\text{ accepts }A$，$\exists M_B=(K_B, \Sigma, \delta_B, s_B, F_B)\text{ accepts }B$

    $\text{let }M=(K, \Sigma, \delta, s, F)$，where:

    - $K = K_A\times K_B$
    - $s = (s_A, s_B)$
    - $F = \{(q_A, q_B): q_A\in F_A\text{ or }q_B\in F_B\}$
    - $\delta$: $\forall q_A\in K_A, \forall q_B\in K_B, \forall a\in\Sigma,\ \delta\big((q_A, q_B), a\big) = \big(\delta_A(q_A, a), \delta_B(q_B, a)\big)$

    $\text{then }M\text{ accepts }A\cup B$

??? success "Proof. if $A$ and $B$ are regular, so is $A\circ B$"
    思路：连接两个接收 $A$ 和 $B$ 的 NFA

    $\exists M_A=(K_A, \Sigma, \Delta_A, s_A, F_A)\text{ accepts }A$，$\exists M_B=(K_B, \Sigma, \Delta_B, s_B, F_B)\text{ accepts }B$

    \automata\zoom{1.2}
        \node[initial,initial distance=1cm,state]       (q_0)   {};
        \node[state,accepting]          at (2,0.7)      (q_1)   {};
        \node[state,accepting]          at (2,-0.7)     (q_2)   {};
        \node                           at (1,0)        (dots)  {$\cdots$};
        \node                           at (1,1.8)              {$M_A$};
        \draw[rounded corners] (-0.8,-1.4) rectangle (2.8,1.4);
        
        \node[initial,state]            at (4.8, 0)     (p_0)   {};
        \node[state,accepting]          at (6.8,0.7)    (p_1)   {};
        \node[state,accepting]          at (6.8,-0.7)   (p_2)   {};
        \node                           at (5.8,0)      (dots)  {$\cdots$};
        \node                           at (5.8,1.8)            {$M_B$};
        \draw[rounded corners] (4,-1.4) rectangle (7.6,1.4);
        
        \path
        (q_1)   edge [bend left]        node [above] {e} (p_0)
        (q_2)   edge [bend right]       node [below] {e} (p_0);

    $\text{let }M=(K, \Sigma, \Delta, s, F)$，where:

    - $K = K_A\cup K_B$
    - $s = s_A$
    - $F = F_B$
    - $\Delta = \Delta_A\cup \Delta_B\cup \{(q_A, e, s_B): q_A\in F_A\}$

    $\text{then }M\text{ accepts }A\circ B$

??? success "Proof. if $A$ and $B$ are regular, so is $A^*$"
    思路：让一个接收 $A$ 的 NFA 自己进行循环

    $\exists M_A=(K_A, \Sigma, \Delta_A, s_A, F_A)\text{ accepts }A$

    \automata\zoom{1.2}
        \node[initial,state,accepting]  at (-2, 0)  (q)     {};
        \node[initial,state]                        (q_0)   {};
        \node[state,accepting]          at (2,0.7)  (q_1)   {};
        \node[state,accepting]          at (2,-0.7) (q_2)   {};
        \node                           at (1,0)    (dots)  {$\cdots$};
        \node                           at (1,1.8)          {$M_A$};
        \draw[rounded corners] (-0.8,-1.4) rectangle (2.8,1.4);
        
        \path
        (q)     edge                node         {e} (q_0)
        (q_1)   edge [bend right]   node [above] {e} (q_0)
        (q_2)   edge [bend left]    node [below] {e} (q_0);

    !!! warning "注意"
        $A^*$ 包括空串，所以要保证初始状态也是接受状态。但同时又不能让 $M_A$ 的初始状态变为接受状态，也不能让其初始状态通过 $e$-transition 到达接受状态，否则如果 $M_A$ 途中返回初始状态，就可能导致接受了其他不该接受的字符串。所以要新建一个初始状态 $s$，通过 $e$-transition 到达 $s_A$，且 $s$ 也是接受状态。
    
    $\text{let }M=(K, \Sigma, \Delta, s, F)$，where:

    - $K = K_A\cup \{s\}$
    - $s = s$（即新建的一个初始状态）
    - $F = F_A\cup \{s\}$
    - $\Delta = \Delta_A\cup \{(s, e, s_A)\}\cup \{(q_A, e, s_A): q_A\in F_A\}$

    $\text{then }M\text{ accepts }A^*$

### Pumping Theorem

可以用来证明一个语言不是正则语言的一个定理。其内容如下：

- 令 $L$ 为一个正则语言
- 则存在一个整数 $p\geq 1$（称为 pumping length）
- 使得对于所有长度不小于 $p$ 的字符串 $w\in L$
- 都可以将 $w$ 分解为三部分 $w=xyz$，满足：
    1. 对于任意 $k\geq 0$，有 $xy^kz\in L$
    2. $|y|\geq 1$
    3. $|xy|\leq p$

??? success "Proof"
    如果 $L$ 是有限的，那么令 $p=\displaystyle\max_{w\in L}|w|+1$ 即可满足所有要求。

    如果 $L$ 是无限的，因为其是正则语言，所以存在一个 DFA $M$ 接受 $L$。令 $p$ 为 $M$ 的状态数，即 $p=|K|$。

    令 $w\in L$ 且 $|w|\geq p$，现假设 $w=a_1a_2\cdots a_n$，则该自动机一定包含如下一条路径：

    \automata
        \node[initial,state]    (q_0)                       {$q_0$};
        \node[state]            (q_1)   [right=of q_0]      {$q_1$};
        \node[state]            (q_2)   [right=of q_1]      {$q_2$};
        \node       at (5, 0)   (dots)                      {$\cdots$};
        \node[state]            (q_n_2) [right=of q_2]      {$q_{n-2}$};
        \node[state]            (q_n_1) [right=of q_n_2]    {$q_{n-1}$};
        \node[state,accepting]  (q_n)   [right=of q_n_1]    {$q_n$};
        
        \path 
            (q_0)   edge      node    {$a_1$}       (q_1)
            (q_1)   edge      node    {$a_2$}       (q_2)
            (q_n_2) edge      node    {$a_{n-1}$}   (q_n_1)
            (q_n_1) edge      node    {$a_n$}       (q_n);
    
    因为自动机只有 $p$ 个状态，但 $n$ 又不小于 $p$，所以一定存在 $0\leq i < j\leq p$，使得 $q_i$ 和 $q_j$ 是同一状态。这样这条路径就可以转化为：

    \automata
        \node[initial,state]                (q_0)   {$q_0$};
        \node[state]            at (4, 0)   (q_i)   {$q_i$};
        \node[state,accepting]  at (8, 0)   (q_n)   {$q_n$};
        
        \path
            (q_0)   edge                node    {$x=a_1\cdots a_i$}     (q_i)
            (q_i)   edge [loop above]   node    {$y=a_{i+1}\cdots a_j$} (q_i)
            (q_i)   edge                node    {$z=a_{j+1}\cdots a_n$} (q_n);
    
    因此 $xy^kz\in L$、$|y|=j-1\geq 1$、$|xy|=j\leq p$ 都满足。

??? example "证明 $L = \{0^n1^n:n\geq 0\}$ 不是正则语言"
    反证法，假设 $L$ 是正则的，令 $p$ 为其 pumping length。
    
    根据 pumping theorem，$0^p1^p\in L$ 可以被写成 $0^p1^p=xyz$，满足：

    - $xy^kz\in L, \forall k\geq 0$
    - $|y|\geq 1$
    - $|xy|\leq p$

    由后两条可以推出 $y=0^t$（其中 $t\geq 1$），那么令 $k=0$，有 $xy^kz=xy^0z=xz=0^{p-t}1^p$，但这个字符串不在 $L$ 中，不符合第一条，产生矛盾，所以 $L$ 一定不是正则语言。

## 正则表达式

一个正则表达式由以下规则定义：

- Atomic：对于 $\emptyset$ 对应语言 $L(\emptyset)=\emptyset$，对于 $a\in\Sigma$ 有 $L(a)=\{a\}$
- Composite：
    - $R_1\cup R_2$ 对应语言 $L(R_1\cup R_2) = L(R_1)\cup L(R_2)$
    - $R_1R_2$ 对应语言 $L(R_1R_2) = L(R_1)\circ L(R_2)$
    - $R_1^*$ 对应语言 $L(R_1^*) = L(R_1)^*$
    - 优先级：$^* > \circ > \cup$
        - Ex. $ab^*\cup b^*a=\big(a(b^*)\big)\cup\big((b^*)a\big)$

其实就类似于各编程语言中使用的正则表达式，不过那些正则表达式一般都加了不属于这里规定的正则表达式的更多功能（比如记录捕获组并在 \1 时引用捕获内容）。

??? example "例子"
    - $\emptyset^*$ 对应语言 $\{e\}$
    - $a(a\cup b)^*b$ 对应语言 $\{w\in\{a, b\}^*: w\text{ starts with }a\text{ and ends with }b\}$
    - $(a\cup b)^*a(a\cup b)^*a(a\cup b)^*$ 对应语言 $\{w\in\{a, b\}^*: w\text{ contains at least two }a\text{'s}\}$

一般用 $R$ 表示正则表达式，用 $L(R)$ 表示正则表达式对应的语言（匹配的字符串集合）。

- 给定一个 NFA $M$，要找一个正则表达式 $R$ 使得 $L(R) = L(M)$
- 考虑化简 $M$，且需要满足要求：
    - 初始状态没有入边
    - 只有一个没有出边的接受状态
- 化简思路：加一个初始状态和接受状态，用 $e$-transition 连接到原来的初始状态和接受状态，然后删除原来的初始状态和接受状态，再逐一删除中间状态

\automata\zoom{1.2}
    \node[initial,state,accepting]  at (-2, 0)  (q)     {};
    \node[initial,state]                        (q_0)   {};
    \node[state,accepting]          at (2,0.7)  (q_1)   {};
    \node[state,accepting]          at (2,-0.7) (q_2)   {};
    \node[state,accepting]          at (4,0)    (q_3)   {};
    \node                           at (1,0)    (dots)  {$\cdots$};
    \node                           at (1,1.8)          {$M$};
    \draw[rounded corners] (-0.8,-1.4) rectangle (2.8,1.4);
    
    \path
    (q)     edge                node         {$e$} (q_0)
    (q_1)   edge [bend left]    node [above] {$e$} (q_3)
    (q_2)   edge [bend right]   node [below] {$e$} (q_3);

??? example "一个化简的示例"
    要化简的自动机如下（已经修改了初始状态和接受状态，原来 $q_1$ 初始 $q_3$ 接受）：

    \automata\zoom{1.2}
        \node[initial,state]    at (0, 0)       (q_4)       {$q_4$};
        \node[state]            at (3, 0)       (q_1)       {$q_1$};
        \node[state]            at (6, 0)       (q_2)       {$q_2$};
        \node[state]            at (4.5, 2.598) (q_3)       {$q_3$};
        \node[state,accepting]  at (9, 0)       (q_5)       {$q_5$};
        
        \path
            (q_4)   edge                        node    {$e$}   (q_1)
            (q_1)   edge                        node    {$b$}   (q_3)
                    edge [in=105,out=135,loop]  node    {$a$}   (q_1)
            (q_2)   edge                        node    {$b$}   (q_1)
                    edge [loop right]           node    {$a$}   (q_2)
            (q_3)   edge                        node    {$b$}   (q_2)
                    edge [loop above]           node    {$a$}   (q_3)
                    edge                        node    {$e$}   (q_5);

    删掉状态 $q_1$（影响到 $q_4\to q_3$ 和 $q_2\to q_3$ 两条路径）：

    \automata\zoom{1.2}
        \node[initial,state]    at (0, 0)       (q_4)       {$q_4$};
        \node[state]            at (6, 0)       (q_2)       {$q_2$};
        \node[state]            at (4.5, 2.598) (q_3)       {$q_3$};
        \node[state,accepting]  at (9, 0)       (q_5)       {$q_5$};
        
        \path
            (q_4)   edge                        node    {$a^*b$}   (q_3)
            (q_2)   edge [bend left]            node    {$ba^*b$}   (q_3)
                    edge [loop right]           node    {$a$}   (q_2)
            (q_3)   edge                        node    {$b$}   (q_2)
                    edge [loop above]           node    {$a$}   (q_3)
                    edge                        node    {$e$}   (q_5);
    
    删掉状态 $q_2$（影响到 $q_3\to q_3$ 路径）：

    \automata\zoom{1.2}
        \node[initial,state]    at (0, 0)       (q_4)       {$q_4$};
        \node[state]            at (4.5, 2.598) (q_3)       {$q_3$};
        \node[state,accepting]  at (9, 0)       (q_5)       {$q_5$};
        
        \path
            (q_4)   edge                        node    {$a^*b$}   (q_3)
            (q_3)   edge [loop below]           node    {$a\cup (ba^*ba^*b)$}   (q_3)
                    edge                        node    {$e$}   (q_5);
    
    删掉状态 $q_3$：

    \automata\zoom{1.2}
        \node[initial,state]    at (0, 0)       (q_4)       {$q_4$};
        \node[state,accepting]  at (9, 0)       (q_5)       {$q_5$};
        
        \path
            (q_4)   edge                        node    {$a^*b(a\cup ba^*ba^*b)^*$}   (q_5);
    
    所以该自动机对应的正则表达式为 $R = a^*b(a\cup ba^*ba^*b)^*$

??? success "形式化描述"
    设 NFA $M=(K, \Sigma, \Delta, s, F)$，其中：

    - $K = \{q_1, q_2, \cdots, q_n\}$，$s = q_{n-1}$，$F = \{q_n\}$
    - $(p, a, q_{n-1})\notin\Delta$，$\forall p\in K, \forall a\in\Sigma$
    - $(q_n, a, p)\notin\Delta$，$\forall p\in K, \forall a\in\Sigma$

    求 $R$ 使得 $L(R) = L(M)$。

    采用动态规划思想，划分子问题：对于 $i, j\in[1, n]$ 以及 $k\in[0, n]$ 定义 $L_{ij}^k=\{w\in\Sigma^*: w\text{ drive M from }q_i\text{ to }q_j\text{ with no intermediate state having index }>k\}$

    - 即 $L_{ij}^k$ 表示从 $q_i$ 到 $q_j$ 的路径表示的语言，且中间状态的下标不大于 $k$
        - 注意中间状态不包含首尾
    - 记 $L_{ij}^k$ 对应的正则表达式为 $R_{ij}^k$

    ??? example "使用前面的自动机的例子"
        \automata\zoom{1}
            \node[initial,state]    at (0, 0)       (q_4)       {$q_4$};
            \node[state]            at (3, 0)       (q_1)       {$q_1$};
            \node[state]            at (6, 0)       (q_2)       {$q_2$};
            \node[state]            at (4.5, 2.598) (q_3)       {$q_3$};
            \node[state,accepting]  at (9, 0)       (q_5)       {$q_5$};
            
            \path
                (q_4)   edge                        node    {$e$}   (q_1)
                (q_1)   edge                        node    {$b$}   (q_3)
                        edge [in=105,out=135,loop]  node    {$a$}   (q_1)
                (q_2)   edge                        node    {$b$}   (q_1)
                        edge [loop right]           node    {$a$}   (q_2)
                (q_3)   edge                        node    {$b$}   (q_2)
                        edge [loop above]           node    {$a$}   (q_3)
                        edge                        node    {$e$}   (q_5);
        
        - $L_{11}^0 = \{e, a\}$，对应 $R_{11}^0 = \emptyset^*\cup a$
            - 注意 $aa$ 不属于 $L_{11}^0$ 因为有中间状态 $q_1$，其下标大于 0
        - $L_{13}^0 = \{b\}$，对应 $R_{12}^0 = b$
        - $L_{41}^1 = \{e, a, aa, \cdots\}$，对应 $R_{41}^1 = \emptyset^*\cup aa^*$

    动态规划过程部分：

    - 目标：$R_{(n-1)n}^{n-2}$
    - 起始已知：
        - $k=0\text{ and if }i=j$，有 $L_{ii}^0 = \{e\}\cup\{a: (q_i, a, q_i)\in\Delta\}$，可写出正则表达式 $R_{ii}^0$
        - $k=0\text{ and if }i\neq j$，有 $L_{ij}^0 = \{a: (q_i, a, q_j)\in\Delta\}$，可写出正则表达式 $R_{ij}^0$
    - 递推关系：$L_{ij}^k = L_{ij}^{k-1}\cup\ ?$
        - 中间过程有若干次会到达 $q_k$，依此来进行划分，有 $L_{ik}^{k-1}$、$L_{kk}^{k-1}$（若干次）、$L_{kj}^{k-1}$ 几个阶段
        - 连接起来有 $L_{ij}^k = L_{ij}^{k-1}\cup L_{ik}^{k-1}\circ\big(L_{kk}^{k-1}\big)^*\circ L_{kj}^{k-1}$
        - 因此对应正则表达式有 $R_{ij}^k = R_{ij}^{k-1}\cup R_{ik}^{k-1}\big(R_{kk}^{k-1}\big)^*R_{kj}^{k-1}$
    
    有以上这些关系，进行动态规划递推即可求解最终的正则表达式。