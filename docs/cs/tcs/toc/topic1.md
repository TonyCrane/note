---
comment: True
counter: True
---

# 语言与自动机

!!! abstract
    理论计算机科学导引第一至第二周课程内容

<!-- <style>
article {
    font-family: "CMU Serif", "LXGW WenKai Screen";
}
</style> -->

<style>
path[stroke="#000"], g[stroke="#000"] {
    stroke: var(--md-default-fg-color);
}
path[stroke="#fff"], g[stroke="#fff"] {
    stroke: var(--md-default-bg-color);
}
path[fill="#fff"] {
    fill: var(--md-default-bg-color);
}
path:not([fill]) {
    fill: var(--md-default-fg-color);
}
</style>

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

???+ success "Proof. if $A$ and $B$ are regular, so is $A\cup B$"
    思路：合并两个接收 $A$ 和 $B$ 的 DFA

    $\exists M_A=(K_A, \Sigma, \delta_A, s_A, F_A)\text{ accepts }A$，$\exists M_B=(K_B, \Sigma, \delta_B, s_B, F_B)\text{ accepts }B$

    $\text{let }M=(K, \Sigma, \delta, s, F)$，where:

    - $K = K_A\times K_B$
    - $s = (s_A, s_B)$
    - $F = \{(q_A, q_B): q_A\in F_A\text{ or }q_B\in F_B\}$
    - $\delta$: $\forall q_A\in K_A, \forall q_B\in K_B, \forall a\in\Sigma,\ \delta\big((q_A, q_B), a\big) = \big(\delta_A(q_A, a), \delta_B(q_B, a)\big)$

    $\text{then }M\text{ accepts }A\cup B$

???+ success "Proof. if $A$ and $B$ are regular, so is $A\circ B$"
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

???+ success "Proof. if $A$ and $B$ are regular, so is $A^*$"
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
