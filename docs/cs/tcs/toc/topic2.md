---
comment: True
counter: True
---

# 上下文无关语言

!!! abstract
    理论计算机科学导引第五至第六周课程内容

## 上下文无关文法

- Context-Free Grammar (CFG) 一些生成字符串的规则
    - e.g. $S\to aSb,\ S\to A,\ A\to c,\ A\to e$
        - 可以生成 $S\Rightarrow aSb\Rightarrow aaSbb\Rightarrow aaAbb\Rightarrow aabb$
    - 其中 $S$ 是起始符号（start symbol），大写字母是非终结符号（non-terminals），小写字母是终结符号（terminals）
- 形式化定义，一个 CFG 是一个四元组 $G=(V, \Sigma, S, R)$
    - $V$：a **finite** set of symbols
    - $\Sigma\subseteq V$：the set of terminals
        - $V-\Sigma$：the set of non-terminals（即 $V\setminus\Sigma$）
    - $S\subseteq V-\Sigma$：the start symbol
    - $R\subseteq (V-\Sigma)\times V^*$：the set of rules
        - 即一个由非终结符号和转换得到的字符串组成的元组构成的集合
- 推导
    - derive in one step: for any $x, y, z\in V^*$, for any $A\in V-\Sigma$
        - $xAy\Rightarrow_G xuy$ if $(A, u)\in R$
    - derive: for any $w, u\in V^*$
        - $w\Rightarrow_G^* u$ if $w=u$ or $w\Rightarrow_G\cdots\Rightarrow_G u$
- 生成字符串：$G$ generates a string $w\in\Sigma^*$ if $S\Rightarrow_G^* w$
- 生成语言：$G$ generates $L(G) = \{w\in\Sigma^*: G\text{ generates }w\}$
- 上下文无关语言（Context-Free Language，CFL）
    - A language is context-free if some CFG generates it

??? example "证明 $\{w\in\{a, b\}^*: w=w^R\}$ 即回文字符串是上下文无关的"
    存在一个 CFG：

    - $S\to e,\ S\to a,\ S\to b$
    - $S\to aSa,\ S\to bSb$
        - 可以简写 $S\to e\ |\ a\ |\ b\ |\ aSa\ |\ bSb$

    可以生成这个语言，所以其是上下文无关的。

### Chomsky Normal Form

- 一个 CFG 是 Chomsky Normal Form（CNF）的，如果它的所有规则都是以下三种形式之一：
    - $S\to e$：只有起始符号可以推导出空串
    - $A\to BC$ for some $B, C\in V-\Sigma$：非终结符号可以推导出两个非终结符号
    - $A\to a$ for some $a\in\Sigma$：非终结符号可以推导出一个终结符号
- 特点：生成一个长度为 $n$ 的串需要 $2n-1$ 步推导
- 定理：任何一个 CFG 都可以转换成等价 CNF 形式（即保证生成语言相同）

???+ note "修改方法（简单证明框架）"
    针对每个规则的以下五种情况进行处理：

    1. 如果起始符号 $S$ 出现在了规则的右侧：
        - 新建新的起始符号 $S_0$，并新建规则 $S_0\to S$
        - 这条处理保证**每条规则的右侧没有起始符号**
    2. $A\to e$ for some $A\neq S$，即非起始符号生成了空串：
        - 删除这条规则，并进行补偿：所有右侧出现 $A$ 的规则都要复制一份将 $A$ 删除
            - 比如 $B\to ACA$ 要改为三条：$B\to CA,\ B\to AC,\ B\to C$
        - 这条处理保证**只有起始符号可以推导出空串**，且其他规则不受影响
    3. $A\to B$ for some $B\in V-\Sigma$，即非终结符号只推导出了一个非终结符号：
        - 删除这条规则，并进行补偿：所有由 $B$ 推导出的规则都要将 $B$ 替换为 $A$
            - 比如 $B\to CDE$ 要改为 $A\to CDE$
            - 不能采用类似第二条的处理，即将右侧出现 $A$ 的替换为 $B$，因为 $A$ 可能是起始符号（因为右侧保证了不会出现起始符号，所以这种情况实际并没有进行补偿，是有问题的）
        - 这条处理保证**非终结符号可以推导出两个或以上非终结符号**
    4. $A\to u_1u_2\cdots u_k$ for some $k\geq 3$，即非终结符号推导出了三个或以上的符号：
        - 新建新的非终结符号 $V_i$，并新建规则 $A\to u_1V_2,\ \cdots,\ V_{k-2}\to u_{k-2}V_{k-1},\ V_{k-1}\to u_{k-1}u_k$
        - 这条处理保证**非终结符号只能推导出两个符号**
    5. $A\to u_1u_2$ at least one $u_i\in\Sigma$，即非终结符号推导出的两个符号中有终结符号：
        - 将终结符号包一层新的非终结符号，例如如果 $u_1$ 非终结而 $u_2$ 终结则新建规则 $A\to u_1V,\ V\to u_2$
        - 这条处理保证**非终结符号只能推导出一个终结符号或两个非终结字符**
    
    如上处理后，所有规则都符合 CNF 的要求。

    ??? example "将 $S\to e\ |\ a\ |\ b\ |\ aSa\ |\ bSb$ 转为 CNF"
        - 右侧有出现起始符号，所以新建规则 $S_0\to S$
        - 存在非终结符号 $S\to e$，删掉并补偿：
            - $S_0\to S,\ S\to a\ |\ b\ |\ aSa\ |\ bSb\ |\ aa\ |\ bb$
        - 存在 $S\to aSa\ |\ bSb$ 一个非终结符号生成三个符号：
            - 新建 $C\to Sa,\ D\to Sb$，替换得到 $S_0\to S,\ S\to a\ |\ b\ |\ aC\ |\ bD\ |\ aa\ |\ bb$
        - 存在推导结果里有 $Sa, Sb, aC, bD$ 这种带有终结符号的：
            - 新建 $A\to a,\ B\to b$，替换即可得到最终的 CNF

        CNF：$S_0\to S,\ A\to a,\ B\to b,\ S\to a\ |\ b\ |\ AC\ |\ BD\ |\ AA\ |\ BB$

## Pushdown Automata

- 下推自动机（Pushdown Automata, PDA）是 NFA 的一个扩展
    - 在 NFA 基础上加了一个额外的栈结构，并在状态转移时会进行栈操作
    - PDA 可以和 CFG 等价
- 形式化定义，一个 PDA 是一个六元组 $P=(K, \Sigma, \Gamma, \Delta, s, F)$
    - 其中 $K, \Sigma, s, F$ 的含义和 NFA 中的相同
    - $\Gamma$: stack alphabet，即栈里面会出现的符号集合
    - $\Delta$: transition relation, a **finite** subset of $(K\times (\Sigma\cup\{e\})\times \Gamma^*)\times (K\times\Gamma^*)$
        - 对比 NFA $(K\times (\Sigma\cup\{e\}))\times K$，即在转移前后都加了栈相关字符串
        - 前一个 $\Gamma^*$ 是栈顶的字符串，匹配后 pop 出来
        - 后一个 $\Gamma^*$ 是在转移后要 push 进去的字符串（从尾到头逐符号 push）
- configuration：$C\in K\times \Sigma^*\times \Gamma^*$，即 PDA 的状态、输入串、栈的状态
- yield in one step 形式化描述 $(p, x, \alpha)\vdash_P(q, y, \beta)$：
    - if $\exists \big((p, a, \gamma), (q, \eta)\big)\in\Delta$ s.t. $x=ay, \alpha=\gamma\tau, \beta=\eta\tau$ for some $\tau\in\Gamma^*$
    - yield 同样即通过 0 步或更多步到达
- PDA 接受字符串：$P$ accepts $w\in\Sigma^*$ if $(s, w, e)\vdash_P^*(q, e, e)$ for some $q\in F$
    - 起始状态是空栈，结束状态要求也是空栈，其他和 NFA 相同
- PDA 接受语言：$P$ accepts $L(P) = \{w\in\Sigma^*: P\text{ accepts }w\}$

??? example "构造 PDA $P$ 使 $L(P) = \{w\in \{0, 1\}^*: \#0\text{'s}=\#1\text{'s in }w\}$"
    即 0 和 1 个数相等的 01 串，思路（利用栈）：

    - 读入 0 时
        - 如果是空栈或者栈顶是 0，则 push 0
        - 否则（即栈顶是 1），pop
    - 读入 1 时
        - 如果是空栈或者栈顶是 1，则 push 1
        - 否则（即栈顶是 0），pop

    所以对应的 PDA $P=(K, \Sigma, \Gamma, \Delta, s, F)$：

    - $K=\{q\},\ s=q,\ F=\{q\},\ \Sigma = \Gamma = \{0, 1\}$
    
    $$
    \begin{align*}
    \Delta = \{&\big((q, 0, 1), (q, e)\big),\quad \text{now is 0 and top is 1 then pop}\\
               &\big((q, 0, e), (q, 0)\big),\quad \text{now is 0 and other case then push 0}\\
               &\big((q, 1, 0), (q, e)\big),\quad \text{now is 1 and top is 0 then pop}\\
               &\big((q, 1, e), (q, 1)\big)\}\quad \text{now is 1 and other case then push 1}
    \end{align*}
    $$

    如上即可通过一个状态和四个转移规则来达到，利用了 NFA “猜测”的特性（并且注意任何时候匹配到了都要 pop，除非匹配 $e$，以及 push $e$ 相当于不变即仅 pop）

### Simple PDA

定义一个更简单的 PDA 形式用于方便后续证明。

A PDA $P=(K, \Sigma, \Gamma, \Delta, s, F)$ is simple, if:

1. $|F| = 1$：只有一个接受状态
2. for each transition $\big((p, a, \alpha), (q, \beta)\big)\in\Delta$, either
    - $\alpha=e$ and $|\beta|=1$ or 
    - $|\alpha|=1$ and $\beta=e$
    - （就是要么 pop 一个字符，要么 push 一个字符）

??? success "证明任意 PDA 都有等价 simple PDA"
    思路就是如果有多步的 push pop 操作，就进行拆分：

    - 如果 $|F|\neq 1$，新建一个接受状态 $f'$
        - $\forall q\in F$，新建转移 $\big((q, e, e), (f', e)\big)$
        - 令 $F = \{f'\}$
    - 如果不满足只 push/pop 一个字符的条件，假设当前不满足的转移是 $\big((p, a, \alpha), (q, \beta)\big)$，依次
        1. 如果 $|\alpha|\geq 1$ 且 $|\beta|\geq 1$（同时 push/pop 了）
            - 新建状态 $r$，将原转移替换为 $\big((p, a, \alpha), (r, e)\big),\ \big((r, e, e), (q, \beta)\big)$
        2. 如果 $|\alpha| > 1$ 且 $\beta = e$（不止 pop 了一个字符）
            - 假设 $\alpha = c_1\cdots c_k, k\geq 2$
            - 新建状态 $r_1, \cdots, r_{k-1}$
            - 将原转移替换为 $\big((p, a, c_1), (r_1, e)\big),\ \big((r_1, e, c_2), (r_2, e)\big),\ \cdots,\ \big((r_{k-1}, e, c_k), (q, e)\big)$
        3. 如果 $\alpha = e$ 且 $|\beta| > 1$（不止 push 了一个字符）
            - 和第二条类似，拆分成 $k$ 步 push
        4. 如果 $\alpha = \beta = e$（没 push 也没 pop）
            - 新建状态 $r$，任取 $b\in\Gamma$，将原规则替换为 $\big((p, a, e), (r, b)\big),\ \big((r, e, b), (q, e)\big)$

### PDA 与 CFG 等价

分两个部分证明：

#### CFG -> PDA

对任意 CFG $G$，存在 PDA $M$ 使得 $L(M)=L(G)$，证明思路：

- 在栈中从 $S$ 开始非确定性地进行字符串的生成
- 将生成的内容和输入比较
- 如果匹配则接受

Given $G=(V, \Sigma, S, R)\Rightarrow P=(K, \Sigma, \Gamma, \Delta, s, F)$, s.t. $L(P)=L(G)$:

- $K=\{s, f\},\ s=s,\ F=\{f\},\ \Gamma = V$
- $\Delta$ 由以下部分组成：
    - $\big((s, e, e), (f, S)\big)$：起始先 push 进 $S$
    - $\big((f, a, a), (f, e)\big),\forall a\in\Sigma$：匹配到输入串则 pop
    - $\big((f, e, A), (f, u)\big),\forall (A, u)\in R$：对于所有规则进行生成，非确定自动机会“猜测”

#### PDA -> CFG

前面证明了任意 PDA -> simple PDA，所以只需要证明 simple PDA -> CFG 即可。

Given $P=(K, \Sigma, \Gamma, \Delta, s, F)$ is simple $\Rightarrow G=(V, \Sigma, S, R)$, s.t. $L(P)=L(G)$:

- 设立一系列非终结符号：$\{A_{pq}: (p, q)\in K\times K\}$，表示从状态 $p$ 到状态 $q$ 的路径
    - 设立的目标：$A_{pq}\Rightarrow^* w\in\Sigma^*$ iff $(p, w, e)\vdash_P^*(q, e, e)$
- 起始符号：$S=A_{sf}$
    - 因为 $s\in L(P)$ iff $(s, w, e)\vdash_P^*(f, e, e)$
- 转移关系 $R$
    - $\forall p\in K$，$A_{pp}\to e$
    - $\forall p, q, r\in K$，有以下两种情况：
        - 如果在从 $p$ 转移到 $q$ 的过程中出现了一个时刻在状态 $r$ 且栈是空的
            - $A_{pq}\to A_{pr}A_{rq}, \forall r\in K$
        - 如果过程中没有出现过任何一次栈为空的情况
            - 注意到第一步和最后一步有对应关系，假设第一步读取 $a$ 并 push $\alpha$，最后一步读取 $b$ 并 pop $\alpha$，所以可以添加以下转移：
            - $A_{pq}\to aA_{p'q'}b, \forall\big((p, a, e), (p', \alpha)\big), \big((q', b, \alpha), (q, e)\big)\in\Delta\text{ for some }\alpha\in\Gamma$

这样就出现了一个类似 DP 的情况，可以证明 $A_{pq}\Rightarrow^* w\in\Sigma^*$ iff $(p, w, e)\vdash_P^*(q, e, e)$：

- 左推右：by induction on length of derivation from $A_{pq}$ to $w$
- 右推左：by induction on number of steps of computation

## CFL 性质

### Closure Properties

PDA 可以定义一个 CFL，所以根据 PDA 的结构，CFL 有以下性质：

如果 $A$ 和 $B$ 是 CFL，则 $A\cup B, A\circ B, A^*$ 也是 CFL，但 $A\cap B, \overline{A}$ 不一定是 CFL。简单证明：设 $G_A=(V_A,\Sigma,S_A,R_A), G_B=(V_B,\Sigma,S_B,R_B)$，则：

- $G_{A\cup B}$：规则 $S\to S_A\ |\ S_B$
- $G_{A\circ B}$：规则 $S\to S_AS_B$
- $G_{A^*}$：规则 $S\to e\ |\ SS_A$

针对 $\cap, \overline{A}$，可以构造反例：

- $A=\{a^ib^jc^k:i=j\}, B=\{a^ib^jc^k:j=k\}$ 都是 context-free 的
- $A\cap B = \{a^nb^nc^n:n\geq 0\}$ 不是 context-free 的（后面会通过 pumping theorem 证明）
- $A\cap B = \overline{\overline{A}\cup\overline{B}}$，所以 $\cap$ 不封闭则 $\overline{A}$ 也不封闭

### Pumping Theorem for CFL

类似正则语言的 pumping theorem，CFL 也有一个相似的定理：

- 令 $L$ 为一个 CFL
- 则存在一个整数 $p\geq 1$（称为 pumping length）
- 使得对于所有长度不小于 $p$ 的字符串 $w\in L$
- 都可以将 $w$ 分解为五个部分 $w=uvxyz$ 满足：
    1. 对于任意 $i\geq 0$，有 $uv^ixy^iz\in L$
    2. $|v| + |y| > 0$
    3. $|vxy| \leq p$

证明思路：非终结符号一共有 $V-\Sigma$ 是有限的，但生成的字符串可以是无限长的，所以生成过程产生的 parse tree 中一定会有重复的非终结符 $Q$，简单画成如下：

<div style="text-align: center;">
    <img src="/assets/images/cs/tcs/toc/topic2/img1.light.png#only-light" width="30%" style="margin: 0 auto;">
    <img src="/assets/images/cs/tcs/toc/topic2/img1.dark.png#only-dark" width="30%" style="margin: 0 auto;">
</div>

即一层一层从上到下生成，最终推导生成 $uvxyz$，可见一定有以下结论：

- $S\Rightarrow^* uQz,\ Q\Rightarrow^* vQy,\ Q\Rightarrow^* x$
- 因此有 $uv^ixy^iz\in L$

??? success "具体的证明"
    $L$ 是 CFL，则存在 CFG $G=(V,\Sigma, S, R)$ 生成它。令 $b=\max\{|u|:(A,u)\in R\}$ 即所有规则里右侧最长的，称 $\mathrm{fanout}\leq b$。也可以知道在如上的 parse tree 中，一个节点最多有 $b$ 个子节点。

    我们已知如果一棵树有 $\mathrm{fanout}\leq b$ 且有 $n$ 个叶节点，则它的高度不小于 $\log_bn$。所以我们令 pumping length $p=b^{|V-\Sigma|+1}$，这样取长度不小于 $p$ 的字符串 $w\in L$，令 $T$ 是生成 $w$ 的且**有最少节点数**的 parse tree。此时字符串中的所有符号都是叶节点，那 $T$ 的高度就不小于 $\log_bp=|V-\Sigma|+1$。所以有如下结论：

    - 在最长的一条路径上，有：
        - $\text{\#edges}\geq |V-\Sigma|+1$
        - $\text{\#nodes}\geq |V-\Sigma|+2$
        - $\text{\#non-terminals}\geq |V-\Sigma|+1$
    - 所以在这条路径上一定有至少一个非终结符号出现了至少两次，我们取**最低的一对**为 $Q$

    接下来是三条结论：

    1. $uv^ixy^iz\in L$ 显然
    2. $|v|+|y| > 0$
        - 唯一不成立的情况是 $v=y=e$，假设是这种情况，所以 $w=uxz$
        - 这样就能找到一棵比 $T$ 节点数更少的 parse tree（少个 $Q$），与假设矛盾
    3. $|vxy|\leq p$
        - 只考虑从上面的 $Q$ 开始的子树 
            - 如果可以证明其高度不大于 $|V-\Sigma|+1$
            - 就可以证明 $|vxy|=\text{\#leaves}\leq b^{h+1}\leq b^{|V-\Sigma|+1}=p$
        - 这里子树的高度就是 $QQa$ 这条路径的长度
            - 因为我们假设了 $QQ$ 是最低的一对
            - 所以这条路径上不会再存在其他重复的非终结符号
            - 因为非终结符号只有 $|V-\Sigma|$ 个，所以路径长度不会超过 $|V-\Sigma|+1$

??? example "证明 $L=\{a^nb^nc^n:n\geq 0\}$ 不是 context-free 的"
    反证法，假设 $L$ 是 CFL，令 $p$ 为其 pumping length，取 $w=a^pb^pc^p$，则可以拆分 $w=uvxyz$。

    根据 pumping theorem，$|vxy|\leq p$，所以有以下两种情况：

    - $vxy$ 只包含 $b$：则 $uv^0xy^0z=uxz$ 中 $b$ 的数量就会比 $a,c$ 都少，所以不在 $L$ 中
    - $vxy$ 中包含 $a,c$ 中的某一个（另一个一定不会在其中）：则 $uv^0xy^0z=uxz$ 中 $a,c$ 的数量就会不平衡，所以不在 $L$ 中

    与第一条矛盾，所以 $L$ 不是 CFL。