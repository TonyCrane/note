---
comment: True
counter: True
---

# 上下文无关语言

!!! abstract
    理论计算机科学导引第五至第？周课程内容

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

### Pushdown Automata

- 下推自动机（Pushdown Automata, PDA）是 NFA 的一个扩展
    - 在 NFA 基础上加了一个额外的栈结构，并在状态转移时会进行栈操作
    - PDA 可以和 CFG 等价
- 形式化定义，一个 PDA 是一个六元组 $P=(K, \Gamma, \Sigma, \Delta, s, F)$
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

    所以对应的 PDA $P=(K, \Gamma, \Sigma, \Delta, s, F)$：

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
