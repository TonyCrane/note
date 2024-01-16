---
comment: True
counter: True
---

# 复杂度理论

!!! abstract
    理论计算机科学导引第十四至第十六周课程内容

## 时间复杂度

### P 问题

- 考虑判定问题 $A=\{0^k1^k:k\geq 0\}$
    - 单带图灵机上，每次消一个 01，复杂度 $\frac{n}{2}O(n) = O(n^2)$
    - 单带图灵机上，每次消一半，复杂度 $O(n\log n)$
    - 双带图灵机上可以达到 $O(n)$
- 定义 $M$ 是在任意输入上停机的 DTM
    - $M$ 的 running time 是一个函数 $f\colon\mathbb{N}\to\mathbb{N}$，$f(n)$ 是 $M$ 在输入长度为 $n$ 的输入上的最大运行步数
    - $\mathrm{DTIME}(t(n))$ 是所有在 $O(t(n))$ 时间内停机的 standard TM 的集合
    - 多带图灵机 running time 为 $t(n)$ 则化为标准图灵机为 $t^2(n)$（最大）
    - 确定性变体 running time 为 $t(n)$ 则化为标准图灵机为 $\mathrm{poly(t(n))}$
- Cobham-Edmonds Thesis：任何 "reasonable" 且 "general" 的确定性计算模型都可以在多项式时间内模拟图灵机
- 定义 $P$ 是所有可以在多项式时间内被确定性图灵机判定的语言的集合
    - $P = \bigcup_{k\geq 0}\mathrm{DTIME}(n^k)$

???+ success "Theorem. every CFL is in $P$"
    Proof. 任意 CFL $A$，存在一个 CFG $G=(V, \Sigma, R, S)$ 生成 $A$ 且是 CNF 的。（说明任意一个字符串 $w\in A$，需要在 $2|w| - 1$ 步内生成）

    但枚举所有长度为 $2|w|-1$ 的字符串需要 $|R|^{2|w|-1}$ 复杂度，非多项式。所以要通过 dp 来实现，假设 $w=a_1\cdots a_n$，问是否有 $S\Rightarrow^* w$。

    - 对于 $1\leq i\leq j\leq n$，定义 $T[i, j] = \{A\in V-\Sigma: A\Rightarrow a_ia_{i+1}\cdots a_j\}$
    - Goal：是否有 $S\in T[1, n]$
    - Base case：对于 $1\leq i\leq n$，有 $T[i, i] = \{A\in V-\Sigma: (A, a_i)\in R\}$
    - Recurrence：对于 $1\leq i\leq j\leq n$，有 $T[i, j] = \bigcup_{k=i}^{j-1}\{A\rightarrow BC: B\Rightarrow^* a_i\cdots a_k\land C\Rightarrow^* a_{k+1}\cdots a_j\}$
        - 即 $T[i, j] = \bigcup_{k=i}^{j-1}\{B\in T[i, k]\land C\in T[k+1, j]\}$
    
    子问题数量为 $\dfrac{n^2}{2}$，每个子问题需要消耗 $n\cdot |R|$ 时间，总共需要 $O(n^3|R|)=O(n^3)$ 时间，是多项式。

### SAT 与 NP 问题

- SAT 即满足性问题，给一个布尔表达式，问是否存在一种变量的组合使整体值为真
    - 比如 $(x_1\lor x_2\lor x_3)\land(x_2\lor\overline{x_3}\lor x_4)\land(x_1\lor x_2\lor x_4\lor x_5)$
- 定义 $M$ 是一个非确定性图灵机，对于任意输入，每个分支都在 $k$ 步内停机，其中 $k$ 只取决于输入
    - $M$ 的 running time 是一个函数 $f\colon\mathbb{N}\to\mathbb{N}$，对于任意长度为 $n$ 的输入，$M$ 的每个分支都在 $f(n)$ 步内停机
- SAT 可以被非确定性图灵机在多项式时间内解决（非确定性生成变量再验证即可）
- 定义 $NP$ 是所有可以在多项式时间内被非确定性图灵机判定的语言的集合
- 定义一个语言 $A$ 被称为多项式可验证的（polynomially verifiable），如果存在一个多项式时间 DTM $V$ 满足对于任意 $x\in\Sigma^*$：
    - 如果 $x\in A$，则存在 $y$ with $|y|\leq\mathrm{poly}(|x|)$ 使得 $V$ accepts $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$
    - 如果 $x\notin A$，则对于任意 $y$ with $|y|\leq\mathrm{poly}(|x|)$，$V$ rejects $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$

??? example "SAT 问题是多项式可验证的"
    - $A$ = SAT
    - $x$ = boolean formular
    - $y$ = a truth assignment that satisfies $x$
    - $V$ = on input $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$:
        1. evaluate $x$ under $y$
        2. if $x$ is satisfied by $y$
        3. &emsp;&emsp;accepts $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$
        4. else
        5. &emsp;&emsp;rejects $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$

???+ success "Theorem. 语言 $A$ 是多项式可判定的当且仅当它是 $NP$ 问题"
    Proof. 左推右，存在多项式时间的 verifier $V$，需要构建一个 NTM $M$ 在多项式时间内判定 $A$。构造 $M$ = on input $\mathtt{"}x\mathtt{"}$:

    1. non-deterministically generate a certificate $y$ with $|y|\leq\mathrm{poly}(|x|)$
    2. run $V$ on input $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$
    3. if $V$ accepts $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$
    4. &emsp;&emsp;accepts $\mathtt{"}x\mathtt{"}$
    5. else
    6. &emsp;&emsp;rejects $\mathtt{"}x\mathtt{"}$

    右推左，存在一个 NTM $M$ 多项式时间内判定 $A$，需要构造一个多项式时间 verifier $V$。构造 $V$ = on input $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$:

    1. run $M$ on $\mathtt{"}x\mathtt{"}$ deterministically under the guidance of $y$
    2. if $M$ accepts $\mathtt{"}x\mathtt{"}$
    3. &emsp;&emsp;accepts $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$
    4. else
    5. &emsp;&emsp;rejects $\mathtt{"}x\mathtt{"}\mathtt{"}y\mathtt{"}$

### NP-Complete 问题

- 尚不知道 $P$ 是否等于 $NP$
- 但 $P\subseteq NP$，因为 DTM 也是 NTM
- Cook & levin 提出了 NP-Complete 问题
    - 如果一个 NP-Complete 问题是一个 P 问题，则 P = NP
- 在规约 $f: A\leq B$ 的基础上加上条件 $f$ 可以在多项式时间内被 DTM 计算，则称 $A$ 可以在多项式时间内规约到 $B$，记作 $A\leq_P B$

???+ success "Theorem. 如果 $A\leq_P B, B\in P$，则 $A\in P$"
    $x\to f(x)$，再判定 $f(x)\in B$ 即可，转化时间 $\mathrm{poly}(|x|)$，判定时间 $\mathrm{poly}(|f(x)|)$，且有 $|f(x)|\leq\mathrm{poly}(|x|)$，所以总时间也是多项式时间。

???+ example "Clique 团问题"
    对于一张图 $G=(V, E)$，一个团（clique）是 $V$ 的一个子集 $V'\subseteq V$，使得对于任意 $u, v\in V'$，$(u, v)\in E$。团问题是 $\mathrm{CLIQUE}=\{\mathtt{"}G\mathtt{"}\mathtt{"}k\mathtt{"}: G\text{ has a clique of at least }k\}$，要证 $\mathrm{3-SAT}\leq_P\mathrm{CLIQUE}$。（3-SAT 是 SAT 的一个变体，每个子句最多有 3 个变量，可以证明 3-SAT 和 SAT 是等价的）

    对于合取范式 $F$，构造一个 $(G, k)$。比如给定 $(x_1\lor x_2\lor\overline{x_3})\land(\overline{x_1}\lor x_2\lor x_3)\land(x_2\lor x_3\lor x_1)$，构造一个图，有九个节点，为每个括号中的三个变量建立三个节点，分为三组，在组之间进行连线建边，满足两个变量不冲突的时候存在一条边（e.g. $x_1$ 和 $\overline{x_1}$ 冲突。有 $m$ 个括号，则定 $k=m$）选中的点即为表达式中为真的变量。可以证明，如果 $F$ 有解，则 $G$ 有一个大小为 $k$ 的团，反之亦然。

???+ example "Vertex Cover 顶点覆盖问题"
    对于图 $G=(V, E)$，选取一个点集 $V'\subseteq V$，使得对于任意 $e\in E$，$e$ 至少有一个端点在 $V'$ 中。$\mathrm{VC}=\{\mathtt{"}G\mathtt{"}\mathtt{"}k\mathtt{"}: G\text{ has a vertex cover of size at most }k\}$。要证 $\mathrm{3-SAT}\leq_P\mathrm{VC}$。

    假设 $F$ 有 $n$ 个变量，$m$ 个子句，构造图，有 $2n+3m$ 个节点。对于每个变量，建立两个点 $x$ 与 $\overline{x}$，并在其间建立一条边。再对于每个子句，建立三个节点，互相连接，并在每个变量和刚创建的 $2n$ 个点中相同的建立一条边。所以一共有 $n+3m+3m$ 条边。

- 定义一个语言 $L$ 是 NP-Complete 的，如果：
    1. $L\in NP$
    2. $\forall L'\in NP, L'\leq_P L$

???+ success "Cook-Levin Theorem. SAT is NP-Complete"
    Proof. 令 $A$ 是任意一个属于 NP 的语言。需要证明 $A\leq_P\mathrm{SAT}$。

    存在一个 NTM $N$ 在 $n^k$ 时间内判定 $A$。判定 $a_1\cdots a_n\in A$ 等价于存在一个分支 $(s, \rhd\underline{⌴}a_1\cdots a_n)\vdash_M(q_1, \rhd u_1\underline{a_1}v_1)\vdash_M\cdots\vdash_M(y, \rhd u\underline{a}v)$，可以写成 $\rhd⌴sa_1\cdots a_n\vdash_M\rhd u_1a_1q_1v_1\vdash_M\cdots\vdash_M\rhd uayv$，其中最多有 $n^k$ 个 configurations，并且每个 configuaration 对应字符串的长度最长 $n^k$。

    建立一个 $n^k\times n^k$ 的表，表中每个格子可以填状态或者 symbol，是否存在这样的转换即能否找到一种正确的填表方式。

    - 对于 $1\leq i\leq n^k,\ 1\leq j\leq n^k, c\in K\cup\Sigma$，$x_{ijc}$ 表示这个位置上是否填了 $c$
    - 需要满足：
        - 对于每一个 $i, j$，要有 $\displaystyle\sum_{c\in k\cup\Sigma}x_{ijc}\geq 1$，即 $\displaystyle\bigvee_{c\in K\cup\Sigma}x_{ijc}$ 为真
        - 对于每一个 $i, j$，要保证一格内只能有一个符号，即 $\displaystyle\bigwedge_{c\neq c'}\overline{x_{ijc}\land x_{ijc'}}=\bigwedge_{c\neq c'}(\overline{x_{ijc}}\lor\overline{x_{ijc'}})$ 为真
        - $x_{11\rhd}\land x_{12⌴}\land x_{13s}\land \cdots$ 为真（规定初始行）
        - 要保证后一行是前一行一步操作到的
            - 用 2*3 的框进行检查，合法的这样的框有 $|K\cup\Sigma|^6$ 种
        - 存在接受状态，$\displaystyle\bigvee_{i, j}x_{ijy}$ 为真
    
???+ success "Theorem. 如果 $A$ 是 NP-Complete 的，$B\in NP, A\leq_P B$，则 $B$ 是 NP-Complete 的"
    Proof. $\forall L'\in NP$, $L\leq_P A$，因为 $A\leq_P B$，所以 $L\leq_P B$。

- SAT、3-SAT、CLIQUE、Vertex Cover 都是 NP-Complete 问题

## 空间复杂度

- 令 $M$ 为一 DTM，称其使用 runs in $f(n)$ space 如果对于任何长度为 $n$ 的输入，$M$ 使用的纸带的格子数最多为 $f(n)$
    - 假定 $f(n)\geq n$
    - 使用单带确定性图灵机（确定性图灵机变种在空间上只差常数）
- 令 $M$ 为一 NTM，类似 DTM，不过每个分支都最多使用 $f(n)$ 格子
- PSPACE 问题为可以由确定性图灵机在多项式空间内解决的问题的集合
- NPSPACE 问题为可以由非确定性图灵机在多项式空间内解决的问题的集合
- P $\subseteq$ PSPACE（$f(n)$ 时间里只够走 $f(n)$ 格）
    - NP $\subseteq$ PSPACE（空间可以复用，再附加多项式空间记住分支的选择情况）
- 如果一台 DTM 使用 $f(n)$ 空间且在任意输入上停机，则其运行时间最多 $|K|\cdot f(n)\cdot |\Sigma|^{f(n)}$
    - configuration 不会重复（不然会有循环不停机）
    - 有 $|K|$ 个状态，$f(n)$ 个读写头位置，纸带上内容 $|\Sigma|^{f(n)}$
    - 是指数时间的
- PSPACE $\subseteq$ EXP
    - EXP 为可以由 DTM 在指数时间（$2^{\mathrm{poly}(n)}$）内判定的问题的集合
    - 有 P $\subseteq$ NP $\subseteq$ PSPACE $\subseteq$ EXP

!!! success "Theorem. NPSPACE = PSPACE"

???+ tip "Savitch's Theorem. 可以被 NTM 在 $f(n)$ 空间内判定的问题可以被 DTM 在 $O(f^2(n))$ 空间内判定"
    Proof. 递归思路。问 configuration 的转化能否 $C_\text{init}\rightsquigarrow C_\text{accept}$（其中所有 configuration 都最多 $f(n)$ 空间），最多 $2^{f(n)}$ 步。

    $C_\text{init}\rightsquigarrow C_\text{accept}$ 当且仅当存在 $C'$ 有 $C_\text{init}\rightsquigarrow C'$ within $2^{f(n) - 1}$ steps，且 $C'\rightsquigarrow C_\text{accept}$ within $2^{f(n) - 1}$ steps，再进行递归判定。虽然不知道 $C'$ 是什么，但选项是有限的，可以 $2^{f(n)}$ 枚举（时间上坏，空间上可以复用，没问题）。

    $Y$ = on input $c_1, c_2, t$（能否从 $c_1$ 走到 $c_2$ 且步数不超过 $t$）:

    1. if $t = 1$
    2. &emsp;&emsp;if $c_1 = c_2$ or $c_1\vdash_M c_2$
    3. &emsp;&emsp;&emsp;&emsp;accept
    4. &emsp;&emsp;else
    5. &emsp;&emsp;&emsp;&emsp;reject
    6. for all configurations $c'$ using at most $f(n)$ space
    7. &emsp;&emsp;run $Y$ on $c_1, c', t/2$
    8. &emsp;&emsp;run $Y$ on $c', c_2, t/2$
    9. &emsp;&emsp;if both accept
    10. &emsp;&emsp;&emsp;&emsp;accept
    11. &emsp;&emsp;else
    12. &emsp;&emsp;&emsp;&emsp;reject

    run $Y$ on $C_\text{init}, C_\text{accept}, 2^{f(n)}$ 即可。空间复杂度：

    - $t=1$ 时，只需要存 $c_1, c_2$，则 $s(1) = O(f(n))$
    - 对于一般的 $t$，需要 $s(t) = O(f(n)) + s(t/2)$（第七八行的空间可以复用）
        - $s(t) = O(f(n)\cdot\log t)$

    最终有空间复杂度为 $O(f(n)\cdot\log 2^{f(n)}) = O(f^2(n))$。

    由此定理即可说明 PSPACE = NPSPACE，且只差一个平方。

- 前面已知 P $\subseteq$ NP $\subseteq$ PSPACE $\subseteq$ EXP
    - 但是否有 P $\subsetneq$ NP $\subsetneq$ PSPACE $\subsetneq$ EXP 都是未知的
    - 但其中至少有一个是真包含的，可以证明 P $\subsetneq$ EXP

???+ success "Hierarchy Theorem."
    空间上，对于任意 $f\colon\mathbb{N}\to\mathbb{N}$（满足一些性质），都存在一个语言 $A$ 满足：

    1. $A$ 可以被 DTM 在 $O(f(n))$ 空间内判定
    2. $A$ 不能被 DTM 在 $o(f(n))$ 空间内判定
        - 大 $O$ 小于等于，小 $o$ 小于，即至少需要 $f(n)$ 空间）
    
    ??? tip "Proof. space version"
        构造一台 DTM $D$，满足两个性质：

        1. $D$ 在 $O(f(n))$ 空间内可以判定某些语言 $A$
        2. 对于任意运行在 $o(f(n))$ 空间内的 DTM $M$，$D$ 和 $M$ 至少在一个输入上面的输出是不一样的

        构造思路，运用 diagonalization。运行在 $o(f(n))$ 空间上的图灵机是可列的，对每个图灵机输入其自身的编码，结果可能是 1（接收）、-1（拒绝）、0（不停机）。就可以构造 $D$，将对角线每个位置取反即可：

        <center>

        |  | $\mathtt{"}M_1\mathtt{"}$ | $\mathtt{"}M_2\mathtt{"}$ | $\mathtt{"}M_3\mathtt{"}$ | $\cdots$ |
        | :---: | :---: | :---: | :---: | :---: |
        | $M_1$ | 1 | | | |
        | $M_2$ | | -1 | | |
        | $M_3$ | | | 0 | |
        | $\vdots$ | | | | $\ddots$ |
        | $D$ | -1 | 1 | 1/-1 | $\cdots$ |

        </center>

        $D$ = on input $\mathtt{"}M\mathtt{"}$:

        1. let n = $|\mathtt{"}M\mathtt{"}|$
        2. compute $f(n)$（前面说的要满足的条件：$f(n)$ 需要在 $f(n)$ 空间内可计算，绝大多数函数都满足）
        3. run $M$ on $\mathtt{"}M\mathtt{"}$ for $c^{f(n)}$ steps
            1. if $M$ does not halts in $c^{f(n)}$ steps, reject
            2. if $M$ ever uses more than $f(n)$ space, reject
        4. if $M$ accepts $\mathtt{"}M\mathtt{"}$
        5. &emsp;&emsp;reject
        6. else
        7. &emsp;&emsp;accept

    时间上，对于任意 $f\colon\mathbb{N}\to\mathbb{N}$（满足一些性质），都存在一个语言 $A$ 满足：

    1. $A$ 可以被 DTM 在 $O(f(n))$ 时间内判定
    2. $A$ 不能被 DTM 在 $o(\dfrac{f(n)}{\log f(n)})$ 时间内判定
        - 时间的 hierarchy theorem 要弱一点，提高 $\log f(n)$ 才能多判定问题

    ??? tip "Proof. time version"
        同样需要构造 $D$ 满足：

        1. $D$ 在 $O(f(n))$ 时间内可以判定某些语言 $A$
        2. 对于任意运行在 $o(\dfrac{f(n)}{\log f(n)})$ 时间内的 DTM $M$，$D$ 和 $M$ 至少在一个输入上面的输出是不一样的

        $D$ = on input $\mathtt{"}M\mathtt{"}$:

        1. let n = $|\mathtt{"}M\mathtt{"}|$
        2. compute $f(n)$（需要在 $O(f(n))$ 时间内可计算）
        3. run $M$ on $\mathtt{"}M\mathtt{"}$ for $\dfrac{f(n)}{\log f(n)}$ steps
            - 这里要除一个 log 的原因在于，需要维护一个 counter，二进制串有 $\log_2 f(n)$ 位，每次加一都需要 $\log f(n)$ 步，乘以总步数后才能保证 $f(n)$ 步
        4. if $M$ accepts $\mathtt{"}M\mathtt{"}$
        5. &emsp;&emsp;reject
        6. else
        7. &emsp;&emsp;accept

- 根据 Hierarchy Theorem，有 P $\subsetneq$ EXP