---
counter: True
comment: True
---

# 词法分析与语法分析

!!! abstract
    编译原理第一至第六周课程内容

## 词法分析

很多东西和计算理论的内容重复了，见[计算理论：语言、自动机与正则表达式](../../tcs/toc/topic1/)。

### 词法分析器自动生成

目标是从正则表达式生成最小状态 DFA，分为以下三步：

- 正则表达式 -> NFA
- NFA -> DFA
- DFA -> 最小 DFA

#### RE -> NFA

Thompson 算法：基于对 RE 的结构进行归纳：

- 对于 $\varepsilon$ 和单个字符直接构造
- 对复合的 RE 递归构造：
    - st 连接：将 s 接受状态和 t 开始状态连接
    - s | t 选择：新建开始和接受状态，$\varepsilon$ 连接到 s 和 t 的开始和接受状态
    - s* 闭包：新建开始和接受状态，$\varepsilon$ 连接开始到接受、s 的接受状态到 s 的开始状态

特点：生成的 NFA 仅一个接受状态，且没有出边。

#### NFA -> DFA

同计算理论中讲到的方法，即子集构造法：

- NFA 的初始状态的 $\varepsilon$ 闭包对应于 DFA 的初始状态
- 针对每个 DFA 状态（对应 NFA 状态子集 $A$）
    - 求输入每个 $a_i$ 后能到达的 NFA 状态的 $\varepsilon$ 闭包并集
    - $S = \varepsilon\mathrm{-closure}(\mathrm{move}(A, a_i))$
    - $S$ 要么是已有符号，要么是新的状态
    - 重复此过程至没有新状态产生
- 包含 NFA 结束状态的所有 DFA 状态都是结束状态

#### DFA -> 最小 DFA

计算理论中没有讲的部分。一个正则语言可能有多个 DFA 识别他，但通过最小化得到的状态数量最少的 DFA 是唯一的。

通过可区分状态（distinguishable states）来进行最小化：

- 如果存在串 $x$，使得从 $s, t$ 出发，一个到达接受状态一个到达非接受状态，则 $s, t$ 可区分
    - $\varepsilon$ 区分任何接受状态和非接受状态
- 如果 $s, t$ 不可区分，则可以直接合并

DFA 最小化算法：

- 划分部分：
    - 初始化分为组 $\Pi = \{S-F, F\}$（接受状态和非接受状态）
    - 对于 $\Pi$ 中的每个组进行迭代划分：
        - 使得一个组中的状态在任意输入下都到达 $\Pi$ 中的同一组
        - 如果到达了不同的组，则划分
        - 不断重复过程直到不可继续划分
- 构造部分：
    - 一个组中选一个代表状态，其他状态均可删掉
    - 包含原开始状态的组的代表为开始状态，接受状态同理（但这个组一定只有接受状态）

## 语法分析

- 基于 CFG 语法进行分析
    - 最左推导：每次替换最左边的非终结符
        - 最右规约就是最左推导的逆过程
    - 最右推导：每次替换最右边的非终结符
- 分析方法：
    - 自顶向下（top-down）：从开始符号开始尝试推导（derive）出输入
        - 每一步推导中**总是**选择最左非终结符进行替换
        - 每一步推导中需要选择用哪个产生式进行替换
    - 自底向上（bottom-up）：尝试根据产生式规则规约（reduce）到开始符号

### 自顶向下分析

#### 递归下降分析

- 递归下降分析（Recursive-Descent Parsing）
    - 即从 S 开始，根据产生式递归推导，直到推导出输入串
    - 可能有非常复杂的回溯，代价太高
    - 分析过程类似 NFA

#### LL(1) 文法与预测分析

- 预测分析法（Predictive Parsing）
    - 此方法接受 LL(k) 文法
        - L（Left-to-right）：从左到右扫描
        - L（Leftmost derivation）：最左推导
        - k：向前看 k 哥 Token 来确定产生式（一般 k=1）
- LL(1)：每次为最左边的非终结符选择产生式时，向前看 1 个输入符号来预测要使用的产生式
    - 构造 First 集和 Follow 集
        - $\mathsf{First}(\alpha) = \{a\mid\alpha\Rightarrow^*a\cdots, a\in T\}$：可以从 $\alpha$ 推导出的串的首个终结符的集合
        - $\mathsf{Follow}(A) = \{a\mid S\Rightarrow^*\cdots Aa\cdots, a\in T\}$：可以跟在 $A$ 后面的终结符的集合
    - LL(1) 文法的要求：对于任何两个产生式 $A\to\alpha\ |\ \beta$ 都满足：
        - $\mathsf{First}(\alpha)\cap\mathsf{First}(\beta) = \varnothing$：$\alpha$ 和 $\beta$ 推导不出以同一个终结符开头的串
        - 如果 $\beta\Rightarrow^*\varepsilon$，则 $\alpha\not\Rightarrow^*\varepsilon$ 且 $\mathsf{First}(\alpha)\cap\mathsf{Follow}(A) = \varnothing$：一个推导出空串时另一个不能产生和推导出空串同样的效果
        - 有了这两个条件可以保证产生式选择的唯一性
- 实现 LL(1) 预测分析
    - 计算出 First、Follow 集
        - Nullable：一个非终结符是否能推导出空串，根据产生式直接归纳判断即可
        - First：采用归纳定义进行计算 $\mathsf{First}(X)$
            - 如果 $X$ 是终结符，则 $\mathsf{First}(X) = \{X\}$
            - 对于产生式 $X\to Y_1Y_2\cdots Y_n$：
                - 并上 $\mathsf{First}(Y_1)$：$X$ 可以推导出的串的首字符一定包含 $Y_1$ 可以推导出的串的首字符
                - 如果 $Y_1$ 是 Nullable，则并上 $\mathsf{First}(Y_2)$：$Y_1$ 是空的时候首字符就要看 $Y_2$
                - 如果 $Y_1$ 和 $Y_2$ 都是 Nullable，则并上 $\mathsf{First}(Y_3)$，以此类推
        - Follow：采用归纳定义进行计算 $\mathsf{Follow}(A)$
            - $\mathsf{Follow}(A) = \{\}$
            - 对于产生式 $B\to\alpha A\beta$：
                - 并上 $\mathsf{First}(\beta)$：$A$ 后面可以跟的串的首字符一定包含 $\beta$ 可以推导出的串的首字符
                - 如果 $\beta$ 是 Nullable，则并上 $\mathsf{Follow}(B)$：后面全是空的时候就要看 $B$ 的 Follow
    - 构造预测分析表
        - 每一行表示一个非终结符 A，每一列 a 表示一个终结符或者输入结束符 \$
        - 表项第 A 行第 a 列表示对于非终结符 A，下一个输入 Token 为 a 时可以选择的产生式
        - 对于每个产生式 $X\to\gamma$，考虑填入第 $X$ 行第 $t$ 列：
            - 如果 $t\in\mathsf{First}(\gamma)$，则填入这个产生式
            - 如果 $\gamma$ 是 Nullable，且 $t\in\mathsf{Follow}(X)$，则填入这个产生式
    - 进行预测分析
        - 只有所有表项中产生式都不超过一个时才是 LL(1) 文法，可以直接根据输入选择产生式进行推导
        - 如果在查表时发现空的表项，则输入中包含语法错误

        
        ???+ example "不是 LL(1) 文法的例子"
            对于文法：$Z\to d\ |\ X\ Y\ Z$，$Y\to c\ |\ \varepsilon$，$X\to Y\ |\ a$：

            <center>

            ||Nullable|First|Follow|
            |:-:|:-:|:-:|:-:|
            |$Z$|False|$\{d, a, c\}$|$\{\}$|
            |$Y$|True|$\{c\}$|$\{d, a, c\}$|
            |$X$|True|$\{a, c\}$|$\{c, d, a\}$|

            </center>

            构造预测分析表：

            <center>

            ||$a$|$c$|$d$|
            |:-:|:-:|:-:|:-:|
            |$Z$|$Z\to X\ Y\ Z$|$Z\to X\ Y\ Z$|$Z\to X\ Y\ Z$<br/>$Z\to d$|
            |$Y$|$Y\to \varepsilon$|$Y\to c$<br/>$Y\to\varepsilon$|$Y\to \varepsilon$|
            |$X$|$X\to a$<br/>$X\to Y$|$X\to Y$|$X\to Y$|

            </center>

            因为有三个表项中包含了两个产生式，所以不是 LL(1) 文法。

- LL(1) 文法的性质：无二义、无左递归、无左公因子
    - 左递归：存在非终结符 $A$ 使得 $A\Rightarrow^+A\alpha$
        - 直接左递归：$A\to A\alpha\ |\ \beta$ 其中 $\alpha\neq\varepsilon$ 且 $\alpha, \beta$ 不以 $A$ 开头
        - 消除直接左递归：改为 $A\to\beta A'$，$A'\to\alpha A'\ |\ \varepsilon$（转为右递归）
    - 左公因子：$A\to\alpha\beta\ |\ \alpha\gamma$ 其中 $\alpha$ 是公共前缀
        - 提左公因子：改为 $A\to\alpha A'$，$A'\to\beta\ |\ \gamma$（推迟决定）
- LL(1) 分析的有点：运行高效（线性时间），适合手动构造和自动生成
- LL(1) 分析的局限性：能分析的文法类型受限

### 自底向上分析

- 基于 LR(k) 文法进行分析
    - L（Left-to-right）：从左到右扫描
    - R（Rightmost derivation in reverse）：最右推导的逆（最左规约）
    - k：向前看 k 个 Token 来确定规约（省略时默认为 1）
    - 有 LR(0)、SLR(1)、LR(1)、LALR(1) 等类型
        - LR(0) < SLR(1) < LALR(1) < LR(1)
    - 所有 LL(k) 文法都是 LR(k) 文法
    - LR 不需要提左公因子，而且可以分析左递归文法
- 自底向上分析的思路是从输入串规约到开始符号
    - 一个与某产生式**体**相匹配的特定字串可以**替换**为该产生式**头**的非终结符
    - 问题在于何时进行规约以及确定规约到哪个非终结符

#### Shift-Reduce

- 移进-规约分析
- 思想是将输入串分为两个子串
    - 右子串是还没有分析过的部分，包含一系列终结符
    - 左子串包含终结符和非终结符
    - 起始状态整个串都属于右子串

???+ example "Shift-Reduce 分析例子"
    对于文法 $E\to E+(E)\ |\ \mathsf{int}$ 分析串 int + (int) + (int)，利用 | 来分割两个部分

    ```text
    | int + (int) + (int)$      初始状态
    int | + (int) + (int)$      移进 int，匹配到规则 E -> int
    E | + (int) + (int)$        规约 E -> int
    E + (int |) + (int)$        移进三次
    E + (E |) + (int)$          规约 E -> int
    E + (E) | + (int)$          移进一次
    E | + (int)$                规约 E -> E + (E)
    E + (int |)$                移进三次
    E + (E |)$                  规约 E -> int
    E + (E) |$                  移进一次
    E |$                        规约 E -> E + (E)，结束
    ```

- 从 Shift-Reduce 可见 LR 进行的是最右推导的逆过程
    - 最右推导中出现的句型称为最右句型
- LR 分析的一般模式：基于栈的 Shift-Reduce
    - 保存两个部分，一个栈用来存储左子串，一个输入缓冲区用来存储右子串
    - 包括四个操作：
        - Shift：将下一个输入的终结符压入栈顶
        - Reduce：在栈里进行规约
            - 栈顶的序列需要匹配到一个产生式的右侧，例如 X -> A B C
            - 从栈中弹出右侧 C B A，压入左侧 X
        - Error：遇到无法进行规约的情况
        - Accpet：移入了 \$，并且栈上的剩余内容可以规约为开始符号
    - 核心问题是何时 Shift 何时 Reduce
- 最通用的无回溯 Shift-Reduce 分析是表驱动的 LR 分析
    - 所有的分析器都使用相同的驱动程序，分析表可以根据文法自动生成

#### LR(0) 分析

- 可以维护一个状态来记录当前识别的进度
- 一个项（item）是一个产生式在其中某一处加一个点
    - 比如 $A\to X\ Y$ 可以有 $A\to\bullet\ X\ Y$、$A\to X\ \bullet\ Y$、$A\to X\ Y\ \bullet$ 三个项
    - $A\to\alpha\bullet\beta$ 表示已经识别了 $\alpha$，接下来要识别 $\beta$
    - $A\to\alpha\beta\bullet$ 表示已经识别了 $\alpha\beta$，接下来可以规约为 $A$
- 项可以作为状态，并且项之间可以通过读入符号来进行跳转
    - 例如 $A\to\bullet\ X\ Y$ 可以通过读入 $X$ 转移到 $A\to X\ \bullet\ Y$
    - 产生式有限 + 产生式右边长度有限 -> 项有限（状态有限）
    - 可以构造出一个有限状态自动机，称为 LR(0) 自动机
        - 这个自动机是用来记录当前识别进度的，而非识别 LR(0) 语言的（因为自动机只能识别正则语言）
- LR(0) Parsing NFA
    - 需要新开始符号 $S'$，加入产生式 $S'\to S\$$ 方便表示起始和终结状态
    - 状态转移
        - $X\to\bullet\ \alpha\beta$ 在接收 $\alpha$ 后转移到 $X\to\alpha\bullet\beta$
        - 如果存在 $X\to\alpha Y\beta$ 以及 $Y\to\gamma$，则 $X\to\alpha\bullet Y\beta$ 可以 $\varepsilon$ 转移到 $Y\to\bullet\ \gamma$
- LR(0) Parsing DFA
    - 可以通过子集构造法来将 NFA 转为 DFA，但通常直接构造 DFA
    - 假设 $I$ 是一个项的集合，$X$ 是一个符号（终结符或非终结符）
        - $\mathsf{Closure}(I)$ 为 $I$ 中所有项的闭包，即所有可以 $\varepsilon$ 推导出的项
            - 对于任意 $I$ 中的 $A\to\alpha\bullet X\beta$，将 $X\to\bullet\ \gamma$ 加入 $I$ 中，直到 $I$ 不变即为其闭包
        - $\mathsf{Goto}(I, X)$ 为 $I$ 中所有项的 $X$ 转移，即所有可以读入 $X$ 转移到的项
            - 对于任意 $I$ 中的 $A\to\alpha\bullet X\beta$，将 $A\to\alpha X\bullet\beta$ 加入空集 $J$ 中
            - $\mathsf{Goto}(I, X)$ 即为 $\mathsf{Closure}(J)$
    - 起始状态为 $\mathsf{Closure}(\{S'\to\bullet\ S\$\})$
    - 结束状态为包含 $S'\to S\bullet\$$ 的状态
    - 构造过程用 Goto 不断计算新状态并添加转移边，直到没有新状态产生
- 通过 Parsing DFA 构造语法分析表
    - 需要构建一个表，行为状态，列为对于每个终结符的 Action 和对于每个非终结符的 GOTO
    - Action 表中的项有三种类型：Shift、Reduce、Accept
        - Shift：状态 *i* 在接收终结符 *t* 后转移到状态 *j*，则 Action[*i*, *t*] = s*j*
        - Reduce：状态 *i* 的结尾是点（可以进行规约），则 Action[*i*, \*] = r*k*
            - 其中 *k* 是可以进行此规约的产生式编号
        - Accept：状态 *i* 包含 $S'\to S\bullet\$$，则 Action[*i*, \$] = accept
    - GOTO 表：状态 *i* 在接收非终结符 *X* 后转移到状态 *j*，则 GOTO[*i*, *X*] = g*j*
- LR 语义分析算法
    - 栈记录的是 LR Parsing DFA 的状态
    - 四个操作：
        - Shift(*j*) 即 s*j*：吸收一个输入 token，将状态 *j* 压入栈
        - Reduce(*k*) 即 r*k*：根据产生式 *k* 进行规约
            - 假设第 *k* 个产生式为 X -> a
            - 从栈顶弹出 *a* 个状态，将状态 GOTO[top(stack), *X*] 压入栈
        - Accept / Error：结束分析，返回成功或报错
    - 所有 LR 分析方法都可以使用这个通用的算法

??? example "完整的 LR(0) 语法分析过程示例"
    分析输入 x x y $，语法为：

    ```text
    0: S' -> S $
    1: S -> x S
    2: S -> y
    ```

    构造 LR(0) Parsing DFA：

    \automata[->,>={Stealth[round]},shorten >=1pt,auto,node distance=4cm,on grid,semithick,inner sep=2pt,bend angle=50,initial text=,every state/.style={draw,rectangle,minimum width=2.8cm}]
        \node[initial,state] (q_1) {\textcircled{\footnotesize 1}\!\begin{tabular}{l} $S'\to\bullet\ S\ \$$ \\ $S\to\bullet\ x\ S$ \\ $S\to\bullet\ y$ \end{tabular}};
        \node[state] at (4, 0) (q_2) {\textcircled{\footnotesize 2}\!\begin{tabular}{l} $S\to x\ \bullet\ S$ \\ $S\to\bullet\ x\ S$ \\ $S\to\bullet\ y$ \end{tabular}};
        \node[state] at (4, -2.5) (q_3) {\textcircled{\footnotesize 3}\ $S\to y\ \bullet$};
        \node[state] at (0, -2.5) (q_4) {\textcircled{\footnotesize 4}\ $S'\to S\ \bullet\ \$$};
        \node[state] at (8, 0) (q_5) {\textcircled{\footnotesize 5}\ $S\to x\ S\ \bullet$};
        \path
            (q_1) edge node {$x$} (q_2)
                  edge node {$y$} (q_3)
                  edge node {$S$} (q_4)
            (q_2) edge node {$S$} (q_5)
                  edge node {$y$} (q_3)
                  edge [in=-45,out=-15,loop] node {$x$} (q_2);

    构造语法分析表：

    <center>

    |State|$x$ (Action)|$y$ (Action)|$\$$ (Action)|$S$ (GOTO)|
    |:--|:--|:--|:--|:--|
    |1|s2|s3||g4|
    |2|s2|s3||g5|
    |3|r2|r2|r2||
    |4|||accept||
    |5|r1|r1|r1||

    </center>

    进行分析：

    <center>

    |Stack|symbols|Buffer|Action|
    |:--|:--|:--|:--|
    |1||x x y \$|shift 2 (push 2)|
    |1 2|x|x y \$|shift 2 (push 2)|
    |1 2 2|x x|y \$|shift 3 (push 2)|
    |1 2 2 3|x x y|\$|reduce 2 (pop 3; push GOTO[2, S])|
    |1 2 2 5|x x S|\$|reduce 1 (pop 5,2; push GOTO[2, S])|
    |1 2 5|x S|\$|reduce 1 (pop 5,2; push GOTO[1, S])|
    |1 4|S|\$|accept|

    </center>

- LR(0) 的 0：是否规约、选择哪个产生式进行规约仅由栈顶状态决定
    - 带有 Reduce 的同一行全是 r*j*
- LR(0) 的局限性：对于 $X\to\alpha\bullet$，直接盲目进行规约
    - 如果存在 $X\to Y$ 和 $X\to Y\ Z$ 两条规则，就会出现冲突

#### SLR(1) 分析

- 利用更多信息来指导规约操作
- “LR 分析是最右推导的逆过程”
    - 所以如果要试图规约 $X\to\cdots$，则需要满足 $t\in\mathsf{Follow}(X)$，其中 $t$ 为下一个 token
- SLR(1) 与 LR(0) 的区别仅在于构造语法分析表时对于 r*j* 项的填入
    - LR(0)：状态 *i* 的结尾是点（可以进行规约），则 Action[*i*, \*] = r*k*
    - SLR(1)：状态 *i* 的结尾是点（可以进行规约），则 Action[*i*, *j*] = r*k*
        - 其中 *j* 为 $\mathsf{Follow}(X)$ 中的全部终结符，$X$ 为第 *k* 个产生式左侧的非终结符

??? example "无法使用 LR(0) 只能使用 SLR(1) 的例子"
    考虑如下语法：

    ```text
    0: S -> E $
    1: E -> T + E
    2: E -> T
    3: T -> x
    ```

    DFA：

    \automata[->,>={Stealth[round]},shorten >=1pt,auto,node distance=4cm,on grid,semithick,inner sep=2pt,bend angle=50,initial text=,every state/.style={draw,rectangle,minimum width=3.2cm}]
        \node[initial,state] (q_1) {\textcircled{\footnotesize 1}\!\begin{tabular}{l} $S\to\bullet\ E\ \$$ \\ $E\to\bullet\ T\ +\ E$ \\ $E\to\bullet\ T$ \\ $T\to\bullet\ x$ \end{tabular}};
        \node[state] at (4.5, 0.5) (q_2) {\textcircled{\footnotesize 2}\ $S\to E\ \bullet\ \$$};
        \node[state] at (4.5, -1) (q_3) {\textcircled{\footnotesize 3}\!\begin{tabular}{l} $E\to T\ \bullet\ +\ E$ \\ $E\to T\ \bullet$ \end{tabular}};
        \node[state] at (4.5, -3) (q_4) {\textcircled{\footnotesize 4}\!\begin{tabular}{l} $E\to T\ +\ \bullet\ E$ \\ $E\to\bullet\ T\ +\ E$ \\ $E\to\bullet\ T$ \\ $T\to\bullet\ x$ \end{tabular}};
        \node[state] at (0, -2) (q_5) {\textcircled{\footnotesize 5}\ $T\to x\ \bullet$};
        \node[state] at (0, -3.5) (q_6) {\textcircled{\footnotesize 6}\ $E\to T\ +\ E\ \bullet$};
        \path
            (q_1) edge node {$E$} (q_2)
                  edge node {$T$} (q_3)
                  edge node {$x$} (q_5)
            (q_3) edge [in=15,out=-15] node {$+$} (q_4)
            (q_4) edge node {$T$} (q_3)
                  edge node {$x$} (q_5)
                  edge node {$E$} (q_6);

    LR(0) 的语法分析表：

    <center>

    |State|$x$ (Action)|$+$ (Action)|$\$$ (Action)|$E$ (GOTO)|$T$ (GOTO)|
    |:--|:--|:--|:--|:--|:--|
    |1|s5|s3||g2|g3|
    |2|||accept|||
    |3|r2|s4,r2|r2|||
    |4|s5|||g6|g3|
    |5|r3|r3|r3|||
    |6|r1|r1|r1|||

    </center>

    此处出现了 s4 和 r2 冲突。使用 SLR(1) 要考虑 Follow：

    - $\mathsf{Follow}(E)=\{\$\}$
    - $\mathsf{Follow}(T)=\{+, \$\}$

    据此构造 SLR(1) 的语法分析表：

    <center>

    |State|$x$ (Action)|$+$ (Action)|$\$$ (Action)|$E$ (GOTO)|$T$ (GOTO)|
    |:--|:--|:--|:--|:--|:--|
    |1|s5|s3||g2|g3|
    |2|||accept|||
    |3||s4|r2|||
    |4|s5|||g6|g3|
    |5||r3|r3|||
    |6|||r1|||

    </center>

- SLR 解决冲突的方法是将按 $A\to \alpha$ 规约的条件增加为：下一个输入符号 $x$ **可以**在**某个句型**中跟在 $A$ 之后
- SLR(1) 的局限性：
    - 仅使用 Follow 集还是太弱
    - LR 分析过程每一步都应该是最右句型，而如果 $\beta Ax$ 不是任何最右句型的前缀，则不应该按 $A\to \alpha$ 规约
    - 换句话说，Follow 集的条件指要求了可以在某句型出现，但没有保证是**最右句型**
    - 所以使用 SLR(1) 仍然会有冲突的可能，还需要进一步严格规约的条件

#### LR(1) 分析

- LR(1) 项中包含了更多信息来消除一些规约动作
    - 形式为 $A\to\alpha\ \bullet\ \beta,\ x$，其中 $x$ 为向前看符号（终结符或 \$）
        - 表示符号栈顶为 $\alpha$，在输入串头部是可以从 $\beta x$ 推导出的串
- 相较 LR(0) 需要修改闭包的定义，增加条件
    - LR(0)：$\mathsf{Closure}(I)$ 为对于任意 $I$ 中的 $A\to\alpha\bullet X\beta$，将 $X\to\bullet\ \gamma$ 加入 $I$ 中，直到 $I$ 不变即为其闭包
    - LR(1)：$\mathsf{Closure}(I)$ 为对于任意 $I$ 中的 $A\to\alpha\bullet X\beta,\ z$，将 $X\to\bullet\ \gamma,\ w$ 加入 $I$ 中，直到 $I$ 不变即为其闭包
        - 其中 $w\in\mathsf{First}(\beta z)$，$X\to\gamma$ 是文法中的产生式
    - 起始状态为 $S'\to\bullet\ S\ \$,\ ?$，因为 \$ 不会被移进，所以 ? 是什么无所谓
- LR(1) 和 LR(0) 的 Goto 基本类似
- 构造 Action 表的时候，对于项 $A\to\alpha\beta\ \bullet,\ x$，只有下一个输入符号为 $x$ 时才可以规约
- LR(1) 的局限性：分析表会有非常多的状态，会非常大

#### LALR(1) 分析

- LALR(1) 用来缩减 LR(1) 的状态数量
- LR(1) DFA 中有很多状态只差了向前看符号，其实可以合并
- 合并状态的依据：LR(1) 项的 core 相同（即除去 lookahead 的第一个部分）
    - 比如 $\{(X\to\alpha\ \bullet\ \beta,\ b), (Y\to\gamma\ \bullet\ \delta,\ d)\}$ 的 core 是 $\{X\to\alpha\ \bullet\ \beta, Y\to\gamma\ \bullet\ \delta\}$
- 根据 LR(1) 的 DFA 构建 LALR(1) 的 DFA：
    - 选择两个有相同 core 的不同状态
    - 通过创建一个合并所有项的新状态来合并状态
    - 添加转移边
- LALR(1) 的分析表更小，需要更少的内存（一般比 LR(1) 小十倍）
    - 介于 SLR(1) 和 LR(1) 之间，分析表和 SLR(1) 一样大，但已经可以处理大部分的程序设计语言

### 错误恢复

- 开发者想要知道程序中的全部错误，而不是遇到第一个错误就停止
- 错误恢复的技术
    - Local error recovery
        - 使用 error 符号来表示错误，然后跳到下一个右括号或分号之后继续分析
            ```text
            exp -> ( error )
            exps -> error ; exp
            ```
        - 当遇到错误时，采取以下行动：
            - 弹出栈中的状态，直到栈顶状态包含 $A\to\alpha\ \bullet\ \mathsf{error}\ \beta$
            - 读入 error 进行转移
            - 如果 $\alpha$ 为空则直接规约，否则跳过后续输入符号直到可以规约
    - Global error recovery
        - 寻找一个插入和删除的最小集合，可以使得修改后的程序是合法的
    - Burke-Fisher error repair
        - 在出现问题的位置前不超过 *k* 个 token 中进行单个 token 的插入/删除/替换
        - 不需要修改 LL(*k*) LR(*k*) LALR 的语法和分析表就可以