---
comment: True
counter: True
---

# 图灵机理论基础

!!! abstract
    理论计算机科学导引第八至第？周课程内容

## 图灵机

### 基本定义

- 一个“纸带”，一个读写头可进行单元格的左右移动和符号的读写
    - 特殊符号 $\rhd$（left end symbol）表示纸带的最左侧，无法覆盖
    - 特殊符号 $⌴$（black symbol）表示纸带这个位置是一个空格子
- 一个图灵机定义为一个五元组 $M=(K, \Sigma, \delta, s, H)$
    - $K$：状态的有限集合
    - $\Sigma$：纸带上可以出现的符号（包括 $\rhd⌴$）
    - $s\in K$：起始状态
    - $H\subseteq K$：停机状态（halting state）的集合
    - $\delta\colon(K-H)\times\Sigma\rightarrow K\times(\{\leftarrow, \rightarrow\}\cup (\Sigma-\{\rhd\}))$：转移函数，其中：
        - $(K-H)$：非停机状态，停机状态无法再转移
        - $\Sigma$：读写头读到的符号
        - $\{\leftarrow, \rightarrow\}$：读写头向左/右移动
        - $(\Sigma-\{\rhd\})$：读写头写入的符号，不能写入 $\rhd$
        - 需要满足 $\forall q\in K, \delta(q, \rhd)=(p, \rightarrow)$ for some $p$
- configuration：$K\times\rhd(\Sigma-\{\rhd\})\times(\{e\}\cup(\Sigma-\{\rhd\})^*(\Sigma-\{\rhd, ⌴\}))$
    - $\rhd(\Sigma-\{\rhd\})$：纸带上到读写头为止的部分，$\rhd$ 开头，最后一个为读写头指向的位置
    - $\{e\}$：读写头右侧没有非空格子的话就是 $e$
    - $(\Sigma-\{\rhd\})^*(\Sigma-\{\rhd, ⌴\})$：读写头右侧的非空格子
    - e.g. $(q, \rhd⌴ab, a)$，等价可以写为 $(q, \rhd⌴a\underline{b}a)$（下划线表示读写头指向的位置）
    - 初始 configuration：$(s, ?)$，纸带内容不同场合有不同约定
    - 停机 configuration：$(h, ?), h\in H$，纸带内容无所谓
- yields in one step / yields
    - $(q_1, \rhd w_1\underline{a_1}u_1)\vdash_M(q_2, \rhd w_2\underline{a_2}u_2)$ if:
        - $\delta(q_1, a_1) = (q_2, a_2),\ w_1=w_2,\ u_1=u_2$：写的情况
        - $\delta(q_1, a_1) = (q_2, \leftarrow),\ w_1=w_2a_2,\ u_2 = a_1u_1$：左移的情况
            - 特殊情况：if $a_1 = ⌴$ and $u_1=e$, $u_2=e$
        - $\delta(q_1, a_1) = (q_2, \rightarrow),\ w_2=w_1a_1,\ u_1 = u_2a_2$：右移的情况
    - yields 还是相等或者 yield 一步或更多步

### 构建图灵机

- basic machines
    - symbol writing machine $M_a$，记为 $a$
        - 效果：如果当前位置可写，就写入 $a$，如果当前位置是 $\rhd$ 就右移一位再写入 $a$
        - 定义 $M_a=(\{s, h\}, \Sigma, \delta, s, \{h\})$，其中 $\delta$ 定义为：
            - $\delta(s, b) = (h, a)$ for each $b\in\Sigma-\{\rhd\}$
            - $\delta(s, \rhd) = (s, \rightarrow)$
    - head moving machine $M_\leftarrow, M_\rightarrow$ 分别记为 $L, R$
        - 效果：读写头向左/右移动一位（左移的话如果当前位置是 $\rhd$ 就停机）
        - 定义 $M_\leftarrow$ 类似 $M_a$，将 $a$ 替换为 $\leftarrow$ 即可
        - 定义 $M_\rightarrow$ 更为简单，不需要考虑 $\rhd$ 的情况
- 采用一个新的表示方法，用来连接图灵机的作用构成更复杂的图灵机

    \automata[->,>={Stealth[round]},auto,node distance=4em,on grid,semithick,inner sep=2pt,bend angle=50,initial text=,every state/.style={draw=none,minimum size=0pt,inner sep=1pt}]
        \node[initial,state]    (m_1)                   {$M_1$};
        \node[state]            (m_2) [right=of m_1]    {$M_2$};
        \node[state]            (m_3) [below=of m_1]    {$M_3$};
        
        \path
            (m_1) edge node {0} (m_2)
            (m_1) edge node {1} (m_3);
    
    - 首先执行图灵机 $M_1$ 直到停机
    - 检查停机状态时当前读写头指向的位置
        - 如果是 0 则执行 $M_2$ 直到停机
        - 如果是 1 则执行 $M_3$ 直到停机
        - 否则直接停机
    - 一些特殊的表示：
        - $>\!\!R\overset{\Sigma}{\longrightarrow} R$，或记为 $>\!\!RR, >\!\!R^2$，右移两格
        - $>\!\!R\overset{a\neq ⌴}{\longrightarrow}Ra$，右移，如果不为空则 copy 到右侧格子
        - $>\!\!R$ 指向自身，箭头上是 $\bar{⌴}$（表示非空格），作用是移动到右侧第一个空格的位置，记为 $R_{⌴}$
        - $>\!\!R$ 指向自身，箭头上是 $⌴$，作用是移动到右侧第一个非空格的位置，记为 $R_{\bar{⌴}}$
        - 同理有记法 $L_{⌴}, L_{\bar{⌴}}$

??? example "构建 left shifting machine $S_\leftarrow$"
    效果是对于任意 $w\in(\Sigma-\{\rhd, ⌴\})^*$，将 $\rhd⌴⌴w\underline{⌴}$ 变为 $\rhd⌴w\underline{⌴}$

    \automata[->,>={Stealth[round]},auto,node distance=4em,on grid,semithick,inner sep=2pt,bend angle=50,initial text=,every state/.style={draw=none,minimum size=0pt,inner sep=1pt}]
        \node[initial,state]    (q_0)                   {$L\sqcup$};
        \node[state]      at (1, 0)      (q_1)    {$R$};
        \node[state]      at (3, 0)      (q_2)     {$\sqcup LaR$};
        \node[state]      at (1, -1)      (q_3)     {$L$};
        
        \path
            (q_0) edge node {} (q_1)
            (q_1) edge node {$a\neq\sqcup$} (q_2)
                  edge node {$\sqcup$} (q_3)
            (q_2) edge [bend right] node {} (q_1);
    
    最右侧的图灵机 $⌴LaR$ 表示先清空当前格，然后左移，将刚读取到的字符写入，然后再右移回来

### 图灵机功能

- Recognize language
    - 图灵机基础上补加一个集合 $\Sigma_0\subseteq \Sigma-\{\rhd, ⌴\}$ 表示输入的字符集
    - 定义起始 configuration 为 $(s, \rhd\underline{⌴}w)$，其中 $w$ 为输入字符串
    - 半判定（semidecides）
        - $M$ semidecides $L(M)=\{w\in\Sigma_0^*: (s, \rhd\underline{⌴}w)\vdash_M^*(h, \rhd u)\}$，其中 $h\in H, u\in\Sigma^*$
        - 语言中的字符串会停机，不属于语言的字符串不停机
        - “半”的原因：判定时间很长的话不知道到底最后会不会停机
    - 判定（decides）
        - 令 $M=(K, \Sigma_0, \Sigma, \delta, s, \{y, n\})$，$M$ decides a language $L\subseteq \Sigma_0^*$ if:
            - $\forall w\in L$, $(s, \rhd\underline{⌴}w)\vdash_M^*(y, \cdots)$，称 $M$ accepts $w$
            - $\forall w\in \Sigma_0^*-L$, $(s, \rhd\underline{⌴}w)\vdash_M^*(n, \cdots)$，称 $M$ rejects $w$
        - 不管接不接受都会停机，只不过停机的状态不同
    - 有图灵机判定一个语言，则称这个语言是 recursive / decidable 的
    - 有图灵机半判定一个语言，则称这个语言是 recursively enumerable / recognizable 的
    - 定理：如果一个语言是 recursive 的，则它是 recursively enumerable 的
        - 给 $n$ 的停机状态变成一个循环不停机的状态就可以
- Compute function
    - 对于 $w\in\Sigma_0^*$，如果 $(s, \rhd\underline{⌴}w)\vdash_M^*(h, \rhd\underline{⌴}y)$（其中 $h\in H, y\in\Sigma_0^*$），则称 $y=M(w)$ 为图灵机在输入 $w$ 时的输出
    - 对于任意函数 $f\colon\Sigma_0^*\rightarrow\Sigma_0^*$，如果存在图灵机 $M$ 使得 $M(w)=f(w)$，则称
        - $M$ computes $f$
        - $f$ 是 recursive / computable 的

???+ example "证明 $L=\{a^nb^nc^n:n\geq 0\}$ 是 recursive 的"
    构造图灵机，思路：每次从左到右依次删一组 abc，改为 x，然后检测最后是否都是 x：

    \automata[->,>={Stealth[round]},auto,node distance=5em,on grid,semithick,inner sep=2pt,bend angle=50,initial text=,every state/.style={draw=none,minimum size=0pt,inner sep=1pt}]
        \node[initial,state]    (q_0)                   {$R$};
        \node[state]            (q_1) [right=of q_0]    {$xR$};
        \node[state]            (q_2) [right=of q_1]    {$xR$};
        \node[state]            (q_3) [right=of q_2]    {$xL\sqcup$};
        \node[state]            (q_4) [below=of q_0]    {$y$};
        \node[state]            (q_5) [right=of q_4]    {$n$};
        
        \path
            (q_0)   edge                node {$a$}          (q_1)
                    edge                node {$\sqcup$}     (q_4)
                    edge                node {$b,c$}        (q_5)
                    edge [loop above]   node {$x$}          (q_0)
            (q_1)   edge                node {$b$}          (q_2)
                    edge                node {$c,\sqcup$}   (q_5)
                    edge [loop above]   node {$a,x$}        (q_1)
            (q_2)   edge                node {$c$}          (q_3)
                    edge                node {$\sqcup$}     (q_5)
                    edge [loop above]   node {$b,x$}        (q_2)
            (q_3)   edge [bend right]   node {}             (q_0);
    
    但这种情况会接受 $abcabc$，所以需要删 $abc$ 之后分别变为 $xyz$，然后再检测：

    \automata[->,>={Stealth[round]},auto,node distance=5em,on grid,semithick,inner sep=2pt,bend angle=50,initial text=,every state/.style={draw=none,minimum size=0pt,inner sep=1pt}]
        \node[initial,state]    (q_0)                   {$R$};
        \node[state]            (q_1) [right=of q_0]    {$xR$};
        \node[state]            (q_2) [right=of q_1]    {$yR$};
        \node[state]            (q_3) [right=of q_2]    {$zL\sqcup$};
        \node[state]            (q_4) [below=of q_0]    {$y$};
        \node[state]            (q_5) [right=of q_4]    {$n$};
        
        \path
            (q_0)   edge                    node                {$a$}               (q_1)
                    edge                    node [swap]         {$\sqcup$}          (q_4)
                    edge [bend right=30]    node [font=\small]  {$b,c,y,z$}         (q_5)
                    edge [loop above]       node                {$x$}               (q_0)
            (q_1)   edge                    node                {$b$}               (q_2)
                    edge                    node                {$c,\sqcup,x,z$}    (q_5)
                    edge [loop above]       node                {$a,y$}             (q_1)
            (q_2)   edge                    node                {$c$}               (q_3)
                    edge [bend left=30]     node [font=\small]  {$\sqcup,a,x,y$}    (q_5)
                    edge [loop above]       node                {$b,z$}             (q_2)
            (q_3)   edge [bend right]       node                {}                  (q_0);