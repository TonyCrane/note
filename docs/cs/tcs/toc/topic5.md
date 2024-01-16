---
comment: True
counter: True
---

# 函数可计算性

!!! abstract
    理论计算机科学导引第十二至第十三周课程内容

从函数的角度来看图灵机的判定性。考虑数值函数 $f\colon\mathbb{N}^k\to\mathbb{N}$，图灵机 $M$ computes $f$ if for any $n_1, \cdots, n_k\in\mathbb{N}$:

$$
M(\mathrm{bin}(n_1), \cdots, \mathrm{bin}(n_k)) = \mathrm{bin}(f(n_1, \cdots, n_k))
$$

## 原始递归函数

- basic functions
    - zero function: $\mathrm{zero}(n_1, n_2, \cdots, n_k) = 0$
    - identity function: $\mathrm{id}_{kj}(n_1, n_2, \cdots, n_k) = n_j$
    - successor function: $\mathrm{succ}(n) = n+1$
- basic functions 都是可计算的
- 两种操作：
    - composition: 
        - $g\colon\mathbb{N}^k\to\mathbb{N}$, $h_1, \cdots, h_k\colon\mathbb{N}^l\to\mathbb{N}$
        - => $f(n_1, \cdots, n_l) = g(h_1(n_1, \cdots, n_l), \cdots, h_k(n_1, \cdots, n_l))$
    - recursive definition:
        - $g\colon\mathbb{N}^{k}\to\mathbb{N}$, $h\colon\mathbb{N}^{k+2}\to\mathbb{N}$
        - $f\colon\mathbb{N}^{k+1}\to\mathbb{N}$, $\begin{cases}f(n_1, \cdots, n_k, 0) = g(n_1, \cdots, n_k) \\ f(n_1, \cdots, n_k, m+1) = h(n_1, \cdots, n_k, m, f(n_1, \cdots, n_k, m))\end{cases}$
- 定义：由 basic functions 和两种操作组合而成的函数为 primitive recursive functions
    - 推论：原始递归函数通过两种操作组合形成的函数仍为原始递归函数

???+ example "原始递归函数的例子"
    $\mathrm{plus2}(n) = n+2$
    :   $= \mathrm{succ}(\mathrm{succ}(n))$

    $\mathrm{plus}(m, n) = m + n$
    :   $\begin{cases}\mathrm{plus}(m, 0) = m \\ \mathrm{plus}(m, n+1) = \mathrm{succ}(\mathrm{plus}(m, n)) = \mathrm{succ}(\mathrm{id}_{3,3}(m, n, \mathrm{plus}(m, n)))\end{cases}$

    $\mathrm{mult}(m, n) = m \times n$
    :   $\begin{cases}\mathrm{mult}(m, 0) = 0 \\ \mathrm{mult}(m, n+1) = \mathrm{plus}(m, \mathrm{mult}(m, n))\end{cases}$

    $\mathrm{exp}(m, n) = m^n$
    :   $\begin{cases}\mathrm{exp}(m, 0) = 1 \\ \mathrm{exp}(m, n+1) = \mathrm{mult}(m, \mathrm{exp}(m, n))\end{cases}$

    $f(n_1, \cdots, n_k) = C$ 常数函数
    :   $\underbrace{\mathrm{succ}(\cdots(\mathrm{succ}}_{C\text{ times}}(\mathrm{zero}(n_1, \cdots, n_k))\cdots))$

    $\mathrm{sgn}(n) = \begin{cases}0 & n = 0 \\ 1 & n > 0\end{cases}$
    :   $\begin{cases}\mathrm{sgn}(0) = 0 \\ \mathrm{sgn}(n+1) = 1\end{cases}$

    $\mathrm{pred}(n) = \begin{cases}0 & n = 0 \\ n-1 & n > 0\end{cases}$
    :   $\begin{cases}\mathrm{pred}(0) = 0 \\ \mathrm{pred}(n+1) = n = \mathrm{id}_{2,1}(n, \mathrm{pred}(n))\end{cases}$

    $m\sim n = \max\{m-n, 0\}$
    :   $\begin{cases}m\sim 0 = m \\ m\sim (n+1) = \mathrm{pred}(m\sim n)\end{cases}$

- 如果 $f, g$ 均为原始递归函数，则 $f+g, f - g, f\cdot g$ 均为原始递归函数
- 函数值只有 0 1 的函数 => predicates
- 如果两个 predicates $p, q$ 都是原始递归函数，则 $p\land q, p\lor q, \lnot p$ 均为原始递归函数
    - $\lnot p = 1 - p, p\land q = p\cdot q, p\lor q = \mathrm{positive}(p+q)$

???+ example "predicates 例子"
    $\mathrm{positive}(n) = \mathrm{sgn}(n)$

    $\mathrm{iszero}(n) = 1 - \mathrm{sgn}(n)$

    $\mathrm{geq}(m, n) = \mathrm{iszero}(n\sim m)$

    $\mathrm{eq}(m, n) = \mathrm{geq}(m, n)\land\mathrm{geq}(n, m)$

- 条件函数 $f(n_1, \cdots, n_k) = \begin{cases}g(n_1, \cdots, n_k) & \text{if }p(n_1, \cdots, n_k)\\ h(n_1, \cdots, n_k) & \text{otherwise}\end{cases}$
    - 如果 $g, h, p$ 都是原始递归函数，则 $f$ 也是
    - $f=p\cdot g + (1\sim p)\cdot h$

???+ example "其他复杂原始递归函数例子"
    $\mathrm{rem}(m, n) = m \% n$
    :   $\begin{cases}\mathrm{rem}(0, n) = 0 \\ \mathrm{rem}(m+1, n) = \begin{cases}0 & \text{if }m+1\text{ is divisible by }n\\ \mathrm{rem}(m, n) + 1 & \text{otherwise}\end{cases}\end{cases}$

        其中 $m+1$ 被 $n$ 整除当且仅当 $\mathrm{eq}(\mathrm{rem}(m, n), \mathrm{pred}(n))$

    $\mathrm{div}(m, n) = \lfloor m/n\rfloor$（假定 $n\neq 0$）
    :   $\begin{cases}\mathrm{div}(0, n) = 0 \\ \mathrm{div}(m+1, n) = \begin{cases}\mathrm{div}(m, n) + 1 & \text{if }m+1\text{ is divisible by }n\\ \mathrm{div}(m, n) & \text{otherwise}\end{cases}\end{cases}$

    $\mathrm{digit}(m, n, p) = a_{m-1}$，其中 $n = \cdots+a_{m-1}p^{m-1}+\cdots+a_1p+a_0$（即将 $n$ 用 $p$ 进制表示并取第 $m$ 位）
    :   $\mathrm{digit}(m, n, p) = \mathrm{div}(\mathrm{rem}(n, p^m), p^{m-1})$

    $\mathrm{sum}_f(m, n) = \sum_{k = 0}^n f(m, k)$
    :   $\begin{cases}\mathrm{sum}_f(m, 0) = f(m, 0) \\ \mathrm{sum}_f(m, n+1) = \mathrm{sum}_f(m, n) + f(m, \mathrm{succ}(n))\end{cases}$

    $\mathrm{mult}_f(m, n) = \prod_{k = 0}^n f(m, k)$ 同理

    给定一个 primitive recursive predicates $p$，定义 $g_p(n)$（bounded disjunction）为在 $[0, n]$ 中是否存在值使 $p$ 为真，定义 $h_p(n)$（bounded conjunction）为在 $[0, n]$ 中的任意值是否都使得 $p$ 为真
    :   $g_p(n) = \mathrm{positive}(\sum_{k=0}^n p(k)) = \mathrm{positive}(\mathrm{sum}_p(n))$（第一个参数丢掉了）

        $h_p(n) = \prod_{k=0}^n p(k) = \mathrm{mult}_p(n)$

???+ success "Lemma. 原始递归函数都是可计算的"
    Proof. basic functions 都是可计算的，且 composition 和 recursive definition 会保留可计算性，所以组合而成的所有原始递归函数都是可计算的。

???+ tip "反之，所有可计算的函数**不**都是原始递归函数"
    所有的原始递归函数都可以通过类似正则表达式一样的方式来描述，意味着原始递归函数是可以枚举的。所以构造图灵机 $M$ = on input $n$:

    1. enumerate all unary primitive recursive functions $g_1, g_2, \cdots$ to get $g_n$
    2. compute $g_n(n)$
    3. return $g_n(n) + 1$

    称 $M$ 这时候 compute $g^*$，但 $g^*\neq g_n$，所以 $g^*$ 不是原始递归函数。

## <span class="heti-skip">μ-递归函数</span>

- 在原始递归函数的基础上附加一个操作：minimalization of minimalizable functions
    - 给定函数 $g\colon\mathbb{N}^{k+1}\to\mathbb{N}$
    - 令 $f(n_1, \cdots, n_k) = \begin{cases}\text{minimum }m\text{ with }g(n_1, \cdots, n_k, m) = 1 &\text{if exists}\\ 0 &\text{otherwise}\end{cases}$
    - 称 $f$ is a minimalization of $g$，记作 $\mu m[g(n_1, \cdots, n_k, m) = 1]$

???+ example "<span class="heti-skip">μ-递归函数</span>的例子"
    $\log(m, n) = \lceil\log_{m+2}(n+1)\rceil$
    :   相当于 $\min\{p:(m+2)^p\geq n+1\}$，即 $\mu p[\mathrm{geq}((m+2)^p, n+1) = 1]$

- 一个函数 $g$ 是 minimalizable 的如果
    - $g$ 是可计算的
    - 对于任意 $n_1, \cdots n_k$，都存在 $m\geq 0$ 使得 $g(n_1, \cdots, n_k, m) = 1$
- minimalization of $g$ is computable if $g$ is minimalizable
    - 判断一个可计算函数 $g$ 是否是 minimalizable 的是不可判定的（停机问题）

???+ success "Theorem. 数值函数 $f$ 是 <span class="heti-skip">μ-递归</span>的当且仅当它可计算"
    Proof. 左推右，各三个操作都保留可计算性，所以显然。

    右推左，Proof Sketch: $f$ 可计算 => 存在图灵机 $M$ computes $f$ => $(s, \rhd\underline{⌴}n)\vdash_M(q_1, \rhd u_1\underline{a_1}v_1)\vdash_M\cdots\vdash_M(h, \rhd\underline{⌴}f(n))$

    将这个转换过程提取称串 $\rhd⌴sn\!\rhd\!u_1a_1q_1v_1\cdots\rhd\!⌴hf(n)$（把状态放在当前读写头右侧）。通过映射 $\Sigma\cup K\to\{0, \cdots, b-1\}$（其中 $b=|\Sigma\cup K|$）将这个串转换为 $b$ 进制的整数，所以整个的转换过程就是：

    $$
    n\to\rhd⌴sn\to\rhd⌴sn\!\rhd\!u_1a_1q_1v_1\cdots\rhd\!⌴hf(n)\to\rhd⌴hf(n)\to f(n)
    $$

    这里每个都是一个 $b$ 进制整数，所以只要证明每一次转换的函数都是 <span class="heti-skip">μ-递归</span>的即可：

    - $n$
        - $h_1(n) = \rhd⌴s\cdot b^{\log_b n} + n$（在前面添加 $\rhd⌴s$）
    - $\rhd⌴sn$
        - $h_2(n) = \mu m[\mathrm{iscomp}(\rhd⌴sn, m)\land\mathrm{ishalted}(m)]$
            - 找到一个最小的串，使之可以由 $\rhd⌴sn$ 生成，并且最终是停机状态
            - $\mathrm{iscomp}$ 和 $\mathrm{ishalted}$ 都是原始递归的，但没有证明
    - $\rhd⌴sn\!\rhd\!u_1a_1q_1v_1\cdots\rhd\!⌴hf(n)$
        - $h_3(n) = \mathrm{rem}(n, b^{k^*+1})$ 其中 $k^* = \mu k[\mathrm{isdigit}(k, n, b) = \rhd]$
            - 找到最后一个 $\rhd$ 的位置并取其和其后的部分
    - $\rhd⌴hf(n)$
        - $h_4$ 和 $h_3$ 同理，找最后一个 $h$ 的位置并取其后的部分
    - $f(n)$

## Unrestricted Grammar

!!! warning "应该不属于这一章，但先记在这里了"

- Context-Free Grammar 无上下文，而这里的 Grammar 可以有上下文
    - 即例如 $uAv\to w$，只有上下文 $uv$ 都匹配了才可以进行替换
- 一个 Grammar 同样是一个四元组 $G=(V, \Sigma, S, R)$
    - $V, \Sigma, S$ 定义和 CFG 相同
    - $R$ is a finite subset of $(V^*(V-\Sigma)V^*)\times V^*$
        - 对比 CFG 的 $R\subseteq (V-\Sigma)\times V^*$，可见其多了上下文 $V^*$
    - 同样可以定义 $\Rightarrow_G, \Rightarrow_G^*$ 以及生成语言 $L(G)$

??? example "给出语言 $\{a^nb^nc^n:n\geq 0\}$ 的文法"
    - $S\to ABCS$：生成 $ABCABC\cdots ABCS$
    - $BA\to AB,\ CA\to AC,\ CB\to BC$：重排为 $A\cdots AB\cdots BC\cdots CS$
    - $S\to T_c$：结尾变成标志符
    - $CT_c\to T_cc,\ BT_c\to BT_b$：向左替换所有的 $C$，并在遇到 $B$ 时变成 $T_b$
    - $BT_b\to T_bb,\ AT_b\to AT_a$：同理
    - $AT_a\to T_aa,\ T_a\to e$

???+ success "Theorem. 一个语言可以被某一文法生成当且仅当它可以被某一图灵机半判定"
    Proof. 左推右，给定文法 $G$ 需要给出一个图灵机 $M$ 半判定 $L(G)$ 即可，所以只需要枚举文法可以生成的所有字符串再进行比较即可。

    右推左，给定图灵机 $M$ 要找文法 $G$ 生成 $L(M)$。图灵机半判定的过程中，纸带上的变化：

    $$
    \rhd⌴sw\vdash\rhd⌴u_1a_1q_1v_1\vdash\cdots\vdash\rhd⌴h
    $$

    所以我们期望文法 $G$ 的表现是可以给出如下的替换链：

    $$
    S\Rightarrow \rhd⌴h\triangle\Rightarrow\cdots\Rightarrow\rhd⌴u_1a_1q_1v_1\triangle\Rightarrow\rhd⌴sw\triangle\Rightarrow w
    $$

    即从停机状态往前推，一直找到初始状态得到字符串 $w$，并且在中间给每个状态加上一个三角标记结尾。这样我们可以构造 $G$ 的转换规则：

    - $\rhd⌴s\to e,\ \triangle\to e$：将最后字符串的开头结尾去掉
    - 枚举图灵机的每条转换规则：
        - 如果 $\delta(q, a) = (p, b)$，即图灵机这条规则在进行写操作
            - 我们知道此时图灵机在 $uaqv\triangle\vdash_M ubpv\triangle$
            - 所以逆推回来并去掉无用的上下文得到 $bp\to aq$
        - 如果 $\delta(q, a) = (p, \rightarrow)$，即读写头右移
            - 此时图灵机 $uaqbv\triangle\vdash_M uabpv\triangle$
            - 则添加规则，对于任意 $b\in\Sigma, abp\to aqb$（这里 $a$ 不能去掉，是有用的上下文）
            - 如果 $b=⌴$ 且 $v=e$，则 $a⌴p\triangle\to aq\triangle$
        - 如果 $\delta(q, a) = (p, \leftarrow)$，即读写头左移，和右移同理