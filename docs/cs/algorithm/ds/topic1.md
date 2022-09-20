---
counter: True
comment: True
---

# 算法分析基础

!!! abstract
    数据结构基础第 1 至 2 周课程内容

## 算法与分析

- 一个定义好的、计算机可执行的、解决某一问题的有限步骤
- 需要有以下特征：
    - Input
    - Output
    - Definiteness
    - Finiteness
    - Effectiveness
- program 不需要 finite（比如操作系统）
- 算法分析内容：
    - 运行时间：与机器和编译器有关
    - 时间复杂度、空间复杂度：与机器和编译器无关
- 复杂度分析假设
    - 指令按顺序执行
    - 所有指令（运算）都消耗同一时间单元
    - 数据规模是给定的，且有无限空间
- 一般需要分析 $T_{\mathrm{avg}}(N)$（平均情况）和 $T_{\mathrm{worst}}(N)$（最差情况），$N$ 是输入的数据规模（也可以有多个输入规模）

## 复杂度渐进记号
### 定义
- 大 $O$ 表示法 $T(N) = O(f(N))$，如果存在常数 $c$ 和 $n_0$ 使得当 $N\geq n_0$ 时 $T(N)\leq c\cdot f(N)$
    - 渐进上界，即 $T(N)$ 的阶不会高于 $f(N)$（增长比 $f(N)$ 慢或相同，<=）
- 大 $\Omega$ 表示法 $T(N) = \Omega(g(N))$，如果存在常数 $c$ 和 $n_0$ 使得当 $N\geq n_0$ 时 $T(N)\geq c\cdot g(N)$
    - 渐进下界，即 $T(N)$ 的阶不会低于 $f(N)$（增长比 $f(N)$ 快或相同，>=） 
- 大 $\Theta$ 表示法 $T(N) = \Theta(h(N))$，当且仅当 $T(N) = O(h(N))$ 且 $T(N) = \Omega(h(N))$
    - 渐进紧确界，即 $T(N)$ 需要与 $h(N)$ 同阶（增长速度相同 =）
- 小 $o$ 表示法 $T(N) = o(p(N))$，当 $T(N) = O(p(N))$ 且 $T(N)\ne \Theta(p(N))$ 时
    - 非渐进紧确上界（$T(N)$ 增长比 $p(N)$ 慢，<）
- 小 $\omega$ 表示法 $T(N) = \omega(p(N))$，当 $T(N) = \Omega(q(N))$ 且 $T(N)\ne \Theta(q(N))$ 时
    - 非渐进紧确下界（$T(N)$ 增长比 $q(N)$ 快，>）

### 规则
- 如果 $T_1(N) = O(f(N))$ 且 $T_2(N) = O(g(N))$，则：
    - $T_1(N) + T_2(N) = \mathrm{max}(O(f(N)), O(g(N)))$
    - $T_1(N)\cdot T_2(N) = O(f(N)\cdot g(N))$
- 如果 $T(N)$ 是 $N$ 的 $k$ 次多项式，则 $T(N) = \Theta(N^k)$
- 对于任意常数 $k$ 均有 $\log^kN = O(N)$
- 大 O 记号比较：[Big O Cheat Sheet](https://www.bigocheatsheet.com/)
- 分析规则：
    - for 循环的运行时间是循环内部语句的最长时间（含 for 判断）乘循环次数
    - 嵌套 for 循环要逐次相乘
    - if else 语句的运行时间不超过判断时间+耗时最长的语句块的运行时间
- 补充：主定理。假设有 $T(n) = aT(n/b)+f(n)$（$a\geq 1, b>1$），则：
    - 如果存在常数 $\epsilon > 0$ 有 $f(n) = O(n^{\log_ba-\epsilon})$，则 $T(n) = \Theta(n^{\log_ba})$
    - 如果 $f(n) = \Theta(n^{\log_ba})$ 则 $T(n) = \Theta(n^{\log_ba}\log n)$
    - 如果存在常数 $\epsilon > 0$ 有 $f(n) = \Omega(n^{\log_ba+\epsilon})$，同时存在常数 $c<1$ 使得对于充分大 $n$ 有 $af(n/b)\leq cf(n)$ 则 $T(N) = \Theta(f(n))$

## 例：最大子序列和问题
### O(N³)
直接枚举开头结尾，并计算中间子序列和：
```c 
int MaxSubsequenceSum(const int a[], int N) {
    int res = 0;
    for (int i = 0; i < N; ++i) {
        for (int j = i; j < N; ++j) {
            int now = 0;
            for (k = i; k <= j; ++k) {
                now += a[k];
            }
            res = max(res, now);
        }
    }
    return res;
} 
```
### O(N²)
同样枚举开头结尾，不过动态计算子序列和，省去最内层循环
```c
int MaxSubsequenceSum(const int a[], int N) {
    int res = 0;
    for (int i = 0; i < N; ++i) {
        int now = 0;
        for (int j = i; j < N; ++j) {
            now += a[j];
            res = max(res, now);
        }
    }
    return res;
}
```
### O(NlogN)
使用分治算法

$$
\begin{align*}
T(N) &= 2T(N/2)+cN,\quad T(1) = O(1) \\
&= 2\left(2T(N/2^2)+cN/2\right)+cN \\
&= 2^kO(1) + ckN\qquad\text{where }N/2^k=1 \\
&= O(N\log N)
\end{align*}
$$

### O(N)
动态规划思想
```c
int MaxSubsequenceSum(const int a[], int N) {
    int res = 0, now = 0;
    for (int i = 0; i < N; ++i) {
        now += a[i];
        res = max(res, now);
        now = max(now, 0);
    }
    return res;
}
```