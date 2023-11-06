---
counter: True
comment: True
---

# 函数与递归

!!! abstract
    编程语言原理第八周至第？周课程内容

## 函数

- 函数定义：将名字绑定到带约束变量的 abt 来定义
- 函数应用：用合适类型的特定表达式来替换约束变量从而得到一个表达式

### 一阶函数

- 扩充定义 ED 语言：
    - $\mathsf{Exp}\ e::=\mathrm{apply}\{f\}(e)$ 表示 $f(e)$
    - $\mathsf{Exp}\ e::=\mathrm{fun}\{\tau_1; \tau_2\}(x_1.e_2; f.e)$ 表示 $\mathrm{fun}\ f(x_1:\tau_1):\tau_2=e_2\ \mathrm{in}\ e$
        - 将 $e$ 中函数名 $f$ 绑定到模式 $x_1.e_2$（具有参数 $x_1$ 和定义 $e_2$）
        - $f(\tau_1; \tau_2)$ 和 $f(\tau_1):\tau_2$ 等价，称为函数头，$\tau_1$ 是参数类型，$\tau_2$ 是返回值类型
- 函数代换，记作 $[\![x_1.e_2/f]\!]e$
    - $\dfrac{}{[\![x_1.e_2/f]\!]\mathrm{apply}\{f\}(e_1)=\mathrm{let}([\![x_1.e_2/f]\!]e_1; x_1.e_2)}$
    - 理解为施加函数应用，令“函数体” $e_2$ 中的参数 $x_1$ 为 $[\![x_1.e_2/f]\!]e_1$，即经过代换后的参数 $e_1$
- 动态语义
    - $\dfrac{}{\mathrm{fun}\{\tau_1; \tau_2\}(x_1.e_2; f.e)\mapsto [\![x_1.e_2/f]\!]e}$
    - $e$ 中函数 $f$ 参数是 $x_1$ 结果为 $e_2$，这个定义的语义就是在 $e$ 中进行函数代换

### 高阶函数
- 扩充定义 EF 语言：
    - 函数类型：$\mathsf{Typ}\ \tau ::= \mathrm{arr}(\tau_1; \tau_2)$ 表示一个 $\tau_1\rightarrow\tau_2$ 的函数类型
    - 函数抽象：$\mathsf{Exp}\ e ::= \mathrm{lam}\{\tau\}(x.e)$ 表示一个带类型的 λ 函数 $\lambda(x:\tau)e$（函数类型的引入形式）
    - 函数应用：$\mathsf{Exp}\ e ::= \mathrm{ap}(e_1; e_2)$ 表示 $e_1(e_2)$（函数类型的消去形式）
- 函数是一等的，可以和其他表达式一样，可以作为参数和返回值
- 静态语义：$\dfrac{\Gamma, x:\tau_1\vdash e:\tau_2}{\Gamma\vdash\mathrm{lam}\{\tau_1\}(x.e):\mathrm{arr}(\tau_1; \tau_2)},\ \dfrac{\Gamma\vdash e_1:\mathrm{arr}(\tau_2; \tau)\quad\Gamma\vdash e_2:\tau_2}{\Gamma\vdash \mathrm{ap}(e_1; e_2):\tau}$
- 引理 8.2（反转，inversion）：假设 $\Gamma\vdash e:\tau$
    - 如果 $e=\mathrm{lam}\{\tau_1\}(x.e_2)$ 那么 $\tau=\mathrm{arr}(\tau_1; \tau_2)$ 且 $\Gamma,x:\tau_1\vdash e_2:\tau_2$
    - 如果 $e=\mathrm{ap}(e_1; e_2)$ 那么存在 $\tau_2$ 使得 $\Gamma\vdash e_1:\mathrm{arr}(\tau_2; \tau)$ 且 $\Gamma\vdash e_2:\tau_2$
- 同样成立的旧性质：
    - 引理 8.3（代换，substitution）：如果 $\Gamma, x:\tau\vdash e':\tau'$ 且 $\Gamma\vdash e:\tau$，那么 $\Gamma\vdash [e/x]e':\tau'$
    - 引理 8.4（保持性，preservation）：如果 $e:\tau$ 且 $e\mapsto e'$ 那么 $e':\tau$
    - 引理 8.5（范式，canonical forms）：如果 $e:\mathrm{arr}(\tau_1; \tau_2)$ 且 $e\text{ val}$ 那么对于满足 $x:\tau_1\vdash e_2:\tau_2$ 的变量 $x$ 和表达式 $e_2$ 有 $e=\lambda(x:\tau_1)e_2$
    - 引理 8.6（进展性，progress）：如果 $e:\tau$ 则要么 $e\text{ val}$ 要么存在 $e'$ 使得 $e\mapsto e'$

### 动态作用域

比如考虑如下代码，该输出什么（1 还是 2）：

```text
x <- 1
f <- function(a) x + a
g <- function() {
    x <- 2
    f(0)
}
g()
```

- 静态作用域（static scoping）又称为词法作用域（lexical scoping），根据程序的词法结构就决定
    - 大部分编程语言都是静态作用域的
    - 函数访问的始终是被创建（声明）处的变量
    - 如上的例子中静态作用域会输出 1
- 动态作用域（dynamic scoping），在运行时确定
    - 函数访问的是调用的位置或者说执行到当前位置时的“环境”中的变量
    - 如上的例子中动态作用域会输出 2
- 书上的例子：在用到高阶函数时会出现区别
    - 考虑函数 $e := (\lambda(x:\mathrm{num}).\ (\lambda(y:\mathrm{num}).\ (x+y)))(42)$
        - 静态作用域根据 abt 进行代换，化为 $e=\lambda(y:\mathrm{num}).\ 42+y$
        - 动态作用域下会得到开项 $e=\lambda(y:\mathrm{num}).\ x+y$
            - 变量绑定尽量晚的确定，根据求值时的环境决定，所以此时还不需要 $x$，它是自由的
    - 再计算 $\Big(\lambda(f:\mathrm{num}\rightarrow\mathrm{num}).\ \big(\lambda(x:\mathrm{num}).\ f(0)\big)\big(7\big)\Big)\Big(e\Big)$
        - 静态作用域求值下将 $f$ 代换为 $e$，这样 $f(0)$ 得到了 42 然后此时 $(\lambda(x:\mathrm{num}).\ 42)(7)$ 的值仍为 42
        - 动态作用域求值下最终 $x=0, y=7$ 所以结果为 7