---
comment: True
counter: True
---

# 逻辑与推理

!!! abstract
    人工智能基础第 2 周课程内容

    参考：

    - 《人工智能导论：模型与算法》- 吴飞


## 命题逻辑
- 命题逻辑（proposition logic）是应用一套形式化规则对以符号表示的描述性陈述（称为命题）进行推理的系统
- 命题逻辑以原子命题作为最基本的单位，无法对原子命题进行分解（分离其主语与谓语）
- 命题逻辑是数理逻辑的基础
- 通过命题联结词（connectives）对已有命题进行组合，得到新命题，称为符合命题（compound proposition）
    - 命题合取 conjunction，$p\wedge q$
    - 命题析取 disjunction，$p\vee q$
    - 命题否定 negation，$\neg p$
    - 命题蕴含 implication，$p\rightarrow q$，$p$ 为前件，$q$ 为后件
    - 命题双向蕴含 bi-implication，$p\leftrightarrow q$
- 逻辑等价：在所有情况下都有相同真假结果
    - 逆否命题：$(\alpha\rightarrow\beta)\equiv\neg\beta\rightarrow\neg\alpha$
    - 蕴含消除：$(\alpha\rightarrow\beta)\equiv\neg\alpha\vee\beta$
    - 双向消除：$(\alpha\leftrightarrow\beta)\equiv(\alpha\rightarrow\beta)\wedge(\beta\rightarrow\alpha)$
    - ...
- 推理：按照某种策略从前提出发推出结论的过程。常见推理规则：
    - 假言推理 modus ponens：$\alpha\rightarrow\beta, \alpha\Rightarrow\beta$
    - 与消解 and-elimination：$\alpha_1\wedge\alpha_2\wedge\cdots\wedge\alpha_n\Rightarrow\alpha_i(1\leq i\leq n)$
    - 与导入 and-introduction：$\alpha_1,\alpha_2,\cdots,\alpha_n\Rightarrow\alpha_1\wedge\alpha_2\wedge\cdots\wedge\alpha_n$
    - 双重否定 double-negation elimation
    - 单项消解或单项归结 unit resolution：$\alpha\vee\beta,\neg\beta\Rightarrow\alpha$
    - 消解或归结 resolution：$\alpha\vee\beta,\neg\beta\vee\gamma\Rightarrow\alpha\vee\gamma$
- 范式（normal form）是把命题公式化为一种标准的形式，作用是可以进行两个命题的等价判断
    - 析取范式 disjunctive normal form（DNF）：有限个简单合取式构成的析取式称为析取范式
    - 合取范式 conjunctive normal form（CNF）：有限个简单析取式构成的合取式称为合取范式
    - 一个 DNF 不成立当且仅当每个简单合取式都不成立
    - 一个 CNF 成立当且仅当每个简单析取式都成立
    - 命题公式的 DNF 和 CNF 都是不唯一的

## 谓词逻辑
- 命题逻辑无法表达局部与整体、一般与个别的关系
- 将原子命题进一步细化，分解出个体、谓词和量词，来表达个体与总体的内在联系和数量关系，就是谓词逻辑（predicate logic）的研究内容
- 个体：个体式指所研究领域中可以独立存在的具体或抽象的概念
    - 具体、特定 -> 个体常量；抽象、泛指 -> 个体变量
    - 规定，用小写字母 $a$ 至 $w$ 表示个体常量（$x,y,z$ 表示个体变量）
    - 个体的取值范围称为个体域
- 谓词：谓词是用来刻画个体属性或者描述个体之间的关系存在性的元素，其值为真或假
    - 包含一个参数的谓词称为一元谓词，表示一元关系
    - 包含多个参数的谓词称为多元谓词，表示个体间的多元关系
    - 规定，用 $A(\cdots)$ 至 $Z(\cdots)$ 表示谓词，为大写字母后跟括号，括号内放置个体常量或变量
- 量词：全称量词和存在量词统称为量词
    - 全称量词：表示一切的、所有的、凡事、每一个等，符号 $\forall$
    - 存在量词：表示存在、有一个、某些等，符号 $\exist$
    - 全称量词的描述性是可以用相应的存在量词的藐视形式替换
    - 约束变元：在全称量词或存在量词约束条件下的变量符号
    - 自由变元：不受全称量词或存在量词约束的变量符号
    - 定理：自由变元既可以存在于量词的约束范围之内，也可以存在于量词约束范围之外，即：
        - $(\forall x)(A(x)\vee B)\equiv(\forall x)A(x)\vee B$
        - $(\forall x)(A(x)\wedge B)\equiv(\forall x)A(x)\wedge B$
        - $(\exist x)(A(x)\vee B)\equiv(\exist x)A(x)\vee B$
        - $(\exist x)(A(x)\wedge B)\equiv(\exist x)A(x)\wedge B$
    - 定理：在约束变元相同的条件下，量词的运算满足分配率
    - 定理：当公式中存在多个量词时，若多个量词都是全称量词或者都是存在量词，则量词位置可以互换；若多个量词中既有全称量词又有存在量词，则量词位置不可以随意互换    
- 谓词逻辑：
    - 只包含个体谓词和个体量词的谓词逻辑称为一阶谓词逻辑，无法对谓词和量词进行量化
    - 需要高阶谓词和高阶量词进行量化，包含高阶谓词和高阶量词的谓词逻辑称为高阶谓词逻辑
- 项：项是描述对象的逻辑表达式，递归定义：
    - 常量符号和变量符号是项
    - 若 $f(x_1, x_2,\cdots, x_n)$ 是 $n$ 元函数符号，$t_1, t_2, \cdots, t_n$ 是项，则 $f(t_1, t_2, \cdots, t_n)$ 是项
    - 有限次数地使用上述规则产生的符号串是项
- 原子谓词公式：若 $P(x_1, x_2, \cdots, x_n)$ 是 $n$ 元谓词，$t_1, t_2, \cdots, t_n$ 是项，则称 $P(t_1, t_2, \cdots, t_n)$ 为原子谓词公式，简称原子公式
- 合式公式：由逻辑联结词和原子公式构成的用于陈述事实的复杂语句，又称谓词公式：
    - 命题常项，命题变项，原子谓词公式都是合式公式
    - 通过逻辑联结词联结合式公式得到的也是合式公式
    - 如果 $A$ 是合式公式，$x$ 是个体变项，则 $(\exist x)A(x), (\forall x)A(x)$ 也是合式公式
    - 有限次数地使用上述规则
- 推理规则（$A(x)$ 是谓词公式，$x$ 和 $y$ 是变元，$a$ 是常量符号）
    - 全称量词消去 universal instantiation（UI）：$(\forall x)A(x)\Rightarrow A(y)$
    - 全称量词引入 universal generalization（UG）：$A(y)\Rightarrow(\forall x)A(x)$
    - 存在量词消去 existential instantiation（EI）：$(\exist x)A(x)\Rightarrow A(a)$
    - 存在量词引入 existential generalization（EG）：$A(a)\Rightarrow(\exist x)A(x)$

## 知识图谱推理
- 知识图谱（knowledge graph）由有向图（directed graph）构成，被用来描述现实世界中实体及实体之间的关系
- 两个节点和连接边可表示为形如 <left_node, relation, right_node\> 的三元组形式，也可表示为一阶逻辑（fisrt order logic，FOL）的形式
- 关系推理是统计关系学习研究的基本问题，也是当前知识图谱领域研究的热点问题
- 归纳逻辑程序设计（inductive logic programming，ILP）
    - ILP 是机器学习和逻辑程序设计交叉领域的研究内容
    - ILP 使用一阶谓词逻辑进行知识表示，通过修改和扩充逻辑表达式对现有知识进行归纳，完成推理内容
    - FOIL（first order inductive learner）算法是 ILP 的代表性方法，通过**序贯覆盖**学习推理规则
- 路径排序算法（path ranking algorithm，GRA）
    - 将实体之间的关联路径作为特征，来学习目标关系的分类器
    - 流程：
        1. 特征抽取：生成并选择路径特征集合。生成路径方法：随机游走（random walk）、BFS、DFS
        2. 特征计算：计算每个训练样例的特征值 $P(s\rightarrow t; \pi_j)$，表示从实体节点 $s$ 出发，通过关系路径 $\pi_j$ 达到实体节点 $t$ 的概率。或表示是否存在这样一条路径，或表示路径出现的频次频率
        3. 分类器训练：根据训练样例特征值，为目标关系训练分类器。训练后可用于推理两个实体间是否存在目标关系

### FOIL 算法
- 算法内容
    - 输入：目标谓词 $P$，目标谓词 $P$ 的训练样例（正例集合 $E^+$ 和反例集合 $E^-$），以及其它背景知识样例
    - 输出：可得到目标谓词这一结论的推理规则
    - 过程：
        1. 将目标谓词作为所学习推理规则的结论
        2. 将其它谓词逐一作为**前提约束谓词**加入推理规则，计算所得到推理规则的 FOIL 信息增益值，选取可带来最大信息增益值的前提约束谓词加入原来的推理规则，得到新的推理规则，并将训练样例集合中与该推理规则不符的样例去掉
        3. 重复 b. 过程，知道所得到的推理规则不覆盖任何反例
- 目标谓词是需要推断规则的结论，也称为规则头
- 给定推理结论后，FOIL 算法学习得到使得结论满足的前提条件，即目标谓词作为结论的推理规则
- FOIL 算法从一般到特殊，逐步添加目标谓词的前提约束谓词，直到所构成的推理规则不覆盖任何反例
- 添加前提约束谓词后所得的推理规则的质量的好坏由信息增益值（information gain）作为评估标准，计算方法：
    
    $$
    \mathrm{FOIL\_Gain} = \widehat{m_+}\cdot\left(\log_2\frac{\widehat{m_+}}{\widehat{m_+}+\widehat{m_-}}-\log_2\frac{m_+}{m_++m_-}\right)
    $$

    - $\widehat{m_+}, \widehat{m_-}$ 是增加前提约束谓词后得到的新推理规则能覆盖的正例和反例数目
    - $m_+, m_-$ 是原推理规则覆盖的正例和反例数目

## 因果推理
- 因果推理（causal inference）是指从观察到的数据中推断出因果关系的过程
- 辛普森悖论
    - 某组病人，不用药的恢复率大于用药的恢复率；但单独观察男性和女性，均是用药的恢复率大于不用药的恢复率
    - 辛普森悖论（Simpson's paradox）是指在某些情况下，某个变量的总体效应与其子集的效应相反
    - 即 $\dfrac{b}{a}<\dfrac{d}{c}, \dfrac{b'}{a'}<\dfrac{d'}{c'}, \dfrac{b+b'}{a+a'}>\dfrac{d+d'}{c+c'}$
    - 辛普森悖论表明，在某些情况下，忽略潜在的变量可能会改变已有结论
- 结构因果模型（structural causal model，SCM）
    - 潜在结果分析框架（Rubin-Neyman Causal Model）、
    - 后面大概是一大堆，听不懂看不懂，感觉不重要，开摆（？