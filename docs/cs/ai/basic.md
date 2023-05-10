---
counter: True
comment: True
---

# 人工智能基础

!!! abstract
    浙江大学 “人工智能基础” 课程复习笔记

    参考教材：《人工智能导论：模型与算法》- 吴飞

    一门我觉得很烂的课，反正没学到任何有用的知识，这里记的东西基本都是书上抄下来的，因为考试大部分考各种概念……  
    前两部分是上课边听边记的，会详细一点（？）而且没那么偏向概念，后面基本上就全是挑概念抄了  
    几个实验没有任何含金量和记录的必要，设计的很烂而且几乎学不到东西

    图灵班课程学习指南：[人工智能基础](https://zju-turing.github.io/TuringCourses/major_basic/ai_basic/)

## 逻辑与推理
### 命题逻辑
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

### 谓词逻辑
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

### 知识图谱推理
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

??? note "FOIL 算法"
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

## 搜索求解
### 搜索算法基础
- 评价指标
    - 完备性：能否找到解（不一定最优）
    - 最优性：能否保证找到的第一个解是最优解
    - 时间复杂度（通过扩展的结点数量衡量）
    - 空间复杂度（通过同时记录的结点数量衡量）
- 搜索算法框架
    ```text
    F <- {根节点}
    while F != ∅ do
        n <- pick_from(F)
        F <- F - {n}
        if goal_test(n) then
            return n.path
        end
        F <- F ∪ successor_nodes(n)
    end
    ```
    - pick_from 决定扩展结点的顺序，successor_nodes 决定哪些节点可被放入边缘集合（fringe set，也叫开表，open list）以在后面扩展（expand）
    - 每次从边缘集合中取出最上层（最浅）的结点时是广度优先搜索（breadth first search，BFS）
    - 每次从边缘集合中取出最下层（最深）的结点时是深度优先搜索（depth first search，DFS）
    - 放弃扩展部分结点的做法称为剪枝（pruning）

### 启发式搜索
- 利用一些能够辅助算法做出决策的额外信息的搜索算法称为启发式搜索（heuristic search），或有信息搜索（informed search）
- 提供的这些辅助信息称为启发信息
- 启发信息通常形式化为一个关于结点的函数 $h(n)$，其用于估计结点 $n$ 距离达到目标还需付出多少代价，这个函数称为启发函数（heuristic function）
    - 启发函数通常是非负的
    - 常见用法是用来更改前面的 pick_from 函数来规定挑选结点的顺序
- 对于任意结点 $n$，决定了搜索算法扩展结点 $n$ 的优先度的函数 $f(n)$ 称为评价函数（evaluation function）
    - 评价函数值越小，被挑选的优先级越高
    - 深度优先搜索中 $f(n)$ 可被定义为该结点深度的倒数
    - 广度优先搜索中 $f(n)$ 可被定义为该结点深度
- 贪婪最佳优先搜索
    - 即 greedy best-first search，GBFS
    - 优先扩展距离目标近的结点，即令 $f(n) = h(n)$
    - 不排除环路的贪婪最佳优先搜索算法是不完备的
    - 排除环路的贪婪最佳优先搜索是完备的，但不一定最优
    - 最坏情况下的时间复杂度和空间复杂度均为 $O(b^m)$
        - $b$ 为分支因子（每个结点最大的分支数目）
        - $m$ 为最大深度，也就是搜索树中路径的最大可能长度

- 智能体不唯一，解决信息确定、全局可观察、轮流行动、输赢收益零和的博弈问题，求解这样问题的算法称为对抗搜索（adversarial search）或博弈搜索（game search）
- 智能体会选择最大化自身利益、最小化对手利益的策略
- 形式化描述：
    - 状态：状态 $s$ 包括当前游戏局面和当前行动的智能体，初始状态 $s_0$ 为游戏开始时的状态。$\mathrm{player}(s)$ 表示状态 $s$ 下行动的智能体
    - 动作：动作是指 $\mathrm{player}(s)$ 在当前局面下可以采取的操作 $a$，记动作集合为 $\mathrm{actions}(s)$
    - 状态转移：状态转移函数 $s' = \mathrm{result}(s, a)$ 表示在状态 $s$ 下采取动作 $a$ 后的下一个状态
    - 终局状态测试：终局状态测试函数 $\mathrm{terminal\_test}(s)$ 用于测试游戏是否在状态 $s$ 下结束
    - 终局得分：终局得分函数 $\mathrm{utility}(s, p)$ 表示在状态 $s$ 下玩家 $p$ 的得分
        - 对于二人零和博弈，只需要记录其中一人的终局得分即可

#### 最大最小搜索
- 最大最小搜索（minimax search）是求解对抗搜索问题的基本算法
- 该算法假设两名玩家在决策时总是理性地倾向于最大化自己的得分（最小化对方得分）
- 算法过程
    - 假设以最大化得分为目标的玩家为 MAX，以最小化得分为目标的玩家为 MIN
    - 某一层由 MAX 玩家行动，则其会选择得分最大的子树进行行动
    - 某一层由 MIN 玩家行动，则其会选择得分最小的子树进行行动
    - 递归地进行上述过程，直到达到终局状态
    - （子树的得分由所有它的子树的得分取最大或最小得到）

$$
\mathrm{minimax}(s) = \begin{cases}
\mathrm{utility}(s) & \text{if terminal\_test(}s\text{)} \\
\max_{a \in \mathrm{actions}(s)} \mathrm{minimax}(\mathrm{result}(s, a)) & \text{if player(}s\text{) = MAX} \\
\min_{a \in \mathrm{actions}(s)} \mathrm{minimax}(\mathrm{result}(s, a)) & \text{if player(}s\text{) = MIN}
\end{cases}
$$

- 最大最小搜索的时间复杂度为 $O(b^m)$，空间复杂度为 $O(bm)$

#### Alpha-Beta 剪枝
- 如果搜索树极大，则最大最小搜索的开销巨大，无法在合理时间内返回结果
- Alpha-Beta 剪枝算法的思想如下：

    $$
    \begin{align*}
    \mathrm{minimax}(s_0) &= \max(\min(3, 9, 10), \min(2, x, y), \min(10, 5, 1))\\
    &= \max(3, \min(2, x, y), 1)
    \end{align*}
    $$

    - 上式中 $\min(2, x, y)$ 肯定小于 2，而外面一层求最大值又有 3 比它大
    - 所以就没有必要去搜索 $x, y$ 对应的子树得到具体的 $x, y$ 值，可以将这两个动作剪枝掉

### 蒙特卡洛树搜索
- 四个步骤
    - 选择（selection）：算法从搜索树的根节点开始，向下递归选择子节点直到到达叶子结点或者到达还具有未被扩展的子节点的节点 L，向下递归选择的过程可由 UCB1 算法来实现，在递归选择过程中记录下每个节点被选择的次数和每个节点得到的奖励均值
    - 扩展（expansion）：如果节点 L 还不是一个终止节点，则随机扩展它的一个未被扩展过的后继边缘节点 M
    - 模拟（simulation）：从节点 M 出发，模拟扩展搜索树，直到找到一个终止节点
    - 反向传播（back propagation）：用模拟所得结果回溯更新模拟路径中 M 及以上节点的奖励均值和被访问次数

??? note "代码"
    ```python
    class AIPlayer:
        def __init__(self, color, C=1.2, iterations=100):
            self.player = color
            self.C = C
            self.iterations = iterations
        
        def game_over(self, board):
            # 根据当前棋盘，判断棋局是否终止
            # 如果当前选手没有合法下棋的位子，则切换选手；如果另外一个选手也没有合法的下棋位置，则比赛停止。
            b_list = list(board.get_legal_actions('X'))
            w_list = list(board.get_legal_actions('O'))
            is_over = len(b_list) == 0 and len(w_list) == 0  # 返回值 True/False
            return is_over

        def uct_search(self, root, iterations):
            for i in range(iterations):
                node = self.select(root)
                reward = self.simulate(node)
                self.backpropagate(node, reward)
            return self.ucb(root, 0).action

        def select(self, node):
            while not self.game_over(node.board):
                if len(node.children) == 0 or not node.finished():
                    return self.expand(node)
                else:
                    node = self.ucb(node, self.C)
            return node
        
        def expand(self, node):
            actions = list(node.board.get_legal_actions(node.player))
            if len(actions) == 0:
                return node.parent
            visited = [child.action for child in node.children]
            actions = [action for action in actions if action not in visited]
            action = random.choice(actions)
            new_board = deepcopy(node.board)
            new_board._move(action, node.player)
            node.expend(new_board, action, 'X' if node.player == 'O' else 'O')
            return node.children[-1]
        
        def ucb(self, node, C):
            max_ucb = -float('inf')
            max_children = []
            for child in node.children:
                ucb = child.reward / child.cnt + C * math.sqrt(2 * math.log(node.cnt) / child.cnt)
                if ucb > max_ucb:
                    max_ucb = ucb
                    max_children = [child]
                elif ucb == max_ucb:
                    max_children.append(child)
            if len(max_children) == 0:
                return node.parent
            return random.choice(max_children)
        
        def simulate(self, node):
            board = deepcopy(node.board)
            player = node.player
            while not self.game_over(board):
                actions = list(board.get_legal_actions(player))
                if not len(actions) == 0:
                    action = random.choice(actions)
                    board._move(action, player)
                player = 'X' if player == 'O' else 'O'
            return self.evaluate(board)
        
        def evaluate(self, board: Board):
            winner, diff = board.get_winner()
            if winner == 2:
                return 0
            winner = 'X' if winner == 0 else 'O'
            if winner == self.player:
                return 10 + diff
            else:
                return -10 - diff

        def backpropagate(self, node: TreeNode, reward):
            while node:
                node.cnt += 1
                if node.player == self.player:
                    node.reward -= reward
                else:
                    node.reward += reward
                node = node.parent

        def get_move(self, board):
            if self.player == 'X':
                player_name = '黑棋'
            else:
                player_name = '白棋'
            print("请等一会，对方 {}-{} 正在思考中...".format(player_name, self.player))
            root = TreeNode(deepcopy(board), None, None, self.player)
            action = self.uct_search(root, self.iterations)
            return action
    ```

## 机器学习：监督学习
### 机器学习基本概念
- 机器学习的目标是从原始数据中提取特征，学习一个映射函数 f 将上述特征（或原始数据）映射到语义空间，寻找数据和任务目标之间的关系
- 机器学习种类
    - 监督学习
        - 给定带有标签信息的训练集合，学习从输入到输出的映射
        - 一般被应用在回归或分类的任务中
    - 无监督学习
        - 最大特点是**数据无标签**
        - 一般被应用在聚类或若干降维任务中
        - 半监督学习依赖于部分被标注的数据
    - 强化学习
        - 一种序列数据决策学习方法
        - 从与环境交互中学习，通过回报值（reward）让智能体（agent）学习到在不同状态（state）下如何选择行为方式（action）
- 监督学习
    - 在训练过程中希望映射函数在训练数据集上得到所有样本的“损失和”最小
    - 损失函数包括 0-1 损失函数（相等为 0，反之为 1），平方损失函数，绝对损失函数，对数损失函数（对数似然函数）
    - 监督学习一般包含三个部分内容：
        - 从训练数据集中学习得到映射函数 f
        - 在测试数据集上测试映射函数 f
        - 在未知数据集上测试映射函数 f（投入使用）
    - 训练及中产生的损失一般称为经验风险（empirical risk），越小对训练集拟合效果越好
    - 测试集中加入从真实数据分布采样的样本时，测试集上的损失会不断逼近期望风险（expected risk），越小模型越好
    - 机器学习的目标是追求期望风险最小化
    - 结构风险最小化（structural risk minimization）：防止过学习，基于过学习时参数值通常都较大这一发现，在经验风险上加上表示模型复杂度的正则化项（regularizer）或惩罚项（penalty term），在最小化经验风险与降低模型复杂度之间寻找平衡
    - 主要的监督学习方法：
        - 判别方法（discriminative approach）
            - 直接学习判别函数 f(X) 或者条件概率分布 P(Y|X) 作为预测的模型
            - 典型判别模型包括回归模型、神经网络、支持向量机和 Ada boosting
        - 生成方法（generative approach）
            - 从数据中学习联合概率分布 P(X, Y)（通过似然概率 P(X|Y) 和类概率 P(Y) 乘积来求）
            - 生成模型典型方法为贝叶斯方法、隐马尔可夫链
            - 难点在于联合分布概率或似然概率很难求

### 回归分析
- 一元线性回归
- 多元线性回归
    - 有 $m$ 个训练数据 $\{(\mathbf{x}_i, y_i)\}_{i=1}^m$，要找到参数 $\mathbf{a}$，使线性函数 $f(\mathbf{x}_i)=a_0+\mathbf{a}^\top\mathbf{x}_i$ 最小化均方误差函数 

    $$
    J_m=\dfrac{1}{m}\sum_{i=1}^m\left(y_i-f(\mathbf{x}_i)\right)^2=(\mathbf{y}-\mathbf{X}^\top\mathbf{a})^\top(\mathbf{y}-\mathbf{X}^\top\mathbf{a})
    $$

    - 对均方误差函数求导得 $\nabla J(\mathbf{a}) = -2\mathbf{X}(\mathbf{y}-\mathbf{X}^\top\mathbf{a})$，令其为 0 解得 $\mathbf{a}=(\mathbf{X}\mathbf{X}^\top)^{-1}\mathbf{X}\mathbf{y}$
- 逻辑斯蒂回归/对数几率回归
    - 线性回归对离群点非常敏感，导致模型不稳定，为了缓解这个问题可以考虑逻辑斯蒂回归（logistic regression）
    - 在回归模型中引入 sigmoid 函数，逻辑斯蒂回归模型

    $$
    y=\dfrac{1}{1+e^{-z}}=\dfrac{1}{1+e^{\mathbf{w}^\top\mathbf{x}+b}}
    $$

    - 逻辑斯蒂回归函数的输出具有概率意义，一般用于二分类问题
    - 逻辑斯蒂回归是一个线性模型，在预测时可以计算线性函数 $\mathbf{w}^\top\mathbf{x}+b$ 取值是否大于 0 来判断输入数据的类别归属
    - 求解参数的典型做法是最大化对数似然（log likelihood）函数
    - 最大似然估计目的是计算似然函数的最大值，而分类过程是需要损失函数最小化，常用梯度下降法（gradient descent）：批量梯度下降、随机梯度下降、小批量梯度下降
    - 只能用于解决二分类问题
    - 多分类可以将其推广为多项逻辑斯蒂回归模型，即 softmax 函数

### 决策树
- 通过树形结构来进行分类的方法
- 每个非叶子结点表示对分类目标在某个属性上的一个判断，每个分支代表基于该属性做出的一个判断，每个叶子结点代表一种分类结果
- 决策树将分类问题分解为若干基于单个信息的推理任务，采用树状结构来逐步完成决策判断
- 建立决策树的过程，就是不断选择属性值对样本集进行划分、直至每个子样本为同一个类别
    - 对于较大数据集，需要理论和方法来评价不同属性值划分的子样本集的好坏程度
- 构建决策树
    - 性能好的决策树随着划分不断进行，决策树分支结点样本集的纯度会越来越高，即所包含样本尽可能属于相同类别
    - 信息熵（entropy）可以用来衡量样本集和纯度，越大说明不确定性越大纯度越低
        - 划分样本集前后信息熵的减少量称为信息增益（information gain）用来衡量样本复杂度减少的程度
    - 如果划分后的不同子样本集都只存在同类样本，那么停止划分
    - 一般而言，信息增益偏向选择分支多的数学，一些场合容易导致模型过拟合
        - 一个直接的想法是对分支过多进行惩罚，即另一个纯度衡量指标

### 线性判别分析
- 线性判别分析（linear discriminant analysis，LDA）是一种基于监督学习的降维方法，也称为 Fisher 线性判别分析（FDA）
- 对于一组具有标签信息的高位数据样本，LDA 利用其类别信息将其线性投影到一个低维空间熵，在低维空间中同一类别样本尽可能靠近，不同类样本尽可能彼此远离
    - 类内方差小，类间间隔大
- LDA 与主成分分析（PCA）紧密相关，都在寻找最佳解释数据的变量线性组合
- 对线性判别分析的降维步骤描述
    - 计算数据样本集中每个类别样本的均值
    - 计算类内散度矩阵 $\mathbf{S}_w=\mathbf{\Sigma}_1+\mathbf{\Sigma}_2$（$\mathbf{\Sigma}$ 协方差矩阵）和类间散度矩阵 $\mathbf{S}_b=(\mathbf{m}_2-\mathbf{m}_1)(\mathbf{m}_2-\mathbf{m}_1)^\top$
    - 根据 $\mathbf{S}_w^{-1}\mathbf{S}_b\mathbf{W}=\lambda\mathbf{W}$ 来求解 $\mathbf{S}_w^{-1}\mathbf{S}_b$ 所对应的前 $r$ 个最大特征值所对应的特征向量 $(\mathbf{w}_1, \mathbf{w}_2, \cdots, \mathbf{w}_r)$ 构成矩阵 $\mathbf{W}$
    - 通过矩阵 $\mathbf{W}$ 将每个样本映射到低维空间，实现特征降维
- PCA 是一种无监督学习的降维方法，LDA 是监督学习
    - PCA 和 LDA 均是优化寻找特征向量 $\mathbf{w}$ 来实现降维
    - PCA 寻找投影后数据间方差最大的投影方向，LDA 寻找类内方差小、类间间隔大的投影方向
    - PCA 可以将 d 为数据降至小于 d 的任意维度
    - LDA 将为后得到维度与数据样本类别个数 K 有关，d 维数据有 K 个类别，则降维维度小于或等于 min(K-1, d)

### Ada Boosting
- Ada Boosting（自适应提升）通过集成（ensemble）手段来达到提升（boosting）算法性能目的
- 对于一个复杂分类任务，将其分解为若干个子任务，然后将若干个子任务综合构建到一起，最终完成复杂分类任务
    - 每个子任务只能完成成体任务的部分，是一个弱分类器（weak classifier）
    - 将若干个弱分类器组合起来形成强分类器（strong classifier），可以完成复杂分类任务
- 可计算学习理论
    - 可计算理论关心什么样的问题可以被计算
        - 一个任务如果是图灵可停机的，那么该任务可计算
    - 可学习理论关心什么样的任务可以被习得，从而能被算法模型完成
    - 概率近似正确（PAC）研究问题包括
        - 如何知道学习所得的假设（hypothesis）是正确的
        - 为了接近真实假设所需要的训练数据是多少
        - 假设空间的复杂度如何度量以及如何选择假设空间
    - 概率近似正确可学习（PAC-learnable）：能够完成任务的概率大于 0.5 即大于随机分类器，称为弱分类器
        - 强可学习模型：学习模型能够以较高精度对绝大多数样本完成识别分类任务
        - 弱可学习模型：学习模型仅能完成若干部分样本识别与分类，精度略高于随机猜测
        - 强可学习和弱可学习是等价的（可以利用 ada boosting 算法）
- Ada Boosting 算法
    - 解决两个核心问题
        - 在每个弱分类器学习过程中，如何提高在上一轮中被错误分类的样本权重，即关注目前尚未被正确分类的样本
        - 如何将一系列弱分类器组合成强分类器，给分类误差小的弱分类器赋予更大权重，同时减少分类误差大的弱分类器的权重
    - 通过集成学习方法将若干个弱分类器组合成强分类器
    - Ada Boosting 算法的基本思想（from copilot）
        - 通过迭代的方式，每一轮迭代都会产生一个弱分类器，每个弱分类器都会对样本进行分类
        - 在每一轮迭代中，根据上一轮迭代的分类结果，对样本进行加权，使得被错误分类的样本权重增大，被正确分类的样本权重减小
        - 在每一轮迭代中，根据上一轮迭代的分类结果，计算弱分类器的权重
        - 将所有弱分类器的分类结果进行加权求和，得到最终的强分类器
    - Ada Boosting 采取了序列化学习机制，即一个分类器学习完成后才会进行下一个分类器的学习，后一个分类器的学习受到前面的影响
    - Ada Boosting 实际是在最小化指数损失函数
    - 在第 m 次迭代中，Ada Boosting 总是趋向于将具有最小误差的学习模型选做本轮次生成的弱分类器 Gm，促使累积误差快速下降
    - Ada Boosting 可归属为集成学习这一分类方法
        - 另一种常用的集成学习方法是袋装法（bagging）
            - 不改变样本数据的权重，通过并行和随机采样的思想来将多个弱学习模型集成为强学习模型

## 统计机器学习：无监督学习
### K 均值聚类
- K-means 算法要求特征变量连续，数据没有异常值
- K-means 的目标是将 n 个 d 维的数据划分为 K 个聚簇，使得簇内的方差最小化，是局部最优不一定全局最优
- K-means 是一个易受初始值影响的迭代算法，常用初始化方法包括 forgy 和 random partition
- 算法步骤
    - 初始化聚类质心
    - 对数据进行聚类：将每个数据放入与之距离最近的聚类质心所在聚类集合中
    - 更新聚类质心：根据聚类结果更新聚类质心
    - 迭代：上述操作进行迭代，直到到达迭代次数上限/两次迭代中聚类质心保持不变
- 通常 K-means 收敛速度很快，对于聚簇数量 $K$ 和维度 $d$，能在 $O(n^{dK+1})$ 复杂度内收敛
- K-means 假设数据没有离群点，对离群点的处理和其它数据一样
    - 可以使用其他目标函数或 K-medoids 算法来减小离群点的影响（K-medoids 选择聚簇中的一个点而不是均值作为聚类中心）
- K-means 需要事先确定聚类数目 K，一般在一个范围内遍历，选择最优的一个
- K-means 聚类算法对数据的尺度敏感
- K-means 属于硬聚类（hard clustering），即每个数据只能属于一个聚簇
    - 层次聚类（hierarchical clustering）不需要事先决定聚类数目 K
    - 基于降维的聚类算法谱聚类（spectral clustering）对数据所在坐标空间不敏感
- K-means 可以用于图像压缩，即将所有色彩替换为聚类后的 K 种色彩

### 主成分分析
- PCA 是一种特征降维的方法，也称 KL 变换、霍林特变换、本征正交分解
- 主成分分析通过分析找到数据特征的主要成分，使用这些主要成分来代替原始数据
- PCA 要求降维后的结果要保持原始数据的原有结构，要求最大程度保持原始高维数据的总体方差结构
- 降维需要尽可能将数据向方差最大的方向进行投影，使得数据所蕴含的信息丢失得尽可能少
- PCA 思想是将 d 维特征数据映射到 l 维空间（d>>l），去除原始数据之间的冗余性（去除相关性），将原始数据向这些数据方差最大的方向进行投影，然后继续寻找保持方差第二的方向进行投影，使数据每一维的方差都尽可能大
- 算法步骤
    - 对于每个样本数据 $x_i$ 进行中心化处理：$x_i:=x_i-\mu, \mu=\dfrac{1}{n}\sum_{j=1}^nx_j$
    - 计算原始样本数据的协方差矩阵：$\mathbf{\Sigma} = \dfrac{1}{n-1}\mathbf{X}^\top\mathbf{X}$
    - 对协方差矩阵 $\mathbf{\Sigma}$ 进行特征值分解，对所得特征根进行排序 $\lambda_1\geq\lambda_2\geq\cdots\geq\lambda_l$
    - 取前 $l$ 个特征根所对应特征向量 $\mathbf{w}_1, \mathbf{w}_2, \cdots, \mathbf{w}_l$ 组成映射矩阵
- 其他常用降维方法
    - 非负矩阵分解（NMF），将非负的大矩阵分解为两个非负的小矩阵，
    - 多维尺度法（MDS）保持原始数据之间两两距离不变，但无法对新数据集合进行降维（out-of-sample）
    - 局部线性嵌入（LLE）是一种非线性降维方法，一个流形的局部可以近似于一个非欧氏空间，每个样本均可以利用其邻居进行线性重构

### 特征人脸方法
- 特征人脸方法是基于外观的人脸识别方法，目的是捕捉人脸图像集合中特征信息，使用该信息对各个人脸图像进行编码和比较
- 使用 PCA 手段来表示特征人脸，本质是使用一组特征向量线性组合来表示原始人脸，进而实现人脸识别
- 在特征维度较高的情况下，主成分分析算法暴力求解特征向量是一个耗时操作，可以使用奇异值分解（SVD）来实现主成分分析

### 潜在语义分析
- 潜在语义分析，又称为隐形语义分析（LSA/LSI）是一种从海量文本数据中学习单词-单词、单词-文档以及文档-文档之间的隐形关系，从而得到文档和单词表达特征的方法
- 该方法的基本思想是综合考虑某些单词在哪些文档中同时出现以此来决定该词语的含义与其他的词语的相似度
- LSI 被广泛运用在了语义理解任务中，如自动文档分类、文本摘要和关系发现
- 潜在语义分析思想
    - 先构建一个单词-文档矩阵 A
    - 进而寻找该矩阵的低秩逼近，来挖掘单词-单词、单词-文档以及文档-文档之间的关联关系

### 期望最大化算法
- 假设由 n 个数据样本构成的集合 $\mathcal{D}=\{x_1, x_2, \cdots, x_n\}$ 以参数为 $\Theta$ 的某个模型以一定概率独立采样得到，于是可以通过最大似然估计法（MLE）来求取参数 $\Theta$，使得在参数为 $\Theta$ 的模型下，样本集 $\mathcal{D}$ 出现的概率最大
    - 也可以使用最大后验估计（MAP）来估计参数 $\Theta$
    - 都是充分利用已有数据，在参数模型确定（只是参数值未知）的情况下，对所优化目标中的参数求导，令导数为 0，求取模型的参数值
- 一些情况下难以事先确定模型，无法用 MLE 或 MAP
- 期望最大化（expectation maximization，EM）算法是一种用于解决含有隐变量问题的参数估计方法
    - 求取期望（E 步骤）：先假设模型参数的初始值，估计隐变量取值
    - 期望最大化（M 步骤）：基于观测数据、模型参数和隐变量取值一起来最大化拟合数据，更新参数模型，直到算法收敛
- EM 算法不能保证找到全局的最大值，有可能找到一个鞍点
- EM 算法步骤
    - 初始化参数取值 $\Theta^0$
    - 求取期望步骤：计算 $Q(\Theta|\Theta^t)=\sum_{i=1}^n\sum_{z_i}P(z_i|x_i,\Theta)\log P(x_i, z_i|\Theta)$
        - 含义是对数似然函数 $\log P(x_i, z_i|\Theta)$ 在已观测数据 $X$ 和当前参数 $\Theta^t$ 下去估计隐变量 $Z$ 的条件概率分布
    - 期望最大化步骤：$\Theta^{t+1}=\argmax_\Theta Q(\Theta|\Theta^t)$
    - 重复二三步，直到收敛

## 深度学习
### 前馈神经网络
- 前馈神经网络（feedforward neural network，FNN）是一种最简单的神经网络，由输入层、隐藏层和输出层组成
    - 每层神经元只和相邻层神经元相连，即每层神经元只接受相邻前序神经层中神经元传来的信息，只给相邻后续神经层中神经元传递信息
    - 同一层的神经元之间没有任何连接，后续神经层也不向前序相邻神经层传递信息
    - 是目前最为广泛的神经网络之一
- 神经元
    - 给定 $n$ 个二值化输入数据 $x_i$ 与连接参数 $w_i$，MCP 神经元对输入数据线性加权求和然后将结果根据阈值 $\theta$ 进行二值化，得到输出 $y=\Phi\left(\sum_{i=1}^nw_ix_i\right)$
    - 二值可能是 0 和 1 也可能是 -1 和 1
- 激活函数
    - 神经网络使用非线性函数作为激活函数，通过对多个非线性函数进行组合，来实现对输入信息的非线性变换
    - 激活函数必须是连续可导的
    - 常用激活函数
        - sigmoid，$f(x)=\dfrac{1}{1+e^{-x}}$，导数 $f'(x)=f(x)(1-f(x))$
        - tanh，$f(x)=\dfrac{1-e^{-2x}}{1+e^{-2x}}$，导数 $f'(x)=1-f^2(x)$
        - ReLU，$f(x)=\max(0, x)$，导数 0/1
            - 有效克服梯度消失问题
        - softmax，一般用在多分类问题中，$f(x_i)=\dfrac{e^{x_i}}{\sum_{j=1}^ke^{x_j}}$
            - 可将输出概率最大的作为分类目标
- 损失函数（loss function）/代价函数（cost function）
    - 用来计算模型预测值与真实值之间的误差
    - 均方误差损失函数 $\mathrm{MSE}=\dfrac{1}{n}\sum_{i=1}^n(y_i-\hat{y}_i)^2$
    - 交叉熵损失函数，度量两个概率分布之间的差异 $H(p, q)=-\sum_xp(x)\log q(x)$
        - 旨在描绘通过概率分布 $q$ 来表达概率分布 $p$ 的困难程度
        - 交叉熵越小，两个概率分布越接近
- 感知机模型
    - 单层感知机
        - 由一个输入层和一个输出层构成，输出层输出 -1 或 1
        - 可作为一种二类线性分类模型
        - 单层感知机构建损失函数来计算模型预测值与数据真实值之间的误差，通过修改权重最小化损失函数值，来优化模型参数
        - 单层感知机可被用来区分线性可分数据
    - 多层感知机
        - 由输入层、输出层和至少一层的隐藏层构成
        - 相邻层之间全连接
- 参数优化
    - 神经网络参数优化是一种监督学习的过程
    - 模型会利用反向传播算法将损失函数计算所得误差从输出端出发，由后向前传递给神经网络中的每个单元，然后通过梯度下降算法对神经网络中的参数进行更新
    - 梯度下降（gradient descent）
        - 批量梯度下降：在整个训练集上计算损失误差
        - 随机梯度下降：在每个训练样本上计算损失误差，收敛快，但可能出现目标函数震荡不稳定现象
        - 小批量梯度下降：选取训练集上小批量样本计算损失误差，最常用
    - 反向传播（back propagation，BP）

### 卷积神经网络
- 卷积（convolution）是针对像素点的空间依赖性来对图像进行处理的一种技术
- 卷积滤波的结果在卷积神经网络中被称为特征图（feature map）
- 在卷积操作时，经常会采用 padding（填充）和 striding（步长）两种方法
- 池化（pooling）
    - 可用某一区域子块的统计信息来刻画该区域中所有像素点呈现的空间分布模式，来替代区域子块中所有像素点取值
    - 池化操作对卷积结果特征图进行约减，实现了下采样，同时保留了特征图中主要信息
    - 最大池化、平均池化、k 最大池化（取前 k 个最大值，常用于自然语言处理）
- 神经网络正则化
    - 深度神经网络结构复杂参数众多，容易造成过拟合，需要采取一些正则化技术来提升神经网络泛化能力（generalization）
    - dropout：随机丢掉一部分神经元来减少神经网络复杂度
    - 批归一化：通过规范化手段，把神经网络每层中任意神经元的输入值分布改为标准正态分布，把偏移较大的分布强制映射为标准正态分布
    - L1 和 L2 正则化

### 循环神经网络
- 循环神经网络（recurrent neural network，RNN）是一类处理序列数据时采用的网格结构
- 循环神经网络本质是模拟人所具有的记忆能力，在学习过程中记住部分已经出现的信息，并利用所记住的信息影响后续节点输出
- RNN 在自然语言处理如语音识别、情感分析、机器翻译等领域有重要应用
- 循环神经网络模型
    - 循环神经网络在处理数据过程中构成了一个循环体
    - 对于一个序列数据，在每一时刻 $t$，循环神经网络单元会读取当前输入数据 $x_t$ 和前一时刻输入数据 $x_{t-1}$ 所对应的隐式编码结果 $h_{t-1}$，一起生成 $t$ 时刻的隐式编码结果 $h_t$
    - 激活函数一般可为 sigmoid 或 tanh，使模型能够忘掉无关信息同时更新记忆内容
    - 训练方式为沿时间反向传播算法（BPTT）
    - 当序列过长时，循环神经网络也容易出现梯度消失或梯度爆炸的问题
- 长短时记忆网络（LSTM）：引入了内部记忆单元和门结构来对当前输入信息以及前序时刻所生成的信息进行整合和传递
- 门控循环单元（gated recurrent unit，GRU）：一种对 LSTM 简化的深度学习模型
    - 不使用记忆单元来传递信息，而是使用隐藏状态来传递，有更高的计算速度
    - 只包含更新门和重置门

### 深度学习应用
- 词向量模型
    - 词袋模型（bag of words），将文本看作是一组词的集合，忽略词与词之间的顺序关系
    - 分布式向量表达（distributed vector representation）
        - 利用深度学习模型，将每个单词表征为 N 维实值的分布式向量
        - 词向量（Word2Vec）是较为经典的模型
            - 训练模式有 continuous bag-of-words（CBOW）和 skip-gram
- 图像分类和目标定位
    - 输入一幅图像，首先利用卷积神经网络来提取视觉特征，得到一个特征向量来表示输入图像
    - 这个向量作为输入特征分别传送给两个任务，即分类任务和定位任务
    - 分类任务中，使用 softmax
    - 定位任务中，将向量转化为一个四维向量，表示定位边界

## 强化学习
### 强化学习问题定义
- 智能体（agent），根据经验做出判断并执行动作；环境（environment），智能体意外的一切
- 状态（state），智能体对环境的一种理解和编码；动作（action）；策略（policy），当前状态执行某个动作的依据；奖励（reaward）
- 与监督学习和无监督学习相比，强化学习基于评估，数据来源于时序交互，决策过程是序贯决策，目标是选择能够获取最大收益的状态到动作的映射
- 马尔可夫决策过程
    - 马尔可夫性（Markov property）：下一刻的状态 $X_{t+1}$ 只由当前状态 $X_t$ 决定，与更早的所有状态均无关
    - 满足马尔可夫性的离散随机过程被称为马尔可夫链（Markov chain）
    - 定义离散马尔可夫过程 $\{S_t\}_{t=0, 1, \cdots}$，可以定义状态转移概率 $P(S_{t+1}|S_t,A_t)$，其中 $A_t$ 为在状态 $S_t$ 下执行的动作
    - 定义奖励函数 $R_{t+1}=R(S_t, A_t, S_{t+1})$ 描述从第 $t$ 步状态转移采取动作 $A_t$ 到第 $t+1$ 步状态的奖励
    - 在每个时刻定义回报（return）来反映该时刻可得到的累加奖励 $G_t=R_{t+1}+\gamma R_{t+2}+\gamma^2R_{t+3}+\cdots$，其中 $\gamma$ 称为折扣因子
    - 一般情况下，初始状态和终止状态并不包括在马尔可夫决策过程定义中
        - 可以添加虚拟的初始状态和终止状态，虚拟初始状态以一定概率转移到真正初始状态，真正终止状态以概率 1 转移到虚拟终止状态
    - 智能体逐步采取行动，可得到一个状态序列 $(S_0, S_1, \cdots)$ 称为轨迹（trajectory），轨迹长度可以是无限的，也可以有终止状态 $S_T$
        - 包含终止状态的问题叫分段（episodic）问题，此时从初始状态到终止状态的完整轨迹称为一个片段（episode）
        - 不包含终止状态的问题叫持续（continuing）问题
- 强化学习问题定义
    - 智能体选择动作的模型即策略函数，$\pi(s, a)$ 表示在状态 $s$ 下采取动作 $a$ 的概率
        - 一个好的策略函数应该能够使智能体在采取了一系列行动之后可得到最佳奖励
    - 价值函数（value function），$V_\pi(s)=\mathbb{E}_\pi[G_t|S_t=s]$ 表示智能体在时刻 $t$ 时处于状态 $s$ 时，按照策略 $\pi$ 采取行动时所得到的回报的期望
    - 动作-价值函数，$q_\pi(s, a)=\mathbb{E}_\pi[G_t|S_t=s, A_t=a]$
    - 强化学习可以转化为一个策略学习问题，给定一个马尔可夫决策过程 $MDP=(S, A, P, R, \gamma)$，学习一个最优策略 $\pi^*$，对任意 $s\in S$ 使得 $V_{\pi^*}(s)$ 值最大
- 贝尔曼方程（Bellman equation）/动态规划方程（dynamic programming equation）
    - $V_\pi(s)=\sum_{a\in A}\pi(s, a)q_\pi(s, a)$，可用动作-价值函数来表达价值函数
        - 状态 $s$ 的价值可用该状态下可采取所有动作而取得的期望价值来表述
    - $q_pi(s, a) = \sum_{s'\in S}P(s'|s, a)[R(s, a, s')+\gamma V_\pi(s')]$，可用价值函数来表示动作-价值函数
        - 在某个状态下执行某一个动作所得的价值可以通过执行该动作之后进入的所有状态获得的瞬时奖励和后续状态可取得价值的期望来表示
    - 价值函数贝尔曼方程：$V_\pi(s)=\mathbb{E}_{a\sim \pi(s, \cdot)}\mathbb{E}_{s'\sim P(\cdot | s, a)}[R(s, a, s'), \gamma V_pi(s')]$
        - 价值函数取值和时间没有关系，只与策略 $\pi$、在策略 $\pi$ 下从某个状态转移到后续状态所取得的回报以及在后续所得回报有关
        - $V_\pi$ 由两个部分构成：执行当前动作所得到的瞬时奖励，在后续状态所能得到的回报的期望的折扣值
    - 贝尔曼方程描述了价值函数或动作-价值函数的递推关系，是研究强化学习问题的重要手段
    - 求解最优策略的一种方法是求解最优的价值函数或最优的动作-价值函数，即基于价值方法（value-based approach）

### 基于价值的强化学习
- 一种求解最优策略的思路：从一个任意的策略开始，首先计算该策略下价值函数，然后根据价值函数调整改进策略使其更优，不断迭代直到策略收敛
    - 通过策略计算价值函数的过程称为策略评估（policy evaluation）
    - 通过价值优化策略的过程叫做策略优化（policy improvement）
    - 策略评估和策略优化交替进行的强化学习求解方法叫做通用策略迭代（GPI）
    - 几乎所有强化学习方法都可以使用 GPI 来解释
- 策略优化定理
    - 假设当前策略为 $\pi$，对应的价值函数和动作-价值函数为 $V_\pi, q_\pi$，则可以构造策略 $\pi'(s)=\argmax_aq_\pi(s, a)$，此时 $\pi'$ 不比 $\pi$ 差
    - 给定策略、价值函数和动作-价值函数，就可以通过该式计算得到更好或同等的策略

## 人工智能博弈
### 博弈论基础概念
- 参与博弈的决策主体被称为玩家或参与者（player），通常被认为是完全理性的
- 在博弈中参与者能获得的与博弈相关的知识称为信息（information）
- 博弈需要遵循一定的规则（rule）
- 参与者可以采取的行动方案称为策略（strategy）
    - 策略必须是一整套在采取行动之前就已经准备好的完整方案
    - 一个参与者能采纳策略的全体组合形成其所拥有的策略集（strategy set）
    - 参与者也可以按照一定概率随机选择若干不同行动，称为混合策略（mixed strategy），反之称为纯策略（pure strategy）
- 参与者采取各自行动后形成的状态称为局势（outcome），不同局势下各个参与者所得到的利益或回报称为博弈的收益（payoff）
    - 混合策略下收益为期望收益（expected payoff）
- 博弈分类
    - 是否允许参与者之间合作：合作博弈（cooperative game）、非合作博弈（non-……）
    - 决策时间：静态博弈（static game）、动态博弈（dynamic game）
        - 静态博弈中所有参与者同时决策，动态博弈中由规则决定先后且后者知道前者的行动
    - 对信息的了解程度：完全信息博弈（complete information game）、不完全信息博弈（in-……）
        - 完全信息博弈中所有参与者都知道所有信息，不完全信息博弈中参与者只知道部分信息
        - 完美信息博弈（perfect information game）：参与者知道所有参与者之前采取的行动
    - 总收益：零和博弈（zero-sum game）、非零和博弈（non-……）
- 纳什均衡（Nash equilibrium）：博弈的稳定局势
    - 纳什定理：若参与者有限，每位参与者采取策略的集合有限，收益函数为实值函数，则博弈对抗必存在混合策略意义下的纳什均衡
    - 策梅洛定理（Zermelo's theorem）：对于任意一个有限步的双人完全信息零和动态博弈，一定存在先手必胜策略/后手必胜策略/双方保平策略