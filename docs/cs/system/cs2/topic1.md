---
counter: True
comment: True
---

# 流水线 CPU

!!! abstract
    计算机系统 Ⅱ 第 2 至 6 周课程内容


## 效率估测

- 单周期 CPU 的时钟周期为最长的指令运行时间
- 流水线 CPU 的时钟周期为最长的操作时间

### 计算指标
#### 吞吐量
吞吐量（TP，Throughput）：$TP = \dfrac{n}{T}$（$n$ 表示指令条数，$T$ 表示运行总时长）

![](/assets/images/cs/system/cs2/topic1/img1_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img1_dark.png#only-dark)

上图中同一数字为同一条指令，纵坐标为不同阶段的操作

- 记每条指令的阶段数为 $m$（阶数）、每个阶段的运行时间为 $\Delta t_0$，则 $T = (m+n-1)\Delta t_0$，$TP = \dfrac{n}{m+n-1}\cdot\dfrac{1}{\Delta t_0}$
- 最大吞吐量：当 $n\gg m$ 时，$TP$ 达到最大，即 $TP_{\rm max}=\dfrac{1}{\Delta t_0}$
- 实际情况下各阶段的运行时间不同，最长的称为瓶颈阶段（bottleneck segment）
    - 这种情况下 $TP$ 的计算方式不变，$TP_{\rm max}=\dfrac{1}{\max(\Delta t_1, \Delta t_2, \cdots, \Delta t_m)}$
- 解决流水线瓶颈的方法：
    - 将瓶颈阶段细分为可以流水线操作的更小阶段（Subdivision）
    - 重叠执行不同指令的瓶颈阶段（Repetition）

#### 加速比
加速比（Sp，Speedup）：$Sp = \dfrac{\text{Execution Time}_\text{non-pipelined}}{\text{Execution Time}_\text{pipelined}}$

- 同上图，可以计算得到 $Sp = \dfrac{n\cdot m\cdot\Delta t_0}{(m+n-1)\Delta t_0} = \dfrac{nm}{m+n-1}$
- 当 $n\gg m$ 时，$Sp=m$

#### 效率
效率（$\eta$）：$\eta = \dfrac{Sp}{m}$

- 当 $n\gg m$ 时，$\eta=1$

## 流水线冒险
有三种类型的流水线冒险：

- 结构冒险（Structural Hazard）：由于流水线硬件结构的限制，导致流水线不能正常工作
- 数据冒险（Data Hazard）：由于流水线中的指令需要访问同一数据，导致流水线不能正常工作
- 控制冒险（Control Hazard）：由于流水线中的指令需要访问同一控制信号，导致流水线不能正常工作

### 结构冒险
- 对于冯诺伊曼架构的计算机，只有一个主存的情况，可能有两条指令的 IF 和 MEM 阶段会产生冲突（对于 load store 类指令 MEM 会访问主存）
- 解决方案
    - 等待（Stall）直到主存访问完成后再取指
    - 添加硬件，例如添加一个主存（比如哈弗架构就不存在结构冒险）
- 结构冒险总是可以通过添加额外硬件来解决

### 数据冒险
- 数据冒险的原因：流水线中的指令需要访问同一数据，但是该数据在流水线中的不同阶段被修改
    - 如 `add x1, x2, x3; sub x4, x1, x5` 两条指令，x1 在 add 的 EX 阶段被修改，在 WB 阶段才会被写回寄存器，而 sub 的 ID 阶段需要访问 x1，因此产生数据冒险
- 解决方案
    - 等待（Stall）直到数据可用（会损失两个时钟周期才等到 ID 在 WB 后）
    - 前递（Forwarding）：在 ID 阶段，如果需要访问的数据在 EX 阶段被修改，那么就直接从 EX 阶段取数据，而不是从寄存器文件中取数据
        - 并不能完全解决数据冒险（比如 load + add，后一条的 EX 需要前一条的 MEM 结果，而前一条 MEM 输出无法接到后一条 EX 前）
        - 如上的 load-use data hazard 情况下暂停一个时钟周期（pipeline stall / bubble），等待 MEM 阶段完成，然后应用 forwarding，将 MEM 结果直接传入后一条指令的 EX 阶段
    - 通过软件在编译时避免出现 load-use 情况

### 控制冒险
- 常发生在条件跳转（分支）指令的情况下，即 branch 指令后下一条指令可能会发生跳转而不是读取的下一条指令
- 解决方案
    - 等待（Stall）直到分支条件计算完成得到下一个 PC 后再对下一条指令进行取指
        - 可以将分支判断提前到 ID 阶段（读取寄存器之后就判断），只需要 stall 一个周期
    - 预测（Prediction）：
        - 简单版本：总是认为分支不会发生，即总是预测不发生跳转，如果发生跳转则插入一条 bubble
        - 复杂版本：根据情况进行预测，例如一个循环最后的分支语句总是预测发生跳转
        - 动态预测：根据历史跳转情况进行预测
    - 延迟决策（Delayed Decision）：将 branch 前的无关指令移动到 branch 之后的 bubble 处（分支延迟槽）执行，减少为了等待而插入的无意义 bubble 代码

## RISC-V 流水线
- RISC-V 流水线一般包含五个阶段：
    - IF (Instruction Fetch)：取指，取出 I-Mem 中 PC 地址处的指令
    - ID (Instruction Decode)：译码，将指令解码为控制信号，并读取寄存器值
    - EX (Execute)：执行，执行 ALU 操作
    - MEM (Memory Access)：访存，访问 D-Mem 进行写入或读取
    - WB (Write Back)：写回，将结果写回寄存器文件
- RISC-V ISA 对于流水线的优点：
    - 指令长度固定为 32 位，易于在一个周期内进行取指或译码
    - 指令格式少且规整，易于在一个周期内译码、读取寄存器
    - 使用 load/store 寻址结构，一个周期计算地址、一个周期访存
    - 访存操作都是对齐的，可以在一个周期内进行
- 流水线实现：
    - 添加阶段寄存器（pipeline register）来分隔每个阶段：IF/ID、ID/EX、EX/MEM、MEM/WB
        - 这四个阶段寄存器和 PC 寄存器一起将流水线分为了五个部分
        - 可以**看作**只有这五个时序电路，其它内部操作都是组合逻辑，在内部运行
        - 五个寄存器在上升沿进行更新，阶段寄存器进行流转，记录当前指令需要的信息
    - 数据通路中有两个回路
        - MEM 阶段计算分支结果，输出给 PC。可能会引起控制冒险
        - WB 阶段写回寄存器，可能会引起数据冒险
    - ID 和 WB 阶段同时使用寄存器组文件，但不会产生结构冒险，因为 ID 阶段只读取寄存器，WB 阶段只写入寄存器，相当于分为了两个部分

## 冒险解决

在 RISC-V 五阶流水线中冒险的具体解决方法。

### 数据冒险

- 即后面的指令需要从寄存器组中读取前面的指令写入的结果
- RISC-V 流水线中有两种情况
    - use-use hazard：即两条 R 型指令产生了数据冒险，可分为几种情况：
       - 两条指令相邻
        - 两条指令间隔一条
        - 两条指令间隔两条（可通过改进寄存器组解决）
    - load-use hazard：即一条 load 指令和一条 R 型指令产生了数据冒险

![](/assets/images/cs/system/cs2/topic1/img2_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img2_dark.png#only-dark)

上图是 use-use 类型冒险的示意图，其中红色线表示正常情况下读取-访问的关系，蓝色线表示通过前递技术解决冒险时的读取-访问关系。

#### 前递（Forwarding）

- 即如上图，通过添加硬件连接的方式来将前一条指令 ALU 的输出直接传递给后面指令的 ALU 输入，而忽略寄存器
- 需要在后一条冲突指令的 EX 阶段进行判断，通过多路选择器选择 ALU 输入来源（原样还是利用前递传递的数据）

##### 探测冒险

![](/assets/images/cs/system/cs2/topic1/img3_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img3_dark.png#only-dark)

如上图，需要关注的为虚线框起来的部分，可以清晰的知道，探测方式是：

- 相邻指令（EX hazard）
    - EX/MEM.RegWrite == 1：即前一条指令写入了寄存器
    - EX/MEM.Rd != 0：即前一条指令写入的不是 x0（如果是 x0 则不会发生任何变化）
    - EX/MEM.Rd == ID/EX.Rs1 或 ID/EX.Rs2：即前一条指令写入的寄存器与后一条指令某一操作数相同
- 隔一条指令（MEM hazard）同理
    - MEM/WB.RegWrite == 1
    - MEM/WB.Rd != 0
    - MEM/WB.Rd == ID/EX.Rs1 或 ID/EX.Rs2

硬件设计：

![](/assets/images/cs/system/cs2/topic1/img4_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img4_dark.png#only-dark)

简化得到相关的通路图如上，即增加一个 Forwarding Unit 来判断冒险，并且给出两个控制信号（ForwardA 和 ForwardB）来选择 ALU 的输入。除此之外，EX/MEM 和 MEM/WB 阶段的 reg_write 控制信号也要传给 Forwarding Unit。

##### 双重冒险

- 双重冒险（double data hazard）即有三条指令连续，且都有冲突，例如
    ```asm
    add x1, x1, x2
    add x1, x1, x3
    add x1, x1, x4
    ```
- 这种情况下应该算作两个 EX hazard（即相邻的两条算一次冲突）
- 因此需要改进 MEM hazard 的判断，防止在这种情况下第三条指令的 x1 读取到第一条指令的结果，即存在 EX hazard 时不认为存在 MEM hazard：
    - MEM/WB.RegWrite == 1
    - MEM/WB.Rd != 0
    - 没有 EX hazard
        - not(EX/MEM.RegWrite == 1 and EX/MEM.Rd != 0 and EX/MEM.Rd == ID/EX.Rs1 或 ID/EX.Rs2)
    - MEM/WB.Rd == ID/EX.Rs1 或 ID/EX.Rs2

#### 暂停（Stall）

- load-use 情况下 ALU 的输入来自前一条指令 Data Memory 的输出而非前面指令的 ALU 结果，因此需要额外的一次 bubble（暂停一个周期）
- 探测，需要提前在 ID 阶段就进行探测 load-use 冒险，如果存在就暂停、插入 bubble
    - ID/EX.MemRead == 1 (ID/EX.MemWrite == 0)
    - ID/EX.Rd == IF/ID.Rs1 或 IF/ID.Rs2
- 暂停流水线
    - 强制 ID/EX 阶段寄存器中的控制信号变为 0（相当于插入一条 nop）
    - 阻止 PC 寄存器和 IF/ID 阶段寄存器更新
- 对于 load-use 冒险，在暂停一个周期后就可以按照 MEM hazard 进行前递解决

![](/assets/images/cs/system/cs2/topic1/img5_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img5_dark.png#only-dark)

如上图所示，第二条指令在 ID 阶段时检测到存在 load-use 冒险，在此暂停，然后下一个周期继续运行，这样中间就多了一条 bubble，然后在 EX 阶段就可以正常接收到 MEM hazard 的前递值了。

具体的硬件实现和前面类似，在 ID 阶段加一个 Hazard Detection Unit 来检测 load-use 冒险，接收它需要的值，输出 PCWrite、IF/IDWrite 控制信号（新增）以及一个控制信号用来选择 ID/EX 阶段寄存器的控制信号部分来自控制单元还是置零。

### 分支冒险

TODO

## 非线性流水线调度

- 线性流水线逐个运行每一个阶段，每一个阶段都会运行且仅运行一次，没有反馈和前馈
- 非线性流水线存在反馈和前馈连接，其一个阶段（部件）可能使用一次或多次
- 非线性流水线仅通过连接图不能够确定流水线的运行顺序，一个连接图可能对应多个不同的运行顺序
- 非线性流水线的运行需要通过预约表（reservation table）来表示
    - 每一行表示一个阶段，每一列表示一个时钟周期
    - 整个表表示一个任务的运行流程，如果在某个周期运行某一阶段，则在对应位置打上 X
    - 线性流水线也有预约表，不过都是固定的，为一个正方形表格，对角线上都是 X

如下图就是一个非线性流水线的连接图，和它的一个预约表：

![](/assets/images/cs/system/cs2/topic1/img6_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img6_dark.png#only-dark)


<style>
.md-typeset table:not([class]) th {
    min-width: 2rem;
}
</style>

<div style="text-align: center" markdown="1">

||1|2|3|4|5|6|7|
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
|S1|X|||X|||X|
|S2||X|||X|||
|S3||X||||X||
|S4|||X|||||

</div>

- 非线性流水线不能像线性流水线一样直接逐个任务贴在一起依次运行，因为会出现冲突（同一周期不同任务使用同一阶段，即结构冒险）
- 非线形流水线需要通过调度算法来找到最优的任务启动方式，使得任务间不会产生冲突，而且运行最高效
- 第一个任务进入流水线后，第二个任务进入且不发生冲突的时间称为启动距离。在同一个调度方式中启动距离可能不同，最佳的调度方式是使平均启动距离最短

### 非线性流水线调度算法
两个概念：

- 禁止集合（prohibit sets），指预约表中每一行任意两个 X 之间的距离构成的集合。意义为：两个任务之间的间隔不能是这个集合中的任意一个值
- 冲突向量（conflict vector），表示为 $(C_m, C_{m-1}, \cdots, C_2, C_1)$，其中 $m$ 为禁止集合中的最大值，如果 $i$ 在禁止集合中，则 $C_i=1$ 否则 $C_i=0$

对于上面的预约表，禁止集合为 $F=\{3, 4, 6\}$，初始冲突向量为 $C=\mathtt{101100}$。

因此参考于初始冲突向量，下一个任务只可能在后第 1、2、5、7 个周期进入（右数 1、2、5 位为 0，7 为总长度加一，相当于硬等一个任务的时常）。以后第一个周期进入为例。第二个任务的初始冲突向量也为 $C=\mathtt{101100}$，此时第一个任务经过了一个周期，冲突向量右移一位变为 $C=\mathtt{10110}$。接着再考虑加入第三个任务，这个任务不能和 1、2 两个冲突，所以此时整体的冲突向量应该是前两个任务此时的冲突向量按位求或，即 $\mathtt{101100} | \mathtt{10110} = \mathtt{111110}$。所以第三个任务只能在后一个周期进入。

这样依此类推，最终不再计算下去的条件为：冲突向量变为了全 1，只能等待一个任务的时长回到初始状态；或者得到的冲突向量和之前的某个相同（达成了循环）。最终可以画出一个状态图。

对于上面的例子，它的状态图如下（方块内为冲突向量，箭头上为等待几个周期进入，即启动距离）：

![](/assets/images/cs/system/cs2/topic1/img7_light.png#only-light)
![](/assets/images/cs/system/cs2/topic1/img7_dark.png#only-dark)

所以它的几种调度方式（用启动距离表示）和平均启动距离为：

<div style="text-align: center" markdown="1">

|调度方式|平均启动距离|
|:--|:--:|
|7|7|
|1, 7|4|
|1, 1, 7|3|
|2, 7|4.5|
|2, 5|3.5|
|2, 5, 7|4.67|
|5|5|
|5, 2|3.5|
|5, 7|6|

</div>

所以最短平均启动距离为 3，对应的调度方式为 1、1、7。