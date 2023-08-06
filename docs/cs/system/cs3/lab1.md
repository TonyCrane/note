---
counter: True
comment: True
---

# 动态分支预测

!!! abstract
    计算机系统 Ⅲ lab1 实验报告（2023.03.09 ~ 2023.03.30）

    !!! warning "仅供学习参考，请勿抄袭"

## 实验内容
- 在给定框架或 lab0 的基础上实现用 BTB 和 BHT 做动态分支预测；
- 通过仿真测试和上板验证；
- 指出使用了 BTB 和 BHT 的跳转指令位置，展示 PC 的变化和 BHT 状态变化；
- 思考题：
    1. 分析分支预测成功和预测失败时的相关波形。
    2. 在正确实现 BTB 和 BHT 的情况下，有没有可能会出现 BHT 预测分支发生跳转，也就是 branch taken，但是 BTB 中查不到目标跳转地址，为什么？
    3. 前面介绍的 BHT 和 BTB 都是基于内容检索，即通过将当前 PC 和表中存储的 PC 比较来确定分支信息存储于哪一表项。这种设计很像一个全相联的 cache，硬件逻辑实际上会比较复杂，那么能否参考直接映射或者组相联的 cache 来简化 BHT/BTB 的存储和检索逻辑？简述思路。

## 关于给定框架

由于前面自己编写的 CPU 的跳转部分实现的有些奇怪，重构起来工作量比较大，所以临时使用了给定的框架来完成本次试验。

由于框架除了动态分支预测之外的部分都已经完全实现好，~~而且没有文档~~。所以只需要分析一下 RV32core 中有关 PC 处理和跳转的部分即可。

### PC 修改流程
根据 IF 段相关代码，可以总结 PC（即 PC_IF）的修改流程如下：
![](/assets/images/cs/system/cs3/lab1/pc.png)

- 下一周期的 PC_IF 由 next_PC_IF 决定
- 如果动态分支预测模块给出的 refetch 为 1 即需要重新取指，则下一周期的 PC 由当前在 ID 阶段的指令（即跳转指令）给出
    - 这里根据控制单元给出的 Branch_ctrl，如果不跳转则为 PC_ID+4
    - 如果跳转则为 jump_PC_ID
- 如果 refetch 为 0 即不需要重新取指，则下一周期的 PC 由当前在 IF 阶段的指令给出
    - 根据动态分支预测模块给出的针对当前 IF 阶段指令是否跳转的结果 taken，如果不跳转则为 PC_IF+4
    - 如果跳转则为 pc_to_take<<2（即 BTB 给出的目标地址）

### Branch_Prediction 模块接口理解

Branch_Prediction 模块现有的接口如下：

```verilog
module Branch_Prediction (
    input           clk,
    input           rst,
    input   [7:0]   PC_Branch,
    input           J,
    input           Branch_ID,
    input   [7:0]   PC_to_branch,
    output          taken,
    output  [7:0]   PC_to_take,
    output          refetch
);
```

- clk rst 为全局时钟和复位信号
- PC_Branch 为当前 IF 阶段指令对应的 PC >> 2（如果 IF 阶段指令为跳转，则意思就同命名一样，即表示分支指令所在的 PC）
- J 为当前 ID 阶段控制单元给出的 ID 阶段对应指令是否为跳转指令（包括无条件跳转和分支）
- Branch_ID 为当前 ID 阶段控制单元给出的 ID 阶段对应指令是否有进行跳转（包括无条件跳转，和分支采取的跳转）
- PC_to_branch 为当前 ID 阶段控制单元给出的 ID 阶段对应指令的跳转目标地址
- taken 为需要输出的，针对 IF 阶段指令是否预测跳转的结果
- PC_to_take 为针对 IF 阶段指令预测跳转的目标地址
- refetch 为针对当前在 ID 阶段的跳转指令，如果预测错误，则需要通知 IF 段重新取指

除此之外，因为我们要在分支跳转指令进到 ID 阶段的时候再修改 BTB BHT，所以为了方便，我们还可以将当前的 PC_ID 也传入到模块中。

## 动态分支预测实现
### 时序部分设计
针对前面分析的 PC 修改流程以及动态分支预测模块接口，可以设计出动态分支预测模块应有的时序表现。假设一个情形是一个分支指令，在 IF 阶段预测跳转，在 ID 阶段检查发现不应该跳转，所以重新取指。那么这个情形的时序应该是：
![](/assets/images/cs/system/cs3/lab1/timing.png)

所以 taken、refetch、PC_to_take 直接通过 BTB BHT 等 assign 就可以。然后对于 ID 阶段的跳转指令，需要等待下一次时钟正边缘到来，根据实际的 Branch_ID 是否跳转等来修改 BHT BTB。

### 代码实现
对于 BTB 和 BHT，我这里使用一种类似哈希表的实现来方便访问。因为程序的长度不大（一共 235 条指令），所以可以为每一条指令分配一个 BTB 和 BHT 的空间：

```verilog
localparam SIZE = 256;
reg [7:0] BTB [0:SIZE-1];
reg [1:0] BHT [0:SIZE-1];
```

接着我们来 assign refetch、taken 和 PC_to_take。根据 2 bit BHT 的状态转移图，我们可以看出当高位为 1 的时候就是要预测跳转的时候，所以可以直接将 BHT[PC_Branch][1] assign 给 taken。对于 PC_to_take，它的值就是 BTB[PC_Branch]。

至于 refetch，这个变量是针对于在 ID 阶段的分支跳转指令的，那么它有以下几种情况需要重新取指：

- 一定是在 ID 阶段为分支跳转指令的前提下（即 J = 1）
    - IF 阶段预测了跳转，但实际上并不跳转
    - IF 阶段预测不跳转，但实际上发生了跳转
    - IF 阶段预测跳转，实际上也进行了跳转，但是跳转的目的地址不同（例如通过 ra 来 jalr 返回）

对于前两种情况，就是 IF 阶段的预测和 ID 阶段的实际情况不一样，所以可以表示为 BHT[PC_ID][1] != Branch_ID；对于最后一种情况，IF 阶段预测的跳转地址为 BTB[PC_ID]，实际的跳转地址为 PC_to_branch，所以在 Branch_ID 为 1 的基础上判断这两个相不相等即可：

```verilog
assign refetch = J && (BHT[PC_ID][1] != Branch_ID || (Branch_ID && BTB[PC_ID] != PC_to_branch));
assign taken <= BHT[PC_Branch][1];
assign PC_to_take <= BTB[PC_Branch];
```

接下来剩下的时序部分就是对于 BTB 和 BHT 的更新。只需要针对在 J（ID 阶段是跳转指令）的前提下，分别讨论 Branch_ID 为 1（taken）和 0（not taken）两种情况然后对 BHT 进行状态转移即可。同时在 taken 的时候要记录/修改 BTB 的值：

```verilog
always @(posedge clk or posedge rst) begin
    if (rst) begin
        for (integer i = 0; i < SIZE; i = i + 1) begin
            BTB[i] <= 8'b0;
            BHT[i] <= 2'b00;
        end
    end else if (J) begin       // branch/jump inst now in ID stage
        if (Branch_ID) begin    // branch taken
            BTB[PC_ID] <= PC_to_branch;
            if      (BHT[PC_ID] == 2'b10) BHT[PC_ID] <= 2'b11;
            else if (BHT[PC_ID] == 2'b01) BHT[PC_ID] <= 2'b11;
            else if (BHT[PC_ID] == 2'b00) BHT[PC_ID] <= 2'b01;
        end else begin          // branch not taken
            if      (BHT[PC_ID] == 2'b11) BHT[PC_ID] <= 2'b10;
            else if (BHT[PC_ID] == 2'b10) BHT[PC_ID] <= 2'b00;
            else if (BHT[PC_ID] == 2'b01) BHT[PC_ID] <= 2'b00;
        end
    end
end
```

对于 RV32core 中的接入，因为加了一个 PC_ID，所以添加一个输入即可，其他代码都无需改动：

```verilog
Branch_Prediction branch_prediction(
    .clk(debug_clk),
    .rst(rst),
    .PC_Branch(PC_IF[9:2]),
    .taken(taken),
    .PC_to_take(pc_to_take),
    .PC_ID(PC_ID[9:2])
    .J(j),
    .Branch_ID(Branch_ctrl),
    .PC_to_branch(jump_PC_ID[9:2]),
    .refetch(refetch)
);
```

## 实验测试结果
### 仿真波形及输出

仿真可以正确运行所给的程序，完整的波形包括串口输出如下：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/full_marked.png" width="90%" style="margin: 0 auto;">
</div>


再针对分支预测部分详细看一下波形，下面分为几种情况。

1. **预测不跳转失败**

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/wave1.png" width="80%" style="margin: 0 auto;">
</div>

在 0xc 这条指令，由于是第一次运行，BHT 为 00，所以预测不跳转，但实际上进行了跳转，所以在 0xc 进入 ID 阶段时 refetch 信号变为了 1，接下来下一周期 PC_IF 重新取指得到了正确的跳转位置，同时 BHT 更新为了 01，BTB 也更新到了目的地址。整个波形和前面预先设计的时序图是一致的。

2. **预测跳转成功，但跳转地址不同**

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/wave2.png" width="90%" style="margin: 0 auto;">
</div>

在 0x384 这条指令的位置，因为 BHT 为 11，所以会预测跳转，根据 BTB 跳转到了 0x390 的位置，但是在下一周期发现实际上要跳转的位置是 0x2d0，所以 refetch 信号也会变为 1，并且在下一个周期 BTB 被修改为了 0x2d0 对应的 0xb4。但是 BHT 不会更新，因为它只负责预测跳不跳转，正确性先不需要它考虑。

3. **预测跳转成功**

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/wave3.png" width="80%" style="margin: 0 auto;">
</div>

0x330 这条指令预测跳转了，并且在 ID 阶段验证确实应该跳转，所以 refetch 为 0，然后就直接无间隙地继续运行下去了。

4. **预测不跳转失败+预测跳转失败**

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/wave4.png" width="90%" style="margin: 0 auto;">
</div>

这里的情况是 0x344 指令跳转到 0x330，然后 0x330 不跳转接到 0x334。但是两次的分支预测都是错误的，前一个预测了不跳转，后一个预测了跳转，所以各浪费了一个周期。具体的修改在波形中也可以清晰的看出来。另外，这里第二次 refetch 半个周期后才变为 1 是因为为了处理 forwarding，给寄存器组加了 double bump，即在负边缘更新寄存器，更新之后相关判断才开始认为预测失败了。

5. **预测不跳转成功**

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/wave5.png" width="80%" style="margin: 0 auto;">
</div>

这种情况看起来就比较简单了，0x284 这条指令预测不跳转，实际上也不跳转，而且 BHT 为 00 也不需要修改，所以就直接继续运行没有什么其他影响了。


### 上板验证
上板测试一切正常，而且可以通过串口得到程序正确的输出：

<div style="text-align: center;">
<img src="/assets/images/cs/system/cs3/lab1/serial.png" width="65%" style="margin: 0 auto;">
</div>

## 思考题

1. **分析分支预测成功和预测失败时的相关波形**

波形分析见上，四种情况的波形已经解释过了。

2. **在正确实现 BTB 和 BHT 的情况下，有没有可能会出现 BHT 预测分支发生跳转，也就是 branch taken，但是 BTB 中查不到目标跳转地址，为什么？**

没有可能，因为初始情况下的 BHT 都是 00，也就是不预测跳转。想要让 BHT 预测跳转，一定会先经过两次预测错误（也就是实际上会跳转，BHT 从 00->01->11）。这种情况下因为已经发生过了两次跳转，那么这个地址对应的 BTB 就一定已经被更新为了前面的跳转地址，所以 BTB 一定能够查到目标跳转地址。

3. **前面介绍的 BHT 和 BTB 都是基于内容检索，即通过将当前 PC 和表中存储的 PC 比较来确定分支信息存储于哪一表项。这种设计很像一个全相联的 cache，硬件逻辑实际上会比较复杂，那么能否参考直接映射或者组相联的 cache 来简化 BHT/BTB 的存储和检索逻辑？简述思路。**

还不是太清楚 cache 相关的知识。对于我的实现方式不需要考虑这个问题，因为我的实现相当于一个哈希表，可以直接通过 PC 来访问对应的分支信息。如果 BTB 和 BHT 设计为了队列/栈这种结构需要逐一比较的话，我认为可能还是不容易参考 cache 的设计，因为这个队列的内容和结构是会不断变化的。
