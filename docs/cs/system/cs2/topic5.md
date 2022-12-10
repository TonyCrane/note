---
counter: True
comment: True
---

# CPU 调度

!!! abstract
    计算机系统 Ⅱ 第 13 周课程内容

## 基础概念
- 此处不区分进程与线程的概念
    - 内核线程才是一个被调度的实体，最小单位
- 进程的执行会分为两个类型
    - CPU burst：大部分时间在做 CPU 运算
        - 不同进程、不同计算机的 CPU burst 长度差别很大
    - I/O burst：大部分时间在做 I/O
        - 进程大部分都是 I/O burst
- 当前进程在 I/O burst 时会调度到另一个进程进行执行

### CPU 调度器
- CPU Scheduler 是操作系统内核中负责调度的部件
- 工作方式是从 ready queue 中选择一个进程来将 CPU 资源分配给它
- CPU 调度发生的时机（将 CPU 资源分配给其它任务）
    - 当前进程从 running 状态转换到 waiting 状态，例如进行 I/O 等待
    - 当前进程从 running 状态转换到 ready 状态，例如中断产生
    - 当前进程从 waiting 状态转换到 ready 状态，例如 I/O 完成
    - 当前进程从 running 状态转换到 terminated 状态，即进程结束
- 上面第一个和第四个是非抢占式的（nonpreemptive）
    - 当前进程主动放弃 CPU 资源
    - 也称为协作式调度（cooperative scheduling）
    - 使用非抢占式调度的情况下，一旦一个程序被分配了 CPU 资源，则会一直执行，直到结束或者等待 I/O
- 第二个和第三个是抢占式的（preemptive）
    - 抢占式调度需要硬件支持，例如计时器
    - 需要一些同步的元语（synchronization primitives）

### 抢占
- 抢占（preemption）是指进程在执行过程中非自愿地被中断
- cooperative multitasking os：进程一直运行到主动放弃 CPU 资源或等待 I/O
- preemptive multitasking os：调度器会强制切换进程

#### 用户态抢占
用户态抢占有两种发生的时机：

- 系统调用完成后从内核态返回用户态时
- 进行完中断处理后从内核态返回用户态时

#### 内核态抢占
而如果用户态在执行时进行了系统调用，此时在内核态执行代码，如果此时发生了中断，也有两种情况：

- 处理结束后仍然返回到被打断前的程序，继续完成系统调用
    - 此时就称为内核非抢占（kernel nonpreemption）
    - 但是仍然会发生用户态抢占
        - 可能在返回用户态时发生抢占，切换到另一个进程
- 处理结束后返回到调度器，选择了一个更高优先级的进程进行执行
    - 此时就称为内核抢占（kernel preemption）

### Dispatcher
- Dispatcher 是操作系统内核中负责进程切换的部件：
    - 切换上下文
    - 切换到用户态
    - 跳转到正确的位置恢复执行
- Dispatch latency：dispatcher 进行切换时的花费的时间（从暂停一个进程到恢复另一个进程）

### 调度准则
在调度的时候进行选择时需要考虑的因素

- CPU 利用率（utilization）：CPU 资源的利用率，越大越好
- 吞吐量（throughput）：单位时间内完成的工作量，越多越好
- 周转时间（turnaround time）：从提交一个作业到完成该作业所需要的时间
- 等待时间（waiting time）：在 ready queue 中等待的总时间
- 响应时间（response time）：从用户提交请求到得到第一次响应所需要的时间

调度算法优化时希望更高的 CPU 利用率、吞吐量，更短的周转时间、等待时间、响应时间。

- 大部分情况是优化平均值
- 一些情况下想要优化最小/最大值
    - 例如实时系统，必须要保证在一定时间内完成
- 对于交互系统，希望响应时间的变化尽可能小

## 调度算法
### FCFS 调度算法
FCFS（First Come First Served）：先来先服务

- 是一种非抢占式调度
- waiting time 即将所有等待时间加起来除以总任务数

### SJF 调度算法
SJF（Shortest Job First）：最短作业优先

- 下一个 CPU burst 最短的进程优先执行
- 是可证明的最优（平均等待时间最短的）调度算法
- SJF 可以是抢占式的，也可以是非抢占式的
    - 抢占式的 SJF 又称为 shortest-remaining-time-first 调度算法
- 难点是如果预测 CPU burst 的长度
    - 假设和历史 CPU burst 相关
    - 通过 exponential averaging 来预测
        - $\tau_{n+1}=\alpha t_n+(1-\alpha )\tau_n$ ，其中：
            - $\tau_{n+1}$：预测的下一个 CPU burst 长度
            - $\tau_n$：第 n 次预测的 CPU burst
            - $t_n$：第 n 次实际的 CPU burst
            - $\alpha$：平滑因子，表示历史预测的权重
        - 越老的历史占的权重越小，新的预测占的权重越大
    
### 优先级调度算法
优先级调度算法（priority scheduling）：根据优先级来调度

- 为每一个进程评估一个优先级
- 最高优先级的进程优先进行
- SJF 是优先级调度的一种特例
    - 即令预测下一个 CPU burst 最短的进程优先级更高
- 同样可以是抢占式的也可以是非抢占式的
- 优先级调度算法的弊端是可能会导致“饥饿”（starvation）
    - 即低优先级的进程可能永远不会被执行
    - 解决方案是引入 aging，等待时间越长，优先级会提高

### 时间片轮转调度算法
Round Robin（RR）：时间片轮转

- 每一个进程都有一个时间片（time quantum）q
- 在时间片用完之后会被切换到下一个进程
    - 也就是说，每个进程都会被执行 q 时间
- 时间片 q 的大小会影响到性能
    - q 太大，相当于退化到 FCFS
    - q 太小，切换过于频繁，上下文切换的开销过大
    - 通常是 10-100 ms
- 一定是抢占式的调度

### 多级队列调度算法
Multi-level Queue Scheduling：多级队列调度算法

- ready queue 被分成多个队列
    - 比如分成交互性队列和批处理队列
- 一个进程会被永久地分到一个队列中
- 每个队列可以有自己的调度算法
    - 例如，高交互性的进程队列可以使用 RR 算法，低交互的批处理队列可以使用 FCFS 算法
- 队列之间也需要进行调度
    - 可以是固定优先级的调度，但是会导致饥饿
    - 可以通过时间片轮转来调度

### 多级反馈队列调度算法
Multi-level Feedback Queue Scheduling：多级反馈队列调度算法

- 和多级队列调度的区别是一个进程可以在不同的队列之间进行迁移
- 尝试推测进程的性质
    - 即是交互性的还是批处理的
- aging 也可以通过这种方式来实现
- 目的是来给交互性、I/O intensive 的进程更高的调度优先级
- 是最通用的调度算法