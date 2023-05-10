---
counter: True
comment: True
---

# 系统量化研究方法

!!! abstract
    计算机系统 Ⅲ 第 2 周课程内容

## CPU 性能

- CPU 执行时间 = CPU 时钟周期数 * CPU 时钟周期时间 = CPU 时钟周期数 / CPU 时钟频率
- IC：Instruction Count，指令数
- CPI：Cycle Per Instruction，每条指令的时钟周期数
    - 由 CPU 硬件决定
    - 不同的指令也会有不同的 CPI，平均 CPI 取决于指令的组合方式
    - CPI = CPU 时钟周期数 / IC
    - CPU 执行时间 = IC * CPI / CPU 时钟频率

## Amdahl 定律

- Amdahl 定律指出了，当提升系统性能时，有多大的收益受限于被提升的部分所占的运行时间比例
- $T_\text{improved} = \dfrac{T_\text{affected}}{\text{improvement factor}} + T_\text{unaffected}$
- 加速比 Sp = 改进后的运行时间 / 改进前的运行时间
- $T_\text{new} = T_\text{old}\times \left((1-f)+\dfrac{f}{Sp}\right)$
- $Sp_\text{overall} = \dfrac{T_\text{old}}{T_\text{new}} = \dfrac{1}{(1-f)+\dfrac{f}{Sp}}$
    - 其中 $Sp$ 为被优化部分的加速比，$Sp_\text{overall}$ 为整体加速比，$f$ 为被优化部分所占的运行时间比例

## 经典的体系结构思想
- 摩尔定律
    - 每过 18-24 个月，集成电路的晶体管数量将增加一倍
- 使用抽象来简化设计
- 让最常见的情况更快
- 通过并行来提高性能
    - 由很多级别的并行，比如指令集并行、进程并行等
- 通过流水线来提高性能
    - 将任务分为多段，让多个任务的不同阶段同时进行
    - 通常用来提高指令吞吐量
- 通过预测来提高性能
- 使用层次化的内存
    - 让最常访问的数据在更高层级，访问更快