---
counter: True
comment: True
---

# RISC-V 特权级 ISA（页表相关）

!!! abstract
    RISC-V 指令集的特权级部分。这里只包含页表相关的内容，其他的内容在 [RISC-V 特权级 ISA（基础&中断）](privileged/)里。

    参考：

    - [The RISC-V Instruction Set Manual Volume II: Privileged Architecture v.20211203](https://github.com/riscv/riscv-isa-manual/releases/download/Priv-v1.12/riscv-privileged-20211203.pdf)
    - 浙江大学 “计算机系统 Ⅲ “（大二春夏）课程

操作系统实现虚拟地址需要硬件的支持，需要操作系统向 CPU 通知设置页表，在访问时 CPU 再进行地址的翻译。而这些页表的设置操作都是在 Supervisor 模式下进行设置的，因为 User 模式不应该关心这些，Machine 模式直接访问物理地址也不关心。所以关于分页的 ISA 都在 Supervisor 里。

## 相关 CSR 寄存器
### sstatus
<style>
.csr-bit {
    background-color: #3f6ec6b0;
    border-radius: 3px;
    font-size: .4rem;
    padding: 4px;
}
.csr-behav {
    background-color: #e6695bb0;
    border-radius: 3px;
    font-size: .4rem;
    padding: 4px;
}
</style>

- <span class="csr-bit">18</span> SUM：是否允许 Supervisor 模式访问用户态内存（permit Supervisor User Memory access）
- <span class="csr-bit">19</span> MXR：是否允许读取可执行页面的内存（Make eXecutable Readable）

### satp
satp 为 Supervisor Address Translation and Protection，即用于设置页表的寄存器。

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;text-transform: none;">
    <span>satp</span>
    <span>32 位 Supervisor</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnodel">30</td>
    <td class="riscv-table-numnode" colspan="7"></td>
    <td class="riscv-table-numnoder">22</td>
    <td class="riscv-table-numnodel">21</td>
    <td class="riscv-table-numnode" colspan="20"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="1" class="riscv-table-node-little">M</td>
    <td colspan="9" class="riscv-table-node-little">ASID</td>
    <td colspan="22" class="riscv-table-node-little">PPN</td>
</tr>
</table>

- PPN：根页表物理页号（Physical Page Number）
- ASID：地址空间 ID（Address Space ID）
- M（MODE）：分页模式
    - 0：Bare 不进行地址翻译或者保护
    - 1：Sv32 采用 Sv32 模式虚拟地址翻译

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;text-transform: none;">
    <span>satp</span>
    <span>64 位 Supervisor</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel" style="word-wrap: normal">63</td>
    <td class="riscv-table-numnode" colspan="2"></td>
    <td class="riscv-table-numnoder" style="font-size: 0">60</td>
    <td class="riscv-table-numnodel" style="word-wrap: normal">59</td>
    <td class="riscv-table-numnode" colspan="14"></td>
    <td class="riscv-table-numnoder" style="font-size: 0">44</td>
    <td class="riscv-table-numnodel" style="word-wrap: normal">43</td>
    <td class="riscv-table-numnode" colspan="42"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="4" class="riscv-table-node-little">M</td>
    <td colspan="16" class="riscv-table-node-little">ASID</td>
    <td colspan="44" class="riscv-table-node-little">PPN</td>
</tr>
</table>

- PPN：根页表物理页号（Physical Page Number）
- ASID：地址空间 ID（Address Space ID）
- M（MODE）：分页模式
    - 0：Bare 不进行地址翻译或者保护

<div style="display: flex; justify-content: flex-start; margin-left: 1.9em;" markdown="1">
<div markdown="1">

- 8：Sv39&emsp;
- 9：Sv48 

</div><div markdown="1">

- 10：Sv57 
- 11：Sv64（保留）

</div></div>

</div>
</div>
    
## 相关特权指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>sfence.vma</span>
    <span>R 型</span>
</div>
<div class="card-body" markdown="1" style="padding-top: 0;">

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">25</td>
    <td class="riscv-table-numnodel">24</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">15</td>
    <td class="riscv-table-numnodel">14</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnodel">6</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="7" class="riscv-table-node-little">0001001</td>
    <td colspan="5" class="riscv-table-node-little">rs2</td>
    <td colspan="5" class="riscv-table-node-little">rs1</td>
    <td colspan="3" class="riscv-table-node-little">000</td>
    <td colspan="5" class="riscv-table-node-little">00000</td>
    <td colspan="7" class="riscv-table-node-little">1110011</td>
</tr>
</table>

- **指令格式**：sfence.vma rs1, rs2
- **指令作用**：刷新 TLB（Translation Lookaside Buffer）中的虚拟地址到物理地址的映射缓存
    - rs1 rs2 均为 x0 时，刷新所有 TLB
    - rs1 指定要刷新的虚拟地址，不为 x0 则只刷新所在的叶页表项
    - rs2 指定 ASID，不为 x0 则只刷新指定 ASID 的 TLB

</div>
</div>

## Sv32 分页模式

Sv32 模式规定的虚拟地址有 32 位，物理地址有 34 位，结构分别为：

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnode" colspan="2"></td>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="8"></td>
    <td class="riscv-table-numnoder">22</td>
    <td class="riscv-table-numnodel">21</td>
    <td class="riscv-table-numnode" colspan="8"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="2"></td>
    <td colspan="10" class="riscv-table-node-little">VPN[1]</td>
    <td colspan="10" class="riscv-table-node-little">VPN[0]</td>
    <td colspan="12" class="riscv-table-node-little">page offset</td>
</tr>
</table>

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">33</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">22</td>
    <td class="riscv-table-numnodel">21</td>
    <td class="riscv-table-numnode" colspan="8"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="10" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="12" class="riscv-table-node-little">page offset</td>
</tr>
</table>

其中 VPN 即 Virtual Page Number 虚拟页号，PPN 即 Physical Page Number 物理页号。转换的目标就是把 20 位虚拟页号转为 22 位物理页号，offset 不变。

Sv32 使用二级页表，每一个页表包含 2^10=1024 个页表项，每个页表项占 4 个字节，所以一个页表正好 4KiB 占一页内存且必须页对齐。每一个页表项的内容如下：

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">31</td>
    <td class="riscv-table-numnode" colspan="10"></td>
    <td class="riscv-table-numnoder">20</td>
    <td class="riscv-table-numnodel">19</td>
    <td class="riscv-table-numnode" colspan="8"></td>
    <td class="riscv-table-numnoder">10</td>
    <td class="riscv-table-numnodel">9</td>
    <td class="riscv-table-numnoder">8</td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnoder">6</td>
    <td class="riscv-table-numnoder">5</td>
    <td class="riscv-table-numnoder">4</td>
    <td class="riscv-table-numnoder">3</td>
    <td class="riscv-table-numnoder">2</td>
    <td class="riscv-table-numnoder">1</td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="12" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="10" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="2" class="riscv-table-node-little">RSW</td>
    <td class="riscv-table-node-little">D</td>
    <td class="riscv-table-node-little">A</td>
    <td class="riscv-table-node-little">G</td>
    <td class="riscv-table-node-little">U</td>
    <td class="riscv-table-node-little">X</td>
    <td class="riscv-table-node-little">W</td>
    <td class="riscv-table-node-little">R</td>
    <td class="riscv-table-node-little">V</td>
</tr>
</table>

其中 PPN[1] PPN[0] 为下一级页表的物理页号/物理地址的高 20 位。剩下的为 flag：

- RSW：保留位，必须为 0
- A（Accessed）、D（Dirty）：叶页表项是否被访问过、是否被写过（没细看，反正都是 0 就行）
- G（Global）：全局位，如果为 1 则不会被 TLB 清除（也没细看）
- U（User）：用户位，如果为 1 则允许用户态访问
- X（eXecute）、W（Write）、R（Read）：可执行、可写、可读位
    - RWX 全为 0 时表示当前页表项指向下一级页表
    - W 为 1，R 一定也为 1（W 为 1、R 为 0 是保留状态）
- V（Valid）：有效位，如果为 1 则表示该页表项有效，否则在访问时会触发异常

地址翻译的流程图为：

![](/assets/images/cs/pl/riscv/paging/sv32_light.png#only-light)
![](/assets/images/cs/pl/riscv/paging/sv32_dark.png#only-dark)

上图是使用二级页表的翻译过程。除此之外还有一种特殊的情况，即也可以使用一级页表（superpage），当第一级页表的 RWX 不全为 0 时，表示当前页表项是叶页表项，此时会判断 PPN[0] 的值，如果不全为 0 则抛出异常。然后在翻译时 PPN[1] 保留，VPN[0] 并入 page offset：

![](/assets/images/cs/pl/riscv/paging/sv32__light.png#only-light)
![](/assets/images/cs/pl/riscv/paging/sv32__dark.png#only-dark)

???+ example "文档中对于地址翻译的详细描述"
    记待翻译的虚拟地址为 va，结果的物理地址为 pa

    1. 令 a = satp.PPN << 12，i = 1
    2. 令 pte = *(a + (va.VPN[i] << 2))
        - 如果 pte 的访问过程中违反了 PMA 或 PMP 的检查，抛出对应访问类型的 Access Fault 异常
    3. 如果 pte.V = 0 或者（pte.R = 0 且 pte.W = 1）或者其他保留位没有置 0，抛出对应访问类型的 Page Fault 异常
    4. 目前 pte 是合法的。如果 pte.R = 1 或 pte.X = 1（即不全为 0）则跳到第 6 步
    5. 目前 pte 指向下一级页表。令 i = i - 1，a = pte.PPN << 12，跳到第 2 步
        - 如果 i < 0，抛出对应访问类型的 Page Fault 异常
    6. 目前 pte 是一个叶页表项。根据 pte.R/W/X/U、当前特权级、SUM MXR 位判断当前访问权限是否合法，不合法则抛出对应访问类型的 Page Fault 异常
    7. 如果 i > 0 且 pte.PPN[i-1:0] != 0，说明当前是 superpage 且没对齐，抛出对应访问类型的 Page Fault 异常
    8. 与 pte.A pte.D 有关的一些没细看
    9. 翻译成功，接下来填写转换后的物理地址
        - pa.pgoff = va.pgoff
        - 如果 i > 0，说明当前是 superpage translation，令 pa.PPN[i-1:0] = va.VPN[i-1:0]
            - 即扩充 offset 的范围
        - pa.PPN[1:i] = pte.PPN[1:i]

## Sv39 分页模式
Sv39 模式规定虚拟地址为 39 位，物理地址为 56 位。且虚拟地址的高 [63:39] 位必须和 38 位保持一致，否则会触发 Page Fault。虚拟地址有 27 位 VPN，通过三级页表转换为 44 位 PPN，剩下的 12 位为 offset 不变。虚拟地址和物理地址的结构如下：

!!! note "下面 index 后面有 ... 的表示这部分没有按照实际长度比例来"

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnode" colspan="2"></td>
    <td class="riscv-table-numnodel">38</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">30</td>
    <td class="riscv-table-numnodel">29</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">21</td>
    <td class="riscv-table-numnodel">20</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="2"></td>
    <td colspan="6" class="riscv-table-node-little">VPN[2]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[1]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[0]</td>
    <td colspan="8" class="riscv-table-node-little">page offset</td>
</tr>
</table>

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">55...</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">30</td>
    <td class="riscv-table-numnodel">29</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">21</td>
    <td class="riscv-table-numnodel">20</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="8" class="riscv-table-node-little">PPN[2]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="8" class="riscv-table-node-little">page offset</td>
</tr>
</table>

Sv39 每个页表有 2^9=512 个页表项，每个页表项有 8 字节，因此每个页表同样为 4KiB 大小，且必须对齐。其中每个页表项的结构如下：

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">63</td>
    <td class="riscv-table-numnodel">62</td>
    <td class="riscv-table-numnoder">61</td>
    <td class="riscv-table-numnodel">60...</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">54</td>
    <td class="riscv-table-numnodel">53...</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">28</td>
    <td class="riscv-table-numnodel">27...</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">19</td>
    <td class="riscv-table-numnodel">18...</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">10</td>
    <td class="riscv-table-numnodel">9</td>
    <td class="riscv-table-numnoder">8</td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnoder">6</td>
    <td class="riscv-table-numnoder">5</td>
    <td class="riscv-table-numnoder">4</td>
    <td class="riscv-table-numnoder">3</td>
    <td class="riscv-table-numnoder">2</td>
    <td class="riscv-table-numnoder">1</td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td class="riscv-table-node-little">N</td>
    <td colspan="2" class="riscv-table-node-little">PBMT</td>
    <td colspan="3" class="riscv-table-node-little"></td>
    <td colspan="8" class="riscv-table-node-little">PPN[2]</td>
    <td colspan="7" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="7" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="2" class="riscv-table-node-little">RSW</td>
    <td class="riscv-table-node-little">D</td>
    <td class="riscv-table-node-little">A</td>
    <td class="riscv-table-node-little">G</td>
    <td class="riscv-table-node-little">U</td>
    <td class="riscv-table-node-little">X</td>
    <td class="riscv-table-node-little">W</td>
    <td class="riscv-table-node-little">R</td>
    <td class="riscv-table-node-little">V</td>
</tr>
</table>

其中：

- 高位三部分保留，如果有不为 0 的则抛出 Page Fault 异常
    - N 保留给 Svnapot 扩展，没实现的话必须为 0
    - PBMT 保留给 Svpbmt 扩展，没实现的话必须为 0
    - [60:54] 位保留给后续标准使用，目前必须为 0
- PPN[2] PPN[1] PPN[0] 为物理页号
- 后面的标识位和 Sv32 一样

地址翻译过程和 Sv32 类似，只是多了一级页表。而且 Sv39 的每一级页表项也都可以是叶页表项，同样页表项后续的 PPN 必须是 0 否则视为未对齐抛出 Page Fault 异常。因此 Sv39 支持 4KiB 粒度的分页 pages、2MiB 粒度的分页 megapages 和 1GiB 粒度的分页 gigapages。其中使用三级页表的地址翻译过程如下：

![](/assets/images/cs/pl/riscv/paging/sv39_light.png#only-light)
![](/assets/images/cs/pl/riscv/paging/sv39_dark.png#only-dark)

只使用二级页表和一级页表的 megapages 和 gigapages 也不难理解，其实就相当于 page offset 向上扩充覆盖到了 VPN[0] 或 VPN[1]，这里就不画了。

??? example "文档中对于地址翻译的详细描述"
    记待翻译的虚拟地址为 va，结果的物理地址为 pa

    1. 令 a = satp.PPN << 12，i = 2
    2. 令 pte = *(a + (va.VPN[i] << 3))
        - 如果 pte 的访问过程中违反了 PMA 或 PMP 的检查，抛出对应访问类型的 Access Fault 异常
    3. 如果 pte.V = 0 或者（pte.R = 0 且 pte.W = 1）或者其他保留位没有置 0，抛出对应访问类型的 Page Fault 异常
    4. 目前 pte 是合法的。如果 pte.R = 1 或 pte.X = 1（即不全为 0）则跳到第 6 步
    5. 目前 pte 指向下一级页表。令 i = i - 1，a = pte.PPN << 12，跳到第 2 步
        - 如果 i < 0，抛出对应访问类型的 Page Fault 异常
    6. 目前 pte 是一个叶页表项。根据 pte.R/W/X/U、当前特权级、SUM MXR 位判断当前访问权限是否合法，不合法则抛出对应访问类型的 Page Fault 异常
    7. 如果 i > 0 且 pte.PPN[i-1:0] != 0，说明当前是 superpage 且没对齐，抛出对应访问类型的 Page Fault 异常
    8. 与 pte.A pte.D 有关的一些没细看
    9. 翻译成功，接下来填写转换后的物理地址
        - pa.pgoff = va.pgoff
        - 如果 i > 0，说明当前是 superpage translation，令 pa.PPN[i-1:0] = va.VPN[i-1:0]
            - 即扩充 offset 的范围
        - pa.PPN[2:i] = pte.PPN[2:i]

## Sv48 分页模式
Sv39 提供的 39 位虚拟地址可能会不够用，所以扩展得到了 Sv48 模式，在 Sv39 基础上加了一级页表，为虚拟地址高位多加了 9 位的 VPN[3]，将物理地址 26 位的 PPN[2] 分为了 17 位的 PPN[3] 和 9 位的 PPN[2]：

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnode" colspan="2"></td>
    <td class="riscv-table-numnodel">47</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">39</td>
    <td class="riscv-table-numnodel">38</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">30</td>
    <td class="riscv-table-numnodel">29</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">21</td>
    <td class="riscv-table-numnodel">20</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="2"></td>
    <td colspan="6" class="riscv-table-node-little">VPN[3]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[2]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[1]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[0]</td>
    <td colspan="8" class="riscv-table-node-little">page offset</td>
</tr>
</table>

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">55...</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">39</td>
    <td class="riscv-table-numnodel">38</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">30</td>
    <td class="riscv-table-numnodel">29</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">21</td>
    <td class="riscv-table-numnodel">20</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="8" class="riscv-table-node-little">PPN[3]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[2]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="8" class="riscv-table-node-little">page offset</td>
</tr>
</table>

使用四级页表，每个页表内页表项数量和长度都没有变化，页表项内容也只是从 PPN[2] 拆分出了 PPN[3]：

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">63</td>
    <td class="riscv-table-numnodel">62</td>
    <td class="riscv-table-numnoder">61</td>
    <td class="riscv-table-numnodel">60...</td>
    <td class="riscv-table-numnode" colspan="1"></td>
    <td class="riscv-table-numnoder">54</td>
    <td class="riscv-table-numnodel">53...</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">37</td>
    <td class="riscv-table-numnodel">36...</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">28</td>
    <td class="riscv-table-numnodel">27...</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">19</td>
    <td class="riscv-table-numnodel">18...</td>
    <td class="riscv-table-numnode" colspan="5"></td>
    <td class="riscv-table-numnoder">10</td>
    <td class="riscv-table-numnodel">9</td>
    <td class="riscv-table-numnoder">8</td>
    <td class="riscv-table-numnoder">7</td>
    <td class="riscv-table-numnoder">6</td>
    <td class="riscv-table-numnoder">5</td>
    <td class="riscv-table-numnoder">4</td>
    <td class="riscv-table-numnoder">3</td>
    <td class="riscv-table-numnoder">2</td>
    <td class="riscv-table-numnoder">1</td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td class="riscv-table-node-little"></td>
    <td colspan="2" class="riscv-table-node-little"></td>
    <td colspan="3" class="riscv-table-node-little"></td>
    <td colspan="8" class="riscv-table-node-little">PPN[3]</td>
    <td colspan="7" class="riscv-table-node-little">PPN[2]</td>
    <td colspan="7" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="7" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="2" class="riscv-table-node-little">RSW</td>
    <td class="riscv-table-node-little">D</td>
    <td class="riscv-table-node-little">A</td>
    <td class="riscv-table-node-little">G</td>
    <td class="riscv-table-node-little">U</td>
    <td class="riscv-table-node-little">X</td>
    <td class="riscv-table-node-little">W</td>
    <td class="riscv-table-node-little">R</td>
    <td class="riscv-table-node-little">V</td>
</tr>
</table>

地址的翻译过程也类似，只是可能会多一级查询，这里不再赘述。

同样每一级页表项都可以作为叶页表项，因此 Sv48 的分页支持四种粒度 4KiB pages、2MiB megapages、1GiB gigapages 和 512GiB terapages。

??? example "文档中对于地址翻译的详细描述"
    记待翻译的虚拟地址为 va，结果的物理地址为 pa

    1. 令 a = satp.PPN << 12，i = 3
    2. 令 pte = *(a + (va.VPN[i] << 3))
        - 如果 pte 的访问过程中违反了 PMA 或 PMP 的检查，抛出对应访问类型的 Access Fault 异常
    3. 如果 pte.V = 0 或者（pte.R = 0 且 pte.W = 1）或者其他保留位没有置 0，抛出对应访问类型的 Page Fault 异常
    4. 目前 pte 是合法的。如果 pte.R = 1 或 pte.X = 1（即不全为 0）则跳到第 6 步
    5. 目前 pte 指向下一级页表。令 i = i - 1，a = pte.PPN << 12，跳到第 2 步
        - 如果 i < 0，抛出对应访问类型的 Page Fault 异常
    6. 目前 pte 是一个叶页表项。根据 pte.R/W/X/U、当前特权级、SUM MXR 位判断当前访问权限是否合法，不合法则抛出对应访问类型的 Page Fault 异常
    7. 如果 i > 0 且 pte.PPN[i-1:0] != 0，说明当前是 superpage 且没对齐，抛出对应访问类型的 Page Fault 异常
    8. 与 pte.A pte.D 有关的一些没细看
    9. 翻译成功，接下来填写转换后的物理地址
        - pa.pgoff = va.pgoff
        - 如果 i > 0，说明当前是 superpage translation，令 pa.PPN[i-1:0] = va.VPN[i-1:0]
            - 即扩充 offset 的范围
        - pa.PPN[3:i] = pte.PPN[3:i]

## Sv57 分页模式
在 Sv48 基础上又加了一级页表，为虚拟地址高位多加了 9 位的 VPN[4]，将物理地址 17 位的 PPN[3] 分为了 8 位的 PPN[4] 和 9 位的 PPN[3]：

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel">56</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">48</td>
    <td class="riscv-table-numnodel">47</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">39</td>
    <td class="riscv-table-numnodel">38</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">30</td>
    <td class="riscv-table-numnodel">29</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">21</td>
    <td class="riscv-table-numnodel">20</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td colspan="6" class="riscv-table-node-little">VPN[4]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[3]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[2]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[1]</td>
    <td colspan="6" class="riscv-table-node-little">VPN[0]</td>
    <td colspan="8" class="riscv-table-node-little">page offset</td>
</tr>
</table>

<table class="riscv-table" style="margin-bottom: 0.6em">
<tr>
    <td class="riscv-table-numnodel"></td>
    <td class="riscv-table-numnodel">55</td>
    <td class="riscv-table-numnode" colspan="3"></td>
    <td class="riscv-table-numnoder">48</td>
    <td class="riscv-table-numnodel">47</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">39</td>
    <td class="riscv-table-numnodel">38</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">30</td>
    <td class="riscv-table-numnodel">29</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">21</td>
    <td class="riscv-table-numnodel">20</td>
    <td class="riscv-table-numnode" colspan="4"></td>
    <td class="riscv-table-numnoder">12</td>
    <td class="riscv-table-numnodel">11</td>
    <td class="riscv-table-numnode" colspan="6"></td>
    <td class="riscv-table-numnoder">0</td>
</tr>
<tr>
    <td></td>
    <td colspan="5" class="riscv-table-node-little">PPN[4]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[3]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[2]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[1]</td>
    <td colspan="6" class="riscv-table-node-little">PPN[0]</td>
    <td colspan="8" class="riscv-table-node-little">page offset</td>
</tr>
</table>

使用五级页表，每个页表内页表项数量和长度都没有变，内容差别和物理地址同样，从 PPN[3] 中拆出了 PPN[4]，具体就不展示了。

翻译过程类似，同样每一级页表项都可以作为叶页表项，因此 Sv57 的分页支持五种粒度 4KiB pages、2MiB megapages、1GiB gigapages、512GiB terapages 和 256TiB petapages。

??? example "文档中对于地址翻译的详细描述"
    记待翻译的虚拟地址为 va，结果的物理地址为 pa

    1. 令 a = satp.PPN << 12，i = 4
    2. 令 pte = *(a + (va.VPN[i] << 3))
        - 如果 pte 的访问过程中违反了 PMA 或 PMP 的检查，抛出对应访问类型的 Access Fault 异常
    3. 如果 pte.V = 0 或者（pte.R = 0 且 pte.W = 1）或者其他保留位没有置 0，抛出对应访问类型的 Page Fault 异常
    4. 目前 pte 是合法的。如果 pte.R = 1 或 pte.X = 1（即不全为 0）则跳到第 6 步
    5. 目前 pte 指向下一级页表。令 i = i - 1，a = pte.PPN << 12，跳到第 2 步
        - 如果 i < 0，抛出对应访问类型的 Page Fault 异常
    6. 目前 pte 是一个叶页表项。根据 pte.R/W/X/U、当前特权级、SUM MXR 位判断当前访问权限是否合法，不合法则抛出对应访问类型的 Page Fault 异常
    7. 如果 i > 0 且 pte.PPN[i-1:0] != 0，说明当前是 superpage 且没对齐，抛出对应访问类型的 Page Fault 异常
    8. 与 pte.A pte.D 有关的一些没细看
    9. 翻译成功，接下来填写转换后的物理地址
        - pa.pgoff = va.pgoff
        - 如果 i > 0，说明当前是 superpage translation，令 pa.PPN[i-1:0] = va.VPN[i-1:0]
            - 即扩充 offset 的范围
        - pa.PPN[4:i] = pte.PPN[4:i]

## 操作系统中开启分页

在操作系统中开启分页机制，大体上需要做以下事情：

- 分配物理地址页，每页中写好需要映射部分的页表项
    - 注意 PTE 标识位的权限，以及 PTE.V 位
- 将页表的物理地址末尾截断得到根页表物理页号
- 同分页模式一起写入 satp 寄存器
    - 写入的同时就已经启用分页了，所以要注意 pc+4 是否仍然可以访问
- 执行 sfence.vma x0, x0 指令，刷新 TLB 缓存

这里存在一个主要的问题，设置 satp 寄存器的同时就会开启分页机制，但同时不会修改 pc，所以就要考虑下一条指令读取的问题。大概有两种处理方法：

- 提前设置 stvec 为设置 satp 之后的下一条指令的虚拟地址
    - 这样开启分页后继续执行会产生异常，跳转到 stvec 地址，在 S 态继续执行
- 进行两次页表的设置
    - 第一次设置临时页表，将代码段同时映射到高位的虚拟地址，以及建立一个等值映射
    - 设置 satp 后仍可以通过等值映射根据物理地址访问后续指令
    - 后续通过将 ra 设置为高位虚拟地址再 ret，这时 pc 就开始在虚拟地址上执行了
    - 然后再布局完整的页表，设置 satp，此时内核态的虚拟地址映射不会发生变化，设置后 pc 仍可以正常执行

在 qemu 实际运行中，旧版 qemu（起码 7.0 之前）实测会有问题，使用第二种方法的话，即使不进行等值映射，qemu 也可以正常执行后续指令，但一旦使用 gdb 单步跟踪，就会在设置 satp 后立马挂掉（~~薛定谔的代码~~）。尚不清楚是什么原因，姑且怀疑是 qemu 对于指令缓存处理的问题（ps：这里即使调用 fence.i 清除指令缓存也一样可以执行）。

相关问题以及一种 patch：[[PATCH] target/riscv: Exit current TB after an sfence.vma](https://lore.kernel.org/all/7f383fc2.81a2.17f93c0dad7.Coremail.phantom@zju.edu.cn/)