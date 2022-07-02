---
counter: True
comment: True
fold_toc: True
---

# x86 汇编语言

!!! abstract 

    - 自学，看书《汇编语言（第4版）》王爽
    - 浙江大学白洪欢老师 “汇编语言”（大一春夏）课程
    - https://faydoc.tripod.com/cpu/index.htm

## 基础知识

??? note "一些仅供了解的东西"

    - 机器语言：机器指令（二进制数）的集合
    - CPU 可以执行机器指令，进行运算
    - 汇编语言主体是汇编指令，汇编指令通过编译器编译为机器码给计算机执行
    - 寄存器：CPU 中可以存储数据的器件
    - 汇编语言组成：
        - 汇编指令：有对应的机器码，是机器码的助记符
        - 伪指令：由编译器执行，没有对应机器码
        - 其他符号（+-*/等）：由编译器识别，没有对应机器码 
    - 指令和数据在内存中存放，被 CPU 使用
    - 指令和数据在内存中没有区别，都是二进制信息
    - 计算机最小信息单位是 bit，8 个 bit 组成一个 Byte，一个存储单元可以存储一个 Byte（8 个二进制位），存储单元从 0 开始编号
    - CPU 通过总线与存储器芯片传输地址、数据、控制信息（总线：连接 CPU 和其他芯片的一堆导线）
    - CPU 从内存读取数据的过程：
        - CPU 通过地址线将地址信息发出
        - CPU 通过控制线发出内存读命令，告知指定存储器芯片要从中读取数据
        - 存储器将所需地址处的数据通过数据线送给 CPU
    - CPU 通过**地址总线**指定存储单元。地址总线上能传送多少个不同的信息，CPU 就可以对多少个存储单元进行寻址
    - **一个 CPU 有 n 根地址线，则这个 CPU 的地址总线宽度为 n，这样的 CPU 最多可以寻找 2<sup>n</sup> 个内存单元**
    - CPU 通过**数据总线**来与内存或其他器件之间传送数据。数据总线的宽度决定了 CPU 与外界的数据传送速度
    - **8 根数据总线一次可以传送一个 8 为二进制数据（1 个字节），16 根数据总线一次可以传送两个字节**
    - 8088 CPU 的数据总线宽度为 8，8086 CPU 的数据总线宽度为 16
    - CPU 通过控制总线对外部器件进行控制。控制总线的宽度决定了 CPU 对外部器件的控制能力
    - 主板上器件通过总线和 CPU 相连
    - CPU 通过插在扩展插槽上的接口卡间接控制外设
    - 存储器芯片从读写上分为 随机存储器（RAM）和 只读存储器（ROM）
        - RAM 可读可写，但必须带电存储，关机后内容丢失
        - ROM 只读不写，但关机后内容不丢失
    - 存储器从功能和连接上分为：
        - 随机存储器：存放供 CPU 使用的绝大部分程序和数据，由装在主板上的 RAM 和插在扩展插槽上的 RAM 组成 
        - 装有 BIOS 的 ROM：厂商提供的软件系统，通过它利用该硬件设备进行最基本的输入输出
        - 接口卡上的 RAM：某些接口卡需要对大批量输入、输出数据进行暂时存储，在其上装有 RAM（如显存）
    - CPU 在操控存储器的时候，把它们当作内存来对待，把它们总的看作一个由若干存储单元组成的逻辑存储器，即内存地址空间
    - 所有物理存储器被看作一个由若干存储单元组成的逻辑存储器，每个物理存储器在其中占有一个地址段，即地址空间

### 数据的表示与组织

二进制数末尾用 B/b 作后缀，十六进制末尾用 H/h 作后缀且如果开头为字母则要在前面加一个 0，八进制末尾用 Q/q 作后缀，十进制不用后缀

一个二进制位叫一位（bit），四个位叫一个半字节（nibble），八个位叫一个字节（byte），十六个位叫一个字（word），三十二个位叫一个双字（double word）

字符可以直接使用单引号括字符来表示，也可以用对应 ASCII 码来表示

### 内部寄存器

8086 内部一共有 14 个 16 位寄存器，8 个通用寄存器，4 个段寄存器，2 个控制寄存器

- 通用寄存器
    - 数据寄存器：ax bx cx dx，用于存放数据。每个寄存器为 16 位，可分为高低 8 位，高 8 位分别为 ah bh ch dh，低八位分别为 al bl cl dl，且如果只修改八位，则不会影响到另外八位（比如溢出不会从 al 溢出到 ah）
        - ax：累加器，常用作累加，且在乘除法、串运算、IO 中有专门用处
        - bx：基址寄存器，常用来存放寻址的基址
        - cx：计数寄存器，常用在循环中作为计数器
        - dx：数据寄存器，存放 IO 端口地址，且在双字运算中作为 ax 的扩展高十六位
    - 变址寄存器：si di，常用来寻址
        - si：源变址寄存器
        - di：目的变址寄存器
    - 指针寄存器：sp bp，常与 ss 构成远指针
        - sp：堆栈指针寄存器，ss:sp 指向堆栈顶端
        - bp：基址指针寄存器，常用 ss:bp 指向堆栈中数据
- 段寄存器：cs ss ds es
    - cs：代码段寄存器，存放代码段的段地址
    - ss：堆栈段寄存器，存放堆栈段的段地址
    - ds：数据段寄存器，存放数据段的段地址
    - es：附加数据段寄存器，存放附加数据段段地址
- 控制寄存器：ip fl
    - ip：指令指针寄存器，存放代码段的偏移地址， cs:ip 指向下一条指令的首字节，不能直接访问 ip
    - fl：标志寄存器，16 位但只使用 9 位表示 6 个状态标志和 3 个控制标志（df if tf）
        - of：overflow flag 溢出标志，第 11 位，表示运算是否溢出
        - df：direction flag 方向标志，第 10 位，标志字符串处理指令中处理信息的方向
        - if：interrupt flag 中断标志，第 9 位，是否允许外部硬件中断
        - tf：trace flag 跟踪标志，第 8 位，CPU 是否进入单步工作状态
        - sf：sign flag 符号标志，第 7 位，运算结果的符号（1 表示负）
        - zf：zero flag 零标志，第 6 位，运算结果是否为 0
        - af：auxiliary carry flag 辅助进位标志，第 4 位，记录运算时第三位是否向左侧产生进借位
        - pf：parity flag 奇偶标志，第 2 位，结果操作数中低 8 位 1 的个数是否为偶数
        - cf：carry flag 进位标志，第 0 位，运算时最高位是否向左侧有进借位

80386 32 位寄存器一共有 16 个

- 通用寄存器
    - eax ebx ecx edx，可以使用例如 ax 表示低 16 位，ah al 分别表示低 16 位中的高低 8 位
    - esi edi，低 16 位为 si di
    - esp ebp，低 16 位为 sp bp
- 段寄存器：cs ss ds es fs gs（多了两个附加数据段寄存器）
- 控制寄存器：eip eflags

### 8086 内存组织

可访问的内存一共有 1MB，十六进制表示为 00000h~FFFFFh，这样用 20 位表示的地址称为物理地址

寻址时使用的是 段地址:偏移地址 形式的逻辑地址，对应的物理地址为 段地址*16+偏移地址，汇编里写成 段地址:[偏移地址]。同样也容易看出一个存储单元对应的逻辑地址表示并不唯一

### 指令系统与寻址方式

汇编指令一般由操作码（opcode）和操作数（operand）构成，任何指令都有操作码，操作数的个数不一定

#### 操作数寻址方式

- **立即数方式**：即操作数为常数
- **寄存器方式**：以寄存器为操作数
- **直接寻址**：通过逻辑地址表示操作数，且偏移地址为立即数，比如 [1234h]、ss:[1234h]，省略情况默认 ds
- **间接寻址**：逻辑地址的偏移地址以间接形式表示，方括号内只能是 bx bp si di，且表示为 基址寄存器（bx bp 选其一或没有）+ 变址寄存器（si di 选其一或没有）+ 位移量（立即数或没有）的形式  
    即 bx bp 不能同时出现，si di 不能同时出现  
    省略段地址时，如果偏移地址内有 bp 出现，则缺省段地址为 ss，其它情况均为 ds  
    段地址不能是立即数，一般除 cs ss ds 外的其它段地址预先存在 es 中再寻址

## 8086 汇编指令

如果指令中没有标志位表格，则该指令不影响任何标志位。右斜线表示该标志位由结果决定，全部填充为根据特殊意义设定（注意中会具体说），打叉为 undefined（一般不变）

### 数据传送指令

#### 通用数据传送指令

<div class="card" markdown="1">
<div class="card-header">mov</div>
<div class="card-body" markdown="1">

- **指令格式**：mov a, b
- **指令作用**：将 b 的值传入 a
- **注意**：a 是寄存器或者逻辑地址，b 可以是寄存器、逻辑地址或立即数，但 a b 最多有一个是逻辑地址，且如果是将立即数传入逻辑地址所指内存时要标注大小（byte ptr / word ptr），并且 a b 宽度需一致。不能把立即数赋值给段寄存器，也不能把段寄存器赋值给段寄存器。不影响任何标志位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">push</div>
<div class="card-body" markdown="1">

- **指令格式**：push a
- **指令作用**：将 a 压入栈，即 sp = sp - 2, word ptr ss:[sp] = a
- **注意**：a 是寄存器或者逻辑地址，内容一定是 16 位，不能是立即数，不能是 fl。不影响任何标志位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">pop</div>
<div class="card-body" markdown="1">

- **指令格式**：pop a
- **指令作用**：从栈上弹出 16 位数值到 a 中，即 a = word ptr ss:[sp], sp = sp + 2
- **注意**：a 是寄存器或者逻辑地址，一定是 16 位，不能是 cs fl。不影响任何标志位

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">xchg</div>
<div class="card-body" markdown="1">

- **指令格式**：xchg op1, op2
- **指令作用**：交换 op1 op2，即 tmp = op1, op1 = op2, op2 = tmp
- **注意**：op1 op2 是寄存器或者内存，不能都是内存，且不能是段寄存器。不影响任何标志位

</div>
</div>

#### 端口输入输出指令

<div class="card" markdown="1">
<div class="card-header">in</div>
<div class="card-body" markdown="1">

- **指令格式**：in acc, port
- **指令作用**：从端口读数据到 al 或 ax 中，即 acc = [port]（端口中内容）
- **注意**：acc 一定是 al 或 ax，port 一定是 dx 或立即数，如果是立即数则最大 0FFh。是 ax 则 [port] 存入 al，[port+1] 存入 ah

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">out</div>
<div class="card-body" markdown="1">

- **指令格式**：out port, acc
- **指令作用**：把 al 或 ax 中值写入端口，即 [port] = acc
- **注意**：port 一定是 dx 或立即数（立即数最大 0FFh），acc 一定是 al 或 ax。是 ax 则 al 写入 [port]，ah 写入 [port+1]

</div>
</div>

#### 地址传送指令

<div class="card" markdown="1">
<div class="card-header">lea</div>
<div class="card-body" markdown="1">

- **指令格式**：lea dest, src
- **指令作用**：将 src 的有效地址传入 dest，即 dest = offset src
- **注意**：dest 是寄存器，src 是内存变量。取 src 的偏移地址

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">lds</div>
<div class="card-body" markdown="1">

- **指令格式**：lds dest, src
- **指令作用**：将 src 处远指针装入 ds:dest，即 dest = word ptr [src], ds = word ptr [src+2]
- **注意**：dest 是寄存器，src 是双字大小内存

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">les</div>
<div class="card-body" markdown="1">

- **指令格式**：les dest, src
- **指令作用**：将 src 处远指针装入 es:dest，即 dest = word ptr [src], es = word ptr [src+2]
- **注意**：dest 是寄存器，src 是双字大小内存

</div>
</div>

#### 标志寄存器传送指令

<div class="card" markdown="1">
<div class="card-header">lahf</div>
<div class="card-body" markdown="1">

- **指令格式**：lahf
- **指令作用**：将 fl 低 8 位复制到 ah，即 ah = fl & 0FFh

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">sahf</div>
<div class="card-body" markdown="1">

- **指令格式**：sahf
- **指令作用**：将 ah 存入 fl 低 8 位，即 fl = (fl & 0FF00h) | 2 | (ah & 0D5h)
- **注意**：只保留 ah 的 0 2 4 6 7 位（cf pf af zf sf），且第 1 位恒为 1

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">pushf</div>
<div class="card-body" markdown="1">

- **指令格式**：pushf
- **指令作用**：将 fl 压入堆栈，即 push fl（不能直接执行）

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">popf</div>
<div class="card-body" markdown="1">

- **指令格式**：popf
- **指令作用**：从堆栈弹出 16 位到 fl，即 pop fl（不能直接执行

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node fl-affected">DF</td>
    <td class="fl-table-node fl-affected">IF</td>
    <td class="fl-table-node fl-affected">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

### 转换指令

#### 符号扩充指令

<div class="card" markdown="1">
<div class="card-header">cbw</div>
<div class="card-body" markdown="1">

- **指令格式**：cbw
- **指令作用**：将字节 al 扩充为字 ax，即将 al 符号位扩展到 ah

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cwd</div>
<div class="card-body" markdown="1">

- **指令格式**：cwd
- **指令作用**：将字 ax 扩充为双字 dx:ax（直接拼接），即将 ax 符号位扩展到 dx

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">xlat</div>
<div class="card-body" markdown="1">

- **指令格式**：xlat
- **指令作用**：换码指令，al = byte ptr ds:[bx+al]
- **注意**：一般使 ds:bx 指向一张表，然后功能即类似列表索引取值

</div>
</div>

### 算数指令

#### 加法指令

<div class="card" markdown="1">
<div class="card-header">add</div>
<div class="card-body" markdown="1">

- **指令格式**：add dest, src
- **指令作用**：将 src 加到 dest 上，即 dest += src
- **注意**：src 可以是立即数/寄存器/内存，dest 可以是寄存器/内存，但二者不能都为内存，宽度要一致。可能会产生进位（cf）和溢出（of）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">inc</div>
<div class="card-body" markdown="1">

- **指令格式**：inc op
- **指令作用**：将 op 加一，即 op += 1
- **注意**：op 为寄存器或内存。不影响 cf 位

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">adc</div>
<div class="card-body" markdown="1">

- **指令格式**：adc dest, src
- **指令作用**：带进位加，即 dest = dest + src + cf
- **注意**：操作数规则与 add 相同，可以用于模拟 32 位加法

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

#### 减法指令

<div class="card" markdown="1">
<div class="card-header">sub</div>
<div class="card-body" markdown="1">

- **指令格式**：sub dest, src
- **指令作用**：从 dest 减去 src，即 dest -= src
- **注意**：操作数格式同 add，会产生溢出（of），借位也会使 cf 变 1

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">sbb</div>
<div class="card-body" markdown="1">

- **指令格式**：sbb dest, src
- **指令作用**：带借位减，dest = dest - src - cf
- **注意**：操作数格式同 add

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">dec</div>
<div class="card-body" markdown="1">

- **指令格式**：dec op
- **指令作用**：将 op 减一，即 op -= 1
- **注意**：op 为寄存器或内存。不影响 cf 位

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">neg</div>
<div class="card-body" markdown="1">

- **指令格式**：neg op
- **指令作用**：op = -op
- **注意**：op 为寄存器或内存。非零数求补后 cf=1，0 求补后 cf=0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cmp</div>
<div class="card-body" markdown="1">

- **指令格式**：cmp op1, op2
- **指令作用**：用 op1 减 op2，但丢弃结果只影响标志位
- **注意**：操作数格式同 sub，用于在 jump 指令前给出符号位作为条件判断依据。

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

#### 乘法指令

<div class="card" markdown="1">
<div class="card-header">mul</div>
<div class="card-body" markdown="1">

- **指令格式**：mul src
- **指令作用**：非符号数乘法，当 src 为 8 位时 ax = al * src，当 src 为 16 位时 dx:ax = ax * src
- **注意**：src 是寄存器或内存。如果高位（一半）是 0，则将 of cf 置 0，否则置 1

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">imul</div>
<div class="card-body" markdown="1">

- **指令格式**：imul src
- **指令作用**：符号数乘法，乘法方式同 mul，但将两个乘数和积都视为符号数

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

#### 除法指令

<div class="card" markdown="1">
<div class="card-header">div</div>
<div class="card-body" markdown="1">

- **指令格式**：div op
- **指令作用**：无符号数除法
    - 当 op 为 8 位时，al = ax / op, ah = ax % op
    - 当 op 为 16 位时，ax = dx:ax / op, dx = dx:ax % op
- **注意**：op 是寄存器或内存，可以得到商和余数

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">idiv</div>
<div class="card-body" markdown="1">

- **指令格式**：idiv
- **指令作用**：符号数除法，除法操作同 div，但将除数、被除数、商和余数都视为符号数

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">CF</td>
</tr>
</table>

</div>
</div>

#### 逻辑运算指令

<div class="card" markdown="1">
<div class="card-header">and</div>
<div class="card-body" markdown="1">

- **指令格式**：and dest, src
- **指令作用**：按位与运算，dest = dest & src, of=0, cf=0
- **注意**：操作数格式同 add，of 和 cf 都会置 0，但会影响 zf

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">or</div>
<div class="card-body" markdown="1">

- **指令格式**：or dest, src
- **指令作用**：按位或运算，dest = dest | src, of=0, cf=0
- **注意**：操作数格式同 add，of 和 cf 都会置 0，但会影响 zf

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">xor</div>
<div class="card-body" markdown="1">

- **指令格式**：xor dest, src
- **指令作用**：按位异或运算，dest = dest ^ src, of=0, cf=0
- **注意**：操作数格式同 add，of 和 cf 都会置 0，但会影响 zf

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">not</div>
<div class="card-body" markdown="1">

- **指令格式**：not op
- **指令作用**：对 op 按位求反，op = ~op
- **注意**：op 为寄存器或内存

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">test</div>
<div class="card-body" markdown="1">

- **指令格式**：test op1, op2
- **指令作用**：位测试，op1 & op2 丢弃结果仅影响符号位
- **注意**：主要用到 zf 的变化，为 jz jnz 提供 zf

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

#### 移位指令

<div class="card" markdown="1">
<div class="card-header">shl</div>
<div class="card-body" markdown="1">

- **指令格式**：shl dest, count
- **指令作用**：对 dest 逻辑左移 count 位，右侧补 0，左侧最后溢出的一位落入 cf
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）
- **标志位**：若 count 为 0，则不影响 sf zf af pf，否则根据结果设置（af 为 undefined），cf 为移出的最后一位，当 count 为 1 时，如果结果的最高位和 cf 相同则 of 为 0 反之为 1，当 count 不为 1 时 of 为 undefined

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-special">SF</td>
    <td class="fl-table-node fl-special">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">shr</div>
<div class="card-body" markdown="1">

- **指令格式**：shr dest, count
- **指令作用**：对 dest 逻辑右移 count 位，左侧补 0，右侧最后溢出的一位落入 cf
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）
- **标志位**：若 count 为 0，则不影响 sf zf af pf，否则根据结果设置（af 为 undefined），cf 为移出的最后一位，当 count 为 1 时，如果结果的最高位和 cf 相同则 of 为 0 反之为 1，当 count 不为 1 时 of 为 undefined

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-special">SF</td>
    <td class="fl-table-node fl-special">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">sal</div>
<div class="card-body" markdown="1">

- **指令格式**：sal dest, count
- **指令作用**：对 dest 算数左移 count 位，同逻辑左移
- **注意**：与 shl 完全相同
- **标志位**：若 count 为 0，则不影响 sf zf af pf，否则根据结果设置（af 为 undefined），cf 为移出的最后一位，当 count 为 1 时，如果结果的最高位和 cf 相同则 of 为 0 反之为 1，当 count 不为 1 时 of 为 undefined

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-special">SF</td>
    <td class="fl-table-node fl-special">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">sar</div>
<div class="card-body" markdown="1">

- **指令格式**：sar dest, count
- **指令作用**：对 dest 算数右移 count 位，左侧补符号位，右侧最后溢出的一位落入 cf
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）
- **标志位**：若 count 为 0，则不影响 sf zf af pf，否则根据结果设置（af 为 undefined），cf 为移出的最后一位，当 count 为 1 时，如果结果的最高位和 cf 相同则 of 为 0 反之为 1，当 count 不为 1 时 of 为 undefined

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-special">SF</td>
    <td class="fl-table-node fl-special">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">rol</div>
<div class="card-body" markdown="1">

- **指令格式**：rol dest, count
- **指令作用**：对 dest 循环左移 count 位，最高位回到最低位同时移到 cf 中
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）。如果移位大于 1 时，of undefined，否则 of 为 cf 与结果最高位的异或

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">ror</div>
<div class="card-body" markdown="1">

- **指令格式**：ror dest, count
- **指令作用**：对 dest 循环右移 count 位，最低位回到最高位同时移到 cf 中
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）。如果移位大于 1 时，of undefined，否则 of 为两个最高位的异或

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">rcl</div>
<div class="card-body" markdown="1">

- **指令格式**：rcl dest, count
- **指令作用**：带进位循环左移，即 cf 加在 dest 左侧一起循环左移
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）。如果移位大于 1 时，of undefined，否则 of 为 cf 与结果最高位的异或

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">rcr</div>
<div class="card-body" markdown="1">

- **指令格式**：rcr dest, count
- **指令作用**：带进位循环右移，即 cf 加在 dest 右侧一起循环右移
- **注意**：dest 可以是寄存器或内存，count 是 1 或 cl（8086 里不能为其它内容）。如果移位大于 1 时，of undefined，否则 of 为两个最高位的异或

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

### 十进制调整指令

BCD 码是使用二进制编码十进制数，可以分为压缩 BCD 码和非压缩 BCD 码

#### 压缩 BCD 码调整指令

压缩 BCD 码即是使用 4 个二进制位表示 1 个十进制数，如 37h 表示 37。与这些指令相关的是 af 标志，它在加减法时如果低四位和高四位间发生了十六进制进位则变为 1。因此也会正好差 6，daa das 作用则是将这个 6 调整回来，使结果继续为压缩 BCD 码

<div class="card" markdown="1">
<div class="card-header">daa</div>
<div class="card-body" markdown="1">

- **指令格式**：daa
- **指令作用**：在 al 被做加法后将结果 al 调整为 BCD 码
    - if (af == 1 || (al&0Fh) > 9) al += 6, af = 1; else af = 0
    - if (cf == 1 || al > 9Fh) al += 60h, cf = 1; else cf = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">das</div>
<div class="card-body" markdown="1">

- **指令格式**：das
- **指令作用**：在 al 被做减法后将结果 al 调整为 BCD 码
    - if (af == 1 || (al&0Fh) > 9) al -= 6, af = 1; else af = 0
    - if (cf == 1 || al > 9Fh) al -= 60h, cf = 1; else cf = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

#### 非压缩 BCD 码调整指令

非压缩 BCD 码使用 8 个二进制位表示 1 个十进制位，其中高 4 位没有意义，比如 06h 16h 26h 均表示十进制数 6

<div class="card" markdown="1">
<div class="card-header">aaa</div>
<div class="card-body" markdown="1">

- **指令格式**：aaa
- **指令作用**：加法的 ASCII 调整，在 al 被做加法后连带 ah 一起调整 ax 为非压缩 BCD 码
    - if (af == 1 || (al&0Fh) > 9) al = (al+6)&0Fh, ah += 1, af = 1, cf = 1
    - else af = 0, cf = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


??? example "例"

    ```asm
    mov ah, 0
    mov al, '8'   ; al = 38h
    add al, '9'   ; al = 38h + 39h = 71h, af = 1, cf = 0
    aaa           ; ax = 0107h 即 17
    
    mov ax, 0505h ; 55
    add al, 9     ; al = 0Eh, af = 0, cf = 0
    aaa           ; ax = 0604h 即 64
    ```

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">aas</div>
<div class="card-body" markdown="1">

- **指令格式**：aas
- **指令作用**：减法的 ASCII 调整，在 al 被做减法后连带 ah 一起调整 ax 为非压缩 BCD 码
    - if (af == 1 || (af&0Fh) > 9) al = (al-6)&0Fh, ah -= 1, af = 1, cf = 1
    - else af = 0, cf = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


??? example "例"

    ```asm
    mov ax, 0201h  ; 21
    sub al, 9      ; al = 0F8h, af = 1, cf = 1
    aas            ; ax = 0102h 即 12

    mov ax, 0335h  ; 35
    sub al, 38h    ; (减 8) al = 0FDh, af = 1, cf = 1
    aas            ; ax = 0207h 即 27
    ```

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">aam</div>
<div class="card-body" markdown="1">

- **指令格式**：aam
- **指令作用**：乘法的 ASCII 调整，在 al 被做乘法后对其做调整
    - ah = al / 10, al = al % 10

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">CF</td>
</tr>
</table>


??? example "例"

    ```asm
    mov al, 3
    mov bl, 4
    mul bl    ; ax = 000Ch
    aam       ; ax = 0102h 即 12
    ```

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">aad</div>
<div class="card-body" markdown="1">

- **指令格式**：aad
- **指令作用**：除法的 ASCII 调整，在 ax 被做除法**前**对其进行调整，使除法结果为 BCD 码
    - al = ah * 10 + al, ah = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">CF</td>
</tr>
</table>


??? example "例"

    ```asm
    mov ax, 0105h  ; 15
    mov cl, 4
    aad            ; ax = 000Fh
    div cl         ; al = 03h, ah = 03h
    ```

</div>
</div>

### 字符串操作指令

字符串操作指令分为 movs 字符串传送、cmps 字符串比较、scas 字符串扫描、stos 存入字符串、lods 从字符串取五种，它们都可以接一个指令前缀。如果不接前缀，则只执行一次，如果接前缀，则重复执行。lods 指令不常用前缀

<div class="card" markdown="1">
<div class="card-header">前缀 rep</div>
<div class="card-body" markdown="1">

- **作用**：把后面的字符串操作指令重复 cx 次
- **注意**：cx 需要提前设置，一般不接 cmps scas

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">前缀 repe / repz</div>
<div class="card-body" markdown="1">

- **作用**：最多重复 cx 次，且仅当比较相等时继续重复
- **注意**：cx 需要提前设置，不能用在 movs stos 上

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">前缀 repne / repnz</div>
<div class="card-body" markdown="1">

- **作用**：最多重复 cx 次，且仅当比较不相等时继续重复
- **注意**：cx 需要提前设置，不能用在 movs stos 上

</div>
</div>

#### 字符串传送指令

<div class="card" markdown="1">
<div class="card-header">movsb</div>
<div class="card-body" markdown="1">

- **指令格式**：movsb / rep movsb
- **指令作用**：以字节为单位从 ds:[si] 传送数据到 es:[di]，并移动 si di
- **注意**：si di 的移动与 df 有关，预先用 cld std 设置，df=0 则 si di 移向下一个字节，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">movsw</div>
<div class="card-body" markdown="1">

- **指令格式**：movsw / rep movsw
- **指令作用**：以字为单位从 ds:[si] 传送数据到 es:[di]，并移动 si di
- **注意**：si di 的移动与 df 有关，预先用 cld std 设置，df=0 则 si di 移向下一个字，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">movs</div>
<div class="card-body" markdown="1">

- **指令格式**：
    - (rep) movs byte ptr es:[di], byte ptr seg:[si]
    - (rep) movs word ptr es:[di], word ptr seg:[si]
- **指令作用**：以字节/字为单位从 seg:[si] 传送数据到 es:[di]，并移动 si di
- **注意**：seg 可以是 cs ds es ss 中任意一个，当 seg 为 ds 时与 movsb/movsw 等价。si di 的移动与 df 有关，预先用 cld std 设置，df=0 则 si di 移向下一个字节/字，否则移向上一个

</div>
</div>

#### 字符串比较指令

<div class="card" markdown="1">
<div class="card-header">cmpsb</div>
<div class="card-body" markdown="1">

- **指令格式**：cmpsb / repe cmpsb / repne cmpsb
- **指令作用**：比较字节 ds:[si] 与 es:[di]，即 byte ptr ds:[si] - byte ptr es:[di] 丢弃结果保留标志位，并移动 si di
- **注意**：si di 的移动不会影响标志位。si di 的移动与 df 有关，预先用 cld std 设置，df=0 则 si di 移向下一个字节，否则移向上一个

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cmpsw</div>
<div class="card-body" markdown="1">

- **指令格式**：cmpsw / repe cmpsw / repne cmpsw
- **指令作用**：比较字 ds:[si] 与 es:[di]，即 word ptr ds:[si] - word ptr es:[di] 丢弃结果保留标志位，并移动 si di
- **注意**：si di 的移动不会影响标志位。si di 的移动与 df 有关，预先用 cld std 设置，df=0 则 si di 移向下一个字，否则移向上一个

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cmps</div>
<div class="card-body" markdown="1">

- **指令格式**：
    - (repe/repne) cmps byte ptr seg:[si], byte ptr es:[di]
    - (repe/repne) cmps word ptr seg:[si], word ptr es:[di]
- **指令作用**：比较字节/字 seg:[si] 与 es:[di]，即左减右丢弃结果保留标志位，并移动 si di
- **注意**：seg 可以是 cs ds es ss 中任意一个。si di 的移动不会影响标志位。si di 的移动与 df 有关，预先用 cld std 设置，df=0 则 si di 移向下一个字节/字，否则移向上一个

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

#### 字符串扫描指令

<div class="card" markdown="1">
<div class="card-header">scasb</div>
<div class="card-body" markdown="1">

- **指令格式**：scasb / repe scasb / repne scasb
- **指令作用**：比较 al 与 es:[di]，即计算 al - es:[di] 丢弃结果保留符号位，并移动 di
- **注意**：di 的移动不会影响标志位。di 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字节，否则移向上一个

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">scasw</div>
<div class="card-body" markdown="1">

- **指令格式**：scasw / repe scasw / repne scasw
- **指令作用**：比较 ax 与 es:[di]，即计算 ax - es:[di] 丢弃结果保留符号位，并移动 di
- **注意**：di 的移动不会影响标志位。di 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字，否则移向上一个

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>


</div>
</div>

#### 存入字符串指令

<div class="card" markdown="1">
<div class="card-header">stosb</div>
<div class="card-body" markdown="1">

- **指令格式**：stosb / rep stosb
- **指令作用**：把字节 al 存入 es:[di] 中，并移动 di
- **注意**：di 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字节，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">stosw</div>
<div class="card-body" markdown="1">

- **指令格式**：stosw / rep stosw
- **指令作用**：把字 ax 存入 es:[di] 中，并移动 di
- **注意**：di 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字，否则移向上一个

</div>
</div>

#### 从字符串取指令

<div class="card" markdown="1">
<div class="card-header">lodsb</div>
<div class="card-body" markdown="1">

- **指令格式**：lodsb
- **指令作用**：从 ds:[si] 读取一个字节存入 al，并移动 si
- **注意**：si 的移动与 df 有关，预先用 cld std 设置，df=0 则 si 移向下一个字节，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">lodsw</div>
<div class="card-body" markdown="1">

- **指令格式**：lodsw
- **指令作用**：从 ds:[si] 读取一个字存入 ax，并移动 si
- **注意**：si 的移动与 df 有关，预先用 cld std 设置，df=0 则 si 移向下一个字，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">lods</div>
<div class="card-body" markdown="1">

- **指令格式**：
    - lods byte ptr seg:[si]
    - lods word ptr seg:[si]
- **指令作用**：从 seg:[si] 读取一个字节/字存入 al/ax，并移动 si
- **注意**：seg 可以是 cs ds es ss 中任意一个。si 的移动与 df 有关，预先用 cld std 设置，df=0 则 si 移向下一个字节/字，否则移向上一个

</div>
</div>

### 控制转移指令

#### 无条件跳转指令

无条件跳转指令 jmp 有三种形式，即短跳、近跳、远跳，其操作码和操作数均不同

<div class="card" markdown="1">
<div class="card-header">jmp 短跳</div>
<div class="card-body" markdown="1">

- **指令格式**：jmp dest / jmp short dest
- **指令作用**：将 ip 指针赋值为 dest，即跳转到 dest
- **注意**：dest 只能为立即数，且目标地址 dest 与下条指令的偏移地址之间距离在范围 [-128, 127] 内。会编码为两字节（EBxx，后两位为距离）

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">jmp 近跳</div>
<div class="card-body" markdown="1">

- **指令格式**：jmp dest
- **指令作用**：将 ip 指针赋值为 dest，即跳转到 dest
- **注意**：dest 为立即数或寄存器或内存，如果是立即数则目标地址与下条指令偏移地址之间距离在 [-32768, 32767] 内。会编码为三字节

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">jmp 远跳</div>
<div class="card-body" markdown="1">

- **指令格式**：jmp dest
- **指令作用**：将 cs:ip 赋值为 dest，即跳转到 dest
- **注意**：cs 也会改变，dest 可以是立即数或内存，如果是立即数要写成 段地址:偏移地址 的形式，如果是内存则存储的第一个字表示偏移地址、第二个字表示段地址

</div>
</div>

#### 条件跳转指令

<div class="card" markdown="1">
<div class="card-header">j<em>cc</em> 类指令</div>
<div class="card-body" markdown="1">

- **指令格式**：j*cc* dest
- **指令作用**：如果与标志位有关的条件 *cc* 成立，则令 ip 等于 dest，即跳转到 dest
- **注意**：这些跳转都是短跳，需要目标地址与下条指令偏移地址距离在 [-128, 127] 内

??? abstract "所有此类指令及条件"

    |指令|意义|条件|备注|
    |:--:|:--:|:--|:--:|
    |jz|等于零则跳|zf=1|等价于 je|
    |jnz|不等于零则跳|zf=0|等价于 jne|
    |jc|有进位则跳|cf=1|等价于 jb jnae|
    |jnc|无进位则跳|cf=0|等价于 jnb jae|
    |js|有符号位则跳|sf=1||
    |jns|无符号位则跳|sf=0||
    |jo|有溢出位则跳|of=1||
    |jno|无溢出位则跳|of=0||
    |jp/jpe|有奇偶位则跳|pf=1||
    |jnp/jpo|无奇偶位则跳|pf=0||
    |ja/jnbe|无符号大于则跳|cf=0 and zf=0||
    |jae/jnb|无符号大于等于则跳|cf=0|等价于 jnc|
    |jb/jae|无符号小于则跳|cf=1|等价于 jc|
    |jbe/jna|无符号小于等于则跳|cf=1 or zf=1||
    |jg/jnle|有符号大于则跳|sf=of and zf=0||
    |jge/jnl|有符号大于等于则跳|sf=of||
    |jl/jnge|有符号小于则跳|sf!=of||
    |jle/jng|有符号小于等于则跳|sf!=of or zf=1||
    |je|相等则跳|zf=1|等价于 jz|
    |jne|不相等则跳|zf=0|等价于 jnz|

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">jcxz</div>
<div class="card-body" markdown="1">

- **指令格式**：jcxz dest
- **指令作用**：如果 cx 等于零则令 ip 等于 dest 即跳转到 dest
- **注意**：属于短跳，需要目标地址与下条指令偏移地址距离在 [-128, 127] 内

</div>
</div>

#### 循环指令

<div class="card" markdown="1">
<div class="card-header">loop</div>
<div class="card-body" markdown="1">

- **指令格式**：loop dest
- **指令作用**：cx 表示循环次数，cx 先减 1，如果 cx 不为 0 则跳转到 dest
- **注意**：dest 是立即数，loop 属于短跳，需要目标地址与下条指令偏移地址距离在 [-128, 127] 内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">loopz</div>
<div class="card-body" markdown="1">

- **指令格式**：loopz dest
- **指令作用**：如果等于零则循环，先 cx 减 1（此处不影响标志位），然后如果 cx != 0 且 zf == 1 则跳转到 dest
- **注意**：dest 是立即数，loopz 属于短跳，需要目标地址与下条指令偏移地址距离在 [-128, 127] 内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">loope</div>
<div class="card-body" markdown="1">

- **指令格式**：loope dest
- **指令作用**：如果相等则循环
- **注意**：完全等价于 loopz

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">loopnz</div>
<div class="card-body" markdown="1">

- **指令格式**：loopnz dest
- **指令作用**：如果不等于零则循环，先 cx 减 1（此处不影响标志位），然后如果 cx != 0 且 zf == 0 则跳转到 dest
- **注意**：dest 是立即数，loopnz 属于短跳，需要目标地址与下条指令偏移地址距离在 [-128, 127] 内

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">loopne</div>
<div class="card-body" markdown="1">

- **指令格式**：loopne dest
- **指令作用**：如果不相等则循环
- **注意**：完全等价于 loopnz

</div>
</div>

#### 子程序调用与返回指令

call 类似 jmp 的近跳远跳也有近过程调用和远过程调用，其区别也在于 cs 是否发生变化

<div class="card" markdown="1">
<div class="card-header">call 近调用</div>
<div class="card-body" markdown="1">

- **指令格式**：call dest
- **指令作用**：将下条指令偏移地址入栈然后跳转到 dest，即 push ip, ip = dest
- **注意**：dest 可以是立即数或寄存器或内存

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">retn</div>
<div class="card-body" markdown="1">

- **指令格式**：retn / ret / retn count / ret count
- **指令作用**：近返回
    - retn / ret：从栈中弹出一个十六位数到 ip，即 pop ip
    - retn count / ret count：先 pop ip 然后 sp += count
- **注意**：如果有 count 则 count 是立即数，一般用于从 call 近调用返回

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">call 远调用</div>
<div class="card-body" markdown="1">

- **指令格式**：call dest
- **指令作用**：push cs, push ip, cs:ip = dest
- **注意**：dest 可以是立即数或内存，如果是立即数要写成 段地址:偏移地址 的形式，如果是内存则存储的第一个字表示偏移地址、第二个字表示段地址

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">retf</div>
<div class="card-body" markdown="1">

- **指令格式**：retf / retf count
- **指令作用**：远返回，pop ip, pop cs，若有 count 则 sp += count
- **注意**：如果有 count 则 count 是立即数，一般用于从 call 远调用返回

</div>
</div>

#### 中断和中断返回指令

中断指令一般用于向系统提出中断请求得到系统的服务，可以看作调用系统提供的函数

<div class="card" markdown="1">
<div class="card-header">int</div>
<div class="card-body" markdown="1">

- **指令格式**：int n
- **指令作用**：调用 n 号中断，等效的操作有
    - pushf, push cs, push ip
    - tf = 0, if = 0, ip = word ptr 0:[n\*4], cs = word ptr 0:[n\*4+2]
- **注意**：n 为立即数，称为中断号，在范围 [0, 0FFh] 内，if tf 是否清空由不同处理器决定

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node fl-special">IF</td>
    <td class="fl-table-node fl-special">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">into</div>
<div class="card-body" markdown="1">

- **指令格式**：into
- **指令作用**：溢出中断，如果 of == 1 则调用 4 号中断（int 4h），if tf 是否清空由不同处理器决定

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node fl-special">IF</td>
    <td class="fl-table-node fl-special">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">iret</div>
<div class="card-body" markdown="1">

- **指令格式**：iret
- **指令作用**：中断返回，等效操作有 pop ip, pop cs, popf
- **注意**：一般用于从 int 或 into 产生的中断中返回，标志位回到中断前的状态

</div>
</div>

### 杂类指令

<div class="card" markdown="1">
<div class="card-header">clc</div>
<div class="card-body" markdown="1">

- **指令格式**：clc
- **指令作用**：清空进位位，即 cf = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">stc</div>
<div class="card-body" markdown="1">

- **指令格式**：stc
- **指令作用**：设置进位位，即 cf = 1

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cmc</div>
<div class="card-body" markdown="1">

- **指令格式**：cmc
- **指令作用**：进位位求反，即 cf = ~cf

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cld</div>
<div class="card-body" markdown="1">

- **指令格式**：cld
- **指令作用**：清空方向位，即 df = 0（正方向）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node fl-special">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">std</div>
<div class="card-body" markdown="1">

- **指令格式**：std
- **指令作用**：设置方向位，即 df = 1（负方向）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node fl-special">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">cli</div>
<div class="card-body" markdown="1">

- **指令格式**：cli
- **指令作用**：禁止中断，即 if = 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node special">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">sti</div>
<div class="card-body" markdown="1">

- **指令格式**：sti
- **指令作用**：允许中断，即 if = 1

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node fl-special">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node">SF</td>
    <td class="fl-table-node">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header">nop</div>
<div class="card-body" markdown="1">

- **指令格式**：nop
- **指令作用**：无操作，机器码 90h，占用一个字节空间，且消耗运行时间，但不进行操作

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">hlt</div>
<div class="card-body" markdown="1">

- **指令格式**：hlt
- **指令作用**：停止处理器工作，直到系统复位或发送非屏蔽中断或外部中断

</div>
</div>

## 8086 汇编程序编写

### 汇编程序基本结构

```asm
data segment                            ; 汇编指示语句
hey  db 'Hello,world!', 0Dh, 0Ah, '$'   ; 伪指令语句
data ends                               ; 汇编指示语句

code segment                            ; 汇编指示语句
assume cs:code, ds:data                 ; 汇编指示语句
main:                                   ; 指令语句
    mov ax, data                        ; ...
    mov ds, ax
    mov ah, 9
    mov dx, offset hey
    int 21h
    mov ah, 4Ch
    int 21h
code ends                               ; 汇编指示语句
end main                                ; 汇编指示语句
```

### 段的定义、假设与引用
#### 段定义
```asm
<segmentname> segment [<align>] [<combine>] ['<class>']
    <statements>
<segmentname> ends
```

方括号中可以省略

- align：对齐方式，byte word dword para page（para 为 16 字节，page 为 256 字节）缺省为 para
- combine：合并类型，public stack common memory at，public 一般用于代码段数据段，stack 用于堆栈段
    - ss 自动初始化为堆栈段的段地址，sp 自动初始化为堆栈段末尾字节偏移地址加 1
    - 代码段数据段可以省略 public，堆栈段不能省略 stack
- 'class'：类别名

数据段定义时初始数据伪指令为 `变量名（标号名）、大小、内容`，大小即为 db dw dd 等。如果重复可以用 `大小 内容 dup(次数)` 的形式

堆栈段定义一般使用：
```asm
stk segment stack
db 100h dup(0)
stk ends
```
即开启一个 100h 大小的堆栈

#### 段的假设
assume 用来建立段寄存器与段的关系，帮助汇编编译程序补充段地址

一般写为 `#!asm assume cs:code ds:data ss:stk` 的形式，这样解析变量时就可以自动填充段地址，比如使用 `#!asm mov ah, [abc]` 来引用 data 段中变量 abc，abc 的段地址为 data，而通过 assume 知道 data 就是 ds，因此会被解释为 `#!asm mov ah, ds:[...]`

虽然 cs 和 ss 会自动赋值为段地址，但 ds 和 es 不会，需要在代码段里手动修改

#### 段的引用
直接写段名就是段地址。使用 `seg 变量名` 或 `seg 标号名` 即表示变量/标号所在的段地址

### 程序的结束
#### 源程序的结束
使用 end 指令结束，格式为 `#!asm end 标号名`，指定程序从标号处开始运行

#### 程序段前缀
程序段前缀（Program Segment Prefix，PSP）是一段长度为 100h 字节的内存。DOS 在运行程序时，先为程序分配一个 PSP，然后 DOS 读取改程序内容装入 PSP 后面的内存中，最后把 ds 和 es 设置为 PSP 段地址，把 ss 和 sp 设置为堆栈段段地址和堆栈段最后一个字节的偏移地址加 1，再把 cs 设置为代码段段地址，ip 设置为源程序中 end 指定标号的偏移地址，然后程序从 cs:ip 开始运行

PSP 里面存放了与程序运行有关的重要信息，比如命令行参数、环境块段地址、父程序的 PSP 段地址等

#### 程序的终止
通常调用 21h 号中断的 4C 号功能终止，如：
```asm
mov ah, 4Ch
mov al, 返回码
int 21h
```

### 汇编程序语句

- 空白不敏感
- 常数可以使用整型常数、字符常数、字符串常数（拆为字符）
- 可以使用常数表达式作为常数，有 + - * / mod shl shr not and or xor seg offset，常数表达式中不能出现寄存器等，只能是常数
- 可以使用 eql 和 = 定义符号常数
    - = 的右侧只能是数值类型或字符类型的常数或常数表达式，可以对同一符号重新定义
    - eql 的右侧还可以是字符串、汇编语句（`#!asm dosint eql <int 21h>`），但不能对同一符号重新定义
- 变量名和标号名的命名：可以是 52 个大小写字母、10 个数字、以及 @\$?\_，数字不能开头，\$ 与 ? 不能单独使用，一般不区分大小写（编译时加上 /ml 区分大小写）
- 标号定义
    - `#!asm 标号名:` 即可
    - 或者 `#!asm 标号名 label near|far|byte|word|dword`
        - near far 标识近标号和远标号
        - byte word dword 标识标号为变量
- 变量的引用可以直接使用变量名或者 [变量名]
- 可以使用 变量名[偏移] 来类似数组引用值，但偏移记得偏移 1 就是加一个字节，而不是下一个元素

### 子程序设计

子程序又称过程，即类似高级语言中的函数，通过 call 调用 ret 返回，可以近调用或远调用。过程的定义：
```asm
<name> proc <attribute>
    ...
<name> endp
```
其中 attribute 为 near 或 far，near 定义近过程供近调用，只能在同一代码段内起作用；far 定义远过程供远调用，可以在同一代码段或不同代码段内使用

如果达到函数的效果也可以不定义过程，只定义一个标号，然后使用 ret / retn 返回

过程中要保护某些寄存器的值，此时要在过程开头 push 入堆栈，结尾从堆栈 pop 回来

#### 堆栈传递参数
使用堆栈传递参数有三种标准方式
##### __cdecl 方式
c 语言的标准方式，参数从右到左压入堆栈，并且由调用者清理堆栈。
```asm
f:
    push bp
    mov bp, sp
    ...
    mov sp, bp
    pop bp
    ret

main:
    ...
    push a2         ; 压入参数
    push a1
    call f
    add sp, 4       ; 清理堆栈
```
##### __pascal 方式
pascal 语言的标准方式，参数从左到右压入堆栈，由被调用者清理堆栈。
```asm
f:
    push bp
    mov bp, sp
    ...
    mov sp, bp
    pop bp
    ret 4

main:
    ...
    push a1
    push a2
    call f
```

##### __stdcall 方法
Windows API 的标准方法，参数从右到左压入堆栈，由被调用者清理堆栈

#### 动态变量与堆栈结构

比如 c 语言的规范，在函数中会有动态局部变量，这些变量会存放在堆栈上。函数开头先 push bp 存下前帧指针，然后 mov bp, sp 将 bp 移动到栈顶。之后可以 sub sp, ... 来向上移动 sp 指针，这样就可以为函数留出堆栈上的一部分空间，这些空间被用来存放局部变量。执行过 sub sp, ... 后的堆栈结构如：
```text
+-------------+
|             |     <- sp
+-------------+     \
|             |      |
+-------------+      |
|             |      |
+-------------+      |- 局部变量空间
|             |      |
+-------------+      |
|             |      |
+-------------+     /
|      bp     |     <- bp
+-------------+
| return addr |     <- 由 call 压入
+-------------+
|     arg0    |     <- [bp+4]
+-------------+
|     arg1    |     <- [bp+6]
+-------------+
|     ...     |
+-------------+
```
如图即为通过 sub sp, 10 开辟了 10 个字节的局部变量空间，此时再进行 push 和 pop 操作时则会向上增长不会覆盖该函数的空间。

参数和局部变量也都通过 bp 来访问，比如参数从 [bp+4] 开始是第一个参数，然后 [bp+6] 是第二个，……。局部变量都是通过 [bp-...] 来进行访问的

这样的帧栈结构在函数退出时先 mov sp, bp，此时 sp 回落回 bp 的位置，局部变量全部失效，然后 pop bp 取出前帧指针，再 ret，此时 pop 出返回地址返回，然后在调用者处情况堆栈中的参数

C 语言的函数里 bp 不要被更改，同样也需要保护 bx si di 的值，使其在调用函数前后不变，且函数的返回值由 ax 提供，所以一般的函数写法就是：
```asm
f:
    push bp
    mov bp, sp
    sub sp, ...
    push bx
    push si
    push di
    ...             ; [bp+?] 为参数
    ...             ; [bp-?] 为局部变量
    mov ax, ...     ; 设置返回值
    pop di
    pop si
    pop bx
    mov sp, bp
    pop bp
    ret
```
这种写法下帧栈结构和寄存器都不会乱掉，即使是进行递归也没有问题


### 中断
中断是在 CPU 运行期间遇到某些情况暂时中止当前程序，去执行另一段特殊处理程序的过程。分为内部中断和外部中断，内部中断一般就是由 int 指令或者 CPU 的某些错误或者调试服务引起的，外部中断一般就是时钟中断、键盘中断等

中断调用与返回在前面指令部分有介绍

#### 中断向量
中断向量即中断服务程序入口的地址，为 4 个字节，前两个字节为偏移地址，后两个字节为段地址

系统中一共有 256 个中断号，范围在 00h 到 0FFh，段地址 0000h 处为中断向量表，中断向量的地址位于 0000:[4\*中断号]，例如 word ptr 0:[20h] 存放 8h 时钟中断的偏移地址，word ptr 0:[22h] 存放时钟中断的段地址

#### 更改中断向量
可以直接通过令 es 为 0，通过 es:[...] 的方式来更改中断向量，但程序结束后并不会改回来，而产生错误。因此要在改之前存下原来的中断向量，程序结束前再改回原来的中断向量

??? example "例"

    ```asm
    code segment
    assume cs:code
    old_00h dw 0, 0
    int_00h:
        mov ch, 10h
        iret
    main:
        push cs
        pop ds
        xor ax, ax
        mov es, ax
        mov bx, 0
        mov ax, es:[bx]
        mov dx, es:[bx+2]
        mov old_00h[0], ax
        mov old_00h[2], dx
        mov word ptr es:[bx], offset int_00h
        mov es:[bx+2], cs
        mov ax, 123h
        mov ch, 1
        div ch
        mov ax, old_00h[0]
        mov dx, old_00h[2]
        mov es:[bx], ax
        mov es:[bx+2], dx
        mov ah, 4Ch
        int 21h
    code ends
    end main
    ```

#### 除法溢出

除法溢出有两种情况：

- 除以 0 会溢出
- 商无法保存到 al 或 ax 中，会发生溢出

溢出的时候会在 div 指令的前面插入一条 `#!asm int 00h` 并运行，DOS 执行 0 号中断会输出溢出信息并终止程序

因此也就可以修改 0 号中断的中断向量，使之继续运行，0 号中断退出后仍会重新运行刚刚出现问题的 div 指令，一个例子见上（即修改中断向量的那个例子）

#### 时钟延迟

#### DOS 中断
DOS 中断即是 int 21h，它作为一个函数集包含了标准输入/输出、文件管理、内存管理、进程管理的中断调用，提供了诸多子功能（ah 为功能号），完整见 [Ralf Brown's Interrupt List](../asm_int_list/intr/int.htm)，下面是一些常用功能

<div class="card" markdown="1">
<div class="card-header">AH=01h</div>
<div class="card-body" markdown="1">

- **功能**：输入字符功能
- **作用**：从键盘读入单个字符，如果是 Ctrl-Break 则退出，否则将键值送入 al 中

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">AH=02h</div>
<div class="card-body" markdown="1">

- **功能**：输出字符功能
- **作用**：将 dl 以字符的形式（ASCII）打印出来

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">AH=09h</div>
<div class="card-body" markdown="1">

- **功能**：输出字符串功能
- **作用**：将 ds:dx 处字符串输出，该字符串必须以 '$' 结尾

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">AH=0Ah</div>
<div class="card-body" markdown="1">

- **功能**：输入字符串功能
- **作用**：ds:dx 为一个 buf，buf 的第一个字节为允许输入的最多字符数，中断后第二个字节变为实际输入的字符数，第三个字节开始是输入的字符内容。如果输入超过最大字符数，则会发出铃声，并且光标不再移动

</div>
</div>

<div class="card" markdown="1">
<div class="card-header">AH=4Ch</div>
<div class="card-body" markdown="1">

- **功能**：终止程序功能
- **作用**：退出当前程序，返回码为 al（DOS 中不会处理，可以不写）

</div>
</div>

### BIOS 中断

<div class="card" markdown="1">
<div class="card-header">int 10h</div>
<div class="card-body" markdown="1">

- **类型**：视频中断
- **子功能**：ah = 00h 号功能切换显示模式
    - al = 03h 表示 80\*25 文本模式
    - al = 13h 表示 320\*200\*256 图形模式

</div>
</div>

#### 文本模式编程
程序运行时默认终端就处于文本模式，可以直接通过写入相应内存地址来更改显示文本的内容

整个文本模式的屏幕左上角坐标为 (0, 0)，右下角坐标为 (79, 24)。内存结构为一个字表示一个字符（高 8 位为显示的字符，低 8 位中高 4 位为背景色，低 4 位为前景色），(x, y) 位置处的字符对应内存位于 word ptr B800:[(y\*80+x)\*2] 处

编程时先设置 es 为 0B800h，然后计算出 bx = (y\*80+x)\*2，然后令 byte ptr es:[bx] = 字符，byte ptr es:[bx+1] = 颜色

#### 图形模式编程
把显卡切换到图形模式使用 int 10h 中断，`#!asm mov ax, 0013h` 设置子功能号为 0，模式编号 al 为 13h 即图形模式，然后 `#!asm int 10h` 即可切换到图形模式，这种情况下是 320*200 分辨率、256 色的模式。

屏幕上的一个点对应显卡内存上的一个字节，表示颜色。点 (x, y) 位于内存 0A00:[320*y+x] 的位置，颜色：
```text
0 黑    1 蓝    2 绿    3 青    4 红    5 洋红
6 棕    7 白    8 灰    9 亮蓝  A 亮绿  B 亮青
C 亮红  D 紫    E 黄    F 亮白
```
编程时设置 es 为 0A00h，然后向 byte ptr es:[...] 中写入颜色码即可更改某处像素点颜色

再使用 `#!asm mov ax, 0003h` 后 `#!asm int 10h` 切换回文本模式

## 80x86 增加指令

### 80186

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>insb</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：insb / rep insb
- **指令作用**：(input from port to string) 等价于 in al, dx; mov es:[di], al 并移动 di
- **注意**：di 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字节，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>insw</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：insw / rep insw
- **指令作用**：(input from port to string) 等价于 in ax, dx; mov es:[di], ax 并移动 di
- **注意**：di 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>outsb</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：outsb / rep outsb
- **指令作用**：(output string to port) 等价于 mov al, ds:[si]; out al, dx 并移动 si
- **注意**：si 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字节，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>outsw</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：outsw / rep outsw
- **指令作用**：(output string to port) 等价于 mov ax, ds:[si]; out ax, dx 并移动 si
- **注意**：si 的移动与 df 有关，预先用 cld std 设置，df=0 则 di 移向下一个字，否则移向上一个

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>pusha</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：pusha
- **指令作用**：push 所有通用用途寄存器，顺序从先到后为 ax cx dx bx sp bp si di

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>popa</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：popa
- **指令作用**：pop 到所有通用用途寄存器，顺序从先到后为 di si bp sp bx dx cx ax

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>立即数语法扩展</span>
    <span>80186</span>
</div>
<div class="card-body" markdown="1">

- push 可以直接接立即数
- imul shl shr sal sar rol ror rcl rcr 第二个操作数可以是立即数

</div>
</div>

### 80286

80286 增加了保护模式及相关指令，不写在这里了

### 80386

80386（即 i386）升级到了 32 位架构，寄存器均变为 32 位（以 e 开头），增加了 fs gs 两个附加数据段寄存器。一些指令从 8086 自然扩展支持 32 位，不在此赘述

#### bit 相关指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bt</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：bt src, pos
- **指令作用**：(bit test) 将 src 的第 pos 位拷贝到 cf 中
- **注意**：src 是寄存器或内存单元，pos 是寄存器或立即数（从右向左从零开始数）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bts</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：bts src, pos
- **指令作用**：(bit test and set) 将 src 的第 pos 位拷贝到 cf 中后将其设为 1
- **注意**：src 是寄存器或内存单元，pos 是寄存器或立即数（从右向左从零开始数）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>btr</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：btr src, pos
- **指令作用**：(bit test and reset) 将 src 的第 pos 位拷贝到 cf 中后将其设为 0
- **注意**：src 是寄存器或内存单元，pos 是寄存器或立即数（从右向左从零开始数）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>btc</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：btc src, pos
- **指令作用**：(bit test and complement) 将 src 的第 pos 位拷贝到 cf 中后将其反转
- **注意**：src 是寄存器或内存单元，pos 是寄存器或立即数（从右向左从零开始数）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-undefined">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bsf</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：bsf dest, src
- **指令作用**：(bit scan forward) 在 src 中搜索最低位的 1 对应索引存放在 dest 中
- **注意**：dest 是寄存器，src 是寄存器或内存单元。如果 src 是 0 则 dest 不变，zf 置为 1 否则为 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-special">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>bsr</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：bsr dest, src
- **指令作用**：(bit scan reverse) 在 src 中搜索最高位的 1 对应索引存放在 dest 中
- **注意**：dest 是寄存器，src 是寄存器或内存单元。如果 src 是 0 则 dest 不变，zf 置为 1 否则为 0

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-undefined">SF</td>
    <td class="fl-table-node fl-special">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">CF</td>
</tr>
</table>


</div>
</div>

#### 数据转移指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>movsx</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：movsx dest, src
- **指令作用**：(move with sign-extension) 将 src 符号扩展到 dest
- **注意**：dest 为寄存器，src 为寄存器或内存单元。可以 8 -> 16、8 -> 32、16 -> 32

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>movzx</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：movsx dest, src
- **指令作用**：(move with zero-extension) 将 src 零扩展到 dest
- **注意**：dest 为寄存器，src 为寄存器或内存单元。可以 8 -> 16、8 -> 32、16 -> 32

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>pushad</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：pushad
- **指令作用**：将 32 位通用用途寄存器压入堆栈，顺序从先到后为 eax ecx edx ebx esp ebp esi edi
- **注意**：pusha 仍为压入 16 位寄存器

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>popad</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：popad
- **指令作用**：pop 出 32 位通用用途寄存器，顺序从先到后为 edi esi ebp esp ebx edx ecx eax
- **注意**：popa 仍为弹出 16 位寄存器

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>pushfd</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：pushfd
- **指令作用**：将 eflags 压入堆栈
- **注意**：pushf 仍为 16 位（即 eflags 的低 16 位）

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>popfd</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：popfd
- **指令作用**：从堆栈弹出到 eflags
- **注意**：popf 仍为 16 位（即 eflags 的低 16 位）

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">OF</td>
    <td class="fl-table-node fl-affected">DF</td>
    <td class="fl-table-node fl-affected">IF</td>
    <td class="fl-table-node fl-affected">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">CF</td>
</tr>
</table>

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lss</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：lss dest, src
- **指令作用**：将 src 处远指针装入 ss:dest
- **注意**：dest 是寄存器，src 是 m16:16 或 m16:32

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lfs</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：lfs dest, src
- **指令作用**：将 src 处远指针装入 fs:dest
- **注意**：dest 是寄存器，src 是 m16:16 或 m16:32

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>lgs</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：lgs dest, src
- **指令作用**：将 src 处远指针装入 gs:dest
- **注意**：dest 是寄存器，src 是 m16:16 或 m16:32

</div>
</div>

#### 转换指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>cdq</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：cdq
- **指令作用**：将 eax 扩充为 edx:eax（直接拼接），即将 eax 符号位扩展到 edx

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>cwde</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：cwde
- **指令作用**：将 ax 符号扩充为 eax
- **注意**：cwd 仍为将 ax 扩充到 dx:ax

</div>
</div>

#### 运算指令

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>imul 语法扩展</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：imul dest, src
- **指令作用**：（支持传入两个操作数）dest = dest * src，截取结果的低位存入 dest
- **注意**：dest 为寄存器，src 为寄存器或存储单元。结果对于有符号数乘法和无符号数乘法相同

</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>shld</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：shld r1, r2, imm / shld r1, r2, cl
- **指令作用**：r1 = r1<<cl ∣ r2>>(register_width - cl)
- **注意**：r1 是寄存器或内存单元，r2 是寄存器，第三个操作数是 cl 或 8 位立即数。cf 为移出的最后一位，如果移位为 1 且符号位发生了改变，则 of 为 1 反之为 0，如果移位大于 1，则 of undefined

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>shrd</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：shrd r1, r2, imm / shrd r1, r2, cl
- **指令作用**：r1 = r1>>cl ∣ r2<<(register_width - cl)
- **注意**：r1 是寄存器或内存单元，r2 是寄存器，第三个操作数是 cl 或 8 位立即数。cf 为移出的最后一位，如果移位为 1 且符号位发生了改变，则 of 为 1 反之为 0，如果移位大于 1，则 of undefined

<table class="fl-table" style="margin-top: 0.6em">
<tr>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special fl-undefined">OF</td>
    <td class="fl-table-node">DF</td>
    <td class="fl-table-node">IF</td>
    <td class="fl-table-node">TF</td>
    <td class="fl-table-node fl-affected">SF</td>
    <td class="fl-table-node fl-affected">ZF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-undefined">AF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-affected">PF</td>
    <td class="fl-table-node"></td>
    <td class="fl-table-node fl-special">CF</td>
</tr>
</table>


</div>
</div>

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>set<em>cc</em> 类指令</span>
    <span>80386</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：set*cc* dest
- **指令作用**：如果 *cc* 满足，则将字节 dest 设为 1，否则设为 0
- **注意**：*cc* 同 j*cc*，dest 为 8 位寄存器或字节大小存储单元

</div>
</div>

#### 字符串类指令

针对 32 位新增 CMPSD LODSD SCASD STOSD MOVSD INSD OUTSD 七个字符串相关指令，意义均和 8086 / 80186 类似，不再赘述

#### 控制转移指令

针对 32 位新增 IRETD 指令（与 IRET 相同，机器码也相同），JECXZ 指令（jump if ecx equal zero）不再赘述


## 80386 保护模式原理

### 实模式与保护模式的区别

- 实模式（real mode）
    - 段地址和偏移地址均为 16 位
    - 段地址*10h + 偏移地址 = 物理地址
    - 每个段的最大长度 = 10000h 字节
    - 每个段同时具有 Read Write eXecute 属性
    - 操作系统和用户代码没有权限上的差别，都是 ring0（最高权限）
- 保护模式（protected mode）
    - 段地址和偏移地址可以是 16位:16位 也可以是 16位:32位
    - gdt[段地址].base_addr + 偏移地址 = 物理地址
    - 每个段的最大长度 = 4G 字节
    - 数据段的属性：只读、读写
    - 代码段的属性：只执行不可读、可执行可读
    - 操作系统和用户代码有权限上的差别，操作系统为 ring0，用户代码为 ring3

阻止 ring3 的代码访问 ring0 的数据：

```asm
mov ax, 段地址
mov ds, ax          ; 这一步会被限制
mov ebx, 偏移地址
mov al, ds:[ebx]
```

当段寄存器被赋值的时候，CPU 会进行权限检查，把当前 cs 的低 2 位和段地址对应的描述符所包含的 DPL 进行比较如果 “cs.cpl <= 段地址->描述符.DPL” 则允许访问，否则产生 General Protection Fault

CPL（current privilege level）即 cs 的低 2 位，表示当前程序的权限，DPL（descriptor privilege level）表示段地址对应描述符的权限。意义即是 ring?，数字越小权限越大

### 段描述符

gdt（global descriptor table）全局描述符表，是一个结构数组，每个元素均为 8 字节。

程序中的段地址实际上叫 selector，selector 对应的描述符为 gdt+(selector&0FFF8h) 处的 8 字节（即丢掉 selector 的低 3 位）

```text
gdt+00h
gdt+08h
                    +---+---+-base_addr--+
                    |   |   |            |
                    --  --  --          --
gdt+10h     FF, FF, 00, 80, 0B, F3, 0F, 00      ; 整体 8 字节是段地址 10h 的描述符（descriptor）
            ~~  ~~              ==  ^~
            +---+---------------|---|+
                |               |   +-- Granularity = bit 7
                |               +-- DPL = bit 6, 5 = 11
                +-- limit           ||
                                    ||
                       1111 0011 <- 0F
                       |--| | ||
                       |  | | |+-- Accessed 
                       |  | | +-- bit 1
                       |  | +-- bit 3
                       |  +-- S
                       +-- Present = bit 7
gdt+18h
```

- 第 5 个字节的第 6、5 个 bit 为 DPL
    - 例上面 10h 段的 DPL 为 11b 即 3（F3 -> 1*11*1 0011）
- 第 2、3、4、7 个字节为段起始地址 base_addr，小端序
    - 例上面 10h 段的段起始地址为 000B8000h
- 第 0、1 个字节和第 6 个字节的后半个字节为最大偏移地址 limit，小端序
    - 例上面 10h 段的最大偏移地址为 0FFFFFh，最小偏移地址为 0，所以段长度为 100000h 即 1M
- 第 6 个字节的第 7 个 bit 为粒度 Granularity，当该位为 1 时，limit 的单位变成 page（页，一页为 4k=1000h 字节）
    - 例如如果 limit 为 FFFFF，G 为 1，则最大偏移地址变为 FFFFFFFF（最后一页的地址为 [FFFFF000, FFFFFFFF]）
- 第 5 个字节的其它 bit
    - 第 7 bit 为 Present，表示该段是否存在
    - 第 4 bit 为 S，S = 1 表示是数据段或代码段，0 则是系统描述符（包括下面的 call gate）
    - 第 3 bit 为 0 表示是数据段，1 表示是代码段
    - 第 1 bit，如果是数据段，则 1 表示可写，代码段时 1 表示可读
    - 第 0 bit 为 Accessed 表示描述符是否被访问过
    
段地址（其实叫 selector）10h 对应的描述符的 DPL 为 11，即权限为 ring3（DPL 为 3（最低）的时候所有程序都是有权访问的）

假设前面那段代码中赋值给 ax 的段地址为 10h，cs 为 08h（0000 10*00*），则 cs.cpl = 00，于是 cs.cpl < 10h->descriptor.DPL，因此当前程序有权把 ds 赋值为 10h，即有权访问该段中的数据

若段描述符描述的是一个数据段，则访问者的 CPL 必须**小于等于**该段描述符的 DPL。若段描述符描述的是一个代码段，则访问者的 CPL 必须**等于**该段描述符的 DPL 才能 jmp、call 到该段里面的函数

当访问者的 CPL 大于某个代码段描述符的 DPL 时，则只能用 call call_gate_selector:0 这样的方式间接调用该代码段中的函数

### call gate
call gate 即调用门，可以看作低权限调用高权限函数的跳板。它本身需要用 8 个字节来描述，格式例如：

```text
            +---+--------------------+---+-- 目标函数偏移地址
            |   |                    |   |
            --  --                  --  --
gdt+20h     78, 56, 08, 00, 02, EC, 34, 12
                    ==  ==  ^^  ~~
                    |    |  |   |
            +-------|----|--|---+---- 属性
            |       |    |  +---- 参数的个数
            |       +----+---- 目标函数的段地址（selector）
            |
            EC = 1110 1100
                 |==^ ----
                 || | |
                 || | +-- type，0C 即表示是 32 位调用门
                 || +-- S = 0，是系统描述符
                 |+-- DPL
                 +-- Present
```

当 gdt 里的 S = 0 时，表示当前描述符是一个系统描述符而不是数据段或代码段的描述符。系统描述符有 tss（task state segment）描述符、task gate 描述符、interrupt gate 描述符、trap gate 描述符等，S = 0 且 type = 1100b 时即表示当前描述符是 32 位的调用门

属性中的 DPL 是 call gate 自己的权限而不是目标函数的权限，目标函数的 DPL 要通过第 2、3 字节的 selector 找到对应描述符的 DPL

调用 call gate 时的权限比较：

1. 调用者的 CPL <= call_gate_selector->descripter.DPL
2. 调用者的 CPL >= call_gate_selector->descriptor.target_selector->descriptor.DPL


CPU 从 ROM 启动后进入实模式，而实模式的权限都是 ring0，可以在实模式中执行 retf 来降级到 ring3。构造 jmp far ptr tss_selector:0 可以从 ring0 强行跳回 ring3（需要构造 tss 与对应的描述符）

以 memset(p, 0, n) 为例，ring0 函数如何防止 ring3 传递一个恶意的指针如 ring0 指针 p。ring3 进程假如不调用 memset()，而是自己做 *p = ... 的写入一定会触发 GPF(General Protect Fault) 即在该指令前插入并调用 int 0Dh

假设在 ring3 中调用 memset(p, 0, 1) p = 0x2800000000（假设 0x28 这个 selector 对应段的 DPL 是 0）
```asm
push 1
push 0
push 28h
push 0
call far ptr call_gate_to_memset:0
```
当这条 call 发生时，ring3 的堆栈中仅有 call 指令上方 push 的参数，并没有下条指令的段地址和偏移地址。CPU 会从当前进程的 tss（task state segment，通过 ltr 指令赋值）中取出 ss0 及 esp0 作为新的堆栈指针（ss = ss0, esp = esp0），进行堆栈切换。之后进行的操作有：

1. push ring3 的 ss、push ring3 的 esp
2. 把 ring3 中的参数全部复制到 ring0 堆栈中
3. push ring3 的 cs、push ring3 的 eip
4. jmp 目标函数

memset 函数中会取出调用者的 cs，取出 CPL 与参数 p 段地址的 DPL 进行比较

```asm
memset:
    push ebp
    mov ebp, esp
    mov cx, [ebp+8]     ; 调用者 ring3 的 cs
    mov ax, [ebp+10h]   ; 28h
    arpl ax, cx         ; adjust request privilege level
                        ; 会把 cx 的低 2 位复制给 ax 的低 2 位，即 ax 变为 2Bh
    mov ds, ax          ; 这里会触发 GPF
                        ; CPU 进行权限检查，当 cs.cpl <= 28h 段的 DPL 
                        ; && ax.rpl <= 28h 段的 DPL 时才能赋值成功（ax.rpl 即 ax 的低 2 位）
```

<div class="card" markdown="1">
<div class="card-header" style="display: flex;justify-content: space-between;">
    <span>arpl</span>
    <span>保护模式</span>
</div>
<div class="card-body" markdown="1">

- **指令格式**：arpl dest, src
- **指令作用**：（adjust request privilege level）当 src 的低 2 位大于 dest 的低 2 位时，会把 src 的低 2 位复制给 dest 的低 2 位
- **注意**：dest 为寄存器或内存，src 为寄存器

</div>
</div>

