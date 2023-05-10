---
counter: True
comment: True
---

# Chisel

> The Constructing Hardware in a Scala Embedded Language (Chisel) is an open-source hardware description language (HDL) used to describe digital electronics and circuits at the register-transfer level. Chisel is based on Scala as an embedded domain-specific language (DSL). Chisel inherits the object-oriented and functional programming aspects of Scala for describing digital hardware. Using Scala as a basis allows describing circuit generators. High quality, free access documentation exists in several languages.
> 
> Circuits described in Chisel can be converted to a description in Verilog for synthesis and simulation.
> 
> <div style="text-align: right">———— 维基百科</div>

!!! abstract
    自学 Chisel 的笔记。

    参考：

    - [Chisel Book](http://www.imm.dtu.dk/~masca/chisel-book.pdf)

## 环境配置等
Chisel 环境的整体框架可以理解为 Chisel 是 Scala 的一个库，Scala 是基于 JVM 的语言，所以要安装 Java 环境和 Scala。而且 Chisel 的编译结果是 Verilog 代码，所以要想综合、仿真、上板等则需要额外配置用的 FPGA 板子相应的工具。

Chisel book 上说 Scala 依赖于 Java JDK 1.8 或更高版本，或者使用 OpenJDK 8 或 11，反正 Java 的版本号我就没看懂过，电脑上恰好有 JDK 1.8 我就能跑就行了。

然后 mac 上庄 Scala 只需要装下 sbt（scala build tool）：`brew install sbt`。book 上还说要装 GTKWave，这个可以通过 `brew install homebrew/cask/gtkwave` 来安装，不过看起来是个显示波形的，目前没用上。

推荐的 IDE 是 IntelliJ IDEA，不过 vsc 也不是不能用，而且也推荐了一个扩展 Scala (Metals)，还可以。

### 测试
可以用 chisel book 提供的 chisel-examples 来测试：

```bash
$ git clone https://github.com/schoeberl/chisel-examples.git
$ cd chisel-examples/hello-world
$ sbt run
```

在下载一堆模块后，正常的话可以在当前目录下看到 Hello.v 即编译出来的 verilog 代码，配合 verilog/hello_top.v 顶层模块就可以使用了。

也可以通过 `sbt test` 来进行测试，这里会模拟实际运行情况，并产生输出等。

## Chisel 构建流程及测试



## 基础组件
### 类型及常量
- Bits、UInt、SInt 都表示一系列比特构成的向量，不过含义不同
    - Bits 只是一个比特序列
    - UInt 表示一个无符号整数
    - SInt 表示一个有符号整数，负数采用补码表示
- 需要以 *type*(*Width*) 的形式来指定位宽
    - 位宽写法为 *数值*.W，比如 8.W
    - UInt(8.W) 表示一个 8 位的无符号整数，SInt(10.W) 表示一个 10 位的有符号整数
- Chisel 中的常量可以以类似写法 *数值*.*类型缩写* 表示
    - 0.U 表示一个无符号常量 0，-3.S 表示一个有符号常量 -3
    - 可以同样规定位宽，比如 3.U(4.W) 表示一个 4 位的无符号常量 3
    - **注意**：易错的地方是 3.U(4.W) 不能写为 3.U(4)，因为 (4) 表示取第 4 位的比特，后面会用到
- 其他常量字面量
    - 可以通过字符串加类型来使用其他进制，开头用 h/o/b 标注，比如以下均表示 255：
        - "hff".U
        - "o377".U
        - "b1111_1111".U
    - 也可以通过字符串表示其 ASCII 码，比如 'A'.U
- 布尔类型 Bool
    - 值有 true.B 和 false.B
- 使用 val 关键字定义变量

### 组合逻辑电路
- 使用布尔运算符即可描述组合逻辑电路
    - 比如 `#!scala val logic = (a & b) | c`
- 位运算符
    - `& | ^ ~` 分别表示与、或、异或、非
    - `<< >>` 分别表示左移、右移
- 逻辑运算符
    - `&& || !` 分别表示与、或、非，只能用在 Bool 类型上
    - `=== =/=` 分别判断是否相等/不等
    - `> >= < <=` 用于比较大小
- 算数运算符：
    - `+ -` 加减/负，结果的位宽是两个操作数中较大的那个
        - `+& -&` 会扩展一位
    - `*` 乘，结果的位宽是两个操作数的位宽之和
    - `/ %` 除和取模，结果的位宽**一般**是第一个操作数的位宽
- 可以先通过 val 定义一个 Wire 变量，然后通过 := 操作符来更新赋值
    ```scala
    val w = Wire(Uint())
    w := a & b
    ```
- 其他内置硬件函数，下中 v、a、b 均表示变量，可以是 UInt 和 SInt
    - v.andR v.orR v.xorR 规约操作，即对所有位依次进行位运算
    - v(n) 提取 v 的某一位（最右一位为 0 号）
    - v(end, start) 提起 v 的 [end:start] 位
    - a ## b，将 b 接在 a 后面（即 a 在高位），也可写为 Cat(a, b, ...)
- 多路选择器
    - `#!scala val result = Mux(sel, a, b)`
    - sel 为 true.B 时结果为 a，否则为 b
    - a 和 b 可以是任意 Chisel 类型，但要保证二者相同

### 寄存器
- Chisel 内置提供了寄存器，具体实现为 D 锁存器
- 寄存器会隐式连接到一个全局的 clock 和 reset 上，当 clock 到达上升沿则更新
- 几种寄存器
    - 普通 Reg
        - Reg(t, next, init)
            - t 表示寄存器数据类型
            - next 是数据的输入端，也是寄存器延迟一个周期的输出（跟随的变量）
            - init 是复位时的输出
        - 使用上可以直接 `#!scala val reg = Reg(UInt(8.W))`，这样就会自动连接到全局的 clock 和 reset 上
            - 可以通过 `#!scala reg := next` 来更新 
            - 可以通过 `#!scala val out = reg` 来读取
    - RegNext
        - RegNext(next)
            - 在每个上升沿都会将值更新为跟随的变量值，跟随变量初始为 next，后续进行赋值后则跟随新的变量
            - 比如 `#!scala val reg = RegNext(a)` 则会转化为如下 verilog 代码：
                ```verilog
                always @(posedge clock) begin
                    reg <= a;
                end
                ```
        - RegNext(next, init)
            - 带有复位值
            ```verilog
            always @(posedge clock) begin
                if (reset) begin
                    reg <= init;
                end else begin
                    reg <= next;
                end
            end
            ```
    - RegInit 即带有初始值，可以不用显示赋值就开始使用
    - RegEnable(next, init, enable)，带一个使能端，只有 enable 为 true.B 时才会更新
- 比如一个从 0 到 9 不断计数的寄存器就可以写为
    ```scala
    val cntReg = RegInit(0.U(8.W))
    cntReg := Mux(cntReg === 9.U, 0.U, cntReg + 1.U)
    ```

### 打包结构
Chisel 提供了两种将信号打包的类型，分别是 Bundle 和 Vec，分别类似于结构体和数组。同时它们可以创建新的 Chisel 类型并且可以嵌套。

#### Bundle
- 类似于 C 中的结构体，可以将不同类型的信号包裹起来并且命名
- 通过 class 并继承 Bundle 来创建一个新的 Bundle 类型：
    ```scala
    class Channel extends Bundle {
        val data = UInt(32.W)
        val valid = Bool()
    }
    ```
- 通过 new 来创建然后包装在 Wire 中使用：
    ```scala
    val ch = Wire(new Channel())
    ch.data := 123.U
    ch.valid := true.B
    val b = ch.valid
    val channel = ch
    ```

#### Vec
- 类似于 C 中的数组，可以将**相同类型**的信号打包成数组
- Vec 一般有几种用途
    - 硬件中的动态寻址，可以用作多路选择器
    - 可以用来构建寄存器组
    - 组合 Module 的接口
    - 其他用途推荐使用 Seq
- 组合逻辑中的 Vec
    - 使用 Vec 创建后包裹在 Wire 中
    - Vec 的第一个参数为元素个数，第二个参数为元素类型
    ```scala
    val v = Wire(Vec(3, UInt(4.W)))
    v(0) := x
    v(1) := y
    v(2) := z
    val muxOut = vec(select)
    ```
    - 可以使用 VecInit 来创建有初始值的 Vec
        - 此时不需要包裹在 Wire 中，因为它已经是一个 Chisel 硬件类型了
        ```scala
        val defVecSig = VecInit(d, e, f)
        val vecOutSig = defVecSig(select)
        ```
- 寄存器组
    - 使用 Vec 创建后包裹在 Reg 中
    - 用法和前面类似，只是行为和寄存器相同而不是 wire
    - 比如可以使用 `#!scala val registerFile = Reg(Vec(32, UInt(32.W)))` 来创建一个 32 个 32 位寄存器的寄存器组
    - 可以结合 RegInit 和 VecInit 创建带初始化值的寄存器组
        ```scala
        val initReg = RegInit(VecInit(Seq.fill(32)(0.U(32.W))))
        ```

### 硬件类型
- UInt、SInt、Bits 都是 Chisel 的数据类型，它们不表示任何硬件结构
- 将它们包装进 Wire、Reg、IO 等才会生成硬件
    - Wire 表示组合逻辑
    - Reg 表示寄存器（由 D 锁存器构成）
    - IO 表示一个 module 的接口
- 任何 Chisel 数据类型都可以包装进 Wire、Reg、IO
- 通过 `#!scala val number = Wire(UInt())` 创建一个不可变的 scala 变量
    - 后续通过 := 操作符来更新值，但不可使用 =
        - = 是 Scala 的赋值操作符，用来**创建**硬件
        - := 是 Chisel 的赋值操作符，用来给**已经存在**的硬件（重新）赋值
- 可以通过 WireDefault 来创建带有初始值的 Wire
    ```scala
    val number = Wire(UInt())
    number := 10.U
    // 等价于
    val number = WireDefault(10.U(4.W))
    ```
