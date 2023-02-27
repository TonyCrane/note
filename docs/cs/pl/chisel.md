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

## 基础组件
### 类型及常量
