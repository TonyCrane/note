---
counter: True
comment: True
---

# Yul 语言

!!! abstract
    Yul 是一门编写以太坊虚拟机程序的中间语言。它旨在同时提供可读性、清晰的控制流、简单的字节码转换和优化。在编写有长度限制的合约代码时较为常用。

    官方文档：[docs.soliditylang.org > Yul](https://docs.soliditylang.org/en/latest/yul.html)

## 语法
- 注释和 solidity 同样使用 `//` 和 `/* */`
- 标识符可以包含 `.`

### 字面量
- 整数字面量
    - 直接使用十进制来表示
    - 使用 0x 以十六进制表示
    - 必须小于 $2^{256}$，无符号，大端存储
- 字符串
    - 双引号包裹，最长 32 字节
    - 可以使用 `\xNN` 指定 hex 值，或者 `\uNNNN` 来指定一个 Unicode 码位（会转为 UTF-8 存储）
    - 存储时右侧补 0（即左对齐），大端
- 十六进制字符串
    - hex 开头加引号，例如 hex"616263"
    - 字节序列不超过 32 字节（64 个十六进制字符）
    - 存储同字符串
- 布尔值
    - 小写 true false
- 默认情况下都是 u256，通过冒号加 `u8`、`u32`、`u64`、`u128` 将可以指定其它大小
    - 目前并没有实现这些内容，不能通过编译

### 变量
- 声明
    - 使用 let 关键字来进行声明
    - 变量的作用域只在当前大括号范围内（声明之后）
    - 变量存储在栈上，不会直接影响到 memory 和 storage（要使用 mload mstore sload sstore 等）
    - 如果类型不为 u256，需要使用冒号加类型名来指定（尚未实现）
        ```yul
        {
            let zero:u32 := 0:u32
            let v:u256, t:u32 := f()
        }
        ```
- 当变量被引用时，会复制一份（利用 DUP 指令）
- 变量赋值
    - 使用 := 来进行变量的赋值
    - 可以同时赋值多个变量，左右两侧变量个数需要相等
    - 同一变量不能多次出现在 := 左侧
    - 可以重复赋值来覆盖
    ```yul
    let v := 0
    v := 2
    let t := add(v, 2)
    ```

### 控制流语句
- if 语句
    ```yul
    if <condition> { <body> }
    ```
    - 只有 if，没有 else（需要的话可以使用 switch）
- switch 语句
    - 比较常规，switch-case-default 结构
    ```yul
    ...
    switch calldataload(4)
    case 0 {
        x := calldataload(0x24)
    }
    default {
        x := calldataload(0x44)
    }
    ...
    ```
    - 至少有一种情况（包括 default）
    - 所有 case 同一类型
    - 如果所有情况都被覆盖了，则不允许出现 default
- for 循环
    ```yul
    for { <init> } <condition> { <post> } { <body> }
    ```
    - 大括号不可少
    - 可以使用 break 和 continue
    ```yul
    {
        let x := 0
        for { let i := 0 } lt(i, 0x100) { i := add(i, 0x20) } {
            x := add(x, mload(i))
        }
    }
    ```
    - 可以达到 while 循环的效果：
        ```yul
        for { } <condition> { } { <body> }
        ```

### 函数
- 函数定义
    ```yul
    function <name>(<param1>, <param2>, ...) -> <return1>, <return2>, ... { <body> }
    ```
    - 返回值直接写在 -> 后面
    - 只在定义的大括号内有效
    - 通过 leave 关键字来退出当前函数
        - 此时返回值直接使用当前返回变量中现有的值
        - return 是一个 EVM 指令，用于退出当前执行上下文（内部消息调用），而不仅仅是当前函数
    - 此时定义的函数只是一个普通的可以内部调用的函数，而不是 solidity 中可供外部调用的合约接口
    - 函数定义在整个块（大括号）中可见（即使在定义之前）
    - 参数和返回参数必须不同
    - 函数内部不能使用函数外的变量
- 函数调用
    - 正常通过括号调用
- 例如：
    ```yul
    mstore(0x80, add(mload(0x80), 3))
    ```
    - 可以直接被翻译为 `PUSH1 3 PUSH1 0x80 MLOAD ADD PUSH1 0x80 MSTORE`
    ```yul
    function f(x, y) -> a, b { ... }
    let x, y := f(1, mload(0))
    ```
    - 参数从右向左传入（先将右侧的压入栈）
    - 返回值右侧的在栈顶
- 内置 EVM 函数
    - 一般为 EVM 指令名小写，参数也与 EVM 指令的栈输入一致（栈顶在参数列表左侧）
    - 一些稍有不同的：
        - SHA3 指令，对应函数名为 keccak256
        - 没有提供 jump 系列指令（JUMP、JUMPI、JUMPDEST）因为会混淆控制流
        - 没有提供 DUP、SWAP、PUSH 系列指令，因为会混淆栈操作
        - 提供了一个 invalid() 函数来从未知指令终止执行
- 其它内置函数
    - datasize(x): 返回 Yul object 中某部分的数据大小
    - dataoffset(x): 在字节码中的偏移量
    - datacopy(t, f, l): 复制到内存中（等价于 codecopy）

### Yul 对象
- 一个 Yul object 至少由一个 code 块组成（而且最多一个 code），还可以有 data 块和 object 块，例如：
    ```yul
    object "object1" {
        code {
            ...
        }
        object "object2" {
            code {
                ...
            }
        }
        data "data1" hex"..."
    }
    ```
- code 即执行的代码，object 可以看成合约，那么 code 就是 constructor
- 叫做 ".metadata" 的 data 不能从代码中访问，它会直接附加在字节码的最末尾
- 例如一个合约可以写为：
    ```yul
    object "Contract" {
        code {
            sstore(0, caller())
            datacopy(0, dataoffset("runtime"), datasize("runtime"))
            return(0, datasize("runtime"))
        }
        object "runtime" {
            code {
                require(iszero(callvalue())) // not payable
                switch selector()
                case ... {
                    ...
                }
                case ... {

                }
                ...
                default {
                    revert(0, 0) // no fallback function
                }
                
                function ...
                ...
            }
        }
    }
    ```

## 编译
Remix 上就可以选择编译源语言为 Yul。