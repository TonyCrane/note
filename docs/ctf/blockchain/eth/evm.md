---
comment: True
counter: True
---

# 以太坊虚拟机

!!! abstract
    以太坊的智能合约会在 EVM（Ethereum Virtual Machine，以太坊虚拟机）上运行。本文主要介绍 EVM 的基础知识。

    参考

    - [Ethereum Virtual Machine (EVM) Opcodes](https://ethervm.io/)
    - [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
    - [Ethereum Developer Documentation](https://ethereum.org/en/developers/docs/evm)
    - [Ethereum EVM Illustrated](https://takenobu-hs.github.io/downloads/ethereum_evm_illustrated.pdf)

## EVM 简介
EVM 是一个栈结构的虚拟机，没有寄存器，栈的深度最大 1024，每个元素都是 256 位（32 字节）的。同时在执行期间会维护一个瞬时内存（memory），其执行后不会持久存在。

EVM 有一套指令集，每条指令都有一个 8 位的 opcode，指令的参数可以是立即数、栈元素等。

## EVM 字节码
完整的 EVM 字节码及解释可见：[ethervm.io](https://ethervm.io/)，这里进行一下分类：

### 运算指令

没有特殊说明都是在模 2^256 的意义下进行运算。

!!! note
    下面表格中的栈输入、栈输出均是左侧为栈顶

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 01 | ADD | a, b | a + b | |
| 02 | MUL | a, b | a * b | |
| 03 | SUB | a, b | a - b | |
| 04 | DIV | a, b | a // b | uint256 除法 |
| 05 | SDIV | a, b | a // b | int256 除法 |
| 06 | MOD | a, b | a % b | uint256 取模 |
| 07 | SMOD | a, b | a % b | int256 取模 |
| 08 | ADDMOD | a, b, c | (a + b) % c |  |
| 09 | MULMOD | a, b, c | (a * b) % c |  |
| 0a | EXP | a, b | a ** b |  |
| 0b | SIGNEXTEND | b, x | signextend(x, b) | 将 x 从 (b+1)*8 位符号扩展到 256 位 |

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 10 | LT | a, b | a < b | |
| 11 | GT | a, b | a > b | |
| 12 | SLT | a, b | a < b | int256 比较 |
| 13 | SGT | a, b | a > b | int256 比较 |
| 14 | EQ | a, b | a == b | |
| 15 | ISZERO | a | a == 0 | |
| 16 | AND | a, b | a & b | |
| 17 | OR | a, b | a \| b | |
| 18 | XOR | a, b | a ^ b | |
| 19 | NOT | a | ~a | |
| 1a | BYTE | i, x | x[i] | 取 x 的第 i 个字节（从高位算） |
| 1b | SHL | a, b | b << a | |
| 1c | SHR | a, b | b >> a | 逻辑右移 |
| 1d | SAR | a, b | b >> a | 算数右移 |

| 字节码 | 名称 | 栈输入 | 栈输出 |
| :--- | :--- | :--- | :--- |
| 20 | SHA3 | offset, length | keccak256(mem[offset:offset+length]) |

### 特殊指令
一些以太坊特有的指令，比如取一些交易信息、区块信息等

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 30 | ADDRESS |  | address | 当前合约地址 |
| 31 | BALANCE | addr | addr.balance |  |
| 32 | ORIGIN |  | tx.origin |  |
| 33 | CALLER |  | msg.sender |  |
| 34 | CALLVALUE |  | msg.value |  |
| 35 | CALLDATALOAD | i | msg.data[i:i+32] |  |
| 36 | CALLDATASIZE |  | len(msg.data) |  |
| 38 | CODESIZE |  | len(this.code) |  |
| 3a | GASPRICE |  | tx.gasprice |  |
| 3b | EXTCODESIZE | addr | len(addr.code) |  |
| 3d | RETURNDATASIZE |  | len(returndata) | 上一次调用的返回数据长度 |
| 3f | EXTCODEHASH | addr | keccak256(addr.code) | 地址不存在则返回 0 |
| 40 | BLOCKHASH | number | block.blockHash(blockNumber) |  |
| 41 | COINBASE |  | block.coinbase |  |
| 42 | TIMESTAMP |  | block.timestamp |  |
| 43 | NUMBER |  | block.number |  |
| 44 | DIFFICULTY |  | block.difficulty |  |
| 45 | GASLIMIT |  | block.gaslimit |  |
| 46 | CHAINID |  | chainid |  |
| 47 | SELFBALANCE |  | this.balance |  |
| 48 | BASEFEE |  | block.basefee |  |

| 字节码 | 名称 | 栈输入 | 描述 |
| :--- | :--- | :--- | :--- |
| 37 | CALLDATACOPY | memOffset, dataOffset, length | mem[memOffset:memOffset+length] = msg.data[dataOffset:dataOffset+length] |
| 39 | CODECOPY | memOffset, codeOffset, length | mem[memOffset:memOffset+length] = this.code[codeOffset:codeOffset+length] |
| 3c | EXTCODECOPY | addr, memOffset, codeOffset, length | mem[memOffset:memOffset+length] = addr.code[codeOffset:codeOffset+length] |
| 3e | RETURNDATACOPY | memOffset, dataOffset, length | mem[memOffset:memOffset+length] = returndata[dataOffset:dataOffset+length] |

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 58 | PC | | pc | 当前指令的位置 |
| 59 | MSIZE | | mem.length | 内存大小 |
| 5a | GAS | | gas | 剩余 gas |

### 存储指令
EVM 执行时有三个存储位置：

- 栈（stack）：通过 PUSH、POP 系列在当前执行的栈上进行读写
- 内存（memory）：通过 MLOAD、MSTORE 系列在当前执行的内存上进行读写
- 链上存储（storage）：通过 SLOAD、SSTORE 系列在当前合约的存储区进行读写（是持久化的）

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 50 | POP | a |  |  |
| 51 | MLOAD | offset | mem[offset:offset+32] |  |
| 52 | MSTORE | offset, value |  | mem[offset:offset+32] = value |
| 53 | MSTORE8 | offset, value |  | mem[offset] = value |
| 54 | SLOAD | key | storage[key] |  |
| 55 | SSTORE | key, value |  | storage[key] = value |

并且提供了很多 PUSH 指令，分别处理不同大小的输入立即数：

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 60 | PUSH1 |  | uint8 | 压入一个 1 字节的值 |
| 61 | PUSH2 |  | uint16 | 压入一个 2 字节的值 |
| ... | ... | ... | ... | ... |
| 7f | PUSH32 |  | uint256 | 压入一个 32 字节的值 |

以及一些栈上的数据操作，即 DUP 和 SWAP，分别表示复制栈上某处数据到栈顶以及交换栈上两个数据：

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 80 | DUP1 | a | a, a | 将栈顶数据复制一份到栈顶 |
| 81 | DUP2 | _, a | a, _, a | 复制栈上第 2 个数据到栈顶 |
| 82 | DUP3 | \_, \_, a | a, \_, \_, a | 复制栈上第 3 个数据到栈顶 |
| ... | ... | ... | ... | ... |
| 8f | DUP16 | ... | ... | 复制栈上第 16 个数据到栈顶 |
| 90 | SWAP1 | a, b | b, a | 交换栈顶两个数据 |
| 91 | SWAP2 | a, _, b | b, _, a | 交换栈上第 2 个数据和栈顶数据 |
| 92 | SWAP3 | a, \_, \_, b | b, \_, \_, a | 交换栈上第 3 个数据和栈顶数据 |
| ... | ... | ... | ... | ... |
| 9f | SWAP16 | ... | ... | 交换栈上第 16 个数据和栈顶数据 |

### 跳转指令
EVM 的跳转比较特别，它不能随意跳转到任何位置，只能跳转到一个 JUMPDEST 指令的位置。

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| 56 | JUMP | dest |  | 跳转到 dest 位置 |
| 57 | JUMPI | dest, cond |  | 如果 cond 非 0 则跳转到 dest 位置 |
| 5b | JUMPDEST |  |  | 标记一个跳转目标 |

### 日志指令
在链上记录日志，也就是 event。

| 字节码 | 名称 | 栈输入 | 描述 |
| :--- | :--- | :--- | :--- |
| a0 | LOG0 | offset, length | LOG0(mem[offset:offset+length]) |
| a1 | LOG1 | offset, length, topic0 | LOG1(mem[offset:offset+length], topic0) |
| ... | ... | ... | ... |
| a4 | LOG4 | offset, length, topic0~3 | LOG4(mem[offset:offset+length], topic0~3) |

### 创建合约地址指令
创建合约地址有两种指令，CREATE 和 CREATE2，后者是君士坦丁堡硬分叉后引入的。

| 字节码 | 名称 | 栈输入 | 栈输出 | 描述 |
| :--- | :--- | :--- | :--- | :--- |
| f0 | CREATE | value, offset, length | address |  |
| f5 | CREATE2 | value, offset, length, salt | address |  |

### 调用、返回、自毁指令
#### 远程调用指令
EVM 中远程调用有四种：

- call：远程调用，如果有状态修改，修改的是被调用合约的状态
- callcode：远程调用，如果有状态修改，修改的是调用合约的状态（不建议使用，由 delegatecall 取代）
- delegatecall：远程调用，如果有状态修改，修改的是调用合约的状态
- staticcall：远程调用，不能存在状态修改

其中 callcode 和 delegatecall 的区别是，对于一个调用：Alice 通过交易调用了合约 A，合约 A 中通过某一远程调用调用了合约 B，那么：

- callcode：合约 A 中的 msg.sender 是 Alice，合约 B 中的 msg.sender 是 A
- delegatecall：合约 A 和 B 中的 msg.sender 都是 Alice

| 字节码 | 名称 | 栈输入 | 栈输出 |
| :--- | :--- | :--- | :--- |
| f1 | CALL | gas, to, value, argsOffset, argsLength, retOffset, retLength | success |
| f2 | CALLCODE | gas, to, value, argsOffset, argsLength, retOffset, retLength | success |
| f4 | DELEGATECALL | gas, to, argsOffset, argsLength, retOffset, retLength | success |
| fa | STATICCALL | gas, to, argsOffset, argsLength, retOffset, retLength | success |

#### 返回指令
返回指令也可以算为两种，一种是 RETURN 正常返回，另一种是 REVERT 异常回滚（同时 REVERT 会回滚所有的状态修改）。

| 字节码 | 名称 | 栈输入 | 描述 |
| :--- | :--- | :--- | :--- |
| f3 | RETURN | offset, length | return mem[offset:offset+length] |
| fd | REVERT | offset, length | revert mem[offset:offset+length] |

#### 自毁指令
自毁即 solidity 代码中的 selfdestruct，销毁当前合约，并将所有余额转移到指定地址。

| 字节码 | 名称 | 栈输入 | 描述 |
| :--- | :--- | :--- | :--- |
| ff | SELFDESTRUCT | address | selfdestruct(address) |

## EVM 逆向
有时题目不会给出合约源码，这时就需要对字节码进行逆向。一些常用的网站：

- [ethervm.io/decompile](https://ethervm.io/decompile)
- [dedaube Contract Library](https://library.dedaub.com/decompile)
- [etherscan](https://etherscan.io/contractsVerified)
- Binary Ninja 的插件 [:material-github: crytic/ethersplay](https://github.com/crytic/ethersplay)
- etherscan 上也是有逆向功能的