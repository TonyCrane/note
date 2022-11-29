---
comment: True
counter: True
---

# 以太坊基础

!!! abstract
    一些 ETH 题目中会用到的以太坊基础知识

## 基础环境
- [Remix](https://remix.ethereum.org/)：以太坊智能合约 IDE
- [MetaMask](https://metamask.io/)：以太坊钱包
- [Etherscan](https://etherscan.io/)：以太坊区块链浏览器
- [geth](https://geth.ethereum.org/)：交互工具

## 账户
以太坊中的账户（Account）分为两类，分别是外部账户（Externally Owned Account, EOA）和合约账户（Contract Account）。

- 外部账户
    - 由人创建的，相当于钱包，可以存储以太币，发送交易等
    - 每个外部账户都有一对公私钥，用于签署交易等
        - 私钥是一个 256 位数（32 字节）
        - 公钥由私钥经 ECDSA 计算而来，是一个 64 字节的数
        - 地址是公钥计算 keccak256 哈希后取后 20 字节的值（一般表示为 0x + 40 个十六进制字符）
- 合约账户
    - 合约账户是由外部账户通过交易创建的账户，其中包含合约代码
    - 合约地址
        - CREATE 操作码：通过创建者地址、交易的 nonce 值共同计算 keccak256 哈希得到
        - CREATE2 操作码（君士坦丁堡硬分叉后）：通过创建者地址、盐值、合约创建代码计算得到
    - 合约账户同样也可以存储、拥有以太币
    - 向一个合约账户发送交易相当于调用合约中的函数
    - 合约账户不能自行发起交易，但可以在被调用时向外发送交易

这两类账户都是 “状态对象”，一个以太坊账户包含：

- nonce：已经发送的交易数量
- balance：账户余额，即存储的以太币数量
- storageRoot：存储区的哈希值，指向合约账户的存储数据区
- codeHash：代码区的哈希值，指向合约账户存储的智能合约代码

### 以太币单位
以太币的最小单位是 wei，其是一个很小的单位，一些其他单位：

- 1 Kwei (1 Babbage) = $10^3$ wei
- 1 Mwei (1 Lovelace) = $10^6$ wei
- 1 Gwei (1 Shannon) = $10^9$ wei
- 1 Szabo (1 microether) = $10^{12}$ wei
- 1 Finney (1 milliether) = $10^{15}$ wei
- 1 Ether = $10^{18}$ wei

单位换算：[Ethereum Unit Converter](https://converter.murkin.me/)

## 交易
以太坊中的交易（Transaction）指的是从一条账户发送到另一条账户的消息的签名数据包，无论是转账还是创建智能合约、调用智能合约都是通过交易进行的。每一笔交易也会支付一定的手续费。

### 交易内容
一条交易包含以下内容：

- from：交易发送者地址
- to：交易接收者地址，如果为空则表示是在创建智能合约
- value：交易金额，即发送方要给接收方转移的以太币数量（wei 为单位）
- data：交易数据，如果是创建智能合约则是智能合约代码，如果是调用智能合约则是调用的函数名和参数
- gasPrice：交易的 gas 价格，即每单位 gas 的价格（wei 为单位）
- gasLimit：交易的 gas 上限，即交易允许执行的最大 gas 数量
- nonce：交易的序号，即发送者已经发送的交易数量

除此之外发送的交易数据包还需要包含：

- hash：交易的哈希值，由前面的内容和 chainId 计算得到
- v、r、s：交易签名的三个部分，由发送者私钥对交易哈希值进行签名得到

#### 三种交易
以太坊的交易可以分为三种场景：

- 转账交易：从一个账户向另一个账户发送以太币
    - 必须要指定 from、to、value，分别表示发送者、接收者、转移的以太币数量（其它字段有默认值）
    - 交易数据包中的 data 为空
    - 接收方可以是 EOA 也可以是合约账户
- 创建合约交易：创建一个合约账户（将合约部署到链上）
    - 必须要指定 from、data，分别表示发送者、合约代码（编译后的字节码）
    - 交易数据包中的 to 为空
- 调用合约交易：调用一个合约账户的函数
    - 必须要指定 from、to、data，分别表示发送者、接收者、调用的信息
    - data 字段是编码后的函数名（选择子）和参数

### 交易手续费
每笔交易都需要支付一定的手续费，来补偿执行时的计算开销，同时也会支付给矿工作为打包交易的奖励。

手续费不是由以太币直接计算的，而是通过 gas 来作为单位，通过 gasPrice 与以太币进行换算。

gasPrice 是一单位 gas 对应的以太币价值（wei 为单位），gasLimit 是交易发送者愿意为这笔交易支付的最大 gas 数量。在交易执行时，会消耗 gas，如果消耗的 gas 数量小于 gasLimit，则交易成功执行，矿工会收取实际消耗的 gas * gasPrice 的手续费；如果执行过程中消耗的 gas 超过了 gasLimit，则交易失败，会回滚（revert）到交易执行前的状态，同时矿工会收取 gasLimit * gasPrice 的手续费。

## 合约
合约账户和创建合约、调用合约的交易在前面已经说过了。下面是一些关于合约的实现、原理等内容。

### 编写合约
合约一般是使用 Solidity 语言进行编写的，除此之外也有 Yul 等语言。关于 Solidity 的语法就不在这里写了。

合约编写后需要通过编译器编译成 EVM 可执行的字节码。相关字节码在另外的章节来写（TODO）

总之可以使用 Remix IDE 来进行合约的编写、编译、部署、调试等操作。

### 合约的创建
前面说到了合约要通过交易来进行创建，这个交易的 to 字段应该为空，且 data 字段为编译后的合约字节码。

在执行交易时，这个 data 字段的内容会被放在 EVM 上执行，它可以是任意可执行的字节码，遇到 return 指令直接返回，也可以返回结果（且有回显）。

一般的合约字节码会分为两个部分，即 creationCode 和 runtimeCode。它们是拼接在一起的一个整体。在 EVM 运行字节码时，先执行 creationCode 部分，其作用是运行构建函数、设置合约初始状态，然后返回 runtimeCode，这个将会被部署到链上代码区。之后在链上存储的就只是 runtimeCode 部分，也是调用时会执行的实际部分。

如果合约的构建函数是 payable 的，那么可以在创建交易的时候通过 value 字段来附带以太币，这些以太币会被转移到合约账户中。如果不是 payable 但创建时向其转账了，那么这条交易会 revert。

### 合约的调用
合约的调用也是通过交易来进行的，这个交易的 to 字段应该为合约账户地址，data 字段为编码后的函数名和参数，称为 calldata。

calldata 分为两个部分，开头四个字节会表明要调用的函数，也被称为 function selector；后面的部分是函数的参数。

#### Selector
Selector 是函数签名的 keccak256 哈希值的前四个字节。

其中函数签名：

- 基础原型是由函数名称加上括号括起来的参数类型列表，参数类型之间用逗号分隔且无空格
- 对于 uint 类型要转成 uint64
- 对于结构体，会将其成员类型展开并用括号括起来

在进行一个调用的时候，会先将 data 中的 selector 与合约中的函数签名进行比对：

- 如果存在相同的函数签名，那么就会调用这个函数
- 如果不存在：
    - 如果存在 fallback 函数，那么就会调用 fallback 函数
    - 否则 revert

相应的逻辑是在合约编译的时候写在 runtimeCode 里的，其大致逻辑是：
```text
if (msg.value) { revert(); } // 如果不是 payable 的话会有这句
if (msg.data.length == 0) { fallback(); } // 如果没有 fallback 就 revert
if (msg.data[0:4] == selector1) {
    function1();
} else if (msg.data[0:4] == selector2) {
    function2();
} else {
    fallback(); // 如果有 fallback
    // revert(); // 如果没有 fallback
}
```

### 合约中获取数据
Solidity 中有一些全局变量可以用来获取区块信息、交易信息等：

- block.chainid、block.coinbase、block.number、block.timestamp……
- msg.data：完整的 calldata
- msg.sender：当前调用者的地址
- msg.sig：selector，也就是 calldata 的前四个字节
- msg.value：交易中附带的以太币数量（wei）
- tx.gasprice：交易的 gasprice
- tx.origin：交易的发起者（整条调用链最开头的账户）

## 存储
以太坊会为合约提供一个存储空间，其存储相当于一个 $2^{256}$ 大小的数组，数组中每个元素称为插槽（slot），每个插槽的大小是 256 位，也就是 32 字节。整体容量非常巨大，但存储是稀疏的，即只会存储有值的插槽。

Solidity 规定了合约内变量的存储方式，大致是：

- 单个值类型
    - 以低位对齐（右对齐）的方式存储在一个插槽中
    - 一个基本类型只会占据它所需的空间，比如 uint8 只会占用 1 字节
    - 如果当前插槽还可以容纳下一个值，则下一个值继续在当前插槽存储（在当前值“左边”）
    - 如果当前插槽容纳不下下一个值，则下一个值会存储在下一个插槽中
    - 对于结构体，存储时一定会新开一个插槽，其内部存储仍然按照上面的规则
    - 例如如下合约的存储：
        ```solidity
        contract C {
            address a;
            uint8 b;
            uint256 c;
            bytes24 d;
        }

        // -----------------------------------------------------
        // | unused (11) | b (1) |            a (20)           | <- slot 0
        // -----------------------------------------------------
        // |                       c (32)                      | <- slot 1
        // -----------------------------------------------------
        // | unused (8) |                d (24)                | <- slot 2
        // -----------------------------------------------------
        ```
- 映射
    - 即 solidity 中的 mapping
    - 例如 mapping(address => uint256) a
        - 会先在如上顺序存储中占据一整个插槽（slot p）
        - 映射中键 addr 对应的值会存在 keccak256(addr . p) 的插槽中（. 表示连接）
- 动态数组
    - 同样在顺序存储中占据一整个插槽 slot p，其内容是该动态数组现在的长度
    - 数组内容存储的开头是 slot keccak(p)
- 字节数组和字符串
    - 如果长度小于 32 字节
        - 和单个值类型一样，存储在一个插槽中，高位对齐（左对齐）
        - 该插槽最低位会存储 length * 2
    - 如果长度超过了 31 字节
        - 当前占据一整个插槽（slot p）存储 length * 2 + 1
        - 数组内容实际存储的开头是 slot keccak(p)

以太坊上的这些存储都是公开的，即使在 Solidity 中规定了是 private 变量，也不会在存储中隐藏。这些存储可以通过 rpc 的 eth_getStorageAt 接口来读取，即 getStorageAt(address, slot)。

## 交互
在 geth（Go Ethereum）实现的以太坊协议中，可以通过 rpc（remote process call，远程过程调用）的方式来和以太坊网络进行交互。

### geth
geth 是以太坊官方提供的一个实现了以太坊协议的客户端，是以太坊网络的一个入口点。geth 的 rpc 接口可以通过 http 或者 websocket 来访问，也可以通过 ipc 来访问。

可以通过 geth 来创建节点，也可以连接到已有的以太坊网络、测试网络、私有网络，也可以通过 geth 来搭建私链。

一般对于 CTF 题目来说会有一个已经搭好的私链，然后给出一个 rpc 接口，可以通过 geth attach 的方式连接然后执行命令。具体的命令用法就不写了。

一般的 CTF 题目会使用 [:material-github: chainflag/eth-challenge-base](https://github.com/chainflag/eth-challenge-base) 来搭建环境，其中包含了私链、防火墙、水管（faucet，用于发放 eth）以及题目接口。这个防火墙为了防止爬链找别人的交易会只保留几个 rpc 方法，通过 geth 来执行这些命令部署合约、发送交易是比较不方便的，所以一般使用 web3.js / web3.py 来进行交互。

### web3.py
web3.py 是一个 python 的以太坊 rpc 客户端。由于 challenge base 的防火墙只留下了极少方法，所以发送交易时要先 sighTransaction 手动签署，然后 sendRawTransaction 发送交易数据。

常用交互代码：
```python
from web3 import Web3
# from rich import print

w3 = Web3(Web3.HTTPProvider('...'))

hacker = '...'
target = '...'
privateKey = '...'

def get_txn(src, dst, data, value=0, gas=0x200000):
    return {
        "chainId": w3.eth.chainId,
        "from": src,
        "to": dst,
        "gasPrice": w3.toWei(1.1, 'gwei'),
        "gas": gas,
        "value": w3.toWei(value, 'ether'),
        "nonce": w3.eth.getTransactionCount(src),
        "data": data
    }

def transact(src, dst, data, value=0, gas=0x200000):
    data = get_txn(src, dst, data, value, gas)
    transaction = w3.eth.account.signTransaction(data, privateKey).rawTransaction
    txn_hash = w3.eth.sendRawTransaction(transaction).hex()
    txn_receipt = w3.eth.waitForTransactionReceipt(txn_hash)
    return txn_receipt

print("[+] Deploying exploit contract...")
txn_receipt = transact(hacker, None, bytes.fromhex("..."))
print(txn_receipt)
print("[*] Exploit contract deployed at", txn_receipt['contractAddress'])
contractAddress = txn_receipt['contractAddress']
```
```python
from web3 import Web3, HTTPProvider
# from rich import print
import json

w3 = Web3(HTTPProvider('...'))

hacker = "..."
target = "..."
privateKey = "..."

def run(sender, func, value=0, gas=0x200000):
    txn = func.buildTransaction({
        'nonce': w3.eth.getTransactionCount(sender),
        'gas': gas,
        'gasPrice': w3.toWei(1.1, 'gwei'),
        "value": w3.toWei(value, 'ether'),
    })
    if gas == None:
        txn['gas'] = w3.eth.estimateGas(txn)
    transaction = w3.eth.account.signTransaction(txn, privateKey).rawTransaction
    txn_hash = w3.eth.sendRawTransaction(transaction).hex()
    txn_receipt = w3.eth.waitForTransactionReceipt(txn_hash)
    return txn_receipt

bytecode, abi = json.load(open("Exploit.json"))
exploitContract = w3.eth.contract(abi=abi, bytecode=bytecode)

print("[+] Deploying exploit contract...")
txn_receipt = run(hacker, exploitContract.constructor(target))
print("[*] Exploit contract deployed at", txn_receipt['contractAddress'])
exploitContract = w3.eth.contract(abi=abi, address=txn_receipt['contractAddress'])
```

### Remix + MetaMask
Remix IDE 提供了调试的 Javascript VM，同时也可以连接以太坊主链、测试链，还可以直接连接到 Web3 Provider，也可以连接到 Injected Provider，比如 MetaMask。MetaMask 中也可以自由选择网络。

然后就可以在 Remix 中进行合约的部署和调用了。

不过对于 CTF 题目来说可能不太好用。我一般会选择在 JS VM 中调试好后通过 web3.py 来交互。