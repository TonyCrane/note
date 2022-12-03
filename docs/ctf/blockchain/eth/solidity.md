---
counter: True
comment: True
---

# Solidity 语言

!!! abstract
    Solidity 是一门编写智能合约的语言，是以太坊的官方语言。

    官方文档：[docs.soliditylang.org](https://docs.soliditylang.org/en/latest/index.html)

## 整体结构
### 源文件结构
- 扩展名 `.sol`
- 第一行是 `// SPDX-License-Identifier: <SPDX-License-Identifier>`，用于声明许可证
    - 不声明许可证的话要写 UNLICENSED，不然会警告
- 接下来是 pragma 语句
    - 指定版本：`#!solidity pragma solidity ^0.8.0;`
    - 指定 ABI 编解码器版本：`#!solidity pragma abicoder v2;`
        - 0.8.0 之后默认使用 v2 版本
- 接下来是 import 语句
    ```solidity
    import "filename";
    import * as symbolName from "filename";
    import "filename" as symbolName;
    import {symbol1 as alias, symbol2} from "filename";
    ```
- 后面就是合约内容了
    - 注释使用 `//` 和 `/* */`，也可以使用 `///` 和 `/** */` 作为文档注释

### 合约结构
- 使用 contract 关键字声明合约
    ```solidity
    contract SimpleStorage {
        uint storedData;
    }
    ```
- 合约内定义的变量（类似属性）称为状态变量（state variables），会被存储在区块链上合约对应的存储区（storage）中
- 合约内定义的函数（类似方法）称为函数（functions），会被存储在区块链上合约对应的代码区（code）中
    ```solidity
    contract SimpleStorage {
        uint storedData;
        function set(uint x) public {
            storedData = x;
        }
        function get() public view returns (uint) {
            return storedData;
        }
    }
    ```
    - 函数也可以定义在合约外面作为工具使用
- 合约中还可以定义修改器（modifier）、事件（event）、结构体（struct）、枚举（enum）等

## 类型
Solidity 是静态类型语言，且没有 undifined、null 等空值概念，取代的是类型默认值。
### 基本值类型
- 布尔类型
    - 小写 true、false
    - ||、&&、!、==、!= 运算符
        - || 和 && 有短路操作
- 整型
    - int 和 uint 表示有符号和无符号整型，默认 256 位（32 字节）
    - 其它大小有 uint8、uint16 等等（均指位数）
    - int 负数通过补码存储
    - 运算符：+、-、*、/、%、**、<<、>>、&、|、^、~、==、!=、<、<=、>、>=
        - / 向 0 舍入
        - ** 指数运算，不过 x\*\*3 要比 x\*x\*x 消耗更多 gas
        - 0 ** 0 定义为 1
    - 可以通过 `type(uint).min` 和 `type(uint).max` 获取最大最小值
    - 0.8.0 以上版本会有溢出检查
        - 存在溢出会以 assert 失败的形式 revert 调用
        - 可以通过 `unchecked { ... }` 块关闭溢出检查
- 地址
    - address 表示 20 字节的地址
    - address payable 表示可以接收以太币的地址，多了 transfer 和 send 方法
    - 可以从 address payable 到 address 隐式转换，不能从 address 到 payable 隐式转换
        - 可以通过 payable(<address>) 显式转换
    - 可以在地址和 uint160、整型字面量、bytes20、合约之间显式转换
    - 将合约转为 payable 地址时要求合约可以接收以太币（有 receive 或 fallback 函数）
        - 0 地址除外，payable(0) 是合法的
    - 可以使用比较运算符比较地址
    - 从 bytes32 转到 address 会截断（取左边 20 字节）
        - 0.4.24 开始要求显式截断：`address(uint160(bytes20(b32)))` 或 `address(uint160(uint256(b32)))`
    - 成员
        - balance：查询地址余额（wei 为单位）
        - transfer：向地址转账，x.transfer(10) 表示从当前地址向 x 转 10 wei，失败会 revert
        - send：向地址转账，类似 transfer 不过失败会返回 false
        - call、delegatecall、staticcall：远程调用
            ```solidity
            bytes memory payload = abi.encodeWithSignature("register(string)", "MyName");
            (bool success, bytes memory returnData) = address(nameReg).call(payload);
            require(success);
            ```
            - payload 是 bytes memory，可以使用 abi.encodeWithSignature 生成
            - 可以通过 modifier 指定 gas 和 value
                ```solidity
                address(nameReg).call{gas: 20000, value: 1 ether}(payload);
                ```
                - 只有 call 支持 value
        - code：获取地址上的合约，返回 bytes memory，且可能为空
        - codehash：获取地址上合约的 keccak256 哈希，addr.codehash 比 keccak256(addr.code) 消耗更少 gas
    - 带大小写校验的 20 字节十六进制字面量是地址（不带校验会产生错误）
- 合约类型
    - 每个合约都相当于一个新类型
    - 可以显式与 address 转换
    - 合约的成员是所有外部函数（external、public）以及标记为 public 的状态变量
- 定长字节数组
    - bytes1、bytes2、bytes3……bytes32
    - 运算符：==、!=、<、<=、>、>=、&、|、^、~、<<、>>、[]
    - .length 访问字节数组长度（只读）
    - bytes、string 是变长字节数组，不属于值类型，在下面再说
    - 字符串字面量可以隐式转换为这些 bytes*n* 类型
        - 字符串字面量可以使用单引号或双引号
        - \xNN 转义十六进制，\uNNNN 转义 Unicode（到 UTF-8）
        - 写在字面量里的字符必须是 ASCII 字符
        - 可以使用 `hex"..."` 字面量表示十六进制字节数组
        - 可以使用 `unicode"..."` 直接在内部写 Unicode 字符
- 枚举类型
    ```solidity
    enum ActionChoices { GoLeft, GoRight, GoStraight, SitStill }
    ```
    - 至少有一个成员，且默认为第一个成员
    - 不能超过 256 个成员
    - 可以与整型显式转换（从 0 开始）
    - 可以使用 `ActionChoices.GoStraight` 访问成员
- 用户自定义值类型
    ```solidity
    type UFixed256x18 is uint256;
    ```
    - 然后可以使用 library 为其添加方法
- 函数类型
    ```solidity
    function (<parameter types>) {internal|external} [pure|view|payable] [returns (<return types>)]
    ```
    - 默认情况下是 internal，可以省略
        - 但仅限表示函数类型的时候，合约函数定义时不可以省略可见性
    - pure 函数可以隐式转换为 view 和 non-payable
    - view、payable 可以隐式转换为 non-payable
    - 当前合约内的 public 函数同时是 internal 和 external 的，f 表示 internal 形式，this.f 表示 external 形式
    - 成员
        - address：函数所在合约的地址
        - selector：当前函数的选择子
        - 0.7.0 之前还有 .gas(uint) 和 .value(uint) 用来制定调用时的 gas 和 value，之后删除了，需要使用 {gas: ..., value: ...}
    - 例子

        ??? example
            ```solidity
            // SPDX-License-Identifier: GPL-3.0
            pragma solidity >=0.4.22 <0.9.0;


            contract Oracle {
                struct Request {
                    bytes data;
                    function(uint) external callback;
                }

                Request[] private requests;
                event NewRequest(uint);

                function query(bytes memory data, function(uint) external callback) public {
                    requests.push(Request(data, callback));
                    emit NewRequest(requests.length - 1);
                }

                function reply(uint requestID, uint response) public {
                    // Here goes the check that the reply comes from a trusted source
                    requests[requestID].callback(response);
                }
            }


            contract OracleUser {
                Oracle constant private ORACLE_CONST = Oracle(address(0x00000000219ab540356cBB839Cbe05303d7705Fa)); // known contract
                uint private exchangeRate;

                function buySomething() public {
                    ORACLE_CONST.query("USD", this.oracleResponse);
                }

                function oracleResponse(uint response) public {
                    require(
                        msg.sender == address(ORACLE_CONST),
                        "Only oracle can call this."
                    );
                    exchangeRate = response;
                }
            }
            ```

### 引用类型
- 引用类型可以使一个值通过不同名称被修改
    - 而值类型在使用的时候会复制一份
- 数据位置（data location）
    - 每个引用类型都需要附加一个数据位置，表示数据在哪里存储
    - 三种位置：
        - memory：在 memory 中存储，生命周期只在当前调用中
        - storage：状态变量区，生命周期和合约相同
        - calldata：只在函数中，且不可修改，可从函数返回，应优先考虑使用这种
        - 0.6.9 之前限制只能在 external 函数中使用 calldata，之后没有限制
        - 0.5.0 之前可以省略，之后必须指定
    - 赋值行为：
        - 在 storage 和 memory 之间赋值（或从 calldata 赋值）始终会创建一份独立的拷贝
        - 在 memory 和 memory 之间赋值仅创建引用
        - 从 storage 赋值给局部的 storage 变量会仅创建引用
        - 其它情况下赋值给 storage 始终进行拷贝
        ```solidity
        contract C {
            uint[] x; // storage 存储，只有此时可以省略位置

            function f(uint[] memory memoryArray) public {
                x = memoryArray; // memory -> storage，拷贝整个数组
                uint[] storage y = x; // storage -> local storage，引用
                y[7]; // 可以得到第 8 个元素
                y.pop(); // 修改了 y，同时 x 也会被更改
                delete x; // 清理了数组 x，同时也会清理 y
                g(x); // 调用 g，参数为 storage -> local storage，引用
                h(x); // 调用 h，参数为 storage -> memory，拷贝
            }

            function g(uint[] storage) internal pure {}
            function h(uint[] memory) public pure {}
        }
        ```
- 数组
    - 在编译期可以是定长的也可以是变长的
    - T 类型的定长（长度为 k）数组类型为 T[k]，变长类型为 T[]
    - 与其它语言不同的是，例如 uint[][5] 表示的是有 5 个元素的定长数组（数组中元素是 uint[] 类型）
    - 将数组类型的状态变量标记为 public 的话会创建一个 getter 函数，输入为索引
    - 越界访问会导致 assert 错误
    - 可以使用 .push() 和 .push(value) 来在动态大小数组末尾追加新元素
        - .push() 追加默认值并返回引用
    - 动态大小数组只能在 storage 中调整大小，在 memory 中一旦分配便不能修改大小
    - 数组字面量和其它语言一样是 [..., ..., ...]，始终是固定长度的
    - 不能将固定长度的数组赋值给动态大小的数组（需要逐元素赋值）
    - 成员：
        - length：长度
        - push()：添加一个 0 元素，返回引用（string 不可用）
            ```solidity
            x.push().t = 2
            x.push() = b
            ```
        - push(x)：末尾追加元素，什么都不返回（string 不可用）
        - pop()：末尾删除一个元素，什么都不返回（string 不可用）
    - 在嵌套数组中要时刻注意避免悬垂引用（因为没有针对单个值的引用，所以一维数组不会出现悬垂引用的情况）
    - 可以使用切片，语法类似 python（没有 step）
        - 没有类型名称，只可以在中间表达式中使用
        - 目前只有 calldata 数组实现了切片
- 字节数组和字符串
    - bytes 类似 bytes1[]，不过在 calldata 和 memory 中是紧密打包的
        - storage 中 bytes1[] 也是紧密打包
        - calldata 和 memory 中 bytes1[] 会有 31 字节的填充
        - 使用 bytes 比 bytes1[] 更便宜
        - 如果长度有限制，则使用 bytes1……bytes32 比 bytes 更便宜
    - string 等价于 bytes，不过不允许访问索引
    - bytes 存储任意长度原始字节流，string 存储任意长度 UTF-8 字符串数据
    - string.concat 和 bytes.concat 可以分别用于 string 和 concat 的连接，返回值是 memory 的
    - 可以通过 new 来在 memory 上分配数组，不过长度固定：
        ```solidity
        uint[] memory a = new uint[](7);
        bytes memory b = new bytes(8);
        ```
- 结构体
    ```solidity
    struct Campaign {
        address payable beneficiary;
        uint fundingGoal;
        uint numFunders;
        uint amount;
        mapping (uint => Funder) funders;
    }
    ```
    - 可以包含映射、数组等，可以嵌套，但是不能包含自身类型
    - 通过 . 来访问内部成员

### 映射类型
- 定义：
    ```solidity
    mapping(KeyType => ValueType) VariableName
    ```
    - KeyType 可以是内置值变量：bytes、string、address、enum 等
        - 不能是用户定义的和复杂类型：mappings、structs、数组等
    - ValueType 可以是任何类型
- 不会存储键，会将键对应值存储在 slot keccak256(key) 中（哈希表）
    - 因此没有长度概念
    - 以及如果不记录额外信息的话，无法完全擦除一个映射
- 映射只能存储在 storage 中作为状态变量
- 标记为 public 的话，会创建一个 getter，输入为键，返回为值
- Iterable Mapping
    - 可以记录额外信息，枚举键

    ??? success "implementation"
        ```solidity
        // SPDX-License-Identifier: GPL-3.0
        pragma solidity ^0.8.8;

        struct IndexValue { uint keyIndex; uint value; }
        struct KeyFlag { uint key; bool deleted; }

        struct itmap {
            mapping(uint => IndexValue) data;
            KeyFlag[] keys;
            uint size;
        }

        type Iterator is uint;

        library IterableMapping {
            function insert(itmap storage self, uint key, uint value) internal returns (bool replaced) {
                uint keyIndex = self.data[key].keyIndex;
                self.data[key].value = value;
                if (keyIndex > 0)
                    return true;
                else {
                    keyIndex = self.keys.length;
                    self.keys.push();
                    self.data[key].keyIndex = keyIndex + 1;
                    self.keys[keyIndex].key = key;
                    self.size++;
                    return false;
                }
            }

            function remove(itmap storage self, uint key) internal returns (bool success) {
                uint keyIndex = self.data[key].keyIndex;
                if (keyIndex == 0)
                    return false;
                delete self.data[key];
                self.keys[keyIndex - 1].deleted = true;
                self.size --;
            }

            function contains(itmap storage self, uint key) internal view returns (bool) {
                return self.data[key].keyIndex > 0;
            }

            function iterateStart(itmap storage self) internal view returns (Iterator) {
                return iteratorSkipDeleted(self, 0);
            }

            function iterateValid(itmap storage self, Iterator iterator) internal view returns (bool) {
                return Iterator.unwrap(iterator) < self.keys.length;
            }

            function iterateNext(itmap storage self, Iterator iterator) internal view returns (Iterator) {
                return iteratorSkipDeleted(self, Iterator.unwrap(iterator) + 1);
            }

            function iterateGet(itmap storage self, Iterator iterator) internal view returns (uint key, uint value) {
                uint keyIndex = Iterator.unwrap(iterator);
                key = self.keys[keyIndex].key;
                value = self.data[key].value;
            }

            function iteratorSkipDeleted(itmap storage self, uint keyIndex) private view returns (Iterator) {
                while (keyIndex < self.keys.length && self.keys[keyIndex].deleted)
                    keyIndex++;
                return Iterator.wrap(keyIndex);
            }
        }

        // How to use it
        contract User {
            // Just a struct holding our data.
            itmap data;
            // Apply library functions to the data type.
            using IterableMapping for itmap;

            // Insert something
            function insert(uint k, uint v) public returns (uint size) {
                // This calls IterableMapping.insert(data, k, v)
                data.insert(k, v);
                // We can still access members of the struct,
                // but we should take care not to mess with them.
                return data.size;
            }

            // Computes the sum of all stored data.
            function sum() public view returns (uint s) {
                for (
                    Iterator i = data.iterateStart();
                    data.iterateValid(i);
                    i = data.iterateNext(i)
                ) {
                    (, uint value) = data.iterateGet(i);
                    s += value;
                }
            }
        }
        ```

### 运算符
前面有提到过，下面是一些补充

- 三目运算符：
    ```solidity
    <expression> ? <trueExpression> : <falseExpression>
    ```
- 复合运算符、自增/自减等
    - 可以使用 -= *= /= %= |= &= ^= <<= >>= 等
    - a++ a-- --a ++a 意义也和 C 中相同
- delete
    - delete a 会将该类型的初始值赋值给 a
    - 可以作用与数组上
    - 对于映射是没有用的
- 优先级和其它语言类似

## 单位和特殊变量、函数
### 单位
- 以太币单位：
    - 1 wei == 1
    - 1 gwei == 1e9
    - 1 ether == 1e18
    - finney szabo 在 0.7.0 中删掉了
- 时间单位：
    - 1 seconds == 1
    - 1 minutes == 60 seconds == 60
    - 1 hours == 60 minutes == 3600
    - 1 days == 24 hours == 86400
    - 1 weeks == 7 days == 604800
    - 由于闰年，years 在 0.5.0 中删掉了
    - 由于闰秒，时间可能不精准

### 特殊变量、函数
- 区块、交易相关
    - block 相关变量：
        - block.basefee、block.chainid、block.difficulty、block.gaslimit、block.number、block.timestamp：uint
        - block.coinbase：address payable
    - 交易、消息相关变量：
        - msg.data（bytes calldata）、msg.sender（address）、msg.sig（bytes4）、msg.value（uint）
        - tx.gasprice（uint）、tx.origin（address）
    - 函数
        - blockhash(uint blockNumber) returns (bytes32)：最近 256 块返回哈希，之前的返回 0
        - gasleft() returns (uint256)：当前剩余的 gas
- ABI 编解码
    - abi.decode(bytes memory encodedData, (...)) returns (...)：ABI 解码数据得到参数
        ```solidity
        (uint a, uint[2] memory b, bytes memory c) = abi.decode(data, (uint, uint[2], bytes))
        ```
    - abi.encode(...) returns (bytes memory)：ABI 编码
    - abi.encodedPacked(...) returns (bytes memory)：打包编码
    - abi.encodeWithSelector(bytes4 selector, ...) returns (bytes memory)：对后面参数进行编码，然后开头加上 selector
    - abi.encodeWithSignature(string memory signature, ...) returns (bytes memory)：等价于先将签名计算得到 selector 然后再调用 encodeWithSelector
    - abi.encodeCall(function functionPointer, (...)) returns (bytes memory)：检查类型，并编码
- 错误处理
    - assert(bool condition)：如果 condition 不为 true 则抛出 Panic 错误然后 revert（用于内部错误）
    - require(bool condition)：如果 condition 不为 true 则 revert（用于外部错误）
    - require(bool condition, string memory message)：同上，错误时提供信息
    - revert()：终止执行并 revert 状态更改
    - revert(string memory reason)：同上，但提供信息
- 数学和密码学函数
    - addmod(uint x, uint y, uint k) returns (uint)：计算 (x + y) % k
        - 0.5.0 后会 assert(k != 0)
    - mulmod(uint x, uint y, uint k) returns (uint)：计算 (x * y) % k
        - 0.5.0 后会 assert(k != 0)
    - keccak256(bytes memory) returns (bytes32)：计算 keccak-256 哈希
        - 0.5.0 之前有别名 sha3，后面移除了
    - sha256(bytes memory) returns (bytes32)：计算 sha-256 哈希
    - ripemd160(bytes memory) returns (bytes20)：计算 ripemd-160 哈希
    - ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address)：从圆锥曲线签名中恢复与公钥关联的地址，出错时返回 0
        - r 是前面 ECDSA 值的前 32 字节，s 是接下来的 32 字节，v 是最后一字节
- 合约相关
    - this：指当前合约
    - selfdestruct(address payable recipient)：自毁合约并将所有余额转移给 recipient
        - 会强制转账，不会进入接收方的 receive 函数
        - 交易结束后才会摧毁，如果 revert 了会撤销销毁
        - 0.5.0 之前有别名 suicide，后面移除了
- 类型信息
    - 对于合约：
        - type(C).name：合约名称
        - type(C).creationCode：内联汇编中有用，无法在合约自身中访问这个属性
        - type(C).runtimeCode：运行时字节码
    - 对于接口：
        - type(I).interfaceId：EIP-165 规定的接口标识符值
    - 对于整数类型：
        - type(T).min、type(T).max
- 保留关键字
    - after, alias, apply, auto, byte, case, copyof, default, define, final, implements, in, inline, let, macro, match, mutable, null, of, partial, promise, reference, relocatable, sealed, sizeof, static, supports, switch, typedef, typeof, var

## 语句和控制结构
### 控制结构
- 和其他语言一样提供了控制流相关的语句：
    - if-else
        - 不能省略条件的小括号，只有一个语句时可以省略大括号
        - 条件必须是布尔类型，因为 solidity 没有在非布尔类型和布尔类型之间的转换
    - while、do、for、break、continue
    - return
- 同时提供了 try-catch 语句，不过只能用于外部函数调用或者合约创建语句中

### 函数调用
- 内部函数调用直接写函数名并调用即可
    - 也可以进行递归调用，不过栈深度最多 1024 插槽，可能会爆栈
- 外部函数调用，使用 this.f(...) 或 c.f(...)
    - this 指当前合约，即通过外部调用的方式调用自身函数
    - c 指合约实例，f 是 c 中的函数
    - 可以附加 gas 和 value，在函数名后、括号前增加即可：
        ```solidity
        c.f{value: ..., gas: ...}(...)
        ```
    - 如果被调用的函数中产生了异常，则整个调用也是异常的
- 通过参数名称调用函数
    ```solidity
    function set(uint key, uint value) public {
        data[key] = value;
    }
    function f() public {
        set({value: 2, key: 3});
    }
    ```

### 通过 new 创建合约
- 在合约中也可以通过 new 创建另一个合约
    ```solidity
    D newD = new D(arg);
    D newD = new D{value: amount}(arg);
    ```
    - 如果 D 的 constructor 是 payable 的话，可以在创建时传入以太币
    - 如果创建失败，则会抛出异常
- 加盐创建（即使用 create2 创建）
    - 前面的创建方式使用 create 指令，地址由创建者地址和 nonce 计算
    - 可以通过指定 salt（一个 bytes32 值）的方式来使用 create2 指令的机制创建合约
        ```solidity
        D newD = new D{salt: salt}(arg);
        ```
    - 地址的计算方式是：
        ```solidity
        address predictedAddress = address(uint160(uint(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(abi.encodePacked(
                type(D).creationCode,
                abi.encode(arg)
            ))
        )))));
        ```
    - 因为地址的计算与 nonce 和 runtimeCode 无关，所以可以在原地址合约被销毁后重新在其地址上部署新的合约（只要保证 creationCode、salt、arg 一致就可以在同一位置创建合约）

### 赋值语句及作用域
- 赋值语句可以自动解包多个值，也可以在解包赋值时定义变量：
    ```solidity
    contract C {
        uint index;

        function f() public pure returns (uint, bool, uint) {
            return (7, true, 2);
        }

        function g() public {
            (uint x, , uint y) = f();
            (x, y) = (y, x);
            (index, , ) = f(); // Sets the index to 7
        }
    }
    ```
- 变量作用域和 C99 的规定相同（大括号分隔等）
    - 0.5.0 之前使用 JavaScript 的作用域规则，即作用域在整个范围内而不是声明之后
        - 如下代码在 0.5.0 之前可以编译，之后会报错：
        ```solidity
        contract C {
            function f() pure public returns (uint) {
                x = 2;
                uint x;
                return x;
            }
        }
        ```

### unchecked 语句
- 在 0.8.0 后，会检查溢出，如果发生溢出则会导致 assert 错误
- 在 0.8.0 后不检查溢出需要使用 unchecked 块：
    ```solidity
    contract C {
        function f(uint a, uint b) pure public returns (uint) {
            unchecked { return a - b; }
        }
        function g(uint a, uint b) pure public returns (uint) {
            return a - b;
        }
    }
    ```
    - 调用 f(2, 3) 会返回 2**256-1，调用 g(2, 3) 会导致错误
- unchecked 可以在块内的任何位置使用，不能嵌套
- 只对当前块内的语句有效，从 unchecked 块内调用的外部函数不受其影响
- 不能再 checked 块内使用 _;（modifier 定义时）
- unchecked 不能仅用除以零和模零的检查

### 错误处理
- solidity 使用状态回滚来处理错误，即直接撤销当前调用及所有子调用中所有的状态更改
- 子调用出现异常之后会直接向上传递，即继续异常退出，除非被 try-catch 语句捕获
    - send、call、delegatecall、staticcall 出错不会抛出异常，而会返回 false
    - 但是如果调用的账户不存在的话，call、delegatecall、staticcall 仍会返回 true，所以要提前检查
- Panic
    - Panic 是 assert 语句失败时抛出的错误类型
    - assert 抛出的错误类型时 Panic(uint256)，其包含了错误代码：
        - 0x00：编译器插入的 panic
        - 0x01：手动调用 assert 时，验证值不为 true
        - 0x11：unchecked 块外出现了溢出
        - 0x12：除以零或者模零
        - 0x21：将过大的值或者负值转换为枚举
        - 0x22：访问错误编码的 storage 字节数组
        - 0x31：对空数组执行 pop
        - 0x32：越界访问数组
        - 0x41：分配了太多内存或者创建了过大数组
        - 0x51：调用了内部函数类型的零初始化函数
    - assert 应用于内部检查错误，正常设计运行的程序不应该会抛出 Panic
- Error
    - Error 是 require 语句失败时抛出的错误类型
    - 抛出的错误类型为 Error(string)
        - 即 require(x, s) 中 x 为 false 时会抛出 Error(s)
    - require 无法使用自定义错误类型，可以改写为 if (!condition) revert CustomError();
- revert
    - revert 可以直接抛出异常并回滚，前面的 Panic 和 Error 就是通过 revert 抛出的
    - revert 可以使用自定义错误类型 revert CustomError(arg1, arg2)
    - 为了向后兼容也可以直接使用 revert 函数：revert() 以及 revert("description")
- try-catch
    - try-catch 语句可以捕获前面说到的错误：
    ```solidity
    try feed.getData(token) returns (uint v) {
        return (v, true);
    } catch Error(string memory reason) {
        ...
    } catch Panic(uint errorCode) {
        ...
    } catch (bytes memory lowLevelData) {
        ...
    }
    ```
    - Error(string memory reason) 用于捕获 require 或者 revert("...") 产生的错误
    - Panic(uint errorCode) 用于捕获 assert 产生的 Panic 错误
    - catch (bytes memory lowLevelData) 用于捕获剩余的其它错误
    - catch 用于捕获所有剩余错误并忽略
    - 为了捕获所有错误，应该至少有一句 catch { ... } 或 catch (bytes memory lowLevelData) { ... }
    - 如果在 try-catch 中解码返回值时产生了错误，则会从当前合约向上抛出异常，而不会进入下面的 catch 语句中
    - 如果在解码 Error(string memory reason) 时出现了错误，且有更低级的 catch 语句，则会进入更低级的 catch 中
    - 如果外部调用结束后达到了错误块，那么此时外部调用造成的状态修改已经被回滚了
    - 调用时调用者会保留至少 1/64 的 gas，因此即使调用因为 gas 耗尽而失败，调用者仍然有剩余 gas 可以进行错误处理

## 合约
### 创建合约
- 当合约创建时会执行 constructor 构造函数
- 可以没有 constructor，有的话只能有一个，不支持重载
- 创建合约时构造函数的参数会被编码为 ABI 编码的数据，然后放在合约的后面
- 合约中创建另一个合约一定要知道创建合约的源码
    - 因此不能循环创建自身合约

### 可见性和 getter
- 状态变量可见性
    - public：编译器会自动创建 getter 函数
        - 自身调用时 this.x 会使用 getter，直接使用 x 则不会调用 getter（直接读取插槽）
    - internal（默认可见性）：只有合约内部可以访问（包括派生合约），没有 getter
        - 只是没有 getter，仍然可以通过 getStorageAt 插槽读取
    - private：类似 internal，不过在派生合约中不可访问
- 函数可见性
    - external：合约接口的一部分，智能从其他合约或者交易中调用，不能内部调用（f() 不可以，但 this.f() 可以）
    - public：合约接口的一部分，可以从其他合约或者交易中调用，也可以内部调用
    - internal：只能在合约内部（包括派生合约）调用，不能从外部调用，不会暴露给外部
    - private：类似 internal，不过在派生合约中不可用
- getter 函数
    - 编译器会自动为所有 public 状态变量创建 getter 函数
    - getter 函数的可见性是 external 的
    - 对于数组变量，getter 函数是输入索引返回值（防止过高的 gas 消耗）
        - 想要返回整个数组的话需要自己写另一个函数
    - 一个复杂例子：
        ```solidity
        contract Complex {
            struct Data {
                uint a;
                bytes3 b;
                mapping (uint => uint) map;
                uint[3] c;
                uint[] d;
                bytes e;
            }
            mapping (uint => mapping(bool => Data[])) public data;
        }
        ```
        - 为 data 生成的 getter 为：
        ```solidity
        function data(uint arg1, bool arg2, uint arg3)
            public
            returns (uint a, bytes3 b, bytes memory e)
        {
            a = data[arg1][arg2][arg3].a;
            b = data[arg1][arg2][arg3].b;
            e = data[arg1][arg2][arg3].e;
        }
        ```
        - 返回值会忽略结构体中的 mapping、数组

### 函数修改器
- 修改器（modifier）可以修改函数的行为
- 修改器是合约的可继承属性，可以被派生合约覆盖，前提是修改器被标记为了 virtual
- 定义：
    ```solidity
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    modifier costs(uint price) {
        require(msg.value >= price);
        _;
    }
    ```
    - 可以带参数，也可以省略参数（甚至省略括号）
    - 下划线的位置（占位符）表示要插入的被修改的函数体
    - 占位符可以多次出现，每个都会替换成被修改的函数体
- 修改器不能访问、更改修改的函数的参数和返回值
- 需要传入参数时需要显式写入
    ```solidity
    function buy(uint price) public payable costs(price) {
        // ...
    }
    ```
- 可以加多个 modifier，空格分隔，且从左到右依次进行评估

### 常量和不可变的状态变量
- 状态变量可以标记为 constant 或者 immutable，他们在运行时字节码中都会被直接替换为相应的值，而不需要读取插槽，gas 消耗要小得多
- constant 和 immutable 的区别：
    - constant 是在编译期就要知道值的，会全局替换符号（类似 C 的宏）
    - immutable 可以在构造函数中进行一次赋值，之后会在拷贝运行时函数时进行替换
    - immutable 在替换的时候会保留 32 个字节，而 constant 不会，因此 constant 有时比 immutable 更偏移
- constant 和 immutable 目前只支持 string 和值类型
- constant 中不可以访问 storage、区块信息、执行信息的等。但可以使用内置函数如 kaccak256 等
- immutable 限制要比 constant 少，因为是在运行 creationCode 的适合计算值的

### 函数
- 函数参数
    - 和声明变量一样，指定类型和名称
    - 函数内没有使用的参数可以省略名称
- 函数返回值
    - 可以返回多个值
    - 函数声明最后使用 returns 关键字
    - 可以通过返回值的变量名进行隐式返回
        ```solidity
        function func(uint a, uint b) public pure returns (uint sum, uint product) {
            sum = a + b;
            product = a * b;
        }
        ```
    - 也可以通过 return 语句手动返回：
        ```solidity
        function func(uint a, uint b) public pure returns (uint sum, uint product) {
            return (a + b, a * b)
        }
        ```
        - 此时 returns 中的变量名是不必需的
    - 不可以在非 internal 的函数中返回以下类型：
        - mappings
        - internal 函数
        - 位置为 storage 的引用类型
        - 使用 ABI v1 编码器时的多维数组
        - 使用 ABI v1 编码器时的结构体
- 合约外也可以定义函数，称为 free functions，默认可见性是 internal 的
    - 编译时会将代码潜入调用它的合约中
    - 也可以调用其他合约、发送以太币，自毁等
    - 不能访问 this 变量，不能访问 storage 和不在作用域内的函数
- 状态可变性
    - 可以在函数定义中加入 view 或 pure 来指定该函数的状态可变性
    - view：承诺不会修改状态
        - 对于拜占庭或更高版本的 EVM，会使用 STATICCALL 来调用 view 函数确保不修改状态
        - 对于库中的 view 函数，仍然会使用 DELEGATECALL 来调用，但是会在编译时进行检查
        - 以下语句会被视为修改状态：
            - 写入状态变量
            - 触发事件
            - 创建其他合约
            - 使用 selfdestruct
            - 通过调用发送以太币
            - 调用没有标记为 view 和 pure 的函数
            - 使用 low-level 的 call
            - 内联汇编中包含特定字节码
        - 0.5.0 版本之前 constant 是 view 的别名
        - getter 方法会被自动标记为 view
    - pure：承诺不会读取、修改状态
        - 对于拜占庭或更高版本的 EVM，会使用 STATICCALL 来调用 pure 函数确保不修改状态（但不能确保不读取）
        - 读取 immutable 变量也算为非纯操作
        - 以下情况会被视为读取状态：
            - 读取状态变量
            - 访问 balance（address(this).balance 或 addr.balance 都算）
            - 访问 block、tx、msg 成员（msg.sig 和 msg.data 除外）
            - 调用没有标记为 pure 的函数
            - 内联汇编中包含特定字节码
- 特殊函数
    - receive 函数
        - 一个合约最多有一个 receive 函数。定义为：
            ```solidity
            receive() external payable { ... }
            ```
            - 没有 function 关键字
            - 不能有参数，不能返回任何值，必须是 external 可见性，和 payable 的
            - 可以是 virtual 的（可以被覆盖），可以有 modifier
        - receive 函数在合约收到空 calldata 时执行，例如通过接收通过 .send 或者 .transfer 发送的以太币时
        - 如果没有 receive 函数会检查有没有 payable 的 fallback 函数
        - 没有 receive 也没有 payable 的 fallback 的话，合约将不能通过交易接收以太币（接收的话会抛出异常）
        - 最坏情况下 receive 函数只有 2300 的 gas 可用（接收来自 send 和 transfer 时）
            - 此时只可以进行基本的日志操作
            - 写入存储、创建合约、调用大量消耗 gas 的外部函数、发送以太币都会消耗比 2300 更多的 gas
    - fallback 函数
        - 一个合约最多有一个 fallback 函数。定义为：
            ```solidity
            fallback() external [payable] { ... }
            fallback(bytes calldata input) external [payable] returns (bytes memory output) { ... }
            ```
            - 没有 function 关键字
            - 必须是 external 可见性
            - 可以是 virtual 的（可以被覆盖），可以有 modifier
        - fallback 在以下情况下被调用：
            - 有 calldata，但合约中没有匹配的签名
            - 没有 calldata，且没有 receive 函数
        - 要接收以太币的话一定要标记为 payable
        - 如果定义为带参数的版本，则：
            - input 等价于 msg.data
            - output 不会经过编码，会直接无修改地返回（甚至不填充）
        - 在最坏情况下，和 receive 一样只有 2300 gas 可用，但在 gas 充足情况下可以任意执行复杂操作。
    - 无法接收以太币的合约也可以通过 coinbase transaction（挖矿奖励）和 selfdestruct 目的地址的方式强制接收以太币，且无法绕过
- 函数重载
    - 一个合约可以有多个同名，但是参数类型不同的函数，例如：
        ```solidity
        contract A {
            function f(uint value) public pure returns (uint out) {
                out = value;
            }

            function f(uint value, bool really) public pure returns (uint out) {
                if (really)
                    out = value;
            }
        }
        ```
    - 在调用时会考虑，如果所有参数都可以隐式转换为预期类型，则可以调用该函数
    - 如果有多个函数可以调用，则会失败，例如：
        ```solidity
        contract A {
            function f(uint8 val) public pure returns (uint8 out) {
                out = val;
            }

            function f(uint256 val) public pure returns (uint256 out) {
                out = val;
            }
        }
        ```
        - 调用 f(50) 的话不会成功，因为 50 可以同时隐式转换为 uint8 和 uint256

### 事件
- Solidity 提供了比 EVM 的 log 更高级的事件记录，称为 event
- 应用程序可以通过 RPC 接口订阅和监听 events
- event 是合约的可继承成员，调用时会将参数存储到交易日志中，保留在区块链上
- 日志和 event 内容不能在合约中访问
- 最多可以为三个参数标记 indexed
    - 标记为 indexed 的参数会被存到一个特殊的称为 topics 的数据结构中
    - 一个 topic 只能包含 32 字节，更多的需要计算 keccak256 哈希
    - 其余部分会被 ABI 编码然后存在 log 的数据部分
    - topics 支持搜索事件，可以用来过滤
- 事件有成员 selector，是一个包事件签名的 keccak256 哈希的 bytes32 类型
- 通过 event 关键字定义：
    ```solidity
    event Deposit(
        address indexed from,
        bytes32 indexed id,
        uint value
    );
    ```
- 通过 emit 关键字触发事件：
    ```solidity
    emit Deposit(msg.sender, id, msg.value);
    ```

### 错误与回滚
- Solidity 提供了 Error 来以更方便、省 gas 的方式向用户传达为什么操作失败了
- 一种错误可以通过 error 关键字来定义：
    ```solidity
    error InsufficientBalance(uint256 available, uint256 required);
    ```
- 然后可以且仅可以在 revert 语句中使用：
    ```solidity
    ...
    revert InsufficientBalance({
        available: balance[msg.sender],
        required: amount
    });
    ```
- 这样同样使用 ABI 编码来返回信息，包括 error 的 selector 和具体内容的编码
- require(condition, "description") 等价于 if (!condition) revert Error("description")，其中 Error 为内置类型
- assert 产生的 revert 等价于 revert Panic(uint256)，Panic 也是一个内置类型

### 继承
- Solidity 的继承机制类似 Python，有多重继承
- 通过定义合约时加入 is 子句来继承
- 可以通过 ContractName.functionName 或 super.functionName 的形式调用
- 继承时状态变量不能遮蔽（shadowing），即不能创建新的同名变量
- 继承覆盖函数时，可以被覆盖的函数必须标记为 virtual，进行覆盖的函数必须标记为 override
    - 从多个合约覆盖函数要用 override 显示写出所有覆盖的函数
- 接口中所有函数自动为 virtual
- 从 0.8.8 开始，覆盖接口函数时不需要标记 override（多继承除外）
- modifier 的覆盖同样需要 virtual 和 override
- 构造函数只针对于当前合约，继承带有有参数的构造函数的合约时，需要显式调用父类构造函数
    ```solidity
    contract Base {
        constructor(uint x) { ... }
    }

    contract Child1 is Base(1) {
        constructor(uint x, uint y) { ... }
    }

    contract Child2 is Base {
        constructor(uint x) Base(x) { ... }
    }
    ```

### 抽象合约
- 当合约包含没有实现的部分时要标记为 abstract
- 当不打算直接创建这个合约的时候，也可以将其标记为 abstract（即使所有函数都实现了）
- 在 contract 前加上 abstract 关键字来标记为抽象合约，没有实现的函数不需要写函数体，只需要给出声明（标记为 virtual）
    ```solidity
    abstract contract Feline {
        function utterance() public virtual returns (bytes32);
    }
    ```
- 其它合约通过继承抽象合约来实现它
    - 如果仍待包含没有实现的部分，则仍需要标记为 abstract
- 类似于接口，但比接口限制更少

### 接口
- 类似于抽象合约，但是：
    - 接口中不能实现任何函数
    - 不能继承自其他合约，但可以继承自其它接口
    - 所有声明的函数都必须标记为 external
    - 不能声明构造函数、状态变量和 modifier
- 接口通过 interface 关键字定义，不使用 contract：
    ```solidity
    interface Token {
        enum TokenType { Fungible, NonFungible }
        struct Coin { string obverse; string reverse; }
        function transfer(address recipient, uint amount) external;
    }
    ```
- 接口中的所有函数都隐含 virtual，覆盖它们的函数也不需要标记 override

### 库
- 库是一组函数的集合，可以在其它合约中使用
    - 使用 DELEGATECALL 进行调用（家园版本前使用 CALLCODE）
- 库通过 library 关键字定义：
    ```solidity
    struct Data {
        mapping (uint => bool) flags;
    }
    library Set {
        function insert(Data storage self, uint value) public returns (bool) {
            if (self.flags[value]) return false;
            self.flags[value] = true;
            return true;
        }
        function remove(Data storage self, uint value) public returns (bool) {
            if (!self.flags[value]) return false;
            self.flags[value] = false;
            return true;
        }
        function contains(Data storage self, uint value) public returns (bool) {
            return self.flags[value];
        }
    }
    ```
- 手动使用：
    ```solidity
    contract C {
        Set.Data knownValues;
        function register(uint value) public {
            require(Set.insert(knownValues, value));
        }
    }
    ```
- 相比于合约，库有以下限制：
    - 不能拥有状态变量
    - 不能继承或者被继承
    - 不能接受以太币
    - 不能被销毁

### using for 语句
- 语句 using A for B; 表示将函数 A 作为任何 B 类型的变量的成员函数，且函数的第一个参数为其自身（类似 python 中的 self）
    - 可以在文件范围（合约外），也可以在合约内
- using A for B 中的 A 可以是：
    - 文件级别的函数，或者库中的函数
    - 可以写多个，用大括号包裹，逗号隔开：
        ```solidity
        using {f, g, L.f} for uint;
        ```
    - 可以是一个库的名字，即将库中的所有函数都附加在类型上：using L for uint;
- 对于 B 部分：
    - 可以是一个指定的显式类型（不需要数据位置标记）
    - 在合约中可以是 *，用来将库中的函数附加到所有类型上：using L for *;

## 内联汇编
- solidity 代码中可以使用内联汇编，会绕过安全检查，要少用
- 内联汇编写在 `assembly { ... }` 块中，使用 Yul 语法，见：[Yul 语言](yul)
- 内联汇编中可以使用 solidity 局部变量
- 不同的汇编块有不同命名空间，不能互相访问
- 可以通过 a.slot 访问状态变量 a 所在的插槽

## 编译
直接在 Remix 里编译是最方便的，还可以选择不同版本的编译器。

本地编译我也没试过（x