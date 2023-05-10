---
comment: True
---

# AliyunCTF 2023 Writeup

!!! abstract
    阿里云第一次办 CTF，奖金比较多，题目不简单，做了几个 misc，有点烦

---

## OOBdetection
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

给出了一个新定义的简单语言的 EBNF 描述，要求在两分钟内判断三百个程序是否会产生数组越界（oob）或者其他错误（unknown）。

给了 EBNF 所以就直接顺着走编译原理 interpreter 那路，没学过编译原理，搜了搜看 python 有 lark-parser 可以解析，但是题给的 EBNF 写法不能用，改了改（这个 lark 感觉要求的写法还挺严格的）：

??? question "SC 语言 EBNF 描述"
    ```ebnf
    prog : deflist arrlist

    deflist : (vardef ";")*

    arrlist : (arrayexpr ";")*

    TYPENAME : "int"      
        
    vardef : TYPENAME ID ("[" expr "]")*
           | TYPENAME ID "=" DIGITSEQUENCE 
            
    arrayunit : ID "[" expr "]" ("[" expr "]")*
            
    arrayexpr : ID ASSIGNMENTOPERATOR arrayunit
              | ID ASSIGNMENTOPERATOR expr
              | arrayunit ASSIGNMENTOPERATOR expr
            
    expr : arrayunit OP expr
         | ID OP expr    
         | DIGITSEQUENCE OP expr 
         | arrayunit                         
         | ID                        
         | DIGITSEQUENCE

    OP : "/" | "*" | "+" | "-"

    ID : IDNONDIGIT (IDNONDIGIT | DIGIT)*

    DIGITSEQUENCE : NZDIGIT DIGIT*

    NZDIGIT : "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"

    DIGIT : "0" |  "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"

    IDNONDIGIT : "a".."z" | "A".."Z" | "_"

    ASSIGNMENTOPERATOR : "="

    %ignore " "
    %ignore "\n"
    ```

然后丢给 lark，创建一个 parser 就可以对输入的程序分析出 ast 了，然后递归遍历 ast 即可。

可以创建两个字典，一个存变量、一个存字典。为了判断越界错误，最简单的方法就是跟着程序一起在 python 内创建出一个同样大小的数组，在访问的时候如果越界会抛出 IndexError 异常，try-except 捕获即可。同时还要注意 python 是支持负数索引访问的，所以在访问之前还要特别判断一下负数索引的情况，此时也应该 oob。

对于其他错误，如果变量或者数组没定义就进行了使用，这时会抛出 KeyError，也是捕获一下就可以，除此之外的错误就是除以零的错误，判断一下或者捕获 ZeroDivisionError 都可以。

??? done "exp"
    ```python
    from pwn import *
    from hashlib import sha256
    from lark import Lark, Token

    p = remote(...)

    parser = Lark(r"""
        ...
    """, start = "prog")

    var = {}
    arr = {}

    def array_unit(tree):
        Id = tree.children[0].value
        res = arr[Id]
        for child in tree.children[1:]:
            sub = expr_sc(child)
            if sub < 0:
                raise IndexError
            res = res[sub]
        if res == "unknown":
            raise KeyError
        return res

    def array_unit_write(tree, val):
        Id = tree.children[0].value
        res = arr[Id]
        for child in tree.children[1:-1]:
            sub = expr_sc(child)
            if sub < 0:
                raise IndexError
            res = res[sub]
        sub = expr_sc(tree.children[-1])
        if sub < 0:
            raise IndexError
        res[sub] = val

    def expr_sc(tree):
        if isinstance(tree, Token):
            if tree.type == "DIGITSEQUENCE":
                return int(tree.value)
            elif tree.type == "ID":
                if var[tree.value] == "unknown":
                    raise KeyError
                else:
                    return var[tree.value]
            else:
                return array_unit(tree)
        if len(tree.children) == 3:
            if tree.children[1].value == "+":
                return expr_sc(tree.children[0]) + expr_sc(tree.children[2])
            elif tree.children[1].value == "-":
                return expr_sc(tree.children[0]) - expr_sc(tree.children[2])
            elif tree.children[1].value == "*":
                return expr_sc(tree.children[0]) * expr_sc(tree.children[2])
            elif tree.children[1].value == "/":
                return expr_sc(tree.children[0]) // expr_sc(tree.children[2])
        elif tree.data == "arrayunit":
            return array_unit(tree)
        else:
            return expr_sc(tree.children[0])

    def def_sc(tree):
        if len(tree.children) == 2:
            var[tree.children[1].value] = "unknown"
        elif isinstance(tree.children[2], Token):
            var[tree.children[1].value] = int(tree.children[2].value)
        else:
            a = "unknown"
            for child in tree.children[2:][::-1]:
                if a == "unknown":
                    a = [a for i in range(expr_sc(child))]
                else:
                    a = [a[:] for i in range(expr_sc(child))]
            arr[tree.children[1].value] = a

    def array_sc(tree):
        child1 = tree.children[0]
        child2 = tree.children[1]
        child3 = tree.children[2]
        if isinstance(child1, Token):
            if child3.data == "expr":
                var[child1.value] = expr_sc(child3)
            else:
                var[child1.value] = array_unit(child3)
        else:
            array_unit_write(child1, expr_sc(child3))

    def run_sc(tree):
        if tree.data == "prog":
            for child in tree.children:
                run_sc(child)
        elif tree.data == "deflist":
            for child in tree.children:
                def_sc(child)
        elif tree.data == "arrlist":
            for child in tree.children:
                array_sc(child)

    p.recvuntil(b"!\n")

    for rnd in range(300):
        print(f"[*] round #{rnd}")
        p.recvuntil(b"!")
        code = p.recvuntil(b"Your", drop=True).decode().strip()
        var = {}
        arr = {}
        tree = parser.parse(code)
        try:
            run_sc(tree)
        except IndexError:
            print(f"[+] oob detected")
            p.sendlineafter(b"):", b"oob")
        except (KeyError, ZeroDivisionError):
            print(f"[+] unknown detected")
            p.sendlineafter(b"):", b"unknown")
        else:
            print(f"[+] safe")
            p.sendlineafter(b"):", b"safe")

    p.interactive()
    ```

flag: **aliyunctf{0k_y0u_kn0w_h0w_to_analyse_Pr0gram}**。

---

## 消失的电波
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

一个非常坐牢的谜语题。给了一个音频，包含三长三短一共六段，每一种长度的波形是完全一样的。Au 里面缩放可以看到：

![](/assets/images/writeups/aliyunctf2023/wave1.png)

不难想到一高一低是 1 和 0，可以用 python scipy.io.wavefile 来读取波形数据，然后用 scipy.signal.argrelextrema 来找到所有极值，和一个阈值比较，高了就是 1 低了就是 0。处理结果可以发现所有 1 都是三个一起出现，0 都是四个一起出现，所以三个 1 替换为一个 1、四个 0 替换为一个 0，最后可以得到如下结果：

```python
import numpy as np
from scipy.io import wavfile
from scipy.signal import argrelextrema

sample_rate, data = wavfile.read("OVUB7rdc9oH112Ve.wav")

sections = []

sections.append(np.trim_zeros(data[50000:150000]))
sections.append(np.trim_zeros(data[150000:230000]))
sections.append(np.trim_zeros(data[230000:300000]))
sections.append(np.trim_zeros(data[300000:370000]))
sections.append(np.trim_zeros(data[370000:420000]))
sections.append(np.trim_zeros(data[420000:]))

for i, section in enumerate(sections):
    print("".join([str(int(i)) for i in (section[argrelextrema(section, np.greater)[0]] > 8000)]).replace("111", "1").replace("0000", "0"))

"""
00101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010011111011100110110111101101111010100101101101001000010011101000110110011111100111011001100110011100010110000100100110001001100010100101111101001101000010100101100001101111100010110010111011001001111010101000101001101110100010010100101110101111000110110010110101001111010010100100110110011
00101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010011111011100110110111101101111010100101101101001000010011101000110110011111100111011001100110011100010110000100100110001001100010100101111101001101000010100101100001101111100010110010111011001001111010101000101001101110100010010100101110101111000110110010110101001111010010100100110110011
00101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010011111011100110110111101101111010100101101101001000010011101000110110011111100111011001100110011100010110000100100110001001100010100101111101001101000010100101100001101111100010110010111011001001111010101000101001101110100010010100101110101111000110110010110101001111010010100100110110011
0010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101010001101100011011000110110001101
0010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101010001101100011011000110110001101
0010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101000101010001010100010101010001101100011011000110110001101
"""
```

转为 ASCII 可以发现前面的都是 *，应该是没有用的，第二种短的都是 0x8d，第一种 01 串应该是主要信息。

然后这里卡了一整天，在 CyberChef 里乱试，最后 yyy 睡觉梦到了解法（x 在 CyberChef 里是这样的：

![](/assets/images/writeups/aliyunctf2023/wave2.png)

第二种 01 串完全没有用到。很奇怪。

这个结果解释起来就是一个阿里云的 OSS 对象存储，位置在杭州，bucket 名是 ALBB-iot2023，对象是 OpYdCuMtkQ8Yjhm2。于是访问 https://ALBB-iot2023.oss-cn-hangzhou.aliyuncs.com/OpYdCuMtkQ8Yjhm2，跳转到了 D3CTF 平台草，wget 一下，里面有一个 base64，解码一下是 aliyunctf{you_are_a_jocker}，假 flag，joker 还写错了（x

最后试出来其实 bucket 是 iot2023，ALBB 只是提示是阿里云的应该，而且阿里云 OSS bucket 名称其实不允许是大写。访问 https://iot2023.oss-cn-hangzhou.aliyuncs.com/OpYdCuMtkQ8Yjhm2，得到了一个二进制文件，file 一下是 Mach-O 正好 mac 可以跑，可以看到输出：

```text
[1682249479.453][LK-0313] MQTT user calls aiot_mqtt_connect api, connect
[1682249479.453][LK-032A] mqtt host: a1eAwsBKddO.iot-as-mqtt.cn-shanghai.aliyuncs.com
[1682249479.453][LK-0317] user name: ncApIY2XV9NUIY4VpbGk&a1eAwsBKddO
[1682249479.453][LK-0318] password: 70C3EC7A5774AF26EADEA867686238A403EF7A17118ABCABF1B49A8153D897DA
establish tcp connection with server(host='a1eAwsBKddO.iot-as-mqtt.cn-shanghai.aliyuncs.com', port=[443])
success to establish tcp, fd=5
local port: 61892
[1682249479.487][LK-1000] establish mbedtls connection with server(host='a1eAwsBKddO.iot-as-mqtt.cn-shanghai.aliyuncs.com', port=[443])
[1682249479.574][LK-1000] success to establish mbedtls connection, (cost 45329 bytes in total, max used 48297 bytes)
[1682249479.601][LK-0313] MQTT connect success in 148 ms
AIOT_MQTTEVT_CONNECT
[1682249479.601][LK-0309] sub: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/get
[1682249479.601][LK-0309] pub: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/update

[LK-030A] > 7B 22 69 64 22 3A 22 31  22 7D                   | {"id":"1"}      

suback, res: -0x0000, packet id: 1, max qos: 1
heartbeat response
[1682249479.668][LK-0309] pub: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/get

[LK-030A] < 54 72 79 20 65 6E 74 65  72 69 6E 67 20 77 68 61 | Try entering wha
[LK-030A] < 74 20 79 6F 75 20 77 61  6E 74 EF BC 81 EF BC 81 | t you want......
[LK-030A] < EF BC 81                                         | ...             

pub, qos: 0, topic: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/get
pub, payload: Try entering what you want！！！
[1682249480.917][LK-0309] pub: /ext/notify

[LK-030A] < 7B 22 74 69 74 6C 65 22  3A 22 6B 69 63 6B 22 2C | {"title":"kick",
[LK-030A] < 22 63 6F 6E 74 65 6E 74  22 3A 22 4B 69 63 6B 65 | "content":"Kicke
[LK-030A] < 64 20 62 79 20 74 68 65  20 73 61 6D 65 20 64 65 | d by the same de
[LK-030A] < 76 69 63 65 22 7D                                | vice"}          

pub, qos: 0, topic: /ext/notify
pub, payload: {"title":"kick","content":"Kicked by the same device"}
[1682249480.917][LK-1000] mbedtls_ssl_recv error, res: -0x7880
[1682249480.917][LK-1000] adapter_network_deinit
```

看起来就是和一个阿里云的 MQTT 服务进行通信，用户名和密码都有，主机和端口也有。这个 MQTT 连接 subscribe 了 /.../.../user/get，publish 到 /.../.../user/update。发送了一个 `{"id":"1"}`，然后得到了 `Try entering what you want`。

所以可以尝试一下发送其他内容，可以使用 python 的 sdk 来进行连接，也可以直接 patch 这个程序。但是 IDA 里面 patch 会有问题，不如直接修改二进制文件，需要修改的内容是 `{"id":"1"}` 以及发送的长度，修改成 `{"id":"flag"}` 之后运行就可以得到：

```text
...
[1682249712.939][LK-0309] sub: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/get
[1682249712.939][LK-0309] pub: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/update

[LK-030A] > 7B 22 69 64 22 3A 22 66  6C 61 67 22 7D          | {"id":"flag"}   

suback, res: -0x0000, packet id: 1, max qos: 1
heartbeat response
[1682249712.999][LK-0309] pub: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/get

[LK-030A] < 61 6C 69 79 75 6E 63 74  66 7B 35 35 35 38 62 65 | aliyunctf{5558be
[LK-030A] < 32 65 32 38 36 66 65 62  65 39 62 61 35 34 63 37 | 2e286febe9ba54c7
[LK-030A] < 32 31 63 62 34 61 30 65  36 31 7D                | 21cb4a0e61}     

pub, qos: 0, topic: /a1eAwsBKddO/ncApIY2XV9NUIY4VpbGk/user/get
pub, payload: aliyunctf{5558be2e286febe9ba54c721cb4a0e61}
```

所以 flag: **aliyunctf{5558be2e286febe9ba54c721cb4a0e61}**。

最后总结一下，这题折磨了时间最久，我觉得漏洞也不小，叫垃圾题好像也不至于，但确实傻逼（x。主要有以下几点我还不明白：

- 音频里每条为什么要重复三次，为什么开头会有一堆 \*\*\*\*，为什么后三条内容是 0x8d8d8d8d 的一点用都没有
    - 我觉得可能是某种通讯的协议之类的，但是没有找到
- 这个 01 串的处理确实有点要脑洞的，不太好，卡了很长时间（但是如果是通讯协议的要求那我无话可说）
- 解出来的 ALBB-iot2023.oss.... 的写法真的很容易混淆的，而且得到假 flag 之后就会觉得已经没有可用信息了
    - 虽然 bucket 名不能大写这个问题确实后来才发现
- MQTT 协议的出现有点突兀，像是硬套娃+宣传阿里云产品，而且已有库好像都不太好用，还是直接 patch 可执行文件方便，以及到底要 pub 什么也要猜，不好

---

## HappyTree
![](https://img.shields.io/badge/-CRYPTO-orange?style=flat-square)
![](https://img.shields.io/badge/-BLOCKCHAIN-orange?style=flat-square)

其实就是一道 ETH 题，密码学成分不多。四老师做的，看了一下还挺好玩的。

??? question "题目合约"
    ```solidity
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract Greeter {
        uint256 public x;
        uint256 public y;
        bytes32 public root;
        mapping(bytes32 => bool) public used_leafs;

        constructor(bytes32 root_hash) {
            root = root_hash;
        }

        modifier onlyGreeter() {
            require(msg.sender == address(this));
            _;
        }

        function g(bool a) internal returns (uint256, uint256) {
            if (a) return (0, 1);
            assembly {
                return(0, 0)
            }
        }

        function a(uint256 i, uint256 n) public onlyGreeter {
            x = n;
            g((n <= 2));
            x = i;
        }

        function b(
            bytes32[] calldata leafs,
            bytes32[][] calldata proofs,
            uint256[] calldata indexs
        ) public {
            require(leafs.length == proofs.length, "Greeter: length not equal");
            require(leafs.length == indexs.length, "Greeter: length not equal");

            for (uint256 i = 0; i < leafs.length; i++) {
                require(
                    verify(proofs[i], leafs[i], indexs[i]),
                    "Greeter: proof invalid"
                );
                require(used_leafs[leafs[i]] == false, "Greeter: leaf has be used");
                used_leafs[leafs[i]] = true;
                this.a(i, y);
                y++;
            }
        }

        function verify(
            bytes32[] memory proof,
            bytes32 leaf,
            uint256 index
        ) internal view returns (bool) {
            bytes32 hash = leaf;

            for (uint256 i = 0; i < proof.length; i++) {
                bytes32 proofElement = proof[i];

                if (index % 2 == 0) {
                    hash = keccak256(abi.encodePacked(hash, proofElement));
                } else {
                    hash = keccak256(abi.encodePacked(proofElement, hash));
                }

                index = index / 2;
            }

            return hash == root;
        }

        function isSolved() public view returns (bool) {
            return x == 2 && y == 4;
        }
    }
    ```

以及给了一些已有的信息：

```text
alice: 0x81376b9868b292a46a1c486d344e427a3088657fda629b5f4a647822d329cd6a
Bob:   0x28cac318a86c8a0a6a9156c2dba2c8c2363677ba0514ef616592d81557e679b6
Calor: 0x804cd8981ad63027eb1d4a7e3ac449d0685f3660d6d8b1288eb12d345ca2331d
root:  0xb57c9b430ecc5b184f7ab285b8c9ca898e3e528c4668d136ee0fab03ae716f86
```

要做的就是调用 b 函数，通过验证，这时会修改 x 和 y 的值，最终要使得 x == 2 且 y == 4。

y == 4 的话从代码看没什么好说的就是要在 b 函数里面循环验证四组，但这样的话 x 的预期就应该是 3（因为函数 g 里面 assembly 的 return 是 EVM 的 return 字节码，效果是直接返回整个调用，而不是返回当前函数调用）。

但是这个写法很奇怪，搜索可以搜到 https://blog.soliditylang.org/2022/09/08/storage-write-removal-before-conditional-termination/，是一个 bug，在 0.8.17 版本之前编译出来的结果会导致如果 g 里面直接结束交易了，其实这之前 a 函数里面之前的 x 的修改并不会发生，导致 x 的值还是上次得到的 2。

所以其实只要提供四组可以验证的 leafs proofs index 就可以了。可以得到：

```text
a = keccak256(abi.encodePacked(alice, bob)) = 0x9b1a0a45cfdc60f45820808958c1895d44da61c8f804f5560020a373b23ad51e
b = keccak256(abi.encodePacked(calor, calor)) = 0x4a35f5bda2916fbfac6936f63313cee16979995b2409de59ceda0377bae8c486
同时
keccak256(abi.encodePacked(a, b)) == root
```

所以那么现在就有了：

```text
root == root
hash(a, b) == root
hash(b, a) == root
hash(hash(alice, bob), b) == hash(a, b) == root
```

这四组就可以通过验证了。flag: **aliyunctf{scuy6bart2dwep6smad2step6cust}**

---

## 懂得都懂带带弟弟
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

没正经做出来，也不会 v8，但是这个题的非预期挺 6 的所以记录一下。

一个 js v8 的题，在最新版上 patch 删除掉了 write、read、readbuffer、readline、load、os 等功能，并且 revert 了 commit 30e4ba6df4cdf5582de4d79850bcd270e6a75a7a，加回来了一些之前删掉的序列化的功能。要求是与服务器上运行的 d8 解释器交互，读取到服务器上的 flag。

这题的非预期就是可以直接通过 import() 然后导致加载进来的 flag 内容语法错误，在报错信息中直接打出 flag：

```js
V8 version 11.4.117
d8> import("../flag")
/flag:1: SyntaxError: Unexpected token '{'
aliyunctf{woot_woot_thanks_for_closing_the_issue_hey_it_regressed_rEEOpENPLZhttps__github_com_nodejs_node_issues_18265_6144641bbe2c577a}
         ^
SyntaxError: Unexpected token '{'

/flag:1: SyntaxError: Unexpected token '{'
aliyunctf{woot_woot_thanks_for_closing_the_issue_hey_it_regressed_rEEOpENPLZhttps__github_com_nodejs_node_issues_18265_6144641bbe2c577a}
         ^
SyntaxError: Unexpected token '{'

[object Promise]
d8>
```

同时也可以看到预期做法其实是参考 https://github.com/nodejs/node/issues/18265。