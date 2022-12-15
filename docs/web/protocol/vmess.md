---
counter: True
comment: True
---

# VMess 协议

!!! abstract
    VMess 是 V2Ray 原创的基于 TCP 的加密通讯协议，常用于代理服务器的通讯上。

    在 2022 强网杯线上赛的时候学了这个协议，记录一下

    参考：

    - [~~VMess 协议 - V2Ray 开发者文档~~](https://www.v2ray.com/developer/protocols/vmess.html)（全是错误，不要看）
    - [:material-github: v2ray/v2ray-core: proxy/vmess](https://github.com/v2ray/v2ray-core/tree/master/proxy/vmess)
    - [:material-github: worstass/leaf: leaf/src/proxy/vmess](https://github.com/worstass/leaf/tree/master/leaf/src/proxy/vmess)
    - [VMess 协议 - V2Ray 白话文教程](https://toutyrater.github.io/basic/vmess.html)

## VMess 基础

VMess 通过 uuid 和时间进行认证，uuid 可以看成一个 16 字节的随机数，形如 43509e50-1164-11ed-861d-0242ac120002（4-2-2-2-6 字节），几乎完全随机，可以通过 https://www.uuidgenerator.net/ 生成。需要保证客户端和服务端设置的 uuid 相同，否则无法解密。以及客户端和服务端的时间设置不能偏差太多（90 秒以内）

- VMess 是一个无状态协议，即客户端和服务器之间不需要握手即可直接传输数据，每一次数据传输对之前和之后的其它数据传输没有影响
- VMess 的客户端发起一次请求，服务器判断该请求是否来自一个合法的客户端。如验证通过，则转发该请求，并把获得的响应发回给客户端
- VMess 使用非对称格式，即客户端发出的请求和服务器端的响应使用了不同的格式

## 通讯协议内容

VMess 是非对称格式，所以分客户端请求和服务端响应两个格式

并且 VMess 基于 TCP 协议，以下的内容均包含在 TCP 协议的数据部分中

以下均是不使用 AEAD 的情况，使用 AEAD 时会有差别

### 客户端请求
客户端请求的内容为：

- 16 字节**认证信息**（Certification Information）
- 不定长（下面解释）**指令部分**（Instruction Part），也称请求头（header）
- 余下的均是**数据部分**（Data Part）

#### 认证信息
认证信息用来给服务端确认 uuid 以及时间是否正确，如果不正确则整个包都无法解码

整个认证信息部分使用 [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) 计算哈希

- 使用的 hash 函数是 md5
- 密钥为十六字节的 uuid（即除去 "-" 后读为 16 个字节内容
- 信息为当前的 UTC 时间（Unix 时间戳，精确到秒）上下随机浮动 30 秒，然后表示为 8 字节大端格式

即利用 Python 实现认证信息编码：
```python
import time, hmac, random # 标准库
uuid = bytes.fromhex("43509e50-1164-11ed-861d-0242ac120002".replace("-", ""))
t = int(time.time()) + random.randint(-30, 30)
cert_info = hmac.new(uuid, int.to_bytes(t, 8, "big"), digestmod='md5').digest()
```

在进行认证的时候会取当前时间，前后分别枚举 120 秒，根据 uuid 计算 hash 然后与认证信息进行比较，正常情况下会得到唯一的一个时间戳 T，在后面指令部分也会用到

V2Ray 服务端的代码实现是缓存、更新这 240 秒内的哈希值，方便进行快速查找（[validator.go](https://github.dev/v2ray/v2ray-core/blob/master/proxy/vmess/validator.go#L157)）

#### 指令部分

指令部分整体是使用 AES-128-CFB 加密过的

- key 为 `md5(uuid + b"c48619fe-8f02-49e0-b9e9-edf763e17e21")`
    - 这里需要注意，uuid 为 16 字节，后面接的是固定的，而且并且不是 16 字节 uuid 而是 36 字节（字符串转 bytes，一个字符一个字节）
- iv 为 `md5(T * 4)`，其中 T 为上面用于计算 hmac 哈希的时间戳（8 字节大端）

```python
import hashlib
from Crypto.Cipher import AES # pycryptodome
key = hashlib.md5(uuid + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()
iv = hashlib.md5(t * 4).digest()
cipher = AES.new(key=key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
inst_part = cipher.encrypt(inst)
```

未加密的指令内容为：

- （ 1 字节）版本号 ver：始终为 1
- （16 字节）数据部分加密 iv：随机生成，供数据部分加密使用（后也称请求 iv）
- （16 字节）数据部分加密 key：随机生成，供数据部分加密使用（后也称请求 key）
- （ 1 字节）响应认证 V：随机生成，用于匹配响应
- （ 1 字节）选项 opt
    - .......S：是否使用标准格式数据流（一般均为 1）
    - ......R.：已弃用
    - .....M<span style="font-variant-ligatures: none;">..</span>：数据部分及响应是否开启 mask（后面会详细解释）
    - ....P<span style="font-variant-ligatures: none;">...</span>：数据部分及响应是否开启 padding
- （ 1 字节）P 与 Sec
    - （前 4 bit）余量 P：在校验码前添加的字节数
    - （后 4 bit）加密方式 Sec：对于数据部分及响应使用的加密方式（*此处文档有误*）
        - 0x1：使用 AES-128-CFB 算法（少用）
        - 0x3：使用 AES-128-GCM 算法
        - 0x4：使用 ChaCha20-Poly1305 算法
        - 0x5：不加密（少用）
- （ 1 字节）保留，默认为 0x00
- （ 1 字节）指令 cmd：为 0x01 时使用 TCP、为 0x02 时使用 UDP
- （ 2 字节）端口号 port：2 字节大端格式的整型端口号
- （ 1 字节）地址类型 T：为 0x01 到 0x03
- （ ? 字节）地址 A：
    - 当 T == 0x01 时：A 为 4 字节 IPv4 地址
    - 当 T == 0x02 时：A 为 1 字节的长度 L 后接 L 字节的域名
    - 当 T == 0x03 时：A 为 16 字节 IPv6 地址
- （ P 字节）随机值：随机填充，长度由前面的 P 决定
- （ 4 字节）校验码 F：指令部分除校验码以外所有内容的 fnv1a 哈希值
    ```python
    from fnvhash import fnv1a_32 # pip install fnvhash
    F = int.to_bytes(fnv1a_32(inst[:45+P]), 4, "big")
    ```

按照上面的规则码好指令之后再经过 AES-128-CFB 加密，得到相同长度的密文，就是最后要放入包中的指令部分

解码时根据认证信息得到时间戳进而计算出 iv，经过 AES-128-CFB 解密即可

#### 数据部分
数据格式分为基础格式（basic format）和标准格式（standard format）。其中基础格式已经弃用，但为向后兼容所保留，仅支持不加密和 AES-128-CFB（Sec 为 0x1 或 0x5）

*这部分文档也有问题*

##### 基础格式
如果指令部分 opt 中 S 为 0，则使用基础格式，数据直接写在数据部分中

- 如果 Sec == 0x1 则使用 AES-128-CFB 加密，加密使用的 key 和 iv 在指令部分中
- 如果 Sec == 0x5 则不加密，即直接写入明文

##### 标准格式
如果指令部分 opt 中 S 为 1，则使用标准格式，进行分块写入

每一个块包含 2 字节的长度 L，以及 L 字节的数据包，其中：

- 长度 L：2 字节大端格式的整型
    - 当 opt 中 M 为 0 时，L 就是真实值
    - 当 opt 中 M 为 1 时，L = 真实长度 xor mask。这里的 mask 先采用 Shake128 根据请求 iv（即指令部分中的 iv）生成一个 RequestMask，然后每次 mask 为从 RequestMask 中取两个字节以大端序转为整型，具体后面会详细解释
- 数据包：根据加密方式进行加密，传输结束时发送空数据包表示结束，需要计算出 padding_len（后面详细解释），并记 l = L - padding_len
    - 不加密（Sec == 0x5）：直接写入 l 字节明文，后接 padding
    - AES-128-CFB（Sec == 0x1）
        - 前 4 字节为后 l-4 字节的 fnv1a 哈希（大端）
        - 中间 l-4 字节为 AES-128-CFB 加密后的密文，key 和 iv 均是指令部分中的请求 key 和请求 iv
        - 后接 padding
    - AES-128-GCM（Sec == 0x3）
        - 前 l-16 字节：AES-128-GCM 加密后的密文
            - key 为指令部分中的请求 key
            - iv 为 2 字节的 count 拼接上 10 字节的请求 iv 的第 3～12 字节（requestBodyIV[2:12]），其中 count 从第一个数据包 0 开始，每个数据包增加 1，编码为 2 字节大端格式
        - 中间 16 字节：AES-128-GCM 得到的认证信息
        - 后接 padding
    - ChaCha20-Poly1305（Sec == 0x4）
        - 前 l-16 字节：ChaCha20-Poly1305 加密后的密文
            - key 为 md5(请求 key) + md5(md5(请求 key))
            - iv 同上 AES-128-GCM
        - 中间 16 字节：ChaCha20-Poly130 得到的认证信息
        - 后接 padding

**关于 padding 和 mask**：padding 长度不固定且内容随机，它和长度的 mask 使用同一个 Shake128 生成，padding 长度为从中取两个字节，按大端序转为整型，然后模 64。一个简单的类：

```python
class Mask:
    def __init__(self, nonce: bytes):  # 此处 nonce 即为 iv
        self.hasher = hashlib.shake_128(nonce)
        self.buffer = self.hasher.digest(60000) # 提前计算出足够用的部分
        self.ptr = 0
    def next(self) -> int:
        res = self.buffer[self.ptr:self.ptr+2]
        self.ptr += 2
        return int.from_bytes(res, "big")
    def encode(self, size: bytes) -> int:
        mask = self.next()
        size = int.from_bytes(size, "big")
        return mask ^ size
    def decode(self, size: bytes) -> int:
        mask = self.next()
        size = int.from_bytes(size, "big")
        return mask ^ size
    def next_padding_len(self) -> int:
        return self.next() % 64
```

对于同一个请求，其所有数据包都使用同一个 Mask，在编码的时候先生成 padding_len，然后再 encode 数据包长度（不能反过来）

以解密为例（下面例子中是 AES-128-GCM）更能清晰地表现出这个加密方法：

```python
cnt = 0
sizeParser = Mask(requestBodyIV) # 请求指令部分中包含的 iv
dec_key = requestBodyKey # 请求指令部分中包含的 key
while request_body: # request_body 即请求的数据部分
    dec_iv = int.to_bytes(cnt, 2, "big") + requestBodyIV[2:12]
    padding_len = sizeParser.next_padding_len()
    length = sizeParser.decode(request_body[:2]) - padding_len # 获取密文长度

    request_body = request_body[2:] # 除去长度信息
    cipher = AES.new(key=dec_key, mode=AES.MODE_GCM, nonce=dec_iv)
    res = cipher.decrypt_and_verify(
        request_body[:length-16],
        request_body[length-16:length]
    ) # 解密并验证 16 字节认证信息

    request_body = request_body[length:]      # 除去密文
    request_body = request_body[padding_len:] # 除去 padding
    cnt += 1 # 下一个数据包
```

### 服务器响应
响应头使用 AES-128-CFB 加密

- 响应 key 为 md5(请求 key)
- 响应 iv 为 md5(请求 iv)

其头部明文信息为：

- （1 字节）响应信息 V：和对应请求头中的 V 保持一致
- （1 字节）选项 opt：弃用，为 0
- （1 字节）指令 cmd：为 0x01 时还有动态端口指令，仅使用 AEAD 时才会有，其余情况为 0
    - 动态端口指令这里不详细解释
- （1 字节）指令长度 M：使用 AEAD 时才会有，其余情况为 0

对于不使用 AEAD 的情况，其响应头除 V 之外都为 0

剩余的部分就是响应的数据，其编码方式与请求数据一致，差别仅在于使用的 Mask 的 nonce 为响应 iv，以及加密所使用的 key 和 iv 都是响应部分的（也就是对请求的 key 和 iv 进行 md5）