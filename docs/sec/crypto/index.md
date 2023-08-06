---
comment: True
counter: True
---

# 密码学

!!! abstract
    浙江大学 “密码学” 课程相关知识笔记

    这里的内容主要是针对于密码学这门课的。由于一系列原因，这门课的目的其实是进行代码实践，而不偏重于理论。更多关于密码学的理论知识等如果我会写的话后续会加在 CTF 部分的笔记里。

    课程主要内容是古典密码、哈希算法（md5、sha1）、分组加密模式（ecb、cbc、cfb）、流密码（rc4）、四大加密算法（DES、AES、RSA、ECC）。笔记主要是期末复习的时候写的总结，并不全面。

    参考：

    - 图灵班课程学习指南：[密码学](https://zju-turing.github.io/TuringCourses/major_mandatory/cryptography/)

## 数学基础

- $a, b$ 为整数，且至少有一个不为 0，则一定存在整数 $x, y$ 使得 $ax + by = \gcd(a, b)$
- 若 $a+b \equiv 0 \pmod n$，则 $a, b$ 互为模 $n$ 的**加法逆元**
    - 加法逆元一定存在
- 若 $ab \equiv 1 \pmod n$，则 $a, b$ 互为模 $n$ 的**乘法逆元**，$a$ 的乘法逆元记为 $a^{-1}$
    - 乘法逆元不一定存在
    - $a$ 的逆元存在，则 $\gcd(a, n) = 1$
    - 求乘法逆元，根据 $ax+ny = \gcd(a, n) = 1$ 以及 $aa^{-1}\equiv 1\pmod n$，即求解 $x$
    - 扩展欧几里得算法，求解 $ax+by = \gcd(a, b)$ 中的 $x, y$
        ```c 
        void exgcd(LL a, LL b, LL& d, LL& x, LL& y) {
            if (!b) { d = a; x = 1; y = 0; }
            else { exgcd(b, a % b, d, y, x); y -= x * (a / b); }
        }
        ```

        ???+ example
            求 13 在模 35 下的逆元（求解 13x + 35y = 1）
            ```text
            35 / 13 = 2 ... 9
            13 / 9 = 1 ... 4
            9 / 4 = 2 ... 1
            
            1 = 9 - 2 * 4
              = (35 - 13 * 2) - 2 * (13 - 9 * 1)
              = (35 - 13 * 2) - 2 * (13 - (35 - 13 * 2) * 1)
              = 3 * 35 - 8 * 13
            ```
            
            所以 x = -8, y = 3，得 13 在模 35 下的逆元为 -8，即 27。


## 古典密码
### 单表加密
- 加法密码
    - $y = (x + key)\bmod 26$
    - $x = (y - key)\bmod 26$ 利用加法逆元
- 乘法密码
    - $y = (x \times key)\bmod 26$
    - $x = (y \times key^{-1})\bmod 26$ 利用乘法逆元
- 仿射密码
    - 结合加法密码和乘法密码
    - $y = (ax + b)\bmod 26$
    - $x = a^{-1}(y - b)\bmod 26$

### 多表密码
相同的明文对应的密文会有变化。

- Vigenere 密码
    - 密钥循环使用，第 $i$ 位为 $key_i$
    - $y_i = (x_i + key_i)\bmod 26$
    - $x_i = (y_i - key_i)\bmod 26$

#### Enigma

整体逻辑就不写了，大概就是五个选三个转子，右侧是输入输出，左侧是反射板，每个转子有 RingSetting 和 MessageKey 属性

- RingSetting：初始位置，不变的
- MessageKey：从设定的 key 开始，可以转动（加 1）

对于每个字符：

- 经过插线板查表 P1 = plugboard[P - 'A']
    - P 是明文，P1 什么的命名有些混乱见谅
    - `- 'A'` 什么的后面也不再写了，反正理解了就好
- 转动最右侧转子：MessageKey[2] = (MessageKey[2] + 1) % 26
- 检查左侧的转子是否会发生转动：
    - 如果当前转子转到了对应位置，则下一个转子转动
        - 五个转子从 1 号到 5 号的位置分别为 RFWKA（拍洗头佬马屁）
    - 可能会发生 double stepping
        - 如果中间的转子转到了对应位置的前一个，则它也会发生转动（同时带动左侧的也转）
        - 机械结构决定的 double stepping，只会发生在 2 号转子
- 从右到左查询转子，每个的操作：
    - 计算 delta = MessageKey[i] - RingSetting[i]
    - 查表 P2 = rotor[i][P1 + delta]
    - 得到 P2 - delta
- 经过反射板查表（类似插线板）
- 从左到右查询转子，每个的操作：
    - 计算 delta = MessageKey[i] - RingSetting[i]
    - 查找 index 使得 rotor[i][index] = P3 + delta
    - 得到 index - delta
- 经过插线板查表 C = plugboard[P3 - 'A']
    - C 即对应的密文
    - 同状态下 C 作为明文即可得到解密结果 P

## 哈希算法

- md5
    - message 任意长（0 也可以），digest 固定 16 字节（128 位）
    - 分块填充
        - 每块 64 字节（512 位）
        - 填充至保证最后一块长度为 56 字节（留出 8 字节存储 message 长度）
            - 填充方式为一个 0x80 后全是 0x00（即后一位 1 接下来全是 0）
            - 一定会存在填充，恰好为 56 字节时需要填充 64 字节
        - 最后 8 字节存储 message 长度
            - 以比特为单位的长度，小端序存储
    - openssl
        - `#!c MD5(message, length, digest)`
        ```c 
        MD5_CTX m;
        MD5_Init(&m);
        MD5_Update(&m, message, length);
        MD5_Final(digest, &m);
        ```
    - 彩虹表
        - 思想：预计算有限原文的摘要，节省原文与摘要映射的空间
        - 需要一个消减函数 R，可以将摘要映射回原文空间中的一个值
        - 选择一个起始信息 M0 逐次计算形成一条链：
            ```text
            M0 --H--> H0 --R--> M1 --H--> H1 ... --R--> Hn
            ```
        - 这样只需要记录一系列 M0 和 Hn 就可以实现查表
        - 假设要破解 Hm，同样对 Hm 施加 R、H，直到得到的 Hn 在表中出现，就说明 Mm 和 Hm 在这条链上，沿着 M0 开始的链找到 Mm 即可
        - 缺点是消减函数需要避免两条链碰撞
- sha1
    - message 不超过 2^64 位，digest 固定 20 字节（160 位）
    - 和 md5 同样分块填充，填充方法基本一致
        - 差别在于 message 长度用大端序存储

## 分组加密模式
- ECB：电子密码本模式
    - 分块，分别以同种方式加密，合并
    - $C_i=\mathrm{enc}(P_i), P_i=\mathrm{dec}(C_i)$
    - 优点：可以并行计算
    - 缺点：相同明文块得到的密文块相同，安全性较差
- CBC：密文块链接模式
    - 每块加密前将明文块与前一块密文块异或
        - 与第一块明文块异或的称为 IV（Initialization Vector），长度要等宽
    - $C_i=\mathrm{enc}(P_i\oplus C_{i-1}), P_i=\mathrm{dec}(C_i)\oplus C_{i-1}$
    - 当前块的密文与前一块的密文有关
    - 加密只能串行，解密可以并行
    - 密文块出错影响两个明文块，密文块缺失影响后续所有明文块
    - 密文偷窃模式（ciphertext stealing）
        - 最后一块不够长时 pad 0 会导致密文长于原文（改变了明文长度）
        - 解决方法：倒数第二个密文块只保留最后一个明文块同样长度的字节，即 C1 || C2 || ... || Cn-1' || Cn，其中 Cn-1' 长度可能会小于块大小
        - CBC-CS1：即如上保留密文块
        - CBC-CS2：如果最后一个块不完整，则交换后两个密文块
        - CBC-CS3：无条件交换后两个密文块
- CFB：密文反馈模式
    - 加密 iv 然后与明文块异或，得到密文块
        - iv 长于明文块
    - 比如 iv 为 64 位 (iv[0]..iv[7])，块大小为 8 位，则每次：
        ```c 
        iv_ = enc(iv)
        C[i] = P[i] ^ iv_[0]    // 每次都只用 iv 的第一个字节
        iv = (iv << 8) | C[i]   // 将 C[i] 放到 iv 的最后一个字节
        ```
    - 解密：
        ```c 
        iv_ = enc(iv)   // 同样是加密，不需要解密
        P[i] = C[i] ^ iv_[0]
        iv = (iv << 8) | C[i]
        ```
    - 逐字节，适合流加密，用于网络传输之类，传输过程中出错一个字节只影响九个字节，后续可以恢复，效率低

## 流密码

- rc4
    - 每次加解密一个字节，高效
    - 密钥长度 1-256 字节，内部有一个 256 字节的状态向量 S
    - 状态向量初始化：
        ```c 
        for (int i = 0; i < 256; ++i) S[i] = i;
        int j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + S[i] + key[i % len(key)]) % 256;
            swap(S[i], S[j]);
        }
        ```
    - 加解密过程相同：
        ```c 
        int i = 0, j = 0;
        for (int k = 0; k < message_len; ++k) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            swap(S[i], S[j]);
            message[k] ^= S[(S[i] + S[j]) % 256];
        }
        ```

## DES

- 块加密算法，每次明文八字节密文八字节，密钥 64 位（56 位有效、8 位校验）
- 存在的问题：密钥太短，差分攻击可以缩短工作量，sbox 设计规则没有公开
- 主要流程：初始置换（ip）、16 轮迭代（f 函数）、逆初始置换（fp/ip-1）
- 初始置换：
    - 64 bit -> 64 bit
    - 如：ip[0] = 58，初始第 58 位为置换后第 1 位
    - 置换后记左侧 32 位为 $L_0$，右侧 32 位为 $R_0$
- 子密钥生成：
    - 每一轮的 f 函数都需要一个 48 位子密钥，都是由初始 64 位密钥生成的
    - PC-1 表置换（key_perm_table）
        - 64 bit -> 56 bit（去掉校验位并打乱）
        - 置换过程同 ip
        - 置换后记左 28 位为 $C_0$，右 28 位为 $D_0$
    - 循环左移
        - 有一张表记录每一轮循环左移的位数（1 或 2）
        - $C_{i-1}$ 循环左移 1/2 位得到 $C_i$，$D$ 同理
        - 得到 $C_1, \cdots, C_{16}$ 和 $D_1, \cdots, D_{16}$
    - PC-2 表置换（key_56bit_to_48bit_table）
        - 56 bit -> 48 bit（每组 $CD$ 中选 48 位并打乱）
        - $C_n$ 和 $D_n$ 从左到右拼到一起置换后得到第 $n$ 轮子密钥 $K_n$
- 轮函数
    - 初始置换后得到了 $L_0$ 和 $R_0$
    - 每一轮进行：
        - $L_i = R_{i-1}$
        - $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$
    - 16 轮后得到 $L_{16}$ 和 $R_{16}$，调换一下拼接 $R_{16}L_{16}$ 再逆初始置换后得到密文
- f 函数
    - DES 算法核心，两个输入 32 位 R 和 48 位 K，输出 32 位
    - E 扩展置换（plaintext_32bit_expanded_to_48bit_table）
        - 32 bit -> 48 bit（扩展 R 到 48 位）
    - E 扩展后的结果与 K 异或，得到 48 位结果
    - S-box 置换
        - 48 位结果分为 8 组，每组 6 位，分别进入对应 sbox 中进行置换得到 4 位结果
            - 每个 sbox 4 行 16 列
            - 6 位中第 1 位和第 6 位组成行数，中间 4 位组成列数
            - sbox 对应行列位置上的数就是得到的 4 位结果
        - 8 组 4 位结果拼起来得到 32 位结果
    - P 盒置换（sbox_perm_table）
        - 32 bit -> 32 bit（打乱 32 位结果）
        - 置换后得到 f 函数的输出
- DES 解密：和加密过程相同，将子密钥逆序即可“从后往前”逆推 16 轮
- 上述加解密都是针对一个块的，可以配合 ECB CBC CFB 等分组加密模式使用
- openssl
    - DES_ncbc_encrypt
        ```c 
        DES_cblock iv = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xED};
        unsigned char key[8] = ...;
        des_key_schedule ks;
        des_set_key((DES_cblock *)k, ks);
        DES_ncbc_encrypt(plain, cipher, strlen(plain), &ks, &iv, DES_ENCRYPT);
        // 解密将最后一个参数改为 DES_DECRYPT
        ```
    - DES_cfb_encrypt
        - 写法和 ncbc 基本一致
- 双重 DES
    - $C = \mathrm{enc}(\mathrm{enc}(P, K_1), K_2)$，预期是使密钥变为 112 位，增大枚举难度
    - meet in the middle attack 
        - 枚举 $K_1$，计算 $\mathrm{enc}(P, K_1)$，得到一系列 $P'$
        - 枚举 $K_2$，计算 $\mathrm{dec}(C, K_2)$，得到一系列 $C'$
        - 枚举 $K_2$ 过程中检查 $C'$ 是否出现在前面一系列 $P'$ 中即可
        - 难度最大才 2^57 次枚举，只增强了一倍
- 三重 DES
    - $C = \mathrm{enc}(\mathrm{dec}(\mathrm{enc}(P, K_1), K_2), K_3)$
    - $P = \mathrm{dec}(\mathrm{enc}(\mathrm{dec}(C, K_3), K_2), K_1)$
    - 缺点：加密速度慢，密钥长度长

## AES
### 有限域

- AES 使用 $GF(2^8)$ 伽罗瓦域，不可约多项式为 $x^8 + x^4 + x^3 + x + 1$
    - 二进制为 100011011，十六进制为 0x11B
- $GF(2^8)$ 上每个多项式都可以表示为一个 8 位二进制数
- 加法：二进制异或
- 乘法：多项式乘法（注意加是异或），模 $x^8 + x^4 + x^3 + x + 1$
    - 手工计算，长除法算模
    - 农夫算法
        ```c 
        unsigned int p = 0; // 结果
        for (int i = 0; i < 8; ++i) {
            if (y & 1) p ^= x;  // y 右移丢失 1 则 p += x
            y >>= 1;
            x <<= 1;
            if (x & 0x100) x ^= 0x11B; // x 左移进位 1 则 x -= 0x11B
        }
        ```

### AES 算法

- 每次 128 位（16 字节）分组，密钥长度 128/192/256 位（16/24/32 字节）
- 每一块明文转为 4*4 的矩阵，$\mathbf{S}_{i\bmod 4, i/4} = \mathbf{byte}_i$（从上到下从左到右）
- 进行多轮加密（128 位密钥进行 10 轮），每轮都有一个密钥，也是 4*4 矩阵
- 加密过程（p 为明文矩阵，k 为密钥矩阵）：
    ```c 
    unsigned char a[4] = {0x03, 0x01, 0x01, 0x02};
    AddRoundKey(p, k);
    for (int i = 1; i <= 10; ++i) {
        ByteSub(p, 16);
        ShiftRow(p);
        if (i != 10) MixColumn(p, a);
        AddRoundKey(p, k + 16 * i);
    }
    ```
- AddRoundKey 矩阵异或
- ByteSub 逐字节进行 sbox 置换：p[i] = sbox[p[i]]
    - sbox 生成：$\mathrm{sbox}_a = ((a^{-1}\times \mathtt{0x1F})\bmod (x^8+1))\oplus \mathtt{0x63}$
    ```c 
    for (int i = 0; i < 256; ++i) {
        sbox[i] = aes_8bit_mul_mod_0x101(aes_8bit_inverse(i), 0x1F) ^ 0x63;
    }
    ```
- ShiftRow 行移位
    - 第一行不变，第二行循环左移 1 位，第三行循环左移 2 位，第四行循环左移 3 位
    ```text
    0 1 2 3       0 1 2 3
    4 5 6 7  -->  5 6 7 4
    8 9 A B       A B 8 9
    C D E F       F C D E
    ```
- MixColumn 列混淆
    - 取出矩阵的每一列，作为一个多项式（低位在上），与 $a(x)$ 相乘，再模 $x^4 + 1$
        - 加密时 $a(x) = 3x^3 + x^2 + x + 2$ [0x03, 0x01, 0x01, 0x02]
        - 解密时 $a(x) = 11x^3 + 13x^2 + 9x + 14$ [0x0B, 0x0D, 0x09, 0x0E]
        - 模 $x^4 + 1$ 就相当于把超过 4 次的项都减去 $x^4$
    - 例如一列从上到下为 [4, 3, 2, 1]，则运算为  
        <div class="arithmatex">\\[
        \begin{bmatrix}
        2 & 3 & 1 & 1 \\\\
        1 & 2 & 3 & 1 \\\\
        1 & 1 & 2 & 3 \\\\
        3 & 1 & 1 & 2
        \end{bmatrix}\times
        \begin{bmatrix}
        4 \\\\ 3 \\\\ 2 \\\\ 1
        \end{bmatrix} =
        \begin{bmatrix}
        8\oplus 1\oplus 2\oplus 5\\\\
        \cdots \\\\ \cdots \\\\ \cdots
        \end{bmatrix} =
        \begin{bmatrix}
        14 \\\\ 5 \\\\ 0 \\\\ 15
        \end{bmatrix}
        \\]</div>
        - 这里乘法是 8 位 mod 0x11B 的有限域乘法，加法是异或
    - 计算之后再放回原来的列
- 密钥生成过程
    - 取上轮密钥的最后一列，循环上移一位，进行 ByteSub，与上轮密钥第一列异或，再将第一位和 $2^{i-1}\bmod \mathtt{0x11B}$ 异或得到新一轮密钥的第一列
        - 第一位异或的分别是 01 02 04 08 10 20 40 80 1b 36
    - 上轮密钥第二列异或新一轮密钥第一列，得到新一轮密钥的第二列
    - 上轮密钥第三列异或新一轮密钥第二列，得到新一轮密钥的第三列
    - 上轮密钥第四列异或新一轮密钥第三列，得到新一轮密钥的第四列
- 解密过程就逆着推回去就可以了
- 小白老师的写法有一些不一样的地方
    - 大概是为了 memcpy 方便以及同一行的可以当做一个 int 处理，所以好多地方列变成了行
    - 明文块是从左到右从上到下排列的
    - 每轮进行的操作为：
        ```c 
        ByteSub(p, 16);
        MixColumnInverse(p, a, 0);
        ShiftRow(p);
        if (i != 10) MixColumn(p, a, 1);
        else MixColumn(p, a, 0);
        AddRoundKey(p, k + 16 * i);
        ```
    - MixColumn 加了一个参数 do_mul
        - MixColumn 取出一列，乘完放回一行
        - do_mul=0 则只进行这个列转行的操作
        - MixColumnInverse(p, a, 0) 也就相当于将 p 行转列
    - 因为 AddRoundKey 的参数 p 这时是行优先的，所以密钥的计算也是行优先计算的
- openssl
    ```c 
    AES_KEY k;
    AES_set_encrypt_key("...", 128, &k);
    AES_encrypt(plain, cipher, &k);
    AES_decrypt(cipher, plain, &k);
    ```

## RSA
### 数学基础
- 欧拉函数
    - $\phi(n)$ 表示小于 $n$ 且与 $n$ 互质的数的个数
    - 若 $n_1, n_2$ 互素，则 $\phi(n_1n_2) = \phi(n_1)\phi(n_2)$
    - $\phi(n) = n\prod_{p|n}(1-\frac{1}{p})$（其中 $p$ 为质数/质因子）
    ???+ example
        $$
        \begin{aligned}
        \phi(100) = 100\times(1-\frac{1}{2})(1-\frac{1}{5}) = 100\times\frac{1}{2}\times\frac{4}{5} = 40\\
        \phi(100) = \phi(2^2\times 5^2) = 2^{2-1}(2-1)\times 5^{2-1}(5-1) = 40
        \end{aligned}
        $$
- 欧拉定理
    - 若 $a$ 与 $n$ 互质，则 $a^{\phi(n)} \equiv 1 \pmod{n}$
- 费马小定理
    - 若 $p$ 为素数，且 $a$ 与 $p$ 互质，则 $a^{p-1} \equiv 1 \pmod{p}$
    - 因为 $\phi(p) = p - 1$
- 中国剩余定理
    - 设 $m_1, m_2, \cdots, m_r$ 两两互素，则同余方程组 $x \equiv a_i \pmod{m_i}$ 模 $M=m_1m_2\cdots m_r$ 有唯一解 $x = \sum_{i=1}^ra_iM_iy_i\bmod M$
        - 其中 $M_i=M/m_i$, $y_i=M_i^{-1}\bmod m_i$

### RSA 算法

- 非对称密码体制，有公钥和私钥
- RSA 算法过程
    - 选取两个不相等的大素数 $p$ 和 $q$，计算 $n = pq$，$\phi(n) = (p-1)(q-1)$
        - $n$ 公开，$p$ 和 $q$ 保密
    - 随机选取加密密钥 $e$，使得 $1 < e < \phi(n)$，且 $e$ 与 $\phi(n)$ 互质
    - 找到 $d$ 使得 $ed \equiv 1 \pmod{\phi(n)}$
    - 公钥为 $(n, e)$，私钥为 $(n, d)$
    - 加密：$c = m^e \bmod n$
    - 解密：$m = c^d \bmod n$
- 证明略，带入前面的数学基础一通化就好了
- 安全性
    - 能分解 $n$ 的因子 -> 得到 $p$ 和 $q$ -> 破解 RSA 不比因子分解更困难
    - 不分解因子直接求 $\phi(n)$ -> 有 $\phi(n), n$ 可以直接求得 $p, q$ -> 不比因子分解更容易
        - $p+q=n-\phi(n)+1$
        - $p-q=\sqrt{(p+q)^2-4n}$
    - 不分解因子不求 $\phi(n)$ 直接求解 $d$ -> $ed-1$ 是 $\phi(n)$ 倍数 -> 同样可求 $p, q$ -> 不比因子分解更容易
    - 目前 $n$ 长度为 1024 bit 到 2048 bit 是合理的
    - 避免选取容易分解的 $n$
        - $p, q$ 长度相差不多
        - $p-1, q-1$ 有大素因子
        - $\gcd(p-1, q-1)$ 应该很小
- openssl
    - 大数相关
        ```c 
        BIGNUM *pn = BN_new();
        BN_bin2bn(buf, n, pn);
        BN_hex2bn(&pn, "...");
        BN_CTX *ctx = BN_CTX_new();
        BN_mod_exp(pout, pin, pe, pn, ctx); // 乘方求模
        n = BN_bn2bin(pout, buf);
        BN_CTF_free(ctx);
        BN_free(pn);
        ```
        - BN 是 128/256/512/1024 位证书
    - RSA 相关
        ```c
        RSA *rsa = RSA_new();
        rsa = RSA_generate_key(bits_len, e, NULL, NULL);
        n = RSA_public_encrypt(n, in, out, rsa, RSA_PKCS1_PADDING); // 公钥加密
        n = RSA_private_decrypt(n, in, out, rsa, RSA_PKCS1_PADDING); // 私钥解密
        n = RSA_private_encrypt(n, in, out, rsa, RSA_PKCS1_PADDING); // 私钥加密
        n = RSA_public_decrypt(n, in, out, rsa, RSA_PKCS1_PADDING); // 公钥解密
        RSA_free(rsa);
        ```
    - N 为 128 位时明文长度也必须是 128 位，且明文值要小于 N，密文长度也是 128 位
        - 如果明文位数很小，$m^e<N$，则解密时不需要用到 $d$，直接对 $m$ 开 $e$ 次方即可
    - 比如明文 char m[] = {'A', 'B', 'C', 'D', 0, 0, ...} 当作大数 0x414243440000... 处理
- blinding 模式防止侧信道计时攻击
- 大数快速幂
    ```c 
    int pow_mod(int a, int p, int n) {
        if (p == 0 && n == 1) return 0;
        if (p == 0) return 1;
        int ans = pow_mod(a, p / 2, n); ans = ans * ans % n;
        if (p % 2 == 1) ans = ans * a % n;
        return ans;
    }
    int pow_mod(int a, int p, int n) {
        a %= n; int ans = 1;
        for (; p; p >>= 1, a *= a, a %= n) if(p & 1) ans = ans * a % n;
        return ans;
    }
    ```
- 数字签名
    - 对消息内容进行摘要，比如 md5，得到 M
    - A 用自己的私钥对 M 进行加密，得到签名 M'
    - B 用 A 的公钥对 M' 解密，将结果与消息摘要 M 比较

## ECC
### 数学基础
- 有限域上椭圆曲线
    - 设 $p>3$ 为素数，有限域 $Z_p$ 上椭圆曲线 $y^2=x^3+ax+b$ 是由无穷远点 $\mathcal{O}$ 和满足 $y^2\equiv x^3+ax+b\pmod{p}$ 的点 $(x, y)\in Z_p\times Z_p$ 组成的集合 $E$
        - 其中 $a, b\in Z_p$，$4a^3+27b^2\not\equiv 0\pmod{p}$
    - 定义加法：$P=(x_1, y_1)\in E, Q=(x_2, y_2)\in E$
        - 如果 $x_1=x_2, y_1=y_2=0$，则 $P+Q=\mathcal{O}$
        - 如果 $x_1=x_2, y_1=-y_2\neq 0$，则 $P+Q=\mathcal{O}$
        - 否则 $P+Q=(x_3, y_3)$
            - $x_3 = \lambda^2-x_1-x_2$
            - $y_3 = \lambda(x_1-x_3)-y_1$
            - $\lambda = \begin{cases}(y_2-y_1)(x_2-x_1)^{-1} & \text{if }P\neq Q \\(3x_1^2+a)(2y_1)^{-1} & \text{if }P=Q\end{cases}$
        - 实数域上椭圆曲线加法就是两点连线与曲线的交点关于 x 轴的对称点
        ???+ example
            曲线 $a=1, p=11$，有点 $\alpha=(2, 7)$，求 $2\alpha$  
            $\lambda = (3x_1^2+a)(2y_1)^{-1} = (3\times 4+1)(2\times 7)^{-1} = 2\times 3^{-1} = 2\times 4 = 8\pmod{11}$  
            $x_3 = \lambda^2-x_1-x_2 = 8^2-2-2 = 60 = 5\pmod{11}$  
            $y_3 = \lambda(x_1-x_3)-y_1 = 8\times(2-5)-7 = -31 = 2\pmod{11}$  
            $2\alpha = (x_3, y_3) = (5, 2)$
    - 阶
        - 曲线的阶：$|E|$（曲线上点的个数）
        - 点的阶：$nP=\mathcal{O}$ 的最小正整数 $n$
    - 生成元/基点
        - 如果点 $P$ 的阶 $n=|E|$，称 $P$ 为 $E$ 的一个生成元
        - 如果 $P$ 是 $E$ 的生成元，则 $E=\{P, 2P, 3P, ..., (n-1)P, \mathcal{O}\}$
    - 一条椭圆曲线由 $a, b, p$，基点 $G$，$G$ 的阶，余因子决定
        - 余因子为曲线的阶 / $G$ 的阶，通常为 1
    - 离散对数问题
        - $P$ 是 $E$ 的生成元，$Q$ 是 $E$ 上的任意点，求 $n$ 使得 $nP=Q$
        - 离散对数问题是难解的，是 ECC 的基础
- 欧拉准则
    - 设 $p>2$ 是一个素数，$x$ 是一个整数与 $p$ 互素
    - 如果 $y^2\equiv x\pmod p$ 有解，则称 $x$ 是 $p$ 的平方剩余，否则称为平方非剩余
    - $x$ 是模 $p$ 的平方剩余当且仅当 $x^{(p-1)/2}\equiv 1\pmod p$
        - $x$ 两个平方根为 $\pm x^{(p+1)/4}\bmod p$
    - $x$ 是模 $p$ 的平方非剩余当且仅当 $x^{(p-1)/2}\equiv -1\pmod p$

### ECC 算法
- Menezes-Vanstone 公钥密码体制
    - $p>3$ 大素数，$Z_p$ 上椭圆曲线 $E$，基点 $G$，$G$ 的阶 $n$
    - 私钥 $d$ 是一个小于 $n$ 的随机数
    - 公钥点 $R=dG$
    - 加密：对 $m$ 进行加密，得到密文两部分 $(r, s)$
        - 选取随机数 $k<n$
        - $r=(kG)_x$
        - $s=m\times(kR)_x\bmod n$
    - 解密：
        - $\dfrac{s}{(d(kG))_x}=\dfrac{m\times(kR)_x}{(kdG)_x}=\dfrac{m\times(kdG)_x}{(kdG)_x}=\dfrac{m\times(kR)_x}{(kR)_x}=m$
        - 需要通过 $r$ 找到点 $kG$，然后利用私钥解密
- ecdsa 签名验证
    - 签名
        - $r = (kG)_x$
        - $s = k^{-1}(m+rd)\bmod p$
    - 验证
        - $(s^{-1}\times m\times G + s^{-1}\times r\times R)$ 横坐标是否等于 $r$
- ecnr 签名验证
    - 签名
        - $r = (kG)_x+m$
        - $s = k-rd$
    - 验证
        - $r-(sG+rR)_x$ 是否等于 $m$
- openssl
    - 曲线参数 $a, b, p, n, G$ 和私钥 $d$ 都用 BN 给出
    - 设置曲线
        ```c 
        EC_GROUP *group = EC_GROUP_new(EC_GFp_mont_method());
        BN_CTX *ctx = BN_CTX_new();
        EC_GROUP_set_curve_GFp(group, p, a, b, ctx);
        ```
    - 设置基点
        ```c
        EC_POINT *G = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates_GFp(group, G, Gx, Gy, ctx);
        EC_GROUP_set_generator(group, G, n, BN_value_one());
        ```
    - 计算公钥 $R=dG$（点乘）
        ```c 
        EC_POINT *R = EC_POINT_new(group);
        EC_POINT_mul(group, R, d, NULL, NULL, ctx);
        ```
    - 其他函数
        ```c 
        EC_POINT_get_affine_coordinates_GFp(...) // 类似 set，获取点横纵坐标
        EC_POINT_mul(group, T, NULL, R, k, ctx); // 计算 T=kR
        EC_POINT_set_compressed_coordinates_GFp(group, T, r, 0, ctx); // T 横坐标为 r，计算纵坐标
        EC_POINT_free EC_GROUP_free
        ```
    - 大数相关
        ```c 
        long ticks = (long)time(NULL);
        RAND_add(&ticks, sizeof(ticks), 1);
        BN_rand(k, BN_num_bits(n), 0, 0); // 产生与 n 位数相等的随机数 k
        BN_copy(k, d); // 复制
        BN_mod_mul(s, m, tx, n, ctx); // s = m * (kR)_x mod n
        BN_mod_inverse(k, k, n, ctx); // k = k^-1 mod n
        ```