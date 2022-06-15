---
counter: True
comment: True
---

# 编码及古典密码

!!! abstract 
    题目中也经常会出现一些和编码和古典密码有关的过程

    编码需要根据特征判断出编码方式，古典密码则需要知道密钥来解密

## 编码
### Base64
Base64 是将3个8位转为4个6位二进制数的编码方法。如果编码后不为4的倍数则补`=`，所以特征是结尾会有 0-2 个 `=`<br/>
并且6位二进制数会被映射为可打印字符，分别是 `A-Za-z0-9+/` 63个字符，算 `=` 64个

### Base系列
|编码方式|特征|字符集|
|:--:|:--|:--|
|Base100|编码为 emoji||
|Base85|特殊字符多|<code>0-9A-Za-z!#$%&()*+-;<=>?@^_`{\|}~</code>|
|Base64|结尾会有0-2个等号|`A-Za-z0-9+/`|
|Base58|没有特殊字符、没有`0OIl`|`1-9A-HJ-NP-Za-km-z`|
|Base36||`0-9A-Z`|
|Base32|结尾会有较多等号|`A-Z2-7`|
|Base16|是一个十六进制串|`0-9A-F`|

工具：[:material-github: mufeedvh/basecrack](https://github.com/mufeedvh/basecrack)

### xxencode & uuencode
类似 Base64

- xxencode 字符集：`+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`
- uuencode 字符集：` !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` 空格可能会改为 <code>`</code>

工具：python `codecs.encode / codecs.decode`

### Unicode
- https://home.unicode.org/
- https://tool.chinaz.com/Tools/Unicode.aspx

### Emojis 
- https://www.emojiall.com/zh-hans
- [emoji-aes](https://aghorler.github.io/emoji-aes/)（需要 key），特征：🙃💵🌿🎤等开头

### 工具
- DenCode：https://dencode.com/
- Ciphey：[:material-github: Ciphey/Ciphey](https://github.com/Ciphey/Ciphey)
- CyberChef：https://gchq.github.io/CyberChef/
- emoji-aes：https://aghorler.github.io/emoji-aes/
- tool box：http://www.hiencode.com/

### 其他编码
- 盲文数学：https://nemeth.aphtech.org/
- 三词地址：https://map.what3words.com/

## 古典密码