---
comment: True
---

# SECCON CTF 2022 Final Writeup

!!! abstract
    参加的第一次线下赛，在日本，玩的很开心，题也都很有意思。

    不过 misc 只有一道物理题，web 比较坐牢我也不会，KoH 还挺刺激挺有意思的。

---

## Sniffer
![](https://img.shields.io/badge/-MISC-informational?style=flat-square)

一道物理设备的题，不难，但实操还是很有意思的，解题限时 50 分钟，解题前两小时才会下发题目。

目的大概是有两个设备 PC1 和 PC2，一个在跑 alice.py（下发），另一个在跑 bob.py（未知），中间通过网线连接。要求是仅能接触网线的中间部分，要得到 Alice 通过 socket 连接发送出去的两个 flag，第一个是明文，第二个会经过公钥交换加密。现场会提供交换机、网线、水晶头、剪线设备。

第一想法是拉过来监听流量，但因为是 socket 还要保持与 Bob 的连接，有点麻烦。而且第二个 flag 还要利用中间人攻击，也是麻烦。

换个思路，Alice 和 Bob 通过 socket 直接连接，访问是基于 ip 确定的，所以只要能伪造 ip，让 Alice 以为我们就是 Bob，就可以正常通信完美拿到 flag。

交换机型号 NETGEAR ProSafe Plus GS105Ev2，可以查到相关使用手册。

到现场后首先要完成的就是剪线+接水晶头，题目里说了使用的是 T568A 接线方式，给 Alice 那一侧颜色排好接好水晶头插在交换机上（还不能测试，接水晶头效果也没办法验证），另外再接一根线到自己电脑上。按照手册指导打开路由，配置好静态 ip 即可，这时本机的 ip 就可以设置为 Bob 的 192.168.1.103，ping 一下 Alice 102 也能 ping 通。然后跑一下预先写好的 exp 就能直接拿到两个 flag 了：

```python
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import socket
import struct
import time

def send_bytes(sock, data):
    assert len(data) < 0x10000
    sock.send(struct.pack('<H', len(data)))
    sock.send(data)

def recv_bytes(sock):
    size = struct.unpack('<H', sock.recv(2))[0]
    return sock.recv(size)

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

parameters = dh.DHParameterNumbers(p, g).parameters(default_backend())
priv = parameters.generate_private_key()
pub2 = priv.public_key()
pub_bytes = pub2.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

address = ('0.0.0.0', 12345)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
server.bind(address)
server.listen(5)

print("[+] Listening on {}:{}".format(*address))
while True:
    client, addr = server.accept()
    print('[+] FLAG1:', recv_bytes(client))
    pub = recv_bytes(client)
    send_bytes(client, pub_bytes)
    buf2 = recv_bytes(client)
    pub1 = serialization.load_pem_public_key(pub)
    shared = priv.exchange(pub1)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared)
    key = base64.urlsafe_b64encode(digest.finalize()[:32])
    f = Fernet(key)
    print('[+] FLAG2:', f.decrypt(buf2))
    client.close()
```

flag1: **SECCON{c4bl3_ch0k1ch0k1}**、flag2: **SECCON{DH_1s_n0t_s4f3_4g41n5t_p4ck3t_m4n1pul4t10n}**