---
counter: True
comment: True
---

# 内网穿透与代理

!!! abstract
    这里是一些校外访问校内网的方法，以及一些内网穿透的方法。

    有参考：

    - [应用篇 反向代理 2 - 新 V2Ray 白话文指南](https://guide.v2fly.org/app/reverse2.html)

## ZJU Connect

最方便的本地访问校内网的方式是使用 [:material-github: Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)，它基于 EasierConnect，可以完全取代 EasyConnect。可以通过 docker 很方便地部署：

```yaml
services:
  zju-connect:
    image: mythologyli/zju-connect
    container_name: zju-connect
    restart: unless-stopped
    ports:
      - 1080:1080
      - 1081:1081
    volumes:
      - ./config.toml:/home/nonroot/config.toml
```

其中 config.toml 根据 repo 里的 config.toml.example 修改即可。开启后配合 ZJU-Rule 使用可以直接在订阅链接的地方加上一条 `tg://socks?server=127.0.0.1&port=1080&remarks=ZJU RVPN`，详见 [Clash 代理配置](clash.md)。

不过因为它走的是 RVPN，所以同一时刻只能有一个连接，不能在多个设备上同时使用。

## ZJU aTrust

!!! info "about aTrust"
    自 25 年 5 月开始，原来的 RVPN (ZJU Connect) 禁用了大量端口，推荐的 VPN 服务更新到了深信服的另一个软件 aTrust 上，地址为 <https://vpn.zju.edu.cn>。连接后会修改 route 表，对需要内网的地址转发到 atrust 的 utun 接口上。

    但 atrust 毕竟还是深信服的产品，肯定还是不会想让它跑在本机上，这里是用 docker 部署 atrust socks5 代理的方法。

[:material-github: docker-easyconnect/docker-easyconnect](https://github.com/docker-easyconnect/docker-easyconnect/) 提供了一个 aTrust 的 docker 镜像，可以提供 socks5 代理接口。但其实现方式是直接开图形界面的 aTrust 客户端进行登录，内包了一个图形界面，所以镜像比较大（2G+）。可以使用下面的 compose 来部署服务：

```yaml
services:
  atrust:
    image: hagb/docker-atrust:latest
    environment:
      - PASSWORD=123456 # vnc 密码
      - URLWIN=1
    devices:
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    ports:
      - 5901:5901   # vnc 端口
      - 1080:1080   # socks5 端口
      - 8888:8888   # http 端口
      - 54631:54631 # aTrust 控制端口，可使宿主机 web 访问
    sysctls:
      - net.ipv4.conf.default.route_localnet=1
    restart: unless-stopped
```

启动后可以通过宿主机浏览器访问 <https://vpn.zju.edu.cn> 进行登录，或者通过 vnc 客户端连接到 vnc://localhost:5901 打开图形界面进行登录。

登录后就可以使用 1080 或者 8888 端口的代理了，用法和上面的 ZJU Connect 类似，订阅链接为 `tg://socks?server=127.0.0.1&port=1080&remarks=ZJU ATRUST`。

实测如果使用了 ZJU-Rule 且启用了全局代理，例如 clash 开启了系统代理的话，需要绕过一些原本被 ZJU-Rule 判定为内网的地址：

```text
DOMAIN-SUFFIX,vpn.zju.edu.cn
IP-CIDR,210.32.129.102/32,no-resolve
IP-CIDR,210.32.174.64/32,no-resolve
IP-CIDR,210.32.3.87/32,no-resolve
IP-CIDR,10.3.9.92/31,no-resolve
IP-CIDR,10.3.9.94/32,no-resolve
```

这些在我自己部署的 ZJU-Rule 里已经添加了，[:material-github: SubConv/ZJU-Rule](https://github.com/SubConv/ZJU-Rule/pull/4) 也已 merge，但目前尚不确定还有没有其他需要绕过的地址。

??? note "关于绕过的地址"
    这些是实测下来走内网代理会导致客户端无法使用的地址，后三条可能为隧道用的地址，如果走了内网会导致一直发大量包，建立大量连接导致代理无法使用。

    通过 netstat -nr 可以查看 aTrust 修改后的 route 表，可以确认在 10.0.0.0/8 网段内需要绕过的地址：

    ```text
    10.0.0.1/32        utun9              UGc                 utun9       
    10.0.0.2/31        utun9              UGc                 utun9       
    10.0.0.4/30        utun9              UGc                 utun9       
    10.0.0.8/29        utun9              UGc                 utun9       
    10.0.0.16/28       utun9              UGc                 utun9       
    10.0.0.32/27       utun9              UGc                 utun9       
    10.0.0.64/26       utun9              UGc                 utun9       
    10.0.0.128/25      utun9              UGc                 utun9       
    10.0.1/24          utun9              UGc                 utun9       
    10.0.2/23          utun9              UGc                 utun9       
    10.0.4/22          utun9              UGc                 utun9       
    10.0.8/21          utun9              UGc                 utun9       
    10.0.16/20         utun9              UGc                 utun9       
    10.0.32/19         utun9              UGc                 utun9       
    10.0.64/18         utun9              UGc                 utun9       
    10.0.128/17        utun9              UGc                 utun9       
    10.1/16            utun9              UGc                 utun9       
    10.2/16            utun9              UGc                 utun9       
    10.3/21            utun9              UGc                 utun9       
    10.3.8/24          utun9              UGc                 utun9       
    10.3.9/26          utun9              UGc                 utun9       
    10.3.9.64/28       utun9              UGc                 utun9       
    10.3.9.80/29       utun9              UGc                 utun9       
    10.3.9.88/30       utun9              UGc                 utun9       
    10.3.9.95/32       utun9              UGc                 utun9       
    10.3.9.96/27       utun9              UGc                 utun9       
    10.3.9.128/25      utun9              UGc                 utun9       
    10.3.10/23         utun9              UGc                 utun9       
    10.3.12/22         utun9              UGc                 utun9       
    10.3.16/20         utun9              UGc                 utun9       
    10.3.32/19         utun9              UGc                 utun9       
    10.3.64/18         utun9              UGc                 utun9       
    10.3.128/17        utun9              UGc                 utun9       
    10.4/14            utun9              UGc                 utun9       
    10.8/13            utun9              UGc                 utun9       
    10.16/12           utun9              UGc                 utun9       
    10.32/11           utun9              UGc                 utun9       
    10.64/10           utun9              UGc                 utun9       
    10.128/11          utun9              UGc                 utun9       
    10.160/12          utun9              UGc                 utun9       
    10.176/13          utun9              UGc                 utun9       
    10.184/14          utun9              UGc                 utun9       
    10.188/15          utun9              UGc                 utun9       
    10.190/18          utun9              UGc                 utun9       
    10.190.64/29       utun9              UGc                 utun9       
    10.190.64.8/31     utun9              UGc                 utun9       
    10.190.126.251/32  utun9              UGc                 utun9       
    10.190.126.252/30  utun9              UGc                 utun9       
    10.190.127/24      utun9              UGc                 utun9       
    10.190.128/17      utun9              UGc                 utun9       
    10.191/16          utun9              UGc                 utun9       
    10.192/11          utun9              UGc                 utun9       
    10.224/12          utun9              UGc                 utun9       
    10.240/13          utun9              UGc                 utun9       
    10.248/14          utun9              UGc                 utun9       
    10.252/15          utun9              UGc                 utun9       
    10.254/16          utun9              UGc                 utun9       
    10.255/17          utun9              UGc                 utun9       
    10.255.128/18      utun9              UGc                 utun9       
    10.255.192/19      utun9              UGc                 utun9       
    10.255.224/20      utun9              UGc                 utun9       
    10.255.240/21      utun9              UGc                 utun9       
    10.255.248/22      utun9              UGc                 utun9       
    10.255.252/23      utun9              UGc                 utun9       
    10.255.254/24      utun9              UGc                 utun9       
    10.255.255/25      utun9              UGc                 utun9       
    10.255.255.128/26  utun9              UGc                 utun9       
    10.255.255.192/27  utun9              UGc                 utun9       
    10.255.255.224/28  utun9              UGc                 utun9       
    10.255.255.240/29  utun9              UGc                 utun9       
    10.255.255.248/30  utun9              UGc                 utun9       
    10.255.255.252/31  utun9              UGc                 utun9       
    10.255.255.254/32  utun9              UGc                 utun9       
    ```

    可以发现 10.3.9.92-94 三个地址以及 10.190.64.10 - 10.190.126.250 部分的地址是不在 route 表里的，需要直连，但后面这个 ip 段是什么作用还不清楚，目前看来不会影响 atrust 使用。

    210.32.\* 部分的地址只有少部分标为了内网，210.32.3/129/174.\* 都不在这个范围内。

但 docker-atrust 这个镜像不能实现自动登录和保活，临时使用手动开启的话还可以接受，如果需要自动登录可以尝试 [:material-github: kenvix/aTrustLogin](https://github.com/kenvix/aTrustLogin) 的容器，compose 如下：

```yaml
services:
  atrust:
    image: kenvix/docker-atrust-autologin:latest
    environment:
      - ATRUST_OPTS=--portal_address=https://vpn.zju.edu.cn --username=学号 --password=密码 --cookie_tid=需要获取 --cookie_sig=需要获取
      - PASSWORD=vnc密码
      - URLWIN=1
    devices:
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    volumes:
      - ./data:/root
    ports:
      - 5901:5901
      - 1080:1080
      - 8888:8888
    sysctls:
      - net.ipv4.conf.default.route_localnet=1
    shm_size: 256m
    restart: unless-stopped
```

这个容器会利用 selenium 进行网页的自动登录，但 ZJU 的 atrust 第一次登录需要经过图形验证码，绕过的话需要手动登录一次然后获取 cookie 里的 tid 和 tid.sig 字段，填到 compose 的 ATRUST_OPTS 里（详见 [aTrustLogin README](https://github.com/kenvix/aTrustLogin)）。以及第一次还需要进行手机验证码的输入，这个过程容器没有实现，在等待填写验证码的一步容器 log 就会提示连接成功，但实际还需要验证码。这里需要手动打开 vnc 图形界面后输入验证码。

但实际用下来这个自动登录也不太稳定，在我用的时候出现过莫名其妙密码错误的情况，但实际密码并未填错，怀疑是 cookie 的问题，而且密码错误有十次的限制，还是有一定风险。并且不像 zju connect，这个容器需要把登录密码直接写在环境变量里，安全性略低。同时这个镜像比 docker-atrust 还要大 1G，综合考虑不推荐。

## tailscale

tailscale 可以实现异地组网，在内网机器上和外部机器上都安装 tailscale 并登录到同一个账号后，就可以通过 tailscale 分配的 100.xx.xx.xx 的 ip 互相访问了，不管是否在同一网络环境下。

这样来直接访问内网上自己的服务还是很方便的，不过缺点是手机端 tailscale 会占掉 VPN 连接，这样同时就不能再开其他 vpn 了。

接下来是关于使用 tailscale 实现内网访问的几种方法。

### V2Ray 正向代理

既然通过 tailscale 可以异地组网直接连接到内网服务器上，那么就可以通过 v2ray 的正向代理来通过内网服务器代理访问其他内网地址。利用 docker 部署 v2ray：

```yaml
services:
  v2ray:
    image: v2fly/v2fly-core:latest
    container_name: v2fly
    ports:
      - xxx:xxx # inbound 端口需要填在这里暴露出来
    environment:
      - TZ=Asia/Shanghai
    volumes:
      - ./v2ray.json:/etc/v2ray.json
    command: ["run", "-config", "/etc/v2ray.json"]
    restart: always
```

v2ray.json 的写法较简单：

```json
{
    "inbounds": [{
        "port": xxx,  // 需要暴露的端口
        "protocol": "vmess",
        "settings": {
            "clients": [{
                "id": "<uuid>",  // 随机生成的 uuid
                "alterId": 0
            }]
        }
    }],
    "outbounds": [{
        "protocol": "freedom"
    }]
}
```

开启 docker 后就可以通过 tailscale 给的内网服务器的 ip（100.64/9 网段）以及端口来使用代理了，订阅链接还是 `vmess://<base64>?remarks=ZJU%20...` 的格式，其中 base64 是 URL safe base64 编码的 `auto:<uuid>@<tailscale ip>:<port>`。

不过缺点是 clash 开了 TUN 之后这个代理就连不上了，即使 TUN 绕过了 tailscale 的网段还是不行，可能是 clash 的 TUN 和 tailscale 本身冲突了导致的，还没仔细研究过。

### tailscale socks5 代理

通过 tailscale 也可以使用内网机器作为代理访问内网，一种方法为[使用 V2Ray 正向代理](#v2ray_1)，另一种方法是直接使用 tailscale 提供的代理。在内网 Linux 机器上需要修改 tailscaled 的配置文件 /etc/default/tailscaled，添加 FLAGS：

```text
PORT="41641"

FLAGS="--socks5-server=0.0.0.0:<port> --outbound-http-proxy-listen=0.0.0.0:<port>"
```

然后 systemctl restart tailscaled 重启服务即可，这样在其他连接了 tailscale 的设备上就可以使用 `tg://socks?server=<tailscale ip>&port=<port>&remarks=ZJU TS` 的代理了。同样 clash 开了 TUN 也不能用了。

### tailscale subnet

tailscale 还可以设置子网路由，允许内网机器作为路由器来访问其他内网地址。在内网机器上需要开启子网路由：

```bash
sudo tailscale set --advertise-routes=<子网> --accept-dns=false
```

之后在 tailscale admin 页面上手动批准这个路由，在其他设备上开启 use subnet 就可以直接访问这个子网了，tailscale 会自动添加该子网的路由表。

## V2Ray 反向代理

如果有一台自己的公网服务器的话，就可以通过 v2ray 的反向代理来搭建一个内网穿透的 vmess 服务节点，然后就可以在任何设备的 clash 里使用了。主要参考[新 V2Ray 白话文指南里的反向代理部分](https://guide.v2fly.org/app/reverse2.html)。

这里有三台机器，分别是 zju、public、end（这里就不像文档一样记作 A B C 了），其中 zju 是在校内网环境下且能访问公网的机器，public 是公网服务器，end 是你正在使用的设备。主要逻辑是：

![图源新 V2Ray 白话文指南](https://guide.v2fly.org/assets/img/block_of_reverse-vmess.cd11ba0c.png)

即校内的服务器 zju 一个 freedom 的 outbound 访问内网，一个 vmess 的 outbound 主动连接到公网服务器；公网服务器一个 inbound 接收来自 zju 的连接，并通过 portal 和 bridge 建立反向代理，另一个 vmess inbound 接收来自其他设备的连接，这个也就是提供 vmess 服务的节点。

我们需要在 zju 和 public 上部署 v2ray 服务，然后设备上使用 vmess:// 节点就可以了。

v2ray 可以使用 docker 来部署：

```yaml
services:
  v2ray:
    image: v2fly/v2fly-core:latest
    container_name: v2fly
    ports:
      - xxx:xxx # inbound 端口需要填在这里暴露出来
    environment:
      - TZ=Asia/Shanghai
    volumes:
      - ./v2ray.json:/etc/v2ray.json
    command: ["run", "-config", "/etc/v2ray.json"]
    restart: always
```

主要需要配置的是 v2ray.json

??? example "zju 内网机器上的配置"
    ```json
    {
        "reverse": {
            "bridges": [{
                "tag": "bridge",
                "domain": "nas.local"   // 随便设置，但要全局统一
            }]
        },
        "outbounds": [{
            "tag": "tunnel",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": "<ip or domain>",    // 公网服务器的 ip 或域名
                    "port": <port_1>,               // 公网服务器的 inbound 端口
                    "users": [{
                        "id": "<uuid_1>",           // 随机生成的 uuid
                        "alterId": 0
                    }]
                }]
            }
        }, {
            "tag": "out",
            "protocol": "freedom",
            "settings": {}
        }],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["bridge"],
                "domain": ["full:nas.local"],   // 这里要和前面的 domain 一致
                "outboundTag": "tunnel"
            }, {
                "type": "field",
                "inboundTag": ["bridge"],
                "outboundTag": "out"
            }]
        }
    }
    ```

??? example "public 公网服务器上的配置"
    ```json
    {
        "reverse": {
            "portals": [{
                "tag": "portal",
                "domain": "nas.local"   // 和 zju 上的 domain 统一
            }]
        },
        "inbounds": [{
            "tag": "tunnel",
            "port": <port_2>,           // 提供外部设备连接的端口
            "protocol": "vmess",
            "settings": {
                "clients": [{
                    "id": "<uuid_2>",   // 新随机生成的 uuid，外部设备用
                    "alterId": 0
                }]
            }
        }, {
            "tag": "interconn",
            "port": <port_1>,
            "protocol": "vmess",
            "settings": {
                "clients": [{
                    "id": "<uuid_1>",   // 同 zju 上的 uuid
                    "alterId": 0
                }]
            }
        }],
        "routing": {
            "rules": [{
                "type": "field",
                "inboundTag": ["interconn"],
                "outboundTag": "portal"
            }, {
                "type": "field",
                "inboundTag": ["tunnel"],
                "outboundTag": "portal"
            }]
        }
    }
    ```

这两个机器上运行起 v2ray 后，就可以连接 public 提供的 vmess 服务了，订阅链接可以写 `vmess://<base64>?remarks=ZJU%20...`，其中 base64 是 URL safe base64 编码的 `auto:<uuid_2>@<ip or domain>:<port_2>`，这样就可以在 clash 里使用了，剩余步骤见 [Clash 代理配置](clash.md)。（注意在公网服务器上不能开 TUN 模式）
