---
counter: True
comment: True
---

# 内网穿透与反向代理

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

## tailscale

tailscale 可以实现异地组网，在内网机器上和外部机器上都安装 tailscale 并登录到同一个账号后，就可以通过 tailscale 分配的 100.xx.xx.xx 的 ip 互相访问了，不管是否在同一网络环境下。

这样来直接访问内网上自己的服务还是很方便的，不过缺点是手机端 tailscale 会占掉 VPN 连接，这样同时就不能再开其他 vpn 了。

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