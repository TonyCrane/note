---
counter: True
comment: True
---

# Clash 代理配置

!!! abstract
    这里是一些 clash 相关的配置，包括安装、使用、订阅连接转换等。

    有参考：

    - [无 GUI 的 Linux 基于 clash 代理上网解决方案](https://blog.juis.top/posts/aa921244.html)

## Clash 安装与配置
### GUI

Clash 相关的很多 repo 已经都关掉了，但还能查到一些 ClashX、ClashX Pro 这些经典软件的安装包还可以用。

但更推荐用一些“活的”工具，比如 [:material-github: clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev) 和 [:material-github: mihomo-party](https://github.com/mihomo-party-org/mihomo-party)，前者是 tauri，后者是 electron，都是跨平台的。

GUI 的软件安装就不多说了，即装即用就好，但 mihomo-party 会默认接管 DNS 配置，可能会导致内网连不上之类的，在设置里面直接关掉接管 DNS 就好了。

### 无 GUI

一般在服务器上配置 clash 就需要直接配置 [:material-github: MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 也就是套皮的 clash meta 了。

#### 准备工作

下载之前可以专门准备一个目录比如 `~/proxy` 来放相关的文件。

在 [release](https://github.com/MetaCubeX/mihomo/releases) 页面下载最新的压缩包再解压就好，版本选择普通没带标签或者 compatible 的应该都可以，下载的人也最多：

```shell
wget https://github.com/MetaCubeX/mihomo/releases/download/v1.18.10/mihomo-linux-amd64-compatible-v1.18.10.gz -O mihomo.gz
gzip -d mihomo.gz
mv mihomo clash
chmod +x clash
```

运行起来的话还需要 cache.db 和 geoip.metadb，启动的时候会自动下载，但会比较慢，有下载过的可以直接 scp 上去。

之后还需要一个 `config.yaml` 配置文件，是提供代理服务器和规则的，直接将 clash 的订阅链接拉下来就好：

```shell
wget <your subscription link> -O config.yaml
```

准备好后可能还要修改一下头部的 dns 配置，不然开了 TUN 之后可能会连不上内网：

```yaml
dns:
    enable: true
    enhanced-mode: redir-host
    nameserver:
        - 10.10.0.21
        - 10.10.2.21
    fallback:
        - 114.114.114.114
        - 8.8.8.8
    ipv6: false
```

#### systemd 配置

接着我们需要起一个 systemd 服务来运行 clash，创建文件 `/etc/systemd/system/clash.service` 并写入：

```toml
[Unit]
Description=Clash-Meta Daemon.
After=network.target NetworkManager.service systemd-networkd.service iwd.service

[Service]
Type=simple
LimitNPROC=500
LimitNOFILE=1000000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_TIME CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_TIME CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
Restart=always
ExecStartPre=/usr/bin/sleep 1s
ExecStart=/path/to/proxy/clash -d /path/to/proxy
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

`/path/to/proxy` 改成我们之前准备的那个目录，即存放了 clash 和 config.yaml 的目录。然后启动就好：

```shell
sudo systemctl daemon-reload
sudo systemctl start clash
sudo systemctl status clash
```

之后终端就可以通过 `#!shell export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 all_proxy=socks5://127.0.0.1:7890` 来设置代理了，可以将这个 alias 到 proxy 之类的命令来方便使用。设置完可以通过 `#!shell curl -v -I https://www.google.com/` 来测试代理是否生效。

取消代理的话直接 `#!shell unset https_proxy http_proxy all_proxy` 就好。

#### UI 界面与 TUN 模式

mihomo 也提供了一个网页 dashboard，可以通过 config.yaml 来配置。首先需要下载 ui assets：

```shell
git clone https://github.com/metacubex/metacubexd.git -b gh-pages /path/to/proxy/ui
```

然后在 config.yaml 里面加上：

```yaml
secret: <your secret>
external-ui: /path/to/proxy/ui
external-controller: 0.0.0.0:<port>
```

再重启 systemd 服务之后就可以通过 `http://<ip>:<port>/ui` 来访问 dashboard 了，其中后端填 `http://<ip>:<port>`，密钥就是 secret。

TUN 模式在配置一页里面直接点击“开启 TUN 转发”就好了，之后机器的所有流量都会走这个代理。

##### 反代访问

想要通过域名来直接访问的话可以通过 nginx 或 caddy 来配置，同时我们可以将原来的 `/ui/` 提至 `/`，将 `/` 再移动到 `/api/` 去，这样访问起来会更加方便。

??? success "nginx 配置"
    目前我的配置，可能会有点臃肿，但能用
    ```nginx
    location ^~ /api/ {
        proxy_pass http://127.0.0.1:<port>/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header REMOTE-HOST $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        add_header Cache-Control no-cache;
    }

    location ^~ / {
        proxy_pass http://127.0.0.1:<port>/ui/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header REMOTE-HOST $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        add_header X-Cache $upstream_cache_status;
    }
    ```

??? success "Caddy 配置"
    Caddy 写起来可能会略有刁钻，需要判断一下路径：

    ```caddy
    @ui {
        not path /api*
    }

    handle_path /api* {
        reverse_proxy localhost:<port>
    }

    handle @ui {
        rewrite * /ui{uri}
        reverse_proxy localhost:<port>
    }
    ```

## 订阅转换

机场提供的订阅链接在代理组方面可能不太好用，我们可以只利用其中的节点信息，然后根据节点名称进行分类，重建一个更方便分类管理、规则匹配的订阅，这个就是 subconverter 干的事情，整套服务都可以自建，分为前后端，部署起来也不复杂。

### subconverter

后端使用 [:material-github: tindy2013/subconverter](https://github.com/tindy2013/subconverter)，我有一个修改了的版本 [:material-github: TonyCrane/subconverter](https://github.com/TonyCrane/subconverter)，阉割了一些 API 管理的方法，并且为所有 API 的访问加上了 token 验证，自己部署的话也可以部署我这个。

我们需要 repo 里面的 base 目录作为工作目录，以下会记为 `/path/to/base`。首先需要将 subconverter 的二进制下载到工作目录里，然后复制一份 `pref.example.ini` 到 `pref.ini`，修改一些配置：

```ini
[common]
api_mode=true
api_access_token=...    # 我修改的那一份会用这个 token 对所有 api 进行验证
exclude_remarks=(到期|剩余流量|时间|官网|产品|平台|通知)    # 如果你的订阅里面有其他的关键词也可以加进去，我加了一个“通知”

[managed_config]
managed_config_prefix=https://xxx  # 你的服务地址

[server]
listen=127.0.0.1    # 最终反代出去的话监听端口可以改成本地
port=xxx            # 可以修改服务端口
```

然后需要开一个 systemd 服务，`/etc/systemd/system/subconverter.service`：

```toml
[Unit]
Description=Subscription Convert API
After=network.target

[Service]
Type=simple
ExecStart=/path/to/base/subconverter
WorkingDirectory=/path/to/base
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

systemctl 启动这个服务之后就可以在对应端口上使用了，同样也可以利用 nginx 或 caddy 反代出去。

### ZJU-Rule

ZJU 可以使用 [:material-github: SubConv/ZJU-Rule](https://github.com/SubConv/ZJU-Rule) 来基于 ACL4SSR 添加 ZJU 相关的分流规则，需要将其 clone 到 `/path/to/base` 里。

本地使用的话需要将 `ZJU-Rule/Clash/config/ZJU.ini` 里的 `https://raw.githubusercontent.com/SubConv/ZJU-Rule/main/` 都改成 `ZJU-Rule/`，否则每次都会从远程拉规则。

然后在 base 里的 `pref.ini` 里加上：

```ini
[common]
default_external_config=ZJU-Rule/Clash/config/ZJU.ini
```

这样默认使用的就是本地的 ZJU-Rule 了。所有规则的入口都在这个 `ZJU.ini` 里，想加自己的规则的话可以从这里入手，在对应的 .list 文件里添加。

### sub-web

前端使用 [:material-github: CareyWang/sub-web](https://github.com/CareyWang/sub-web)，这个网站的主要用途就是辅助配置生成使用 subconverter 的新订阅链接。

用 docker 搭建就好，官方镜像是 `careywong/subweb:latest`，如果需要修改网站内容的话需要自己 build，docker-compose 如下：

```yaml
name: subweb-docker

services:
    subweb:
        build: sub-web  # 源码文件夹
        container_name: subweb
        restart: always
        ports:
            - '<port>:80'
```

基本上需要修改的就是 `src/views/Subconverter.vue` 这个文件，如果用了我加了 token 的后端的话，需要在这里加上一个 form 用了填 token，可以记录值为 `form.token`，然后在 makeUrl 函数里类似位置添加：

```javascript
if (this.form.token !== "") {
    this.customSubUrl +=
        "&token=" + encodeURIComponent(this.form.token);
}
```

另外一个很重要的需要更改的是 remoteConfig 配置，我的配置添加了：

```javascript
remoteConfig: [{
    label: "ZJU-Rule",
    options: [{
        label: "本地 ZJU-Rule（默认、稳定，带 TonyCrane 域名规则）",
        value: ""
    }, {
        label: "GitHub ZJU-Rule（可能出现下载问题）",
        value:
        "https://raw.githubusercontent.com/SubConv/ZJU-Rule/main/Clash/config/ZJU.ini"
    }]
}, ...
```

这样规则 ini 是空的话就会使用到 subconverter 的 `default_external_config` 也就是我们之前配置的本地 ZJU.ini。另外还加了一个直接拉取 GitHub 上的版本的选项，其他规则就由 sub-web 默认提供就够了（基本上有 ZJU-Rule 就只用 ZJU-Rule 了）。

然后在使用的时候订阅链接一行一行粘贴（不要有空行），选择后端地址 `http(s)://...:.../sub?`，再选择远程配置，之后生成链接就可以贴到 clash 里用了。

## 特殊订阅链接

前面搞好的 sub-web 在贴订阅链接的时候除了贴机场的链接以外，还可以同时带一些自己搭建的代理服务，这些通过特定的 protocol 就可以解析成一个节点了。

- socks 代理，可以使用 tg 的 protocol： 
    ```text
    tg://socks?server=<ip>&port=<port>&remarks=<name>
    ```
- vmess 代理，通过 vmess protocol：
    ```text
    vmess://<base64>?remarks=<name>&alterId=...
    vmess://<base64>?remarks=<name>&obfsParam=<host>&path=/<path>/&obfs=websocket&alterId=...
    ```
    - 其中 base64 编码的是 `<cipher>:<uuid>@<host>:<port>`，cipher 可以用 auto
        - 需要用 URL Safe 的字符集进行编码
    - 后者会生成下面这样的节点信息：
        ```yaml
        - name: <name>
          ...
          network: ws
          ws-opts:
            path: /<path>/
            headers:
              Host: <host>
        ```

另外这里的 name 会被 subconverter 用来匹配节点信息，比如其中带“日本”“东京”字样则会划分到日本节点一类，使用 ZJU-Rule 并带“ZJU”字样则会分配到 ZJU 内网一类（并且不会被自动切换选用）。