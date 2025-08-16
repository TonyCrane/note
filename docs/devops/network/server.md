---
counter: True
comment: True
---

# Web 服务器相关

!!! abstract
    关于 nginx、caddy 和其他相关工具的使用记录。

## Nginx

目前在公网服务器上我还在使用 nginx，根配置文件在 `/etc/nginx/nginx.conf`，整体逻辑是：

```nginx
...

http {
    server {
        listen 80;
        listen 443 ssl http2;
        server_name ...;
        index ...;
        root ...;
    }

    server {
        ...
    }

    ...
}
```

我习惯是把所有网站的配置都放在一个文件夹里，然后全局 nginx.conf 里的 http 只留一些基本配置，然后 include 一个 `site-list.conf` 文件，里面再放一堆 include 分别引入每个网站的配置文件。

### http 裸服务模板

一般是在准备第一次申请证书的时候用的：

```nginx
server {
    listen 80;
    server_name ...;
    index index.html;
    root /websites/.../wwwroot;
    location /.well-known/ {
        allow all;
    }
}
```

### 静态 https 服务模板

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name ...;
    index index.html;
    root /websites/.../wwwroot;

    if ($server_port !~ 443) {
        rewrite ^(/.*)$ https://$host$1 permanent;
    }

    ssl_certificate /websites/.../cert/fullchain.pem;
    ssl_certificate_key /websites/.../cert/key.pem;
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000";
    error_page 497 https://$host$request_uri;

    location /.well-known/ {
        allow all;
    }

    access_log /websites/logs/....log;
    error_log /websites/logs/....error.log;
}
```

### 反代服务模板

```nginx
location ^~ / {
    proxy_pass localhost:...;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header REMOTE-HOST $remote_addr;
    add_header X-Cache $upstream_cache_status;
}

location /.well-known/ {    # 需要保留这个，用于 acme.sh 自动续签
    allow all;
}
```

### 跳转服务模板

```nginx
location ^~ / {
    rewrite ^/.* <url> permanent;
}

location /.well-known/ {
    allow all;
}

access_log off;
```

- permanent 是永久重定向，状态码 301
    - 表示已经永久移动到新位置，所有对原始 url 的请求、搜索引擎的权重等都会转移到新的 url 上
    - 一般作为短链跳转、不更改目的地址的情况下用 301 即可
- redirect 是临时重定向，状态码 302
    - 不保证以后会不会改目的地址，据说不推荐使用

### 多个 location 匹配顺序

一个 server 里可以有多个 location 规则，分别可以写：

- 精确匹配：
    - location = /uri
- 前缀匹配：
    - location /uri
    - location ^~ /uri
- 正则匹配：
    - location ~ /uri：区分大小写
    - location ~* /uri：不区分大小写
    - location !~ /uri：区分大小写，不匹配
- 通用匹配：
    - location /：匹配所有请求

顺序是：

- 精确匹配优先级最高
- 查找有没有完全满足前缀匹配
- 匹配所有 ^~ 的 location，找到最长的一个（和声明顺序无关）
    - 如果找得到：跳过正则匹配，进行其他的前缀匹配
    - 如果找不到，接下去
- 进行正则匹配，按照配置中的顺序依次匹配
    - 有匹配成功：立即停止，使用这个 location，不匹配其他正则
    - 没匹配成功，匹配下一个，如果都匹配不上，接下去
- 进行其他不带修饰的前缀匹配
    - 和带 ^~ 的一样，找到整体最长的一个
- 如果还是没有匹配，使用通用匹配

可以用工具 [:material-github: detailyang/nginx-location-match-visible](https://detailyang.github.io/nginx-location-match-visible/) 来测试匹配情况。

### acme.sh

Nginx 上配置 SSL 证书可以用 acme.sh 来自动完成：

- 安装 acme.sh：
    ```shell
    curl https://get.acme.sh | sh -s email=my@example.com
    ```
- 申请证书：
    ```shell
    acme.sh --issue -d domain.example.com --webroot /path/to/wwwroot
    ```
- 安装证书：
    ```shell
    acme.sh --install-cert -d domain.example.com \
        --key-file /path/to/cert/key.pem \
        --fullchain-file /path/to/cert/fullchain.pem \
        --reloadcmd "sudo service nginx force-reload"
    ```
    - 之后 acme 会定期自动续签，并更新两个 pem 文件，再自动执行 reload 指令

## Caddy

[Caddy](https://caddyserver.com/docs/) 是一个更便于使用、效率更高的 web 服务器，我在新配置的内网服务器上转用了 caddy。通过 apt 安装会默认开启一个 systemd 服务，运行配置 `/etc/caddy/Caddyfile`：

```shell
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

用起来的话 caddy 的配置少得多，所以直接在 `/etc/caddy/Caddyfile` 一个文件里写就可以了，运行前可以先 fmt 一下：

```shell
cd /etc/caddy
caddy fmt --overwrite
```

然后重新载入 caddy 就可以更新配置了：

```shell
systemctl reload caddy
```

Caddyfile 的格式大体上是：

```nginx
{
    email ...   # 全局配置
}

(snippet) {
    ...
}

site_addr1 site_addr2 {
    @post {     # 定义一个 matcher
        method POST
    }
    reverse_proxy @post localhost:... {  # 使用 matcher
        ...     # 额外配置
    }
    file_server /static     # 静态文件服务
    import snippet
}

site_addr3 {
    redir https://...{uri}
}

site_addr4 {
    reverse_proxy localhost:...     # 反代这样一句就够了
}   
```

### TLS 证书

Caddy 会自动为服务申请证书，需要全局配置一下 email，默认配置下就会通过公共的 ACME CA 来进行申请，并将 HTTP 服务自动重定向到 HTTPS 服务。（我目前只在内网服务器上用了 caddy，所以不会涉及到公网证书的问题，还没试过）

兼容 HTTP 的话需要单独配置新的 site：

```nginx
http://site_addr {
    reverse_proxy ...
    ...
}
```

### 内网证书

在 site block 里面 `tls internal` 就可以使用内部根证书签发的证书了，但证书需要在访问的设备上手动信任。

默认情况下根证书有效期 10 年，中间证书有效期七天，网站证书有效期 12 个小时，这个时间都太短了，可以配置：

```nginx
{
    pki {
        ca local {
            intermediate_lifetime 90d
        }
    }
}

site_addr {
    tls {
        on_demand   # 内网可以 on_demand 按需签发
        issuer internal {
            lifetime 30d
        }
    }

    ...
}
```

根证书在 `/var/lib/caddy/.local/share/caddy/pki/authorities/local` 目录下，是 root.crt 文件，拷贝出来之后在访问的设备上信任即可。

### 泛域名解析

只需要设置一个泛域名的 DNS，然后 caddy 可以通过 host matcher 来根据不同域名来配置不同的服务。

```nginx
*.example.com example.com {
    tls {
        on_demand
        issuer internal
    }

    @root host example.com
    handle @root {
        ...
    }

    @sub host sub.example.com
    handle @sub {
        ...
    }
    
    ...

    handle {
        abort
    }
}
```

### 插件安装

caddy 可以通过 xcaddy 工具来安装插件，不过逻辑是将插件编译进 caddy 的二进制中，即相当于重新编译 caddy。通过 go 安装 xcaddy：

```shell
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

通过 xcaddy 附带插件构建 caddy：

```shell
xcaddy build --with github.com/sjtug/caddy2-filter
```

构建后需要用 ./caddy 手动替换掉 /usr/bin/caddy，或更改 caddy.service。

### 一些杂项

- handle 和 handle_path 的区别：
    - handle_path 在 handle 的基础上自动应用 uri strip_prefix
        ```nginx
        handle_path /prefix/* {
            ...
        }
        # 等价于
        handle /prefix/* {
            uri strip_prefix /prefix
            ...
        }
        ```
    - handle_path 不能用 named matcher（即 @...），只能用 path matcher
