---
counter: True
comment: True
---

# Docker 相关配置与技术

!!! abstract
    一些常用/常忘的 docker 命令、Dockerfile 等

## 安装
- `curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun`
- `sudo curl -L "https://github.com/docker/compose/releases/download/1.25.5/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose`
- `sudo chmod +x /usr/local/bin/docker-compose`

macOS 推荐直接 `brew install orbstack` 安装 [OrbStack](https://docs.orbstack.dev/quick-start)，内置了 docker 且更优化更便捷。

docker pull 等需要使用代理的话需要修改配置（不会使用系统代理和终端环境变量代理），修改在 `~/.docker/config.json`（OrbStack 在 `~/.orbstack/config/docker.json` 或通过设置界面修改）：

```json
{
  "proxies": {
    "http-proxy": "http:\/\/127.0.0.1:7890",
    "https-proxy": "http:\/\/127.0.0.1:7890"
  }
}
```

## docker 命令
### 镜像相关
- `docker images` 列出本地镜像
- `docker search <image>` 搜索镜像
- `docker pull <image>` 拉取镜像
- `docker rmi <image>` 删除镜像
- `docker build -t <image> .` 从 Dockerfile 构建镜像，并打上 tag `<image>`
- `docker export <image> > <file>.tar` 保存镜像为 tar 包
- `docker import <file>.tar <image>` 从 tar 包导入镜像
- `docker tag <image> <image>:<tag>` 给镜像打 tag（重命名）

### 容器相关
- `docker ps -a` 列出正在运行的容器
- `docker run -it <image>` 运行镜像
    - `-d` 后台运行
    - `-p <host>:<container>` 端口映射
    - `-v <host>:<container>` 目录映射
    - `-e <key>=<value>` 环境变量
    - `--name <name>` 容器名
    - `--rm` 运行完后自动删除容器
    - `--network <network>` 指定网络
- `docker start <container>` 启动容器
- `docker restart <container>` 重启容器
- `docker stop <container>` 停止容器
- `docker rm <container>` 删除容器
- `docker exec -it <container> /bin/bash` 进入容器
- `docker cp ... ...` 在本地和容器之间复制文件（用法类似 scp）

### 网络相关
- `docker network ls` 列出网络
- `docker network create <network>` 创建网络
- `docker network connect <network> <container>` 将容器连接到网络
- `docker network inspect <network>` 查看网络信息
- `docker network rm <network>` 删除网络

### 仓库相关
- `docker login <url>` 连接 registry
    - `docker login` 连接到 Docker Hub
    - `docker login ghcr.io` 连接到 GitHub 的仓库，用户名是 GitHub 用户名，密码是 GitHub 生成的 token（ghp_ 开头）
- `docker logout <url>` 断开 registry
- `docker push <image>` 推送镜像到 registry（会根据前缀自动选择 registry）
- `docker pull <image>` 从 registry 拉取镜像

#### registry 镜像
可以利用 registry 镜像来自建私有 registry

- `docker pull registry:2` 拉取 registry 镜像
- 需要挂载的目录
    - `./auth:/auth`：用户名和密码。在本地 auth 目录下执行 `docker run --entrypoint htpasswd registry:2.7.0 -Bbn <username> <password> > htpasswd` 生成文件
    - `./certs:/certs`：SSL 证书，可以用 acme.sh 来签
    - `./registry:/var/lib/registry`：registry 数据
- 启动 registry：
    ```shell
    docker run -itd -p 5000:5000 --restart=always --name registry \
		-v ./certs:/certs \
		-v ./auth:/auth \
		-v ./registry:/var/lib/registry \
		-e "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/fullchain.cer" \
		-e "REGISTRY_HTTP_TLS_KEY=/certs/<domain>.key" \
		-e "REGISTRY_AUTH=htpasswd" -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
        -e "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd" \
        registry:2
    ```
- `docker login <url>` 登录 registry
- `docker tag <image> <url>/<image>` 给镜像打上 registry 的 tag
- `docker push <url>/<image>` 推送镜像到 registry

### 跨平台兼容性

- 利用 buildx 跨架构构建：
    - `docker buildx build --platform linux/amd64,linux/arm64 -t <image> .` 
- 运行时指定架构：
    - `docker run -it -d --platform linux/amd64 ...`

## Dockerfile
### 常用换源
#### Ubuntu 软件源
```dockerfile
RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list
# RUN sed -i s@/archive.ubuntu.com/@/<...>/@g /etc/apt/sources.list
RUN apt-get clean
RUN apt-get update
```

#### Debian 软件源
```dockerfile
RUN sed -i s/deb.debian.org/mirrors.aliyun.com/g /etc/apt/sources.list && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo 'Asia/Shanghai' >/etc/timezone
RUN apt-get update
```

## docker compose

常用模板：

```yaml
name: <project_name>
services:
  <service_name>:
    image: <image> # build: <path> 从 Dockerfile 构建镜像
    container_name: <container_name>
    restart: always
    ports:
      - <host>:<container>
    volumes:
      - <host>:<container>
    environment:
      - <key>=<value>
```

- restart 常用参数：
    - always：无论怎么退出都会进行重启，可以开机自启动
    - unless-stopped：除非手动停止，否则会重启
    - on-failure：只在非零退出码时重启
- ports：端口映射
    - 指定监听的 IP：`<ip>:<host>:<container>`，如果不指定 IP，则监听 0.0.0.0
    - 监听 IPv6：`[::]:<host>:<container>`
- command：覆盖镜像的默认命令
- env_file：指定环境变量文件

```bash
docker compose up -d # 后台启动服务
docker compose up --build -d # 构建镜像并启动服务
docker compose down # 停止服务
docker compose logs -f # 查看日志
```

### 多容器网络

可以在一个 docker compose 文件的 services 中定义多个容器，默认情况他们会加入同一个网络：

```yaml
services:
  app: # 省略了其他配置
    links:
      - db
    depends_on:
      - db
  db:
    expose:
      - <port>
```

- links：使 app 容器可以通过 `db` 访问 db 容器
- depends_on：在 db 容器启动后再启动 app 容器
- expose：使 db 暴露端口，如果 Dockerfile 里 EXPOSE 了可以省略
    - app 容器可以通过 `db:<port>` 链接来直接访问（注意这个 port 是容器内端口，不是映射的宿主机端口）
    - 如果宿主机需要访问 db 则需要通过 ports 映射出来

如果需要让同一个 services 中的不同容器采用不同网络，则需要通过 networks 来指定：

```yaml
services:
  app: # 省略了其他配置
    networks:
      - appnet
  db:
    networks:
      - dbnet

networks:
  appnet:
    driver: bridge
  dbnet:
    driver: bridge
```

### IPv6 支持

需要指定网络，并为网络启用 IPv6 支持：

```yaml
networks:
  v6net:
    enable_ipv6: true
```

### healthcheck

容器健康检查，如果 Dockerfile 没有指定 HEALTHCHECK，则可以在 docker compose 中指定：

```yaml
services:
  app:
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
      interval: 30s # 检查间隔
      timeout: 30s  # 超时时间
      retries: 3    # 尝试次数
      start_period: 0s  # 容器启动后多久开始第一次检测
```

在多容器 depends_on 时，可以依赖于健康监测结果：

```yaml
depends_on:
  db:
    condition: service_healthy
```

service_started 表示容器启动，service_completed_successfully 表示容器成功完成，service_healthy 表示容器健康检查通过。

### composerize

[:material-github: composerize/composerize](https://github.com/composerize/composerize) 可以将 docker run 的命令转换为 docker compose 文件：

```bash
npm install -g composerize
composerize docker run ... > docker-compose.yml
```

也可以通过在线服务 <https://composerize.com/> 来转换。同时也有 docker compose 转命令的版本 [:material-github: composerize/decomposerize](https://github.com/composerize/decomposerize)。

## podman

[podman](https://podman.io/) 在一定程度上可以替代 docker，拥有更好的 rootless 支持且不需要守护进程，而且 cockpit 有属于 podman 的管理界面，可以直接通过 apt 安装，并通过 pip 安装 [podman-compose](https://github.com/containers/podman-compose)：

```bash
sudo apt install podman
pip install podman-compose
```

原 docker 命令都可以将 docker 替换为 podman 来使用，docker compose 也可以替换为 podman-compose。

需要注意的：

- podman 默认 rootless，普通用户和 root 用户相当于不同的环境（包括拉取下来的本地镜像）
- 防火墙开关或修改后需要重载网络：`podman network reload -a`

## 其他问题

### 容器内访问 host 端口

容器的端口映射是将容器内的端口映射到 host 上，并不能实现从容器内反向访问 host 端口的服务。而且从 localhost:port 进行访问的话，localhost 仍表示容器本身，而非宿主机。

docker 可以通过添加额外的 host 指向 host-gateway 来实现：

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
# 命令：--add-host=host.docker.internal:host-gateway
```

podman 可以直接使用 `host.containers.internal` 来表示宿主机。

### 空间清理

podman 和 docker 用法一致：

- docker system df：查看占用空间情况（-v 更细致）
- docker system prune：清理所有已停止容器、未被使用的网络、dangling 镜像、未使用的构建缓存
- docker image prune：清理 dangling 镜像
    - 可能会残留 `<none>` 镜像，使用 docker image prune --filter "dangling=true" 删除
- docker image prune -a：删除所有未被使用的镜像
 