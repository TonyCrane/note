---
counter: True
comment: True
---

# 基本配置与工具

!!! abstract
    一些网络配置基本工具的使用记录。

## 配置工具
### NetworkManager

debian 上 `sudo apt install network-manager` 即可安装 nmcli 和 nmtui，通过 systemd 服务 NetworkManager 启动。

- `nmcli device show`：显示设备信息，可以显示是否托管、连接状态等
- `nmtui`：通过 TUI 来配置具体的网络接口连接
    - Edit 再 Activate 即可修改连接配置

### firewalld

`sudo apt install firewalld` 安装，通过 systemd 服务 firewalld 启动。可以通过 cockpit 直接管理，还没用过 firewall-cmd，以后再补充。

但在开启 firewall 的时候如果是远程连接记得把 ssh 端口改回 22，不然默认直接只开放 22 会导致把自己墙出去。

### ethtool

`sudo apt install ethtool` 安装，可以查看网卡的详细信息，比如速率、双工模式等。

- `ethtool <interface>`：查看网卡基本设置
- `ethtool -s <interface> speed 1000 duplex full`：设置网卡速率和双工模式
    - 修改后可以通过 `ethtool <interface>` 查看是否生效
    - 修改的时候建议在机器上直接操作，不要远程，否则容易断掉连不上

如果修改后 speed 显示 `Unkown!` 可以等一会儿（至少我等一会儿就好了），一直不行的话可能就是不支持，需要再改回去。

## 诊断工具
### 连接诊断

- `ping`：通过 ICMP 测试联通性，记得先在网络没问题的地方 ping 一下看看目的是否禁了 ping
- `traceroute`：显示数据包到达目的地的路径（UDP）
- `iperf`：测试网络带宽，需要在两台机器上都安装 iperf，一台作为服务端，一台作为客户端
    - 服务端：`iperf -s`，默认开在 5001 端口
    - 客户端：`iperf -c <server_ip>`

### 端口相关

- 查看端口占用
    - lsof：`sudo apt install lsof` `lsof -i:<port>`
        - 只能看到当前用户进程的，非当前用户拥有的即使占用了也不显示
        - 所以用 sudo 才能正确查询是否占用
    - netstat：`sudo apt install net-tools` `netstat -tunlp`
        - -t TCP -u UDP -n 用数字显示 -l 仅列出监听状态 -p 显示进程
        - 不是当前用户拥有的也会显示是否占用，但不会显示进程信息
        - 可以 `| grep <port>` 来筛选端口，每列分别为：
            - 协议、RecvQ、SendQ、本地地址、远程地址、状态、PID/进程名
- 查看端口是否开放
    - nmap：macOS 上 `brew install nmap` `nmap <ip> -p <port>`：扫描指定端口
        - Open：nmap 发出 SYN，服务器上监听的进程恢复 SYN/ACK，nmap 直接 RST
        - Closed：nmap 发出 SYN，服务器上直接 RST（一般是因为没有进程监听端口）
        - Filtered：没收到应答，可能是被防火墙屏蔽了，也可能是端口上的服务没有响应

### DNS

`sudo apt install dnsutils`

- dig：`dig <domain>`
- nslookup：`nslookup <domain>`
